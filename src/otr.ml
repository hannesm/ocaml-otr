module State = Otr_state

module Engine = struct
  open Otr_state
  open Rresult

  let policy ctx p = List.mem p ctx.config.policies

  let handle_cleartext ctx =
    match ctx.state.message_state with
    | MSGSTATE_PLAINTEXT when policy ctx `REQUIRE_ENCRYPTION -> [`Warning "received unencrypted data"]
    | MSGSTATE_PLAINTEXT -> []
    | MSGSTATE_ENCRYPTED _ | MSGSTATE_FINISHED -> [`Warning "received unencrypted data"]

  let commit ctx their_versions =
    match Otr_ake.dh_commit ctx their_versions with
    | Ok (ctx, out) -> Ok (ctx, Some out)
    | Error (Otr_ake.Unknown e) -> Error e
    | Error Otr_ake.VersionMismatch -> Error "couldn't agree on a version"
    | Error Otr_ake.InstanceMismatch -> Error "wrong instances"
    | Error (Otr_ake.Unexpected _) -> Error "unexpected message"

  let handle_whitespace_tag ctx their_versions =
    let warn = handle_cleartext ctx in
    (if policy ctx `WHITESPACE_START_AKE then
       commit ctx their_versions
     else
       Ok (ctx, None) ) >>| fun (ctx, out) ->
    (ctx, out, warn)

  let handle_error ctx =
    if policy ctx `ERROR_START_AKE then
      Some (Otr_builder.query_message ctx.config.versions)
    else
      None

  let handle_tlv state typ buf =
    let open Otr_packet in
    match typ with
    | Some PADDING -> (state, None, [])
    | Some DISCONNECTED -> ({ state with message_state = MSGSTATE_FINISHED },
                            None,
                            [`Warning "OTR connection lost"])
    | Some EXTRA_SYMMETRIC_KEY -> (state, None, [`Warning "not handling extra symmetric key"])
    | Some (SMP_MESSAGE_1 | SMP_MESSAGE_2 | SMP_MESSAGE_3 | SMP_MESSAGE_4 | SMP_ABORT | SMP_MESSAGE_1Q as smp_type) ->
      begin match Otr_smp.handle_smp state.smp_state smp_type buf with
        | Ok (smp_state, out, usr) -> ({ state with smp_state }, out, usr)
        | Error e ->
          let msg = Otr_smp.error_to_string e in
          ({ state with smp_state = SMPSTATE_EXPECT1 }, None, [`Warning msg])
      end
    | None -> (state, None, [`Warning "unknown tlv type"])

  let rec filter_map ?(f = fun x -> x) = function
    | []    -> []
    | x::xs ->
      match f x with
      | None    ->       filter_map ~f xs
      | Some x' -> x' :: filter_map ~f xs

  let handle_tlvs state = function
    | None -> Ok (state, None, [])
    | Some data ->
      let rec process_data state data out warn =
        match Cstruct.len data with
        | 0 -> (state, out, warn)
        | _ -> match Otr_parser.parse_tlv data with
          | Ok (typ, buf, rest) ->
            let state, out', warn' = handle_tlv state typ buf in
            process_data state rest (out' :: out) (warn @ warn')
          | Error _ -> (state, out, [`Warning "ignoring malformed TLV"])
      in
      let state, out, warn = process_data state (Cstruct.of_string data) [] [] in
      let out = match filter_map out with
        | [] -> None
        | xs -> Some (Cstruct.to_string (Cstruct.concat xs))
      in
      Ok (state, out, warn)

  let guard p e = if p then Ok () else Error e

  let decrypt dh_keys symm version instances bytes =
    match Otr_parser.parse_data bytes with
    | Ok (version', instances', _flags, s_keyid, r_keyid, dh_y, ctr', encdata, mac, reveal) ->
      if version <> version' then
        Ok (dh_keys, symm, None, [`Warning "ignoring message with invalid version"])
      else if
        match version, instances, instances' with
        | `V3, Some (mya, myb), Some (youra, yourb) when (mya = youra) && (myb = yourb) -> false
        | `V2, _, _ -> false
        | _ -> true
      then
        Ok (dh_keys, symm, None, [`Warning "ignoring message with invalid instances"])
      else
        begin match Otr_ratchet.check_keys dh_keys s_keyid r_keyid dh_y with
          | Some x -> Ok (dh_keys, symm, None, [`Warning x])
          | None ->
            let symm, keyblock = Otr_ratchet.keys dh_keys symm s_keyid r_keyid in
            if ctr' <= keyblock.recv_ctr then
              Ok (dh_keys, symm, None, [`Warning "ignoring message with invalid counter"])
            else
              let stop = Cstruct.len bytes - Cstruct.len reveal - 4 - 20 in
              guard (stop >= 0) "invalid data" >>= fun () ->
              let mac' = Otr_crypto.sha1mac ~key:keyblock.recv_mac (Cstruct.sub bytes 0 stop) in
              guard (Cstruct.equal mac mac') "invalid mac" >>| fun () ->
              let dec = Cstruct.to_string (Otr_crypto.crypt ~key:keyblock.recv_aes ~ctr:ctr' encdata) in
              let txt, data =
                let len = String.length dec in
                let stop =
                  try String.index dec '\000'
                  with Not_found -> len
                in
                let txt = String.sub dec 0 stop in
                if stop = len || succ stop = len then
                  (txt, "")
                else
                  let stop' = succ stop in
                  (txt, String.sub dec stop' (len - stop'))
              in
              let data = if data = "" then None else Some data in
              let ret = (if txt = "" then [] else [`Received_encrypted txt]) in
              let dh_keys = Otr_ratchet.rotate_keys dh_keys s_keyid r_keyid dh_y
              and symm = Otr_ratchet.set_recv_counter ctr' s_keyid r_keyid symm
              in
              (dh_keys, symm, data, ret)
        end
    | Error Otr_parser.Underflow -> Error "Malformed OTR data message: parser reported underflow"
    | Error Otr_parser.LeadingZero -> Error "Malformed OTR data message: parser reported leading zero"
    | Error (Otr_parser.Unknown x) -> Error ("Malformed OTR data message: " ^ x)

  let encrypt dh_keys symm reveal_macs version instances flags data =
    let symm, reveal = Otr_ratchet.reveal dh_keys symm in
    let our_id = Int32.pred dh_keys.our_keyid in
    let symm, keyblock = Otr_ratchet.keys dh_keys symm dh_keys.their_keyid our_id in
    let our_ctr = Int64.succ keyblock.send_ctr in
    let enc = Otr_crypto.crypt ~key:keyblock.send_aes ~ctr:our_ctr (Cstruct.of_string data) in
    let data = Otr_builder.data version instances flags our_id dh_keys.their_keyid (snd dh_keys.dh) our_ctr enc in
    let mac = Otr_crypto.sha1mac ~key:keyblock.send_mac data in
    let reveal =
      let macs = if reveal_macs then
          Cstruct.concat (List.map (fun x -> x.recv_mac) reveal)
        else
          Cstruct.create 0
      in
      Otr_builder.encode_data macs
    in
    let out = Cstruct.concat [ data ; mac ; reveal] in
    let symm = Otr_ratchet.inc_send_counter dh_keys.their_keyid our_id symm in
    (symm, out)

  let wrap_b64string = function
    | None -> None
    | Some m ->
      let encoded = Base64.encode_string (Cstruct.to_string m) in
      Some (otr_mark ^ encoded ^ ".")

  let handle_data ctx bytes =
    match ctx.state.message_state with
    | MSGSTATE_PLAINTEXT ->
      begin match Otr_ake.handle_auth ctx bytes with
        | Ok (ctx, out, warn) -> Ok (ctx, wrap_b64string out, warn)
        | Error (Otr_ake.Unexpected ignore) ->
          if ignore then
            Ok (ctx, None, [])
          else
            let warn = "received encrypted data while in plaintext mode, ignoring unreadable message" in
            Ok (ctx,
                Some (otr_err_mark ^ " ignoring unreadable message"),
                [`Warning warn])
        | Error (Otr_ake.Unknown x) ->  Error ("AKE error encountered: " ^ x)
        | Error Otr_ake.VersionMismatch ->
          Ok (ctx, None, [`Warning "wrong version in message"])
        | Error Otr_ake.InstanceMismatch ->
          Ok (ctx, None, [`Warning "wrong instances in message"])
      end
    | MSGSTATE_ENCRYPTED enc_data ->
      decrypt enc_data.dh_keys enc_data.symms ctx.version ctx.instances bytes >>= fun (dh_keys, symms, data, ret) ->
      let state = { ctx.state with message_state = MSGSTATE_ENCRYPTED { enc_data with dh_keys ; symms } } in
      handle_tlvs state data >>= fun (state, out, warn) ->
      let state, out = match out with
        | None -> (state, None)
        | Some x ->
          match state.message_state with
          | MSGSTATE_ENCRYPTED enc_data ->
            let symms, out = encrypt enc_data.dh_keys enc_data.symms (reveal_macs ctx) ctx.version ctx.instances false ("\000" ^ x) in
            ({ state with message_state = MSGSTATE_ENCRYPTED { enc_data with symms } },
             wrap_b64string (Some out))
          | _ -> (state, out)
      in
      let ctx = { ctx with state } in
      Ok (ctx, out, ret @ warn)
    | MSGSTATE_FINISHED ->
      Ok (ctx, None, [`Warning "received data while in finished state, ignoring"])

  (* operations triggered by a user *)
  let start_otr ctx =
    (reset_session ctx, Otr_builder.query_message ctx.config.versions)

  let send_otr ctx data =
    match ctx.state.message_state with
    | MSGSTATE_PLAINTEXT when policy ctx `REQUIRE_ENCRYPTION ->
      (ctx,
       Some (Otr_builder.query_message ctx.config.versions),
       `Warning ("didn't send message, there was no encrypted connection: " ^ data))
    | MSGSTATE_PLAINTEXT when policy ctx `SEND_WHITESPACE_TAG ->
      (* XXX: and you have not received a plaintext message from this correspondent since last entering MSGSTATE_PLAINTEXT *)
      (ctx, Some (data ^ (Otr_builder.tag ctx.config.versions)), `Sent data)
    | MSGSTATE_PLAINTEXT -> (ctx, Some data, `Sent data)
    | MSGSTATE_ENCRYPTED enc_data ->
      let symms, out = encrypt enc_data.dh_keys enc_data.symms (reveal_macs ctx) ctx.version ctx.instances false data in
      let state = { ctx.state with message_state = MSGSTATE_ENCRYPTED { enc_data with symms } } in
      let out = wrap_b64string (Some out) in
      ({ ctx with state }, out, `Sent_encrypted data)
    | MSGSTATE_FINISHED ->
      (ctx, None, `Warning ("didn't send message, OTR session is finished: " ^ data))

  let end_otr ctx =
    match ctx.state.message_state with
    | MSGSTATE_PLAINTEXT -> (ctx, None)
    | MSGSTATE_ENCRYPTED enc_data ->
      let data = Cstruct.to_string (Otr_builder.tlv Otr_packet.DISCONNECTED) in
      let _, out = encrypt enc_data.dh_keys enc_data.symms (reveal_macs ctx) ctx.version ctx.instances true ("\000" ^ data) in
      (reset_session ctx, wrap_b64string (Some out))
    | MSGSTATE_FINISHED ->
      (reset_session ctx, None)

  let handle_fragment ctx (k, n) frag =
    match k, n, fst ctx.fragments with
    | 1, _, _ -> ({ ctx with fragments = ((k, n), frag) }, None)
    | k, n, (stored_k, stored_n) when n = stored_n && k = succ stored_k && n = k ->
      (* last fragment *)
      let full = (snd ctx.fragments) ^ frag in
      (rst_frag ctx, Some full)
    | k, n, (stored_k, stored_n) when n = stored_n && k = succ stored_k ->
      ({ ctx with fragments = ((k, n), (snd ctx.fragments) ^ frag) }, None)
    | _ -> (rst_frag ctx, None)

  let handle_fragment_v3 ctx instances kn frag =
    match ctx.instances, instances with
    | Some (a, b), (a', b') when (a = a' && b = b') || b' = 0l ->
      handle_fragment ctx kn frag
    | _ -> (ctx, None)

  let recv text = match text with None -> [] | Some x -> [ `Received x ]

  let handle_input ctx = function
    | `PlainTag (versions, text) ->
      begin match handle_whitespace_tag ctx versions with
        | Ok (ctx, out, warn) ->
          (ctx, wrap_b64string out, warn @ recv text)
        | Error e ->
          (reset_session ctx,
           Some (otr_err_mark ^ e),
           [`Warning e] @ recv text)
      end
    | `Query versions ->
      begin match commit ctx versions with
        | Ok (ctx, out) -> (ctx, wrap_b64string out, [])
        | Error e -> (reset_session ctx, Some (otr_err_mark ^ e), [`Warning e] )
      end
    | `Error message ->
      let out = handle_error ctx in
      (reset_session ctx, out,
       [`Received_error ("Received OTR Error: " ^ message)])
    | `Data bytes ->
      begin match handle_data ctx bytes with
        | Ok (ctx, out, warn) -> (ctx, out, warn)
        | Error e -> (reset_session ctx, Some (otr_err_mark ^ e), [ `Warning e])
      end
    | `String message ->
      let user = handle_cleartext ctx in
      (ctx, None, user @ recv (Some message))
    | `ParseError err ->
      (reset_session ctx,
       Some (otr_err_mark ^ err),
       [`Warning (err ^ " while parsing OTR message")])
    | `Fragment_v2 _ | `Fragment_v3 _ ->
      (reset_session ctx,
       Some (otr_err_mark ^ "unexpected recursive fragment"),
       [`Warning "ignoring unexpected recursive fragment"])

  let handle_fragments ctx = function
    | `Fragment_v2 (kn, piece) ->
      if ctx.version = `V2 then
        Ok (handle_fragment ctx kn piece)
      else
        Error "wrong version in V2 fragment"
    | `Fragment_v3 (instances, kn, piece) ->
      if ctx.version = `V3 then
        Ok (handle_fragment_v3 ctx instances kn piece)
      else
        Error "wrong version in V3 fragment"

  (* session -> string -> (session * to_send * ret) *)
  let handle ctx bytes =
    match Otr_parser.classify_input bytes with
    | `Fragment_v2 _ | `Fragment_v3 _ as f ->
      begin match handle_fragments ctx f with
        | Ok (ctx, None)   -> (ctx, None, [])
        | Ok (ctx, Some x) -> handle_input ctx (Otr_parser.classify_input x)
        | Error txt -> (ctx, Some (otr_err_mark ^ txt), [`Warning txt])
      end
    | x -> handle_input (rst_frag ctx) x

  let handle_smp ctx call =
    let enc enc_data out smp_state =
      let data = "\000" ^ (Cstruct.to_string out) in
      let symms, out = encrypt enc_data.dh_keys enc_data.symms (reveal_macs ctx) ctx.version ctx.instances false data in
      let message_state = MSGSTATE_ENCRYPTED { enc_data with symms } in
      let state = { ctx.state with message_state ; smp_state } in
      ({ ctx with state }, wrap_b64string (Some out))
    in
    match ctx.state.message_state with
    | MSGSTATE_ENCRYPTED enc_data -> ( match call enc_data ctx.state.smp_state with
        | Ok (smp_state, Some out) ->
          let st, out = enc enc_data out smp_state in
          (st, out, [])
        | Ok (smp_state, None) ->
          let state = { ctx.state with smp_state } in
          ({ ctx with state }, None, [])
        | Error e ->
          let out = Otr_builder.tlv Otr_packet.SMP_ABORT in
          let st, out = enc enc_data out SMPSTATE_EXPECT1 in
          let err = Otr_smp.error_to_string e in
          (st, out, [`Warning err]) )
    | _ -> (ctx, None, [`Warning "need an encrypted session for SMP"])

  let start_smp ctx ?question secret =
    handle_smp ctx (fun enc smp -> Otr_smp.start_smp ctx.dsa enc smp ?question secret)

  let abort_smp ctx =
    handle_smp ctx (fun _ smp -> Otr_smp.abort_smp smp)

  let answer_smp ctx secret =
    handle_smp ctx (fun enc smp -> Otr_smp.handle_secret ctx.dsa enc smp secret)
end

module Utils = struct
  open State

  let fingerprint x =
    let fp = Otr_crypto.OtrDsa.fingerprint x in
    Cstruct.to_string fp

  let their_fingerprint ctx =
    match ctx.state.message_state with
    | MSGSTATE_ENCRYPTED enc -> Some (fingerprint enc.their_dsa)
    | _ -> None

  let own_fingerprint dsa =
    fingerprint (Mirage_crypto_pk.Dsa.pub_of_priv dsa)
end

