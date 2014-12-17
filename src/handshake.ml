open State

let policy ctx p = List.mem p ctx.config.policies

(* Monadic control-flow core. *)
type error = string
include Control.Or_error_make (struct type err = error end)

let handle_cleartext ctx =
  match ctx.state.message_state with
  | `MSGSTATE_PLAINTEXT when policy ctx `REQUIRE_ENCRYPTION -> [`Warning "received unencrypted data"]
  | `MSGSTATE_PLAINTEXT -> []
  | `MSGSTATE_ENCRYPTED _ | `MSGSTATE_FINISHED -> [`Warning "received unencrypted data"]

let commit ctx their_versions =
  match Ake.dh_commit ctx their_versions with
  | Ake.Ok (ctx, out) -> return (ctx, Some out)
  | Ake.Error (Ake.Unknown e) -> fail e
  | Ake.Error Ake.VersionMismatch -> fail "couldn't agree on a version"
  | Ake.Error Ake.InstanceMismatch -> fail "wrong instances"
  | Ake.Error (Ake.Unexpected _) -> fail "unexpected message"

let handle_whitespace_tag ctx their_versions =
  let warn = handle_cleartext ctx in
  (if policy ctx `WHITESPACE_START_AKE then
     commit ctx their_versions
   else
     return (ctx, None) ) >|= fun (ctx, out) ->
  (ctx, out, warn)

let handle_error ctx =
  if policy ctx `ERROR_START_AKE then
    Some (Builder.query_message ctx.config.versions)
  else
    None

let select_dh keys send recv =
  ( if keys.their_keyid = send then
      return (keys.gy, 0L)
    else
      ( guard (keys.their_keyid = Int32.succ send) "wrong keyid" >>= fun () ->
        guard (Cstruct.len keys.previous_gy > 0) "no previous gy" >|= fun () ->
        (keys.previous_gy, keys.their_ctr) ) ) >>= fun (gy, ctr) ->
  ( if keys.our_keyid = recv then
      return keys.dh
    else
      ( guard (keys.our_keyid = Int32.succ recv) "wrong keyid" >|= fun () ->
        keys.previous_dh ) ) >|= fun dh ->
  (dh, gy, ctr)

let update_keys keys send recv dh_y ctr =
  let keys = { keys with their_ctr = ctr } in
  let keys =
    if keys.their_keyid = send then
      { keys with their_keyid = Int32.succ send ;
                  previous_gy = keys.gy ;
                  gy = dh_y ;
                  their_ctr = 0L ; }
    else
      keys
  in
  if keys.our_keyid = recv then
    { keys with our_keyid = Int32.succ recv ;
                previous_dh = keys.dh ;
                dh = Crypto.gen_dh_secret () ;
                our_ctr = 0L ; }
  else
    keys

let handle_tlv state typ _buf =
  let open Packet in
  match typ with
  | Some PADDING -> (state, None, [])
  | Some DISCONNECTED -> ({ state with message_state = `MSGSTATE_FINISHED },
                          None,
                          [`Warning "OTR connection lost"])
  | Some _ -> (state, None, [`Warning "not handling this tlv"])
  | None -> (state, None, [`Warning "unknown tlv type"])

let rec filter_map ?(f = fun x -> x) = function
  | []    -> []
  | x::xs ->
      match f x with
      | None    ->       filter_map ~f xs
      | Some x' -> x' :: filter_map ~f xs

let handle_tlvs state = function
  | None -> return (state, None, [])
  | Some data ->
    let rec process_data state data out warn =
      match Cstruct.len data with
      | 0 -> (state, out, warn)
      | _ -> match Parser.parse_tlv data with
        | Parser.Ok (typ, buf, rest) ->
          let state, out', warn' = handle_tlv state typ buf in
          process_data state rest (out' :: out) (warn @ warn')
        | Parser.Error _ -> (state, out, [`Warning "ignoring malformed TLV"])
    in
    let state, out, warn = process_data state (Cstruct.of_string data) [] [] in
    let out = match filter_map out with
      | [] -> None
      | xs -> Some (Cstruct.to_string (Nocrypto.Uncommon.Cs.concat xs))
    in
    return (state, out, warn)

let decrypt keys version instances bytes =
  match Parser.parse_data bytes with
  | Parser.Ok (version', instances', _flags, s_keyid, r_keyid, dh_y, ctr', encdata, mac, reveal) ->
    select_dh keys s_keyid r_keyid >>= fun ((dh_secret, gx), gy, ctr) ->
    if version <> version' then
      return (keys, None, [`Warning "ignoring message with invalid version"])
    else if
      match version, instances, instances' with
      | `V3, Some (mya, myb), Some (youra, yourb) when (mya = youra) && (myb = yourb) -> false
      | `V2, _, _ -> false
      | _ -> true
    then
      return (keys, None, [`Warning "ignoring message with invalid instances"])
    else if ctr' <= ctr then
      return (keys, None, [`Warning "ignoring message with invalid counter"])
    else
      let high = Crypto.mpi_gt gx gy in
      ( match Crypto.dh_shared dh_secret gy with
        | Some x -> return x
        | None -> fail "invalid DH public key" ) >>= fun shared ->
      let _, _, recvaes, recvmac = Crypto.data_keys shared high in
      let stop = Cstruct.len bytes - Cstruct.len reveal - 4 - 20 in
      guard (stop >= 0) "invalid data" >>= fun () ->
      let mac' = Crypto.sha1mac ~key:recvmac (Cstruct.sub bytes 0 stop) in
      guard (Nocrypto.Uncommon.Cs.equal mac mac') "invalid mac" >|= fun () ->
      let dec = Cstruct.to_string (Crypto.crypt ~key:recvaes ~ctr:ctr' encdata) in
      let txt, data =
        try
          let stop = String.index dec '\000' in
          let stop' = succ stop in
          String.(sub dec 0 stop, sub dec stop' (length dec - stop'))
        with _ -> (dec, "")
      in
      let data = if data = "" then None else Some data in
      let ret = (if txt = "" then [] else [`Received_encrypted txt]) in
      let keys = update_keys keys s_keyid r_keyid dh_y ctr' in
      (keys, data, ret)
  | Parser.Error Parser.Underflow -> fail "Malformed OTR data message: parser reported undeflow"
  | Parser.Error (Parser.Unknown x) -> fail ("Malformed OTR data message: " ^ x)

let encrypt version instances flags keys ?(reveal = Cstruct.create 0) data =
  let (dh_secret, gx), gy = (keys.previous_dh, keys.gy) in
  let high = Crypto.mpi_gt gx gy in
  ( match Crypto.dh_shared dh_secret gy with
    | Some x -> return x
    | None -> fail "invalid DH public key" ) >|= fun shared ->
  let sendaes, sendmac, _, _ = Crypto.data_keys shared high in
  let our_ctr = Int64.succ keys.our_ctr in
  let enc = Crypto.crypt ~key:sendaes ~ctr:our_ctr (Cstruct.of_string data) in
  let our_id = Int32.pred keys.our_keyid in
  let data = Builder.data version instances flags our_id keys.their_keyid (snd keys.dh) our_ctr enc in
  let mac = Crypto.sha1mac ~key:sendmac data in
  let reveal = Builder.encode_data reveal in
  let out = Nocrypto.Uncommon.Cs.concat [ data ; mac ; reveal] in
  ({ keys with our_ctr }, out)

let wrap_b64string = function
  | None -> None
  | Some m ->
    let encoded = Nocrypto.Base64.encode m in
    Some ("?OTR:" ^ Cstruct.to_string encoded ^ ".")

let handle_data ctx bytes =
  match ctx.state.message_state with
  | `MSGSTATE_PLAINTEXT ->
    ( match Ake.handle_auth ctx bytes with
      | Ake.Ok (ctx, out, warn) -> return (ctx, wrap_b64string out, warn)
      | Ake.Error (Ake.Unexpected ignore) ->
        if ignore then
          return (ctx, None, [])
        else
          return (ctx,
                  Some "?OTR Error: ignoring unreadable message",
                  [`Warning "received encrypted data while in plaintext mode, ignoring unreadable message"])
      | Ake.Error (Ake.Unknown x) ->  fail ("AKE error encountered: " ^ x)
      | Ake.Error Ake.VersionMismatch ->
        return (ctx, None, [`Warning "wrong version in message"])
      | Ake.Error Ake.InstanceMismatch ->
        return (ctx, None, [`Warning "wrong instances in message"]) )
  | `MSGSTATE_ENCRYPTED keys ->
    decrypt keys ctx.version ctx.instances bytes >>= fun (keys, data, ret) ->
    let state = { ctx.state with message_state = `MSGSTATE_ENCRYPTED keys } in
    handle_tlvs state data >>= fun (state, out, warn) ->
    ( match out with
      | None -> return (state, None)
      | Some x -> match encrypt ctx.version ctx.instances false keys x with
        | Ok (keys, out) ->
          return ({ state with message_state = `MSGSTATE_ENCRYPTED keys },
                  wrap_b64string (Some out))
        | Error e -> fail e ) >|= fun (state, out) ->
    let ctx = { ctx with state } in
    (ctx, out, ret @ warn)
  | `MSGSTATE_FINISHED ->
    return (ctx, None, [`Warning "received data while in finished state, ignoring"])

(* operations triggered by a user *)
let start_otr ctx =
  (reset_session ctx, Builder.query_message ctx.config.versions)

let send_otr ctx data =
  match ctx.state.message_state with
  | `MSGSTATE_PLAINTEXT when policy ctx `REQUIRE_ENCRYPTION ->
    (ctx,
     Some (Builder.query_message ctx.config.versions),
     `Warning ("didn't sent message, there was no encrypted connection: " ^ data))
  | `MSGSTATE_PLAINTEXT when policy ctx `SEND_WHITESPACE_TAG ->
    (* XXX: and you have not received a plaintext message from this correspondent since last entering MSGSTATE_PLAINTEXT *)
    (ctx, Some (data ^ (Builder.tag ctx.config.versions)), `Sent data)
  | `MSGSTATE_PLAINTEXT -> (ctx, Some data, `Sent data)
  | `MSGSTATE_ENCRYPTED keys ->
    ( match encrypt ctx.version ctx.instances false keys data with
      | Ok (keys, out) ->
        let state = { ctx.state with message_state = `MSGSTATE_ENCRYPTED keys } in
        let out = wrap_b64string (Some out) in
        ({ ctx with state }, out, `Sent_encrypted data)
      | Error e -> (ctx, None, `Warning ("Otr error: " ^ e ^ " while trying to encrypt: " ^ data) ) )
  | `MSGSTATE_FINISHED ->
     (ctx, None, `Warning ("didn't sent message, OTR session is finished: " ^ data))

let end_otr ctx =
  match ctx.state.message_state with
  | `MSGSTATE_PLAINTEXT -> (ctx, None)
  | `MSGSTATE_ENCRYPTED keys ->
    (* Send a Data Message, encoding a message with an empty human-readable part, and TLV type 1. *)
    let data = Cstruct.to_string (Builder.tlv 1) in
    ( match encrypt ctx.version ctx.instances true keys ("\000" ^ data) with
      | Ok (_keys, out) -> (reset_session ctx, wrap_b64string (Some out))
      | Error _ -> (reset_session ctx, None) )
  | `MSGSTATE_FINISHED ->
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

let handle_input (ctx : session) = function
  | `PlainTag (versions, text) ->
    ( match handle_whitespace_tag ctx versions with
      | Ok (ctx, out, warn) ->
        (ctx, wrap_b64string out, warn @ recv text)
      | Error e ->
        (reset_session ctx,
         Some ("?OTR Error: " ^ e),
         [`Warning ("OTR Error: " ^ e)] @ recv text) )
  | `Query versions ->
    ( match commit ctx versions with
      | Ok (ctx, out) -> (ctx, wrap_b64string out, [])
      | Error e -> (reset_session ctx,
                    Some ("?OTR Error: " ^ e),
                    [`Warning ("OTR Error: " ^ e)] ) )
  | `Error message ->
    let out = handle_error ctx in
    (reset_session ctx, out,
     [`Received_error ("Received OTR Error: " ^ message)])
  | `Data bytes ->
    ( match handle_data ctx bytes with
      | Ok (ctx, out, warn) ->
        (ctx, out, warn)
      | Error e ->
        (reset_session ctx,
         Some ("?OTR Error: " ^ e),
         [ `Warning ("OTR error " ^ e)]) )
  | `String message ->
    let user = handle_cleartext ctx in
    (ctx, None, user @ recv (Some message))
  | `ParseError err ->
    (reset_session ctx,
     Some ("?OTR Error: " ^ err),
     [`Warning (err ^ " while processing OTR message")])
  | `Fragment_v2 _ | `Fragment_v3 _ ->
    (reset_session ctx,
     Some ("?OTR Error: unexpected recursive fragment"),
     [`Warning "ignoring unexpected recursive fragment"])

let handle_fragments (ctx : session) = function
  | `Fragment_v2 (kn, piece) ->
    if ctx.version = `V2 then
      return (handle_fragment ctx kn piece)
    else
      fail ("?OTR Error: wrong version in fragment")
  | `Fragment_v3 (instances, kn, piece) ->
    if ctx.version = `V3 then
      return (handle_fragment_v3 ctx instances kn piece)
    else
      fail ("?OTR Error: wrong version in fragment")

(* session -> string -> (session * to_send * ret) *)
let handle (ctx : session) bytes =
  match Parser.classify_input bytes with
  | `Fragment_v2 _ | `Fragment_v3 _ as f ->
    ( match handle_fragments ctx f with
      | Ok (ctx, None)   -> (ctx, None, [])
      | Ok (ctx, Some x) -> handle_input ctx (Parser.classify_input x)
      | Error txt -> (ctx,
                      Some ("?OTR Error: " ^ txt),
                      [`Warning ("Error: " ^ txt)]) )
    | x -> handle_input (rst_frag ctx) x
