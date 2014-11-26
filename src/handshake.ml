open State

let policy ctx p = List.mem p ctx.config.policies

(* Monadic control-flow core. *)
type error = string
include Control.Or_error_make (struct type err = error end)

let handle_cleartext ctx =
  let warn = match ctx.state.message_state with
    | MSGSTATE_PLAINTEXT when policy ctx `REQUIRE_ENCRYPTION ->
      Some "unencrypted data"
    | MSGSTATE_PLAINTEXT -> None
    | MSGSTATE_ENCRYPTED _ | MSGSTATE_FINISHED -> Some "unencrypted data"
  in
  (ctx, warn)

let commit ctx their_versions warn =
  match Ake.dh_commit ctx their_versions with
  | Ake.Ok (ctx, out) -> return (ctx, Some out, warn)
  | Ake.Error (Ake.Unknown e) -> fail e
  | Ake.Error Ake.VersionMismatch -> fail "couldn't agree on a version"
  | Ake.Error Ake.InstanceMismatch -> fail "wrong instances"

let handle_whitespace_tag ctx their_versions =
  let warn = match ctx.state.message_state with
    | MSGSTATE_PLAINTEXT when policy ctx `REQUIRE_ENCRYPTION ->
      Some "unencrypted data"
    | MSGSTATE_PLAINTEXT -> None
    | MSGSTATE_ENCRYPTED _ | MSGSTATE_FINISHED -> Some "unencrypted data"
  in
  if policy ctx `WHITESPACE_START_AKE then
    commit ctx their_versions warn
  else
    return (ctx, None, warn)

let handle_query ctx their_versions =
  commit ctx their_versions None

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

let merge a b =
  match a, b with
  | None, None -> None
  | None, Some a -> Some a
  | Some a, None -> Some a
  | Some a, Some b -> Some (a ^ b)

let handle_tlv state typ buf =
  let open Packet in
  match typ with
  | Some PADDING -> (state, None, None)
  | Some DISCONNECTED -> ({ state with message_state = MSGSTATE_FINISHED },
                          None,
                          Some "OTR connection lost")
  | Some _ -> (state, None, Some "not handling this tlv")
  | None -> (state, None, Some "unknown tlv type")

let rec filter_map ?(f = fun x -> x) = function
  | []    -> []
  | x::xs ->
      match f x with
      | None    ->       filter_map ~f xs
      | Some x' -> x' :: filter_map ~f xs

let handle_tlvs state = function
  | None -> return (state, None, None)
  | Some data ->
    let rec process_data state data out warn =
      match Cstruct.len data with
      | 0 -> (state, out, warn)
      | _ -> match Parser.parse_tlv data with
        | Parser.Ok (typ, buf, rest) ->
          let state, out', warn' = handle_tlv state typ buf in
          process_data state rest (out' :: out) (merge warn warn')
        | Parser.Error _ -> (state, out, Some "ignoring malformed TLV")
    in
    let state, out, warn = process_data state (Cstruct.of_string data) [] None in
    let out = match filter_map out with
      | [] -> None
      | xs -> Some (Cstruct.to_string (Nocrypto.Uncommon.Cs.concat xs))
    in
    return (state, out, warn)

let decrypt keys version instances bytes =
  match Parser.parse_data bytes with
  | Parser.Ok (version', instances', flags, s_keyid, r_keyid, dh_y, ctr', encdata, mac, reveal) ->
    select_dh keys s_keyid r_keyid >>= fun ((dh_secret, gx), gy, ctr) ->
    if version <> version' then
      return (None, None, Some "ignoring message with invalid version", keys)
    else if
      match version, instances, instances' with
      | `V3, Some (mya, myb), Some (youra, yourb) when (mya = youra) && (myb = yourb) -> false
      | `V2, _, _ -> false
      | _ -> true
    then
      return (None, None, Some "ignoring message with invalid instances", keys)
    else if ctr' <= ctr then
      return (None, None, Some "ignoring message with invalid counter", keys)
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
      let maybe_s s = if String.length s = 0 then None else Some s in
      let txt = maybe_s txt
      and data = maybe_s data
      in
      let keys = update_keys keys s_keyid r_keyid dh_y ctr' in
      (txt, data, None, keys)
  | Parser.Error Parser.Underflow -> fail "Malformed OTR data message: parser reported undeflow"
  | Parser.Error (Parser.Unknown x) -> fail ("Malformed OTR data message: " ^ x)

let encrypt version instances keys ?(reveal = Cstruct.create 0) data =
  let (dh_secret, gx), gy = (keys.previous_dh, keys.gy) in
  let high = Crypto.mpi_gt gx gy in
  ( match Crypto.dh_shared dh_secret gy with
    | Some x -> return x
    | None -> fail "invalid DH public key" ) >|= fun shared ->
  let sendaes, sendmac, _, _ = Crypto.data_keys shared high in
  let our_ctr = Int64.succ keys.our_ctr in
  let enc = Crypto.crypt ~key:sendaes ~ctr:our_ctr (Cstruct.of_string data) in
  let our_id = Int32.pred keys.our_keyid in
  let data = Builder.data version instances our_id keys.their_keyid (snd keys.dh) our_ctr enc in
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
  | MSGSTATE_PLAINTEXT ->
    ( match Ake.handle_auth ctx bytes with
      | Ake.Ok (ctx, out, warn) -> return (ctx, wrap_b64string out, warn, None)
      | Ake.Error Ake.Unexpected -> return (ctx,
                                            Some "?OTR Error: ignoring unreadable message",
                                            Some "received encrypted data while in plaintext mode",
                                            None)
      | Ake.Error (Ake.Unknown x) ->  fail ("AKE error encountered: " ^ x)
      | Ake.Error Ake.VersionMismatch ->
        return (ctx, None, Some "wrong version in packet", None)
      | Ake.Error Ake.InstanceMismatch ->
        return (ctx, None, Some "wrong instances in packet", None) )
  | MSGSTATE_ENCRYPTED keys ->
    decrypt keys ctx.version ctx.instances bytes >>= fun (msg, data, warn, keys) ->
    let state = { ctx.state with message_state = MSGSTATE_ENCRYPTED keys } in
    handle_tlvs state data >>= fun (state, out, warn) ->
    ( match out with
      | None -> return (state, None)
      | Some x -> match encrypt ctx.version ctx.instances keys x with
        | Ok (keys, out) -> return ({ state with message_state = MSGSTATE_ENCRYPTED keys },
                                    wrap_b64string (Some out))
        | Error e -> fail e ) >|= fun (state, out) ->
    let ctx = { ctx with state } in
    (ctx, out, warn, msg)
  | MSGSTATE_FINISHED ->
    return (ctx, None, Some "received data while in finished state, ignoring", Some (Cstruct.to_string bytes))

(* operations triggered by a user *)
let start_otr ctx =
  (ctx, Builder.query_message ctx.config.versions)

let send_otr ctx data =
  match ctx.state.message_state with
  | MSGSTATE_PLAINTEXT when policy ctx `REQUIRE_ENCRYPTION ->
    (ctx,
     Some (Builder.query_message ctx.config.versions),
     Some "didn't send message, there was no encrypted connection")
  | MSGSTATE_PLAINTEXT when policy ctx `SEND_WHITESPACE_TAG ->
    (* XXX: and you have not received a plaintext message from this correspondent since last entering MSGSTATE_PLAINTEXT *)
    (ctx, Some (Builder.tag ctx.config.versions ^ data), None)
  | MSGSTATE_PLAINTEXT -> (ctx, Some data, None)
  | MSGSTATE_ENCRYPTED keys ->
    ( match encrypt ctx.version ctx.instances keys data with
      | Ok (keys, out) ->
        let state = { ctx.state with message_state = MSGSTATE_ENCRYPTED keys } in
        let out = wrap_b64string (Some out) in
        ({ ctx with state }, out, None)
      | Error e -> (ctx, None, Some ("otr error: " ^ e)) )
  | MSGSTATE_FINISHED ->
     (ctx, None, Some "message couldn't be sent since OTR session is finished.")

let end_otr ctx =
  let state = { ctx.state with message_state = MSGSTATE_PLAINTEXT } in
  match ctx.state.message_state with
  | MSGSTATE_PLAINTEXT -> (ctx, None, None)
  | MSGSTATE_ENCRYPTED keys ->
    (* Send a Data Message, encoding a message with an empty human-readable part, and TLV type 1. *)
    let data = Cstruct.to_string (Builder.tlv 1) in
    ( match encrypt ctx.version ctx.instances keys ("\000" ^ data) with
      | Ok (_keys, out) -> ({ ctx with state }, wrap_b64string (Some out), None)
      | Error e -> (reset_session ctx, None, None) )
  | MSGSTATE_FINISHED ->
     ({ ctx with state }, None, None)

(* session -> string -> (session * to_send * user_msg * data_received * cleartext_received) *)
let handle (ctx : session) bytes =
  match Parser.classify_input bytes with
  | `PlainTag (versions, text) ->
    ( match handle_whitespace_tag ctx versions with
      | Ok (ctx, out, warn) -> (ctx, wrap_b64string out, warn, None, text)
      | Error e -> (reset_session ctx, Some ("?OTR Error: " ^ e), Some e, None, None) )
  | `Query (versions, text) ->
    ( match handle_query ctx versions with
      | Ok (ctx, out, warn) -> (ctx, wrap_b64string out, warn, None, text)
      | Error e -> (reset_session ctx, Some ("?OTR Error: " ^ e), Some e, None, None) )
  | `Error (message, text) ->
    let out = handle_error ctx in
    (reset_session ctx, out, Some ("Error: " ^ message), None, text)
  | `Data (bytes, message) ->
    ( match handle_data ctx bytes with
      | Ok (ctx, out, warn, enc) -> (ctx, out, warn, enc, message)
      | Error e -> (reset_session ctx, Some ("?OTR Error: " ^ e), Some e, None, None) )
  | `String message ->
    let ctx, warn = handle_cleartext ctx in
    (ctx, None, warn, None, Some message)
  | `ParseError (err, message) ->
    let ctx, warn = handle_cleartext ctx in
    (reset_session ctx, Some ("?OTR Error: " ^ err), warn, None, Some message)
