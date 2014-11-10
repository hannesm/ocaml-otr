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

let handle_encrypted_data ctx keys bytes =
  match Parser.parse_data bytes with
  | Parser.Ok (version, instances, flags, s_keyid, r_keyid, dh_y, ctr', encdata, mac, reveal) ->
    select_dh keys s_keyid r_keyid >>= fun ((dh_secret, gx), gy, ctr) ->
    if version <> ctx.version then
      return (ctx, None, Some "ignoring message with invalid version", None)
    else if
      match version, ctx.instances, instances with
      | `V3, Some (mya, myb), Some (youra, yourb) when (mya = youra) && (myb = yourb) -> false
      | `V2, _, _ -> false
      | _ -> true
    then
      return (ctx, None, Some "ignoring message with invalid instances", None)
    else if ctr' <= ctr then
      return (ctx, None, Some "ignoring message with invalid counter", None)
    else
      let high = Crypto.mpi_gt gx gy in
      ( match Crypto.dh_shared dh_secret gy with
        | Some x -> return x
        | None -> fail "invalid DH public key" ) >>= fun shared ->
      let _, _, recvaes, recvmac = Crypto.data_keys shared high in
      let stop = Cstruct.len bytes - Cstruct.len reveal - 4 - 20 in
      guard (stop >= 0) "invalid data" >>= fun () ->
      let mac' = Crypto.sha1mac ~key:recvmac (Cstruct.sub bytes 0 stop) in
      let ctrcs =
        let buf = Nocrypto.Uncommon.Cs.create_with 16 0 in
        Cstruct.BE.set_uint64 buf 0 ctr' ;
        buf
      in
      let dec = Crypto.crypt ~key:recvaes ~ctr:ctrcs encdata in
      guard (Nocrypto.Uncommon.Cs.equal mac mac') "invalid mac" >|= fun () ->
      (* might contain trailing 0 *)
      let last = pred (Cstruct.len dec) in
      (* TODO: actually search for first 0x00 -- might also indicate other TLV! *)
      let txt = if Cstruct.get_uint8 dec last = 0 then
          Cstruct.to_string (Cstruct.sub dec 0 last)
        else
          Cstruct.to_string dec
      in
      let keys = update_keys keys s_keyid r_keyid dh_y ctr' in
      let state = { ctx.state with message_state = MSGSTATE_ENCRYPTED keys } in
      ({ ctx with state }, None, None, Some txt)
  | Parser.Error Parser.Underflow -> fail "Malformed OTR data message: parser reported undeflow"
  | Parser.Error (Parser.Unknown x) -> fail ("Malformed OTR data message: " ^ x)

let handle_data ctx bytes =
  match ctx.state.message_state with
  | MSGSTATE_PLAINTEXT ->
    ( match Ake.handle_auth ctx bytes with
      | Ake.Ok (ctx, out) -> return (ctx, out, None, None)
      | Ake.Error (Ake.Unknown x) ->  fail ("AKE error encountered" ^ x)
      | Ake.Error Ake.VersionMismatch ->
        Printf.printf "packet with wrong version received, ignoring\n" ;
        return (ctx, None, Some "wrong version in packet", None)
      | Ake.Error Ake.InstanceMismatch ->
        Printf.printf "packet with wrong instances received, ignoring\n" ;
        return (ctx, None, Some "wrong instances in packet", None) )
  | MSGSTATE_ENCRYPTED keys -> handle_encrypted_data ctx keys bytes
  | _ -> fail ("couldn't handle data")

let wrap_b64string = function
  | None -> None
  | Some m ->
    let encoded = Nocrypto.Base64.encode m in
    Some ("?OTR:" ^ Cstruct.to_string encoded ^ ".")

(* operations triggered by a user *)
let start_otr ctx =
  (ctx, Builder.query_message ctx.config.versions)

let encrypt version instances keys data =
  let (dh_secret, gx), gy = (keys.previous_dh, keys.gy) in
  let high = Crypto.mpi_gt gx gy in
  ( match Crypto.dh_shared dh_secret gy with
    | Some x -> return x
    | None -> fail "invalid DH public key" ) >|= fun shared ->
  let sendaes, sendmac, _, _ = Crypto.data_keys shared high in
  let our_ctr = Int64.succ keys.our_ctr in
  let ctr =
    let buf = Nocrypto.Uncommon.Cs.create_with 16 0 in
    Cstruct.BE.set_uint64 buf 0 our_ctr ;
    buf
  in
  let enc = Crypto.crypt ~key:sendaes ~ctr (Cstruct.of_string data) in
  let our_id = Int32.pred keys.our_keyid in
  let data = Builder.data version instances our_id keys.their_keyid (snd keys.dh) our_ctr enc in
  let mac = Crypto.sha1mac ~key:sendmac data in
  let reveal = Builder.encode_data (Cstruct.create 0) in
  let out = Nocrypto.Uncommon.Cs.concat [ data ; mac ; reveal] in
  ({ keys with our_ctr },
   wrap_b64string (Some out))

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
      | Ok (_keys, out) -> ({ ctx with state }, out, None)
      | Error e -> ({ ctx with state }, None, None) )
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
      | Ok (ctx, out, warn, enc) -> (ctx, wrap_b64string out, warn, enc, message)
      | Error e -> (reset_session ctx, Some ("?OTR Error: " ^ e), Some e, None, None) )
  | `String message ->
    let ctx, warn = handle_cleartext ctx in
    (ctx, None, warn, None, Some message)
  | `ParseError (err, message) ->
    let ctx, warn = handle_cleartext ctx in
    (reset_session ctx, Some ("?OTR Error: " ^ err), warn, None, Some message)
