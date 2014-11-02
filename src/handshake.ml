open State

open Handshake_utils

let handle_cleartext ctx =
  let warn = match ctx.state.message_state with
    | MSGSTATE_PLAINTEXT when policy ctx `REQUIRE_ENCRYPTION ->
      Some "unencrypted data"
    | MSGSTATE_PLAINTEXT -> None
    | MSGSTATE_ENCRYPTED _ | MSGSTATE_FINISHED -> Some "unencrypted data"
  in
  (ctx, warn)

let handle_whitespace_tag ctx their_versions =
  let warn = match ctx.state.message_state with
    | MSGSTATE_PLAINTEXT when policy ctx `REQUIRE_ENCRYPTION ->
      Some "unencrypted data"
    | MSGSTATE_PLAINTEXT -> None
    | MSGSTATE_ENCRYPTED _ | MSGSTATE_FINISHED -> Some "unencrypted data"
  in
  let ctx, data_out =
    if policy ctx `WHITESPACE_START_AKE then
      Handshake_ake.dh_commit ctx their_versions
    else
      (ctx, [])
  in
  (ctx, data_out, warn)

let handle_query ctx their_versions =
  Handshake_ake.dh_commit ctx their_versions

let handle_error ctx =
  if policy ctx `ERROR_START_AKE then
    Some (Builder.query_message ctx.config.versions)
  else
    None

let select_dh keys send recv =

  let y =
    if keys.their_keyid = send then
      ( Printf.printf "using current y\n" ;
        keys.y )
    else
      ( assert (keys.their_keyid = Int32.succ send) ;
        assert (Cstruct.len keys.previous_y > 0) ;
        Printf.printf "using previous y\n" ;
        keys.previous_y )
  in
  let dh =
    if keys.our_keyid = recv then
      ( Printf.printf "using current dh\n" ;
        keys.dh )
    else
      ( assert (keys.our_keyid = Int32.succ recv) ;
        Printf.printf "using previous dh\n" ;
        keys.previous_dh )
  in
  (dh, y)

let dh_gen_secret () =
  let secret, gx = Crypto.gen_dh_secret () in
  { secret ; gx ; gy = Cstruct.create 0 }

let update_keys keys s_keyid r_keyid dh_y ctr =
  let keys = { keys with their_ctr = ctr } in
  let keys =
    if keys.their_keyid = s_keyid then
      { keys with their_keyid = Int32.succ s_keyid ;
                  previous_y = keys.y ;
                  y = dh_y ;
                  their_ctr = 0L
      }
    else
      (assert (keys.their_keyid = Int32.succ s_keyid) ;
       keys)
  in
  if keys.our_keyid = r_keyid then
    { keys with our_keyid = Int32.succ r_keyid ;
                previous_dh = keys.dh ;
                dh = dh_gen_secret () ;
                our_ctr = 0L ;
    }
  else
    (assert (keys.our_keyid = Int32.succ r_keyid) ;
     keys)

let handle_encrypted_data ctx keys bytes =
  match Parser.parse_check_data ctx.version ctx.instances bytes with
  | Parser.Ok (flags, s_keyid, r_keyid, dh_y, ctr, encdata, mac, reveal) ->
    assert (ctr > keys.their_ctr) ;
    Printf.printf "reveal %d\n" (Cstruct.len reveal) ; Cstruct.hexdump reveal ;
    let {secret; gx}, gy = select_dh keys s_keyid r_keyid in
    let high = Crypto.mpi_g gx gy in
    let shared = Crypto.dh_shared secret gy in
    let sendaes, sendmac, recvaes, recvmac = Crypto.data_keys shared high in
    let stop = Cstruct.len bytes - Cstruct.len reveal - 4 - 20 in
    let mac' = Crypto.sha1mac ~key:recvmac (Cstruct.sub bytes 0 stop) in
    let ctrcs =
      let buf = Nocrypto.Uncommon.Cs.create_with 16 0 in
      Cstruct.BE.set_uint64 buf 0 ctr ;
      buf
    in
    let dec = Crypto.crypt ~key:recvaes ~ctr:ctrcs encdata in
    assert (Nocrypto.Uncommon.Cs.equal mac mac') ;
    (* might contain trailing 0 *)
    let last = pred (Cstruct.len dec) in
    let txt = if Cstruct.get_uint8 dec last = 0 then Cstruct.to_string (Cstruct.sub dec 0 last) else Cstruct.to_string dec in
    (* retain some information: dh_y, ctr, data_keys *)
    let keys = update_keys keys s_keyid r_keyid dh_y ctr in
    let state = { ctx.state with message_state = MSGSTATE_ENCRYPTED keys } in
    ({ ctx with state }, [], None, Some txt)
  | Parser.Error _ ->
    (ctx, [], Some "malformed data message received", None)

let handle_data ctx bytes =
  match ctx.state.message_state with
  | MSGSTATE_PLAINTEXT ->
    let ctx, out, enc = Handshake_ake.handle_auth ctx bytes in
    (ctx, out, None, enc)
  | MSGSTATE_ENCRYPTED keys -> handle_encrypted_data ctx keys bytes
  | _ -> (ctx, [], Some ("couldn't handle data"), None)

let wrap_b64string = function
  | [] -> None
  | msgs ->
    let encode = Nocrypto.(Base64.encode (Uncommon.Cs.concat msgs)) in
    Some ("?OTR:" ^ Cstruct.to_string encode ^ ".")

(* operations triggered by a user *)
let start_otr ctx =
  (ctx, Builder.query_message ctx.config.versions)

let send_otr ctx data =
  match ctx.state.message_state with
  | MSGSTATE_PLAINTEXT when policy ctx `REQUIRE_ENCRYPTION ->
    (ctx,
     [Builder.query_message ctx.config.versions],
     Some "didn't send message, there was no encrypted connection")
  | MSGSTATE_PLAINTEXT when policy ctx `SEND_WHITESPACE_TAG ->
    (* XXX: and you have not received a plaintext message from this correspondent since last entering MSGSTATE_PLAINTEXT *)
    (ctx, [Builder.tag ctx.config.versions ^ data], None)
  | MSGSTATE_PLAINTEXT -> (ctx, [data], None)
  | MSGSTATE_ENCRYPTED keys ->
    let { secret; gx }, gy = (keys.previous_dh, keys.y) in
    let high = Crypto.mpi_g gx gy in
    let shared = Crypto.dh_shared secret gy in
    let sendaes, sendmac, recvaes, recvmac = Crypto.data_keys shared high in
    let ctr = 1L in
    let ctrv = let b = Cstruct.create 8 in Cstruct.BE.set_uint64 b 0 ctr ; b in
    let ctrf = Nocrypto.Uncommon.Cs.(concat [ ctrv ; create_with 8 0 ]) in
    let enc = Crypto.crypt ~key:sendaes ~ctr:ctrf (Cstruct.of_string data) in
    let data = Builder.data ctx.version ctx.instances (Int32.pred keys.our_keyid) keys.their_keyid keys.dh.gx ctrv enc in
    let mac = Crypto.sha1mac ~key:sendmac data in
    let out = wrap_b64string [ data ; mac ; Builder.encode_data (Cstruct.create 0)] in
    let out = match out with | Some x -> [x] | None -> [] in
    (ctx, out, None)
  | MSGSTATE_FINISHED ->
     (ctx, [], Some "message couldn't be sent since OTR session is finished.")

let end_otr ctx =
  let state = { ctx.state with message_state = MSGSTATE_PLAINTEXT } in
  match ctx.state.message_state with
  | MSGSTATE_PLAINTEXT -> (ctx, [], None)
  | MSGSTATE_ENCRYPTED _ ->
     (* Send a Data Message, encoding a message with an empty human-readable part, and TLV type 1. *)
     (* let out = data TLV1 in *)
     ({ ctx with state }, [], None)
  | MSGSTATE_FINISHED ->
     ({ ctx with state }, [], None)

(* session -> string -> (session * to_send * user_msg * data_received * cleartext_received) *)
let handle (ctx : session) bytes =
  match Parser.classify_input bytes with
  | `PlainTag (versions, text) ->
    Printf.printf "received plaintag!\n" ;
    let ctx, out, warn = handle_whitespace_tag ctx versions in
    (ctx, wrap_b64string out, warn, None, text)
  | `Query (versions, text) ->
    Printf.printf "received query!\n" ;
    let ctx, out = handle_query ctx versions in
    (ctx, wrap_b64string out, None, None, text)
  | `Error (message, text) ->
    Printf.printf "received error!\n" ;
    let out = handle_error ctx in
    (ctx, out, Some ("Error: " ^ message), None, text)
  | `Data (bytes, message) ->
    Printf.printf "received data:" ; Cstruct.hexdump bytes ;
    let ctx, out, warn, enc = handle_data ctx bytes in
    (ctx, wrap_b64string out, warn, enc, message)
  | `String message ->
    Printf.printf "received plain string! %s\n" message ;
    let ctx, warn = handle_cleartext ctx in
    (ctx, None, warn, None, Some message)
  | `ParseError (warn, message) ->
    Printf.printf "parse error! %s (input %s)\n" warn message ;
    let ctx, warn = handle_cleartext ctx in
    (ctx, None, warn, None, Some message)
