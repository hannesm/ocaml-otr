open State

open Handshake_utils

let handle_cleartext ctx =
  let warn = match ctx.state.message_state with
    | MSGSTATE_PLAINTEXT when policy ctx `REQUIRE_ENCRYPTION ->
      Some "unencrypted data"
    | MSGSTATE_ENCRYPTED | MSGSTATE_FINISHED -> Some "unencrypted data"
    | MSGSTATE_PLAINTEXT -> None
  in
  (ctx, warn)

let handle_whitespace_tag ctx their_versions =
  let warn = match ctx.state.message_state with
    | MSGSTATE_PLAINTEXT when policy ctx `REQUIRE_ENCRYPTION ->
      Some "unencrypted data"
    | MSGSTATE_ENCRYPTED | MSGSTATE_FINISHED -> Some "unencrypted data"
    | MSGSTATE_PLAINTEXT -> None
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

let handle_data ctx bytes =
  match ctx.state.message_state with
  | MSGSTATE_PLAINTEXT -> Handshake_ake.handle_auth ctx bytes
  | _ -> (ctx, [], None)

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
  | MSGSTATE_ENCRYPTED ->
(*     let datum = Crypto.encrypt data in
     (* XXX: Store the plaintext message for possible retransmission. *)
     (s, [data datum], None) *)
     (ctx, [], None)
  | MSGSTATE_FINISHED ->
     (ctx, [], Some "message couldn't be sent since OTR session is finished.")

let end_otr ctx =
  let state = { ctx.state with message_state = MSGSTATE_PLAINTEXT } in
  match ctx.state.message_state with
  | MSGSTATE_PLAINTEXT -> (ctx, [], None)
  | MSGSTATE_ENCRYPTED ->
     (* Send a Data Message, encoding a message with an empty human-readable part, and TLV type 1. *)
     (* let out = data TLV1 in *)
     ({ ctx with state }, [], None)
  | MSGSTATE_FINISHED ->
     ({ ctx with state }, [], None)

let wrap_b64string = function
  | [] -> None
  | msgs ->
    let encode = Nocrypto.(Base64.encode (Uncommon.Cs.concat msgs)) in
    Some ("?OTR:" ^ Cstruct.to_string encode ^ ".")

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
    let ctx, out, enc = handle_data ctx bytes in
    (ctx, wrap_b64string out, None, enc, message)
  | `String message ->
    Printf.printf "received plain string! %s\n" message ;
    let ctx, warn = handle_cleartext ctx in
    (ctx, None, warn, None, Some message)
  | `ParseError (warn, message) ->
    Printf.printf "parse error! %s (input %s)\n" warn message ;
    let ctx, warn = handle_cleartext ctx in
    (ctx, None, warn, None, Some message)
