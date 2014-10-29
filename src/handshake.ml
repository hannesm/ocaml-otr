open State

let handle_cleartext ctx =
  let warn = match ctx.state.message_state with
    | MSGSTATE_PLAINTEXT ->
      if List.mem `REQUIRE_ENCRYPTION ctx.config.policies then
         Some "unencrypted data"
       else
         None
    | MSGSTATE_ENCRYPTED | MSGSTATE_FINISHED ->
      Some "unencrypted data"
  in
  (ctx, warn)

let select_version ours theirs =
  let test v = List.mem v theirs in
  match List.filter test ours with
  | v::_ -> Some v
  | [] -> None

let instances = function
  | `V2 -> None
  | `V3 -> Some (Crypto.instance_tag (), 0l)

let maybe_commit ctx their_versions =
  match select_version ctx.config.versions their_versions with
  | None -> (* send error message no matching version! *) assert false
  | Some version ->
    let secret, gx = Crypto.gen_dh_secret () in
    let r = Crypto.gen_symmetric_key () in
    let gxmpi = Crypto.crypt ~key:r ~ctr:(Crypto.ctr0 ()) gx in
    let h = Crypto.hash gx in
    let instances = instances version in
    let dh_commit = Builder.dh_commit version instances gxmpi h in
    let dh_params = { secret ; gx ; gy = Cstruct.create 0 } in
    let state = {
      ctx.state with auth_state = AUTHSTATE_AWAITING_DHKEY (dh_commit, h, dh_params, r)
    } in
    ({ ctx with version ; instances ; state }, [dh_commit])

let handle_whitespace_tag ctx their_versions =
  let warn = match ctx.state.message_state with
    | MSGSTATE_PLAINTEXT ->
      if List.mem `REQUIRE_ENCRYPTION ctx.config.policies then
        Some "unencrypted data"
      else
        None
    | MSGSTATE_ENCRYPTED | MSGSTATE_FINISHED ->
      Some "unencrypted data"
  in
  let ctx, data_out =
    if List.mem `WHITESPACE_START_AKE ctx.config.policies then
      maybe_commit ctx their_versions
    else
      (ctx, [])
  in
  (ctx, data_out, warn)

let handle_query ctx their_versions =
  maybe_commit ctx their_versions

let handle_error ctx =
  if List.mem `ERROR_START_AKE ctx.config.policies then
    Some (Builder.query_message ctx.config.versions)
  else
    None

(* authentication handshake *)
let dh_key_await_revealsig ctx buf =
  let secret, gy = Crypto.gen_dh_secret () in
  let out = Builder.dh_key ctx.version ctx.instances gy in
  let dh_params = { secret ; gy ; gx = Cstruct.create 0 } in
  let state = { ctx.state with auth_state = AUTHSTATE_AWAITING_REVEALSIG (dh_params, buf) } in
  ({ ctx with state }, out)

let (<+>) = Nocrypto.Uncommon.Cs.append

let check_key_reveal_sig ctx { secret ; gx } r gy =
  let shared_secret = Crypto.dh_shared secret gy in
  let keys = Crypto.derive_keys shared_secret in
  let { c ; m1 ; m2 } = keys in
  let keyidb = 1l in
  let pubb = Crypto.OtrDsa.priv_to_wire ctx.config.dsa in
  let sigb =
    let mb = Crypto.mac ~key:m1 [ gx ; gy ; pubb ; Builder.encode_int keyidb ] in
    Crypto.OtrDsa.signature ~key:ctx.config.dsa mb
  in
  let enc_sig =
    let xb = pubb <+> Builder.encode_int keyidb <+> sigb in
    Crypto.crypt ~key:c ~ctr:(Crypto.ctr0 ()) xb
  in
  let mac = Crypto.mac160 ~key:m2 enc_sig in
  let reveal_sig = Builder.reveal_signature ctx.version ctx.instances r enc_sig mac in
  let dh_params = { secret ; gx ; gy } in
  let state = { ctx.state with auth_state = AUTHSTATE_AWAITING_SIG (reveal_sig, keys, dh_params) } in
  ({ ctx with state }, reveal_sig)

let check_reveal_send_sig ctx { secret ; gy } dh_commit buf =
  let r, enc_data, mac = Parser.parse_reveal buf in
  let gx =
    let gxenc, hgx = Parser.parse_dh_commit dh_commit in
    let gx = Crypto.crypt ~key:r ~ctr:(Crypto.ctr0 ()) gxenc in
    let hgx' = Crypto.hash gx in
    assert (Nocrypto.Uncommon.Cs.equal hgx hgx') ;
    gx
  in
  let shared_secret = Crypto.dh_shared secret gx in
  let { c ; c' ; m1 ; m2 ; m1' ; m2' } = Crypto.derive_keys shared_secret in
  let mac' = Crypto.mac160 ~key:m2 enc_data in
  assert (Nocrypto.Uncommon.Cs.equal mac mac') ;
  let pubb, keyidb =
    let xb = Crypto.crypt ~key:c ~ctr:(Crypto.ctr0 ()) enc_data in
    (* split into pubb, keyidb, sigb *)
    let (p,q,gg,y), keyidb, sigb = Parser.parse_signature_data xb in
    let pubb = Crypto.OtrDsa.pub ~p ~q ~gg ~y in
    let mb = Crypto.mac ~key:m1 [ gx ; gy ; Crypto.OtrDsa.to_wire pubb ; Builder.encode_int keyidb ] in
    assert (Crypto.OtrDsa.verify ~key:pubb sigb mb) ;
    (pubb, keyidb)
  in
  (* pick keyida *)
  let keyida = 1l in
  let puba = Crypto.OtrDsa.priv_to_wire ctx.config.dsa in
  let siga =
    let ma = Crypto.mac ~key:m1' [ gy ; gx ; puba ; Builder.encode_int keyida ] in
    Crypto.OtrDsa.signature ~key:ctx.config.dsa ma
  in
  let enc =
    let xa = puba <+> Builder.encode_int keyida <+> siga in
    Crypto.crypt ~key:c' ~ctr:(Crypto.ctr0 ()) xa
  in
  let m = Crypto.mac160 ~key:m2' enc in
  let state = { auth_state = AUTHSTATE_NONE ; message_state = MSGSTATE_ENCRYPTED } in
  ({ ctx with state }, Builder.signature ctx.version ctx.instances enc m)

let check_sig ctx { c' ; m1' ; m2' } { gx ; gy } signature =
  (* decrypt signature, verify it and macs *)
  let enc_data =
    let enc_data, mac = Parser.decode_data signature in
    assert (Cstruct.len mac = 20) ;
    let mymac = Crypto.mac160 ~key:m2' enc_data in
    assert (Nocrypto.Uncommon.Cs.equal mac mymac) ;
    enc_data
  in
  let puba, keyida =
    let dec = Crypto.crypt ~key:c' ~ctr:(Crypto.ctr0 ()) enc_data in
    (* split into puba keyida siga(Ma) *)
    let (p, q, gg, y), keyida, siga = Parser.parse_signature_data dec in
    let puba = Crypto.OtrDsa.pub ~p ~q ~gg ~y in
    let ma = Crypto.mac ~key:m1' [ gy ; gx ; Crypto.OtrDsa.to_wire puba ; Builder.encode_int keyida ] in
    assert (Crypto.OtrDsa.verify ~key:puba siga ma) ;
    (puba, keyida)
  in
  let state = { auth_state = AUTHSTATE_NONE ; message_state = MSGSTATE_ENCRYPTED } in
  { ctx with state }

let handle_auth ctx bytes =
  let open Packet in
  let typ, buf = Parser.parse_auth ctx bytes in
  match typ, ctx.state.auth_state with
  | DH_COMMIT, AUTHSTATE_NONE ->
    (* send dh_key,  go to AWAITING_REVEALSIG *)
    let ctx, dh_key = dh_key_await_revealsig ctx buf in
    (ctx, [dh_key], None)
  | DH_COMMIT, AUTHSTATE_AWAITING_DHKEY (dh_c, h, _, _) ->
    (* compare hash *)
    let their_hash = Cstruct.sub buf (Cstruct.len buf - 32) 32 in
    if Crypto.hash_gt h their_hash then
      (ctx, [dh_c], None)
    else
      let ctx, dh_key = dh_key_await_revealsig ctx buf in
      (ctx, [dh_key], None)
  | DH_COMMIT, AUTHSTATE_AWAITING_REVEALSIG ({ gy } as dh_params, _) ->
    (* use this dh_commit ; resend dh_key *)
    let state = { ctx.state with auth_state = AUTHSTATE_AWAITING_REVEALSIG (dh_params, buf) } in
    let out = Builder.dh_key ctx.version ctx.instances gy in
    ({ ctx with state }, [out], None)
  | DH_COMMIT, AUTHSTATE_AWAITING_SIG _ ->
    (* send dh_key, go to AWAITING_REVEALSIG *)
    let ctx, dh_key = dh_key_await_revealsig ctx buf in
    (ctx, [dh_key], None)

  | DH_KEY, AUTHSTATE_AWAITING_DHKEY (_, _, dh_params, r) ->
    (* reveal_sig -> AUTHSTATE_AWAITING_SIG *)
    let ctx, reveal = check_key_reveal_sig ctx dh_params r buf in
    (ctx, [reveal], None)

  | DH_KEY, AUTHSTATE_AWAITING_SIG (reveal_sig, _, { gy }) ->
    (* same dh_key? -> retransmit REVEAL_SIG *)
    if Nocrypto.Uncommon.Cs.equal gy buf then
      (ctx, [reveal_sig], None)
    else
      (ctx, [], None)

  | REVEAL_SIGNATURE, AUTHSTATE_AWAITING_REVEALSIG (dh_params, dh_commit)  ->
    (* do work, send signature -> AUTHSTATE_NONE, MSGSTATE_ENCRYPTED *)
    let ctx, out = check_reveal_send_sig ctx dh_params dh_commit buf in
    (ctx, [out], None)

  | SIGNATURE, AUTHSTATE_AWAITING_SIG (_, keys, dh_params) ->
    (* decrypt signature, verify sig + macs -> AUTHSTATE_NONE, MSGSTATE_ENCRYPTED *)
    let ctx = check_sig ctx keys dh_params buf in
    (ctx, [], None)

  | _ -> (ctx, [], None)


let handle_data ctx bytes =
  match ctx.state.message_state with
  | MSGSTATE_PLAINTEXT -> handle_auth ctx bytes
  | _ -> (ctx, [], None)


(* operations triggered by a user *)
let start_otr ctx =
  (ctx, Builder.query_message ctx.config.versions)

let send_otr ctx data =
  match ctx.state.message_state with
  | MSGSTATE_PLAINTEXT ->
     if List.mem `REQUIRE_ENCRYPTION ctx.config.policies then
       (ctx, [Builder.query_message ctx.config.versions], Some "didn't send message, there was no encrypted connection")
     else if List.mem `SEND_WHITESPACE_TAG ctx.config.policies then
       (* XXX: and you have not received a plaintext message from this correspondent since last entering MSGSTATE_PLAINTEXT *)
       (ctx, [Builder.tag ctx.config.versions ^ data], None)
     else
       (ctx, [data], None)
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
    Printf.printf "received string!" ; Cstruct.(hexdump (of_string message)) ;
    let ctx, warn = handle_cleartext ctx in
    (ctx, None, warn, None, Some message)

