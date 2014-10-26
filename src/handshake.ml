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
    let gxmpi = Crypto.crypt ~key:r ~ctr:Crypto.ctr0 gx in
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
  let keyid = Builder.encode_int keyidb in
  let pub = Crypto.OtrDsa.priv_to_wire ctx.config.dsa in
  let mb = Crypto.mac ~key:m1 [ gx ; gy ; pub ; keyid ] in
  let signature = Crypto.OtrDsa.signature ~key:ctx.config.dsa mb in
  let xb = pub <+> keyid <+> signature in
  let enc_sig = Crypto.crypt ~key:c ~ctr:Crypto.ctr0 xb in
  let mac = Crypto.mac160 ~key:m2 [ enc_sig ] in
  let reveal_sig = Builder.reveal_signature ctx.version ctx.instances r enc_sig mac in
  let dh_params = { secret ; gx ; gy } in
  let state = { ctx.state with auth_state = AUTHSTATE_AWAITING_SIG (reveal_sig, keys, dh_params) } in
  ({ ctx with state }, reveal_sig)

let check_reveal_send_sig ctx { secret ; gy } dh_commit buf =
  let (r, enc_data, mac) = Parser.parse_reveal buf in
  let gxenc, dh_commit = Parser.decode_data dh_commit in
  let hgx, dh_commit = Parser.decode_data dh_commit in
  assert (Cstruct.len dh_commit = 0) ;
  let gx = Crypto.crypt ~key:r ~ctr:Crypto.ctr0 gxenc in
  let hgx' = Crypto.hash gx in
  assert (Nocrypto.Uncommon.Cs.equal hgx hgx') ;
  let shared_secret = Crypto.dh_shared secret gx in
  let { c ; c' ; m1 ; m2 ; m1' ; m2' } = Crypto.derive_keys shared_secret in
  let mac' = Crypto.mac160 ~key:m2 [ enc_data ] in
  assert (Nocrypto.Uncommon.Cs.equal mac mac') ;
  let xb = Crypto.crypt ~key:c ~ctr:Crypto.ctr0 enc_data in
  (* split into pubb, keyidb, sigb *)
  let (p,q,gg,y), keyidb, sigb = Parser.parse_signature_data xb in
  let pubb = Crypto.OtrDsa.pub ~p ~q ~gg ~y in
  let pubb_wire = Crypto.OtrDsa.to_wire pubb in
  let mb = Crypto.mac ~key:m1 [ gx ; gy ; pubb_wire ; Builder.encode_int keyidb ] in
  assert (Crypto.OtrDsa.verify ~key:pubb sigb mb) ;
  (* pick keyida *)
  let keyida = 1l in
  let puba = Crypto.OtrDsa.priv_to_wire ctx.config.dsa in
  let ma = Crypto.mac ~key:m1' [ gy ; gx ; puba ; Builder.encode_int keyida ] in
  let siga = Crypto.OtrDsa.signature ~key:ctx.config.dsa ma in
  let xa = puba <+> (Builder.encode_int keyida) <+> siga in
  let enc = Crypto.crypt ~key:c' ~ctr:Crypto.ctr0 xa in
  let m = Crypto.mac160 ~key:m2' [ enc ] in
  let state = { auth_state = AUTHSTATE_NONE ; message_state = MSGSTATE_ENCRYPTED } in
  ({ ctx with state }, Builder.signature ctx.version ctx.instances enc m)

let check_sig ctx { c' ; m1' ; m2' } { gx ; gy } signature =
  (* decrypt signature, verify it and macs *)
  let enc_data, mac = Cstruct.(split signature (len signature - 20)) in
  let mymac = Crypto.mac160 ~key:m2' [ enc_data ] in
  assert (Nocrypto.Uncommon.Cs.equal mac mymac) ;
  let dec = Crypto.crypt ~key:c' ~ctr:Crypto.ctr0 enc_data in
  (* split into puba keyida siga(Ma) *)
  let (p, q, gg, y), keyida, siga = Parser.parse_signature_data dec in
  let keyid = Builder.encode_int keyida in
  let puba = Crypto.OtrDsa.pub ~p ~q ~gg ~y in
  let ma = Crypto.mac ~key:m1' [ gy ; gx ; (Crypto.OtrDsa.to_wire puba) ; keyid ] in
  assert (Crypto.OtrDsa.verify ~key:puba siga ma) ;
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
  (ctx, [Builder.query_message ctx.config.versions])

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

let maybe_concat prefix postfix =
  match prefix, postfix with
  | None, None -> None
  | Some pre, Some post -> Some ("before: " ^ pre ^ " after: " ^ post)
  | Some pre, None -> Some pre
  | None, Some post -> Some post

(* TODO: fragmentation (using ',' as final character) *)
let classify bytes =
  let otr_mark = Str.regexp_string "?OTR:"
  and otr_err_mark = Str.regexp_string "?OTR Error:"
  and otr_query_mark = Str.regexp_string "?OTR"
  and tag_prefix = Str.regexp_string " \t  \t\t\t\t \t \t \t  "
  in

  if Str.string_match otr_mark bytes 0 then
    let start = 5 + Str.search_forward otr_mark bytes 0 in
    let stop = String.index_from bytes start '.' in
    let b64data = String.sub bytes start (stop - start) in
    let leftover =
      let prefix = if start > 5 then Some (String.sub bytes 0 (start - 5)) else None in
      let len = String.length bytes in
      let postfix = if stop + 1 < len then Some (String.sub bytes stop (len - stop)) else None in
      maybe_concat prefix postfix
    in
    `Data (Nocrypto.Base64.decode (Cstruct.of_string b64data), leftover)
  else if Str.string_match otr_err_mark bytes 0 then
    `Error bytes
  else if Str.string_match otr_query_mark bytes 0 then
    let start = 4 + Str.search_forward otr_query_mark bytes 0 in
    let data = String.sub bytes start (String.length bytes - start) in
    let versions, post = Parser.parse_query data in
    let prefix = if start > 4 then Some (String.sub bytes 0 (start - 4)) else None in
    let text = maybe_concat prefix post in
    `Query (versions, text)
  else if Str.string_match tag_prefix bytes 0 then
    let start = 16 + Str.search_forward tag_prefix bytes 0 in
    let prefix = if start > 16 then Some (String.sub bytes 0 (start - 16)) else None in
    let tag_data = String.sub bytes start (String.length bytes - start) in
    if String.length tag_data mod 8 == 0 then
      let rec find_versions bytes acc =
        match String.length bytes with
        | 0 -> List.rev acc
        | _ ->
          let rest = String.sub bytes 8 (String.length bytes - 8) in
          match String.sub bytes 0 8 with
          | "  \t\t  \t " -> find_versions rest (`V2 :: acc)
          | "  \t\t  \t\t" -> find_versions rest (`V3 :: acc)
          | _ -> find_versions rest acc
      in
      let vs = find_versions tag_data [] in
      `PlainTag (vs, prefix)
    else
      `String bytes
  else
    `String bytes

let wrap_b64string = function
  | [] -> None
  | msgs ->
    let encode = Nocrypto.(Base64.encode (Uncommon.Cs.concat msgs)) in
    Some ("?OTR:" ^ Cstruct.to_string encode ^ ".")

(* session -> string -> (session * to_send * user_msg * data_received * cleartext_received) *)
let handle (ctx : session) bytes =
  match classify bytes with
  | `PlainTag (versions, text) ->
    let ctx, out, warn = handle_whitespace_tag ctx versions in
    (ctx, wrap_b64string out, warn, None, text)
  | `Query (versions, text) ->
    let ctx, out = handle_query ctx versions in
    (ctx, wrap_b64string out, None, None, text)
  | `Error message ->
    let out = handle_error ctx in
    (ctx, out, None, None, Some message)
  | `Data (bytes, message) ->
    let ctx, out, enc = handle_data ctx bytes in
    (ctx, wrap_b64string out, None, enc, message)
  | `String message ->
    let ctx, warn = handle_cleartext ctx in
    (ctx, None, warn, None, Some message)

