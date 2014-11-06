
open State

(* Monadic control-flow core. *)
type error = string
include Control.Or_error_make (struct type err = error end)

let instance_tag () =
  (* 32 bit random, >= 0x00000100 *)
  let tag = Cstruct.BE.get_uint32 (Nocrypto.Rng.generate 4) 0 in
  Int32.(logor tag 0x100l)

let select_version ours theirs =
  let test v = List.mem v theirs in
  match List.filter test ours with
  | v::_ -> Some v
  | [] -> None

let instances = function
  | `V2 -> None
  | `V3 -> Some (0l, instance_tag ())

let safe_parse f x =
  match f x with
  | Parser.Ok x -> return x
  | Parser.Error _ -> fail "error while parsing"

(* authentication handshake *)
let dh_commit ctx their_versions =
  match select_version ctx.config.versions their_versions with
  | None -> fail "intersection of requested and supported versions is empty"
  | Some version ->
    let dh_secret, gx = Crypto.gen_dh_secret () in
    let r = Crypto.gen_symmetric_key () in
    let gxmpi = Builder.encode_data gx in
    let gxmpi' = Crypto.crypt ~key:r ~ctr:(Crypto.ctr0 ()) gxmpi in
    let h = Crypto.hash gxmpi in
    let instances = instances version in
    let dh_commit = Builder.dh_commit version instances gxmpi' h in
    let auth_state = AUTHSTATE_AWAITING_DHKEY (dh_commit, h, (dh_secret, gx), r)
    and message_state = MSGSTATE_PLAINTEXT in (* not entirely sure about this.. *)
    let state = { auth_state ; message_state } in
    return ({ ctx with version ; instances ; state }, [dh_commit])

let dh_key_await_revealsig ctx buf =
  let dh_secret, gx = Crypto.gen_dh_secret () in
  let out = Builder.dh_key ctx.version ctx.instances gx in
  let auth_state = AUTHSTATE_AWAITING_REVEALSIG ((dh_secret, gx), buf) in
  let state = { ctx.state with auth_state } in
  ({ ctx with state }, out)

let (<+>) = Nocrypto.Uncommon.Cs.append

let check_key_reveal_sig ctx (dh_secret, gx) r gy =
  safe_parse Parser.parse_gy gy >>= fun gy ->
  ( match Crypto.dh_shared dh_secret gy with
    | Some s -> return s
    | None -> fail "invalid DH public key"  ) >|= fun shared_secret ->
  let keys = Crypto.derive_keys shared_secret in
  let { c ; m1 ; m2 } = keys in
  let keyidb = 1l in
  let pubb = Crypto.OtrDsa.priv_to_wire ctx.config.dsa in
  let sigb =
    let gxmpi = Builder.encode_data gx
    and gympi = Builder.encode_data gy
    in
    let mb = Crypto.mac ~key:m1 [ gxmpi ; gympi ; pubb ; Builder.encode_int keyidb ] in
    Crypto.OtrDsa.signature ~key:ctx.config.dsa mb
  in
  let enc_sig =
    let xb = pubb <+> Builder.encode_int keyidb <+> sigb in
    Crypto.crypt ~key:c ~ctr:(Crypto.ctr0 ()) xb
  in
  let mac = Crypto.mac160 ~key:m2 enc_sig in
  let reveal_sig = Builder.reveal_signature ctx.version ctx.instances r enc_sig mac in
  let state = { ctx.state with auth_state = AUTHSTATE_AWAITING_SIG (reveal_sig, keys, (dh_secret, gx), gy) } in
  ({ ctx with state }, reveal_sig)

let check_reveal_send_sig ctx (dh_secret, gy) dh_commit buf =
  safe_parse Parser.parse_reveal buf >>= fun (r, enc_data, mac) ->
  safe_parse Parser.parse_dh_commit dh_commit >>= fun (gxenc, hgx) ->
  let gx = Crypto.crypt ~key:r ~ctr:(Crypto.ctr0 ()) gxenc in
  let hgx' = Crypto.hash gx in
  guard (Nocrypto.Uncommon.Cs.equal hgx hgx') "hgx does not match hgx'" >>= fun () ->
  safe_parse Parser.parse_gy gx >>= fun gx ->
  ( match Crypto.dh_shared dh_secret gx with
    | Some x -> return x
    | None -> fail "invalid DH public key" ) >>= fun shared_secret ->
  let { ssid ; c ; c' ; m1 ; m2 ; m1' ; m2' } = Crypto.derive_keys shared_secret in
  let mac' = Crypto.mac160 ~key:m2 enc_data in
  guard (Nocrypto.Uncommon.Cs.equal mac mac') "mac does not match mac'" >>= fun () ->
  let xb = Crypto.crypt ~key:c ~ctr:(Crypto.ctr0 ()) enc_data in
  (* split into pubb, keyidb, sigb *)
  safe_parse Parser.parse_signature_data xb >>= fun ((p, q, gg, y), keyidb, sigb) ->
  let pubb = Nocrypto.Dsa.pub ~p ~q ~gg ~y in
  let gxmpi = Builder.encode_data gx
  and gympi = Builder.encode_data gy
  in
  let mb = Crypto.mac ~key:m1 [ gxmpi ; gympi ; Crypto.OtrDsa.to_wire pubb ; Builder.encode_int keyidb ] in
  guard (Crypto.OtrDsa.verify ~key:pubb sigb mb) "DSA verification failed" >>= fun () ->
  Printf.printf "PUBB their fingerprint" ; Cstruct.hexdump (Crypto.OtrDsa.fingerprint pubb) ;
  (* pick keyida *)
  let keyida = 1l in
  let puba = Crypto.OtrDsa.priv_to_wire ctx.config.dsa in
  let siga =
    let gxmpi = Builder.encode_data gx
    and gympi = Builder.encode_data gy
    in
    let ma = Crypto.mac ~key:m1' [ gympi ; gxmpi ; puba ; Builder.encode_int keyida ] in
    Crypto.OtrDsa.signature ~key:ctx.config.dsa ma
  in
  let enc =
    let xa = puba <+> Builder.encode_int keyida <+> siga in
    Crypto.crypt ~key:c' ~ctr:(Crypto.ctr0 ()) xa
  in
  let m = Crypto.mac160 ~key:m2' enc in
  let keys =
    let dh = Crypto.gen_dh_secret ()
    and previous_y = Cstruct.create 0
    in
    { dh ; previous_dh = (dh_secret, gy) ; our_keyid = 2l ; our_ctr = 0L ;
      y = gx ; previous_y ; their_keyid = keyida ; their_ctr = 0L }
  in
  let state = {
    auth_state = AUTHSTATE_NONE ;
    message_state = MSGSTATE_ENCRYPTED keys
  } in
  return ({ ctx with state ; their_dsa = Some pubb ; ssid },
          Builder.signature ctx.version ctx.instances enc m)

let check_sig ctx { ssid ; c' ; m1' ; m2' } (dh_secret, gx) gy signature =
  (* decrypt signature, verify it and macs *)
  safe_parse Parser.decode_data signature >>= fun (enc_data, mac) ->
  guard (Cstruct.len mac = 20) "mac has wrong length" >>= fun () ->
  let mymac = Crypto.mac160 ~key:m2' enc_data in
  guard (Nocrypto.Uncommon.Cs.equal mac mymac) "mac do not match" >>= fun () ->
  let dec = Crypto.crypt ~key:c' ~ctr:(Crypto.ctr0 ()) enc_data in
  (* split into puba keyida siga(Ma) *)
  safe_parse Parser.parse_signature_data dec >>= fun ((p,q,gg,y), keyida, siga) ->
  let puba = Nocrypto.Dsa.pub ~p ~q ~gg ~y in
  let gxmpi = Builder.encode_data gx
  and gympi = Builder.encode_data gy
  in
  let ma = Crypto.mac ~key:m1' [ gympi ; gxmpi ; Crypto.OtrDsa.to_wire puba ; Builder.encode_int keyida ] in
  guard (Crypto.OtrDsa.verify ~key:puba siga ma) "DSA verification failed" >>= fun () ->
  Printf.printf "PUBA their fingerprint" ; Cstruct.hexdump (Crypto.OtrDsa.fingerprint puba) ;
  let keys =
    let dh = Crypto.gen_dh_secret ()
    and previous_y = Cstruct.create 0
    in
    { dh ; previous_dh = (dh_secret, gx) ; our_keyid = 2l ; our_ctr = 0L ;
      y = gy ; previous_y ; their_keyid = keyida ; their_ctr = 0L }
  in
  let state = {
    auth_state = AUTHSTATE_NONE ;
    message_state = MSGSTATE_ENCRYPTED keys
  } in
  return { ctx with state ; their_dsa = Some puba ; ssid }

let handle_auth ctx bytes =
  let open Packet in
  safe_parse Parser.parse_header bytes >>= fun (version, typ, instances, buf) ->
  ( match ctx.state.auth_state with
    | AUTHSTATE_NONE -> return { ctx with version }
    | _ ->
      guard (version = ctx.version) "wrong version" >|= fun () ->
      ctx ) >>= fun (ctx) ->
  ( match version, instances, ctx.instances with
    | `V3, Some (yoursend, yourrecv), Some (mysend, myrecv) when mysend = 0l ->
      guard ((yourrecv = myrecv) && (Int32.shift_right_logical yoursend 8 > 0l)) "wrong instance tags" >|= fun () ->
      { ctx with instances = Some (yoursend, myrecv) }
    | `V3, Some (yoursend, yourrecv), Some (mysend, myrecv) ->
      guard ((yourrecv = myrecv) && (yoursend = mysend)) "wrong instance tags" >|= fun () ->
      ctx
    | `V3, Some (yoursend, yourrecv), None ->
      if Int32.shift_right_logical yourrecv 8 = 0l then
        let myinstance = instance_tag () in
        return { ctx with instances = Some (yoursend, myinstance) }
      else (* other side has an encrypted session with us, but we do not *)
        return ctx
    | `V2, _ , _ -> return ctx
    | _ -> fail "wonky instances" ) >>= fun (ctx) ->
  match typ, ctx.state.auth_state with
  | DH_COMMIT, AUTHSTATE_NONE ->
    (* send dh_key,  go to AWAITING_REVEALSIG *)
    let ctx, dh_key = dh_key_await_revealsig ctx buf in
    return (ctx, [dh_key], None)
  | DH_COMMIT, AUTHSTATE_AWAITING_DHKEY (dh_c, h, _, _) ->
    (* compare hash *)
    (* XXX: potentially throws! *)
    let their_hash = Cstruct.sub buf (Cstruct.len buf - 32) 32 in
    if Crypto.mpi_gt h their_hash then
      return (ctx, [dh_c], None)
    else
      let ctx, dh_key = dh_key_await_revealsig ctx buf in
      return (ctx, [dh_key], None)
  | DH_COMMIT, AUTHSTATE_AWAITING_REVEALSIG ((dh_secret, gx), _) ->
    (* use this dh_commit ; resend dh_key *)
    let state = { ctx.state with auth_state = AUTHSTATE_AWAITING_REVEALSIG ((dh_secret, gx), buf) } in
    let out = Builder.dh_key ctx.version ctx.instances gx in
    return ({ ctx with state }, [out], None)
  | DH_COMMIT, AUTHSTATE_AWAITING_SIG _ ->
    (* send dh_key, go to AWAITING_REVEALSIG *)
    let ctx, dh_key = dh_key_await_revealsig ctx buf in
    return (ctx, [dh_key], None)

  | DH_KEY, AUTHSTATE_AWAITING_DHKEY (_, _, dh_params, r) ->
    (* reveal_sig -> AUTHSTATE_AWAITING_SIG *)
    check_key_reveal_sig ctx dh_params r buf >|= fun (ctx, reveal) ->
    (ctx, [reveal], None)

  | DH_KEY, AUTHSTATE_AWAITING_SIG (reveal_sig, _, _, gy) ->
    (* same dh_key? -> retransmit REVEAL_SIG *)
    safe_parse Parser.parse_gy buf >|= fun gy' ->
    if Nocrypto.Uncommon.Cs.equal gy gy' then
      (ctx, [reveal_sig], None)
    else
      (ctx, [], None)

  | REVEAL_SIGNATURE, AUTHSTATE_AWAITING_REVEALSIG (dh_params, dh_commit)  ->
    (* do work, send signature -> AUTHSTATE_NONE, MSGSTATE_ENCRYPTED *)
    check_reveal_send_sig ctx dh_params dh_commit buf >|= fun (ctx, out) ->
    (ctx, [out], None)

  | SIGNATURE, AUTHSTATE_AWAITING_SIG (_, keys, dh_params, gy) ->
    (* decrypt signature, verify sig + macs -> AUTHSTATE_NONE, MSGSTATE_ENCRYPTED *)
    check_sig ctx keys dh_params gy buf >|= fun ctx ->
    (ctx, [], None)

  | DATA, _ ->
    Printf.printf "received data message while in plaintext mode, ignoring\n" ;
    return (ctx, [], None)

  | _ -> fail "what's that?"
