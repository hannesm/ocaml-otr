
open State
open Handshake_utils

(* authentication handshake *)
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
  match Parser.parse_auth bytes with
    | Parser.Ok  (version, typ, instances, buf) ->
      let ctx = match ctx.state.auth_state with
        | AUTHSTATE_NONE -> { ctx with version }
        | _ -> assert (version = ctx.version) ; ctx
      in
      Printf.printf "handling version %d\n%!" (int_of_version ctx.version) ;
      let ctx = match version, instances, ctx.instances with
        | `V3, Some (yoursend, yourrecv), Some (mysend, myrecv) when mysend = 0l ->
          assert ((yourrecv = myrecv) && (yoursend > 0x100l)) ;
          { ctx with instances = Some (yoursend, myrecv) }
        | `V3, Some (yoursend, yourrecv), Some (mysend, myrecv) ->
          assert ((yourrecv = myrecv) && (yoursend = mysend)) ;
          ctx
        | `V3, Some (yoursend, yourrecv), None ->
          assert (yourrecv < 0x100l) ;
          let myinstance = instance_tag () in
          { ctx with instances = Some (yoursend, myinstance) }
        | `V2, _ , _ -> ctx
        | _ -> Printf.printf "wonky instances\n%!" ; assert false
      in
      begin
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
      end
    | Parser.Error _ -> (ctx, [], None)

