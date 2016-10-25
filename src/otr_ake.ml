open Result

open Otr_state

(* Monadic control-flow core. *)
type error =
  | Unknown of string
  | Unexpected of bool
  | VersionMismatch
  | InstanceMismatch

include Otr_control.Or_error_make (struct type err = error end)
type 'a result = ('a, error) Result.result

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
  | Ok x -> return x
  | Error Otr_parser.Underflow -> fail (Unknown "underflow error while parsing")
  | Error Otr_parser.LeadingZero -> fail (Unknown "leading zero of a MPI while parsing")
  | Error (Otr_parser.Unknown x) -> fail (Unknown ("error while parsing: " ^ x))

let mac_sign_encrypt hmac ckey priv gx gy keyid =
  let (<+>) = Nocrypto.Uncommon.Cs.(<+>) in
  let pub =
    let pub = Nocrypto.Dsa.pub_of_priv priv in
    Otr_crypto.OtrDsa.to_wire pub
  in
  let sigb =
    let gxmpi = Otr_builder.encode_data gx
    and gympi = Otr_builder.encode_data gy
    in
    let mb = Otr_crypto.mac ~key:hmac [ gxmpi ; gympi ; pub ; Otr_builder.encode_int keyid ] in
    Otr_crypto.OtrDsa.signature ~key:priv mb
  in
  let xb = pub <+> Otr_builder.encode_int keyid <+> sigb in
  Otr_crypto.crypt ~key:ckey ~ctr:0L xb

let mac_verify hmac signature pub gx gy keyid =
  let gxmpi = Otr_builder.encode_data gx
  and gympi = Otr_builder.encode_data gy
  in
  let mb = Otr_crypto.mac ~key:hmac [ gxmpi ; gympi ; Otr_crypto.OtrDsa.to_wire pub ; Otr_builder.encode_int keyid ] in
  guard (Otr_crypto.OtrDsa.verify ~key:pub signature mb) (Unknown "DSA verification failed")

(* authentication handshake *)
let dh_commit ctx their_versions =
  match select_version ctx.config.versions their_versions with
  | None -> fail VersionMismatch
  | Some version ->
    let dh_secret, gx = Otr_crypto.gen_dh_secret () in
    let r = Otr_crypto.gen_symmetric_key () in
    let gxmpi = Otr_builder.encode_data gx in
    let gxmpi' = Otr_crypto.crypt ~key:r ~ctr:0L gxmpi in
    let h = Otr_crypto.hash gxmpi in
    let instances = instances version in
    let dh_commit = Otr_builder.dh_commit version instances gxmpi' h in
    let auth_state = AUTHSTATE_AWAITING_DHKEY (dh_commit, h, (dh_secret, gx), r)
    and message_state = MSGSTATE_PLAINTEXT (* not entirely sure about this.. *)
    and smp_state = SMPSTATE_EXPECT1 in
    let state = { auth_state ; message_state ; smp_state } in
    return ({ ctx with version ; instances ; state }, dh_commit)

let dh_key_await_revealsig ctx buf =
  let dh_secret, gx = Otr_crypto.gen_dh_secret () in
  let out = Otr_builder.dh_key ctx.version ctx.instances gx in
  let auth_state = AUTHSTATE_AWAITING_REVEALSIG ((dh_secret, gx), buf) in
  let state = { ctx.state with auth_state } in
  ({ ctx with state }, out)

let check_key_reveal_sig ctx (dh_secret, gx) r gy =
  safe_parse Otr_parser.parse_gy gy >>= fun gy ->
  ( match Otr_crypto.dh_shared dh_secret gy with
    | Some s -> return s
    | None -> fail (Unknown "invalid DH public key")  ) >|= fun shared_secret ->
  let (ssid, c, c', m1, m2, m1', m2') = Otr_crypto.derive_keys shared_secret in
  let keyidb = 1l in
  let enc_sig = mac_sign_encrypt m1 c ctx.dsa gx gy keyidb in
  let mac = Otr_crypto.mac160 ~key:m2 enc_sig in
  let reveal_sig = Otr_builder.reveal_signature ctx.version ctx.instances r enc_sig mac in
  let auth_state = AUTHSTATE_AWAITING_SIG (reveal_sig, (ssid, c', m1', m2'), (dh_secret, gx), gy) in
  let state = { ctx.state with auth_state } in
  ({ ctx with state }, reveal_sig)

let keys previous_dh gy their_keyid =
  let dh = Otr_crypto.gen_dh_secret ()
  and previous_gy = Cstruct.create 0
  in
  { dh ; previous_dh ; our_keyid = 2l ;
    gy ; previous_gy ; their_keyid }

let format_ssid ssid high =
  let f, s = Cstruct.BE.(get_uint32 ssid 0, get_uint32 ssid 4) in
  Printf.sprintf "%s%08lx%s %s%08lx%s"
    (if high then "[" else "") f (if high then "]" else "")
    (if high then "" else "[") s (if high then "" else "]")

let check_reveal_send_sig ctx (dh_secret, gy) dh_commit buf =
  safe_parse Otr_parser.parse_reveal buf >>= fun (r, enc_data, mac) ->
  safe_parse Otr_parser.parse_dh_commit dh_commit >>= fun (gxenc, hgx) ->
  let gx = Otr_crypto.crypt ~key:r ~ctr:0L gxenc in
  let hgx' = Otr_crypto.hash gx in
  guard (Cstruct.equal hgx hgx') (Unknown "hgx does not match hgx'") >>= fun () ->
  safe_parse Otr_parser.parse_gy gx >>= fun gx ->
  ( match Otr_crypto.dh_shared dh_secret gx with
    | Some x -> return x
    | None -> fail (Unknown "invalid DH public key") ) >>= fun shared_secret ->
  let (ssid, c, c', m1, m2, m1', m2') = Otr_crypto.derive_keys shared_secret in
  let mac' = Otr_crypto.mac160 ~key:m2 enc_data in
  guard (Cstruct.equal mac mac') (Unknown "mac does not match mac'") >>= fun () ->
  let xb = Otr_crypto.crypt ~key:c ~ctr:0L enc_data in
  (* split into pubb, keyidb, sigb *)
  safe_parse Otr_parser.parse_signature_data xb >>= fun (pubb, keyidb, sigb) ->
  mac_verify m1 sigb pubb gx gy keyidb >|= fun () ->
  (* pick keyida *)
  let keyida = 1l in
  let enc_sig = mac_sign_encrypt m1' c' ctx.dsa gy gx keyida in
  let m = Otr_crypto.mac160 ~key:m2' enc_sig in
  let dh_keys = keys (dh_secret, gy) gx keyida in
  let high = false in
  let enc_data = { dh_keys ; symms = [] ; their_dsa = pubb ; ssid ; high } in
  let state = {
    auth_state = AUTHSTATE_NONE ;
    message_state = MSGSTATE_ENCRYPTED enc_data ;
    smp_state = SMPSTATE_EXPECT1 ;
  } in
  ({ ctx with state },
   Otr_builder.signature ctx.version ctx.instances enc_sig m,
   format_ssid ssid high)

let check_sig ctx (ssid, c', m1', m2') (dh_secret, gx) gy signature =
  (* decrypt signature, verify it and macs *)
  safe_parse Otr_parser.decode_data signature >>= fun (enc_data, mac) ->
  guard (Cstruct.len mac = 20) (Unknown "mac has wrong length") >>= fun () ->
  let mymac = Otr_crypto.mac160 ~key:m2' enc_data in
  guard (Cstruct.equal mac mymac) (Unknown "mac do not match") >>= fun () ->
  let dec = Otr_crypto.crypt ~key:c' ~ctr:0L enc_data in
  (* split into puba keyida siga(Ma) *)
  safe_parse Otr_parser.parse_signature_data dec >>= fun (puba, keyida, siga) ->
  mac_verify m1' siga puba gy gx keyida >|= fun () ->
  let dh_keys = keys (dh_secret, gx) gy keyida in
  let high = true in
  let enc_data = { dh_keys ; symms = [] ; their_dsa = puba ; ssid ; high } in
  let state = {
    auth_state = AUTHSTATE_NONE ;
    message_state = MSGSTATE_ENCRYPTED enc_data ;
    smp_state = SMPSTATE_EXPECT1 ;
  } in
  ({ ctx with state }, format_ssid ssid high)

let handle_commit_await_key ctx dh_c h version instances buf =
  (try return (Cstruct.sub buf (Cstruct.len buf - 32) 32)
   with _ -> fail (Unknown "underflow") ) >>= fun their_hash ->
  if Otr_crypto.mpi_gt h their_hash then
    return (ctx, Some dh_c)
  else
    guard (List.mem version ctx.config.versions) (Unknown "version") >|= fun () ->
    let ctx = { ctx with version ; instances } in
    let ctx, dh_key = dh_key_await_revealsig ctx buf in
    (ctx, Some dh_key)

let check_version_instances ctx version instances =
  begin match ctx.state.auth_state with
    | AUTHSTATE_NONE -> return { ctx with version }
    | _ ->
      guard (version = ctx.version) VersionMismatch >|= fun () ->
      ctx
  end >>= fun ctx ->
  match version, instances, ctx.instances with
    | `V3, Some (yoursend, yourrecv), Some (mysend, myrecv) when mysend = 0l ->
      guard ((yourrecv = myrecv) && (Int32.shift_right_logical yoursend 8 > 0l)) InstanceMismatch >|= fun () ->
      { ctx with instances = Some (yoursend, myrecv) }
    | `V3, Some (yoursend, yourrecv), Some (mysend, myrecv) ->
      guard ((yourrecv = myrecv) && (yoursend = mysend)) InstanceMismatch >|= fun () ->
      ctx
    | `V3, Some (yoursend, yourrecv), None ->
      if Int32.shift_right_logical yourrecv 8 = 0l then
        let myinstance = instance_tag () in
        return { ctx with instances = Some (yoursend, myinstance) }
      else (* other side has an encrypted session with us, but we do not *)
        if ctx.state.auth_state = AUTHSTATE_NONE then
          (* hack for interop with coy.im *)
          return { ctx with instances }
        else (* if this happens, shit hits the fan - let's talk V2 to have Builder:header not run into failed assertions *)
          return { ctx with version = `V2 }
    | `V2, _ , _ -> return ctx
    | _ -> fail InstanceMismatch

let handle_auth ctx bytes =
  let open Otr_packet in
  safe_parse Otr_parser.parse_header bytes >>= fun (version, typ, instances, buf) ->
  (* simultaneous open *)
  match typ, ctx.state.auth_state with
  | DH_COMMIT, AUTHSTATE_AWAITING_DHKEY (dh_c, h, _, _) ->
    handle_commit_await_key ctx dh_c h version instances buf >|= fun (ctx, out) ->
    (ctx, out, [])
  | _ ->
    check_version_instances ctx version instances >>= fun ctx ->
    match typ, ctx.state.auth_state with
    | DH_COMMIT, AUTHSTATE_NONE ->
      let ctx, dh_key = dh_key_await_revealsig ctx buf in
      return (ctx, Some dh_key, [])
    | DH_COMMIT, AUTHSTATE_AWAITING_REVEALSIG ((dh_secret, gx), _) ->
      let auth_state = AUTHSTATE_AWAITING_REVEALSIG ((dh_secret, gx), buf) in
      let state = { ctx.state with auth_state } in
      let dh_key = Otr_builder.dh_key ctx.version ctx.instances gx in
      return ({ ctx with state }, Some dh_key, [])
    | DH_COMMIT, AUTHSTATE_AWAITING_SIG _ ->
      (* send dh_key, go to AWAITING_REVEALSIG *)
      let ctx, dh_key = dh_key_await_revealsig ctx buf in
      return (ctx, Some dh_key, [])

    | DH_KEY, AUTHSTATE_AWAITING_DHKEY (_, _, dh_params, r) ->
      (* reveal_sig -> AUTHSTATE_AWAITING_SIG *)
      check_key_reveal_sig ctx dh_params r buf >|= fun (ctx, reveal) ->
      (ctx, Some reveal, [])

    | DH_KEY, AUTHSTATE_AWAITING_SIG (reveal_sig, _, _, gy) ->
      (* same dh_key? -> retransmit REVEAL_SIG *)
      safe_parse Otr_parser.parse_gy buf >|= fun gy' ->
      if Cstruct.equal gy gy' then
        (ctx, Some reveal_sig, [])
      else
        (ctx, None, [])

    | REVEAL_SIGNATURE, AUTHSTATE_AWAITING_REVEALSIG (dh_params, dh_commit)  ->
      (* do work, send signature -> AUTHSTATE_NONE, MSGSTATE_ENCRYPTED *)
      check_reveal_send_sig ctx dh_params dh_commit buf >|= fun (ctx, out, ssid) ->
      (ctx, Some out, [`Established_encrypted_session ssid])

    | SIGNATURE, AUTHSTATE_AWAITING_SIG (_, keys, dh_params, gy) ->
      (* decrypt signature, verify sig + macs -> AUTHSTATE_NONE, MSGSTATE_ENCRYPTED *)
      check_sig ctx keys dh_params gy buf >|= fun (ctx, ssid) ->
      (ctx, None, [`Established_encrypted_session ssid])

    | DATA, _ ->
      safe_parse Otr_parser.parse_data_body buf >>= fun (flag, _, _, _, _, _, _, _) ->
      fail (Unexpected flag)

    | _ -> (* ignore this message *) return (ctx, None, [`Warning "ignoring unknown message"])
