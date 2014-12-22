
open State

(* Monadic control-flow core. *)
type error =
  | Unknown of string
  | Unexpected of bool
  | VersionMismatch
  | InstanceMismatch

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
  | Parser.Error Parser.Underflow -> fail (Unknown "underflow error while parsing")
  | Parser.Error (Parser.Unknown x) -> fail (Unknown ("error while parsing: " ^ x))

let mac_sign_encrypt hmac ckey priv gx gy keyid =
  let (<+>) = Nocrypto.Uncommon.Cs.(<+>) in
  let pub =
    let pub = Nocrypto.Dsa.pub_of_priv priv in
    Crypto.OtrDsa.to_wire pub
  in
  let sigb =
    let gxmpi = Builder.encode_data gx
    and gympi = Builder.encode_data gy
    in
    let mb = Crypto.mac ~key:hmac [ gxmpi ; gympi ; pub ; Builder.encode_int keyid ] in
    Crypto.OtrDsa.signature ~key:priv mb
  in
  let xb = pub <+> Builder.encode_int keyid <+> sigb in
  Crypto.crypt ~key:ckey ~ctr:0L xb

let mac_verify hmac signature pub gx gy keyid =
  let gxmpi = Builder.encode_data gx
  and gympi = Builder.encode_data gy
  in
  let mb = Crypto.mac ~key:hmac [ gxmpi ; gympi ; Crypto.OtrDsa.to_wire pub ; Builder.encode_int keyid ] in
  guard (Crypto.OtrDsa.verify ~key:pub signature mb) (Unknown "DSA verification failed")

(* authentication handshake *)
let dh_commit ctx their_versions =
  match select_version ctx.config.versions their_versions with
  | None -> fail VersionMismatch
  | Some version ->
    let dh_secret, gx = Crypto.gen_dh_secret () in
    let r = Crypto.gen_symmetric_key () in
    let gxmpi = Builder.encode_data gx in
    let gxmpi' = Crypto.crypt ~key:r ~ctr:0L gxmpi in
    let h = Crypto.hash gxmpi in
    let instances = instances version in
    let dh_commit = Builder.dh_commit version instances gxmpi' h in
    let auth_state = AUTHSTATE_AWAITING_DHKEY (dh_commit, h, (dh_secret, gx), r)
    and message_state = `MSGSTATE_PLAINTEXT in (* not entirely sure about this.. *)
    let state = { auth_state ; message_state } in
    return ({ ctx with version ; instances ; state }, dh_commit)

let dh_key_await_revealsig ctx buf =
  let dh_secret, gx = Crypto.gen_dh_secret () in
  let out = Builder.dh_key ctx.version ctx.instances gx in
  let auth_state = AUTHSTATE_AWAITING_REVEALSIG ((dh_secret, gx), buf) in
  let state = { ctx.state with auth_state } in
  ({ ctx with state }, out)

let check_key_reveal_sig ctx (dh_secret, gx) r gy =
  safe_parse Parser.parse_gy gy >>= fun gy ->
  ( match Crypto.dh_shared dh_secret gy with
    | Some s -> return s
    | None -> fail (Unknown "invalid DH public key")  ) >|= fun shared_secret ->
  let keys = Crypto.derive_keys shared_secret in
  let { c ; m1 ; m2 ; _ } = keys in
  let keyidb = 1l in
  let enc_sig = mac_sign_encrypt m1 c ctx.config.dsa gx gy keyidb in
  let mac = Crypto.mac160 ~key:m2 enc_sig in
  let reveal_sig = Builder.reveal_signature ctx.version ctx.instances r enc_sig mac in
  let state = { ctx.state with auth_state = AUTHSTATE_AWAITING_SIG (reveal_sig, keys, (dh_secret, gx), gy) } in
  ({ ctx with state }, reveal_sig)

let keys previous_dh gy their_keyid =
  let dh = Crypto.gen_dh_secret ()
  and previous_gy = Cstruct.create 0
  in
  { dh ; previous_dh ; our_keyid = 2l ; our_ctr = 0L ;
    gy ; previous_gy ; their_keyid    ; their_ctr = 0L }

let check_reveal_send_sig ctx (dh_secret, gy) dh_commit buf =
  safe_parse Parser.parse_reveal buf >>= fun (r, enc_data, mac) ->
  safe_parse Parser.parse_dh_commit dh_commit >>= fun (gxenc, hgx) ->
  let gx = Crypto.crypt ~key:r ~ctr:0L gxenc in
  let hgx' = Crypto.hash gx in
  guard (Nocrypto.Uncommon.Cs.equal hgx hgx') (Unknown "hgx does not match hgx'") >>= fun () ->
  safe_parse Parser.parse_gy gx >>= fun gx ->
  ( match Crypto.dh_shared dh_secret gx with
    | Some x -> return x
    | None -> fail (Unknown "invalid DH public key") ) >>= fun shared_secret ->
  let { ssid ; c ; c' ; m1 ; m2 ; m1' ; m2' } = Crypto.derive_keys shared_secret in
  let mac' = Crypto.mac160 ~key:m2 enc_data in
  guard (Nocrypto.Uncommon.Cs.equal mac mac') (Unknown "mac does not match mac'") >>= fun () ->
  let xb = Crypto.crypt ~key:c ~ctr:0L enc_data in
  (* split into pubb, keyidb, sigb *)
  safe_parse Parser.parse_signature_data xb >>= fun (pubb, keyidb, sigb) ->
  mac_verify m1 sigb pubb gx gy keyidb >>= fun () ->
  (* pick keyida *)
  let keyida = 1l in
  let enc_sig = mac_sign_encrypt m1' c' ctx.config.dsa gy gx keyida in
  let m = Crypto.mac160 ~key:m2' enc_sig in
  let keys = keys (dh_secret, gy) gx keyida in
  let state = {
    auth_state = AUTHSTATE_NONE ;
    message_state = `MSGSTATE_ENCRYPTED keys
  } in
  return ({ ctx with state ; their_dsa = Some pubb ; ssid ; high = false },
          Builder.signature ctx.version ctx.instances enc_sig m)

let check_sig ctx { ssid ; c' ; m1' ; m2' ; _ } (dh_secret, gx) gy signature =
  (* decrypt signature, verify it and macs *)
  safe_parse Parser.decode_data signature >>= fun (enc_data, mac) ->
  guard (Cstruct.len mac = 20) (Unknown "mac has wrong length") >>= fun () ->
  let mymac = Crypto.mac160 ~key:m2' enc_data in
  guard (Nocrypto.Uncommon.Cs.equal mac mymac) (Unknown "mac do not match") >>= fun () ->
  let dec = Crypto.crypt ~key:c' ~ctr:0L enc_data in
  (* split into puba keyida siga(Ma) *)
  safe_parse Parser.parse_signature_data dec >>= fun (puba, keyida, siga) ->
  mac_verify m1' siga puba gy gx keyida >>= fun () ->
  let keys = keys (dh_secret, gx) gy keyida in
  let state = {
    auth_state = AUTHSTATE_NONE ;
    message_state = `MSGSTATE_ENCRYPTED keys
  } in
  return { ctx with state ; their_dsa = Some puba ; ssid ; high = true }

let handle_commit_await_key ctx dh_c h buf =
  (try return (Cstruct.sub buf (Cstruct.len buf - 32) 32)
   with _ -> fail (Unknown "underflow") ) >|= fun their_hash ->
  if Crypto.mpi_gt h their_hash then
    (ctx, Some dh_c)
  else
    let ctx, dh_key = dh_key_await_revealsig ctx buf in
    (ctx, Some dh_key)

let check_version_instances ctx version instances =
  ( match ctx.state.auth_state with
    | AUTHSTATE_NONE -> return { ctx with version }
    | _ ->
      guard (version = ctx.version) VersionMismatch >|= fun () ->
      ctx ) >>= fun (ctx) ->
  ( match version, instances, ctx.instances with
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
        return ctx
    | `V2, _ , _ -> return ctx
    | _ -> fail InstanceMismatch )

let format_ssid { ssid ; high ; _ } =
  let f, s = Cstruct.BE.(get_uint32 ssid 0, get_uint32 ssid 4) in
  Printf.sprintf "%s%08lx%s %s%08lx%s"
    (if high then "[" else "") f (if high then "]" else "")
    (if high then "" else "[") s (if high then "" else "]")

let handle_auth ctx bytes =
  let open Packet in
  safe_parse Parser.parse_header bytes >>= fun (version, typ, instances, buf) ->
  check_version_instances ctx version instances >>= fun ctx ->
  match typ, ctx.state.auth_state with
  | DH_COMMIT, AUTHSTATE_NONE ->
    let ctx, dh_key = dh_key_await_revealsig ctx buf in
    return (ctx, Some dh_key, [])
  | DH_COMMIT, AUTHSTATE_AWAITING_DHKEY (dh_c, h, _, _) ->
    handle_commit_await_key ctx dh_c h buf >|= fun (ctx, out) ->
    (ctx, out, [])
  | DH_COMMIT, AUTHSTATE_AWAITING_REVEALSIG ((dh_secret, gx), _) ->
    let auth_state = AUTHSTATE_AWAITING_REVEALSIG ((dh_secret, gx), buf) in
    let state = { ctx.state with auth_state } in
    let dh_key = Builder.dh_key ctx.version ctx.instances gx in
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
    safe_parse Parser.parse_gy buf >|= fun gy' ->
    if Nocrypto.Uncommon.Cs.equal gy gy' then
      (ctx, Some reveal_sig, [])
    else
      (ctx, None, [])

  | REVEAL_SIGNATURE, AUTHSTATE_AWAITING_REVEALSIG (dh_params, dh_commit)  ->
    (* do work, send signature -> AUTHSTATE_NONE, MSGSTATE_ENCRYPTED *)
    check_reveal_send_sig ctx dh_params dh_commit buf >|= fun (ctx, out) ->
    (ctx, Some out, [`Established_encrypted_session (format_ssid ctx)])

  | SIGNATURE, AUTHSTATE_AWAITING_SIG (_, keys, dh_params, gy) ->
    (* decrypt signature, verify sig + macs -> AUTHSTATE_NONE, MSGSTATE_ENCRYPTED *)
    check_sig ctx keys dh_params gy buf >|= fun ctx ->
    (ctx, None, [`Established_encrypted_session (format_ssid ctx)])

  | DATA, _ ->
    safe_parse Parser.parse_data_body buf >>= fun (flag, _, _, _, _, _, _, _) ->
    fail (Unexpected flag)

  | _ -> (* ignore this message *) return (ctx, None, [`Warning "ignoring unknown message"])
