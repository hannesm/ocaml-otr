open Otr_state

(* Monadic control-flow core. *)
type error =
  | Unknown of string
  | Unexpected of bool
  | VersionMismatch
  | InstanceMismatch

let instance_tag () =
  (* 32 bit random, >= 0x00000100 *)
  let tag = String.get_int32_be (Mirage_crypto_rng.generate 4) 0 in
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
  | Ok x -> Ok x
  | Error Otr_parser.Underflow -> Error (Unknown "underflow error while parsing")
  | Error Otr_parser.LeadingZero -> Error (Unknown "leading zero of a MPI while parsing")
  | Error (Otr_parser.Unknown x) -> Error (Unknown ("error while parsing: " ^ x))

let mac_sign_encrypt hmac ckey priv gx gy keyid =
  let pub =
    let pub = Mirage_crypto_pk.Dsa.pub_of_priv priv in
    Otr_crypto.OtrDsa.to_wire pub
  in
  let sigb =
    let gxmpi = Otr_builder.encode_data gx
    and gympi = Otr_builder.encode_data gy
    in
    let mb = Otr_crypto.mac ~key:hmac [ gxmpi ; gympi ; pub ; Otr_builder.encode_int keyid ] in
    Otr_crypto.OtrDsa.signature ~key:priv mb
  in
  let xb = pub ^ Otr_builder.encode_int keyid ^ sigb in
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
  | None -> Error VersionMismatch
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
    Ok ({ ctx with version ; instances ; state }, dh_commit)

let dh_key_await_revealsig ctx buf =
  let dh_secret, gx = Otr_crypto.gen_dh_secret () in
  let out = Otr_builder.dh_key ctx.version ctx.instances gx in
  let auth_state = AUTHSTATE_AWAITING_REVEALSIG ((dh_secret, gx), buf) in
  let state = { ctx.state with auth_state } in
  ({ ctx with state }, out)

let check_key_reveal_sig ctx (dh_secret, gx) r gy =
  let* gy = safe_parse Otr_parser.parse_gy gy in
  let* shared_secret =
    Option.to_result ~none:(Unknown "invalid DH public key")
      (Otr_crypto.dh_shared dh_secret gy)
  in
  let (ssid, c, c', m1, m2, m1', m2') = Otr_crypto.derive_keys shared_secret in
  let keyidb = 1l in
  let enc_sig = mac_sign_encrypt m1 c ctx.dsa gx gy keyidb in
  let mac = Otr_crypto.mac160 ~key:m2 enc_sig in
  let reveal_sig = Otr_builder.reveal_signature ctx.version ctx.instances r enc_sig mac in
  let auth_state = AUTHSTATE_AWAITING_SIG (reveal_sig, (ssid, c', m1', m2'), (dh_secret, gx), gy) in
  let state = { ctx.state with auth_state } in
  Ok ({ ctx with state }, reveal_sig)

let keys previous_dh gy their_keyid =
  let dh = Otr_crypto.gen_dh_secret ()
  and previous_gy = ""
  in
  { dh ; previous_dh ; our_keyid = 2l ;
    gy ; previous_gy ; their_keyid }

let format_ssid ssid high =
  let f, s = String.(get_int32_be ssid 0, get_int32_be ssid 4) in
  Printf.sprintf "%s%08lx%s %s%08lx%s"
    (if high then "[" else "") f (if high then "]" else "")
    (if high then "" else "[") s (if high then "" else "]")

let check_reveal_send_sig ctx (dh_secret, gy) dh_commit buf =
  let* r, enc_data, mac = safe_parse Otr_parser.parse_reveal buf in
  let* gxenc, hgx = safe_parse Otr_parser.parse_dh_commit dh_commit in
  let gx = Otr_crypto.crypt ~key:r ~ctr:0L gxenc in
  let hgx' = Otr_crypto.hash gx in
  let* () = guard (String.equal hgx hgx') (Unknown "hgx does not match hgx'") in
  let* gx = safe_parse Otr_parser.parse_gy gx in
  let* shared_secret =
    Option.to_result
      ~none:(Unknown "invalid DH public key")
      (Otr_crypto.dh_shared dh_secret gx)
  in
  let ssid, c, c', m1, m2, m1', m2' = Otr_crypto.derive_keys shared_secret in
  let mac' = Otr_crypto.mac160 ~key:m2 enc_data in
  let* () = guard (String.equal mac mac') (Unknown "mac does not match mac'") in
  let xb = Otr_crypto.crypt ~key:c ~ctr:0L enc_data in
  (* split into pubb, keyidb, sigb *)
  let* pubb, keyidb, sigb = safe_parse Otr_parser.parse_signature_data xb in
  let* () = mac_verify m1 sigb pubb gx gy keyidb in
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
  Ok ({ ctx with state },
      Otr_builder.signature ctx.version ctx.instances enc_sig m,
      format_ssid ssid high)

let check_sig ctx (ssid, c', m1', m2') (dh_secret, gx) gy signature =
  (* decrypt signature, verify it and macs *)
  let* enc_data, mac = safe_parse Otr_parser.decode_data signature in
  let* () = guard (String.length mac = 20) (Unknown "mac has wrong length") in
  let mymac = Otr_crypto.mac160 ~key:m2' enc_data in
  let* () = guard (String.equal mac mymac) (Unknown "mac do not match") in
  let dec = Otr_crypto.crypt ~key:c' ~ctr:0L enc_data in
  (* split into puba keyida siga(Ma) *)
  let* puba, keyida, siga = safe_parse Otr_parser.parse_signature_data dec in
  let* () = mac_verify m1' siga puba gy gx keyida in
  let dh_keys = keys (dh_secret, gx) gy keyida in
  let high = true in
  let enc_data = { dh_keys ; symms = [] ; their_dsa = puba ; ssid ; high } in
  let state = {
    auth_state = AUTHSTATE_NONE ;
    message_state = MSGSTATE_ENCRYPTED enc_data ;
    smp_state = SMPSTATE_EXPECT1 ;
  } in
  Ok ({ ctx with state }, format_ssid ssid high)

let handle_commit_await_key ctx dh_c h version instances buf =
  let* () = guard (String.length buf >= 32) (Unknown "underflow") in
  let their_hash = String.sub buf (String.length buf - 32) 32 in
  if Otr_crypto.mpi_gt h their_hash then
    Ok (ctx, Some dh_c)
  else
    let* () = guard (List.mem version ctx.config.versions) (Unknown "version") in
    let ctx = { ctx with version ; instances } in
    let ctx, dh_key = dh_key_await_revealsig ctx buf in
    Ok (ctx, Some dh_key)

let check_version_instances ctx version instances =
  let* ctx =
    match ctx.state.auth_state with
    | AUTHSTATE_NONE -> Ok { ctx with version }
    | _ ->
      let* () = guard (version = ctx.version) VersionMismatch in
      Ok ctx
  in
  match version, instances, ctx.instances with
    | `V3, Some (yoursend, yourrecv), Some (mysend, myrecv) when mysend = 0l ->
      let* () = guard ((yourrecv = myrecv) && (Int32.shift_right_logical yoursend 8 > 0l)) InstanceMismatch in
      Ok { ctx with instances = Some (yoursend, myrecv) }
    | `V3, Some (yoursend, yourrecv), Some (mysend, myrecv) ->
      let* () = guard ((yourrecv = myrecv) && (yoursend = mysend)) InstanceMismatch in
      Ok ctx
    | `V3, Some (yoursend, yourrecv), None ->
      if Int32.shift_right_logical yourrecv 8 = 0l then
        let myinstance = instance_tag () in
        Ok { ctx with instances = Some (yoursend, myinstance) }
      else (* other side has an encrypted session with us, but we do not *)
        if ctx.state.auth_state = AUTHSTATE_NONE then
          (* hack for interop with coy.im *)
          Ok { ctx with instances }
        else (* if this happens, shit hits the fan - let's talk V2 to have Builder:header not run into failed assertions *)
          Ok { ctx with version = `V2 }
    | `V2, _ , _ -> Ok ctx
    | _ -> Error InstanceMismatch

let handle_auth ctx bytes =
  let open Otr_packet in
  let* version, typ, instances, buf = safe_parse Otr_parser.parse_header bytes in
  (* simultaneous open *)
  match typ, ctx.state.auth_state with
  | DH_COMMIT, AUTHSTATE_AWAITING_DHKEY (dh_c, h, _, _) ->
    let* ctx, out = handle_commit_await_key ctx dh_c h version instances buf in
    Ok (ctx, out, [])
  | _ ->
    let* ctx = check_version_instances ctx version instances in
    match typ, ctx.state.auth_state with
    | DH_COMMIT, AUTHSTATE_NONE ->
      let ctx, dh_key = dh_key_await_revealsig ctx buf in
      Ok (ctx, Some dh_key, [])
    | DH_COMMIT, AUTHSTATE_AWAITING_REVEALSIG ((dh_secret, gx), _) ->
      let auth_state = AUTHSTATE_AWAITING_REVEALSIG ((dh_secret, gx), buf) in
      let state = { ctx.state with auth_state } in
      let dh_key = Otr_builder.dh_key ctx.version ctx.instances gx in
      Ok ({ ctx with state }, Some dh_key, [])
    | DH_COMMIT, AUTHSTATE_AWAITING_SIG _ ->
      (* send dh_key, go to AWAITING_REVEALSIG *)
      let ctx, dh_key = dh_key_await_revealsig ctx buf in
      Ok (ctx, Some dh_key, [])

    | DH_KEY, AUTHSTATE_AWAITING_DHKEY (_, _, dh_params, r) ->
      (* reveal_sig -> AUTHSTATE_AWAITING_SIG *)
      let* ctx, reveal = check_key_reveal_sig ctx dh_params r buf in
      Ok (ctx, Some reveal, [])

    | DH_KEY, AUTHSTATE_AWAITING_SIG (reveal_sig, _, _, gy) ->
      (* same dh_key? -> retransmit REVEAL_SIG *)
      let* gy' = safe_parse Otr_parser.parse_gy buf in
      if String.equal gy gy' then
        Ok (ctx, Some reveal_sig, [])
      else
        Ok (ctx, None, [])

    | REVEAL_SIGNATURE, AUTHSTATE_AWAITING_REVEALSIG (dh_params, dh_commit)  ->
      (* do work, send signature -> AUTHSTATE_NONE, MSGSTATE_ENCRYPTED *)
      let* ctx, out, ssid = check_reveal_send_sig ctx dh_params dh_commit buf in
      Ok (ctx, Some out, [`Established_encrypted_session ssid])

    | SIGNATURE, AUTHSTATE_AWAITING_SIG (_, keys, dh_params, gy) ->
      (* decrypt signature, verify sig + macs -> AUTHSTATE_NONE, MSGSTATE_ENCRYPTED *)
      let* ctx, ssid = check_sig ctx keys dh_params gy buf in
      Ok (ctx, None, [`Established_encrypted_session ssid])

    | DATA, _ ->
      let* flag, _, _, _, _, _, _, _ =
        safe_parse Otr_parser.parse_data_body buf
      in
      Error (Unexpected flag)

    | _ -> (* ignore this message *) Ok (ctx, None, [`Warning "ignoring unknown message"])
