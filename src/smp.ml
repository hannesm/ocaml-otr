
open State

type error =
  | UnexpectedMessage
  | InvalidZeroKnowledgeProof

let error_to_string = function
  | UnexpectedMessage -> "unexpected SMP message"
  | InvalidZeroKnowledgeProof -> "invalid zero knowledge proof"

include Control.Or_error_make (struct type err = error end)

let own_fingerprint ctx =
  Crypto.OtrDsa.fingerprint (Nocrypto.Dsa.pub_of_priv ctx.config.dsa)

let their_fingerprint ctx =
  match ctx.their_dsa with
  | Some p -> Crypto.OtrDsa.fingerprint p
  | None -> assert false

let start_smp ctx ?question secret =
  ( match ctx.state.smp_state with
    | SMPSTATE_EXPECT1 -> return ()
    | _ -> fail UnexpectedMessage ) >|= fun () ->
  let a2, g2a = Crypto.gen_dh_secret ()
  and a3, g3a = Crypto.gen_dh_secret ()
  in
  let c2, d2 = Crypto.proof_knowledge a2 1
  and c3, d3 = Crypto.proof_knowledge a3 2
  in
  let x = Crypto.prepare_secret (own_fingerprint ctx) (their_fingerprint ctx) ctx.ssid secret in
  let data = [ g2a ; c2 ; d2 ; g3a ; c3 ; d3 ]
  and smp_state = SMPSTATE_EXPECT2 (x, a2, a3)
  in
  let out = match question with
    | None -> Builder.tlv ~data Packet.SMP_MESSAGE_1
    | Some x -> Builder.tlv ~data ~predata:(Cstruct.of_string (x ^ "\000")) Packet.SMP_MESSAGE_1Q
  in
  (smp_state, Some out)

let abort_smp smp_state =
  match smp_state with
  | SMPSTATE_EXPECT1 -> return (SMPSTATE_EXPECT1, None)
  | _ -> return (SMPSTATE_EXPECT1, Some (Builder.tlv Packet.SMP_ABORT))

let handle_smp_1 data =
  match Parser.parse_datas data 6 with
  | Parser.Error _ -> fail UnexpectedMessage
  | Parser.Ok xs ->
    let g2a = List.nth xs 0
    and c2 = List.nth xs 1
    and d2 = List.nth xs 2
    and g3a = List.nth xs 3
    and c3 = List.nth xs 4
    and d3 = List.nth xs 5
    in
    if Crypto.check_proof g2a c2 d2 1 && Crypto.check_proof g3a c3 d3 2 then
      return (SMPSTATE_WAIT_FOR_Y (g2a, g3a), None, [ `SMP_awaiting_secret ])
    else
      fail InvalidZeroKnowledgeProof

let handle_secret ctx secret =
  match ctx.state.smp_state with
  | SMPSTATE_WAIT_FOR_Y (g2a, g3a) ->
    let b2, g2b = Crypto.gen_dh_secret ()
    and b3, g3b = Crypto.gen_dh_secret ()
    in
    let c2, d2 = Crypto.proof_knowledge b2 3
    and c3, d3 = Crypto.proof_knowledge b3 4
    in
    ( match Crypto.dh_shared b2 g2a, Crypto.dh_shared b3 g3a with
      | Some g2, Some g3 ->
        let r, gr = Crypto.gen_dh_secret ()
        and y = Crypto.prepare_secret (their_fingerprint ctx) (own_fingerprint ctx) ctx.ssid secret
        in
        let pb = Crypto.pow_s g3 r
        and qb = Crypto.mult_pow gr g2 y
        in
        let cp, d5, d6 = Crypto.proof_equal_coords g2 g3 r y 5 in
        let out = Builder.tlv ~data:[ g2b ; c2 ; d2 ; g3b ; c3 ; d3 ; pb ; qb ; cp ; d5 ; d6 ] Packet.SMP_MESSAGE_2
        and smp_state = SMPSTATE_EXPECT3 (g3a, g2, g3, b3, pb, qb)
        in
        return (smp_state, Some out)
      | _ -> fail UnexpectedMessage )
  | _ -> fail UnexpectedMessage

let handle_smp_2 x a2 a3 data =
  match Parser.parse_datas data 11 with
  | Parser.Error _ -> fail UnexpectedMessage
  | Parser.Ok xs ->
    let g2b = List.nth xs 0
    and c2 = List.nth xs 1
    and d2 = List.nth xs 2
    and g3b = List.nth xs 3
    and c3 = List.nth xs 4
    and d3 = List.nth xs 5
    and pb = List.nth xs 6
    and qb = List.nth xs 7
    and cp = List.nth xs 8
    and d5 = List.nth xs 9
    and d6 = List.nth xs 10
    in
    if Crypto.check_proof g2b c2 d2 3 && Crypto.check_proof g3b c3 d3 4 then
      match Crypto.dh_shared a2 g2b, Crypto.dh_shared a3 g3b with
      | Some g2, Some g3 ->
        if Crypto.check_equal_coords g2 g3 pb qb cp d5 d6 5 then
          let r, gr = Crypto.gen_dh_secret () in
          let pa = Crypto.pow_s g3 r
          and qa = Crypto.mult_pow gr g2 x
          in
          let cp, d5, d6 = Crypto.proof_equal_coords g2 g3 r x 6 in
          let pab = Crypto.compute_p pa pb
          and qab = Crypto.compute_p qa qb
          in
          let ra = Crypto.pow_s qab a3
          and cr, d7 = Crypto.proof_eq_logs qab a3 7
          in
          let out = Builder.tlv ~data:[ pa ; qa ; cp ; d5 ; d6 ; ra ; cr ; d7 ] Packet.SMP_MESSAGE_3
          and smp_state = SMPSTATE_EXPECT4 (g3b, pab, qab, a3)
          in
          return (smp_state, out)
        else
          fail UnexpectedMessage
      | _ -> fail UnexpectedMessage
    else
      fail UnexpectedMessage

let handle_smp_3 g3a g2 g3 b3 pb qb data =
  match Parser.parse_datas data 8 with
  | Parser.Error _ -> fail UnexpectedMessage
  | Parser.Ok xs ->
    let pa = List.nth xs 0
    and qa = List.nth xs 1
    and cp = List.nth xs 2
    and d5 = List.nth xs 3
    and d6 = List.nth xs 4
    and ra = List.nth xs 5
    and cr = List.nth xs 6
    and d7 = List.nth xs 7
    in
    if Crypto.check_equal_coords g2 g3 pa qa cp d5 d6 6 then
      let pab = Crypto.compute_p pa pb
      and qab = Crypto.compute_p qa qb
      in
      if Crypto.check_eq_logs cr g3a qab d7 ra 7 then
        let rb = Crypto.pow_s qab b3
        and cr, d7 = Crypto.proof_eq_logs qab b3 8
        in
        let out = Builder.tlv ~data:[ rb ; cr ; d7 ] Packet.SMP_MESSAGE_4 in
        let rab = Crypto.pow_s ra b3 in
        let ret =
          if Nocrypto.Uncommon.Cs.equal rab pab then
            `SMP_success
          else
            `SMP_failure
        in
        let smp_state = SMPSTATE_EXPECT1 in
        return (smp_state, out, ret)
      else
        fail UnexpectedMessage
    else
      fail UnexpectedMessage

let handle_smp_4 g3b pab qab a3 data =
  match Parser.parse_datas data 3 with
  | Parser.Error _ -> fail UnexpectedMessage
  | Parser.Ok xs ->
    let rb = List.nth xs 0
    and cr = List.nth xs 1
    and d7 = List.nth xs 2
    in
    if Crypto.check_eq_logs cr g3b qab d7 rb 8 then
      let rab = Crypto.pow_s rb a3 in
      let ret =
        if Nocrypto.Uncommon.Cs.equal rab pab then
          `SMP_success
        else
          `SMP_failure
      in
      return (SMPSTATE_EXPECT1, ret)
    else
      fail UnexpectedMessage

let handle_smp smp_state typ data =
  let open Packet in
  match smp_state, typ with
  | SMPSTATE_EXPECT1, SMP_MESSAGE_1 ->
    handle_smp_1 data >|= fun (s, o, r) ->
    (s, o, r)
  | SMPSTATE_EXPECT1, SMP_MESSAGE_1Q ->
    let str = Cstruct.to_string data in
    ( try
        let stop = String.index str '\000' in
        let stop' = succ stop in
        return (String.sub str 0 stop, Cstruct.shift data stop')
      with
        Not_found -> fail UnexpectedMessage ) >>= fun (question, data) ->
    handle_smp_1 data >|= fun (s, o, r) ->
    (s, o, [ `SMP_received_question question ] @ r)
  | SMPSTATE_EXPECT2 (x, a2, a3), SMP_MESSAGE_2 ->
    handle_smp_2 x a2 a3 data >|= fun (s, o) ->
    (s, Some o, [])
  | SMPSTATE_EXPECT3 (g3a, g2, g3, b3, pb, qb), SMP_MESSAGE_3 ->
    handle_smp_3 g3a g2 g3 b3 pb qb data >|= fun (s, o, r) ->
    (s, Some o, [r])
  | SMPSTATE_EXPECT4 (g3b, pab, qab, ra), SMP_MESSAGE_4 ->
    handle_smp_4 g3b pab qab ra data >|= fun (s, r) ->
    (s, None, [r])
  | _, SMP_ABORT ->
    return (SMPSTATE_EXPECT1, None, [])
  | _, _ ->
    let abort = Builder.tlv SMP_ABORT in
    return (SMPSTATE_EXPECT1, Some abort, [])
