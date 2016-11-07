open Rresult

open Otr_state

type error =
  | UnexpectedMessage
  | InvalidZeroKnowledgeProof

let error_to_string = function
  | UnexpectedMessage -> "unexpected SMP message"
  | InvalidZeroKnowledgeProof -> "invalid zero knowledge proof"

type 'a result = ('a, error) Result.result

let fp = Otr_crypto.OtrDsa.fingerprint
let my_fp dsa = fp (Nocrypto.Dsa.pub_of_priv dsa)

let start_smp dsa enc_data smp_state ?question secret =
  ( match smp_state with
    | SMPSTATE_EXPECT1 -> Ok ()
    | _ -> Error UnexpectedMessage ) >>| fun () ->
  let a2, g2a = Otr_crypto.gen_dh_secret ()
  and a3, g3a = Otr_crypto.gen_dh_secret ()
  in
  let c2, d2 = Otr_crypto.proof_knowledge a2 1
  and c3, d3 = Otr_crypto.proof_knowledge a3 2
  in
  let x = Otr_crypto.prepare_secret (my_fp dsa) (fp enc_data.their_dsa) enc_data.ssid secret in
  let data = [ g2a ; c2 ; d2 ; g3a ; c3 ; d3 ]
  and smp_state = SMPSTATE_EXPECT2 (x, a2, a3)
  in
  let out = match question with
    | None -> Otr_builder.tlv ~data Otr_packet.SMP_MESSAGE_1
    | Some x -> Otr_builder.tlv ~data ~predata:(Cstruct.of_string (x ^ "\000")) Otr_packet.SMP_MESSAGE_1Q
  in
  (smp_state, Some out)

let abort_smp smp_state =
  match smp_state with
  | SMPSTATE_EXPECT1 -> Ok (SMPSTATE_EXPECT1, None)
  | _ -> Ok (SMPSTATE_EXPECT1, Some (Otr_builder.tlv Otr_packet.SMP_ABORT))

let handle_smp_1 data =
  match Otr_parser.parse_datas data 6 with
  | Error _ -> Error UnexpectedMessage
  | Ok xs ->
    let g2a = List.nth xs 0
    and c2 = List.nth xs 1
    and d2 = List.nth xs 2
    and g3a = List.nth xs 3
    and c3 = List.nth xs 4
    and d3 = List.nth xs 5
    in
    if Otr_crypto.check_proof g2a c2 d2 1 && Otr_crypto.check_proof g3a c3 d3 2 then
      Ok (SMPSTATE_WAIT_FOR_Y (g2a, g3a), None, [ `SMP_awaiting_secret ])
    else
      Error InvalidZeroKnowledgeProof

let handle_secret dsa enc_data smp_state secret =
  match smp_state with
  | SMPSTATE_WAIT_FOR_Y (g2a, g3a) ->
    let b2, g2b = Otr_crypto.gen_dh_secret ()
    and b3, g3b = Otr_crypto.gen_dh_secret ()
    in
    let c2, d2 = Otr_crypto.proof_knowledge b2 3
    and c3, d3 = Otr_crypto.proof_knowledge b3 4
    in
    ( match Otr_crypto.dh_shared b2 g2a, Otr_crypto.dh_shared b3 g3a with
      | Some g2, Some g3 ->
        let r, gr = Otr_crypto.gen_dh_secret ()
        and y = Otr_crypto.prepare_secret (fp enc_data.their_dsa) (my_fp dsa) enc_data.ssid secret
        in
        let pb = Otr_crypto.pow_s g3 r
        and qb = Otr_crypto.mult_pow gr g2 y
        in
        let cp, d5, d6 = Otr_crypto.proof_equal_coords g2 g3 r y 5 in
        let out = Otr_builder.tlv ~data:[ g2b ; c2 ; d2 ; g3b ; c3 ; d3 ; pb ; qb ; cp ; d5 ; d6 ] Otr_packet.SMP_MESSAGE_2
        and smp_state = SMPSTATE_EXPECT3 (g3a, g2, g3, b3, pb, qb)
        in
        Ok (smp_state, Some out)
      | _ -> Error UnexpectedMessage )
  | _ -> Error UnexpectedMessage

let handle_smp_2 x a2 a3 data =
  match Otr_parser.parse_datas data 11 with
  | Error _ -> Error UnexpectedMessage
  | Ok xs ->
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
    if Otr_crypto.check_proof g2b c2 d2 3 && Otr_crypto.check_proof g3b c3 d3 4 then
      match Otr_crypto.dh_shared a2 g2b, Otr_crypto.dh_shared a3 g3b with
      | Some g2, Some g3 ->
        if Otr_crypto.check_equal_coords g2 g3 pb qb cp d5 d6 5 then
          let r, gr = Otr_crypto.gen_dh_secret () in
          let pa = Otr_crypto.pow_s g3 r
          and qa = Otr_crypto.mult_pow gr g2 x
          in
          let cp, d5, d6 = Otr_crypto.proof_equal_coords g2 g3 r x 6 in
          let pab = Otr_crypto.compute_p pa pb
          and qab = Otr_crypto.compute_p qa qb
          in
          let ra = Otr_crypto.pow_s qab a3
          and cr, d7 = Otr_crypto.proof_eq_logs qab a3 7
          in
          let out = Otr_builder.tlv ~data:[ pa ; qa ; cp ; d5 ; d6 ; ra ; cr ; d7 ] Otr_packet.SMP_MESSAGE_3
          and smp_state = SMPSTATE_EXPECT4 (g3b, pab, qab, a3)
          in
          Ok (smp_state, out)
        else
          Error UnexpectedMessage
      | _ -> Error UnexpectedMessage
    else
      Error UnexpectedMessage

let handle_smp_3 g3a g2 g3 b3 pb qb data =
  match Otr_parser.parse_datas data 8 with
  | Error _ -> Error UnexpectedMessage
  | Ok xs ->
    let pa = List.nth xs 0
    and qa = List.nth xs 1
    and cp = List.nth xs 2
    and d5 = List.nth xs 3
    and d6 = List.nth xs 4
    and ra = List.nth xs 5
    and cr = List.nth xs 6
    and d7 = List.nth xs 7
    in
    if Otr_crypto.check_equal_coords g2 g3 pa qa cp d5 d6 6 then
      let pab = Otr_crypto.compute_p pa pb
      and qab = Otr_crypto.compute_p qa qb
      in
      if Otr_crypto.check_eq_logs cr g3a qab d7 ra 7 then
        let rb = Otr_crypto.pow_s qab b3
        and cr, d7 = Otr_crypto.proof_eq_logs qab b3 8
        in
        let out = Otr_builder.tlv ~data:[ rb ; cr ; d7 ] Otr_packet.SMP_MESSAGE_4 in
        let rab = Otr_crypto.pow_s ra b3 in
        let ret =
          if Cstruct.equal rab pab then
            `SMP_success
          else
            `SMP_failure
        in
        let smp_state = SMPSTATE_EXPECT1 in
        Ok (smp_state, out, ret)
      else
        Error UnexpectedMessage
    else
      Error UnexpectedMessage

let handle_smp_4 g3b pab qab a3 data =
  match Otr_parser.parse_datas data 3 with
  | Error _ -> Error UnexpectedMessage
  | Ok xs ->
    let rb = List.nth xs 0
    and cr = List.nth xs 1
    and d7 = List.nth xs 2
    in
    if Otr_crypto.check_eq_logs cr g3b qab d7 rb 8 then
      let rab = Otr_crypto.pow_s rb a3 in
      let ret =
        if Cstruct.equal rab pab then
          `SMP_success
        else
          `SMP_failure
      in
      Ok (SMPSTATE_EXPECT1, ret)
    else
      Error UnexpectedMessage

let handle_smp smp_state typ data =
  let open Otr_packet in
  match smp_state, typ with
  | SMPSTATE_EXPECT1, SMP_MESSAGE_1 ->
    handle_smp_1 data >>| fun (s, o, r) ->
    (s, o, r)
  | SMPSTATE_EXPECT1, SMP_MESSAGE_1Q ->
    let str = Cstruct.to_string data in
    ( try
        let stop = String.index str '\000' in
        let stop' = succ stop in
        Ok (String.sub str 0 stop, Cstruct.shift data stop')
      with
        Not_found -> Error UnexpectedMessage ) >>= fun (question, data) ->
    handle_smp_1 data >>| fun (s, o, r) ->
    (s, o, [ `SMP_received_question question ] @ r)
  | SMPSTATE_EXPECT2 (x, a2, a3), SMP_MESSAGE_2 ->
    handle_smp_2 x a2 a3 data >>| fun (s, o) ->
    (s, Some o, [])
  | SMPSTATE_EXPECT3 (g3a, g2, g3, b3, pb, qb), SMP_MESSAGE_3 ->
    handle_smp_3 g3a g2 g3 b3 pb qb data >>| fun (s, o, r) ->
    (s, Some o, [r])
  | SMPSTATE_EXPECT4 (g3b, pab, qab, ra), SMP_MESSAGE_4 ->
    handle_smp_4 g3b pab qab ra data >>| fun (s, r) ->
    (s, None, [r])
  | _, SMP_ABORT ->
    Ok (SMPSTATE_EXPECT1, None, [])
  | _, _ ->
    let abort = Otr_builder.tlv SMP_ABORT in
    Ok (SMPSTATE_EXPECT1, Some abort, [])
