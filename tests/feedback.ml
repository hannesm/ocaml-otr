open Otr.State
open Otr.Engine

let teststring = "abcdedsajlkjdslkjflkjflkrjlkdlkadhkjncjknckj"

let data () =
  let cnt = Random.int (pred (String.length teststring)) in
  String.sub teststring 0 (succ cnt)

let send ctx =
  let str = data () in
  let ctx, out, user = send_otr ctx str in
  ( match user with
    | `Sent_encrypted x when x = str -> ()
    | _ -> assert false ) ;
  let out = match out with None -> assert false | Some x -> x in
  (ctx, out, str)

let recv ctx data str =
  let ctx, out, msgs = handle ctx data in
  assert (out = None);
  ( match msgs with
    | (`Received_encrypted x) :: [] when x = str -> ()
    | _ -> assert false ) ;
  ctx

let start_session _ =
  let buf = Cstruct.create 16 in
  Nocrypto.Rng.reseed buf ;
  let keya = Nocrypto.Dsa.generate `Fips1024 in
  let keyb = Nocrypto.Dsa.generate `Fips1024 in
  let cfga = config all_versions all_policies in
  let cfgb = config all_versions all_policies in
  let ctxa = new_session cfga keya () in
  let ctxb = new_session cfgb keyb () in
  let ctxa, query = start_otr ctxa in
  let ctxb, out, msg = handle ctxb query in
  (* dh_commit *)
  assert (List.length msg = 0) ;
(*  ( match ctxb.state.auth_state with
    | AUTHSTATE_AWAITING_DHKEY _ -> ()
    | _ -> assert false ); *)
  assert (not (is_encrypted ctxb)) ;
  let out = match out with None -> assert false | Some x -> x in
  let ctxa, out, msg = handle ctxa out in
  (* dh_key *)
  assert (List.length msg = 0) ;
(*  ( match ctxa.state.auth_state with
    | AUTHSTATE_AWAITING_REVEALSIG _ -> ()
    | _ -> assert false ); *)
  assert (not (is_encrypted ctxa)) ;
  let out = match out with None -> assert false | Some x -> x in
  let ctxb, out, msg = handle ctxb out in
  (* reveal_sig *)
  assert (List.length msg = 0) ;
(*  ( match ctxb.state.auth_state with
    | AUTHSTATE_AWAITING_SIG _ -> ()
    | _ -> assert false ); *)
  assert (not (is_encrypted ctxb)) ;
  let out = match out with None -> assert false | Some x -> x in
  let ctxa, out, msg = handle ctxa out in
  (* sig *)
  assert (List.length msg = 1) ;
  (*  assert (ctxa.state.auth_state = AUTHSTATE_NONE) ; *)
  assert (is_encrypted ctxa) ;
  (*let ssida, higha = match ctxa.state.message_state with
    | MSGSTATE_ENCRYPTED enc_data -> enc_data.ssid, enc_data.high
    | _ -> assert false
    in *)
  let out = match out with None -> assert false | Some x -> x in
  let ctxb, _out, msg = handle ctxb out in
  (* finished *)
  assert (List.length msg = 1) ;
  (*  assert (ctxb.state.auth_state = AUTHSTATE_NONE) ; *)
  assert (is_encrypted ctxb) ;
(*  let ssidb, highb = match ctxb.state.message_state with
    | MSGSTATE_ENCRYPTED enc_data -> enc_data.ssid, enc_data.high
    | _ -> assert false
  in
  assert (Cstruct.equal ssida ssidb) ;
  ( match higha, highb with
    | false, true -> ()
    | true, false -> ()
    | _ -> assert false ) ; *)
  let ctxa, out, str = send ctxa in
  let ctxb = recv ctxb out str in
  let ctxa, out, str = send ctxa in
  let ctxb = recv ctxb out str in
  let ctxa, out, str = send ctxa in
  let ctxb = recv ctxb out str in

  let ctxb, out, str = send ctxb in
  let ctxa = recv ctxa out str in
  let ctxa, out, str = send ctxa in
  let ctxb = recv ctxb out str in

  let ctxb, out, str = send ctxb in
  let ctxa = recv ctxa out str in
  let ctxa, out, str = send ctxa in
  let ctxb = recv ctxb out str in

  let ctxb, out, str = send ctxb in
  let ctxa = recv ctxa out str in
  let ctxa, out, str = send ctxa in
  let ctxb = recv ctxb out str in

  let ctxa, out, str = send ctxa in
  let ctxb = recv ctxb out str in
  let ctxa, out, str = send ctxa in
  let ctxb = recv ctxb out str in
  let ctxa, out, str = send ctxa in
  let ctxb = recv ctxb out str in

  let ctxb, out, str = send ctxb in
  let ctxa = recv ctxa out str in
  let ctxb, out, str = send ctxb in
  let ctxa = recv ctxa out str in
  let ctxb, out, str = send ctxb in
  let ctxa = recv ctxa out str in

  let ctxa, fin = end_otr ctxa in
(*  ( match ctxa.state.message_state with
    | MSGSTATE_PLAINTEXT -> ()
    | _ -> assert false ) ; *)
  assert (not (is_encrypted ctxa)) ;
  let fin = match fin with None -> assert false | Some x -> x in
  let ctxb, out, msg = handle ctxb fin in
  assert (out = None) ;
  ( match msg with
    | (`Warning x)::[] -> assert (x = "OTR connection lost")
    | _ -> assert false ) ;
  assert (not (is_encrypted ctxb))
(*  ( match ctxb.state.message_state with
    | MSGSTATE_FINISHED -> ()
    | _ -> assert false ) *)

let _ =
  for _i = 0 to 10 do
    start_session ()
  done
