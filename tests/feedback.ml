

open Otr.State
open Otr.Handshake

let start_session _ =
  let buf = Cstruct.create 16 in
  Nocrypto.Rng.reseed buf ;
  let keya = Nocrypto.Dsa.generate `Fips1024 in
  let keyb = Nocrypto.Dsa.generate `Fips1024 in
  let ctxa = empty_session ~dsa:keya () in
  let ctxb = empty_session ~dsa:keyb () in
  let ctxa, query = start_otr ctxa in
  let ctxb, out, msg = handle ctxb query in
  (* dh_commit *)
  assert (List.length msg = 0) ;
  ( match ctxb.state.auth_state with
    | AUTHSTATE_AWAITING_DHKEY _ -> ()
    | _ -> assert false );
  let out = match out with None -> assert false | Some x -> x in
  let ctxa, out, msg = handle ctxa out in
  (* dh_key *)
  assert (List.length msg = 0) ;
  ( match ctxa.state.auth_state with
    | AUTHSTATE_AWAITING_REVEALSIG _ -> ()
    | _ -> assert false );
  let out = match out with None -> assert false | Some x -> x in
  let ctxb, out, msg = handle ctxb out in
  (* reveal_sig *)
  assert (List.length msg = 0) ;
  ( match ctxb.state.auth_state with
    | AUTHSTATE_AWAITING_SIG _ -> ()
    | _ -> assert false );
  let out = match out with None -> assert false | Some x -> x in
  let ctxa, out, msg = handle ctxa out in
  (* sig *)
  assert (List.length msg = 1) ;
  assert (ctxa.state.auth_state = AUTHSTATE_NONE) ;
  (match ctxa.state.message_state with
  | `MSGSTATE_ENCRYPTED _ -> ()
  | _ -> assert false );
  let out = match out with None -> assert false | Some x -> x in
  let ctxb, out, msg = handle ctxb out in
  (* finished *)
  assert (List.length msg = 1) ;
  assert (ctxb.state.auth_state = AUTHSTATE_NONE) ;
  match ctxb.state.message_state with
  | `MSGSTATE_ENCRYPTED _ -> ()
  | _ -> assert false

let _ =
  for i = 0 to 10 do
    start_session ()
  done
