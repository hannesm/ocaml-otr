
open State

let fingerprint x =
  let fp = Crypto.OtrDsa.fingerprint x in
  Cstruct.to_string fp

let their_fingerprint ctx =
  match ctx.state.message_state with
  | MSGSTATE_ENCRYPTED enc -> Some (fingerprint enc.their_dsa)
  | _ -> None

let own_fingerprint config =
  fingerprint (Nocrypto.Dsa.pub_of_priv config.dsa)
