
type keyblock = {
  ssid : Cstruct.t ;
  c    : Cstruct.t ;
  c'   : Cstruct.t ;
  m1   : Cstruct.t ;
  m2   : Cstruct.t ;
  m1'  : Cstruct.t ;
  m2'  : Cstruct.t ;
}

type dh_params = {
  secret : Nocrypto.Dh.secret ;
  gx     : Cstruct.t ;
  gy     : Cstruct.t
}

type message_state =
  | MSGSTATE_PLAINTEXT
  | MSGSTATE_ENCRYPTED
  | MSGSTATE_FINISHED

type auth_state =
  | AUTHSTATE_NONE
  | AUTHSTATE_AWAITING_DHKEY of Cstruct.t * Cstruct.t * dh_params * Cstruct.t
  | AUTHSTATE_AWAITING_REVEALSIG of dh_params * Cstruct.t
  | AUTHSTATE_AWAITING_SIG of Cstruct.t * keyblock * dh_params

type policy = [
  | `REQUIRE_ENCRYPTION
  | `SEND_WHITESPACE_TAG
  | `WHITESPACE_START_AKE
  | `ERROR_START_AKE
]

type version = [ `V2 | `V3 ]

type config = {
  policies : policy list ;
  versions : version list ;
  dsa      : Nocrypto.Dsa.priv ;
}

type state = {
  message_state : message_state ;
  auth_state    : auth_state ;
}

type session = {
  instances : (int32 * int32) option ;
  version : version ;
  state : state ;
  config : config ;
}

let (<?>) ma b = match ma with None -> b | Some a -> a

let empty_session ?policies ?versions ~dsa () =
  let policies = policies <?> [] in
  let versions = versions <?> [`V3 ; `V2] in
  let config = { policies ; versions ; dsa } in
  let state = { message_state = MSGSTATE_PLAINTEXT ; auth_state = AUTHSTATE_NONE } in
  { instances = None ; version = `V3 ; state ; config }
