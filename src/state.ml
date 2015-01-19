
open Sexplib.Conv

type ret = [
  | `Warning of string
  | `Received_error of string
  | `Received of string
  | `Established_encrypted_session of string
  | `Received_encrypted of string
  | `SMP_awaiting_secret
  | `SMP_received_question of string
  | `SMP_success
  | `SMP_failure
]

type dh_params = (Nocrypto.Dh.secret * Cstruct.t) with sexp

type encryption_keys = {
  dh          : dh_params ;
  previous_dh : dh_params ;
  our_keyid   : int32 ;
  our_ctr     : int64 ;
  gy          : Cstruct.t ;
  previous_gy : Cstruct.t ;
  their_keyid : int32 ;
  their_ctr   : int64 ;
} with sexp

type message_state = [
  | `MSGSTATE_PLAINTEXT
  | `MSGSTATE_ENCRYPTED of encryption_keys
  | `MSGSTATE_FINISHED
] with sexp

let message_state_to_string = function
  | `MSGSTATE_PLAINTEXT   -> "plain"
  | `MSGSTATE_ENCRYPTED _ -> "encrypted"
  | `MSGSTATE_FINISHED    -> "finished"

type auth_state =
  | AUTHSTATE_NONE
  | AUTHSTATE_AWAITING_DHKEY of Cstruct.t * Cstruct.t * dh_params * Cstruct.t
  | AUTHSTATE_AWAITING_REVEALSIG of dh_params * Cstruct.t
  | AUTHSTATE_AWAITING_SIG of Cstruct.t * (Cstruct.t * Cstruct.t * Cstruct.t * Cstruct.t) * dh_params * Cstruct.t
with sexp

let auth_state_to_string = function
  | AUTHSTATE_NONE                 -> "none"
  | AUTHSTATE_AWAITING_DHKEY _     -> "awaiting dh key"
  | AUTHSTATE_AWAITING_REVEALSIG _ -> "awaiting reveal signature"
  | AUTHSTATE_AWAITING_SIG _       -> "awaiting signature"

type smp_state =
  | SMPSTATE_WAIT_FOR_Y of Cstruct.t * Cstruct.t
  | SMPSTATE_EXPECT1
  | SMPSTATE_EXPECT2 of Cstruct.t * Nocrypto.Dh.secret * Nocrypto.Dh.secret
  | SMPSTATE_EXPECT3 of Cstruct.t * Cstruct.t * Cstruct.t * Nocrypto.Dh.secret * Cstruct.t * Cstruct.t
  | SMPSTATE_EXPECT4 of Cstruct.t * Cstruct.t * Cstruct.t * Nocrypto.Dh.secret
with sexp

let smp_state_to_string = function
  | SMPSTATE_WAIT_FOR_Y _ -> "waiting for secret"
  | SMPSTATE_EXPECT1      -> "expect 1"
  | SMPSTATE_EXPECT2 _    -> "expect 2"
  | SMPSTATE_EXPECT3 _    -> "expect 3"
  | SMPSTATE_EXPECT4 _    -> "expect 4"

type policy = [
  | `REQUIRE_ENCRYPTION
  | `SEND_WHITESPACE_TAG
  | `WHITESPACE_START_AKE
  | `ERROR_START_AKE
] with sexp

let policy_to_string = function
  | `REQUIRE_ENCRYPTION   -> "require encryption"
  | `SEND_WHITESPACE_TAG  -> "send whitespace tag"
  | `WHITESPACE_START_AKE -> "whitespace starts key exchange"
  | `ERROR_START_AKE      -> "error starts key exchange"

let all_policies = [ `REQUIRE_ENCRYPTION ; `SEND_WHITESPACE_TAG ; `WHITESPACE_START_AKE ; `ERROR_START_AKE ]

type version = [ `V2 | `V3 ] with sexp

let version_to_string = function
  | `V2 -> "version 2"
  | `V3 -> "version 3"

let all_versions = [ `V2 ; `V3 ]

type config = {
  policies : policy list ;
  versions : version list ;
  dsa      : Nocrypto.Dsa.priv ;
} with sexp

type state = {
  message_state : message_state ;
  auth_state    : auth_state ;
  smp_state     : smp_state ;
} with sexp

type session = {
  instances : (int32 * int32) option ;
  version : version ;
  state : state ;
  config : config ;
  their_dsa : Nocrypto.Dsa.pub option ;
  ssid : Cstruct.t ;
  high : bool ;
  fragments : ((int * int) * string) ;
} with sexp

let session_to_string s =
  let instances = match s.instances with
    | None -> ""
    | Some (x, y) ->
      Printf.sprintf ", instances: other %08lx, my %08lx" x y
  in
  let state = s.state in
  let version, auth_state, smp_state =
    let ver v = " " ^ version_to_string v in
    match state.message_state with
    | `MSGSTATE_PLAINTEXT when state.auth_state = AUTHSTATE_NONE -> ("", " (auth none)", "")
    | `MSGSTATE_PLAINTEXT -> (ver s.version, " (auth " ^ (auth_state_to_string state.auth_state) ^ ")", "")
    | `MSGSTATE_ENCRYPTED _ -> (ver s.version, "", " (smp " ^ (smp_state_to_string state.smp_state) ^ ")")
    | `MSGSTATE_FINISHED -> (ver s.version, "", "")
  in
  "state: " ^ (message_state_to_string s.state.message_state) ^ auth_state ^
  version ^ smp_state ^
  instances

let (<?>) ma b = match ma with None -> b | Some a -> a

let new_session config _ =
  let state = {
    message_state = `MSGSTATE_PLAINTEXT ;
    auth_state = AUTHSTATE_NONE ;
    smp_state = SMPSTATE_EXPECT1
  } in
  { instances = None ; version = `V3 ; state ; config ; their_dsa = None ;
    ssid = Cstruct.create 0 ; high = false ; fragments = ((0, 0), "") }

let empty_session ?policies ?versions ~dsa _ =
  let policies = policies <?> all_policies in
  let versions = versions <?> all_versions in
  let config = { policies ; versions ; dsa } in
  new_session config ()

let rst_frag ctx = { ctx with fragments = ((0, 0), "") }

let reset_session ctx =
  let cfg = ctx.config in
  empty_session ~policies:cfg.policies ~versions:cfg.versions ~dsa:cfg.dsa ()
