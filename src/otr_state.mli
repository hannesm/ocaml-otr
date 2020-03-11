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

type dh_params = (Mirage_crypto_pk.Dh.secret * Cstruct.t)

type dh_keys = {
  dh          : dh_params ;
  previous_dh : dh_params ;
  our_keyid   : int32 ;
  gy          : Cstruct.t ;
  previous_gy : Cstruct.t ;
  their_keyid : int32 ;
}

type symmetric_keys = {
  send_aes : Cstruct.t ;
  send_mac : Cstruct.t ;
  send_ctr : int64 ;
  recv_aes : Cstruct.t ;
  recv_mac : Cstruct.t ;
  recv_ctr : int64 ;
}

type symms = (int32 * int32 * symmetric_keys) list

type enc_data = {
  dh_keys   : dh_keys ;
  symms     : symms ;
  their_dsa : Mirage_crypto_pk.Dsa.pub ;
  ssid      : Cstruct.t ;
  high      : bool ;
}

type message_state =
  | MSGSTATE_PLAINTEXT
  | MSGSTATE_ENCRYPTED of enc_data
  | MSGSTATE_FINISHED

type auth_state =
  | AUTHSTATE_NONE
  | AUTHSTATE_AWAITING_DHKEY of Cstruct.t * Cstruct.t * dh_params * Cstruct.t
  | AUTHSTATE_AWAITING_REVEALSIG of dh_params * Cstruct.t
  | AUTHSTATE_AWAITING_SIG of Cstruct.t * (Cstruct.t * Cstruct.t * Cstruct.t * Cstruct.t) * dh_params * Cstruct.t

type smp_state =
  | SMPSTATE_WAIT_FOR_Y of Cstruct.t * Cstruct.t
  | SMPSTATE_EXPECT1
  | SMPSTATE_EXPECT2 of Cstruct.t * Mirage_crypto_pk.Dh.secret * Mirage_crypto_pk.Dh.secret
  | SMPSTATE_EXPECT3 of Cstruct.t * Cstruct.t * Cstruct.t * Mirage_crypto_pk.Dh.secret * Cstruct.t * Cstruct.t
  | SMPSTATE_EXPECT4 of Cstruct.t * Cstruct.t * Cstruct.t * Mirage_crypto_pk.Dh.secret

type policy = [
  | `REQUIRE_ENCRYPTION
  | `SEND_WHITESPACE_TAG
  | `WHITESPACE_START_AKE
  | `ERROR_START_AKE
  | `REVEAL_MACS
]

val sexp_of_policy : policy -> Sexplib.Sexp.t
val policy_of_sexp : Sexplib.Sexp.t -> policy

val policy_to_string : policy -> string

val string_to_policy : string -> policy option

val all_policies : policy list

type version = [ `V2 | `V3 ]

val sexp_of_version : version -> Sexplib.Sexp.t
val version_of_sexp : Sexplib.Sexp.t -> version

val version_to_string : version -> string

val string_to_version : string -> version option

val all_versions : version list

type config = {
  policies : policy list ;
  versions : version list ;
}

val sexp_of_config : config -> Sexplib.Sexp.t
val config_of_sexp : Sexplib.Sexp.t -> config

val config : version list -> policy list -> config

type state = {
  message_state : message_state ;
  auth_state    : auth_state ;
  smp_state     : smp_state ;
}

type session = {
  instances : (int32 * int32) option ;
  version : version ;
  state : state ;
  config : config ;
  dsa : Mirage_crypto_pk.Dsa.priv ;
  fragments : ((int * int) * string) ;
}

val rst_frag : session -> session

val reset_session : session -> session

val reveal_macs : session -> bool

val session_to_string : session -> string

val version : session -> version

val is_encrypted : session -> bool

val their_dsa : session -> Mirage_crypto_pk.Dsa.pub option

val new_session : config -> Mirage_crypto_pk.Dsa.priv -> unit -> session

val update_config : config -> session -> session

val tag_prefix : string
val tag_v2 : string
val tag_v3 : string
val otr_prefix : string
val otr_mark : string
val otr_err_mark : string
val otr_v2_frag : string
val otr_v3_frag : string
