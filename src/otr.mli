
module State : sig

  (** possible return values from engine functions *)
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

  (** OTR configurable policies *)
  type policy = [
    | `REQUIRE_ENCRYPTION
    | `SEND_WHITESPACE_TAG
    | `WHITESPACE_START_AKE
    | `ERROR_START_AKE
    | `REVEAL_MACS
  ] with sexp

  (** returns a string given a policy *)
  val policy_to_string : policy -> string

  (** returns a policy option given a string *)
  val string_to_policy : string -> policy option

  (** returns a list of all available policies *)
  val all_policies : policy list

  (** OTR protocol versions *)
  type version = [ `V2 | `V3 ] with sexp

  (** return a string given a version *)
  val version_to_string : version -> string

  (** return a version option given a string *)
  val string_to_version : string -> version option

  (** returns a list of all available versions *)
  val all_versions : version list

  (** some otr session *)
  type session

  (** an otr config *)
  type config = {
    policies : policy list ;
    versions : version list ;
  } with sexp

  (** config constructor, given a version list, policy list and DSA private key *)
  val config : version list -> policy list -> config

  (** [update_config config session] is [session], the [session]
  adjusted to the [config].  The [session] might not conform to the
  config anymore! *)
  val update_config : config -> session -> session

  (** returns the spoken protocol version in this session *)
  val version : session -> version

  (** string representation of a session *)
  val session_to_string : session -> string

  (** creates a new session given a configuration *)
  val new_session : config -> Nocrypto.Dsa.priv -> unit -> session

  (** returns whether the session is in encryption state *)
  val is_encrypted : session -> bool

  (** returns the DSA public key used by the communication partner (if session is encrypted) *)
  val their_dsa : session -> Nocrypto.Dsa.pub option
end

module Engine : sig
  (** [start_otr ctx] is [ctx, out] where [out] should be sent to the communication partner. It initiates an OTR session. *)
  val start_otr : State.session -> State.session * string

  (** [send_otr ctx message] is [ctx, out, user] where [out] should be sent to the communication partner and [user] be presented to the user. The message is encrypted with the keys inside the session. *)
  val send_otr : State.session -> string ->
    State.session * string option *
    [ `Warning of string | `Sent of string | `Sent_encrypted of string ]

  (** [end_otr ctx] is [ctx, out] where [out] should be sent to the communication partner. It ends the session. *)
  val end_otr : State.session -> State.session * string option

  (** [handle ctx data] is [ctx, out, ret] where [out] should be sent to the communication partner, [ret] presented to the user. It decrypts and handles the data which came from the communication partner. *)
  val handle : State.session -> string -> State.session * string option * State.ret list

  (** [start_smp ctx ?question secret] is [ctx, out, ret] where [out] should be sent to the communication partner, [ret] presented to the user. It starts the socialists millionairs problem with the shared [secret] and possibly a [question]. *)
  val start_smp : State.session -> ?question:string -> string -> State.session * string option * State.ret list

  (** [abort_smp ctx] is [ctx, out, ret] where [out] should be sent to the communication patner, [ret] presented to the user. It aborts a running socialist millionairs problem. *)
  val abort_smp : State.session -> State.session * string option * State.ret list

  (** [answer_smp ctx secret] is [ctx, out, ret] where [out] should be sent to the communication partner, [ret] presented to the user. The [secret] is compared with the communication partners secret. *)
  val answer_smp : State.session -> string -> State.session * string option * State.ret list
end

module Utils : sig
  (** returns the fingerprint of the communication partner if the session is encrypted *)
  val their_fingerprint : State.session -> string option

  (** returns the own fingerprint of the DSA key in the configuration *)
  val own_fingerprint : Nocrypto.Dsa.priv -> string
end
