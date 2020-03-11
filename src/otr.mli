(** Off-the-Record, in pure OCaml

    Off-the-Record (OTR) ({{:https://otr.cypherpunks.ca/otr-wpes.pdf}
    developed by Goldberg et al.}) is a cryptographic protocol used in
    instant messaging.  It provides both authentication (using
    long-term 1024 bit DSA keys), and encryption (using AES 128 in
    counter mode).  An authenticated Diffie-Hellman key exchange (with
    1536 bit {{:https://tools.ietf.org/html/rfc3526#section-2}Oakley5}
    group) establishes the shared secrets (providing forward secrecy).

    The
    {{:https://en.wikipedia.org/wiki/Socialist_millionaire}socialist
    millionaire problem} (SMP) allows in-band verification of the
    long-term DSA keys using a shared secret and zero knowledge
    proofs.

    This implementation covers both protocol
    {{:https://otr.cypherpunks.ca/Protocol-v2-3.1.0.html}version 2}
    and {{:https://otr.cypherpunks.ca/Protocol-v3-4.0.0.html}version
    3}, and implements the socialist millionairs problem.  {!State}
    defines configuration and types, {!Engine} processing of incoming
    and outgoing messages as well as initiation and teardown of
    sessions and socialist millionairs problem, and {!Utils} provides
    basic fingerprint utilities as defined in the OTR
    specification.

    {e %%VERSION%% - {{:%%PKG_HOMEPAGE%% }homepage}}
 *)

(** States and types *)
module State : sig

  (** {2 Type definitions and predicates} *)

  (** Return values of functions in the {!Engine} module. *)
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

  (** OTR policies, as defined in the protocol. *)
  type policy = [
    | `REQUIRE_ENCRYPTION
    | `SEND_WHITESPACE_TAG
    | `WHITESPACE_START_AKE
    | `ERROR_START_AKE
    | `REVEAL_MACS
  ]

  val sexp_of_policy : policy -> Sexplib.Sexp.t
  val policy_of_sexp : Sexplib.Sexp.t -> policy

  (** [policy_to_string policy] is [string], the string representation
      of the given [policy]. *)
  val policy_to_string : policy -> string

  (** [string_to_policy string] is [policy], the [policy] matching the
      string ([None] if none matches). *)
  val string_to_policy : string -> policy option

  (** [all_policies] returns a list of all defined policies. *)
  val all_policies : policy list

  (** OTR protocol versions supported by this library *)
  type version = [ `V2 | `V3 ]

  val sexp_of_version : version -> Sexplib.Sexp.t
  val version_of_sexp : Sexplib.Sexp.t -> version

  (** [version_to_string version] is [string], the string
     representation of the [version]. *)
  val version_to_string : version -> string

  (** [string_to_version string] is [version], the [version] matching
      the string ([None] if none matches). *)
  val string_to_version : string -> version option

  (** [all_versions] returns a list of all supported versions. *)
  val all_versions : version list

  (** OTR configuration consisting of a set of policies and versions. *)
  type config = {
    policies : policy list ;
    versions : version list ;
  }

  val sexp_of_config : config -> Sexplib.Sexp.t
  val config_of_sexp : Sexplib.Sexp.t -> config

  (** [config versions policies] is [config], the configuration with
      the given [versions] and [policies]. *)
  val config : version list -> policy list -> config

  (** An abstract OTR session *)
  type session

  (** [session_to_string session] is [string], the string
      representation of the [session]. *)
  val session_to_string : session -> string

  (** [version session] is [version], the current active protocol
      version of this [session]. *)
  val version : session -> version

  (** [is_encrypted session] is [true] if the session is
      established. *)
  val is_encrypted : session -> bool

  (** [their_dsa session] is [dsa], the public DSA key used by the
      communication partner (if the session is established). *)
  val their_dsa : session -> Mirage_crypto_pk.Dsa.pub option

  (** [new_session configuration dsa ()] is [session], a fresh session given
      the [configuration] and [dsa] private key. *)
  val new_session : config -> Mirage_crypto_pk.Dsa.priv -> unit -> session

  (** [update_config config session] is [session], the [session]
      adjusted to the [config].  Note: the [session] might not conform
      to the config anymore! *)
  val update_config : config -> session -> session
end

(** Message processing *)
module Engine : sig

  (** {2 Message processing} *)

  (** Either when an OTR session should be established, or if a
      message containing OTR data is received, the corresponding
      function should be called to decrypt or encrypt the OTR data, or
      initiate a handshake. *)

  (** [start_otr session] is [session', out], which initiates an OTR
      session. [out] should be sent to the communication partner,
      [session'] used in further API calls.  The [session] is reset,
      and [out] contains an OTR query message (content depends on the
      configured {!State.version}). *)
  val start_otr : State.session -> State.session * string

  (** [send_otr session message] is [session', out, user_data], where
      [out] should be sent to the communication partner and
      [user_data] be presented to the user.  Depending on the current
      [session] state and configured {!State.policy}, [out] can be
      encrypted, or the initiation of an OTR session, or the plain
      text.  [session'] should be used in subsequent API calls.
      [user_data] contains more information on what happened with
      [message] (whether it was sent in plain, encrypted, or not at
      all). *)
  val send_otr : State.session -> string ->
    State.session * string option *
    [ `Warning of string | `Sent of string | `Sent_encrypted of string ]

  (** [end_otr session] is [session', out], which ends the OTR
      session. [out] should be sent to the communication partner,
      [session'] should be used in subsequent calls. *)
  val end_otr : State.session -> State.session * string option

  (** [handle session data] is [session', out, ret], which handles
      received data. [out] should be sent to the communication partner
      (might contain data to complete a handshake), [ret] should be
      presented to the user. [handle] potentially decrypts the
      incoming message, or proceeds in the handshake setup.
      [session'] should be used in subsequent calls. *)
  val handle : State.session -> string -> State.session * string option * State.ret list

  (** [start_smp session ~question shared_secret] is
      [session', out, ret], which starts the
      {{:https://en.wikipedia.org/wiki/Socialist_millionaire}
      socialist millionairs problem} if the [session] is already
      established, using potentially the [question] and
      [shared_secret]. [out] should be sent to the communication
      partner, and [ret] presented to the user.  [session'] should be
      used in subsequent calls. *)
  val start_smp : State.session -> ?question:string -> string -> State.session * string option * State.ret list

  (** [abort_smp session] is [session', out, ret], which aborts an
      unfinished SMP.  [out] should be sent to the communication
      patner, and [ret] presented to the user.  [session'] should be used
      in subsequent calls. *)
  val abort_smp : State.session -> State.session * string option * State.ret list

  (** [answer_smp session secret] is [session', out, ret], which
      answers the SMP.  [out] should be sent to the communication
      partner, and [ret] presented to the user. The given [secret] is
      compared (in a zero-knowledge style) with the communication
      partners secret.  [session'] should be used in subsequent
      calls. *)
  val answer_smp : State.session -> string -> State.session * string option * State.ret list
end

(** Utilities *)
module Utils : sig
  (** {2 Fingerprint Utilities} *)

  (** An OTR fingerprint is the [`SHA1] hash of the public key
      prepended with the key type. *)

  (** [their_fingerprint session] is [fp], the fingerprint of the
      communication partner ([None] if no session is established).  *)
  val their_fingerprint : State.session -> string option

  (** [own_fingerprint dsa] is [fp], the fingerprint of the private
      DSA key. *)
  val own_fingerprint : Mirage_crypto_pk.Dsa.priv -> string
end
