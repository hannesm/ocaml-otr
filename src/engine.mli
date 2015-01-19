open State

(** [start_otr ctx] is [ctx, out] where [out] should be sent to the communication partner. It initiates an OTR session. *)
val start_otr : session -> session * string

(** [send_otr ctx message] is [ctx, out, user] where [out] should be sent to the communication partner and [user] be presented to the user. The message is encrypted with the keys inside the session. *)
val send_otr : session -> string ->
  session * string option *
  [ `Warning of string | `Sent of string | `Sent_encrypted of string ]

(** [end_otr ctx] is [ctx, out] where [out] should be sent to the communication partner. It ends the session. *)
val end_otr : session -> session * string option

(** [handle ctx data] is [ctx, out, ret] where [out] should be sent to the communication partner, [ret] presented to the user. It decrypts and handles the data which came from the communication partner. *)
val handle : session -> string -> session * string option * ret list

(** [start_smp ctx ?question secret] is [ctx, out, ret] where [out] should be sent to the communication partner, [ret] presented to the user. It starts the socialists millionairs problem with the shared [secret] and possibly a [question]. *)
val start_smp : session -> ?question:string -> string -> session * string option * ret list

(** [abort_smp ctx] is [ctx, out, ret] where [out] should be sent to the communication patner, [ret] presented to the user. It aborts a running socialist millionairs problem. *)
val abort_smp : session -> session * string option * ret list

(** [answer_smp ctx secret] is [ctx, out, ret] where [out] should be sent to the communication partner, [ret] presented to the user. The [secret] is compared with the communication partners secret. *)
val answer_smp : session -> string -> session * string option * ret list
