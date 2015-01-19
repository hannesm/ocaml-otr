open State

(** [start_otr ctx] is [ctx, out] where [out] should be sent to the communication partner *)
val start_otr : session -> session * string

(** [send_otr ctx message] is [ctx, out, user] where [out] should be sent to the communication partner and [user] be presented to the user *)
val send_otr : session -> string ->
  session * string option *
  [ `Warning of string | `Sent of string | `Sent_encrypted of string ]

(** [end_otr ctx] is [ctx, out] where [out] should be sent to the communication partner. *)
val end_otr : session -> session * string option

(** [handle ctx data] is [ctx, out, ret] where [out] should be sent to the communication partner, [ret] presented to the user. *)
val handle : session -> string -> session * string option * ret list
