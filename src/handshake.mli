open State

(** [start_otr ctx] is [ctx, out] where [out] should be sent to the communication partner *)
val start_otr : session -> session * string

(** [send_otr ctx message] is [ctx, out, user] where [out] sholuld be sent to the communication partner and [user] be presented to the user *)
val send_otr : session -> string -> session * string option * string option

(** [end_otr ctx] is [ctx, out] where [out] should be sent to the communication partner. *)
val end_otr : session -> session * string option

(** [handle ctx data] is [ctx, out, user, data] where [out] should be sent to the communication partner, [user] presented to the user, and [data] is the received decrypted data *)
val handle : session -> string -> session * string option * string option * string option
