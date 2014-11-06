

val start_otr : State.session -> State.session * string

val send_otr : State.session -> string -> State.session * string list * string option

val end_otr : State.session -> State.session * string list * string option

val handle : State.session -> string -> State.session * string option * string option * string option * string option
