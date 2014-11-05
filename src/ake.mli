
include Control.Or_error with type err = string

val dh_commit : State.session -> State.version list -> (State.session * Cstruct.t list) or_error
val handle_auth : State.session -> Cstruct.t -> (State.session * Cstruct.t list * string option) or_error
