
val dh_commit : State.session -> State.version list -> (State.session * Cstruct.t list)
val handle_auth : State.session -> Cstruct.t -> (State.session * Cstruct.t list * string option)
