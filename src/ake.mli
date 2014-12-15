
type error =
  | Unknown of string
  | Unexpected of bool
  | VersionMismatch
  | InstanceMismatch

include Control.Or_error with type err = error

val dh_commit : State.session -> State.version list -> (State.session * Cstruct.t) or_error
val handle_auth : State.session -> Cstruct.t ->
  (State.session * Cstruct.t option * State.ret list) or_error
