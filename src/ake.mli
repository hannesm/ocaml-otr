
type error =
  | Unknown of string
  | Unexpected of bool
  | VersionMismatch
  | InstanceMismatch

type 'a result = ('a, error) Result.result

val dh_commit : State.session -> State.version list -> (State.session * Cstruct.t) result

val handle_auth : State.session -> Cstruct.t ->
  (State.session * Cstruct.t option * State.ret list) result
