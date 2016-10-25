
type error =
  | Unknown of string
  | Unexpected of bool
  | VersionMismatch
  | InstanceMismatch

type 'a result = ('a, error) Result.result

val dh_commit : Otr_state.session -> Otr_state.version list -> (Otr_state.session * Cstruct.t) result

val handle_auth : Otr_state.session -> Cstruct.t ->
  (Otr_state.session * Cstruct.t option * Otr_state.ret list) result
