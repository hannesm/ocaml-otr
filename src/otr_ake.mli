
type error =
  | Unknown of string
  | Unexpected of bool
  | VersionMismatch
  | InstanceMismatch

val dh_commit : Otr_state.session -> Otr_state.version list ->
  (Otr_state.session * Cstruct.t, error) result

val handle_auth : Otr_state.session -> Cstruct.t ->
  (Otr_state.session * Cstruct.t option * Otr_state.ret list, error) result
