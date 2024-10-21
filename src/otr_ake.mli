
type error =
  | Unknown of string
  | Unexpected of bool
  | VersionMismatch
  | InstanceMismatch

val dh_commit : Otr_state.session -> Otr_state.version list ->
  (Otr_state.session * string, error) result

val handle_auth : Otr_state.session -> string ->
  (Otr_state.session * string option * Otr_state.ret list, error) result
