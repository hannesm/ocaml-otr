
type error =
  | UnexpectedMessage
  | InvalidZeroKnowledgeProof

val error_to_string : error -> string

include Control.Or_error with type err = error

val start_smp : State.session -> ?question:string -> string -> (State.smp_state * Cstruct.t option) or_error

val abort_smp : State.smp_state -> (State.smp_state * Cstruct.t option) or_error

val handle_smp : State.smp_state -> Packet.tlv_type -> Cstruct.t -> (State.smp_state * Cstruct.t option * State.ret list) or_error

val handle_secret : State.session -> string -> (State.smp_state * Cstruct.t option) or_error
