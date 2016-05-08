
type error =
  | UnexpectedMessage
  | InvalidZeroKnowledgeProof

val error_to_string : error -> string

type 'a result = ('a, error) Result.result

val start_smp : Nocrypto.Dsa.priv -> State.enc_data -> State.smp_state -> ?question:string -> string -> (State.smp_state * Cstruct.t option) result

val abort_smp : State.smp_state -> (State.smp_state * Cstruct.t option) result

val handle_smp : State.smp_state -> Packet.tlv_type -> Cstruct.t -> (State.smp_state * Cstruct.t option * State.ret list) result

val handle_secret : Nocrypto.Dsa.priv -> State.enc_data -> State.smp_state -> string -> (State.smp_state * Cstruct.t option) result
