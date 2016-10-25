
type error =
  | UnexpectedMessage
  | InvalidZeroKnowledgeProof

val error_to_string : error -> string

type 'a result = ('a, error) Result.result

val start_smp : Nocrypto.Dsa.priv -> Otr_state.enc_data -> Otr_state.smp_state -> ?question:string -> string -> (Otr_state.smp_state * Cstruct.t option) result

val abort_smp : Otr_state.smp_state -> (Otr_state.smp_state * Cstruct.t option) result

val handle_smp : Otr_state.smp_state -> Otr_packet.tlv_type -> Cstruct.t -> (Otr_state.smp_state * Cstruct.t option * Otr_state.ret list) result

val handle_secret : Nocrypto.Dsa.priv -> Otr_state.enc_data -> Otr_state.smp_state -> string -> (Otr_state.smp_state * Cstruct.t option) result
