
type error =
  | UnexpectedMessage
  | InvalidZeroKnowledgeProof

val error_to_string : error -> string

val start_smp : Mirage_crypto_pk.Dsa.priv -> Otr_state.enc_data -> Otr_state.smp_state -> ?question:string -> string -> (Otr_state.smp_state * Cstruct.t option, error) result

val abort_smp : Otr_state.smp_state -> (Otr_state.smp_state * Cstruct.t option, error) result

val handle_smp : Otr_state.smp_state -> Otr_packet.tlv_type -> Cstruct.t -> (Otr_state.smp_state * Cstruct.t option * Otr_state.ret list, error) result

val handle_secret : Mirage_crypto_pk.Dsa.priv -> Otr_state.enc_data -> Otr_state.smp_state -> string -> (Otr_state.smp_state * Cstruct.t option, error) result
