
val query_message : Otr_state.version list -> string
val tag : Otr_state.version list -> string
val encode_int : int32 -> Cstruct.t
val encode_data : Cstruct.t -> Cstruct.t
val dh_commit : Otr_state.version -> (int32 * int32) option -> Cstruct.t -> Cstruct.t -> Cstruct.t
val dh_key : Otr_state.version -> (int32 * int32) option -> Cstruct.t -> Cstruct.t
val reveal_signature : Otr_state.version -> (int32 * int32) option -> Cstruct.t -> Cstruct.t -> Cstruct.t -> Cstruct.t
val signature : Otr_state.version -> (int32 * int32) option -> Cstruct.t -> Cstruct.t -> Cstruct.t
val data : Otr_state.version -> (int32 * int32) option -> bool -> int32 -> int32 -> Cstruct.t -> int64 -> Cstruct.t -> Cstruct.t

val tlv : ?data:Cstruct.t list -> ?predata:Cstruct.t -> Otr_packet.tlv_type -> Cstruct.t
