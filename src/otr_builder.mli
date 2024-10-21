
val query_message : Otr_state.version list -> string
val tag : Otr_state.version list -> string
val encode_int : int32 -> string
val encode_data : string -> string
val dh_commit : Otr_state.version -> (int32 * int32) option -> string -> string -> string
val dh_key : Otr_state.version -> (int32 * int32) option -> string -> string
val reveal_signature : Otr_state.version -> (int32 * int32) option -> string -> string -> string -> string
val signature : Otr_state.version -> (int32 * int32) option -> string -> string -> string
val data : Otr_state.version -> (int32 * int32) option -> bool -> int32 -> int32 -> string -> int64 -> string -> string

val tlv : ?data:string list -> ?predata:string -> Otr_packet.tlv_type -> string
