
val query_message : State.version list -> string
val tag : State.version list -> string
val encode_int : int32 -> Cstruct.t
val encode_data : Cstruct.t -> Cstruct.t
val dh_commit : State.version -> (int32 * int32) option -> Cstruct.t -> Cstruct.t -> Cstruct.t
val dh_key : State.version -> (int32 * int32) option -> Cstruct.t -> Cstruct.t
val reveal_signature : State.version -> (int32 * int32) option -> Cstruct.t -> Cstruct.t -> Cstruct.t -> Cstruct.t
val signature : State.version -> (int32 * int32) option -> Cstruct.t -> Cstruct.t -> Cstruct.t
val data : State.version -> (int32 * int32) option -> int32 -> int32 -> Cstruct.t -> int64 -> Cstruct.t -> Cstruct.t
