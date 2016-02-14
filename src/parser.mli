type error =
  | Unknown       of string
  | Underflow
  | LeadingZero

include Control.Or_error with type err = error

type ret = [
  | `Data of Cstruct.t
  | `ParseError of string
  | `Error of string
  | `PlainTag of State.version list * string option
  | `Query of State.version list
  | `String of string
  | `Fragment_v2 of (int * int) * string
  | `Fragment_v3 of (int32 * int32) * (int * int) * string
]

val ret_of_sexp : Sexplib.Type.t -> ret
val sexp_of_ret : ret -> Sexplib.Type.t

val classify_input : string -> ret

val decode_data : Cstruct.t -> (Cstruct.t * Cstruct.t) or_error
val parse_gy : Cstruct.t -> Cstruct.t or_error
val parse_header : Cstruct.t -> (State.version * Packet.message_type * (int32 * int32) option * Cstruct.t) or_error
val parse_signature_data : Cstruct.t -> (Nocrypto.Dsa.pub * int32 * (Cstruct.t * Cstruct.t)) or_error
val parse_reveal : Cstruct.t -> (Cstruct.t * Cstruct.t * Cstruct.t) or_error
val parse_dh_commit : Cstruct.t -> (Cstruct.t * Cstruct.t) or_error
val parse_data : Cstruct.t -> (State.version * (int32 * int32) option * bool * int32 * int32 * Cstruct.t * int64 * Cstruct.t * Cstruct.t * Cstruct.t) or_error
val parse_data_body : Cstruct.t -> (bool * int32 * int32 * Cstruct.t * int64 * Cstruct.t * Cstruct.t * Cstruct.t) or_error

val parse_query : string -> (State.version list * string option) or_error

val parse_tlv : Cstruct.t -> (Packet.tlv_type option * Cstruct.t * Cstruct.t) or_error

val parse_datas : Cstruct.t -> int -> (Cstruct.t list) or_error
