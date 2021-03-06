type error =
  | Unknown of string
  | Underflow
  | LeadingZero

type ret = [
  | `Data of Cstruct.t
  | `ParseError of string
  | `Error of string
  | `PlainTag of Otr_state.version list * string option
  | `Query of Otr_state.version list
  | `String of string
  | `Fragment_v2 of (int * int) * string
  | `Fragment_v3 of (int32 * int32) * (int * int) * string
]

val classify_input : string -> ret

val decode_data : Cstruct.t -> (Cstruct.t * Cstruct.t, error) result
val parse_gy : Cstruct.t -> (Cstruct.t, error) result
val parse_header : Cstruct.t -> (Otr_state.version * Otr_packet.message_type * (int32 * int32) option * Cstruct.t, error) result
val parse_signature_data : Cstruct.t -> (Mirage_crypto_pk.Dsa.pub * int32 * (Cstruct.t * Cstruct.t), error) result
val parse_reveal : Cstruct.t -> (Cstruct.t * Cstruct.t * Cstruct.t, error) result
val parse_dh_commit : Cstruct.t -> (Cstruct.t * Cstruct.t, error) result
val parse_data : Cstruct.t -> (Otr_state.version * (int32 * int32) option * bool * int32 * int32 * Cstruct.t * int64 * Cstruct.t * Cstruct.t * Cstruct.t, error) result
val parse_data_body : Cstruct.t -> (bool * int32 * int32 * Cstruct.t * int64 * Cstruct.t * Cstruct.t * Cstruct.t, error) result

val parse_query : string -> (Otr_state.version list * string option, error) result

val parse_tlv : Cstruct.t -> (Otr_packet.tlv_type option * Cstruct.t * Cstruct.t, error) result

val parse_datas : Cstruct.t -> int -> (Cstruct.t list, error) result
