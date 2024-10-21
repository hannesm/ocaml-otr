type error =
  | Unknown of string
  | Underflow
  | LeadingZero

type ret = [
  | `Data of string
  | `ParseError of string
  | `Error of string
  | `PlainTag of Otr_state.version list * string option
  | `Query of Otr_state.version list
  | `String of string
  | `Fragment_v2 of (int * int) * string
  | `Fragment_v3 of (int32 * int32) * (int * int) * string
]

val classify_input : string -> ret

val decode_data : string -> (string * string, error) result
val parse_gy : string -> (string, error) result
val parse_header : string -> (Otr_state.version * Otr_packet.message_type * (int32 * int32) option * string, error) result
val parse_signature_data : string -> (Mirage_crypto_pk.Dsa.pub * int32 * (string * string), error) result
val parse_reveal : string -> (string * string * string, error) result
val parse_dh_commit : string -> (string * string, error) result
val parse_data : string -> (Otr_state.version * (int32 * int32) option * bool * int32 * int32 * string * int64 * string * string * string, error) result
val parse_data_body : string -> (bool * int32 * int32 * string * int64 * string * string * string, error) result

val parse_query : string -> (Otr_state.version list * string option, error) result

val parse_tlv : string -> (Otr_packet.tlv_type option * string * string, error) result

val parse_datas : string -> int -> (string list, error) result
