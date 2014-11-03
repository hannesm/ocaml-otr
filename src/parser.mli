type error =
  | TrailingBytes of string
  | WrongLength   of string
  | Unknown       of string
  | Underflow

include Control.Or_error with type err = error

type ret = [
  | `Data of Cstruct.t * string option
  | `ParseError of string * string
  | `Error of string * string option
  | `PlainTag of State.version list * string option
  | `Query of State.version list * string option
  | `String of string
]

val classify_input : string -> ret

val decode_data : Cstruct.t -> (Cstruct.t * Cstruct.t)
val parse_header : Cstruct.t -> (State.version * Packet.message_type * (int32 * int32) option * Cstruct.t) or_error
val parse_signature_data : Cstruct.t -> ((Cstruct.t * Cstruct.t * Cstruct.t * Cstruct.t) * int32 * (Cstruct.t * Cstruct.t))
val parse_reveal : Cstruct.t -> (Cstruct.t * Cstruct.t * Cstruct.t)
val parse_dh_commit : Cstruct.t -> (Cstruct.t * Cstruct.t)
val parse_check_data : State.version -> (int32 * int32) option -> Cstruct.t -> (int * int32 * int32 * Cstruct.t * int64 * Cstruct.t * Cstruct.t * Cstruct.t) or_error

val parse_query : string -> (State.version list * string option) or_error
