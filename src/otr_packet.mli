
type message_type =
    | DH_COMMIT
    | DATA
    | DH_KEY
    | REVEAL_SIGNATURE
    | SIGNATURE

val message_type_to_int : message_type -> int
val int_to_message_type : int -> message_type option

type tlv_type =
  | PADDING
  | DISCONNECTED
  | SMP_MESSAGE_1
  | SMP_MESSAGE_2
  | SMP_MESSAGE_3
  | SMP_MESSAGE_4
  | SMP_ABORT
  | SMP_MESSAGE_1Q
  | EXTRA_SYMMETRIC_KEY

val tlv_type_to_int : tlv_type -> int
val int_to_tlv_type : int -> tlv_type option
