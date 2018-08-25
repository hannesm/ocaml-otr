
type message_type =
    | DH_COMMIT
    | DATA
    | DH_KEY
    | REVEAL_SIGNATURE
    | SIGNATURE

let message_type_to_int = function
  | DH_COMMIT -> 2
  | DATA -> 3
  | DH_KEY -> 0x0a
  | REVEAL_SIGNATURE -> 0x11
  | SIGNATURE -> 0x12

let int_to_message_type = function
  | 2 -> Some DH_COMMIT
  | 3 -> Some DATA
  | 0x0a -> Some DH_KEY
  | 0x11 -> Some REVEAL_SIGNATURE
  | 0x12 -> Some SIGNATURE
  | _ -> None

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

let tlv_type_to_int = function
  | PADDING -> 0
  | DISCONNECTED -> 1
  | SMP_MESSAGE_1 -> 2
  | SMP_MESSAGE_2 -> 3
  | SMP_MESSAGE_3 -> 4
  | SMP_MESSAGE_4 -> 5
  | SMP_ABORT -> 6
  | SMP_MESSAGE_1Q -> 7
  | EXTRA_SYMMETRIC_KEY -> 8

let int_to_tlv_type = function
  | 0 -> Some PADDING
  | 1 -> Some DISCONNECTED
  | 2 -> Some SMP_MESSAGE_1
  | 3 -> Some SMP_MESSAGE_2
  | 4 -> Some SMP_MESSAGE_3
  | 5 -> Some SMP_MESSAGE_4
  | 6 -> Some SMP_ABORT
  | 7 -> Some SMP_MESSAGE_1Q
  | 8 -> Some EXTRA_SYMMETRIC_KEY
  | _ -> None
