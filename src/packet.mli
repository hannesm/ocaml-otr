[%%cenum
type message_type =
    | DH_COMMIT [@id 2]
    | DATA [@id 3]
    | DH_KEY [@id 0x0a]
    | REVEAL_SIGNATURE [@id 0x11]
    | SIGNATURE [@id 0x12]
  [@@uint8_t] [@@sexp]
]

[%%cenum
type tlv_type =
  | PADDING [@id 0]
  | DISCONNECTED [@id 1]
  | SMP_MESSAGE_1 [@id 2]
  | SMP_MESSAGE_2 [@id 3]
  | SMP_MESSAGE_3 [@id 4]
  | SMP_MESSAGE_4 [@id 5]
  | SMP_ABORT [@id 6]
  | SMP_MESSAGE_1Q [@id 7]
  | EXTRA_SYMMETRIC_KEY [@id 8]
  [@@uint16_t] [@@sexp]
]

val int_of_version : State.version -> int

val version_of_int : int -> State.version option
