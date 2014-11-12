
cenum message_type {
  DH_COMMIT        = 2 ;
  DATA             = 3 ;
  DH_KEY           = 0x0a ;
  REVEAL_SIGNATURE = 0x11 ;
  SIGNATURE        = 0x12 ;
} as uint8_t (sexp)

cenum tlv_type {
  PADDING = 0 ;
  DISCONNECTED = 1 ;
  SMP_MESSAGE_1 = 2 ;
  SMP_MESSAGE_2 = 3 ;
  SMP_MESSAGE_3 = 4 ;
  SMP_MESSAGE_4 = 5 ;
  SMP_ABORT = 6 ;
  SMP_MESSAGE_1Q = 7 ;
  EXTRA_SYMMETRIC_KEY = 8
} as uint16_t (sexp)

let int_of_version = function
  | `V2 -> 2
  | `V3 -> 3

let version_of_int = function
  | 2 -> Some `V2
  | 3 -> Some `V3
  | _ -> None
