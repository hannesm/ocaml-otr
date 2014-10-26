
cenum message_type {
  DH_COMMIT        = 2 ;
  DH_KEY           = 0x0a ;
  REVEAL_SIGNATURE = 0x11 ;
  SIGNATURE        = 0x12 ;
} as uint8_t (sexp)

cenum packet_version {
  V2 = 2 ;
  V3 = 3 ;
} as uint16_t (sexp)

let packet_version_of_version = function
  | `V2 -> V2
  | `V3 -> V3

let version_of_packet_version = function
  | V2 -> `V2
  | V3 -> `V3
