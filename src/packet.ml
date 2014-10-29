
cenum message_type {
  DH_COMMIT        = 2 ;
  DH_KEY           = 0x0a ;
  REVEAL_SIGNATURE = 0x11 ;
  SIGNATURE        = 0x12 ;
} as uint8_t (sexp)

let int_of_version = function
  | `V2 -> 2
  | `V3 -> 3

let version_of_int = function
  | 2 -> Some `V2
  | 3 -> Some `V3
  | _ -> None
