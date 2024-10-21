
val mpi_gt : string -> string -> bool

module OtrDsa : sig
  val pub : p:string -> q:string -> gg:string -> y:string -> (Mirage_crypto_pk.Dsa.pub, [> `Msg of string ]) result
  val to_wire : ?notag:unit -> Mirage_crypto_pk.Dsa.pub -> string
  val fingerprint : Mirage_crypto_pk.Dsa.pub -> string
  val signature : key:Mirage_crypto_pk.Dsa.priv -> string -> string
  val verify : key:Mirage_crypto_pk.Dsa.pub -> string * string -> string -> bool
end

val derive_keys : string -> (string * string * string * string * string * string * string)
val data_keys : string -> bool -> (string * string * string * string)

val crypt : key:string -> ctr:int64 -> string -> string

val gen_symmetric_key : unit -> string

val hash : string -> string
val mac : key:string -> string list -> string
val mac160 : key:string -> string -> string
val sha1mac : key:string -> string -> string

val gen_dh_secret : unit -> (Mirage_crypto_pk.Dh.secret * string)
val dh_shared : Mirage_crypto_pk.Dh.secret -> string -> string option
val check_gy : string -> bool

val pow_s : string -> Mirage_crypto_pk.Dh.secret -> string
val mult_pow : string -> string -> string -> string

val proof_knowledge : Mirage_crypto_pk.Dh.secret -> int -> (string * string)
val check_proof : string -> string -> string -> int -> bool

val proof_equal_coords : string -> string -> Mirage_crypto_pk.Dh.secret -> string -> int -> (string * string * string)
val check_equal_coords : string -> string -> string -> string -> string -> string -> string -> int -> bool

val proof_eq_logs : string -> Mirage_crypto_pk.Dh.secret -> int -> string * string
val check_eq_logs : string -> string -> string -> string -> string -> int -> bool

val compute_p : string -> string -> string

val prepare_secret : string -> string -> string -> string -> string
