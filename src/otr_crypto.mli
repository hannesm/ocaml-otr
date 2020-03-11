
val mpi_gt : Cstruct.t -> Cstruct.t -> bool

module OtrDsa : sig
  val pub : p:Cstruct.t -> q:Cstruct.t -> gg:Cstruct.t -> y:Cstruct.t -> (Mirage_crypto_pk.Dsa.pub, [> `Msg of string ]) result
  val to_wire : ?notag:unit -> Mirage_crypto_pk.Dsa.pub -> Cstruct.t
  val fingerprint : Mirage_crypto_pk.Dsa.pub -> Cstruct.t
  val signature : key:Mirage_crypto_pk.Dsa.priv -> Cstruct.t -> Cstruct.t
  val verify : key:Mirage_crypto_pk.Dsa.pub -> Cstruct.t * Cstruct.t -> Cstruct.t -> bool
end

val derive_keys : Cstruct.t -> (Cstruct.t * Cstruct.t * Cstruct.t * Cstruct.t * Cstruct.t * Cstruct.t * Cstruct.t)
val data_keys : Cstruct.t -> bool -> (Cstruct.t * Cstruct.t * Cstruct.t * Cstruct.t)

val crypt : key:Cstruct.t -> ctr:int64 -> Cstruct.t -> Cstruct.t

val gen_symmetric_key : unit -> Cstruct.t

val hash : Cstruct.t -> Cstruct.t
val mac : key:Cstruct.t -> Cstruct.t list -> Cstruct.t
val mac160 : key:Cstruct.t -> Cstruct.t -> Cstruct.t
val sha1mac : key:Cstruct.t -> Cstruct.t -> Cstruct.t

val gen_dh_secret : unit -> (Mirage_crypto_pk.Dh.secret * Cstruct.t)
val dh_shared : Mirage_crypto_pk.Dh.secret -> Cstruct.t -> Cstruct.t option
val check_gy : Cstruct.t -> bool

val pow_s : Cstruct.t -> Mirage_crypto_pk.Dh.secret -> Cstruct.t
val mult_pow : Cstruct.t -> Cstruct.t -> Cstruct.t -> Cstruct.t

val proof_knowledge : Mirage_crypto_pk.Dh.secret -> int -> (Cstruct.t * Cstruct.t)
val check_proof : Cstruct.t -> Cstruct.t -> Cstruct.t -> int -> bool

val proof_equal_coords : Cstruct.t -> Cstruct.t -> Mirage_crypto_pk.Dh.secret -> Cstruct.t -> int -> (Cstruct.t * Cstruct.t * Cstruct.t)
val check_equal_coords : Cstruct.t -> Cstruct.t -> Cstruct.t -> Cstruct.t -> Cstruct.t -> Cstruct.t -> Cstruct.t -> int -> bool

val proof_eq_logs : Cstruct.t -> Mirage_crypto_pk.Dh.secret -> int -> Cstruct.t * Cstruct.t
val check_eq_logs : Cstruct.t -> Cstruct.t -> Cstruct.t -> Cstruct.t -> Cstruct.t -> int -> bool

val compute_p : Cstruct.t -> Cstruct.t -> Cstruct.t

val prepare_secret : Cstruct.t -> Cstruct.t -> Cstruct.t -> string -> Cstruct.t
