
val mpi_gt : Cstruct.t -> Cstruct.t -> bool

module OtrDsa : sig
  val to_wire : ?notag:unit -> Nocrypto.Dsa.pub -> Cstruct.t
  val priv_to_wire : Nocrypto.Dsa.priv -> Cstruct.t
  val fingerprint : Nocrypto.Dsa.pub -> Cstruct.t
  val signature : key:Nocrypto.Dsa.priv -> Cstruct.t -> Cstruct.t
  val verify : key:Nocrypto.Dsa.pub -> Cstruct.t * Cstruct.t -> Cstruct.t -> bool
end

val derive_keys : Cstruct.t -> State.keyblock
val data_keys : Cstruct.t -> bool -> (Cstruct.t * Cstruct.t * Cstruct.t * Cstruct.t)

val ctr0 : unit -> Cstruct.t
val crypt : key:Cstruct.t -> ctr:Cstruct.t -> Cstruct.t -> Cstruct.t

val gen_symmetric_key : unit -> Cstruct.t

val hash : Cstruct.t -> Cstruct.t
val mac : key:Cstruct.t -> Cstruct.t list -> Cstruct.t
val mac160 : key:Cstruct.t -> Cstruct.t -> Cstruct.t
val sha1mac : key:Cstruct.t -> Cstruct.t -> Cstruct.t

val gen_dh_secret : unit -> (Nocrypto.Dh.secret * Cstruct.t)
val dh_shared : Nocrypto.Dh.secret -> Cstruct.t -> Cstruct.t
