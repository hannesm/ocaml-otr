let encode_mpi n =
  Otr_builder.encode_data (Mirage_crypto_pk.Z_extra.to_cstruct_be n)

let (<+>) = Cstruct.append

let mpi_gt h1 h2 =
  Mirage_crypto_pk.Z_extra.(of_cstruct_be h1 > of_cstruct_be h2)

module OtrDsa = struct
  open Mirage_crypto_pk.Dsa

  let pub ~p ~q ~gg ~y =
    (* TODO check whether they must be FIPS *)
    let z_of_cs = Mirage_crypto_pk.Z_extra.of_cstruct_be ?bits:None in
    Mirage_crypto_pk.Dsa.pub ~p:(z_of_cs p) ~q:(z_of_cs q) ~gg:(z_of_cs gg) ~y:(z_of_cs y) ()

  let to_wire ?notag ({ p ; q ; gg ; y } : pub) =
    let tag =
      match notag with
      | None   -> let buf = Cstruct.create 2 in Cstruct.memset buf 0 ; buf
      | Some _ -> Cstruct.create 0
    in
    tag <+> encode_mpi p <+> encode_mpi q <+> encode_mpi gg <+> encode_mpi y

  let fingerprint k =
    (* only handling key type 0000, DSA *)
    Mirage_crypto.Hash.digest `SHA1 (to_wire ~notag:() k)

  let signature ~key data =
    let r, s = sign ~key (massage ~key:(pub_of_priv key) data) in
    r <+> s

  let verify ~key rs data =
    verify ~key rs (massage ~key data)
end

let derive_keys data =
  let secbytes = Otr_builder.encode_data data in
  let h2 b = Mirage_crypto.Hash.digest `SHA256 ((Cstruct.of_string b) <+> secbytes) in
  let ssid = Cstruct.sub (h2 "\000") 0 8 in
  let c, c' = Cstruct.split (h2 "\001") 16 in
  let m1 = h2 "\002" in
  let m2 = h2 "\003" in
  let m1' = h2 "\004" in
  let m2' = h2 "\005" in
  (ssid, c, c', m1, m2, m1', m2')


let data_keys data high =
  let secbytes = Otr_builder.encode_data data in
  let send, recv = if high then ("\001", "\002") else ("\002", "\001") in
  let h1 b = Mirage_crypto.Hash.digest `SHA1 ((Cstruct.of_string b) <+> secbytes) in
  let sendaes = Cstruct.sub (h1 send) 0 16 in
  let sendmac = Mirage_crypto.Hash.digest `SHA1 sendaes in
  let recvaes = Cstruct.sub (h1 recv) 0 16 in
  let recvmac = Mirage_crypto.Hash.digest `SHA1 recvaes in
  (sendaes, sendmac, recvaes, recvmac)

module AES_CTR = Mirage_crypto.Cipher_block.AES.CTR

let crypt ~key ~ctr msg =
  AES_CTR.encrypt ~key:(AES_CTR.of_secret key) ~ctr:(0L, ctr) msg

let gen_symmetric_key () =
  Mirage_crypto_rng.generate 16

let hash data =
  Mirage_crypto.Hash.digest `SHA256 data

let mac ~key data =
  let data= Cstruct.concat data in
  Mirage_crypto.Hash.mac `SHA256 ~key data

let mac160 ~key data =
  let buf = mac ~key [ Otr_builder.encode_data data ] in
  Cstruct.sub buf 0 20

let sha1mac = Mirage_crypto.Hash.mac `SHA1

let group = Mirage_crypto_pk.Dh.Group.oakley_5

let gen_dh_secret () =
  Mirage_crypto_pk.Dh.gen_key group

let dh_shared = Mirage_crypto_pk.Dh.shared

let check_gy gy =
  let open Mirage_crypto_pk in
  let gy = Z_extra.of_cstruct_be gy in
  gy <= Z.one || gy >= Z.(pred group.Dh.p) || gy = group.Dh.gg

let smp_hash version mpis =
  let buf = Cstruct.create 1 in
  Cstruct.set_uint8 buf 0 version ;
  hash (Cstruct.concat (buf :: List.map encode_mpi mpis))

let oakley_5_q = Z.((group.Mirage_crypto_pk.Dh.p - one) / (succ one))

let minus_mult_q a b c =
  (* OCaml mod: -5 mod 4 -> -1, but we need 3 instead *)
  let res = Z.((a - b * c) mod oakley_5_q) in
  if Z.(res < zero) then
    Z.(res + oakley_5_q)
  else
    res

let proof_knowledge sec static =
  let open Mirage_crypto_pk in
  let r, pub = gen_dh_secret () in
  let pub = Z_extra.of_cstruct_be pub in
  let c = smp_hash static [pub] in
  let cz = Z_extra.of_cstruct_be c in
  let d = minus_mult_q r.Dh.x sec.Dh.x cz in
  (c, Z_extra.to_cstruct_be d)

let powZ gz expz =
  Z.(powm gz expz group.Mirage_crypto_pk.Dh.p)

let pow_s g exp =
  let gz = Mirage_crypto_pk.Z_extra.of_cstruct_be g
  and expz = exp.Mirage_crypto_pk.Dh.x
  in
  let res = powZ gz expz in
  Mirage_crypto_pk.Z_extra.to_cstruct_be res

let mult_powZ a b e =
  let b = powZ b e in
  Z.(a * b mod group.Mirage_crypto_pk.Dh.p)

let mult_pow a g exp =
  let open Mirage_crypto_pk in
  let az = Z_extra.of_cstruct_be a
  and gz = Z_extra.of_cstruct_be g
  and expz = Z_extra.of_cstruct_be exp
  in
  let res = mult_powZ az gz expz in
  Z_extra.to_cstruct_be res

let check_proof g c d static =
  let open Mirage_crypto_pk in
  let gz = Z_extra.of_cstruct_be g
  and cz = Z_extra.of_cstruct_be c
  and dz = Z_extra.of_cstruct_be d
  in
  let m = group.Dh.p in
  let pub = Z.(powZ (succ one) dz * powZ gz cz mod m) in
  let c' = smp_hash static [ pub ] in
  Cstruct.equal c' c

let proof_equal_coords g2 g3 r y static =
  let open Mirage_crypto_pk in
  let r1, gr1 = gen_dh_secret ()
  and r2, _ = gen_dh_secret ()
  in
  let a = powZ (Z_extra.of_cstruct_be g3) r1.Dh.x
  and b = mult_powZ (Z_extra.of_cstruct_be gr1) (Z_extra.of_cstruct_be g2) r2.Dh.x
  in
  let cp = smp_hash static [ a ; b ] in
  let cpz = Z_extra.of_cstruct_be cp in
  let d1 = minus_mult_q r1.Dh.x r.Dh.x cpz
  and d2 = minus_mult_q r2.Dh.x (Z_extra.of_cstruct_be y) cpz
  in
  (cp, Z_extra.to_cstruct_be d1, Z_extra.to_cstruct_be d2)

let check_equal_coords g2 g3 pb qb cp d1 d2 static =
  let open Mirage_crypto_pk in
  let pbz = Z_extra.of_cstruct_be pb
  and qbz = Z_extra.of_cstruct_be qb
  and cpz = Z_extra.of_cstruct_be cp
  in
  let check n = Z.(n > one && n <= (pred (pred group.Dh.p))) in
  if check pbz && check qbz then
    let a =
      let a = powZ (Z_extra.of_cstruct_be g3) (Z_extra.of_cstruct_be d1)
      and b = powZ pbz cpz
      in
      Z.(a * b mod group.Dh.p)
    and b =
      let a = powZ Z.(succ one) (Z_extra.of_cstruct_be d1)
      and b = powZ (Z_extra.of_cstruct_be g2) (Z_extra.of_cstruct_be d2)
      and c = powZ qbz cpz
      in
      Z.(a * b * c mod group.Dh.p)
    in
    let cp' = smp_hash static [ a ; b ] in
    Cstruct.equal cp' cp
  else
    false

let proof_eq_logs p a static =
  let open Mirage_crypto_pk in
  let pz = Z_extra.of_cstruct_be p in
  let r, gr = gen_dh_secret () in
  let cr =
    let a = Z_extra.of_cstruct_be gr
    and b = powZ pz r.Dh.x
    in
    smp_hash static [ a ; b ]
  in
  let d = minus_mult_q r.Dh.x a.Dh.x (Z_extra.of_cstruct_be cr) in
  (cr, Z_extra.to_cstruct_be d)

let check_eq_logs c g p d r static =
  let open Mirage_crypto_pk in
  let rz = Z_extra.of_cstruct_be r in
  let check n = Z.(n > one && n <= (pred (pred group.Dh.p))) in
  if check rz then
    let dz = Z_extra.of_cstruct_be d
    and cz = Z_extra.of_cstruct_be c
    in
    let a =
      let a = powZ Z.(succ one) dz
      and b = powZ (Z_extra.of_cstruct_be g) cz
      in
      Z.(a * b mod group.Dh.p)
    and b =
      let a = powZ (Z_extra.of_cstruct_be p) dz
      and b = powZ rz cz
      in
      Z.(a * b mod group.Dh.p)
    in
    let c' = smp_hash static [ a ; b ] in
    Cstruct.equal c c'
  else
    false

let compute_p pa pb =
  let open Mirage_crypto_pk in
  let paz = Z_extra.of_cstruct_be pa
  and pbz = Z_extra.of_cstruct_be pb
  in
  let p = Z.(paz * (invert pbz group.Dh.p) mod group.Dh.p) in
  Z_extra.to_cstruct_be p

let prepare_secret initiator_fp responder_fp ssid secret =
  let version = Cstruct.of_string "\001" in
  let data = version <+> initiator_fp <+> responder_fp <+> ssid <+> (Cstruct.of_string secret) in
  hash data
