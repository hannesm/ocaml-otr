
open State
open Packet

let (<+>) = Nocrypto.Uncommon.Cs.append

let query_message versions =
  let is v = List.mem v versions in
  match is `V2, is `V3 with
    | true, true -> "?OTRv23?"
    | true, false -> "?OTRv2?"
    | false, true -> "?OTRv3?"
    | false, false -> "?OTRv?"

let tag versions =
  let is v = List.mem v versions in
  let prefix = " \t  \t\t\t\t \t \t \t  " in
  let v2 = "  \t\t  \t " in
  let v3 = "  \t\t  \t\t" in
  match is `V2, is `V3 with
    | true, true -> prefix ^ v3 ^ v2
    | true, false -> prefix ^ v2
    | false, true -> prefix ^ v3
    | false, false -> ""

let header version instances typ =
  let open Cstruct in
  let buf = match version with
    | `V2 -> create 3
    | `V3 -> create 11
  in
  BE.set_uint16 buf 0 (packet_version_to_int (packet_version_of_version version)) ;
  set_uint8 buf 2 (message_type_to_int typ) ;
  (match version, instances with
   | `V2, None -> ()
   | `V3, Some (our, their) ->
     BE.set_uint32 buf 3 our ;
     BE.set_uint32 buf 7 their
   | _ -> assert false );
  buf

let encode_data data =
  let lenbuf = Cstruct.create 4 in
  Cstruct.BE.set_uint32 lenbuf 0 (Int32.of_int (Cstruct.len data)) ;
  lenbuf <+> data

let encode_int data =
  let buf = Cstruct.create 4 in
  Cstruct.BE.set_uint32 buf 0 data ;
  buf

let dh_commit version instances dhshared hashed =
  let header = header version instances DH_COMMIT in
  header <+> encode_data dhshared <+> encode_data hashed

let dh_key version instances shared =
  let header = header version instances DH_KEY in
  header <+> shared

let reveal_signature version instances r enc_sig mac =
  let header = header version instances REVEAL_SIGNATURE in
  header <+> encode_data r <+> enc_sig <+> mac

let signature version instances enc mac =
  let header = header version instances SIGNATURE in
  header <+> encode_data enc <+> mac
