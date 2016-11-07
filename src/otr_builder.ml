
open Otr_state

let int_of_version = function
  | `V2 -> 2
  | `V3 -> 3

let (<+>) = Cstruct.append

let query_message versions =
  let is v = List.mem v versions in
  match is `V2, is `V3 with
    | true, true -> otr_prefix ^ "v23?"
    | true, false -> otr_prefix ^ "v2?"
    | false, true -> otr_prefix ^ "v3?"
    | false, false -> otr_prefix ^ "v?"

let tag versions =
  let is v = List.mem v versions in
  match is `V2, is `V3 with
    | true, true -> tag_prefix ^ tag_v3 ^ tag_v2
    | true, false -> tag_prefix ^ tag_v2
    | false, true -> tag_prefix ^ tag_v3
    | false, false -> ""

let header version instances typ =
  let open Cstruct in
  let buf = match version with
    | `V2 -> create 3
    | `V3 -> create 11
  in
  BE.set_uint16 buf 0 (int_of_version version) ;
  set_uint8 buf 2 (Otr_packet.message_type_to_int typ) ;
  (match version, instances with
   | `V2, None -> ()
   | `V3, Some (them, us) ->
     BE.set_uint32 buf 3 us ;
     BE.set_uint32 buf 7 them
   | _ -> assert false );
  buf

let encode_int data =
  let buf = Cstruct.create 4 in
  Cstruct.BE.set_uint32 buf 0 data ;
  buf

let encode_data data =
  encode_int (Int32.of_int (Cstruct.len data)) <+> data

let dh_commit version instances dhshared hashed =
  let header = header version instances Otr_packet.DH_COMMIT in
  header <+> encode_data dhshared <+> encode_data hashed

let dh_key version instances shared =
  let header = header version instances Otr_packet.DH_KEY in
  header <+> encode_data shared

let reveal_signature version instances r enc_sig mac =
  let header = header version instances Otr_packet.REVEAL_SIGNATURE in
  header <+> encode_data r <+> encode_data enc_sig <+> mac

let signature version instances enc mac =
  let header = header version instances Otr_packet.SIGNATURE in
  header <+> encode_data enc <+> mac

let data version instances flags keyida keyidb dh_y ctr data =
  let open Cstruct in
  let header = header version instances Otr_packet.DATA in
  let keys = create 9 in
  set_uint8 keys 0 (if flags then 1 else 0) ;
  BE.set_uint32 keys 1 keyida ;
  BE.set_uint32 keys 5 keyidb ;
  let ctr =
    let buf = create 8 in
    BE.set_uint64 buf 0 ctr ;
    buf
  in
  header <+> keys <+> encode_data dh_y <+> ctr <+> encode_data data

let tlv ?data ?predata typ =
  let buf = Cstruct.create 4 in
  Cstruct.BE.set_uint16 buf 0 (Otr_packet.tlv_type_to_int typ) ;
  match data with
  | Some payload ->
    let llen = encode_int (Int32.of_int (List.length payload)) in
    let data = Cstruct.concat (llen :: List.map encode_data payload) in
    let pred = match predata with
      | None -> Cstruct.create 0
      | Some x -> x
    in
    let data = pred <+> data in
    Cstruct.BE.set_uint16 buf 2 (Cstruct.len data) ;
    buf <+> data
  | None ->
    Cstruct.BE.set_uint16 buf 2 0 ;
    buf
