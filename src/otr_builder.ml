
open Otr_state

let int_of_version = function
  | `V2 -> 2
  | `V3 -> 3

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
  let buf = match version with
    | `V2 -> Bytes.create 3
    | `V3 -> Bytes.create 11
  in
  Bytes.set_uint16_be buf 0 (int_of_version version) ;
  Bytes.set_uint8 buf 2 (Otr_packet.message_type_to_int typ) ;
  (match version, instances with
   | `V2, None -> ()
   | `V3, Some (them, us) ->
     Bytes.set_int32_be buf 3 us ;
     Bytes.set_int32_be buf 7 them
   | _ -> assert false );
  Bytes.unsafe_to_string buf

let encode_int data =
  let buf = Bytes.create 4 in
  Bytes.set_int32_be buf 0 data ;
  Bytes.unsafe_to_string buf

let encode_data data =
  encode_int (Int32.of_int (String.length data)) ^ data

let dh_commit version instances dhshared hashed =
  let header = header version instances Otr_packet.DH_COMMIT in
  header ^ encode_data dhshared ^ encode_data hashed

let dh_key version instances shared =
  let header = header version instances Otr_packet.DH_KEY in
  header ^ encode_data shared

let reveal_signature version instances r enc_sig mac =
  let header = header version instances Otr_packet.REVEAL_SIGNATURE in
  header ^ encode_data r ^ encode_data enc_sig ^ mac

let signature version instances enc mac =
  let header = header version instances Otr_packet.SIGNATURE in
  header ^ encode_data enc ^ mac

let data version instances flags keyida keyidb dh_y ctr data =
  let header = header version instances Otr_packet.DATA in
  let keys = Bytes.create 9 in
  Bytes.set_uint8 keys 0 (if flags then 1 else 0) ;
  Bytes.set_int32_be keys 1 keyida ;
  Bytes.set_int32_be keys 5 keyidb ;
  let ctr =
    let buf = Bytes.create 8 in
    Bytes.set_int64_be buf 0 ctr ;
    buf
  in
  header ^ Bytes.unsafe_to_string keys ^ encode_data dh_y ^ Bytes.unsafe_to_string ctr ^ encode_data data

let tlv ?data ?predata typ =
  let buf = Bytes.create 4 in
  Bytes.set_uint16_be buf 0 (Otr_packet.tlv_type_to_int typ) ;
  match data with
  | Some payload ->
    let llen = encode_int (Int32.of_int (List.length payload)) in
    let data = String.concat "" (llen :: List.map encode_data payload) in
    let pred = match predata with
      | None -> ""
      | Some x -> x
    in
    let data = pred ^ data in
    Bytes.set_uint16_be buf 2 (String.length data) ;
    Bytes.unsafe_to_string buf ^ data
  | None ->
    Bytes.set_uint16_be buf 2 0 ;
    Bytes.unsafe_to_string buf
