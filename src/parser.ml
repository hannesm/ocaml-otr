
open Packet
open Cstruct
open State

let decode_data buf =
  let size = BE.get_uint32 buf 0 in
  let intsize = Int32.to_int size in
  (sub buf 4 intsize, shift buf (4 + intsize))

let parse_query str =
  match String.length str with
  | 1 when String.get str 0 = '?' -> ([], None)
  | x when x > 1 ->
    let rec parse_v str acc idx =
      match String.get str idx with
      | '2' -> parse_v str (`V2 :: acc) (idx + 1)
      | '3' -> parse_v str (`V3 :: acc) (idx + 1)
      | '?' ->
        let leftover =
          let l = String.length str in
          let r = succ idx in
          if l > r then Some (String.sub str r (l - r)) else None
        in
        (List.rev acc, leftover)
      | _ -> parse_v str acc (idx + 1)
    in
    (match String.get str 0, String.get str 1 with
     | '?', 'v' -> parse_v str [] 2
     | 'v', _ -> parse_v str [] 1
     | _ -> ([], Some str) )

  | x -> ([], Some str)

let assert_versions theirs ours =
  match int_to_packet_version theirs with
  | Some version -> assert (version_of_packet_version version = ours)
  | None -> assert false

let parse_auth ctx bytes =
  let theirs = BE.get_uint16 bytes 0 in
  assert_versions theirs ctx.version ;
  let typ = match int_to_message_type (get_uint8 bytes 2) with
    | Some x -> x
    | None -> assert false
  in
  (typ,
   match ctx.version with
   | `V2 -> shift bytes 3
   | `V3 -> (* instance tags -- retrieve, compare, set *) shift bytes 11)

let parse_key buf =
  let tag, buf = split buf 2 in
  assert (BE.get_uint16 tag 0 = 0) ;
  let p, buf = decode_data buf in
  let q, buf = decode_data buf in
  let gg, buf = decode_data buf in
  let y, buf = decode_data buf in
  ((p, q, gg, y), buf)

let parse_signature_data buf =
  let key, buf = parse_key buf in
  let keyida, buf = BE.get_uint32 buf 0, shift buf 4 in
  let siga = split buf 20 in
  ( key, keyida, siga)

let parse_reveal buf =
  let r, buf = decode_data buf in
  let enc_data, mac = decode_data buf in
  assert (len mac = 20) ;
  (r, enc_data, mac)

let parse_dh_commit buf =
  let gxenc, buf = decode_data buf in
  let hgx, buf = decode_data buf in
  assert (len buf = 0) ;
  assert (len hgx = 32) ;
  (gxenc, hgx)
