
open Packet
open Cstruct
open State

type error =
  | TrailingBytes of string
  | WrongLength   of string
  | Unknown       of string
  | Underflow

module Or_error =
  Control.Or_error_make (struct type err = error end)
open Or_error

exception Parser_error of error

let raise_unknown msg        = raise (Parser_error (Unknown msg))
and raise_wrong_length msg   = raise (Parser_error (WrongLength msg))
and raise_trailing_bytes msg = raise (Parser_error (TrailingBytes msg))

let catch f x =
  try return (f x) with
  | Parser_error err   -> fail err
  | Invalid_argument _ -> fail Underflow

let decode_data buf =
  let size = BE.get_uint32 buf 0 in
  let intsize = Int32.to_int size in
  (sub buf 4 intsize, shift buf (4 + intsize))

(*let decode_data = catch decode_data_exn*)

(* input is a string which starts with ?OTR *)
let parse_query_exn str =
  let rec parse_v idx acc =
    match String.get str idx with
    | '2' -> parse_v (succ idx) (`V2 :: acc)
    | '3' -> parse_v (succ idx) (`V3 :: acc)
    | '?' ->
      let rst =
        let l = String.length str in
        let next = succ idx in
        if l > next then Some (String.sub str next (l - next)) else None
      in
      (List.rev acc, rst)
    | _ -> parse_v (succ idx) acc
  in
  match String.(get str 4, get str 5) with
  | '?', 'v' -> parse_v 6 []
  | 'v', _ -> parse_v 5 []
  | _ -> raise_unknown "no usable version found"

let parse_query = catch parse_query_exn

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
