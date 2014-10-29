
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

(* String splitting at index idx *)
let string_split str idx =
  if idx > 0 then
    let pre = Some (String.sub str 0 idx)
    and idx' = succ idx
    and len = String.length str
    in
    if idx' < len then
      (pre, Some (String.(sub str idx' (len - idx'))))
    else
      (pre, None)
  else
    (None, Some str)

(* parse query string *)
let parse_query_exn str =
  let rec parse_v idx acc =
    match String.get str idx with
    | '2' -> parse_v (succ idx) (`V2 :: acc)
    | '3' -> parse_v (succ idx) (`V3 :: acc)
    | '?' ->
      let _, post = string_split str idx in
      (List.rev acc, post)
    | _ -> parse_v (succ idx) acc
  in
  match String.(get str 0, get str 1) with
  | '?', 'v' -> parse_v 2 []
  | 'v', _ -> parse_v 1 []
  | _ -> raise_unknown "no usable version found"

let parse_query = catch parse_query_exn

(* string parsing, classification *)
let maybe_concat pre post =
  match pre, post with
  | None, None -> None
  | Some pre, Some post -> Some ("before: " ^ pre ^ " after: " ^ post)
  | Some pre, None -> Some pre
  | None, Some post -> Some post

let re_match_exn re relen data =
  let idx = Str.search_forward re data 0 in
  match string_split data idx with
  | pre, Some data -> (pre, String.(sub data relen (length data - relen)))
  | _ -> raise_unknown "re matched, but no data found"

let re_match (re, relen) data =
  try Ok (re_match_exn re relen data) with _ -> Error (Unknown "parse failed")


let otr_mark, otr_err_mark, otr_query_mark, tag_prefix =
  let re str = (Str.regexp_string str, String.length str) in
  (re "?OTR:",
   re "?OTR Error:",
   re "?OTR",
   re " \t  \t\t\t\t \t \t \t  ")

(* TODO: fragmentation (',' as final character) *)
let classify_input bytes =
  match re_match otr_mark bytes with
  | Ok (pre, data) ->
    begin
      try
        match string_split data (String.index data '.') with
        | Some data, post ->
          let b64data = Cstruct.of_string data in
          `Data (Nocrypto.Base64.decode b64data, maybe_concat pre post)
        | None, _ -> `ParseError ("empty OTR message", bytes)
      with Not_found -> `ParseError ("malformed OTR message", bytes)
      (* TODO: fragmentation *)
    end
  | Error _ -> match re_match otr_err_mark bytes with
    | Ok (pre, data) -> `Error (data, pre)
    | Error _ -> match re_match otr_query_mark bytes with
      | Ok (pre, data) ->
        ( match parse_query data with
          | Ok (versions, post) -> `Query (versions, maybe_concat pre post)
          | Error _ -> `ParseError ("Malformed OTR query", bytes) )
      | Error _ -> match re_match tag_prefix bytes with
        | Ok (pre, data) ->
          let len = String.length data in
          let rec find_mark idx acc =
            if len - idx < 8 then
              let _, post = string_split data idx in
              `PlainTag (List.rev acc, maybe_concat pre post)
            else
              match String.sub data idx 8 with
              | "  \t\t  \t " -> find_mark (idx + 8) (`V2 :: acc)
              | "  \t\t  \t\t" -> find_mark (idx + 8) (`V3 :: acc)
              | _ -> find_mark (idx + 8) acc
          in
          (try find_mark 0 [] with Not_found -> `ParseError ("Malformed tag", bytes) )
        | Error _ -> `String bytes

(* real OTR data parsing *)
let decode_data buf =
  let size = BE.get_uint32 buf 0 in
  let intsize = Int32.to_int size in
  (sub buf 4 intsize, shift buf (4 + intsize))

(*let decode_data = catch decode_data_exn*)


let parse_auth bytes =
  ( match version_of_int (BE.get_uint16 bytes 0) with
    | None -> raise_unknown "version"
    | Some v -> return v ) >>= fun version ->
  ( match int_to_message_type (get_uint8 bytes 2) with
    | Some x -> return x
    | None -> raise_unknown "message type" ) >>= fun typ ->
  ( match version with
    | `V2 -> return (None, shift bytes 3)
    | `V3 ->
      let instances = Some BE.(get_uint32 bytes 3, get_uint32 bytes 7) in
      return (instances, shift bytes 11) ) >|= fun (instances, buf) ->
  (version, typ, instances, buf)

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
