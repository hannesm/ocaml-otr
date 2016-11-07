open Cstruct
open Rresult
open Astring

open Otr_packet

type error =
  | Unknown of string
  | Underflow
  | LeadingZero

type 'a result = ('a, error) Result.result

let maybe a =
  if a = "" then None else Some a

(* parse query string *)
let parse_query str =
  let parse_v acc = function
    | '2' -> `V2 :: acc
    | '3' -> `V3 :: acc
    | _ -> acc
  in
  let parse idx =
    let _, left = Astring.String.span ~max:idx str in
    match Astring.String.cut ~sep:"?" left with
    | None -> ([], None)
    | Some (vs, post) ->
      let versions = Astring.String.fold_left parse_v [] vs in
      (List.rev versions, maybe post)
  in
  match String.get str 0, String.get str 1 with
  | '?', 'v' -> Ok (parse 2)
  | 'v', _ -> Ok (parse 1)
  | _ -> Error (Unknown "no usable version found")

let mark_match sep data =
  match Astring.String.cut ~sep data with
  | Some (pre, post) -> Ok (maybe pre, post)
  | None -> Error (Unknown "parse failed")

open Sexplib.Conv

type ret = [
  | `Data of Cstruct.t
  | `ParseError of string
  | `Error of string
  | `PlainTag of Otr_state.version list * string option
  | `Query of Otr_state.version list
  | `String of string
  | `Fragment_v2 of (int * int) * string
  | `Fragment_v3 of (int32 * int32) * (int * int) * string
] [@@deriving sexp]

let parse_data data =
  match Astring.String.cut ~sep:"." data with
  | None -> Error (Unknown "empty OTR message")
  | Some (data, rest) ->
    let b64data = Cstruct.of_string data in
    match Nocrypto.Base64.decode b64data with
    | None -> Error (Unknown "bad base64 data")
    | Some x -> Ok (x, maybe rest)

let parse_plain_tag data =
  let rec find_mark str acc =
    if String.length str < 8 then
      (List.rev acc, maybe str)
    else
      let tag, rest = Astring.String.span ~max:8 str in
      if tag = Otr_state.tag_v2 then
        find_mark rest (`V2 :: acc)
      else if tag = Otr_state.tag_v3 then
        find_mark rest (`V3 :: acc)
      else
        find_mark rest acc
  in
  find_mark data []

let guard p e = if p then Ok () else Error e

let parse_fragment data =
  match Astring.String.cuts ~sep:"," data with
  | k :: n :: piece :: rest ->
    let k = int_of_string k in
    let n = int_of_string n in
    guard
      (k > 0 && k <= 65535)
      (Unknown "k must be between 0 and 65535") >>= fun () ->
    guard
      (n > 0 && n <= 65535)
      (Unknown "n must be between 0 and 65535") >>= fun () ->
    guard
      (k <= n)
      (Unknown "k must be smaller or equal to n") >>= fun () ->
    guard
      (String.length piece > 0)
      (Unknown "fragment must be of non-zero size") >>= fun () ->
    guard
      (String.length (String.concat ~sep:"" rest) = 0)
      (Unknown "too many elements") >>= fun () ->
    Ok ((k, n), piece)
  | _ -> Error (Unknown "invalid fragment")

let parse_fragment_v3 data =
  match Astring.String.cut ~sep:"|" data with
  | Some (sender_instance, data) ->
    ( match Astring.String.cut ~sep:"," data with
      | Some (receiver_instance, data) ->
        let sender_instance = Scanf.sscanf sender_instance "%lx" (fun x -> x) in
        let receiver_instance = Scanf.sscanf receiver_instance "%lx" (fun x -> x) in
        parse_fragment data >>| fun (kn, piece) ->
        ((sender_instance, receiver_instance), kn, piece)
      | None -> Error (Unknown "invalid fragment (receiver_instance)"))
  | None -> Error (Unknown "invalid fragment (sender_instance)")

let classify_input bytes =
  let open Otr_state in
  match mark_match otr_v2_frag bytes with
  | Ok (pre, data) ->
    begin match parse_fragment data with
      | Ok data when pre = None -> `Fragment_v2 data
      | Ok _ -> `ParseError "Malformed v2 fragment (predata)"
      | Error _ -> `ParseError "Malformed v2 fragment"
    end
  | Error _ -> match mark_match otr_v3_frag bytes with
    | Ok (pre, data) ->
      begin match parse_fragment_v3 data with
        | Ok data when pre = None -> `Fragment_v3 data
        | Ok _ -> `ParseError "Malformed v3 fragment (predata)"
        | Error _ -> `ParseError "Malformed v3 fragment"
      end
    | Error _ -> match mark_match otr_mark bytes with
      | Ok (pre, data) ->
        begin match parse_data data with
          | Ok (data, post) when pre = None && post = None -> `Data data
          | Ok _ -> `ParseError "Malformed OTR data (pre/postdata)"
          | Error _ -> `ParseError "Malformed OTR data message"
        end
      | Error _ -> match mark_match otr_err_mark bytes with
        | Ok (pre, data) when pre = None -> `Error data
        | Ok _ -> `ParseError "Malformed Error received (predata)"
        | Error _ ->  match mark_match otr_prefix bytes with
          | Ok (pre, data) ->
            begin match parse_query data with
              | Ok (versions, _) when pre = None -> `Query versions
              | Ok _ -> `ParseError "Malformed OTR query (pre/postdata)"
              | Error _ -> `ParseError "Malformed OTR query"
            end
          | Error _ -> match mark_match tag_prefix bytes with
            | Ok (pre, data) ->
              begin match parse_plain_tag data with
                | (versions, None) -> `PlainTag (versions, pre)
                | _ -> `ParseError "Malformed Tag (postdata)"
              end
            | Error _ -> `String bytes


(* real OTR data parsing *)
let decode_data buf =
  guard (len buf >= 4) Underflow >>= fun () ->
  let size = BE.get_uint32 buf 0 in
  let intsize = Int32.to_int size in
  guard (len buf >= 4 + intsize) Underflow >>| fun () ->
  (sub buf 4 intsize, shift buf (4 + intsize))

let parse_gy data =
  decode_data data >>= fun (gy, rst) ->
  guard (len rst = 0) Underflow >>= fun () ->
  guard (get_uint8 gy 0 <> 0) LeadingZero >>| fun () ->
  gy


let version_of_int = function
  | 2 -> Ok `V2
  | 3 -> Ok `V3
  | _ -> Error (Unknown "version")

let parse_header bytes =
  guard (len bytes >= 3) Underflow >>= fun () ->
  version_of_int (BE.get_uint16 bytes 0) >>= fun version ->
  let typ = get_uint8 bytes 2 in
  R.of_option
    ~none:(fun () -> Error (Unknown "message type"))
    (int_to_message_type typ) >>= fun typ ->
  match version with
  | `V2 -> Ok (version, typ, None, shift bytes 3)
  | `V3 ->
    guard (len bytes >= 11) Underflow >>| fun () ->
    let mine = BE.get_uint32 bytes 3
    and thei = BE.get_uint32 bytes 7
    in
    (version, typ, Some (mine, thei), shift bytes 11)

let parse_signature_data buf =
  guard (len buf >= 2) Underflow >>= fun () ->
  let tag, buf = split buf 2 in
  guard (BE.get_uint16 tag 0 = 0) (Unknown "key tag != 0") >>= fun () ->
  decode_data buf >>= fun (p, buf) ->
  guard (get_uint8 p 0 <> 0) LeadingZero >>= fun () ->
  decode_data buf >>= fun (q, buf) ->
  guard (get_uint8 q 0 <> 0) LeadingZero >>= fun () ->
  decode_data buf >>= fun (gg, buf) ->
  guard (get_uint8 gg 0 <> 0) LeadingZero >>= fun () ->
  decode_data buf >>= fun (y, buf) ->
  guard (get_uint8 y 0 <> 0) LeadingZero >>= fun () ->
  let key = Otr_crypto.OtrDsa.pub ~p ~q ~gg ~y in
  guard (len buf = 44) (Unknown "signature lengh") >>| fun () ->
  let keyida = BE.get_uint32 buf 0 in
  let buf = shift buf 4 in
  let siga = split buf 20 in
  (key, keyida, siga)

let parse_reveal buf =
  decode_data buf >>= fun (r, buf) ->
  decode_data buf >>= fun (enc_data, mac) ->
  guard (len mac = 20) (Unknown "wrong mac length") >>| fun () ->
  (r, enc_data, mac)

let parse_dh_commit buf =
  decode_data buf >>= fun (gxenc, buf) ->
  decode_data buf >>= fun (hgx, buf) ->
  guard ((len buf = 0) && (len hgx = 32)) (Unknown "bad dh_commit") >>| fun () ->
  (gxenc, hgx)

let parse_data_body buf =
  guard (len buf >= 9) Underflow >>= fun () ->
  let flags = get_uint8 buf 0
  and s_keyid = BE.get_uint32 buf 1
  and r_keyid = BE.get_uint32 buf 5
  in
  decode_data (shift buf 9) >>= fun (dh_y, buf) ->
  guard (get_uint8 dh_y 0 <> 0) LeadingZero >>= fun () ->
  guard (len buf >= 8) Underflow >>= fun () ->
  let ctr = BE.get_uint64 buf 0 in
  decode_data (shift buf 8) >>= fun (encdata, buf) ->
  guard (len buf >= 20) Underflow >>= fun () ->
  let mac = sub buf 0 20 in
  decode_data (shift buf 20) >>= fun (reveal, buf) ->
  guard (len buf = 0) Underflow >>| fun () ->
  let flags = if flags = 1 then true else false in
  (flags, s_keyid, r_keyid, dh_y, ctr, encdata, mac, reveal)

let parse_data buf =
  parse_header buf >>= fun (version, typ, instances, buf) ->
  guard (typ = DATA) (Unknown "type") >>= fun () ->
  parse_data_body buf >>| fun (flags, s_keyid, r_keyid, dh_y, ctr, encdata, mac, reveal) ->
  (version, instances, flags, s_keyid, r_keyid, dh_y, ctr, encdata, mac, reveal)

let parse_tlv buf =
  guard (len buf >= 4) Underflow >>= fun () ->
  let typ = BE.get_uint16 buf 0 in
  let l = BE.get_uint16 buf 2 in
  guard (len buf >= 4 + l) Underflow >>| fun () ->
  (int_to_tlv_type typ, sub buf 4 l, shift buf (4 + l))

let parse_datas buf n =
  let rec p_data buf acc = function
    | 0 when len buf = 0 -> Ok (List.rev acc)
    | 0 -> Error Underflow
    | n ->
      decode_data buf >>= fun (x, buf) ->
      guard (get_uint8 x 0 <> 0) LeadingZero >>= fun () ->
      p_data buf (x :: acc) (pred n)
  in
  guard (len buf >= 4) Underflow >>= fun () ->
  let cnt = BE.get_uint32 buf 0 in
  if cnt = Int32.of_int n then
    p_data (shift buf 4) [] n
  else
    Error Underflow
