open Otr_packet
open Otr_state

type error =
  | Unknown of string
  | Underflow
  | LeadingZero

let maybe a = if a = "" then None else Some a

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
      let versions = String.fold_left parse_v [] vs in
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

type ret = [
  | `Data of string
  | `ParseError of string
  | `Error of string
  | `PlainTag of Otr_state.version list * string option
  | `Query of Otr_state.version list
  | `String of string
  | `Fragment_v2 of (int * int) * string
  | `Fragment_v3 of (int32 * int32) * (int * int) * string
]

let parse_data data =
  match Astring.String.cut ~sep:"." data with
  | None -> Error (Unknown "empty OTR message")
  | Some (data, rest) ->
    match Base64.decode data with
    | Ok x -> Ok (x, maybe rest)
    | Error (`Msg m) -> Error (Unknown ("bad base64 data: " ^ m))

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

let parse_fragment data =
  match Astring.String.cuts ~sep:"," data with
  | k :: n :: piece :: rest ->
    let k = int_of_string k in
    let n = int_of_string n in
    let* () =
      guard
        (k > 0 && k <= 65535)
        (Unknown "k must be between 0 and 65535")
    in
    let* () =
      guard
        (n > 0 && n <= 65535)
        (Unknown "n must be between 0 and 65535")
    in
    let* () =
      guard
        (k <= n)
        (Unknown "k must be smaller or equal to n")
    in
    let* () =
      guard
        (String.length piece > 0)
        (Unknown "fragment must be of non-zero size")
    in
    let* () =
      guard
        (String.length (String.concat "" rest) = 0)
        (Unknown "too many elements")
    in
    Ok ((k, n), piece)
  | _ -> Error (Unknown "invalid fragment")

let parse_fragment_v3 data =
  match Astring.String.cut ~sep:"|" data with
  | Some (sender_instance, data) ->
    ( match Astring.String.cut ~sep:"," data with
      | Some (receiver_instance, data) ->
        let sender_instance = Scanf.sscanf sender_instance "%lx" (fun x -> x) in
        let receiver_instance = Scanf.sscanf receiver_instance "%lx" (fun x -> x) in
        let* kn, piece = parse_fragment data in
        Ok ((sender_instance, receiver_instance), kn, piece)
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
  let* () = guard (String.length buf >= 4) Underflow in
  let size = Stdlib.String.get_int32_be buf 0 in
  let intsize = Int32.to_int size in
  let* () = guard (String.length buf >= 4 + intsize) Underflow in
  Ok (String.sub buf 4 intsize, String.sub buf (4 + intsize) (String.length buf - (4 + intsize)))

let parse_gy data =
  let* gy, rst = decode_data data in
  let* () = guard (String.length rst = 0) Underflow in
  let* () = guard (String.get_uint8 gy 0 <> 0) LeadingZero in
  Ok gy


let version_of_int = function
  | 2 -> Ok `V2
  | 3 -> Ok `V3
  | _ -> Error (Unknown "version")

let parse_header bytes =
  let* () = guard (String.length bytes >= 3) Underflow in
  let* version = version_of_int (String.get_uint16_be bytes 0) in
  let typ = String.get_uint8 bytes 2 in
  let* typ =
    Option.to_result
      ~none:(Unknown "message type")
      (int_to_message_type typ)
  in
  match version with
  | `V2 -> Ok (version, typ, None, String.sub bytes 3 (String.length bytes - 3))
  | `V3 ->
    let* () = guard (String.length bytes >= 11) Underflow in
    let mine = String.get_int32_be bytes 3
    and thei = String.get_int32_be bytes 7
    in
    Ok (version, typ, Some (mine, thei), String.sub bytes 11 (String.length bytes - 11))

let parse_signature_data buf =
  let* () = guard (String.length buf >= 2) Underflow in
  let tag, buf = String.sub buf 0 2, String.sub buf 2 (String.length buf - 2) in
  let* () = guard (String.get_uint16_be tag 0 = 0) (Unknown "key tag != 0") in
  let* p, buf = decode_data buf in
  let* () = guard (String.get_uint8 p 0 <> 0) LeadingZero in
  let* q, buf = decode_data buf in
  let* () = guard (String.get_uint8 q 0 <> 0) LeadingZero in
  let* gg, buf = decode_data buf in
  let* () = guard (String.get_uint8 gg 0 <> 0) LeadingZero in
  let* y, buf = decode_data buf in
  let* () = guard (String.get_uint8 y 0 <> 0) LeadingZero in
  let* key =
    Result.map_error
      (function `Msg m -> Unknown m)
      (Otr_crypto.OtrDsa.pub ~p ~q ~gg ~y)
  in
  let* () = guard (String.length buf = 44) (Unknown "signature lengh") in
  let keyida = String.get_int32_be buf 0 in
  let siga =
    String.sub buf 4 20,
    String.sub buf 24 (String.length buf - 24)
  in
  Ok (key, keyida, siga)

let parse_reveal buf =
  let* r, buf = decode_data buf in
  let* enc_data, mac = decode_data buf in
  let* () = guard (String.length mac = 20) (Unknown "wrong mac length") in
  Ok (r, enc_data, mac)

let parse_dh_commit buf =
  let* gxenc, buf = decode_data buf in
  let* hgx, buf = decode_data buf in
  let* () =
    guard ((String.length buf = 0) && (String.length hgx = 32)) (Unknown "bad dh_commit")
  in
  Ok (gxenc, hgx)

let parse_data_body buf =
  let* () = guard (String.length buf >= 9) Underflow in
  let flags = String.get_uint8 buf 0
  and s_keyid = String.get_int32_be buf 1
  and r_keyid = String.get_int32_be buf 5
  in
  let* dh_y, buf = decode_data (String.sub buf 9 (String.length buf - 9)) in
  let* () = guard (String.get_uint8 dh_y 0 <> 0) LeadingZero in
  let* () = guard (String.length buf >= 8) Underflow in
  let ctr = String.get_int64_be buf 0 in
  let* encdata, buf = decode_data (String.sub buf 8 (String.length buf - 8)) in
  let* () = guard (String.length buf >= 20) Underflow in
  let mac = String.sub buf 0 20 in
  let* reveal, buf = decode_data (String.sub buf 20 (String.length buf - 20)) in
  let* () = guard (String.length buf = 0) Underflow in
  let flags = if flags = 1 then true else false in
  Ok (flags, s_keyid, r_keyid, dh_y, ctr, encdata, mac, reveal)

let parse_data buf =
  let* version, typ, instances, buf = parse_header buf in
  let* () = guard (typ = DATA) (Unknown "type") in
  let* flags, s_keyid, r_keyid, dh_y, ctr, encdata, mac, reveal =
    parse_data_body buf
  in
  Ok (version, instances, flags, s_keyid, r_keyid, dh_y, ctr, encdata, mac, reveal)

let parse_tlv buf =
  let* () = guard (String.length buf >= 4) Underflow in
  let typ = String.get_uint16_be buf 0 in
  let l = String.get_uint16_be buf 2 in
  let* () = guard (String.length buf >= 4 + l) Underflow in
  Ok (int_to_tlv_type typ, String.sub buf 4 l, String.sub buf (4 + l) (String.length buf - (4 + l)))

let parse_datas buf n =
  let rec p_data buf acc = function
    | 0 when String.length buf = 0 -> Ok (List.rev acc)
    | 0 -> Error Underflow
    | n ->
      let* x, buf = decode_data buf in
      let* () = guard (String.get_uint8 x 0 <> 0) LeadingZero in
      p_data buf (x :: acc) (pred n)
  in
  let* () = guard (String.length buf >= 4) Underflow in
  let cnt = String.get_int32_be buf 0 in
  if cnt = Int32.of_int n then
    p_data (String.sub buf 4 (String.length buf - 4)) [] n
  else
    Error Underflow
