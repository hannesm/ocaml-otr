open OUnit2

open Otr
open Otr.Parser

let parse_query (input, (output, rest)) _ =
  Parser.(match parse_query input with
      | Or_error.Ok (versions, left) ->
        assert_equal output versions ;
        assert_equal rest left
      | Or_error.Error _ -> assert_failure "expected different output")

let query_parser_tests =
  (* these are from protocol-v3-4.0.0.html (ignoring version 1, 4, x) *)
  List.map parse_query
           [ ("?OTRv2?", ([`V2], None)) ;
             ("?OTRv23?", ([`V2 ; `V3], None)) ;
             ("?OTR?v2?", ([`V2], None)) ;
             ("?OTRv24x?", ([`V2], None)) ;
             ("?OTR?v24x?", ([`V2], None)) ;
             ("?OTR?v?", ([], None)) ;
             ("?OTRv?", ([], None)) ;
             ("?OTRv2? bla", ([`V2], Some " bla")) ]

let parse_query_neg input _ =
  Parser.(match parse_query input with
      | Or_error.Ok _ -> assert_failure "expected different output"
      | Or_error.Error _ -> ())

let query_parser_neg_tests =
  List.map parse_query_neg [ "?OTR?" ; "?OTR" ; "?OTR?45?" ; "?OTR45?" ]

let query_tests =
  List.mapi (fun i f -> "Parse query " ^ string_of_int i >:: f)
            query_parser_tests @
  List.mapi (fun i f -> "Parse neg query " ^ string_of_int i >:: f)
            query_parser_neg_tests


let reader_tests =
  query_tests

let suite =
  "All" >::: [
    "Reader" >::: reader_tests ;
  ]
