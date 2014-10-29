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
           [ ("v2?", ([`V2], None)) ;
             ("v23?", ([`V2 ; `V3], None)) ;
             ("?v2?", ([`V2], None)) ;
             ("v24x?", ([`V2], None)) ;
             ("?v24x?", ([`V2], None)) ;
             ("?v?", ([], None)) ;
             ("v?", ([], None)) ;
             ("v2? bla", ([`V2], Some " bla")) ]

let parse_query_neg input _ =
  Parser.(match parse_query input with
      | Or_error.Ok _ -> assert_failure "expected different output"
      | Or_error.Error _ -> ())

let query_parser_neg_tests =
  List.map parse_query_neg
    [ "?" ; "" ; "?45?" ; "45?" ;
      "blabalablabla" ; "v12345" ]

let query_tests =
  List.mapi (fun i f -> "Parse query " ^ string_of_int i >:: f)
            query_parser_tests @
  List.mapi (fun i f -> "Parse neg query " ^ string_of_int i >:: f)
            query_parser_neg_tests


let parser_tests =
  query_tests

let suite =
  "All" >::: [
    "Parser" >::: parser_tests ;
  ]
