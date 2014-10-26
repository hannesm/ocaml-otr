open OUnit2

let parse_query (input, output) _ =
  let computed = Parser.parse_query input in
  match computed = output with
  | true -> ()
  | false -> assert_failure "expected different output"

let query_parser_tests =
  (* these are from protocol-v3-4.0.0.html (ignoring version 1, 4, x) *)
  List.map parse_query
           [ ("?OTR?" , []) ;
             ("?OTRv2?", [`V2]) ;
             ("?OTRv23?", [`V2 ; `V3]) ;
             ("?OTR?v2?", [`V2]) ;
             ("?OTRv24x?", [`V2]) ;
             ("?OTR?v24x?", [`V2]) ;
             ("?OTR?v?", []) ;
             ("?OTRv?", []) ]

let query_tests =
  List.mapi (fun i f -> "Parse query " ^ string_of_int i >:: f)
            query_parser_tests

let reader_tests =
  query_tests

let suite =
  "All" >::: [
    "Reader" >::: reader_tests ;
  ]
