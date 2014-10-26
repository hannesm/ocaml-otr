open OUnit2

let parse_query (input, (output, rest)) _ =
  let (computed, rest') = Parser.parse_query input in
  match computed = output, rest' = rest with
  | true, true -> ()
  | _ -> assert_failure "expected different output"

let query_parser_tests =
  (* these are from protocol-v3-4.0.0.html (ignoring version 1, 4, x) *)
  List.map parse_query
           [ ("?" , ([], None)) ;
             ("v2?", ([`V2], None)) ;
             ("v23?", ([`V2 ; `V3], None)) ;
             ("?v2?", ([`V2], None)) ;
             ("v24x?", ([`V2], None)) ;
             ("?v24x?", ([`V2], None)) ;
             ("?v?", ([], None)) ;
             ("v?", ([], None)) ;
             ("v2? bla", ([`V2], Some " bla")) ]

let query_tests =
  List.mapi (fun i f -> "Parse query " ^ string_of_int i >:: f)
            query_parser_tests

let reader_tests =
  query_tests

let suite =
  "All" >::: [
    "Reader" >::: reader_tests ;
  ]
