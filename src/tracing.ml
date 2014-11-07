
(* This is so not thread-safe it's not even funny. *)


let eprint_sexp sexp =
  output_string stderr Sexplib.Sexp.(to_string_hum sexp) ;
  output_string stderr "\n\n" ;
  flush stderr

let current = ref (Some eprint_sexp)

let active ~hook f =
  let prev = !current in
  current := Some hook ;
  try
    let res = f () in
    ( current := prev ; res )
  with exn -> ( current := prev ; raise exn )

let form_trace id sexp =
  let open Sexplib in
  Sexp.(List [ Atom id ; sexp ])

let is_tracing () = !current <> None

let sexp ~tag lz =
  match !current with
  | None      -> ()
  | Some hook -> hook @@ form_trace tag (Lazy.force lz)

let sexps ~tag lzs = if is_tracing () then List.iter (sexp ~tag) lzs

let sexpf ~tag ~f x = sexp ~tag @@ lazy (f x)

let sexpfs ~tag ~f xs = if is_tracing () then List.iter (sexpf ~tag ~f) xs
