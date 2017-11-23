#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"
open Topkg

let () =
  let opams =
    [ Pkg.opam_file "opam" ~lint_deps_excluding:(Some ["ppx_deriving"]) ]
  in
  Pkg.describe ~opams "otr" @@ fun _c ->
  Ok [
    Pkg.mllib ~api:["Otr"] "src/otr.mllib";
    Pkg.test "feedback"
  ]
