#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"
open Topkg

let () =
  Pkg.describe "otr" @@ fun _c ->
  Ok [
    Pkg.mllib ~api:["Otr"] "src/otr.mllib";
    Pkg.test "feedback"
  ]
