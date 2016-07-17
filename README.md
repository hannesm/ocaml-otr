## OTR - Off the record implementation purely in OCaml

%%VERSION%%

This is an implementation of version 2 and 3 of the Off-the-record
protocol (https://otr.cypherpunks.ca/Protocol-v3-4.0.0.html) in OCaml.

Including the socialist millionairs protocol to authenticate a
communication partner over an encrypted channel providing a shared
secret.

## Documentation

[![Build Status](https://travis-ci.org/hannesm/ocaml-otr.svg?branch=master)](https://travis-ci.org/hannesm/ocaml-otr)

[API documentation](https://hannesm.github.io/ocaml-otr/doc/) is available online

Best to be used with [jackline](http://github.com/hannesm/jackline).

## Installation

`opam install otr` will install this library, once you have installed OCaml (>=
4.02.0) and opam (>= 1.2.2).