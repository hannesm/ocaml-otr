open State

(* Monadic control-flow core. *)
type error = string
include Control.Or_error_make (struct type err = error end)
exception Handshake_error of error
let raise_unknown msg = raise (Handshake_error msg)

