
open Otr_state

val check_keys : dh_keys -> int32 -> int32 -> string -> string option

val keys : dh_keys -> symms -> int32 -> int32 -> symms * symmetric_keys

val rotate_keys : dh_keys -> int32 -> int32 -> string -> dh_keys

val set_recv_counter : int64 -> int32 -> int32 -> symms -> symms
val inc_send_counter : int32 -> int32 -> symms -> symms

val reveal : dh_keys -> symms -> symms * symmetric_keys list
