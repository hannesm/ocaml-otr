open State

let instance_tag () =
  (* 32 bit random, >= 0x00000100 *)
  let tag = Cstruct.BE.get_uint32 (Nocrypto.Rng.generate 4) 0 in
  Int32.(logor tag 0x100l)

let select_version ours theirs =
  let test v = List.mem v theirs in
  match List.filter test ours with
  | v::_ -> Some v
  | [] -> None

let instances = function
  | `V2 -> None
  | `V3 -> Some (0l, instance_tag ())

let policy ctx p = List.mem p ctx.config.policies
