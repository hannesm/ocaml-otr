type ret = [
  | `Warning of string
  | `Received_error of string
  | `Received of string
  | `Established_encrypted_session of string
  | `Received_encrypted of string
  | `SMP_awaiting_secret
  | `SMP_received_question of string
  | `SMP_success
  | `SMP_failure
]

type dh_params = (Mirage_crypto_pk.Dh.secret * Cstruct.t)

type dh_keys = {
  dh          : dh_params ;
  previous_dh : dh_params ;
  our_keyid   : int32 ;
  gy          : Cstruct.t ;
  previous_gy : Cstruct.t ;
  their_keyid : int32 ;
}

type symmetric_keys = {
  send_aes : Cstruct.t ;
  send_mac : Cstruct.t ;
  send_ctr : int64 ;
  recv_aes : Cstruct.t ;
  recv_mac : Cstruct.t ;
  recv_ctr : int64 ;
}

type symms = (int32 * int32 * symmetric_keys) list

type enc_data = {
  dh_keys   : dh_keys ;
  symms     : symms ;
  their_dsa : Mirage_crypto_pk.Dsa.pub ;
  ssid      : Cstruct.t ;
  high      : bool ;
}

type message_state =
  | MSGSTATE_PLAINTEXT
  | MSGSTATE_ENCRYPTED of enc_data
  | MSGSTATE_FINISHED

let message_state_to_string = function
  | MSGSTATE_PLAINTEXT   -> "plain"
  | MSGSTATE_ENCRYPTED _ -> "encrypted"
  | MSGSTATE_FINISHED    -> "finished"

type auth_state =
  | AUTHSTATE_NONE
  | AUTHSTATE_AWAITING_DHKEY of Cstruct.t * Cstruct.t * dh_params * Cstruct.t
  | AUTHSTATE_AWAITING_REVEALSIG of dh_params * Cstruct.t
  | AUTHSTATE_AWAITING_SIG of Cstruct.t * (Cstruct.t * Cstruct.t * Cstruct.t * Cstruct.t) * dh_params * Cstruct.t

let auth_state_to_string = function
  | AUTHSTATE_NONE                 -> "none"
  | AUTHSTATE_AWAITING_DHKEY _     -> "awaiting dh key"
  | AUTHSTATE_AWAITING_REVEALSIG _ -> "awaiting reveal signature"
  | AUTHSTATE_AWAITING_SIG _       -> "awaiting signature"

type smp_state =
  | SMPSTATE_WAIT_FOR_Y of Cstruct.t * Cstruct.t
  | SMPSTATE_EXPECT1
  | SMPSTATE_EXPECT2 of Cstruct.t * Mirage_crypto_pk.Dh.secret * Mirage_crypto_pk.Dh.secret
  | SMPSTATE_EXPECT3 of Cstruct.t * Cstruct.t * Cstruct.t * Mirage_crypto_pk.Dh.secret * Cstruct.t * Cstruct.t
  | SMPSTATE_EXPECT4 of Cstruct.t * Cstruct.t * Cstruct.t * Mirage_crypto_pk.Dh.secret

let smp_state_to_string = function
  | SMPSTATE_WAIT_FOR_Y _ -> "waiting for secret"
  | SMPSTATE_EXPECT1      -> "initial"
  | SMPSTATE_EXPECT2 _    -> "waiting for msg 2"
  | SMPSTATE_EXPECT3 _    -> "waiting for msg 3"
  | SMPSTATE_EXPECT4 _    -> "waiting for msg 4"

type policy = [
  | `REQUIRE_ENCRYPTION
  | `SEND_WHITESPACE_TAG
  | `WHITESPACE_START_AKE
  | `ERROR_START_AKE
  | `REVEAL_MACS
]

let policy_to_string = function
  | `REQUIRE_ENCRYPTION   -> "require encryption"
  | `SEND_WHITESPACE_TAG  -> "send whitespace tag"
  | `WHITESPACE_START_AKE -> "whitespace starts key exchange"
  | `ERROR_START_AKE      -> "error starts key exchange"
  | `REVEAL_MACS          -> "reveal mac keys"

let string_to_policy = function
  | "REQUIRE_ENCRYPTION"   -> Some `REQUIRE_ENCRYPTION
  | "SEND_WHITESPACE_TAG"  -> Some `SEND_WHITESPACE_TAG
  | "WHITESPACE_START_AKE" -> Some `WHITESPACE_START_AKE
  | "ERROR_START_AKE"      -> Some `ERROR_START_AKE
  | "REVEAL_MACS"          -> Some `REVEAL_MACS
  | _ -> None

let policy_of_sexp = function
  | Sexplib.Sexp.Atom atom ->
    (match string_to_policy atom with
     | None -> invalid_arg "bad sexp"
     | Some v -> v)
  | _ -> invalid_arg "bad sexp"

let sexp_of_policy p =
  let str = match p with
    | `REQUIRE_ENCRYPTION   -> "REQUIRE_ENCRYPTION"
    | `SEND_WHITESPACE_TAG  -> "SEND_WHITESPACE_TAG"
    | `WHITESPACE_START_AKE -> "WHITESPACE_START_AKE"
    | `ERROR_START_AKE      -> "ERROR_START_AKE"
    | `REVEAL_MACS          -> "REVEAL_MACS"
  in
  Sexplib.Sexp.Atom str

let all_policies = [ `REQUIRE_ENCRYPTION ; `SEND_WHITESPACE_TAG ; `WHITESPACE_START_AKE ; `ERROR_START_AKE ; `REVEAL_MACS ]

type version = [ `V2 | `V3 ]

let version_to_string = function
  | `V2 -> "version 2"
  | `V3 -> "version 3"

let string_to_version = function
  | "V2" -> Some `V2
  | "V3" -> Some `V3
  | _ -> None

let version_of_sexp = function
  | Sexplib.Sexp.Atom v ->
    (match string_to_version v with
     | None -> invalid_arg "bad version"
     | Some x -> x)
  | _ -> invalid_arg "bad sexp"

let sexp_of_version v =
  let str = match v with
    | `V2 -> "V2"
    | `V3 -> "V3"
  in
  Sexplib.Sexp.Atom str

let all_versions = [ `V2 ; `V3 ]

type config = {
  policies : policy list ;
  versions : version list ;
}

let config_of_sexp = function
  | Sexplib.Sexp.List fields_sexp ->
    let policies_field = ref None
    and versions_field = ref None
    in
    let rec iter = function
      | (Sexplib.Sexp.List ((Sexplib.Sexp.Atom field_name)::field::[]))::tail ->
        ((match field_name with
            | "policies" ->
              (match !policies_field with
               | None ->
                 let fvalue = Sexplib.Conv.list_of_sexp policy_of_sexp field in
                 policies_field := Some fvalue
               | Some _ -> invalid_arg "duplicate field")
            | "versions" ->
              (match !versions_field with
               | None ->
                 let fvalue = Sexplib.Conv.list_of_sexp version_of_sexp field in
                 versions_field := Some fvalue
               | Some _ -> invalid_arg "duplicate field")
            | _ -> invalid_arg "extra field") ;
         iter tail)
      | [] -> ()
      | _ -> invalid_arg "bad sexp"
    in
    (iter fields_sexp;
     match !policies_field, !versions_field with
     | (Some policies_value, Some versions_value) ->
       { policies = policies_value; versions = versions_value }
     | _ -> invalid_arg "incomplete sexp")
   | _ -> invalid_arg "bad sexp"

let sexp_of_config { policies = v_policies; versions = v_versions } =
  let bnds = [] in
  let bnds =
    let arg = Sexplib.Conv.sexp_of_list sexp_of_version v_versions in
    (Sexplib.Sexp.List [Sexplib.Sexp.Atom "versions"; arg]) :: bnds in
  let bnds =
    let arg = Sexplib.Conv.sexp_of_list sexp_of_policy v_policies in
    (Sexplib.Sexp.List [Sexplib.Sexp.Atom "policies"; arg]) :: bnds in
  Sexplib.Sexp.List bnds

type state = {
  message_state : message_state ;
  auth_state    : auth_state ;
  smp_state     : smp_state ;
}

type session = {
  instances : (int32 * int32) option ;
  version : version ;
  state : state ;
  config : config ;
  dsa : Mirage_crypto_pk.Dsa.priv ;
  fragments : ((int * int) * string) ;
}

let update_config config ctx = { ctx with config }

let version x = x.version

let reveal_macs session =
  List.mem `REVEAL_MACS session.config.policies

let session_to_string s =
  let instances = match s.instances with
    | None -> ""
    | Some (x, y) ->
      Printf.sprintf ", instances: other %08lx, my %08lx" x y
  in
  let state = s.state in
  let version, auth_state, smp_state =
    let ver v = " " ^ version_to_string v in
    match state.message_state with
    | MSGSTATE_PLAINTEXT when state.auth_state = AUTHSTATE_NONE -> ("", " (auth none)", "")
    | MSGSTATE_PLAINTEXT -> (ver s.version, " (auth " ^ (auth_state_to_string state.auth_state) ^ ")", "")
    | MSGSTATE_ENCRYPTED _ -> (ver s.version, "", " (smp " ^ (smp_state_to_string state.smp_state) ^ ")")
    | MSGSTATE_FINISHED -> (ver s.version, "", "")
  in
  "state: " ^ (message_state_to_string s.state.message_state) ^ auth_state ^
  version ^ smp_state ^
  instances

let new_session config dsa () =
  let state = {
    message_state = MSGSTATE_PLAINTEXT ;
    auth_state = AUTHSTATE_NONE ;
    smp_state = SMPSTATE_EXPECT1
  }
  and version = match config.versions with
    | [x] -> x
    | [] -> assert false
    | x when List.mem `V3 x -> `V3
    | _ -> `V2
  in
  { instances = None ;
    version ;
    state ;
    config ;
    dsa ;
    fragments = ((0, 0), "")
  }

let config versions policies =
  if List.length versions = 0 then
    invalid_arg "no versions supplied" ;
  { versions ; policies }

let rst_frag ctx = { ctx with fragments = ((0, 0), "") }

let reset_session ctx = new_session ctx.config ctx.dsa ()

let is_encrypted ctx =
  match ctx.state.message_state with
  | MSGSTATE_ENCRYPTED _ -> true
  | _ -> false

let their_dsa ctx =
  match ctx.state.message_state with
  | MSGSTATE_ENCRYPTED enc_data -> Some enc_data.their_dsa
  | _ -> None

let tag_prefix = " \t  \t\t\t\t \t \t \t  "
and tag_v2 = "  \t\t  \t "
and tag_v3 = "  \t\t  \t\t"
and otr_prefix = "?OTR"

let otr_mark, otr_err_mark, otr_v2_frag, otr_v3_frag =
  (otr_prefix ^ ":", otr_prefix ^ " Error:", otr_prefix ^ ",", otr_prefix ^ "|")
