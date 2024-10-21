## v1.0.0 (2024-10-21)

* Use string instead of cstruct (#16 @hannesm)

## v0.3.10 (2021-10-25)

* remove rresult dependency
* use sexplib0 instead of sexplib for mirage-crypto 0.10.4+ compatibility
  (the dependency stated sexplib0 since some time, but sexplib was inherited
   via mirage-crypto-pk)

## v0.3.9 (2021-08-04)

* use Cstruct.length instead of deprecated Cstruct.len (requires cstruct 6.0.0)

## v0.3.8 (2020-03-15)

* fix crypt function (0.3.7 used the counter wrong, the 0 should be the other half)

## v0.3.7 (2020-03-11)

* use mirage-crypto instead of nocrypto

## 0.3.6 (2019-02-16)

* move build system to dune

## 0.3.5 (2018-08-25)

* remove usage of ppx

## 0.3.4 (2017-11-23)

* prefix modules with "Otr_"
* drop OCaml < 4.03.0 support

## 0.3.3 (2016-07-17)

* improve interop (instance tags) #10
* don't pack anymore
* switch to topkg

## 0.3.2 (2016-05-09)

* use result, 4.03 compatibility

## 0.3.1 (2016-03-21)

* get rid of camlp4, use ppx instead

## 0.3.0 (2015-12-20)

* add `update_config` function to update a session with given parameters
* use Astring instead of Stringext for String functionality

## 0.2.0 (2015-07-02)

* config contains policies and versions, but no longer the DSA key
* DSA key needs to be provided separately in new_session
* own_fingerprint takes a DSA key, not a config

## 0.1.1 (2015-04-25)

* expose full config structure
* handle simultaneous open (both parties send a DH_COMMIT) gracefully

## 0.1.0 (2015-01-24)

* initial release
