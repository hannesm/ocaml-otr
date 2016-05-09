0.3.2 (2016-05-09):
* use result, 4.03 compatibility

0.3.1 (2016-03-21):
* get rid of camlp4, use ppx instead

0.3.0 (2015-12-20):
* add `update_config` function to update a session with given parameters
* use Astring instead of Stringext for String functionality

0.2.0 (2015-07-02):
* config contains policies and versions, but no longer the DSA key
* DSA key needs to be provided separately in new_session
* own_fingerprint takes a DSA key, not a config

0.1.1 (2015-04-25):
* expose full config structure
* handle simultaneous open (both parties send a DH_COMMIT) gracefully

0.1.0 (2015-01-24):
* initial release