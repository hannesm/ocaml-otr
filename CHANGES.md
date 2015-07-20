master:
* add `update_config` function to update a session with given parameters

0.2.0 (2015-07-02):
* config contains policies and versions, but no longer the DSA key
* DSA key needs to be provided separately in new_session
* own_fingerprint takes a DSA key, not a config

0.1.1 (2015-04-25):
* expose full config structure
* handle simultaneous open (both parties send a DH_COMMIT) gracefully

0.1.0 (2015-01-24):
* initial release