# rlm_opendirectory
## Metadata
<dl>
  <dt>category</dt><dd>authentication</dd>
</dl>

## Summary

Integrates with an Apple OpenDirectory service on the same host as
FreeRADIUS to allow OpenDirectory users to authenticate.

This module does not provide the user's password, so cannot be
used with other authentication modules such as rlm_eap_peap.
