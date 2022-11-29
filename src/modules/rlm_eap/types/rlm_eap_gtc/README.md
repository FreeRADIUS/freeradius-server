# rlm_eap_gtc
## Metadata
<dl>
  <dt>category</dt><dd>authentication</dd>
</dl>

## Summary
Implements [RFC 3748](https://tools.ietf.org/html/rfc3748) EAP-GTC authentication.  EAP-GTC allows EAP authentication
using a plaintext password.

Does not provide keying material for 802.11i, so cannot be used for WPA/2-Enterprise authentication unless wrapped
in another method such as EAP-TTLS.
