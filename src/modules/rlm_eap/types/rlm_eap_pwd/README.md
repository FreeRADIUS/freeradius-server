# rlm_eap_pwd
## Metadata
<dl>
  <dt>category</dt><dd>authentication</dd>
</dl>

## Summary
Implements EAP-PWD as described by [RFC 5931](https://tools.ietf.org/html/rfc5931).

EAP-PWD allows authentication using a PSK (the user's password).  The PSK is not sent in the clear, instead each side
proves knowledge of the password using Elliptic Curve cryptography.
