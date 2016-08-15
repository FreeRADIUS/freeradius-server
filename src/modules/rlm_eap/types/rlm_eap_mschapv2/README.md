# rlm_eap_mschapv2
## Metadata
<dl>
  <dt>category</dt><dd>authentication</dd>
</dl>

## Summary
Implements EAP-MSCHAPv2.  Usually used as an inner method for PEAP.

Allows NTLMv2 style authentication against Active-Directory, or where the NT-Password is known.

Technically does provide its own keying material via MPPE key attributes which could be used for 802.11i
(WPA/2-Enterprise) but in most instances, the keying material from an outer method is used instead.
