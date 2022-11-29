# rlm_eap_peap
## Metadata
<dl>
  <dt>category</dt><dd>authentication</dd>
</dl>

## Summary
Implements PEAPv0, Microsoft's proprietary EAP method.

Allows NTLMv2 style authentication against Active-Directory, or where the NT-Password is known.

PEAP can also act as a transport for SoH (Statement of Health) messages, and as such, can be used as part of a NAC
solution, providing firewall, patch level, and antivirus state of the client.
