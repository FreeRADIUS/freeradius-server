# rlm_eap_psk
## Metadata
<dl>
  <dt>category</dt><dd>authentication</dd>
</dl>

## Summary
Implements [RFC 4764](https://tools.ietf.org/html/rfc4764) EAP-PSK authentication.  EAP-PSK is a mutual-authentication
EAP method which is built entirely on AES-128, and uses a 16-byte pre-shared key.

The protocol state machine, message parsing, and cryptography live in the `eap_psk` process module
(`src/process/eap_psk`).  This submodule derives the next packet type from the session state, pushes the request into
the configured `eap-psk` virtual server, and translates the reply packet type back into an EAP result.

The pre-shared key is selected by the identity the peer asserts (`ID_P`): the `recv Identity-Response` section of the
`eap-psk` virtual server receives the asserted `Identity`, and supplies the key as `control.Password.PSK`, which must
be exactly 16 bytes long.  The server identity (`ID_S`) is configured in the virtual server, and may be overridden
per session from the `send Identity-Request` section.  See `raddb/sites-available/eap-psk` for a worked example.

EAP-PSK performs the four-message AKEP2-style exchange:

1. server -> peer: `Flags(T=0) || RAND_S || ID_S`
2. peer -> server: `Flags(T=1) || RAND_S || RAND_P || MAC_P || ID_P`
3. server -> peer: `Flags(T=2) || RAND_S || MAC_S || PCHANNEL`
4. peer -> server: `Flags(T=3) || RAND_S || PCHANNEL`

Messages which fail validation are silently discarded (RFC 4764 Section 4.1): the previous request is re-sent so the
peer can retry.  Policy may force an explicit EAP-Failure instead by setting `reply.Packet-Type := ::Failure`.

On success, the derived MSK is delivered in the Microsoft MPPE keys,
which means that EAP-PSK can be used for WPA/2-Enterprise
authentication.

All of the AES, CMAC, EAX, and random-number operations use OpenSSL, so the module is built only when OpenSSL is available.

## Configuration
<dl>
  <dt>virtual_server</dt><dd>The <code>eap-psk</code> virtual server which looks up the pre-shared key for a peer identity.</dd>
</dl>
