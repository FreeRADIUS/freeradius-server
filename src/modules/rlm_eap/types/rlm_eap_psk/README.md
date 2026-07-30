# rlm_eap_psk
## Metadata
<dl>
  <dt>category</dt><dd>authentication</dd>
</dl>

## Summary
Implements [RFC 4764](https://tools.ietf.org/html/rfc4764) EAP-PSK authentication.  EAP-PSK is a mutual-authentication
EAP method which is built entirely on AES-128, and uses a 16-byte pre-shared key.

The pre-shared key is taken from the `Password.Cleartext` attribute, which must be exactly 16 bytes long.  The server
identity (`ID_S`) sent to the peer is configured with the `identity` option (default `FreeRADIUS`).

EAP-PSK performs the four-message AKEP2-style exchange:

1. server -> peer: `Flags(T=0) || RAND_S || ID_S`
2. peer -> server: `Flags(T=1) || RAND_S || RAND_P || MAC_P || ID_P`
3. server -> peer: `Flags(T=2) || RAND_S || MAC_S || PCHANNEL`
4. peer -> server: `Flags(T=3) || RAND_S || PCHANNEL`

On success, the derived MSK is delivered in the Microsoft MPPE keys,
which means that EAP-PSK can be used for WPA/2-Enterprise
authentication.

All of the AES, CMAC, EAX, and random-number operations use OpenSSL, so the module is built only when OpenSSL is available.

## Configuration
<dl>
  <dt>identity</dt><dd>The server NAI (`ID_S`) sent in the first message.  Defaults to <code>FreeRADIUS</code>.</dd>
</dl>
