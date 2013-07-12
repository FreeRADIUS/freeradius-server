

rlm_hmac works a bit like rlm_digest

It can use either a Cleartext-Password or a Digest-HA1 value.  It
looks for both of them.

It is biased for STUN/TURN.  Specifically, this means that

- the HMAC key value is a H(A1) value (where H is MD5)

- the HMAC variant is HMAC-SHA1

It should be fairly trivial to generalise this module to
support other HMAC variants or key variants.  Digest-HA1
is convenient because it is used by SIP too.

Testing
-------

It can be tested by adding something like this to 
the file raddb/mods-config/files/authorize:

test   Auth-Type := HMAC, Cleartext-Password := "foobar"
       Reply-Message = "hello world"

testha1	Auth-Type := HMAC, Digest-HA1 := "61616161616161616161616161616161"
	Reply-Message = "hello world"

and creating a file /tmp/hmac.req:

User-Name = "test",
HMAC-Realm = "example.org",
HMAC-User-Name = "test",
HMAC-Nonce = "01234567890123456789012345678901",
HMAC-Algorithm = "HMAC-SHA1",
HMAC-Body = "unimportant message"

radclient can then be invoked with something like this:

  radclient -f /tmp/hmac.req localhost auth testing123

The reply packet (Access-Accept) contains the HMAC-Code value.
It can be used to verify a HMAC from a peer or to sign a message
to be sent to the peer.  STUN/TURN needs to use the values in
both of these paradigms.

