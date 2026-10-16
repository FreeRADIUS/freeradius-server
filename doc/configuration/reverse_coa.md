# Reverse CoA over RADIUS/TLS

The code is in v3.2.x behind a build flag, and is experimental.  Build
with

    CFLAGS += -DWITH_COA_TUNNEL

in Make.inc after running configure.  `radiusd -xxv` lists
`recv-coa-from-home-server : yes` when the flag is set.

## What it does

A RADIUS/TLS client opens a connection to the server as usual.  With
`type = auth+acct+coa` on the listener, the server may send
CoA-Request and Disconnect-Request packets back down that connection,
and the client answers on it.  This is draft-ietf-radext-reverse-coa.
Routing is by Operator-Name, as in RFC 8559 Section 3.2, or by any
other string policy chooses.

There are two roles.

The server role is the one which accepts connections: a listener with
`type = auth+acct+coa` and TLS.  Policy attaches keys to a connection
by setting `control:Originating-Realm-Key`; the key is attached when
the server sends a reply on that connection for a request which set
it.  A connection can carry many keys, each once, up to `max_keys` in
the listener's `coa` section.  A value with a leading `-` removes that
key; a leading `+` is accepted and ignored.  A Status-Server from the
peer carrying Operator-Name values with the same signs does the same.
Keys go with the connection when it closes.

A CoA or Disconnect to be sent down a connection carries one or more
strings in `control:Proxy-To-Originating-Realm` (for received packets)
or in the `coa` or `disconnect` list (for packets originated with
`update coa` or `update disconnect`).  They are tried in the order
policy set them, and the first one which names an open connection
wins.  Among several connections with the same key, the one with the
fewest requests in flight is used.

The client role is a NAS, or a proxy in front of one: a home server
with `type = auth+acct+coa` and a `recv_coa { virtual_server = ... }`
section.  Requests arriving on the outbound connection run through
that virtual server, and the reply goes back on the same connection.
A dynamic home server, for example one added from a NAPTR lookup, may
have a `recv_coa` section too.

`raddb/sites-available/reverse-coa` is a complete server-side example.

## Per-client flag

`reverse_coa = yes|no` in a client block says whether that client
takes CoA on its own connections.  The default is `yes`.  With `no`,
no key is attached for the client, from policy or from Status-Server,
and nothing is sent down its connections.  This is the per-client
flag of draft section 4; the `+coa` listener type stays the switch
for the listener.

## Session affinity

A peer with several connections to the server carries sessions on
each of them.  A CoA for a session has to go down the connection which
carried that session (the OpenRoaming connection management text says
so, and a NAS behind a proxy may only answer there).  The example site
does it in policy: the Accounting-Response to a Start attaches
`sid:<Acct-Session-Id>` as a key, the Stop removes it, and the
Access-Accept attaches `cui:<Chargeable-User-Identity>` when one was
issued.  The originate policy then sets the session key first and the
Operator-Name after it, so a request follows the session when it can
and the realm when it must.

The server does not keep a session table of its own; the attributes a
CoA needs (Operator-Name as recorded, Acct-Session-Id, CUI,
Operator-NAS-Identifier verbatim if the peer sent one) come from
wherever accounting is stored, and policy copies them into the
request.  When several server instances share that store, record
which instance answered the Access-Accept: only that instance holds
the connection, and a request injected elsewhere is proxied to it as
an ordinary CoA.

## Keep the connection open

With `lifetime = 0`, an `idle_timeout` of 0 on the listener is turned
into 30 seconds, and the client's own `idle_timeout` (default 30) is
applied as the minimum of the two.  Set a lifetime and
`idle_timeout = 0` on both the listener limit and the client limit.

Peers keep the connection alive with Status-Server.  Set
`status_server = yes` in `radiusd.conf` so that the server answers
them on TLS connections.

After a reconnect the keys are attached again by the next replies
whose requests set them, and nothing can be routed to that peer in
between.

## Timers

`coa { irt mrt mrc mrd }` inside the listener sets the timers for
packets sent down the connection.  Nothing is sent twice over a
stream.  `mrd` is how long the server waits for the NAS to answer a
proxied request, and an originated request gives up at `mrc` or
`mrd`.  The home server made for an inbound connection waits `mrd`
as well.

A home server over TCP or TLS which cannot be connected to is retried
with an exponential back-off, from one second doubling up to
`connect_fail_interval`, with jitter.  A reply from it resets the
back-off.

## Error causes

A request whose keys name no open connection is answered with
`Proxy-Request-Not-Routable` (502).  A request whose key is known but
whose connections all have 256 requests in flight is answered with
`Proxy-Processing-Error` (505).  The example site answers a request
without Operator-Name with `Missing-Attribute` (402) from policy, and
one with a stale Event-Timestamp with `Invalid-Request` (404).
Protocol-Error from the NAS is accepted as a reply and turned into the
matching NAK for a client which does not take Protocol-Error.

A peer which does not implement reverse CoA discards the request
silently, and the server answers 502 after `mrd`.  Policy can remember
that per Operator-Name, for example with rlm_cache, and stop sending
to that peer.

## Testing

`src/tests/radsec` covers the feature, including a Disconnect sent
down the tunnel.  It is not part of `make test`.  On a developer build
with the flag:

    make -C src/tests/radsec tests.radsec

## Known limits

- Operator-Name namespaces other than 1 are not routed by rlm_realm's
  forward CoA path.  The keys set by policy can be any string.
- The key table is per process.  Several instances need the store
  described under session affinity.
- A dynamic home server created from DNS is not re-resolved when the
  DNS TTL expires; the lookup has to be run again by policy, and a
  changed address replaces the old one.
