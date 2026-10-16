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
Routing is by Operator-Name, as in RFC 8559 Section 3.2.

There are two roles.

The server role is the one which accepts connections: a listener with
`type = auth+acct+coa` and TLS.  Policy attaches a key to a connection
by setting `control:Originating-Realm-Key`, normally from
`Operator-Name`.  The key is attached when the server sends the first
reply on that connection for a request which set it.  A CoA or
Disconnect to be sent down a connection carries the same string in
`control:Proxy-To-Originating-Realm` (for received packets) or in the
`coa` or `disconnect` list (for packets originated with `update coa`
or `update disconnect`).  The server picks an open connection holding
that key.

The client role is a NAS, or a proxy in front of one: a home server
with `type = auth+acct+coa` and a `recv_coa { virtual_server = ... }`
section.  Requests arriving on the outbound connection run through
that virtual server, and the reply goes back on the same connection.

`raddb/sites-available/reverse-coa` is a complete server-side example.

## Keep the connection open

With `lifetime = 0`, an `idle_timeout` of 0 on the listener is turned
into 30 seconds, and the client's own `idle_timeout` (default 30) is
applied as the minimum of the two.  Set a lifetime and
`idle_timeout = 0` on both the listener limit and the client limit.

The key is per connection.  After a reconnect it is attached again by
the next reply whose request sets it, and nothing can be routed to
that peer in between.

## Timers

`coa { irt mrt mrc mrd }` inside the listener sets the timers for
packets sent down the connection.  Packets proxied to the NAS are not
retransmitted, and `mrd` is how long the server waits for the NAS to
answer.  Packets originated with `update coa` still use `irt`, `mrt`
and `mrc`.

## Error causes

A request which the policy does not give a key, or whose key has no
open connection, is answered with `Proxy-Request-Not-Routable` (502).
The example site answers a request without Operator-Name with
`Missing-Attribute` (402) from policy.

## Testing

`src/tests/radsec` covers the feature, including a Disconnect sent
down the tunnel.  It is not part of `make test`.  On a developer build
with the flag:

    make -C src/tests/radsec tests.radsec

## Known limits

- Operator-Name namespaces other than 1 are not routed by rlm_realm's
  forward CoA path.  The key set by policy can be any string.
- One key per connection.  Draft section 6 requires many realms per
  connection.
- No capability flag per client.  The `+coa` listener type is the
  switch.
- Protocol-Error is not accepted as a reply on the inbound connection.
- No Event-Timestamp check in the CoA path.
- Originated packets over TLS still run the UDP retransmit timers.
