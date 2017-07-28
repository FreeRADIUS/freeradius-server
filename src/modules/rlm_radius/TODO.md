# rlm_radius

## Multiple connections

rlm_radius_udp.c now has one connection, in `c->active`, which is an
`fr_dlist_t`.  That needs to be moved to a heap, ordered by (1)
most-recently active (i.e. most recent sent packet that had a
response), followed by (2) number of free IDs.

When we need a connection, we pop it from the heap.  Allocate an ID,
and push it back to the heap.

When we get a reply, we grab the connection, check / update
`last_sent_with_reply`, free the ID (unless it's Status-Server ping
checks), and extract / insert the connection back into the heap.

When the packet times out, we just free the ID (unless it's
Status-Server ping checks), and extract / insert the connection back
into the heap.

We need to extract / insert because it's location may have changed...

We *probably* want to keep one connection "full", if at all possible.
i.e. the heap should prefer connections with *fewer* free IDs.
... unless we're using extended ID, in which was we always pick an
active connection.  i.e. one that's writable.

The "full" connections should be on a *separate* heap, or maybe a
`fr_dlist_t`.  The extract / insert connection work needs to be done
in it's own function, because it's mostly magic, and needs to be done
in multiple places.

## Packet retransmission timers

Via similar code to v3.  See references to "jitter" and "mrt / irt /
mrc" in process.c in v3.

## Connection status management

Mark a connection live / dead / zombie based on packet retransmission
timers.  Set / do Status-Server checks as necessary.


## Type = Access-Request checking

Which (if set) limits the outbound packet types mainly so that we can
fail int the module instead of not getting a reply from the home
server and it mirrors the old configuration.

This also allows us to parse "Access-Request { ... }" sub-sections
only if there's an Access-Request.  i.e. we only get the debug output
for the various timers if they're needed.

see `rlm_radius.h`, retransmission intervals are in:

`rlm_radius_retry_t	packets[FR_MAX_PACKET_CODE];`

## status_check = Status-Server

add status_check = Status-Server or Access-Request, ala old code

The main issue here is the ID allocation... If this is set, then we
need to reserve one ID via `rr_track_alloc()` for the status-server
check.  Then use that ID if there are no responses to packets.

We should also allow `status_check = auto`, which picks it up from the
list of allowed packet types.  We then need to require config for
username / password, for Access-Request, and just username for
Accounting-Request.

## Replication (i.e. not proxying)

allow for "no reply" proxying, where we don't care about getting the reply
i.e. we still drain the socket, we just don't do anything with the replies

