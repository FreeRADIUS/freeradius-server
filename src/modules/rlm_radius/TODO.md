# rlm_radius

## 2017-10-11

After refactoring...

* on read(), don't put connection into active state, as it may not be writable?
 * or, just do it, and hope for the best... with the event loop handling it


## RADIUS fixes

* idle out old connections

* limit # of bad / reconnected connections

* move status_u allocation and init to connection alloc

## connection state

* maybe move Status-Server to fixed-time pings, as recommended in RFC 3539?
  * low priority, and probably not useful

## Limits

We limit the number of connections, but not the number of proxied
packets.  This is because (for now), each connection can only proxy 256 packets...

## Status Checks
    
* connection negotiation in Status-Server in proto_radius
  * some is there (Response-Length)
  * add more?  Extended ID, etc.

## Core Issues

things to do in the server core.  Tracked here because it's related to
the work in rlm_radius.

## Cleanup_delay

* need to double-check cleanup_delay
  * it works, but it's likely set too small?
  * especially if the client retransmits are 10s?
  * or maybe it was the dup detection bug (timestamp) where it didn't detect dups...

## sequence / ACK in network / worker

* double-check ENABLE_SKIPS in src/lib/io/channel.c.  It's disabled
  for now, as it caused problems.  So it ALWAYS signals the other side. :(

We should move to a "must_signal" approach, as with the network side
The worker should suppress signals if it sees that the ACKs from the
other end haven't caught up to it's sent packets.  Otherwise, it must
signal.

this whole thing is wrong... we end up signaling on every damned packet in real life...

OK... fix the damned channel to use queue depth instead of ACKs
which makes them less general, but better.  The worker can NAK a packet, send a reply, or mark it ask discarded

DATA		N -> W: (packet + queue 1, active)

DATA		N <- W (packet + queue is now 0, inactive)

DISCARD		N <- W (no packet, queue is now 0, inactive)

SLEEPING	N <- W (no packet, queue is 1, inactive)

We also need an "must_signal" flag, for if the other end is
sleeping... the network always sets it, I guess..

### Fork

* fix fork

    fork server.packet-type {
        &foo += &parent:bar
    }

* fork is an 'update' section that also runs a new virtual server.  A
  little weird, but it should work.

* needs helper functions in virtual_server.c to do it.. and to create
  child request_t async stuff with listen, protocol handler, etc.

* fork also needs to do this sanity check on compile, so that it knows
  it can dereference sections which exist...

### clean up request_t structure

many fields are essentially unused.  request->proxy is no longer used,
but is referenced all over the place.

grunt work, but very useful.

### Network and worker fixups

* switch worker selection from recursing / heap to O(N) lookups and "power of 2"
  * see comments in src/lib/io/network.c

* associate packets with a particular worker across multiple packets
  * once this is done, we can move to per-thread SSL contexts, and drop contention massively
  * with the caveat that *all SSL work* has to be done in one thread
  * hopefully this doesn't affect things like SQL drivers?  need to check...

* do NUMA for high-end systems
  * associate N network threads with W worker threads
