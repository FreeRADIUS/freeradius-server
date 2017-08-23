# rlm_radius

## Multiple connections

We probably don't want to load-balance across connections via
"num_outstanding" as with "load-balance" in v3.  We probably don't
want to order "live" connections by number of free packets.  Instead,
just use the "most lively" connection.  Which should do automatic
load-balancing.  i.e. if it JUST responded to us, it's probably ready
to take another packet.

We don't want "revive_interval", as (unlike v3) outgoing sockets are
connected.  When a connection fails, we rely on the underlying
connection state machine to try re-opening the connection.

... but only if we don't have Status-Server pings
(i.e. application-layer watchdog).  If we have that, then


The `rlm_radius` module should not have an idea as to the status of
the server, across multiple connections.  i.e. each connection is
handled separately.  That is because especially for TCP, one
connection can be dropped by a firewall, but another one can be fine.
So it should just treat each connection independently.

### What works

Connection states are:

* opening - connecting to the other end
* active - available for new requests
* full - no more IDs available on this connection
* zombie - has received MRC / MRT / MRD timeouts
  * TODO: we should start pinging as soon as a connection is zombie

### RADIUS fixes on retransmits

* don't do `u->packet = talloc_memdup()` if we're going to edit the
  packet

* delete rr->id and re-allocate it on retransmit if the packet changes
  * if the IDs are all allocated, a delete / re-allocate means that it
    gets the same ID.  So we might as well just do that all of the time.

### Limits

* limit the maximum number of proxied packets
* limit the maximum number of outgoing connections

Both will likely require atomic variables in rlm_radius.c, which are
slow...  Or, we just don't limit the number of proxied packets, and
instead rely on the other end to do some kind of push-back.  (HA!)

We should limit the number of outgoing connections, tho.

### Status Checks
    
    status_checks {
	type = Status-Server 
	# mrt, irt, mrc taken from another section, as per Access-Request, etc.
	
	# update the Status-Server packet here???
	# probably no need for a separate virtual server...
	# i.e. no policies
	# no if / then / else conditions
	# no templates, just static strings
	update request {
		User-Name = ...
		User-Password = ...
	}
    }


## synchronous proxying

much lower priority, as it requires other changes to the core

ala v3.  All retransmissions started by the client.

This requires a "signal" handler to be added when the module calls
unlang_yield.

The call to the signal handler is already in proto_radius_auth and
friends.

We could probably add a signal handler to the module, to handle the
DONE signal.  This would allow graceful cleanups.  Those are mostly
already handled via the talloc_free() hierarchy and destructors. But
it may be nice to distinguish the situations.  And, it lets us test
the signal handler independent of anything else.

Doing synchronous proxying also mean having the network side return
DUP PACKET (somehow).  And, send that dup packet signal to the worker.
Which somehow associates it with a request (probably via a simple
network thread + packet identifier).  This means that the worker has
to have yet another tree tracking packets... but it will allow for
signaling if necessary.

We probaby want the network + worker to be able to send IDs of 0/0,
which means "no tracking", as that will likely be the common case.

We also need the same thing for conflicting packets... we need a way
to tell the end modules to stop retransmitting the packet, as no one
cares about it any more.

## miscellaneous

* Check on packet lifetime timers in network side?
i.e. cleanup_delay, Double-check that they work...

* double-check ENABLE_SKIPS in src/lib/io/channel.c

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

What else...

* need to move to queue depth / active flag in channels / network / worker
  * the current ACK, and "my_view_of_their_shit" is just too complex

* need to double-check cleanup_delay
  * it works, but it's likely set too small?
  * especially if the client retransmits are 10s?
  * or maybe it was the dup detection bug (timestamp) where it didn't detect dups...

* really need to add dup and conflicting packet detection to the core..
  * which lets Status-Server get processed, and synchronous proxying
  * add cancel / signal handler in rlm_radius.

* ensure that the retransmission is independent of which connection
the packet is sent on.  This means keeping the various timers in 'u'
instead of in 'rr'.  i.e. if a connection closes, the packet should
just retransmit on a new connection.

* connection negotiation in Status-Server

* `status_check = auto`, which picks it up from the list of allowed
packet types.  We then need to require config for username / password,
for Access-Request, and just username for Accounting-Request.

