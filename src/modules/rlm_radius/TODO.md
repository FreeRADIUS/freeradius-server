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

We need to extract / insert the connection because it's location may have changed...

We probably don't want to load-balance across connections via
"num_outstanding" as with "load-balance" in v3.  We probably don't
want to order "live" connections by number of free packets.  Instead,
just use the "most lively" connection.  Which should do automatic
load-balancing.  i.e. if it JUST responded to us, it's probably ready
to take another packet.

The "full" connections should be on a *separate* heap, or maybe a
`fr_dlist_t`.  The extract / insert connection work needs to be done
in it's own function, because it's mostly magic, and needs to be done
in multiple places.

We need to track:

* connection state: connecting, live, full, zombie, dead
* connecting = trying, but not yet open
* live connections which have IDs available
* live connections which are "full"
  * either no more IDs, or we've seen EWOULDBLOCK
  * these don't have packets sent to them
* zombie connections
  * these don't have packets sent to them
  * they have Status-Server checks done
  * they are moved to "live" if we get 3 responses to Status-Server
  * they are moved to "live" if we get a response to a previously proxied request
* dead connections are closed

We need some more configuration options:

    # per-connection limits
    connection {
	# this is a per-thread limit.  Oops.
	max_connections
	connect_timeout
	reconnect_delay
	idle_timeout

	# as per 3.0
	response_window
	response_timeouts
	zombie_period
	revive_interval
    }
    
    # return RLM_MODULE_USERLOCK if we're sitting on too many packets
    # note that this is a per-thread limit.  Sorry about that.
    max_packets = 65536
    
    status_checks {
	type = Status-Server  # or NONE
	# mrt, irt, mrc taken from another section, as per Access-Request, etc.
	
	num_answers_to_alive
	# check_interval and check_timeout are no longer relevant
	# we just use MRT, IRT, etc.  if the response doesn't come
	# by the time we're sending the next packet, it's a timeout.
	
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

The `rlm_radius` module should not have an idea as to the status of
the server, across multiple connections.  i.e. each connection is
handled separately.  That is because especially for TCP, one
connection can be dropped by a firewall, but another one can be fine.
So it should just treat each connection independently.

The module should also track the state of multiple connections:

* connecting (all connections are connecting)
* live (one or more connection is live)
* full (all connections are full)
  * this should probably just return to the connecting state,
  * unless it hits max_connections
* zombie (all connections are zombie)
* dead (all connections are dead)
  * this should probably just return it to the connecting state.

## Connection status management

Mark a connection live / dead / zombie based on packet retransmission
timers.  Do Status-Server checks as necessary.

## status_check

add status_check = Status-Server or Access-Request, ala old code

The main issue here is the ID allocation... If this is set, then we
need to reserve one ID via `rr_track_alloc()` for the status-server
check.  Then use that ID if there are no responses to packets.

We should also allow `status_check = auto`, which picks it up from the
list of allowed packet types.  We then need to require config for
username / password, for Access-Request, and just username for
Accounting-Request.

## synchronous proxying

ala v3.  All retransmissions started by the client.

This requires a "signal" handler to be added when the module calls unlang_yield.

The call to the signal handler is already in proto_radius_auth and friends.

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

## miscellaneous

* Check on packet lifetime timers in network side?
i.e. cleanup_delay, Double-check that they work...
