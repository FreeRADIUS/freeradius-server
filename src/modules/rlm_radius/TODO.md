# rlm_radius

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

ala v3.  All retransmissions started by the client.

This is probably trivial as a side-effect of doing de-dup /
conflicting packet in the server core.

This requires a "signal" handler to be added when the module calls
unlang_yield.

The call to the signal handler is already in proto_radius_auth and
friends.

We should add a signal handler to the module, to handle the DUP / DONE
signals.  This would allow graceful cleanups.  Those are mostly
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

* fix fork

    fork server.packet-type {
        &foo += &parent:bar
    }

* fork is an 'update' section that also runs a new virtual server.  A
  little weird, but it should work.

* needs helper functions in virtual_server.c to do it.. and to create
  child REQUEST async stuff with listen, protocol handler, etc.

* fork also needs to do this sanity check on compile, so that it knows
  it can dereference things which exist...