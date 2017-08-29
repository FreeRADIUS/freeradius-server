# rlm_radius

## RADIUS fixes

* delete rr->id and re-allocate it on retransmit if the packet changes
  * if the IDs are all allocated, a delete / re-allocate means that it
    gets the same ID.  So we might as well just do that all of the time.

* ensure that the retransmission is independent of which connection
  the packet is sent on.  This means keeping the various timers in 'u'
  instead of in 'rr'.  i.e. if a connection closes, the packet should
  just retransmit on a new connection.

## connection state

* CONN_UNUSED isn't used...

* CONN_STATUS_CHECKS isn't used... it's probably not useful, and
  should be deleted.

* maybe move Status-Server to fixed-time pings, as recommended in RFC 3539?
  * low priority, and probably not useful

## Limits

* limit the maximum number of proxied packets
* limit the maximum number of outgoing connections

Both will likely require atomic variables in rlm_radius.c, which are
slow...  Or, we just don't limit the number of proxied packets, and
instead rely on the other end to do some kind of push-back.  (HA!)

We should limit the number of outgoing connections, tho.

## Status Checks
    
* connection negotiation in Status-Server
  * some is there (Response-Length)
  * add more?  Extended ID, etc.

* enable editing of the contents of status check packets, specifically
  for Access-Request, etc. which need a User-Name

* it's probably better to just have an "update" section than manual
  configs?

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
  child REQUEST async stuff with listen, protocol handler, etc.

* fork also needs to do this sanity check on compile, so that it knows
  it can dereference sections which exist...

### clean up REQUEST structure

in_request_hash, in_proxy_hash, etc. are essentially unused.

all of those (and listen.c, etc.) need to be cleaned up and deleted.

grunt work, but very useful.
