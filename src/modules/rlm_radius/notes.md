# converting to connection tracker...

Notes:

* probably want a "synchronous" flag in connection struct, it just makes things easier
* and also whether or not we do status checks...

## status_check_timeout()

pretty much all RADIUS stuff

## conn_zombie_timeout()

about half RADIUS stuff

* needs to know if status checks are used
  * likely can go to a bool in connection

* needs to have callback io_

## state_transition()

* add io_transition_state_out(ctx, u, c)
 * returns true/false for continue
 * on false the caller just returns
 * due to status checks not transitioning to a different state
  * and on true, sets c->slots_free

* add io_transition_state_in(ctx, u, c)
  * returns true/false for succeeded
  * on false, it transitions u back to QUEUED
  * and on true, sets c->slots_free

## conn_read()

* can move all of the RADIUS stuff into a callback
  * it's all pretty well encapsulated

## retransmit_packet()

Essentially all RADIUS stuff

* called from response_timeout (conn handler)
* and mod_signal

* should be io_retransmit_packet()

## response_timeout()

Top half is all RADIUS

bottom half is connection handling
* which calls retransmit_packet()

## conn_write()

Writes a packet to a connection

Essentially 100% RADIUS

## conn_writable()

* checks for pending status packets, and writes those if necessary

* calls conn_write() to do protocol-specific dirty work

otherwise 100% non-RADIUS

## udp_request_free()

checks synchronous.  Otherwise 100% non-RADIUS

## status_udp_request_free()

essentially 100% RADIUS

## _conn_failed()

* needs RADIUS to delete status check retransmission timers and clean up the packets

* ideally io_transition_failed()

## _conn_open()

* callback to print the name of the connection?

* maybe io_transition_open() to build the status checks
  * can be moved to separate function without too much trouble

## conn_alloc()

* calls rr_track_create, maybe io_alloc() ?

## mod_push()

* sets initial retry timer && u->code?

everything else is non-RADIUS

## mod_signal()

check synchronous, but otherwise non-RADIUS
