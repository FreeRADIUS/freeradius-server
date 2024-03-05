# Binary IO API

The binary input / output (bio) API is intended to abstract a wide
range of issues related to network IO.  Historically (v3) we just
"wrote the code until it worked", which meant that the same piece of
code handled network transport issues (e.g. TCP), protocol issues
(e.g. RADIUS), connection issues (up / down / reconnect), and eventing
issues (socket readable / blocked).

This style of programming lead to complex interconnected state
machines which were difficult to write, to maintain, and to debug.

v4 is better with many of these functions split out into separate
APIs, such as connections, trunking, etc.  However, the input
listeners and output client modules (e.g. rlm_radius and radclient)
still have the transport and protocol states intermixed.  This makes
the read / write routines complex, and difficult to extend.

For these reasons and more, as of early 2024, v4 does not have input
TLS listeners, or output TCP or TLS for RADIUS proxying.  We then have
a horrid mess dynamic clients, haproxy connections, network source IP
filtering, UDP vs TCP issues, and connected vs unconnected sockets,
and finally TLS. It is essentially impossible to write code which
handles all of these issues simultaneously.

The issues addressed by bios include the following items:

* be based on _independent blocks_ (e.g. file IO, memory buffers,
  etc).

* be composable, so that blocks can be _chained_ or _unchained_ to
  oqbtain complex functionality.

* be _abstracted_ so that the application using the bio has little
  need to understand the difference between the individual blocks

* be _declarative_ where possible, so an application can declare a
  data structure saying "this is the kind of bio I want", and the
  underlying bio "alloc" or "create" API does the right thing.

* be _callback_ oriented, so that the bio calls the application to do
  application-specific things, and the bio handles the abstractions

* be _state machine_ oriented, so that inside of the bio, the
  functionality is broken into a series of small functions.  If the
  bio is in a different state, it changes its internal function
  pointers to manage that state.  This approach is better than large
  functions with masses of if / then / else

* be _exposed_ so that the individual blocks do not hide everything
  from the application.  Each block exports an info / state structure.
  The application can example the internal state of the block.  This
  approach stops the M*N API explosion typically seen when every block
  has to implement all of the get/set functionality of every other
  block.

* Be _modifiable_ so that blocks can be chained / unchained on the
  fly.  This capability allows applications to add / delete things
  like dynamic filters (haproxy or dynamic client) on the fly.

* Allow for a _separation_ of application issues (basic bio
  read/write) from protocol state machine issues (packet retransmit,
  etc.)  The application largely just calls read / write to the bio,
  any bio modifications are done by the protocol state machine.

* be _asynchronous_ where possible.  Anything can block at any time.  There
  are callbacks if necessary.

* _avoid_ run-time memory allocations for bio operations.  Everything
  should operate on pre-allocated structures

* O(1) operations where possible.

* each bio in large part runs as its own state machine.  It does what
  it needs to do.  It exposes APIs for the caller (who must know what
  it is).  It has its own callbacks to modify its operation.

* the bios do _not_ need to be thread-safe.

There are some explicit _non-goals_ for the bio API.  These non-goals are
issues which are outside of the scope of bios, such as:

* As an outcome of simplicity, there are no bio-specific wrappers for
  modifying file descriptors.  An application is free to cache the FD,
  associate it with the application layer, and call eventing functions
  to get "readable" or "writable" callbacks.  The application can also
  get / set socket information manually, such as "get IP" or "bind to
  particular port".

* configuration. The bios expose configuration structures (static
  input used to create a bio), and run-time informational structures
  (dynamic information about the state of the bio).  The API is small,
  and all uses of get/set member functions should be avoided.  We
  presume that the caller is smart enough to not muck with the current
  state of the bio.

* eventing and timers.  The bios can allow an underlying file
  descriptor to be used, but the bio layers usually run nothing more
  than state-specific callbacks, defined on a per-bio basis.

* decoding / encoding packet contents.  This is handled by dbuffs,
  which are bounds checkers around memory buffers.  i.e. they check
  and enforce nested bounds on packets, nested attributes, etc.  But
  dbuffs have no concept of multiple packets, deduplication, file
  descriptors, etc.

