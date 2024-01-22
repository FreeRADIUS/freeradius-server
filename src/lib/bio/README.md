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

* abstracting TCP versus UDP socket IO

* allowing packet-based reads and writes, instead of byte-based
  * i.e. so that application protocol state machines do not have to
  * deal with partial packets.

* Use protocol-agnostic memory buffers to track partial reads and
  partial writes.

* allowing "written" data to be cancelled or "unwritten".  Packets
  which have been written to the bio, but not yet to the network can
  be cancelled at any time.  The data then disappears from the bio,
  and is never written to the network.

* allowing chaining, so that an application can write RADIUS packets
  to a bio, and then have those packets go through a TLS
  transformation, and then out a TCP socket.

* Chaining also allows applications to selectively add per-chain
  functionality, without affecting the producer or consumer of data.

* allowing unchaining, so that we can have a bio say "I'm done, and no
  longer needed".  This happens for example when we have a connection
  from haproxy.  The first ~128 bytes of a TCP connection are the
  original src/dst ip/port.  The data after that is just the TLS
  transport.  The haproxy layer needs to be able to intercept and read
  that data, and then remove itself from the chain of bios.

* abstraction, so that the application can be handed a bio, and use
  it.  The underlying bio might be UDP, TCP, TLS, etc.  The
  application does not know, and can behave identically for all
  situations.  There are some limitations, of course.  Something has
  to create the bios and their respective chains.  But once a "RADIUS"
  bio, has been created, the RADIUS application can read and write
  packets to it without worrying about underlying issues of UDP vs
  TCP, TLS vs clear-text, dedup, etc.

* simplicity.  Any transport-specific function knows only about that
  transport, and it's own bio.  It does not need to know about other
  bios (unless it needs them, as with TLS -> TCP).  The function does
  not know about packets or protocols.  We should be able to use the
  same basic UDP/TCP network bios for most protocols.  Or if we
  cannot, the duplicated code should be trivial, and little more than
  `read()` and some checks for error conditions (EOF, blocked, etc.)

* If the caller needs to do something with a particular bio, that bio
  will expose an API specific to that bio.  There is no reason to copy
  that status back up the bio chain.  This also means that the caller
  often needs to cache the multiple bios, which is fine.

* asynchronous at its core.  Anything can block at any time.  There
  are callbacks if necessary.

* no run-time memory allocations for bio operations.  Everything
  operates on pre-allocated structures

* O(1) operations where possible.

* each bio in large part runs as its own state machine.  It does what
  it needs to do.  It exposes APIs for the caller (who must know what
  it is).  It has its own callbacks to modify its operation.

* not thread-safe.  Use locks, people.

There are explicit _non-goals_ for the bio API.  These non-goals are
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
  descriptor to be used, but the bio layer itself runs nothing more
  than state-specific callbacks, defined on a per-bio basis.

* decoding / encoding packet contents.  This is handled by dbuffs,
  which are bounds checkers around memory buffers.  i.e. they check
  and enforce nested bounds on packets, nested attributes, etc.  But
  dbuffs have no concept of multiple packets, deduplication, file
  descriptors, etc.
