# Dynamic client notes

Ideally we want dynamic clients to be generic across all RADIUS protocols (UDP, TCP, etc.)

Right now they're not.

We have the functions:

* dynamic_client_packet_restore(), which needs
  * inst->dynamic_clients
  * inst->ft
* dynamic_client_packet_save() which needs
  * TALLOC_CTX for allocating dynamic_packet_t
  * inst->dynamic_clients
  * inst->ft
  * proto_radius_udp_address_t address (for addresses)
* dynamic_client_alloc() which needs
  * TALLOC_CTX for allocating the dynamic client
  * inst->dynamic_clients
  * inst->ft, for calling dynamic_client_packet_save()
  * inst->el, for deleting timer events
* dynamic_client_expire(), a timer callback, which needs
  * inst->name for debug messages
  * inst->dynamic_clients
  * inst->cleanup_delay
  * calls dynamic_client_timer()
* dynamic_client_timer()
  * inst->el
  * inst for calling dynamic_client_expire()

So this can be put into a library for UDP / TCP uses

* putting name, ft, el, cleanup_delay into dynamic_client_t
* dynamically allocating inst->dynamic_clients?
  * that will be hard due to mod_instantiate issues...
  * better to just have a TALLOC_CTX in dynamic_client_t

# Connected UDP sockets

It's best to have the connected sockets themselves be just an instance
of proto_radius_udp.  That makes everything simple.

The question is whether or not we want to put the "track connection"
logic also into proto_radius_udp.  If so, we need to have special
logic to deal with that.

Connected UDP sockets require a "wildcard" socket, where packets are
received for new connections.  Once a connection has been established,
"connected" sockets read subsequent packets.

TBH, we probably want to dynamically change the "read" routine, to
avoid all kinds of issues related to if / then / else checking in the
main mod_read() routine.  That also allows for TCP sockets to have one
function for accept(), and another for read().

## Socket / Threading issues

The main issue here is that wildcard sockets are opened before
connected sockets.  As such, they may receive one or more packets
which are really for the connected sockets.  Dynamic clients make this
problem worse, as it may take large amounts of time to define a new
client.  During this time, the wildcard socket may receive dozens or
hundreds of packets.

Once the connected socket has been established, it will receive new
packets sent on that connection.  However, the old packets will still
be tracked / handled in the wildcard socket.

The problem is how to get them from one place to another.  These old
packets may still be read by the wildcard socket after the connected
socket has been opened.  So that relationship must be maintained for a
long period of time.

Further, these packets have to be sent from one thread to another, and
then somehow the connected socket has to process them, without reading
them from the socket.  We could use a shared mutex / linked list, but
the connected socket would then have to lock / check the mutex on
every packet, which is slow and expensive.

The solution would be to have a new `app_io` method, called
`mod_inject`.  This function would take the module context, a
per-packet context (e.g. src/dst IP/port), along with a packet plus
length.  The module would process this packet *as if it had been
received from the network*.  Any replies would be sent back out the
connected socket.

The question then becomes how to get that "injected" packet from one
network thread to another.  The wildcard socket knows it's own network
thread, and the `listen_t` handle of the connected socket.  And, the
connected socket via `mod_event_list_set()` has the handle to it's
local network thread.  We can therefore use all of this information to
send the packet to the appropriate network thread, which can then
route it to the listener, and then call `mod_inject`.

The only requirement here is that the wildcard and connected sockets
interact via a mutex and a linked list.  i.e. the parent wildcard
socket maintains a linked list of active children, with private
knowledge of their instance data.  The connected socket (child) then
has a pointer to the parent instance also.

When a parent opens a child socket, it:

* allocates the instance data,
* links the instance data to the parent via mutex  / linked list, and vice versa
* links ALL outstanding packets for this connection to the linked list
  * the structure has to hold `fr_dlist_t entry; fr_dlist_t packets; proto_radius_udp_t *child;`
  * and protected by a mutex
  * the `entry` is for the list of children
  * the `packets` are for the list of packets for this child.
* calls `mod_instantiate()` for the child socket
* then injects the listener into the scheduler.

When the child starts, it:

* `mod_event_list_add()` looks at the parent to see if there are any
  packets, and calls `mod_inject()` if so.

When the parent receives a subsequent packet for that child, it:

* locks the mutex finds the data structure above calls
* `fr_network_listen_inject()` with `child->nr` network socket, &&
* packet data in order to inject the packet.

All of this complexity is to deal with the idea that we want to keep
packets we've received.  Dropping packets is bad.  Relying on the NAS
to retransmit packets is bad.

If a child socket closes, it locks the mutex and removes itself from
the parents list.  Any subsequent packet will then hit the "new
connection" code, and proceed as before.

## proto_radius_connected_udp

Pretty much implemented as documented below.

### NAT

NAT mostly works.  The main limitation left is that the client list is
by source IP, and NOT by src/dst ip/port.  The solution is to keep
track of ongoing sessions (src/dst IP/port).  And then look up packets
in THAT table / tree, first.  If there's a match, send it over.
Otherwise, don't.

### how it works

uses the `proto_radius_udp_t` for simplicity

Which has added:

* proto_radius_udp_master_t structure, which contains
  * `TALLOC_CTX *ctx` talloc ctx for hash table && associated packets
  * `fr_hash_t *children;` for children, i.e. child IP addresses
    * which then needs to be cleaned up manually in `mod_detach()`
  * `int max_children`, etc. for tracking children
    * num_children is taken from the hash table
  * `pthread_mutex_t child_mutex` for the `children` hash
* `bool connection` true if connection oriented
* proto_radius_udp_child_t structure, which contains
  * packet ptr / length / recv_time (child only) for injected packets
  * `proto_radius_udp_t *master` for children to point to wildcard sockets

### Logic

proto_radius_connected_udp does:

* read packet
* look up allowed codes, etc.
* look up packet by src IP/port in `inst->children`
  * hash_cmp looks at src IP/port
* if found
  * lock mutex
  * `talloc_memdup(inst->hash_ctx, packet, packet_len)
  * probably best to have this packet be it's own talloc ctx...
    * so that the other network side can free it if necessary
  * call `fr_network_listen_inject(child->nr, child, packet data, recv_time)`
    * would be nice to have it take "my nr", so that it can bypass locks, etc.
  * return
* check for a known client
* if !found
  * do dynamic client stuff
  * return
* allocate child `proto_radius_udp_t`
  * with a new talloc ctx, so that the child can use it in a different thread
* `connect()` new socket
* add socket to `child->sockfd`
* set `child->master = inst`
* call `mod_instantiate()` on it
  * to get name and various other things

Much of this can likely be done in proto_radius_udp, with a few new functions

### mod_inject()

`mod_inject()` returns an error if there's already an injected packet.  This should never happen.

Otherwise, it saves packet / length / recv_time and returns

### mod_read()

`mod_read()` is hacked to:

* check for injected packets
* if exist, use that && NULL out the packet ptr
  * i.e. NOT free it
* otherwise behave as normal

### fr_network_listen_inject

fr_network_listen_inject() sends a control-plane message to the
destination network, which contains the packet information and the
socket data.

# Notes on proto_radius implementation

We wanted a generic proto_radius_transport, which contains the generic
functions encode / decode, nak, send_reply, etc.  The problem is that
much of this is transport-specific...

* split up fr_transport_t into multiple things:
  * IO layer (open / close / read / write)
    * proto_radius_udp
  * protocol (encode / decode)
    * proto_radius
  * process (radius_server_auth / acct / coa / status )
    * proto_radius_auth, etc.
