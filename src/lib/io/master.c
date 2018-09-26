/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 * @file io/master.c
 * @brief Master IO handler
 *
 * @copyright 2018 Alan DeKok (aland@freeradius.org)
 */
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/server/modules.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/io/master.h>
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/server/rad_assert.h>

#define PR_CONNECTION_MAGIC (0x434f4e4e)
#define PR_MAIN_MAGIC	    (0x4d4149e4)

typedef struct fr_io_live_t {
	fr_event_list_t			*el;				//!< event list, for the master socket.
	fr_network_t			*nr;				//!< network for the master socket

	fr_trie_t			*trie;				//!< trie of clients
	fr_heap_t			*pending_clients;		//!< heap of pending clients
	fr_heap_t			*alive_clients;			//!< heap of active clients

	fr_listen_t			*listen;			//!< The master IO path
	fr_listen_t			*child;				//!< The child IO path
	fr_schedule_t			*sc;				//!< the scheduler

	// @todo - count num_nak_clients, and num_nak_connections, too
	uint32_t			num_connections;		//!< number of dynamic connections
	uint32_t			num_pending_packets;   		//!< number of pending packets
} fr_io_live_t;

/** A saved packet
 *
 */
typedef struct {
	int			heap_id;
	uint32_t		priority;
	fr_time_t		recv_time;
	fr_io_track_t		*track;
	uint8_t			*buffer;
	size_t			buffer_len;
} fr_io_pending_packet_t;


/** Client states
 *
 */
typedef enum {
	PR_CLIENT_INVALID = 0,
	PR_CLIENT_STATIC,				//!< static / global clients
	PR_CLIENT_NAK,					//!< negative cache entry
	PR_CLIENT_DYNAMIC,				//!< dynamically defined client
	PR_CLIENT_CONNECTED,				//!< dynamically defined client in a connected socket
	PR_CLIENT_PENDING,				//!< dynamic client pending definition
} fr_io_client_state_t;

typedef struct fr_io_connection_t fr_io_connection_t;

/** Client definitions for master IO
 *
 */
typedef struct fr_io_client_t {
	fr_io_connection_t		*connection;	//!< parent connection
	fr_io_client_state_t		state;		//!< state of this client
	fr_ipaddr_t			src_ipaddr;	//!< packets come from this address
	fr_ipaddr_t			network;	//!< network for dynamic clients
	RADCLIENT			*radclient;	//!< old-style definition of this client

	int				packets;	//!< number of packets using this client
	int				pending_id;	//!< for pending clients
	int				alive_id;	//!< for all clients

	bool				use_connected;	//!< does this client allow connected sub-sockets?
	bool				ready_to_delete; //!< are we ready to delete this client?
	bool				in_trie;	//!< is the client in the trie?

	fr_io_instance_t const		*inst;		//!< parent instance for master IO handler
	fr_io_live_t			*live;
	fr_event_timer_t const		*ev;		//!< when we clean up the client
	rbtree_t			*table;		//!< tracking table for packets

	fr_heap_t			*pending;	//!< pending packets for this client
	fr_hash_table_t			*addresses;	//!< list of src/dst addresses used by this client

	pthread_mutex_t			mutex;		//!< for parent / child signaling
	fr_hash_table_t			*ht;		//!< for tracking connected sockets
} fr_io_client_t;

/** Track a connection
 *
 *  This structure contains information about the connection,
 *  a pointer to the library instance so that we can clean up on exit,
 *  and the listener.
 *
 *  It also points to a client structure which is for this connection,
 *  and only this connection.
 *
 *  Finally, a pointer to the parent client, so that the child can
 *  tell the parent it's alive, and the parent can push packets to the
 *  child.
 */
struct fr_io_connection_t {
	int				magic;		//!< sparkles and unicorns
	char const			*name;		//!< taken from proto_FOO_TRANSPORT
	int				packets;	//!< number of packets using this connection
	fr_io_address_t   		*address;      	//!< full information about the connection.
	fr_listen_t			*listen;	//!< master listener for this socket
	fr_listen_t			*child;		//!< child listener for this socket
	fr_io_client_t			*client;	//!< our local client (pending or connected).
	fr_io_client_t			*parent;	//!< points to the parent client.
	dl_instance_t   		*dl_inst;	//!< for submodule

	bool				dead;		//!< roundabout way to get the network side to close a socket
	bool				paused;		//!< event filter doesn't like resuming something that isn't paused
	fr_event_list_t			*el;		//!< event list for this connection
	fr_network_t			*nr;		//!< network for this connection
};

static fr_event_update_t pause_read[] = {
	FR_EVENT_SUSPEND(fr_event_io_func_t, read),
	{ 0 }
};

static fr_event_update_t resume_read[] = {
	FR_EVENT_RESUME(fr_event_io_func_t, read),
	{ 0 }
};

/*
 *  Return negative numbers to put 'one' at the top of the heap.
 *  Return positive numbers to put 'two' at the top of the heap.
 */
static int pending_packet_cmp(void const *one, void const *two)
{
	fr_io_pending_packet_t const *a = one;
	fr_io_pending_packet_t const *b = two;
	int rcode;

	/*
	 *	Larger numbers mean higher priority
	 */
	rcode = (a->priority < b->priority) - (a->priority > b->priority);
	if (rcode != 0) return rcode;

	/*
	 *	Smaller numbers mean packets were received earlier.
	 *	We want to process packets in time order.
	 */
	rcode = (a->recv_time > b->recv_time) - (a->recv_time < b->recv_time);
	if (rcode != 0) return rcode;

	/*
	 *	After that, it doesn't really matter what order the
	 *	packets go in.  Since we'll never have two identical
	 *	"recv_time" values, the code should never get here.
	 */
	return 0;
}

/*
 *	Order clients in the pending_clients heap, based on the
 *	packets that they contain.
 */
static int pending_client_cmp(void const *one, void const *two)
{
	fr_io_pending_packet_t const *a;
	fr_io_pending_packet_t const *b;

	fr_io_client_t const *c1 = one;
	fr_io_client_t const *c2 = two;

	a = fr_heap_peek(c1->pending);
	b = fr_heap_peek(c2->pending);

	rad_assert(a != NULL);
	rad_assert(b != NULL);

	return pending_packet_cmp(a, b);
}


static int address_cmp(void const *one, void const *two)
{
	int rcode;
	fr_io_address_t const *a = one;
	fr_io_address_t const *b = two;

	rcode = (a->src_port - b->src_port);
	if (rcode != 0) return rcode;

	rcode = (a->dst_port - b->dst_port);
	if (rcode != 0) return rcode;

	rcode = (a->if_index - b->if_index);
	if (rcode != 0) return rcode;

	rcode = fr_ipaddr_cmp(&a->src_ipaddr, &b->src_ipaddr);
	if (rcode != 0) return rcode;

	return fr_ipaddr_cmp(&a->dst_ipaddr, &b->dst_ipaddr);
}

static uint32_t connection_hash(void const *ctx)
{
	uint32_t hash;
	fr_io_connection_t const *c = ctx;

	hash = fr_hash(&c->address->src_ipaddr, sizeof(c->address->src_ipaddr));
	hash = fr_hash_update(&c->address->src_port, sizeof(c->address->src_port), hash);

	hash = fr_hash_update(&c->address->if_index, sizeof(c->address->if_index), hash);

	hash = fr_hash_update(&c->address->dst_ipaddr, sizeof(c->address->dst_ipaddr), hash);
	return fr_hash_update(&c->address->dst_port, sizeof(c->address->dst_port), hash);
}


static int connection_cmp(void const *one, void const *two)
{
	fr_io_connection_t const *a = one;
	fr_io_connection_t const *b = two;

	return address_cmp(a->address, b->address);
}


static int track_cmp(void const *one, void const *two)
{
	fr_io_track_t const *a = one;
	fr_io_track_t const *b = two;
	int rcode;

	/*
	 *	Call the per-protocol comparison function, if it
	 *	exists.
	 */
	rcode = a->client->inst->app_io->compare(a->client->inst->app_io_instance,
						 a->packet, b->packet);
	if (rcode != 0) return rcode;

	/*
	 *	Connected sockets MUST have all tracking entries use
	 *	the same client definition.
	 */
	if (a->client->connection) {
		rad_assert(a->client == b->client);
		return 0;
	}

	rad_assert(!b->client->connection);

	/*
	 *	Unconnected sockets must check src/dst ip/port.
	 */
	return address_cmp(a->address, b->address);
}


static fr_io_pending_packet_t *pending_packet_pop(fr_io_live_t *live)
{
	fr_io_client_t *client;
	fr_io_pending_packet_t *pending;

	client = fr_heap_pop(live->pending_clients);
	if (!client) {
		/*
		 *	99% of the time we don't have pending clients.
		 *	So we might as well free this, so that the
		 *	caller doesn't keep checking us for every packet.
		 */
		talloc_free(live->pending_clients);
		live->pending_clients = NULL;
		return NULL;
	}

	pending = fr_heap_pop(client->pending);
	rad_assert(pending != NULL);

	/*
	 *	If the client has more packets pending, add it back to
	 *	the heap.
	 */
	if (fr_heap_num_elements(client->pending) > 0) {
		(void) fr_heap_insert(live->pending_clients, client);
	}

	rad_assert(live->num_pending_packets > 0);
	live->num_pending_packets--;

	return pending;
}

static RADCLIENT *radclient_clone(TALLOC_CTX *ctx, RADCLIENT const *parent)
{
	RADCLIENT *c;

	if (!parent) return NULL;

	c = talloc_zero(ctx, RADCLIENT);
	if (!c) return NULL;

	/*
	 *	Do NOT set ipaddr or src_ipaddr.  The caller MUST do this!
	 */

#define DUP_FIELD(_x) do { if (parent->_x) {c->_x = talloc_strdup(c, parent->_x); if (!c->_x) {goto error;}}} while (0)
#define COPY_FIELD(_x) c->_x = parent->_x

	DUP_FIELD(longname);
	DUP_FIELD(shortname);
	DUP_FIELD(secret);
	DUP_FIELD(nas_type);
	DUP_FIELD(server);
	DUP_FIELD(nas_type);

	COPY_FIELD(message_authenticator);
	/* dynamic MUST be false */
	COPY_FIELD(server_cs);
	COPY_FIELD(cs);
	COPY_FIELD(proto);
	COPY_FIELD(use_connected);

#ifdef WITH_TLS
	COPY_FIELD(tls_required);
#endif

	return c;

	/*
	 *	@todo - fill in other fields, too!
	 */

error:
	talloc_free(c);
	return NULL;
}
#undef COPY_FIELD
#undef DUP_FIELD


/** Count the number of connections used by active clients.
 *
 *  Unfortunately, we also count NAK'd connections, too, even if they
 *  are closed.  The alternative is to walk through all connections
 *  for each client, which would be a long time.
 */
static int count_connections(void *ctx, UNUSED uint8_t const *key, UNUSED int keylen, void *data)
{
	fr_io_client_t *client = data;
	int connections;

	/*
	 *	This client has no connections, skip the mutex lock.
	 */
	if (!client->ht) return 0;

	rad_assert(client->use_connected);

	pthread_mutex_lock(&client->mutex);
	connections = fr_hash_table_num_elements(client->ht);
	pthread_mutex_unlock(&client->mutex);

	*((uint32_t *) ctx) += connections;

	return 0;
}


static int connection_free(fr_io_connection_t *connection)
{
	/*
	 *	This is it's own talloc context, as there are
	 *	thousands of packets associated with it.
	 */
	talloc_free(connection->client);
	return 0;
}

/** Create a new connection.
 *
 *  Called ONLY from the master socket.
 */
static fr_io_connection_t *fr_io_connection_alloc(fr_io_instance_t const *inst,
						  fr_io_live_t *live,
						  fr_io_client_t *client, int fd,
						  fr_io_address_t *address,
						  fr_io_connection_t *nak)
{
	int rcode;
	fr_io_connection_t *connection;
	dl_instance_t *dl_inst = NULL;
	fr_listen_t *li;
	RADCLIENT *radclient;

	/*
	 *	Reload the app_io module as a "new" library.  This
	 *	causes the link count for the library to be correct.
	 *	It also allocates a new instance data for it, too.
	 *	Passing CONF_SECTION of NULL ensures that there's no
	 *	config for it, as we'll just clone it's contents from
	 *	the original.  It also means that detach should be
	 *	called when the instance data is freed.
	 */
	if (!nak) {
		if (inst->max_connections) {
			/*
			 *	We've hit the connection limit.  Walk
			 *	over all clients with connections, and
			 *	count the number of connections used.
			 */
			if (live->num_connections >= inst->max_connections) {
				live->num_connections = 0;

				(void) fr_trie_walk(live->trie, &live->num_connections, count_connections);

				if ((live->num_connections + 1) >= inst->max_connections) {
					DEBUG("Too many open connections.  Ignoring dynamic client %s.  Discarding packet.", client->radclient->shortname);
					return NULL;
				}
			}
		}

		if (dl_instance(NULL, &dl_inst, NULL, inst->dl_inst, inst->transport, DL_TYPE_SUBMODULE) < 0) {
			DEBUG("Failed to find proto_%s_%s", inst->app->name, inst->transport);
			return NULL;
		}
		rad_assert(dl_inst != NULL);
	} else {
		dl_inst = talloc_init("nak");
	}

	MEM(connection = talloc_zero(dl_inst, fr_io_connection_t));
	MEM(connection->address = talloc_memdup(connection, address, sizeof(*address)));
	(void) talloc_set_name_const(connection->address, "fr_io_address_t");

	connection->magic = PR_CONNECTION_MAGIC;
	connection->parent = client;
	connection->dl_inst = dl_inst;

	MEM(connection->client = talloc_named(NULL, sizeof(fr_io_client_t), "fr_io_client_t"));
	memset(connection->client, 0, sizeof(*connection->client));

	MEM(connection->client->radclient = radclient = radclient_clone(connection->client, client->radclient));

	talloc_set_destructor(connection, connection_free);

	connection->client->pending_id = -1;
	connection->client->alive_id = -1;
	connection->client->connection = connection;

	/*
	 *	Create the packet tracking table for this client.
	 *
	 *	#todo - unify the code with static clients?
	 */
	if (inst->app_io->track_duplicates) {
		MEM(connection->client->table = rbtree_talloc_create(client, track_cmp, fr_io_track_t,
								     NULL, RBTREE_FLAG_NONE));
	}

	/*
	 *	Set this radclient to be dynamic, and active.
	 */
	radclient->dynamic = true;
	radclient->active = true;

	/*
	 *	address->client points to a "static" client.  We want
	 *	to clean up everything associated with the connection
	 *	when it closes.  So we need to point to our own copy
	 *	of the client here.
	 */
	connection->address->radclient = connection->client->radclient;
	connection->client->inst = inst;
	connection->client->live = live;

	/*
	 *	Create a heap for packets which are pending for this
	 *	client.
	 */
	MEM(connection->client->pending = fr_heap_create(connection->client, pending_packet_cmp,
							 fr_io_pending_packet_t, heap_id));

	/*
	 *	Clients for connected sockets are always a /32 or /128.
	 */
	connection->client->src_ipaddr = address->src_ipaddr;
	connection->client->network = address->src_ipaddr;

	/*
	 *	Don't initialize mutex or hash table.
	 *	Connections cannot spawn other connections.
	 */

	/*
	 *	If this client state is pending, then the connection
	 *	state is pending, too.  That allows NAT gateways to be
	 *	defined dynamically, AND for them to have multiple
	 *	connections, each with a different client.  This
	 *	allows for different shared secrets to be used for
	 *	different connections.  Once the client gets defined
	 *	for this connection, it will be either "connected" or
	 *	not.  If connected, then the parent client remains
	 *	PENDING.  Otherwise, the parent client is moved to
	 *	DYNAMIC
	 *
	 *	If this client state is static or dynamic,
	 *	then we're just using connected sockets behind
	 *	that client.  The connections here all use the
	 *	same shared secret, but they use different
	 *	sockets, so they allow for sharing of IO
	 *	across CPUs / threads.
	 */
	switch (client->state) {
	case PR_CLIENT_PENDING:
		connection->client->state = PR_CLIENT_PENDING;

		/*
		 *	Needed for rlm_radius, which refuses to proxy packets
		 *	that define a dynamic client.
		 */
		radclient->active = false;
		break;

	case PR_CLIENT_STATIC:
	case PR_CLIENT_DYNAMIC:
		connection->client->state = PR_CLIENT_CONNECTED;
		break;

	case PR_CLIENT_INVALID:
	case PR_CLIENT_NAK:
	case PR_CLIENT_CONNECTED:
		rad_assert(0 == 1);
		talloc_free(dl_inst);
		return NULL;
	}

	if (!nak) {
		/*
		 *	Get the child listener.
		 */
		MEM(li = connection->child = talloc(connection, fr_listen_t));
		memcpy(li, live->listen, sizeof(*li));

		/*
		 *	Glue in the actual app_io
		 */
		li->app_io = live->child->app_io;
		li->thread_instance = dl_inst->data;
		li->app_io_instance = li->thread_instance;

		/*
		 *	There isn't a need to re-parse the
		 *	configuration.  So we just copy the parent
		 *	config to the child.  We assume that the users
		 *	are smart enough to ensure that they don't
		 *	modify fields which are meant to be "const".
		 *
		 *	@todo - figure this all out.  The issue is
		 *	that the dl API will allocate (for instance)
		 *	proto_radius_udp_t.  We want to pass that
		 *	struct to mod_bootstrap && mod_instantiate.
		 *	BUT we want to pass per-socket information to
		 *	mod_read(), and to pretty much everything
		 *	else.  There doesn't seem to be a clear way to
		 *	make that distinction with the current APIs.
		 *	So, we just hack it...
		 */
		memcpy(connection->child->thread_instance, inst->app_io_instance, inst->app_io->inst_size);
		connection->child->app_io_instance = connection->child->thread_instance;

		/*
		 *	Create the listener, based on our listener.
		 */
		MEM(li = connection->listen = talloc(connection, fr_listen_t));

		/*
		 *	Note that our instance is effectively 'const'.
		 *
		 *	i.e. we can't add things to it.  Instead, we have to
		 *	put all variable data into the connection.
		 */
		memcpy(li, live->listen, sizeof(*li));

		/*
		 *	Glue in the connection to the listener.
		 */
		rad_assert(li->app_io == &fr_master_app_io);
		li->thread_instance = connection;
		li->app_io_instance = li->thread_instance;

		/*
		 *	Instantiate the child, and open the socket.
		 */
		rad_assert(inst->app_io->connection_set != NULL);

		if (inst->app_io->connection_set(connection->child, connection->address) < 0) {
			DEBUG("Failed setting connection for socket.");
			talloc_free(dl_inst);
			return NULL;
		}

		/*
		 *	UDP sockets: open a new socket, and then
		 *	connect it to the client.  This emulates the
		 *	behavior of accept().
		 */
		if (fd < 0) {
			socklen_t salen;
			struct sockaddr_storage src;

			if (inst->app_io->open(connection->child) < 0) {
				DEBUG("Failed opening connected socket.");
				talloc_free(dl_inst);
				return NULL;
			}

			fd = connection->child->fd;

			if (fr_ipaddr_to_sockaddr(&connection->address->src_ipaddr, connection->address->src_port, &src, &salen) < 0) {
				DEBUG("Failed getting IP address");
				talloc_free(dl_inst);
				return NULL;
			}

			if (connect(fd, (struct sockaddr *) &src, salen) < 0) {
				close(fd);
				ERROR("Failed in connect: %s", fr_syserror(errno));
				talloc_free(dl_inst);
				return NULL;
			}
		} else {
			connection->child->fd = fd;
		}

		/*
		 *	Set the new FD, and get the module to set it's connection name.
		 */
		if (inst->app_io->fd_set(connection->child, fd) < 0) {
			DEBUG3("Failed setting FD to %s", inst->app_io->name);
			close(fd);
			return NULL;
		}

		li->fd = fd;

		if (!inst->app_io->get_name) {
			char src_buf[128], dst_buf[128];

			fr_value_box_snprint(src_buf, sizeof(src_buf), fr_box_ipaddr(connection->address->src_ipaddr), 0);
			fr_value_box_snprint(dst_buf, sizeof(dst_buf), fr_box_ipaddr(connection->address->dst_ipaddr), 0);

			connection->name = talloc_typed_asprintf(connection, "proto_%s from client %s port %u to server %s port %u",
								 inst->app_io->name,
								 src_buf, connection->address->src_port,
								 dst_buf, connection->address->dst_port);
		} else {
			connection->name = inst->app_io->get_name(connection->child);
		}

	}

	/*
	 *	Add the connection to the set of connections for this
	 *	client.
	 */
	pthread_mutex_lock(&client->mutex);
	if (nak) (void) fr_hash_table_delete(client->ht, nak);
	rcode = fr_hash_table_insert(client->ht, connection);
	client->ready_to_delete = false;
	pthread_mutex_unlock(&client->mutex);

	if (rcode < 0) {
		ERROR("proto_%s - Failed inserting connection into tracking table.  Closing it, and discarding all packets for connection %s.", inst->app_io->name, connection->name);
		goto cleanup;
	}

	/*
	 *	It's a NAK client.  Set the state to NAK, and don't
	 *	add it to the scheduler.
	 */
	if (nak) {
		connection->name = talloc_strdup(connection, nak->name);
		connection->client->state = PR_CLIENT_NAK;
		connection->el = nak->el;
		return connection;
	}

	DEBUG("proto_%s - starting connection %s", inst->app_io->name, connection->name);
	connection->nr = fr_schedule_listen_add(live->sc, connection->listen);
	if (!connection->nr) {
		ERROR("proto_%s - Failed inserting connection into scheduler.  Closing it, and diuscarding all packets for connection %s.", inst->app_io->name, connection->name);
		pthread_mutex_lock(&client->mutex);
		(void) fr_hash_table_delete(client->ht, connection);
		pthread_mutex_unlock(&client->mutex);

	cleanup:
		talloc_free(dl_inst);
		return NULL;
	}

	/*
	 *	We have one more connection.  Note that we do
	 *	NOT decrement this counter when a connection
	 *	closes, as the close is done in a child
	 *	thread.  Instead, we just let counter hit the
	 *	limit, and then walk over the clients to reset
	 *	the count.
	 */
	live->num_connections++;

	return connection;
}


/*
 *	And here we go into the rabbit hole...
 *
 *	@todo future - have a similar structure
 *	fr_io_connection_io, which will duplicate some code,
 *	but may make things simpler?
 */
static void get_inst(void *instance, fr_io_instance_t const **inst, fr_io_connection_t **connection,
		     fr_listen_t **child)
{
	int magic;

	magic = *(int *) instance;
	if (magic == PR_MAIN_MAGIC) {
		*inst = instance;
		*connection = NULL;
		if (child) *child = (*inst)->live->child;

	} else {
		rad_assert(magic == PR_CONNECTION_MAGIC);
		*connection = instance;
		*inst = (*connection)->client ->inst;
		if (child) *child = (*connection)->child;
	}
}


static RADCLIENT *radclient_alloc(TALLOC_CTX *ctx, int ipproto, fr_io_address_t *address)
{
	RADCLIENT *client;
	char src_buf[128];

	MEM(client = talloc_zero(ctx, RADCLIENT));

	fr_value_box_snprint(src_buf, sizeof(src_buf), fr_box_ipaddr(address->src_ipaddr), 0);

	client->longname = client->shortname = talloc_strdup(client, src_buf);

	client->secret = client->nas_type = talloc_strdup(client, "");

	client->ipaddr = address->src_ipaddr;

	client->src_ipaddr = address->dst_ipaddr;

	client->proto = ipproto;
	client->dynamic = true;

	return client;
}


static fr_io_track_t *fr_io_track_add(fr_io_client_t *client,
						    fr_io_address_t *address,
						    uint8_t const *packet, fr_time_t recv_time, bool *is_dup)
{
	fr_io_track_t my_track, *track = NULL;

	my_track.address = address;
	my_track.client = client;
	memcpy(my_track.packet, packet, sizeof(my_track.packet));

	if (client->inst->app_io->track_duplicates) track = rbtree_finddata(client->table, &my_track);
	if (!track) {
		MEM(track = talloc_zero(client, fr_io_track_t));
		talloc_get_type_abort(track, fr_io_track_t);

		MEM(track->address = talloc_zero(track, fr_io_address_t));
		memcpy(track->address, address, sizeof(*address));
		track->address->radclient = client->radclient;

		track->client = client;
		if (client->connection) {
			track->address = client->connection->address;
		}

		memcpy(track->packet, packet, sizeof(track->packet));
		track->timestamp = recv_time;
		track->packets = 1;
		return track;
	}

	talloc_get_type_abort(track, fr_io_track_t);

	/*
	 *	Is it exactly the same packet?
	 */
	if (memcmp(track->packet, my_track.packet, sizeof(my_track.packet)) == 0) {
		/*
		 *	Ignore duplicates while the client is
		 *	still pending.
		 */
		if (client->state == PR_CLIENT_PENDING) {
			DEBUG("Ignoring duplicate packet while client %s is still pending dynamic definition",
			      client->radclient->shortname);
			return NULL;
		}

		*is_dup = true;
		track->packets++;
		return track;
	}

	/*
	 *	The new packet is different from the old one.
	 */
	memcpy(track->packet, my_track.packet, sizeof(my_track.packet));
	track->timestamp = recv_time;
	track->packets++;

	if (track->ev) {
		(void) talloc_const_free(track->ev);
		track->ev = NULL;
	}

	/*
	 *	We haven't yet sent a reply, this is a conflicting
	 *	packet.
	 */
	if (track->reply_len == 0) {
		return track;
	}

	/*
	 *	Free any cached replies.
	 */
	if (track->reply) {
		talloc_const_free(track->reply);
		track->reply = NULL;
		track->reply_len = 0;
	}

	return track;
}

static int pending_free(fr_io_pending_packet_t *pending)
{
	fr_io_track_t *track = pending->track;

	/*
	 *	Note that we don't check timestamps, replies, etc.  If
	 *	a packet is pending, then any conflicting packet gets
	 *	the "pending" entry marked as such, and a new entry
	 *	added.  Any duplicate packet gets suppressed.  And
	 *	because the packets are pending, track->reply MUST be
	 *	NULL.
	 */
	rad_assert(track->packets > 0);
	track->packets--;

	/*
	 *	No more packets using this tracking entry,
	 *	delete it.
	 */
	if (track->packets == 0) {
		if (track->client->inst->app_io->track_duplicates) {
			rad_assert(track->client->table != NULL);
			(void) rbtree_deletebydata(track->client->table, track);
		}

		// @todo - put this into a slab allocator
		talloc_free(track);
	}

	return 0;
}

static fr_io_pending_packet_t *fr_io_pending_alloc(fr_io_client_t *client,
						   uint8_t const *buffer, size_t packet_len,
						   fr_io_track_t *track,
						   int priority)
{
	fr_io_pending_packet_t *pending;

	MEM(pending = talloc_zero(client->pending, fr_io_pending_packet_t));

	MEM(pending->buffer = talloc_memdup(pending, buffer, packet_len));
	pending->buffer_len = packet_len;
	pending->priority = priority;
	pending->track = track;
	pending->recv_time = track->timestamp; /* there can only be one */

	talloc_set_destructor(pending, pending_free);

	/*
	 *	Insert the pending packet for this client.  If it
	 *	fails, silently discard the packet.
	 */
	if (fr_heap_insert(client->pending, pending) < 0) {
		talloc_free(pending);
		return NULL;
	}

	/*
	 *	We only track pending packets for the
	 *	main socket.  For connected sockets,
	 *	we pause the FD, so the number of
	 *	pending packets will always be small.
	 */
	if (!client->connection) client->live->num_pending_packets++;

	return pending;
}


/*
 *	Remove a client from the list of "live" clients.
 *
 *	This function is only used for the "main" socket.  Clients
 *	from connections do not use it.
 */
static int _client_free(fr_io_client_t *client)
{
	rad_assert(client->in_trie);
	rad_assert(!client->connection);
	rad_assert(fr_heap_num_elements(client->live->alive_clients) > 0);

	(void) fr_trie_remove(client->live->trie, &client->src_ipaddr.addr, client->src_ipaddr.prefix);
	(void) fr_heap_extract(client->live->alive_clients, client);

	return 0;
}

/**  Implement 99% of the read routines.
 *
 *  The app_io->read does the transport-specific data read.
 */
static ssize_t mod_read(fr_listen_t *li, void **packet_ctx, fr_time_t **recv_time_p,
			uint8_t *buffer, size_t buffer_len, size_t *leftover, uint32_t *priority, bool *is_dup)
{
	fr_io_instance_t const *inst;
	fr_io_live_t *live;
	ssize_t packet_len = -1;
	fr_time_t recv_time = 0;
	fr_io_client_t *client;
	fr_io_address_t address;
	fr_io_connection_t my_connection, *connection;
	fr_io_pending_packet_t *pending;
	fr_io_track_t *track;
	fr_listen_t *child;
	int value, accept_fd = -1;

	get_inst(li->thread_instance, &inst, &connection, &child);

	live = inst->live;
	track = NULL;

	/*
	 *	There was data left over from the previous read, go
	 *	get the rest of it now.  We MUST do this instead of
	 *	popping a pending packet, because the leftover bytes
	 *	are already in the output buffer.
	 */
	if (*leftover) goto do_read;

redo:
	/*
	 *	Read one pending packet.  The packet may be pending
	 *	because of dynamic client definitions, or because it's
	 *	for a connected UDP socket, and was sent over by the
	 *	"master" UDP socket.
	 */
	if (connection) {
		/*
		 *	The connection is dead.  Tell the network side
		 *	to close it.
		 */
		if (connection->dead) {
			DEBUG("Dead connection %s", connection->name);
			return -1;
		}

		pending = fr_heap_pop(connection->client->pending);

	} else if (live->pending_clients) {
		pending = pending_packet_pop(live);

	} else {
		pending = NULL;
	}

	if (pending) {
		rad_assert(buffer_len >= pending->buffer_len);
		track = pending->track;

		/*
		 *	Clear the destructor as we now own the
		 *	tracking entry.
		 */
		talloc_set_destructor(pending, NULL);

		/*
		 *	We received a conflicting packet while this
		 *	packet was pending.  Discard this entry and
		 *	try to get another one.
		 *
		 *	Note that the pending heap is *simple*.  We
		 *	just track priority and recv_time.  This means
		 *	it's fast, but also that it's hard to look up
		 *	random packets in the pending heap.
		 */
		if (pending->recv_time != track->timestamp) {
			DEBUG3("Discarding old packet");
			talloc_free(pending);
			goto redo;
		}

		/*
		 *	We have a valid packet.  Copy it over to the
		 *	caller, and return.
		 */
		*packet_ctx = track;
		*recv_time_p = &track->timestamp;
		*leftover = 0;
		*priority = pending->priority;
		recv_time = pending->recv_time;
		client = track->client;

		memcpy(buffer, pending->buffer, pending->buffer_len);
		packet_len = pending->buffer_len;

		/*
		 *	Shouldn't be necessary, but what the heck...
		 */
		memcpy(&address, track->address, sizeof(address));
		talloc_free(pending);

		/*
		 *	Skip over all kinds of logic to find /
		 *	allocate the client, when we don't need to do
		 *	it any more.
		 */
		goto have_client;

	} else if (!connection && (inst->ipproto == IPPROTO_TCP)) {
		struct sockaddr_storage saremote;
		socklen_t salen;

		salen = sizeof(saremote);
#

		/*
		 *	We're a TCP socket but are NOT connected.  We
		 *	must be the master socket.  Accept the new
		 *	connection, and figure out src/dst IP/port.
		 */
		accept_fd = accept(child->fd,
				   (struct sockaddr *) &saremote, &salen);

		/*
		 *	Couldn't open a NEW socket, but THIS ONE is
		 *	OK.  So don't return -1.
		 */
		if (accept_fd < 0) {
			DEBUG("proto_%s_%s - failed to accept new socket: %s",
			      inst->app->name, inst->transport, fr_syserror(errno));
			return 0;
		}

#ifdef __clang_analyzer__
		saremote.ss_family = AF_INET; /* clang doesn't know that accept() initializes this */
#endif

		/*
		 *	Get IP addresses only if we have IP addresses.
		 */
		if ((saremote.ss_family == AF_INET) || (saremote.ss_family == AF_INET6)) {
			(void) fr_ipaddr_from_sockaddr(&saremote, salen, &address.src_ipaddr, &address.src_port);
			salen = sizeof(saremote);

			/*
			 *	@todo - only if the local listen address is "*".
			 */
			(void) getsockname(accept_fd, (struct sockaddr *) &saremote, &salen);
			(void) fr_ipaddr_from_sockaddr(&saremote, salen, &address.dst_ipaddr, &address.dst_port);
		}

	} else {
		fr_io_address_t *local_address;
		fr_time_t *local_recv_time;

do_read:
		local_address = &address;
		local_recv_time = &recv_time;

		/*
		 *	@todo TCP - handle TCP connected sockets, where we
		 *	don't get a packet here, but instead get told
		 *	there's a new socket.  In that situation, we
		 *	have to get the new sockfd, figure out what
		 *	the source IP is, etc.
		 *
		 *	If we can, we shoe-horn this into the "read"
		 *	routine, which should make the rest of the
		 *	code simpler
		 *
		 *	@todo TCP - for connected TCP sockets which are
		 *	dynamically defined, have the app_io_read()
		 *	function STOP reading the socket once a packet
		 *	has been read.  That puts backpressure on the
		 *	client...
		 *
		 *	@todo TLS - for TLS and dynamic sockets, do the SSL setup here,
		 *		but have a structure which describes the TLS data
		 *		and run THAT through the dynamic client definition,
		 *		instead of using RADIUS packets.
		 */
		packet_len = inst->app_io->read(child, (void **) &local_address, &local_recv_time,
					  buffer, buffer_len, leftover, priority, is_dup);
		if (packet_len <= 0) {
			return packet_len;
		}

		/*
		 *	Not allowed?  Discard it.  The other function
		 *	has done any complaining, if necessary.
		 */
		value = inst->app->priority(inst, buffer, packet_len);
		if (value <= 0) {
			char src_buf[128];

			/*
			 *	@todo - unix sockets
			 */
			fr_value_box_snprint(src_buf, sizeof(src_buf), fr_box_ipaddr(address.src_ipaddr), 0);
			DEBUG2("proto_%s - ignoring packet %d from IP %s. It is not configured as 'type = ...'",
			       inst->app_io->name, buffer[0], src_buf);
			return 0;
		}
		*priority = value;

		/*
		 *	If the connection is pending, pause reading of
		 *	more packets.  If mod_write() accepts the
		 *	connection, it will resume reading.
		 *	Otherwise, it will close the socket without
		 *	resuming it.
		 */
		if (connection &&
		    (connection->client->state == PR_CLIENT_PENDING)) {
			rad_assert(!connection->paused);

			connection->paused = true;
			(void) fr_event_filter_update(connection->el,
						      child->fd,
						      FR_EVENT_FILTER_IO, pause_read);
		}
	}

	/*
	 *	Look up the client, unless we already have one (for a
	 *	connected socket).
	 */
	if (!connection) {
		client = fr_trie_lookup(live->trie, &address.src_ipaddr.addr, address.src_ipaddr.prefix);
		rad_assert(!client || !client->connection);

	} else {
		client = connection->client;

		/*
		 *	We don't care what the read function says
		 *	about address.  We have it already.
		 */
		address = *connection->address;
	}

	/*
	 *	Negative cache entry.  Drop the packet.
	 */
	if (client && client->state == PR_CLIENT_NAK) {
		if (accept_fd >= 0) close(accept_fd);
		return 0;
	}

	/*
	 *	If there's no client, try to pull one from the global
	 *	/ static client list.  Or if dynamic clients are
	 *	allowed, try to define a dynamic client.
	 */
	if (!client) {
		RADCLIENT *radclient = NULL;
		fr_io_client_state_t state;
		fr_ipaddr_t const *network = NULL;
		char src_buf[128];

		/*
		 *	We MUST be the master socket.
		 */
		rad_assert(!connection);

		radclient = inst->app_io->client_find(live->child, &address.src_ipaddr, inst->ipproto);
		if (radclient) {
			state = PR_CLIENT_STATIC;

			/*
			 *	Make our own copy that we can modify it.
			 */
			MEM(radclient = radclient_clone(live, radclient));
			radclient->active = true;

		} else if (inst->dynamic_clients) {
			if (inst->max_clients && (fr_heap_num_elements(live->alive_clients) >= inst->max_clients)) {
				fr_value_box_snprint(src_buf, sizeof(src_buf), fr_box_ipaddr(address.src_ipaddr), 0);

				if (accept_fd <= 0) {
					DEBUG("proto_%s - ignoring packet code %d from client IP address %s - too many dynamic clients are defined",
					      inst->app_io->name, buffer[0], src_buf);
				} else {
					DEBUG("proto_%s - ignoring connection attempt from client IP address %s - too many dynamic clients are defined",
					      inst->app_io->name, src_buf);
					close(accept_fd);
				}
				return 0;
			}

			/*
			 *	Look up the allowed networks.
			 */
			network = fr_trie_lookup(inst->networks, &address.src_ipaddr.addr, address.src_ipaddr.prefix);
			if (!network) goto ignore;

			/*
			 *	It exists, but it's a "deny" rule, ignore it.
			 */
			if (network->af == AF_UNSPEC) goto ignore;

			/*
			 *	Allocate our local radclient as a
			 *	placeholder for the dynamic client.
			 */
			radclient = radclient_alloc(live, inst->ipproto, &address);
			state = PR_CLIENT_PENDING;

		} else {
		ignore:
			fr_value_box_snprint(src_buf, sizeof(src_buf), fr_box_ipaddr(address.src_ipaddr), 0);

			if (accept_fd < 0) {
				DEBUG("proto_%s - ignoring packet code %d from unknown client IP address %s",
				      inst->app_io->name, buffer[0], src_buf);
			} else {
				DEBUG("proto_%s - ignoring connection attempt from unknown client IP address %s",
				      inst->app_io->name, src_buf);
				close(accept_fd);
			}
			return 0;
		}

		/*
		 *	Create our own local client.  This client
		 *	holds our state which really shouldn't go into
		 *	RADCLIENT.
		 *
		 *	Note that we create a new top-level talloc
		 *	context for this client, as there may be tens
		 *	of thousands of packets associated with this
		 *	client.  And we want to avoid problems with
		 *	O(N) issues in talloc.
		 */
		MEM(client = talloc_named(NULL, sizeof(fr_io_client_t), "fr_io_client_t"));
		memset(client, 0, sizeof(*client));

		client->state = state;
		client->src_ipaddr = radclient->ipaddr;
		client->radclient = radclient;
		client->inst = inst;
		client->live = live;

		if (network) {
			client->network = *network;
		} else {
			client->network = client->src_ipaddr;
		}

		/*
		 *	At this point, this variable can only be true
		 *	for STATIC clients.  PENDING clients may set
		 *	it to true later, after they've been defined.
		 */
		client->use_connected = radclient->use_connected;

		/*
		 *	Create the pending heap for pending clients.
		 */
		if (state == PR_CLIENT_PENDING) {
			MEM(client->pending = fr_heap_create(client, pending_packet_cmp,
							     fr_io_pending_packet_t, heap_id));
		}

		/*
		 *	Create the packet tracking table for this client.
		 */
		if (inst->app_io->track_duplicates) {
			rad_assert(inst->app_io->compare != NULL);
			MEM(client->table = rbtree_talloc_create(client, track_cmp, fr_io_track_t,
								 NULL, RBTREE_FLAG_NONE));
		}

		/*
		 *	Allow connected sockets to be set on a
		 *	per-client basis.
		 */
		if (client->use_connected) {
			rad_assert(client->state == PR_CLIENT_STATIC);

			(void) pthread_mutex_init(&client->mutex, NULL);
			MEM(client->ht = fr_hash_table_create(client, connection_hash, connection_cmp, NULL));
		}

		/*
		 *	Add the newly defined client to the trie of
		 *	allowed clients.
		 */
		if (fr_trie_insert(live->trie, &client->src_ipaddr.addr, client->src_ipaddr.prefix, client)) {
			ERROR("proto_%s - Failed inserting client %s into tracking table.  Discarding client, and all packets for it.",
			      inst->app_io->name, client->radclient->shortname);
			talloc_free(client);
			if (accept_fd >= 0) close(accept_fd);
			return -1;
		}

		client->in_trie = true;

		/*
		 *	Track the live clients so that we can clean
		 *	them up.
		 */
		(void) fr_heap_insert(live->alive_clients, client);
		client->pending_id = -1;

		/*
		 *	Now that we've inserted it into the heap and
		 *	incremented the numbers, set the destructor
		 *	function.
		 */
		talloc_set_destructor(client, _client_free);
	}

have_client:
	rad_assert(client->state != PR_CLIENT_INVALID);
	rad_assert(client->state != PR_CLIENT_NAK);

	/*
	 *	We've accepted a new connection.  Go allocate it, and
	 *	let it read from the socket.
	 */
	if (accept_fd >= 0) {
		if (!fr_io_connection_alloc(inst, live, client, accept_fd, &address, NULL)) {
			DEBUG("Failed to allocate connection from client %s.", client->radclient->shortname);
			close(accept_fd);
		}

		return 0;
	}

	/*
	 *	No connected sockets, OR we are the connected socket.
	 *
	 *	Track this packet and return it if necessary.
	 */
	if (connection || !client->use_connected) {

		/*
		 *	Add the packet to the tracking table, if it's
		 *	not already there.  Pending packets will be in
		 *	the tracking table, but won't be counted as
		 *	"live" packets.
		 */
		if (!track) {
			track = fr_io_track_add(client, &address, buffer, recv_time, is_dup);
			if (!track) {
				DEBUG("Failed tracking packet from client %s - discarding it.", client->radclient->shortname);
				return 0;
			}
		}

		/*
		 *	This is a pending dynamic client.  See if we
		 *	have to either run the dynamic client code to
		 *	define the client, OR to push the packet onto
		 *	the pending queue for this client.
		 */
		if (client->state == PR_CLIENT_PENDING) {
			char src_buf[128];

			/*
			 *	Track pending packets for the master
			 *	socket.  Connected sockets are paused
			 *	as soon as they are defined, so we
			 *	won't be reading any more packets from
			 *	them.
			 *
			 *	Since we don't have pending packets
			 *	for connected sockets, we don't need
			 *	to track pending packets.
			 */
			if (!connection && inst->max_pending_packets && (live->num_pending_packets >= inst->max_pending_packets)) {
				fr_value_box_snprint(src_buf, sizeof(src_buf), fr_box_ipaddr(client->src_ipaddr), 0);

				DEBUG("Too many pending packets for client %s - discarding packet", src_buf);
				return 0;
			}

			/*
			 *	Allocate the pending packet structure.
			 */
			pending = fr_io_pending_alloc(client, buffer, packet_len,
						      track, *priority);
			if (!pending) {
				fr_value_box_snprint(src_buf, sizeof(src_buf), fr_box_ipaddr(client->src_ipaddr), 0);
				DEBUG("Failed tracking packet from client %s - discarding packet", src_buf);
				return 0;
			}

			if (fr_heap_num_elements(client->pending) > 1) {
				fr_value_box_snprint(src_buf, sizeof(src_buf), fr_box_ipaddr(client->src_ipaddr), 0);
				DEBUG("Client %s is still being dynamically defined.  Caching this packet until the client has been defined.", src_buf);
				return 0;
			}

			/*
			 *	Tell this packet that it's defining a
			 *	dynamic client.
			 */
			track->dynamic = recv_time;

		} else {
			/*
			 *	One more packet being used by this client.
			 *
			 *	Note that pending packets don't count against
			 *	the "live packet" count.
			 */
			client->packets++;
		}

		/*
		 *	Remove all cleanup timers for the client /
		 *	connection.  It's still in use, so we don't
		 *	want to clean it up.
		 */
		if (client->ev) {
			talloc_const_free(client->ev);
			client->ready_to_delete = false;
		}

		/*
		 *	Return the packet.
		 */
		*recv_time_p = &track->timestamp;
		*packet_ctx = track;
		return packet_len;
	}

	/*
	 *	This must be the main UDP socket which creates
	 *	connections.
	 */
	rad_assert(inst->ipproto == IPPROTO_UDP);

	/*
	 *	We're using connected sockets, but this socket isn't
	 *	connected.  It must be the master socket.  The master
	 *	can either be STATIC, DYNAMIC, or PENDING.  Whatever
	 *	the state, the child socket will take care of handling
	 *	the packet.  e.g. dynamic clients, etc.
	 */
	{
		bool nak = false;

		my_connection.address = &address;

		pthread_mutex_lock(&client->mutex);
		connection = fr_hash_table_finddata(client->ht, &my_connection);
		if (connection) nak = (connection->client->state == PR_CLIENT_NAK);
		pthread_mutex_unlock(&client->mutex);

		/*
		 *	The connection is in NAK state, ignore packets
		 *	for it.
		 */
		if (nak) {
			DEBUG("Discarding packet to NAKed connection %s", connection->name);
			return 0;
		}
	}

	/*
	 *	No existing connection, create one.
	 */
	if (!connection) {
		connection = fr_io_connection_alloc(inst, live, client, -1, &address, NULL);
		if (!connection) {
			DEBUG("Failed to allocate connection from client %s.  Discarding packet.", client->radclient->shortname);
			return 0;
		}
	}

	DEBUG("Sending packet to connection %s", connection->name);

	/*
	 *	Inject the packet into the connected socket.  It will
	 *	process the packet as if it came in from the network.
	 *
	 *	@todo future - after creating the connection, put the current
	 *	packet into connection->pending, instead of inject?,
	 *	and then call fr_network_listen_read() from the
	 *	child's instantiation routine???

	 *	@todo TCP - for ACCEPT sockets, we don't have a
	 *	packet, so don't do this.  Instead, the connection
	 *	will take care of figuring out what to do.
	 */
	(void) fr_network_listen_inject(connection->nr, connection->listen,
					buffer, packet_len, recv_time);
	return 0;
}

/** Inject a packet to a connection.
 *
 *  Always called in the context of the network.
 */
static int mod_inject(fr_listen_t *li, uint8_t *buffer, size_t buffer_len, fr_time_t recv_time)
{
	fr_io_instance_t const *inst;
	int		priority;
	bool		is_dup = false;
	fr_io_connection_t *connection;
	fr_io_pending_packet_t *pending;
	fr_io_track_t *track;

	get_inst(li->thread_instance, &inst, &connection, NULL);

	if (!connection) {
		DEBUG2("Received injected packet for an unconnected socket.");
		return -1;
	}

	priority = inst->app->priority(inst, buffer, buffer_len);
	if (priority <= 0) {
		return -1;
	}

	/*
	 *	Track this packet, because that's what mod_read expects.
	 */
	track = fr_io_track_add(connection->client, connection->address, buffer,
				       recv_time, &is_dup);
	if (!track) {
		DEBUG2("Failed injecting packet to tracking table");
		return -1;
	}

	talloc_get_type_abort(track, fr_io_track_t);

	/*
	 *	@todo future - what to do with duplicates?
	 */
	rad_assert(!is_dup);

	/*
	 *	Remember to restore this packet later.
	 */
	pending = fr_io_pending_alloc(connection->client, buffer, buffer_len,
				      track, priority);
	if (!pending) {
		DEBUG2("Failed injecting packet due to allocation error");
		return -1;
	}

	return 0;
}

/** Open a new listener
 *
 */
static int mod_open(fr_listen_t *li)
{
	fr_io_instance_t const *inst;

	inst = li->thread_instance;

	if (inst->app_io->open(inst->live->child) < 0) return -1;

	li->fd = inst->live->child->fd;	/* copy this back up */

	return 0;
}


/** Set the event list for a new socket
 *
 * @param[in] li the listener
 * @param[in] el the event list
 * @param[in] nr context from the network side
 */
static void mod_event_list_set(fr_listen_t *li, fr_event_list_t *el, void *nr)
{
	fr_io_instance_t const *inst;
	fr_io_connection_t *connection;

	get_inst(li->thread_instance, &inst, &connection, NULL);

	/*
	 *	We're not doing IO, so there are no timers for
	 *	cleaning up packets, dynamic clients, or connections.
	 */
	if (!inst->submodule) return;

	/*
	 *	No dynamic clients AND no packet cleanups?  We don't
	 *	need timers.
	 */
	if (!inst->dynamic_clients &&
	    (inst->cleanup_delay.tv_sec == 0) &&
	    (inst->cleanup_delay.tv_usec == 0)) {
		return;
	}

	/*
	 *	Set event list and network side for this socket.
	 */
	if (!connection) {
		inst->live->el = el;
		inst->live->nr = nr;

	} else {
		connection->el = el;
		connection->nr = nr;
	}
}


static void client_expiry_timer(fr_event_list_t *el, struct timeval *now, void *uctx)
{
	fr_io_client_t *client = uctx;
	fr_io_instance_t const *inst;
	fr_io_connection_t *connection;
	struct timeval when;
	struct timeval const *delay;
	int packets, connections;

	/*
	 *	No event list?  We don't need to expire the client.
	 */
	if (!el) return;

	DEBUG("TIMER - checking status of client %s", client->radclient->shortname);

	// @todo - print out what we plan on doing next
	connection = client->connection;
	inst = client->inst;

	rad_assert(client->state != PR_CLIENT_STATIC);

	/*
	 *	Called from the read or write functions with
	 *	now==NULL, to signal that we have to *set* the timer.
	 */
	if (!now) {
		switch (client->state) {
		case PR_CLIENT_CONNECTED:
			rad_assert(connection != NULL);
			delay = &inst->idle_timeout;
			break;

		case PR_CLIENT_DYNAMIC:
			delay = &inst->idle_timeout;
			break;

		case PR_CLIENT_NAK:
			rad_assert(!connection);
			delay = &inst->nak_lifetime;
			break;

		default:
			rad_assert(0 == 1);
			return;
		}

		goto reset_timer;
	}

	/*
	 *	Count active packets AND pending packets.
	 */
	packets = client->packets;
	if (client->pending) packets += fr_heap_num_elements(client->pending);

	/*
	 *	It's a negative cache entry.  Just delete it.
	 */
	if (client->state == PR_CLIENT_NAK) {
	delete_client:
		rad_assert(packets == 0);

		/*
		 *	It's a connected socket.  Remove it from the
		 *	parents list of connections, and delete it.
		 */
		if (connection) {
			fr_io_client_t *parent = connection->parent;

			pthread_mutex_lock(&parent->mutex);
			(void) fr_hash_table_delete(parent->ht, connection);
			pthread_mutex_unlock(&parent->mutex);

			/*
			 *	Mark the connection as dead, and tell
			 *	the network side to stop reading from
			 *	it.
			 */
			connection->dead = true;
			fr_network_listen_read(connection->nr, connection->listen);
			return;
		}

		talloc_free(client);
		return;
	}

	/*
	 *	It's a dynamically defined client.  If no one is using
	 *	it, clean it up after an idle timeout.
	 */
	if ((client->state == PR_CLIENT_DYNAMIC) ||
	    (client->state == PR_CLIENT_CONNECTED)) {
		if (packets > 0) {
			client->ready_to_delete = false;
			return;
		}

		/*
		 *	No packets, check / set idle timeout.
		 */
		goto idle_timeout;
	}

	/*
	 *	The client is pending definition.  It's either a
	 *	dynamic client which has timed out, OR it's a
	 *	"place-holder" client for connected sockets.
	 */
	rad_assert(client->state == PR_CLIENT_PENDING);

	/*
	 *	This is a dynamic client pending definition.
	 *	But it's taken too long to define, so we just
	 *	delete the client, and all packets for it.  A
	 *	new packet will cause the dynamic definition
	 *	to be run again.
	 */
	if (!client->use_connected) {
		if (!packets) {
			goto delete_client;
		}

		/*
		 *	Tell the writer to NOT dynamically define the
		 *	client.  We've run into a problem.  Then,
		 *	return.  The writer will take care of calling
		 *	us again when it notices that a PENDING client
		 *	is ready to delete.
		 *
		 *	TBH... that shouldn't happen?  We should rely
		 *	on the write to do this all of the time...
		 */
		client->ready_to_delete = true;
		return;
	}

	rad_assert(!connection);
	rad_assert(client->ht != NULL);

	/*
	 *	Find out how many connections are using this
	 *	client.
	 */
	pthread_mutex_lock(&client->mutex);
	connections = fr_hash_table_num_elements(client->ht);
	pthread_mutex_unlock(&client->mutex);

	/*
	 *	No connections are using this client.  If
	 *	we've passed the idle timeout, then just
	 *	delete it.  Otherwise, set an idle timeout (as
	 *	above);
	 */
	if (!connections) {
idle_timeout:
		/*
		 *	We didn't receive any packets during the
		 *	idle_timeout, just delete it.
		 */
		if (client->ready_to_delete) {
			if (connection) {
				DEBUG("proto_%s - idle timeout for connection %s", inst->app_io->name, connection->name);
			} else {
				DEBUG("proto_%s - idle timeout for client %s", inst->app_io->name, client->radclient->shortname);
			}
			goto delete_client;
		}

		/*
		 *	No packets and no idle timeout set, go set
		 *	idle timeut.
		 */
		client->ready_to_delete = true;
		delay = &inst->idle_timeout;
		goto reset_timer;
	}

	/*
	 *	There are live sub-connections.  Poll again after a
	 *	long period of time.  Once all of the connections are
	 *	closed, we can then delete this client.
	 *
	 *	@todo - maybe just leave it?  we want to be able to
	 *	clean up this client after a while tho... especially
	 *	if the total number of clients is limited.
	 */
	client->ready_to_delete = false;
	delay = &inst->check_interval;

reset_timer:
	gettimeofday(&when, NULL);
	fr_timeval_add(&when, &when, delay);

	if (fr_event_timer_insert(client, el, &client->ev,
				  &when, client_expiry_timer, client) < 0) {
		ERROR("proto_%s - Failed adding timeout for dynamic client %s.  It will be permanent!",
		      inst->app_io->name, client->radclient->shortname);
		return;
	}

	return;
}


static void packet_expiry_timer(fr_event_list_t *el, struct timeval *now, void *uctx)
{
	fr_io_track_t *track = talloc_get_type_abort(uctx, fr_io_track_t);
	fr_io_client_t *client = track->client;
	fr_io_instance_t const *inst = client->inst;

	/*
	 *	@todo - figure out how to do this only for SOME
	 *	packets, not just RADIUS ones.
	 */
	if (el && !now &&
	    ((inst->cleanup_delay.tv_sec | inst->cleanup_delay.tv_usec) != 0)) {

		struct timeval when;

		gettimeofday(&when, NULL);
		fr_timeval_add(&when, &when, &inst->cleanup_delay);

		if (fr_event_timer_insert(client, el, &track->ev,
					  &when, packet_expiry_timer, track) == 0) {
			return;
		}

		DEBUG("proto_%s - Failed adding cleanup_delay for packet.  Discarding packet immediately",
			inst->app_io->name);
	}

	/*
	 *	So that all cleanup paths can come here, not just the
	 *	timeout ones.
	 */
	if (now) {
		DEBUG2("TIMER - proto_%s - cleanup delay for ID %d", inst->app_io->name, track->packet[1]);
	} else {
		DEBUG2("proto_%s - cleaning up ID %d", inst->app_io->name, track->packet[1]);
	}

	/*
	 *	Delete the tracking entry.
	 */
	rad_assert(track->packets > 0);
	track->packets--;

	if (track->packets == 0) {
		if (inst->app_io->track_duplicates) (void) rbtree_deletebydata(client->table, track);
		talloc_free(track);

	} else {
		if (track->reply) {
			talloc_free(track->reply);
			track->reply = NULL;
		}

		track->reply_len = 0;
	}

	rad_assert(client->packets > 0);
	client->packets--;

	/*
	 *	The client isn't dynamic, stop here.
	 */
	if (client->state == PR_CLIENT_STATIC) return;

	rad_assert(client->state != PR_CLIENT_NAK);
	rad_assert(client->state != PR_CLIENT_PENDING);

	/*
	 *	If necessary, call the client expiry timer to clean up
	 *	the client.
	 */
	if (client->packets == 0) {
		client_expiry_timer(el, now, client);
	}
}

static ssize_t mod_write(fr_listen_t *li, void *packet_ctx, fr_time_t request_time,
			 uint8_t *buffer, size_t buffer_len, size_t written)
{
	fr_io_instance_t const *inst;
	fr_io_live_t *live;
	fr_io_connection_t *connection;
	fr_io_track_t *track = packet_ctx;
	fr_io_client_t *client;
	RADCLIENT *radclient;
	fr_listen_t *child;
	int packets;
	fr_event_list_t *el;

	get_inst(li->thread_instance, &inst, &connection, &child);

	live = inst->live;
	client = track->client;
	packets = client->packets;
	if (connection) {
		el = connection->el;
	} else {
		el = live->el;
	}


	if (client->pending) packets += fr_heap_num_elements(client->pending);

	/*
	 *	A well-defined client means just send the reply.
	 */
	if (client->state != PR_CLIENT_PENDING) {
		ssize_t packet_len;

		/*
		 *	The request later received a conflicting
		 *	packet, so we discard this one.
		 */
		if (track->timestamp != request_time) {
			rad_assert(track->packets > 0);
			rad_assert(client->packets > 0);
			track->packets--;
			client->packets--;
			packets--;

			DEBUG3("Suppressing reply as we have a newer packet");

			/*
			 *	No packets left for this client, reset
			 *	idle timeouts.
			 */
			if ((packets == 0) && (client->state != PR_CLIENT_STATIC)) {
				client_expiry_timer(el, NULL, client);
			}
			return buffer_len;
		}

		rad_assert(track->reply == NULL);

		/*
		 *	We have a NAK packet, or the request
		 *	has timed out, and we don't respond.
		 */
		if (buffer_len < 20) {
			track->reply_len = 1; /* don't respond */
			packet_expiry_timer(el, NULL, track);
			return buffer_len;
		}

		/*
		 *	We have a real packet, write it to the network
		 *	via the underlying transport write.
		 */

		packet_len = inst->app_io->write(child, track, request_time,
						 buffer, buffer_len, written);
		if (packet_len > 0) {
			rad_assert(buffer_len == (size_t) packet_len);
			MEM(track->reply = talloc_memdup(track, buffer, buffer_len));
			track->reply_len = buffer_len;
		} else {
			track->reply_len = 1; /* don't respond */
		}

		/*
		 *	Expire the packet (if necessary).
		 */
		packet_expiry_timer(el, NULL, track);

		return packet_len;
	}

	/*
	 *	The client is pending, so we MUST have dynamic clients.
	 *
	 *	If there's a connected socket and no dynamic clients, then the
	 *	client state is set to CONNECTED when the client is created.
	 */
	rad_assert(inst->dynamic_clients);

	/*
	 *	The request has timed out trying to define the dynamic
	 *	client.  Oops... try again.
	 */
	if ((buffer_len == 1) && (*buffer == true)) {
		DEBUG("Request has timed out trying to define a new client.  Trying again.");
		goto reread;
	}

	/*
	 *	The dynamic client was NOT defined.  Set it's state to
	 *	NAK, delete all pending packets, and close the
	 *	tracking table.
	 */
	if (buffer_len == 1) {
		client->state = PR_CLIENT_NAK;
		talloc_free(client->pending);
		if (client->table) TALLOC_FREE(client->table);
		rad_assert(client->packets == 0);

		/*
		 *	If we're a connected UDP socket, allocate a
		 *	new connection which is the place-holder for
		 *	the NAK.  We will reject packets from from the
		 *	src/dst IP/port.
		 *
		 *	The timer will take care of deleting the NAK
		 *	connection (which doesn't have any FDs
		 *	associated with it).  The network side will
		 *	call mod_close() when the original connection
		 *	is done, which will then free that connection,
		 *	too.
		 */
		if (connection && (inst->ipproto == IPPROTO_UDP)) {
			connection = fr_io_connection_alloc(inst, live, client, -1, connection->address, connection);
			client_expiry_timer(el, NULL, connection->client);

			errno = ECONNREFUSED;
			return -1;
		}

		/*
		 *	For connected TCP sockets, we just call the
		 *	expiry timer, which will close and free the
		 *	connection.
		 */

		client_expiry_timer(el, NULL, client);
		return buffer_len;
	}

	rad_assert(buffer_len == sizeof(radclient));

	memcpy(&radclient, buffer, sizeof(radclient));

	if (!connection) {
		fr_ipaddr_t ipaddr;

		/*
		 *	Check the encapsulating network against the
		 *	address that the user wants to use, but only
		 *	for unconnected sockets.
		 */
		if (client->network.af != radclient->ipaddr.af) {
			DEBUG("Client IP address %pV IP version does not match the source network %pV of the packet.",
			      fr_box_ipaddr(radclient->ipaddr), fr_box_ipaddr(client->network));
			goto error;
		}

		/*
		 *	Network prefix is more restrictive than the one given
		 *	by the client... that's bad.
		 */
		if (client->network.prefix > radclient->ipaddr.prefix) {
			DEBUG("Client IP address %pV is not within the prefix with the defined network %pV",
			      fr_box_ipaddr(radclient->ipaddr), fr_box_ipaddr(client->network));
			goto error;
		}

		ipaddr = radclient->ipaddr;
		fr_ipaddr_mask(&ipaddr, client->network.prefix);
		if (fr_ipaddr_cmp(&ipaddr, &client->network) != 0) {
			DEBUG("Client IP address %pV is not within the defined network %pV.",
			      fr_box_ipaddr(radclient->ipaddr), fr_box_ipaddr(client->network));
			goto error;
		}

		/*
		 *	We can't define dynamic clients as networks (for now).
		 *
		 *	@todo - If we did allow it, we would have to remove
		 *	this client from the trie, update it's IP address, and
		 *	re-add it.  We can PROBABLY do this if this client
		 *	isn't already connected, AND radclient->use_connected
		 *	is true.  But that's for later...
		 */
		if (((radclient->ipaddr.af == AF_INET) &&
		     (radclient->ipaddr.prefix != 32)) ||
		    ((radclient->ipaddr.af == AF_INET6) &&
		     (radclient->ipaddr.prefix != 128))) {
			ERROR("prot_radius - Cannot define a dynamic client as a network");

		error:
			talloc_free(radclient);

			/*
			 *	Remove the pending client from the trie.
			 */
			if (!connection) {
				talloc_free(client);
				return buffer_len;
			}

			/*
			 *	Remove this connection from the parents list of connections.
			 */
			pthread_mutex_lock(&connection->parent->mutex);
			(void) fr_hash_table_delete(connection->parent->ht, connection);
			pthread_mutex_unlock(&connection->parent->mutex);

			talloc_free(connection);
			return buffer_len;
		}
	}

	/*
	 *	The new client is mostly OK.  Copy the various fields
	 *	over.
	 */
#define COPY_FIELD(_x) client->radclient->_x = radclient->_x
#define DUP_FIELD(_x) client->radclient->_x = talloc_strdup(client->radclient, radclient->_x)

	/*
	 *	Only these two fields are set.  Other strings in
	 *	radclient are copies of these ones.
	 */
	talloc_const_free(client->radclient->shortname);
	talloc_const_free(client->radclient->secret);

	DUP_FIELD(longname);
	DUP_FIELD(shortname);
	DUP_FIELD(secret);
	DUP_FIELD(nas_type);

	COPY_FIELD(ipaddr);
	COPY_FIELD(message_authenticator);
	COPY_FIELD(use_connected);

	// @todo - fill in other fields?

	talloc_free(radclient);

	radclient = client->radclient; /* laziness */
	radclient->server_cs = inst->server_cs;
	radclient->server = cf_section_name2(inst->server_cs);
	radclient->cs = NULL;

	/*
	 *	This is a connected socket, and it's just been
	 *	allowed.  Go poke the network side to read from the
	 *	socket.
	 */
	if (connection) {
		rad_assert(connection != NULL);
		rad_assert(connection->client == client);
		rad_assert(client->connection != NULL);

		client->state = PR_CLIENT_CONNECTED;

		radclient->active = true;

		/*
		 *	Connections can't spawn new connections.
		 */
		client->use_connected = radclient->use_connected = false;

		/*
		 *	If we were paused. resume reading from the
		 *	connection.
		 *
		 *	Note that the event list doesn't like resuming
		 *	a connection that isn't paused.  It just sets
		 *	the read function to NULL.
		 */
		if (connection->paused) {
			(void) fr_event_filter_update(el, child->fd,
						      FR_EVENT_FILTER_IO, resume_read);
		}

		goto finish;
	}

	rad_assert(connection == NULL);
	rad_assert(client->use_connected == false); /* we weren't sure until now */

	/*
	 *	Disallow unsupported configurations.
	 */
	if (radclient->use_connected && !inst->app_io->connection_set) {
		DEBUG("proto_%s - cannot use connected sockets as underlying 'transport = %s' does not support it.",
		      inst->app_io->name, inst->transport);
		goto error;
	}


	/*
	 *	Dynamic clients can spawn new connections.
	 */
	client->use_connected = radclient->use_connected;

	/*
	 *	The admin has defined a client which uses connected
	 *	sockets.  Go spawn it
	 */
	if (client->use_connected) {
		rad_assert(connection == NULL);


		/*
		 *	Leave the state as PENDING.  Each connection
		 *	will then cause a dynamic client to be
		 *	defined.
		 */
		(void) pthread_mutex_init(&client->mutex, NULL);
		MEM(client->ht = fr_hash_table_create(client, connection_hash, connection_cmp, NULL));

	} else {
		/*
		 *	The client has been allowed.
		 */
		client->state = PR_CLIENT_DYNAMIC;
		client->radclient->active = true;
	}

	/*
	 *	Add this client to the master socket, so that
	 *	mod_read() will see the pending client, pop the
	 *	pending packet, and process it.
	 *
	 */
	if (!live->pending_clients) {
		MEM(live->pending_clients = fr_heap_create(live, pending_client_cmp,
							   fr_io_client_t, pending_id));
	}

	rad_assert(client->pending_id < 0);
	(void) fr_heap_insert(live->pending_clients, client);

finish:
	/*
	 *	Maybe we defined the client, but the original packet
	 *	timed out, so there's nothing more to do.  In that case, set up the expiry timers.
	 */
	if (packets == 0) {
		client_expiry_timer(el, NULL, client);
	}

reread:
	/*
	 *	If there are pending packets (and there should be at
	 *	least one), tell the network socket to call our read()
	 *	function again.
	 */
	if (fr_heap_num_elements(client->pending) > 0) {
		if (connection) {
			fr_network_listen_read(connection->nr, connection->listen);
		} else {
			fr_network_listen_read(live->nr, live->listen);
		}
	}

	return buffer_len;
}

/** Close the socket.
 *
 */
static int mod_close(fr_listen_t *li)
{
	fr_io_instance_t const *inst;
	fr_io_connection_t *connection;
	fr_listen_t *child;

	get_inst(li->thread_instance, &inst, &connection, &child);

	if (inst->app_io->close) {
		int rcode;

		rcode = inst->app_io->close(child);
		if (rcode < 0) return rcode;
	} else {
		close(child->fd);
		child->fd = -1;
	}

	/*
	 *	We allocated this, so we're responsible for closing
	 *	it.
	 */
	if (connection) {
		DEBUG("Closing connection %s", connection->name);
		if (connection->client->pending) {
			TALLOC_FREE(connection->client->pending); /* for any pending packets */
		}
		talloc_free(connection->dl_inst);
	}

	return 0;
}


static int mod_bootstrap(void *instance, CONF_SECTION *cs)
{
	fr_io_instance_t *inst = instance;

	/*
	 *	Set our magic so that we know if we're a connection or
	 *	an instance.
	 */
	inst->magic = PR_MAIN_MAGIC;

	/*
	 *	Find and bootstrap the application IO handler.
	 */
	inst->app_io = (fr_app_io_t const *) inst->submodule->module->common;

	inst->app_io_conf = inst->submodule->conf;
	inst->app_io_instance = inst->submodule->data;
	if (inst->app_io->bootstrap && (inst->app_io->bootstrap(inst->app_io_instance,
								inst->app_io_conf) < 0)) {
		cf_log_err(inst->app_io_conf, "Bootstrap failed for proto_%s", inst->app_io->name);
		return -1;
	}

	/*
	 *	The caller determines if we have dynamic clients.
	 */
	if (inst->dynamic_clients) {
		/*
		 *	Load proto_dhcpv4_dynamic_client
		 */
		if (dl_instance(cs, &inst->dynamic_submodule,
				cs, inst->dl_inst, "dynamic_client", DL_TYPE_SUBMODULE) < 0) {
			cf_log_err(cs, "Failed finding proto_%s_dynamic_client", inst->app->name);
			return -1;
		}

		/*
		 *	Don't bootstrap the dynamic submodule.  We're
		 *	not even sure what that means...
		 */
	}

	if (inst->ipproto && !inst->app_io->connection_set) {
		cf_log_err(inst->app_io_conf, "Cannot set TCP for proto_%s - internal set error", inst->app_io->name);
		return -1;
	}

	/*
	 *	Get various information after bootstrapping the
	 *	application IO module.
	 */
	if (inst->app_io->network_get) {
		inst->app_io->network_get(inst->app_io_instance, &inst->ipproto, &inst->dynamic_clients, &inst->networks);
	}

	return 0;
}


static char const *mod_name(fr_listen_t *li)
{
	fr_io_instance_t const *inst = li->thread_instance;

	if (!li->app_io->get_name) return li->app_io->name;

	return li->app_io->get_name(inst->live->child);
}


static int mod_instantiate(void *instance, CONF_SECTION *conf)
{
	fr_io_instance_t *inst = instance;

	rad_assert(inst->app_io != NULL);

	if (inst->app_io->instantiate &&
	    (inst->app_io->instantiate(inst->app_io_instance,
				       inst->app_io_conf) < 0)) {
		cf_log_err(conf, "Instantiation failed for \"proto_%s\"", inst->app_io->name);
		return -1;
	}

	/*
	 *	Instantiate the dynamic client processor.
	 */
	if (inst->dynamic_clients) {
		fr_app_worker_t const	*app_process;

		app_process = (fr_app_worker_t const *) inst->dynamic_submodule->module->common;
		if (app_process->instantiate && (app_process->instantiate(inst->dynamic_submodule->data, conf) < 0)) {
			cf_log_err(conf, "Instantiation failed for \"%s\"", app_process->name);
			return -1;
		}
	}

	return 0;
}

/** Create a trie from arrays of allow / deny IP addresses
 *
 * @param ctx	the talloc ctx
 * @param af	the address family to allow
 * @param allow the array of IPs / networks to allow.  MUST be talloc'd
 * @param deny	the array of IPs / networks to deny.  MAY be NULL, MUST be talloc'd
 * @return
 *	- fr_trie_t on success
 *	- NULL on error
 */
fr_trie_t *fr_master_io_network(TALLOC_CTX *ctx, int af, fr_ipaddr_t *allow, fr_ipaddr_t *deny)
{
	fr_trie_t *trie;
	size_t i, num;

	MEM(trie = fr_trie_alloc(ctx));

	num = talloc_array_length(allow);
	rad_assert(num > 0);

	for (i = 0; i < num; i++) {
		fr_ipaddr_t *network;
		char buffer[256];

		/*
		 *	Can't add v4 networks to a v6 socket, or vice versa.
		 */
		if (allow[i].af != af) {
			fr_value_box_snprint(buffer, sizeof(buffer), fr_box_ipaddr(allow[i]), 0);
			fr_strerror_printf("Address family in entry %zd - 'allow = %s' does not match 'ipaddr'", i + 1, buffer);
			talloc_free(trie);
			return NULL;
		}

		/*
		 *	Duplicates are bad.
		 */
		network = fr_trie_match(trie,
					&allow[i].addr, allow[i].prefix);
		if (network) {
			fr_value_box_snprint(buffer, sizeof(buffer), fr_box_ipaddr(allow[i]), 0);
			fr_strerror_printf("Cannot add duplicate entry 'allow = %s'", buffer);
			talloc_free(trie);
			return NULL;
		}

		/*
		 *	Look for overlapping entries.
		 *	i.e. the networks MUST be disjoint.
		 *
		 *	Note that this catches 192.168.1/24
		 *	followed by 192.168/16, but NOT the
		 *	other way around.  The best fix is
		 *	likely to add a flag to
		 *	fr_trie_alloc() saying "we can only
		 *	have terminal fr_trie_user_t nodes"
		 */
		network = fr_trie_lookup(trie,
					 &allow[i].addr, allow[i].prefix);
		if (network && (network->prefix <= allow[i].prefix)) {
			fr_value_box_snprint(buffer, sizeof(buffer), fr_box_ipaddr(allow[i]), 0);
			fr_strerror_printf("Cannot add overlapping entry 'allow = %s'", buffer);
			fr_strerror_printf("Entry is completely enclosed inside of a previously defined network.");
			talloc_free(trie);
			return NULL;
		}

		/*
		 *	Insert the network into the trie.
		 *	Lookups will return the fr_ipaddr_t of
		 *	the network.
		 */
		if (fr_trie_insert(trie,
				   &allow[i].addr, allow[i].prefix,
				   &allow[i]) < 0) {
			fr_value_box_snprint(buffer, sizeof(buffer), fr_box_ipaddr(allow[i]), 0);
			fr_strerror_printf("Failed adding 'allow = %s' to tracking table.", buffer);
			talloc_free(trie);
			return NULL;
		}
	}

	/*
	 *	And now check denied networks.
	 */
	num = talloc_array_length(deny);
	if (!num) return trie;

	/*
	 *	Since the default is to deny, you can only add
	 *	a "deny" inside of a previous "allow".
	 */
	for (i = 0; i < num; i++) {
		fr_ipaddr_t *network;
		char buffer[256];

		/*
		 *	Can't add v4 networks to a v6 socket, or vice versa.
		 */
		if (deny[i].af != af) {
			fr_value_box_snprint(buffer, sizeof(buffer), fr_box_ipaddr(deny[i]), 0);
			fr_strerror_printf("Address family in entry %zd - 'deny = %s' does not match 'ipaddr'", i + 1, buffer);
			talloc_free(trie);
			return NULL;
		}

		/*
		 *	Duplicates are bad.
		 */
		network = fr_trie_match(trie,
					&deny[i].addr, deny[i].prefix);
		if (network) {
			fr_value_box_snprint(buffer, sizeof(buffer), fr_box_ipaddr(deny[i]), 0);
			fr_strerror_printf("Cannot add duplicate entry 'deny = %s'", buffer);
			talloc_free(trie);
			return NULL;
		}

		/*
		 *	A "deny" can only be within a previous "allow".
		 */
		network = fr_trie_lookup(trie,
					 &deny[i].addr, deny[i].prefix);
		if (!network) {
			fr_value_box_snprint(buffer, sizeof(buffer), fr_box_ipaddr(deny[i]), 0);
			fr_strerror_printf("The network in entry %zd - 'deny = %s' is not contained within a previous 'allow'",
				   i + 1, buffer);
			talloc_free(trie);
			return NULL;
		}

		/*
		 *	We hack the AF in "deny" rules.  If
		 *	the lookup gets AF_UNSPEC, then we're
		 *	adding a "deny" inside of a "deny".
		 */
		if (network->af != af) {
			fr_value_box_snprint(buffer, sizeof(buffer), fr_box_ipaddr(deny[i]), 0);
			fr_strerror_printf("The network in entry %zd - 'deny = %s' is overlaps with another 'deny' rule",
				   i + 1, buffer);
			talloc_free(trie);
			return NULL;
		}

		/*
		 *	Insert the network into the trie.
		 *	Lookups will return the fr_ipaddr_t of
		 *	the network.
		 */
		if (fr_trie_insert(trie,
				   &deny[i].addr, deny[i].prefix,
				   &deny[i]) < 0) {
			fr_value_box_snprint(buffer, sizeof(buffer), fr_box_ipaddr(deny[i]), 0);
			fr_strerror_printf("Failed adding 'deny = %s' to tracking table.", buffer);
			talloc_free(trie);
			return NULL;
		}

		/*
		 *	Hack it to make it a deny rule.
		 */
		deny[i].af = AF_UNSPEC;
	}

	return trie;
}


static int _client_heap_free(fr_heap_t *heap)
{
	fr_io_client_t *client;

	/*
	 *	Each client is it's own talloc context, so we have to
	 *	clean them up individually.
	 *
	 *	The client destructor will remove them from the heap,
	 *	so we don't need to do that here.
	 */
	while ((client = fr_heap_peek(heap)) != NULL) {
		talloc_free(client);
	}

	return 0;
}


int fr_master_io_listen(TALLOC_CTX *ctx, fr_io_instance_t *inst, fr_schedule_t *sc,
			size_t default_message_size, size_t num_messages)
{
	fr_listen_t	*li, *child;
	fr_io_live_t	*live;

	/*
	 *	No IO paths, so we don't initialize them.
	 */
	if (!inst->app_io) {
		rad_assert(!inst->dynamic_clients);
		return 0;
	}

	/*
	 *	Build the #fr_listen_t.  This describes the complete
	 *	path data takes from the socket to the decoder and
	 *	back again.
	 */
	MEM(li = talloc_zero(ctx, fr_listen_t));

	li->app = inst->app;
	li->app_instance = inst->app_instance;
	li->server_cs = inst->server_cs;

	/*
	 *	Set configurable parameters for message ring buffer.
	 */
	li->default_message_size = default_message_size;
	li->num_messages = num_messages;

	live = inst->live = talloc_zero(ctx, fr_io_live_t);
	live->listen = li;
	live->sc = sc;

	/*
	 *	Create the trie of clients for this socket.
	 */
	MEM(live->trie = fr_trie_alloc(live));

	MEM(live->alive_clients = fr_heap_create(live, pending_client_cmp,
						 fr_io_client_t, alive_id));
	talloc_set_destructor(live->alive_clients, _client_heap_free);

	/*
	 *	Set the listener to call our master trampoline function.
	 */
	li->app_io = &fr_master_app_io;
	li->thread_instance = inst;
	li->app_io_instance = li->thread_instance;

	/*
	 *	Create the child listener, so that it can later be
	 *	passed to the app_io functions.
	 */
	child = live->child = talloc_zero(li, fr_listen_t);
	memcpy(child, li, sizeof(*child));

	/*
	 *	Reset these fields to point to the actual data.
	 */
	child->app_io = inst->app_io;
	child->thread_instance = inst->app_io_instance;
	child->app_io_instance = child->thread_instance;

	/*
	 *	Don't set the connection for the main socket.  It's not connected.
	 */
	if (inst->app_io->open(child) < 0) {
		cf_log_err(inst->app_io_conf, "Failed opening %s interface", inst->app_io->name);
		talloc_free(li);
		return -1;
	}

	li->fd = child->fd;	/* copy this back up */

	/*
	 *	Add the socket to the scheduler, which might
	 *	end up in a different thread.
	 */
	if (!fr_schedule_listen_add(sc, li)) {
		talloc_free(li);
		return -1;
	}

	return 0;
}

int fr_app_process_bootstrap(dl_instance_t **type_submodule, CONF_SECTION *conf, CONF_SECTION *server_cs)
{
	int i = 0;
	CONF_PAIR *cp = NULL;

	/*
	 *	Bootstrap the process modules
	 */
	while ((cp = cf_pair_find_next(conf, cp, "type"))) {
		char const		*value;
		dl_t const		*module = talloc_get_type_abort_const(type_submodule[i]->module, dl_t);
		fr_app_worker_t const	*app_process = (fr_app_worker_t const *)module->common;

		if (app_process->bootstrap && (app_process->bootstrap(type_submodule[i]->data,
								      type_submodule[i]->conf) < 0)) {
			cf_log_err(conf, "Bootstrap failed for \"%s\"", app_process->name);
			return -1;
		}

		value = cf_pair_value(cp);

		/*
		 *	Add handlers for the virtual server calls.
		 *	This is so that when one virtual server wants
		 *	to call another, it just looks up the data
		 *	here by packet name, and doesn't need to trawl
		 *	through all of the listeners.
		 */
		if (!cf_data_find(server_cs, fr_io_process_t, value)) {
			fr_io_process_t *process_p;

			process_p = talloc(server_cs, fr_io_process_t);
			*process_p = app_process->entry_point;

			(void) cf_data_add(server_cs, process_p, value, NULL);
		}

		i++;
	}

	return 0;
}


int fr_app_process_instantiate(dl_instance_t **type_submodule, dl_instance_t **type_submodule_by_code, int code_max, CONF_SECTION *conf)
{
	int i;
	CONF_PAIR *cp = NULL;

	/*
	 *	Instantiate the process modules
	 */
	i = 0;
	while ((cp = cf_pair_find_next(conf, cp, "type"))) {
		fr_app_worker_t const	*app_process;
		fr_dict_enum_t const	*enumv;
		int			code;

		app_process = (fr_app_worker_t const *)type_submodule[i]->module->common;
		if (app_process->instantiate &&
		    (app_process->instantiate(type_submodule[i]->data, type_submodule[i]->conf) < 0)) {
			cf_log_err(conf, "Instantiation failed for \"%s\"", app_process->name);
			return -1;
		}

		/*
		 *	We've already done bounds checking in the type_parse function
		 */
		enumv = cf_data_value(cf_data_find(cp, fr_dict_enum_t, NULL));
		if (!fr_cond_assert(enumv)) return -1;

		code = enumv->value->vb_uint32;
		if (code >= code_max) {
			cf_log_err(conf, "Invalid type code \"%s\" for \"%s\"", enumv->alias, app_process->name);
			return -1;
		}

		type_submodule_by_code[code] = type_submodule[i];	/* Store the process function */
		i++;
	}

	return 0;
}


fr_app_io_t fr_master_app_io = {
	.magic			= RLM_MODULE_INIT,
	.name			= "radius_master_io",

	.bootstrap		= mod_bootstrap,
	.instantiate		= mod_instantiate,

	.default_message_size	= 4096,
	.track_duplicates	= true,

	.read			= mod_read,
	.write			= mod_write,
	.inject			= mod_inject,

	.open			= mod_open,
	.close			= mod_close,
	.event_list_set		= mod_event_list_set,
	.get_name		= mod_name,
};
