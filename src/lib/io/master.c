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
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/io/master.h>

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/log.h>

#include <freeradius-devel/util/debug.h>

#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/syserror.h>

typedef struct {
	fr_event_list_t			*el;				//!< event list, for the master socket.
	fr_network_t			*nr;				//!< network for the master socket

	fr_trie_t			*trie;				//!< trie of clients
	fr_heap_t			*pending_clients;		//!< heap of pending clients
	fr_heap_t			*alive_clients;			//!< heap of active dynamic clients

	fr_listen_t			*listen;			//!< The master IO path
	fr_listen_t			*child;				//!< The child (app_io) IO path
	fr_schedule_t			*sc;				//!< the scheduler

	// @todo - count num_nak_clients, and num_nak_connections, too
	uint32_t			num_connections;		//!< number of dynamic connections
	uint32_t			num_pending_packets;   		//!< number of pending packets
	uint64_t			client_id;			//!< Unique client identifier.

	struct {
		fr_rate_limit_t			accept_failed;
		fr_rate_limit_t			alloc_failed;
		fr_rate_limit_t			bad_type;
		fr_rate_limit_t			conn_alloc_failed;
		fr_rate_limit_t			max_connections;
		fr_rate_limit_t			queue_full;
		fr_rate_limit_t			repeat_nak;
		fr_rate_limit_t			too_many_pending;
		fr_rate_limit_t			tracking_failed;
		fr_rate_limit_t			unknown_client;
	} rate_limit;
} fr_io_thread_t;

/** A saved packet
 *
 */
typedef struct {
	fr_heap_index_t		heap_id;
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

/*
 *	Dynamic clients are run through the normal src/process/foo state machine.
 *
 *	request->async->packet_ctx is an fr_io_track_t
 *
 *	track->dynamic is set to a non-zero value.
 *
 *	The dynamic client code returns a buffer of 1 byte for a NAK.
 *
 *	If the client creation is successful, then it does talloc(NULL, fr_client_t),
 *	fills out the structure, and sends the pointer in the buffer (8 bytes).
 *
 *	This code will take over ownership of the structure, and
 *	create the dynamic client.
 */

typedef struct fr_io_connection_s fr_io_connection_t;

/** Client definitions for master IO
 *
 */
struct fr_io_client_s {
	fr_io_connection_t		*connection;	//!< parent connection
	fr_io_client_state_t		state;		//!< state of this client
	fr_ipaddr_t			src_ipaddr;	//!< packets come from this address
	fr_ipaddr_t			network;	//!< network for dynamic clients
	fr_client_t			*radclient;	//!< old-style definition of this client

	int				packets;	//!< number of packets using this client
	fr_heap_index_t			pending_id;	//!< for pending clients
	fr_heap_index_t			alive_id;	//!< for all clients

	bool				use_connected;	//!< does this client allow connected sub-sockets?
	bool				ready_to_delete; //!< are we ready to delete this client?
	bool				in_trie;	//!< is the client in the trie?

	fr_io_instance_t const		*inst;		//!< parent instance for master IO handler
	fr_io_thread_t			*thread;
	fr_timer_t			*ev;		//!< when we clean up the client
	fr_rb_tree_t			*table;		//!< tracking table for packets

	fr_heap_t			*pending;	//!< pending packets for this client
	fr_hash_table_t			*addresses;	//!< list of src/dst addresses used by this client

	pthread_mutex_t			mutex;		//!< for parent / child signaling
	fr_hash_table_t			*ht;		//!< for tracking connected sockets
};

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
struct fr_io_connection_s {
	char const			*name;		//!< taken from proto_FOO_TRANSPORT
	int				packets;	//!< number of packets using this connection
	fr_io_address_t   		*address;      	//!< full information about the connection.
	fr_listen_t			*listen;	//!< master listener for this socket
	fr_listen_t			*child;		//!< child listener (app_io) for this socket
	fr_io_client_t			*client;	//!< our local client (pending or connected).
	fr_io_client_t			*parent;	//!< points to the parent client.
	module_instance_t   		*mi;		//!< for submodule

	bool				dead;		//!< roundabout way to get the network side to close a socket
	bool				paused;		//!< event filter doesn't like resuming something that isn't paused
	bool				in_parent_hash;	//!< for tracking thread issues
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

static int track_free(fr_io_track_t *track)
{
	FR_TIMER_DELETE_RETURN(&track->ev);
	talloc_free_children(track);

	fr_assert(track->client->packets > 0);
	track->client->packets--;

	return 0;
}

static int track_dedup_free(fr_io_track_t *track)
{
	fr_assert(track->client->table != NULL);
	fr_assert(fr_rb_find(track->client->table, track) != NULL);

	if (!fr_rb_delete(track->client->table, track)) {
		fr_assert(0);
	}

	return track_free(track);
}

/*
 *  Return negative numbers to put 'one' at the top of the heap.
 *  Return positive numbers to put 'two' at the top of the heap.
 */
static int8_t pending_packet_cmp(void const *one, void const *two)
{
	fr_io_pending_packet_t const *a = talloc_get_type_abort_const(one, fr_io_pending_packet_t);
	fr_io_pending_packet_t const *b = talloc_get_type_abort_const(two, fr_io_pending_packet_t);
	int ret;

	/*
	 *	Higher priority elements are larger than lower
	 *	priority elements.  So if "a" is larger than "b", we
	 *	wish to prefer "a".
	 */
	ret = CMP_PREFER_LARGER(a->priority, b->priority);
	if (ret != 0) return ret;

	/*
	 *	Smaller numbers mean packets were received earlier.
	 *	We want to process packets in time order.  So if "a"
	 *	is smaller than "b", we wish to prefer "a".
	 *
	 *	After that, it doesn't really matter what order the
	 *	packets go in.  Since we'll never have two identical
	 *	"recv_time" values, the code should never get here.
	 */
	return CMP_PREFER_SMALLER(fr_time_unwrap(a->recv_time), fr_time_unwrap(b->recv_time));
}

/*
 *	Order clients in the pending_clients heap, based on the
 *	packets that they contain.
 */
static int8_t pending_client_cmp(void const *one, void const *two)
{
	fr_io_pending_packet_t const *a;
	fr_io_pending_packet_t const *b;

	fr_io_client_t const *c1 = talloc_get_type_abort_const(one, fr_io_client_t);
	fr_io_client_t const *c2 = talloc_get_type_abort_const(two, fr_io_client_t);

	a = fr_heap_peek(c1->pending);
	b = fr_heap_peek(c2->pending);

	fr_assert(a != NULL);
	fr_assert(b != NULL);

	return pending_packet_cmp(a, b);
}


static int8_t address_cmp(void const *one, void const *two)
{
	fr_io_address_t const *a = talloc_get_type_abort_const(one, fr_io_address_t);
	fr_io_address_t const *b = talloc_get_type_abort_const(two, fr_io_address_t);
	int8_t ret;

	CMP_RETURN(a, b, socket.inet.src_port);
	CMP_RETURN(a, b, socket.inet.dst_port);
	CMP_RETURN(a, b, socket.inet.ifindex);

	ret = fr_ipaddr_cmp(&a->socket.inet.src_ipaddr, &b->socket.inet.src_ipaddr);
	if (ret != 0) return ret;

	return fr_ipaddr_cmp(&a->socket.inet.dst_ipaddr, &b->socket.inet.dst_ipaddr);
}

static uint32_t connection_hash(void const *ctx)
{
	uint32_t hash;
	fr_io_connection_t const *c = talloc_get_type_abort_const(ctx, fr_io_connection_t);

	hash = fr_hash(&c->address->socket.inet.src_ipaddr, sizeof(c->address->socket.inet.src_ipaddr));
	hash = fr_hash_update(&c->address->socket.inet.src_port, sizeof(c->address->socket.inet.src_port), hash);

	hash = fr_hash_update(&c->address->socket.inet.ifindex, sizeof(c->address->socket.inet.ifindex), hash);

	hash = fr_hash_update(&c->address->socket.inet.dst_ipaddr, sizeof(c->address->socket.inet.dst_ipaddr), hash);
	return fr_hash_update(&c->address->socket.inet.dst_port, sizeof(c->address->socket.inet.dst_port), hash);
}

static int8_t connection_cmp(void const *one, void const *two)
{
	fr_io_connection_t const *a = talloc_get_type_abort_const(one, fr_io_connection_t);
	fr_io_connection_t const *b = talloc_get_type_abort_const(two, fr_io_connection_t);

	return address_cmp(a->address, b->address);
}


static int8_t track_cmp(void const *one, void const *two)
{
	fr_io_track_t const *a = talloc_get_type_abort_const(one, fr_io_track_t);
	fr_io_track_t const *b = talloc_get_type_abort_const(two, fr_io_track_t);
	int ret;

	fr_assert(a->client != NULL);
	fr_assert(b->client != NULL);
	fr_assert(a->client == b->client); /* tables are per-client */

	fr_assert(!a->client->connection);
	fr_assert(!b->client->connection);

	/*
	 *	Unconnected sockets must check src/dst ip/port.
	 */
	ret = address_cmp(a->address, b->address);
	if (ret != 0) return ret;

	/*
	 *	Call the per-protocol comparison function.
	 */
	ret = a->client->inst->app_io->track_compare(a->client->inst->app_io_instance,
						     a->client->thread->child->thread_instance,
						     a->client->radclient,
						     a->packet, b->packet);
	return CMP(ret, 0);
}


static int8_t track_connected_cmp(void const *one, void const *two)
{
	fr_io_track_t const *a = talloc_get_type_abort_const(one, fr_io_track_t);
	fr_io_track_t const *b = talloc_get_type_abort_const(two, fr_io_track_t);
	int ret;

	fr_assert(a->client != NULL);
	fr_assert(b->client != NULL);

	fr_assert(a->client->connection);
	fr_assert(b->client->connection);
	fr_assert(a->client == b->client);
	fr_assert(a->client->connection == b->client->connection);

	/*
	 *	Note that we pass the connection "client", as
	 *	we may do negotiation specific to this connection.
	 */
	ret = a->client->inst->app_io->track_compare(a->client->inst->app_io_instance,
						     a->client->connection->child->thread_instance,
						     a->client->connection->client->radclient,
						     a->packet, b->packet);
	return CMP(ret, 0);
}


static fr_io_pending_packet_t *pending_packet_pop(fr_io_thread_t *thread)
{
	fr_io_client_t *client;
	fr_io_pending_packet_t *pending;

	client = fr_heap_pop(&thread->pending_clients);
	if (!client) {
		fr_assert(thread->num_pending_packets == 0);

		/*
		 *	99% of the time we don't have pending clients.
		 *	So we might as well free this, so that the
		 *	caller doesn't keep checking us for every packet.
		 */
		talloc_free(thread->pending_clients);
		thread->pending_clients = NULL;
		return NULL;
	}

	pending = fr_heap_pop(&client->pending);
	fr_assert(pending != NULL);

	/*
	 *	If the client has more packets pending, add it back to
	 *	the heap.
	 */
	if (fr_heap_num_elements(client->pending) > 0) {
		if (fr_heap_insert(&thread->pending_clients, client) < 0) {
			fr_assert(0 == 1);
		}
	}

	fr_assert(thread->num_pending_packets > 0);
	thread->num_pending_packets--;

	return pending;
}

static fr_client_t *radclient_clone(TALLOC_CTX *ctx, fr_client_t const *parent)
{
	fr_client_t *c;

	if (!parent) return NULL;

	c = talloc_zero(ctx, fr_client_t);
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

	COPY_FIELD(require_message_authenticator);
	COPY_FIELD(require_message_authenticator_is_set);
	COPY_FIELD(limit_proxy_state);
	COPY_FIELD(limit_proxy_state_is_set);
	COPY_FIELD(received_message_authenticator);
	COPY_FIELD(first_packet_no_proxy_state);
	/* dynamic MUST be false */
	COPY_FIELD(server_cs);
	COPY_FIELD(cs);
	COPY_FIELD(proto);
	COPY_FIELD(active);

	COPY_FIELD(use_connected);

#ifdef WITH_TLS
	COPY_FIELD(tls_required);
#endif

	c->ipaddr = parent->ipaddr;
	c->src_ipaddr = parent->src_ipaddr;

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
static int count_connections(UNUSED uint8_t const *key, UNUSED size_t keylen, void *data, void *ctx)
{
	fr_io_client_t *client = talloc_get_type_abort(data, fr_io_client_t);
	int connections;

	pthread_mutex_lock(&client->mutex);

	if (!client->ht) {
		pthread_mutex_unlock(&client->mutex);
		return 0;
	}

	connections = fr_hash_table_num_elements(client->ht);
	pthread_mutex_unlock(&client->mutex);

	fr_assert(client->use_connected);
	*((uint32_t *) ctx) += connections;

	return 0;
}


static int _client_free(fr_io_client_t *client)
{
	TALLOC_FREE(client->pending);

	return 0;
}

static void client_pending_free(fr_io_client_t *client)
{
	size_t num;

	fr_assert(!client->connection);

	if (!client->pending) return;

	num = fr_heap_num_elements(client->pending);

	fr_assert(client->thread->num_pending_packets >= num);
	client->thread->num_pending_packets -= num;

	TALLOC_FREE(client->pending);
}


static int connection_free(fr_io_connection_t *connection)
{
	/*
	 *	This is it's own talloc context, as there are
	 *	thousands of packets associated with it.
	 */
	TALLOC_FREE(connection->client);

	return 0;
}

/** Create a new connection.
 *
 *  Called ONLY from the master socket.
 */
static fr_io_connection_t *fr_io_connection_alloc(fr_io_instance_t const *inst,
						  fr_io_thread_t *thread,
						  fr_io_client_t *client, int fd,
						  fr_io_address_t *address,
						  fr_io_connection_t *nak)
{
	int ret;
	fr_io_connection_t *connection;
	module_instance_t *mi = NULL;
	fr_listen_t *li;
	fr_client_t *radclient;

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
		CONF_SECTION *cs;
		char *inst_name;

		if (inst->max_connections || client->radclient->limit.max_connections) {
			uint32_t max_connections = inst->max_connections ? inst->max_connections : client->radclient->limit.max_connections;

			/*
			 *	We've hit the connection limit.  Walk
			 *	over all clients with connections, and
			 *	count the number of connections used.
			 */
			if (thread->num_connections >= max_connections) {
				thread->num_connections = 0;

				(void) fr_trie_walk(thread->trie, &thread->num_connections, count_connections);

				if ((thread->num_connections + 1) >= max_connections) {
					RATE_LIMIT_LOCAL(&thread->rate_limit.max_connections, INFO,
							 "proto_%s - Ignoring connection from client %s - 'max_connections' limit reached.",
							 inst->app->common.name, client->radclient->shortname);
					if (fd >= 0) close(fd);
					return NULL;
				}
			}
		}

		/*
		 *	Add a client module into a sublist
		 */
		inst_name = talloc_asprintf(NULL, "%"PRIu64, thread->client_id++);
		mi = module_instance_copy(inst->clients, inst->submodule, inst_name);

		cs = cf_section_dup(mi, NULL, inst->submodule->conf,
				    cf_section_name1(inst->submodule->conf),
				    cf_section_name2(inst->submodule->conf), false);
		if (module_instance_conf_parse(mi, cs) < 0) {
			cf_log_err(inst->server_cs, "Failed parsing module config");
			goto cleanup;
		}

		/* Thread local module lists never run bootstrap */
		if (module_instantiate(mi) < 0) {
			cf_log_err(inst->server_cs, "Failed instantiating module");
			goto cleanup;
		}

		if (module_thread_instantiate(mi, mi, thread->el) < 0) {
			cf_log_err(inst->server_cs, "Failed instantiating module");
			goto cleanup;
		}

		/*
		 *	FIXME - Instantiate the new module?!
		 */
		talloc_free(inst_name);
		fr_assert(mi != NULL);
	} else {
		mi = talloc_init_const("nak");
	}

	MEM(connection = talloc_zero(mi, fr_io_connection_t));
	MEM(connection->address = talloc_memdup(connection, address, sizeof(*address)));
	(void) talloc_set_name_const(connection->address, "fr_io_address_t");

	connection->parent = client;
	connection->mi = mi;

	MEM(connection->client = talloc_named(NULL, sizeof(fr_io_client_t), "fr_io_client_t"));
	memset(connection->client, 0, sizeof(*connection->client));

	MEM(connection->client->radclient = radclient = radclient_clone(connection->client, client->radclient));

	talloc_set_destructor(connection->client, _client_free);
	talloc_set_destructor(connection, connection_free);

	connection->client->pending_id = FR_HEAP_INDEX_INVALID;
	connection->client->alive_id = FR_HEAP_INDEX_INVALID;
	connection->client->connection = connection;

	/*
	 *	Create the packet tracking table for this client.
	 *
	 *	#todo - unify the code with static clients?
	 */
	if (inst->app_io->track_duplicates) {
		MEM(connection->client->table = fr_rb_inline_talloc_alloc(client, fr_io_track_t, node,
									  track_connected_cmp, NULL));
	}

	/*
	 *	Set this radclient to be dynamic, and active.
	 */
	radclient->dynamic = true;
	radclient->active = true;

	/*
	 *	address->socket.inet.client points to a "static" client.  We want
	 *	to clean up everything associated with the connection
	 *	when it closes.  So we need to point to our own copy
	 *	of the client here.
	 */
	connection->address->radclient = connection->client->radclient;
	connection->client->inst = inst;
	connection->client->thread = thread;

	/*
	 *	Create a heap for packets which are pending for this
	 *	client.
	 */
	MEM(connection->client->pending = fr_heap_alloc(connection->client, pending_packet_cmp,
							 fr_io_pending_packet_t, heap_id, 0));

	/*
	 *	Clients for connected sockets are always a /32 or /128.
	 */
	connection->client->src_ipaddr = address->socket.inet.src_ipaddr;
	connection->client->network = address->socket.inet.src_ipaddr;

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
		fr_assert(0 == 1);
		goto cleanup;
	}

	if (!nak) {
		/*
		 *	Get the child listener.
		 */
		MEM(li = connection->child = talloc(connection, fr_listen_t));
		memcpy(li, thread->listen, sizeof(*li));

		/*
		 *	Glue in the actual app_io
		 */
		li->connected = true;
		li->app_io = thread->child->app_io;
		li->thread_instance = connection;
		li->app_io_instance = mi->data;
		li->track_duplicates = thread->child->app_io->track_duplicates;

		/*
		 *	Create writable thread instance data.
		 */
		connection->child->thread_instance = talloc_zero_array(NULL, uint8_t,
								       inst->app_io->common.thread_inst_size);
		talloc_set_destructor(connection->child, fr_io_listen_free);
		talloc_set_name(connection->child->thread_instance, "proto_%s_thread_t",
				inst->app_io->common.name);

		/*
		 *	This is "const", and the user can't
		 *	touch it.  So we just reuse the same
		 *	configuration everywhere.
		 */
		connection->child->app_io_instance = inst->app_io_instance;

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
		memcpy(li, thread->listen, sizeof(*li));

		/*
		 *	Glue in the connection to the listener.
		 */
		fr_assert(li->app_io == &fr_master_app_io);

		li->connected = true;
		li->thread_instance = connection;
		li->app_io_instance = li->thread_instance;
		li->track_duplicates = thread->child->app_io->track_duplicates;

		/*
		 *	Instantiate the child, and open the socket.
		 */
		fr_assert(inst->app_io->connection_set != NULL);

		if (inst->app_io->connection_set(connection->child, connection->address) < 0) {
			DEBUG("proto_%s - Failed setting connection for socket.", inst->app->common.name);
			goto cleanup;
		}

		/*
		 *	UDP sockets: open a new socket, and then
		 *	connect it to the client.  This emulates the
		 *	behavior of accept().
		 *
		 *	Note that there is a small window between the
		 *	bind() and connect() where UDP packets for the
		 *	wildcard socket can get received by this
		 *	socket.  We hope that this time frame is as
		 *	small as possible.
		 *
		 *	i.e. we ignore the problem, and don't
		 *	currently check dst ip/port for UDP packets
		 *	received on connected sockets.
		 */
		if (fd < 0) {
			socklen_t salen;
			struct sockaddr_storage src;

			if (fr_ipaddr_to_sockaddr(&src, &salen,
						  &connection->address->socket.inet.src_ipaddr,
						  connection->address->socket.inet.src_port) < 0) {
				DEBUG("proto_%s - Failed getting IP address", inst->app->common.name);
				talloc_free(mi);
				return NULL;
			}

			if (inst->app_io->open(connection->child) < 0) {
				DEBUG("proto_%s - Failed opening connected socket.", inst->app->common.name);
				talloc_free(mi);
				return NULL;
			}

			fd = connection->child->fd;

			if (connect(fd, (struct sockaddr *) &src, salen) < 0) {
				ERROR("proto_%s - Failed in connect: %s", inst->app->common.name, fr_syserror(errno));
				goto cleanup;
			}
		} else {
			connection->child->fd = fd;
		}

		/*
		 *	Set the new FD, and get the module to set it's connection name.
		 */
		if (inst->app_io->fd_set(connection->child, fd) < 0) {
			DEBUG3("Failed setting FD to %s", inst->app_io->common.name);
			goto cleanup;
		}

		li->fd = fd;

		if (!inst->app_io->get_name) {
			connection->name = fr_asprintf(connection, "proto_%s from client %pV port "
						       "%u to server %pV port %u",
						       inst->app->common.name,
						       fr_box_ipaddr(connection->address->socket.inet.src_ipaddr),
						       connection->address->socket.inet.src_port,
						       fr_box_ipaddr(connection->address->socket.inet.dst_ipaddr),
						       connection->address->socket.inet.dst_port);
		} else {
			connection->name = inst->app_io->get_name(connection->child);
		}

		/*
		 *	Set the names for the listeners.
		 */
		connection->listen->name = connection->name;
		connection->child->name = connection->name;
	}

	/*
	 *	Add the connection to the set of connections for this
	 *	client.
	 */
	pthread_mutex_lock(&client->mutex);
	if (client->ht) {
		if (nak) (void) fr_hash_table_delete(client->ht, nak);
		ret = fr_hash_table_insert(client->ht, connection);
		client->ready_to_delete = false;
		connection->in_parent_hash = true;

		if (!ret) {
			pthread_mutex_unlock(&client->mutex);
			ERROR("proto_%s - Failed inserting connection into tracking table.  "
			      "Closing it, and discarding all packets for connection %s.",
			      inst->app_io->common.name, connection->name);
			goto cleanup;
		}
	}
	pthread_mutex_unlock(&client->mutex);

	/*
	 *	It's a NAK client.  Set the state to NAK, and don't
	 *	add it to the scheduler.
	 */
	if (nak) {
		INFO("proto_%s - Verification failed for packet from dynamic client %pV - adding IP address to the NAK cache",
		     inst->app_io->common.name, fr_box_ipaddr(client->src_ipaddr));

		connection->name = talloc_strdup(connection, nak->name);
		connection->client->state = PR_CLIENT_NAK;
		connection->el = nak->el;
		return connection;
	}

	DEBUG("proto_%s - starting connection %s", inst->app_io->common.name, connection->name);
	connection->nr = fr_schedule_listen_add(thread->sc, connection->listen);
	if (!connection->nr) {
		ERROR("proto_%s - Failed inserting connection into scheduler.  "
		      "Closing it, and diuscarding all packets for connection %s.",
		      inst->app_io->common.name, connection->name);
		pthread_mutex_lock(&client->mutex);
		if (client->ht) (void) fr_hash_table_delete(client->ht, connection);
		pthread_mutex_unlock(&client->mutex);

	cleanup:
		if (fd >= 0) close(fd);
		talloc_free(mi);
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
	thread->num_connections++;

	return connection;
}


/*
 *	And here we go into the rabbit hole...
 *
 *	@todo future - have a similar structure
 *	fr_io_connection_io, which will duplicate some code,
 *	but may make things simpler?
 */
static void get_inst(fr_listen_t *li, fr_io_instance_t const **inst, fr_io_thread_t **thread,
		     fr_io_connection_t **connection, fr_listen_t **child)
{
	if (!li->connected) {
		*inst = li->app_io_instance;
		if (thread) *thread = li->thread_instance;
		*connection = NULL;
		if (child) *child = ((fr_io_thread_t *)li->thread_instance)->child;

	} else {
		fr_assert(connection != NULL);

		*connection = li->thread_instance;
		*inst = (*connection)->client->inst;
		if (thread) *thread = NULL;
		if (child) *child = (*connection)->child;
	}
}


static fr_client_t *radclient_alloc(TALLOC_CTX *ctx, int ipproto, fr_io_address_t *address)
{
	fr_client_t	*radclient;
	char		*shortname;

	MEM(radclient = talloc_zero(ctx, fr_client_t));

	fr_value_box_aprint(radclient, &shortname, fr_box_ipaddr(address->socket.inet.src_ipaddr), NULL);
	radclient->longname = radclient->shortname = shortname;

	radclient->secret = radclient->nas_type = talloc_strdup(radclient, "");

	radclient->ipaddr = address->socket.inet.src_ipaddr;

	radclient->src_ipaddr = address->socket.inet.dst_ipaddr;

	radclient->proto = ipproto;
	radclient->dynamic = true;

	return radclient;
}

/*
 *	Remove a client from the list of "live" clients.
 *
 *	This function is only used for the "main" socket.  Clients
 *	from connections do not use it.
 */
static int _client_live_free(fr_io_client_t *client)
{
	talloc_get_type_abort(client, fr_io_client_t);

	fr_assert(client->in_trie);
	fr_assert(!client->connection);
	fr_assert(client->thread);

	if (client->pending) client_pending_free(client);

	(void) fr_trie_remove_by_key(client->thread->trie, &client->src_ipaddr.addr, client->src_ipaddr.prefix);

	if (client->thread->alive_clients) {
		fr_assert(fr_heap_num_elements(client->thread->alive_clients) > 0);
		(void) fr_heap_extract(&client->thread->alive_clients, client);
	}

	return 0;
}

/** Allocate a dynamic client.
 *
 */
static fr_io_client_t *client_alloc(TALLOC_CTX *ctx, fr_io_client_state_t state,
				    fr_io_instance_t const *inst, fr_io_thread_t *thread, fr_client_t *radclient,
				    fr_ipaddr_t const *network)
{
	fr_io_client_t *client;

	/*
	 *	Create our own local client.  This client
	 *	holds our state which really shouldn't go into
	 *	fr_client_t.
	 *
	 *	Note that we create a new top-level talloc
	 *	context for this client, as there may be tens
	 *	of thousands of packets associated with this
	 *	client.  And we want to avoid problems with
	 *	O(N) issues in talloc.
	 */
	MEM(client = talloc_named(ctx, sizeof(fr_io_client_t), "fr_io_client_t"));
	memset(client, 0, sizeof(*client));

	client->state = state;
	client->src_ipaddr = radclient->ipaddr;
	client->radclient = radclient;
	client->inst = inst;
	client->thread = thread;

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
		MEM(client->pending = fr_heap_alloc(client, pending_packet_cmp,
						    fr_io_pending_packet_t, heap_id, 0));
	}

	/*
	 *	Create the packet tracking table for this client.
	 */
	if (inst->app_io->track_duplicates) {
		fr_assert(inst->app_io->track_compare != NULL);
		MEM(client->table = fr_rb_inline_talloc_alloc(client, fr_io_track_t, node, track_cmp, NULL));
	}

	/*
	 *	Allow connected sockets to be set on a
	 *	per-client basis.
	 */
	if (client->use_connected) {
		fr_assert(client->state == PR_CLIENT_STATIC);

		(void) pthread_mutex_init(&client->mutex, NULL);
		MEM(client->ht = fr_hash_table_alloc(client, connection_hash, connection_cmp, NULL));
	}

	/*
	 *	Add the newly defined client to the trie of
	 *	allowed clients.
	 */
	if (fr_trie_insert_by_key(thread->trie, &client->src_ipaddr.addr, client->src_ipaddr.prefix, client)) {
		ERROR("proto_%s - Failed inserting client %s into tracking table.  Discarding client, and all packets for it.",
		      inst->app_io->common.name, client->radclient->shortname);
		talloc_free(client);
		return NULL;
	}

	client->in_trie = true;

	/*
	 *	It's a static client.  Don't insert it into the list of alive clients, as those are only for
	 *	dynamic clients.
	 */
	if (state == PR_CLIENT_STATIC) return client;

	fr_assert(thread->alive_clients != NULL);

	/*
	 *	Track the live clients so that we can clean
	 *	them up.
	 */
	(void) fr_heap_insert(&thread->alive_clients, client);
	client->pending_id = FR_HEAP_INDEX_INVALID;

	/*
	 *	Now that we've inserted it into the heap and
	 *	incremented the numbers, set the destructor
	 *	function.
	 */
	talloc_set_destructor(client, _client_live_free);

	return client;
}


static fr_io_track_t *fr_io_track_add(fr_io_client_t *client,
				      fr_io_address_t *address,
				      uint8_t const *packet, size_t packet_len,
				      fr_time_t recv_time, bool *is_dup)
{
	size_t len;
	fr_io_track_t *track, *old;

	*is_dup = false;

	/*
	 *	Allocate a new tracking structure.  Most of the time
	 *	there are no duplicates, so this is fine.
	 */
	if (client->connection) {
		MEM(track = talloc_zero_pooled_object(client, fr_io_track_t, 1, sizeof(*track) + 64));
		track->address = client->connection->address;
	} else {
		fr_io_address_t *my_address;

		MEM(track = talloc_zero_pooled_object(client, fr_io_track_t, 1, sizeof(*track) + sizeof(*track->address) + 64));
		MEM(track->address = my_address = talloc(track, fr_io_address_t));

		*my_address = *address;
		my_address->radclient = client->radclient;
	}

	track->client = client;

	track->timestamp = recv_time;
	track->packets = 1;

	/*
	 *	We're not tracking duplicates, so just return the
	 *	tracking entry.  This tracks src/dst IP/port, client,
	 *	receive time, etc.
	 */
	if (!client->inst->app_io->track_duplicates) {
		client->packets++;
		talloc_set_destructor(track, track_free);
		return track;
	}

	/*
	 *	We are checking for duplicates, see if there is a dup
	 *	already in the tree.
	 */
	track->packet = client->inst->app_io->track_create(client->inst->app_io_instance,
							   client->thread->child->thread_instance,
							   client->radclient,
							   track, packet, packet_len);
	if (!track->packet) {
		talloc_free(track);
		return NULL;
	}

	/*
	 *	No existing duplicate.  Return the new tracking entry.
	 */
	old = fr_rb_find(client->table, track);
	if (!old) goto do_insert;

	fr_assert(old->client == client);

	/*
	 *	It cannot be both in the free list and in the tracking table.
	 *
	 *	2020-08-17, this assertion fails randomly in travis.
	 *	Which means that "track" was in the free list, *and*
	 *	in the rbtree.
	 */
	fr_assert(old != track);

	/*
	 *	The new packet has the same dedup fields as the old
	 *	one, BUT it may be a conflicting packet.  Check for
	 *	that via a simple memcmp().
	 *
	 *	It's an exact duplicate.  Drop the new one and
	 *	use the old one.
	 *
	 *	If there's a cached reply, the caller will take care
	 *	of sending it to the network layer.
	 */
	len = talloc_array_length(old->packet);
	if ((len == talloc_array_length(track->packet)) &&
	    (memcmp(old->packet, track->packet, len) == 0)) {
		fr_assert(old != track);

		/*
		 *	Ignore duplicates while the client is
		 *	still pending.
		 */
		if (client->state == PR_CLIENT_PENDING) {
			DEBUG("Ignoring duplicate packet while client %s is still pending dynamic definition",
			      client->radclient->shortname);
			talloc_free(track);
			return NULL;
		}

		*is_dup = true;
		old->packets++;
		talloc_free(track);

		/*
		 *	Retransmits can sit in the outbound queue for
		 *	a while.  We don't want to time out this
		 *	struct while the packet is in the outbound
		 *	queue.
		 */
		FR_TIMER_DISARM(old->ev);
		return old;
	}

	/*
	 *	Else it's a conflicting packet.  Which is OK if we
	 *	already have a reply.  We just delete the old entry,
	 *	and insert the new one.
	 *
	 *	If there's no reply, then the old request is still
	 *	"live".  Delete the old one from the tracking tree,
	 *	and return the new one.
	 */
	if (old->reply_len || old->do_not_respond) {
		talloc_free(old);

	} else {
		fr_assert(client == old->client);

		if (!fr_rb_delete(client->table, old)) {
			fr_assert(0);
		}
		FR_TIMER_DELETE(&old->ev);

		talloc_set_destructor(old, track_free);

		old->discard = true; /* don't send any reply, there's nowhere for it to go */
	}

do_insert:
	if (!fr_rb_insert(client->table, track)) {
		fr_assert(0);
	}

	client->packets++;
	talloc_set_destructor(track, track_dedup_free);
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
	fr_assert(track->packets > 0);
	track->packets--;

	/*
	 *	No more packets using this tracking entry,
	 *	delete it.
	 */
	if (track->packets == 0) talloc_free(track);

	return 0;
}

static fr_io_pending_packet_t *fr_io_pending_alloc(fr_io_connection_t *connection, fr_io_client_t *client,
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
	if (fr_heap_insert(&client->pending, pending) < 0) {
		talloc_free(pending);
		return NULL;
	}

	/*
	 *	We only track pending packets for the
	 *	main socket.  For connected sockets,
	 *	we pause the FD, so the number of
	 *	pending packets will always be small.
	 */
	if (!connection) client->thread->num_pending_packets++;

	return pending;
}


/*
 *	Order clients in the alive_clients heap, based on their IP
 *	address.
 *
 *	This function is only used for the "main" socket.  Clients
 *	from connections do not use it.
 */
static int8_t alive_client_cmp(void const *one, void const *two)
{
	fr_io_client_t const *a = talloc_get_type_abort_const(one, fr_io_client_t);
	fr_io_client_t const *b = talloc_get_type_abort_const(two, fr_io_client_t);

	return fr_ipaddr_cmp(&a->src_ipaddr, &b->src_ipaddr);
}

/**  Implement 99% of the read routines.
 *
 *  The app_io->read does the transport-specific data read.
 */
static ssize_t mod_read(fr_listen_t *li, void **packet_ctx, fr_time_t *recv_time_p,
			uint8_t *buffer, size_t buffer_len, size_t *leftover)
{
	fr_io_instance_t const	*inst;
	fr_io_thread_t		*thread;
	ssize_t			packet_len = -1;
	fr_time_t		recv_time = fr_time_wrap(0);
	fr_io_client_t		*client;
	fr_io_address_t		address;
	fr_io_connection_t	my_connection, *connection;
	fr_io_pending_packet_t	*pending = NULL;
	fr_io_track_t		*track;
	fr_listen_t		*child;
	int			value, accept_fd = -1;
	uint32_t		priority = PRIORITY_NORMAL;

/** Log that we ignore clients in debug mode, or when it's enabled for a listener
 */
#define LOG_IGNORED_CLIENTS(_inst) ((_inst)->log_ignored_clients || fr_debug_lvl >= 1)

	get_inst(li, &inst, &thread, &connection, &child);

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

		pending = fr_heap_pop(&connection->client->pending);

	} else if (thread->pending_clients) {
		pending = pending_packet_pop(thread);

	} else {
		pending = NULL;
	}

	if (pending) {
		fr_assert(buffer_len >= pending->buffer_len);
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
		if (fr_time_neq(pending->recv_time, track->timestamp)) {
			DEBUG3("Discarding old packet");
			TALLOC_FREE(pending);
			goto redo;
		}

		/*
		 *	We have a valid packet.  Copy it over to the
		 *	caller, and return.
		 */
		*packet_ctx = track;
		*leftover = 0;
		recv_time = *recv_time_p = pending->recv_time;
		client = track->client;

		memcpy(buffer, pending->buffer, pending->buffer_len);
		packet_len = pending->buffer_len;

		/*
		 *	Shouldn't be necessary, but what the heck...
		 */
		memcpy(&address, track->address, sizeof(address));
		TALLOC_FREE(pending);

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
			RATE_LIMIT_LOCAL(&thread->rate_limit.accept_failed,
					 INFO, "proto_%s - failed to accept new socket: %s",
					 inst->app->common.name, fr_syserror(errno));
			return 0;
		}

		/*
		 *	Set the new descriptor to be non-blocking.
		 */
		(void) fr_nonblock(accept_fd);

#ifdef STATIC_ANALYZER
		saremote.ss_family = AF_INET; /* static analyzer doesn't know that accept() initializes this */
#endif

		/*
		 *	Get IP addresses only if we have IP addresses.
		 */
		if ((saremote.ss_family == AF_INET) || (saremote.ss_family == AF_INET6)) {
			memset(&address.socket, 0, sizeof(address.socket));
			(void) fr_ipaddr_from_sockaddr(&address.socket.inet.src_ipaddr, &address.socket.inet.src_port,
						       &saremote, salen);
			salen = sizeof(saremote);

			/*
			 *	@todo - only if the local listen address is "*".
			 */
			(void) getsockname(accept_fd, (struct sockaddr *) &saremote, &salen);
			(void) fr_ipaddr_from_sockaddr(&address.socket.inet.dst_ipaddr, &address.socket.inet.dst_port,
						       &saremote, salen);
			address.socket.type = (inst->ipproto == IPPROTO_TCP) ? SOCK_STREAM : SOCK_DGRAM;
			address.socket.fd = accept_fd;
		}

	} else {
		fr_io_address_t *local_address;

		/*
		 *	We're either not a TCP socket, or we are a
		 *	connected TCP socket.  Just read it.
		 */
do_read:
		local_address = &address;

		/*
		 *	@todo - For connected TCP sockets which are
		 *	dynamically defined, the app_io read()
		 *	function should stop reading the socket if the
		 *	server is busy.  That change puts TCP
		 *	backpressure on the client.
		 *
		 *	@todo TLS - for TLS and dynamic sockets, do
		 *	the SSL setup here, but have a structure which
		 *	describes the TLS data and run THAT through
		 *	the dynamic client definition, instead of
		 *	using normal packets.  Or, rely on the app_io
		 *	read() function to do all TLS work?  Given
		 *	that some protocols have "starttls" beginning
		 *	after a clear-text exchange, it's likely best
		 *	to have yet another layer of trampoline
		 *	functions which do all of the TLS work.
		 */
		packet_len = inst->app_io->read(child, (void **) &local_address, &recv_time,
					  buffer, buffer_len, leftover);
		if (packet_len <= 0) {
			return packet_len;
		}

		/*
		 *	Not allowed?  Discard it.  The priority()
		 *	function has done any complaining, if
		 *	necessary.
		 */
		if (inst->app->priority) {
			value = inst->app->priority(inst->app_instance, buffer, packet_len);
			if (value <= 0) {
				static fr_rate_limit_t bad_type;

				/*
				 *	@todo - unix sockets.  We need to use
				 *	the "name" of the socket, in the
				 *	listener?
				 */
				if (LOG_IGNORED_CLIENTS(inst)) {
					RATE_LIMIT_LOCAL(thread ? &thread->rate_limit.bad_type : &bad_type, INFO,
							 "proto_%s - ignoring packet from IP %pV. It is not configured as 'type = ...'",
							 inst->app_io->common.name, fr_box_ipaddr(address.socket.inet.src_ipaddr));
				}
				return 0;
			}
			priority = value;
		}

		/*
		 *	If the connection is pending, pause reading of
		 *	more packets.  If mod_write() accepts the
		 *	connection, it will resume reading.
		 *	Otherwise, it will close the socket without
		 *	resuming it.
		 */
		if (connection &&
		    (connection->client->state == PR_CLIENT_PENDING)) {
			fr_assert(!connection->paused);

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
		client = fr_trie_lookup_by_key(thread->trie,
					&address.socket.inet.src_ipaddr.addr, address.socket.inet.src_ipaddr.prefix);
		fr_assert(!client || !client->connection);

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
		fr_client_t *radclient = NULL;
		fr_io_client_state_t state;
		fr_ipaddr_t const *network = NULL;
		char const *error;

		/*
		 *	We MUST be the master socket.
		 */
		fr_assert(!connection);

		radclient = inst->app_io->client_find(thread->child, &address.socket.inet.src_ipaddr, inst->ipproto);
		if (radclient) {
			state = PR_CLIENT_STATIC;

			/*
			 *	Make our own copy that we can modify it.
			 */
			MEM(radclient = radclient_clone(thread, radclient));
			radclient->active = true;

		} else if (inst->dynamic_clients) {
			if (inst->max_clients && (fr_heap_num_elements(thread->alive_clients) >= inst->max_clients)) {
				error = "Too many dynamic clients have been defined";
				goto ignore;
			}

			/*
			 *	Look up the allowed networks.
			 */
			network = fr_trie_lookup_by_key(inst->networks, &address.socket.inet.src_ipaddr.addr,
						 address.socket.inet.src_ipaddr.prefix);
			if (!network) {
				error = "Address is outside of the the 'allow' network range";
				goto ignore;
			}

			/*
			 *	It exists, but it's a "deny" rule, ignore it.
			 */
			if (network->af == AF_UNSPEC) {
				error = "Address is forbidden by the 'deny' network range";
				goto ignore;
			}

			/*
			 *	Allocate our local radclient as a
			 *	placeholder for the dynamic client.
			 */
			radclient = radclient_alloc(thread, inst->ipproto, &address);
			state = PR_CLIENT_PENDING;

		} else {
			char const *msg;

			error = "No matching 'client' definition was found";

		ignore:
			if (accept_fd < 0) {
				msg = "packet";
			} else {
				msg = "connection attempt";
				close(accept_fd);
			}

			if (LOG_IGNORED_CLIENTS(inst)) {
				static fr_rate_limit_t unknown_client;
				RATE_LIMIT_LOCAL(thread ? &thread->rate_limit.unknown_client : &unknown_client,
						 ERROR, "proto_%s - Ignoring %s from IP address %pV - %s",
						 inst->app_io->common.name, msg, fr_box_ipaddr(address.socket.inet.src_ipaddr),
						 error);
			}

			return 0;
		}

		MEM(client = client_alloc(thread, state, inst, thread, radclient, network));
	}

have_client:
	fr_assert(client->state != PR_CLIENT_INVALID);
	fr_assert(client->state != PR_CLIENT_NAK);

	/*
	 *	We've accepted a new connection.  Go allocate it, and
	 *	let it read from the socket.
	 */
	if (accept_fd >= 0) {
		if (!fr_io_connection_alloc(inst, thread, client, accept_fd, &address, NULL)) {
			static fr_rate_limit_t alloc_failed;

			RATE_LIMIT_LOCAL(thread ? &thread->rate_limit.conn_alloc_failed : &alloc_failed,
					 ERROR, "Failed to allocate connection from client %s", client->radclient->shortname);
		}

		return 0;
	}

	/*
	 *	No connected sockets, OR we are the connected socket.
	 *
	 *	Track this packet and return it if necessary.
	 */
	if (connection || !client->use_connected) {
		fr_io_track_t *to_free = NULL;

		/*
		 *	Add the packet to the tracking table, if it's
		 *	not already there.  Pending packets will be in
		 *	the tracking table, but won't be counted as
		 *	"live" packets.
		 */
		if (!track) {
			static 	fr_rate_limit_t tracking_failed;
			bool	is_dup = false;

			track = fr_io_track_add(client, &address, buffer, packet_len, recv_time, &is_dup);
			if (!track) {
				RATE_LIMIT_LOCAL(thread ? &thread->rate_limit.tracking_failed : &tracking_failed,
						 ERROR, "Failed tracking packet from client %s - discarding it",
						 client->radclient->shortname);
				return 0;
			}

			/*
			 *	If there's a cached reply, just send that and don't do anything else.
			 */
			if (is_dup) {
				fr_network_t *nr;

				if (track->do_not_respond) {
					DEBUG("Ignoring retransmit from client %s - we are not responding to this request", client->radclient->shortname);
					return 0;
				}

				if (track->discard) {
					DEBUG("Ignoring transmit from client %s - we previously received a newer / conflicting packet", client->radclient->shortname);
					return 0;
				}

				if (!track->reply) {
					fr_assert(!track->finished);
					DEBUG("Ignoring retransmit from client %s - we are still processing the request", client->radclient->shortname);
					return 0;
				}

				if (connection) {
					nr = connection->nr;
				} else {
					nr = thread->nr;
				}

				/*
				 *	@todo - mark things up so that we know to keep 'track' around
				 *	until the packet is actually written to the network.  OR, add
				 *	a network API so that the talloc_free() function can remove
				 *	the packet from the queue of packets to be retransmitted.
				 *
				 *	Perhaps via having fr_network_listen_write() return a pointer
				 *	to the localized message, and then caching that in the tracking
				 *	structure.
				 */
				DEBUG("Sending duplicate reply to client %s", client->radclient->shortname);
				fr_network_listen_write(nr, li, track->reply, track->reply_len,
							track, track->timestamp);
				return 0;
			}

			/*
			 *	Got to free this if we don't process the packet.
			 */
			to_free = track;
		}

		/*
		 *	This is a pending dynamic client.  See if we
		 *	have to either run the dynamic client code to
		 *	define the client, OR to push the packet onto
		 *	the pending queue for this client.
		 */
		if (client->state == PR_CLIENT_PENDING) {
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
			if (!connection && inst->max_pending_packets && (thread->num_pending_packets >= inst->max_pending_packets)) {
				RATE_LIMIT_LOCAL(&thread->rate_limit.too_many_pending,
						 ERROR, "Too many pending dynamic client packets for listener - discarding packet from %pV",
						 fr_box_ipaddr(client->src_ipaddr));

			discard:
				talloc_free(to_free);
				return 0;
			}

			/*
			 *	Allocate the pending packet structure.
			 */
			pending = fr_io_pending_alloc(connection, client, buffer, packet_len,
						      track, priority);
			if (!pending) {
				static fr_rate_limit_t alloc_failed;
				RATE_LIMIT_LOCAL(thread ? &thread->rate_limit.alloc_failed : &alloc_failed,
						 ERROR, "proto_%s - Failed allocating space for dynamic client %pV - discarding packet",
						 inst->app_io->common.name, fr_box_ipaddr(client->src_ipaddr));
				goto discard;
			}

			if (fr_heap_num_elements(client->pending) > 1) {
				DEBUG("Verification is still pending for dynamic client %pV - queuing additional packet(s)",
				      fr_box_ipaddr(client->src_ipaddr));
				return 0;
			}

			/*
			 *	Tell this packet that it's defining a
			 *	dynamic client.
			 */
			track->dynamic = recv_time;

			INFO("proto_%s - Verification started for packet from dynamic client %pV - queuing new packets",
			     inst->app_io->common.name,	fr_box_ipaddr(client->src_ipaddr));
		}

		/*
		 *	Remove all cleanup timers for the client /
		 *	connection.  It's still in use, so we don't
		 *	want to clean it up.
		 */
		if (fr_timer_armed(client->ev)) {
			FR_TIMER_DELETE_RETURN(&client->ev);
			client->ready_to_delete = false;
		}

		/*
		 *	Return the packet.
		 */
		*recv_time_p = track->timestamp;
		*packet_ctx = track;
		return packet_len;
	}

	/*
	 *
	 */
	fr_assert(!pending);

	/*
	 *	This must be the main UDP socket which creates
	 *	connections.
	 */
	fr_assert(inst->ipproto == IPPROTO_UDP);

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
		connection = fr_hash_table_find(client->ht, &my_connection);
		if (connection) nak = (connection->client->state == PR_CLIENT_NAK);
		pthread_mutex_unlock(&client->mutex);

		/*
		 *	The connection is in NAK state, ignore packets
		 *	for it.
		 */
		if (nak) {
			RATE_LIMIT_LOCAL(&thread->rate_limit.repeat_nak, ERROR, "proto_%s - Discarding repeated packet from NAK'd dynamic client %pV",
					 inst->app_io->common.name, fr_box_ipaddr(address.socket.inet.src_ipaddr));

			DEBUG("Discarding packet to NAKed connection %s", connection->name);
			return 0;
		}
	}

	/*
	 *	No existing connection, create one.
	 */
	if (!connection) {
		connection = fr_io_connection_alloc(inst, thread, client, -1, &address, NULL);
		if (!connection) {
			RATE_LIMIT_LOCAL(&thread->rate_limit.conn_alloc_failed,
					 ERROR, "Failed to allocate connection from client %s.  Discarding packet.", client->radclient->shortname);
			return 0;
		}
	}

	DEBUG("Sending packet to connection %s", connection->name);

	/*
	 *	Inject the packet into the connected socket.  It will
	 *	process the packet as if it came in from the network.
	 *
	 *	@todo future - after creating the connection, put the
	 *	current packet into connection->pending, instead of
	 *	inject?, and then call fr_network_listen_read() from
	 *	the child's instantiation routine???
	 *
	 *	@todo TCP - for ACCEPT sockets, we don't have a
	 *	packet, so don't do this.  Instead, the connection
	 *	will take care of figuring out what to do.
	 *
	 *	We don't need "to_free" after this, as it will be
	 *	tracked in the connected socket.
	 */
	if (fr_network_listen_inject(connection->nr, connection->listen,
				     buffer, packet_len, recv_time) < 0) {
		RATE_LIMIT_LOCAL(&thread->rate_limit.queue_full, PERROR,
				 "proto_%s - Discarding packet from dynamic client %pV - cannot push packet to connected socket",
				 inst->app_io->common.name, fr_box_ipaddr(address.socket.inet.src_ipaddr));
		/*
		 *	Don't return an error, because that will cause the listener to close its socket.
		 */
	}

	return 0;
}

/** Inject a packet to a connection.
 *
 *  Always called in the context of the network.
 */
static int mod_inject(fr_listen_t *li, uint8_t const *buffer, size_t buffer_len, fr_time_t recv_time)
{
	fr_io_instance_t const *inst;
	int		priority;
	bool		is_dup = false;
	fr_io_connection_t *connection;
	fr_io_pending_packet_t *pending;
	fr_io_track_t *track;

	get_inst(li, &inst, NULL, &connection, NULL);

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
	track = fr_io_track_add(connection->client, connection->address,
				buffer, buffer_len, recv_time, &is_dup);
	if (!track) {
		DEBUG2("Failed injecting packet to tracking table");
		return -1;
	}

	talloc_get_type_abort(track, fr_io_track_t);

	/*
	 *	@todo future - what to do with duplicates?
	 */
	fr_assert(!is_dup);

	/*
	 *	Remember to restore this packet later.
	 */
	pending = fr_io_pending_alloc(connection, connection->client, buffer, buffer_len,
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
	fr_io_thread_t *thread;
	fr_io_instance_t const *inst;

	thread = li->thread_instance;
	inst = li->app_io_instance;

	if (inst->app_io->open(thread->child) < 0) return -1;

	li->fd = thread->child->fd;	/* copy this back up */

	/*
	 *	Set the name of the socket.
	 */
	if (!li->app_io->get_name) {
		li->name = li->app_io->common.name;
	} else {
		li->name = li->app_io->get_name(li);
	}

	/*
	 *	Note that we're opening a child socket, so we don't
	 *	put it into the list of global listeners.
	 */

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
	fr_io_thread_t *thread;
	fr_listen_t *child;

	get_inst(li, &inst, &thread, &connection, &child);

	/*
	 *	We're not doing IO, so there are no timers for
	 *	cleaning up packets, dynamic clients, or connections.
	 */
	if (!inst->submodule) return;

	if (inst->app_io->event_list_set) {
		inst->app_io->event_list_set(child, el, nr);
	}

	/*
	 *	Set event list and network side for this socket.
	 */
	if (!connection) {
		thread->el = el;
		thread->nr = nr;

	} else {
		connection->el = el;
		connection->nr = nr;
	}
}


static void client_expiry_timer(fr_timer_list_t *tl, fr_time_t now, void *uctx)
{
	fr_io_client_t		*client = talloc_get_type_abort(uctx, fr_io_client_t);
	fr_io_instance_t const	*inst;
	fr_io_connection_t	*connection;
	fr_time_delta_t		delay;
	int			connections;

	/*
	 *	No event list?  We don't need to expire the client.
	 */
	if (!tl) return;

	// @todo - print out what we plan on doing next
	connection = client->connection;
	inst = client->inst;

	fr_assert(client->state != PR_CLIENT_STATIC);

	/*
	 *	Called from the read or write functions with
	 *	now==0, to signal that we have to *set* the timer.
	 */
	if (fr_time_eq(now, fr_time_wrap(0))) {
		/*
		 *	The timer is already set, don't do anything.
		 */
		if (fr_timer_armed(client->ev)) return;

		switch (client->state) {
		case PR_CLIENT_CONNECTED:
			fr_assert(connection != NULL);
			delay = inst->idle_timeout;
			if (fr_time_delta_ispos(client->radclient->limit.idle_timeout) &&
			    (fr_time_delta_lt(client->radclient->limit.idle_timeout, inst->idle_timeout))) {
				delay = client->radclient->limit.idle_timeout;
			}
			break;

		case PR_CLIENT_DYNAMIC:
			delay = inst->dynamic_timeout;
			break;

		case PR_CLIENT_NAK:
			delay = inst->nak_lifetime;
			break;

		default:
			fr_assert(0 == 1);
			return;
		}

		DEBUG("TIMER - setting idle timeout to %pVs for connection from client %s", fr_box_time_delta(delay), client->radclient->shortname);

		goto reset_timer;
	}

	/*
	 *	It's a negative cache entry.  Just delete it.
	 */
	if (client->state == PR_CLIENT_NAK) {
		INFO("proto_%s - Expiring NAK'd dynamic client %pV - permitting new packets to be verified",
		     inst->app_io->common.name, fr_box_ipaddr(client->src_ipaddr));

	delete_client:
		fr_assert(client->packets == 0);

		/*
		 *	It's a connected socket.  Remove it from the
		 *	parents list of connections, and delete it.
		 */
		if (connection) {
			pthread_mutex_lock(&connection->parent->mutex);
			if (connection->in_parent_hash) {
				connection->in_parent_hash = false;
				(void) fr_hash_table_delete(connection->parent->ht, connection);
			}
			pthread_mutex_unlock(&connection->parent->mutex);

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

	DEBUG("TIMER - checking status of dynamic client %s %pV", client->radclient->shortname, fr_box_ipaddr(client->src_ipaddr));

	/*
	 *	It's a dynamically defined client.  If no one is using
	 *	it, clean it up after an idle timeout.
	 */
	if ((client->state == PR_CLIENT_DYNAMIC) ||
	    (client->state == PR_CLIENT_CONNECTED)) {
		if (client->packets > 0) {
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
	fr_assert(client->state == PR_CLIENT_PENDING);

	/*
	 *	This is a dynamic client pending definition.
	 *	But it's taken too long to define, so we just
	 *	delete the client, and all packets for it.  A
	 *	new packet will cause the dynamic definition
	 *	to be run again.
	 */
	if (!client->use_connected) {
		if (!client->packets) {
			DEBUG("proto_%s - No packets are using unconnected socket %s", inst->app_io->common.name, connection->name);
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

	fr_assert(!connection);

	/*
	 *	Find out how many connections are using this
	 *	client.
	 */
	pthread_mutex_lock(&client->mutex);
	fr_assert(client->ht != NULL);
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
				DEBUG("proto_%s - idle timeout for connection %s", inst->app_io->common.name, connection->name);
			} else {
				DEBUG("proto_%s - idle timeout for client %s", inst->app_io->common.name, client->radclient->shortname);
			}
			goto delete_client;
		}

		/*
		 *	No packets and no idle timeout set, go set
		 *	idle timeut.
		 */
		client->ready_to_delete = true;
		delay = client->state == PR_CLIENT_DYNAMIC ? inst->dynamic_timeout : inst->idle_timeout;
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
	delay = inst->check_interval;

reset_timer:
	if (fr_timer_in(client, tl, &client->ev,
			delay, false, client_expiry_timer, client) < 0) {
		ERROR("proto_%s - Failed adding timeout for dynamic client %s.  It will be permanent!",
		      inst->app_io->common.name, client->radclient->shortname);
		return;
	}

	return;
}


/*
 *	Expire cached packets after cleanup_delay time
 */
static void packet_expiry_timer(fr_timer_list_t *tl, fr_time_t now, void *uctx)
{
	fr_io_track_t *track = talloc_get_type_abort(uctx, fr_io_track_t);
	fr_io_client_t *client = track->client;
	fr_io_instance_t const *inst = client->inst;

	/*
	 *	Insert the timer if requested.
	 *
	 *	On duplicates this also extends the expiry timer.
	 */
	if (fr_time_eq(now, fr_time_wrap(0)) && !track->discard && inst->app_io->track_duplicates) {
		fr_assert(fr_time_delta_ispos(inst->cleanup_delay));
		fr_assert(track->do_not_respond || track->reply_len);

		track->expires = fr_time_add(fr_time(), inst->cleanup_delay);

		/*
		 *	if the timer succeeds, then "track"
		 *	will be cleaned up when the timer
		 *	fires.
		 */
		if (fr_timer_at(track, tl, &track->ev,
				track->expires,
				false, packet_expiry_timer, track) == 0) {
			DEBUG("proto_%s - cleaning up request in %.6fs", inst->app_io->common.name,
			      fr_time_delta_unwrap(inst->cleanup_delay) / (double)NSEC);
			return;
		}

		DEBUG("proto_%s - Failed adding cleanup_delay for packet.  Discarding packet immediately",
		      inst->app_io->common.name);
	}

	/*
	 *	So that all cleanup paths can come here, not just the
	 *	timeout ones.
	 */
	if (fr_time_neq(now, fr_time_wrap(0))) {
		DEBUG2("TIMER - proto_%s - cleanup delay", inst->app_io->common.name);
	} else {
		DEBUG2("proto_%s - cleaning up", inst->app_io->common.name);
	}

	/*
	 *	Delete the tracking entry.
	 */
	talloc_free(track);

	/*
	 *	The client isn't dynamic, stop here.
	 */
	if (client->state == PR_CLIENT_STATIC) return;

	fr_assert(client->state != PR_CLIENT_NAK);
	fr_assert(client->state != PR_CLIENT_PENDING);

	/*
	 *	If necessary, call the client expiry timer to clean up
	 *	the client.
	 */
	if (client->packets == 0) {
		client_expiry_timer(tl, now, client);
	}
}

static ssize_t mod_write(fr_listen_t *li, void *packet_ctx, fr_time_t request_time,
			 uint8_t *buffer, size_t buffer_len, size_t written)
{
	fr_io_instance_t const *inst;
	fr_io_thread_t *thread;
	fr_io_connection_t *connection;
	fr_io_track_t *track = talloc_get_type_abort(packet_ctx, fr_io_track_t);
	fr_io_client_t *client;
	fr_client_t *radclient;
	fr_listen_t *child;
	fr_event_list_t *el;
	char const *name;

	get_inst(li, &inst, &thread, &connection, &child);

	client = track->client;
	if (connection) {
		el = connection->el;
		name = connection->name;
	} else {
		el = thread->el;
		name = li->name;
	}

	DEBUG3("Processing reply for %s", name);

	/*
	 *	A fully defined client means that we just send the reply.
	 */
	if (client->state != PR_CLIENT_PENDING) {
		ssize_t packet_len;

		track->finished = true;

		/*
		 *	The request received a conflicting packet, so we
		 *	discard this one.
		 */
		if (fr_time_neq(track->timestamp, request_time) || track->discard) {
			fr_assert(track->packets > 0);
			track->packets--;
			DEBUG3("Suppressing reply as we have a newer / conflicing packet from the same source");
			track->discard = true;
			goto setup_timer;
		}

		/*
		 *	We have a NAK packet, or the request has timed
		 *	out, or it was discarded due to a conflicting
		 *	packet.  We don't respond, but we do cache the
		 *	"do not respond" reply for a period of time.
		 */
		if ((buffer_len == 1) || track->do_not_respond) {
			DEBUG3("Not sending response to request - it is marked as 'do not respond'");
			track->do_not_respond = true;
			goto setup_timer;
		}

		/*
		 *	We have a real packet, write it to the network
		 *	via the underlying transport write.
		 */
		packet_len = inst->app_io->write(child, track, request_time,
						 buffer, buffer_len, written);
		if (packet_len <= 0) {
			ERROR("Failed writing the reply - not sending any response on %s", name);
			track->discard = true;
			packet_expiry_timer(el->tl, fr_time_wrap(0), track);
			return packet_len;
		}

		/*
		 *	Only a partial write.  The network code will
		 *	take care of calling us again, and we will set
		 *	the expiry timer at that point.
		 */
		if ((size_t) packet_len < buffer_len) {
			DEBUG3("Partial write (%zd < %zu)", packet_len, buffer_len);
			return packet_len;
		}

		/*
		 *	We're not tracking duplicates, so just expire
		 *	the packet now.
		 */
		if (!inst->app_io->track_duplicates) {
			DEBUG3("Not tracking duplicates - expiring the request");
			goto setup_timer;
		}

		/*
		 *	Cache the reply packet if we're doing dedup.
		 *
		 *	On resend duplicate reply, the reply is
		 *	already filled out.  So we don't do that twice.
		 */
		if (!track->reply) {
			DEBUG3("Caching reply");
			MEM(track->reply = talloc_memdup(track, buffer, buffer_len));
			track->reply_len = buffer_len;
		}

		/*
		 *	Set the timer to expire the packet.
		 *
		 *	On dedup this also extends the timer.
		 */
	setup_timer:
		packet_expiry_timer(el->tl, fr_time_wrap(0), track);
		return buffer_len;
	}

	/*
	 *	The client is pending, so we MUST have dynamic clients.
	 *
	 *	If there's a connected socket and no dynamic clients, then the
	 *	client state is set to CONNECTED when the client is created.
	 */
	fr_assert(inst->dynamic_clients);
	fr_assert(client->pending != NULL);

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
		INFO("proto_%s - Verification failed for packet from dynamic client %pV - adding IP address to the NAK cache",
		     inst->app_io->common.name,	fr_box_ipaddr(client->src_ipaddr));

		client->state = PR_CLIENT_NAK;
		if (!connection) {
			client_pending_free(client);
		} else {
			TALLOC_FREE(client->pending);
		}
		if (client->table) TALLOC_FREE(client->table);
		fr_assert(client->packets == 0);

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
			connection = fr_io_connection_alloc(inst, thread, client, -1, connection->address, connection);
			client_expiry_timer(el->tl, fr_time_wrap(0), connection->client);

			errno = ECONNREFUSED;
			return -1;
		}

		/*
		 *	For connected TCP sockets, we just call the
		 *	expiry timer, which will close and free the
		 *	connection.
		 */
		client_expiry_timer(el->tl, fr_time_wrap(0), client);
		return buffer_len;
	}

	fr_assert(buffer_len == sizeof(radclient));

	memcpy(&radclient, buffer, sizeof(radclient));

	if (!connection) {
		fr_ipaddr_t ipaddr;

		/*
		 *	Check the encapsulating network against the
		 *	address that the user wants to use, but only
		 *	for unconnected sockets.
		 */
		if (client->network.af != radclient->ipaddr.af) {
			DEBUG("Client IP address %pV IP family does not match the source network %pV of the packet.",
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
			ERROR("Cannot define a dynamic client as a network");

		error:
			talloc_free(radclient);

			/*
			 *	Remove the pending client from the trie.
			 */
			fr_assert(!connection);
			talloc_free(client);
			return buffer_len;
		}
	}

	/*
	 *	The new client is mostly OK.  Copy the various fields
	 *	over.
	 */
#define COPY_FIELD(_dest, _x) _dest->radclient->_x = radclient->_x
#define DUP_FIELD(_dest, _x) _dest->radclient->_x = talloc_strdup(_dest->radclient, radclient->_x)

	/*
	 *	Only these two fields are set.  Other strings in
	 *	radclient are copies of these ones.
	 */
	talloc_const_free(client->radclient->shortname);
	talloc_const_free(client->radclient->secret);

	DUP_FIELD(client, longname);
	DUP_FIELD(client, shortname);
	DUP_FIELD(client, secret);
	DUP_FIELD(client, nas_type);

	COPY_FIELD(client, ipaddr);
	COPY_FIELD(client, src_ipaddr);
	COPY_FIELD(client, require_message_authenticator);
	COPY_FIELD(client, require_message_authenticator_is_set);
	COPY_FIELD(client, limit_proxy_state);
	COPY_FIELD(client, limit_proxy_state_is_set);
	COPY_FIELD(client, use_connected);
	COPY_FIELD(client, cs);

	// @todo - fill in other fields?

	talloc_free(radclient);

	radclient = client->radclient; /* laziness */
	radclient->server_cs = inst->server_cs;
	radclient->server = cf_section_name2(inst->server_cs);

	/*
	 *	This is a connected socket, and it's just been
	 *	allowed.  Go poke the network side to read from the
	 *	socket.
	 */
	if (connection) {
		fr_assert(connection != NULL);
		fr_assert(connection->client == client);
		fr_assert(client->connection != NULL);

		client->state = PR_CLIENT_CONNECTED;

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

		connection->parent->radclient->active = true;
		fr_assert(connection->parent->state == PR_CLIENT_PENDING);
		connection->parent->state = PR_CLIENT_DYNAMIC;

		DUP_FIELD(connection->parent, longname);
		DUP_FIELD(connection->parent, shortname);
		DUP_FIELD(connection->parent, secret);
		DUP_FIELD(connection->parent, nas_type);

		COPY_FIELD(connection->parent, ipaddr);
		COPY_FIELD(connection->parent, src_ipaddr);
		COPY_FIELD(connection->parent, require_message_authenticator);
		COPY_FIELD(connection->parent, require_message_authenticator_is_set);
		COPY_FIELD(connection->parent, limit_proxy_state);
		COPY_FIELD(connection->parent, limit_proxy_state_is_set);
		COPY_FIELD(connection->parent, use_connected);
		COPY_FIELD(connection->parent, cs);

		/*
		 *	Re-parent the conf section used to build this client
		 *	so its lifetime is linked to parent client
		 */
		talloc_steal(connection->parent->radclient, connection->parent->radclient->cs);

		/*
		 *	The client has been allowed.
		 */
		client->state = PR_CLIENT_DYNAMIC;
		client->radclient->active = true;

		INFO("proto_%s - Verification succeeded for packet from dynamic client %pV - processing queued packets",
		     inst->app_io->common.name,	fr_box_ipaddr(client->src_ipaddr));
		goto finish;
	} else {
		/*
		 *	Re-parent the conf section used to build this client
		 *	so its lifetime is linked to the client
		 */
		talloc_steal(radclient, radclient->cs);
	}

	fr_assert(connection == NULL);
	fr_assert(client->use_connected == false); /* we weren't sure until now */

	/*
	 *	Disallow unsupported configurations.
	 */
	if (radclient->use_connected && !inst->app_io->connection_set) {
		DEBUG("proto_%s - cannot use connected sockets as underlying 'transport = %s' does not support it.",
		      inst->app_io->common.name, inst->submodule->module->exported->name);
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
		fr_assert(connection == NULL);


		/*
		 *	Leave the state as PENDING.  Each connection
		 *	will then cause a dynamic client to be
		 *	defined.
		 */
		(void) pthread_mutex_init(&client->mutex, NULL);
		MEM(client->ht = fr_hash_table_alloc(client, connection_hash, connection_cmp, NULL));

	} else {
		/*
		 *	The client has been allowed.
		 */
		client->state = PR_CLIENT_DYNAMIC;
		client->radclient->active = true;

		INFO("proto_%s - Verification succeeded for packet from dynamic client %pV - processing %d queued packets",
		     inst->app_io->common.name,	fr_box_ipaddr(client->src_ipaddr),
		     fr_heap_num_elements(client->pending));
	}

	/*
	 *	Add this client to the master socket, so that
	 *	mod_read() will see the pending client, pop the
	 *	pending packet, and process it.
	 *
	 */
	if (!thread->pending_clients) {
		MEM(thread->pending_clients = fr_heap_alloc(thread, pending_client_cmp,
							   fr_io_client_t, pending_id, 0));
	}

	fr_assert(!fr_heap_entry_inserted((client->pending_id)));
	(void) fr_heap_insert(&thread->pending_clients, client);

finish:
	/*
	 *	Maybe we defined the client, but the original packet
	 *	timed out, so there's nothing more to do.  In that case, set up the expiry timers.
	 */
	if (client->packets == 0) {
		client_expiry_timer(el->tl, fr_time_wrap(0), client);
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
			fr_network_listen_read(thread->nr, thread->listen);
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

	get_inst(li, &inst, NULL, &connection, &child);

	if (inst->app_io->close) {
		int ret;

		ret = inst->app_io->close(child);
		if (ret < 0) return ret;
	} else {
		close(child->fd);
//		child->fd = -1;
	}

	if (!connection) return 0;

	/*
	 *	We allocated this, so we're responsible for closing
	 *	it.
	 */
	DEBUG("Closing connection %s", connection->name);
	if (connection->client->pending) {
		TALLOC_FREE(connection->client->pending); /* for any pending packets */
	}

	/*
	 *	Remove connection from parent hash table
	 */
	pthread_mutex_lock(&connection->parent->mutex);
	if (connection->in_parent_hash) {
		connection->in_parent_hash = false;
		(void) fr_hash_table_delete(connection->parent->ht, connection);
	}
	pthread_mutex_unlock(&connection->parent->mutex);

	talloc_free(connection->mi);

	return 0;
}

static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	fr_io_instance_t *inst = mctx->mi->data;
	CONF_SECTION *conf = mctx->mi->conf;

	inst->mi = mctx->mi;
	inst->app_io = (fr_app_io_t const *) inst->submodule->exported;
	inst->app_io_conf = inst->submodule->conf;
	inst->app_io_instance = inst->submodule->data;

	/*
	 *	If we're not tracking duplicates then we don't need a
	 *	cleanup delay.
	 *
	 *	If we are tracking duplicates, then we must have a non-zero cleanup delay.
	 */
	if (!inst->app_io->track_duplicates) {
		inst->cleanup_delay = fr_time_delta_wrap(0);

	} else {
		FR_TIME_DELTA_BOUND_CHECK("cleanup_delay", inst->cleanup_delay, >=, fr_time_delta_from_sec(1));

		if (!inst->app_io->track_create) {
			cf_log_err(inst->app_io_conf, "Internal error: 'track_duplicates' is set, but there is no 'track create' function");
			return -1;
		}
	}

	/*
	 *	Get various information after bootstrapping the
	 *	application IO module.
	 */
	if (inst->app_io->network_get) {
		inst->app_io->network_get(&inst->ipproto, &inst->dynamic_clients, &inst->networks, inst->app_io_instance);
	}

	if ((inst->ipproto == IPPROTO_TCP) && !inst->app_io->connection_set) {
		cf_log_err(inst->app_io_conf, "Missing 'connection set' API for proto_%s", inst->app_io->common.name);
		return -1;
	}

	/*
	 *	Ensure that the dynamic client sections exist
	 */
	if (inst->dynamic_clients) {
		CONF_SECTION *server = cf_item_to_section(cf_parent(conf));

		if (!cf_section_find(server, "new", "client")) {
			cf_log_err(conf, "Cannot use 'dynamic_clients = yes' as the virtual server has no 'new client { ... }' section defined.");
			return -1;
		}

		if (!cf_section_find(server, "add", "client")) {
			cf_log_warn(conf, "No 'add client { ... }' section was defined.");
		}

		if (!cf_section_find(server, "deny", "client")) {
			cf_log_warn(conf, "No 'deny client { ... }' section was defined.");
		}
	}

	/*
	 *	Create a list of client modules.
	 *
	 *	FIXME - Probably only want to do this for connected sockets?
	 *
	 *	FIXME - We probably want write protect enabled?
	 */
	inst->clients = module_list_alloc(inst, &module_list_type_thread_local, "clients", false);
	module_list_mask_set(inst->clients, MODULE_INSTANCE_BOOTSTRAPPED);

	return 0;
}


static char const *mod_name(fr_listen_t *li)
{
	fr_io_thread_t *thread;
	fr_io_connection_t *connection;
	fr_listen_t *child;
	fr_io_instance_t const *inst;

	get_inst(li, &inst, &thread, &connection, &child);

	fr_assert(child != NULL);
	return child->app_io->get_name(child);
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

	MEM(trie = fr_trie_alloc(ctx, NULL, NULL));

	num = talloc_array_length(allow);
	fr_assert(num > 0);

	for (i = 0; i < num; i++) {
		fr_ipaddr_t *network;

		/*
		 *	Can't add v4 networks to a v6 socket, or vice versa.
		 */
		if (allow[i].af != af) {
			fr_strerror_printf("Address family in entry %zd - 'allow = %pV' "
					   "does not match 'ipaddr'", i + 1, fr_box_ipaddr(allow[i]));
			talloc_free(trie);
			return NULL;
		}

		/*
		 *	Duplicates are bad.
		 */
		network = fr_trie_match_by_key(trie,
					&allow[i].addr, allow[i].prefix);
		if (network) {
			fr_strerror_printf("Cannot add duplicate entry 'allow = %pV'",
					   fr_box_ipaddr(allow[i]));
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
		network = fr_trie_lookup_by_key(trie,
					 &allow[i].addr, allow[i].prefix);
		if (network && (network->prefix <= allow[i].prefix)) {
			fr_strerror_printf("Cannot add overlapping entry 'allow = %pV'", fr_box_ipaddr(allow[i]));
			fr_strerror_const("Entry is completely enclosed inside of a previously defined network.");
			talloc_free(trie);
			return NULL;
		}

		/*
		 *	Insert the network into the trie.
		 *	Lookups will return the fr_ipaddr_t of
		 *	the network.
		 */
		if (fr_trie_insert_by_key(trie,
				   &allow[i].addr, allow[i].prefix,
				   &allow[i]) < 0) {
			fr_strerror_printf("Failed adding 'allow = %pV' to tracking table", fr_box_ipaddr(allow[i]));
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

		/*
		 *	Can't add v4 networks to a v6 socket, or vice versa.
		 */
		if (deny[i].af != af) {
			fr_strerror_printf("Address family in entry %zd - 'deny = %pV' "
					   "does not match 'ipaddr'", i + 1, fr_box_ipaddr(deny[i]));
			talloc_free(trie);
			return NULL;
		}

		/*
		 *	Duplicates are bad.
		 */
		network = fr_trie_match_by_key(trie,
					&deny[i].addr, deny[i].prefix);
		if (network) {
			fr_strerror_printf("Cannot add duplicate entry 'deny = %pV'", fr_box_ipaddr(deny[i]));
			talloc_free(trie);
			return NULL;
		}

		/*
		 *	A "deny" can only be within a previous "allow".
		 */
		network = fr_trie_lookup_by_key(trie,
					 &deny[i].addr, deny[i].prefix);
		if (!network) {
			fr_strerror_printf("The network in entry %zd - 'deny = %pV' is not "
					   "contained within a previous 'allow'", i + 1, fr_box_ipaddr(deny[i]));
			talloc_free(trie);
			return NULL;
		}

		/*
		 *	We hack the AF in "deny" rules.  If
		 *	the lookup gets AF_UNSPEC, then we're
		 *	adding a "deny" inside of a "deny".
		 */
		if (network->af != af) {
			fr_strerror_printf("The network in entry %zd - 'deny = %pV' is overlaps "
					   "with another 'deny' rule", i + 1, fr_box_ipaddr(deny[i]));
			talloc_free(trie);
			return NULL;
		}

		/*
		 *	Insert the network into the trie.
		 *	Lookups will return the fr_ipaddr_t of
		 *	the network.
		 */
		if (fr_trie_insert_by_key(trie,
				   &deny[i].addr, deny[i].prefix,
				   &deny[i]) < 0) {
			fr_strerror_printf("Failed adding 'deny = %pV' to tracking table", fr_box_ipaddr(deny[i]));
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


int fr_io_listen_free(fr_listen_t *li)
{
	if (!li->thread_instance) return 0;

	talloc_free(li->thread_instance);
	return 0;
}

int fr_master_io_listen(fr_io_instance_t *inst, fr_schedule_t *sc,
			size_t default_message_size, size_t num_messages)
{
	fr_listen_t	*li, *child;
	fr_io_thread_t	*thread;

	/*
	 *	No IO paths, so we don't initialize them.
	 */
	if (!inst->app_io) {
		fr_assert(!inst->dynamic_clients);
		return 0;
	}

	if (!inst->app_io->common.thread_inst_size) {
		fr_strerror_const("IO modules MUST set 'thread_inst_size' when using the master IO handler.");
		return -1;
	}

	/*
	 *	Build the #fr_listen_t.  This describes the complete
	 *	path data takes from the socket to the decoder and
	 *	back again.
	 */
	MEM(li = talloc_zero(NULL, fr_listen_t));
	talloc_set_destructor(li, fr_io_listen_free);

	/*
	 *	The first listener is the one for the application
	 *	(e.g. RADIUS).  However, we mangle the IO path to
	 *	point to the master IO handler.  That allows all of
	 *	the high-level work (dynamic client checking,
	 *	connected sockets, etc.) to be handled by the master
	 *	IO handler.
	 *
	 *	This listener is then passed to the network code,
	 *	which calls our trampoline functions to do the actual
	 *	work.
	 */
	li->app = inst->app;
	li->app_instance = inst->app_instance;
	li->server_cs = inst->server_cs;

	/*
	 *	Set configurable parameters for message ring buffer.
	 */
	li->default_message_size = default_message_size;
	li->num_messages = num_messages;

	/*
	 *	Per-socket data lives here.
	 */
	thread = talloc_zero(NULL, fr_io_thread_t);
	thread->listen = li;
	thread->sc = sc;

	/*
	 *	Create the trie of clients for this socket.
	 */
	MEM(thread->trie = fr_trie_alloc(thread, NULL, NULL));

	if (inst->dynamic_clients) {
		MEM(thread->alive_clients = fr_heap_alloc(thread, alive_client_cmp,
							  fr_io_client_t, alive_id, 0));
	}

	/*
	 *	Set the listener to call our master trampoline function.
	 */
	li->app_io = &fr_master_app_io;
	li->thread_instance = thread;
	li->app_io_instance = inst;
	li->track_duplicates = inst->app_io->track_duplicates;

	/*
	 *	The child listener points to the *actual* IO path.
	 *
	 *	We need to create a complete listener here (e.g.
	 *	RADIUS + RADIUS_UDP), because the underlying IO
	 *	functions expect to get passed a full listener.
	 *
	 *	Once the network side calls us, we will call the child
	 *	listener to do the actual IO.
	 */
	child = thread->child = talloc_zero(li, fr_listen_t);
	memcpy(child, li, sizeof(*child));

	/*
	 *	Reset these fields to point to the IO instance data.
	 */
	child->app_io = inst->app_io;
	child->track_duplicates = inst->app_io->track_duplicates;

	if (child->app_io->common.thread_inst_size > 0) {
		child->thread_instance = talloc_zero_array(NULL, uint8_t,
							   inst->app_io->common.thread_inst_size);
		talloc_set_destructor(child, fr_io_listen_free);

		talloc_set_name(child->thread_instance, "proto_%s_thread_t",
				inst->app_io->common.name);

		/*
		 *	This is "const", and the user can't
		 *	touch it.  So we just reuse the same
		 *	configuration everywhere.
		 */
		child->app_io_instance = inst->app_io_instance;

	} else {
		child->thread_instance = inst->app_io_instance;
		child->app_io_instance = child->thread_instance;
	}

	/*
	 *	Don't call connection_set() for the main socket.  It's
	 *	not connected.  Instead, tell the IO path to open the
	 *	socket for us.
	 */
	if (inst->app_io->open(child) < 0) {
		cf_log_err(inst->app_io_conf, "Failed opening %s interface", inst->app_io->common.name);
		talloc_free(li);
		return -1;
	}

	li->fd = child->fd;	/* copy this back up */

	if (!child->app_io->get_name) {
		child->name = child->app_io->common.name;
	} else {
		child->name = child->app_io->get_name(child);
	}
	li->name = child->name;

	/*
	 *	Record which socket we opened.
	 */
	if (child->app_io_addr) {
		fr_listen_t *other;

		other = listen_find_any(thread->child);
		if (other) {
			ERROR("Failed opening %s - that port is already in use by another listener in server %s { ... } - %s",
			      child->name, cf_section_name2(other->server_cs), other->name);

			ERROR("got socket %d %d\n", child->app_io_addr->inet.src_port, other->app_io_addr->inet.src_port);

			talloc_free(li);
			return -1;
		}

		(void) listen_record(child);
	}

	/*
	 *	Add the socket to the scheduler, where it might end up
	 *	in a different thread.
	 */
	if (!fr_schedule_listen_add(sc, li)) {
		talloc_free(li);
		return -1;
	}

	return 0;
}

/*
 *	Used to create a tracking structure for fr_network_sendto_worker()
 */
fr_io_track_t *fr_master_io_track_alloc(fr_listen_t *li, fr_client_t *radclient, fr_ipaddr_t const *src_ipaddr, int src_port,
					fr_ipaddr_t const *dst_ipaddr, int dst_port)
{
	fr_io_instance_t const	*inst;
	fr_io_thread_t		*thread;
	fr_io_connection_t	*connection;
	fr_listen_t		*child;
	fr_io_track_t		*track;
	fr_io_client_t		*client;
	fr_io_address_t		*address;
	fr_listen_t		*parent = talloc_parent(li);

	(void) talloc_get_type_abort(parent, fr_listen_t);

	get_inst(parent, &inst, &thread, &connection, &child);

	fr_assert(child == li);

	if (unlikely(!thread)) return NULL;
	fr_assert(thread->trie != NULL);

	client = fr_trie_lookup_by_key(thread->trie, &src_ipaddr->addr, src_ipaddr->prefix);
	if (!client) {
		MEM(client = client_alloc(thread, PR_CLIENT_STATIC, inst, thread, radclient, NULL));
	}

	MEM(track = talloc_zero_pooled_object(client, fr_io_track_t, 1, sizeof(*track) + sizeof(track->address) + 64));
	MEM(track->address = address = talloc_zero(track, fr_io_address_t));
	track->client = client;

	address->socket.inet.src_port = src_port;
	address->socket.inet.dst_port = dst_port;

	address->socket.inet.src_ipaddr = *src_ipaddr;
	address->socket.inet.dst_ipaddr = *dst_ipaddr;
	address->radclient = radclient;

	return track;
}


fr_app_io_t fr_master_app_io = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "radius_master_io",

		.instantiate		= mod_instantiate,
	},
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
