// rlm_radius_udp has to have links back to rlm_radius_link_t...
// open / close have to be in rlm_radius, for radius_ctx -> udp_ctx changes
// fd_active, etc. need to have callbacks in udp, for status-server checks...


/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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
 * @file rlm_radius.c
 * @brief A RADIUS client library.
 *
 * @copyright 2016  The FreeRADIUS server project
 * @copyright 2016  Network RADIUS SARL
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/rad_assert.h>

#include "rlm_radius.h"

static int transport_parse(TALLOC_CTX *ctx, void *out, CONF_ITEM *ci, CONF_PARSER const *rule);

/*
 *	Define a structure for our module configuration.
 */
typedef struct radius_instance {
	char const		*name;		//!< Module instance name.

	struct timeval		connection_timeout;
	struct timeval		reconnection_delay;
	struct timeval		idle_timeout;

	dl_instance_t		*io_submodule;	//!< As provided by the transport_parse
	fr_radius_client_io_t	*client_io;	//!< Easy access to the client_io handle
	void			*client_io_instance; //!< Easy access to the client_io instance
	CONF_SECTION		*client_io_conf;  //!< Easy access to the client_io's config section
} rlm_radius_t;

typedef struct rlm_radius_connection_t rlm_radius_connection_t;


/** Per-thread instance data
 *
 * Contains buffers and connection handles specific to the thread.
 */
typedef struct {
	rlm_radius_t const	*inst;			//!< Instance of the module.
	fr_event_list_t		*el;			//!< This thread's event list.

	bool			pending;		//!< We have pending messages to write.
	fr_dlist_t		queued;			//!< re-queued when a connection fails

	fr_dlist_t		active;			//!< list of connected sockets
	fr_dlist_t		frozen;			//!< list of zombie sockets... not quite dead
	fr_dlist_t		closed;			//!< list of closed sockets
} rlm_radius_thread_t;

struct rlm_radius_connection_t {
	char const		*name;			//!< humanly readable name of this connection

	fr_dlist_t		entry;			//!< in connected / opening list
	rlm_radius_t const	*inst;			//!< Instance of the module.
	rlm_radius_thread_t	*thread;		//!< thread instance
	fr_event_list_t		*el;			//!< This thread's event list.

	fr_connection_t		*conn;			//!< Connection to our destination.

	void			*client_io_ctx;		//!< client IO context

	bool			pending;		//!< we have pending messages to write
	int			waiting;		//!< written, but waiting for replies

	fr_dlist_t		queued;			//!< queued for sending
	fr_dlist_t		sent;			//!< actually sent
};

typedef struct rlm_radius_link_t {
	bool			waiting;       		//!< queued or live
	rlm_rcode_t		rcode;			//!< from the transport
	REQUEST			*request;		//!< the request we are for
	fr_dlist_t		entry;			//!< linked list of queued or sent
	rlm_radius_connection_t	*c;			//!< which connection we're queued or sent
	void			*request_io_ctx;
} rlm_radius_link_t;


static CONF_PARSER const timer_config[] = {
	{ FR_CONF_OFFSET("connection", FR_TYPE_TIMEVAL, rlm_radius_t, connection_timeout),
	  .dflt = STRINGIFY(5) },

	{ FR_CONF_OFFSET("reconnect", FR_TYPE_TIMEVAL, rlm_radius_t, reconnection_delay),
	  .dflt = STRINGIFY(5) },

	{ FR_CONF_OFFSET("idle", FR_TYPE_TIMEVAL, rlm_radius_t, idle_timeout),
	  .dflt = STRINGIFY(300) },

	CONF_PARSER_TERMINATOR
};



/*
 *	A mapping of configuration file names to internal variables.
 */
static CONF_PARSER const module_config[] = {
	{ FR_CONF_OFFSET("transport", FR_TYPE_VOID, rlm_radius_t, io_submodule),
	  .func = transport_parse },

	{ FR_CONF_POINTER("timers", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) timer_config },

	CONF_PARSER_TERMINATOR
};

/** Wrapper around dl_instance
 *
 * @param[in] ctx	to allocate data in (instance of proto_radius).
 * @param[out] out	Where to write a dl_instance_t containing the module handle and instance.
 * @param[in] ci	#CONF_PAIR specifying the name of the type module.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int transport_parse(TALLOC_CTX *ctx, void *out, CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	char const	*name = cf_pair_value(cf_item_to_pair(ci));
	dl_instance_t	*parent_inst;
	CONF_SECTION	*cs = cf_item_to_section(cf_parent(ci));
	CONF_SECTION	*transport_cs;

	transport_cs = cf_section_find(cs, name, NULL);

	/*
	 *	Allocate an empty section if one doesn't exist
	 *	this is so defaults get parsed.
	 */
	if (!transport_cs) transport_cs = cf_section_alloc(cs, cs, name, NULL);

	parent_inst = cf_data_value(cf_data_find(cs, dl_instance_t, "rlm_radius"));
	rad_assert(parent_inst);

	return dl_instance(ctx, out, transport_cs, parent_inst, name, DL_TYPE_SUBMODULE);
}


static void mod_radius_fd_idle(rlm_radius_connection_t *c);

static void mod_radius_fd_active(rlm_radius_connection_t *c);

static void mod_radius_conn_error(UNUSED fr_event_list_t *el, int sock, UNUSED int flags, int fd_errno, void *uctx);

static int CC_HINT(nonnull) mod_add(rlm_radius_t *inst, rlm_radius_connection_t *c, REQUEST *request);

/** Clear the backlog of t->queued
 *
 */
static void mod_clear_backlog(UNUSED rlm_radius_thread_t *t)
{
	//@ todo - move t->queued to new connections
	// call mod_add() with the request
}

/** Get a REQUEST from the transport.
 *
 */
static void mod_radius_conn_read(fr_event_list_t *el, int sock, UNUSED int flags, void *uctx)
{
	rlm_radius_connection_t	*c = talloc_get_type_abort(uctx, rlm_radius_connection_t);
	rlm_radius_t const	*inst = c->inst;
	rlm_radius_link_t	*link;
	int status;
	rlm_rcode_t rcode;
	REQUEST *request;

	/*
	 *	There may or may not be data.  If there isn't, it's not always an error.
	 */
	status = inst->client_io->read(&request, &rcode, el, sock, c->client_io_ctx);
	if (status == 0) return;

	if (status < 0) {
		fr_connection_reconnect(c->conn);
		return;
	}

	rad_assert(request != NULL);
	rad_assert(rcode != RLM_MODULE_YIELD);

	(void) talloc_get_type_abort(request, REQUEST);

	/*
	 *	Save the return code of the transport in the link.
	 */
	link = request_data_get(request, c, 0);
	if (!link) {
		RDEBUG("Failed finding link to transport");
		unlang_resumable(request);
		return;
	}

	link->waiting = false;
	link->rcode = rcode;

	unlang_resumable(request);
}

/** There's space available to write data, so do that...
 *
 */
static void mod_radius_conn_writable(UNUSED fr_event_list_t *el, UNUSED int sock, UNUSED int flags, void *uctx)
{
	rlm_radius_connection_t	*c = talloc_get_type_abort(uctx, rlm_radius_connection_t);
	fr_dlist_t *entry, *next;
	bool sent;

	/*
	 *	Send all of the requests to the transport.
	 */
	for (entry = FR_DLIST_FIRST(c->queued);
	     entry != NULL;
	     entry = next) {
		rlm_radius_link_t *link;

		link = fr_ptr_to_type(rlm_radius_link_t, entry, entry);

		next = FR_DLIST_NEXT(c->queued, entry);

		rad_assert(link->waiting = false);

		fr_dlist_remove(&link->entry);
		fr_dlist_insert_head(&c->sent, &link->entry);
		link->waiting = true;
		sent = true;

		// @todo - if this returns EWOULDBLOCK, stop
		// @todo - if this returns "too many requests", stop.  But the caller should have checked...
		(void) c->inst->client_io->write(link->request, link->request_io_ctx, c->client_io_ctx);
	}

	// @todo - maybe grab more packets from t->queued?

	/*
	 *	We didn't send anything, go flush the socket.
	 */
	if (!sent) (void) c->inst->client_io->flush(c->client_io_ctx);

	mod_radius_fd_idle(c);
}

/** Set the socket to idle
 *
 *  But keep the read event open, just in case the other end sends us
 *  data  That way we can process it.
 *
 * @param[in] c		Connection data structure
 */
static void mod_radius_fd_idle(rlm_radius_connection_t *c)
{
	rlm_radius_thread_t	*t = c->thread;
	rlm_radius_t const	*inst = t->inst;

	/*
	 *	Transport wants to send it's own data, so don't disable
	 *	the write callback.
	 */
	if (inst->client_io->fd_idle &&
	    !inst->client_io->fd_idle(c->client_io_ctx)) {
		return;
	}

	DEBUG3("Marking socket (%i) as idle", fr_connection_get_fd(c->conn));
	if (fr_event_fd_insert(c, c->el, fr_connection_get_fd(c->conn),
			       mod_radius_conn_read, NULL, mod_radius_conn_error, c) < 0) {
		PERROR("Failed inserting FD event");
		talloc_free(c);
	}
}

/** Set the socket to active
 *
 * We have messages we want to send, so need to know when the socket is writable.
 *
 * @param[in] c		Connection data structure
 */
static void mod_radius_fd_active(rlm_radius_connection_t *c)
{
	rlm_radius_thread_t	*t = c->thread;
	rlm_radius_t const	*inst = t->inst;

	DEBUG3("Marking socket (%i) as active - Draining requests", fr_connection_get_fd(c->conn));

	/*
	 *	Tell the transport that we're making the connection
	 *	active.
	 */
	if (inst->client_io->fd_active) (void) inst->client_io->fd_active(c->client_io_ctx);

	if (fr_event_fd_insert(c, c->el, fr_connection_get_fd(c->conn),
			       mod_radius_conn_read, mod_radius_conn_writable,
			       mod_radius_conn_error, c) < 0) {
		PERROR("Failed inserting FD event");
		talloc_free(c);
	}
}

/** Connection errored
 *
 */
static void mod_radius_conn_error(UNUSED fr_event_list_t *el, UNUSED int sock, UNUSED int flags, int fd_errno, void *uctx)
{
	rlm_radius_connection_t	*c = talloc_get_type_abort(uctx, rlm_radius_connection_t);

	ERROR("Connection %s failed): %s", c->name, fr_syserror(fd_errno));

	/*
	 *	Something bad happened... Fix it.  The connection API
	 *	will take care of deleting the FD from the event list,
	 *	and will call our mod_radius_conn_close() routine.
	 */
	fr_connection_reconnect(c->conn);
}

/** Deal with a failure case.
 *
 */
static fr_connection_state_t mod_radius_conn_failed(UNUSED int fd, fr_connection_state_t prev, void *uctx)
{
	rlm_radius_connection_t	*c = talloc_get_type_abort(uctx, rlm_radius_connection_t);
	rlm_radius_thread_t	*t = c->thread;
	fr_dlist_t		*entry, *next;

	/*
	 *	If it's not trying to reconnect, trash the entire
	 *	connection.
	 */
	if (prev != FR_CONNECTION_STATE_CONNECTED) {
		talloc_free(c);
		return FR_CONNECTION_STATE_HALTED;
	}

	/*
	 *	Remove the connection from whatever list it's in, and
	 *	add it to the "closed" list.
	 */
	fr_dlist_remove(&c->entry);
	fr_dlist_insert_tail(&t->closed, &c->entry);

	/*
	 *	Move any requests from the "sent" back to the
	 *	"queued" list.
	 */
	for (entry = FR_DLIST_FIRST(c->sent);
	     entry != NULL;
	     entry = next) {
		rlm_radius_link_t *link;

		link = fr_ptr_to_type(rlm_radius_link_t, entry, entry);

		next = FR_DLIST_NEXT(c->sent, entry);

		rad_assert(link->waiting = true);
		link->waiting = false;
		c->waiting--;

		fr_dlist_remove(&link->entry);
		fr_dlist_insert_head(&c->queued, &link->entry);

		c->pending = true;
	}

	/*
	 *	Once the connection is open again, the pending queue
	 *	will be automatically cleared by the "open" callback.
	 */

	return FR_CONNECTION_STATE_INIT;
}

/** Shutdown/close a file descriptor
 *
 */
static void mod_conn_close(int fd, void *uctx)
{
	rlm_radius_connection_t	*c = talloc_get_type_abort(uctx, rlm_radius_connection_t);
	rlm_radius_thread_t	*t = c->thread;
	rlm_radius_t const	*inst = t->inst;

	DEBUG2("Closing - %s", c->name);

	inst->client_io->close(fd, c->client_io_ctx);
}

/** Process notification that fd is open
 *
 */
static fr_connection_state_t mod_radius_conn_open(int fd, fr_event_list_t *el, void *uctx)
{
	rlm_radius_connection_t	*c = talloc_get_type_abort(uctx, rlm_radius_connection_t);
	rlm_radius_thread_t	*t = c->thread;
	rlm_radius_t const	*inst = t->inst;
	fr_connection_state_t	state;

	/*
	 *	Tell the underlying transport that it's now open.
	 */
	state = inst->client_io->open(fd, el, c->client_io_ctx);
	if (state != FR_CONNECTION_STATE_CONNECTED) {
		return state;
	}

	/*
	 *	Get the (possibly new) name of the connection.
	 */
	if (c->name) talloc_const_free(&c->name);

	c->name = inst->client_io->get_name(c, c->client_io_ctx);

	DEBUG2("Connected - %s", c->name);

	/*
	 *	Remove the connection from the "frozen" list, and add
	 *	it to the "active" list.
	 */
	fr_dlist_remove(&c->entry);
	fr_dlist_insert_tail(&t->active, &c->entry);

	/*
	 *	If we have data pending, add the writable event immediately
	 */
	if (c->pending) {
		mod_radius_fd_active(c);
	} else {
		mod_radius_fd_idle(c);
	}

	return FR_CONNECTION_STATE_CONNECTED;
}

/** Initialise a new outbound connection
 *
 * @param[out] fd_out	Where to write the new file descriptor.
 * @param[in] uctx	A #rlm_radius_thread_t.
 */
static fr_connection_state_t mod_radius_conn_init(int *fd_out, void *uctx)
{
	rlm_radius_connection_t	*c = talloc_get_type_abort(uctx, rlm_radius_connection_t);
	rlm_radius_thread_t	*t = c->thread;
	rlm_radius_t const	*inst = t->inst;

	memset(c->client_io_ctx, 0, inst->client_io->io_inst_size);

	return inst->client_io->init(fd_out, c->client_io_ctx);
}


/** The connection is beign free'd
 */
static int mod_radius_conn_free(rlm_radius_connection_t *c)
{
	fr_dlist_t *entry, *next;
	rlm_radius_thread_t *t = c->thread;

	/*
	 *	Remove us from whatever list we're in.
	 */
	fr_dlist_remove(&c->entry);

	 /*
	  *	Move any requests from the connection "sent" back to the
	  *	thread "queued" list.
	  */
	for (entry = FR_DLIST_FIRST(c->sent);
	     entry != NULL;
	     entry = next) {
		rlm_radius_link_t *link;

		link = fr_ptr_to_type(rlm_radius_link_t, entry, entry);

		next = FR_DLIST_NEXT(c->sent, entry);

		rad_assert(link->waiting = true);
		rad_assert(link->request != NULL);

		(void) c->inst->client_io->remove(link->request, link->request_io_ctx, c->client_io_ctx);
		link->waiting = false;
		c->waiting--;

		fr_dlist_remove(&link->entry);
		fr_dlist_insert_head(&t->queued, &link->entry);

		t->pending = true;
	}

	 /*
	  *	Move any requests from the connection "queued" back to the
	  *	thread "queued" list.
	  */
	for (entry = FR_DLIST_FIRST(c->queued);
	     entry != NULL;
	     entry = next) {
		rlm_radius_link_t *link;

		link = fr_ptr_to_type(rlm_radius_link_t, entry, entry);

		next = FR_DLIST_NEXT(c->queued, entry);

		rad_assert(link->waiting = false);

		fr_dlist_remove(&link->entry);
		fr_dlist_insert_head(&t->queued, &link->entry);

		t->pending = true;
	}

	if (t->pending) mod_clear_backlog(t);

	return 0;
}

/** Free and rlm_radius_link_t
 *
 *  Unlink it from the queued / sent list, and remove it from the
 *  transport.
 */
static int mod_link_free(rlm_radius_link_t *link)
{
	rlm_radius_connection_t *c = link->c;
	rlm_radius_t const *inst = c->inst;
	REQUEST *request = link->request;

	fr_dlist_remove(&link->entry);
	if (!link->waiting) return 0;

	/*
	 *	Tell the transport that the request is no longer active.
	 */
	(void) inst->client_io->remove(request, link->request_io_ctx, c->client_io_ctx);
	link->waiting = false;

	return 0;
}


static int CC_HINT(nonnull) mod_add(rlm_radius_t *inst, rlm_radius_connection_t *c, REQUEST *request)
{
	rlm_radius_link_t *link;
	size_t size;

	/*
	 *	The client IO module may need to store per-request
	 *	data.  Add it here for simpliciy.
	 */
	size = sizeof(rlm_radius_link_t);
	if (inst->client_io->request_inst_size) {
		size += 15;
		size &= ~((size_t) 15);

		size += inst->client_io->request_inst_size;
	}

	link = (rlm_radius_link_t *) talloc_zero_array(request, uint64_t, (size / sizeof(uint64_t)));
	talloc_set_type(link, rlm_radius_link_t);
	rad_assert(link != NULL);

	if (size > sizeof(rlm_radius_link_t)) {
		link->request_io_ctx = (void *) (link + 1);
	}

	/*
	 *	Add the request to the outoging queue, and associate
	 *	it with the request.
	 */
	fr_dlist_insert_tail(&c->queued, &link->entry);
	link->request = request;
	link->c = c;
	link->waiting = false;

	talloc_set_destructor(link, mod_link_free);

	(void) request_data_add(request, c, 0, link, true, true, false);

	if (inst->client_io->write(request, link->request_io_ctx, c->client_io_ctx) < 0) {
		talloc_free(link);
		return RLM_MODULE_FAIL;
	}

	link->waiting = true;

	// @todo - insert max_request_timeout
	// retransmission timeouts, etc. MUST be handled by the IO handler, which gets REQUEST in it's write() routine

	/*
	 *	If there are no pending writes, enable the write
	 *	callback.  It will wake up and write the packets to
	 *	the socket.
	 */
	if (!c->pending) {
		c->pending = true;
		mod_radius_fd_active(c);
	}

	return 0;
}

/** Continue after unlang_resumable()
 *
 */
static rlm_rcode_t mod_radius_resume( REQUEST *request, UNUSED void *instance, UNUSED void *thread, void *ctx)
{
//	rlm_radius_t *inst = talloc_get_type_abort(instance, rlm_radius_t);
//	rlm_radius_thread_t *t = talloc_get_type_abort(thread, rlm_radius_thread_t);
	rlm_radius_connection_t *c = talloc_get_type_abort(ctx, rlm_radius_connection_t);
	rlm_radius_link_t *link;
	rlm_rcode_t rcode;

	link = request_data_get(request, c, 0);
	if (!link) {
		RDEBUG("Failed finding link to transport");
		return RLM_MODULE_FAIL;
	}
	(void) talloc_get_type_abort(link, rlm_radius_link_t);

	rcode = link->rcode;
	rad_assert(rcode != RLM_MODULE_YIELD);
	rad_assert(link->waiting == false);
	talloc_free(link);

	return rcode;
}


/** Send packets outbound.
 *
 */
static rlm_rcode_t CC_HINT(nonnull) mod_process(void *instance, void *thread, REQUEST *request)
{
	rlm_radius_t *inst = instance;
	rlm_radius_thread_t *t = talloc_get_type_abort(thread, rlm_radius_thread_t);
	rlm_radius_connection_t *c;
	fr_dlist_t *entry;

	/*
	 *	Another connection has closed and moved it's requests
	 *	back to the main thread.  Recycle them through to
	 *	other connections.
	 */
	if (t->pending) {
		mod_clear_backlog(t);
	}

	entry = FR_DLIST_FIRST(t->active);
	if (!entry) {
		REDEBUG("No active connections");
		return RLM_MODULE_FAIL;
	}

	/*
	 *	Pick the first one for now.
	 */
	c = fr_ptr_to_type(rlm_radius_connection_t, entry, entry);

	// @todo - find the "most recently started" connection which has a response
	// @todo - check the connection busy-ness before calling mod_add()

	if (mod_add(inst, c, request) < 0) return RLM_MODULE_FAIL;

	return unlang_module_yield(request, mod_radius_resume, NULL, c);
}


/** Bootstrap the module
 *
 * Bootstrap I/O and type submodules.
 *
 * @param[in] instance	Ctx data for this module
 * @param[in] conf    our configuration section parsed to give us instance.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mod_bootstrap(void *instance, CONF_SECTION *conf)
{
	rlm_radius_t *inst = talloc_get_type_abort(instance, rlm_radius_t);

	inst->name = cf_section_name2(conf);
	if (!inst->name) inst->name = cf_section_name1(conf);

	FR_TIMEVAL_BOUND_CHECK("timers.connection", &inst->connection_timeout, >=, 1, 0);
	FR_TIMEVAL_BOUND_CHECK("timers.connection", &inst->connection_timeout, <=, 30, 0);

	FR_TIMEVAL_BOUND_CHECK("timers.reconnect", &inst->reconnection_delay, >=, 5, 0);
	FR_TIMEVAL_BOUND_CHECK("timers.reconned", &inst->reconnection_delay, <=, 300, 0);

	FR_TIMEVAL_BOUND_CHECK("timers.idle", &inst->connection_timeout, >=, 30, 0);
	FR_TIMEVAL_BOUND_CHECK("timers.idle", &inst->connection_timeout, <=, 600, 0);

	rad_assert(inst->client_io->io_inst_size > 0);

	if (!inst->client_io->bootstrap) return 0;

	if (inst->client_io->bootstrap(inst->client_io_instance, inst->client_io_conf) < 0) {
		cf_log_err(inst->client_io_conf, "Bootstrap failed for \"%s\"",
			   inst->client_io->name);
		return -1;
	}

	return 0;
}


/** Instantiate the module
 *
 * Instantiate I/O and type submodules.
 *
 * @param[in] instance	Ctx data for this module
 * @param[in] conf	our configuration section parsed to give us instance.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mod_instantiate(void *instance, UNUSED CONF_SECTION *conf)
{
	rlm_radius_t *inst = talloc_get_type_abort(instance, rlm_radius_t);

	if (!inst->client_io->instantiate) return 0;

	if (inst->client_io->instantiate(inst->client_io_instance, inst->client_io_conf) < 0) {
		cf_log_err(inst->client_io_conf, "Instantiate failed for \"%s\"",
			   inst->client_io->name);
		return -1;
	}

	return 0;
}

/** Detach thread-specific data
 *
 *  Which gives us a chance to clean up.
 */
static int mod_thread_detach(void *thread)
{
	rlm_radius_thread_t *t = talloc_get_type_abort(thread, rlm_radius_thread_t);
//	rlm_radius_t const *inst = t->inst;
	fr_dlist_t *entry, *next;

	/*
	 *	Free up all of the connections.
	 */
	for (entry = FR_DLIST_FIRST(t->frozen);
	     entry != NULL;
	     entry = next) {
		rlm_radius_connection_t *c;

		c = fr_ptr_to_type(rlm_radius_connection_t, entry, entry);

		next = FR_DLIST_NEXT(t->frozen, entry);
		talloc_free(c);
	}

	for (entry = FR_DLIST_FIRST(t->active);
	     entry != NULL;
	     entry = next) {
		rlm_radius_connection_t *c;

		c = fr_ptr_to_type(rlm_radius_connection_t, entry, entry);

		next = FR_DLIST_NEXT(t->active, entry);
		talloc_free(c);
	}

	for (entry = FR_DLIST_FIRST(t->closed);
	     entry != NULL;
	     entry = next) {
		rlm_radius_connection_t *c;

		c = fr_ptr_to_type(rlm_radius_connection_t, entry, entry);

		next = FR_DLIST_NEXT(t->closed, entry);
		talloc_free(c);
	}

	/*
	 *	Now that all of the connections are closed, all of the
	 *	requests we manage should be in t->queued.
	 */
	for (entry = FR_DLIST_FIRST(t->queued);
	     entry != NULL;
	     entry = next) {
		REQUEST *request;
		rlm_radius_link_t *link;

		link = fr_ptr_to_type(rlm_radius_link_t, entry, entry);

		next = FR_DLIST_NEXT(t->queued, entry);

		request = link->request;
		link->rcode = RLM_MODULE_FAIL;
		rad_assert(link->waiting == false);

		unlang_resumable(request);
	}

	return 0;
}

static int mod_thread_instantiate(CONF_SECTION const *cs, void *instance, fr_event_list_t *el, void *thread)
{
	rlm_radius_t *inst = talloc_get_type_abort(instance, rlm_radius_t);
	rlm_radius_thread_t *t = talloc_get_type_abort(thread, rlm_radius_thread_t);
	rlm_radius_connection_t *c;

	c = talloc_zero(t, rlm_radius_connection_t);
	c->name = "<pending>";
	c->inst = inst;
	c->thread = t;
	c->el = el;

	FR_DLIST_INIT(c->entry);
	FR_DLIST_INIT(c->queued);
	FR_DLIST_INIT(c->sent);

	/*
	 *	Open ONE connection.  mod_process() will open more if necessary.
	 */
	 c->client_io_ctx = talloc_zero_array(t, uint8_t, inst->client_io->io_inst_size);
	if (!c->client_io_ctx) {
		cf_log_err(cs, "Failed allocating IO instance");
		return -1;
	}

	talloc_set_destructor(c, mod_radius_conn_free);

	FR_DLIST_INIT(t->queued);
	FR_DLIST_INIT(t->active);
	FR_DLIST_INIT(t->frozen);
	FR_DLIST_INIT(t->closed);

	/*
	 *	This opens the outbound connection
	 */
	c->conn = fr_connection_alloc(c, el, &inst->connection_timeout, &inst->reconnection_delay,
				      mod_radius_conn_init, mod_radius_conn_open, mod_conn_close,
				      inst->name, c);
	if (c->conn == NULL) return -1;

	/*
	 *	We have to catch errors on failed.
	 */
	fr_connection_failed_func(c->conn, mod_radius_conn_failed);

	/*
	 *	Add the connection to the "closed" list, because it's
	 *	not open, and there are no requests outstanding on it.
	 */
	fr_dlist_insert_tail(&t->closed, &c->entry);

	fr_connection_start(c->conn);

	return 0;
}


/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern rad_module_t rlm_radius;
rad_module_t rlm_radius = {
	.magic		= RLM_MODULE_INIT,
	.name		= "radius",
	.type		= RLM_TYPE_THREAD_SAFE | RLM_TYPE_RESUMABLE,
	.inst_size	= sizeof(rlm_radius_t),
	.config		= module_config,
	.bootstrap	= mod_bootstrap,
	.instantiate	= mod_instantiate,
	.thread_instantiate = mod_thread_instantiate,
	.thread_detach	= mod_thread_detach,
	.methods = {
		[MOD_PREACCT]		= mod_process,
		[MOD_AUTHENTICATE]     	= mod_process,
	},
};
