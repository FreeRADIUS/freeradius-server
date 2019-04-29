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
 *
 * @brief Functions for allocating requests and storing internal data in them.
 * @file src/lib/server/request.c
 *
 * @copyright 2015 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/rad_assert.h>
#include <freeradius-devel/unlang/base.h>

/** Per-request opaque data, added by modules
 *
 */
struct request_data_t {
	fr_dlist_t	list;			//!< Next opaque request data struct linked to this request.

	void const	*unique_ptr;		//!< Key to lookup request data.
	int		unique_int;		//!< Alternative key to lookup request data.
	char const	*type;			//!< Opaque type e.g. VALUE_PAIR, fr_dict_attr_t etc...
	void		*opaque;		//!< Opaque data.
	bool		free_on_replace;	//!< Whether to talloc_free(opaque) when the request data is removed.
	bool		free_on_parent;		//!< Whether to talloc_free(opaque) when the request is freed
	bool		persist;		//!< Whether this data should be transfered to a session_entry_t
						//!< after we're done processing this request.
};

/** Callback for freeing a request struct
 *
 */
static int _request_free(REQUEST *request)
{
	rad_assert(!request->ev);

#ifndef NDEBUG
	request->magic = 0x01020304;	/* set the request to be nonsense */
#endif
	request->client = NULL;
#ifdef WITH_PROXY
	request->proxy = NULL;
#endif

	/*
	 *	This is parented separately.
	 *
	 *	The reason why it's OK to do this, is if the state attributes
	 *	need to persist across requests, they will already have been
	 *	moved to a fr_state_entry_t, with the state pointers in the
	 *	request being set to NULL, before the request is freed.
	 */
	if (request->state_ctx) TALLOC_FREE(request->state_ctx);

	talloc_free_children(request);

	return 0;
}

/** Create a new REQUEST data structure
 *
 */
REQUEST *request_alloc(TALLOC_CTX *ctx)
{
	REQUEST *request;

	request = talloc_zero(ctx, REQUEST);
	if (!request) return NULL;
	talloc_set_destructor(request, _request_free);
#ifndef NDEBUG
	request->magic = REQUEST_MAGIC;
#endif
#ifdef WITH_PROXY
	request->proxy = NULL;
#endif
	request->reply = NULL;
	request->control = NULL;
	request->username = NULL;
	request->password = NULL;

	/*
	 *	These may be changed later by request_pre_handler
	 */
	request->log.lvl = req_debug_lvl;	/* Default to global debug level */
	request->log.dst = talloc_zero(request, log_dst_t);
	request->log.dst->func = vlog_request;
	request->log.dst->uctx = &default_log;

	request->module = NULL;
	request->component = "<core>";

	MEM(request->stack = unlang_interpret_stack_alloc(request));

	request->runnable_id = -1;
	request->time_order_id = -1;

	request->state_ctx = talloc_init("session-state");

	/*
	 *	Initialise the request data list
	 */
	fr_dlist_talloc_init(&request->data, request_data_t, list);

	return request;
}

static REQUEST *request_init_fake(REQUEST *request, REQUEST *fake)
{
	fake->number = request->child_number++;
	fake->name = talloc_typed_asprintf(fake, "%s.%" PRIu64 , request->name, fake->number);

	fake->seq_start = 0;	/* children always start with their own sequence */

	fake->parent = request;
	fake->dict = request->dict;
	fake->config = request->config;
	fake->client = request->client;

	/*
	 *	For new server support.
	 *
	 *	FIXME: Key instead off of a "virtual server" data structure.
	 *
	 *	FIXME: Permit different servers for inner && outer sessions?
	 */
	fake->server_cs = request->server_cs;

	fake->packet = fr_radius_alloc(fake, true);
	if (!fake->packet) {
		talloc_free(fake);
		return NULL;
	}

	fake->reply = fr_radius_alloc(fake, false);
	if (!fake->reply) {
		talloc_free(fake);
		return NULL;
	}

	fake->master_state = REQUEST_ACTIVE;

	/*
	 *	Fill in the fake request.
	 */
	fake->packet->sockfd = -1;
	fake->packet->src_ipaddr = request->packet->src_ipaddr;
	fake->packet->src_port = request->packet->src_port;
	fake->packet->dst_ipaddr = request->packet->dst_ipaddr;
	fake->packet->dst_port = 0;

	/*
	 *	This isn't STRICTLY required, as the fake request MUST NEVER
	 *	be put into the request list.  However, it's still reasonable
	 *	practice.
	 */
	fake->packet->id = fake->number & 0xff;
	fake->packet->code = request->packet->code;
	fake->packet->timestamp = request->packet->timestamp;

	/*
	 *	Required for new identity support
	 */
	fake->listener = request->listener;

	/*
	 *	Fill in the fake reply, based on the fake request.
	 */
	fake->reply->sockfd = fake->packet->sockfd;
	fake->reply->src_ipaddr = fake->packet->dst_ipaddr;
	fake->reply->src_port = fake->packet->dst_port;
	fake->reply->dst_ipaddr = fake->packet->src_ipaddr;
	fake->reply->dst_port = fake->packet->src_port;
	fake->reply->id = fake->packet->id;
	fake->reply->code = 0; /* UNKNOWN code */

	/*
	 *	Copy debug information.
	 */
	memcpy(&(fake->log), &(request->log), sizeof(fake->log));
	fake->log.unlang_indent = 0;	/* Apart from the indent which we reset */
	fake->log.module_indent = 0;	/* Apart from the indent which we reset */

	return fake;
}


/*
 *	Create a new REQUEST, based on an old one.
 *
 *	This function allows modules to inject fake requests
 *	into the server, for tunneled protocols like TTLS & PEAP.
 */
REQUEST *request_alloc_fake(REQUEST *request, fr_dict_t const *namespace)
{
	REQUEST *fake;

	fake = request_alloc(request);
	if (!fake) return NULL;

	if (!request_init_fake(request, fake)) return NULL;

	if (namespace) fake->dict = namespace;

	return fake;
}

/** Allocate a fake request which is detachable from the parent.
 * i.e. if the parent goes away, sometimes the child MAY continue to
 * run.
 *
 */
REQUEST *request_alloc_detachable(REQUEST *request, fr_dict_t const *namespace)
{
	REQUEST *fake;

	fake = request_alloc(NULL);
	if (!fake) return NULL;

	if (!request_init_fake(request, fake)) return NULL;

	if (namespace) fake->dict = namespace;

	/*
	 *	Ensure that we use our own version of the logging
	 *	information, and not the original request one.
	 */
	fake->log.dst = talloc_zero(fake, log_dst_t);
	memcpy(fake->log.dst, request->log.dst, sizeof(*fake->log.dst));

	/*
	 *	Associate the child with the parent, using the child's
	 *	pointer as a unique identifier.  Free it if the parent
	 *	goes away, but don't persist it across
	 *	challenge-response boundaries.
	 */
	if (request_data_talloc_add(request, fake, 0, REQUEST, fake, true, true, false) < 0) {
		talloc_free(fake);
		return NULL;
	}

	return fake;
}

/** Unlink a subrequest from its parent
 *
 * @note This should be used for requests in preparation for freeing them.
 *
 * @param[in] fake		request to unlink.
 * @param[in] will_free		Caller super pinky swears to free
 *				the request ASAP, and that it wont
 *				touch persistable request data,
 *				request->state_ctx or request->state.
 * @return
 *	 - 0 on success.
 *	 - -1 on failure.
 */
int request_detach(REQUEST *fake, bool will_free)
{
	REQUEST		*request = fake->parent;

	rad_assert(request != NULL);

	/*
	 *	Unlink the child from the parent.
	 */
	request_data_get(request, fake, 0);

	/*
	 *	Fixup any sate or persistent
	 *	request data.
	 */
	fr_state_detach(fake, will_free);

	fake->parent = NULL;

	while (!request->backlog) {
		rad_assert(request->parent != NULL);
		request = request->parent;
	}

	fake->backlog = request->backlog;

	return 0;
}

/* Initialise a dlist for storing request data
 *
 * @param[in] list to initialise.
 */
void request_data_list_init(fr_dlist_head_t *data)
{
	fr_dlist_talloc_init(data, request_data_t, list);
}

/** Ensure opaque data is freed by binding its lifetime to the request_data_t
 *
 * @param rd	Request data being freed.
 * @return
 *	- 0 if free on parent is false or there's no opaque data.
 *	- ...else whatever the destructor for the opaque data returned.
 */
static int _request_data_free(request_data_t *rd)
{
	if (rd->free_on_parent && rd->opaque) {
		int ret;

		DEBUG4("%s: Freeing request data %s%s%p at %p:%i via destructor",
			__FUNCTION__,
			rd->type ? rd->type : "", rd->type ? " " : "",
		       rd->opaque, rd->unique_ptr, rd->unique_int);
		ret = talloc_free(rd->opaque);
		rd->opaque = NULL;

		return ret;
	}
	return 0;
}

/** Add opaque data to a REQUEST
 *
 * The unique ptr is meant to be a module configuration, and the unique
 * integer allows the caller to have multiple opaque data associated with a REQUEST.
 *
 * @param[in] request		to associate data with.
 * @param[in] unique_ptr	Identifier for the data.
 * @param[in] unique_int	Qualifier for the identifier.
 * @param[in] type		Type of data (if talloced)
 * @param[in] opaque		Data to associate with the request.  May be NULL.
 * @param[in] free_on_replace	Free opaque data if this request_data is replaced.
 * @param[in] free_on_parent	Free opaque data if the request is freed.
 *				Must not be set if the opaque data is also parented by
 *				the request or state (double free).
 * @param[in] persist		Transfer request data to an #fr_state_entry_t, and
 *				add it back to the next request we receive for the
 *				session.
 * @return
 *	- -2 on bad arguments.
 *	- -1 on memory allocation error.
 *	- 0 on success.
 */
int _request_data_add(REQUEST *request, void const *unique_ptr, int unique_int, char const *type, void *opaque,
		      bool free_on_replace, bool free_on_parent, bool persist)
{
	request_data_t	*rd = NULL;

	/*
	 *	Request must have a state ctx
	 */
	rad_assert(request);
	rad_assert(!persist || request->state_ctx);
	rad_assert(!persist ||
		   (talloc_parent(opaque) == request->state_ctx) ||
		   (talloc_parent(opaque) == talloc_null_ctx()));
	rad_assert(!free_on_parent || (talloc_parent(opaque) != request));

#ifndef TALLOC_GET_TYPE_ABORT_NOOP
	if (type) opaque = _talloc_get_type_abort(opaque, type, __location__);
#endif

	while ((rd = fr_dlist_next(&request->data, rd))) {
		if ((rd->unique_ptr != unique_ptr) || (rd->unique_int != unique_int)) continue;

		fr_dlist_remove(&request->data, rd);	/* Unlink from the list */

		/*
		 *	If caller requires custom behaviour on free
		 *	they must set a destructor.
		 */
		if (rd->free_on_replace && rd->opaque) {
			RDEBUG4("%s: Freeing %s%s%p at %p:%i via replacement",
				__FUNCTION__,
				rd->type ? rd->type : "", rd->type ? " " : "",
				rd->opaque, rd->unique_ptr, rd->unique_int);
			talloc_free(rd->opaque);
		}
		/*
		 *	Need a new one, rd one's parent is wrong.
		 *	And no, we can't just steal.
		 */
		if (rd->persist != persist) {
			rd->free_on_parent = false;
			TALLOC_FREE(rd);
		}

		break;	/* replace the existing entry */
	}

	/*
	 *	Only alloc new memory if we're not replacing
	 *	an existing entry.
	 *
	 *	Tie the lifecycle of the data to either the state_ctx
	 *	or the request, depending on whether it should
	 *	persist or not.
	 */
	if (!rd) {
		if (persist) {
			rad_assert(request->state_ctx);
			rd = talloc_zero(request->state_ctx, request_data_t);
		} else {
			rd = talloc_zero(request, request_data_t);
		}
		talloc_set_destructor(rd, _request_data_free);
	}
	if (!rd) return -1;

	rd->unique_ptr = unique_ptr;
	rd->unique_int = unique_int;
	rd->type = type;
	rd->opaque = opaque;
	rd->free_on_replace = free_on_replace;
	rd->free_on_parent = free_on_parent;
	rd->persist = persist;

	fr_dlist_insert_head(&request->data, rd);

	RDEBUG4("%s: %s%s%p at %p:%i, free_on_replace: %s, free_on_parent: %s, persist: %s",
		__FUNCTION__,
		rd->type ? rd->type : "", rd->type ? " " : "",
		rd->opaque, rd->unique_ptr, rd->unique_int,
		free_on_replace ? "yes" : "no",
		free_on_parent ? "yes" : "no",
		persist ? "yes" : "no");

	return 0;
}

/** Get opaque data from a request
 *
 * @note The unique ptr is meant to be a module configuration, and the unique
 *	integer allows the caller to have multiple opaque data associated with a REQUEST.
 *
 * @param[in] request		to retrieve data from.
 * @param[in] unique_ptr	Identifier for the data.
 * @param[in] unique_int	Qualifier for the identifier.
 * @return
 *	- NULL if no opaque data could be found.
 *	- the opaque data. The entry holding the opaque data is removed from the request.
 */
void *request_data_get(REQUEST *request, void const *unique_ptr, int unique_int)
{
	request_data_t	*rd = NULL;

	if (!request) return NULL;

	while ((rd = fr_dlist_next(&request->data, rd))) {
		void *ptr;

		if ((rd->unique_ptr != unique_ptr) || (rd->unique_int != unique_int)) continue;

		ptr = rd->opaque;

		rd->free_on_parent = false;	/* Don't free opaque data we're handing back */
		fr_dlist_remove(&request->data, rd);

#ifndef TALLOC_GET_TYPE_ABORT_NOOP
		if (rd->type) ptr = _talloc_get_type_abort(ptr, rd->type, __location__);
#endif

		RDEBUG4("%s: %s%s%p at %p:%i retrieved and unlinked",
			__FUNCTION__,
			rd->type ? rd->type : "", rd->type ? " " : "",
			rd->opaque, rd->unique_ptr, rd->unique_int);

		talloc_free(rd);

		return ptr;
	}

	RDEBUG4("%s: No request data found at %p:%i", __FUNCTION__, unique_ptr, unique_int);

	return NULL;		/* wasn't found, too bad... */
}

/** Get opaque data from a request without removing it
 *
 * @note The unique ptr is meant to be a module configuration, and the unique
 * 	integer allows the caller to have multiple opaque data associated with a REQUEST.
 *
 * @param request	to retrieve data from.
 * @param unique_ptr	Identifier for the data.
 * @param unique_int	Qualifier for the identifier.
 * @return
 *	- NULL if no opaque data could be found.
 *	- the opaque data.
 */
void *request_data_reference(REQUEST *request, void const *unique_ptr, int unique_int)
{
	request_data_t	*rd = NULL;

	if (!request) return NULL;

	while ((rd = fr_dlist_next(&request->data, rd))) {
		if ((rd->unique_ptr != unique_ptr) || (rd->unique_int != unique_int)) continue;

#ifndef TALLOC_GET_TYPE_ABORT_NOOP
		if (rd->type) rd->opaque = _talloc_get_type_abort(rd->opaque, rd->type, __location__);
#endif

		RDEBUG4("%s: %s%s%p at %p:%i retrieved",
			__FUNCTION__,
			rd->type ? rd->type : "", rd->type ? " " : "",
			rd->opaque, rd->unique_ptr, rd->unique_int);

		return rd->opaque;
	}

	RDEBUG4("%s: No request data found at %p:%i", __FUNCTION__, unique_ptr, unique_int);

	return NULL;		/* wasn't found, too bad... */
}

/** Loop over all the request data, pulling out ones matching persist state
 *
 * @param[out] out	Head of result list.
 * @param[in] request	to search for request_data_t in.
 * @param[in] persist	Whether to pull persistable or non-persistable data.
 * @return number of request_data_t retrieved.
 */
int request_data_by_persistance(fr_dlist_head_t *out, REQUEST *request, bool persist)
{
	int		count = 0;
	request_data_t	*rd = NULL, *prev;

	while ((rd = fr_dlist_next(&request->data, rd))) {
		if (rd->persist != persist) continue;

		prev = fr_dlist_remove(&request->data, rd);
		fr_dlist_insert_tail(out, rd);
		rd = prev;
	}

	return count;
}

/** Return how many request data entries exist of a given persistence
 *
 * @param[in] request	to check in.
 * @param[in] persist	Whether to count persistable or non-persistable data.
 * @return number of request_data_t that exist in persistable or non-persistable form
 */
int request_data_by_persistance_count(REQUEST *request, bool persist)
{
	int 		count = 0;
	request_data_t	*rd = NULL;

	while ((rd = fr_dlist_next(&request->data, rd))) {
		if (rd->persist != persist) continue;

		count++;
	}

	return count;
}

/** Add request data back to a request
 *
 * @note May add multiple entries (if they're linked).
 * @note Will not check for duplicates.
 *
 * @param request	to add data to.
 * @param in		Data to add.
 */
void request_data_restore(REQUEST *request, fr_dlist_head_t *in)
{
	fr_dlist_move(&request->data, in);
}

/** Realloc any request_data_t structs in a new ctx
 *
 */
void request_data_ctx_change(TALLOC_CTX *state_ctx, REQUEST *request)
{
	fr_dlist_head_t		head;
	request_data_t		*rd = NULL, *prev;

	fr_dlist_talloc_init(&head, request_data_t, list);

	while ((rd = fr_dlist_next(&request->data, rd))) {
		request_data_t	*new;

		if (!rd->persist) continue;	/* Parented by the request */

		prev = fr_dlist_remove(&request->data, rd);	/* Unlink from the list */
		new = talloc(state_ctx, request_data_t);
		memcpy(new, rd, sizeof(*new));
		rd->free_on_parent = false;
		talloc_free(rd);
		rd = prev;

		fr_dlist_insert_tail(&head, new);
	}

	fr_dlist_move(&request->data, &head);
}

/** Used for removing data from subrequests that are about to be freed
 *
 * @param[in] request	to remove persistable data from.
 */
void request_data_persistable_free(REQUEST *request)
{
	fr_dlist_head_t	head;

	fr_dlist_talloc_init(&head, request_data_t, list);

	request_data_by_persistance(&head, request, true);

	fr_dlist_talloc_free(&head);
}

void request_data_dump(REQUEST *request)
{
	request_data_t	*rd = NULL;
	int count = 0;

	if (fr_dlist_empty(&request->data)) {
		RDEBUG("No request data");
		return;
	}

	RDEBUG("Current request data:");
	RINDENT();
	while ((rd = fr_dlist_next(&request->data, rd))) {
		RDEBUG("[%i] %s%p %s at %p:%i",
		       count,
		       rd->type ? rd->type : "",
		       rd->opaque,
		       rd->persist ? "[persist]" : "",
		       rd->unique_ptr,
		       rd->unique_int);

		count++;
	}
	REXDENT();
}

/** Free any subrequest request data if the dlist head is freed
 *
 */
static int _free_subrequest_data(fr_dlist_head_t *head)
{
	request_data_t *rd = NULL, *prev;

	while ((rd = fr_dlist_next(head, rd))) {
		prev = fr_dlist_remove(head, rd);
		talloc_free(rd);
		rd = prev;
	}

	return 0;
}

/** Store persistable data from a subrequest in its parent
 *
 * @param[in] request		The child request to retrieve state from.
 * @param[in] unique_ptr	A parent may have multiple subrequests spawned
 *				by different modules.  This identifies the module
 *      			or other facility that spawned the subrequest.
 * @param[in] unique_int	Further identification.
 */
void request_data_store_in_parent(REQUEST *request, void *unique_ptr, int unique_int)
{
	fr_dlist_head_t	*head;

	if (request_data_by_persistance_count(request, true) == 0) return;

	MEM(head = talloc_zero(request->parent->state_ctx, fr_dlist_head_t));
	fr_dlist_talloc_init(head, request_data_t, list);
	talloc_set_destructor(head, _free_subrequest_data);

	/*
	 *	Pull everything out of the child,
	 *	add it to our temporary list head...
	 */
	request_data_by_persistance(head, request, true);

	/*
	 *	...add that to the parent request under
	 *	the specified unique identifiers.
	 */
	request_data_add(request->parent, unique_ptr, unique_int, head, true, false, true);
}

/** Restore subrequest data from a parent request
 *
 * @param[in] request		The child request to restore state to.
 * @param[in] unique_ptr	A parent may have multiple subrequests spawned
 *				by different modules.  This identifies the module
 *      			or other facility that spawned the subrequest.
 * @param[in] unique_int	Further identification.
 */
void request_data_restore_to_child(REQUEST *request, void *unique_ptr, int unique_int)
{
	fr_dlist_head_t *head;

	/*
	 *	All requests are alloced with a state_ctx.
	 *	In this case, nothing should be parented
	 *	off it already, so we can just free it.
	 */
	rad_assert(talloc_get_size(request->state_ctx) == 0);
	TALLOC_FREE(request->state_ctx);
	request->state_ctx = request->parent->state_ctx;	/* Use top level state ctx */

	head = request_data_get(request->parent, unique_ptr, unique_int);
	if (!head) return;

	request_data_restore(request, head);
	talloc_free(head);
}

#ifdef WITH_VERIFY_PTR
/*
 *	Verify a packet.
 */
static void packet_verify(char const *file, int line, REQUEST const *request, RADIUS_PACKET const *packet, char const *type)
{
	TALLOC_CTX *parent;

	if (!packet) {
		fprintf(stderr, "CONSISTENCY CHECK FAILED %s[%i]: RADIUS_PACKET %s pointer was NULL", file, line, type);
		if (!fr_cond_assert(0)) fr_exit_now(1);
	}

	parent = talloc_parent(packet);
	if (parent != request) {
		ERROR("CONSISTENCY CHECK FAILED %s[%i]: Expected RADIUS_PACKET %s to be parented by %p (%s), "
		      "but parented by %p (%s)", file, line, type, request, talloc_get_name(request),
		      parent, parent ? talloc_get_name(parent) : "NULL");

		fr_log_talloc_report(packet);
		if (parent) fr_log_talloc_report(parent);

		rad_assert(0);
	}

	PACKET_VERIFY(packet);

	if (!packet->vps) return;

	fr_pair_list_verify(file, line, packet, packet->vps);
}

/*
 *	Catch horrible talloc errors.
 */
void request_verify(char const *file, int line, REQUEST const *request)
{
	if (!request) {
		fprintf(stderr, "CONSISTENCY CHECK FAILED %s[%i]: REQUEST pointer was NULL", file, line);
		if (!fr_cond_assert(0)) fr_exit_now(1);
	}

	(void) talloc_get_type_abort_const(request, REQUEST);

	rad_assert(request->magic == REQUEST_MAGIC);

	if (talloc_get_size(request) != sizeof(REQUEST)) {
		fprintf(stderr, "CONSISTENCY CHECK FAILED %s[%i]: expected REQUEST size of %zu bytes, got %zu bytes",
			file, line, sizeof(REQUEST), talloc_get_size(request));
		if (!fr_cond_assert(0)) fr_exit_now(1);
	}

	fr_pair_list_verify(file, line, request, request->control);
	fr_pair_list_verify(file, line, request->state_ctx, request->state);

	if (request->username) VP_VERIFY(request->username);
	if (request->password) VP_VERIFY(request->password);

	rad_assert(request->server_cs != NULL);

	if (request->packet) {
		packet_verify(file, line, request, request->packet, "request");
		if ((request->packet->code == FR_CODE_ACCESS_REQUEST) &&
		    (request->reply && !request->reply->code)) {
			rad_assert(request->state_ctx != NULL);
		}
	}
	if (request->reply) packet_verify(file, line, request, request->reply, "reply");

	if (request->async) {
		(void) talloc_get_type_abort(request->async, fr_async_t);
		rad_assert(talloc_parent(request->async) == request);
	}

}

/** Verify all request data is parented by the specified context
 *
 * @note Only available if built with WITH_VERIFY_PTR
 *
 * @param parent	that should hold the request data.
 * @param entry		to verify.
 * @return
 *	- true if chunk lineage is correct.
 *	- false if one of the chunks is parented by something else.
 */
bool request_data_verify_parent(TALLOC_CTX *parent, fr_dlist_head_t *entry)
{
	request_data_t	*rd = NULL;

	while ((rd = fr_dlist_next(entry, rd))) if (talloc_parent(rd) != parent) return false;

	return true;
}
#endif
