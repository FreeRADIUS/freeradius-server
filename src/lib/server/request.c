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

	MEM(request->stack = unlang_stack_alloc(request));

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
REQUEST *request_alloc_fake(REQUEST *request)
{
	REQUEST *fake;

	fake = request_alloc(request);
	if (!fake) return NULL;

	return request_init_fake(request, fake);
}

/** Allocate a fake request which is detachable from the parent.
 * i.e. if the parent goes away, sometimes the child MAY continue to
 * run.
 *
 */
REQUEST *request_alloc_detachable(REQUEST *request)
{
	REQUEST *fake;

	fake = request_alloc(NULL);
	if (!fake) return NULL;

	if (!request_init_fake(request, fake)) return NULL;

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


/** Detach a detachable request.
 *
 *  @note the caller still has to set fake->async->detached
 */
int request_detach(REQUEST *fake)
{
	REQUEST *request = fake->parent;

	rad_assert(request != NULL);
	rad_assert(talloc_parent(fake) != request);

	/*
	 *	Unlink the child from the parent.
	 */
	if (!request_data_get(request, fake, 0)) {
		return -1;
	}

	fake->parent = NULL;

	while (!request->backlog) {
		rad_assert(request->parent != NULL);
		request = request->parent;
	}

	fake->backlog = request->backlog;

	return 0;
}

REQUEST *request_alloc_proxy(REQUEST *request)
{
	request->proxy = request_alloc(request);
	if (!request->proxy) return NULL;

	request->proxy->log = request->log;
	request->proxy->parent = request;
	request->proxy->number = request->number;
	request->proxy->seq_start = request->seq_start;
	request->proxy->config = request->config;

	return request->proxy;
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

#ifdef WITH_VERIFY_PTR
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
