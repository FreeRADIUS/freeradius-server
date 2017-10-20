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
 * @file main/request.c
 *
 * @copyright 2015 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/interpreter.h>
#include <freeradius-devel/rad_assert.h>

/** Per-request opaque data, added by modules
 *
 */
struct request_data_t {
	request_data_t	*next;			//!< Next opaque request data struct linked to this request.

	void const	*unique_ptr;		//!< Key to lookup request data.
	int		unique_int;		//!< Alternative key to lookup request data.
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
	if (request->state_ctx) talloc_free(request->state_ctx);

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
	request->log.dst->func = vradlog_request;
	request->log.dst->uctx = &default_log;

	request->module = NULL;
	request->component = "<core>";

#ifdef HAVE_TALLOC_POOLED_OBJECT
	/*
	 *	If we have talloc_pooled_object allocate the
	 *	stack as a combined chunk/pool, with memory
	 *	to hold at mutable data for at least a quarter
	 *	of the maximum number of stack frames.
	 *
	 *	Having a dedicated pool for mutable stack data
	 *	means we don't have memory fragmentations issues
	 *	as we would if request were used as the pool.
	 *
	 *	This number is pretty arbitrary, but it seems
	 *	like too low level to make into a tuneable.
	 */
	request->stack = talloc_pooled_object(request, unlang_stack_t, UNLANG_STACK_MAX / 4,
					      sizeof(unlang_stack_state_t));
#else
	request->stack = talloc_zero(request, unlang_stack_t);
#endif
	request->runnable_id = -1;
	request->time_order_id = -1;

	request->state_ctx = talloc_init("session-state");

	return request;
}

static REQUEST *request_init_fake(REQUEST *request, REQUEST *fake)
{
	fake->number = request->child_number++;
	fake->name = talloc_asprintf(fake, "%s.%" PRIu64 , request->name, fake->number);

	fake->seq_start = 0;	/* children always start with their own sequence */

	fake->parent = request;
	fake->root = request->root;
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
	if (request_data_add(request, fake, 0, fake, true, true, false) < 0) {
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
	request->proxy->root = request->root;

	return request->proxy;
}


/** Ensure opaque data is freed by binding its lifetime to the request_data_t
 *
 * @param this Request data being freed.
 * @return 0, or whatever the destructor for the opaque data returned.
 */
static int _request_data_free(request_data_t *this)
{
	if (this->free_on_parent && this->opaque) {
		int ret;

		DEBUG4("Freeing request data %p (%s) at %p:%i via destructor",
		       this->opaque, talloc_get_name(this->opaque), this->unique_ptr, this->unique_int);
		ret = talloc_free(this->opaque);
		this->opaque = NULL;

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
int request_data_add(REQUEST *request, void const *unique_ptr, int unique_int, void *opaque,
		     bool free_on_replace, bool free_on_parent, bool persist)
{
	request_data_t *this, **last, *next;

	/*
	 *	Request must have a state ctx
	 */
	rad_assert(request);
	rad_assert(!persist || request->state_ctx);
	rad_assert(!persist ||
		   (talloc_parent(opaque) == request->state_ctx) ||
		   (talloc_parent(opaque) == talloc_null_ctx()));
	rad_assert(!free_on_parent || (talloc_parent(opaque) != request));

	this = next = NULL;
	for (last = &(request->data); *last != NULL; last = &((*last)->next)) {
		*last = talloc_get_type_abort(*last, request_data_t);
		if (((*last)->unique_ptr == unique_ptr) && ((*last)->unique_int == unique_int)) {
			this = *last;
			next = this->next;

			/*
			 *	If caller requires custom behaviour on free
			 *	they must set a destructor.
			 */
			if (this->free_on_replace && this->opaque) {
				RDEBUG4("Freeing request data %p at %p:%i via replacement",
					this->opaque, this->unique_ptr, this->unique_int);
				talloc_free(this->opaque);
			}
			/*
			 *	Need a new one, this one's parent is wrong.
			 *	And no, we can't just steal.
			 */
			if (this->persist != persist) {
				this->free_on_parent = false;
				TALLOC_FREE(this);
			}

			break;	/* replace the existing entry */
		}
	}

	/*
	 *	Only alloc new memory if we're not replacing
	 *	an existing entry.
	 *
	 *	Tie the lifecycle of the data to either the state_ctx
	 *	or the request, depending on whether it should
	 *	persist or not.
	 */
	if (!this) {
		if (persist) {
			rad_assert(request->state_ctx);
			this = talloc_zero(request->state_ctx, request_data_t);
		} else {
			this = talloc_zero(request, request_data_t);
		}
		talloc_set_destructor(this, _request_data_free);
	}
	if (!this) return -1;

	this->next = next;
	this->unique_ptr = unique_ptr;
	this->unique_int = unique_int;
	this->opaque = opaque;
	this->free_on_replace = free_on_replace;
	this->free_on_parent = free_on_parent;
	this->persist = persist;

	*last = this;

	RDEBUG4("Added request data %p at %p:%i", this->opaque, this->unique_ptr, this->unique_int);

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
	request_data_t **last;

	if (!request) return NULL;

	for (last = &(request->data); *last != NULL; last = &((*last)->next)) {
		*last = talloc_get_type_abort(*last, request_data_t);
		if (((*last)->unique_ptr == unique_ptr) && ((*last)->unique_int == unique_int)) {
			request_data_t	*this;
			void		*ptr;

			this = *last;
			ptr = this->opaque;

			/*
			 *	Remove the entry from the list, and free it.
			 */
			*last = this->next;
			this->free_on_parent = false;	/* Don't free opaque data we're handing back */
			talloc_free(this);

			return ptr;
		}
	}

	return NULL;		/* wasn't found, too bad... */
}

/** Loop over all the request data, pulling out ones matching persist state
 *
 * @param[out] out	Head of result list.
 * @param[in] request	to search for request_data_t in.
 * @param[in] persist	Whether to pull persistable or non-persistable data.
 * @return number of request_data_t retrieved.
 */
int request_data_by_persistance(request_data_t **out, REQUEST *request, bool persist)
{
	int count = 0;

	request_data_t **last, *head = NULL, **next;

	next = &head;

	for (last = &(request->data); *last != NULL; last = &((*last)->next)) {
		*last = talloc_get_type_abort(*last, request_data_t);
		if ((*last)->persist == persist) {
			request_data_t	*this;

			/* Unlink it from the list */
			this = *last;
			*last = this->next;

			/* Add it to our list of data to return */
			this->next = NULL;
			*next = this;
			next = &this->next;
			count++;
		}
		if (!*last) break;
	}
	*out = head;

	return count;
}

/** Add request data back to a request
 *
 * @note May add multiple entries (if they're linked).
 * @note Will not check for duplicates.
 *
 * @param request	to add data to.
 * @param entry		the data to add.
 */
void request_data_restore(REQUEST *request, request_data_t *entry)
{
	request_data_t **last;

	/*
	 *	Wind to the end of the current request data
	 */
	for (last = &(request->data); *last != NULL; last = &((*last)->next)) if (!(*last)->next) break;
	*last = entry;

	{
		request_data_t *this;

		for (this = request->data; this; this = this->next) this = talloc_get_type_abort(this, request_data_t);
	}
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
	request_data_t **last;

	for (last = &(request->data); *last != NULL; last = &((*last)->next)) {
		if (((*last)->unique_ptr == unique_ptr) &&
		    ((*last)->unique_int == unique_int)) return (*last)->opaque;
	}

	return NULL;		/* wasn't found, too bad... */
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
bool request_data_verify_parent(TALLOC_CTX *parent, request_data_t *entry)
{
	request_data_t **last;

	for (last = &entry; *last != NULL; last = &((*last)->next)) if (talloc_parent(entry) != parent) return false;
	return true;
}
#endif
