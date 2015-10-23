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
#include <freeradius-devel/rad_assert.h>

/** Per-request opaque data, added by modules
 *
 */
struct request_data_t {
	request_data_t	*next;		//!< Next opaque request data struct linked to this request.

	void		*unique_ptr;	//!< Key to lookup request data.
	int		unique_int;	//!< Alternative key to lookup request data.
	void		*opaque;	//!< Opaque data.
	bool		free_opaque;	//!< Whether to talloc_free(opaque) when the request data is removed.
	bool		persist;	//!< Whether this data should be transfered to a session_entry_t
					//!< after we're done processing this request.
};

/** Callback for freeing a request struct
 *
 */
static int _request_free(REQUEST *request)
{
	rad_assert(!request->in_request_hash);
#ifdef WITH_PROXY
	rad_assert(!request->in_proxy_hash);
#endif
	rad_assert(!request->ev);

#ifdef WITH_COA
	rad_assert(request->coa == NULL);
#endif

#ifndef NDEBUG
	request->magic = 0x01020304;	/* set the request to be nonsense */
#endif
	request->client = NULL;
#ifdef WITH_PROXY
	request->home_server = NULL;
#endif

	/*
	 *	This is parented separately.
	 *
	 *	The reason why it's OK to do this, is if the state attributes
	 *	need to persist across requests,  they will already have been
	 *	moved to a fr_state_entry_t, with the state pointers in the
	 *	request being set to NULL, before the request is freed.
	 */
	if (request->state_ctx) talloc_free(request->state_ctx);

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
#ifdef WITH_PROXY
	request->proxy_reply = NULL;
#endif
	request->config = NULL;
	request->username = NULL;
	request->password = NULL;
	request->timestamp = time(NULL);
	request->log.lvl = rad_debug_lvl; /* Default to global debug level */

	request->module = "";
	request->component = "<core>";
	request->log.func = vradlog_request;

	request->state_ctx = talloc_init("session-state");

	return request;
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

	fake->number = request->number;
#ifdef HAVE_PTHREAD_H
	fake->child_pid = request->child_pid;
#endif
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
	fake->server = request->server;

	fake->packet = rad_alloc(fake, true);
	if (!fake->packet) {
		talloc_free(fake);
		return NULL;
	}

	fake->reply = rad_alloc(fake, false);
	if (!fake->reply) {
		talloc_free(fake);
		return NULL;
	}

	fake->master_state = REQUEST_ACTIVE;
	fake->child_state = REQUEST_RUNNING;

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
	fake->timestamp = request->timestamp;
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
	fake->log.indent = 0;	/* Apart from the indent which we reset */

	return fake;
}

#ifdef WITH_COA
REQUEST *request_alloc_coa(REQUEST *request)
{
	if (!request || request->coa) return NULL;

	/*
	 *	Originate CoA requests only when necessary.
	 */
	if ((request->packet->code != PW_CODE_ACCESS_REQUEST) &&
	    (request->packet->code != PW_CODE_ACCOUNTING_REQUEST)) return NULL;

	request->coa = request_alloc_fake(request);
	if (!request->coa) return NULL;

	request->coa->options = RAD_REQUEST_OPTION_COA;	/* is a CoA packet */
	request->coa->packet->code = 0; /* unknown, as of yet */
	request->coa->child_state = REQUEST_RUNNING;
	request->coa->proxy = rad_alloc(request->coa, false);
	if (!request->coa->proxy) {
		TALLOC_FREE(request->coa);
		return NULL;
	}

	return request->coa;
}
#endif

/*
 *	Add opaque data (with a "free" function) to a REQUEST.
 *
 *	The unique ptr is meant to be a module configuration,
 *	and the unique integer allows the caller to have multiple
 *	opaque data associated with a REQUEST.
 */
int request_data_add(REQUEST *request, void *unique_ptr, int unique_int, void *opaque,
		     bool free_opaque, bool persist)
{
	request_data_t *this, **last, *next;

	/*
	 *	Request must have a state ctx
	 */
	rad_assert(!persist || request->state_ctx);

	/*
	 *	Some simple sanity checks.
	 */
	if (!request || !opaque) return -1;

	this = next = NULL;
	for (last = &(request->data); *last != NULL; last = &((*last)->next)) {
#ifdef WITH_VERIFY_PTR
		talloc_get_type_abort(*last, request_data_t);
#endif
		if (((*last)->unique_ptr == unique_ptr) && ((*last)->unique_int == unique_int)) {
			this = *last;
			next = this->next;

			/*
			 *	If caller requires custom behaviour on free
			 *	they must set a destructor.
			 */
			if (this->opaque && this->free_opaque) talloc_free(this->opaque);

			/*
			 *	Need a new one, this one's parent is wrong.
			 *	And no, we can't just steal.
			 */
			if (this->persist != persist) TALLOC_FREE(this);

			break;	/* replace the existing entry */
		}
		if (!*last) break;
	}

	/*
	 *	Only alloc new memory if we're not replacing
	 *	an existing entry.
	 *
	 *	Tie the lifecycle of the data to either the state_ctx
	 *	or the request, depending on whether it should
	 *	persist or not.
	 */
	if (!this) this = talloc_zero(persist ? request->state_ctx : request, request_data_t);
	if (!this) return -1;

	this->next = next;
	this->unique_ptr = unique_ptr;
	this->unique_int = unique_int;
	this->opaque = opaque;
	this->free_opaque = free_opaque;
	this->persist = persist;

	*last = this;

	return 0;
}

/** Get opaque data from a request
 *
 */
void *request_data_get(REQUEST *request, void *unique_ptr, int unique_int)
{
	request_data_t **last;

	if (!request) return NULL;

	for (last = &(request->data); *last != NULL; last = &((*last)->next)) {
#ifdef WITH_VERIFY_PTR
		talloc_get_type_abort(*last, request_data_t);
#endif
		if (((*last)->unique_ptr == unique_ptr) && ((*last)->unique_int == unique_int)) {
			request_data_t	*this;
			void		*ptr;

			this = *last;
			ptr = this->opaque;

			/*
			 *	Remove the entry from the list, and free it.
			 */
			*last = this->next;
			talloc_free(this);

			return ptr; 		/* don't free it, the caller does that */
		}
		if (!*last) break;
	}

	return NULL;		/* wasn't found, too bad... */
}

/** Loop over all the request data, pulling out ones matching persist
 *
 * @param[out] out Head of result list.
 * @param[in] request The current request.
 * @param[in] persist Whether to pull persistable or non-persistable data.
 */
void request_data_by_persistance(request_data_t **out, REQUEST *request, bool persist)
{
	request_data_t **last, *head = NULL, **next;

	next = &head;

	for (last = &(request->data); *last != NULL; last = &((*last)->next)) {
#ifdef WITH_VERIFY_PTR
		talloc_get_type_abort(*last, request_data_t);
#endif
		if ((*last)->persist == persist) {
			request_data_t	*this;

			/* Unlink it from the list */
			this = *last;
			*last = this->next;

			/* Add it to our list of data to return */
			this->next = NULL;
			*next = this;
			next = &this->next;
		}
		if (!*last) break;
	}

	*out = head;
}

/** Add request data back to a request
 *
 * @note May add multiple entries (if they're linked).
 * @note Will not check for duplicates.
 *
 * @param request to add data to.
 * @param entry the data to add.
 */
void request_data_restore(REQUEST *request, request_data_t *entry)
{
	request_data_t **last;

	/*
	 *	Wind to the end of the current request data
	 */
	for (last = &(request->data); *last != NULL; last = &((*last)->next)) if (!(*last)->next) break;
	*last = entry;

#ifdef WITH_VERIFY_PTR
	{
		request_data_t *this;

		for (this = request->data; this; this = this->next) talloc_get_type_abort(this, request_data_t);
	}
#endif
}

/*
 *	Get opaque data from a request without removing it.
 */
void *request_data_reference(REQUEST *request, void *unique_ptr, int unique_int)
{
	request_data_t **last;

	for (last = &(request->data); *last != NULL; last = &((*last)->next)) {
		if (((*last)->unique_ptr == unique_ptr) &&
		    ((*last)->unique_int == unique_int)) return (*last)->opaque;
	}

	return NULL;		/* wasn't found, too bad... */
}
