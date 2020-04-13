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
 * @file src/lib/server/request_data.c
 *
 * @copyright 2019 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/server/request_data.h>

/** Per-request opaque data, added by modules
 *
 */
struct request_data_s {
	fr_dlist_t	list;			//!< Next opaque request data struct linked to this request.

	void const	*unique_ptr;		//!< Key to lookup request data.
	int		unique_int;		//!< Alternative key to lookup request data.
	char const	*type;			//!< Opaque type e.g. VALUE_PAIR, fr_dict_attr_t etc...
	void		*opaque;		//!< Opaque data.
	bool		free_on_replace;	//!< Whether to talloc_free(opaque) when the request data is removed.
	bool		free_on_parent;		//!< Whether to talloc_free(opaque) when the request is freed
	bool		persist;		//!< Whether this data should be transfered to a session_entry_t
						//!< after we're done processing this request.

#ifndef NDEBUG
	char const	*file;			//!< File where this request data was added.
	int		line;			//!< Line where this request data was added.
#endif
};

static char *request_data_description(TALLOC_CTX *ctx, request_data_t *rd)
{
		char *where;
		char *what;
		char *out;

		/*
		 *	Where was the request data added
		 */
#ifndef NDEBUG
		where = talloc_typed_asprintf(NULL, " added at %s:%i", rd->file, rd->line);
#else
		where = NULL;
#endif

		/*
		 *	What was added
		 */
		if (rd->type) {
			what = talloc_typed_asprintf(NULL, "%p (%s)", rd->opaque, rd->type);
		} else {
			what = talloc_typed_asprintf(NULL, "%p", rd->opaque);
		}

		out = talloc_typed_asprintf(ctx, "[0x%012"PRIxPTR":%i]%s %p, opaque %s%s",
					    (uintptr_t)rd->unique_ptr,
					    rd->unique_int,
					    rd->persist ? "[P]" : "",
					    rd,
					    what,
					    where ? where : "");
		talloc_free(what);
		talloc_free(where);

		return out;
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
	char *desc = NULL;

	/*
	 *	In the vast majority of cases the request data will
	 *	unlinked from its list before being freed.
	 *	But in case it's not, do this now.
	 *
	 *	This helps in a very specific case where there's a list
	 *	of request_data_t, and the state_ctx that the
	 *	request_data_t is parented off is freed without the
	 *	request_data_t being unlinked explicitly, but before
	 *	the request itself is freed something attempts to access
	 *	the request_data_t list, and runs into freed memory.
	 *
	 *	It's a similar pattern to structs removing themselves
	 *	from trees when they're freed, but with the added bonus
	 *	of never running into use after free errors/
	 */
	fr_dlist_entry_unlink(&rd->list);

	if (DEBUG_ENABLED4) desc = request_data_description(rd, rd);

	if (rd->free_on_parent && rd->opaque) {
		int	ret;

		DEBUG4("%s - freed with opaque data", desc);

		ret = talloc_free(rd->opaque);
		rd->opaque = NULL;

		return ret;
	}

	DEBUG4("%s - freed, but leaving opaque data", desc);

	return 0;
}

/** Allocate request data
 *
 * @param[in] ctx	to allocate request data in.
 * @return new request data.
 */
static inline request_data_t *request_data_alloc(TALLOC_CTX *ctx)
{
	request_data_t *rd;

	MEM(rd = talloc_zero(ctx, request_data_t));
	talloc_set_destructor(rd, _request_data_free);

	return rd;
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
 * @param[in] file		request data was added in.
 * @param[in] line		request data was added on.
 * @return
 *	- -2 on bad arguments.
 *	- -1 on memory allocation error.
 *	- 0 on success.
 */
int _request_data_add(REQUEST *request, void const *unique_ptr, int unique_int, char const *type, void *opaque,
		      bool free_on_replace, bool free_on_parent, bool persist,
#ifndef NDEBUG
		      char const *file, int line
#else
		      UNUSED char const *file, UNUSED int line
#endif
		      )
{
	request_data_t	*rd = NULL;

	/*
	 *	Request must have a state ctx
	 */
	fr_assert(request);
	fr_assert(!persist || request->state_ctx);
	fr_assert(!persist ||
		   (talloc_parent(opaque) == request->state_ctx) ||
		   (talloc_parent(opaque) == talloc_null_ctx()));
	fr_assert(!free_on_parent || (talloc_parent(opaque) != request));

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
			fr_assert(request->state_ctx);
			rd = request_data_alloc(request->state_ctx);
		} else {
			rd = request_data_alloc(request);
		}

	}
	if (!rd) return -1;

	rd->unique_ptr = unique_ptr;
	rd->unique_int = unique_int;
	rd->type = type;
	rd->opaque = opaque;
	rd->free_on_replace = free_on_replace;
	rd->free_on_parent = free_on_parent;
	rd->persist = persist;
#ifndef NDEBUG
	rd->file = file;
	rd->line = line;
#endif

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

/** Loop over all the request data, copying, then freeing ones matching persist state
 *
 * @param[in] ctx	To allocate new request_data_t.
 * @param[out] out	Head of result list. If NULL, data
 *			will be reparented in place.
 * @param[in] request	to search for request_data_t in.
 * @param[in] persist	Whether to pull persistable or non-persistable data.
 * @return number of request_data_t retrieved.
 */
int request_data_by_persistance_reparent(TALLOC_CTX *ctx, fr_dlist_head_t *out, REQUEST *request, bool persist)
{
	int			count = 0;
	request_data_t		*rd = NULL, *new, *prev;
	fr_dlist_head_t		head;

	fr_dlist_talloc_init(&head, request_data_t, list);

	while ((rd = fr_dlist_next(&request->data, rd))) {
		if (rd->persist != persist) continue;

		prev = fr_dlist_remove(&request->data, rd);

		new = request_data_alloc(ctx);
		memcpy(new, rd, sizeof(*new));

		/*
		 *	Clear the list pointers...
		 */
		memset(&new->list, 0, sizeof(new->list));
		rd->free_on_parent = false;
		talloc_free(rd);

		if (out) {
			fr_dlist_insert_tail(out, new);
		} else {
			fr_dlist_insert_tail(&head, new);
		}
		rd = prev;
	}

	if (!out) fr_dlist_move(&request->data, &head);

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


void request_data_list_dump(REQUEST *request, fr_dlist_head_t *head)
{
	request_data_t	*rd = NULL;
	int count = 0;

	if (fr_dlist_empty(head)) return;

	while ((rd = fr_dlist_next(head, rd))) {
		char *desc;

		desc = request_data_description(NULL, rd);
		ROPTIONAL(RDEBUG, DEBUG, "%s", desc);
		talloc_free(desc);
		count++;
	}
}

void request_data_dump(REQUEST *request)
{
	request_data_list_dump(request, &request->data);
}


/** Free any subrequest request data if the dlist head is freed
 *
 */
static int _free_child_data(fr_dlist_head_t *head)
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
 * @note #request_data_restore_to_child should have been called
 *	on the request before any request data is added to it,
 *	so that the state_ctx is set correctly.
 *
 * @param[in] request		The child request to retrieve state from.
 * @param[in] unique_ptr	A parent may have multiple subrequests spawned
 *				by different modules.  This identifies the module
 *      			or other facility that spawned the subrequest.
 * @param[in] unique_int	Further identification.
 * @return
 *	- 0 on success.
 *	- <0 on failure.
 */
int request_data_store_in_parent(REQUEST *request, void const *unique_ptr, int unique_int)
{
	fr_dlist_head_t	*child_list;

	if (!fr_cond_assert_msg((request->state_ctx == request->parent->state_ctx),
	    "Child's state_ctx (%p), differs from parent's (%p). "
	    "Unbalanced calls to request_data_restore_to_child/request_data_store_in_parent or "
	    "request_data_restore_to_child never called",
	    request->state_ctx, request->parent->state_ctx)) return -1;

	/*
	 *	Move child request data back into its
	 *	parent.
	 */
	if (request_data_by_persistance_count(request, true) > 0) {
		MEM(child_list = talloc_zero(request->parent->state_ctx, fr_dlist_head_t));
		fr_dlist_talloc_init(child_list, request_data_t, list);
		talloc_set_destructor(child_list, _free_child_data);

		/*
		 *	Pull everything out of the child,
		 *	add it to our temporary list head...
		 */
		request_data_by_persistance(child_list, request, true);

		/*
		 *	...and add the request_data from
		 *	the child back into the parent.
		 */
		request_data_talloc_add(request->parent, unique_ptr, unique_int,
					fr_dlist_head_t, child_list, true, false, true);
	}

	/*
	 *	Ensure request_data_restore_to_child
	 *      can be called again if it's actually
	 *	needed, by giving the child it's own
	 *      unique state_ctx again.
	 */
	MEM(request->state_ctx = talloc_init("session-state"));

	return 0;
}

/** Restore subrequest data from a parent request
 *
 * @param[in] request		The child request to restore state to.
 * @param[in] unique_ptr	A parent may have multiple subrequests spawned
 *				by different modules.  This identifies the module
 *      			or other facility that spawned the subrequest.
 * @param[in] unique_int	Further identification.
 * @return
 *	- 0 on success.
 *	- <0 on failure.
 */
int request_data_restore_to_child(REQUEST *request, void const *unique_ptr, int unique_int)
{
	fr_dlist_head_t *head;

	/*
	 *	All requests are alloced with a state_ctx.
	 *	In this case, nothing should be parented
	 *	off it already, so we can just free it.
	 */
	if (!fr_cond_assert_msg((talloc_get_size(request->state_ctx) == 0),
				"Child's state_ctx must contain no "
				"allocations when restoring data from a parent")) return -1;

	/*
	 *	If the parent and child state_ctxs are the
	 *	same, then it means this function has been
	 *	called before, without request_data_store_in_parent
	 *	being called afterwards.
	 */
	if (!fr_cond_assert_msg((request->state_ctx != request->parent->state_ctx),
				"Child's state_ctx must not be equal to its parent's state_ctx.  "
	    			"Unbalanced calls to request_data_restore_to_child/request_data_store_in_parent"))
	    			return -1;

	/*
	 *	Destroy the child's state_ctx and have it
	 *	use its parent's.
	 */
	TALLOC_FREE(request->state_ctx);
	request->state_ctx = request->parent->state_ctx;	/* Use top level state ctx */

	head = request_data_get(request->parent, unique_ptr, unique_int);
	if (!head) return 0;

	request_data_restore(request, head);
	talloc_free(head);

	return 0;
}

#ifdef WITH_VERIFY_PTR
bool request_data_persistable(request_data_t *rd)
{
	return rd->persist;
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
