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

#include <freeradius-devel/server/request.h>
#include <freeradius-devel/server/request_data.h>
#include <freeradius-devel/unlang/interpret.h>

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/atexit.h>

static fr_dict_t const *dict_freeradius;

extern fr_dict_autoload_t request_dict[];
fr_dict_autoload_t request_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	DICT_AUTOLOAD_TERMINATOR
};

fr_dict_attr_t const *request_attr_root;
fr_dict_attr_t const *request_attr_request;
fr_dict_attr_t const *request_attr_reply;
fr_dict_attr_t const *request_attr_control;
fr_dict_attr_t const *request_attr_state;
fr_dict_attr_t const *request_attr_local;

extern fr_dict_attr_autoload_t request_dict_attr[];
fr_dict_attr_autoload_t request_dict_attr[] = {
	{ .out = &request_attr_root, .name = "root", .type = FR_TYPE_GROUP, .dict = &dict_freeradius },
	{ .out = &request_attr_request, .name = "request", .type = FR_TYPE_GROUP, .dict = &dict_freeradius },
	{ .out = &request_attr_reply, .name = "reply", .type = FR_TYPE_GROUP, .dict = &dict_freeradius },
	{ .out = &request_attr_control, .name = "control", .type = FR_TYPE_GROUP, .dict = &dict_freeradius },
	{ .out = &request_attr_state, .name = "session-state", .type = FR_TYPE_GROUP, .dict = &dict_freeradius },
	{ .out = &request_attr_local, .name = "local-variables", .type = FR_TYPE_GROUP, .dict = &dict_freeradius },
	DICT_AUTOLOAD_TERMINATOR
};

#ifndef NDEBUG
static int _state_ctx_free(fr_pair_t *state)
{
	DEBUG4("state-ctx %p freed", state);

	return 0;
}
#endif

static inline void CC_HINT(always_inline) request_log_init_orphan(request_t *request)
{
	/*
	 *	These may be changed later by request_pre_handler
	 */
	request->log.lvl = fr_debug_lvl;	/* Default to global debug level */
	if (!request->log.dst) {
		request->log.dst = talloc_zero(request, log_dst_t);
	} else {
		memset(request->log.dst, 0, sizeof(*request->log.dst));
	}
	request->log.dst->func = vlog_request;
	request->log.dst->uctx = &default_log;
	request->log.dst->lvl = fr_debug_lvl;
}

/** Prepend another logging destination to the list.
 *

 * @param request	the request
 * @param log_dst	the logging destination
 * @param lvl		the new request debug lvl
 */
void request_log_prepend(request_t *request, fr_log_t *log_dst, fr_log_lvl_t lvl)
{
	log_dst_t *dst;

	if (lvl == L_DBG_LVL_DISABLE) {
		while (request->log.dst) {
			dst = request->log.dst->next;
			talloc_free(request->log.dst);
			request->log.dst = dst;
		}
		request->log.lvl = L_DBG_LVL_OFF;
		return;
	}

	/*
	 *	Remove a particular log destination.
	 */
	if (lvl == L_DBG_LVL_OFF) {
		log_dst_t **last;

		last = &request->log.dst;
		while (*last) {
			dst = *last;
			if (((fr_log_t *)dst->uctx)->parent == log_dst) {
				*last = dst->next;
				talloc_free(dst);
				if (!request->log.dst) request->log.lvl = L_DBG_LVL_OFF;
				return;
			}

			last = &(dst->next);
		}

		return;
	}

	/*
	 *	Change the debug level of an existing destination.
	 */
	for (dst = request->log.dst; dst != NULL; dst = dst->next) {
		if (((fr_log_t *)dst->uctx)->parent == log_dst) {
			dst->lvl = lvl;
			if (lvl > request->log.lvl) request->log.lvl = lvl;
			return;
		}
	}

	/*
	 *	Not found, add a new log destination.
	 */
	MEM(dst = talloc_zero(request, log_dst_t));

	dst->func = vlog_request;
	dst->uctx = log_dst;

	dst->lvl = lvl;
	if (lvl > request->log.lvl) request->log.lvl = lvl;
	dst->next = request->log.dst;

	request->log.dst = dst;
}

static inline void CC_HINT(always_inline) request_log_init_child(request_t *child, request_t const *parent)
{
	/*
	 *	Copy debug information.
	 */
	memcpy(&(child->log), &(parent->log), sizeof(child->log));
	child->log.indent.unlang = 0;	/* Apart from the indent which we reset */
	child->log.indent.module = 0;	/* Apart from the indent which we reset */
	child->log.lvl = parent->log.lvl;
}

static inline void CC_HINT(always_inline) request_log_init_detachable(request_t *child, request_t const *parent)
{
	request_log_init_child(child, parent);

	/*
	 *	Ensure that we use our own version of the logging
	 *	information, and not the original request one.
	 */
	child->log.dst = talloc_zero(child, log_dst_t);
	memcpy(child->log.dst, parent->log.dst, sizeof(*child->log.dst));
}

static inline CC_HINT(always_inline) int request_detachable_init(request_t *child, request_t *parent)
{
	/*
	 *	Associate the child with the parent, using the child's
	 *	pointer as a unique identifier.  Free it if the parent
	 *	goes away, but don't persist it across
	 *	challenge-response boundaries.
	 */
	if (request_data_talloc_add(parent, child, 0, request_t, child, true, true, false) < 0) return -1;

	return 0;
}

static inline CC_HINT(always_inline) int request_child_init(request_t *child, request_t *parent)
{
	child->number = parent->child_number++;
	if (!child->proto_dict) {
		child->proto_dict = parent->proto_dict;
		child->local_dict = parent->proto_dict;
	}

	if ((parent->seq_start == 0) || (parent->number == parent->seq_start)) {
		child->name = talloc_typed_asprintf(child, "%s.%" PRIu64, parent->name, child->number);
	} else {
		child->name = talloc_typed_asprintf(child, "(%s,%" PRIu64 ").%" PRIu64,
						   parent->name, parent->seq_start, child->number);
	}
	child->seq_start = 0;	/* children always start with their own sequence */
	child->parent = parent;

	/*
	 *	For new server support.
	 *
	 *	FIXME: Key instead off of a "virtual server" data structure.
	 *
	 *	FIXME: Permit different servers for inner && outer sessions?
	 */
	child->packet = fr_packet_alloc(child, true);
	if (!child->packet) {
		talloc_free(child);
		return -1;
	}

	child->reply = fr_packet_alloc(child, false);
	if (!child->reply) {
		talloc_free(child);
		return -1;
	}

	return 0;
}

/** Setup logging and other fields for a request
 *
 * @param[in] file		the request was allocated in.
 * @param[in] line		the request was allocated on.
 * @param[in] request		to (re)-initialise.
 * @param[in] type		of request to initialise.
 * @param[in] args		Other optional arguments.
 */
int _request_init(char const *file, int line,
		  request_t *request, request_type_t type,
		  request_init_args_t const *args)
{
	fr_dict_t const *dict;

	/*
	 *	Sanity checks for different requests types
	 */
	switch (type) {
	case REQUEST_TYPE_EXTERNAL:
		fr_assert(args);

		if (!fr_cond_assert_msg(!args->parent, "External requests must NOT have a parent")) return -1;

		fr_assert(args->namespace);

		dict = args->namespace;
		break;

	case REQUEST_TYPE_INTERNAL:
		if (!args || !args->namespace) {
			dict = fr_dict_internal();
		} else {
			dict = args->namespace;
		}
		break;

	case REQUEST_TYPE_DETACHED:
		fr_assert_fail("Detached requests should start as type == REQUEST_TYPE_INTERNAL, "
			       "args->detachable and be detached later");
		return -1;

	/* Quiet GCC */
	default:
		fr_assert_fail("Invalid request type");
		return -1;
	}

	*request = (request_t){
#ifndef NDEBUG
		.magic = REQUEST_MAGIC,
#endif
		.type = type,
		.master_state = REQUEST_ACTIVE,
		.proto_dict = fr_dict_proto_dict(dict),
		.local_dict = dict,
		.component = "<pre-core>",
		.flags = {
			.detachable = args && args->detachable,
		},
		.alloc_file = file,
		.alloc_line = line
	};


	/*
	 *	Initialise the stack
	 */
	MEM(request->stack = unlang_interpret_stack_alloc(request));

	/*
	 *	Initialise the request data list
	 */
	request_data_list_init(&request->data);

	{
		fr_pair_t *vp = NULL, *pair_root;

		/*
		 *	Alloc the pair root this is a
		 *	special pair which does not
		 *	free its children when it is
		 *	freed.
		 */
		pair_root = fr_pair_root_afrom_da(request, request_attr_root);
		if (unlikely(!pair_root)) return -1;
		request->pair_root = pair_root;

		/*
		 *	Copy all the pair lists over into
		 *	the request.  We then check for
		 *	the any uninitialised lists and
		 *	create them locally.
		 */
		if (args) memcpy(&request->pair_list, &args->pair_list, sizeof(request->pair_list));

#define list_init(_ctx, _list) \
	do { \
		vp = fr_pair_afrom_da(_ctx, request_attr_##_list); \
		if (unlikely(!vp)) { \
			talloc_free(pair_root); \
			memset(&request->pair_list, 0, sizeof(request->pair_list)); \
			return -1; \
		} \
		fr_pair_append(&pair_root->children, vp); \
		request->pair_list._list = vp; \
	} while(0)

		if (!request->pair_list.request) list_init(request->pair_root, request);
		if (!request->pair_list.reply) list_init(request->pair_root, reply);
		if (!request->pair_list.control) list_init(request->pair_root, control);
		if (!request->pair_list.local) list_init(request->pair_root, local);
		if (!request->pair_list.state) {
			list_init(NULL, state);
#ifndef NDEBUG
			talloc_set_destructor(request->pair_list.state, _state_ctx_free);
#endif
		}
	}

	/*
	 *	Initialise packets and additional
	 *	fields if this is going to be a
	 *	child request.
	 */
	if (args && args->parent) {
		if (request_child_init(request, args->parent) < 0) return -1;

		if (args->detachable) {
			if (request_detachable_init(request, args->parent) < 0) return -1;
			request_log_init_detachable(request, args->parent);
		} else {
			request_log_init_child(request, args->parent);
		}
	} else {
		request_log_init_orphan(request);
	}

	/*
	 *	This is only used by src/lib/io/worker.c
	 */
	fr_dlist_entry_init(&request->listen_entry);

	return 0;
}

/** Callback for slabs to deinitialise the request
 *
 * Does not need to be called for local requests.
 *
 * @param[in] request		deinitialise
 * @return
 *	- 0 in the request was deinitialised.
 *	- -1 if the request is in an unexpected state.
 */
int request_slab_deinit(request_t *request)
{
	fr_assert_msg(!fr_timer_armed(request->timeout),
		      "alloced %s:%i: %s still in the  timeout sublist",
		      request->alloc_file,
		      request->alloc_line,
		      request->name ? request->name : "(null)");
	fr_assert_msg(!fr_heap_entry_inserted(request->runnable),
		      "alloced %s:%i: %s still in the runnable heap ID %i",
		      request->alloc_file,
		      request->alloc_line,
		      request->name ? request->name : "(null)", request->runnable);

	RDEBUG3("Request deinitialising (%p)", request);

	/*
	 *	state_ctx is parented separately.
	 */
	if (request->session_state_ctx) TALLOC_FREE(request->session_state_ctx);

	/*
	 *	Zero out everything.
	 */
	memset(request, 0, sizeof(*request));

#ifndef NDEBUG
	request->component = "free_list";
	request->runnable = FR_HEAP_INDEX_INVALID;
	request->magic = 0x01020304;	/* set the request to be nonsense */
#endif

	return 0;
}

static inline CC_HINT(always_inline) request_t *request_alloc_pool(TALLOC_CTX *ctx)
{
	request_t *request;

	/*
	 *	Only allocate requests in the NULL
	 *	ctx.  There's no scenario where it's
	 *	appropriate to allocate them in a
	 *	pool, and using a strict talloc
	 *	hierarchy means that child requests
	 *	cannot be returned to a free list
	 *	and would have to be freed.
	 */
	MEM(request = talloc_pooled_object(ctx, request_t,
					   REQUEST_POOL_HEADERS,
					   REQUEST_POOL_SIZE));
	fr_assert(ctx != request);

	return request;
}

static int _request_local_free(request_t *request)
{
	RDEBUG4("Local request freed (%p)", request);

	/*
	 *	Ensure anything that might reference the request is
	 *	freed before it is.
	 */
	talloc_free_children(request);

	/*
	 *	state_ctx is parented separately.
	 *
	 *	The reason why it's OK to do this, is if the state attributes
	 *	need to persist across requests, they will already have been
	 *	moved to a fr_state_entry_t, with the state pointers in the
	 *	request being set to NULL, before the request is freed/
	 *
	 *	Note also that we do NOT call TALLOC_FREE(), which
	 *	sets state_ctx=NULL.  We don't control the order in
	 *	which talloc frees the children.  And the parents
	 *	state_ctx pointer needs to stick around so that all of
	 *	the children can check it.
	 *
	 *	If this assertion hits, it means that someone didn't
	 *	call fr_state_store_in_parent()
	 */
	if (request->session_state_ctx) {
		fr_assert(!request->parent || (request->session_state_ctx != request->parent->session_state_ctx));

		talloc_free(request->session_state_ctx);
	}

#ifndef NDEBUG
	request->magic = 0x01020304;	/* set the request to be nonsense */
#endif

	return 0;
}

/** Allocate a request that's not in the free list
 *
 * This can be useful if modules need a persistent request for their own purposes
 * which needs to be outside of the normal free list, so that it can be freed
 * when the module requires, not when the thread destructor runs.
 */
request_t *_request_local_alloc(char const *file, int line, TALLOC_CTX *ctx,
				request_type_t type, request_init_args_t const *args)
{
	request_t *request;

	request = request_alloc_pool(ctx);
	if (_request_init(file, line, request, type, args) < 0) return NULL;

	talloc_set_destructor(request, _request_local_free);

	return request;
}

/** Replace the session_state_ctx with a new one.
 *
 *  NOTHING should rewrite request->session_state_ctx.
 *
 *  It's now a pair, and is stored in request->pair_root.
 *  So it's wrong for anyone other than this function to play games with it.
 *
 * @param[in] request	to replace the state of.
 * @param[in] new_state	state to assign to the request.
 *			May be NULL in which case a new_state state will
 *			be alloced and assigned.
 *
 * @return the fr_pair_t containing the old state list.
 */
fr_pair_t *request_state_replace(request_t *request, fr_pair_t *new_state)
{
	fr_pair_t *old = request->session_state_ctx;

	fr_assert(request->session_state_ctx != NULL);
	fr_assert(request->session_state_ctx != new_state);

	fr_pair_remove(&request->pair_root->children, old);

	/*
	 *	Save (or delete) the existing state, and re-initialize
	 *	it with a brand new one.
	 */
	if (!new_state) MEM(new_state = fr_pair_afrom_da(NULL, request_attr_state));

	request->session_state_ctx = new_state;

	fr_pair_append(&request->pair_root->children, new_state);

	return old;
}

/** Unlink a subrequest from its parent
 *
 * @note This should be used for requests in preparation for freeing them.
 *
 * @param[in] child		request to unlink.
 * @return
 *	 - 0 on success.
 *	 - -1 on failure.
 */
int request_detach(request_t *child)
{
	request_t	*request = child->parent;

	/*
	 *	Already detached or not detachable
	 */
	if (request_is_detached(child)) return 0;

	if (!request_is_detachable(child)) {
		fr_strerror_const("Request is not detachable");
		return -1;
	}

	/*
	 *	Unlink the child from the parent.
	 */
	request_data_get(request, child, 0);

	child->parent = NULL;

	/*
	 *	Request is now detached
	 */
	child->type = REQUEST_TYPE_DETACHED;

	/*
	 *	...and is no longer detachable.
	 */
	child->flags.detachable = 0;

	return 0;
}

static int _request_global_free(UNUSED void *uctx)
{
	fr_dict_autofree(request_dict);
	return 0;
}

static int _request_global_init(UNUSED void *uctx)
{
	if (fr_dict_autoload(request_dict) < 0) {
		PERROR("%s", __FUNCTION__);
		return -1;
	}
	if (fr_dict_attr_autoload(request_dict_attr) < 0) {
		PERROR("%s", __FUNCTION__);
		fr_dict_autofree(request_dict);
		return -1;
	}
	return 0;
}

int request_global_init(void)
{
	int ret;
	fr_atexit_global_once_ret(&ret, _request_global_init, _request_global_free, NULL);
	return ret;
}

#ifdef WITH_VERIFY_PTR
/*
 *	Verify a packet.
 */
static void packet_verify(char const *file, int line,
			  request_t const *request, fr_packet_t const *packet, fr_pair_list_t *list, char const *type)
{
	TALLOC_CTX *parent;

	fr_fatal_assert_msg(packet, "CONSISTENCY CHECK FAILED %s[%i]: fr_packet_t %s pointer was NULL",
			    file, line, type);

	parent = talloc_parent(packet);
	if (parent != request) {
		fr_log_talloc_report(packet);
		if (parent) fr_log_talloc_report(parent);


		fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%i]: Expected fr_packet_t %s to be parented "
				     "by %p (%s), but parented by %p (%s)",
				     file, line, type, request, talloc_get_name(request),
				     parent, parent ? talloc_get_name(parent) : "NULL");
	}

	/*
	 *	Enforce nesting at the top level.  This catches minor programming bugs in the server core.
	 *
	 *	If we care more, we could do these checks recursively.  But the tmpl_tokenize code already
	 *	enforces parent / child namespaces.  So the end user shouldn't be able to break the parenting.
	 *
	 *	This code really only checks for programming bugs where the C code creates a pair, and then
	 *	adds it to the wrong list.  This was happening during the transition from flat to nested, as
	 *	the code was in the middle of being fixed.  It should only happen now if the programmer
	 *	forgets, and uses the wrong APIs.
	 */
	fr_pair_list_foreach(list, vp) {
		if (vp->da->flags.is_raw) continue;

		if (vp->da->flags.internal) continue;

		if (vp->da->depth > 1) {
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%i]: Expected fr_pair_t %s to be parented "
				     "by (%s), but it is instead at the top-level %s list",
					     file, line, vp->da->name, vp->da->parent->name, type);
		}
	}

	PACKET_VERIFY(packet);
}

/*
 *	Catch horrible talloc errors.
 */
void request_verify(char const *file, int line, request_t const *request)
{
	request_data_t *rd = NULL;

	fr_fatal_assert_msg(request, "CONSISTENCY CHECK FAILED %s[%i]: request_t pointer was NULL", file, line);

	(void) talloc_get_type_abort_const(request, request_t);

	fr_assert(request->magic == REQUEST_MAGIC);

	(void)talloc_get_type_abort(request->request_ctx, fr_pair_t);
	fr_pair_list_verify(file, line, request->request_ctx, &request->request_pairs, true);
	(void)talloc_get_type_abort(request->reply_ctx, fr_pair_t);
	fr_pair_list_verify(file, line, request->reply_ctx, &request->reply_pairs, true);
	(void)talloc_get_type_abort(request->control_ctx, fr_pair_t);
	fr_pair_list_verify(file, line, request->control_ctx, &request->control_pairs, true);
	(void)talloc_get_type_abort(request->session_state_ctx, fr_pair_t);

#ifndef NDEBUG
	{
		TALLOC_CTX *parent = talloc_parent(request->session_state_ctx);

		fr_assert_msg((parent == NULL) || (parent == talloc_null_ctx()),
			      "session_state_ctx must not be parented by another chunk, but is parented by %s",
			      talloc_get_name(talloc_parent(request->session_state_ctx)));
	}
#endif

	fr_pair_list_verify(file, line, request->session_state_ctx, &request->session_state_pairs, true);
	fr_pair_list_verify(file, line, request->local_ctx, &request->local_pairs, true);

	fr_assert(request->proto_dict != NULL);
	fr_assert(request->local_dict != NULL);

	if (request->packet) {
		packet_verify(file, line, request, request->packet, &request->request_pairs, "request");
	}
	if (request->reply) {
		packet_verify(file, line, request, request->reply, &request->reply_pairs, "reply");
	}

	if (request->async) {
		(void) talloc_get_type_abort(request->async, fr_async_t);
		fr_assert(talloc_parent(request->async) == request);
	}

	while ((rd = fr_dlist_next(&request->data, rd))) {
		(void) talloc_get_type_abort(rd, request_data_t);

		if (request_data_persistable(rd)) {
			fr_assert(request->session_state_ctx);
			fr_assert(talloc_parent(rd) == request->session_state_ctx);
		} else {
			fr_assert(talloc_parent(rd) == request);
		}
	}
}
#endif
