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
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/unlang/base.h>

static request_init_args_t	default_args;

static fr_dict_t const *dict_freeradius;

extern fr_dict_autoload_t request_dict[];
fr_dict_autoload_t request_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ NULL }
};

fr_dict_attr_t const *request_attr_root;
fr_dict_attr_t const *request_attr_request;
fr_dict_attr_t const *request_attr_reply;
fr_dict_attr_t const *request_attr_control;
fr_dict_attr_t const *request_attr_state;

extern fr_dict_attr_autoload_t request_dict_attr[];
fr_dict_attr_autoload_t request_dict_attr[] = {
	{ .out = &request_attr_root, .name = "root", .type = FR_TYPE_GROUP, .dict = &dict_freeradius },
	{ .out = &request_attr_request, .name = "request", .type = FR_TYPE_GROUP, .dict = &dict_freeradius },
	{ .out = &request_attr_reply, .name = "reply", .type = FR_TYPE_GROUP, .dict = &dict_freeradius },
	{ .out = &request_attr_control, .name = "control", .type = FR_TYPE_GROUP, .dict = &dict_freeradius },
	{ .out = &request_attr_state, .name = "session-state", .type = FR_TYPE_GROUP, .dict = &dict_freeradius },
	{ NULL }
};

/** The thread local free list
 *
 * Any entries remaining in the list will be freed when the thread is joined
 */
static _Thread_local fr_dlist_head_t *request_free_list; /* macro */

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
}

static inline void CC_HINT(always_inline) request_log_init_child(request_t *child, request_t const *parent)
{
	/*
	 *	Copy debug information.
	 */
	memcpy(&(child->log), &(parent->log), sizeof(child->log));
	child->log.unlang_indent = 0;	/* Apart from the indent which we reset */
	child->log.module_indent = 0;	/* Apart from the indent which we reset */
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
	child->name = talloc_typed_asprintf(child, "%s.%" PRIu64 , parent->name, child->number);
	child->seq_start = 0;	/* children always start with their own sequence */
	child->parent = parent;
	child->dict = parent->dict;
	child->config = parent->config;
	child->client = parent->client;

	/*
	 *	For new server support.
	 *
	 *	FIXME: Key instead off of a "virtual server" data structure.
	 *
	 *	FIXME: Permit different servers for inner && outer sessions?
	 */
	child->server_cs = parent->server_cs;

	child->packet = fr_radius_packet_alloc(child, true);
	if (!child->packet) {
		talloc_free(child);
		return -1;
	}

	child->reply = fr_radius_packet_alloc(child, false);
	if (!child->reply) {
		talloc_free(child);
		return -1;
	}

	/*
	 *	Fill in the child request.
	 */
	child->packet->socket = parent->packet->socket;
	child->packet->socket.inet.dst_port = 0;
	child->packet->socket.fd = -1;

	/*
	 *	This isn't STRICTLY required, as the child request MUST NEVER
	 *	be put into the request list.  However, it's still reasonable
	 *	practice.
	 */
	child->packet->id = child->number & 0xff;
	child->packet->code = parent->packet->code;
	child->packet->timestamp = parent->packet->timestamp;

	/*
	 *	Fill in the child reply, based on the child request.
	 */
	fr_socket_addr_swap(&child->reply->socket, &child->packet->socket);
	child->reply->id = child->packet->id;
	child->reply->code = 0; /* UNKNOWN code */
	child->reply->socket.fd = -1;

	return 0;
}

/** Setup logging and other fields for a request
 *
 * @param[in] file		the request was allocated in.
 * @param[in] line		the request was allocated on.
 * @param[in] request		to (re)-initialise.
 */
static inline CC_HINT(always_inline) int request_init(char const *file, int line,
						      request_t *request, request_init_args_t const *args)
{

	*request = (request_t){
#ifndef NDEBUG
		.magic = REQUEST_MAGIC,
#endif
		.request_state = REQUEST_INIT,
		.master_state = REQUEST_ACTIVE,
		.dict = args->namespace,
		.component = "<pre-core>",
		.runnable_id = -1,
		.time_order_id = -1,
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
		memcpy(&request->pair_list, &args->pair_list, sizeof(request->pair_list));

#define list_init(_ctx, _list) \
	do { \
		vp = fr_pair_afrom_da(_ctx, request_attr_##_list); \
		if (unlikely(!vp)) { \
			talloc_free(pair_root); \
			memset(&request->pair_list, 0, sizeof(request->pair_list)); \
			return -1; \
		} \
		fr_pair_add(&pair_root->children, vp); \
		request->pair_list._list = vp; \
	} while(0)

		if (!request->pair_list.request) list_init(request->pair_root, request);
		if (!request->pair_list.reply) list_init(request->pair_root, reply);
		if (!request->pair_list.control) list_init(request->pair_root, control);
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
	if (args->parent) {
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
	return 0;
}

/** Callback for freeing a request struct
 *
 * @param[in] request		to free or return to the free list.
 * @return
 *	- 0 in the request was freed.
 *	- -1 if the request was inserted into the free list.
 */
static int _request_free(request_t *request)
{
	fr_assert(!request->ev);

	/*
	 *	Reinsert into the free list if it's not already
	 *	in the free list.
	 *
	 *	If it *IS* already in the free list, then free it.
	 */
	if (unlikely(fr_dlist_entry_in_list(&request->free_entry))) {
		fr_dlist_entry_unlink(&request->free_entry);	/* Don't trust the list head to be available */
		goto really_free;
	}

	/*
	 *	We keep a buffer of <active> + N requests per
	 *	thread, to avoid spurious allocations.
	 */
	if (fr_dlist_num_elements(request_free_list) <= 256) {
		fr_dlist_head_t		*free_list;

		if (request->session_state_ctx) {
			fr_assert(talloc_parent(request->session_state_ctx) != request);	/* Should never be directly parented */
			talloc_free(request->session_state_ctx);	/* Not parented from the request */
		}
		free_list = request_free_list;

		/*
		 *	Reinitialise the request
		 */
		talloc_free_children(request);

		memset(request, 0, sizeof(*request));
		request->component = "free_list";

		/*
		 *	Reinsert into the free list
		 */
		fr_dlist_insert_head(free_list, request);
		request_free_list = free_list;

		return -1;	/* Prevent free */
 	}

	/*
	 *	Ensure anything that might reference the request is
	 *	freed before it is.
	 */
	talloc_free_children(request);

really_free:
	/*
	 *	state_ctx is parented separately.
	 */
	if (request->session_state_ctx) TALLOC_FREE(request->session_state_ctx);

#ifndef NDEBUG
	request->magic = 0x01020304;	/* set the request to be nonsense */
#endif

	return 0;
}

/** Free any free requests when the thread is joined
 *
 */
static void _request_free_list_free_on_exit(void *arg)
{
	fr_dlist_head_t *list = talloc_get_type_abort(arg, fr_dlist_head_t);
	request_t		*request;

	/*
	 *	See the destructor for why this works
	 */
	while ((request = fr_dlist_head(list))) talloc_free(request);
	talloc_free(list);
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
					   1 + 					/* Stack pool */
					   UNLANG_STACK_MAX + 			/* Stack Frames */
					   2 + 					/* packets */
					   10,					/* extra */
					   (UNLANG_FRAME_PRE_ALLOC * UNLANG_STACK_MAX) +	/* Stack memory */
					   (sizeof(fr_pair_t) * 5) +		/* pair lists and root*/
					   (sizeof(fr_radius_packet_t) * 2) +	/* packets */
					   128					/* extra */
					   ));
	fr_assert(ctx != request);

	return request;
}

/** Create a new request_t data structure
 *
 * @param[in] file	where the request was allocated.
 * @param[in] line	where the request was allocated.
 * @param[in] ctx	to bind the request to.
 * @param[in] args	Optional arguments.
 * @return
 *	- A request on success.
 *	- NULL on error.
 */
request_t *_request_alloc(char const *file, int line, TALLOC_CTX *ctx, request_init_args_t const *args)
{
	request_t		*request;
	fr_dlist_head_t		*free_list;

	if (!args) args = &default_args;

	/*
	 *	Setup the free list, or return the free
	 *	list for this thread.
	 */
	if (unlikely(!request_free_list)) {
		MEM(free_list = talloc(NULL, fr_dlist_head_t));
		fr_dlist_init(free_list, request_t, free_entry);
		fr_thread_local_set_destructor(request_free_list, _request_free_list_free_on_exit, free_list);
	} else {
		free_list = request_free_list;
	}

	request = fr_dlist_head(free_list);
	if (!request) {
		request = request_alloc_pool(ctx);
		talloc_set_destructor(request, _request_free);
	} else {
		/*
		 *	Remove from the free list, as we're
		 *	about to use it!
		 */
		fr_dlist_remove(free_list, request);
	}

	if (request_init(file, line, request, args) < 0) {
		talloc_free(request);
		return NULL;
	}

	/*
	 *	Initialise entry in free list
	 */
	fr_dlist_entry_init(&request->free_entry);	/* Needs to be initialised properly, else bad things happen */

	/*
	 *	Bind lifetime to a parent.
	 *
	 *	If the parent is freed the destructor
	 *	will fire, and return the request
	 *	to a "top level" free list.
	 */
	if (ctx) talloc_link_ctx(ctx, request);

	return request;
}

static int _request_local_free(request_t *request)
{
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
request_t *_request_local_alloc(char const *file, int line, TALLOC_CTX *ctx, request_init_args_t const *args)
{
	request_t *request;

	if (!args) args = &default_args;

	request = request_alloc_pool(ctx);
	if (request_init(file, line, request, args) < 0) return NULL;

	talloc_set_destructor(request, _request_local_free);

	return request;
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
	request_t		*request = child->parent;

	fr_assert(request != NULL);

	/*
	 *	Unlink the child from the parent.
	 */
	request_data_get(request, child, 0);

	child->parent = NULL;

	while (!request->backlog) {
		fr_assert(request->parent != NULL);
		request = request->parent;
	}

	child->backlog = request->backlog;

	return 0;
}

int request_global_init(void)
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

void request_global_free(void)
{
	fr_dict_autofree(request_dict);
}

#ifdef WITH_VERIFY_PTR
/*
 *	Verify a packet.
 */
static void packet_verify(char const *file, int line,
			  request_t const *request, fr_radius_packet_t const *packet, char const *type)
{
	TALLOC_CTX *parent;

	fr_fatal_assert_msg(packet, "CONSISTENCY CHECK FAILED %s[%i]: fr_radius_packet_t %s pointer was NULL",
			    file, line, type);

	parent = talloc_parent(packet);
	if (parent != request) {
		fr_log_talloc_report(packet);
		if (parent) fr_log_talloc_report(parent);


		fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%i]: Expected fr_radius_packet_t %s to be parented "
				     "by %p (%s), but parented by %p (%s)",
				     file, line, type, request, talloc_get_name(request),
				     parent, parent ? talloc_get_name(parent) : "NULL");
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

	fr_fatal_assert_msg(talloc_get_size(request) == sizeof(request_t),
			    "CONSISTENCY CHECK FAILED %s[%i]: expected request_t size of %zu bytes, got %zu bytes",
			    file, line, sizeof(request_t), talloc_get_size(request));

	(void)talloc_get_type_abort(request->request_ctx, fr_pair_t);
	fr_pair_list_verify(file, line, request->request_ctx, &request->request_pairs);
	(void)talloc_get_type_abort(request->reply_ctx, fr_pair_t);
	fr_pair_list_verify(file, line, request->reply_ctx, &request->reply_pairs);
	(void)talloc_get_type_abort(request->control_ctx, fr_pair_t);
	fr_pair_list_verify(file, line, request->control_ctx, &request->control_pairs);
	(void)talloc_get_type_abort(request->session_state_ctx, fr_pair_t);
	fr_assert_msg(talloc_parent(request->session_state_ctx) == NULL,
		      "session_state_ctx must not be parented by another chunk, but is parented by %s",
		      talloc_get_name(talloc_parent(request->session_state_ctx)));

	fr_pair_list_verify(file, line, request->session_state_ctx, &request->session_state_pairs);

	fr_assert(request->server_cs != NULL);

	if (request->packet) {
		packet_verify(file, line, request, request->packet, "request");
#if 0
		/*
		 *	@todo - a multi-protocol server shouldn't have
		 *	hard-coded RADIUS.
		 */
		if ((request->packet->code == FR_CODE_ACCESS_REQUEST) &&
		    (request->reply && !request->reply->code)) {
			fr_assert(request->session_state_ctx != NULL);
		}
#endif
	}
	if (request->reply) packet_verify(file, line, request, request->reply, "reply");

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
