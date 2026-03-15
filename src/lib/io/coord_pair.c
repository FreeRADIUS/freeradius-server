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
 * @brief Sending pair lists to and from coordination threads
 * @file io/coord_pair.c
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/internal/internal.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/io/coord_pair.h>
#include <freeradius-devel/io/coord_priv.h>
#include <freeradius-devel/server/main_config.h>
#include <freeradius-devel/util/dlist.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/unlang/call.h>
#include <freeradius-devel/unlang/interpret.h>

static _Atomic(uint64_t) request_number = 0;

FR_SLAB_TYPES(request, request_t)
FR_SLAB_FUNCS(request, request_t)

static fr_dlist_head_t	*coord_pair_regs = NULL;
static module_list_t	*coord_pair_modules;
static fr_dict_attr_t const	*attr_worker_id = NULL;

/** Registration of pair list callbacks
 *
 */
struct fr_coord_pair_reg_s {
	fr_dlist_t			entry;			//!< Entry in list of pair list registrations
	fr_dict_attr_t const 		*attr_packet_type;	//!< Attribute containing packet type
	fr_dict_attr_t const		*root;			//!< Pair list decoding root attribute
	fr_coord_worker_pair_cb_reg_t	**callbacks;		//!< Array of pointers to callbacks
	uint32_t			max_packet_type;	//!< Largest valid value for packet type
	uint32_t			cb_id;			//!< The coordinator callback ID used for pair list handling
	fr_time_delta_t			max_request_time;	//!< Maximum time for coordinator request processing.
	fr_slab_config_t		reuse;			//!< Request slab allocation config.
	virtual_server_t const		*vs;			//!< Virtual server containing coordinator process sections.
};

struct fr_coord_pair_s {
	fr_coord_t			*coord;			//!< Coordinator which this coord pair is attached to.
	fr_coord_pair_reg_t		*coord_pair_reg;	//!< Registration details for this coord pair
	fr_event_list_t			*el;			//!< Event list for interpreter.
	unlang_interpret_t		*intp;			//!< Interpreter for running requests.
	fr_heap_t			*runnable;		//!< Current runnable requests.

	fr_timer_list_t			*timeout;		//!< Track when requests timeout using a dlist.
	fr_time_delta_t			predicted;		//!< How long we predict a request will take to execute.
	fr_time_tracking_t		tracking;		//!< How much time the coordinator has spent doing things.
	uint64_t			num_active;		//!< Number of active requests.
	request_slab_list_t		*slab;			//!< slab allocator for request_t
};

/** Packet context used when coordinator messages are processed through an interpreter
 *
 * Allows access to the coordinator structure and arbitrary data
 * throughout the state machine.
 */
typedef struct {
	fr_coord_pair_t			*coord_pair;		//!< Coordinator pair this packet is for.
	void				*uctx;			//!< Source specific ctx.
} fr_coord_packet_ctx_t;

/** Conf parser to read slab settings from module config
 */
static const conf_parser_t request_reuse_config[] = {
	FR_SLAB_CONFIG_CONF_PARSER
	CONF_PARSER_TERMINATOR
};

/** Remove a coord pair registration from the list when it is freed
 */
static int _coord_pair_reg_free(fr_coord_pair_reg_t *to_free)
{
	fr_assert(coord_pair_regs);

	fr_dlist_remove(coord_pair_regs, to_free);

	/* If all the registrations are gone, free the list */
	if (fr_dlist_num_elements(coord_pair_regs) == 0) {
		TALLOC_FREE(coord_pair_regs);
		TALLOC_FREE(coord_pair_modules);
	}
	return 0;
}

/** Register a set of callbacks for pair list based coordinator messages
 *
 * Returns a structure to pass as uctx to fr_coord_cb_t using the
 * macro FR_COORD_PAIR_CB_CTX_SET.
 *
 * @param ctx		to allocate the registration under.
 * @param reg_ctx	Callback details to register.
 */
fr_coord_pair_reg_t *fr_coord_pair_register(TALLOC_CTX *ctx, fr_coord_pair_reg_ctx_t *reg_ctx)
{
	fr_coord_pair_reg_t		*coord_pair_reg;
	fr_coord_worker_pair_cb_reg_t	*cb_reg = reg_ctx->worker_cb;
	CONF_SECTION			*cs;
	CONF_PAIR			*cp;

	fr_assert(reg_ctx->root);

	/* Resolve the Worker-Id attribute if not already done */
	if (!attr_worker_id) {
		attr_worker_id = fr_dict_attr_by_name(NULL, fr_dict_root(fr_dict_internal()), "Worker-Id");
		if (!attr_worker_id) {
			ERROR("Failed to resolve Worker-Id attribute");
			return NULL;
		}
	}

	if (!coord_pair_regs) {
		MEM(coord_pair_regs = talloc_zero(NULL, fr_dlist_head_t));
		fr_dlist_init(coord_pair_regs, fr_coord_pair_reg_t, entry);
		MEM(coord_pair_modules = module_list_alloc(NULL, &module_list_type_global, "coord", true));
	}

	MEM(coord_pair_reg = talloc(ctx, fr_coord_pair_reg_t));
	*coord_pair_reg = (fr_coord_pair_reg_t) {
		.root = reg_ctx->root,
		.cb_id = reg_ctx->cb_id,
		.max_request_time = fr_time_delta_eq(reg_ctx->max_request_time, fr_time_delta_from_msec(0)) ?
			main_config->worker.max_request_time : reg_ctx->max_request_time,
	};

	while (cb_reg->callback) {
		if (cb_reg->packet_type > coord_pair_reg->max_packet_type) {
			coord_pair_reg->max_packet_type = cb_reg->packet_type;
		}
		cb_reg++;
	}

	/*
	 *	A sane limit on packet type values to avoid a huge array.
	 *	If larger values are needed in the future we can use a folded array.
	 */
	fr_assert(coord_pair_reg->max_packet_type <= 256);

	MEM(coord_pair_reg->callbacks = talloc_zero_array(coord_pair_reg, fr_coord_worker_pair_cb_reg_t *,
							  coord_pair_reg->max_packet_type + 1));

	cb_reg = reg_ctx->worker_cb;
	while (cb_reg->callback) {
		coord_pair_reg->callbacks[cb_reg->packet_type] = cb_reg;
		cb_reg++;
	}

	cs = cf_section_find(reg_ctx->cs, "reuse", NULL);

	/*
	 *	Create an empty "reuse" section if one is not found, so defaults are applied
	 */
	if (!cs) {
		cs = cf_section_alloc(reg_ctx->cs, reg_ctx->cs, "reuse", NULL);
	}

	if (cf_section_rules_push(cs, request_reuse_config) < 0) {
	fail:
		talloc_free(coord_pair_reg);
		return NULL;
	}
	if (cf_section_parse(coord_pair_reg, &coord_pair_reg->reuse, cs) < 0) goto fail;

	/*
	 *	Set defaults for request slab allocation, if not set by conf parsing
	 */
	if (coord_pair_reg->reuse.child_pool_size == 0) coord_pair_reg->reuse.child_pool_size = REQUEST_POOL_SIZE;
	if (coord_pair_reg->reuse.num_children == 0) coord_pair_reg->reuse.num_children = REQUEST_POOL_HEADERS;

	cp = cf_pair_find(reg_ctx->cs, "virtual_server");
	if (!cp) {
		cf_log_err(reg_ctx->cs, "Missing virtual_server option");
		goto fail;
	}

	coord_pair_reg->vs = virtual_server_find(cf_pair_value(cp));
	if (!coord_pair_reg->vs) {
		cf_log_err(cp, "Virtual server not found");
		goto fail;
	}

	/*
	 *	Validate that the virtual server uses the correct namespace.
	 */
	if (reg_ctx->root->dict != virtual_server_dict_by_cs(virtual_server_cs(coord_pair_reg->vs))) {
		cf_log_err(cp, "Virtual server has namespace %s, should be %s",
			   fr_dict_root(virtual_server_dict_by_cs(virtual_server_cs(coord_pair_reg->vs)))->name,
			   fr_dict_root(coord_pair_reg->root->dict)->name);
		goto fail;
	}
	coord_pair_reg->attr_packet_type = virtual_server_packet_type_by_cs(virtual_server_cs(coord_pair_reg->vs));

	fr_dlist_insert_tail(coord_pair_regs, coord_pair_reg);
	talloc_set_destructor(coord_pair_reg, _coord_pair_reg_free);

	return coord_pair_reg;
}

/** Return the coordinator callback ID associated with a coord_pair_reg_t
 */
uint32_t fr_coord_pair_reg_cb_id(fr_coord_pair_reg_t *coord_pair_reg)
{
	fr_assert(coord_pair_reg);
	return coord_pair_reg->cb_id;
}

/*
 *	The following set of callbacks for request handling are mirrors of
 *	their equivalent in worker.c
 */

/** Signal the unlang interpreter that it needs to stop running the request
 *
 * @param[in] request	request to cancel.  The request may still run to completion.
 */
static void coord_pair_stop_request(request_t *request)
{
	unlang_interpret_signal(request, FR_SIGNAL_CANCEL);
}

/** Enforce max_request_time
 *
 * @param[in] tl	the coordinators's timer list.
 * @param[in] when	the current time
 * @param[in] uctx	the request_t timing out.
 */
static void _coord_pair_request_timeout(UNUSED fr_timer_list_t *tl, UNUSED fr_time_t when, void *uctx)
{
	request_t	*request = talloc_get_type_abort(uctx, request_t);

	REDEBUG("Request has reached max_request_time - signalling it to stop");
	coord_pair_stop_request(request);

	request->rcode = RLM_MODULE_TIMEOUT;
}

/** Set, or re-set the request timer
 *
 * @param[in] coord_pair	the coord_pair_t containing the timeout lists.
 * @param[in] request		that we're timing out.
 * @param[in] timeout		the timeout to set.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int fr_coord_pair_request_timeout_set(fr_coord_pair_t *coord_pair, request_t *request, fr_time_delta_t timeout)
{
	if (unlikely(fr_timer_in(request, coord_pair->timeout, &request->timeout, timeout,
				 true, _coord_pair_request_timeout, request) < 0)) {
		RERROR("Failed to create request timeout timer");
		return -1;
	}

	return 0;
}

/** Start time tracking for a request, and mark it as runnable.
 */
static int coord_pair_request_time_tracking_start(fr_coord_pair_t *coord_pair, request_t *request, fr_time_t now)
{
	fr_assert(!fr_timer_armed(request->timeout));

	if (unlikely(fr_coord_pair_request_timeout_set(coord_pair, request,
						       coord_pair->coord_pair_reg->max_request_time) < 0)) {
		RERROR("Failed to set request timeout");
		return -1;
	}

	RDEBUG3("Time tracking started in yielded state");
	fr_time_tracking_start(&coord_pair->tracking, &request->async->tracking, now);
	fr_time_tracking_yield(&request->async->tracking, now);
	coord_pair->num_active++;

	fr_assert(!fr_heap_entry_inserted(request->runnable));
	(void) fr_heap_insert(&coord_pair->runnable, request);

	return 0;
}

/** End time tracking for a request
 */
static void coord_pair_request_time_tracking_end(fr_coord_pair_t *coord_pair, request_t *request, fr_time_t now)
{
	RDEBUG3("Time tracking ended");
	fr_time_tracking_end(&coord_pair->predicted, &request->async->tracking, now);
	fr_assert(coord_pair->num_active > 0);
	coord_pair->num_active--;

	TALLOC_FREE(request->timeout);	/* Disarm the request timer */
}


static inline CC_HINT(always_inline)
void coord_pair_request_init(fr_event_list_t *el, request_t *request, fr_time_t now, void *packet_ctx)
{
	if (!request->packet) MEM(request->packet = fr_packet_alloc(request, false));
	if (!request->reply) MEM(request->reply = fr_packet_alloc(request, false));

	request->packet->timestamp = now;
	request->async = talloc_zero(request, fr_async_t);
	request->async->recv_time = now;
	request->async->el = el;
	request->async->packet_ctx = packet_ctx;
	fr_dlist_entry_init(&request->async->entry);
}

static inline CC_HINT(always_inline)
void coord_pair_request_name_number(request_t *request)
{
	request->number = atomic_fetch_add_explicit(&request_number, 1, memory_order_seq_cst);
	if (request->name) talloc_const_free(request->name);
	request->name = talloc_asprintf(request, "Coord-%"PRIu64, request->number);
}

static int _coord_pair_request_deinit( request_t *request, UNUSED void *uctx)
{
	return request_slab_deinit(request);
}

static void coord_pair_request_bootstrap(fr_coord_pair_t *coord_pair, uint32_t worker_id, fr_dbuff_t *dbuff,
					 fr_time_t now, void *uctx)
{
	request_t		*request;
	int			ret;
	fr_pair_t		*vp;
	fr_coord_packet_ctx_t	*packet_ctx;

	request = request_slab_reserve(coord_pair->slab);
	if (!request) {
		ERROR("Coordinator failed allocating new request");
		return;
	}

	request_slab_element_set_destructor(request, _coord_pair_request_deinit, coord_pair);

	if (request_init(request, REQUEST_TYPE_INTERNAL,
			 (&(request_init_args_t){
				.namespace = virtual_server_dict_by_cs(virtual_server_cs(coord_pair->coord_pair_reg->vs))
			 }))) {
		ERROR("Coordinator failed initializing new request");
	error:
		request_slab_release(request);
		return;
	}

	MEM(packet_ctx = talloc(request, fr_coord_packet_ctx_t));
	*packet_ctx = (fr_coord_packet_ctx_t) {
		.coord_pair = coord_pair,
		.uctx = uctx
	};
	coord_pair_request_init(coord_pair->el, request, now, packet_ctx);
	coord_pair_request_name_number(request);

	unlang_interpret_set(request, coord_pair->intp);

	if (fr_pair_append_by_da(request->request_ctx, &vp, &request->request_pairs, attr_worker_id) < 0) goto error;
	vp->vp_uint32 = worker_id;

	ret = fr_internal_decode_list_dbuff(request->pair_list.request, &request->request_pairs,
					   fr_dict_root(request->proto_dict), dbuff, NULL);
	if (ret < 0) {
		RERROR("Failed decoding packet");
		goto error;
	}

	vp = fr_pair_find_by_da(&request->request_pairs, NULL, coord_pair->coord_pair_reg->attr_packet_type);
	if (!vp) {
		RERROR("Missing %s attribute", coord_pair->coord_pair_reg->attr_packet_type->name);
		goto error;
	}

	request->packet->code = vp->vp_uint32;

	if (virtual_server_push(NULL, request, coord_pair->coord_pair_reg->vs, UNLANG_TOP_FRAME) < 0) {
		RERROR("Protocol failed to set 'process' function");
		goto error;
	}

	coord_pair_request_time_tracking_start(coord_pair, request, now);
}

static void _coord_pair_request_internal_init(request_t *request, void *uctx)
{
	fr_coord_pair_t	*coord_pair = talloc_get_type_abort(uctx, fr_coord_pair_t);
	fr_time_t	now = fr_time();

	fr_assert(request->packet);
	fr_assert(request->reply);

	request->packet->timestamp = now;
	request->async = talloc_zero(request, fr_async_t);
	request->async->recv_time = now;
	request->async->el = coord_pair->el;
	fr_dlist_entry_init(&request->async->entry);

	/*
	 *	Requests generated by the interpreter
	 *	are always marked up as internal.
	 */
	fr_assert(request_is_internal(request));
	coord_pair_request_time_tracking_start(coord_pair, request, now);
}

/** External request is now complete - will never happen with coordinators
 *
 */
static void _coord_pair_request_done_external(UNUSED request_t *request, UNUSED rlm_rcode_t rcode, UNUSED void *uctx)
{
	fr_assert(0);
}

/** Internal request (i.e. one generated by the interpreter) is now complete
 *
 * Whatever generated the request is now responsible for freeing it.
 */
static void _coord_pair_request_done_internal(request_t *request, UNUSED rlm_rcode_t rcode, void *uctx)
{
	fr_coord_pair_t	*coord_pair = talloc_get_type_abort(uctx, fr_coord_pair_t);

	coord_pair_request_time_tracking_end(coord_pair, request, fr_time());

	fr_assert(!fr_heap_entry_inserted(request->runnable));
	fr_assert(!fr_timer_armed(request->timeout));
	fr_assert(!fr_dlist_entry_in_list(&request->async->entry));
}

/** Detached request (i.e. one generated by the interpreter with no parent) is now complete
 *
 * As the request has no parent, then there's nothing to free it
 * so we have to.
 */
static void _coord_pair_request_done_detached(request_t *request, UNUSED rlm_rcode_t rcode, UNUSED void *uctx)
{
	fr_assert(!fr_heap_entry_inserted(request->runnable));

	TALLOC_FREE(request->timeout);

	fr_assert(!fr_dlist_entry_in_list(&request->async->entry));

	talloc_free(request);
}

/** Make us responsible for running the request
 *
 */
static void _coord_pair_request_detach(request_t *request, void *uctx)
{
	fr_coord_pair_t	*coord_pair = talloc_get_type_abort(uctx, fr_coord_pair_t);

	RDEBUG4("%s - Request detaching", __FUNCTION__);

	if (request_is_detachable(request)) {
		/*
		*	End the time tracking...  We don't track detached requests,
		*	because they don't contribute for the time consumed by an
		*	external request.
		*/
		if (request->async->tracking.state == FR_TIME_TRACKING_YIELDED) {
			RDEBUG3("Forcing time tracking to running state, from yielded, for request detach");
			fr_time_tracking_resume(&request->async->tracking, fr_time());
		}
		coord_pair_request_time_tracking_end(coord_pair, request, fr_time());

		if (request_detach(request) < 0) RPEDEBUG("Failed detaching request");

		RDEBUG3("Request is detached");
	} else {
		fr_assert_msg(0, "Request is not detachable");
	}
}

/** Request is now runnable
 *
 */
static void _coord_pair_request_runnable(request_t *request, void *uctx)
{
	fr_coord_pair_t	*coord_pair = uctx;

	RDEBUG4("%s - Request marked as runnable", __FUNCTION__);
	fr_heap_insert(&coord_pair->runnable, request);
}

/** Interpreter yielded request
 *
 */
static void _coord_pair_request_yield(request_t *request, UNUSED void *uctx)
{
	RDEBUG4("%s - Request yielded", __FUNCTION__);
	if (likely(!request_is_detached(request))) fr_time_tracking_yield(&request->async->tracking, fr_time());
}

/** Interpreter is starting to work on request again
 *
 */
static void _coord_pair_request_resume(request_t *request, UNUSED void *uctx)
{
	RDEBUG4("%s - Request resuming", __FUNCTION__);
	if (likely(!request_is_detached(request))) fr_time_tracking_resume(&request->async->tracking, fr_time());
}

/** Check if a request is scheduled
 *
 */
static bool _coord_pair_request_scheduled(request_t const *request, UNUSED void *uctx)
{
	return fr_heap_entry_inserted(request->runnable);
}

/** Update a request's priority
 *
 */
static void _coord_pair_request_prioritise(request_t *request, void *uctx)
{
	fr_coord_pair_t *coord_pair = talloc_get_type_abort(uctx, fr_coord_pair_t);

	RDEBUG4("%s - Request priority changed", __FUNCTION__);

	/* Extract the request from the runnable queue _if_ it's in the runnable queue */
	if (fr_heap_extract(&coord_pair->runnable, request) < 0) return;

	/* Reinsert it to re-evaluate its new priority */
	fr_heap_insert(&coord_pair->runnable, request);
}

/** Compare two requests by priority and sequence
 */
static int8_t coord_pair_runnable_cmp(void const *one, void const *two)
{
	request_t const	*a = one, *b = two;
	int ret;

	ret = CMP(b->priority, a->priority);
	if (ret != 0) return ret;

	return CMP(a->sequence, b->sequence);
}

/** Create the coord_pair coord instance data
 */
static fr_coord_pair_t *fr_coord_pair_create(TALLOC_CTX *ctx, fr_coord_t *coord, fr_event_list_t *el,
					     bool single_thread, void *uctx)
{
	fr_coord_pair_t		*coord_pair;
	fr_coord_pair_reg_t	*coord_pair_reg = talloc_get_type_abort(uctx, fr_coord_pair_reg_t);

	MEM(coord_pair = talloc(ctx, fr_coord_pair_t));
	*coord_pair = (fr_coord_pair_t) {
		.coord = coord,
		.coord_pair_reg = coord_pair_reg,
		.el = el
	};

	coord_pair->runnable = fr_heap_talloc_alloc(coord_pair, coord_pair_runnable_cmp, request_t, runnable, 0);
	if (!coord_pair->runnable) {
		fr_strerror_const("Failed creating runnable heap");
	fail:
		talloc_free(coord_pair);
		return NULL;
	}

	coord_pair->timeout = fr_timer_list_ordered_alloc(coord_pair, el->tl);
	if (!coord_pair->timeout) {
		fr_strerror_const("Failed creating timeouts list");
		goto fail;
	}

	coord_pair->intp = unlang_interpret_init(coord_pair, el,
					&(unlang_request_func_t){
						.init_internal = _coord_pair_request_internal_init,

						.done_external = _coord_pair_request_done_external,
						.done_internal = _coord_pair_request_done_internal,
						.done_detached = _coord_pair_request_done_detached,

						.detach = _coord_pair_request_detach,
						.yield = _coord_pair_request_yield,
						.resume = _coord_pair_request_resume,
						.mark_runnable = _coord_pair_request_runnable,

						.scheduled = _coord_pair_request_scheduled,
						.prioritise = _coord_pair_request_prioritise
					}, coord_pair);

	if (!coord_pair->intp) goto fail;

	if (!(coord_pair->slab = request_slab_list_alloc(coord_pair, el, &coord_pair_reg->reuse, NULL, NULL,
							 coord_pair, true, false))) {
		goto fail;
	}

	if (!single_thread) unlang_interpret_set_thread_default(coord_pair->intp);

	return coord_pair;
}

static inline CC_HINT(always_inline) void coord_run_request(fr_coord_pair_t *coord_pair, fr_time_t start)
{
	request_t	*request;
	fr_time_t	now;

	now = start;

	while (fr_time_delta_lt(fr_time_sub(now, start), fr_time_delta_from_msec(1)) &&
	((request = fr_heap_pop(&coord_pair->runnable)) != NULL)) {
		REQUEST_VERIFY(request);
		fr_assert(!fr_heap_entry_inserted(request->runnable));

		(void)unlang_interpret(request, UNLANG_REQUEST_RESUME);

		now = fr_time();
	}
}

/*
 *	Pre and post events used in single threaded mode
 */

static int fr_coord_pair_pre_event(UNUSED fr_time_t now, UNUSED fr_time_delta_t wake, void *uctx)
{
	fr_coord_pair_t *coord_pair = talloc_get_type_abort(uctx, fr_coord_pair_t);
	request_t *request;

	request = fr_heap_peek(coord_pair->runnable);
	return request ? 1 : 0;
}

static void fr_coord_pair_post_event(UNUSED fr_event_list_t *el, UNUSED fr_time_t now, void *uctx)
{
	fr_coord_pair_t *coord_pair = talloc_get_type_abort(uctx, fr_coord_pair_t);

	coord_run_request(coord_pair, fr_time());
}

/** Event callback in multi threaded mode
 */
static void fr_coord_pair_event(UNUSED fr_event_list_t *el, void *uctx)
{
	fr_coord_pair_t *coord_pair = talloc_get_type_abort(uctx, fr_coord_pair_t);

	coord_run_request(coord_pair, fr_time());
}

/** Callback run when a coordinator receives pair list data
 *
 * Converts the data into a request.
 */
void fr_coord_pair_data_recv(UNUSED fr_coord_t *coord, uint32_t worker_id, fr_dbuff_t *dbuff, fr_time_t now, void *inst, void *uctx)
{
	fr_coord_pair_reg_t	*coord_pair_reg = talloc_get_type_abort(uctx, fr_coord_pair_reg_t);
	fr_coord_pair_t		*coord_pair = talloc_get_type_abort(inst, fr_coord_pair_t);
	coord_pair_request_bootstrap(coord_pair, worker_id, dbuff, now, coord_pair_reg);

	return;
}

/** Callback run when a worker receives pair list data
 *
 * Finds the packet type attribute in the data and calls the callback
 * registered against the value of that attribute.
 *
 * @param cw	Worker which received the message.
 * @param dbuff	Data received.
 * @param now	Time the data is received.
 * @param uctx	The coord_pair registration.
 */
void fr_coord_worker_pair_data_recv(fr_coord_worker_t *cw, fr_dbuff_t *dbuff, fr_time_t now, void *uctx)
{
	fr_coord_pair_reg_t		*coord_pair_reg = talloc_get_type_abort(uctx, fr_coord_pair_reg_t);
	fr_pair_list_t			list;
	fr_pair_t			*vp;

	fr_pair_list_init(&list);
	if (fr_internal_decode_list_dbuff(NULL, &list, coord_pair_reg->root, dbuff, NULL) < 0) {
		PERROR("Failed to decode data as pair list");
		goto free;
	}

	vp = fr_pair_find_by_da_nested(&list, NULL, coord_pair_reg->attr_packet_type);

	if (!vp) {
		ERROR("Message received without %s", coord_pair_reg->attr_packet_type->name);
		goto free;
	}

	if (vp->vp_uint32 > coord_pair_reg->max_packet_type || !coord_pair_reg->callbacks[vp->vp_uint32]) {
		ERROR("Message received with invalid value %pP", vp);
		goto free;
	}

	coord_pair_reg->callbacks[vp->vp_uint32]->callback(cw, coord_pair_reg, &list, now,
							   coord_pair_reg->callbacks[vp->vp_uint32]->uctx);

free:
	fr_pair_list_free(&list);
}

/** Send a reply list from a coordinator to a worker
 *
 * @param request	containing the reply to send.
 * @param worker_id	to send the reply to.
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int fr_coord_to_worker_reply_send(request_t *request, uint32_t worker_id)
{
	fr_dbuff_t		dbuff;
	fr_dbuff_uctx_talloc_t	tctx;
	fr_coord_packet_ctx_t	*packet_ctx = talloc_get_type_abort(request->async->packet_ctx, fr_coord_packet_ctx_t);
	fr_coord_pair_reg_t	*coord_pair_reg = talloc_get_type_abort(packet_ctx->uctx, fr_coord_pair_reg_t);
	int			ret;

	if (fr_dbuff_init_talloc(NULL, &dbuff, &tctx, 1024, SIZE_MAX) == NULL) return -1;
	if (fr_internal_encode_list(&dbuff, &request->reply_pairs, NULL) < 0) {
		fr_dbuff_free_talloc(&dbuff);
		return -1;
	}

	ret = fr_coord_to_worker_send(packet_ctx->coord_pair->coord, worker_id, coord_pair_reg->cb_id, &dbuff);

	fr_dbuff_free_talloc(&dbuff);

	return ret;
}

/** Send a pair list from a worker to a coordinator
 *
 * The pair list must include an attribute indicating the packet type
 *
 * @param cw	The coord worker sending the data.
 * @param list	of pairs to send.
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int fr_worker_to_coord_pair_send(fr_coord_worker_t *cw, fr_coord_pair_reg_t *coord_pair_reg, fr_pair_list_t *list)
{
	fr_dbuff_t		dbuff;
	fr_dbuff_uctx_talloc_t	tctx;
	int			ret;

	if (fr_dbuff_init_talloc(NULL, &dbuff, &tctx, 1024, SIZE_MAX) == NULL) return -1;
	if (fr_internal_encode_list(&dbuff, list, NULL) < 0) return -1;

	ret = fr_worker_to_coord_send(cw, coord_pair_reg->cb_id, &dbuff);

	fr_dbuff_free_talloc(&dbuff);
	return ret;
}

/** Plugin creation called during coordinator creation.
 *
 * @param ctx		to allocate the plugin in.
 * @param el		Event list for plugin to use.
 * @param single_thread	is the server in single thread mode.
 * @param uctx		configured for the callback this plugin relates to.
 * @return
 *	- fr_coord_plugin_t on success
 *	- NULL on failure
 */
fr_coord_cb_inst_t *fr_coord_pair_inst_create(TALLOC_CTX *ctx, fr_coord_t *coord, fr_event_list_t *el,
					       bool single_thread, void *uctx)
{
	fr_coord_cb_inst_t	*cb_inst;
	fr_coord_pair_t		*coord_pair;

	MEM(cb_inst = talloc(ctx, fr_coord_cb_inst_t));

	*cb_inst = (fr_coord_cb_inst_t) {
		.event_pre_cb = fr_coord_pair_pre_event,
		.event_post_cb = fr_coord_pair_post_event,
		.event_cb = fr_coord_pair_event
	};

	coord_pair = fr_coord_pair_create(ctx, coord, el, single_thread, uctx);
	if (!coord_pair) {
		talloc_free(cb_inst);
		return NULL;
	}

	cb_inst->inst_data = coord_pair;

	return cb_inst;
}
