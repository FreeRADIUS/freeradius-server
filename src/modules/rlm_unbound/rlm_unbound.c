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
 * @file rlm_unbound.c
 * @brief DNS services via libunbound.
 *
 * @copyright 2013 The FreeRADIUS server project
 * @copyright 2013 Brian S. Julin (bjulin@clarku.edu)
 */
RCSID("$Id$")

#define LOG_PREFIX "rlm_unbound - "

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/log.h>
#include <fcntl.h>

DIAG_OFF(DIAG_UNKNOWN_PRAGMAS)
DIAG_OFF(documentation)
#include <unbound.h>
DIAG_ON(documentation)
DIAG_ON(DIAG_UNKNOWN_PRAGMAS)
#include "log.h"

typedef struct {
	char const	*name;

	uint32_t	timeout;

	char const	*filename;
} rlm_unbound_t;
typedef struct {
	struct ub_ctx		*ub;		//!< Unbound ctx
	rlm_unbound_t		*inst;		//!< Instance data
	unbound_log_t		*u_log;		//!< Unbound log structure
	fr_event_list_t		*el;		//!< Current thread event list
} rlm_unbound_thread_t;

typedef struct {
	rlm_unbound_t		*inst;		//!< Instance data
	rlm_unbound_thread_t	*t;		//!< Thread structure
	request_t		*request;	//!< Current request being processed
	fr_event_timer_t const	*ev;		//!< For timing out the query
	int			async_id;	//!< Id of async query for stopping due to timeout
	struct ub_result	*result;	//!< Result of current query
	int			done;		//!< Indicator that the unbound callback has been called
	fr_type_t		return_type;	//!< Data type to parse result into
	bool			has_priority;	//!< Does the returned data start with a priority field
	uint16_t		count;		//!< Number of results to return
} unbound_xlat_thread_inst_t;

/*
 *	A mapping of configuration file names to internal variables.
 */
static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("filename", FR_TYPE_FILE_INPUT | FR_TYPE_REQUIRED, rlm_unbound_t, filename), .dflt = "${modconfdir}/unbound/default.conf" },
	{ FR_CONF_OFFSET("timeout", FR_TYPE_UINT32, rlm_unbound_t, timeout), .dflt = "3000" },
	CONF_PARSER_TERMINATOR
};

/*
 *	Cleanup events after unbound has either completed or timed out
 */
static void unbound_event_cleanup(unbound_xlat_thread_inst_t *xt)
{
	fr_event_fd_delete(xt->t->el, ub_fd(xt->t->ub), FR_EVENT_FILTER_IO);
	if(xt->ev) fr_event_timer_delete(&xt->ev);
}

/*
 *	Callback sent to libunbound for xlat functions.  Simply links the
 *	new ub_result via a pointer that has been allocated from the heap,
 *	and marks the request as runnable
 */
static void link_ubres(void *my_arg, int err, struct ub_result *result)
{
	unbound_xlat_thread_inst_t	*xt = talloc_get_type_abort(my_arg, unbound_xlat_thread_inst_t);
	xt->done = 1;

	/*
	 *	Note that while result will be NULL on error, we are explicit
	 *	here because that is actually a behavior that is suboptimal
	 *	and only documented in the examples.  It could change.
	 */
	if (err) {
		ERROR("%s", ub_strerror(err));
		xt->result = NULL;
	} else {
		xt->result = result;
	}

	unbound_event_cleanup(xt);

	unlang_interpret_mark_runnable(xt->request);
}

/*
 *	Convert labels as found in a DNS result to a NULL terminated string.
 *
 *	Result is written to string buffer allocated against vb.
 *	Returns XLAT_ACTION_DONE on success or XLAT_ACTION_FAIL on failure.
 */
static int rrlabels_tovb(fr_value_box_t *vb, char *rr)
{
	fr_sbuff_t		sbuff;
	fr_sbuff_uctx_talloc_t	sbuff_ctx;
	size_t			count;

	/*
	 *	Allocate a buffer up to the "maximum" dns length
	 */
	if(!fr_sbuff_init_talloc(vb, &sbuff, &sbuff_ctx, strlen(rr), FR_MAX_STRING_LEN)) {
		ERROR("Failed to allocate buffer for DNS label parsing");
		return XLAT_ACTION_FAIL;
	}

	/* 	Copy data to the buffer, checking format as we go */
	while (1) {
		count = *((unsigned char *)(rr));
		if (!count) break;

		if (fr_sbuff_used(&sbuff)) {
			fr_sbuff_in_char(&sbuff, '.');
		}

		rr++;
		if (count > 63 || strlen(rr) < count) return XLAT_ACTION_FAIL;
		fr_sbuff_in_bstrncpy(&sbuff, rr, count);
		rr += count;
	}

	fr_sbuff_trim_talloc(&sbuff, SIZE_MAX);
	fr_value_box_strdup_shallow(vb, NULL, fr_sbuff_buff(&sbuff), true);
	return XLAT_ACTION_DONE;
}

/*
 *	Callback from timeout event.  Cancel the unbound.
 */
static void ub_timeout(UNUSED fr_event_list_t *el, UNUSED fr_time_t now, void *uctx)
{
	unbound_xlat_thread_inst_t	*xt = talloc_get_type_abort(uctx, unbound_xlat_thread_inst_t);
	request_t			*request = xt->request;

	REDEBUG("Timeout waiting for DNS resolution");
	ub_cancel(xt->t->ub, xt->async_id);
	unbound_event_cleanup(xt);

	unlang_interpret_mark_runnable(request);
}

/*
 *	Callback from event on the unbound fd.  Simply calls ub_process to interpret results.
 */
static void ub_data_read(UNUSED fr_event_list_t *el, UNUSED int fd, UNUSED int flags, void *uctx)
{
	unbound_xlat_thread_inst_t	*xt = talloc_get_type_abort(uctx, unbound_xlat_thread_inst_t);

	ub_process(xt->t->ub);
}


/*
 *	Xlat resume callback after unbound has either returned or timed out
 *	Parse the results and add to the output
 */
static xlat_action_t xlat_unbound_resume(TALLOC_CTX *ctx, fr_dcursor_t *out, request_t *request,
					 UNUSED void const *xlat_inst, void *xlat_thread_inst,
					 UNUSED fr_value_box_list_t *in, UNUSED void *rctx)
{
	fr_value_box_t			*vb;
	unbound_xlat_thread_inst_t	*xt = talloc_get_type_abort(xlat_thread_inst, unbound_xlat_thread_inst_t);
	uint16_t			i = 0;

	if ((xt->done == 0) || (!(xt->result))) {
		RWDEBUG("%s - No result", xt->inst->name);
		return XLAT_ACTION_FAIL;
	}

	/*	Check for unbound errors */
	if (xt->result->bogus) {
		RWDEBUG("%s - Bogus DNS response", xt->inst->name);
	error:
		ub_resolve_free(xt->result);
		return XLAT_ACTION_FAIL;
	}

	if (xt->result->nxdomain) {
		RDEBUG2("%s - NXDOMAIN", xt->inst->name);
		goto error;
	}

	if (!xt->result->havedata) {
		RDEBUG2("%s - Empty result", xt->inst->name);
		goto error;
	}

	/*
	 *	unbound results are in an array of char[].
	 *	The last entry is a NULL pointer.
	 *	Process up to xt->count results, adding each as a separate box.
	 */
	do {
		vb = fr_value_box_alloc_null(ctx);
		switch (xt->return_type) {
		case FR_TYPE_IPV4_ADDR:
		case FR_TYPE_IPV6_ADDR:
		case FR_TYPE_OCTETS:
			if (fr_value_box_from_network(ctx, vb, xt->return_type, NULL, (uint8_t *)xt->result->data[i], xt->result->len[i], true) < 0) {
			error2:
				talloc_free(vb);
				goto error;
			}
			break;
		case FR_TYPE_STRING:
		{
			size_t offset = 0;
			if (xt->has_priority) {
				/*
				 *	This result type has a priority before the label
				 *	add the priority first as a separate box
				 */
				fr_value_box_t	*priority_vb;
				if (xt->result->len[i] < 3) {
					REDEBUG("%s - Invalid data returned", xt->inst->name);
					goto error2;
				}
				priority_vb = fr_value_box_alloc_null(ctx);
				if (fr_value_box_from_network(ctx, priority_vb, FR_TYPE_UINT16, NULL, (uint8_t *)xt->result->data[i], 2, true) < 0) {
					talloc_free(priority_vb);
					goto error2;
				}
				fr_dcursor_append(out, priority_vb);
				offset = 2;
			}
			/*	String types require decoding of dns format labels */
			if (rrlabels_tovb(vb, xt->result->data[i] + offset) == XLAT_ACTION_FAIL) goto error2;
		}
			break;
		default:
			goto error2;
		}

		fr_dcursor_append(out, vb);
	} while  ((++i < xt->count) && (xt->result->data[i]));

	ub_resolve_free(xt->result);

	return XLAT_ACTION_DONE;
}


static xlat_arg_parser_t const xlat_unbound_args[] = {
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	{ .single = true, .type = FR_TYPE_UINT16 },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Perform a DNS lookup using libunbound
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_unbound(UNUSED TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out, request_t *request,
				  UNUSED void const *xlat_inst, void *xlat_thread_inst,
				  fr_value_box_list_t *in)
{
	fr_value_box_t			*host_vb = fr_dlist_head(in);
	fr_value_box_t			*query_vb = fr_dlist_next(in, host_vb);
	fr_value_box_t			*count_vb = fr_dlist_next(in, query_vb);
	unbound_xlat_thread_inst_t	*xt = talloc_get_type_abort(xlat_thread_inst, unbound_xlat_thread_inst_t);
	rlm_unbound_thread_t		*t = xt->t;

	if (host_vb->length == 0) {
		REDEBUG("Can't resolve zero length host");
		return XLAT_ACTION_FAIL;
	}

#define UB_QUERY(_record, _rrvalue, _return, _hasprio) \
	if (strcmp(query_vb->vb_strvalue, _record) == 0) { \
		ub_resolve_async(t->ub, host_vb->vb_strvalue, _rrvalue, 1, xt, link_ubres, &xt->async_id); \
		xt->return_type = _return; \
		xt->has_priority = _hasprio; \
	}

	UB_QUERY("A", 1, FR_TYPE_IPV4_ADDR, false)
	else UB_QUERY("AAAA", 28, FR_TYPE_IPV6_ADDR, false)
	else UB_QUERY("PTR", 12, FR_TYPE_STRING, false)
	else UB_QUERY("MX", 15, FR_TYPE_STRING, true)
	else UB_QUERY("SRV", 33, FR_TYPE_STRING, true)
	else UB_QUERY("TXT", 16, FR_TYPE_STRING, false)
	else UB_QUERY("CERT", 37, FR_TYPE_OCTETS, false)
	else {
		REDEBUG("Invalid / unsupported DNS query type");
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Set the maximum number of records we want to return
	 */
	if ((count_vb) && (count_vb->type == FR_TYPE_UINT16) && (count_vb->vb_uint16 > 0)) {
		xt->count = count_vb->vb_uint16;
	} else {
		xt->count = UINT16_MAX;
	}

	xt->request = request;
	xt->done = 0;

	/*
	 *	Setup event to read the fd provided by unbound
	 */
	if (fr_event_fd_insert(xt, t->el, ub_fd(t->ub), ub_data_read, NULL, NULL, xt) < 0) {
		REDEBUG("Unable to attach event to read unbound results");
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Setup event to timeout unbound resolvers exceeding configured timeout
	 */
	if (fr_event_timer_in(xt, t->el, &xt->ev, fr_time_delta_from_msec(xt->inst->timeout), ub_timeout, xt) < 0) {
		REDEBUG("Unable to attach unbound timeout event");
		return XLAT_ACTION_FAIL;
	}

	return unlang_xlat_yield(request, xlat_unbound_resume, NULL, NULL);
}

static int mod_xlat_thread_instantiate(UNUSED void *xlat_inst, void *xlat_thread_inst,
				       UNUSED xlat_exp_t const *exp, void *uctx)
{
	rlm_unbound_t			*inst = talloc_get_type_abort(uctx, rlm_unbound_t);
	unbound_xlat_thread_inst_t	*xt = talloc_get_type_abort(xlat_thread_inst, unbound_xlat_thread_inst_t);

	xt->inst = inst;
	xt->t = talloc_get_type_abort(module_thread_by_data(inst)->data, rlm_unbound_thread_t);

	return 0;
}

static int mod_thread_instantiate(UNUSED CONF_SECTION const *cs, void *instance, fr_event_list_t *el, void *thread)
{
	rlm_unbound_t		*inst = talloc_get_type_abort(instance, rlm_unbound_t);
	rlm_unbound_thread_t	*t = talloc_get_type_abort(thread, rlm_unbound_thread_t);
	int			res;

	t->inst = inst;
	t->el = el;
	t->ub = ub_ctx_create();
	if (!t->ub) {
		PERROR("Unable to create unbound ctx");
		return -1;
	}

	/*
	 *	Ensure unbound uses threads
	 */
	res = ub_ctx_async(t->ub, 1);
	if (res) {
	error:
		PERROR("%s", ub_strerror(res));
		return -1;
	}

	/*
	 *	Load settings from the unbound config file
	 */
	res = ub_ctx_config(t->ub, UNCONST(char *, inst->filename));
	if (res) goto error;

	if (unbound_log_init(t, &t->u_log, t->ub) < 0) {
		PERROR("Failed to initialise unbound log");
		return -1;
	}

	/*
	 *	The unbound context needs to be "finalised" to fix its settings.
	 *	The API does not expose a method to do this, rather it happens on first
	 *	use.  A quick workround is to delete data which won't be present
	 */
	ub_ctx_data_remove(t->ub, "notar33lsite.foo123.nottld A 127.0.0.1");

	return 0;
}

static int mod_thread_detach(UNUSED fr_event_list_t *el, void *thread)
{
	rlm_unbound_thread_t	*t = talloc_get_type_abort(thread, rlm_unbound_thread_t);

	ub_process(t->ub);
	talloc_free(t->u_log);
	ub_ctx_delete(t->ub);

	return 0;
}

static int mod_bootstrap(void *instance, CONF_SECTION *conf)
{
	rlm_unbound_t	*inst = instance;
	xlat_t		*xlat;

	inst->name = cf_section_name2(conf);
	if (!inst->name) inst->name = cf_section_name1(conf);

	if (inst->timeout > 10000) {
		cf_log_err(conf, "timeout must be 0 to 10000");
		return -1;
	}

	if(!(xlat = xlat_register(NULL, inst->name, xlat_unbound, false))) return -1;
	xlat_func_args(xlat, xlat_unbound_args);
	xlat_async_thread_instantiate_set(xlat, mod_xlat_thread_instantiate, unbound_xlat_thread_inst_t, NULL, inst);

	return 0;
}

extern module_t rlm_unbound;
module_t rlm_unbound = {
	.magic			= RLM_MODULE_INIT,
	.name			= "unbound",
	.type			= RLM_TYPE_THREAD_SAFE,
	.inst_size		= sizeof(rlm_unbound_t),
	.config			= module_config,
	.bootstrap		= mod_bootstrap,

	.thread_inst_size	= sizeof(rlm_unbound_thread_t),
	.thread_inst_type	= "rlm_unbound_thread_t",
	.thread_instantiate	= mod_thread_instantiate,
	.thread_detach		= mod_thread_detach,
};
