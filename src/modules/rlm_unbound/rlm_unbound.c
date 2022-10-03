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

#define LOG_PREFIX mctx->inst->name

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/server/log.h>
#include <fcntl.h>

#include "io.h"
#include "log.h"

typedef struct {
	char const	*name;
	uint32_t	timeout;

	char const	*filename;		//!< Unbound configuration file
	char const	*resolvconf;		//!< resolv.conf file to use
	char const	*hosts;			//!< hosts file to load
} rlm_unbound_t;

typedef struct {
	unbound_io_event_base_t	*ev_b;		//!< Unbound event base
	rlm_unbound_t		*inst;		//!< Instance data
	unbound_log_t		*u_log;		//!< Unbound log structure
} rlm_unbound_thread_t;

typedef struct {
	int			async_id;	//!< Id of async query
	request_t		*request;	//!< Current request being processed
	rlm_unbound_thread_t	*t;		//!< Thread running this request
	int			done;		//!< Indicator that the callback has been called
						///< Negative values indicate errors.
	bool			timedout;	//!< Request timedout.
	fr_type_t		return_type;	//!< Data type to parse results into
	bool			has_priority;	//!< Does the returned data start with a priority field
	uint16_t		count;		//!< Number of results to return
	fr_value_box_list_t	list;		//!< Where to put the parsed results
	TALLOC_CTX		*out_ctx;	//!< CTX to allocate parsed results in
	fr_event_timer_t const	*ev;		//!< Event for timeout
} unbound_request_t;

/*
 *	A mapping of configuration file names to internal variables.
 */
static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("filename", FR_TYPE_FILE_INPUT, rlm_unbound_t, filename), .dflt = "${modconfdir}/unbound/default.conf" },
	{ FR_CONF_OFFSET("timeout", FR_TYPE_UINT32, rlm_unbound_t, timeout), .dflt = "3000" },
	{ FR_CONF_OFFSET("resolvconf", FR_TYPE_FILE_INPUT, rlm_unbound_t, resolvconf) },
	{ FR_CONF_OFFSET("hosts", FR_TYPE_FILE_INPUT, rlm_unbound_t, hosts) },
	CONF_PARSER_TERMINATOR
};

static int _unbound_request_free(unbound_request_t *ur)
{
	/*
	 *	Cancel an outstanding async unbound call if the request is being freed
	 */
	if ((ur->async_id != 0) && (ur->done == 0)) ub_cancel(ur->t->ev_b->ub, ur->async_id);

	return 0;
}

/**	Callback called by unbound when resolution started with ub_resolve_event() completes
 *
 * @param mydata	the request tracking structure set up before ub_resolve_event() was called
 * @param rcode		should be the rcode from the reply packet, but appears not to be
 * @param packet	wire format reply packet
 * @param packet_len	length of wire format packet
 * @param sec		DNSSEC status code
 * @param why_bogus	String describing DNSSEC issue if sec = 1
 * @param rate_limited	Was the request rate limited due to unbound workload
 */
static void xlat_unbound_callback(void *mydata, int rcode, void *packet, int packet_len, int sec,
				  char *why_bogus, UNUSED int rate_limited)
{
	unbound_request_t	*ur = talloc_get_type_abort(mydata, unbound_request_t);
	request_t		*request = ur->request;
	fr_dbuff_t		dbuff;
	uint16_t		qdcount = 0, ancount = 0, i, rdlength = 0;
	uint8_t			pktrcode = 0, skip = 0;
	ssize_t			used;
	fr_value_box_t		*vb;

	/*
	 *	Request has completed remove timeout event and set
	 *	async_id to 0 so ub_cancel() is not called when ur is freed
	 */
	if (ur->ev) (void)fr_event_timer_delete(&ur->ev);
	ur->async_id = 0;

	/*
	 *	Bogus responses have the "sec" flag set to 1
	 */
	if (sec == 1) {
		RERROR("%s", why_bogus);
		ur->done = -16;
		goto resume;
	}

	RHEXDUMP4((uint8_t const *)packet, packet_len, "Unbound callback called with packet [length %d]", packet_len);

	fr_dbuff_init(&dbuff, (uint8_t const *)packet, (size_t)packet_len);

	/*	Skip initial header entries */
	fr_dbuff_advance(&dbuff, 3);

	/*
	 *	Extract rcode - it doesn't appear to be passed in as a
	 *	parameter, contrary to the documentation...
	 */
	fr_dbuff_out(&pktrcode, &dbuff);
	rcode = pktrcode & 0x0f;
	if (rcode != 0) {
		ur->done = 0 - rcode;
		REDEBUG("DNS rcode is %d", rcode);
		goto resume;
	}

	fr_dbuff_out(&qdcount, &dbuff);
	if (qdcount > 1) {
		RERROR("DNS results packet with multiple questions");
		ur->done = -32;
		goto resume;
	}

	/*	How many answer records do we have? */
	fr_dbuff_out(&ancount, &dbuff);
	RDEBUG4("Unbound returned %d answers", ancount);

	/*	Skip remaining header entries */
	fr_dbuff_advance(&dbuff, 4);

	/*	Skip the QNAME */
	fr_dbuff_out(&skip, &dbuff);
	while (skip > 0) {
		if (skip > 63) {
			/*
			 *	This is a pointer to somewhere else in the the packet
			 *	Pointers use two octets
			 *	Just move past the pointer to the next label in the question
			 */
			fr_dbuff_advance(&dbuff, 1);
		} else {
			if (fr_dbuff_remaining(&dbuff) < skip) break;
			fr_dbuff_advance(&dbuff, skip);
		}
		fr_dbuff_out(&skip, &dbuff);
	}

	/*	Skip QTYPE and QCLASS */
	fr_dbuff_advance(&dbuff, 4);

	/*	We only want a limited number of replies */
	if (ancount > ur->count) ancount = ur->count;

	fr_value_box_list_init(&ur->list);

	/*	Read the answer RRs */
	for (i = 0; i < ancount; i++) {
		fr_dbuff_out(&skip, &dbuff);
		if (skip > 63) fr_dbuff_advance(&dbuff, 1);

		/*	Skip TYPE, CLASS and TTL */
		fr_dbuff_advance(&dbuff, 8);

		fr_dbuff_out(&rdlength, &dbuff);
		RDEBUG4("RDLENGTH is %d", rdlength);

		MEM(vb = fr_value_box_alloc_null(ur->out_ctx));
		switch (ur->return_type) {
		case FR_TYPE_IPV4_ADDR:
		case FR_TYPE_IPV6_ADDR:
		case FR_TYPE_OCTETS:
			if (fr_value_box_from_network(ur->out_ctx, vb, ur->return_type, NULL,
						      &dbuff, rdlength, true) < 0) {
			error:
				talloc_free(vb);
				fr_dlist_talloc_free(&ur->list);
				ur->done = -32;
				goto resume;
			}
			break;

		case FR_TYPE_STRING:
			if (ur->has_priority) {
				/*
				 *	This record type has a priority before the label
				 *	add the priority first as a separate box
				 */
				fr_value_box_t	*priority_vb;
				if (rdlength < 3) {
					REDEBUG("%s - Invalid data returned", ur->t->inst->name);
					goto error;
				}
				MEM(priority_vb = fr_value_box_alloc_null(ur->out_ctx));
				if (fr_value_box_from_network(ur->out_ctx, priority_vb, FR_TYPE_UINT16, NULL,
							      &dbuff, 2, true) < 0) {
					talloc_free(priority_vb);
					goto error;
				}
				fr_dlist_insert_tail(&ur->list, priority_vb);
			}

			/*	String types require decoding of dns format labels */
			used = fr_dns_label_to_value_box(ur->out_ctx, vb, (uint8_t const *)packet, packet_len,
							 (uint8_t const *)fr_dbuff_current(&dbuff), true, NULL);
			if (used < 0) goto error;
			fr_dbuff_advance(&dbuff, (size_t)used);
			break;

		default:
			RERROR("No meaningful output type set");
			goto error;
		}

		fr_dlist_insert_tail(&ur->list, vb);

	}

	ur->done = 1;

resume:
	unlang_interpret_mark_runnable(ur->request);
}

/**	Callback from our timeout event to cancel a request
 *
 */
static void xlat_unbound_timeout(UNUSED fr_event_list_t *el, UNUSED fr_time_t now, void *uctx)
{
	unbound_request_t	*ur = talloc_get_type_abort(uctx, unbound_request_t);
	request_t		*request = ur->request;

	REDEBUG("Timeout waiting for DNS resolution");
	unlang_interpret_mark_runnable(request);

	ur->timedout = true;
}

/*
 *	Xlat signal callback if an unbound request needs cancelling
 */
static void xlat_unbound_signal(xlat_ctx_t const *xctx, request_t *request, fr_state_signal_t action)
{
	unbound_request_t	*ur = talloc_get_type_abort(xctx->rctx, unbound_request_t);

	if (action != FR_SIGNAL_CANCEL) return;

	if (ur->ev) (void)fr_event_timer_delete(&ur->ev);

	RDEBUG2("Forcefully cancelling pending unbound request");
}

/*
 *	Xlat resume callback after unbound has either returned or timed out
 *	Move the parsed results to the xlat output cursor
 */
static xlat_action_t xlat_unbound_resume(UNUSED TALLOC_CTX *ctx, fr_dcursor_t *out,
					 xlat_ctx_t const *xctx,
					 request_t *request, UNUSED fr_value_box_list_t *in)
{
	fr_value_box_t		*vb;
	unbound_request_t	*ur = talloc_get_type_abort(xctx->rctx, unbound_request_t);

	/*
	 *	Request timed out
	 */
	if (ur->timedout) return XLAT_ACTION_FAIL;

#define RCODEERROR(_code, _message) case _code: \
	REDEBUG(_message, ur->t->inst->name); \
	goto error

	/*	Check for unbound errors */
	switch (ur->done) {
	case 1:
		break;

	default:
		REDEBUG("%s - Unknown DNS error", ur->t->inst->name);
	error:
		talloc_free(ur);
		return XLAT_ACTION_FAIL;

	RCODEERROR(0, "%s - No result");
	RCODEERROR(-1, "%s - Query format error");
	RCODEERROR(-2, "%s - DNS server failure");
	RCODEERROR(-3, "%s - Nonexistent domain name");
	RCODEERROR(-4, "%s - DNS server does not support query type");
	RCODEERROR(-5, "%s - DNS server refused query");
	RCODEERROR(-16, "%s - Bogus DNS response");
	RCODEERROR(-32, "%s - Error parsing DNS response");
	}

	/*
	 *	Move parsed results into xlat cursor
	 */
	while ((vb = fr_dlist_pop_head(&ur->list))) {
		fr_dcursor_append(out, vb);
	}

	talloc_free(ur);
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
static xlat_action_t xlat_unbound(TALLOC_CTX *ctx, fr_dcursor_t *out,
				  xlat_ctx_t const *xctx,
				  request_t *request, fr_value_box_list_t *in)
{
	rlm_unbound_t const		*inst = talloc_get_type_abort_const(xctx->mctx->inst->data, rlm_unbound_t);
	rlm_unbound_thread_t		*t = talloc_get_type_abort(xctx->mctx->thread, rlm_unbound_thread_t);
	fr_value_box_t			*host_vb = fr_dlist_head(in);
	fr_value_box_t			*query_vb = fr_dlist_next(in, host_vb);
	fr_value_box_t			*count_vb = fr_dlist_next(in, query_vb);
	unbound_request_t		*ur;

	if (host_vb->length == 0) {
		REDEBUG("Can't resolve zero length host");
		return XLAT_ACTION_FAIL;
	}

	MEM(ur = talloc_zero(unlang_interpret_frame_talloc_ctx(request), unbound_request_t));
	talloc_set_destructor(ur, _unbound_request_free);

	/*
	 *	Set the maximum number of records we want to return
	 */
	if ((count_vb) && (count_vb->type == FR_TYPE_UINT16) && (count_vb->vb_uint16 > 0)) {
		ur->count = count_vb->vb_uint16;
	} else {
		ur->count = UINT16_MAX;
	}

	ur->request = request;
	ur->t = t;
	ur->out_ctx = ctx;

#define UB_QUERY(_record, _rrvalue, _return, _hasprio) \
	if (strcmp(query_vb->vb_strvalue, _record) == 0) { \
		ur->return_type = _return; \
		ur->has_priority = _hasprio; \
		ub_resolve_event(t->ev_b->ub, host_vb->vb_strvalue, _rrvalue, 1, ur, \
				xlat_unbound_callback, &ur->async_id); \
	}

	/* coverity[dereference] */
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
	 *	unbound returned before we yielded - run the callback
	 *	This is when serving results from local data
	 */
	if (ur->async_id == 0) {
		xlat_ctx_t our_xctx = *xctx;

		our_xctx.rctx = ur;	/* Make the rctx available to the resume function */

		return xlat_unbound_resume(ctx, out, &our_xctx, request, in);
	}

	if (fr_event_timer_in(ur, ur->t->ev_b->el, &ur->ev, fr_time_delta_from_msec(inst->timeout),
			      xlat_unbound_timeout, ur) < 0) {
		REDEBUG("Unable to attach unbound timeout_envent");
		ub_cancel(t->ev_b->ub, ur->async_id);
		return XLAT_ACTION_FAIL;
	}

	return unlang_xlat_yield(request, xlat_unbound_resume, xlat_unbound_signal, ur);
}

static int mod_thread_instantiate(module_thread_inst_ctx_t const *mctx)
{
	rlm_unbound_t		*inst = talloc_get_type_abort(mctx->inst->data, rlm_unbound_t);
	rlm_unbound_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_unbound_thread_t);
	int			res;

	t->inst = inst;
	if (unbound_io_init(t, &t->ev_b, mctx->el) < 0) {
		PERROR("Unable to create unbound event base");
		return -1;
	}

	/*
	 *	Ensure unbound uses threads
	 */
	res = ub_ctx_async(t->ev_b->ub, 1);
	if (res) {
	error:
		PERROR("%s", ub_strerror(res));
		return -1;
	}

	/*
	 *	Load settings from the unbound config file
	 */
	res = ub_ctx_config(t->ev_b->ub, UNCONST(char *, inst->filename));
	if (res) goto error;

	if (unbound_log_init(t, &t->u_log, t->ev_b->ub) < 0) {
		PERROR("Failed to initialise unbound log");
		return -1;
	}

	/*
	 *	Load resolv.conf if specified
	 */
	if (inst->resolvconf) ub_ctx_resolvconf(t->ev_b->ub, inst->resolvconf);

	/*
	 *	Load hosts file if specified
	 */
	if (inst->hosts) ub_ctx_hosts(t->ev_b->ub, inst->hosts);

	/*
	 *	The unbound context needs to be "finalised" to fix its settings.
	 *	The API does not expose a method to do this, rather it happens on first
	 *	use.  A quick workround is to delete data which won't be present
	 */
	ub_ctx_data_remove(t->ev_b->ub, "notar33lsite.foo123.nottld A 127.0.0.1");

	return 0;
}

static int mod_thread_detach(module_thread_inst_ctx_t const *mctx)
{
	rlm_unbound_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_unbound_thread_t);

	talloc_free(t->u_log);
	talloc_free(t->ev_b);

	return 0;
}

static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	rlm_unbound_t	*inst = talloc_get_type_abort(mctx->inst->data, rlm_unbound_t);
	xlat_t		*xlat;

	inst->name = mctx->inst->name;

	if (inst->timeout > 10000) {
		cf_log_err(mctx->inst->conf, "timeout must be 0 to 10000");
		return -1;
	}

	if(!(xlat = xlat_register_module(NULL, mctx, mctx->inst->name, xlat_unbound, XLAT_FLAG_NEEDS_ASYNC))) return -1;
	xlat_func_args(xlat, xlat_unbound_args);

	return 0;
}

extern module_rlm_t rlm_unbound;
module_rlm_t rlm_unbound = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "unbound",
		.type			= MODULE_TYPE_THREAD_SAFE,
		.inst_size		= sizeof(rlm_unbound_t),
		.config			= module_config,
		.bootstrap		= mod_bootstrap,

		.thread_inst_size	= sizeof(rlm_unbound_thread_t),
		.thread_inst_type	= "rlm_unbound_thread_t",
		.thread_instantiate	= mod_thread_instantiate,
		.thread_detach		= mod_thread_detach
	}
};
