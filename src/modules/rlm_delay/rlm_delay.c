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
 * @file rlm_delay.c
 * @brief Add an artificial delay to requests.
 *
 * @copyright 2016 The FreeRADIUS server project
 * @copyright 2016 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/server/map_proc.h>
#include <freeradius-devel/util/time.h>
#include <freeradius-devel/unlang/xlat_func.h>

typedef struct {
	tmpl_t		*delay;			//!< How long we delay for.
	bool		relative;		//!< Whether the delay is relative to the start of request processing.
	bool		force_reschedule;	//!< Whether we should force rescheduling of the request.
} rlm_delay_t;

/*
 *	A mapping of configuration file names to internal variables.
 */
static const conf_parser_t module_config[] = {
	{ FR_CONF_OFFSET("delay", rlm_delay_t, delay) },
	{ FR_CONF_OFFSET("relative", rlm_delay_t, relative), .dflt = "no" },
	{ FR_CONF_OFFSET("force_reschedule", rlm_delay_t, force_reschedule), .dflt = "no" },
	CONF_PARSER_TERMINATOR
};

typedef struct {
	fr_retry_config_t	retry_cfg;
	fr_time_t		when;
} rlm_delay_retry_t;

/** Called when the timeout has expired
 *
 * Marks the request as resumable, and prints the delayed delay time.
 */
static void _delay_done(module_ctx_t const *mctx, request_t *request, fr_retry_t const *retry)
{
	rlm_delay_retry_t *yielded = talloc_get_type_abort(mctx->rctx, rlm_delay_retry_t);

	RDEBUG2("Delay done");

	/*
	 *	timeout should never be *before* the scheduled time,
	 *	if it is, something is very broken.
	 */
	if (!fr_cond_assert(fr_time_gteq(retry->updated, yielded->when))) REDEBUG("Unexpected resume time");
}

static void _xlat_delay_done(xlat_ctx_t const *xctx, request_t *request, fr_time_t fired)
{
	fr_time_t *yielded = talloc_get_type_abort(xctx->rctx, fr_time_t);

	RDEBUG2("Delay done");

	/*
	 *	timeout should never be *before* the scheduled time,
	 *	if it is, something is very broken.
	 */
	if (!fr_cond_assert(fr_time_gt(fired, *yielded))) REDEBUG("Unexpected resume time");

	unlang_interpret_mark_runnable(request);
}

static int delay_add(request_t *request, fr_time_t *resume_at, fr_time_t now,
		     fr_time_delta_t delay, bool force_reschedule, bool relative)
{
	/*
	 *	Delay is zero (and reschedule is not forced)
	 */
	if (!force_reschedule && !fr_time_delta_ispos(delay)) return 1;

	/*
	 *	Process the delay relative to the start of packet processing
	 */
	if (relative) {
		*resume_at = fr_time_add(request->packet->timestamp, delay);
	} else {
		*resume_at = fr_time_add(now, delay);
	}

	/*
	 *	If resume_at is in the past (and reschedule is not forced), just return noop
	 */
	if (!force_reschedule && fr_time_lteq(*resume_at, now)) return 1;

	if (fr_time_gt(*resume_at, now)) {
		RDEBUG2("Delaying request by ~%pVs", fr_box_time_delta(fr_time_sub(*resume_at, now)));
	} else {
		RDEBUG2("Rescheduling request");
	}

	return 0;
}

/** Called resume_at the delay is complete, and we're running from the interpreter
 *
 */
static unlang_action_t mod_delay_return(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_delay_retry_t *yielded = talloc_get_type_abort(mctx->rctx, rlm_delay_retry_t);

	/*
	 *	Print how long the delay *really* was.
	 */
	RDEBUG3("Request delayed by %pV", fr_box_time_delta(fr_time_sub(fr_time(), yielded->when)));
	talloc_free(yielded);

	RETURN_MODULE_OK;
}

static unlang_action_t CC_HINT(nonnull) mod_delay(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_delay_t const	*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_delay_t);
	fr_time_delta_t		delay;
	rlm_delay_retry_t	*yielded;
	fr_time_t		resume_at;

	if (inst->delay) {
		if (tmpl_aexpand_type(request, &delay, FR_TYPE_TIME_DELTA,
				      request, inst->delay, NULL, NULL) < 0) {
			RPEDEBUG("Failed parsing %s as delay time", inst->delay->name);
			RETURN_MODULE_FAIL;
		}
	} else {
		delay = fr_time_delta_wrap(0);
	}

	/*
	 *	Record the time that we yielded the request
	 */
	MEM(yielded = talloc(unlang_interpret_frame_talloc_ctx(request), rlm_delay_retry_t));
	yielded->when = fr_time();

	/*
	 *	Setup the delay for this request
	 */
	if (delay_add(request, &resume_at, yielded->when, delay,
		      inst->force_reschedule, inst->relative) != 0) {
		RETURN_MODULE_NOOP;
	}

	RDEBUG3("Current time %pVs, resume time %pVs",
		fr_box_time(yielded->when), fr_box_time(resume_at));

	/*
	 *
	 */
	yielded->retry_cfg = (fr_retry_config_t) {
		.mrd = delay,
		.mrc = 1,
	};

	return unlang_module_yield_to_retry(request, mod_delay_return, _delay_done, NULL, 0,
					    yielded, &yielded->retry_cfg);
}

static xlat_action_t xlat_delay_resume(TALLOC_CTX *ctx, fr_dcursor_t *out,
				       xlat_ctx_t const *xctx,
				       request_t *request, UNUSED fr_value_box_list_t *in)
{
	fr_time_t	*yielded_at = talloc_get_type_abort(xctx->rctx, fr_time_t);
	fr_time_delta_t	delayed;
	fr_value_box_t	*vb;

	delayed = fr_time_sub(fr_time(), *yielded_at);
	talloc_free(yielded_at);

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_TIME_DELTA, NULL));
	vb->vb_time_delta = delayed;

	RDEBUG3("Request delayed by %pVs", vb);

	fr_dcursor_insert(out, vb);

	return XLAT_ACTION_DONE;
}

static void xlat_delay_cancel(UNUSED xlat_ctx_t const *xctx, request_t *request, UNUSED fr_signal_t action)
{
	RDEBUG2("Cancelling delay");
}

static xlat_arg_parser_t const xlat_delay_args[] = {
	{ .single = true, .type = FR_TYPE_TIME_DELTA },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Xlat to delay the request
 *
 * Example (delay 2 seconds):
@verbatim
%delay(2)
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_delay(UNUSED TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out,
				xlat_ctx_t const *xctx,
				request_t *request, fr_value_box_list_t *in)
{
	rlm_delay_t const	*inst = talloc_get_type_abort(xctx->mctx->mi->data, rlm_delay_t);
	fr_time_t		resume_at, *yielded_at;
	fr_value_box_t		*delay = fr_value_box_list_head(in);

	/*
	 *	Record the time that we yielded the request
	 */
	MEM(yielded_at = talloc(request, fr_time_t));
	*yielded_at = fr_time();

	/*
	 *	If there's no input delay, just yield and
	 *	immediately re-enqueue the request.
	 *	This is very useful for testing.
	 */
	if (!delay) {
		if (!fr_cond_assert(delay_add(request, &resume_at, *yielded_at, fr_time_delta_wrap(0), true, true) == 0)) {
			return XLAT_ACTION_FAIL;
		}
		goto yield;
	}

	if (delay_add(request, &resume_at, *yielded_at, delay->vb_time_delta,
		      inst->force_reschedule, inst->relative) != 0) {
		RDEBUG2("Not adding delay");
		talloc_free(yielded_at);
		return XLAT_ACTION_DONE;
	}

yield:
	RDEBUG3("Current time %pVs, resume time %pVs", fr_box_time(*yielded_at), fr_box_time(resume_at));

	if (unlang_xlat_timeout_add(request, _xlat_delay_done, yielded_at, resume_at) < 0) {
		RPEDEBUG("Adding event failed");
		return XLAT_ACTION_FAIL;
	}

	return unlang_xlat_yield(request, xlat_delay_resume, xlat_delay_cancel, ~FR_SIGNAL_CANCEL, yielded_at);
}

static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	xlat_t		*xlat;

	xlat = module_rlm_xlat_register(mctx->mi->boot, mctx, NULL, xlat_delay, FR_TYPE_TIME_DELTA);
	xlat_func_args_set(xlat, xlat_delay_args);
	return 0;
}

extern module_rlm_t rlm_delay;
module_rlm_t rlm_delay = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "delay",
		.flags		= 0,
		.inst_size	= sizeof(rlm_delay_t),
		.config		= module_config,
		.bootstrap	= mod_bootstrap
	},
	.method_group = {
		.bindings = (module_method_binding_t[]){
			{ .section = SECTION_NAME(CF_IDENT_ANY, CF_IDENT_ANY), .method = mod_delay },
			MODULE_BINDING_TERMINATOR
		}
	}
};
