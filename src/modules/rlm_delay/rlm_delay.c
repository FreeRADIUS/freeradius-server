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
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/server/map_proc.h>
#include <freeradius-devel/util/time.h>

typedef struct {
	char const	*xlat_name;		//!< Name of our xlat function.
	vp_tmpl_t	*delay;			//!< How long we delay for.
	bool		relative;		//!< Whether the delay is relative to the start of request processing.
	bool		force_reschedule;	//!< Whether we should force rescheduling of the request.
} rlm_delay_t;

/*
 *	A mapping of configuration file names to internal variables.
 */
static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("delay", FR_TYPE_TMPL, rlm_delay_t, delay) },
	{ FR_CONF_OFFSET("relative", FR_TYPE_BOOL, rlm_delay_t, relative), .dflt = "no" },
	{ FR_CONF_OFFSET("force_reschedule", FR_TYPE_BOOL, rlm_delay_t, force_reschedule), .dflt = "no" },
	CONF_PARSER_TERMINATOR
};

/** Called when the timeout has expired
 *
 * Marks the request as resumable, and prints the delayed delay time.
 */
static void _delay_done(UNUSED module_ctx_t const *mctx, REQUEST *request, void *rctx, fr_time_t fired)
{
	fr_time_t *yielded = talloc_get_type_abort(rctx, fr_time_t);

	RDEBUG2("Delay done");

	/*
	 *	timeout should never be *before* the scheduled time,
	 *	if it is, something is very broken.
	 */
	if (!fr_cond_assert(fired >= *yielded)) REDEBUG("Unexpected resume time");

	unlang_interpret_resumable(request);
}

static void _xlat_delay_done(REQUEST *request,
			     UNUSED void *xlat_inst, UNUSED void *xlat_thread_inst, void *rctx, fr_time_t fired)
{
	fr_time_t *yielded = talloc_get_type_abort(rctx, fr_time_t);

	RDEBUG2("Delay done");

	/*
	 *	timeout should never be *before* the scheduled time,
	 *	if it is, something is very broken.
	 */
	if (!fr_cond_assert(fired > *yielded)) REDEBUG("Unexpected resume time");

	unlang_interpret_resumable(request);
}

static int delay_add(REQUEST *request, fr_time_t *resume_at, fr_time_t now,
		     fr_time_t delay, bool force_reschedule, bool relative)
{
	/*
	 *	Delay is zero (and reschedule is not forced)
	 */
	if (!force_reschedule && (delay == 0)) return 1;

	/*
	 *	Process the delay relative to the start of packet processing
	 */
	if (relative) {
		*resume_at = request->packet->timestamp + delay;
	} else {
		*resume_at = now + delay;
	}

	/*
	 *	If resume_at is in the past (and reschedule is not forced), just return noop
	 */
	if (!force_reschedule && (*resume_at <= now)) return 1;

	if (*resume_at > now) {
		RDEBUG2("Delaying request by ~%pVs", fr_box_time_delta(*resume_at - now));
	} else {
		RDEBUG2("Rescheduling request");
	}

	return 0;
}

/** Called resume_at the delay is complete, and we're running from the interpreter
 *
 */
static rlm_rcode_t mod_delay_return(UNUSED module_ctx_t const *mctx, REQUEST *request, void *rctx)
{
	fr_time_t *yielded = talloc_get_type_abort(rctx, fr_time_t);

	/*
	 *	Print how long the delay *really* was.
	 */
	RDEBUG3("Request delayed by %pV", fr_box_time_delta(fr_time() - *yielded));
	talloc_free(yielded);

	return RLM_MODULE_OK;
}

static void mod_delay_cancel(UNUSED module_ctx_t const *mctx, REQUEST *request, void *rctx,
			     fr_state_signal_t action)
{
	if (action != FR_SIGNAL_CANCEL) return;

	RDEBUG2("Cancelling delay");

	(void) unlang_module_timeout_delete(request, rctx);
}

static rlm_rcode_t CC_HINT(nonnull) mod_delay(module_ctx_t const *mctx, REQUEST *request)
{
	rlm_delay_t const	*inst = talloc_get_type_abort_const(mctx->instance, rlm_delay_t);
	fr_time_delta_t		delay;
	fr_time_t		resume_at, *yielded_at;

	if (inst->delay) {
		if (tmpl_aexpand_type(request, &delay, FR_TYPE_TIME_DELTA,
				      request, inst->delay, NULL, NULL) < 0) return RLM_MODULE_FAIL;
	} else {
		delay = 0;
	}

	/*
	 *	Record the time that we yielded the request
	 */
	MEM(yielded_at = talloc(request, fr_time_t));
	*yielded_at = fr_time();

	/*
	 *	Setup the delay for this request
	 */
	if (delay_add(request, &resume_at, *yielded_at, delay,
		      inst->force_reschedule, inst->delay) != 0) {
		return RLM_MODULE_NOOP;
	}

	/*
	 *	FIXME - Should print wallclock time
	 */
	RDEBUG3("Current time %pVs, resume time %pVs",
		fr_box_time_delta(*yielded_at), fr_box_time_delta(resume_at));

	if (unlang_module_timeout_add(request, _delay_done, yielded_at, resume_at) < 0) {
		RPEDEBUG("Adding event failed");
		return RLM_MODULE_FAIL;
	}

	return unlang_module_yield(request, mod_delay_return, mod_delay_cancel, yielded_at);
}

static xlat_action_t xlat_delay_resume(TALLOC_CTX *ctx, fr_cursor_t *out,
				       REQUEST *request,
				       UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
				       UNUSED fr_value_box_t **in, void *rctx)
{
	fr_time_t	*yielded_at = talloc_get_type_abort(rctx, fr_time_t);
	fr_time_t	delayed;
	fr_value_box_t	*vb;

	delayed = fr_time() - *yielded_at;
	talloc_free(yielded_at);

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_TIME_DELTA, NULL, false));
	vb->vb_time_delta = delayed;

	RDEBUG3("Request delayed by %pVs", vb);

	fr_cursor_insert(out, vb);

	return XLAT_ACTION_DONE;
}

static void xlat_delay_cancel(REQUEST *request, UNUSED void *instance, UNUSED void *thread,
			      UNUSED void *rctx, fr_state_signal_t action)
{
	if (action != FR_SIGNAL_CANCEL) return;

	RDEBUG2("Cancelling delay");
}

/** Xlat to delay the request
 *
 * Example (delay 2 seconds):
@verbatim
"%{delay:2}"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_delay(TALLOC_CTX *ctx, UNUSED fr_cursor_t *out,
				REQUEST *request, void const *xlat_inst, UNUSED void *xlat_thread_inst,
				fr_value_box_t **in)
{
	rlm_delay_t const	*inst;
	void			*instance;
	fr_time_delta_t		delay;
	fr_time_t		resume_at, *yielded_at;

	memcpy(&instance, xlat_inst, sizeof(instance));	/* Stupid const issues */

	inst = talloc_get_type_abort(instance, rlm_delay_t);

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
	if (!*in) {
		if (!fr_cond_assert(delay_add(request, &resume_at, *yielded_at, 0, true, true) == 0)) {
			return XLAT_ACTION_FAIL;
		}
		goto yield;
	}

	if (fr_value_box_list_concat(ctx, *in, in, FR_TYPE_STRING, true) < 0) {
		RPEDEBUG("Failed concatenating input");
		talloc_free(yielded_at);
		return XLAT_ACTION_FAIL;
	}

	if (fr_time_delta_from_str(&delay, (*in)->vb_strvalue, FR_TIME_RES_SEC) < 0) {
		RPEDEBUG("Failed parsing delay time");
		talloc_free(yielded_at);
		return XLAT_ACTION_FAIL;
	}

	if (delay_add(request, &resume_at, *yielded_at, delay, inst->force_reschedule, inst->relative) != 0) {
		RDEBUG2("Not adding delay");
		talloc_free(yielded_at);
		return XLAT_ACTION_DONE;
	}

yield:
	/*
	 *	FIXME - Should print wallclock time
	 */
	RDEBUG3("Current time %pVs, resume time %pVs", fr_box_time_delta(*yielded_at), fr_box_time_delta(resume_at));

	if (unlang_xlat_event_timeout_add(request, _xlat_delay_done, yielded_at, resume_at) < 0) {
		RPEDEBUG("Adding event failed");
		return XLAT_ACTION_FAIL;
	}

	return unlang_xlat_yield(request, xlat_delay_resume, xlat_delay_cancel, yielded_at);
}

static int mod_xlat_instantiate(void *xlat_inst, UNUSED xlat_exp_t const *exp, void *uctx)
{
	*((void **)xlat_inst) = talloc_get_type_abort(uctx, rlm_delay_t);
	return 0;
}

static int mod_bootstrap(void *instance, CONF_SECTION *conf)
{
	rlm_delay_t *inst = instance;
	xlat_t const *xlat;

	inst->xlat_name = cf_section_name2(conf);
	if (!inst->xlat_name) inst->xlat_name = cf_section_name1(conf);

	xlat = xlat_async_register(inst, inst->xlat_name, xlat_delay);
	xlat_async_instantiate_set(xlat, mod_xlat_instantiate, rlm_delay_t *, NULL, inst);
	return 0;
}

extern module_t rlm_delay;
module_t rlm_delay = {
	.magic		= RLM_MODULE_INIT,
	.name		= "delay",
	.type		= 0,
	.inst_size	= sizeof(rlm_delay_t),
	.config		= module_config,
	.bootstrap	= mod_bootstrap,
	.methods = {
		[MOD_PREACCT]		= mod_delay,
		[MOD_AUTHORIZE]		= mod_delay,
		[MOD_POST_AUTH]		= mod_delay,
	},
};
