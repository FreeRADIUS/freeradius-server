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
 * @file xlat_profiling.c
 * @brief Functions for controlling profilers attached to the running server
 *
 * The comments in this file use the terms of each profiler.  Callgrind
 * counts costs (instruction fetches, cache misses, branch mispredictions)
 * into one cost centre per function, and writes the cost centres as a
 * profile dump.  gperftools records samples of the program counter on a
 * timer, and writes the samples to a profile file.
 *
 * @copyright 2026 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/unlang/xlat_priv.h>

#ifdef HAVE_VALGRIND_CALLGRIND_H
#  include <valgrind/callgrind.h>

/** Log and return false if the server is not running under valgrind
 *
 * A natively running process ignores callgrind client requests.  Every
 * callgrind function therefore fails when valgrind is not attached, rather
 * than silently succeeding.  A misconfigured profiling run then shows in
 * the log instead of producing an empty profile.
 */
static bool callgrind_attached(request_t *request)
{
	if (RUNNING_ON_VALGRIND) return true;

	RERROR("Refusing callgrind request, the server is not running under valgrind");
	return false;
}

/** Switch callgrind instrumentation on
 *
 * Start valgrind with `valgrind --tool=callgrind --instr-atstart=no`, then
 * call `%callgrind.start()` from the `server.start` trigger to keep server
 * startup out of the profile.  Instrumentation is process-wide, so the
 * thread that calls the function does not matter.
 *
 * Use this function when the profile should begin later than process
 * start.  Configuration parsing and module instantiation have finished
 * when the `server.start` trigger fires.
 *
@verbatim
%callgrind.start()
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_callgrind_start(TALLOC_CTX *ctx, fr_dcursor_t *out,
					       UNUSED xlat_ctx_t const *xctx,
					       request_t *request, UNUSED fr_value_box_list_t *args)
{
	fr_value_box_t	*dst;

	if (!callgrind_attached(request)) return XLAT_ACTION_FAIL;

	CALLGRIND_START_INSTRUMENTATION;

	MEM(dst = fr_value_box_alloc(ctx, FR_TYPE_BOOL, NULL));
	dst->vb_bool = true;
	fr_dcursor_append(out, dst);

	return XLAT_ACTION_DONE;
}

/** Switch callgrind instrumentation off
 *
 * Use this function when the profile should end before process exit.  A
 * call from the `server.stop` trigger keeps thread teardown out of the
 * profile.  A call from a policy ends the profile after a chosen section
 * of unlang.  If no trigger or policy calls this function, callgrind
 * keeps counting costs until process exit and writes the profile dump at
 * exit.
 *
@verbatim
%callgrind.stop()
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_callgrind_stop(TALLOC_CTX *ctx, fr_dcursor_t *out,
					      UNUSED xlat_ctx_t const *xctx,
					      request_t *request, UNUSED fr_value_box_list_t *args)
{
	fr_value_box_t	*dst;

	if (!callgrind_attached(request)) return XLAT_ACTION_FAIL;

	CALLGRIND_STOP_INSTRUMENTATION;

	MEM(dst = fr_value_box_alloc(ctx, FR_TYPE_BOOL, NULL));
	dst->vb_bool = true;
	fr_dcursor_append(out, dst);

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_func_callgrind_dump_args[] = {
	{ .required = false, .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Write the cost data collected so far to a profile dump, then reset cost data
 *
 * Callgrind records the optional label in the description field of the dump.
 * The label lets the reader distinguish the dumps when one run produces several.
 *
 * Use this function when one run should produce several profile dumps,
 * such as one dump per load step, or one dump for the load phase and one
 * dump for shutdown.  Instrumentation stays on, and each dump holds only
 * the costs counted since the previous dump.  `callgrind_annotate`
 * accepts several dumps at once.
 *
@verbatim
%callgrind.dump([<label>])
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_callgrind_dump(TALLOC_CTX *ctx, fr_dcursor_t *out,
					      UNUSED xlat_ctx_t const *xctx,
					      request_t *request, fr_value_box_list_t *args)
{
	fr_value_box_t	*dst, *label;

	XLAT_ARGS(args, &label);

	if (!callgrind_attached(request)) return XLAT_ACTION_FAIL;

	if (label) {
		CALLGRIND_DUMP_STATS_AT(label->vb_strvalue);
	} else {
		CALLGRIND_DUMP_STATS;
	}

	MEM(dst = fr_value_box_alloc(ctx, FR_TYPE_BOOL, NULL));
	dst->vb_bool = true;
	fr_dcursor_append(out, dst);

	return XLAT_ACTION_DONE;
}

/** Zero the costs collected so far without writing a dump
 *
 * Use this function to discard the costs of a period that the profile
 * should not include.  Examples are the cache warmup after
 * `%callgrind.start()`, and a settling period after a load step changes
 * the request rate.  Call this function when the period ends.  The next
 * profile dump, or the dump at process exit, then holds only the costs
 * counted after the call.
 *
@verbatim
%callgrind.zero()
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_callgrind_zero(TALLOC_CTX *ctx, fr_dcursor_t *out,
					      UNUSED xlat_ctx_t const *xctx,
					      request_t *request, UNUSED fr_value_box_list_t *args)
{
	fr_value_box_t	*dst;

	if (!callgrind_attached(request)) return XLAT_ACTION_FAIL;

	CALLGRIND_ZERO_STATS;

	MEM(dst = fr_value_box_alloc(ctx, FR_TYPE_BOOL, NULL));
	dst->vb_bool = true;
	fr_dcursor_append(out, dst);

	return XLAT_ACTION_DONE;
}
#endif	/* HAVE_VALGRIND_CALLGRIND_H */

#ifdef HAVE_GPERFTOOLS_PROFILER_H
#  include <gperftools/profiler.h>
/** Start the gperftools CPU profiler, writing samples to a file
 *
 * The function fails if the profiler is already running, so a second
 * start never silently discards a running profile.  The `limit files { ... }`
 * section restricts the filename in the same way as for the `%file.*`
 * functions.
 *
 * Use this function to measure where the server spends wall-clock time.
 * The profiler samples the program counter on a timer at close to native
 * speed, so the server handles a realistic load while the profiler runs.
 * Callgrind measures instruction and cache behaviour instead, and slows
 * the server by a large factor.  The `server.start` trigger is the usual
 * place to call this function.
 *
@verbatim
%gperftools.start(<filename>)
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_gperftools_start(TALLOC_CTX *ctx, fr_dcursor_t *out,
						UNUSED xlat_ctx_t const *xctx,
						request_t *request, fr_value_box_list_t *args)
{
	fr_value_box_t		*dst, *vb;
	struct ProfilerState	state;

	XLAT_ARGS(args, &vb);
	fr_assert(vb->type == FR_TYPE_STRING);

	if (!xlat_file_allowed(request, vb)) return XLAT_ACTION_FAIL;

	ProfilerGetCurrentState(&state);
	if (state.enabled) {
		RERROR("Profiler already running, writing to %s", state.profile_name);
		return XLAT_ACTION_FAIL;
	}

	if (ProfilerStart(vb->vb_strvalue) == 0) {
		RERROR("Failed starting profiler with output file %s", vb->vb_strvalue);
		return XLAT_ACTION_FAIL;
	}

	MEM(dst = fr_value_box_alloc(ctx, FR_TYPE_BOOL, NULL));
	dst->vb_bool = true;
	fr_dcursor_append(out, dst);

	return XLAT_ACTION_DONE;
}

/** Log and return false if the gperftools CPU profiler is not running
 */
static bool gperftools_running(request_t *request)
{
	struct ProfilerState	state;

	ProfilerGetCurrentState(&state);
	if (state.enabled) return true;

	RERROR("Profiler not running");
	return false;
}

/** Write the buffered gperftools samples to the profile file, then stop the profiler
 *
 * Use this function to end the profile at a known point, usually from
 * the `server.stop` trigger.  `%gperftools.start()` starts a stopped
 * profiler again with a new profile file.
 *
@verbatim
%gperftools.stop()
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_gperftools_stop(TALLOC_CTX *ctx, fr_dcursor_t *out,
					       UNUSED xlat_ctx_t const *xctx,
					       request_t *request, UNUSED fr_value_box_list_t *args)
{
	fr_value_box_t	*dst;

	if (!gperftools_running(request)) return XLAT_ACTION_FAIL;

	ProfilerFlush();
	ProfilerStop();

	MEM(dst = fr_value_box_alloc(ctx, FR_TYPE_BOOL, NULL));
	dst->vb_bool = true;
	fr_dcursor_append(out, dst);

	return XLAT_ACTION_DONE;
}

/** Write the buffered gperftools samples to the profile file and keep the profiler running
 *
 * Use this function during a long run, so that `pprof` can read a partial
 * profile while the server keeps running.  Also use this function before
 * a step that might crash the server.  The buffered samples then reach
 * the profile file before the crash.
 *
@verbatim
%gperftools.flush()
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_gperftools_flush(TALLOC_CTX *ctx, fr_dcursor_t *out,
						UNUSED xlat_ctx_t const *xctx,
						request_t *request, UNUSED fr_value_box_list_t *args)
{
	fr_value_box_t	*dst;

	if (!gperftools_running(request)) return XLAT_ACTION_FAIL;

	ProfilerFlush();

	MEM(dst = fr_value_box_alloc(ctx, FR_TYPE_BOOL, NULL));
	dst->vb_bool = true;
	fr_dcursor_append(out, dst);

	return XLAT_ACTION_DONE;
}
#endif	/* HAVE_GPERFTOOLS_PROFILER_H */

/** Register the control functions for every profiler that the build compiled in
 *
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int xlat_profiling_init(void)
{
#if defined(HAVE_VALGRIND_CALLGRIND_H) || defined(HAVE_GPERFTOOLS_PROFILER_H)
	xlat_t *xlat;

#define XLAT_REGISTER_PROFILING(_xlat, _func, _args) \
do { \
	if (unlikely((xlat = xlat_func_register(NULL, _xlat, _func, FR_TYPE_BOOL)) == NULL)) return -1; \
	xlat_func_args_set(xlat, _args); \
	xlat_func_flags_set(xlat, XLAT_FUNC_FLAG_INTERNAL); \
} while (0)

#define XLAT_REGISTER_PROFILING_VOID(_xlat, _func) \
do { \
	if (unlikely((xlat = xlat_func_register(NULL, _xlat, _func, FR_TYPE_BOOL)) == NULL)) return -1; \
	xlat_func_flags_set(xlat, XLAT_FUNC_FLAG_INTERNAL); \
} while (0)

#  ifdef HAVE_VALGRIND_CALLGRIND_H
	XLAT_REGISTER_PROFILING_VOID("callgrind.start", xlat_func_callgrind_start);
	XLAT_REGISTER_PROFILING_VOID("callgrind.stop", xlat_func_callgrind_stop);
	XLAT_REGISTER_PROFILING("callgrind.dump", xlat_func_callgrind_dump, xlat_func_callgrind_dump_args);
	XLAT_REGISTER_PROFILING_VOID("callgrind.zero", xlat_func_callgrind_zero);
#  endif

#  ifdef HAVE_GPERFTOOLS_PROFILER_H
	XLAT_REGISTER_PROFILING("gperftools.start", xlat_func_gperftools_start, xlat_func_file_name_args);
	XLAT_REGISTER_PROFILING_VOID("gperftools.stop", xlat_func_gperftools_stop);
	XLAT_REGISTER_PROFILING_VOID("gperftools.flush", xlat_func_gperftools_flush);
#  endif

#undef XLAT_REGISTER_PROFILING
#undef XLAT_REGISTER_PROFILING_VOID
#endif

	return 0;
}
