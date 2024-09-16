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
 * @file xlat_eval.c
 * @brief String expansion ("translation").  Evaluation of pre-parsed xlat expansions.
 *
 * @copyright 2018-2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2000,2006 The FreeRADIUS server project
 * @copyright 2000 Alan DeKok (aland@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/unlang/xlat.h>
#include <freeradius-devel/unlang/xlat_priv.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/types.h>
#include <freeradius-devel/util/sbuff.h>
#include <freeradius-devel/util/value.h>

#include <freeradius-devel/unlang/unlang_priv.h>	/* Remove when everything uses new xlat API */


static int instance_count = 0;

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;

static fr_dict_autoload_t xlat_eval_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

fr_dict_attr_t const *attr_expr_bool_enum; /* xlat_expr.c */
fr_dict_attr_t const *attr_cast_base; /* xlat_expr.c */

static fr_dict_attr_t const *attr_cast_time_res_sec;
static fr_dict_attr_t const *attr_cast_time_res_min;
static fr_dict_attr_t const *attr_cast_time_res_hour;
static fr_dict_attr_t const *attr_cast_time_res_day;
static fr_dict_attr_t const *attr_cast_time_res_week;
static fr_dict_attr_t const *attr_cast_time_res_month;
static fr_dict_attr_t const *attr_cast_time_res_year;
static fr_dict_attr_t const *attr_cast_time_res_csec;
static fr_dict_attr_t const *attr_cast_time_res_msec;
static fr_dict_attr_t const *attr_cast_time_res_usec;
static fr_dict_attr_t const *attr_cast_time_res_nsec;

static fr_dict_attr_autoload_t xlat_eval_dict_attr[] = {
	{ .out = &attr_expr_bool_enum, .name = "Expr-Bool-Enum", .type = FR_TYPE_BOOL, .dict = &dict_freeradius },
	{ .out = &attr_cast_base, .name = "Cast-Base", .type = FR_TYPE_UINT8, .dict = &dict_freeradius },

	{ .out = &attr_cast_time_res_sec, .name = "Cast-Time-Res-Sec", .type = FR_TYPE_TIME_DELTA, .dict = &dict_freeradius },
	{ .out = &attr_cast_time_res_min, .name = "Cast-Time-Res-Min", .type = FR_TYPE_TIME_DELTA, .dict = &dict_freeradius },
	{ .out = &attr_cast_time_res_hour, .name = "Cast-Time-Res-Hour", .type = FR_TYPE_TIME_DELTA, .dict = &dict_freeradius },
	{ .out = &attr_cast_time_res_day, .name = "Cast-Time-Res-Day", .type = FR_TYPE_TIME_DELTA, .dict = &dict_freeradius },
	{ .out = &attr_cast_time_res_week, .name = "Cast-Time-Res-Week", .type = FR_TYPE_TIME_DELTA, .dict = &dict_freeradius },
	{ .out = &attr_cast_time_res_month, .name = "Cast-Time-Res-Month", .type = FR_TYPE_TIME_DELTA, .dict = &dict_freeradius },
	{ .out = &attr_cast_time_res_year, .name = "Cast-Time-Res-Year", .type = FR_TYPE_TIME_DELTA, .dict = &dict_freeradius },
	{ .out = &attr_cast_time_res_csec, .name = "Cast-Time-Res-Centi-Sec", .type = FR_TYPE_TIME_DELTA, .dict = &dict_freeradius },
	{ .out = &attr_cast_time_res_msec, .name = "Cast-Time-Res-Milli-Sec", .type = FR_TYPE_TIME_DELTA, .dict = &dict_freeradius },
	{ .out = &attr_cast_time_res_usec, .name = "Cast-Time-Res-Micro-Sec", .type = FR_TYPE_TIME_DELTA, .dict = &dict_freeradius },
	{ .out = &attr_cast_time_res_nsec, .name = "Cast-Time-Res-Nano-Sec", .type = FR_TYPE_TIME_DELTA, .dict = &dict_freeradius },

	{ NULL }
};

fr_table_num_sorted_t const xlat_action_table[] = {
	{ L("done"),		XLAT_ACTION_DONE	},
	{ L("fail"),		XLAT_ACTION_FAIL	},
	{ L("push-child"),	XLAT_ACTION_PUSH_CHILD	},
	{ L("yield"),		XLAT_ACTION_YIELD	}
};
size_t xlat_action_table_len = NUM_ELEMENTS(xlat_action_table);

/*
 *	This should be updated if fr_time_precision_table[] adds more time resolutions.
 */
static fr_table_ptr_ordered_t const xlat_time_precision_table[] = {
	{ L("microseconds"),	&attr_cast_time_res_usec },
	{ L("us"),		&attr_cast_time_res_usec },

	{ L("nanoseconds"),	&attr_cast_time_res_nsec },
	{ L("ns"),		&attr_cast_time_res_nsec },

	{ L("milliseconds"),	&attr_cast_time_res_msec },
	{ L("ms"),		&attr_cast_time_res_msec },

	{ L("centiseconds"),	&attr_cast_time_res_csec },
	{ L("cs"),		&attr_cast_time_res_csec },

	{ L("seconds"),		&attr_cast_time_res_sec },
	{ L("s"),		&attr_cast_time_res_sec },

	{ L("minutes"),		&attr_cast_time_res_min },
	{ L("m"),		&attr_cast_time_res_min },

	{ L("hours"),		&attr_cast_time_res_hour },
	{ L("h"),		&attr_cast_time_res_hour },

	{ L("days"),		&attr_cast_time_res_day },
	{ L("d"),		&attr_cast_time_res_day },

	{ L("weeks"),		&attr_cast_time_res_week },
	{ L("w"),		&attr_cast_time_res_week },

	/*
	 *	These use special values FR_TIME_DUR_MONTH and FR_TIME_DUR_YEAR
	 */
	{ L("months"),		&attr_cast_time_res_month },
	{ L("M"),		&attr_cast_time_res_month },

	{ L("years"),		&attr_cast_time_res_year },
	{ L("y"),		&attr_cast_time_res_year },

};
static size_t xlat_time_precision_table_len = NUM_ELEMENTS(xlat_time_precision_table);

fr_dict_attr_t const *xlat_time_res_attr(char const *res)
{
	fr_dict_attr_t const **da_p;

	da_p = fr_table_value_by_str(xlat_time_precision_table, res, NULL);
	if (!da_p) return NULL;

	return *da_p;
}

static ssize_t xlat_eval_sync(TALLOC_CTX *ctx, char **out, request_t *request, xlat_exp_head_t const * const head,
			      xlat_escape_legacy_t escape, void  const *escape_ctx);

/** Reconstruct the original expansion string from an xlat tree
 *
 * @param[in] out	sbuff to print result in.
 * @param[in] node	in the tree to start printing.
 * @return
 *	- The original expansion string on success.
 *	- NULL on error.
 */
static fr_slen_t xlat_fmt_print(fr_sbuff_t *out, xlat_exp_t const *node)
{
	switch (node->type) {
	case XLAT_BOX:
	case XLAT_GROUP:
		fr_assert(node->fmt != NULL);
		return fr_sbuff_in_sprintf(out, "%pV", fr_box_strvalue_buffer(node->fmt));

	case XLAT_ONE_LETTER:
		fr_assert(node->fmt != NULL);
		return fr_sbuff_in_sprintf(out, "%%%s", node->fmt);

	case XLAT_TMPL:
		fr_assert(node->fmt != NULL);
		if (tmpl_is_attr(node->vpt) && (node->fmt[0] == '&')) {
			return fr_sbuff_in_strcpy(out, node->fmt);
		} else {
			return fr_sbuff_in_sprintf(out, "%%{%pV}", fr_box_strvalue_buffer(node->fmt));
		}

	case XLAT_VIRTUAL:
		return fr_sbuff_in_sprintf(out, "%%{%s}", node->call.func->name);

#ifdef HAVE_REGEX
	case XLAT_REGEX:
		return fr_sbuff_in_sprintf(out, "%%{%u}", node->regex_index);
#endif

	case XLAT_FUNC:
	{
		bool			first_done = false;
		fr_sbuff_t 		our_out;
		fr_slen_t		slen;

		/*
		 *	No arguments, just print an empty function.
		 */
		if (!xlat_exp_head(node->call.args)) return fr_sbuff_in_sprintf(out, "%%%s()", node->call.func->name);

		our_out = FR_SBUFF(out);
		FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "%%%s(", node->call.func->name);

		xlat_exp_foreach(node->call.args, arg) {
			if ((first_done) && (node->call.func->input_type == XLAT_INPUT_ARGS)) {
				FR_SBUFF_IN_CHAR_RETURN(&our_out, ',');
			}

			slen = xlat_fmt_print(&our_out, arg);
			if (slen < 0) return slen - fr_sbuff_used(&our_out);

			first_done = true;
		}

		FR_SBUFF_IN_CHAR_RETURN(&our_out, ')');
		return fr_sbuff_set(out, &our_out);
	}

	default:
		return 0;
	}
}

/** Output what we're currently expanding
 *
 * @param[in] request	The current request.
 * @param[in] node	Being processed.
 * @param[in] args	from previous expansion.
 * @param[in] line	Unused
 */
static inline void xlat_debug_log_expansion(request_t *request, xlat_exp_t const *node, fr_value_box_list_t const *args, UNUSED int line)
{
	if (node->flags.constant) return;

	if (!RDEBUG_ENABLED2) return;

	/*
	 *	Because it's difficult to keep track of what
	 *	the function was actually called with,
	 *	we print the concatenated arguments list as
	 *	well as the original fmt string.
	 */
	if ((node->type == XLAT_FUNC) && !xlat_is_literal(node->call.args)) {
		RDEBUG2("| %%%s(%pM)", node->call.func->name, args);
	} else {
		fr_sbuff_t *agg;

		FR_SBUFF_TALLOC_THREAD_LOCAL(&agg, 1024, SIZE_MAX);

		if (xlat_fmt_print(agg, node) < 0) {
			RERROR("Failed printing expansion");
			return;
		}
		RDEBUG2("| %s", fr_sbuff_start(agg)); /* print line number here for debugging */
	}
}

/** Output the list result of an expansion
 *
 * @param[in] request	The current request.
 * @param[in] node	which was expanded.
 * @param[in] result	of the expansion.
 */
static inline void xlat_debug_log_list_result(request_t *request, xlat_exp_t const *node, fr_value_box_list_t const *result)
{
	if (node->flags.constant) return;

	if (!RDEBUG_ENABLED2) return;

	RDEBUG2("| --> %pM", result);
}

/** Output the result of an expansion
 *
 * @param[in] request	The current request.
 * @param[in] node	which was expanded.
 * @param[in] result	of the expansion.
 */
static inline void xlat_debug_log_result(request_t *request, xlat_exp_t const *node, fr_value_box_t const *result)
{
	if (node->flags.constant) return;

	if (!RDEBUG_ENABLED2) return;

	RDEBUG2("| --> %pV", result);
}

/** Process an individual xlat argument value box group
 *
 * @param[in] ctx	to allocate any additional buffers in
 * @param[in,out] list	of value boxes representing one argument
 * @param[in] request	currently being processed
 * @param[in] name	of the function being called
 * @param[in] arg	specification of current argument
 * @param[in] arg_num	number of current argument in the argument specifications
 * @return
 *	- XLAT_ACTION_DONE on success.
 *	- XLAT_ACTION_FAIL on failure.
 */
static xlat_action_t xlat_process_arg_list(TALLOC_CTX *ctx, fr_value_box_list_t *list, request_t *request,
					   char const *name, xlat_arg_parser_t const *arg, unsigned int arg_num)
{
	fr_value_box_t *vb;

#define ESCAPE(_arg, _vb, _arg_num) \
do { \
	if ((_arg)->func && (!(_vb)->safe_for || !fr_value_box_is_safe_for((_vb), (_arg)->safe_for) || (_arg)->always_escape)) { \
		if ((_arg)->func(request, _vb, (_arg)->uctx) < 0) { \
			RPEDEBUG("Function \"%s\" failed escaping argument %u", name, _arg_num); \
			return XLAT_ACTION_FAIL; \
		} \
		fr_value_box_mark_safe_for((_vb), (_arg)->safe_for); \
	} \
} while (0)

	if (fr_value_box_list_empty(list)) {
		if (arg->required) {
			REDEBUG("Function \"%s\" is missing required argument %u", name, arg_num);
			return XLAT_ACTION_FAIL;
		}
		return XLAT_ACTION_DONE;
	}

	vb = fr_value_box_list_head(list);

	/*
	 *	Concatenate child boxes, casting to desired type,
	 *	then replace group vb with first child vb
	 */
	if (arg->concat) {
		if (arg->func) {
			do ESCAPE(arg, vb, arg_num); while ((vb = fr_value_box_list_next(list, vb)));

			vb = fr_value_box_list_head(list);	/* Reset */
		}

		if (fr_value_box_list_concat_in_place(ctx,
						      vb, list, arg->type,
						      FR_VALUE_BOX_LIST_FREE, true,
						      SIZE_MAX) < 0) {
			RPEDEBUG("Function \"%s\" failed concatenating arguments to type %s", name, fr_type_to_str(arg->type));
			return XLAT_ACTION_FAIL;
		}
		fr_assert(fr_value_box_list_num_elements(list) <= 1);

		return XLAT_ACTION_DONE;
	}

	/*
	 *	Only a single child box is valid here.  Check there is
	 *	just one, cast to the correct type
	 */
	if (arg->single) {
		if (fr_value_box_list_num_elements(list) > 1) {
			RPEDEBUG("Function \"%s\" was provided an incorrect number of values at argument %u, "
				 "expected %s got %u",
				 name, arg_num,
				 arg->required ? "0-1" : "1",
				 fr_value_box_list_num_elements(list));
			return XLAT_ACTION_FAIL;
		}

		ESCAPE(arg, vb, arg_num);

		if ((arg->type != FR_TYPE_VOID) && (vb->type != arg->type)) {
		cast_error:
			if (fr_value_box_cast_in_place(ctx, vb,
						       arg->type, NULL) < 0) {
				RPEDEBUG("Function \"%s\" failed to cast argument %u to type %s", name, arg_num, fr_type_to_str(arg->type));
				return XLAT_ACTION_FAIL;
			}
		}

		return XLAT_ACTION_DONE;
	}

	/*
	 *	We're neither concatenating nor do we only expect a single value,
	 *	cast all child values to the required type.
	 */
	if (arg->type != FR_TYPE_VOID) {
		do {
 			ESCAPE(arg, vb, arg_num);
			if (vb->type == arg->type) continue;
			if (fr_value_box_cast_in_place(ctx, vb,
						       arg->type, NULL) < 0) goto cast_error;
		} while ((vb = fr_value_box_list_next(list, vb)));

	/*
	 *	If it's not a void type we still need to escape the values
	 */
	} else if (arg->func) {
		do ESCAPE(arg, vb, arg_num); while ((vb = fr_value_box_list_next(list, vb)));
	}

#undef ESCAPE

	return XLAT_ACTION_DONE;
}


/** Process list of boxed values provided as input to an xlat
 *
 * Ensures that the value boxes passed to an xlat function match the
 * requirements listed in its "args", and escapes any tainted boxes
 * using the specified escaping routine.
 *
 * @param[in] ctx		in which to allocate any buffers.
 * @param[in,out] list		value boxes provided as input.
 * 				List will be modified in accordance to rules
 * 				provided in the args array.
 * @param[in] request		being processed.
 * @param[in] func		to call
 */
static inline CC_HINT(always_inline)
xlat_action_t xlat_process_args(TALLOC_CTX *ctx, fr_value_box_list_t *list,
				request_t *request, xlat_t const *func)
{
	xlat_arg_parser_t const	*arg_p = func->args;
	xlat_action_t		xa;
	fr_value_box_t		*vb, *next;

	/*
	 *	No args registered for this xlat
	 */
	if (!func->args) return XLAT_ACTION_DONE;

	/*
	 *	xlat needs no input processing just return.
	 */
	switch (func->input_type) {
	case XLAT_INPUT_UNPROCESSED:
		return XLAT_ACTION_DONE;

	/*
	 *	xlat takes all input as a single vb.
	 */
	case XLAT_INPUT_ARGS:
		vb = fr_value_box_list_head(list);
		while (arg_p->type != FR_TYPE_NULL) {
			/*
			 *	Separate check to see if the group
			 *	box is there.  Check in
			 *	xlat_process_arg_list verifies it
			 *	has a value.
			 */
			if (!vb) {
				if (arg_p->required) {
				missing:
					REDEBUG("Function \"%s\" is missing required argument %u",
						 func->name, (unsigned int)((arg_p - func->args) + 1));
					return XLAT_ACTION_FAIL;
				}

				/*
				 *	The argument isn't required.  Just omit it.  xlat_func_args_set() enforces
				 *	that optional arguments are at the end of the argument list.
				 */
				return XLAT_ACTION_DONE;
			}

			/*
			 *	Everything in the top level list should be
			 *	groups
			 */
			if (!fr_cond_assert(vb->type == FR_TYPE_GROUP)) return XLAT_ACTION_FAIL;

			/*
			 *	pre-advance, in case the vb is replaced
			 *	during processing.
			 */
			next = fr_value_box_list_next(list, vb);
			xa = xlat_process_arg_list(ctx, &vb->vb_group, request, func->name, arg_p,
						   (unsigned int)((arg_p - func->args) + 1));
			if (xa != XLAT_ACTION_DONE) return xa;

			/*
			 *	This argument doesn't exist.  That might be OK, or it may be a fatal error.
			 */
			if (fr_value_box_list_empty(&vb->vb_group)) {
				/*
				 *	Variadic rules deal with empty boxes differently...
				 */
				switch (arg_p->variadic) {
				case XLAT_ARG_VARIADIC_EMPTY_SQUASH:
					fr_value_box_list_talloc_free_head(list);
					goto do_next;

				case XLAT_ARG_VARIADIC_EMPTY_KEEP:
					goto empty_ok;

				case XLAT_ARG_VARIADIC_DISABLED:
					break;
				}

				/*
				 *	Empty groups for optional arguments are OK, we can just stop processing the list.
				 */
				if (!arg_p->required) {
					/*
					 *	If the caller doesn't care about the type, then we leave the
					 *	empty group there.
					 */
					if (arg_p->type == FR_TYPE_VOID) goto do_next;

					/*
					 *	The caller does care about the type, and we don't have any
					 *	matching data.  Omit this argument, and all arguments after it.
					 *
					 *	i.e. if the caller has 3 optional arguments, all
					 *	FR_TYPE_UINT8, and the first one is missing, then we MUST
					 *	either supply boxes all of FR_TYPE_UINT8, OR we supply nothing.
					 *
					 *	We can't supply a box of any other type, because the caller
					 *	has declared that it wants FR_TYPE_UINT8, and is naively
					 *	accessing the box as vb_uint8, hoping that it's being passed
					 *	the right thing.
					 */
					fr_value_box_list_talloc_free_head(list);
					break;
				}

				/*
				 *	If the caller is expecting a particular type, then getting nothing is
				 *	an error.
				 *
				 *	If the caller manually checks the input type, then we can leave it as
				 *	an empty group.
				 */
				if (arg_p->type != FR_TYPE_VOID) goto missing;
			}

		empty_ok:
			/*
			 *	In some cases we replace the current argument with the head of the group.
			 *
			 *	xlat_process_arg_list() has already done concatenations for us.
			 */
			if (arg_p->single || arg_p->concat) {
				fr_value_box_t *head = fr_value_box_list_pop_head(&vb->vb_group);

				/*
				 *	If we're meant to be smashing the argument
				 *	to a single box, but the group was empty,
				 *	add a null box instead so ordering is maintained
				 *	for subsequent boxes.
				 */
				if (!head) head = fr_value_box_alloc_null(ctx);
				fr_value_box_list_replace(list, vb, head);
				talloc_free(vb);
			}

		do_next:
			if (arg_p->variadic) {
				if (!next) break;
			} else {
				arg_p++;
			}
			vb = next;
		}
		break;
	}

	return XLAT_ACTION_DONE;
}

/** Validate that the return values from an xlat function match what it registered
 *
 * @param[in] request	The current request.
 * @param[in] func	that was called.
 * @param[in] returned	the output list of the function.
 * @param[in] pos	current position in the output list.
 * @return
 *	- true - If return values were correct.
 *	- false - If the return values were incorrect.
 */
static inline CC_HINT(nonnull(1,2,3))
bool xlat_process_return(request_t *request, xlat_t const *func, fr_value_box_list_t const *returned, fr_value_box_t *pos)
{
	unsigned int count = 0;

	/*
	 *  Nothing to validate.  We don't yet enforce that functions
	 *  must return at least one instance of their type.
	 */
	if (!pos || fr_type_is_void(func->return_type)) return true;

	if (fr_type_is_null(func->return_type)) {
		/* Dynamic expansion to get the right name */
		REDEBUG("%s return type registered as %s, but %s expansion produced data",
			func->name, func->name, fr_type_to_str(func->return_type));

		/* We are not forgiving for debug builds */
		fr_assert_fail("Treating invalid return type as fatal");

		return false;
	}

	do {
		if (pos->type != func->return_type) {
			REDEBUG("%s returned invalid result type at index %u.  Expected type %s, got type %s",
				func->name, count, fr_type_to_str(func->return_type), fr_type_to_str(pos->type));

			/* We are not forgiving for debug builds */
			fr_assert_fail("Treating invalid return type as fatal");
		}
		fr_value_box_mark_safe_for(pos, func->return_safe_for); /* Always set this */
		count++;
	} while ((pos = fr_value_box_list_next(returned, pos)));

	return true;
}

/** One letter expansions
 *
 * @param[in] ctx	to allocate boxed value, and buffers in.
 * @param[out] out	Where to write the boxed value.
 * @param[in] request	The current request.
 * @param[in] letter	to expand.
 * @return
 *	- #XLAT_ACTION_FAIL	on memory allocation errors.
 *	- #XLAT_ACTION_DONE	if we're done processing this node.
 *
 */
static inline CC_HINT(always_inline)
xlat_action_t xlat_eval_one_letter(TALLOC_CTX *ctx, fr_value_box_list_t *out,
				   request_t *request, char letter)
{

	char		buffer[64];
	struct tm	ts;
	time_t		now;
	fr_value_box_t	*value;

	now = fr_time_to_sec(request->packet->timestamp);

	switch (letter) {
	case '%':
		MEM(value = fr_value_box_alloc_null(ctx));
		if (fr_value_box_strdup(value, value, NULL, "%", false) < 0) return XLAT_ACTION_FAIL;
		break;

	/*
	 *	RADIUS request values
	 */

	case 'I': /* Request ID */
		MEM(value = fr_value_box_alloc(ctx, FR_TYPE_UINT32, NULL));
		value->datum.uint32 = request->packet->id;
		break;

	case 'n': /* Request number */
		MEM(value = fr_value_box_alloc(ctx, FR_TYPE_UINT64, NULL));
		value->datum.uint64 = request->number;
		break;

	case 's': /* First request in this sequence */
		MEM(value = fr_value_box_alloc(ctx, FR_TYPE_UINT64, NULL));
		value->datum.uint64 = request->seq_start;
		break;

	/*
	 *	Current time
	 */

	case 'c': /* Current epoch time seconds */
		/*
		 *	@todo - leave this as FR_TYPE_DATE, but add an enumv which changes the scale to
		 *	seconds?
		 */
		MEM(value = fr_value_box_alloc(ctx, FR_TYPE_UINT64, NULL));
		value->datum.uint64 = (uint64_t)fr_time_to_sec(fr_time());
		break;

	case 'C': /* Current epoch time microsecond component */
		/*
		 *	@todo - we probably should remove this now that we have FR_TYPE_DATE with scaling.
		 */
		MEM(value = fr_value_box_alloc(ctx, FR_TYPE_UINT64, NULL));
		value->datum.uint64 = (uint64_t)fr_time_to_usec(fr_time()) % 1000000;
		break;

	/*
	 *	Time of the current request
	 */

	case 'd': /* Request day */
		if (!localtime_r(&now, &ts)) {
		error:
			REDEBUG("Failed converting packet timestamp to localtime: %s", fr_syserror(errno));
			return XLAT_ACTION_FAIL;
		}

		MEM(value = fr_value_box_alloc(ctx, FR_TYPE_UINT8, NULL));
		value->datum.uint8 = ts.tm_mday;
		break;

	case 'D': /* Request date */
		if (!localtime_r(&now, &ts)) goto error;

		strftime(buffer, sizeof(buffer), "%Y%m%d", &ts);

		MEM(value = fr_value_box_alloc_null(ctx));
		if (fr_value_box_strdup(value, value, NULL, buffer, false) < 0) goto error;
		break;

	case 'e': /* Request second */
		if (!localtime_r(&now, &ts)) goto error;

		MEM(value = fr_value_box_alloc(ctx, FR_TYPE_UINT8, NULL));
		value->datum.uint8 = ts.tm_sec;
		break;

	case 'G': /* Request minute */
		if (!localtime_r(&now, &ts)) goto error;

		MEM(value = fr_value_box_alloc(ctx, FR_TYPE_UINT8, NULL));
		value->datum.uint8 = ts.tm_min;
		break;

	case 'H': /* Request hour */
		if (!localtime_r(&now, &ts)) goto error;

		MEM(value = fr_value_box_alloc(ctx, FR_TYPE_UINT8, NULL));
		value->datum.uint8 = ts.tm_hour;
		break;

	case 'l': /* Request timestamp as seconds since the epoch */
		/*
		 *	@todo - leave this as FR_TYPE_DATE, but add an enumv which changes the scale to
		 *	seconds?
		 */
		MEM(value = fr_value_box_alloc(ctx, FR_TYPE_UINT64, NULL));
		value->datum.uint64 = (uint64_t ) now;
		break;

	case 'm': /* Request month */
		if (!localtime_r(&now, &ts)) goto error;

		MEM(value = fr_value_box_alloc(ctx, FR_TYPE_UINT8, NULL));
		value->datum.uint8 = ts.tm_mon + 1;
		break;

	case 'M': /* Request time microsecond component */
		/*
		 *	@todo - we probably should remove this now that we have FR_TYPE_DATE with scaling.
		 */
		MEM(value = fr_value_box_alloc(ctx, FR_TYPE_UINT32, NULL));
		value->datum.uint32 = fr_time_to_msec(request->packet->timestamp) % 1000;
		break;

	case 'S': /* Request timestamp in SQL format */
		if (!localtime_r(&now, &ts)) goto error;

		strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &ts);

		MEM(value = fr_value_box_alloc_null(ctx));
		if (fr_value_box_strdup(value, value, NULL, buffer, false) < 0) goto error;
		break;

	case 't': /* Request timestamp in CTIME format */
	{
		char *p;

		CTIME_R(&now, buffer, sizeof(buffer));
		p = strchr(buffer, '\n');
		if (p) *p = '\0';

		MEM(value = fr_value_box_alloc_null(ctx));
		if (fr_value_box_strdup(value, value, NULL, buffer, false) < 0) goto error;
	}
		break;

	case 'T': /* Request timestamp in ISO format */
	{
		int len = 0;

		if (!gmtime_r(&now, &ts)) goto error;

		if (!(len = strftime(buffer, sizeof(buffer) - 1, "%Y-%m-%dT%H:%M:%S", &ts))) {
			REDEBUG("Failed converting packet timestamp to gmtime: Buffer full");
			return XLAT_ACTION_FAIL;
		}
		strcat(buffer, ".");
		len++;
		snprintf(buffer + len, sizeof(buffer) - len, "%03i",
			 (int) fr_time_to_msec(request->packet->timestamp) % 1000);

		MEM(value = fr_value_box_alloc_null(ctx));
		if (fr_value_box_strdup(value, value, NULL, buffer, false) < 0) goto error;
	}
		break;

	case 'Y': /* Request year */
		if (!localtime_r(&now, &ts)) goto error;

		MEM(value = fr_value_box_alloc(ctx, FR_TYPE_UINT16, NULL));

		value->datum.int16 = ts.tm_year + 1900;
		break;

	default:
		fr_assert_fail("%%%c is not a valid one letter expansion", letter);
		return XLAT_ACTION_FAIL;
	}

	fr_value_box_list_insert_tail(out, value);

	return XLAT_ACTION_DONE;
}

typedef struct {
	int			status;
	fr_value_box_list_t	list;
} xlat_exec_rctx_t;

static xlat_action_t xlat_exec_resume(UNUSED TALLOC_CTX *ctx, fr_dcursor_t *out,
				      xlat_ctx_t const *xctx,
				      UNUSED request_t *request, UNUSED fr_value_box_list_t *in)
{
	xlat_exec_rctx_t *rctx = talloc_get_type_abort(xctx->rctx, xlat_exec_rctx_t);

	if (rctx->status != 0) {
		fr_strerror_printf("Program failed with status %d", rctx->status);
		return XLAT_ACTION_FAIL;
	}

	fr_value_box_list_move((fr_value_box_list_t *)out->dlist, &rctx->list);

	return XLAT_ACTION_DONE;
}


/** Signal an xlat function
 *
 * @param[in] signal		function to call.
 * @param[in] exp		Xlat node that previously yielded.
 * @param[in] request		The current request.
 * @param[in] rctx		Opaque (to us), resume ctx provided by the xlat function
 *				when it yielded.
 * @param[in] action		What the request should do (the type of signal).
 */
void xlat_signal(xlat_func_signal_t signal, xlat_exp_t const *exp,
		 request_t *request, void *rctx, fr_signal_t action)
{
	xlat_thread_inst_t *t = xlat_thread_instance_find(exp);

	signal(XLAT_CTX(exp->call.inst, t->data, t->mctx, NULL, rctx), request, action);
}

static xlat_action_t xlat_null_resume(UNUSED TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out,
				      UNUSED xlat_ctx_t const *xctx,
				      UNUSED request_t *request, UNUSED fr_value_box_list_t *in)
{
	return XLAT_ACTION_DONE;
}

/** Call an xlat's resumption method
 *
 * @param[in] ctx		to allocate value boxes in.
 * @param[out] out		a list of #fr_value_box_t to append to.
 * @param[out] child		to evaluate. If a child needs to be evaluated
 *				by the caller, we return XLAT_ACTION_PUSH_CHILD
 *				and place the child to be evaluated here.
 *				Once evaluation is complete, the caller
 *				should call us with the same #xlat_exp_t and the
 *				result of the nested evaluation in result.
 * @param[in] request		the current request.
 * @param[in] head		of the list to evaluate
 * @param[in,out] in		xlat node to evaluate. Advanced as we process
 *				additional #xlat_exp_t.
 * @param[in] result		Previously expanded arguments to this xlat function.
 * @param[in] resume		function to call.
 * @param[in] rctx		Opaque (to us), resume ctx provided by xlat function
 *				when it yielded.
 */
xlat_action_t xlat_frame_eval_resume(TALLOC_CTX *ctx, fr_dcursor_t *out,
				     xlat_exp_head_t const **child,
				     request_t *request,  xlat_exp_head_t const *head, xlat_exp_t const **in,
				     fr_value_box_list_t *result, xlat_func_t resume, void *rctx)
{
	xlat_action_t		xa;
	xlat_exp_t const	*node = *in;

	/*
	 *	It's important that callbacks leave the result list
	 *	in a valid state, as it leads to all kinds of hard
	 *	to debug problems if they free or change elements
	 *	and don't remove them from the list.
	 */
	VALUE_BOX_LIST_VERIFY(result);

	if (node->type != XLAT_FUNC) {
		xa = resume(ctx, out, XLAT_CTX(NULL, NULL, NULL, NULL, rctx), request, result);
	} else {
		xlat_thread_inst_t *t;
		t = xlat_thread_instance_find(node);
		xa = resume(ctx, out, XLAT_CTX(node->call.inst->data, t->data, t->mctx, NULL, rctx), request, result);
		VALUE_BOX_LIST_VERIFY(result);

		RDEBUG2("| %%%s(...)", node->call.func->name);
	}

	switch (xa) {
	case XLAT_ACTION_YIELD:
		RDEBUG2("| (YIELD)");
		return xa;

	case XLAT_ACTION_DONE:
		if (unlang_xlat_yield(request, xlat_null_resume, NULL, 0, NULL) != XLAT_ACTION_YIELD) return XLAT_ACTION_FAIL;

		fr_dcursor_next(out);		/* Wind to the start of this functions output */
		if (node->call.func) {
			RDEBUG2("| --> %pV", fr_dcursor_current(out));
			if (!xlat_process_return(request, node->call.func, (fr_value_box_list_t *)out->dlist,
					 fr_dcursor_current(out))) return XLAT_ACTION_FAIL;
		}

		/*
		 *	It's easier if we get xlat_frame_eval to continue evaluating the frame.
		 */
		*in = xlat_exp_next(head, *in);	/* advance */
		return xlat_frame_eval(ctx, out, child, request, head, in);

	case XLAT_ACTION_PUSH_CHILD:
	case XLAT_ACTION_PUSH_UNLANG:
	case XLAT_ACTION_FAIL:
		break;
	}

	return xa;
}

/** Process the result of a previous nested expansion
 *
 * @param[in] ctx		to allocate value boxes in.
 * @param[out] out		a list of #fr_value_box_t to append to.
 * @param[out] child		to evaluate.  If a child needs to be evaluated
 *				by the caller, we return XLAT_ACTION_PUSH_CHILD
 *				and place the child to be evaluated here.
 *				Once evaluation is complete, the caller
 *				should call us with the same #xlat_exp_t and the
 *				result of the nested evaluation in result.
 * @param[in] request		the current request.
 * @param[in] head		of the list to evaluate
 * @param[in,out] in		xlat node to evaluate.  Advanced as we process
 *				additional #xlat_exp_t.
 * @param[in] env_data		Expanded call env.
 * @param[in] result		of a previous nested evaluation.
 */
xlat_action_t xlat_frame_eval_repeat(TALLOC_CTX *ctx, fr_dcursor_t *out,
				     xlat_exp_head_t const **child,
				     request_t *request, xlat_exp_head_t const *head, xlat_exp_t const **in,
				     void *env_data, fr_value_box_list_t *result)
{
	xlat_exp_t const	*node = *in;

	fr_dcursor_tail(out);	/* Needed for reentrant behaviour and debugging */

	switch (node->type) {
	case XLAT_FUNC:
	{
		xlat_action_t		xa;
		xlat_thread_inst_t	*t;
		fr_value_box_list_t	result_copy;

		t = xlat_thread_instance_find(node);
		fr_assert(t);

		XLAT_DEBUG("** [%i] %s(func-async) - %%%s(%pM)",
			   unlang_interpret_stack_depth(request), __FUNCTION__,
			   node->fmt, result);

		VALUE_BOX_LIST_VERIFY(result);

		/*
		 *	Always need to init and free the
		 *	copy list as debug level could change
		 *	when the xlat function executes.
		 */
		fr_value_box_list_init(&result_copy);

		/*
		 *	Need to copy the input list in case
		 *	the async function mucks with it.
		 */
		if (RDEBUG_ENABLED2) fr_value_box_list_acopy(unlang_interpret_frame_talloc_ctx(request), &result_copy, result);
		xa = xlat_process_args(ctx, result, request, node->call.func);
		if (xa == XLAT_ACTION_FAIL) {
			fr_value_box_list_talloc_free(&result_copy);
			return xa;
		}

		VALUE_BOX_LIST_VERIFY(result);
		xa = node->call.func->func(ctx, out,
					   XLAT_CTX(node->call.inst->data, t->data, t->mctx, env_data, NULL),
					   request, result);
		VALUE_BOX_LIST_VERIFY(result);

		if (RDEBUG_ENABLED2) {
			REXDENT();
			xlat_debug_log_expansion(request, *in, &result_copy, __LINE__);
			RINDENT();
		}
		fr_value_box_list_talloc_free(&result_copy);

		switch (xa) {
		case XLAT_ACTION_FAIL:
			return xa;

		case XLAT_ACTION_PUSH_CHILD:
			RDEBUG3("|   -- CHILD");
			return xa;

		case XLAT_ACTION_PUSH_UNLANG:
			RDEBUG3("|   -- UNLANG");
			return xa;

		case XLAT_ACTION_YIELD:
			RDEBUG3("|   -- YIELD");
			return xa;

		case XLAT_ACTION_DONE:				/* Process the result */
			fr_dcursor_next(out);
			REXDENT();
			xlat_debug_log_result(request, *in, fr_dcursor_current(out));
			if (!xlat_process_return(request, node->call.func,
						 (fr_value_box_list_t *)out->dlist,
						 fr_dcursor_current(out))) return XLAT_ACTION_FAIL;
			RINDENT();
			break;
		}
	}
		break;

	case XLAT_GROUP:
	{
		fr_value_box_t	*arg;

		/*
		 *	We'd like to do indent / exdent for groups, but that also involves fixing all of the
		 *	error paths.  Which we won't do right now.
		 */
		XLAT_DEBUG("** [%i] %s(child) - continuing %%{%s ...}", unlang_interpret_stack_depth(request), __FUNCTION__,
			   node->fmt);

		MEM(arg = fr_value_box_alloc(ctx, FR_TYPE_GROUP, NULL));

		if (!fr_value_box_list_empty(result)) {
			VALUE_BOX_LIST_VERIFY(result);
			fr_value_box_list_move(&arg->vb_group, result);
		}

//		xlat_debug_log_expansion(request, *in, NULL, __LINE__);
//		xlat_debug_log_result(request, *in, arg);

		VALUE_BOX_VERIFY(arg);

		fr_dcursor_insert(out, arg);
	}
		break;

	case XLAT_TMPL:
		fr_assert(tmpl_is_exec(node->vpt));

		if (tmpl_eval_cast_in_place(result, request, node->vpt) < 0) {
			fr_value_box_list_talloc_free(result);
			return XLAT_ACTION_FAIL;
		}

		/*
		 *	First entry is the command to run.  Subsequent entries are the options to pass to the
		 *	command.
		 */
		fr_value_box_list_move((fr_value_box_list_t *)out->dlist, result);
		break;

	default:
		fr_assert(0);
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	It's easier if we get xlat_frame_eval to continue evaluating the frame.
	 */
	*in = xlat_exp_next(head, *in);	/* advance */
	return xlat_frame_eval(ctx, out, child, request, head, in);
}

/** Converts xlat nodes to value boxes
 *
 * Evaluates a single level of expansions.
 *
 * @param[in] ctx		to allocate value boxes in.
 * @param[out] out		a list of #fr_value_box_t to append to.
 * @param[out] child		to evaluate.  If a child needs to be evaluated
 *				by the caller, we return XLAT_ACTION_PUSH_CHILD
 *				and place the child to be evaluated here.
 *				Once evaluation is complete, the caller
 *				should call us with the same #xlat_exp_t and the
 *				result of the nested evaluation in result.
 * @param[in] request		the current request.
 * @param[in] head		of the list to evaluate
 * @param[in,out] in		xlat node to evaluate.  Advanced as we process
 *				additional #xlat_exp_t.
 * @return
 *	- XLAT_ACTION_PUSH_CHILD if we need to evaluate a deeper level of nested.
 *	  child will be filled with the node that needs to be evaluated.
 *	  call #xlat_frame_eval_repeat on this node, once there are results
 *	  from the nested expansion.
 *	- XLAT_ACTION_YIELD a resumption frame was pushed onto the stack by an
 *	  xlat function and we need to wait for the request to be resumed
 *	  before continuing.
 *	- XLAT_ACTION_DONE we're done, pop the frame.
 *	- XLAT_ACTION_FAIL an xlat module failed.
 */
xlat_action_t xlat_frame_eval(TALLOC_CTX *ctx, fr_dcursor_t *out, xlat_exp_head_t const **child,
			      request_t *request, xlat_exp_head_t const *head, xlat_exp_t const **in)
{
	xlat_action_t		xa = XLAT_ACTION_DONE;
	xlat_exp_t const       	*node;
	fr_value_box_list_t	result;		/* tmp list so debug works correctly */
	fr_value_box_t		*value;

	fr_value_box_list_init(&result);

	*child = NULL;

	if (!*in) return XLAT_ACTION_DONE;

	XLAT_DEBUG("** [%i] %s >> entered", unlang_interpret_stack_depth(request), __FUNCTION__);

	for (node = *in; node; node = xlat_exp_next(head, node)) {
	     	*in = node;		/* Update node in our caller */
		fr_dcursor_tail(out);	/* Needed for debugging */
		VALUE_BOX_LIST_VERIFY((fr_value_box_list_t *)out->dlist);

		fr_assert(fr_value_box_list_num_elements(&result) == 0);	/* Should all have been moved */

		switch (node->type) {
		case XLAT_BOX:
			XLAT_DEBUG("** [%i] %s(value_box) - %s", unlang_interpret_stack_depth(request), __FUNCTION__, node->fmt);

			/*
			 *	Empty boxes are only allowed if
			 *      they're the only node in the expansion.
			 *
			 *	If they're found anywhere else the xlat
			 *	parser has an error.
			 */
			fr_assert(((node == *in) && !xlat_exp_next(head, node)) || (talloc_array_length(node->fmt) > 1));

			/*
			 *	We unfortunately need to dup the buffer
			 *	because references aren't threadsafe.
			 */
			MEM(value = fr_value_box_alloc_null(ctx));
			if (fr_value_box_copy(value, value, &node->data) < 0) goto fail;
			fr_dcursor_append(out, value);
			continue;

		case XLAT_ONE_LETTER:
			XLAT_DEBUG("** [%i] %s(one-letter) - %%%s", unlang_interpret_stack_depth(request), __FUNCTION__,
				   node->fmt);

			xlat_debug_log_expansion(request, node, NULL, __LINE__);
			if (xlat_eval_one_letter(ctx, &result, request, node->fmt[0]) == XLAT_ACTION_FAIL) {
			fail:
				fr_value_box_list_talloc_free(&result);
				xa = XLAT_ACTION_FAIL;
				goto finish;
			}
			xlat_debug_log_list_result(request, *in, &result);
			fr_value_box_list_move((fr_value_box_list_t *)out->dlist, &result);
			continue;

		case XLAT_TMPL:
			if (tmpl_is_data(node->vpt)) {
				XLAT_DEBUG("** [%i] %s(value) - %s", unlang_interpret_stack_depth(request), __FUNCTION__,
					   node->vpt->name);

				MEM(value = fr_value_box_alloc(ctx, tmpl_value_type(node->vpt), NULL));

				fr_value_box_copy(value, value, tmpl_value(node->vpt));	/* Also dups taint */
				fr_value_box_list_insert_tail(&result, value);

				/*
				 *	Cast the results if necessary.
				 */
				if (tmpl_eval_cast_in_place(&result, request, node->vpt) < 0) goto fail;

				fr_value_box_list_move((fr_value_box_list_t *)out->dlist, &result);
				continue;

			} else if (tmpl_is_attr(node->vpt)) {
				if (node->fmt[0] == '&') {
					XLAT_DEBUG("** [%i] %s(attribute) - %s", unlang_interpret_stack_depth(request), __FUNCTION__,
						   node->fmt);
				} else {
					XLAT_DEBUG("** [%i] %s(attribute) - %%{%s}", unlang_interpret_stack_depth(request), __FUNCTION__,
						   node->fmt);
				}
				xlat_debug_log_expansion(request, node, NULL, __LINE__);

				if (tmpl_eval_pair(ctx, &result, request, node->vpt) < 0) goto fail;

			} else if (tmpl_is_exec(node->vpt) || tmpl_is_xlat(node->vpt)) {
				xlat_exec_rctx_t *rctx;

				/*
				 *	Allocate and initialize the output context, with value-boxes, exec status, etc.
				 */
				MEM(rctx = talloc_zero(unlang_interpret_frame_talloc_ctx(request), xlat_exec_rctx_t));
				fr_value_box_list_init(&rctx->list);

				xlat_debug_log_expansion(request, node, NULL, __LINE__);

				if (unlang_xlat_yield(request, xlat_exec_resume, NULL, 0, rctx) != XLAT_ACTION_YIELD) goto fail;

				if (unlang_tmpl_push(ctx, &rctx->list, request, node->vpt,
						     TMPL_ARGS_EXEC(NULL, fr_time_delta_from_sec(EXEC_TIMEOUT),
						     		    false, &rctx->status)) < 0) goto fail;

				xa = XLAT_ACTION_PUSH_UNLANG;
				goto finish;

			} else {
#ifdef NDEBUG
				xa = XLAT_ACTION_FAIL;
				goto finish;
#endif

				/*
				 *	Either this should have been handled previously, or we need to write
				 *	code to deal with this case.
				 */
				fr_assert(0);
			}

			xlat_debug_log_list_result(request, node, &result);
			fr_value_box_list_move((fr_value_box_list_t *)out->dlist, &result);
			continue;

		case XLAT_VIRTUAL:
		{
			XLAT_DEBUG("** [%i] %s(virtual) - %%{%s}", unlang_interpret_stack_depth(request), __FUNCTION__,
				   node->fmt);

			xlat_debug_log_expansion(request, node, NULL, __LINE__);
			xa = node->call.func->func(ctx, out,
						   XLAT_CTX(node->call.func->uctx, NULL, NULL, NULL, NULL),
						   request, NULL);
			fr_dcursor_next(out);

			xlat_debug_log_result(request, node, fr_dcursor_current(out));
		}
			continue;

		case XLAT_FUNC:
			XLAT_DEBUG("** [%i] %s(func) - %%%s(...)", unlang_interpret_stack_depth(request), __FUNCTION__,
				   node->fmt);

			/*
			 *	Hand back the child node to the caller
			 *	for evaluation.
			 */
			if (xlat_exp_head(node->call.args)) {
				*child = node->call.args;
				xa = XLAT_ACTION_PUSH_CHILD;
				goto finish;
			}

			/*
			 *	If there's no children we can just
			 *	call the function directly.
			 */
			xa = xlat_frame_eval_repeat(ctx, out, child, request, head, in, NULL, &result);
			if (xa != XLAT_ACTION_DONE || (!*in)) goto finish;
			continue;

#ifdef HAVE_REGEX
		case XLAT_REGEX:
		{
			char *str = NULL;

			XLAT_DEBUG("** [%i] %s(regex) - %%{%s}", unlang_interpret_stack_depth(request), __FUNCTION__,
				   node->fmt);

			xlat_debug_log_expansion(request, node, NULL, __LINE__);
			MEM(value = fr_value_box_alloc_null(ctx));
			if (regex_request_to_sub(ctx, &str, request, node->regex_index) < 0) {
				talloc_free(value);
				continue;
			}
			fr_value_box_bstrdup_buffer_shallow(NULL, value, NULL, str, false);

			xlat_debug_log_result(request, node, value);
			fr_dcursor_append(out, value);
		}
			continue;
#endif

		case XLAT_GROUP:
			XLAT_DEBUG("** [%i] %s(child) - %%{%s ...}", unlang_interpret_stack_depth(request), __FUNCTION__,
				   node->fmt);
			if (!node->group) return XLAT_ACTION_DONE;

			/*
			 *	Hand back the child node to the caller
			 *	for evaluation.
			 */
			*child = node->group;
			xa = XLAT_ACTION_PUSH_CHILD;
			goto finish;

		/*
		 *	Should have been fixed up during pass2
		 */
		case XLAT_INVALID:
		case XLAT_FUNC_UNRESOLVED:
		case XLAT_VIRTUAL_UNRESOLVED:
			fr_assert(0);
			return XLAT_ACTION_FAIL;
		}
	}

finish:
	VALUE_BOX_LIST_VERIFY((fr_value_box_list_t *)out->dlist);
	XLAT_DEBUG("** [%i] %s << %s", unlang_interpret_stack_depth(request),
		   __FUNCTION__, fr_table_str_by_value(xlat_action_table, xa, "<INVALID>"));

	return xa;
}

static ssize_t xlat_eval_sync(TALLOC_CTX *ctx, char **out, request_t *request, xlat_exp_head_t const * const head,
			      xlat_escape_legacy_t escape, void const *escape_ctx)
{
	fr_value_box_list_t	result;
	bool			success = false;
	TALLOC_CTX		*pool = talloc_new(NULL);
	rlm_rcode_t		rcode;
	char			*str;

	XLAT_DEBUG("xlat_eval_sync");

	*out = NULL;

	fr_value_box_list_init(&result);
	/*
	 *	Use the unlang stack to evaluate
	 *	the async xlat up until the point
	 *	that it needs to yield.
	 */
	if (unlang_xlat_push(pool, &success, &result, request, head, true) < 0) {
		talloc_free(pool);
		return -1;
	}

	rcode = unlang_interpret_synchronous(unlang_interpret_event_list(request), request);
	switch (rcode) {
	default:
		break;

	case RLM_MODULE_REJECT:
	case RLM_MODULE_FAIL:
	eval_failed:
		talloc_free(pool);
		return -1;
	}
	if (!success) goto eval_failed;

	if (!fr_value_box_list_empty(&result)) {
		if (escape) {
			fr_value_box_t *vb = NULL;

			/*
			 *	For tainted boxes perform the requested escaping
			 */
			while ((vb = fr_value_box_list_next(&result, vb))) {
				fr_value_box_entry_t entry;
				size_t len, real_len;
				char *escaped;

				if (!vb->tainted) continue;

				if (fr_value_box_cast_in_place(pool, vb, FR_TYPE_STRING, NULL) < 0) {
					RPEDEBUG("Failed casting result to string");
				error:
					talloc_free(pool);
					return -1;
				}

				len = vb->vb_length * 3;
				MEM(escaped = talloc_array(pool, char, len));
				real_len = escape(request, escaped, len, vb->vb_strvalue, UNCONST(void *, escape_ctx));

				entry = vb->entry;
				fr_value_box_clear_value(vb);
				fr_value_box_bstrndup(vb, vb, NULL, escaped, real_len, false);
				vb->entry = entry;

				talloc_free(escaped);
			}
		}

		str = fr_value_box_list_aprint(ctx, &result, NULL, NULL);
		if (!str) {
			talloc_free(pool);
			goto error;
		}
	} else {
		str = talloc_typed_strdup(ctx, "");
	}
	talloc_free(pool);	/* Memory should be in new ctx */

	*out = str;

	return talloc_array_length(str) - 1;
}

/** Replace %whatever in a string.
 *
 * See 'doc/unlang/xlat.adoc' for more information.
 *
 * @param[in] ctx		to allocate expansion buffers in.
 * @param[out] out		Where to write pointer to output buffer.
 * @param[in] outlen		Size of out.
 * @param[in] request		current request.
 * @param[in] head		the xlat structure to expand
 * @param[in] escape		function to escape final value e.g. SQL quoting.
 * @param[in] escape_ctx	pointer to pass to escape function.
 * @return length of string written @bug should really have -1 for failure.
 */
static ssize_t _xlat_eval_compiled(TALLOC_CTX *ctx, char **out, size_t outlen, request_t *request,
				   xlat_exp_head_t const *head, xlat_escape_legacy_t escape, void const *escape_ctx)
{
	char *buff;
	ssize_t slen;

	fr_assert(head != NULL);

	slen = xlat_eval_sync(ctx, &buff, request, head, escape, escape_ctx);
	if (slen < 0) {
		fr_assert(buff == NULL);
		if (*out) **out = '\0';
		return slen;
	}

	/*
	 *	If out doesn't point to an existing buffer
	 *	copy the pointer to our buffer over.
	 */
	if (!*out) {
		*out = buff;
		return slen;
	}

	if ((size_t)slen >= outlen) {
		fr_strerror_const("Insufficient output buffer space");
		return -1;
	}

	/*
	 *	Otherwise copy the talloced buffer to the fixed one.
	 */
	memcpy(*out, buff, slen);
	(*out)[slen] = '\0';
	talloc_free(buff);

	return slen;
}

/** Replace %whatever in a string.
 *
 * See 'doc/unlang/xlat.adoc' for more information.
 *
 * @param[in] ctx		to allocate expansion buffers in.
 * @param[out] out		Where to write pointer to output buffer.
 * @param[in] outlen		Size of out.
 * @param[in] request		current request.
 * @param[in] fmt		string to expand.
 * @param[in] escape		function to escape final value e.g. SQL quoting.
 * @param[in] escape_ctx	pointer to pass to escape function.
 * @return length of string written @bug should really have -1 for failure.
 */
static CC_HINT(nonnull (2, 4, 5))
ssize_t _xlat_eval(TALLOC_CTX *ctx, char **out, size_t outlen, request_t *request, char const *fmt,
		   xlat_escape_legacy_t escape, void const *escape_ctx)
{
	ssize_t len;
	xlat_exp_head_t *head;

	RINDENT();

	/*
	 *	Give better errors than the old code.
	 */
	len = xlat_tokenize(ctx, &head,
			    &FR_SBUFF_IN(fmt, strlen(fmt)),
			    NULL,
			    &(tmpl_rules_t){
				    .attr = {
					    .dict_def = request->dict,
					    .list_def = request_attr_request,
				    },
				    .xlat = {
					    .runtime_el = unlang_interpret_event_list(request),
				    },
				    .at_runtime = true,
			    }, 0);
	if (len == 0) {
		if (*out) {
			**out = '\0';
		} else {
			*out = talloc_zero_array(ctx, char, 1);
		}
		REXDENT();
		return 0;
	}

	if (len < 0) {
		REMARKER(fmt, -(len), "%s", fr_strerror());
		if (*out) **out = '\0';
		REXDENT();
		return -1;
	}

	len = _xlat_eval_compiled(ctx, out, outlen, request, head, escape, escape_ctx);
	talloc_free(head);

	REXDENT();

	return len;
}

ssize_t xlat_eval(char *out, size_t outlen, request_t *request,
		  char const *fmt, xlat_escape_legacy_t escape, void const *escape_ctx)
{
	fr_assert(instance_count);

	return _xlat_eval(request, &out, outlen, request, fmt, escape, escape_ctx);
}

ssize_t xlat_eval_compiled(char *out, size_t outlen, request_t *request,
			   xlat_exp_head_t const *xlat, xlat_escape_legacy_t escape, void const *escape_ctx)
{
	fr_assert(instance_count);

	return _xlat_eval_compiled(request, &out, outlen, request, xlat, escape, escape_ctx);
}

ssize_t xlat_aeval(TALLOC_CTX *ctx, char **out, request_t *request, char const *fmt,
		   xlat_escape_legacy_t escape, void const *escape_ctx)
{
	fr_assert(instance_count);

	*out = NULL;
	return _xlat_eval(ctx, out, 0, request, fmt, escape, escape_ctx);
}

ssize_t xlat_aeval_compiled(TALLOC_CTX *ctx, char **out, request_t *request,
			    xlat_exp_head_t const *xlat, xlat_escape_legacy_t escape, void const *escape_ctx)
{
	fr_assert(instance_count);

	*out = NULL;
	return _xlat_eval_compiled(ctx, out, 0, request, xlat, escape, escape_ctx);
}


/** Synchronous compile xlat_tokenize_argv() into argv[] array.
 *
 *  This is mostly for synchronous evaluation.
 *
 * @param ctx		The talloc_ctx
 * @param[out] argv	the argv array of resulting strings, size is argc + 1
 * @param request	the request
 * @param head		from xlat_tokenize_argv()
 * @param escape	escape function
 * @param escape_ctx	context for escape function
 * @return
 *	- <=0 on error	number indicates which argument caused the problem
 *	- >0 on success	which is argc to the corresponding argv
 */
int xlat_aeval_compiled_argv(TALLOC_CTX *ctx, char ***argv, request_t *request,
			     xlat_exp_head_t const *head, xlat_escape_legacy_t escape, void const *escape_ctx)
{
	int			i;
	ssize_t			slen;
	char			**my_argv;
	size_t			count;

	count = 0;
	xlat_exp_foreach(head, node) {
		count++;
	}

	MEM(my_argv = talloc_zero_array(ctx, char *, count + 1));
	*argv = my_argv;

	fr_assert(instance_count);

	i = 0;
	xlat_exp_foreach(head, node) {
		my_argv[i] = NULL;

		slen = _xlat_eval_compiled(my_argv, &my_argv[i], 0, request, node->group, escape, escape_ctx);
		if (slen < 0) return -i;

		i++;
	}

	return count;
}

/** Turn xlat_tokenize_argv() into an argv[] array, and nuke the input list.
 *
 *  This is mostly for async use.
 */
int xlat_flatten_compiled_argv(TALLOC_CTX *ctx, xlat_exp_head_t ***argv, xlat_exp_head_t *head)
{
	int			i;
	xlat_exp_head_t		**my_argv;
	size_t			count;

	count = 0;
	xlat_exp_foreach(head, node) {
		count++;
	}

	MEM(my_argv = talloc_zero_array(ctx, xlat_exp_head_t *, count + 1));
	*argv = my_argv;

	fr_assert(instance_count);

	i = 0;
	xlat_exp_foreach(head, node) {
		fr_assert(node->type == XLAT_GROUP);
		my_argv[i++] = talloc_steal(my_argv, node->group);
	}

	fr_value_box_list_talloc_free((fr_value_box_list_t *)&head->dlist);

	return count;
}

/** Walk over all xlat nodes (depth first) in a xlat expansion, calling a callback
 *
 * @param[in] head	to evaluate.
 * @param[in] walker	callback to pass nodes to.
 * @param[in] type	if > 0 a mask of types to call walker for.
 * @param[in] uctx	to pass to walker.
 * @return
 *	- 0 on success (walker always returned 0).
 *	- <0 if walker returned <0.
 */
int xlat_eval_walk(xlat_exp_head_t *head, xlat_walker_t walker, xlat_type_t type, void *uctx)
{
	int		ret;

	/*
	 *	Iterate over nodes at the same depth
	 */
	xlat_exp_foreach(head, node) {
		switch (node->type){
		case XLAT_FUNC:
			/*
			 *	Evaluate the function's arguments
			 *	first, as they may get moved around
			 *	when the function is instantiated.
			 */
			if (xlat_exp_head(node->call.args)) {
				ret = xlat_eval_walk(node->call.args, walker, type, uctx);
				if (ret < 0) return ret;
			}

			if (!type || (type & XLAT_FUNC)) {
				ret = walker(node, uctx);
				if (ret < 0) return ret;
			}
			break;

		case XLAT_FUNC_UNRESOLVED:
			if (xlat_exp_head(node->call.args)) {
				ret = xlat_eval_walk(node->call.args, walker, type, uctx);
				if (ret < 0) return ret;
			}

			if (!type || (type & XLAT_FUNC_UNRESOLVED)) {
				ret = walker(node, uctx);
				if (ret < 0) return ret;
			}
			break;

		case XLAT_GROUP:
			if (!type || (type & XLAT_GROUP)) {
				ret = walker(node, uctx);
				if (ret < 0) return ret;
				if (ret > 0) continue;
			}

			/*
			 *	Evaluate the child.
			 */
			ret = xlat_eval_walk(node->group, walker, type, uctx);
			if (ret < 0) return ret;
			break;

		default:
			if (!type || (type & node->type)) {
				ret = walker(node, uctx);
				if (ret < 0) return ret;
			}
			break;
		}
	}

	return 0;
}

int xlat_eval_init(void)
{
	fr_assert(!instance_count);

	if (instance_count > 0) {
		instance_count++;
		return 0;
	}

	instance_count++;

	if (fr_dict_autoload(xlat_eval_dict) < 0) {
		PERROR("%s", __FUNCTION__);
		return -1;
	}

	if (fr_dict_attr_autoload(xlat_eval_dict_attr) < 0) {
		PERROR("%s", __FUNCTION__);
		fr_dict_autofree(xlat_eval_dict);
		return -1;
	}

	return 0;
}

void xlat_eval_free(void)
{
	fr_assert(instance_count > 0);

	if (--instance_count > 0) return;

	fr_dict_autofree(xlat_eval_dict);
}
