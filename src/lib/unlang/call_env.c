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
 * @file unlang/call_env.c
 * @brief Call environment parsing functions
 *
 * @copyright 2023 Network RADIUS SAS (legal@networkradius.com)
 */

RCSID("$Id$")

#include <freeradius-devel/server/log.h>
#include <freeradius-devel/server/cf_util.h>
#include <freeradius-devel/server/tmpl.h>
#include <freeradius-devel/server/rcode.h>
#include <freeradius-devel/server/section.h>
#include <freeradius-devel/server/main_config.h>
#include <freeradius-devel/unlang/action.h>
#include <freeradius-devel/unlang/tmpl.h>
#include <freeradius-devel/unlang/function.h>
#include <freeradius-devel/unlang/interpret.h>
#include <freeradius-devel/unlang/call_env.h>

#include <talloc.h>
#include "call_env.h"

struct call_env_parsed_s {
	call_env_parsed_entry_t		entry;		//!< Entry in list of parsed call_env_parsers.

	union {
		tmpl_t const			*tmpl;		//!< Tmpl produced from parsing conf pair.
		fr_value_box_t const		*vb;		//!< Value box produced from parsing conf pair.
		void const			*ptr;		//!< Data produced from parsing conf pair.
	} data;

	size_t				count;		//!< Number of CONF_PAIRs found, matching the #call_env_parser_t.
	size_t				multi_index;	//!< Array index for this instance.
	call_env_parser_t const		*rule;		//!< Used to produce this.
};
FR_DLIST_FUNCS(call_env_parsed, call_env_parsed_t, entry)

#if defined(DEBUG_CALL_ENV)
#  define CALL_ENV_DEBUG(_ci, fmt, ...) cf_log_debug(_ci, fmt, ##__VA_ARGS__)
#else
#  define CALL_ENV_DEBUG(_ci, ...)
#endif

/** Parse the result of call_env tmpl expansion
 */
static inline CC_HINT(always_inline)
call_env_result_t call_env_result(TALLOC_CTX *ctx, request_t *request, void *out, call_env_parsed_t const *env,
				  fr_value_box_list_t *tmpl_expanded)
{
	fr_value_box_t	*vb;

	vb = fr_value_box_list_head(tmpl_expanded);
	if (!vb) {
		if (!call_env_nullable(env->rule->flags)) {
			RPEDEBUG("Failed to evaluate required module option %s = %s", env->rule->name, env->data.tmpl->name);
			return CALL_ENV_MISSING;
		}
		return CALL_ENV_SUCCESS;
	}

	/*
	 *	Concatenate multiple boxes if needed
	 */
	if ((call_env_concat(env->rule->flags) || call_env_attribute(env->rule->flags)) &&
	    (env->rule->pair.cast_type != FR_TYPE_VOID) &&
	    fr_value_box_list_concat_in_place(vb, vb, tmpl_expanded, env->rule->pair.cast_type,
					      FR_VALUE_BOX_LIST_FREE, true, SIZE_MAX) < 0 ) {
		RPEDEBUG("Failed concatenating values for %s", env->rule->name);
		return CALL_ENV_INVALID;
	}

	if (call_env_single(env->rule->flags) && (fr_value_box_list_num_elements(tmpl_expanded) > 1)) {
		RPEDEBUG("%u values found for %s.  Only one is allowed",
			 fr_value_box_list_num_elements(tmpl_expanded), env->rule->name);
		return CALL_ENV_INVALID;
	}

	while ((vb = fr_value_box_list_pop_head(tmpl_expanded))) {
		switch (env->rule->pair.type) {
		case CALL_ENV_RESULT_TYPE_VALUE_BOX:
			fr_value_box_copy_shallow(ctx, (fr_value_box_t *)(out), vb);
			break;

		case CALL_ENV_RESULT_TYPE_VALUE_BOX_LIST:
			if (!fr_value_box_list_initialised((fr_value_box_list_t *)out)) fr_value_box_list_init((fr_value_box_list_t *)out);
			fr_value_box_list_insert_tail((fr_value_box_list_t *)out, vb);
			break;

		default:
			fr_assert(0);
			break;
		}
	}

	return CALL_ENV_SUCCESS;
}

/** Context to keep track of expansion of call environments
 *
 */
typedef struct {
	call_env_result_t			*result;		//!< Where to write the return code of callenv expansion.
	unlang_result_t				expansion_result;	//!< The result of calling the call env expansions functions.
	call_env_t const			*call_env;		//!< Call env being expanded.
	call_env_parsed_t const			*last_expanded;		//!< The last expanded tmpl.
	fr_value_box_list_t			tmpl_expanded;		//!< List to write value boxes to as tmpls are expanded.
	void					**data;			//!< Final destination structure for value boxes.
} call_env_rctx_t;

static unlang_action_t call_env_expand_repeat(UNUSED unlang_result_t *p_result, request_t *request, void *uctx);

/** Start the expansion of a call environment tmpl.
 *
 */
static unlang_action_t call_env_expand_start(UNUSED unlang_result_t *p_result, request_t *request, void *uctx)
{
	call_env_rctx_t	*call_env_rctx = talloc_get_type_abort(uctx, call_env_rctx_t);
	TALLOC_CTX	*ctx;
	call_env_parsed_t const	*env = NULL;
	void		**out;

again:
	while ((call_env_rctx->last_expanded = call_env_parsed_next(&call_env_rctx->call_env->parsed, call_env_rctx->last_expanded))) {
		env = call_env_rctx->last_expanded;
		fr_assert(env != NULL);

		/*
		 *	Subsections are expanded during parsing to produce a list of
		 *	call_env_parsed_t.  They are not expanded at runtime.
		 */
		fr_assert_msg(call_env_is_subsection(env->rule->flags) == false, "Subsections cannot be expanded at runtime");

		/*
		 *	If there's an offset to copy the output to, do that.
		 *	We may also need to expand the tmpl_t and write out the result
		 *	to the pair offset.
		 */
		if (env->rule->pair.parsed.offset >= 0) {
			/*
			 *	If we only need the tmpl or data, just set the pointer and move the next.
			 */
			out = (void **)((uint8_t *)*call_env_rctx->data + env->rule->pair.parsed.offset);

			/*
			 *	For multi pair options, the pointers need to go into a new array.
			 *	When processing the first expansion, allocate the array, and for
			 *	all expansions adjust the `out` pointer to write to.
			 */
			if (call_env_multi(env->rule->flags)) {
				void **array;
				if (env->multi_index == 0) {
					/*
					 *	Coverity thinks talloc_zero_array being called with the type `void *`
					 *	is a size mismatch.  This works round the false positive.
					 */
					MEM(array = _talloc_zero_array((*call_env_rctx->data), sizeof(uint8_t *),
									env->count, "void *"));
					*out = array;
				}
				array = (void **)(*out);
				out = (void **)((uint8_t *)array + sizeof(void *) * env->multi_index);
			}

			switch (env->rule->pair.parsed.type) {
			case CALL_ENV_PARSE_TYPE_TMPL:
				*out = UNCONST(tmpl_t *, env->data.tmpl);
				break;

			case CALL_ENV_PARSE_TYPE_VALUE_BOX:
				*out = UNCONST(fr_value_box_t *, env->data.vb);
				continue;	/* Can't evaluate these */

			case CALL_ENV_PARSE_TYPE_VOID:
				*out = UNCONST(void *, env->data.ptr);
				continue;	/* Can't evaluate these */
			}
		}

		/*
		 *	If this is not parse_only, we need to expand the tmpl.
		 */
		if ((env->rule->pair.parsed.type == CALL_ENV_PARSE_TYPE_TMPL) && !call_env_parse_only(env->rule->flags)) break;
	}

	if (!call_env_rctx->last_expanded) {	/* No more! */
		if (call_env_rctx->result) *call_env_rctx->result = CALL_ENV_SUCCESS;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	ctx = *call_env_rctx->data;

	fr_assert(env != NULL);

	/*
	 *	Multi pair options should allocate boxes in the context of the array
	 */
	if (call_env_multi(env->rule->flags)) {
		out = (void **)((uint8_t *)(*call_env_rctx->data) + env->rule->pair.offset);

		/*
		 *	For multi pair options, allocate the array before expanding the first entry.
		 */
		if (env->multi_index == 0) {
			void *array;
			MEM(array = _talloc_zero_array((*call_env_rctx->data), env->rule->pair.size,
						       env->count, env->rule->pair.type_name));
			*out = array;
		}
		ctx = *out;
	}

	/*
	 *	If the tmpl is already data, we can just copy the data to the right place.
	 */
	if (tmpl_is_data(call_env_rctx->last_expanded->data.tmpl)) {
		fr_value_box_t		*vb;
		call_env_result_t	result;
		void 			*box_out;

		MEM(vb = fr_value_box_acopy(ctx, &call_env_rctx->last_expanded->data.tmpl->data.literal));
		fr_value_box_list_insert_tail(&call_env_rctx->tmpl_expanded, vb);

		box_out = ((uint8_t*)(*call_env_rctx->data)) + env->rule->pair.offset;

		if (call_env_multi(env->rule->flags)) {
			void *array = *(void **)box_out;
			box_out = ((uint8_t *)array) + env->rule->pair.size * env->multi_index;
		}

		/* coverity[var_deref_model] */
		result = call_env_result(*call_env_rctx->data, request, box_out, env, &call_env_rctx->tmpl_expanded);
		if (result != CALL_ENV_SUCCESS) {
			if (call_env_rctx->result) *call_env_rctx->result = result;
			return UNLANG_ACTION_FAIL;
		}
		goto again;
	}

	if (unlang_tmpl_push(ctx, &call_env_rctx->expansion_result, &call_env_rctx->tmpl_expanded, request,
			     call_env_rctx->last_expanded->data.tmpl,
			     NULL, UNLANG_SUB_FRAME) < 0) return UNLANG_ACTION_FAIL;

	return UNLANG_ACTION_PUSHED_CHILD;
}

/** Extract expanded call environment tmpl and store in env_data
 *
 * If there are more call environments to evaluate, push the next one.
 */
static unlang_action_t call_env_expand_repeat(UNUSED unlang_result_t *p_result, request_t *request, void *uctx)
{
	void			*out = NULL;
	call_env_rctx_t		*call_env_rctx = talloc_get_type_abort(uctx, call_env_rctx_t);
	call_env_parsed_t	const *env;
	call_env_result_t	result;

	/*
	 *	Something went wrong expanding the call env
	 *	return fail.
	 *
	 *	The module should not be executed.
	 */
	if (call_env_rctx->expansion_result.rcode == RLM_MODULE_FAIL) return UNLANG_ACTION_FAIL;

	env = call_env_rctx->last_expanded;
	if (!env) return UNLANG_ACTION_CALCULATE_RESULT;

	/*
	 *	Find the location of the output
	 */
	out = ((uint8_t*)(*call_env_rctx->data)) + env->rule->pair.offset;

	/*
	 *	If this is a multi pair option, the output is an array.
	 *	Find the correct offset in the array
	 */
	if (call_env_multi(env->rule->flags)) {
		void *array = *(void **)out;
		out = ((uint8_t *)array) + env->rule->pair.size * env->multi_index;
	}

	/* coverity[var_deref_model] */
	result = call_env_result(*call_env_rctx->data, request, out, env, &call_env_rctx->tmpl_expanded);
	if (result != CALL_ENV_SUCCESS) {
		if (call_env_rctx->result) *call_env_rctx->result = result;
		return UNLANG_ACTION_FAIL;
	}

	if (!call_env_parsed_next(&call_env_rctx->call_env->parsed, env)) {
		if (call_env_rctx->result) *call_env_rctx->result = CALL_ENV_SUCCESS;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	return unlang_function_push_with_result(&call_env_rctx->expansion_result,
						request,
						call_env_expand_start,
						call_env_expand_repeat,
						NULL,
						0, UNLANG_SUB_FRAME,
						call_env_rctx);
}

/** Initialise the expansion of a call environment
 *
 * @param[in] ctx		in which to allocate destination structure for resulting value boxes.
 * @param[in] request		Current request.
 * @param[out] env_result	Where to write the result of the callenv expansion.  May be NULL
 * @param[in,out] env_data	Where the destination structure should be created.
 * @param[in] call_env		Call environment being expanded.
 */
unlang_action_t call_env_expand(TALLOC_CTX *ctx, request_t *request, call_env_result_t *env_result, void **env_data,
				call_env_t const *call_env)
{
	call_env_rctx_t	*call_env_rctx;

	MEM(call_env_rctx = talloc_zero(ctx, call_env_rctx_t));
	MEM(*env_data = talloc_zero_array(ctx, uint8_t, call_env->method->inst_size));
	talloc_set_name_const(*env_data, call_env->method->inst_type);
	call_env_rctx->result = env_result;
	if (env_result) *env_result = CALL_ENV_INVALID;	/* Make sure we ran to completion*/
	call_env_rctx->data = env_data;
	call_env_rctx->call_env = call_env;
	fr_value_box_list_init(&call_env_rctx->tmpl_expanded);

	return unlang_function_push_with_result(&call_env_rctx->expansion_result,
						request,
						call_env_expand_start,
						call_env_expand_repeat,
						NULL,
						0, UNLANG_SUB_FRAME,
						call_env_rctx);
}

/** Allocates a new call env parsed struct
 *
 */
static inline CC_HINT(always_inline)
call_env_parsed_t *call_env_parsed_alloc(TALLOC_CTX *ctx, call_env_parser_t const *rule)
{
	call_env_parsed_t	*call_env_parsed;

	MEM(call_env_parsed = talloc_zero(ctx, call_env_parsed_t));
	call_env_parsed->rule = rule;
	call_env_parsed->count = 1;
	call_env_parsed->multi_index = 0;

	return call_env_parsed;
}

static inline CC_HINT(always_inline)
int call_env_parsed_valid(call_env_parsed_t const *parsed, CONF_ITEM const *ci, call_env_parser_t const *rule)
{
	tmpl_t const *tmpl;

	if (rule->pair.parsed.type != CALL_ENV_PARSE_TYPE_TMPL) return 0;

	tmpl = parsed->data.tmpl;
	switch (tmpl->type) {
		/*
		 *	These can't be created from a call_env flag which is marked as an attribute.
		 */
	case TMPL_TYPE_DATA:
	case TMPL_TYPE_EXEC:
	case TMPL_TYPE_XLAT:
		fr_assert(!call_env_attribute(rule->flags));
		break;

		/*
		 *	This can be created from multiple types of flags, not just an attribute one.
		 */
	case TMPL_TYPE_ATTR:
		break;

	default:
		cf_log_err(ci, "'%s' expands to invalid tmpl type %s", tmpl->name,
			   tmpl_type_to_str(tmpl->type));
		return -1;
	}

	return 0;
}

/** Standard function we use for parsing call env pairs
 *
 * @note This is called where no custom pair parsing function is provided, but may be called by custom functions to avoid
 *       duplicating the standard parsing code.
 *
 * @param[in] ctx		to allocate any data in.
 * @param[out] out		Where to write the result of parsing.
 * @param[in] t_rules		we're parsing attributes with.  Contains the default dictionary and nested 'caller' tmpl_rules_t.
 * @param[in] ci		The #CONF_SECTION or #CONF_PAIR to parse.
 * @param[in] cec		information about the call.
 * @param[in] rule		Parse rules - How the #CONF_PAIR or #CONF_SECTION should be converted.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int call_env_parse_pair(TALLOC_CTX *ctx, void *out, tmpl_rules_t const *t_rules, CONF_ITEM *ci,
			UNUSED call_env_ctx_t const *cec, call_env_parser_t const *rule)
{
	CONF_PAIR const	*to_parse = cf_item_to_pair(ci);
	tmpl_t		*parsed_tmpl;
	fr_token_t	quote = cf_pair_value_quote(to_parse);

	/*
	 *	If it's marked as containing an attribute reference,
	 *	then always parse it as an attribute reference.
	 */
	if (call_env_attribute(rule->flags) ||
	    ((quote == T_BARE_WORD) && call_env_bare_word_attribute(rule->flags))) {
		if (tmpl_afrom_attr_str(ctx, NULL, &parsed_tmpl, cf_pair_value(to_parse), t_rules) <= 0) {
			return -1;
		}
	} else {
		if (tmpl_afrom_substr(ctx, &parsed_tmpl,
				      &FR_SBUFF_IN(cf_pair_value(to_parse), talloc_strlen(cf_pair_value(to_parse))),
				      quote, value_parse_rules_quoted[cf_pair_value_quote(to_parse)],
				      t_rules) < 0) {
			return -1;
		}
	}
	*(void **)out = parsed_tmpl;

	/*
	 *	All attributes and functions should be resolved at this point
	 */
	return tmpl_resolve(parsed_tmpl, NULL);
}

/** Parse per call env
 *
 * Used for config options which must be parsed in the context in which
 * the module is being called.
 *
 * @param[in] ctx		To allocate parsed environment in.
 * @param[out] parsed		Where to write parsed environment.
 * @param[in] name		Module name for error messages.
 * @param[in] t_rules		controlling how the call env is parsed.
 * @param[in] cs		Module config.
 * @param[in] cec		information about the call.
 * @param[in] rule		to parse.
 * @return
 *	- 0 on success;
 *	- <0 on failure;
 */
int call_env_parse(TALLOC_CTX *ctx, call_env_parsed_head_t *parsed, char const *name, tmpl_rules_t const *t_rules,
			  CONF_SECTION const *cs,
			  call_env_ctx_t const *cec, call_env_parser_t const *rule) {
	CONF_PAIR const		*cp, *next;
	call_env_parsed_t	*call_env_parsed = NULL;
	ssize_t			count, multi_index;
	call_env_parser_t const	*rule_p = rule;

	while (rule_p->name) {
		CALL_ENV_DEBUG(cs, "%s: Parsing call env data for %s", name, section_name_str(rule_p->name));

		if (call_env_is_subsection(rule_p->flags)) {
			CONF_SECTION const *subcs;
			subcs = cf_section_find(cs, rule_p->name, rule_p->section.name2);
			if (!subcs) {
				/*
				 *	No CONF_SECTION, but it's required.  That's an error.
				 */
				if (call_env_required(rule_p->flags)) {
					cf_log_err(cs, "Module %s missing required section \"%s\"", name, rule_p->name);
					return -1;
				}

				/*
				 *	No flag saying "do callback even if subcs is missing", just skip the
				 *	callbacks.
				 */
				if (!call_env_parse_missing(rule_p->flags)) goto next;
			}

			/*
			 *	Hand off to custom parsing function if there is one...
			 */
			if (rule_p->section.func) {
				/*
				 *	Record our position so we can process any new entries
				 *	after the callback returns.
				 */
				call_env_parsed_t *last = call_env_parsed_tail(parsed);

				CALL_ENV_DEBUG(cs, "%s: Calling subsection callback %p", name, rule_p->section.func);

				if (rule_p->section.func(ctx, parsed, t_rules, cf_section_to_item(subcs), cec, rule_p) < 0) {
					cf_log_perr(cs, "Failed parsing configuration section %s",
						    rule_p->name == CF_IDENT_ANY ? cf_section_name(cs) : rule_p->name);
					return -1;
				}

				CALL_ENV_DEBUG(subcs, "%s: Callback returned %u parsed call envs", name,
					       call_env_parsed_num_elements(parsed));

				/*
				 *	We _could_ fix up count and multi_index on behalf of
				 *	the callback, but there's no guarantee that all call_env_parsed_t
				 *	are related to each other, so we don't.
				 */
				call_env_parsed = last;
				while ((call_env_parsed = call_env_parsed_next(parsed, call_env_parsed))) {
					CALL_ENV_DEBUG(subcs, "%s: Checking parsed env", name, rule_p->section.func);
					if (call_env_parsed_valid(call_env_parsed, cf_section_to_item(subcs), rule_p) < 0) {
						cf_log_err(cf_section_to_item(subcs), "Invalid data produced by %s",
							   rule_p->name == CF_IDENT_ANY ? cf_section_name(cs) : rule_p->name);
						return -1;
					}
				}
				goto next;
			}

			if (call_env_parse(ctx, parsed, name, t_rules, subcs, cec, rule_p->section.subcs) < 0) {
				CALL_ENV_DEBUG(cs, "%s: Recursive call failed", name);
				return -1;
			}
			goto next;
		}

		cp = cf_pair_find(cs, rule_p->name);

		if (!cp && !rule_p->pair.dflt) {
			if (!call_env_required(rule_p->flags)) goto next;

			cf_log_err(cs, "Missing required config item '%s'", rule_p->name);
			return -1;
		}

		/*
		 *	Check for additional conf pairs and error
		 *	if there is one and multi is not allowed.
		 */
		if (!call_env_multi(rule_p->flags) && ((next = cf_pair_find_next(cs, cp, rule_p->name)))) {
			cf_log_err(cf_pair_to_item(next), "Invalid duplicate configuration item '%s'", rule_p->name);
			return -1;
		}

		count = cf_pair_count(cs, rule_p->name);
		if (count == 0) count = 1;

		for (multi_index = 0; multi_index < count; multi_index++) {
			CONF_PAIR		*tmp_cp = NULL;
			CONF_PAIR const		*to_parse;
			tmpl_rules_t		our_rules = {};
			fr_type_t 		type = rule_p->pair.cast_type;
			call_env_parse_pair_t	func = rule_p->pair.func ? rule_p->pair.func : call_env_parse_pair;

			if (t_rules) {
				our_rules.parent = t_rules->parent;
				our_rules.attr.dict_def = t_rules->attr.dict_def;
				our_rules.escape = rule_p->pair.escape;	/* Escape rules will now get embedded in the tmpl_t and used at evaluation */
			}

			our_rules.attr.list_def = request_attr_request;
			our_rules.cast = ((type == FR_TYPE_VOID) ? FR_TYPE_NULL : type);
			our_rules.literals_safe_for = rule_p->pair.literals_safe_for;

			call_env_parsed = call_env_parsed_alloc(ctx, rule_p);
			call_env_parsed->count = count;
			call_env_parsed->multi_index = multi_index;

			/*
			 *	With the conf_parser code we can add default pairs
			 *	if they don't exist, but as the same CONF_SECTIONs
			 *	are evaluated multiple times for each module call
			 *	we can't do that here.
			 */
			if (cp) {
				if (call_env_force_quote(rule_p->flags)) {
					to_parse = tmp_cp = cf_pair_alloc(NULL,
							       		  cf_pair_attr(cp), cf_pair_value(cp), cf_pair_operator(cp),
									  cf_pair_attr_quote(cp),
									  call_env_force_quote(rule_p->flags) ? rule_p->pair.dflt_quote : cf_pair_value_quote(cp));
				} else {
					to_parse = cp;
				}
			} else {
				to_parse = tmp_cp = cf_pair_alloc(NULL,
								  rule_p->name, rule_p->pair.dflt, T_OP_EQ,
								  T_BARE_WORD, rule_p->pair.dflt_quote);
			}

			/*
			 *	The parsing function can either produce a tmpl_t as tmpl_afrom_substr
			 *	would, or produce a custom structure, which will be copied into the
			 *	result structure.
			 */
			if (unlikely(func(ctx, &call_env_parsed->data, &our_rules, cf_pair_to_item(to_parse), cec, rule_p) < 0)) {
			error:
				cf_log_perr(to_parse, "Failed to parse configuration item '%s = %s'", rule_p->name, cf_pair_value(to_parse));
				talloc_free(call_env_parsed);
				talloc_free(tmp_cp);
				return -1;
			}
			if (!call_env_parsed->data.ptr) {
				talloc_free(call_env_parsed);
				goto next_pair;
			}

			/*
			 *	Ensure only valid data is produced.
			 */
			if (call_env_parsed_valid(call_env_parsed, cf_pair_to_item(to_parse), rule_p) < 0) goto error;

			call_env_parsed_insert_tail(parsed, call_env_parsed);
		next_pair:
			talloc_free(tmp_cp);
			cp = cf_pair_find_next(cs, cp, rule_p->name);
		}
	next:
		rule_p++;
	}

	CALL_ENV_DEBUG(cs, "Returning afer processing %u rules", (unsigned int)(rule_p - rule));

	return 0;
}

/**  Perform a quick assessment of how many parsed call env will be produced.
 *
 * @param[in,out] names_len	Where to write the sum of bytes required to represent
 *				the strings which will be parsed as tmpls.  This is required
 *				to pre-allocate space for the tmpl name buffers.
 * @param[in] cs		Conf section to search for pairs.
 * @param[in] call_env		to parse.
 * @return Number of parsed_call_env expected to be required.
 */
static size_t call_env_count(size_t *names_len, CONF_SECTION const *cs, call_env_parser_t const *call_env)
{
	size_t	pair_count, tmpl_count = 0;
	CONF_PAIR const	*cp;

	*names_len = 0;

	while (call_env->name) {
		if (call_env_is_subsection(call_env->flags)) {
			CONF_SECTION const *subcs;
			subcs = cf_section_find(cs, call_env->name, call_env->section.name2);
			if (!subcs) goto next;

			/*
			 *	May only be a callback...
			 */
			if (call_env->section.subcs) tmpl_count += call_env_count(names_len, subcs, call_env->section.subcs);
			goto next;
		}
		pair_count = 0;
		cp = NULL;
		while ((cp = cf_pair_find_next(cs, cp, call_env->name))) {
			pair_count++;
			*names_len += talloc_array_length(cf_pair_value(cp));
		}
		if (!pair_count && call_env->pair.dflt) {
			pair_count = 1;
			*names_len += strlen(call_env->pair.dflt);
		}
		tmpl_count += pair_count;
	next:
		call_env++;
	}

	return tmpl_count;
}

/** Allocate a new call_env_parsed_t structure and add it to the list of parsed call envs
 *
 * @note tmpl_t and void * should be allocated in the context of the call_env_parsed_t
 *
 * @param[in] ctx	to allocate the new call_env_parsed_t in.
 * @param[out] head	to add the new call_env_parsed_t to.
 * @param[in] rule	to base call_env_parsed_t around.  MUST NOT BE THE RULE PASSED TO THE CALLBACK.
 *			The rule passed to the callback describes how to parse a subsection, but the
 *			subsection callback is adding rules describing how to parse its children.
 * @return		The new call_env_parsed_t.
 */
call_env_parsed_t *call_env_parsed_add(TALLOC_CTX *ctx, call_env_parsed_head_t *head, call_env_parser_t const *rule)
{
	call_env_parsed_t	*call_env_parsed;
	call_env_parser_t	*our_rules;

	fr_assert_msg(call_env_is_subsection(rule->flags) == false, "Rules added by subsection callbacks cannot be subsections themselves");

	MEM(call_env_parsed = call_env_parsed_alloc(ctx, rule));

	/*
	 *	Copy the rule the callback provided, there's no guarantee
	 *	it's not stack allocated, or in some way ephemeral.
	 */
	MEM(our_rules = talloc(call_env_parsed, call_env_parser_t));
	memcpy(our_rules, rule, sizeof(*our_rules));
	call_env_parsed->rule = our_rules;
	call_env_parsed_insert_tail(head, call_env_parsed);

	return call_env_parsed;
}

/** Assign a tmpl to a call_env_parsed_t
 *
 * @note Intended to be used by subsection callbacks to add a tmpl to be
 *	evaluated during the call.
 *
 * @param[in] parsed		to assign the tmpl to.
 * @param[in] tmpl		to assign.
 */
void call_env_parsed_set_tmpl(call_env_parsed_t *parsed, tmpl_t const *tmpl)
{
	fr_assert_msg(parsed->rule->pair.parsed.type == CALL_ENV_PARSE_TYPE_TMPL, "Rule must indicate parsed output is a tmpl_t");
	parsed->data.tmpl = tmpl;
}

/** Assign a value box to a call_env_parsed_t
 *
 * @note Intended to be used by subsection callbacks to set a static boxed
 *	value to be written out to the result structure.
 *
 * @param[in] parsed		to assign the tmpl to.
 * @param[in] vb		to assign.
 */
void call_env_parsed_set_value(call_env_parsed_t *parsed, fr_value_box_t const *vb)
{
	fr_assert_msg(parsed->rule->pair.parsed.type == CALL_ENV_PARSE_TYPE_VALUE_BOX, "Rule must indicate parsed output is a value box");
	parsed->data.vb = vb;
}

/** Assign data to a call_env_parsed_t
 *
 * @note Intended to be used by subsection callbacks to set arbitrary data
 *       to be written out to the result structure.
 *
 * @param[in] parsed		to assign the tmpl to.
 * @param[in] data		to assign.
 */
void call_env_parsed_set_data(call_env_parsed_t *parsed, void const *data)
{
	fr_assert_msg(parsed->rule->pair.parsed.type == CALL_ENV_PARSE_TYPE_VOID, "Rule must indicate parsed output is a void *");
	parsed->data.ptr = data;
}

/** Assign a count and index to a call_env_parsed_t
 *
 * @note Intended to be used by subsection callbacks to indicate related
 *	call_env_parsed_t.
 *
 * @param[in] parsed		to modify metadata of.
 * @param[in] count		to assign.
 * @param[in] index		to assign.
 */
void call_env_parsed_set_multi_index(call_env_parsed_t *parsed, size_t count, size_t index)
{
	fr_assert_msg(call_env_multi(parsed->rule->flags), "Rule must indicate parsed output is a multi pair");
	parsed->multi_index = index;
	parsed->count = count;
}

/** Remove a call_env_parsed_t from the list of parsed call envs
 *
 * @note Intended to be used by subsection callbacks to remove a call_env_parsed_t
 *	from the list of parsed call envs (typically on error).
 *
 * @param[in] parsed		to remove parsed data from.
 * @param[in] ptr		to remove.
 */
void call_env_parsed_free(call_env_parsed_head_t *parsed, call_env_parsed_t *ptr)
{
	call_env_parsed_remove(parsed, ptr);
	talloc_free(ptr);
}

/** Given a call_env_method, parse all call_env_pair_t in the context of a specific call to an xlat or module method
 *
 * @param[in] ctx		to allocate the call_env_t in.
 * @param[in] name		Module name for error messages.
 * @param[in] call_env_method	containing the call_env_pair_t to evaluate against the specified CONF_SECTION.
 * @param[in] t_rules		that control how call_env_pair_t are parsed.
 * @param[in] cs		to parse in the context of the call.
 * @param[in] cec		information about how the call is being made.
 * @return
 *	- A new call_env_t on success.
 * 	- NULL on failure.
 */
call_env_t *call_env_alloc(TALLOC_CTX *ctx, char const *name, call_env_method_t const *call_env_method,
			   tmpl_rules_t const *t_rules, CONF_SECTION *cs, call_env_ctx_t const *cec)
{
	unsigned int	count;
	size_t		names_len;
	call_env_t	*call_env;

	/*
	 *	Only used if caller doesn't use a more specific assert
	 */
	fr_assert_msg(call_env_method->inst_size, "inst_size 0 for %s, method_env (%p)", name, call_env_method);

	/*
	 *	Firstly assess how many parsed env there will be and create a talloc pool to hold them.
	 *	The pool size is a rough estimate based on each tmpl also allocating at least two children,
	 *	for which we allow twice the length of the value to be parsed.
	 */
	count = call_env_count(&names_len, cs, call_env_method->env);

	/*
	 *  Pre-allocated headers:
	 *	1 header for the call_env_pair_parsed_t, 1 header for the tmpl_t, 1 header for the name,
	 *	one header for the value.
	 *
	 *  Pre-allocated memory:
	 *	((sizeof(call_env_pair_parsed_t) + sizeof(tmpl_t)) * count) + (names of tmpls * 2)... Not sure what
	 *	the * 2 is for, maybe for slop?
	 */
	MEM(call_env = talloc_pooled_object(ctx, call_env_t, count * 4, (sizeof(call_env_parser_t) + sizeof(tmpl_t)) * count + names_len * 2));
	call_env->method = call_env_method;
	call_env_parsed_init(&call_env->parsed);
	if (call_env_parse(call_env, &call_env->parsed, name, t_rules, cs, cec, call_env_method->env) < 0) {
		talloc_free(call_env);
		return NULL;
	}

	return call_env;
}
