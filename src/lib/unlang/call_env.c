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
#include <freeradius-devel/unlang/tmpl.h>
#include "call_env.h"

/** Parse per call env
 *
 * Used for config options which must be parsed in the context in which
 * the module is being called.
 *
 * @param[in] ctx		To allocate parsed environment in.
 * @param[out] parsed		Where to write parsed environment.
 * @param[in] name		Module name for error messages.
 * @param[in] dict_def		Default dictionary to use when tokenizing tmpls.
 * @param[in] cs		Module config.
 * @param[in] call_env		to parse.
 * @return
 *	- 0 on success;
 *	- <0 on failure;
 */
int call_env_parse(TALLOC_CTX *ctx, call_env_parsed_head_t *parsed, char const *name, fr_dict_t const *dict_def,
		   CONF_SECTION const *cs, call_env_t const *call_env) {
	CONF_PAIR const		*cp, *next;
	call_env_parsed_t	*call_env_parsed;
	ssize_t			len, opt_count, multi_index;
	char const		*value;
	fr_token_t		quote;
	fr_type_t		type;

	while (call_env->name) {
		if (FR_BASE_TYPE(call_env->type) == FR_TYPE_SUBSECTION) {
			CONF_SECTION const *subcs;
			subcs = cf_section_find(cs, call_env->name, call_env->section.ident2);
			if (!subcs) goto next;

			if (call_env_parse(ctx, parsed, name, dict_def, subcs, call_env->section.subcs) < 0) return -1;
			goto next;
		}

		cp = cf_pair_find(cs, call_env->name);

		if (!cp && !call_env->dflt) {
			if (!call_env->pair.required) goto next;

			cf_log_err(cs, "Module %s missing required option %s", name, call_env->name);
			return -1;
		}

		/*
		 *	Check for additional conf pairs and error
		 *	if there is one and multi is not allowed.
		 */
		if (!call_env->pair.multi && ((next = cf_pair_find_next(cs, cp, call_env->name)))) {
			cf_log_err(cf_pair_to_item(next), "Invalid duplicate configuration item '%s'", call_env->name);
			return -1;
		}

		opt_count = cf_pair_count(cs, call_env->name);
		if (opt_count == 0) opt_count = 1;

		for (multi_index = 0; multi_index < opt_count; multi_index ++) {
			MEM(call_env_parsed = talloc_zero(ctx, call_env_parsed_t));
			call_env_parsed->rule = call_env;
			call_env_parsed->opt_count = opt_count;
			call_env_parsed->multi_index = multi_index;

			if (cp) {
				value = cf_pair_value(cp);
				len = talloc_array_length(value) - 1;
				quote = cf_pair_value_quote(cp);
			} else {
				value = call_env->dflt;
				len = strlen(value);
				quote = call_env->dflt_quote;
			}

			type = FR_BASE_TYPE(call_env->type);
			if (tmpl_afrom_substr(call_env_parsed, &call_env_parsed->tmpl, &FR_SBUFF_IN(value, len),
					      quote, NULL, &(tmpl_rules_t){
							.cast = (type == FR_TYPE_VOID ? FR_TYPE_NULL : type),
							.attr = {
								.list_def = request_attr_request,
								.dict_def = dict_def
							}
						}) < 0) {
			error:
				talloc_free(call_env_parsed);
				cf_log_perr(cp, "Failed to parse '%s' for %s", cf_pair_value(cp), call_env->name);
				return -1;
			}

			/*
			 *	Ensure only valid TMPL types are produced.
			 */
			switch (call_env_parsed->tmpl->type) {
			case TMPL_TYPE_ATTR:
			case TMPL_TYPE_DATA:
			case TMPL_TYPE_EXEC:
			case TMPL_TYPE_XLAT:
				break;

			default:
				cf_log_err(cp, "'%s' expands to invalid tmpl type %s", value,
					   fr_table_str_by_value(tmpl_type_table, call_env_parsed->tmpl->type, "<INVALID>"));
				goto error;
			}

			call_env_parsed_insert_tail(parsed, call_env_parsed);

			cp = cf_pair_find_next(cs, cp, call_env->name);
		}
	next:
		call_env++;
	}

	return 0;
}

/**  Perform a quick assessment of how many parsed call env will be produced.
 *
 * @param[in,out] vallen	Where to write the sum of the length of pair values.
 * @param[in] cs		Conf section to search for pairs.
 * @param[in] call_env		to parse.
 * @return Number of parsed_call_env expected to be required.
 */
size_t call_env_count(size_t *vallen, CONF_SECTION const *cs, call_env_t const *call_env) {
	size_t	pair_count, tmpl_count = 0;
	CONF_PAIR const	*cp;

	while (call_env->name) {
		if (FR_BASE_TYPE(call_env->type) == FR_TYPE_SUBSECTION) {
			CONF_SECTION const *subcs;
			subcs = cf_section_find(cs, call_env->name, call_env->section.ident2);
			if (!subcs) goto next;

			tmpl_count += call_env_count(vallen, subcs, call_env->section.subcs);
			goto next;
		}
		pair_count = 0;
		cp = NULL;
		while ((cp = cf_pair_find_next(cs, cp, call_env->name))) {
			pair_count++;
			*vallen += talloc_array_length(cf_pair_value(cp));
		}
		if (!pair_count && call_env->dflt) {
			pair_count = 1;
			*vallen += strlen(call_env->dflt);
		}
		tmpl_count += pair_count;
	next:
		call_env++;
	}

	return tmpl_count;
}
