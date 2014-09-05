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

/*
 * $Id$
 *
 * @brief map / template functions
 * @file main/map.c
 *
 * @ingroup AVP
 *
 * @copyright 2013 The FreeRADIUS server project
 * @copyright 2013  Alan DeKok <aland@freeradius.org>
 */

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>

#include <ctype.h>

/** Convert CONFIG_PAIR (which may contain refs) to value_pair_map_t.
 *
 * Treats the left operand as an attribute reference
 * @verbatim<request>.<list>.<attribute>@endverbatim
 *
 * Treatment of left operand depends on quotation, barewords are treated as
 * attribute references, double quoted values are treated as expandable strings,
 * single quoted values are treated as literal strings.
 *
 * Return must be freed with talloc_free
 *
 * @param[in] ctx for talloc
 * @param[in] cp to convert to map.
 * @param[in] dst_request_def The default request to insert unqualified
 *	attributes into.
 * @param[in] dst_list_def The default list to insert unqualified attributes
 *	into.
 * @param[in] src_request_def The default request to resolve attribute
 *	references in.
 * @param[in] src_list_def The default list to resolve unqualified attributes
 *	in.
 * @return value_pair_map_t if successful or NULL on error.
 */
value_pair_map_t *map_from_cp(TALLOC_CTX *ctx, CONF_PAIR *cp,
			      request_refs_t dst_request_def, pair_lists_t dst_list_def,
			      request_refs_t src_request_def, pair_lists_t src_list_def)
{
	value_pair_map_t *map;
	char const *attr;
	char const *value;
	FR_TOKEN type;
	CONF_ITEM *ci = cf_pairtoitem(cp);

	if (!cp) return NULL;

	map = talloc_zero(ctx, value_pair_map_t);
	map->op = cf_pair_operator(cp);
	map->ci = ci;

	attr = cf_pair_attr(cp);
	value = cf_pair_value(cp);
	if (!value) {
		cf_log_err(ci, "Missing attribute value");
		goto error;
	}

	/*
	 *	LHS must always be an attribute reference.
	 */
	map->dst = radius_attr2tmpl(map, attr, dst_request_def, dst_list_def);
	if (!map->dst) {
		cf_log_err(ci, "%s", fr_strerror());
		goto error;
	}

	/*
	 *	RHS might be an attribute reference.
	 */
	type = cf_pair_value_type(cp);
	map->src = radius_str2tmpl(map, value, type, src_request_def, src_list_def);
	if (!map->src) {
		cf_log_err(ci, "%s", fr_strerror());
		goto error;
	}

	/*
	 *	Anal-retentive checks.
	 */
	if (debug_flag > 2) {
		if ((map->dst->type == TMPL_TYPE_ATTR) && (*attr != '&')) {
			WARN("%s[%d]: Please change attribute reference to '&%s %s ...'",
			       cf_pair_filename(cp), cf_pair_lineno(cp),
			       attr, fr_int2str(fr_tokens, map->op, "<INVALID>"));
		}

		if ((map->src->type == TMPL_TYPE_ATTR) && (*value != '&')) {
			WARN("%s[%d]: Please change attribute reference to '... %s &%s'",
			       cf_pair_filename(cp), cf_pair_lineno(cp),
			       fr_int2str(fr_tokens, map->op, "<INVALID>"), value);
		}
	}

	/*
	 *	Values used by unary operators should be literal ANY
	 *
	 *	We then free the template and alloc a NULL one instead.
	 */
	if (map->op == T_OP_CMP_FALSE) {
	 	if ((map->src->type != TMPL_TYPE_LITERAL) || (strcmp(map->src->name, "ANY") != 0)) {
			WARN("%s[%d] Wildcard deletion MUST use '!* ANY'", cf_pair_filename(cp), cf_pair_lineno(cp));
		}

		radius_tmplfree(&map->src);

		map->src = talloc_zero(map, value_pair_tmpl_t);
		map->src->type = TMPL_TYPE_NULL;
	}

	/*
	 *	Lots of sanity checks for insane people...
	 */

	/*
	 *	We don't support implicit type conversion,
	 *	except for "octets"
	 */
	if (map->dst->tmpl_da && map->src->tmpl_da &&
	    (map->src->tmpl_da->type != map->dst->tmpl_da->type) &&
	    (map->src->tmpl_da->type != PW_TYPE_OCTETS) &&
	    (map->dst->tmpl_da->type != PW_TYPE_OCTETS)) {
		cf_log_err(ci, "Attribute type mismatch");
		goto error;
	}

	/*
	 *	What exactly where you expecting to happen here?
	 */
	if ((map->dst->type == TMPL_TYPE_ATTR) &&
	    (map->src->type == TMPL_TYPE_LIST)) {
		cf_log_err(ci, "Can't copy list into an attribute");
		goto error;
	}

	/*
	 *	Depending on the attribute type, some operators are
	 *	disallowed.
	 */
	if (map->dst->type == TMPL_TYPE_ATTR) {
		switch (map->op) {
		default:
			cf_log_err(ci, "Invalid operator for attribute");
			goto error;

		case T_OP_EQ:
		case T_OP_CMP_EQ:
		case T_OP_ADD:
		case T_OP_SUB:
		case T_OP_LE:
		case T_OP_GE:
		case T_OP_CMP_FALSE:
		case T_OP_SET:
			break;
		}
	}

	if (map->dst->type == TMPL_TYPE_LIST) {
		/*
		 *	Only += and :=, and !* operators are supported
		 *	for lists.
		 */
		switch (map->op) {
		case T_OP_CMP_FALSE:
			break;

		case T_OP_ADD:
			if ((map->src->type != TMPL_TYPE_LIST) &&
			    (map->src->type != TMPL_TYPE_EXEC)) {
				cf_log_err(ci, "Invalid source for list '+='");
				goto error;
			}
			break;

		case T_OP_SET:
			if (map->src->type == TMPL_TYPE_EXEC) {
				WARN("%s[%d] Please change ':=' to '=' for list assignment",
				       cf_pair_filename(cp), cf_pair_lineno(cp));
				break;
			}

			if (map->src->type != TMPL_TYPE_LIST) {
				cf_log_err(ci, "Invalid source for ':=' operator");
				goto error;
			}
			break;

		case T_OP_EQ:
			if (map->src->type != TMPL_TYPE_EXEC) {
				cf_log_err(ci, "Invalid source for '=' operator");
				goto error;
			}
			break;

		default:
			cf_log_err(ci, "Operator \"%s\" not allowed for list assignment",
				   fr_int2str(fr_tokens, map->op, "<INVALID>"));
			goto error;
		}
	}

	return map;

error:
	talloc_free(map);
	return NULL;
}

/** Convert an 'update' config section into an attribute map.
 *
 * Uses 'name2' of section to set default request and lists.
 *
 * @param[in] cs the update section
 * @param[out] head Where to store the head of the map.
 * @param[in] dst_list_def The default destination list, usually dictated by
 * 	the section the module is being called in.
 * @param[in] src_list_def The default source list, usually dictated by the
 *	section the module is being called in.
 * @param[in] max number of mappings to process.
 * @return -1 on error, else 0.
 */
int map_from_cs(CONF_SECTION *cs, value_pair_map_t **head,
		pair_lists_t dst_list_def, pair_lists_t src_list_def,
		unsigned int max)
{
	char const *cs_list, *p;

	request_refs_t request_def = REQUEST_CURRENT;

	CONF_ITEM *ci;
	CONF_PAIR *cp;

	unsigned int total = 0;
	value_pair_map_t **tail, *map;
	TALLOC_CTX *ctx;

	*head = NULL;
	tail = head;

	if (!cs) return 0;

	/*
	 *	The first map has cs as the parent.
	 *	The rest have the previous map as the parent.
	 */
	ctx = cs;

	ci = cf_sectiontoitem(cs);

	cs_list = p = cf_section_name2(cs);
	if (cs_list) {
		request_def = radius_request_name(&p, REQUEST_CURRENT);
		if (request_def == REQUEST_UNKNOWN) {
			cf_log_err(ci, "Default request specified "
				   "in mapping section is invalid");
			return -1;
		}

		dst_list_def = fr_str2int(pair_lists, p, PAIR_LIST_UNKNOWN);
		if (dst_list_def == PAIR_LIST_UNKNOWN) {
			cf_log_err(ci, "Default list \"%s\" specified "
				   "in mapping section is invalid", p);
			return -1;
		}
	}

	for (ci = cf_item_find_next(cs, NULL);
	     ci != NULL;
	     ci = cf_item_find_next(cs, ci)) {
		if (total++ == max) {
			cf_log_err(ci, "Map size exceeded");
			goto error;
		}

		if (!cf_item_is_pair(ci)) {
			cf_log_err(ci, "Entry is not in \"attribute = "
				       "value\" format");
			goto error;
		}

		cp = cf_itemtopair(ci);
		map = map_from_cp(ctx, cp, request_def, dst_list_def,
				    REQUEST_CURRENT, src_list_def);
		if (!map) {
			goto error;
		}

		ctx = *tail = map;
		tail = &(map->next);
	}

	return 0;
error:
	TALLOC_FREE(*head);
	return -1;
}

/** Convert strings to value_pair_map_t
 *
 * Treatment of operands depends on quotation, barewords are treated
 * as attribute references, double quoted values are treated as
 * expandable strings, single quoted values are treated as literal
 * strings.
 *
 * Return must be freed with talloc_free
 *
 * @param[in] ctx for talloc
 * @param[in] lhs of the operation
 * @param[in] lhs_type type of the LHS string
 * @param[in] op the operation to perform
 * @param[in] rhs of the operation
 * @param[in] rhs_type type of the RHS string
 * @param[in] dst_request_def The default request to insert unqualified
 *	attributes into.
 * @param[in] dst_list_def The default list to insert unqualified attributes
 *	into.
 * @param[in] src_request_def The default request to resolve attribute
 *	references in.
 * @param[in] src_list_def The default list to resolve unqualified attributes
 *	in.
 * @return value_pair_map_t if successful or NULL on error.
 */
value_pair_map_t *map_from_str(TALLOC_CTX *ctx, char const *lhs, FR_TOKEN lhs_type,
			       FR_TOKEN op, char const *rhs, FR_TOKEN rhs_type,
			       request_refs_t dst_request_def,
			       pair_lists_t dst_list_def,
			       request_refs_t src_request_def,
			       pair_lists_t src_list_def)
{
	value_pair_map_t *map;

	map = talloc_zero(ctx, value_pair_map_t);

	map->dst = radius_str2tmpl(map, lhs, lhs_type, dst_request_def, dst_list_def);
	if (!map->dst) {
	error:
		talloc_free(map);
		return NULL;
	}

	map->op = op;

	map->src = radius_str2tmpl(map, rhs, rhs_type, src_request_def, src_list_def);
	if (!map->src) goto error;

	return map;
}

/** Convert a value pair string to valuepair map
 *
 * Takes a valuepair string with list and request qualifiers and converts it into a
 * value_pair_map_t.
 *
 * @param out Where to write the new map (must be freed with talloc_free()).
 * @param request Current request.
 * @param raw string to parse.
 * @param dst_request_def to use if attribute isn't qualified.
 * @param dst_list_def to use if attribute isn't qualified.
 * @param src_request_def to use if attribute isn't qualified.
 * @param src_list_def to use if attribute isn't qualified.
 * @return 0 on success, < 0 on error.
 */
int map_from_vp_str(value_pair_map_t **out, REQUEST *request, char const *raw,
		    request_refs_t dst_request_def, pair_lists_t dst_list_def,
		    request_refs_t src_request_def, pair_lists_t src_list_def)
{
	char const *p = raw;
	FR_TOKEN ret;

	VALUE_PAIR_RAW tokens;
	value_pair_map_t *map;

	ret = pairread(&p, &tokens);
	if (ret != T_EOL) {
		REDEBUG("Failed tokenising attribute string: %s", fr_strerror());
		return -1;
	}

	map = map_from_str(request, tokens.l_opand, T_BARE_WORD, tokens.op, tokens.r_opand, tokens.quote,
			     dst_request_def, dst_list_def, src_request_def, src_list_def);
	if (!map) {
		REDEBUG("Failed parsing attribute string: %s", fr_strerror());
		return -1;
	}
	*out = map;

	return 0;
}

/** Process map which has exec as a src
 *
 * Evaluate maps which specify exec as a src. This may be used by various sorts of update sections, and so
 * has been broken out into it's own function.
 *
 * @param[out] out Where to write the VALUE_PAIR(s).
 * @param[in] request structure (used only for talloc).
 * @param[in] map the map. The LHS (dst) must be TMPL_TYPE_ATTR or TMPL_TYPE_LIST. The RHS (src) must be TMPL_TYPE_EXEC.
 * @return -1 on failure, 0 on success.
 */
static int map_exec_to_vp(VALUE_PAIR **out, REQUEST *request, value_pair_map_t const *map)
{
	int result;
	char *expanded = NULL;
	char answer[1024];
	VALUE_PAIR **input_pairs = NULL;
	VALUE_PAIR *output_pairs = NULL;

	*out = NULL;

	rad_assert(map->src->type == TMPL_TYPE_EXEC);
	rad_assert((map->dst->type == TMPL_TYPE_ATTR) || (map->dst->type == TMPL_TYPE_LIST));

	/*
	 *	We always put the request pairs into the environment
	 */
	input_pairs = radius_list(request, PAIR_LIST_REQUEST);

	/*
	 *	Automagically switch output type depending on our destination
	 *	If dst is a list, then we create attributes from the output of the program
	 *	if dst is an attribute, then we create an attribute of that type and then
	 *	call pairparsevalue on the output of the script.
	 */
	result = radius_exec_program(request, map->src->name, true, true,
				     answer, sizeof(answer), EXEC_TIMEOUT,
				     input_pairs ? *input_pairs : NULL,
				     (map->dst->type == TMPL_TYPE_LIST) ? &output_pairs : NULL);
	talloc_free(expanded);
	if (result != 0) {
		talloc_free(output_pairs);
		return -1;
	}

	switch (map->dst->type) {
	case TMPL_TYPE_LIST:
		if (!output_pairs) {
			REDEBUG("No valid attributes received from program");
			return -2;
		}
		*out = output_pairs;
		return 0;

	case TMPL_TYPE_ATTR:
	{
		VALUE_PAIR *vp;

		vp = pairalloc(request, map->dst->tmpl_da);
		if (!vp) return -1;
		vp->op = map->op;
		if (pairparsevalue(vp, answer, 0) < 0) {
			pairfree(&vp);
			return -2;
		}
		*out = vp;

		return 0;
	}

	default:
		rad_assert(0);
	}

	return -1;
}

/** Convert a map to a VALUE_PAIR.
 *
 * @param[out] out Where to write the VALUE_PAIR(s), which may be NULL if not found
 * @param[in] request structure (used only for talloc)
 * @param[in] map the map. The LHS (dst) has to be TMPL_TYPE_ATTR or TMPL_TYPE_LIST.
 * @param[in] ctx unused
 * @return 0 on success, -1 on failure
 */
int map_to_vp(VALUE_PAIR **out, REQUEST *request, value_pair_map_t const *map, UNUSED void *ctx)
{
	int rcode = 0;
	VALUE_PAIR *vp = NULL, *new, *found = NULL;
	DICT_ATTR const *da;
	REQUEST *context = request;
	vp_cursor_t cursor;

	*out = NULL;

	/*
	 *	Special case for !*, we don't need to parse RHS as this is a unary operator.
	 */
	if (map->op == T_OP_CMP_FALSE) return 0;

	/*
	 *	List to list found, this is a special case because we don't need
	 *	to allocate any attributes, just finding the current list, and change
	 *	the op.
	 */
	if ((map->dst->type == TMPL_TYPE_LIST) && (map->src->type == TMPL_TYPE_LIST)) {
		VALUE_PAIR **from = NULL;

		if (radius_request(&context, map->src->tmpl_request) == 0) {
			from = radius_list(context, map->src->tmpl_list);
		}
		if (!from) return 0;

		found = paircopy(request, *from);

		/*
		 *	List to list copy is empty if the src list has no attributes.
		 */
		if (!found) return 0;

		for (vp = fr_cursor_init(&cursor, &found);
		     vp;
		     vp = fr_cursor_next(&cursor)) {
			vp->op = T_OP_ADD;
		}

		*out = found;

		return 0;
	}

	/*
	 *	Deal with all non-list operations.
	 */
	da = map->dst->tmpl_da ? map->dst->tmpl_da : map->src->tmpl_da;

	/*
	 *	And parse the RHS
	 */
	switch (map->src->type) {
		ssize_t slen;
		char *str;

	case TMPL_TYPE_XLAT_STRUCT:
		rad_assert(map->dst->tmpl_da);	/* Need to know where were going to write the new attribute */
		rad_assert(map->src->tmpl_xlat != NULL);

		new = pairalloc(request, da);
		if (!new) return -1;

		str = NULL;
		slen = radius_axlat_struct(&str, request, map->src->tmpl_xlat, NULL, NULL);
		if (slen < 0) {
			rcode = slen;
			goto error;
		}

		/*
		 *	We do the debug printing because radius_axlat_struct
		 *	doesn't have access to the original string.  It's been
		 *	mangled during the parsing to xlat_exp_t
		 */
		RDEBUG2("EXPAND %s", map->src->name);
		RDEBUG2("   --> %s", str);

		rcode = pairparsevalue(new, str, 0);
		talloc_free(str);
		if (rcode < 0) {
			pairfree(&new);
			goto error;
		}
		new->op = map->op;
		*out = new;
		break;

	case TMPL_TYPE_XLAT:
		rad_assert(map->dst->tmpl_da);	/* Need to know where were going to write the new attribute */

		new = pairalloc(request, da);
		if (!new) return -1;

		str = NULL;
		slen = radius_axlat(&str, request, map->src->name, NULL, NULL);
		if (slen < 0) {
			rcode = slen;
			goto error;
		}

		rcode = pairparsevalue(new, str, 0);
		talloc_free(str);
		if (rcode < 0) {
			pairfree(&new);
			goto error;
		}
		new->op = map->op;
		*out = new;
		break;

	case TMPL_TYPE_LITERAL:
		new = pairalloc(request, da);
		if (!new) return -1;

		if (pairparsevalue(new, map->src->name, 0) < 0) {
			rcode = 0;
			goto error;
		}
		new->op = map->op;
		*out = new;
		break;

	case TMPL_TYPE_ATTR:
	{
		vp_cursor_t from;

		if (map->dst->type != TMPL_TYPE_ATTR) {
			rad_assert(map->dst->tmpl_da == NULL);
		} else {
			rad_assert(map->dst->tmpl_da != NULL);

			/*
			 *	Matching type, OR src/dst is octets.
			 */
			rad_assert((map->src->tmpl_da->type == map->dst->tmpl_da->type) ||
				   (map->src->tmpl_da->type == PW_TYPE_OCTETS) ||
				   (map->dst->tmpl_da->type == PW_TYPE_OCTETS));
		}

		/*
		 * @todo should log error, and return -1 for v3.1 (causes update to fail)
		 */
		if (radius_tmpl_copy_vp(request, &found, request, map->src) < 0) return 0;

		vp = fr_cursor_init(&from, &found);

		/*
		 *  Src/Dst attributes don't match, convert src attributes
		 *  to match dst.
		 */
		if ((map->dst->type == TMPL_TYPE_ATTR) &&
		    (map->src->tmpl_da->type != map->dst->tmpl_da->type)) {
			vp_cursor_t to;

			(void) fr_cursor_init(&to, out);
			for (; vp; vp = fr_cursor_next(&from)) {
				new = pairalloc(request, da);
				if (!new) return -1;
				if (pairdatacpy(new, vp->da, &vp->data, vp->length) < 0) {
					REDEBUG("Attribute conversion failed: %s", fr_strerror());
					pairfree(&found);
					pairfree(&new);
					return -1;
				}
				vp = fr_cursor_remove(&from);
				talloc_free(vp);

				new->op = map->op;
				fr_cursor_insert(&to, new);
			}
			return 0;
		}

		/*
		 *   Otherwise we just need to fixup the attribute types
		 *   and operators
		 */
		for (; vp; vp = fr_cursor_next(&from)) {
			vp->da = da;
			vp->op = map->op;
		}
		*out = found;
	}
		break;

	case TMPL_TYPE_DATA:
		rad_assert(map->src && map->src->tmpl_da);
		rad_assert(map->dst && map->dst->tmpl_da);
		rad_assert(map->src->tmpl_da->type == map->dst->tmpl_da->type);

		new = pairalloc(request, da);
		if (!new) return -1;

		if (pairdatacpy(new, map->src->tmpl_da, map->src->tmpl_value, map->src->tmpl_length) < 0) goto error;
		new->op = map->op;
		*out = new;
		break;

	/*
	 *	This essentially does the same as rlm_exec xlat, except it's non-configurable.
	 *	It's only really here as a convenience for people who expect the contents of
	 *	backticks to be executed in a shell.
	 *
	 *	exec string is xlat expanded and arguments are shell escaped.
	 */
	case TMPL_TYPE_EXEC:
		return map_exec_to_vp(out, request, map);

	default:
		rad_assert(0);	/* Should have been caught at parse time */

	error:
		pairfree(&vp);
		return rcode;
	}

	return 0;
}

#define DEBUG_OVERWRITE(_old, _new) \
do {\
	if (RDEBUG_ENABLED3) {\
		char *old = vp_aprint_value(request, _old, true);\
		char *new = vp_aprint_value(request, _new, true);\
		RDEBUG3("Overwriting value \"%s\" with \"%s\"", old, new);\
		talloc_free(old);\
		talloc_free(new);\
	}\
} while (0)

/** Convert value_pair_map_t to VALUE_PAIR(s) and add them to a REQUEST.
 *
 * Takes a single value_pair_map_t, resolves request and list identifiers
 * to pointers in the current request, then attempts to retrieve module
 * specific value(s) using callback, and adds the resulting values to the
 * correct request/list.
 *
 * @param request The current request.
 * @param map specifying destination attribute and location and src identifier.
 * @param func to retrieve module specific values and convert them to
 *	VALUE_PAIRS.
 * @param ctx to be passed to func.
 * @return -1 if the operation failed, -2 in the source attribute wasn't valid, 0 on success.
 */
int map_to_request(REQUEST *request, value_pair_map_t const *map, radius_map_getvalue_t func, void *ctx)
{
	int rcode = 0;
	int num;
	VALUE_PAIR **list, *vp, *dst, *head = NULL;
	bool found = false;
	REQUEST *context;
	TALLOC_CTX *parent;
	vp_cursor_t dst_list, src_list;

	/*
	 *	Sanity check inputs.  We can have a list or attribute
	 *	as a destination.
	 */
	if ((map->dst->type != TMPL_TYPE_LIST) &&
	    (map->dst->type != TMPL_TYPE_ATTR)) {
		REDEBUG("Invalid mapping destination");
		return -2;
	}

	context = request;
	if (radius_request(&context, map->dst->tmpl_request) < 0) {
		REDEBUG("Mapping \"%s\" -> \"%s\" invalid in this context", map->src->name, map->dst->name);
		return -2;
	}

	/*
	 *	If there's no CoA packet and we're updating it,
	 *	auto-allocate it.
	 */
	if (((map->dst->tmpl_list == PAIR_LIST_COA) ||
	     (map->dst->tmpl_list == PAIR_LIST_DM)) && !request->coa) {
		request_alloc_coa(context);
		context->coa->proxy->code = (map->dst->tmpl_list == PAIR_LIST_COA) ?
					    PW_CODE_COA_REQUEST :
					    PW_CODE_DISCONNECT_REQUEST;
	}

	list = radius_list(context, map->dst->tmpl_list);
	if (!list) {
		REDEBUG("Mapping \"%s\" -> \"%s\" invalid in this context", map->src->name, map->dst->name);

		return -2;
	}

	parent = radius_list_ctx(context, map->dst->tmpl_list);
	rad_assert(parent);

	/*
	 *	The callback should either return -1 to signify operations error,
	 *	-2 when it can't find the attribute or list being referenced, or
	 *	0 to signify success. It may return "sucess", but still have no
	 *	VPs to work with.
	 */
	if (map->src->type != TMPL_TYPE_NULL) {
		rcode = func(&head, request, map, ctx);
		if (rcode < 0) {
			rad_assert(!head);
			return rcode;
		}
		if (!head) return rcode;
	} else {
		if (debug_flag) map_debug_log(request, map, NULL);
	}

	/*
	 *	Reparent the VPs (func may return multiple)
	 */
	for (vp = fr_cursor_init(&src_list, &head);
	     vp;
	     vp = fr_cursor_next(&src_list)) {
		VERIFY_VP(vp);

		if (debug_flag) map_debug_log(request, map, vp);
		(void) talloc_steal(parent, vp);
	}

	/*
	 *	The destination is a list (which is a completely different set of operations)
	 */
	if (map->dst->type == TMPL_TYPE_LIST) {
		switch (map->op) {
		case T_OP_CMP_FALSE:
			/* We don't need the src VPs (should just be 'ANY') */
			rad_assert(!head);

			/* Clear the entire dst list */
			pairfree(list);

			if (map->dst->tmpl_list == PAIR_LIST_REQUEST) {
				context->username = NULL;
				context->password = NULL;
			}
			return 0;

		case T_OP_SET:
			if (map->src->type == TMPL_TYPE_LIST) {
				pairfree(list);
				*list = head;
			} else {
		case T_OP_EQ:
				rad_assert(map->src->type == TMPL_TYPE_EXEC);
				pairmove(parent, list, &head);
				pairfree(&head);
			}
			goto finish;

		case T_OP_ADD:
			pairadd(list, head);
			head = NULL;
			goto finish;

		default:
			pairfree(&head);
			return -1;
		}
	}

	/*
	 *	Find the destination attribute.  We leave with either
	 *	the dst_list and vp pointing to the attribute or the VP
	 *	being NULL (no attribute at that index).
	 */
	num = map->dst->tmpl_num;
	(void) fr_cursor_init(&dst_list, list);
	if (num != NUM_ANY) {
		while ((dst = fr_cursor_next_by_da(&dst_list, map->dst->tmpl_da, map->dst->tmpl_tag))) {
			if (num-- == 0) break;
		}
	} else {
		dst = fr_cursor_next_by_da(&dst_list, map->dst->tmpl_da, map->dst->tmpl_tag);
	}
	rad_assert(!dst || (map->dst->tmpl_da == dst->da));

	/*
	 *	The destination is an attribute
	 */
	switch (map->op) {
	default:
		break;
	/*
	 * 	!* - Remove all attributes which match dst in the specified list.
	 *	This doesn't use attributes returned by the func(), and immediately frees them.
	 */
	case T_OP_CMP_FALSE:
		/* We don't need the src VPs (should just be 'ANY') */
		rad_assert(!head);
		if (!dst) return 0;

		/*
		 *	Wildcard: delete all of the matching ones, based on tag.
		 */
		if (map->dst->tmpl_num == NUM_ANY) {
			pairdelete(list, map->dst->tmpl_da->attr, map->dst->tmpl_da->vendor, map->dst->tmpl_tag);
			dst = NULL;
		/*
		 *	We've found the Nth one.  Delete it, and only it.
		 */
		} else {
			dst = fr_cursor_remove(&dst_list);
			pairfree(&dst);
		}

		/*
		 *	Check that the User-Name and User-Password
		 *	caches point to the correct attribute.
		 */
		goto finish;

	/*
	 *	-= - Delete attributes in the dst list which match any of the
	 *	src_list attributes.
	 *
	 *	This operation has two modes:
	 *	- If map->dst->tmpl_num > 0, we check each of the src_list attributes against
	 *	  the dst attribute, to see if any of their values match.
	 *	- If map->dst->tmpl_num == NUM_ANY, we compare all instances of the dst attribute
	 *	  against each of the src_list attributes.
	 */
	case T_OP_SUB:
		/* We didn't find any attributes earlier */
		if (!dst) {
			pairfree(&head);
			return 0;
		}

		/*
		 *	Instance specific[n] delete
		 */
		if (map->dst->tmpl_num != NUM_ANY) {
			for (vp = fr_cursor_first(&src_list);
			     vp;
			     vp = fr_cursor_next(&src_list)) {
				head->op = T_OP_CMP_EQ;
				rcode = radius_compare_vps(request, vp, dst);
				if (rcode == 0) {
					dst = fr_cursor_remove(&dst_list);
					pairfree(&dst);
					found = true;
				}
			}
			pairfree(&head);
			if (!found) return 0;
			goto finish;
		}

		/*
		 *	All instances[*] delete
		 */
		for (dst = fr_cursor_current(&dst_list);
		     dst;
		     dst = fr_cursor_next_by_da(&dst_list, map->dst->tmpl_da, map->dst->tmpl_tag)) {
			for (vp = fr_cursor_first(&src_list);
			     vp;
			     vp = fr_cursor_next(&src_list)) {
				head->op = T_OP_CMP_EQ;
				rcode = radius_compare_vps(request, vp, dst);
				if (rcode == 0) {
					dst = fr_cursor_remove(&dst_list);
					pairfree(&dst);
					found = true;
				}
			}
		}
		pairfree(&head);
		if (!found) return 0;
		goto finish;
	}

	/*
	 *	Another fixup pass to set tags on attributes were about to insert
	 */
	if (map->dst->tmpl_tag != TAG_ANY) {
		for (vp = fr_cursor_init(&src_list, &head);
		     vp;
		     vp = fr_cursor_next(&src_list)) {
			vp->tag = map->dst->tmpl_tag;
		}
	}

	switch (map->op) {
	/*
	 *	= - Set only if not already set
	 */
	case T_OP_EQ:
		if (dst) {
			RDEBUG3("Refusing to overwrite (use :=)");
			pairfree(&head);
			return 0;
		}

		/* Insert first instance (if multiple) */
		fr_cursor_first(&src_list);
		fr_cursor_insert(&dst_list, fr_cursor_remove(&src_list));
		/* Free any we didn't insert */
		pairfree(&head);
		break;

	/*
	 *	:= - Overwrite existing attribute with last src_list attribute
	 */
	case T_OP_SET:
		/* Wind to last instance */
		fr_cursor_last(&src_list);
		if (dst) {
			dst = fr_cursor_remove(&dst_list);
			DEBUG_OVERWRITE(dst, fr_cursor_current(&src_list));
			pairfree(&dst);
		}
		fr_cursor_insert(&dst_list, fr_cursor_remove(&src_list));
		/* Free any we didn't insert */
		pairfree(&head);
		break;

	/*
	 *	+= - Add all src_list attributes to the destination
	 */
	case T_OP_ADD:
		/* Insert all the instances! (if multiple) */
		pairadd(list, head);
		head = NULL;
		break;

	/*
	 *	Filtering operators
	 */
	default:
		/*
		 *	If the dst doesn't exist, the filters will add
		 *	it with the given value.
		 */
		if (!dst) {
			RDEBUG3("No existing attribute to filter, adding instead");
			fr_cursor_merge(&dst_list, head);
			head = NULL;
			goto finish;
		}

		/*
		 *	The LHS exists.  We need to limit it's value based on
		 *	the operator, and the value of the RHS.
		 */
		found = false;
		for (vp = fr_cursor_first(&src_list);
		     vp;
		     vp = fr_cursor_next(&src_list)) {
			vp->op = map->op;
			rcode = radius_compare_vps(request, vp, dst);
			vp->op = T_OP_SET;

			switch (map->op) {
			case T_OP_CMP_EQ:
				if (rcode == 0) continue;
			replace:
				dst = fr_cursor_remove(&dst_list);
				DEBUG_OVERWRITE(dst, fr_cursor_current(&src_list));
				pairfree(&dst);
				fr_cursor_insert(&dst_list, fr_cursor_remove(&src_list));
				found = true;
				continue;

			case T_OP_LE:
				if (rcode <= 0) continue;
				goto replace;

			case T_OP_GE:
				if (rcode >= 0) continue;
				goto replace;

			default:
				pairfree(&head);
				return -1;
			}
		}
		pairfree(&head);
		if (!found) return 0;

		break;
	}

finish:
	rad_assert(!head);

	if (map->dst->tmpl_list == PAIR_LIST_REQUEST) {
		context->username = pairfind(*list, PW_USER_NAME, 0, TAG_ANY);
		context->password = pairfind(*list, PW_USER_PASSWORD, 0, TAG_ANY);
	}
	return 0;
}

/** Check whether the destination of a map is currently valid
 *
 * @param request The current request.
 * @param map to check.
 * @return true if the map resolves to a request and list else false.
 */
bool map_dst_valid(REQUEST *request, value_pair_map_t const *map)
{
	REQUEST *context = request;

	if (radius_request(&context, map->dst->tmpl_request) < 0) return false;
	if (!radius_list(context, map->dst->tmpl_list)) return false;

	return true;
}

/**  Print a map to a string
 *
 * @param[out] buffer for the output string
 * @param[in] bufsize of the buffer
 * @param[in] map to print
 * @return the size of the string printed
 */
size_t map_print(char *buffer, size_t bufsize, value_pair_map_t const *map)
{
	size_t len;
	char *p = buffer;
	char *end = buffer + bufsize;

	len = radius_tmpl2str(buffer, bufsize, map->dst);
	p += len;

	*(p++) = ' ';
	strlcpy(p, fr_token_name(map->op), end - p);
	p += strlen(p);
	*(p++) = ' ';

	/*
	 *	The RHS doesn't matter for many operators
	 */
	if ((map->op == T_OP_CMP_TRUE) ||
	    (map->op == T_OP_CMP_FALSE)) {
		strlcpy(p, "ANY", (end - p));
		p += strlen(p);
		return p - buffer;
	}

	rad_assert(map->src != NULL);

	if ((map->dst->type == TMPL_TYPE_ATTR) &&
	    (map->dst->tmpl_da->type == PW_TYPE_STRING) &&
	    (map->src->type == TMPL_TYPE_LITERAL)) {
		*(p++) = '\'';
		len = radius_tmpl2str(p, end - p, map->src);
		p += len;
		*(p++) = '\'';
		*p = '\0';
	} else {
		len = radius_tmpl2str(p, end - p, map->src);
		p += len;
	}

	return p - buffer;
}

/*
 *	Debug print a map / VP
 */
void map_debug_log(REQUEST *request, value_pair_map_t const *map, VALUE_PAIR const *vp)
{
	char *value;
	char buffer[1024];

	rad_assert(vp || (map->src->type == TMPL_TYPE_NULL));

	switch (map->src->type) {
	/*
	 *	Just print the value being assigned
	 */
	default:
	case TMPL_TYPE_LITERAL:
		vp_prints_value(buffer, sizeof(buffer), vp, '\'');
		value = buffer;
		break;

	case TMPL_TYPE_XLAT:
	case TMPL_TYPE_XLAT_STRUCT:
		vp_prints_value(buffer, sizeof(buffer), vp, '"');
		value = buffer;
		break;

	case TMPL_TYPE_DATA:
		vp_prints_value(buffer, sizeof(buffer), vp, '\'');
		value = buffer;
		break;

	/*
	 *	Just printing the value doesn't make sense, but we still
	 *	want to know what it was...
	 */
	case TMPL_TYPE_LIST:
		vp_prints_value(buffer, sizeof(buffer), vp, '\'');

		if (map->src->tmpl_request == REQUEST_OUTER) {
			value = talloc_typed_asprintf(request, "&outer.%s:%s -> %s",
						      fr_int2str(pair_lists, map->src->tmpl_list, "<INVALID>"),
						      vp->da->name, buffer);
		} else {
			value = talloc_typed_asprintf(request, "&%s:%s -> %s",
						      fr_int2str(pair_lists, map->src->tmpl_list, "<INVALID>"),
						      vp->da->name, buffer);
		}
		break;

	case TMPL_TYPE_ATTR:
		vp_prints_value(buffer, sizeof(buffer), vp, '\'');
		value = talloc_typed_asprintf(request, "&%s -> %s", map->src->tmpl_da->name, buffer);
		break;

	case TMPL_TYPE_NULL:
		strcpy(buffer, "ANY");
		value = buffer;
		break;
	}

	switch (map->dst->type) {
	case TMPL_TYPE_LIST:
		RDEBUG("\t%s%s %s %s", map->dst->name, vp ? vp->da->name : "",
		       fr_int2str(fr_tokens, vp ? vp->op : map->op, "<INVALID>"), value);
		break;

	case TMPL_TYPE_ATTR:
		RDEBUG("\t%s %s %s", map->dst->name,
		       fr_int2str(fr_tokens, vp ? vp->op : map->op, "<INVALID>"), value);
		break;

	default:
		break;
	}

	if (value != buffer) talloc_free(value);
}
