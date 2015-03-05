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

/** re-parse a map where the lhs is an unknown attribute.
 *
 *
 * @param map to process.
 * @param rhs_type quotation type around rhs.
 * @param rhs string to re-parse.
 */
bool map_cast_from_hex(value_pair_map_t *map, FR_TOKEN rhs_type, char const *rhs)
{
	size_t len;
	ssize_t rlen;
	uint8_t *ptr;

	DICT_ATTR const *da;
	VALUE_PAIR *vp;
	value_pair_tmpl_t *vpt;

	rad_assert(map != NULL);

	rad_assert(map->lhs != NULL);
	rad_assert(map->lhs->type == TMPL_TYPE_ATTR);

	rad_assert(map->rhs == NULL);
	rad_assert(rhs != NULL);

	VERIFY_MAP(map);

	/*
	 *	If the attribute is still unknown, go parse the RHS.
	 */
	da = dict_attrbyvalue(map->lhs->tmpl_da->attr, map->lhs->tmpl_da->vendor);
	if (!da || da->flags.is_unknown) return false;

	/*
	 *	If the RHS is something OTHER than an octet
	 *	string, go parse it as that.
	 */
	if (rhs_type != T_BARE_WORD) return false;
	if ((rhs[0] != '0') || (tolower((int)rhs[1]) != 'x')) return false;
	if (!rhs[2]) return false;

	len = strlen(rhs + 2);

	ptr = talloc_array(map, uint8_t, len >> 1);
	if (!ptr) return false;

	len = fr_hex2bin(ptr, len >> 1, rhs + 2, len);

	/*
	 *	If we can't parse it, or if it's malformed,
	 *	it's still unknown.
	 */
	rlen = data2vp(NULL, NULL, NULL, NULL, da, ptr, len, len, &vp);
	talloc_free(ptr);

	if (rlen < 0) return false;

	if ((size_t) rlen < len) {
	free_vp:
		pairfree(&vp);
		return false;
	}

	/*
	 *	Was still parsed as an unknown attribute.
	 */
	if (vp->da->flags.is_unknown) goto free_vp;

	/*
	 *	Set the RHS to the PARSED name, not the crap octet
	 *	string which was input.
	 */
	map->rhs = tmpl_alloc(map, TMPL_TYPE_DATA, NULL, 0);
	if (!map->rhs) goto free_vp;

	map->rhs->tmpl_data_type = da->type;
	map->rhs->tmpl_data_length = vp->vp_length;
	if (vp->da->flags.is_pointer) {
		map->rhs->tmpl_data_value.ptr = talloc_memdup(map->rhs, vp->data.ptr, vp->vp_length);
	} else {
		memcpy(&map->rhs->tmpl_data_value, &vp->data, sizeof(map->rhs->tmpl_data_value));
	}
	map->rhs->name = vp_aprints_value(map->rhs, vp, '"');

	/*
	 *	Set the LHS to the REAL attribute name.
	 */
	vpt = tmpl_alloc(map, TMPL_TYPE_ATTR, map->lhs->tmpl_da->name, -1);
	memcpy(&vpt->data.attribute, &map->lhs->data.attribute, sizeof(vpt->data.attribute));
	vpt->tmpl_da = da;

	talloc_free(map->lhs);
	map->lhs = vpt;

	pairfree(&vp);

	VERIFY_MAP(map);

	return true;
}

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
 * @param[in] ctx for talloc.
 * @param[in] out Where to write the pointer to the new value_pair_map_struct.
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
int map_afrom_cp(TALLOC_CTX *ctx, value_pair_map_t **out, CONF_PAIR *cp,
		 request_refs_t dst_request_def, pair_lists_t dst_list_def,
		 request_refs_t src_request_def, pair_lists_t src_list_def)
{
	value_pair_map_t *map;
	char const *attr, *value;
	ssize_t slen;
	FR_TOKEN type;

	*out = NULL;

	if (!cp) return -1;

	map = talloc_zero(ctx, value_pair_map_t);
	map->op = cf_pair_operator(cp);
	map->ci = cf_pair_to_item(cp);

	attr = cf_pair_attr(cp);
	value = cf_pair_value(cp);
	if (!value) {
		cf_log_err_cp(cp, "Missing attribute value");
		goto error;
	}

	/*
	 *	LHS may be an expansion (that expands to an attribute reference)
	 *	or an attribute reference. Quoting determines which it is.
	 */
	type = cf_pair_attr_type(cp);
	switch (type) {
	case T_DOUBLE_QUOTED_STRING:
	case T_BACK_QUOTED_STRING:
		slen = tmpl_afrom_str(ctx, &map->lhs, attr, talloc_array_length(attr) - 1,
				      type, dst_request_def, dst_list_def, true);
		if (slen <= 0) {
			char *spaces, *text;

		marker:
			fr_canonicalize_error(ctx, &spaces, &text, slen, attr);
			cf_log_err_cp(cp, "%s", text);
			cf_log_err_cp(cp, "%s^ %s", spaces, fr_strerror());

			talloc_free(spaces);
			talloc_free(text);
			goto error;
		}
		break;

	default:
		slen = tmpl_afrom_attr_str(ctx, &map->lhs, attr, dst_request_def, dst_list_def, true, true);
		if (slen <= 0) {
			cf_log_err_cp(cp, "Failed parsing attribute reference");

			goto marker;
		}

		if (tmpl_define_unknown_attr(map->lhs) < 0) {
			cf_log_err_cp(cp, "Failed creating attribute %s: %s",
				      map->lhs->name, fr_strerror());
			goto error;
		}
		break;
	}

	/*
	 *	RHS might be an attribute reference.
	 */
	type = cf_pair_value_type(cp);

	if ((type == T_BARE_WORD) && (value[0] == '0') && (tolower((int)value[1] == 'x')) &&
		map_cast_from_hex(map, type, value)) {
		/* do nothing */
	} else {
		slen = tmpl_afrom_str(map, &map->rhs, value, strlen(value), type, src_request_def, src_list_def, true);
		if (slen < 0) goto marker;
		if (tmpl_define_unknown_attr(map->rhs) < 0) {
			cf_log_err_cp(cp, "Failed creating attribute %s: %s", map->rhs->name, fr_strerror());
			goto error;
		}
	}
	if (!map->rhs) {
		cf_log_err_cp(cp, "%s", fr_strerror());
		goto error;
	}

	VERIFY_MAP(map);

	*out = map;

	return 0;

error:
	talloc_free(map);
	return -1;
}

/** Convert an 'update' config section into an attribute map.
 *
 * Uses 'name2' of section to set default request and lists.
 *
 * @param[in] cs the update section
 * @param[out] out Where to store the head of the map.
 * @param[in] dst_list_def The default destination list, usually dictated by
 * 	the section the module is being called in.
 * @param[in] src_list_def The default source list, usually dictated by the
 *	section the module is being called in.
 * @param[in] validate map using this callback (may be NULL).
 * @param[in] ctx to pass to callback.
 * @param[in] max number of mappings to process.
 * @return -1 on error, else 0.
 */
int map_afrom_cs(value_pair_map_t **out, CONF_SECTION *cs,
		 pair_lists_t dst_list_def, pair_lists_t src_list_def,
		 map_validate_t validate, void *ctx,
		 unsigned int max)
{
	char const *cs_list, *p;

	request_refs_t request_def = REQUEST_CURRENT;

	CONF_ITEM *ci;
	CONF_PAIR *cp;

	unsigned int total = 0;
	value_pair_map_t **tail, *map;
	TALLOC_CTX *parent;

	*out = NULL;
	tail = out;

	if (!cs) return 0;

	/*
	 *	The first map has cs as the parent.
	 *	The rest have the previous map as the parent.
	 */
	parent = cs;

	ci = cf_section_to_item(cs);

	cs_list = p = cf_section_name2(cs);
	if (cs_list) {
		p += radius_request_name(&request_def, p, REQUEST_CURRENT);
		if (request_def == REQUEST_UNKNOWN) {
			cf_log_err(ci, "Default request specified in mapping section is invalid");
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
			cf_log_err(ci, "Entry is not in \"attribute = value\" format");
			goto error;
		}

		cp = cf_item_to_pair(ci);
		if (map_afrom_cp(parent, &map, cp, request_def, dst_list_def, REQUEST_CURRENT, src_list_def) < 0) {
			goto error;
		}

		VERIFY_MAP(map);

		/*
		 *	Check the types in the map are valid
		 */
		if (validate && (validate(map, ctx) < 0)) goto error;

		parent = *tail = map;
		tail = &(map->next);
	}

	return 0;
error:
	TALLOC_FREE(*out);
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
 * @param[out] out Where to store the head of the map.
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
int map_afrom_fields(TALLOC_CTX *ctx, value_pair_map_t **out, char const *lhs, FR_TOKEN lhs_type,
		     FR_TOKEN op, char const *rhs, FR_TOKEN rhs_type,
		     request_refs_t dst_request_def,
		     pair_lists_t dst_list_def,
		     request_refs_t src_request_def,
		     pair_lists_t src_list_def)
{
	ssize_t slen;
	value_pair_map_t *map;

	map = talloc_zero(ctx, value_pair_map_t);

	slen = tmpl_afrom_str(map, &map->lhs, lhs, strlen(lhs), lhs_type, dst_request_def, dst_list_def, true);
	if (slen < 0) {
	error:
		talloc_free(map);
		return -1;
	}

	map->op = op;

	if ((map->lhs->type == TMPL_TYPE_ATTR) &&
	    map->lhs->tmpl_da->flags.is_unknown &&
	    map_cast_from_hex(map, rhs_type, rhs)) {
		return 0;
	}

	slen = tmpl_afrom_str(map, &map->rhs, rhs, strlen(rhs), rhs_type, src_request_def, src_list_def, true);
	if (slen < 0) goto error;

	VERIFY_MAP(map);

	*out = map;

	return 0;
}

/** Convert a value pair string to valuepair map
 *
 * Takes a valuepair string with list and request qualifiers and converts it into a
 * value_pair_map_t.
 *
 * @param ctx where to allocate the map.
 * @param out Where to write the new map (must be freed with talloc_free()).
 * @param vp_str string to parse.
 * @param dst_request_def to use if attribute isn't qualified.
 * @param dst_list_def to use if attribute isn't qualified.
 * @param src_request_def to use if attribute isn't qualified.
 * @param src_list_def to use if attribute isn't qualified.
 * @return 0 on success, < 0 on error.
 */
int map_afrom_attr_str(TALLOC_CTX *ctx, value_pair_map_t **out, char const *vp_str,
		       request_refs_t dst_request_def, pair_lists_t dst_list_def,
		       request_refs_t src_request_def, pair_lists_t src_list_def)
{
	char const *p = vp_str;
	FR_TOKEN quote;

	VALUE_PAIR_RAW raw;
	value_pair_map_t *map = NULL;

	quote = gettoken(&p, raw.l_opand, sizeof(raw.l_opand), false);
	switch (quote) {
	case T_BARE_WORD:
		break;

	case T_INVALID:
	error:
		return -1;

	default:
		fr_strerror_printf("Left operand must be an attribute");
		return -1;
	}

	raw.op = getop(&p);
	if (raw.op == T_INVALID) goto error;

	raw.quote = gettoken(&p, raw.r_opand, sizeof(raw.r_opand), false);
	if (raw.quote == T_INVALID) goto error;
	if (!fr_str_tok[raw.quote]) {
		fr_strerror_printf("Right operand must be an attribute or string");
		return -1;
	}

	if (map_afrom_fields(ctx, &map, raw.l_opand, T_BARE_WORD, raw.op, raw.r_opand, raw.quote,
			     dst_request_def, dst_list_def, src_request_def, src_list_def) < 0) {
		return -1;
	}

	rad_assert(map != NULL);
	*out = map;

	VERIFY_MAP(map);

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

	VERIFY_MAP(map);

	rad_assert(map->rhs->type == TMPL_TYPE_EXEC);
	rad_assert((map->lhs->type == TMPL_TYPE_ATTR) || (map->lhs->type == TMPL_TYPE_LIST));

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
	result = radius_exec_program(answer, sizeof(answer), (map->lhs->type == TMPL_TYPE_LIST) ? &output_pairs : NULL,
				     request, map->rhs->name, input_pairs ? *input_pairs : NULL,
				     true, true, EXEC_TIMEOUT);
	talloc_free(expanded);
	if (result != 0) {
		talloc_free(output_pairs);
		return -1;
	}

	switch (map->lhs->type) {
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

		vp = pairalloc(request, map->lhs->tmpl_da);
		if (!vp) return -1;
		vp->op = map->op;
		if (pairparsevalue(vp, answer, -1) < 0) {
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
	ssize_t len;
	VALUE_PAIR *vp = NULL, *new, *found = NULL;
	REQUEST *context = request;
	vp_cursor_t cursor;
	ssize_t slen;
	char *str;

	*out = NULL;

	VERIFY_MAP(map);
	rad_assert(map->lhs != NULL);
	rad_assert(map->rhs != NULL);

	rad_assert((map->lhs->type == TMPL_TYPE_LIST) || (map->lhs->type == TMPL_TYPE_ATTR));

	/*
	 *	Special case for !*, we don't need to parse RHS as this is a unary operator.
	 */
	if (map->op == T_OP_CMP_FALSE) return 0;

	/*
	 *	List to list found, this is a special case because we don't need
	 *	to allocate any attributes, just finding the current list, and change
	 *	the op.
	 */
	if ((map->lhs->type == TMPL_TYPE_LIST) && (map->rhs->type == TMPL_TYPE_LIST)) {
		VALUE_PAIR **from = NULL;

		if (radius_request(&context, map->rhs->tmpl_request) == 0) {
			from = radius_list(context, map->rhs->tmpl_list);
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
	 *	And parse the RHS
	 */
	switch (map->rhs->type) {
	case TMPL_TYPE_XLAT_STRUCT:
		rad_assert(map->lhs->type == TMPL_TYPE_ATTR);
		rad_assert(map->lhs->tmpl_da);	/* We need to know which attribute to create */
		rad_assert(map->rhs->tmpl_xlat != NULL);

		new = pairalloc(request, map->lhs->tmpl_da);
		if (!new) return -1;

		str = NULL;
		slen = radius_axlat_struct(&str, request, map->rhs->tmpl_xlat, NULL, NULL);
		if (slen < 0) {
			rcode = slen;
			goto error;
		}

		/*
		 *	We do the debug printing because radius_axlat_struct
		 *	doesn't have access to the original string.  It's been
		 *	mangled during the parsing to xlat_exp_t
		 */
		RDEBUG2("EXPAND %s", map->rhs->name);
		RDEBUG2("   --> %s", str);

		rcode = pairparsevalue(new, str, -1);
		talloc_free(str);
		if (rcode < 0) {
			pairfree(&new);
			goto error;
		}
		new->op = map->op;
		*out = new;
		break;

	case TMPL_TYPE_XLAT:
		rad_assert(map->lhs->type == TMPL_TYPE_ATTR);
		rad_assert(map->lhs->tmpl_da);	/* We need to know which attribute to create */

		new = pairalloc(request, map->lhs->tmpl_da);
		if (!new) return -1;

		str = NULL;
		slen = radius_axlat(&str, request, map->rhs->name, NULL, NULL);
		if (slen < 0) {
			rcode = slen;
			goto error;
		}

		rcode = pairparsevalue(new, str, -1);
		talloc_free(str);
		if (rcode < 0) {
			pairfree(&new);
			goto error;
		}
		new->op = map->op;
		*out = new;
		break;

	case TMPL_TYPE_LITERAL:
		rad_assert(map->lhs->type == TMPL_TYPE_ATTR);
		rad_assert(map->lhs->tmpl_da);	/* We need to know which attribute to create */

		new = pairalloc(request, map->lhs->tmpl_da);
		if (!new) return -1;

		if (pairparsevalue(new, map->rhs->name, -1) < 0) {
			rcode = 0;
			goto error;
		}
		new->op = map->op;
		*out = new;
		break;

	case TMPL_TYPE_ATTR:
	{
		vp_cursor_t from;

		rad_assert(((map->lhs->type == TMPL_TYPE_ATTR) && map->lhs->tmpl_da) ||
			   ((map->lhs->type == TMPL_TYPE_LIST) && !map->lhs->tmpl_da));

		/*
		 * @todo should log error, and return -1 for v3.1 (causes update to fail)
		 */
		if (tmpl_copy_vps(request, &found, request, map->rhs) < 0) return 0;

		vp = fr_cursor_init(&from, &found);

		/*
		 *  Src/Dst attributes don't match, convert src attributes
		 *  to match dst.
		 */
		if ((map->lhs->type == TMPL_TYPE_ATTR) &&
		    (map->rhs->tmpl_da->type != map->lhs->tmpl_da->type)) {
			vp_cursor_t to;

			(void) fr_cursor_init(&to, out);
			for (; vp; vp = fr_cursor_next(&from)) {
				new = pairalloc(request, map->lhs->tmpl_da);
				if (!new) return -1;

				len = value_data_cast(new, &new->data, new->da->type, new->da,
						      vp->da->type, vp->da, &vp->data, vp->vp_length);
				if (len < 0) {
					REDEBUG("Attribute conversion failed: %s", fr_strerror());
					pairfree(&found);
					pairfree(&new);
					return -1;
				}

				new->vp_length = len;
				vp = fr_cursor_remove(&from);
				talloc_free(vp);

				if (new->da->type == PW_TYPE_STRING) {
					rad_assert(new->vp_strvalue != NULL);
				}

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
			vp->da = map->lhs->tmpl_da;
			vp->op = map->op;
		}
		*out = found;
	}
		break;

	case TMPL_TYPE_DATA:
		rad_assert(map->lhs->tmpl_da);
		rad_assert(map->lhs->type == TMPL_TYPE_ATTR);
		rad_assert(map->lhs->tmpl_da->type == map->rhs->tmpl_data_type);

		new = pairalloc(request, map->lhs->tmpl_da);
		if (!new) return -1;

		len = value_data_copy(new, &new->data, new->da->type, &map->rhs->tmpl_data_value,
				      map->rhs->tmpl_data_length);
		if (len < 0) goto error;

		new->vp_length = len;
		new->op = map->op;
		*out = new;

		VERIFY_MAP(map);
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
		char *old = vp_aprints_value(request, _old, '"');\
		char *new = vp_aprints_value(request, _new, '"');\
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

	value_pair_map_t	exp_map;
	value_pair_tmpl_t	exp_lhs;

	VERIFY_MAP(map);
	rad_assert(map->lhs != NULL);
	rad_assert(map->rhs != NULL);

	/*
	 *	Preprocessing of the LHS of the map.
	 */
	switch (map->lhs->type) {
	/*
	 *	Already in the correct form.
	 */
	case TMPL_TYPE_LIST:
	case TMPL_TYPE_ATTR:
		break;

	/*
	 *	Everything else gets expanded, then re-parsed as an
	 *	attribute reference.
	 */
	case TMPL_TYPE_XLAT:
	case TMPL_TYPE_XLAT_STRUCT:
	case TMPL_TYPE_EXEC:
	{
		char *attr;
		ssize_t slen;

		slen = tmpl_aexpand(request, &attr, request, map->lhs, NULL, NULL);
		if (slen <= 0) {
			REDEBUG("Left side \"%.*s\" of map failed expansion", (int)map->lhs->len, map->lhs->name);
			rad_assert(!attr);
			return -1;
		}

		slen = tmpl_from_attr_str(&exp_lhs, attr, REQUEST_CURRENT, PAIR_LIST_REQUEST, false, false) ;
		if (slen <= 0) {
			REDEBUG("Left side \"%.*s\" expansion not an attribute reference: %s",
				(int)map->lhs->len, map->lhs->name, fr_strerror());
			talloc_free(attr);
			return -1;
		}
		rad_assert((exp_lhs.type == TMPL_TYPE_ATTR) || (exp_lhs.type == TMPL_TYPE_LIST));

		memcpy(&exp_map, map, sizeof(exp_map));
		exp_map.lhs = &exp_lhs;
		map = &exp_map;
	}
		break;

	default:
		rad_assert(0);
		break;
	}


	/*
	 *	Sanity check inputs.  We can have a list or attribute
	 *	as a destination.
	 */
	if ((map->lhs->type != TMPL_TYPE_LIST) &&
	    (map->lhs->type != TMPL_TYPE_ATTR)) {
		REDEBUG("Left side \"%.*s\" of map should be an attr or list but is an %s",
			(int)map->lhs->len, map->lhs->name,
			fr_int2str(tmpl_names, map->lhs->type, "<INVALID>"));
		return -2;
	}

	context = request;
	if (radius_request(&context, map->lhs->tmpl_request) < 0) {
		REDEBUG("Mapping \"%.*s\" -> \"%.*s\" invalid in this context",
			(int)map->rhs->len, map->rhs->name, (int)map->lhs->len, map->lhs->name);
		return -2;
	}

	/*
	 *	If there's no CoA packet and we're updating it,
	 *	auto-allocate it.
	 */
	if (((map->lhs->tmpl_list == PAIR_LIST_COA) ||
	     (map->lhs->tmpl_list == PAIR_LIST_DM)) && !request->coa) {
		request_alloc_coa(context);
		context->coa->proxy->code = (map->lhs->tmpl_list == PAIR_LIST_COA) ?
					    PW_CODE_COA_REQUEST :
					    PW_CODE_DISCONNECT_REQUEST;
	}

	list = radius_list(context, map->lhs->tmpl_list);
	if (!list) {
		REDEBUG("Mapping \"%.*s\" -> \"%.*s\" invalid in this context",
			(int)map->rhs->len, map->rhs->name, (int)map->lhs->len, map->lhs->name);

		return -2;
	}

	parent = radius_list_ctx(context, map->lhs->tmpl_list);
	rad_assert(parent);

	/*
	 *	The callback should either return -1 to signify operations error,
	 *	-2 when it can't find the attribute or list being referenced, or
	 *	0 to signify success. It may return "sucess", but still have no
	 *	VPs to work with.
	 */
	if (map->rhs->type != TMPL_TYPE_NULL) {
		rcode = func(&head, request, map, ctx);
		if (rcode < 0) {
			rad_assert(!head);
			return rcode;
		}
		if (!head) {
			RDEBUG2("No attributes updated");
			return rcode;
		}
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
		pairsteal(parent, vp);
	}

	/*
	 *	The destination is a list (which is a completely different set of operations)
	 */
	if (map->lhs->type == TMPL_TYPE_LIST) {
		switch (map->op) {
		case T_OP_CMP_FALSE:
			/* We don't need the src VPs (should just be 'ANY') */
			rad_assert(!head);

			/* Clear the entire dst list */
			pairfree(list);

			if (map->lhs->tmpl_list == PAIR_LIST_REQUEST) {
				context->username = NULL;
				context->password = NULL;
			}
			return 0;

		case T_OP_SET:
			if (map->rhs->type == TMPL_TYPE_LIST) {
				pairfree(list);
				*list = head;
				head = NULL;
			} else {
		case T_OP_EQ:
				rad_assert(map->rhs->type == TMPL_TYPE_EXEC);
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
	num = map->lhs->tmpl_num;
	(void) fr_cursor_init(&dst_list, list);
	if (num != NUM_ANY) {
		while ((dst = fr_cursor_next_by_da(&dst_list, map->lhs->tmpl_da, map->lhs->tmpl_tag))) {
			if (num-- == 0) break;
		}
	} else {
		dst = fr_cursor_next_by_da(&dst_list, map->lhs->tmpl_da, map->lhs->tmpl_tag);
	}
	rad_assert(!dst || (map->lhs->tmpl_da == dst->da));

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
		if (map->lhs->tmpl_num == NUM_ANY) {
			pairdelete(list, map->lhs->tmpl_da->attr, map->lhs->tmpl_da->vendor, map->lhs->tmpl_tag);
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
	 *	- If map->lhs->tmpl_num > 0, we check each of the src_list attributes against
	 *	  the dst attribute, to see if any of their values match.
	 *	- If map->lhs->tmpl_num == NUM_ANY, we compare all instances of the dst attribute
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
		if (map->lhs->tmpl_num != NUM_ANY) {
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
		     dst = fr_cursor_next_by_da(&dst_list, map->lhs->tmpl_da, map->lhs->tmpl_tag)) {
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
	if (map->lhs->tmpl_tag != TAG_ANY) {
		for (vp = fr_cursor_init(&src_list, &head);
		     vp;
		     vp = fr_cursor_next(&src_list)) {
			vp->tag = map->lhs->tmpl_tag;
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

	/*
	 *	Update the cached username && password.  This is code
	 *	we execute on EVERY update (sigh) so that SOME modules
	 *	MIGHT NOT have to do the search themselves.
	 *
	 *	TBH, we should probably make each module just do the
	 *	search themselves.
	 */
	if (map->lhs->tmpl_list == PAIR_LIST_REQUEST) {
		context->username = NULL;
		context->password = NULL;

		for (vp = fr_cursor_init(&src_list, list);
		     vp;
		     vp = fr_cursor_next(&src_list)) {

			if (vp->da->vendor != 0) continue;
			if (vp->da->flags.has_tag) continue;

			if (!context->username && (vp->da->attr == PW_USER_NAME)) {
				context->username = vp;
				continue;
			}

			if (vp->da->attr == PW_STRIPPED_USER_NAME) {
				context->username = vp;
				continue;
			}

			if (vp->da->attr == PW_USER_PASSWORD) {
				context->password = vp;
				continue;
			}
		}
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

	VERIFY_MAP(map);

	if (radius_request(&context, map->lhs->tmpl_request) < 0) return false;
	if (!radius_list(context, map->lhs->tmpl_list)) return false;

	return true;
}

/**  Print a map to a string
 *
 * @param[out] buffer for the output string
 * @param[in] bufsize of the buffer
 * @param[in] map to print
 * @return the size of the string printed
 */
size_t map_prints(char *buffer, size_t bufsize, value_pair_map_t const *map)
{
	size_t len;
	DICT_ATTR const *da = NULL;
	char *p = buffer;
	char *end = buffer + bufsize;

	VERIFY_MAP(map);

	if (map->lhs->type == TMPL_TYPE_ATTR) da = map->lhs->tmpl_da;

	len = tmpl_prints(buffer, bufsize, map->lhs, da);
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

	rad_assert(map->rhs != NULL);

	if ((map->lhs->type == TMPL_TYPE_ATTR) &&
	    (map->lhs->tmpl_da->type == PW_TYPE_STRING) &&
	    (map->rhs->type == TMPL_TYPE_LITERAL)) {
		*(p++) = '\'';
		len = tmpl_prints(p, end - p, map->rhs, da);
		p += len;
		*(p++) = '\'';
		*p = '\0';
	} else {
		len = tmpl_prints(p, end - p, map->rhs, da);
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

	VERIFY_MAP(map);
	rad_assert(map->lhs != NULL);
	rad_assert(map->rhs != NULL);

	rad_assert(vp || (map->rhs->type == TMPL_TYPE_NULL));

	switch (map->rhs->type) {
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

		if (map->rhs->tmpl_request == REQUEST_OUTER) {
			value = talloc_typed_asprintf(request, "&outer.%s:%s -> %s",
						      fr_int2str(pair_lists, map->rhs->tmpl_list, "<INVALID>"),
						      vp->da->name, buffer);
		} else {
			value = talloc_typed_asprintf(request, "&%s:%s -> %s",
						      fr_int2str(pair_lists, map->rhs->tmpl_list, "<INVALID>"),
						      vp->da->name, buffer);
		}
		break;

	case TMPL_TYPE_ATTR:
		vp_prints_value(buffer, sizeof(buffer), vp, '\'');
		value = talloc_typed_asprintf(request, "&%s -> %s", map->rhs->tmpl_da->name, buffer);
		break;

	case TMPL_TYPE_NULL:
		strcpy(buffer, "ANY");
		value = buffer;
		break;
	}

	switch (map->lhs->type) {
	case TMPL_TYPE_LIST:
		RDEBUG("%s%s %s %s", map->lhs->name, vp ? vp->da->name : "",
		       fr_int2str(fr_tokens, vp ? vp->op : map->op, "<INVALID>"), value);
		break;

	case TMPL_TYPE_ATTR:
		RDEBUG("%s %s %s", map->lhs->name,
		       fr_int2str(fr_tokens, vp ? vp->op : map->op, "<INVALID>"), value);
		break;

	default:
		break;
	}

	if (value != buffer) talloc_free(value);
}
