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
 * @file src/lib/server/map.c
 *
 * @ingroup AVP
 *
 * @copyright 2013 The FreeRADIUS server project
 * @copyright 2013 Alan DeKok (aland@freeradius.org)
 */

RCSID("$Id$")

#include <freeradius-devel/server/exec.h>
#include <freeradius-devel/server/map.h>
#include <freeradius-devel/server/paircmp.h>
#include <freeradius-devel/util/debug.h>

#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/pair_cursor.h>
#include <freeradius-devel/util/pair_legacy.h>

#include <freeradius-devel/protocol/radius/rfc2865.h>
#include <freeradius-devel/protocol/freeradius/freeradius.internal.h>

#include <ctype.h>

#ifdef DEBUG_MAP
static void map_dump(REQUEST *request, vp_map_t const *map)
{
	RDEBUG2(">>> MAP TYPES LHS: %s, RHS: %s",
	        fr_table_str_by_value(tmpl_type_table, map->lhs->type, "???"),
	        fr_table_str_by_value(tmpl_type_table, map->rhs->type, "???"));

	if (map->rhs) {
		RDEBUG2(">>> MAP NAMES %s %s", map->lhs->name, map->rhs->name);
	}
}
#endif

static inline vp_map_t *map_alloc(TALLOC_CTX *ctx)
{
	return talloc_zero(ctx, vp_map_t);
}

/** re-parse a map where the lhs is an unknown attribute.
 *
 *
 * @param map to process.
 * @param rhs_type quotation type around rhs.
 * @param rhs string to re-parse.
 */
bool map_cast_from_hex(vp_map_t *map, FR_TOKEN rhs_type, char const *rhs)
{
	size_t			len;
	uint8_t			*ptr;
	char const		*p;
	pair_list_t		list;

	fr_dict_attr_t const	*da;
	VALUE_PAIR		*vp = NULL;
	vp_tmpl_t		*vpt;
	fr_value_box_t		cast;

	fr_assert(map != NULL);

	fr_assert(map->lhs != NULL);
	fr_assert(tmpl_is_attr(map->lhs));

	fr_assert(map->rhs == NULL);
	fr_assert(rhs != NULL);

	MAP_VERIFY(map);

	/*
	 *	If the attribute is still unknown, go parse the RHS.
	 */
	if (map->lhs->tmpl_da->flags.is_raw) {
		da = fr_dict_attr_child_by_num(map->lhs->tmpl_da->parent,
					       map->lhs->tmpl_da->attr);
		if (!da || da->flags.is_raw) return false;
	} else {
		da = map->lhs->tmpl_da;
	}

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

	fr_hex2bin(ptr, len >> 1, rhs + 2, len);

	/*
	 *	Convert to da->type (if possible);
	 */
	if (fr_value_box_cast(map, &cast, da->type, da, fr_box_octets_buffer(ptr)) < 0) {
		talloc_free(ptr);
		return false;
	}

	/*
	 *	Package the #fr_value_box_t as a #vp_tmpl_t
	 */
	if (tmpl_afrom_value_box(map, &map->rhs, &cast, true) < 0) {
		talloc_free(ptr);
		return false;
	}

	talloc_free(ptr);

	/*
	 *	Set the LHS to the REAL attribute name.
	 *
	 *	@fixme Is this even necessary?  It looks like it goes
	 *	through a lot of work in order to set the name to
	 *	(drum roll) exactly the same thing it was before.
	 */
	vpt = tmpl_alloc(map, TMPL_TYPE_ATTR, NULL, -1, T_BARE_WORD);
	memcpy(&vpt->data.attribute, &map->lhs->data.attribute, sizeof(vpt->data.attribute));
	vpt->tmpl_da = da;

	/*
	 *	Be sure to keep the "&control:" or "control:" prefix.
	 *	If it's there, we re-generate it from whatever was in
	 *	the original name, including the '&'.
	 *
	 *	If we don't have a prefix, ensure that the attribute
	 *	name is prefixed with '&'.
	 */
	p = map->lhs->name;
	if (*p == '&') p++;
	len = radius_list_name(&list, p, PAIR_LIST_UNKNOWN);

	if (list != PAIR_LIST_UNKNOWN) {
		vpt->name = talloc_typed_asprintf(vpt, "%.*s:%s",
					    (int) len, map->lhs->name,
					    map->lhs->tmpl_da->name);
	} else {
		vpt->name = talloc_typed_asprintf(vpt, "&%s",
					    map->lhs->tmpl_da->name);
	}
	vpt->len = strlen(vpt->name);
	vpt->quote = T_BARE_WORD;

	talloc_free(map->lhs);
	map->lhs = vpt;

	fr_pair_list_free(&vp);

	MAP_VERIFY(map);

	return true;
}

/** Convert CONFIG_PAIR (which may contain refs) to vp_map_t.
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
 * @param[in] ctx		for talloc.
 * @param[in] out		Where to write the pointer to the new #vp_map_t.
 * @param[in] cp		to convert to map.
 * @param[in] lhs_rules		rules for parsing LHS attribute references.
 * @param[in] rhs_rules		rules for parsing RHS attribute references.
 * @return
 *	- #vp_map_t if successful.
 *	- NULL on error.
 */
int map_afrom_cp(TALLOC_CTX *ctx, vp_map_t **out, CONF_PAIR *cp,
		 vp_tmpl_rules_t const *lhs_rules, vp_tmpl_rules_t const *rhs_rules)
{
	vp_map_t	*map;
	char const	*attr, *value;
	ssize_t		slen;
	FR_TOKEN	type;

	*out = NULL;

	if (!cp) return -1;

	map = talloc_zero(ctx, vp_map_t);
	map->op = cf_pair_operator(cp);
	map->ci = cf_pair_to_item(cp);

	attr = cf_pair_attr(cp);
	value = cf_pair_value(cp);
	if (!value) {
		cf_log_err(cp, "Missing attribute value");
		goto error;
	}

	/*
	 *	LHS may be an expansion (that expands to an attribute reference)
	 *	or an attribute reference. Quoting determines which it is.
	 */
	type = cf_pair_attr_quote(cp);
	switch (type) {
	case T_DOUBLE_QUOTED_STRING:
	case T_BACK_QUOTED_STRING:
		slen = tmpl_afrom_str(ctx, &map->lhs, attr, talloc_array_length(attr) - 1, type, lhs_rules, true);
		if (slen <= 0) {
			char *spaces, *text;

		marker:
			fr_canonicalize_error(ctx, &spaces, &text, slen, attr);
			cf_log_err(cp, "%s", text);
			cf_log_err(cp, "%s^ %s", spaces, fr_strerror());

			talloc_free(spaces);
			talloc_free(text);
			goto error;
		}
		break;

	default:
		slen = tmpl_afrom_attr_str(ctx, NULL, &map->lhs, attr, lhs_rules);
		if (slen <= 0) {
			cf_log_err(cp, "Failed parsing attribute reference");

			goto marker;
		}

		if (tmpl_define_unknown_attr(map->lhs) < 0) {
			cf_log_perr(cp, "Failed creating attribute %s", map->lhs->name);
			goto error;
		}
		break;
	}

	/*
	 *	RHS might be an attribute reference.
	 */
	type = cf_pair_value_quote(cp);

	if ((type == T_BARE_WORD) && (value[0] == '0') && (tolower((int)value[1]) == 'x') &&
	    tmpl_is_attr(map->lhs) &&
	    map_cast_from_hex(map, type, value)) {
		/* do nothing */
	} else {
		slen = tmpl_afrom_str(map, &map->rhs, value, strlen(value), type, rhs_rules, true);
		if (slen < 0) goto marker;
		if (tmpl_define_unknown_attr(map->rhs) < 0) {
			cf_log_perr(cp, "Failed creating attribute %s", map->rhs->name);
			goto error;
		}
	}
	if (!map->rhs) {
		cf_log_perr(cp, "Failed parsing RHS");
		goto error;
	}

	/*
	 *	We cannot assign a count to an attribute.  That must
	 *	be done in an xlat.
	 */
	if (tmpl_is_attr(map->rhs) &&
	    (map->rhs->tmpl_num == NUM_COUNT)) {
		cf_log_err(cp, "Cannot assign from a count");
		goto error;
	}

	MAP_VERIFY(map);

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
 * @param[in] ctx		for talloc.
 * @param[out] out		Where to store the allocated map.
 * @param[in] cs		the update section
 * @param[in] lhs_rules		rules for parsing LHS attribute references.
 * @param[in] rhs_rules		rules for parsing RHS attribute references.
 * @param[in] validate		map using this callback (may be NULL).
 * @param[in] uctx		to pass to callback.
 * @param[in] max		number of mappings to process.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int map_afrom_cs(TALLOC_CTX *ctx, vp_map_t **out, CONF_SECTION *cs,
		 vp_tmpl_rules_t const *lhs_rules, vp_tmpl_rules_t const *rhs_rules,
		 map_validate_t validate, void *uctx,
		 unsigned int max)
{
	char const	*cs_list, *p;

	CONF_ITEM 	*ci;
	CONF_PAIR 	*cp;

	unsigned int 	total = 0;
	vp_map_t	**tail, *map;
	TALLOC_CTX	*parent;

	vp_tmpl_rules_t	our_lhs_rules = *lhs_rules;	/* Mutable copy of the destination */

	*out = NULL;
	tail = out;

	/*
	 *	The first map has ctx as the parent.
	 *	The rest have the previous map as the parent.
	 */
	parent = ctx;

	ci = cf_section_to_item(cs);

	/*
	 *	Check the destination list for "update" sections.
	 */
	cs_list = p = cf_section_name2(cs);
	if (cs_list && (strcmp(cf_section_name1(cs), "update") == 0)) {
		p += radius_request_name(&our_lhs_rules.request_def, p, REQUEST_CURRENT);
		if (our_lhs_rules.request_def == REQUEST_UNKNOWN) {
			cf_log_err(ci, "Default request specified in mapping section is invalid");
			return -1;
		}

		our_lhs_rules.list_def = fr_table_value_by_str(pair_list_table, p, PAIR_LIST_UNKNOWN);
		if (our_lhs_rules.list_def == PAIR_LIST_UNKNOWN) {
			cf_log_err(ci, "Default list \"%s\" specified in mapping section is invalid", p);
			return -1;
		}
	}

	for (ci = cf_item_next(cs, NULL);
	     ci != NULL;
	     ci = cf_item_next(cs, ci)) {
		if (total++ == max) {
			cf_log_err(ci, "Map size exceeded");
		error:
			TALLOC_FREE(*out);
			return -1;
		}

		/*
		 *	If we have a subsection, AND the name2 is an
		 *	assignment operator, THEN we allow sub-maps.
		 */
		if (cf_item_is_section(ci)) {
			CONF_SECTION *subcs;
			FR_TOKEN token;
			ssize_t slen;
			bool qualifiers = our_lhs_rules.disallow_qualifiers;

			subcs = cf_item_to_section(ci);
			token = cf_section_name2_quote(subcs);

			if (!fr_assignment_op[token]) {
				cf_log_err(ci, "Invalid operator '%s'", fr_tokens[token]);
				goto error;
			}

			MEM(map = map_alloc(parent));
			map->op = token;
			map->ci = ci;

			/*
			 *	The LHS MUST be an attribute name.
			 *	map_afrom_cp() allows for dynamic
			 *	names, but for simplicity we forbid
			 *	them for now.  Once the functionality
			 *	is tested and used, we can allow that.
			 */
			slen = tmpl_afrom_attr_str(ctx, NULL, &map->lhs, cf_section_name1(subcs), &our_lhs_rules);
			if (slen <= 0) {
				cf_log_err(ci, "Failed parsing attribute reference");
				talloc_free(map);
				goto error; /* re-do "goto marker" stuff to print out spaces ? */
			}

			/*
			 *	The LHS MUST be an attribute reference
			 *	for now.
			 */
			if (!tmpl_is_attr(map->lhs)) {
				cf_log_err(ci, "Left side of group '%s' is NOT an attribute reference",
					   map->lhs->name);
				talloc_free(map);
				goto error; /* re-do "goto marker" stuff to print out spaces ? */
			}

			if (map->lhs->tmpl_da->flags.is_unknown) {
				cf_log_err(ci, "Unknown attribute '%s'",
					   map->lhs->name);
				talloc_free(map);
				goto error; /* re-do "goto marker" stuff to print out spaces ? */
			}

			/*
			 *	Only TLV and GROUP can be grouped.
			 *
			 *	@todo - maybe "tagged" too, for stupid
			 *	RADIUS nonsense?
			 */
			if ((map->lhs->tmpl_da->type != FR_TYPE_TLV) &&
			    (map->lhs->tmpl_da->type != FR_TYPE_GROUP)) {
				cf_log_err(ci, "Attribute '%s' MUST be of type 'tlv' or 'group'",
					   map->lhs->name);
				talloc_free(map);
				goto error; /* re-do "goto marker" stuff to print out spaces ? */
			}

			/*
			 *	Fisallow list qualifiers for the child
			 *	templates.  The syntax requires that
			 *	the child attributes go into the
			 *	parent one.
			 */
			our_lhs_rules.disallow_qualifiers = true;

			/*
			 *	This prints out any relevant error
			 *	messages.  We MAY want to print out
			 *	additional ones, but that might get
			 *	complex and confusing.
			 */
			if (map_afrom_cs(map, &map->child, cf_item_to_section(ci),
					 &our_lhs_rules, rhs_rules, validate, uctx, max) < 0) {
				talloc_free(map);
				goto error;
			}

			our_lhs_rules.disallow_qualifiers = qualifiers;
			MAP_VERIFY(map);
			goto next;
		}

		if (!cf_item_is_pair(ci)) {
			cf_log_err(ci, "Entry is not in \"attribute = value\" format");
			goto error;
		}

		cp = cf_item_to_pair(ci);
		fr_assert(cp != NULL);

		if (map_afrom_cp(parent, &map, cp, &our_lhs_rules, rhs_rules) < 0) {
			cf_log_err(ci, "Failed creating map from '%s = %s'",
				   cf_pair_attr(cp), cf_pair_value(cp));
			goto error;
		}

		MAP_VERIFY(map);

		/*
		 *	Check the types in the map are valid
		 */
		if (validate && (validate(map, uctx) < 0)) goto error;

	next:
		parent = *tail = map;
		tail = &(map->next);
	}

	return 0;

}

/** Convert strings to #vp_map_t
 *
 * Treatment of operands depends on quotation, barewords are treated
 * as attribute references, double quoted values are treated as
 * expandable strings, single quoted values are treated as literal
 * strings.
 *
 * Return must be freed with talloc_free
 *
 * @param[in] ctx		for talloc.
 * @param[out] out		Where to store the head of the map.
 * @param[in] lhs		of the tuple.
 * @param[in] lhs_type		type of quoting around the LHS string
 * @param[in] lhs_rules		rules that control parsing of the LHS string.
 * @param[in] op		the operation to perform
 * @param[in] rhs		of the tuple.
 * @param[in] rhs_type		type of quoting aounrd the RHS string.
 * @param[in] rhs_rules		rules that control parsing of the RHS string.
 * @return
 *	- #vp_map_t if successful.
 *	- NULL on error.
 */
int map_afrom_fields(TALLOC_CTX *ctx, vp_map_t **out,
		     char const *lhs, FR_TOKEN lhs_type, vp_tmpl_rules_t const *lhs_rules,
		     FR_TOKEN op,
		     char const *rhs, FR_TOKEN rhs_type, vp_tmpl_rules_t const *rhs_rules)
{
	ssize_t slen;
	vp_map_t *map;

	map = talloc_zero(ctx, vp_map_t);

	slen = tmpl_afrom_str(map, &map->lhs, lhs, strlen(lhs), lhs_type, lhs_rules, true);
	if (slen < 0) {
	error:
		talloc_free(map);
		return -1;
	}

	map->op = op;

	if (tmpl_is_attr(map->lhs) &&
	    map->lhs->tmpl_da->flags.is_raw &&
	    map_cast_from_hex(map, rhs_type, rhs)) {
		return 0;
	}

	slen = tmpl_afrom_str(map, &map->rhs, rhs, strlen(rhs), rhs_type, rhs_rules, true);
	if (slen < 0) goto error;

	MAP_VERIFY(map);

	*out = map;

	return 0;
}

/** Convert a value box to a map
 *
 * This is mainly used in IO modules, where another function is used to convert
 * between the foreign value type and internal values, and the destination
 * attribute is provided as a string.
 *
 * @param[in] ctx		for talloc
 * @param[out] out		Where to store the head of the map.
 * @param[in] lhs		of the operation
 * @param[in] lhs_type		type of the LHS string
 * @param[in] lhs_rules		rules that control parsing of the LHS string.
 * @param[in] op		the operation to perform
 * @param[in] rhs		of the operation
 * @param[in] steal_rhs_buffs	Whether we attempt to save allocs by stealing the buffers
 *				from the rhs #fr_value_box_t.
 * @return
 *	- #vp_map_t if successful.
 *	- NULL on error.
 */
int map_afrom_value_box(TALLOC_CTX *ctx, vp_map_t **out,
			char const *lhs, FR_TOKEN lhs_type, vp_tmpl_rules_t const *lhs_rules,
			FR_TOKEN op,
			fr_value_box_t *rhs, bool steal_rhs_buffs)
{
	ssize_t slen;
	vp_map_t *map;

	map = talloc_zero(ctx, vp_map_t);

	slen = tmpl_afrom_str(map, &map->lhs, lhs, strlen(lhs), lhs_type, lhs_rules, true);
	if (slen < 0) {
	error:
		talloc_free(map);
		return -1;
	}

	map->op = op;

	if (tmpl_afrom_value_box(map, &map->rhs, rhs, steal_rhs_buffs) < 0) goto error;

	MAP_VERIFY(map);
	*out = map;

	return 0;
}

/** Convert a value pair string to valuepair map
 *
 * Takes a valuepair string with list and request qualifiers and converts it into a
 * #vp_map_t.
 *
 * Attribute string is in the format (where @verbatim <qu> @endverbatim is a quotation char ['"]):
 @verbatim
   [<list>:][<qu>]<attribute>[<qu>] <op> [<qu>]<value>[<qu>]
 @endverbatim
 *
 * @param[in] ctx		where to allocate the map.
 * @param[out] out		Where to write the new map.
 * @param[in] vp_str		string to parse.
 * @param[in] lhs_rules		rules for parsing LHS attribute references.
 * @param[in] rhs_rules		rules for parsing RHS attribute references.
 * @return
 *	- 0 on success.
 *	- < 0 on error.
 */
int map_afrom_attr_str(TALLOC_CTX *ctx, vp_map_t **out, char const *vp_str,
		       vp_tmpl_rules_t const *lhs_rules, vp_tmpl_rules_t const *rhs_rules)
{
	char const *p = vp_str;
	FR_TOKEN quote;

	VALUE_PAIR_RAW raw;
	vp_map_t *map = NULL;

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

	if ((map_afrom_fields(ctx, &map,
			      raw.l_opand, T_BARE_WORD, lhs_rules,
			      raw.op,
			      raw.r_opand, raw.quote, rhs_rules) < 0) || !map) {
		return -1;
	}

	*out = map;

	MAP_VERIFY(map);

	return 0;
}

/** Convert a VALUE_PAIR into a map
 *
 * @param[in] ctx		where to allocate the map.
 * @param[out] out		Where to write the new map (must be freed with talloc_free()).
 * @param[in] vp		to convert.
 * @param[in] rules		to insert attributes into.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int map_afrom_vp(TALLOC_CTX *ctx, vp_map_t **out, VALUE_PAIR *vp, vp_tmpl_rules_t const *rules)
{
	char buffer[256];

	vp_map_t *map;

	map = map_alloc(ctx);
	if (!map) {
	oom:
		fr_strerror_printf("Out of memory");
		return -1;
	}

	map->lhs = tmpl_alloc(map, TMPL_TYPE_ATTR, NULL, -1, T_BARE_WORD);
	if (!map->lhs) goto oom;

	map->lhs->tmpl_da = vp->da;
	map->lhs->tmpl_request = rules->request_def;
	map->lhs->tmpl_list = rules->list_def;
	map->lhs->tmpl_num = NUM_ANY;
	map->lhs->tmpl_tag = vp->tag;

	tmpl_snprint(NULL, buffer, sizeof(buffer), map->lhs);
	map->lhs->name = talloc_typed_strdup(map->lhs, buffer);
	map->lhs->len = talloc_array_length(map->lhs->name) - 1;
	map->lhs->quote = T_BARE_WORD;

	map->rhs = tmpl_alloc(map, TMPL_TYPE_DATA, NULL, -1, T_BARE_WORD);
	if (!map->lhs) goto oom;

	switch (vp->vp_type) {
	case FR_TYPE_QUOTED:
		map->rhs->name = fr_value_box_asprint(map->rhs, &vp->data, '"');
		map->rhs->len = talloc_array_length(map->rhs->name) - 1;
		map->rhs->quote = T_DOUBLE_QUOTED_STRING;
		break;

	default:
		map->rhs->name = fr_value_box_asprint(map->rhs, &vp->data, '\0');
		map->rhs->len = talloc_array_length(map->rhs->name) - 1;
		map->rhs->quote = T_BARE_WORD;
		break;
	}

	fr_value_box_copy(map->rhs, &map->rhs->tmpl_value, &vp->data);

	*out = map;

	return 0;
}

static void map_sort_split(vp_map_t *source, vp_map_t **front, vp_map_t **back)
{
	vp_map_t *fast;
	vp_map_t *slow;

	/*
	 *	Stopping condition - no more elements left to split
	 */
	if (!source || !source->next) {
		*front = source;
		*back = NULL;

		return;
	}

	/*
	 *	Fast advances twice as fast as slow, so when it gets to the end,
	 *	slow will point to the middle of the linked list.
	 */
	slow = source;
	fast = source->next;

	while (fast) {
		fast = fast->next;
		if (fast) {
			slow = slow->next;
			fast = fast->next;
		}
	}

	*front = source;
	*back = slow->next;
	slow->next = NULL;
}

static vp_map_t *map_sort_merge(vp_map_t *a, vp_map_t *b, fr_cmp_t cmp)
{
	vp_map_t *result = NULL;

	if (!a) return b;
	if (!b) return a;

	/*
	 *	Compare things in the maps
	 */
	if (cmp(a, b) <= 0) {
		result = a;
		result->next = map_sort_merge(a->next, b, cmp);
	} else {
		result = b;
		result->next = map_sort_merge(a, b->next, cmp);
	}

	return result;
}

/** Sort a linked list of #vp_map_t using merge sort
 *
 * @param[in,out] maps List of #vp_map_t to sort.
 * @param[in] cmp to sort with
 */
void map_sort(vp_map_t **maps, fr_cmp_t cmp)
{
	vp_map_t *head = *maps;
	vp_map_t *a;
	vp_map_t *b;

	/*
	 *	If there's 0-1 elements it must already be sorted.
	 */
	if (!head || !head->next) {
		return;
	}

	map_sort_split(head, &a, &b);	/* Split into sublists */
	map_sort(&a, cmp);		/* Traverse left */
	map_sort(&b, cmp);		/* Traverse right */

	/*
	 *	merge the two sorted lists together
	 */
	*maps = map_sort_merge(a, b, cmp);
}

/** Process map which has exec as a src
 *
 * Evaluate maps which specify exec as a src. This may be used by various sorts of update sections, and so
 * has been broken out into it's own function.
 *
 * @param[in,out] ctx to allocate new #VALUE_PAIR (s) in.
 * @param[out] out Where to write the #VALUE_PAIR (s).
 * @param[in] request structure (used only for talloc).
 * @param[in] map the map. The LHS (dst) must be #TMPL_TYPE_ATTR or #TMPL_TYPE_LIST.
 *	The RHS (src) must be #TMPL_TYPE_EXEC.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int map_exec_to_vp(TALLOC_CTX *ctx, VALUE_PAIR **out, REQUEST *request, vp_map_t const *map)
{
	int result;
	char *expanded = NULL;
	char answer[1024];
	VALUE_PAIR **input_pairs = NULL;
	VALUE_PAIR *output_pairs = NULL;

	*out = NULL;

	MAP_VERIFY(map);

	fr_assert(map->rhs);		/* Quite clang scan */
	fr_assert(tmpl_is_exec(map->rhs));
	fr_assert(tmpl_is_attr(map->lhs) || tmpl_is_list(map->lhs));

	/*
	 *	We always put the request pairs into the environment
	 */
	input_pairs = radius_list(request, PAIR_LIST_REQUEST);

	/*
	 *	Automagically switch output type depending on our destination
	 *	If dst is a list, then we create attributes from the output of the program
	 *	if dst is an attribute, then we create an attribute of that type and then
	 *	call fr_pair_value_from_str on the output of the script.
	 */
	result = radius_exec_program(ctx, answer, sizeof(answer),
				     tmpl_is_list(map->lhs) ? &output_pairs : NULL,
				     request, map->rhs->name, input_pairs ? *input_pairs : NULL,
				     true, true, fr_time_delta_from_sec(EXEC_TIMEOUT));
	talloc_free(expanded);
	if (result != 0) {
		REDEBUG("Exec failed with code (%i)", result);
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

		MEM(vp = fr_pair_afrom_da(ctx, map->lhs->tmpl_da));
		vp->op = map->op;
		vp->tag = map->lhs->tmpl_tag;
		if (fr_pair_value_from_str(vp, answer, -1, '"', false) < 0) {
			RPEDEBUG("Failed parsing exec output");
			fr_pair_list_free(&vp);
			return -2;
		}
		*out = vp;

		return 0;
	}

	default:
		fr_assert(0);
		return -1;
	}
}

/** Convert a map to a #VALUE_PAIR
 *
 * @param[in,out] ctx to allocate #VALUE_PAIR (s) in.
 * @param[out] out Where to write the #VALUE_PAIR (s), which may be NULL if not found
 * @param[in] request The current request.
 * @param[in] map the map. The LHS (dst) has to be #TMPL_TYPE_ATTR or #TMPL_TYPE_LIST.
 * @param[in] uctx unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int map_to_vp(TALLOC_CTX *ctx, VALUE_PAIR **out, REQUEST *request, vp_map_t const *map, UNUSED void *uctx)
{
	int		rcode = 0;
	VALUE_PAIR	*vp = NULL, *found = NULL, *n;
	REQUEST		*context = request;
	fr_cursor_t	cursor;
	ssize_t		slen;
	char		*str;

	*out = NULL;

	MAP_VERIFY(map);
	if (!fr_cond_assert(map->lhs != NULL)) return -1;
	if (!fr_cond_assert(map->rhs != NULL)) return -1;

	fr_assert(tmpl_is_list(map->lhs) || tmpl_is_attr(map->lhs));

	/*
	 *	Special case for !*, we don't need to parse RHS as this is a unary operator.
	 */
	if (map->op == T_OP_CMP_FALSE) return 0;

	/*
	 *	List to list found, this is a special case because we don't need
	 *	to allocate any attributes, just finding the current list, and change
	 *	the op.
	 */
	if (tmpl_is_list(map->lhs) && tmpl_is_list(map->rhs)) {
		VALUE_PAIR **from = NULL;

		if (radius_request(&context, map->rhs->tmpl_request) == 0) {
			from = radius_list(context, map->rhs->tmpl_list);
		}
		if (!from) return 0;

		if (fr_pair_list_copy(ctx, &found, *from) < 0) return -1;

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
		fr_assert(tmpl_is_attr(map->lhs));
		fr_assert(map->lhs->tmpl_da);	/* We need to know which attribute to create */
		fr_assert(map->rhs->tmpl_xlat != NULL);

		MEM(n = fr_pair_afrom_da(ctx, map->lhs->tmpl_da));

		/*
		 *	We do the debug printing because xlat_aeval_compiled
		 *	doesn't have access to the original string.  It's been
		 *	mangled during the parsing to xlat_exp_t
		 */
		RDEBUG2("EXPAND %s", map->rhs->name);
		RINDENT();

		str = NULL;
		slen = xlat_aeval_compiled(request, &str, request, map->rhs->tmpl_xlat, NULL, NULL);
		REXDENT();

		if (slen < 0) {
			rcode = slen;
			goto error;
		}

		RDEBUG2("--> %s", str);

		rcode = fr_pair_value_from_str(n, str, -1, '\0', false);
		talloc_free(str);
		if (rcode < 0) {
			fr_pair_list_free(&n);
			goto error;
		}
		n->op = map->op;
		n->tag = map->lhs->tmpl_tag;
		*out = n;
		break;

	case TMPL_TYPE_XLAT:
		fr_assert(tmpl_is_attr(map->lhs));
		fr_assert(map->lhs->tmpl_da);	/* We need to know which attribute to create */

		MEM(n = fr_pair_afrom_da(ctx, map->lhs->tmpl_da));

		str = NULL;
		slen = xlat_aeval(request, &str, request, map->rhs->name, NULL, NULL);
		if (slen < 0) {
			rcode = slen;
			talloc_free(n);
			goto error;
		}

		rcode = fr_pair_value_from_str(n, str, -1, '\0', false);
		talloc_free(str);
		if (rcode < 0) {
			fr_pair_list_free(&n);
			goto error;
		}
		n->op = map->op;
		n->tag = map->lhs->tmpl_tag;
		*out = n;
		break;

	case TMPL_TYPE_UNPARSED:
		fr_assert(tmpl_is_attr(map->lhs));
		fr_assert(map->lhs->tmpl_da);	/* We need to know which attribute to create */

		MEM(n = fr_pair_afrom_da(ctx, map->lhs->tmpl_da));

		if (fr_pair_value_from_str(n, map->rhs->name, -1, '\0', false) < 0) {
			rcode = 0;
			talloc_free(n);
			goto error;
		}
		n->op = map->op;
		n->tag = map->lhs->tmpl_tag;
		*out = n;
		break;

	case TMPL_TYPE_ATTR:
	{
		fr_cursor_t from;

		fr_assert((tmpl_is_attr(map->lhs) && map->lhs->tmpl_da) ||
			   (tmpl_is_list(map->lhs) && !map->lhs->tmpl_da));

		/*
		 * @todo should log error, and return -1 for v3.1 (causes update to fail)
		 */
		if (tmpl_copy_vps(ctx, &found, request, map->rhs) < 0) return 0;

		vp = fr_cursor_init(&from, &found);

		/*
		 *  Src/Dst attributes don't match, convert src attributes
		 *  to match dst.
		 */
		if (tmpl_is_attr(map->lhs) &&
		    (map->rhs->tmpl_da->type != map->lhs->tmpl_da->type)) {
			fr_cursor_t to;

			(void) fr_cursor_init(&to, out);
			for (; vp; vp = fr_cursor_current(&from)) {
				MEM(n = fr_pair_afrom_da(ctx, map->lhs->tmpl_da));

				if (fr_value_box_cast(n, &n->data,
						      map->lhs->tmpl_da->type, map->lhs->tmpl_da, &vp->data) < 0) {
					RPEDEBUG("Attribute conversion failed");
					fr_pair_list_free(&found);
					talloc_free(n);
					return -1;
				}
				vp = fr_cursor_remove(&from);	/* advances cursor */
				talloc_free(vp);

				fr_assert((n->vp_type != FR_TYPE_STRING) || (n->vp_strvalue != NULL));

				n->op = map->op;
				n->tag = map->lhs->tmpl_tag;
				fr_cursor_append(&to, n);
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
			vp->tag = map->lhs->tmpl_tag;
		}
		*out = found;
	}
		break;

	case TMPL_TYPE_DATA:
		fr_assert(map->lhs->tmpl_da);
		fr_assert(tmpl_is_attr(map->lhs));

		MEM(n = fr_pair_afrom_da(ctx, map->lhs->tmpl_da));

		if (map->lhs->tmpl_da->type == map->rhs->tmpl_value_type) {
			if (fr_value_box_copy(n, &n->data, &map->rhs->tmpl_value) < 0) {
				rcode = -1;
				talloc_free(n);
				goto error;
			}
		} else {
			if (fr_value_box_cast(n, &n->data, n->vp_type, n->da,
					   &map->rhs->tmpl_value) < 0) {
				RPEDEBUG("Implicit cast failed");
				rcode = -1;
				talloc_free(n);
				goto error;
			}
		}
		n->op = map->op;
		n->tag = map->lhs->tmpl_tag;
		*out = n;

		MAP_VERIFY(map);
		break;

	/*
	 *	This essentially does the same as rlm_exec xlat, except it's non-configurable.
	 *	It's only really here as a convenience for people who expect the contents of
	 *	backticks to be executed in a shell.
	 *
	 *	exec string is xlat expanded and arguments are shell escaped.
	 */
	case TMPL_TYPE_EXEC:
		return map_exec_to_vp(ctx, out, request, map);

	default:
		fr_assert(0);	/* Should have been caught at parse time */

	error:
		fr_pair_list_free(&vp);
		return rcode;
	}

	return 0;
}

#define DEBUG_OVERWRITE(_old, _new) \
do {\
	if (RDEBUG_ENABLED3) {\
		char *old = fr_pair_value_asprint(request, _old, '"');\
		char *n = fr_pair_value_asprint(request, _new, '"');\
		RINDENT();\
		RDEBUG3("--> overwriting '%s' with '%s'", old, n);\
		REXDENT();\
		talloc_free(old);\
		talloc_free(n);\
	}\
} while (0)

/** Convert #vp_map_t to #VALUE_PAIR (s) and add them to a #REQUEST.
 *
 * Takes a single #vp_map_t, resolves request and list identifiers
 * to pointers in the current request, then attempts to retrieve module
 * specific value(s) using callback, and adds the resulting values to the
 * correct request/list.
 *
 * @param request The current request.
 * @param map specifying destination attribute and location and src identifier.
 * @param func to retrieve module specific values and convert them to
 *	#VALUE_PAIR.
 * @param ctx to be passed to func.
 * @return
 *	- -1 if the operation failed.
 *	- -2 in the source attribute wasn't valid.
 *	- 0 on success.
 */
int map_to_request(REQUEST *request, vp_map_t const *map, radius_map_getvalue_t func, void *ctx)
{
	int			rcode = 0;
	int			num;
	VALUE_PAIR		**list, *vp, *dst, *head = NULL;
	REQUEST			*context, *tmp_ctx = NULL;
	TALLOC_CTX		*parent;
	vp_cursor_t		dst_list, src_list;

	bool			found = false;

	vp_map_t		exp_map;
	vp_tmpl_t		*exp_lhs;

	MAP_VERIFY(map);
	fr_assert(map->lhs != NULL);
	fr_assert(map->rhs != NULL);

	tmp_ctx = talloc_new(request);

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
	 *	Everything else gets expanded, then re-parsed as an attribute reference.
	 *
	 *	This allows the syntax like:
	 *	- "Attr-%{number}" := "value"
	 */
	case TMPL_TYPE_XLAT:
	case TMPL_TYPE_XLAT_STRUCT:
	case TMPL_TYPE_EXEC:
	{
		char *attr_str;
		ssize_t slen;

		slen = tmpl_aexpand(request, &attr_str, request, map->lhs, NULL, NULL);
		if (slen <= 0) {
			RPEDEBUG("Left side expansion failed");
			fr_assert(!attr_str);
			rcode = -1;
			goto finish;
		}

		slen = tmpl_afrom_attr_str(tmp_ctx, NULL, &exp_lhs, attr_str,
					   &(vp_tmpl_rules_t){
					   	.dict_def = request->dict,
					   	.prefix = VP_ATTR_REF_PREFIX_NO
					   });
		if (slen <= 0) {
			RPEDEBUG("Left side expansion result \"%s\" is not an attribute reference", attr_str);
			talloc_free(attr_str);
			rcode = -1;
			goto finish;
		}
		fr_assert(tmpl_is_attr(exp_lhs) || tmpl_is_list(exp_lhs));

		memcpy(&exp_map, map, sizeof(exp_map));
		exp_map.lhs = exp_lhs;
		map = &exp_map;
	}
		break;

	default:
		fr_assert(0);
		break;
	}


	/*
	 *	Sanity check inputs.  We can have a list or attribute
	 *	as a destination.
	 */
	if (!tmpl_is_list(map->lhs) &&
	    !tmpl_is_attr(map->lhs)) {
		REDEBUG("Left side \"%.*s\" of map should be an attr or list but is an %s",
			(int)map->lhs->len, map->lhs->name,
			fr_table_str_by_value(tmpl_type_table, map->lhs->type, "<INVALID>"));
		rcode = -2;
		goto finish;
	}

	context = request;
	if (radius_request(&context, map->lhs->tmpl_request) < 0) {
		REDEBUG("Mapping \"%.*s\" -> \"%.*s\" invalid in this context",
			(int)map->rhs->len, map->rhs->name, (int)map->lhs->len, map->lhs->name);
		rcode = -2;
		goto finish;
	}

	list = radius_list(context, map->lhs->tmpl_list);
	if (!list) {
		REDEBUG("Mapping \"%.*s\" -> \"%.*s\" invalid in this context",
			(int)map->rhs->len, map->rhs->name, (int)map->lhs->len, map->lhs->name);
		rcode = -2;
		goto finish;
	}

	parent = radius_list_ctx(context, map->lhs->tmpl_list);
	fr_assert(parent);

	/*
	 *	The callback should either return -1 to signify operations error,
	 *	-2 when it can't find the attribute or list being referenced, or
	 *	0 to signify success. It may return "success", but still have no
	 *	VPs to work with.
	 */
	if (!tmpl_is_null(map->rhs)) {
		rcode = func(parent, &head, request, map, ctx);
		if (rcode < 0) {
			fr_assert(!head);
			goto finish;
		}
		if (!head) {
			RDEBUG2("%.*s skipped: No values available", (int)map->lhs->len, map->lhs->name);
			goto finish;
		}
	} else {
		if (RDEBUG_ENABLED) map_debug_log(request, map, NULL);
	}

	/*
	 *	Print the VPs
	 */
#ifndef WITH_VERIFY_PTR
	if (RDEBUG_ENABLED)
#endif
	{
		for (vp = fr_pair_cursor_init(&src_list, &head);
		     vp;
		     vp = fr_pair_cursor_next(&src_list)) {
			VP_VERIFY(vp);

			if (RDEBUG_ENABLED) map_debug_log(request, map, vp);
		}
	}

	/*
	 *	The destination is a list (which is a completely different set of operations)
	 */
	if (tmpl_is_list(map->lhs)) {
		switch (map->op) {
		case T_OP_CMP_FALSE:
			/* We don't need the src VPs (should just be 'ANY') */
			fr_assert(!head);

			/* Clear the entire dst list */
			fr_pair_list_free(list);
			goto finish;

		case T_OP_SET:
			if (tmpl_is_list(map->rhs)) {
				fr_pair_list_free(list);
				*list = head;
				head = NULL;
			} else {
				/* FALL-THROUGH */

		case T_OP_EQ:
				fr_assert(tmpl_is_exec(map->rhs));
				/* FALL-THROUGH */

		case T_OP_ADD:
				fr_pair_list_move(list, &head);
				fr_pair_list_free(&head);
			}
			goto update;

		default:
			fr_pair_list_free(&head);
			rcode = -1;
			goto finish;
		}
	}

	/*
	 *	Find the destination attribute.  We leave with either
	 *	the dst_list and vp pointing to the attribute or the VP
	 *	being NULL (no attribute at that index).
	 */
	num = map->lhs->tmpl_num;
	(void) fr_pair_cursor_init(&dst_list, list);
	if ((num != NUM_ALL) && (num != NUM_ANY)) {
		while ((dst = fr_pair_cursor_next_by_da(&dst_list, map->lhs->tmpl_da, map->lhs->tmpl_tag))) {
			if (num-- == 0) break;
		}
	} else {
		dst = fr_pair_cursor_next_by_da(&dst_list, map->lhs->tmpl_da, map->lhs->tmpl_tag);
	}
	fr_assert(!dst || (map->lhs->tmpl_da == dst->da));

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
		fr_assert(!head);
		if (!dst) goto finish;

		/*
		 *	Wildcard: delete all of the matching ones, based on tag.
		 */
		if (map->lhs->tmpl_num == NUM_ANY) {
			fr_pair_delete_by_child_num(list, map->lhs->tmpl_da->parent,
						    map->lhs->tmpl_da->attr, map->lhs->tmpl_tag);
			dst = NULL;
		/*
		 *	We've found the Nth one.  Delete it, and only it.
		 */
		} else {
			dst = fr_pair_cursor_remove(&dst_list);
			fr_pair_list_free(&dst);
		}

		/*
		 *	Check that the User-Name and User-Password
		 *	caches point to the correct attribute.
		 */
		goto update;

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
			fr_pair_list_free(&head);
			goto finish;
		}

		/*
		 *	Instance specific[n] delete
		 */
		if (map->lhs->tmpl_num != NUM_ANY) {
			for (vp = fr_pair_cursor_head(&src_list);
			     vp;
			     vp = fr_pair_cursor_next(&src_list)) {
				head->op = T_OP_CMP_EQ;
				rcode = paircmp_pairs(request, vp, dst);
				if (rcode == 0) {
					dst = fr_pair_cursor_remove(&dst_list);
					fr_pair_list_free(&dst);
					found = true;
				}
			}
			rcode = 0;
			fr_pair_list_free(&head);
			if (!found) goto finish;
			goto update;
		}

		/*
		 *	All instances[*] delete
		 */
		for (dst = fr_pair_cursor_current(&dst_list);
		     dst;
		     dst = fr_pair_cursor_next_by_da(&dst_list, map->lhs->tmpl_da, map->lhs->tmpl_tag)) {
			for (vp = fr_pair_cursor_head(&src_list);
			     vp;
			     vp = fr_pair_cursor_next(&src_list)) {
				head->op = T_OP_CMP_EQ;
				rcode = paircmp_pairs(request, vp, dst);
				if (rcode == 0) {
					dst = fr_pair_cursor_remove(&dst_list);
					fr_pair_list_free(&dst);
					found = true;
				}
			}
		}
		rcode = 0;
		fr_pair_list_free(&head);
		if (!found) goto finish;
		goto update;
	}

	/*
	 *	Another fixup pass to set tags on attributes we're about to insert
	 */
	if (map->lhs->tmpl_tag != TAG_ANY) {
		for (vp = fr_pair_cursor_init(&src_list, &head);
		     vp;
		     vp = fr_pair_cursor_next(&src_list)) {
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
			fr_pair_list_free(&head);
			goto finish;
		}

		/* Insert first instance (if multiple) */
		fr_pair_cursor_head(&src_list);
		fr_pair_cursor_append(&dst_list, fr_pair_cursor_remove(&src_list));
		/* Free any we didn't insert */
		fr_pair_list_free(&head);
		break;

	/*
	 *	:= - Overwrite existing attribute with last src_list attribute
	 */
	case T_OP_SET:
		/* Wind to last instance */
		fr_pair_cursor_tail(&src_list);
		if (dst) {
			DEBUG_OVERWRITE(dst, fr_pair_cursor_current(&src_list));
			dst = fr_pair_cursor_replace(&dst_list, fr_pair_cursor_remove(&src_list));
			talloc_free(dst);
		} else {
			fr_pair_cursor_append(&dst_list, fr_pair_cursor_remove(&src_list));
		}
		/* Free any we didn't insert */
		fr_pair_list_free(&head);
		break;

	/*
	 *	+= - Add all src_list attributes to the destination
	 */
	case T_OP_ADD:
		/* Insert all the instances! (if multiple) */
		fr_pair_add(list, head);
		head = NULL;
		break;

	/*
	 *	Filter operators
	 */
	case T_OP_NE:
	case T_OP_CMP_EQ:
	case T_OP_GE:
	case T_OP_GT:
	case T_OP_LE:
	case T_OP_LT:
	{
		VALUE_PAIR *a, *b;

		fr_pair_list_sort(&head, fr_pair_cmp_by_da_tag);
		fr_pair_list_sort(list, fr_pair_cmp_by_da_tag);

		fr_pair_cursor_head(&dst_list);

		for (b = fr_pair_cursor_head(&src_list);
		     b;
		     b = fr_pair_cursor_next(&src_list)) {
			for (a = fr_pair_cursor_current(&dst_list);
			     a;
			     a = fr_pair_cursor_next(&dst_list)) {
				int8_t cmp;

				cmp = fr_pair_cmp_by_da_tag(a, b);	/* attribute and tag match */
				if (cmp > 0) break;
				else if (cmp < 0) continue;

				cmp = (fr_value_box_cmp_op(map->op, &a->data, &b->data) == 0);
				if (cmp != 0) {
					a = fr_pair_cursor_remove(&dst_list);
					talloc_free(a);
				}
			}
			if (!a) break;	/* end of the list */
		}
		fr_pair_list_free(&head);
	}
		break;

	default:
		fr_assert(0);	/* Should have been caught be the caller */
		rcode = -1;
		goto finish;
	}

update:
	fr_assert(!head);

finish:
	talloc_free(tmp_ctx);
	return rcode;
}

/**  Print a map to a string
 *
 * @param[out] need	The buffer space we would have needed to
 *			print more of the string.
 * @param[out] out	Buffer to write string to.
 * @param[in] outlen	Size of the output buffer.
 * @param[in] map	to print.
 * @return
 *	- The number of bytes written to the out buffer.
 *	- A number >= outlen if truncation has occurred.
 */
size_t map_snprint(size_t *need, char *out, size_t outlen, vp_map_t const *map)
{
	size_t		len;
	char		*p = out;
	char		*end = out + outlen;
	size_t		our_need;

	if (!need) need = &our_need;

	RETURN_IF_NO_SPACE_INIT(need, 1, p, out, end);

	MAP_VERIFY(map);

	len = tmpl_snprint(need, out, end - p, map->lhs);
	if (*need) return len;
	p += len;

	RETURN_IF_NO_SPACE(need, 1, p, out, end);
	*(p++) = ' ';

	len = strlcpy(p, fr_token_name(map->op), end - p);
	RETURN_IF_TRUNCATED(need, len, p, out, end);

	RETURN_IF_NO_SPACE(need, 1, p, out, end);
	*(p++) = ' ';

	/*
	 *	The RHS doesn't matter for many operators
	 */
	if ((map->op == T_OP_CMP_TRUE) || (map->op == T_OP_CMP_FALSE)) {
		len = strlcpy(p, "ANY", (end - p));
		RETURN_IF_TRUNCATED(need, len, p, out, end - 1);
		return p - out;
	}

	if (!map->child && !fr_cond_assert(map->rhs != NULL)) return -1;

	if (tmpl_is_attr(map->lhs) &&
	    (map->lhs->tmpl_da->type == FR_TYPE_STRING) &&
	    tmpl_is_unparsed(map->rhs)) {
	    	RETURN_IF_NO_SPACE(need, 1, p, out, end);
		*(p++) = '\'';

		len = tmpl_snprint(need, p, end - p, map->rhs);
		if (*need) return len;
		p += len;

		RETURN_IF_NO_SPACE(need, 1, p, out, end);
		*(p++) = '\'';
	} else {
		len = tmpl_snprint(need, p, end - p, map->rhs);
		if (*need) return len;
		p += len;
	}

	*p = '\0';
	return p - out;
}

/*
 *	Debug print a map / VP
 */
void map_debug_log(REQUEST *request, vp_map_t const *map, VALUE_PAIR const *vp)
{
	char *rhs = NULL, *value = NULL;
	char buffer[256];

	MAP_VERIFY(map);
	if (!fr_cond_assert(map->lhs != NULL)) return;
	if (!fr_cond_assert(map->rhs != NULL)) return;

	fr_assert(vp || tmpl_is_null(map->rhs));

	switch (map->rhs->type) {
	/*
	 *	Just print the value being assigned
	 */
	default:
	case TMPL_TYPE_UNPARSED:
		rhs = fr_pair_value_asprint(request, vp, fr_token_quote[map->rhs->quote]);
		break;

	case TMPL_TYPE_XLAT:
	case TMPL_TYPE_XLAT_STRUCT:
		rhs = fr_pair_value_asprint(request, vp, fr_token_quote[map->rhs->quote]);
		break;

	case TMPL_TYPE_DATA:
		rhs = fr_pair_value_asprint(request, vp, fr_token_quote[map->rhs->quote]);
		break;

	/*
	 *	For the lists, we can't use the original name, and have to
	 *	rebuild it using tmpl_snprint, for each attribute we're
	 *	copying.
	 */
	case TMPL_TYPE_LIST:
	{
		vp_tmpl_t	vpt;
		char const	*quote;

		quote = (vp->vp_type == FR_TYPE_STRING) ? "\"" : "";

		/*
		 *	Fudge a temporary tmpl that describes the attribute we're copying
		 *	this is a combination of the original list tmpl, and values from
		 *	the VALUE_PAIR. This way, we get tag info included.
		 */
		memcpy(&vpt, map->rhs, sizeof(vpt));
		vpt.tmpl_da = vp->da;
		vpt.tmpl_num = NUM_ANY;
		vpt.type = TMPL_TYPE_ATTR;

		if (vp->da->flags.is_unknown) memcpy(&vpt.tmpl_unknown, &vp->da, sizeof(vpt.tmpl_unknown));

		/*
		 *	Not appropriate to use map->rhs->quote here, as that's the quoting
		 *	around the list ref. The attribute value has no quoting, so we choose
		 *	the quoting based on the data type.
		 */
		value = fr_pair_value_asprint(request, vp, quote[0]);
		tmpl_snprint(NULL, buffer, sizeof(buffer), &vpt);
		rhs = talloc_typed_asprintf(request, "%s -> %s%s%s", buffer, quote, value, quote);
	}
		break;

	case TMPL_TYPE_ATTR:
	{
		char const *quote;

		quote = (vp->vp_type == FR_TYPE_STRING) ? "\"" : "";

		/*
		 *	Not appropriate to use map->rhs->quote here, as that's the quoting
		 *	around the attr ref. The attribute value has no quoting, so we choose
		 *	the quoting based on the data type.
		 */
		value = fr_pair_value_asprint(request, vp, quote[0]);
		tmpl_snprint(NULL, buffer, sizeof(buffer), map->rhs);
		rhs = talloc_typed_asprintf(request, "%s -> %s%s%s", buffer, quote, value, quote);
	}
		break;

	case TMPL_TYPE_NULL:
		rhs = talloc_typed_strdup(request, "ANY");
		break;
	}

	switch (map->lhs->type) {
	case TMPL_TYPE_LIST:
		/*
		 *	The MAP may have said "list", but if there's a
		 *	VP, it has it's own name, which isn't in the
		 *	map name.
		 */
		if (vp) {
			tmpl_snprint(NULL, buffer, sizeof(buffer), map->lhs);
			RDEBUG2("%s%s %s %s", buffer, vp->da->name, fr_table_str_by_value(fr_tokens_table, vp->op, "<INVALID>"), rhs);
			break;
		}
		/* FALL-THROUGH */

	case TMPL_TYPE_ATTR:
		tmpl_snprint(NULL, buffer, sizeof(buffer), map->lhs);
		RDEBUG2("%s %s %s", buffer, fr_table_str_by_value(fr_tokens_table, vp ? vp->op : map->op, "<INVALID>"), rhs);
		break;

	default:
		break;
	}

	/*
	 *	Must be LIFO free order so we don't leak pool memory
	 */
	talloc_free(rhs);
	talloc_free(value);
}
