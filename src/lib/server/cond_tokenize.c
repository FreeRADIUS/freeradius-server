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
 * @file src/lib/server/cond_eval.c
 * @brief Parse complex conditions
 *
 * @copyright 2013 Alan DeKok (aland@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/cond_eval.h>
#include <freeradius-devel/server/cond.h>
#include <freeradius-devel/server/rad_assert.h>

#include <ctype.h>

static fr_table_num_sorted_t const allowed_return_codes[] = {
	{ "fail",       1 },
	{ "handled",    1 },
	{ "invalid",    1 },
	{ "noop",       1 },
	{ "notfound",   1 },
	{ "ok",	 	1 },
	{ "reject",     1 },
	{ "updated",    1 },
	{ "disallow",   1 }
};
static size_t allowed_return_codes_len = NUM_ELEMENTS(allowed_return_codes);

/*
 *	This file shouldn't use any functions from the server core.
 */

size_t cond_snprint(size_t *need, char *out, size_t outlen, fr_cond_t const *in)
{
	size_t		len;
	char		*p = out;
	char		*end = out + outlen - 1;
	fr_cond_t const	*c = in;
	size_t		our_need;

	if (!need) need = &our_need;

	RETURN_IF_NO_SPACE_INIT(need, 1, p, out, end);

next:
	if (!c) {
		p[0] = '\0';
		return 0;
	}

	if (c->negate) {
		*(p++) = '!';	/* FIXME: only allow for child? */
	}

	switch (c->type) {
	case COND_TYPE_EXISTS:
		rad_assert(c->data.vpt != NULL);
		if (c->cast) {
			len = snprintf(p, end - p, "<%s>", fr_table_str_by_value(fr_value_box_type_table,
				       c->cast->type, "??"));
			RETURN_IF_TRUNCATED(need, len, p, out, end);
		}

		len = tmpl_snprint(need, p, end - p, c->data.vpt);
		if (*need) return len;
		p += len;
		break;

	case COND_TYPE_MAP:
		rad_assert(c->data.map != NULL);
#if 0
		*(p++) = '[';	/* for extra-clear debugging */
#endif
		if (c->cast) {
			len = snprintf(p, end - p, "<%s>", fr_table_str_by_value(fr_value_box_type_table, c->cast->type, "??"));
			RETURN_IF_TRUNCATED(need, len, p, out, end);
		}

		len = map_snprint(need, p, end - p, c->data.map);
		if (*need) return len;
		p += len;
#if 0
		*(p++) = ']';
#endif
		break;

	case COND_TYPE_CHILD:
		rad_assert(c->data.child != NULL);
		*(p++) = '(';
		len = cond_snprint(need, p, (end - p) - 1, c->data.child);	/* -1 for proceeding ')' */
		if (*need) return len;
		if (len >= (outlen - 1)) return len;
		p += len;
		*(p++) = ')';
		break;

	case COND_TYPE_TRUE:
		len = strlcpy(out, "true", outlen);
		RETURN_IF_TRUNCATED(need, len, p, out, end);
		return p - out;

	case COND_TYPE_FALSE:
		len = strlcpy(out, "false", outlen);
		RETURN_IF_TRUNCATED(need, len, p, out, end);
		return p - out;

	default:
		*out = '\0';
		return 0;
	}

	if (c->next_op == COND_NONE) {
		rad_assert(c->next == NULL);
		*p = '\0';
		return p - out;
	}

	if (c->next_op == COND_AND) {
		len = strlcpy(p, " && ", end - p);
		RETURN_IF_TRUNCATED(need, len, p, out, end);

	} else if (c->next_op == COND_OR) {
		len = strlcpy(p, " || ", end - p);
		RETURN_IF_TRUNCATED(need, len, p, out, end);

	} else {
		rad_assert(0 == 1);
	}

	c = c->next;
	goto next;
}


static bool cond_type_check(fr_cond_t *c, fr_type_t lhs_type)
{
	/*
	 *	SOME integer mismatch is OK.  If the LHS has a large type,
	 *	and the RHS has a small type, it's OK.
	 *
	 *	If the LHS has a small type, and the RHS has a large type,
	 *	then add a cast to the LHS.
	 */
	if (lhs_type == FR_TYPE_UINT64) {
		if ((c->data.map->rhs->tmpl_da->type == FR_TYPE_UINT32) ||
		    (c->data.map->rhs->tmpl_da->type == FR_TYPE_UINT16) ||
		    (c->data.map->rhs->tmpl_da->type == FR_TYPE_UINT8)) {
			c->cast = NULL;
			return true;
		}
	}

	if (lhs_type == FR_TYPE_UINT32) {
		if ((c->data.map->rhs->tmpl_da->type == FR_TYPE_UINT16) ||
		    (c->data.map->rhs->tmpl_da->type == FR_TYPE_UINT8)) {
			c->cast = NULL;
			return true;
		}

		if (c->data.map->rhs->tmpl_da->type == FR_TYPE_UINT64) {
			c->cast = c->data.map->rhs->tmpl_da;
			return true;
		}
	}

	if (lhs_type == FR_TYPE_UINT16) {
		if (c->data.map->rhs->tmpl_da->type == FR_TYPE_UINT8) {
			c->cast = NULL;
			return true;
		}

		if ((c->data.map->rhs->tmpl_da->type == FR_TYPE_UINT64) ||
		    (c->data.map->rhs->tmpl_da->type == FR_TYPE_UINT32)) {
			c->cast = c->data.map->rhs->tmpl_da;
			return true;
		}
	}

	if (lhs_type == FR_TYPE_UINT8) {
		if ((c->data.map->rhs->tmpl_da->type == FR_TYPE_UINT64) ||
		    (c->data.map->rhs->tmpl_da->type == FR_TYPE_UINT32) ||
		    (c->data.map->rhs->tmpl_da->type == FR_TYPE_UINT16)) {
			c->cast = c->data.map->rhs->tmpl_da;
			return true;
		}
	}

	if ((lhs_type == FR_TYPE_IPV4_PREFIX) &&
	    (c->data.map->rhs->tmpl_da->type == FR_TYPE_IPV4_ADDR)) {
		return true;
	}

	if ((lhs_type == FR_TYPE_IPV6_PREFIX) &&
	    (c->data.map->rhs->tmpl_da->type == FR_TYPE_IPV6_ADDR)) {
		return true;
	}

	/*
	 *	Same checks as above, but with the types swapped, and
	 *	with explicit cast for the interpretor.
	 */
	if ((lhs_type == FR_TYPE_IPV4_ADDR) &&
	    (c->data.map->rhs->tmpl_da->type == FR_TYPE_IPV4_PREFIX)) {
		c->cast = c->data.map->rhs->tmpl_da;
		return true;
	}

	if ((lhs_type == FR_TYPE_IPV6_ADDR) &&
	    (c->data.map->rhs->tmpl_da->type == FR_TYPE_IPV6_PREFIX)) {
		c->cast = c->data.map->rhs->tmpl_da;
		return true;
	}

	return false;
}


/*
 *	Less code means less bugs
 */
#define return_P(_x) *error = _x;goto return_p
#define return_0(_x) *error = _x;goto return_0
#define return_lhs(_x) *error = _x;goto return_lhs
#define return_rhs(_x) *error = _x;goto return_rhs
#define return_SLEN goto return_slen

static ssize_t cond_check_cast(fr_cond_t *c, char const *start,
			       char const *lhs, char const *rhs, char const **error)
{
	if (tmpl_is_attr(c->data.map->rhs) &&
	    (c->cast->type != c->data.map->rhs->tmpl_da->type)) {
		if (cond_type_check(c, c->cast->type)) {
			return 1;
		}

		*error = "Attribute comparisons must be of the same data type";
		return 0;
	}

#ifdef HAVE_REGEX
	if (tmpl_is_regex(c->data.map->rhs)) {
		*error = "Cannot use cast with regex comparison";
		return -(rhs - start);
	}
#endif

	/*
	 *	The LHS is a literal which has been cast to a data type.
	 *	Cast it to the appropriate data type.
	 */
	if (tmpl_is_unparsed(c->data.map->lhs) &&
	    (tmpl_cast_in_place(c->data.map->lhs, c->cast->type, c->cast) < 0)) {
		*error = "Failed to parse field";
		return -(lhs - start);
	}

	/*
	 *	The RHS is a literal, and the LHS has been cast to a data
	 *	type.
	 */
	if ((tmpl_is_data(c->data.map->lhs)) &&
	    (tmpl_is_unparsed(c->data.map->rhs)) &&
	    (tmpl_cast_in_place(c->data.map->rhs, c->cast->type, c->cast) < 0)) {
		*error = "Failed to parse field";
		return -(rhs - start);
	}

	/*
	 *	We may be casting incompatible
	 *	types.  We check this based on
	 *	their size.
	 */
	if (tmpl_is_attr(c->data.map->lhs)) {
		/*
		 *      dst.min == src.min
		 *	dst.max == src.max
		 */
		if ((dict_attr_sizes[c->cast->type][0] == dict_attr_sizes[c->data.map->lhs->tmpl_da->type][0]) &&
		    (dict_attr_sizes[c->cast->type][1] == dict_attr_sizes[c->data.map->lhs->tmpl_da->type][1])) {
			goto cast_ok;
		}

		/*
		 *	Run-time parsing of strings.
		 *	Run-time copying of octets.
		 */
		if ((c->data.map->lhs->tmpl_da->type == FR_TYPE_STRING) ||
		    (c->data.map->lhs->tmpl_da->type == FR_TYPE_OCTETS)) {
			goto cast_ok;
		}

		/*
		 *	ifid to uint64 is OK
		 */
		if ((c->data.map->lhs->tmpl_da->type == FR_TYPE_IFID) &&
		    (c->cast->type == FR_TYPE_UINT64)) {
			goto cast_ok;
		}

		/*
		 *	ipaddr to ipv4prefix is OK
		 */
		if ((c->data.map->lhs->tmpl_da->type == FR_TYPE_IPV4_ADDR) &&
		    (c->cast->type == FR_TYPE_IPV4_PREFIX)) {
			goto cast_ok;
		}

		/*
		 *	ipv6addr to ipv6prefix is OK
		 */
		if ((c->data.map->lhs->tmpl_da->type == FR_TYPE_IPV6_ADDR) &&
		    (c->cast->type == FR_TYPE_IPV6_PREFIX)) {
			goto cast_ok;
		}

		/*
		 *	uint64 to ethernet is OK.
		 */
		if ((c->data.map->lhs->tmpl_da->type == FR_TYPE_UINT64) &&
		    (c->cast->type == FR_TYPE_ETHERNET)) {
			goto cast_ok;
		}

		/*
		 *	dst.max < src.min
		 *	dst.min > src.max
		 */
		if ((dict_attr_sizes[c->cast->type][1] < dict_attr_sizes[c->data.map->lhs->tmpl_da->type][0]) ||
		    (dict_attr_sizes[c->cast->type][0] > dict_attr_sizes[c->data.map->lhs->tmpl_da->type][1])) {
			*error = "Cannot cast to attribute of incompatible size";
			return 0;
		}
	}

cast_ok:
	/*
	 *	Casting to a redundant type means we don't need the cast.
	 *
	 *	Do this LAST, as the rest of the code above assumes c->cast
	 *	is not NULL.
	 */
	if (tmpl_is_attr(c->data.map->lhs) &&
	    (c->cast->type == c->data.map->lhs->tmpl_da->type)) {
		c->cast = NULL;
	}

	return 1;
}

/*
 *	See if two attribute comparisons are OK.
 */
static ssize_t cond_check_attrs(fr_cond_t *c, char const *start,
			       char const *lhs, FR_TOKEN lhs_type,
				char const *rhs, FR_TOKEN rhs_type,
				char const **error)
{
	vp_tmpl_t *vpt;

	/*
	 *	Two attributes?  They must be of the same type
	 */
	if (tmpl_is_attr(c->data.map->rhs) &&
	    tmpl_is_attr(c->data.map->lhs) &&
	    (c->data.map->lhs->tmpl_da->type != c->data.map->rhs->tmpl_da->type)) {
		if (cond_type_check(c, c->data.map->lhs->tmpl_da->type)) {
			return 1;
		}

		*error = "Attribute comparisons must be of the same data type";
		return 0;
	}

	/*
	 *	Invalid: User-Name == bob
	 *	Valid:   User-Name == "bob"
	 *
	 *	There's no real reason for
	 *	this, other than consistency.
	 */
	if (tmpl_is_attr(c->data.map->lhs) &&
	    !tmpl_is_attr(c->data.map->rhs) &&
	    (c->data.map->lhs->tmpl_da->type == FR_TYPE_STRING) &&
	    (c->data.map->op != T_OP_CMP_TRUE) &&
	    (c->data.map->op != T_OP_CMP_FALSE) &&
	    (c->data.map->rhs->quote == T_BARE_WORD)) {
		return_rhs("Comparison value must be a quoted string");
	}

	/*
	 *	Quotes around non-string
	 *	attributes mean that it's
	 *	either xlat, or an exec.
	 */
	if (tmpl_is_attr(c->data.map->lhs) &&
	    !tmpl_is_attr(c->data.map->rhs) &&
	    (c->data.map->lhs->tmpl_da->type != FR_TYPE_STRING) &&
	    (c->data.map->lhs->tmpl_da->type != FR_TYPE_OCTETS) &&
	    (c->data.map->lhs->tmpl_da->type != FR_TYPE_DATE) &&
	    (rhs_type == T_SINGLE_QUOTED_STRING)) {
		*error = "Comparison value must be an unquoted string";
	return_rhs:
		return -(rhs - start);
	}

	/*
	 *	The LHS has been cast to a data type, and the RHS is a
	 *	literal.  Cast the RHS to the type of the cast.
	 */
	if (c->cast && tmpl_is_unparsed(c->data.map->rhs) &&
	    (tmpl_cast_in_place(c->data.map->rhs, c->cast->type, c->cast) < 0)) {
		return_rhs("Failed to parse field");
	}

	/*
	 *	The LHS is an attribute, and the RHS is a literal.  Cast the
	 *	RHS to the data type of the LHS.
	 *
	 *	Note: There's a hack in here to always parse RHS as the
	 *	equivalent prefix type if the LHS is an IP address.
	 *
	 *	This allows Framed-IP-Address < 192.168.0.0./24
	 */
	if (tmpl_is_attr(c->data.map->lhs) &&
	    (tmpl_is_unparsed(c->data.map->rhs) ||
	     tmpl_is_data(c->data.map->rhs))) {
		fr_type_t type = c->data.map->lhs->tmpl_da->type;

		switch (c->data.map->lhs->tmpl_da->type) {
		case FR_TYPE_IPV4_ADDR:
			if (strchr(c->data.map->rhs->name, '/') != NULL) {
				type = FR_TYPE_IPV4_PREFIX;
				c->cast = fr_dict_attr_child_by_num(fr_dict_root(fr_dict_internal()), FR_CAST_BASE + type);
			}
			break;

		case FR_TYPE_IPV6_ADDR:
			if (strchr(c->data.map->rhs->name, '/') != NULL) {
				type = FR_TYPE_IPV6_PREFIX;
				c->cast = fr_dict_attr_child_by_num(fr_dict_root(fr_dict_internal()), FR_CAST_BASE + type);
			}
			break;

		default:
			break;
		}

		/*
		 *	Do not pass LHS as enumv if we're casting
		 *	as that means there's now a type mismatch between
		 *	lhs and rhs, which means the enumerations
		 *	can never match.
		 */
		if (tmpl_cast_in_place(c->data.map->rhs, type,
				       c->cast ? NULL : c->data.map->lhs->tmpl_da) < 0) {
			fr_dict_attr_t const *da = c->data.map->lhs->tmpl_da;

			if (!fr_dict_attr_is_top_level(da)) goto bad_type;

			switch (da->attr) {
			case FR_AUTH_TYPE:
				/*
				 *	The types for these attributes are dynamically allocated
				 *	by module.c, so we can't enforce strictness here.
				 */
				c->pass2_fixup = PASS2_FIXUP_TYPE;
				break;

			default:
			bad_type:
				return_rhs("Failed to parse value for attribute");
			}
		}

		/*
		 *	Stupid WiMAX shit.
		 *	Cast the LHS to the
		 *	type of the RHS.
		 */
		if (c->data.map->lhs->tmpl_da->type == FR_TYPE_COMBO_IP_ADDR) {
			fr_dict_attr_t const *da;

			da = fr_dict_attr_by_type(c->data.map->lhs->tmpl_da,
						  c->data.map->rhs->tmpl_value_type);
			if (!da) {
				return_rhs("Cannot find type for attribute");
			}
			c->data.map->lhs->tmpl_da = da;
		}
	} /* attr to literal comparison */

	/*
	 *	The RHS will turn into... something.  Allow for prefixes
	 *	there, too.
	 */
	if (tmpl_is_attr(c->data.map->lhs) &&
	    (tmpl_is_xlat(c->data.map->rhs) ||
	     tmpl_is_xlat_struct(c->data.map->rhs) ||
	     tmpl_is_exec(c->data.map->rhs))) {
		if (c->data.map->lhs->tmpl_da->type == FR_TYPE_IPV4_ADDR) {
			c->cast = fr_dict_attr_child_by_num(fr_dict_root(fr_dict_internal()),
							    FR_CAST_BASE + FR_TYPE_IPV4_PREFIX);
		}

		if (c->data.map->lhs->tmpl_da->type == FR_TYPE_IPV6_ADDR) {
			c->cast = fr_dict_attr_child_by_num(fr_dict_root(fr_dict_internal()),
							    FR_CAST_BASE + FR_TYPE_IPV6_PREFIX);
		}
	}

	/*
	 *	If the LHS is a bare word, AND it looks like
	 *	an attribute, try to parse it as such.
	 *
	 *	This allows LDAP-Group and SQL-Group to work.
	 *
	 *	The real fix is to just read the config files,
	 *	and do no parsing until after all of the modules
	 *	are loaded.  But that has issues, too.
	 */
	if (tmpl_is_unparsed(c->data.map->lhs) && (lhs_type == T_BARE_WORD)) {
		int hyphens = 0;
		bool may_be_attr = true;
		size_t i;
		ssize_t attr_slen;

		/*
		 *	Backwards compatibility: Allow Foo-Bar,
		 *	e.g. LDAP-Group and SQL-Group.
		 */
		for (i = 0; i < c->data.map->lhs->len; i++) {
			if (!fr_dict_attr_allowed_chars[(uint8_t) c->data.map->lhs->name[i]]) {
				may_be_attr = false;
				break;
			}

			if (c->data.map->lhs->name[i] == '-') {
				hyphens++;
			}
		}

		if (!hyphens || (hyphens > 3)) may_be_attr = false;

		if (may_be_attr) {
			attr_slen = tmpl_afrom_attr_str(c->data.map, NULL, &vpt, lhs,
							&(vp_tmpl_rules_t){
								.allow_unknown = true,
									.allow_undefined = true
									});
			if ((attr_slen > 0) && (vpt->len == c->data.map->lhs->len)) {
				talloc_free(c->data.map->lhs);
				c->data.map->lhs = vpt;
				c->pass2_fixup = PASS2_FIXUP_ATTR;
			}
		}
	}

	return 1;
}

/*
 *	Like tmpl_preparse(), but expands variables.
 */
static ssize_t cond_preparse(TALLOC_CTX *ctx, char const **out, size_t *outlen, char const *in, size_t inlen,
			     FR_TOKEN *type, char const **error,
			     fr_dict_attr_t const **castda, bool require_regex,
			     CONF_SECTION *cs)
{
	ssize_t slen, my_slen;
	char *p, *expanded;
	char buffer[8192];

        /*
	 *      When 'request_regex == false', tmpl_preparse() treats
	 *      '/' as a bare word.  This is so that the configuration
	 *      file parser can parse filenames, which may begin with
	 *      '/'.  We therefore check for leading '/' here, as
	 *      conditions don't use filenames.
	 */
	if (!require_regex && (*in == '/')) {
		*error = "Unexpected regular expression";
		return 0;
	}

	/*
	 *	Allow dynamic xlat expansion everywhere.
	 */
	slen = tmpl_preparse(out, outlen, in, inlen, type, error, castda, require_regex, true);
	if (slen <= 0) return slen;

	p = strchr(in, '$');
	if (!p) return slen;

	if (!((p[1] == '{') ||
	      ((p[1] == 'E') && (p[2] == 'N') && (p[3] == 'V') &&
	       (p[4] == '{')))) {
		return slen;
	}

	if (!cf_expand_variables(cf_filename(cs), cf_lineno(cs), cf_item_to_section(cf_parent(cs)),
				 buffer, sizeof(buffer), in, slen, NULL)) {
		*error = "Failed expanding configuration variable";
		return -1;
	}

	/*
	 *	We need to tell the caller how many *input* bytes to
	 *	skip.  Which means that we need to keep treat this
	 *	length as different.
	 */
	my_slen = tmpl_preparse(out, outlen, buffer, strlen(buffer), type, error, castda, require_regex, true);
	if (my_slen <= 0) return my_slen;

	if (!*out) return 0; /* for sanity checks, *outlen can be 0 for empty strings */

	/*
	 *	'out' now points to 'buffer', which we don't want.  So
	 *	we need to return a string which the caller can keep track of.
	 */
	expanded = talloc_strndup(ctx, *out, *outlen);
	if (!expanded) {
		*error = "Failed allocating memory";
		return -1;
	}

	*out = expanded;
	return slen;		/* NOT my_slen */
}


/** Tokenize a conditional check
 *
 *  @param[in] ctx	talloc ctx
 *  @param[in] cs	our configuration section
 *  @param[out] pcond	pointer to the returned condition structure
 *  @param[out] error	the parse error (if any)
 *  @param[in] in	the start of the string to process.  Should be "(..."
 *  @param[in] inlen	the length of the string to process
 *  @param[in] brace	look for a closing brace (how many deep we are)
 *  @param[in] rules	for attribute parsing
 *  @return
 *	- Length of the string skipped.
 *	- < 0 (the offset to the offending error) on error.
 */
static ssize_t cond_tokenize(TALLOC_CTX *ctx, CONF_SECTION *cs,
			     fr_cond_t **pcond, char const **error,
			     char const *in, size_t inlen, int brace,
			     vp_tmpl_rules_t const *rules)
{
	ssize_t			slen, tlen;
	char const		*p = in, *end = in + inlen;
	char const		*lhs, *rhs;
	fr_cond_t		*c;
	size_t			lhs_len, rhs_len;
	FR_TOKEN		op, lhs_type, rhs_type;
	bool			regex = false;
	vp_tmpl_rules_t		parse_rules;

	/*
	 *	We allow unknown and undefined attributes here
	 */
	parse_rules = *rules;
	parse_rules.allow_unknown = true;
	parse_rules.allow_undefined = true;

	c = talloc_zero(ctx, fr_cond_t);

	rad_assert(c != NULL);
	lhs_type = rhs_type = T_INVALID;

	fr_skip_whitespace(p);

	if (!*p) {
		return_P("Empty condition is invalid");
	}

	/*
	 *	!COND
	 */
	if (*p == '!') {
		p++;
		c->negate = true;
		fr_skip_whitespace(p);

		/*
		 *  Just for stupidity
		 */
		if (*p == '!') {
			return_P("Double negation is invalid");
		}
	}

	/*
	 *	(COND)
	 */
	if (*p == '(') {
		p++;

		/*
		 *	We've already eaten one layer of
		 *	brackets.  Go recurse to get more.
		 */
		c->type = COND_TYPE_CHILD;
		c->ci = cf_section_to_item(cs);
		slen = cond_tokenize(c, cs, &c->data.child, error, p, end - p, brace + 1, rules);
		if (slen <= 0) return_SLEN;

		if (!c->data.child) {
			return_P("Empty condition is invalid");
		}

		p += slen;
		fr_skip_whitespace(p);
		goto closing_brace;
	}

	/*
	 *	We didn't see anything special.  The condition must be one of
	 *
	 *	FOO
	 *	FOO OP BAR
	 */

	/*
	 *	Grab the LHS
	 */
	slen = cond_preparse(c, &lhs, &lhs_len, p, end - p, &lhs_type, error, &c->cast, false, cs);
	if (slen <= 0) {
		return_SLEN;
	}

	/*
	 *	We may (or not) have an operator
	 */

	/*
	 *	If the LHS is 0xabcdef, then automatically case it to octets.
	 */
	if (!c->cast && (lhs_type == T_BARE_WORD) &&
	    (lhs[0] == '0') && (lhs[1] == 'x') &&
	    ((slen & 0x01) == 0)) {
		if (slen == 2) {
			return_P("Empty octet string is invalid");
		}

		c->cast = fr_dict_attr_child_by_num(fr_dict_root(fr_dict_internal()),
							    FR_CAST_BASE + FR_TYPE_OCTETS);
	}

	p += slen;
	fr_skip_whitespace(p);

	/*
	 *	(FOO)
	 */
	if (*p == ')') {
		if (slen == 0) {
			return_P("Empty string is invalid");
		}

		/*
		 *	don't skip the brace.  We'll look for it later.
		 */
		goto exists;

		/*
		 *	FOO
		 */
	} else if (!*p) {
		if (brace) {
			return_P("No closing brace at end of string");
		}

		goto exists;

		/*
		 *	FOO && ...
		 */
	} else if (((p[0] == '&') && (p[1] == '&')) ||
		   ((p[0] == '|') && (p[1] == '|'))) {

	exists:
		if (c->cast) {
			*error = "Cannot do cast for existence check";
		return_0:
			talloc_free(c);
			return 0;
		}

		c->type = COND_TYPE_EXISTS;
		c->ci = cf_section_to_item(cs);

		tlen = tmpl_afrom_str(c, &c->data.vpt,
				      lhs, lhs_len, lhs_type, &parse_rules, true);
		if (tlen < 0) {
			p = lhs - tlen;
			return_P(fr_strerror());
		}

		rad_assert(!tmpl_is_regex(c->data.vpt));

		if (tmpl_define_unknown_attr(c->data.vpt) < 0) {
			p = lhs - tlen;
			return_P("Failed defining attribute");
		}

		if (tmpl_is_attr_undefined(c->data.vpt)) {
			c->pass2_fixup = PASS2_FIXUP_ATTR;
		}

	} else { /* it's an operator */
		vp_map_t *map;

		/*
		 *	The next thing should now be a comparison operator.
		 */
		c->type = COND_TYPE_MAP;
		c->ci = cf_section_to_item(cs);

		switch (*p) {
		default:
			return_P("Invalid text. Expected comparison operator");

		case '!':
			if (p[1] == '=') {
				op = T_OP_NE;
				p += 2;

#ifdef HAVE_REGEX
			} else if (p[1] == '~') {
				regex = true;

				op = T_OP_REG_NE;
				p += 2;
#endif

			} else if (p[1] == '*') {
				if (lhs_type != T_BARE_WORD) {
					return_P("Cannot use !* on a string");
				}

				op = T_OP_CMP_FALSE;
				p += 2;

			} else {
				goto invalid_operator;
			}
			break;

		case '=':
			if (p[1] == '=') {
				op = T_OP_CMP_EQ;
				p += 2;

#ifdef HAVE_REGEX
			} else if (p[1] == '~') {
				regex = true;

				op = T_OP_REG_EQ;
				p += 2;
#endif

			} else if (p[1] == '*') {
				if (lhs_type != T_BARE_WORD) {
					return_P("Cannot use =* on a string");
				}

				op = T_OP_CMP_TRUE;
				p += 2;

			} else {
			invalid_operator:
				return_P("Invalid operator");
			}

			break;

		case '<':
			if (p[1] == '=') {
				op = T_OP_LE;
				p += 2;

			} else {
				op = T_OP_LT;
				p++;
			}
			break;

		case '>':
			if (p[1] == '=') {
				op = T_OP_GE;
				p += 2;

			} else {
				op = T_OP_GT;
				p++;
			}
			break;
		}

		fr_skip_whitespace(p);

		if (!*p) {
			return_P("Expected text after operator");
		}

		slen = cond_preparse(c, &rhs, &rhs_len, p, end - p, &rhs_type, error, NULL, regex, cs);
		if (slen <= 0) {
			return_SLEN;
		}

		/*
		 *	Duplicate map_from_fields here, as we
		 *	want to separate parse errors in the
		 *	LHS from ones in the RHS.
		 */
		c->data.map = map = talloc_zero(c, vp_map_t);

		tlen = tmpl_afrom_str(map, &map->lhs, lhs, lhs_len,
				      lhs_type, &parse_rules, true);
		if (tlen < 0) {
			p = lhs - tlen;
			return_P(fr_strerror());
		}

		if (tmpl_define_unknown_attr(map->lhs) < 0) {
			*error = "Failed defining attribute";
		return_lhs:
			talloc_free(c);
			return -(lhs - in);
		}

		map->op = op;

		/*
		 *	If the RHS is 0xabcdef... automatically cast it to octets
		 *	unless the LHS is an attribute of type octets, or an
		 *	integer type.
		 */
		if (!c->cast && (rhs_type == T_BARE_WORD) &&
		    (rhs[0] == '0') && (rhs[1] == 'x') &&
		    ((slen & 0x01) == 0)) {
			if (slen == 2) {
				return_P("Empty octet string is invalid");
			}

			if ((map->lhs->type != TMPL_TYPE_ATTR) ||
			    !((map->lhs->tmpl_da->type == FR_TYPE_OCTETS) ||
			      (map->lhs->tmpl_da->type == FR_TYPE_UINT8) ||
			      (map->lhs->tmpl_da->type == FR_TYPE_UINT16) ||
			      (map->lhs->tmpl_da->type == FR_TYPE_UINT32) ||
			      (map->lhs->tmpl_da->type == FR_TYPE_UINT64))) {
				c->cast = fr_dict_attr_child_by_num(fr_dict_root(fr_dict_internal()),
								    FR_CAST_BASE + FR_TYPE_OCTETS);
			}
		}

		/*
		 *	This code converts '&Attr-1.2.3.4 == 0xabcdef'
		 *	into "&Known-Attribure == value"
		 *
		 *	So that the debug output makes more sense, AND
		 *	so that the comparisons are done to known attributes.
		 */
		if (tmpl_is_attr(map->lhs) &&
		    map->lhs->tmpl_da->flags.is_raw &&
		    map_cast_from_hex(map, rhs_type, rhs)) {
			/* do nothing */

		} else {
			tlen = tmpl_afrom_str(map, &map->rhs, rhs, rhs_len, rhs_type,
					      &parse_rules, true);
			if (tlen < 0) {
				p = rhs - tlen;
				return_P(fr_strerror());
			}
		}

		if (tmpl_define_unknown_attr(map->rhs) < 0) {
			*error = "Failed defining attribute";
		return_rhs:
			talloc_free(c);
			return -(rhs - in);
		}

		/*
		 *	Unknown attributes get marked up for pass2.
		 */
		if (tmpl_is_attr_undefined(c->data.map->lhs) ||
		    tmpl_is_attr_undefined(c->data.map->rhs)) {
			c->pass2_fixup = PASS2_FIXUP_ATTR;
		}

#ifdef HAVE_REGEX
		/*
		 *	Parse the regex flags
		 */
		if (regex) {
			int	err;
			ssize_t flen;
			fr_regex_flags_t	regex_flags;

			memset(&regex_flags, 0, sizeof(regex_flags));

			if (!tmpl_is_regex(c->data.map->rhs)) {
				return_rhs("Expected regex");
			}

			/*
			 *	Parse the flags after the *input* string, as "rhs" may have been
			 *	dynamically expanded.
			 */
			flen = regex_flags_parse(&err, &regex_flags, p + slen, strlen(p + slen), true);
			switch (err) {
				/*
				 *	Got flags all the way to the end of the string
				 */
			case 0:
				rad_assert(flen >= 0);
				slen += (size_t)flen;
				break;

				/*
				 *	Found non-flag, this is OK.
				 */
			case -1:
				rad_assert(flen <= 0);
				fr_strerror(); /* Clear out the error buffer */
				slen += (size_t)(-flen);
				break;

			case -2:
				rad_assert(flen <= 0);
				p = rhs + rhs_len + 1;
				p += (size_t)(-flen);
				return_P("Duplicate flag");
			}

			c->data.map->rhs->tmpl_regex_flags = regex_flags;
		}
#endif

		/*
		 *	Save the current config section for later.
		 */
		c->data.map->ci = cf_section_to_item(cs);

		/*
		 *	We cannot compare lists to anything.
		 */
		if (tmpl_is_list(c->data.map->lhs)) {
			return_lhs("Cannot use list references in condition");
		}

		if (tmpl_is_list(c->data.map->rhs)) {
			return_rhs("Cannot use list references in condition");
		}

		/*
		 *	Check cast type.  We can have the RHS
		 *	a string if the LHS has a cast.  But
		 *	if the RHS is an attr, it MUST be the
		 *	same type as the LHS.
		 */
		if (c->cast) {
			tlen = cond_check_cast(c, in, lhs, rhs, error);
		} else {
			tlen = cond_check_attrs(c, in, lhs, lhs_type, rhs, rhs_type, error);
		}
		if (tlen <= 0) {
			talloc_free(c);
			return tlen;
		}

		p += slen;
		fr_skip_whitespace(p);
	} /* parse OP RHS */

closing_brace:
	/*
	 *	...COND)
	 */
	if (*p == ')') {
		if (!brace) {
			return_P("Unexpected closing brace");
		}

		p++;
		fr_skip_whitespace(p);
		goto done;
	}

	/*
	 *	End of string is allowed, unless we're still looking
	 *	for closing braces.
	 */
	if (!*p) {
		if (brace) {
			return_P("No closing brace at end of string");
		}

		goto done;
	}

	/*
	 *	We've parsed all of the condition, stop.
	 */
	if (brace == 0) {
		if (isspace((int) *p)) goto done;

		/*
		 *	Open a section, it's OK to be done.
		 */
		if (*p == '{') goto done;
	}

	/*
	 *	Allow ((a == b) && (b == c))
	 */
	if (!(((p[0] == '&') && (p[1] == '&')) ||
	      ((p[0] == '|') && (p[1] == '|')))) {
		*error = "Unexpected text after condition";
	return_p:
		talloc_free(c);
		return -(p - in);
	}

	/*
	 *	Recurse to parse the next condition.
	 */
	c->next_op = p[0];
	p += 2;

	/*
	 *	May still be looking for a closing brace.
	 */
	slen = cond_tokenize(c, cs, &c->next, error, p, end - p, brace, rules);
	if (slen <= 0) {
	return_slen:
		talloc_free(c);
		return slen - (p - in);
	}
	p += slen;

done:
	/*
	 *	Normalize the condition before returning.
	 *
	 *	We collapse multiple levels of braces to one.  Then
	 *	convert maps to literals.  Then literals to true/false
	 *	statements.  Then true/false ||/&& followed by other
	 *	conditions to just conditions.
	 *
	 *	Order is important.  The more complex cases are
	 *	converted to simpler ones, from the most complex cases
	 *	to the simplest ones.
	 */

	/*
	 *	(FOO)     --> FOO
	 *	(FOO) ... --> FOO ...
	 */
	if ((c->type == COND_TYPE_CHILD) && !c->data.child->next) {
		fr_cond_t *child;

		child = talloc_steal(ctx, c->data.child);
		c->data.child = NULL;

		child->next = talloc_steal(child, c->next);
		c->next = NULL;

		child->next_op = c->next_op;

		/*
		 *	Set the negation properly
		 */
		if ((c->negate && !child->negate) ||
		    (!c->negate && child->negate)) {
			child->negate = true;
		} else {
			child->negate = false;
		}

		talloc_free(c);
		c = child;
	}

	/*
	 *	(FOO ...) --> FOO ...
	 *
	 *	But don't do !(FOO || BAR) --> !FOO || BAR
	 *	Because that's different.
	 */
	if ((c->type == COND_TYPE_CHILD) &&
	    !c->next && !c->negate) {
		fr_cond_t *child;

		child = talloc_steal(ctx, c->data.child);
		c->data.child = NULL;

		talloc_free(c);
		c = child;
	}

	/*
	 *	Convert maps to literals.  Convert one form of map to
	 *	a standardized form.  This doesn't make any
	 *	theoretical difference, but it does mean that the
	 *	run-time evaluation has fewer cases to check.
	 */
	if (c->type == COND_TYPE_MAP) do {
#if 0
			ifprintf(stderr, "LHS %s %d\n",
				 c->data.map->lhs->name,
				 c->datag
#endif


		/*
		 *	!FOO !~ BAR --> FOO =~ BAR
		 */
		if (c->negate && (c->data.map->op == T_OP_REG_NE)) {
			c->negate = false;
			c->data.map->op = T_OP_REG_EQ;
		}

		/*
		 *	FOO !~ BAR --> !FOO =~ BAR
		 */
		if (!c->negate && (c->data.map->op == T_OP_REG_NE)) {
			c->negate = true;
			c->data.map->op = T_OP_REG_EQ;
		}

		/*
		 *	!FOO != BAR --> FOO == BAR
		 */
		if (c->negate && (c->data.map->op == T_OP_NE)) {
			c->negate = false;
			c->data.map->op = T_OP_CMP_EQ;
		}

		/*
		 *	This next one catches "LDAP-Group != foo",
		 *	which doesn't work as-is, but this hack fixes
		 *	it.
		 *
		 *	FOO != BAR --> !FOO == BAR
		 */
		if (!c->negate && (c->data.map->op == T_OP_NE)) {
			c->negate = true;
			c->data.map->op = T_OP_CMP_EQ;
		}

		/*
		 *	FOO =* BAR --> FOO
		 *	FOO !* BAR --> !FOO
		 *
		 *	FOO may be a string, or a delayed attribute
		 *	reference.
		 */
		if ((c->data.map->op == T_OP_CMP_TRUE) ||
		    (c->data.map->op == T_OP_CMP_FALSE)) {
			vp_tmpl_t *vpt;

			vpt = talloc_steal(c, c->data.map->lhs);
			c->data.map->lhs = NULL;

			/*
			 *	Invert the negation bit.
			 */
			if (c->data.map->op == T_OP_CMP_FALSE) {
				c->negate = !c->negate;
			}

			TALLOC_FREE(c->data.map);

			c->type = COND_TYPE_EXISTS;
			c->data.vpt = vpt;
			break;	/* it's no longer a map */
		}

		/*
		 *	Both are data (IP address, integer, etc.)
		 *
		 *	We can do the evaluation here, so that it
		 *	doesn't need to be done at run time
		 */
		if (tmpl_is_data(c->data.map->lhs) &&
		    tmpl_is_data(c->data.map->rhs)) {
			int rcode;

			rad_assert(c->cast != NULL);

			rcode = cond_eval_map(NULL, 0, 0, c);
			TALLOC_FREE(c->data.map);
			c->cast = NULL;
			if (rcode) {
				c->type = COND_TYPE_TRUE;
			} else {
				c->type = COND_TYPE_FALSE;
			}

			break;	/* it's no longer a map */
		}

		/*
		 *	Both are literal strings.  They're not parsed
		 *	as TMPL_TYPE_DATA because there's no cast to an
		 *	attribute.
		 *
		 *	We can do the evaluation here, so that it
		 *	doesn't need to be done at run time
		 */
		if (tmpl_is_unparsed(c->data.map->rhs) &&
		    tmpl_is_unparsed(c->data.map->lhs) &&
		    !c->pass2_fixup) {
			int rcode;

			rad_assert(c->cast == NULL);

			rcode = cond_eval_map(NULL, 0, 0, c);
			if (rcode) {
				c->type = COND_TYPE_TRUE;
			} else {
				DEBUG3("OPTIMIZING (%s %s %s) --> FALSE",
				       c->data.map->lhs->name,
				       fr_table_str_by_value(fr_tokens_table, c->data.map->op, "??"),
				       c->data.map->rhs->name);
				c->type = COND_TYPE_FALSE;
			}

			/*
			 *	Free map after using it above.
			 */
			TALLOC_FREE(c->data.map);
			break;
		}

		/*
		 *	<ipaddr>"foo" CMP &Attribute-Name The cast may
		 *	not be necessary, and we can re-write it so
		 *	that the attribute reference is on the LHS.
		 */
		if (c->cast &&
		    tmpl_is_attr(c->data.map->rhs) &&
		    (c->cast->type == c->data.map->rhs->tmpl_da->type) &&
		    !tmpl_is_attr(c->data.map->lhs)) {
			vp_tmpl_t *tmp;

			tmp = c->data.map->rhs;
			c->data.map->rhs = c->data.map->lhs;
			c->data.map->lhs = tmp;

			c->cast = NULL;

			switch (c->data.map->op) {
			case T_OP_CMP_EQ:
				/* do nothing */
				break;

			case T_OP_LE:
				c->data.map->op = T_OP_GE;
				break;

			case T_OP_LT:
				c->data.map->op = T_OP_GT;
				break;

			case T_OP_GE:
				c->data.map->op = T_OP_LE;
				break;

			case T_OP_GT:
				c->data.map->op = T_OP_LT;
				break;

			default:
				return_0("Internal sanity check failed 1");
			}

			/*
			 *	This must have been parsed into TMPL_TYPE_DATA.
			 */
			rad_assert(!tmpl_is_unparsed(c->data.map->rhs));
		}

	} while (0);

	/*
	 *	Existence checks.  We short-circuit static strings,
	 *	too.
	 *
	 *	FIXME: the data types should be in the template, too.
	 *	So that we know where a literal came from.
	 *
	 *	"foo" is NOT the same as 'foo' or a bare foo.
	 */
	if (c->type == COND_TYPE_EXISTS) {
		switch (c->data.vpt->type) {
		case TMPL_TYPE_XLAT:
		case TMPL_TYPE_ATTR:
		case TMPL_TYPE_ATTR_UNDEFINED:
		case TMPL_TYPE_LIST:
		case TMPL_TYPE_EXEC:
			break;

			/*
			 *	'true' and 'false' are special strings
			 *	which mean themselves.
			 *
			 *	For integers, 0 is false, all other
			 *	integers are true.
			 *
			 *	For strings, '' and "" are false.
			 *	'foo' and "foo" are true.
			 *
			 *	The str2tmpl function takes care of
			 *	marking "%{foo}" as TMPL_TYPE_XLAT, so
			 *	the strings here are fixed at compile
			 *	time.
			 *
			 *	`exec` and "%{...}" are left alone.
			 *
			 *	Bare words must be module return
			 *	codes.
			 */
		case TMPL_TYPE_UNPARSED:
			if ((strcmp(c->data.vpt->name, "true") == 0) ||
			    (strcmp(c->data.vpt->name, "1") == 0)) {
				c->type = COND_TYPE_TRUE;
				TALLOC_FREE(c->data.vpt);

			} else if ((strcmp(c->data.vpt->name, "false") == 0) ||
				   (strcmp(c->data.vpt->name, "0") == 0)) {
				c->type = COND_TYPE_FALSE;
				TALLOC_FREE(c->data.vpt);

			} else if (!*c->data.vpt->name) {
				c->type = COND_TYPE_FALSE;
				TALLOC_FREE(c->data.vpt);

			} else if ((lhs_type == T_SINGLE_QUOTED_STRING) ||
				   (lhs_type == T_DOUBLE_QUOTED_STRING)) {
				c->type = COND_TYPE_TRUE;
				TALLOC_FREE(c->data.vpt);

			} else if (lhs_type == T_BARE_WORD) {
				int rcode;
				bool zeros = true;
				char const *q;

				for (q = c->data.vpt->name;
				     *q != '\0';
				     q++) {
					if (!isdigit((int) *q)) {
						break;
					}
					if (*q != '0') zeros = false;
				}

				/*
				 *	It's all digits, and therefore
				 *	'false' if zero, and 'true' otherwise.
				 */
				if (!*q) {
					if (zeros) {
						c->type = COND_TYPE_FALSE;
					} else {
						c->type = COND_TYPE_TRUE;
					}
					TALLOC_FREE(c->data.vpt);
					break;
				}

				/*
				 *	Allow &Foo-Bar where Foo-Bar is an attribute
				 *	defined by a module.
				 */
				if (c->pass2_fixup == PASS2_FIXUP_ATTR) {
					break;
				}

				rcode = fr_table_value_by_str(allowed_return_codes,
						   c->data.vpt->name, 0);
				if (!rcode) {
					return_0("Expected a module return code");
				}
			}

			/*
			 *	Else lhs_type==T_INVALID, and this
			 *	node was made by promoting a child
			 *	which had already been normalized.
			 */
			break;

		case TMPL_TYPE_DATA:
			return_0("Cannot use data here");

		default:
			return_0("Internal sanity check failed 2");
		}
	}

	/*
	 *	!TRUE -> FALSE
	 */
	if (c->type == COND_TYPE_TRUE) {
		if (c->negate) {
			c->negate = false;
			c->type = COND_TYPE_FALSE;
		}
	}

	/*
	 *	!FALSE -> TRUE
	 */
	if (c->type == COND_TYPE_FALSE) {
		if (c->negate) {
			c->negate = false;
			c->type = COND_TYPE_TRUE;
		}
	}

	/*
	 *	true && FOO --> FOO
	 */
	if ((c->type == COND_TYPE_TRUE) &&
	    (c->next_op == COND_AND)) {
		fr_cond_t *next;

		next = talloc_steal(ctx, c->next);
		c->next = NULL;

		talloc_free(c);
		c = next;
	}

	/*
	 *	false && FOO --> false
	 */
	if ((c->type == COND_TYPE_FALSE) &&
	    (c->next_op == COND_AND)) {
		talloc_free(c->next);
		c->next = NULL;
		c->next_op = COND_NONE;
	}

	/*
	 *	false || FOO --> FOO
	 */
	if ((c->type == COND_TYPE_FALSE) &&
	    (c->next_op == COND_OR)) {
		fr_cond_t *next;

		next = talloc_steal(ctx, c->next);
		c->next = NULL;

		talloc_free(c);
		c = next;
	}

	/*
	 *	true || FOO --> true
	 */
	if ((c->type == COND_TYPE_TRUE) &&
	    (c->next_op == COND_OR)) {
		talloc_free(c->next);
		c->next = NULL;
		c->next_op = COND_NONE;
	}

	*pcond = c;
	return p - in;
}

/** Tokenize a conditional check
 *
 * @param[in] cs	current CONF_SECTION and talloc ctx
 * @param[out] head	the parsed condition structure
 * @param[out] error	the parse error (if any)
 * @param[in] dict	dictionary to resolve attributes in.
 * @param[in] in	the start of the string to process.  Should be "(..."
 * @param[in] inlen	the length of the string to process.
 * @return
 *	- Length of the string skipped.
 *	- < 0 (the offset to the offending error) on error.
 */
ssize_t fr_cond_tokenize(CONF_SECTION *cs,
			 fr_cond_t **head, char const **error,
			 fr_dict_t const *dict, char const *in, size_t inlen)
{
	return cond_tokenize(cs, cs, head, error, in, inlen, 0, &(vp_tmpl_rules_t){ .dict_def = dict });
}

/*
 *	Walk in order.
 */
bool fr_cond_walk(fr_cond_t *c, bool (*callback)(fr_cond_t *cond, void *uctx), void *uctx)
{
	while (c) {
		/*
		 *	Process this one, exit on error.
		 */
		if (!callback(c, uctx)) return false;

		switch (c->type) {
		case COND_TYPE_INVALID:
			return false;

		case COND_TYPE_EXISTS:
		case COND_TYPE_MAP:
		case COND_TYPE_TRUE:
		case COND_TYPE_FALSE:
			break;

		case COND_TYPE_CHILD:
			/*
			 *	Walk over the child.
			 */
			if (!fr_cond_walk(c->data.child, callback, uctx)) {
				return false;
			}
		}

		/*
		 *	No sibling, stop.
		 */
		if (c->next_op == COND_NONE) break;

		/*
		 *	process the next sibling
		 */
		c = c->next;
	}

	return true;
}
