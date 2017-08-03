/*
 * parser.c	Parse various things
 *
 * Version:	$Id$
 *
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
 *
 * Copyright 2013  Alan DeKok <aland@freeradius.org>
 */

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/parser.h>
#include <freeradius-devel/rad_assert.h>

#include <ctype.h>

#define PW_CAST_BASE (1850)

static const FR_NAME_NUMBER allowed_return_codes[] = {
	{ "reject",     1 },
	{ "fail",       1 },
	{ "ok",	 	1 },
	{ "handled",    1 },
	{ "invalid",    1 },
	{ "userlock",   1 },
	{ "notfound",   1 },
	{ "noop",       1 },
	{ "updated",    1 },
	{ NULL, 0 }
};

/*
 *	This file shouldn't use any functions from the server core.
 */

size_t fr_cond_sprint(char *buffer, size_t bufsize, fr_cond_t const *in)
{
	size_t len;
	char *p = buffer;
	char *end = buffer + bufsize - 1;
	fr_cond_t const *c = in;

	rad_assert(bufsize > 0);

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
			len = snprintf(p, end - p, "<%s>", fr_int2str(dict_attr_types,
								      c->cast->type, "??"));
			p += len;
		}

		len = tmpl_prints(p, end - p, c->data.vpt, NULL);
		p += len;
		break;

	case COND_TYPE_MAP:
		rad_assert(c->data.map != NULL);
#if 0
		*(p++) = '[';	/* for extra-clear debugging */
#endif
		if (c->cast) {
			len = snprintf(p, end - p, "<%s>", fr_int2str(dict_attr_types,
								      c->cast->type, "??"));
			p += len;
		}

		len = map_prints(p, end - p, c->data.map);
		p += len;
#if 0
		*(p++) = ']';
#endif
		break;

	case COND_TYPE_CHILD:
		rad_assert(c->data.child != NULL);
		*(p++) = '(';
		len = fr_cond_sprint(p, end - p, c->data.child);
		p += len;
		*(p++) = ')';
		break;

	case COND_TYPE_TRUE:
		strlcpy(buffer, "true", bufsize);
		return strlen(buffer);

	case COND_TYPE_FALSE:
		strlcpy(buffer, "false", bufsize);
		return strlen(buffer);

	default:
		*buffer = '\0';
		return 0;
	}

	if (c->next_op == COND_NONE) {
		rad_assert(c->next == NULL);
		*p = '\0';
		return p - buffer;
	}

	if (c->next_op == COND_AND) {
		strlcpy(p, " && ", end - p);
		p += strlen(p);

	} else if (c->next_op == COND_OR) {
		strlcpy(p, " || ", end - p);
		p += strlen(p);

	} else {
		rad_assert(0 == 1);
	}

	c = c->next;
	goto next;
}


static ssize_t condition_tokenize_string(TALLOC_CTX *ctx, char **out,  char const **error, char const *start,
					 FR_TOKEN *op)
{
	char const *p = start;
	char *q;

	switch (*p++) {
	default:
		return -1;

	case '"':
		*op = T_DOUBLE_QUOTED_STRING;
		break;

	case '\'':
		*op = T_SINGLE_QUOTED_STRING;
		break;

	case '`':
		*op = T_BACK_QUOTED_STRING;
		break;

	case '/':
		*op = T_OP_REG_EQ; /* a bit of a hack. */
		break;

	}

	*out = talloc_array(ctx, char, strlen(start) - 1); /* + 2 - 1 */
	if (!*out) return -1;

	q = *out;

	while (*p) {
		if (*p == *start) {
			/*
			 *	Call the STANDARD parse function to figure out what the string is.
			 */
			if (cf_new_escape) {
				ssize_t slen;
				value_data_t data;
				char quote = *start;
				PW_TYPE src_type = PW_TYPE_STRING;

				/*
				 *	Regex compilers can handle escapes.  So we don't do it.
				 */
				if (quote == '/') quote = '\0';

				slen = value_data_from_str(ctx, &data, &src_type, NULL, start + 1, p - (start + 1), quote);
				if (slen < 0) {
					*error = "error parsing string";
					return slen - 1;
				}

				talloc_free(*out);
				*out = talloc_steal(ctx, data.ptr);
				data.strvalue = NULL;
			} else {
				char *out2;

				*(q++) = '\0'; /* terminate the output string */

				out2 = talloc_realloc(ctx, *out, char, (q - *out));
				if (!out2) {
					*error = "Out of memory";
					return -1;
				}
				*out = out2;
			}

			p++;
			return (p - start);
		}

		if (*p == '\\') {
			if (!p[1]) {
				p++;
				*error = "End of string after escape";
				return -(p - start);
			}

			/*
			 *	Hacks for backwards compatibility
			 */
			if (cf_new_escape) {
				if (p[1] == start[0]) { /* Convert '\'' --> ' */
					p++;
				} else {
					*(q++) = *(p++);
				}

			} else {
				switch (p[1]) {
				case 'r':
					*q++ = '\r';
					break;
				case 'n':
					*q++ = '\n';
					break;
				case 't':
					*q++ = '\t';
					break;
				default:
					*q++ = p[1];
					break;
				}
				p += 2;
				continue;
			}

		}
		*(q++) = *(p++);
	}

	*error = "Unterminated string";
	return -1;
}

static ssize_t condition_tokenize_word(TALLOC_CTX *ctx, char const *start, char **out,
				       FR_TOKEN *op, char const **error)
{
	size_t len;
	char const *p = start;

	if ((*p == '"') || (*p == '\'') || (*p == '`') || (*p == '/')) {
		return condition_tokenize_string(ctx, out, error, start, op);
	}

	*op = T_BARE_WORD;
	if (*p == '&') p++;	/* special-case &User-Name */

	while (*p) {
		/*
		 *	The LHS should really be limited to only a few
		 *	things.  For now, we allow pretty much anything.
		 */
		if (*p == '\\') {
			*error = "Unexpected escape";
			return -(p - start);
		}

		/*
		 *	("foo") is valid.
		 */
		if (*p == ')') {
			break;
		}

		/*
		 *	Spaces or special characters delineate the word
		 */
		if (isspace((int) *p) || (*p == '&') || (*p == '|') ||
		    (*p == '!') || (*p == '=') || (*p == '<') || (*p == '>')) {
			break;
		}

		if ((*p == '"') || (*p == '\'') || (*p == '`')) {
			*error = "Unexpected start of string";
			return -(p - start);
		}

		p++;
	}

	len = p - start;
	if (!len) {
		*error = "Empty string is invalid";
		return 0;
	}

	*out = talloc_array(ctx, char, len + 1);
	memcpy(*out, start, len);
	(*out)[len] = '\0';
	return len;
}


static ssize_t condition_tokenize_cast(char const *start, DICT_ATTR const **pda, char const **error)
{
	char const *p = start;
	char const *q;
	PW_TYPE cast;

	while (isspace((int) *p)) p++; /* skip spaces before condition */

	if (*p != '<') return 0;
	p++;

	q = p;
	while (*q && *q != '>') q++;

	cast = fr_substr2int(dict_attr_types, p, PW_TYPE_INVALID, q - p);
	if (cast == PW_TYPE_INVALID) {
		*error = "Invalid data type in cast";
		return -(p - start);
	}

	/*
	 *	We can only cast to basic data types.  Complex ones
	 *	are forbidden.
	 */
	switch (cast) {
#ifdef WITH_ASCEND_BINARY
	case PW_TYPE_ABINARY:
#endif
	case PW_TYPE_COMBO_IP_ADDR:
	case PW_TYPE_TLV:
	case PW_TYPE_EXTENDED:
	case PW_TYPE_LONG_EXTENDED:
	case PW_TYPE_EVS:
	case PW_TYPE_VSA:
		*error = "Forbidden data type in cast";
		return -(p - start);

	default:
		break;
	}

	*pda = dict_attrbyvalue(PW_CAST_BASE + cast, 0);
	if (!*pda) {
		*error = "Cannot cast to this data type";
		return -(p - start);
	}

	q++;

	while (isspace((int) *q)) q++; /* skip spaces after cast */

	return q - start;
}

static bool condition_check_types(fr_cond_t *c, PW_TYPE lhs_type)
{
	/*
	 *	SOME integer mismatch is OK.  If the LHS has a large type,
	 *	and the RHS has a small type, it's OK.
	 *
	 *	If the LHS has a small type, and the RHS has a large type,
	 *	then add a cast to the LHS.
	 */
	if (lhs_type == PW_TYPE_INTEGER64) {
		if ((c->data.map->rhs->tmpl_da->type == PW_TYPE_INTEGER) ||
		    (c->data.map->rhs->tmpl_da->type == PW_TYPE_SHORT) ||
		    (c->data.map->rhs->tmpl_da->type == PW_TYPE_BYTE)) {
			c->cast = NULL;
			return true;
		}
	}

	if (lhs_type == PW_TYPE_INTEGER) {
		if ((c->data.map->rhs->tmpl_da->type == PW_TYPE_SHORT) ||
		    (c->data.map->rhs->tmpl_da->type == PW_TYPE_BYTE)) {
			c->cast = NULL;
			return true;
		}

		if (c->data.map->rhs->tmpl_da->type == PW_TYPE_INTEGER64) {
			c->cast = c->data.map->rhs->tmpl_da;
			return true;
		}
	}

	if (lhs_type == PW_TYPE_SHORT) {
		if (c->data.map->rhs->tmpl_da->type == PW_TYPE_BYTE) {
			c->cast = NULL;
			return true;
		}

		if ((c->data.map->rhs->tmpl_da->type == PW_TYPE_INTEGER64) ||
		    (c->data.map->rhs->tmpl_da->type == PW_TYPE_INTEGER)) {
			c->cast = c->data.map->rhs->tmpl_da;
			return true;
		}
	}

	if (lhs_type == PW_TYPE_BYTE) {
		if ((c->data.map->rhs->tmpl_da->type == PW_TYPE_INTEGER64) ||
		    (c->data.map->rhs->tmpl_da->type == PW_TYPE_INTEGER) ||
		    (c->data.map->rhs->tmpl_da->type == PW_TYPE_SHORT)) {
			c->cast = c->data.map->rhs->tmpl_da;
			return true;
		}
	}

	if ((lhs_type == PW_TYPE_IPV4_PREFIX) &&
	    (c->data.map->rhs->tmpl_da->type == PW_TYPE_IPV4_ADDR)) {
		return true;
	}

	if ((lhs_type == PW_TYPE_IPV6_PREFIX) &&
	    (c->data.map->rhs->tmpl_da->type == PW_TYPE_IPV6_ADDR)) {
		return true;
	}

	/*
	 *	Same checks as above, but with the types swapped, and
	 *	with explicit cast for the interpretor.
	 */
	if ((lhs_type == PW_TYPE_IPV4_ADDR) &&
	    (c->data.map->rhs->tmpl_da->type == PW_TYPE_IPV4_PREFIX)) {
		c->cast = c->data.map->rhs->tmpl_da;
		return true;
	}

	if ((lhs_type == PW_TYPE_IPV6_ADDR) &&
	    (c->data.map->rhs->tmpl_da->type == PW_TYPE_IPV6_PREFIX)) {
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


/** Tokenize a conditional check
 *
 *  @param[in] ctx for talloc
 *  @param[in] ci for CONF_ITEM
 *  @param[in] start the start of the string to process.  Should be "(..."
 *  @param[in] brace look for a closing brace
 *  @param[out] pcond pointer to the returned condition structure
 *  @param[out] error the parse error (if any)
 *  @param[in] flags do one/two pass
 *  @return length of the string skipped, or when negative, the offset to the offending error
 */
static ssize_t condition_tokenize(TALLOC_CTX *ctx, CONF_ITEM *ci, char const *start, bool brace,
				  fr_cond_t **pcond, char const **error, int flags)
{
	ssize_t slen, tlen;
	char const *p = start;
	char const *lhs_p, *rhs_p;
	fr_cond_t *c;
	char *lhs, *rhs;
	FR_TOKEN op, lhs_type, rhs_type;

	c = talloc_zero(ctx, fr_cond_t);

	rad_assert(c != NULL);
	lhs = rhs = NULL;
	lhs_type = rhs_type = T_INVALID;

	while (isspace((int) *p)) p++; /* skip spaces before condition */

	if (!*p) {
		return_P("Empty condition is invalid");
	}

	/*
	 *	!COND
	 */
	if (*p == '!') {
		p++;
		c->negate = true;
		while (isspace((int) *p)) p++; /* skip spaces after negation */

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
		c->ci = ci;
		slen = condition_tokenize(c, ci, p, true, &c->data.child, error, flags);
		if (slen <= 0) {
			return_SLEN;
		}

		if (!c->data.child) {
			return_P("Empty condition is invalid");
		}

		p += slen;
		while (isspace((int) *p)) p++; /* skip spaces after (COND)*/

	} else { /* it's a bare FOO==BAR */
		/*
		 *	We didn't see anything special.  The condition must be one of
		 *
		 *	FOO
		 *	FOO OP BAR
		 */

		/*
		 *	Grab the LHS
		 */
		if (*p == '/') {
			return_P("Conditional check cannot begin with a regular expression");
		}

		slen = condition_tokenize_cast(p, &c->cast, error);
		if (slen < 0) {
			return_SLEN;
		}
		p += slen;

		lhs_p = p;
		slen = condition_tokenize_word(c, p, &lhs, &lhs_type, error);
		if (slen <= 0) {
			return_SLEN;
		}
		p += slen;

		/*
		 *	If the LHS is 0xabcdef... automatically cast it to octets
		 */
		if (!c->cast && (lhs_type == T_BARE_WORD) &&
		    (lhs[0] == '0') && (lhs[1] == 'x') &&
		    ((slen & 0x01) == 0)) {
			if (slen == 2) {
				return_P("Empty octet string is invalid");
			}

			c->cast = dict_attrbyvalue(PW_CAST_BASE + PW_TYPE_OCTETS, 0);
		}

		while (isspace((int)*p)) p++; /* skip spaces after LHS */

		/*
		 *	We may (or not) have an operator
		 */


		/*
		 *	(FOO)
		 */
		if (*p == ')') {
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
				return_0("Cannot do cast for existence check");
			}

			c->type = COND_TYPE_EXISTS;
			c->ci = ci;

			tlen = tmpl_afrom_str(c, &c->data.vpt, lhs, talloc_array_length(lhs) - 1,
					      lhs_type, REQUEST_CURRENT, PAIR_LIST_REQUEST, false);
			if (tlen < 0) {
				p = lhs_p - tlen;
				return_P(fr_strerror());
			}

			rad_assert(c->data.vpt->type != TMPL_TYPE_REGEX);

			if (c->data.vpt->type == TMPL_TYPE_ATTR_UNDEFINED) {
				c->pass2_fixup = PASS2_FIXUP_ATTR;
			}

		} else { /* it's an operator */
#ifdef HAVE_REGEX
			bool regex = false;
			bool iflag = false;
			bool mflag = false;
#endif
			vp_map_t *map;

			/*
			 *	The next thing should now be a comparison operator.
			 */
			c->type = COND_TYPE_MAP;
			c->ci = ci;

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

			while (isspace((int) *p)) p++; /* skip spaces after operator */

			if (!*p) {
				return_P("Expected text after operator");
			}

			/*
			 *	Cannot have a cast on the RHS.
			 *	But produce good errors, too.
			 */
			if (*p == '<') {
				DICT_ATTR const *cast_da;

				slen = condition_tokenize_cast(p, &cast_da, error);
				if (slen < 0) {
					return_SLEN;
				}

				if (!c->cast) {
					return_P("Unexpected cast");
				}

				if (c->cast != cast_da) {
					return_P("Cannot cast to a different data type");
				}

				return_P("Unnecessary cast");
			}

			/*
			 *	Grab the RHS
			 */
			rhs_p = p;
			slen = condition_tokenize_word(c, p, &rhs, &rhs_type, error);
			if (slen <= 0) {
				return_SLEN;
			}

#ifdef HAVE_REGEX
			/*
			 *	Sanity checks for regexes.
			 */
			if (regex) {
				if (*p != '/') {
					return_P("Expected regular expression");
				}
				for (;;) {
					switch (p[slen]) {
					/*
					 *	/foo/i
					 */
					case 'i':
						iflag = true;
						slen++;
						continue;

					/*
					 *	/foo/m
					 */
					case 'm':
						mflag = true;
						slen++;
						continue;

					default:
						break;
					}
					break;
				}
			} else if (!regex && (*p == '/')) {
				return_P("Unexpected regular expression");
			}

#endif
			/*
			 *	Duplicate map_from_fields here, as we
			 *	want to separate parse errors in the
			 *	LHS from ones in the RHS.
			 */
			c->data.map = map = talloc_zero(c, vp_map_t);

			tlen = tmpl_afrom_str(map, &map->lhs, lhs, talloc_array_length(lhs) - 1,
					      lhs_type, REQUEST_CURRENT, PAIR_LIST_REQUEST, false);
			if (tlen < 0) {
				p = lhs_p - tlen;
				return_P(fr_strerror());
			}

			if (tmpl_define_unknown_attr(map->lhs) < 0) {
				return_lhs("Failed defining attribute");
			return_lhs:
				if (lhs) talloc_free(lhs);
				if (rhs) talloc_free(rhs);
				talloc_free(c);
				return -(lhs_p - start);
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
				    !((map->lhs->tmpl_da->type == PW_TYPE_OCTETS) ||
				      (map->lhs->tmpl_da->type == PW_TYPE_BYTE) ||
				      (map->lhs->tmpl_da->type == PW_TYPE_SHORT) ||
				      (map->lhs->tmpl_da->type == PW_TYPE_INTEGER) ||
				      (map->lhs->tmpl_da->type == PW_TYPE_INTEGER64))) {
					c->cast = dict_attrbyvalue(PW_CAST_BASE + PW_TYPE_OCTETS, 0);
				}
			}

			if ((map->lhs->type == TMPL_TYPE_ATTR) &&
			    map->lhs->tmpl_da->flags.is_unknown &&
			    map_cast_from_hex(map, rhs_type, rhs)) {
				/* do nothing */

			} else {
				tlen = tmpl_afrom_str(map, &map->rhs, rhs, talloc_array_length(rhs) - 1, rhs_type,
						      REQUEST_CURRENT, PAIR_LIST_REQUEST, false);
				if (tlen < 0) {
					p = rhs_p - tlen;
					return_P(fr_strerror());
				}

				if (tmpl_define_unknown_attr(map->rhs) < 0) {
					return_rhs("Failed defining attribute");
				}
			}

			/*
			 *	Unknown attributes get marked up for pass2.
			 */
			if ((c->data.map->lhs->type == TMPL_TYPE_ATTR_UNDEFINED) ||
			    (c->data.map->rhs->type == TMPL_TYPE_ATTR_UNDEFINED)) {
				c->pass2_fixup = PASS2_FIXUP_ATTR;
			}

#ifdef HAVE_REGEX
			if (c->data.map->rhs->type == TMPL_TYPE_REGEX) {
				c->data.map->rhs->tmpl_iflag = iflag;
				c->data.map->rhs->tmpl_mflag = mflag;
			}
#endif

			/*
			 *	Save the CONF_ITEM for later.
			 */
			c->data.map->ci = ci;

			/*
			 *	@todo: check LHS and RHS separately, to
			 *	get better errors
			 */
			if ((c->data.map->rhs->type == TMPL_TYPE_LIST) ||
			    (c->data.map->lhs->type == TMPL_TYPE_LIST)) {
				return_0("Cannot use list references in condition");
			}

			/*
			 *	Check cast type.  We can have the RHS
			 *	a string if the LHS has a cast.  But
			 *	if the RHS is an attr, it MUST be the
			 *	same type as the LHS.
			 */
			if (c->cast) {
				if ((c->data.map->rhs->type == TMPL_TYPE_ATTR) &&
				    (c->cast->type != c->data.map->rhs->tmpl_da->type)) {
					if (condition_check_types(c, c->cast->type)) {
						goto keep_going;
					}

					goto same_type;
				}

#ifdef HAVE_REGEX
				if (c->data.map->rhs->type == TMPL_TYPE_REGEX) {
					return_0("Cannot use cast with regex comparison");
				}
#endif

				/*
				 *	The LHS is a literal which has been cast to a data type.
				 *	Cast it to the appropriate data type.
				 */
				if ((c->data.map->lhs->type == TMPL_TYPE_LITERAL) &&
				    (tmpl_cast_in_place(c->data.map->lhs, c->cast->type, c->cast) < 0)) {
					*error = "Failed to parse field";
					if (lhs) talloc_free(lhs);
					if (rhs) talloc_free(rhs);
					talloc_free(c);
					return -(lhs_p - start);
				}

				/*
				 *	The RHS is a literal, and the LHS has been cast to a data
				 *	type.
				 */
				if ((c->data.map->lhs->type == TMPL_TYPE_DATA) &&
				    (c->data.map->rhs->type == TMPL_TYPE_LITERAL) &&
				    (tmpl_cast_in_place(c->data.map->rhs, c->cast->type, c->cast) < 0)) {
					return_rhs("Failed to parse field");
				}

				/*
				 *	We may be casting incompatible
				 *	types.  We check this based on
				 *	their size.
				 */
				if (c->data.map->lhs->type == TMPL_TYPE_ATTR) {
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
					if ((c->data.map->lhs->tmpl_da->type == PW_TYPE_STRING) ||
					    (c->data.map->lhs->tmpl_da->type == PW_TYPE_OCTETS)) {
						goto cast_ok;
					}

					/*
					 *	ifid to integer64 is OK
					 */
					if ((c->data.map->lhs->tmpl_da->type == PW_TYPE_IFID) &&
					    (c->cast->type == PW_TYPE_INTEGER64)) {
						goto cast_ok;
					}

					/*
					 *	ipaddr to ipv4prefix is OK
					 */
					if ((c->data.map->lhs->tmpl_da->type == PW_TYPE_IPV4_ADDR) &&
					    (c->cast->type == PW_TYPE_IPV4_PREFIX)) {
						goto cast_ok;
					}

					/*
					 *	ipv6addr to ipv6prefix is OK
					 */
					if ((c->data.map->lhs->tmpl_da->type == PW_TYPE_IPV6_ADDR) &&
					    (c->cast->type == PW_TYPE_IPV6_PREFIX)) {
						goto cast_ok;
					}

					/*
					 *	integer64 to ethernet is OK.
					 */
					if ((c->data.map->lhs->tmpl_da->type == PW_TYPE_INTEGER64) &&
					    (c->cast->type == PW_TYPE_ETHERNET)) {
						goto cast_ok;
					}

					/*
					 *	dst.max < src.min
					 *	dst.min > src.max
					 */
					if ((dict_attr_sizes[c->cast->type][1] < dict_attr_sizes[c->data.map->lhs->tmpl_da->type][0]) ||
					    (dict_attr_sizes[c->cast->type][0] > dict_attr_sizes[c->data.map->lhs->tmpl_da->type][1])) {
						return_0("Cannot cast to attribute of incompatible size");
					}
				}

			cast_ok:
				/*
				 *	Casting to a redundant type means we don't need the cast.
				 *
				 *	Do this LAST, as the rest of the code above assumes c->cast
				 *	is not NULL.
				 */
				if ((c->data.map->lhs->type == TMPL_TYPE_ATTR) &&
				    (c->cast->type == c->data.map->lhs->tmpl_da->type)) {
					c->cast = NULL;
				}

			} else {
				vp_tmpl_t *vpt;

				/*
				 *	Two attributes?  They must be of the same type
				 */
				if ((c->data.map->rhs->type == TMPL_TYPE_ATTR) &&
				    (c->data.map->lhs->type == TMPL_TYPE_ATTR) &&
				    (c->data.map->lhs->tmpl_da->type != c->data.map->rhs->tmpl_da->type)) {
					if (condition_check_types(c, c->data.map->lhs->tmpl_da->type)) {
						goto keep_going;
					}

				same_type:
					return_0("Attribute comparisons must be of the same data type");
				}

				/*
				 *	Without a cast, we can't compare "foo" to User-Name,
				 *	it has to be done the other way around.
				 */
				if ((c->data.map->rhs->type == TMPL_TYPE_ATTR) &&
				    (c->data.map->lhs->type != TMPL_TYPE_ATTR)) {
					*error = "Cannot use attribute reference on right side of condition";
				return_0:
					if (lhs) talloc_free(lhs);
					if (rhs) talloc_free(rhs);
					talloc_free(c);
					return 0;
				}

				/*
				 *	Invalid: User-Name == bob
				 *	Valid:   User-Name == "bob"
				 *
				 *	There's no real reason for
				 *	this, other than consistency.
				 */
				if ((c->data.map->lhs->type == TMPL_TYPE_ATTR) &&
				    (c->data.map->rhs->type != TMPL_TYPE_ATTR) &&
				    (c->data.map->lhs->tmpl_da->type == PW_TYPE_STRING) &&
				    (c->data.map->op != T_OP_CMP_TRUE) &&
				    (c->data.map->op != T_OP_CMP_FALSE) &&
				    (rhs_type == T_BARE_WORD)) {
					return_rhs("Must have string as value for attribute");
				}

				/*
				 *	Quotes around non-string
				 *	attributes mean that it's
				 *	either xlat, or an exec.
				 */
				if ((c->data.map->lhs->type == TMPL_TYPE_ATTR) &&
				    (c->data.map->rhs->type != TMPL_TYPE_ATTR) &&
				    (c->data.map->lhs->tmpl_da->type != PW_TYPE_STRING) &&
				    (c->data.map->lhs->tmpl_da->type != PW_TYPE_OCTETS) &&
				    (c->data.map->lhs->tmpl_da->type != PW_TYPE_DATE) &&
				    (rhs_type == T_SINGLE_QUOTED_STRING)) {
					*error = "Value must be an unquoted string";
				return_rhs:
					if (lhs) talloc_free(lhs);
					if (rhs) talloc_free(rhs);
					talloc_free(c);
					return -(rhs_p - start);
				}

				/*
				 *	The LHS has been cast to a data type, and the RHS is a
				 *	literal.  Cast the RHS to the type of the cast.
				 */
				if (c->cast && (c->data.map->rhs->type == TMPL_TYPE_LITERAL) &&
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
				if ((c->data.map->lhs->type == TMPL_TYPE_ATTR) &&
				    (c->data.map->rhs->type == TMPL_TYPE_LITERAL)) {
					PW_TYPE type = c->data.map->lhs->tmpl_da->type;

					switch (c->data.map->lhs->tmpl_da->type) {
					case PW_TYPE_IPV4_ADDR:
						if (strchr(c->data.map->rhs->name, '/') != NULL) {
							type = PW_TYPE_IPV4_PREFIX;
							c->cast = dict_attrbyvalue(PW_CAST_BASE + type, 0);
						}
						break;

					case PW_TYPE_IPV6_ADDR:
						if (strchr(c->data.map->rhs->name, '/') != NULL) {
							type = PW_TYPE_IPV6_PREFIX;
							c->cast = dict_attrbyvalue(PW_CAST_BASE + type, 0);
						}
						break;

					default:
						break;
					}

					if (tmpl_cast_in_place(c->data.map->rhs, type, c->data.map->lhs->tmpl_da) < 0) {
						DICT_ATTR const *da = c->data.map->lhs->tmpl_da;

						if ((da->vendor == 0) &&
						    ((da->attr == PW_AUTH_TYPE) ||
						     (da->attr == PW_AUTZ_TYPE) ||
						     (da->attr == PW_ACCT_TYPE) ||
						     (da->attr == PW_SESSION_TYPE) ||
						     (da->attr == PW_POST_AUTH_TYPE) ||
						     (da->attr == PW_PRE_PROXY_TYPE) ||
						     (da->attr == PW_POST_PROXY_TYPE) ||
						     (da->attr == PW_PRE_ACCT_TYPE) ||
						     (da->attr == PW_RECV_COA_TYPE) ||
						     (da->attr == PW_SEND_COA_TYPE))) {
							/*
							 *	The types for these attributes are dynamically allocated
							 *	by modules.c, so we can't enforce strictness here.
							 */
							c->pass2_fixup = PASS2_FIXUP_TYPE;

						} else {
							return_rhs("Failed to parse value for attribute");
						}
					}

					/*
					 *	Stupid WiMAX shit.
					 *	Cast the LHS to the
					 *	type of the RHS.
					 */
					if (c->data.map->lhs->tmpl_da->type == PW_TYPE_COMBO_IP_ADDR) {
						DICT_ATTR const *da;

						da = dict_attrbytype(c->data.map->lhs->tmpl_da->attr,
								     c->data.map->lhs->tmpl_da->vendor,
								     c->data.map->rhs->tmpl_data_type);
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
				if ((c->data.map->lhs->type == TMPL_TYPE_ATTR) &&
				    ((c->data.map->rhs->type == TMPL_TYPE_XLAT) ||
				     (c->data.map->rhs->type == TMPL_TYPE_XLAT_STRUCT) ||
				     (c->data.map->rhs->type == TMPL_TYPE_EXEC))) {
					if (c->data.map->lhs->tmpl_da->type == PW_TYPE_IPV4_ADDR) {
						c->cast = dict_attrbyvalue(PW_CAST_BASE + PW_TYPE_IPV4_PREFIX, 0);
					}

					if (c->data.map->lhs->tmpl_da->type == PW_TYPE_IPV6_ADDR) {
						c->cast = dict_attrbyvalue(PW_CAST_BASE + PW_TYPE_IPV6_PREFIX, 0);
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
				if ((c->data.map->lhs->type == TMPL_TYPE_LITERAL) && (lhs_type == T_BARE_WORD)) {
					int hyphens = 0;
					bool may_be_attr = true;
					size_t i;
					ssize_t attr_slen;

					/*
					 *	Backwards compatibility: Allow Foo-Bar,
					 *	e.g. LDAP-Group and SQL-Group.
					 */
					for (i = 0; i < c->data.map->lhs->len; i++) {
						if (!dict_attr_allowed_chars[(unsigned char) c->data.map->lhs->name[i]]) {
							may_be_attr = false;
							break;
						}

						if (c->data.map->lhs->name[i] == '-') {
							hyphens++;
							if (hyphens > 1) {
								may_be_attr = false;
								break;
							}
						}
					}

					if (!hyphens || (hyphens > 3)) may_be_attr = false;

					if (may_be_attr) {
						attr_slen = tmpl_afrom_attr_str(c->data.map, &vpt, lhs,
										REQUEST_CURRENT, PAIR_LIST_REQUEST,
										true, true);
						if ((attr_slen > 0) && (vpt->len == c->data.map->lhs->len)) {
							talloc_free(c->data.map->lhs);
							c->data.map->lhs = vpt;
							c->pass2_fixup = PASS2_FIXUP_ATTR;
						}
					}
				}
			} /* we didn't have a cast */

		keep_going:
			p += slen;

			while (isspace((int) *p)) p++; /* skip spaces after RHS */
		} /* parse OP RHS */
	} /* parse a condition (COND) or FOO OP BAR*/

	/*
	 *	...COND)
	 */
	if (*p == ')') {
		if (!brace) {
			return_P("Unexpected closing brace");
		}

		p++;
		while (isspace((int) *p)) p++; /* skip spaces after closing brace */
		goto done;
	}

	/*
	 *	End of string is now allowed.
	 */
	if (!*p) {
		if (brace) {
			return_P("No closing brace at end of string");
		}

		goto done;
	}

	if (!(((p[0] == '&') && (p[1] == '&')) ||
	      ((p[0] == '|') && (p[1] == '|')))) {
		*error = "Unexpected text after condition";
	return_p:
		if (lhs) talloc_free(lhs);
		if (rhs) talloc_free(rhs);
		talloc_free(c);
		return -(p - start);
	}

	/*
	 *	Recurse to parse the next condition.
	 */
	c->next_op = p[0];
	p += 2;

	/*
	 *	May still be looking for a closing brace.
	 */
	slen = condition_tokenize(c, ci, p, brace, &c->next, error, flags);
	if (slen <= 0) {
	return_slen:
		if (lhs) talloc_free(lhs);
		if (rhs) talloc_free(rhs);
		talloc_free(c);
		return slen - (p - start);
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

		lhs = rhs = NULL;
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

		lhs = rhs = NULL;
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
		if ((c->data.map->lhs->type == TMPL_TYPE_DATA) &&
		    (c->data.map->rhs->type == TMPL_TYPE_DATA)) {
			int rcode;

			rad_assert(c->cast != NULL);

			rcode = radius_evaluate_map(NULL, 0, 0, c);
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
		if ((c->data.map->rhs->type == TMPL_TYPE_LITERAL) &&
		    (c->data.map->lhs->type == TMPL_TYPE_LITERAL) &&
		    !c->pass2_fixup) {
			int rcode;

			rad_assert(c->cast == NULL);

			rcode = radius_evaluate_map(NULL, 0, 0, c);
			if (rcode) {
				c->type = COND_TYPE_TRUE;
			} else {
				DEBUG3("OPTIMIZING (%s %s %s) --> FALSE",
				       c->data.map->lhs->name,
				       fr_int2str(fr_tokens, c->data.map->op, "??"),
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
		    (c->data.map->rhs->type == TMPL_TYPE_ATTR) &&
		    (c->cast->type == c->data.map->rhs->tmpl_da->type) &&
		    (c->data.map->lhs->type != TMPL_TYPE_ATTR)) {
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
			rad_assert(c->data.map->rhs->type != TMPL_TYPE_LITERAL);
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
		case TMPL_TYPE_LITERAL:
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

				rcode = fr_str2int(allowed_return_codes,
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

		lhs = rhs = NULL;
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

		lhs = rhs = NULL;
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

	if (lhs) talloc_free(lhs);
	if (rhs) talloc_free(rhs);

	*pcond = c;
	return p - start;
}

/** Tokenize a conditional check
 *
 *  @param[in] ctx for talloc
 *  @param[in] ci for CONF_ITEM
 *  @param[in] start the start of the string to process.  Should be "(..."
 *  @param[out] head the parsed condition structure
 *  @param[out] error the parse error (if any)
 *  @param[in] flags do one/two pass
 *  @return length of the string skipped, or when negative, the offset to the offending error
 */
ssize_t fr_condition_tokenize(TALLOC_CTX *ctx, CONF_ITEM *ci, char const *start, fr_cond_t **head, char const **error, int flags)
{
	return condition_tokenize(ctx, ci, start, false, head, error, flags);
}

/*
 *	Walk in order.
 */
bool fr_condition_walk(fr_cond_t *c, bool (*callback)(void *, fr_cond_t *), void *ctx)
{
	while (c) {
		/*
		 *	Process this one, exit on error.
		 */
		if (!callback(ctx, c)) return false;

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
			if (!fr_condition_walk(c->data.child, callback, ctx)) {
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
