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

/*
 *	This file shouldn't use any functions from the server core.
 */

size_t fr_cond_sprint(char *buffer, size_t bufsize, fr_cond_t const *c)
{
	size_t len;
	char *p = buffer;
	char *end = buffer + bufsize - 1;

next:
	if (c->negate) {
		*(p++) = '!';	/* FIXME: only allow for child? */
	}

	switch (c->type) {
	case COND_TYPE_EXISTS:
		rad_assert(c->data.vpt != NULL);
		len = radius_tmpl2str(p, end - p, c->data.vpt);
		p += len;
		break;

	case COND_TYPE_MAP:
		rad_assert(c->data.map != NULL);
#if 0
		*(p++) = '[';	/* for extra-clear debugging */
#endif
		len = radius_map2str(p, end - p, c->data.map);
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


static ssize_t condition_tokenize_string(TALLOC_CTX *ctx, char const *start, char **out,
					 FR_TOKEN *op, char const **error)
{
	const char *p = start;
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
			*q = '\0';
			p++;
			return (p - start);
		}

		if (*p == '\\') {
			p++;
			if (!*p) {
				*error = "End of string after escape";
				return -(p - start);
			}

			switch (*p) {
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
				*q++ = *p;
				break;
			}
			p++;
			continue;
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
		return condition_tokenize_string(ctx, start, out, op, error);
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

/*
 *	Less code means less bugs
 */
#define return_P(_x) talloc_free(c);*error = _x;return -(p - start)
#define return_SLEN talloc_free(c);return slen -(p - start)


/** Tokenize a conditional check
 *
 *  @param[in] ctx for talloc
 *  @param[in] start the start of the string to process.  Should be "(..."
 *  @param[in] brace look for a closing brace
 *  @param[out] pcond pointer to the returned condition structure
 *  @param[out] error the parse error (if any)
 *  @return length of the string skipped, or when negative, the offset to the offending error
 */
static ssize_t condition_tokenize(TALLOC_CTX *ctx, char const *start, int brace, fr_cond_t **pcond, char const **error)
{
	ssize_t slen;
	const char *p = start;
	fr_cond_t *c;
	char *lhs, *rhs;
	FR_TOKEN op, lhs_type, rhs_type;

	c = talloc_zero(ctx, fr_cond_t);

	rad_assert(c != NULL);

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
		slen = condition_tokenize(c, p, true, &c->data.child, error);
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

		slen = condition_tokenize_word(c, p, &lhs, &lhs_type, error);
		if (slen <= 0) {
			return_SLEN;
		}
		p += slen;

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
			c->type = COND_TYPE_EXISTS;
			c->data.vpt = radius_str2tmpl(c, lhs, lhs_type);
			if (!c->data.vpt) {
				return_P("Failed creating exists");
			}

		} else { /* it's an operator */
			int regex;

			/*
			 *	The next thing should now be a comparison operator.
			 */
			regex = false;
			c->type = COND_TYPE_MAP;
			switch (*p) {
			default:
				return_P("Invalid text. Expected comparison operator");

			case '!':
				if (p[1] == '=') {
					op = T_OP_NE;
					p += 2;

				} else if (p[1] == '~') {
				regex = true;

				op = T_OP_REG_NE;
				p += 2;

				} else if (p[1] == '*') {
					/*
					 *	FOO !* BAR
					 *
					 *	is really !(FOO)
					 *
					 *	FIXME: we should
					 *	really re-write it...
					 */
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

				} else if (p[1] == '~') {
					regex = true;

					op = T_OP_REG_EQ;
					p += 2;

				} else if (p[1] == '*') {
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
			 *	Grab the RHS
			 */
			slen = condition_tokenize_word(c, p, &rhs, &rhs_type, error);
			if (slen <= 0) {
				return_SLEN;
			}

			/*
			 *	Sanity checks for regexes.
			 */
			if (regex) {
				if (*p != '/') {
					return_P("Expected regular expression");
				}

				/*
				 *	Allow /foo/i
				 */
				if (p[slen] == 'i') {
					c->regex_i = true;
					slen++;
				}

			} else if (!regex && (*p == '/')) {
				return_P("Unexpected regular expression");
			}

			c->data.map = radius_str2map(c, lhs, lhs_type, op, rhs, rhs_type,
						     REQUEST_CURRENT, PAIR_LIST_REQUEST,
						     REQUEST_CURRENT, PAIR_LIST_REQUEST);
			if (!c->data.map) {
				return_P("Failed creating check");
			}

			/*
			 *	@todo: check LHS and RHS separately, to
			 *	get better errors
			 */
			if ((c->data.map->src->type == VPT_TYPE_LIST) ||
			    (c->data.map->dst->type == VPT_TYPE_LIST)) {
				talloc_free(c);
				*error = "Cannot use list references in condition";
				return 0;
			}

			if ((c->data.map->src->type == VPT_TYPE_ATTR) &&
			    (c->data.map->dst->type != VPT_TYPE_ATTR)) {
				talloc_free(c);
				*error = "Cannot use attribute reference on right side of condition";
				return 0;
			}

			if ((c->data.map->src->type == VPT_TYPE_ATTR) &&
			    (c->data.map->dst->type == VPT_TYPE_ATTR) &&
			    (c->data.map->dst->da->type != c->data.map->src->da->type)) {
				talloc_free(c);
				*error = "Attribute comparisons must be of the same attribute type";
				return 0;
			}

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
		brace = false;
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
		return_P("Unexpected text after condition");
	}

	/*
	 *	Recurse to parse the next condition.
	 */
	c->next_op = p[0];
	p += 2;

	/*
	 *	May still be looking for a closing brace.
	 */
	slen = condition_tokenize(c, p, brace, &c->next, error);
	if (slen <= 0) {
		return_SLEN;
	}
	p += slen;

done:
	/*
	 *	Normalize it before returning it.
	 */

	/*
	 *	(FOO)     --> FOO
	 *	(FOO) ... --> FOO ...
	 */
	if ((c->type == COND_TYPE_CHILD) && !c->data.child->next) {
		fr_cond_t *child;

		child = c->data.child;
		child->next = c->next;
		child->next_op = c->next_op;
		c->next = NULL;
		c->data.child = NULL;

		/*
		 *	Set the negation properly
		 */
		if ((c->negate && !child->negate) ||
		    (!c->negate && child->negate)) {
			child->negate = true;
		} else {
			child->negate = false;
		}
		
		(void) talloc_steal(ctx, child);
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

		child = c->data.child;
		c->data.child = NULL;
		(void) talloc_steal(ctx, child);
		talloc_free(c);
		c = child;
	}

	/*
	 *	Normalize negation.  This doesn't really make any
	 *	difference, but it simplifies the run-time code in
	 *	evaluate.c
	 */
	if (c->type == COND_TYPE_MAP) {
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
		 *	which doesn't really work, but this hack fixes it.
		 *
		 *	FOO != BAR --> !FOO == BAR
		 */
		if (!c->negate && (c->data.map->op == T_OP_NE)) {
			c->negate = true;
			c->data.map->op = T_OP_CMP_EQ;
		}
	}

	*pcond = c;
	return p - start;
}

/** Tokenize a conditional check
 *
 *  @param[in] ctx for talloc
 *  @param[in] start the start of the string to process.  Should be "(..."
 *  @param[out] head the parsed condition structure
 *  @param[out] error the parse error (if any)
 *  @return length of the string skipped, or when negative, the offset to the offending error
 */
ssize_t fr_condition_tokenize(TALLOC_CTX *ctx, char const *start, fr_cond_t **head, char const **error)
{
	return condition_tokenize(ctx, start, false, head, error);
}
