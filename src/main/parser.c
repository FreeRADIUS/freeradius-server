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

#if 0
#define COND_DEBUG(fmt, ...) printf(fmt, ## __VA_ARGS__);printf("\n")
#endif

/*
 *	This file shouldn't use any functions from the server core.
 */
#ifndef COND_DEBUG
#if 0
#define COND_DEBUG DEBUG
#else
#define COND_DEBUG(...)
#endif
#endif

typedef enum cond_op_t {
	COND_NONE = 0,
	COND_TRUE,
	COND_NOT = '!',
	COND_AND = '&',
	COND_OR = '|'
} cond_op_t;


typedef struct cond_t cond_t;

/*
 *	Allow for the following structures:
 *
 *	FOO			no OP, RHS is NULL
 *	FOO OP BAR
 *	(COND)			no LHS/RHS, child is COND, child OP is TRUE
 *	(!(COND))		no LHS/RHS, child is COND, child OP is NOT
 *	(COND1 OP COND2)	no LHS/RHS, next is COND2, next OP is OP
 */
struct cond_t {
	char		*lhs;
	char		*rhs;
	FR_TOKEN 	op;
	int		regex_i;

	cond_op_t	next_op;
	cond_t		*next;
	cond_op_t	child_op;
	cond_t  	*child;
};

static void cond_debug(const cond_t *c)
{

next:
	if (c->child_op == COND_NOT) {
		printf("!");
	}

	if (c->op != T_OP_INVALID) {
		rad_assert(c->lhs != NULL);
		printf("%s", c->lhs);

		if (c->op != T_OP_CMP_TRUE) {
			printf(" %s ", fr_token_name(c->op));

			rad_assert(c->rhs != NULL);
			printf("%s", c->rhs);
		}

	} else {
		rad_assert(c->child != NULL);

		rad_assert(c->child_op != COND_AND);
		rad_assert(c->child_op != COND_OR);
		rad_assert(c->child != NULL);

		printf("(");
		cond_debug(c->child);
		printf(")");
	}

	if (c->next_op == COND_NONE) {
		rad_assert(c->next == NULL);
		return;
	}

	rad_assert(c->next_op != COND_TRUE);
	rad_assert(c->next_op != COND_NOT);

	if (c->next_op == COND_AND) {
		printf(" && ");

	} else if (c->next_op == COND_OR) {
		printf(" || ");

	} else {
		rad_assert(0 == 1);
	}

	c = c->next;
	goto next;
}


static ssize_t condition_tokenize_string(TALLOC_CTX *ctx, const char *start, char **out, const char **error)
{
	const char *p = start;

	p++;

	COND_DEBUG("STRING %s", start);
	while (*p) {
		if (*p == *start) {
			size_t len = (p + 1) - start;

			COND_DEBUG("end of string %s", p);
			*out = talloc_array(ctx, char, len + 1);

			memcpy(*out, start, len);
			(*out)[len] = '\0';
			return len;
		}

		if (*p == '\\') {
			p++;
			if (!*p) {
				*error = "End of string after escape";
				COND_DEBUG("RETURN %d", __LINE__);
				return -(p - start);
			}
		}
	
		p++;		/* allow anything else */
	}

	*error = "Unterminated string";
	return -1;
}

static ssize_t condition_tokenize_word(TALLOC_CTX *ctx, const char *start, char **out, const char **error)
{
	size_t len;
	const char *p = start;

	if ((*p == '"') || (*p == '\'') || (*p == '`') || (*p == '/')) {
		return condition_tokenize_string(ctx, start, out, error);
	}

	while (*p) {
		/*
		 *	The LHS should really be limited to only a few
		 *	things.  For now, we allow pretty much anything.
		 */
		if (*p == '\\') {
			*error = "Unexpected escape";
			COND_DEBUG("RETURN %d", __LINE__);
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
			COND_DEBUG("RETURN %d", __LINE__);
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
	COND_DEBUG("PARSED WORD %s", *out);
	return len;
}

/** Tokenize a conditional check
 *
 *  @param[in] start the start of the string to process.  Should be "(..."
 *  @param[in] brace look for a closing brace
 *  @param[out] child whether or not a child expression was parsed
 *  @param[out] error the parse error (if any)
 *  @return length of the string skipped, or when negative, the offset to the offending error
 */
static ssize_t condition_tokenize(TALLOC_CTX *ctx, const char *start, int brace, cond_t **pcond, const char **error)
{
	int sub;
	ssize_t slen;
	const char *p = start;
	cond_t *c;

	sub = FALSE;

	COND_DEBUG("START %s", p);

	c = talloc_zero(ctx, cond_t);

	rad_assert(c != NULL);

	while (isspace((int) *p)) p++; /* skip spaces before condition */

	if (!*p) {
		talloc_free(c);
		COND_DEBUG("RETURN %d", __LINE__);
		*error = "Empty condition is invalid";
		return -(p - start);
	}

	/*
	 *	!COND
	 */
	if (*p == '!') {
		 p++;
		 c->child_op = COND_NOT;
		 while (isspace((int) *p)) p++; /* skip spaces after negation */
	}

	/*
	 *	(COND)
	 */
	if (*p == '(') {
		p++;

		if (c->child_op == COND_NONE) c->child_op = COND_TRUE;

		/*
		 *	We've already eaten one layer of
		 *	brackets.  Go recurse to get more.
		 */
		slen = condition_tokenize(c, p, TRUE, &c->child, error);
		if (slen <= 0) {
			talloc_free(c);
			COND_DEBUG("RETURN %d", __LINE__);
			return slen - (p - start);
		}

		if (!c->child) {
			talloc_free(c);
			*error = "Empty condition is invalid";
			COND_DEBUG("RETURN %d", __LINE__);
			return -(p - start);
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
		COND_DEBUG("LHS %s", p);
		slen = condition_tokenize_word(c, p, &c->lhs, error);
		if (slen <= 0) {
			talloc_free(c);
			COND_DEBUG("RETURN %d", __LINE__);
			return slen - (p - start);
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
			c->op = T_OP_CMP_TRUE;

			/*
			 *	FOO
			 */
		} else if (!*p) {
			if (brace) {
				talloc_free(c);
				*error = "No closing brace at end of string";
				COND_DEBUG("RETURN %d", __LINE__);
				return -(p - start);
			}

			c->op = T_OP_CMP_TRUE;

			/*
			 *	FOO && ...
			 */
		} else if (((p[0] == '&') && (p[1] == '&')) ||
			   ((p[0] == '|') && (p[1] == '|'))) {

			c->op = T_OP_CMP_TRUE;

		} else { /* it's an operator */
			int regex;

			COND_DEBUG("OPERATOR %s", p);

			/*
			 *	The next thing should now be a comparison operator.
			 */
			regex = FALSE;
			switch (*p) {
			default:
				talloc_free(c);
				*error = "Invalid text. Expected comparison operator";
				COND_DEBUG("RETURN %d", __LINE__);
				return -(p - start);

			case '!':
				if (p[1] == '=') {
					c->op = T_OP_NE;
					p += 2;

				} else if (p[1] == '~') {
				regex = TRUE;

				c->op = T_OP_REG_NE;
				p += 2;

				} else if (p[1] == '*') {
					c->op = T_OP_CMP_FALSE;
					p += 2;

				} else {
				invalid_operator:
					talloc_free(c);
					*error = "Invalid operator";
					COND_DEBUG("RETURN %d", __LINE__);
					return -(p - start);
				}
				break;

			case '=':
				if (p[1] == '=') {
					c->op = T_OP_CMP_EQ;
					p += 2;

				} else if (p[1] == '~') {
					regex = TRUE;

					c->op = T_OP_REG_EQ;
					p += 2;

				} else if (p[1] == '*') {
					c->op = T_OP_CMP_TRUE;
					p += 2;

				} else {
					goto invalid_operator;
				}

				break;

			case '<':
				if (p[1] == '=') {
					c->op = T_OP_LE;
					p += 2;

				} else {
					c->op = T_OP_LT;
					p++;
				}
				break;

			case '>':
				if (p[1] == '=') {
					c->op = T_OP_GE;
					p += 2;

				} else {
					c->op = T_OP_GT;
					p++;
				}
				break;
			}

			while (isspace((int) *p)) p++; /* skip spaces after operator */

			if (!*p) {
				talloc_free(c);
				*error = "Expected text after operator";
				COND_DEBUG("RETURN %d", __LINE__);
				return -(p - start);
			}

			COND_DEBUG("RHS %s", p);

			/*
			 *	Grab the RHS
			 */
			slen = condition_tokenize_word(c, p, &c->rhs, error);
			if (slen <= 0) {
				talloc_free(c);
				COND_DEBUG("RETURN %d", __LINE__);
				return slen - (p - start);
			}

			/*
			 *	Sanity checks for regexes.
			 */
			if (regex) {
				if (*p != '/') {
					talloc_free(c);
					*error = "Expected regular expression";
					COND_DEBUG("RETURN %d", __LINE__);
					return -(p - start);
				}

				/*
				 *	Allow /foo/i
				 */
				if (p[slen] == 'i') {
					c->regex_i = TRUE;
					slen++;
				}

				COND_DEBUG("DONE REGEX %s", p + slen);

			} else if (!regex && (*p == '/')) {
				talloc_free(c);
				*error = "Unexpected regular expression";
				COND_DEBUG("RETURN %d", __LINE__);
				return -(p - start);
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
			talloc_free(c);
			*error = "Unexpected closing brace";
			COND_DEBUG("RETURN %d", __LINE__);
			return -(p - start);
		}

		p++;
		while (isspace((int) *p)) p++; /* skip spaces after closing brace */
		brace = FALSE;
		goto done;
	}

	/*
	 *	End of string is now allowed.
	 */
	if (!*p) {
		if (brace) {
			talloc_free(c);
			*error = "No closing brace at end of string";
			COND_DEBUG("RETURN %d", __LINE__);
			return -(p - start);
		}

		goto done;
	}

	if (!(((p[0] == '&') && (p[1] == '&')) ||
	      ((p[0] == '|') && (p[1] == '|')))) {
		talloc_free(c);
		*error = "Unexpected text after condition";
		return -(p - start);
	}

	/*
	 *	Recurse to parse the next condition.
	 */
	COND_DEBUG("GOT %c%c", p[0], p[1]);
	c->next_op = p[0];
	p += 2;

	/*
	 *	May still be looking for a closing brace.
	 */
	COND_DEBUG("RECURSE AND/OR");
	slen = condition_tokenize(c, p, brace, &c->next, error);
	if (slen <= 0) {
		talloc_free(c);
		COND_DEBUG("RETURN %d", __LINE__);
		return slen - (p - start);
	}
	p += slen;

done:
	*pcond = c;
	COND_DEBUG("RETURN %d", __LINE__);
	return p - start;
}

/** Tokenize a conditional check
 *
 *  @param[in] start the start of the string to process.  Should be "(..."
 *  @param[out] error the parse error (if any)
 *  @return length of the string skipped, or when negative, the offset to the offending error
 */
ssize_t fr_condition_tokenize(const char *start, const char **error)
{
	ssize_t slen;
	cond_t *c = NULL;

	slen = condition_tokenize(NULL, start, FALSE, &c, error);
	if (slen <= 0) return slen;

	if (!c) {
		COND_DEBUG("RETURN %d", __LINE__);
		*error = "Empty condition is invalid";
		return -1;
	}

	talloc_free(c);

	return slen;
}
