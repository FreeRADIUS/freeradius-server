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


static ssize_t condition_tokenize_string(const char *start, const char **error)
{
	const char *p = start;

	p++;

	COND_DEBUG("STRING %s", start);
	while (*p) {
		if (*p == *start) {
			COND_DEBUG("end of string %s", p);
			return (p + 1) - start;
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


/** Tokenize a conditional check
 *
 *  @param[in] start the start of the string to process.  Should be "(..."
 *  @param[in] brace look for matching braces.
 *  @param[out] child whether or not a child expression was parsed
 *  @param[out] error the parse error (if any)
 *  @return length of the string skipped, or when negative, the offset to the offending error
 */
static ssize_t condition_tokenize(const char *start, int brace, int *child, const char **error)
{
	int sub, regex;
	ssize_t slen;
	const char *p = start;

	sub = FALSE;

	if (p == start) {
		COND_DEBUG("START %s", p);

	} else {
	start_over:
		COND_DEBUG("START OVER %s", p);
	}

	/*
	 *	We expect to see the start of a condition here.
	 */
	while (*p) {
		if (isspace((int) *p)) {
			p++;
			continue;
		}

		/*
		 *	Allow !CONDITION
		 */
		if (*p == '!') {
			p++;
			continue;
		}

		/*
		 *	Grab a sub-condition.
		 */
		if (*p == '(') {
			int mychild = FALSE;

			p++;

			/*
			 *	We've already eaten one layer of
			 *	brackets.  Go recurse to get more.
			 */
			slen = condition_tokenize(p, TRUE, &mychild, error);
			if (slen <= 0) {
				COND_DEBUG("RETURN %d", __LINE__);
				return slen - (p - start);
			}

			if (!mychild) {
				COND_DEBUG("RETURN %d", __LINE__);
				*error = "Empty condition is invalid";
				return -(p - start);
			}
			*child = TRUE;

			if (p[slen - 1] != ')') {
				*error = "No matching close brace";
				COND_DEBUG("RETURN %d", __LINE__);
				return -(p - start);
			}

			p += slen;

			/*
			 *	If we're not looking for more braces,
			 *	we've found the last one.
			 */
			if (!brace) {
				return p - start;
			}

			/*
			 *	Had a leading subcondition.  We now
			 *	allow AND/OR.
			 */
			sub = TRUE;
			continue;
		}

		/*
		 *	Finish the current condition
		 */
		if (*p == ')') {
		closing_brace:
			if (!brace) {
				*error = "Too many closing braces";
				COND_DEBUG("RETURN %d", __LINE__);
				return - (p - start);
			}

			COND_DEBUG("RETURN %d", __LINE__);
			p++;
			return p - start;
		}

		/*
		 *	Look for CONDITION AND CONDITION
		 */
		if (((p[0] == '&') && (p[1] == '&')) ||
		    ((p[0] == '|') && (p[1] == '|'))) {
			COND_DEBUG("Found OR");
			if (!sub) {
				*error = "Expected condition before logical operator";
				COND_DEBUG("RETURN %d", __LINE__);
				return -(p - start);
			}

			/*
			 *	We've now done CONDITION
			 *	AND/OR... allow a bare condition
			 *	again.
			 */
			sub = FALSE;
			p += 2;
			continue;
		}

		/*
		 *	We've seen a subcondition, followed by
		 *	something OTHER than another subcondition or
		 *	AND/OR.  It's a parse error.
		 */
		if (sub) {
			*error = "Expected logical operator || or &&";
			COND_DEBUG("RETURN %d", __LINE__);
			return -(p - start);
		}

		/*
		 *	Something else.  It must be a bare condition.
		 */
		break;
	}

	rad_assert(!isspace((int) *p));

	/*
	 *	FOO
	 *	FOO OP BAR
	 */
	while (*p) {
		/*
		 *	LHS may be a string.
		 */
		if ((*p == '"') || (*p == '\'') || (*p == '`')) {
			COND_DEBUG("LHS %s", p);
			slen = condition_tokenize_string(p, error);
			if (slen <= 0) {
				COND_DEBUG("RETURN %d", __LINE__);
				return slen - (p - start);
			}
			p += slen;

			*child = TRUE;
			break;
		}

		/*
		 *	The LHS should really be limited to only a few
		 *	things.  For now, we allow pretty much anything.
		 */
		if (*p == '\\') {
		unexpected_escape:
			*error = "Unexpected escape";
				COND_DEBUG("RETURN %d", __LINE__);
			return -(p - start);
		}

		/*
		 *	("foo") is valid.
		 */
		if (*p == ')') goto closing_brace;

		/*
		 *	Spaces or AND/OR or OP delineate the LHS.
		 */
		if (isspace((int) *p) || (*p == '&') || (*p == '|') ||
		    (*p == '!') || (*p == '=') || (*p == '<') || (*p == '>')) {
			break;
		}

		*child = TRUE;	/* FIXME: don't do this on every character... oh well */
		p++;
	}

	while (isspace((int) *p)) p++; /* skip spaces */

	/*
	 *	(foo)
	 */
	if (*p == ')') goto closing_brace;

	COND_DEBUG("OPERATOR? %s", p);

	/*
	 *	We've successfully parsed the LHS.  If it's just an
	 *	existence check, the next thing may be AND/OR.
	 */
	if (((p[0] == '&') && (p[1] == '&')) ||
	    ((p[0] == '|') && (p[1] == '|'))) {
		sub = FALSE;
		p += 2;
		COND_DEBUG("AFTER AND/OR %s", p);
		goto start_over;
	}

	/*
	 *	The next thing should now be a comparison operator.
	 */
	regex = FALSE;
	switch (*p) {
	default:
		*error = "Invalid text.  Expected comparison operator";
				COND_DEBUG("RETURN %d", __LINE__);
		return -(p - start);

	case '!':
		regex = (p[1] == '~');

		p++;
		if (!((*p == '=') || (*p == '~') || (*p == '*'))) {
		invalid_operator:
			*error = "Invalid operator";
				COND_DEBUG("RETURN %d", __LINE__);
			return -(p - start);
		}

		p += 2;
		break;

	case '=':
		regex = (p[1] == '~');

		p++;
		if (!((*p == '=') || (*p == '~') || (*p == '*'))) {
			goto invalid_operator;
		}
		p += 2;
		break;

	case '<':
	case '>':
		/*
		 *	Allow a<b
		 */
		if (p[1] == '=') {
			p++;
		}
		p++;
		break;
	}

	while (isspace((int) *p)) p++; /* skip spaces */

	COND_DEBUG("RHS %s", p);

	if (regex) {
		if (*p != '/') {
			*error = "Expected regular expression";
				COND_DEBUG("RETURN %d", __LINE__);
			return -(p - start);
		}

		slen = condition_tokenize_string(p, error);
		if (slen <= 0) {
				COND_DEBUG("RETURN %d", __LINE__);
			return slen - (p - start);
		}
		p += slen;

		/*
		 *	Allow /foo/i
		 */
		if (*p == 'i') p++;

		COND_DEBUG("DONE REGEX %s", p);
		sub = TRUE;
		goto start_over;

	} else if (!regex && (*p == '/')) {
		*error = "Unexpected regular expression";
		COND_DEBUG("RETURN %d", __LINE__);
		return -(p - start);
	}

	if ((*p == '"') || (*p == '`') || (*p == '\'')) {
		slen = condition_tokenize_string(p, error);
		if (slen <= 0) {
				COND_DEBUG("RETURN %d", __LINE__);
			return slen - (p - start);
		}
		p += slen;

		COND_DEBUG("DONE STRING %s", p);
		sub = TRUE;
		goto start_over;
	}

	/*
	 *	The RHS should now be just a bare word.
	 */
	while (*p) {
		/*
		 *	Can't do: aaa"foo".  That's dumb.
		 */
		if ((*p == '"') || (*p == '`') || (*p == '\'')) {
			*error = "Unexpected start of string";
				COND_DEBUG("RETURN %d", __LINE__);
			return -(p - start);
		}

		if (*p == '\\') goto unexpected_escape;

		/*
		 *	Allow braces to close a bare word.
		 */
		if (*p == ')') goto closing_brace;

		/*
		 *	RHS is delineated by a space.
		 */
		if (isspace((int) *p)) {
			COND_DEBUG("SPACE AFTER RHS: %s", p);
			sub = TRUE;
			goto start_over;
		}

		/*
		 *	For now, allow anything else.
		 */

		p++;
	}

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
	int child;
	ssize_t slen;

	slen = condition_tokenize(start, FALSE, &child, error);
	if (slen <= 0) return slen;

	if (!child) {
		COND_DEBUG("RETURN %d", __LINE__);
		*error = "Empty condition is invalid";
		return -1;
	}

	return slen;
}
