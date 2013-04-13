/*
 * evaluate.c	Evaluate complex conditions
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
 * Copyright 2007  The FreeRADIUS server project
 * Copyright 2007  Alan DeKok <aland@deployingradius.com>
 */

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>

#include <ctype.h>

#ifdef HAVE_PCREPOSIX_H
#include <pcreposix.h>
#else
#ifdef HAVE_REGEX_H
#include <regex.h>

/*
 *  For POSIX Regular expressions.
 *  (0) Means no extended regular expressions.
 *  REG_EXTENDED means use extended regular expressions.
 */
#ifndef REG_EXTENDED
#define REG_EXTENDED (0)
#endif

#ifndef REG_NOSUB
#define REG_NOSUB (0)
#endif
#endif
#endif

#ifdef WITH_UNLANG

static int all_digits(const char *string)
{
	const char *p = string;

	if (*p == '-') p++;

	while (isdigit((int) *p)) p++;

	return (*p == '\0');
}

static const char *filler = "????????????????????????????????????????????????????????????????";

static const char *expand_string(char *buffer, size_t sizeof_buffer,
				 REQUEST *request,
				 FR_TOKEN value_type, const char *value)
{
	int result;
	char *p;

	switch (value_type) {
	default:
	case T_BARE_WORD:
	case T_SINGLE_QUOTED_STRING:
		return value;

	case T_BACK_QUOTED_STRING:
		result = radius_exec_program(value, request, 1,
					     buffer, sizeof_buffer, NULL,
					     NULL, 0);
		if (result != 0) {
			return NULL;
		}

		/*
		 *	The result should be ASCII.
		 */
		for (p = buffer; *p != '\0'; p++) {
			if (*p < ' ' ) {
				*p = '\0';
				return buffer;
			}
		}
		return buffer;

	case T_DOUBLE_QUOTED_STRING:
		if (!strchr(value, '%')) return value;

		radius_xlat(buffer, sizeof_buffer, request, value, NULL, NULL);
		return buffer;
	}

	return NULL;
}

#ifdef HAVE_REGEX_H
static FR_TOKEN getregex(const char **ptr, char *buffer, size_t buflen,
			 int *pcflags)
{
	const char *p = *ptr;
	char *q = buffer;

	if (*p != '/') return T_OP_INVALID;

	*pcflags = REG_EXTENDED;

	p++;
	while (*p) {
		if (buflen <= 1) break;

		if (*p == '/') {
			p++;

			/*
			 *	Check for case insensitivity
			 */
			if (*p == 'i') {
				p++;
				*pcflags |= REG_ICASE;
			}

			break;
		}

		if (*p == '\\') {
			int x;
			
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
			case '"':
				*q++ = '"';
				break;
			case '\'':
				*q++ = '\'';
				break;
			case '`':
				*q++ = '`';
				break;
				
				/*
				 *	FIXME: add 'x' and 'u'
				 */

			default:
				if ((p[1] >= '0') && (p[1] <= '9') &&
				    (sscanf(p + 1, "%3o", &x) == 1)) {
					*q++ = x;
					p += 2;
				} else {
					*q++ = p[1];
				}
				break;
			}
			p += 2;
			buflen--;
			continue;
		}

		*(q++) = *(p++);
		buflen--;
	}
	*q = '\0';
	*ptr = p;

	return T_DOUBLE_QUOTED_STRING;
}
#endif

static const FR_NAME_NUMBER modreturn_table[] = {
	{ "reject",     RLM_MODULE_REJECT       },
	{ "fail",       RLM_MODULE_FAIL	 },
	{ "ok",	 RLM_MODULE_OK	   },
	{ "handled",    RLM_MODULE_HANDLED      },
	{ "invalid",    RLM_MODULE_INVALID      },
	{ "userlock",   RLM_MODULE_USERLOCK     },
	{ "notfound",   RLM_MODULE_NOTFOUND     },
	{ "noop",       RLM_MODULE_NOOP	 },
	{ "updated",    RLM_MODULE_UPDATED      },
	{ NULL, 0 }
};


/*
 *	*presult is "did comparison match or not"
 */
static int radius_do_cmp(REQUEST *request, int *presult,
			 FR_TOKEN lt, const char *pleft, FR_TOKEN token,
			 UNUSED FR_TOKEN rt, const char *pright,
#ifdef HAVE_REGEX_H
			 int cflags,
#else
			 UNUSED int cflags,
#endif
			 int modreturn)
{
	int result;
	uint32_t lint, rint;
	VALUE_PAIR *vp = NULL;
#ifdef HAVE_REGEX_H
	char buffer[8192];
#endif

	if (lt == T_BARE_WORD) {
		/*
		 *	Maybe check the last return code.
		 */
		if (token == T_OP_CMP_TRUE) {
			int isreturn;

			/*
			 *	Looks like a return code, treat is as such.
			 */
			isreturn = fr_str2int(modreturn_table, pleft, -1);
			if (isreturn != -1) {
				*presult = (modreturn == isreturn);
				return TRUE;
			}
		}

		/*
		 *	Bare words on the left can be attribute names.
		 */
		if (!(radius_get_vp(request, pleft, &vp) < 0)) {
			VALUE_PAIR *myvp;

			/*
			 *	VP exists, and that's all we're looking for.
			 */
			if (token == T_OP_CMP_TRUE) {
				*presult = (vp != NULL);
				return TRUE;
			}

			if (!vp) {
				const DICT_ATTR *da;
				
				/*
				 *	The attribute on the LHS may
				 *	have been a dynamically
				 *	registered callback.  i.e. it
				 *	doesn't exist as a VALUE_PAIR.
				 *	If so, try looking for it.
				 */
				da = dict_attrbyname(pleft);
				if (da && (da->vendor == 0) && radius_find_compare(da->attr)) {
					VALUE_PAIR *check;
					check = pairmake(request, NULL, pleft, pright, token);
					*presult = (radius_callback_compare(request, NULL, check, NULL, NULL) == 0);
					RDEBUG3("  Callback returns %d",
						*presult);
					pairfree(&check);
					return TRUE;
				}
				
				RDEBUG2("    (Attribute %s was not found)",
				       pleft);
				*presult = 0;
				return TRUE;
			}

#ifdef HAVE_REGEX_H
			/*
			 * 	Regex comparisons treat everything as
			 *	strings.
			 */
			if ((token == T_OP_REG_EQ) ||
			    (token == T_OP_REG_NE)) {
				vp_prints_value(buffer, sizeof(buffer), vp, 0);
				pleft = buffer;
				goto do_checks;
			}
#endif

			myvp = paircopyvp(request, vp);
			if (!pairparsevalue(myvp, pright)) {
				pairbasicfree(myvp);
				RDEBUG2("Failed parsing \"%s\": %s",
				       pright, fr_strerror());
				return FALSE;
			}

			myvp->op = token;
			*presult = paircmp(myvp, vp);
			pairbasicfree(myvp);
			RDEBUG3("  paircmp -> %d", *presult);
			return TRUE;
		} /* else it's not a VP in a list */
	}

#ifdef HAVE_REGEX_H
	do_checks:
#endif
	switch (token) {
	case T_OP_GE:
	case T_OP_GT:
	case T_OP_LE:
	case T_OP_LT:
		if (!all_digits(pright)) {
			RDEBUG2("    (Right field is not a number at: %s)", pright);
			return FALSE;
		}
		rint = strtoul(pright, NULL, 0);
		if (!all_digits(pleft)) {
			RDEBUG2("    (Left field is not a number at: %s)", pleft);
			return FALSE;
		}
		lint = strtoul(pleft, NULL, 0);
		break;
		
	default:
		lint = rint = 0;  /* quiet the compiler */
		break;
	}
	
	switch (token) {
	case T_OP_CMP_TRUE:
		/*
		 *	Check for truth or falsehood.
		 */
		if (all_digits(pleft)) {
			lint = strtoul(pleft, NULL, 0);
			result = (lint != 0);
			
		} else {
			result = (*pleft != '\0');
		}
		break;
		

	case T_OP_CMP_EQ:
		result = (strcmp(pleft, pright) == 0);
		break;
		
	case T_OP_NE:
		result = (strcmp(pleft, pright) != 0);
		break;
		
	case T_OP_GE:
		result = (lint >= rint);
		break;
		
	case T_OP_GT:
		result = (lint > rint);
		break;
		
	case T_OP_LE:
		result = (lint <= rint);
		break;
		
	case T_OP_LT:
		result = (lint < rint);
		break;

#ifdef HAVE_REGEX_H
	case T_OP_REG_EQ: {
		int i, compare;
		regex_t reg;
		regmatch_t rxmatch[REQUEST_MAX_REGEX + 1];
		
		/*
		 *	Include substring matches.
		 */
		compare = regcomp(&reg, pright, cflags);
		if (compare != 0) {
			if (debug_flag) {
				char errbuf[128];

				regerror(compare, &reg, errbuf, sizeof(errbuf));
				DEBUGE("Failed compiling regular expression: %s", errbuf);
			}
			return FALSE;
		}

		compare = regexec(&reg, pleft,
				  REQUEST_MAX_REGEX + 1,
				  rxmatch, 0);
		regfree(&reg);
		
		/*
		 *	Add new %{0}, %{1}, etc.
		 */
		if (compare == 0) for (i = 0; i <= REQUEST_MAX_REGEX; i++) {
			char *r;

			free(request_data_get(request, request,
					      REQUEST_DATA_REGEX | i));

			/*
			 *	No %{i}, skip it.
			 *	We MAY have %{2} without %{1}.
			 */
			if (rxmatch[i].rm_so == -1) continue;
			
			/*
			 *	Copy substring into allocated buffer
			 */
			r = rad_malloc(rxmatch[i].rm_eo -rxmatch[i].rm_so + 1);
			memcpy(r, pleft + rxmatch[i].rm_so,
			       rxmatch[i].rm_eo - rxmatch[i].rm_so);
			r[rxmatch[i].rm_eo - rxmatch[i].rm_so] = '\0';

			request_data_add(request, request,
					 REQUEST_DATA_REGEX | i,
					 r, free);
		}
		result = (compare == 0);
	}
		break;
		
	case T_OP_REG_NE: {
		int compare;
		regex_t reg;
		regmatch_t rxmatch[REQUEST_MAX_REGEX + 1];
		
		/*
		 *	Include substring matches.
		 */
		compare = regcomp(&reg, pright, cflags);
		if (compare != 0) {
			if (debug_flag) {
				char errbuf[128];

				regerror(compare, &reg, errbuf, sizeof(errbuf));
				DEBUGE("Failed compiling regular expression: %s", errbuf);
			}
			return FALSE;
		}

		compare = regexec(&reg, pleft,
				  REQUEST_MAX_REGEX + 1,
				  rxmatch, 0);
		regfree(&reg);
		
		result = (compare != 0);
	}
		break;
#endif
		
	default:
		DEBUGE("Comparison operator %s is not supported",
		      fr_token_name(token));
		result = FALSE;
		break;
	}
	
	*presult = result;
	return TRUE;
}


int radius_evaluate_condition(REQUEST *request, int modreturn, int depth,
			      const char **ptr, int evaluate_it, int *presult)
{
	int found_condition = FALSE;
	int result = TRUE;
	int invert = FALSE;
	int evaluate_next_condition = evaluate_it;
	const char *p;
	const char *q, *start;
	FR_TOKEN token, lt, rt;
	char left[1024], right[1024], comp[4];
	const char *pleft, *pright;
	char  xleft[1024], xright[1024];
	int cflags = 0;
	
	if (!ptr || !*ptr || (depth >= 64)) {
		radlog(L_ERR, "Internal sanity check failed in evaluate condition");
		return FALSE;
	}

	/*
	 *	Horrible parser.
	 */
	p =  *ptr;
	while (*p) {
		while ((*p == ' ') || (*p == '\t')) p++;

		/*
		 *	! EXPR
		 */
		if (!found_condition && (*p == '!')) {
			/*
			 *	Don't change the results if we're not
			 *	evaluating the condition.
			 */
			if (evaluate_next_condition) {
				RDEBUG4(">>> INVERT");
				invert = TRUE;
			}
			p++;

			while ((*p == ' ') || (*p == '\t')) p++;
		}

		/*
		 *	( EXPR )
		 */
		if (!found_condition && (*p == '(')) {
			const char *end = p + 1;

			/*
			 *	Evaluate the condition, bailing out on
			 *	parse error.
			 */
			RDEBUG4(">>> RECURSING WITH ... %s", end);
			if (!radius_evaluate_condition(request, modreturn,
						       depth + 1, &end,
						       evaluate_next_condition,
						       &result)) {
				return FALSE;
			}

			if (invert) {
				if (evaluate_next_condition) {
					RDEBUG2("%.*s Converting !%s -> %s",
						depth, filler,
						(result != FALSE) ? "TRUE" : "FALSE",
						(result == FALSE) ? "TRUE" : "FALSE");
					result = (result == FALSE);
				}
				invert = FALSE;
			}

			/*
			 *	Start from the end of the previous
			 *	condition
			 */
			p = end;
			RDEBUG4(">>> AFTER RECURSION ... %s", end);

			while ((*p == ' ') || (*p == '\t')) p++;

			if (!*p) {
				radlog(L_ERR, "No closing brace");
				return FALSE;
			}

			if (*p == ')') p++; /* eat closing brace */
			found_condition = TRUE;

			while ((*p == ' ') || (*p == '\t')) p++;
		}

		/*
		 *	At EOL or closing brace, update && return.
		 */
		if (found_condition && (!*p || (*p == ')'))) break;

		/*
		 *	Now it's either:
		 *
		 *	WORD
		 *	WORD1 op WORD2
		 *	&& EXPR
		 *	|| EXPR
		 */
		if (found_condition) {
			/*
			 *	(A && B) means "evaluate B
			 *	only if A was true"
			 */
			if ((p[0] == '&') && (p[1] == '&')) {
				if (!result) evaluate_next_condition = FALSE;
				p += 2;
				found_condition = FALSE;
				continue; /* go back to the start */
			}

			/*
			 *	(A || B) means "evaluate B
			 *	only if A was false"
			 */
			if ((p[0] == '|') && (p[1] == '|')) {
				if (result) evaluate_next_condition = FALSE;
				p += 2;
				found_condition = FALSE;
				continue;
			}

			/*
			 *	It must be:
			 *
			 *	WORD
			 *	WORD1 op WORD2
			 */
		}

		if (found_condition) {
			radlog(L_ERR, "Consecutive conditions at %s", p);
			return FALSE;
		}

		RDEBUG4(">>> LOOKING AT %s", p);
		start = p;

		/*
		 *	Look for common errors.
		 */
		if ((p[0] == '%') && (p[1] == '{')) {
			radlog(L_ERR, "Bare %%{...} is invalid in condition at: %s", p);
			return FALSE;
		}

		/*
		 *	Look for WORD1 op WORD2
		 */
		lt = gettoken(&p, left, sizeof(left));
		if ((lt != T_BARE_WORD) &&
		    (lt != T_DOUBLE_QUOTED_STRING) &&
		    (lt != T_SINGLE_QUOTED_STRING) &&
		    (lt != T_BACK_QUOTED_STRING)) {
			radlog(L_ERR, "Expected string or numbers at: %s", p);
			return FALSE;
		}

		pleft = left;
		if (evaluate_next_condition) {
			pleft = expand_string(xleft, sizeof(xleft), request,
					      lt, left);
			if (!pleft) {
				radlog(L_ERR, "Failed expanding string at: %s",
				       left);
				return FALSE;
			}
		}

		/*
		 *	Peek ahead, to see if it's:
		 *
		 *	WORD
		 *
		 *	or something else, such as
		 *
		 *	WORD1 op WORD2
		 *	WORD )
		 *	WORD && EXPR
		 *	WORD || EXPR
		 */
		q = p;
		while ((*q == ' ') || (*q == '\t')) q++;

		/*
		 *	If the next thing is:
		 *
		 *	EOL
		 *	end of condition
		 *      &&
		 *	||
		 *
		 *	Then WORD is just a test for existence.
		 *	Remember that and skip ahead.
		 */
		if (!*q || (*q == ')') ||
		    ((q[0] == '&') && (q[1] == '&')) ||
		    ((q[0] == '|') && (q[1] == '|'))) {
			token = T_OP_CMP_TRUE;
			rt = T_OP_INVALID;
			pright = NULL;
			goto do_cmp;
		}

		/*
		 *	Otherwise, it's:
		 *
		 *	WORD1 op WORD2
		 */
		token = gettoken(&p, comp, sizeof(comp));
		if ((token < T_OP_NE) || (token > T_OP_CMP_EQ) ||
		    (token == T_OP_CMP_TRUE)) {
			radlog(L_ERR, "Expected comparison at: %s", comp);
			return FALSE;
		}
		
		/*
		 *	Look for common errors.
		 */
		if ((p[0] == '%') && (p[1] == '{')) {
			radlog(L_ERR, "Bare %%{...} is invalid in condition at: %s", p);
			return FALSE;
		}
		
		/*
		 *	Validate strings.
		 */
#ifdef HAVE_REGEX_H
		if ((token == T_OP_REG_EQ) ||
		    (token == T_OP_REG_NE)) {
			rt = getregex(&p, right, sizeof(right), &cflags);
			if (rt != T_DOUBLE_QUOTED_STRING) {
				radlog(L_ERR, "Expected regular expression at: %s", p);
				return FALSE;
			}
		} else
#endif
			rt = gettoken(&p, right, sizeof(right));

		if ((rt != T_BARE_WORD) &&
		    (rt != T_DOUBLE_QUOTED_STRING) &&
		    (rt != T_SINGLE_QUOTED_STRING) &&
		    (rt != T_BACK_QUOTED_STRING)) {
			radlog(L_ERR, "Expected string or numbers at: %s", p);
			return FALSE;
		}
		
		pright = right;
		if (evaluate_next_condition) {
			pright = expand_string(xright, sizeof(xright), request,
					       rt, right);
			if (!pright) {
				radlog(L_ERR, "Failed expanding string at: %s",
				       right);
				return FALSE;
			}
		}
		
		RDEBUG4(">>> %d:%s %d %d:%s",
		       lt, pleft, token, rt, pright);
		
	do_cmp:
		if (evaluate_next_condition) {
			/*
			 *	More parse errors.
			 */
			if (!radius_do_cmp(request, &result, lt, pleft, token,
					   rt, pright, cflags, modreturn)) {
				return FALSE;
			}
			RDEBUG4(">>> Comparison returned %d", result);

			if (invert) {
				RDEBUG4(">>> INVERTING result");
				result = (result == FALSE);
			}

			RDEBUG2("%.*s Evaluating %s(%.*s) -> %s",
			       depth, filler,
			       invert ? "!" : "", p - start, start,
			       (result != FALSE) ? "TRUE" : "FALSE");

			invert = FALSE;
			RDEBUG4(">>> GOT result %d", result);

			/*
			 *	Not evaluating it.  We may be just
			 *	parsing it.
			 */
		} else if (request) {
			RDEBUG2("%.*s Skipping %s(%.*s)",
			       depth, filler,
			       invert ? "!" : "", p - start, start);
		}

		found_condition = TRUE;
	} /* loop over the input condition */

	if (!found_condition) {
		radlog(L_ERR, "Syntax error.  Expected condition at %s", p);
		return FALSE;
	}

	RDEBUG4(">>> AT EOL -> %d", result);
	*ptr = p;
	if (evaluate_it) *presult = result;
	return TRUE;
}
#endif


/*
 *	The pairmove() function in src/lib/valuepair.c does all sorts of
 *	extra magic that we don't want here.
 *
 *	FIXME: integrate this with the code calling it, so that we
 *	only paircopy() those attributes that we're really going to
 *	use.
 */
void radius_pairmove(REQUEST *request, VALUE_PAIR **to, VALUE_PAIR *from)
{
	int i, j, count, from_count, to_count, tailto;
	VALUE_PAIR *vp, *next, **last;
	VALUE_PAIR **from_list, **to_list;
	int *edited = NULL;
	REQUEST *fixup = NULL;

	/*
	 *	Set up arrays for editing, to remove some of the
	 *	O(N^2) dependencies.  This also makes it easier to
	 *	insert and remove attributes.
	 *
	 *	It also means that the operators apply ONLY to the
	 *	attributes in the original list.  With the previous
	 *	implementation of pairmove(), adding two attributes
	 *	via "+=" and then "=" would mean that the second one
	 *	wasn't added, because of the existence of the first
	 *	one in the "to" list.  This implementation doesn't
	 *	have that bug.
	 *
	 *	Also, the previous implementation did NOT implement
	 *	"-=" correctly.  If two of the same attributes existed
	 *	in the "to" list, and you tried to subtract something
	 *	matching the *second* value, then the pairdelete()
	 *	function was called, and the *all* attributes of that
	 *	number were deleted.  With this implementation, only
	 *	the matching attributes are deleted.
	 */
	count = 0;
	for (vp = from; vp != NULL; vp = vp->next) count++;
	from_list = rad_malloc(sizeof(*from_list) * count);

	for (vp = *to; vp != NULL; vp = vp->next) count++;
	to_list = rad_malloc(sizeof(*to_list) * count);

	/*
	 *	Move the lists to the arrays, and break the list
	 *	chains.
	 */
	from_count = 0;
	for (vp = from; vp != NULL; vp = next) {
		next = vp->next;
		from_list[from_count++] = vp;
		vp->next = NULL;
	}

	to_count = 0;
	for (vp = *to; vp != NULL; vp = next) {
		next = vp->next;
		to_list[to_count++] = vp;
		vp->next = NULL;
	}
	tailto = to_count;
	edited = rad_malloc(sizeof(*edited) * to_count);
	memset(edited, 0, sizeof(*edited) * to_count);

	RDEBUG4("::: FROM %d TO %d MAX %d", from_count, to_count, count);

	/*
	 *	Now that we have the lists initialized, start working
	 *	over them.
	 */
	for (i = 0; i < from_count; i++) {
		int found;

		RDEBUG4("::: Examining %s", from_list[i]->da->name);

		/*
		 *	Attribute should be appended, OR the "to" list
		 *	is empty, and we're supposed to replace or
		 *	"add if not existing".
		 */
		if (from_list[i]->op == T_OP_ADD) goto append;

		found = FALSE;
		for (j = 0; j < to_count; j++) {
			if (edited[j] || !to_list[j] || !from_list[i]) continue;

			/*
			 *	Attributes aren't the same, skip them.
			 */
			if (from_list[i]->da != to_list[j]->da) {
				continue;
			}

			/*
			 *	We don't use a "switch" statement here
			 *	because we want to break out of the
			 *	"for" loop over 'j' in most cases.
			 */

			/*
			 *	Over-write the FIRST instance of the
			 *	matching attribute name.  We free the
			 *	one in the "to" list, and move over
			 *	the one in the "from" list.
			 */
			if (from_list[i]->op == T_OP_SET) {
				RDEBUG4("::: OVERWRITING %s FROM %d TO %d",
				       to_list[j]->da->name, i, j);
				pairfree(&to_list[j]);
				to_list[j] = from_list[i];
				from_list[i] = NULL;
				edited[j] = TRUE;
				break;
			}

			/*
			 *	Add the attribute only if it does not
			 *	exist... but it exists, so we stop
			 *	looking.
			 */
			if (from_list[i]->op == T_OP_EQ) {
				found = TRUE;
				break;
			}

			/*
			 *	Delete every attribute, independent
			 *	of its value.
			 */
			if (from_list[i]->op == T_OP_CMP_FALSE) {
				goto delete;
			}

			/*
			 *	Delete all matching attributes from
			 *	"to"
			 */
			if ((from_list[i]->op == T_OP_SUB) ||
			    (from_list[i]->op == T_OP_CMP_EQ) ||
			    (from_list[i]->op == T_OP_LE) ||
			    (from_list[i]->op == T_OP_GE)) {
				int rcode;
				int old_op = from_list[i]->op;

				/*
				 *	Check for equality.
				 */
				from_list[i]->op = T_OP_CMP_EQ;

				/*
				 *	If equal, delete the one in
				 *	the "to" list.
				 */
				rcode = radius_compare_vps(NULL, from_list[i],
							   to_list[j]);
				/*
				 *	We may want to do more
				 *	subtractions, so we re-set the
				 *	operator back to it's original
				 *	value.
				 */
				from_list[i]->op = old_op;

				switch (old_op) {
				case T_OP_CMP_EQ:
					if (rcode != 0) goto delete;
					break;

				case T_OP_SUB:
					if (rcode == 0) {
					delete:
						RDEBUG4("::: DELETING %s FROM %d TO %d",
						       from_list[i]->da->name, i, j);
						pairfree(&to_list[j]);
						to_list[j] = NULL;
					}
					break;

					/*
					 *	Enforce <=.  If it's
					 *	>, replace it.
					 */
				case T_OP_LE:
					if (rcode > 0) {
						RDEBUG4("::: REPLACING %s FROM %d TO %d",
						       from_list[i]->da->name, i, j);
						pairfree(&to_list[j]);
						to_list[j] = from_list[i];
						from_list[i] = NULL;
						edited[j] = TRUE;
					}
					break;

				case T_OP_GE:
					if (rcode < 0) {
						RDEBUG4("::: REPLACING %s FROM %d TO %d",
						       from_list[i]->da->name, i, j);
						pairfree(&to_list[j]);
						to_list[j] = from_list[i];
						from_list[i] = NULL;
						edited[j] = TRUE;
					}
					break;
				}

				continue;
			}

			rad_assert(0 == 1); /* panic! */
		}

		/*
		 *	We were asked to add it if it didn't exist,
		 *	and it doesn't exist.  Move it over to the
		 *	tail of the "to" list, UNLESS it was already
		 *	moved by another operator.
		 */
		if (!found && from_list[i]) {
			if ((from_list[i]->op == T_OP_EQ) ||
			    (from_list[i]->op == T_OP_LE) ||
			    (from_list[i]->op == T_OP_GE) ||
			    (from_list[i]->op == T_OP_SET)) {
			append:
				RDEBUG4("::: APPENDING %s FROM %d TO %d",
				       from_list[i]->da->name, i, tailto);
				to_list[tailto++] = from_list[i];
				from_list[i] = NULL;
			}
		}
	}

	/*
	 *	Delete attributes in the "from" list.
	 */
	for (i = 0; i < from_count; i++) {
		if (!from_list[i]) continue;

		pairfree(&from_list[i]);
	}
	free(from_list);

	RDEBUG4("::: TO in %d out %d", to_count, tailto);

	/*
	 *	Re-chain the "to" list.
	 */
	*to = NULL;
	last = to;

	if (to == &request->packet->vps) {
		fixup = request;
	} else if (request->parent && (to == &request->parent->packet->vps)) {
		fixup = request->parent;
	}
	if (fixup) {
		fixup->username = NULL;
		fixup->password = NULL;
	}

	for (i = 0; i < tailto; i++) {
		if (!to_list[i]) continue;
		
		vp = to_list[i];
		RDEBUG4("::: to[%d] = %s", i, vp->da->name);

		/*
		 *	Mash the operator to a simple '='.  The
		 *	operators in the "to" list aren't used for
		 *	anything.  BUT they're used in the "detail"
		 *	file and debug output, where we don't want to
		 *	see the operators.
		 */
		vp->op = T_OP_EQ;

		/*
		 *	Fix dumb cache issues
		 */
		if (fixup && !vp->da->vendor) {
			if ((vp->da->attr == PW_USER_NAME) &&
			    !fixup->username) {
				fixup->username = vp;

			} else if (vp->da->attr == PW_STRIPPED_USER_NAME) {
				fixup->username = vp;

			} else if (vp->da->attr == PW_USER_PASSWORD) {
				fixup->password = vp;
			}
		}

		*last = vp;
		last = &(*last)->next;
		(void) talloc_steal(request, vp);
	}

	rad_assert(request != NULL);
	rad_assert(request->packet != NULL);

	free(to_list);
	free(edited);
}
