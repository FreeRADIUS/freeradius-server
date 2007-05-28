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

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>

static int all_digits(const char *string)
{
	const char *p = string;

	if (*p == '-') p++;

	while (isdigit((int) *p)) p++;

	return (*p == '\0');
}

#ifndef DEBUG4
#define DEBUG4  if (debug_flag > 4)log_debug
#endif

static const char *filler = "????????????????????????????????????????????????????????????????";

static const char *expand_string(char *buffer, size_t sizeof_buffer,
				 REQUEST *request,
				 LRAD_TOKEN value_type, const char *value)
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

		radius_xlat(buffer, sizeof_buffer, value, request, NULL);
		return buffer;
	}

	return NULL;
}

int radius_evaluate_condition(REQUEST *request, int depth,
			      const char **ptr, int evaluate_it, int *presult)
{
	int found_condition = FALSE;
	int result = TRUE;
	int invert = FALSE;
	int evaluate_next_condition = evaluate_it;
	const char *p = *ptr;
	const char *q;
	LRAD_TOKEN token, lt, rt;
	char left[1024], right[1024], comp[4];
	char *pleft, *pright;
	char  xleft[1024], xright[1024];
	int lint, rint;

	if (!ptr || !*ptr || (depth >= 64)) {
		radlog(L_ERR, "Internal sanity check failed in evaluate condition");
		return FALSE;
	}

	while (*p) {
		while ((*p == ' ') || (*p == '\t')) p++;

		if (*p == '!') {
			DEBUG4(">>> INVERT");
			invert = TRUE;
			p++;
		}

		/*
		 *	It's a subcondition.
		 */
		if (*p == '(') {
			const char *end = p + 1;

			/*
			 *	Evaluate the condition, bailing out on
			 *	parse error.
			 */
			DEBUG4(">>> CALLING EVALUATE %s", end);
			if (!radius_evaluate_condition(request, depth + 1,
						       &end,
						       evaluate_next_condition,
						       &result)) {
				return FALSE;
			}

			if (invert && evaluate_next_condition) {
				DEBUG2("%.*s Converting !%s -> %s",
				       depth, filler,
				       (result != FALSE) ? "TRUE" : "FALSE",
				       (result == FALSE) ? "TRUE" : "FALSE");

				       
				result = (result == FALSE);
				invert = FALSE;
			}

			/*
			 *	Start from the end of the previous
			 *	condition
			 */
			p = end;
			DEBUG4(">>> EVALUATE RETURNED ::%s::", end);
			
			if (*p != ')') {
				radlog(L_ERR, "Parse error in condition at: %s", p);
				return FALSE;
			}
			p++;	/* skip it */
			found_condition = TRUE;
			
			while ((*p == ' ') || (*p == '\t')) p++;

			/*
			 *	EOL.  It's OK.
			 */
			if (!*p) {
				DEBUG4(">>> AT EOL");
				*ptr = p;
				*presult = result;
				return TRUE;
				
				/*
				 *	(A && B) means "evaluate B
				 *	only if A was true"
				 */
			} else if ((p[0] == '&') && (p[1] == '&')) {
				if (result == TRUE) {
					evaluate_next_condition = evaluate_it;
				} else {
					evaluate_next_condition = FALSE;
				}
				p += 2;
				
				/*
				 *	(A || B) means "evaluate B
				 *	only if A was false"
				 */
			} else if ((p[0] == '|') && (p[1] == '|')) {
				if (result == FALSE) {
					evaluate_next_condition = evaluate_it;
				} else {
					evaluate_next_condition = FALSE;
				}
				p += 2;

			} else if (*p == ')') {
				DEBUG4(">>> CLOSING BRACE");
				*ptr = p;
				*presult = result;
				return TRUE;

			} else {
				/*
				 *	Parse error
				 */
				radlog(L_ERR, "Unexpected trailing text at: %s", p);
				return FALSE;
			}
		} /* else it wasn't an opening brace */

		while ((*p == ' ') || (*p == '\t')) p++;

		/*
		 *	More conditions, keep going.
		 */
		if ((*p == '(') ||
		    ((p[0] == '!') && (p[1] == '('))) continue;

		DEBUG4(">>> LOOKING AT %s", p);

		/*
		 *	Look for common errors.
		 */
		if ((p[0] == '%') && (p[1] == '{')) {
			radlog(L_ERR, "Bare %%{...} is invalid in condition at: %s", p);
			return FALSE;
		}

		/*
		 *	Look for word == value
		 */
		lt = gettoken(&p, left, sizeof(left));
		if ((lt != T_BARE_WORD) &&
		    (lt != T_DOUBLE_QUOTED_STRING) &&
		    (lt != T_SINGLE_QUOTED_STRING) &&
		    (lt != T_BACK_QUOTED_STRING)) {
			radlog(L_ERR, "Expected string or numbers at: %s", left);
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
		 *	FIXME: lt = word, double-quoted string, or
		 *	single-quoted-string
		 */

		/*
		 *	Peek ahead.  Maybe it's just a check for
		 *	existence.  If so, there shouldn't be anything
		 *	else.
		 */
		q = p;
		while ((*q == ' ') || (*q == '\t')) q++;

		/*
		 *	End of condition, 
		 */
		if (!*q || (*q == ')')) {
			/*
			 *	Check for truth or falsehood.
			 */
			if (all_digits(pleft)) {
				lint = atoi(pleft);
				result = (lint != 0);
			} else {
				result = (*pleft != '\0');
			}

			if (evaluate_next_condition) {
				DEBUG2("%.*s Evaluating %s\"%s\" -> %s",
				       depth, filler,
				       invert ? "!" : "", pleft,
				       (result != FALSE) ? "TRUE" : "FALSE");

			} else if (request) {
				DEBUG2("%.*s Skipping %s\"%s\"",
				       depth, filler,
				       invert ? "!" : "", pleft);
			}

			DEBUG4(">>> I%d %d:%s", invert,
			       lt, left);
			goto end_of_condition;
		}

		/*
		 *	Else it's a full "foo == bar" thingy.
		 */
		token = gettoken(&p, comp, sizeof(comp));
		if ((token < T_OP_NE) || (token > T_OP_CMP_EQ) ||
		    (token == T_OP_CMP_TRUE) ||
		    (token == T_OP_CMP_FALSE)) {
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
		rt = gettoken(&p, right, sizeof(right));
		if ((rt != T_BARE_WORD) &&
		    (rt != T_DOUBLE_QUOTED_STRING) &&
		    (rt != T_SINGLE_QUOTED_STRING) &&
		    (rt != T_BACK_QUOTED_STRING)) {
			radlog(L_ERR, "Expected string or numbers at: %s", right);
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
		
		DEBUG4(">>> %d:%s %d %d:%s",
		       lt, pleft, token, rt, pright);
		
		if (evaluate_next_condition) {
			/*
			 *	Mangle operator && conditions to
			 *	simplify the following code.
			 */
			switch (token) {
			case T_OP_NE:
				invert = (invert == FALSE);
				token = T_OP_CMP_EQ;
				break;
				
			case T_OP_GE:
			case T_OP_GT:
			case T_OP_LE:
			case T_OP_LT:
				if (!all_digits(pleft)) {
					radlog(L_ERR, "Left field is not a number at: %s", pleft);
					return FALSE;
				}
				if (!all_digits(pright)) {
					radlog(L_ERR, "Right field is not a number at: %s", pright);
					return FALSE;
				}
				lint = atoi(pleft);
				rint = atoi(pright);
				break;
				
			default:
				break;
			}

			switch (token) {
			case T_OP_CMP_EQ:
				result = (strcmp(pleft, pright) == 0);
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

			default:
				DEBUG4(">>> NOT IMPLEMENTED %d", token);
				break;
			}

			DEBUG2("%.*s Evaluating %s(\"%s\" %s \"%s\") -> %s",
			       depth, filler,
			       invert ? "!" : "", pleft, comp, pright,
			       (result != FALSE) ? "TRUE" : "FALSE");

			DEBUG4(">>> GOT result %d", result);

			/*
			 *	Not evaluating it.  We may be just
			 *	parsing it.
			 */
		} else if (request) {
			DEBUG2("%.*s Skipping %s(\"%s\" %s \"%s\")",
			       depth, filler,
			       invert ? "!" : "", pleft, comp, pright);
		}

		end_of_condition:
		if (invert) {
			DEBUG4(">>> INVERTING result");
			result = (result == FALSE);
			invert = FALSE;
		}

		/*
		 *	Don't evaluate it.
		 */
		DEBUG4(">>> EVALUATE %d ::%s::",
			evaluate_next_condition, p);

		while ((*p == ' ') || (*p == '\t')) p++;

		/*
		 *	Closing brace or EOL, return.
		 */
		if ((*p == ')') || !*p) {
			DEBUG4(">>> AT EOL2a");
			*ptr = p;
			*presult = result;
			return TRUE;
		}
	} /* loop over the input condition */

	DEBUG4(">>> AT EOL2b");
	*ptr = p;
	*presult = result;
	return TRUE;
}

/*
 *	Copied shamelessly from conffile.c, to simplify the API for
 *	now...
 */
typedef enum conf_type {
	CONF_ITEM_INVALID = 0,
	CONF_ITEM_PAIR,
	CONF_ITEM_SECTION,
	CONF_ITEM_DATA
} CONF_ITEM_TYPE;

struct conf_item {
	struct conf_item *next;
	struct conf_part *parent;
	int lineno;
	CONF_ITEM_TYPE type;
};
struct conf_pair {
	CONF_ITEM item;
	char *attr;
	char *value;
	LRAD_TOKEN operator;
	LRAD_TOKEN value_type;
};


/*
 *	Add attributes to a list.
 */
int radius_update_attrlist(REQUEST *request, CONF_SECTION *cs,
			   const char *name)
{
	CONF_ITEM *ci;
	VALUE_PAIR *head, **tail;
	VALUE_PAIR **vps = NULL;

	if (!request || !cs) return RLM_MODULE_INVALID;

	if (strcmp(name, "request") == 0) {
		vps = &request->packet->vps;

	} else if (strcmp(name, "reply") == 0) {
		vps = &request->reply->vps;

	} else if (strcmp(name, "proxy-request") == 0) {
		if (request->proxy) vps = &request->proxy->vps;

	} else if (strcmp(name, "proxy-reply") == 0) {
		if (request->proxy_reply) vps = &request->proxy_reply->vps;

	} else if (strcmp(name, "config") == 0) {
		vps = &request->config_items;

	} else {
		return RLM_MODULE_INVALID;
	}

	if (!vps) return RLM_MODULE_NOOP; /* didn't update the list */

	head = NULL;
	tail = &head;

	for (ci=cf_item_find_next(cs, NULL);
	     ci != NULL;
	     ci=cf_item_find_next(cs, ci)) {
		const char *value;
		CONF_PAIR *cp;
		VALUE_PAIR *vp;
		char buffer[2048];

		if (cf_item_is_section(ci)) {
			pairfree(&head);
			return RLM_MODULE_INVALID;
		}

		cp = cf_itemtopair(ci);

		value = expand_string(buffer, sizeof(buffer), request,
				      cp->value_type, cp->value);
		if (!value) {
			pairfree(&head);
			return RLM_MODULE_INVALID;
		}

		vp = pairmake(cp->attr, value, cp->operator);
		if (!vp) {
			pairfree(&head);
			return RLM_MODULE_FAIL;
		}

		*tail = vp;
		tail = &vp->next;
	}

	if (!head) return RLM_MODULE_NOOP;

	pairmove(vps, &head);
	pairfree(&head);

	return RLM_MODULE_UPDATED;
}


