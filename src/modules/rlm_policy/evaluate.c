/*
 * evaluate.c		Evaluate a policy language
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
 * Copyright 2004  Alan DeKok <aland@ox.org>
 * Copyright 2006  The FreeRADIUS server project
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include "rlm_policy.h"

#ifdef HAVE_REGEX_H
#include <regex.h>
#endif

#define debug_evaluate if (0) printf

/*
 *	Print stuff we've parsed
 */
static void policy_print(const policy_item_t *item, int indent)
{
	if (!item) {
		if (indent) fprintf(fr_log_fp, "%*s", indent, " ");
		fprintf(fr_log_fp, "[NULL]\n");
		return;
	}

	while (item) {
		switch (item->type) {
		case POLICY_TYPE_BAD:
			if (indent) fprintf(fr_log_fp, "%*s", indent, " ");
			fprintf(fr_log_fp, "[BAD STATEMENT]");
			break;

		case POLICY_TYPE_PRINT:
			if (indent) fprintf(fr_log_fp, "%*s", indent, " ");
			{
				const policy_print_t *this;

				this = (const policy_print_t *) item;

				if (this->rhs_type == POLICY_LEX_BARE_WORD) {
					fprintf(fr_log_fp, "print %s\n", this->rhs);
				} else {
					fprintf(fr_log_fp, "print \"%s\"\n", this->rhs);
				}
			}
			break;

		case POLICY_TYPE_ASSIGNMENT:
			{
				const policy_assignment_t *assign;

				assign = (const policy_assignment_t *) item;
				if (indent) fprintf(fr_log_fp, "%*s", indent, " ");

				fprintf(fr_log_fp, "\t%s %s ", assign->lhs,
				       fr_int2str(rlm_policy_tokens,
						    assign->assign, "?"));
				if (assign->rhs_type == POLICY_LEX_BARE_WORD) {
					fprintf(fr_log_fp, "%s\n", assign->rhs);
				} else {
					/*
					 *	FIXME: escape "
					 */
					fprintf(fr_log_fp, "\"%s\"\n", assign->rhs);
				}
			}
			break;

		case POLICY_TYPE_CONDITIONAL: /* no indentation here */
			{
				const policy_condition_t *condition;

				condition = (const policy_condition_t *) item;

				fprintf(fr_log_fp, "(");

				if (condition->sense) {
					fprintf(fr_log_fp, "!");
				}

				/*
				 *	Nested conditions.
				 */
				if (condition->compare == POLICY_LEX_L_BRACKET) {
					policy_print(condition->child, indent);
					fprintf(fr_log_fp, ")");
					break;
				}

				if (condition->compare == POLICY_LEX_L_NOT) {
					fprintf(fr_log_fp, "!");
					policy_print(condition->child, indent);
					fprintf(fr_log_fp, ")");
					break;
				}

				if (condition->compare == POLICY_LEX_CMP_TRUE) {
					fprintf(fr_log_fp, "%s)", condition->lhs);
					break;
				}

				if (condition->lhs_type == POLICY_LEX_FUNCTION) {
					fprintf(fr_log_fp, "%s()", condition->lhs);
				} else {
					/*
					 *	FIXME: escape ",
					 *	and move all of this logic
					 *	to a function.
					 */
					fprintf(fr_log_fp, "\"%s\"", condition->lhs);
				}

				/*
				 *	We always print this condition.
				 */
				fprintf(fr_log_fp, " %s ", fr_int2str(rlm_policy_tokens,
							    condition->compare,
							    "?"));
				if (condition->rhs_type == POLICY_LEX_BARE_WORD) {
					fprintf(fr_log_fp, "%s", condition->rhs);
				} else {
					/*
					 *	FIXME: escape ",
					 *	and move all of this logic
					 *	to a function.
					 */
					fprintf(fr_log_fp, "\"%s\"", condition->rhs);
				}
				fprintf(fr_log_fp, ")");

				if ((condition->child_condition != POLICY_LEX_BAD) &&
				    (condition->child_condition != POLICY_LEX_BARE_WORD)) {
					fprintf(fr_log_fp, " %s ", fr_int2str(rlm_policy_tokens, condition->child_condition, "?"));
					policy_print(condition->child, indent);
				}
			}
			break;

		case POLICY_TYPE_IF:
			{
				const policy_if_t *statement;

				statement = (const policy_if_t *) item;

				if (indent) fprintf(fr_log_fp, "%*s", indent, " ");
				fprintf(fr_log_fp, "if ");
				policy_print(statement->condition, indent);
				fprintf(fr_log_fp, " {\n");
				policy_print(statement->if_true, indent + 1);
				if (indent) fprintf(fr_log_fp, "%*s", indent, " ");
				if (statement->if_false) {
					fprintf(fr_log_fp, "} else ");
					if (statement->if_false->type == POLICY_TYPE_ASSIGNMENT) {
						fprintf(fr_log_fp, " { ");
						policy_print(statement->if_false, indent + 1);
						if (indent) fprintf(fr_log_fp, "%*s", indent, " ");
						fprintf(fr_log_fp, " }");
					} else {
						policy_print(statement->if_false, indent + 1);
					}
				} else {
					fprintf(fr_log_fp, "}\n");
				}
			}
			break;

		case POLICY_TYPE_ATTRIBUTE_LIST:
			{
				const policy_attributes_t *this;

				this = (const policy_attributes_t *) item;

				if (indent) fprintf(fr_log_fp, "%*s", indent, " ");
				fprintf(fr_log_fp, "%s %s {\n",
				       fr_int2str(policy_reserved_words,
						    this->where, "?"),
				       fr_int2str(rlm_policy_tokens,
						    this->how, "?"));
				policy_print(this->attributes, indent + 1);
				if (indent) fprintf(fr_log_fp, "%*s", indent, " ");
				fprintf(fr_log_fp, "}\n");
			}
			break;

		case POLICY_TYPE_NAMED_POLICY:
			{
				const policy_named_t *this;

				this = (const policy_named_t *) item;
				if (indent) fprintf(fr_log_fp, "%*s", indent, " ");
				fprintf(fr_log_fp, "policy %s {\n", this->name);
				policy_print(this->policy, indent + 1);
				if (indent) fprintf(fr_log_fp, "%*s", indent, " ");
				fprintf(fr_log_fp, "}\n");
			}
			break;

		case POLICY_TYPE_CALL:
			{
				const policy_call_t *this;

				this = (const policy_call_t *) item;
				if (indent) fprintf(fr_log_fp, "%*s", indent, " ");
				fprintf(fr_log_fp, "call %s\n", this->name);
			}
			break;

		case POLICY_TYPE_RETURN:
			{
				const policy_return_t *this;

				this = (const policy_return_t *) item;
				if (indent) fprintf(fr_log_fp, "%*s", indent, " ");
				fprintf(fr_log_fp, "return %s\n",
				       fr_int2str(policy_return_codes,
						    this->rcode, "???"));
			}
			break;

		case POLICY_TYPE_MODULE:
			{
				const policy_module_t *this;

				this = (const policy_module_t *) item;
				if (indent) fprintf(fr_log_fp, "%*s", indent, " ");
				fprintf(fr_log_fp, "module %s <stuff>\n",
				       fr_int2str(policy_component_names,
						    this->component, "???"));
			}
			break;

		default:
			if (indent) fprintf(fr_log_fp, "%*s", indent, " ");
			fprintf(fr_log_fp, "[HUH?]\n");
			break;

		}

		item = item->next;
	}
}


void rlm_policy_print(const policy_item_t *item)
{
	if (!fr_log_fp) return;

	fprintf(fr_log_fp, "# rlm_policy \n");
	policy_print(item, 0);
}

/*
 *	Internal stack of things to do.  This lets us have function
 *	calls...
 *
 *	Yes, we should learn lex, yacc, etc.
 */
#define POLICY_MAX_STACK 16
typedef struct policy_state_t {
	rlm_policy_t	*inst;
	REQUEST		*request; /* so it's not passed on the C stack */
	int		rcode;	/* for functions, etc. */
	int		component; /* for calling other modules */
	int		depth;
	const policy_item_t *stack[POLICY_MAX_STACK];
} policy_state_t;


static int policy_evaluate_name(policy_state_t *state, const char *name);

/*
 *	Push an item onto the state.
 */
static int policy_stack_push(policy_state_t *state, const policy_item_t *item)
{
	rad_assert(state->depth >= 0);

	/*
	 *	Asked to push nothing.  Don't push it.
	 */
	if (!item) return 1;

	/*
	 *	State is full.  Die.
	 */
	if (state->depth >= POLICY_MAX_STACK) {
		return 0;
	}

	/*
	 *	Walk back up the stack, looking for previous ocurrances
	 *	of this name.  If found, we have infinite recursion,
	 *	which we stop dead in the water!
	 *
	 *	This isn't strictly necessary right now, as we look up
	 *	policies by name when they're first referenced.  This
	 *	means that ALL references are backwards (to the start
	 *	of the file), which means that there are no circular
	 *	references.
	 */
	if (item->type == POLICY_TYPE_NAMED_POLICY) {
		int i;

		for (i = 0; i < state->depth; i++) {
			/*
			 *	Check for circular references, by seeing
			 *	if the function is already on the stack.
			 *
			 *	Hmmm... do we want to do this for any type?
			 */
			if (state->stack[i] == item) {
				debug_evaluate("Circular call to policy %s\n",
					       ((const policy_named_t *) item)->name);
				return 0;
			}
		}
	}

	debug_evaluate("push %d %p\n", state->depth, item);

	state->stack[state->depth] = item;
	state->depth++;		/* points to unused entry */

	return 1;
}


/*
 *	Pop an item from the state.
 */
static int policy_stack_pop(policy_state_t *state, const policy_item_t **item)
{
	rad_assert(item != NULL);
	rad_assert(state->depth >= 0);

 redo:
	if (state->depth == 0) {
		*item = NULL;
		return 0;
	}

	*item = state->stack[state->depth - 1];

	/*
	 *	Named policies are on the stack for catching recursion.
	 */
	if ((*item)->type == POLICY_TYPE_NAMED_POLICY) {
		state->depth--;
		goto redo;
	}

	/*
	 *	Process the whole item list.
	 */
	if ((*item)->next) {
		state->stack[state->depth - 1] = (*item)->next;
		debug_evaluate("pop/push %d %p\n", state->depth - 1, *item);
	} else {
		state->depth--;		/* points to unused entry */
		debug_evaluate("pop %d %p\n", state->depth, *item);
	}

	return 1;
}


/*
 *	Evaluate a print statement
 */
static int evaluate_print(policy_state_t *state, const policy_item_t *item)
{
	const policy_print_t *this;

	if (!fr_log_fp) return 1;

	this = (const policy_print_t *) item;

	if (this->rhs_type == POLICY_LEX_BARE_WORD) {
		fprintf(fr_log_fp, "%s\n", this->rhs);
	} else {
		char buffer[1024];

		radius_xlat(buffer, sizeof(buffer), this->rhs,
			    state->request, NULL, NULL);
		fprintf(fr_log_fp, "%s", buffer);
		if (!strchr(buffer, '\n')) fprintf(fr_log_fp, "\n");
	}

	/*
	 *	Doesn't change state->rcode
	 */

	return 1;
}

/*
 *	Return a VALUE_PAIR, given an attribute name.
 *
 *	FIXME: Have it return the N'th one, too, like
 *	doc/variables.txt?
 *
 *	The amount of duplicated code is getting annoying...
 */
static VALUE_PAIR *find_vp(REQUEST *request, const char *name)
{
	const char *p;
	const DICT_ATTR *dattr;
	VALUE_PAIR *vps;

	p = name;
	vps = request->packet->vps;;

	/*
	 *	FIXME: use names from reserved word list?
	 */
	if (strncasecmp(name, "request:", 8) == 0) {
		p += 8;
	} else if (strncasecmp(name, "reply:", 6) == 0) {
		p += 6;
		vps = request->reply->vps;
#ifdef WITH_PROXY
	} else if (strncasecmp(name, "proxy-request:", 14) == 0) {
		p += 14;
		if (request->proxy) {
			vps = request->proxy->vps;
		}
	} else if (strncasecmp(name, "proxy-reply:", 12) == 0) {
		p += 12;
		if (request->proxy_reply) {
			vps = request->proxy_reply->vps;
		}
#endif
	} else if (strncasecmp(name, "control:", 8) == 0) {
		p += 8;
		vps = request->config_items;
	} /* else it must be a bare attribute name */

	if (!vps) {
		return NULL;
	}

	dattr = dict_attrbyname(p);
	if (!dattr) {
		fprintf(stderr, "No such attribute %s\n", p);
		return NULL;	/* no such attribute */
	}

	return pairfind(vps, dattr->attr, dattr->vendor, TAG_ANY);
}


/*
 *	Evaluate an assignment
 *
 *	Not really used much...
 */
static int evaluate_assignment(UNUSED policy_state_t *state, const policy_item_t *item)
{
	const policy_assignment_t *this;
#if 0
	const DICT_ATTR *dattr;
#endif

	this = (const policy_assignment_t *) item;

	rad_assert(this->lhs != NULL);
	rad_assert(this->rhs != NULL);

#if 0
	dattr = dict_attrbyname(this->lhs);
	if (!dattr) {
		fprintf(stderr, "HUH?\n");
		return 0;
	}
#endif

	return 1;
}


/*
 *	Evaluate a condition
 */
static int evaluate_condition(policy_state_t *state, const policy_item_t *item)
{
	int rcode;
	const policy_condition_t *this;
	VALUE_PAIR *vp = NULL;
	const char *data = NULL;
	int compare;
#ifdef HAVE_REGEX_H
	regex_t reg;
#endif
	char buffer[256];
	char lhs_buffer[2048];

	this = (const policy_condition_t *) item;

 redo:
	/*
	 *	FIXME: Don't always do this...
	 */
	if (this->compare != POLICY_LEX_L_BRACKET) {
		if (this->lhs_type == POLICY_LEX_FUNCTION) {
			/*
			 *	We can't call evaluate_call here,
			 *	because that just pushes stuff onto
			 *	the stack, and we want to actually
			 *	evaluate all of it...
			 */
			rcode = policy_evaluate_name(state, this->lhs);
			data = fr_int2str(policy_return_codes, rcode, "???");
			strlcpy(lhs_buffer, data, sizeof(lhs_buffer)); /* FIXME: yuck */
		} else if (this->lhs_type == POLICY_LEX_DOUBLE_QUOTED_STRING) {
			if (radius_xlat(lhs_buffer, sizeof(lhs_buffer), this->lhs,
					state->request, NULL, NULL) > 0) {
				data = lhs_buffer;
			}
		}
	}

	switch (this->compare) {
	case POLICY_LEX_L_BRACKET: /* nested brackets are a special case */
		rcode = evaluate_condition(state, this->child);
		break;

	case POLICY_LEX_L_NOT:
		rcode = evaluate_condition(state, this->child);
		rcode = (rcode == FALSE); /* reverse sense of test */
		break;

	case POLICY_LEX_CMP_FALSE: /* non-existence */
		if (this->lhs_type == POLICY_LEX_BARE_WORD) {
			vp = find_vp(state->request, this->lhs);
			rcode = (vp == NULL);
		} else {
			rcode = (data == NULL);
		}
		break;

	case POLICY_LEX_CMP_TRUE: /* existence */
		if (this->lhs_type == POLICY_LEX_BARE_WORD) {
			vp = find_vp(state->request, this->lhs);
			rcode = (vp != NULL);
		} else {
			rcode = (data != NULL);
		}
		break;

	default:		/* process other comparisons */
		if ((this->compare != POLICY_LEX_CMP_EQUALS) &&
#ifdef HAVE_REGEX_H
		    (this->compare != POLICY_LEX_RX_EQUALS) &&
		    (this->compare != POLICY_LEX_RX_NOT_EQUALS) &&
#endif
		    (this->compare != POLICY_LEX_LT) &&
		    (this->compare != POLICY_LEX_GT) &&
		    (this->compare != POLICY_LEX_LE) &&
		    (this->compare != POLICY_LEX_GE) &&
		    (this->compare != POLICY_LEX_CMP_NOT_EQUALS)) {
			fprintf(stderr, "%d: bad comparison\n",
				this->item.lineno);
			return FALSE;
		}

		if (this->lhs_type == POLICY_LEX_BARE_WORD) {
			VALUE_PAIR *myvp;

			vp = find_vp(state->request, this->lhs);

			/*
			 *	A op B is FALSE if A doesn't
			 *	exist.
			 */
			if (!vp) {
				rcode = FALSE;
				break;
			}

			/*
			 *	FIXME: Move sanity checks to
			 *	post-parse code, so we don't do
			 *	it on every packet.
			 */
			vp_prints_value(buffer, sizeof(buffer), vp, 0);
			myvp = pairmake(vp->name, this->rhs, T_OP_EQ);
			if (!myvp) return FALSE; /* memory failure */
			data = buffer;

			/*
			 *	FIXME: What to do about comparisons
			 *	where vp doesn't exist?  Right now,
			 *	"simplepaircmp" returns -1, which is
			 *	probably a bad idea.  it should
			 *	instead take an operator, a pointer to
			 *	the comparison result, and return
			 *	"true/false" for "comparions
			 *	succeeded/failed", which are different
			 *	error codes than "comparison is less
			 *	than, equal to, or greater than zero".
			 */
			compare = radius_callback_compare(state->request,
							  vp, myvp, NULL, NULL);
			pairfree(&myvp);

		} else {
			/*
			 *	FIXME: Do something for RHS type?
			 */
			fr_printf_log("CMP %s %s\n", lhs_buffer, this->rhs);
			compare = strcmp(lhs_buffer, this->rhs);
		}

		debug_evaluate("CONDITION COMPARE %d\n", compare);

		switch (this->compare) {
		case POLICY_LEX_CMP_EQUALS:
			rcode = (compare == 0);
			break;

		case POLICY_LEX_CMP_NOT_EQUALS:
			rcode = (compare != 0);
			break;

		case POLICY_LEX_LT:
			rcode = (compare < 0);
			break;

		case POLICY_LEX_GT:
			rcode = (compare > 0);
			break;

		case POLICY_LEX_LE:
			rcode =(compare <= 0);
			break;

		case POLICY_LEX_GE:
			rcode = (compare >= 0);
			break;

#ifdef HAVE_REGEX_H
		case POLICY_LEX_RX_EQUALS:
		{ /* FIXME: copied from src/main/valuepair.c */
			int i;
			regmatch_t rxmatch[REQUEST_MAX_REGEX + 1];

			/*
			 *	Include substring matches.
			 */
			if (regcomp(&reg, this->rhs,
				    REG_EXTENDED) != 0) {
				/* FIXME: print error */
				return FALSE;
			}
			rad_assert(data != NULL);
			rcode = regexec(&reg, data,
					REQUEST_MAX_REGEX + 1,
					rxmatch, 0);
			rcode = (rcode == 0);
			regfree(&reg);

			/*
			 *	Add %{0}, %{1}, etc.
			 */
			for (i = 0; i <= REQUEST_MAX_REGEX; i++) {
				char *p;
				char rxbuffer[256];

				/*
				 *	Didn't match: delete old
				 *	match, if it existed.
				 */
				if (!rcode ||
				    (rxmatch[i].rm_so == -1)) {
					p = request_data_get(state->request, state->request,
							     REQUEST_DATA_REGEX | i);
					if (p) {
						free(p);
						continue;
					}

					/*
					 *	No previous match
					 *	to delete, stop.
					 */
					break;
				}

				/*
				 *	Copy substring into buffer.
				 */
				memcpy(rxbuffer,
				       data + rxmatch[i].rm_so,
				       rxmatch[i].rm_eo - rxmatch[i].rm_so);
				rxbuffer[rxmatch[i].rm_eo - rxmatch[i].rm_so] = '\0';

				/*
				 *	Copy substring, and add it to
				 *	the request.
				 *
				 *	Note that we don't check
				 *	for out of memory, which is
				 *	the only error we can get...
				 */
				p = strdup(rxbuffer);
				request_data_add(state->request,
						 state->request,
						 REQUEST_DATA_REGEX | i,
						 p, free);
			}

		}
		break;

		case POLICY_LEX_RX_NOT_EQUALS:
			regcomp(&reg, this->rhs, REG_EXTENDED|REG_NOSUB);
			rad_assert(data != NULL);
			rcode = regexec(&reg, data,
					0, NULL, 0);
			rcode = (rcode != 0);
			regfree(&reg);
				break;
#endif /* HAVE_REGEX_H */
		default:
			rcode = FALSE;
			break;
		} /* switch over comparison operators */
		break;		/* default from first switch over compare */
	}

	if (this->sense) rcode = (rcode == FALSE); /* reverse sense of test */

	/*
	 *	No trailing &&, ||
	 */
	switch (this->child_condition) {
	default:
		return rcode;

	case POLICY_LEX_L_AND:
		if (!rcode) return rcode; /* FALSE && x == FALSE */
		break;

	case POLICY_LEX_L_OR:
		if (rcode) return rcode; /* TRUE && x == TRUE */
		break;
	}

	/*
	 *	Tail recursion.
	 */
	this = (const policy_condition_t *) this->child;
	goto redo;

	return 1;		/* should never reach here */
}


/*
 *	Evaluate an 'if' statement
 */
static int evaluate_if(policy_state_t *state, const policy_item_t *item)
{
	int rcode;
	const policy_if_t *this;

	this = (const policy_if_t *) item;

	/*
	 *	evaluate_condition calls itself recursively.
	 *	We should probably allocate a new state, instead.
	 */
	rcode = evaluate_condition(state, this->condition);
	debug_evaluate("IF condition returned %s\n",
	       rcode ? "true" : "false");
	if (rcode) {
		rcode = policy_stack_push(state, this->if_true);
		if (!rcode) return rcode;
	} else if (this->if_false) {
		rcode = policy_stack_push(state, this->if_false);
		if (!rcode) return rcode;
	}

	/*
	 *	'if' can fail, if the block it's processing fails.
	 */
	return 1;;
}


/*
 *	Make a VALUE_PAIR from a policy_assignment_t*
 *
 *	The assignment operator has to be '='.
 */
static VALUE_PAIR *assign2vp(REQUEST *request,
			     const policy_assignment_t *assign)
{
	VALUE_PAIR *vp;
	FR_TOKEN op = T_OP_EQ;
	const char *value = assign->rhs;
	char buffer[2048];

	if ((assign->rhs_type == POLICY_LEX_DOUBLE_QUOTED_STRING) &&
	    (strchr(assign->rhs, '%') != NULL)) {
		radius_xlat(buffer, sizeof(buffer), assign->rhs,
			    request, NULL, NULL);
		value = buffer;
	}

	/*
	 *	This is crappy.. fix it.
	 */
	switch (assign->assign) {
	case POLICY_LEX_ASSIGN:
		op = T_OP_EQ;
		break;

	case POLICY_LEX_SET_EQUALS:
		op = T_OP_SET;
		break;

	case POLICY_LEX_PLUS_EQUALS:
		op = T_OP_ADD;
		break;

	default:
		fprintf(stderr, "Expected '=' for operator, not '%s' at line %d\n",
			fr_int2str(rlm_policy_tokens,
				     assign->assign, "?"),
			assign->item.lineno);
		return NULL;
	}

	vp = pairmake(assign->lhs, value, op);
	if (!vp) {
		fprintf(stderr, "Failed creating pair: %s %s\n", value, fr_strerror());
	}

	return vp;
}


/*
 *	Evaluate a 'packet .= {attrs}' statement
 */
static int evaluate_attr_list(policy_state_t *state, const policy_item_t *item)
{
	const policy_attributes_t *this;
	VALUE_PAIR **vps = NULL;
	VALUE_PAIR *vp, *head, **tail;
	const policy_item_t *attr;
	policy_lex_t this_how;

	this = (const policy_attributes_t *) item;

	switch (this->where) {
	case POLICY_RESERVED_CONTROL:
		vps = &(state->request->config_items);
		break;

	case POLICY_RESERVED_REQUEST:
		vps = &(state->request->packet->vps);
		break;

	case POLICY_RESERVED_REPLY:
		vps = &(state->request->reply->vps);
		break;

#ifdef WITH_PROXY
	case POLICY_RESERVED_PROXY_REQUEST:
		if (!state->request->proxy) return 0; /* FIXME: print error */
		vps = &(state->request->proxy->vps);
		break;

	case POLICY_RESERVED_PROXY_REPLY:
		if (!state->request->proxy_reply) return 0; /* FIXME: print error */
		vps = &(state->request->proxy_reply->vps);
		break;
#endif

	default:
		return 0;
	}

	head = NULL;
	tail = &head;

	for (attr = this->attributes; attr != NULL; attr = attr->next) {
		if (attr->type != POLICY_TYPE_ASSIGNMENT) {
			fprintf(stderr, "bad assignment in attribute list at line %d\n", attr->lineno);
			pairfree(&head);
			return 0;
		}

		vp = assign2vp(state->request, (const policy_assignment_t *) attr);
		if (!vp) {
			fprintf(stderr, "Failed to allocate VP\n");
			pairfree(&head);
			return 0;
		}
		*tail = vp;
		tail = &(vp->next);
	}

	this_how = this->how;
 retry_how:
	switch (this_how) {
	case POLICY_LEX_SET_EQUALS: /* dangerous: removes all previous things! */
		pairfree(vps);
		*vps = head;
		break;

	case POLICY_LEX_AFTER_TAIL_ASSIGN:
		pairmove(vps, &head);
		pairfree(&head);
		break;

	case POLICY_LEX_ASSIGN: /* 'union' */
		pairmove(vps, &head);
		pairfree(&head);
		break;

	case POLICY_LEX_BEFORE_HEAD_ASSIGN:
		pairmove(&head, vps);
		pairfree(vps);
		*vps = head;
		break;

	case POLICY_LEX_AFTER_TAIL_EQUALS:
	case POLICY_LEX_CONCAT_EQUALS:
		pairadd(vps, head);
		break;

	case POLICY_LEX_BEFORE_HEAD_EQUALS:
		pairadd(&head, *vps);
		*vps = head;
		break;

	case POLICY_LEX_BEFORE_WHERE_EQUALS:
	case POLICY_LEX_AFTER_WHERE_EQUALS:
	case POLICY_LEX_BEFORE_WHERE_ASSIGN:
	case POLICY_LEX_AFTER_WHERE_ASSIGN:
		/* find location*/
		{
			VALUE_PAIR *vpprev = NULL, *vpnext = NULL, *lvp;

			for(lvp = *vps; lvp; vpprev = lvp, lvp = lvp->next) {
				vpnext = lvp->next;
				lvp->next = NULL;
				if (evaluate_condition(state, this->where_loc))
					break;
				lvp->next = vpnext;
			}

			if (lvp) { 
				switch(this_how) {
				case POLICY_LEX_BEFORE_WHERE_EQUALS:
				case POLICY_LEX_BEFORE_WHERE_ASSIGN:
					if (vpprev) {
						lvp->next = vpnext;
						vpnext = lvp;
						vpprev->next = NULL;
						lvp = vpprev;
					}
				default: /* always reached */
					break;
				}

				switch(this_how) {
				case POLICY_LEX_BEFORE_WHERE_EQUALS:
					if (vpprev) 
						pairadd(&lvp, head);
					else
						*vps = lvp = head;
					break;
 				case POLICY_LEX_AFTER_WHERE_EQUALS:
 					pairadd(&lvp, head);
					break;
				case POLICY_LEX_BEFORE_WHERE_ASSIGN:
					if (vpprev) {
						pairmove(&lvp, &head);
						pairfree(&head);
					}
					else
						*vps = lvp = head;
					break;
				case POLICY_LEX_AFTER_WHERE_ASSIGN:
					pairmove(&lvp, &head);
					pairfree(&head);
					break;
				default:/*never reached*/
					break;
				}	
				for( ; lvp && lvp->next; lvp = lvp->next);
				if (lvp)
					lvp->next = vpnext;
				break;
			}

			switch(this_how) {
				case POLICY_LEX_BEFORE_WHERE_EQUALS:
					this_how = POLICY_LEX_BEFORE_HEAD_EQUALS;
					break;
				case POLICY_LEX_AFTER_WHERE_EQUALS:
					this_how = POLICY_LEX_AFTER_TAIL_EQUALS;
					break;
				case POLICY_LEX_BEFORE_WHERE_ASSIGN:
					this_how = POLICY_LEX_BEFORE_HEAD_ASSIGN;
					break;
				case POLICY_LEX_AFTER_WHERE_ASSIGN:
					this_how = POLICY_LEX_AFTER_TAIL_ASSIGN;
					break;
				default: /*never reached*/
					break;
			}
			goto retry_how; 
		}
		/* FALL-THROUGH */

	default:
		fprintf(stderr, "HUH?\n");
		pairfree(&head);
		return 0;
	}

	state->rcode = RLM_MODULE_UPDATED; /* we did stuff */

	return 1;
}


/*
 *	Evaluate a reference call to a module.
 */
static int evaluate_call(policy_state_t *state, const policy_item_t *item)
{
	int rcode;
	const policy_call_t *this;
	const policy_named_t *policy;

	this = (const policy_call_t *) item;

	policy = rlm_policy_find(state->inst->policies, this->name);
	if (!policy) return 0;	/* not found... */

	DEBUG2("rlm_policy: Evaluating policy %s", this->name);

	rad_assert(policy->policy->type != POLICY_TYPE_BAD);
	rad_assert(policy->policy->type < POLICY_TYPE_NUM_TYPES);

	/*
	 *	Push the name of the function onto the stack,
	 *	so that we can catch recursive calls.
	 *
	 *	The "pop" function will skip over it when it sees it.
	 */
	rcode = policy_stack_push(state, (const policy_item_t *) policy);
	if (!rcode) {
		return rcode;
	}

	/*
	 *	Push it onto the stack.  Other code will take care of
	 *	calling it.
	 */
	rcode = policy_stack_push(state, policy->policy);
	if (!rcode) {
		return rcode;
	}

	return 1;
}


/*
 *	Evaluate a return statement
 */
static int evaluate_return(policy_state_t *state, const policy_item_t *item)
{
	const policy_return_t *this;

	this = (const policy_return_t *) item;
	state->rcode = this->rcode;

	return 1;		/* we succeeded */
}


/*
 *	Evaluate a module statement
 */
static int evaluate_module(policy_state_t *state, const policy_item_t *item)
{
	const policy_module_t *this;

	this = (const policy_module_t *) item;

	/*
	 *	Just to be paranoid.  Maybe we want to loosen this
	 *	restriction in the future?
	 */
	if (this->component != state->component) {
		DEBUG2("rlm_policy: Cannot mix & match components");
		return 0;
	}

	DEBUG2("rlm_policy: begin nested call");
	state->rcode = modcall(this->component, this->mc, state->request);
	DEBUG2("rlm_policy: end nested call");

	return 1;		/* we succeeded */
}


/*
 *	State machine stuff.
 */
typedef int (*policy_evaluate_type_t)(policy_state_t *, const policy_item_t *);


/*
 *	MUST be kept in sync with policy_type_t
 */
static policy_evaluate_type_t evaluate_functions[POLICY_TYPE_NUM_TYPES] = {
	NULL,			/* POLICY_TYPE_BAD */
	evaluate_if,
	evaluate_condition,
	evaluate_assignment,
	evaluate_attr_list,
	evaluate_print,
	NULL,			/* define a named policy.. */
	evaluate_call,
	evaluate_return,
	evaluate_module
};


/*
 *	Evaluate a policy, keyed by name.
 */
static int policy_evaluate_name(policy_state_t *state, const char *name)
{
	int rcode;
	const policy_item_t *this;
	policy_named_t mypolicy, *policy;

	mypolicy.name = name;
	policy = rbtree_finddata(state->inst->policies, &mypolicy);
	if (!policy) return RLM_MODULE_FAIL;

	DEBUG2("rlm_policy: Evaluating policy %s", name);

	rad_assert(policy->item.type != POLICY_TYPE_BAD);
	rad_assert(policy->item.type < POLICY_TYPE_NUM_TYPES);

	rcode = policy_stack_push(state, policy->policy);
	if (!rcode) {
		return RLM_MODULE_FAIL;
	}

	/*
	 *	FIXME: Look for magic keywords like "return",
	 *	where the packet gets accepted/rejected/whatever
	 */
	while (policy_stack_pop(state, &this)) {
		rad_assert(this != NULL);
		rad_assert(this->type != POLICY_TYPE_BAD);
		rad_assert(this->type < POLICY_TYPE_NUM_TYPES);

		debug_evaluate("Evaluating at line %d\n",
			       this->lineno);
		rcode = (*evaluate_functions[this->type])(state,
							  this);
		if (!rcode) {
			return RLM_MODULE_FAIL;
		}
	} /* loop until the stack is empty */

	return state->rcode;
}


/*
 *	Evaluate, which is pretty close to print, but we look at what
 *	we're printing.
 */
int rlm_policy_evaluate(rlm_policy_t *inst, REQUEST *request, const char *name)
{
	int rcode;
	policy_state_t *state;

	state = rad_malloc(sizeof(*state));
	memset(state, 0, sizeof(*state));
	state->request = request;
	state->inst = inst;
	state->rcode = RLM_MODULE_OK;
	state->component = fr_str2int(policy_component_names, name,
					RLM_COMPONENT_COUNT);

	rcode = policy_evaluate_name(state, name);

	free(state);

	return rcode;		/* evaluated OK. */
}
