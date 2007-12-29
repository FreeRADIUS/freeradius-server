/*
 * rlm_policy.h    Header file for policy module
 *
 * Version:     $Id$
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
 * Copyright 2004  Alan DeKok <aland@freeradius.org>
 * Copyright 2006  The FreeRADIUS server project
 */
#ifndef _RLM_POLICY_H
#define _RLM_POLICY_H

#include <freeradius-devel/ident.h>
RCSIDH(rlm_policy_h, "$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/modcall.h>
#include <freeradius-devel/rad_assert.h>

/*
 *	Internal lexer.
 */
typedef enum policy_lex_t {
	POLICY_LEX_BAD = 0,
	POLICY_LEX_EOF,		/* end of the file/input */
	POLICY_LEX_EOL,		/* end of the line */
	POLICY_LEX_WHITESPACE,
	POLICY_LEX_HASH,
	POLICY_LEX_L_BRACKET,
	POLICY_LEX_R_BRACKET,
	POLICY_LEX_LC_BRACKET,	/* left curly bracket */
	POLICY_LEX_RC_BRACKET,	/* right curly bracket */
	POLICY_LEX_COMMA,
	POLICY_LEX_L_AND,	/* logical AND */
	POLICY_LEX_L_OR,	/* logical OR */
	POLICY_LEX_AND,		/* bit-wise AND */
	POLICY_LEX_OR,		/* bit-wise OR */
	POLICY_LEX_L_NOT,
	POLICY_LEX_PLUS,	/* + */
	POLICY_LEX_MINUS,	/* - */
	POLICY_LEX_ASSIGN,	/* = */
	POLICY_LEX_CMP_EQUALS,
	POLICY_LEX_CMP_NOT_EQUALS,
	POLICY_LEX_CMP_TRUE,
	POLICY_LEX_CMP_FALSE,
	POLICY_LEX_LT,
	POLICY_LEX_GT,
	POLICY_LEX_LE,
	POLICY_LEX_GE,
	POLICY_LEX_RX_EQUALS,
	POLICY_LEX_RX_NOT_EQUALS,
	POLICY_LEX_SET_EQUALS,	/* := */
	POLICY_LEX_AND_EQUALS,	/* &= */
	POLICY_LEX_OR_EQUALS,	/* |= */
	POLICY_LEX_PLUS_EQUALS,	/* += */
	POLICY_LEX_MINUS_EQUALS, /* -= */
	POLICY_LEX_CONCAT_EQUALS, /* .= */
	POLICY_LEX_VARIABLE,	/* %{foo} */
	POLICY_LEX_FUNCTION,	/* Hmmm... */
	POLICY_LEX_BEFORE_HEAD_ASSIGN, /* ^= */
	POLICY_LEX_BEFORE_WHERE_ASSIGN, /* ^== */
	POLICY_LEX_BEFORE_HEAD_EQUALS, /* ^. */
	POLICY_LEX_BEFORE_WHERE_EQUALS, /* ^.= */
	POLICY_LEX_AFTER_TAIL_ASSIGN, /* $= */
	POLICY_LEX_AFTER_WHERE_ASSIGN, /* $== */
	POLICY_LEX_AFTER_TAIL_EQUALS, /* $. */
	POLICY_LEX_AFTER_WHERE_EQUALS, /* $.= */
	POLICY_LEX_DOUBLE_QUOTED_STRING,
	POLICY_LEX_SINGLE_QUOTED_STRING,
	POLICY_LEX_BACK_QUOTED_STRING,
	POLICY_LEX_BARE_WORD
} policy_lex_t;

typedef enum policy_type_t {
	POLICY_TYPE_BAD = 0,
	POLICY_TYPE_IF,
	POLICY_TYPE_CONDITIONAL,
	POLICY_TYPE_ASSIGNMENT,
	POLICY_TYPE_ATTRIBUTE_LIST,
	POLICY_TYPE_PRINT,
	POLICY_TYPE_NAMED_POLICY,
	POLICY_TYPE_CALL,
	POLICY_TYPE_RETURN,
	POLICY_TYPE_MODULE,
	POLICY_TYPE_NUM_TYPES
} policy_type_t;


/*
 *	For our policy language, we want to have some reserved words.
 */
typedef enum policy_reserved_word_t {
	POLICY_RESERVED_UNKNOWN = 0,
	POLICY_RESERVED_CONTROL,
	POLICY_RESERVED_REQUEST,
	POLICY_RESERVED_REPLY,
	POLICY_RESERVED_PROXY_REQUEST,
	POLICY_RESERVED_PROXY_REPLY,
	POLICY_RESERVED_IF,
	POLICY_RESERVED_ELSE,
	POLICY_RESERVED_DEBUG,
	POLICY_RESERVED_PRINT,
	POLICY_RESERVED_POLICY,
	POLICY_RESERVED_INCLUDE,
	POLICY_RESERVED_RETURN,
	POLICY_RESERVED_MODULE,
	POLICY_RESERVED_NUM_WORDS
} policy_reserved_word_t;


#define POLICY_DEBUG_NONE           0
#define POLICY_DEBUG_PEEK           (1 << 0)
#define	POLICY_DEBUG_PRINT_TOKENS   (1 << 1)
#define	POLICY_DEBUG_PRINT_POLICY   (1 << 2)
#define	POLICY_DEBUG_EVALUATE       (1 << 3)

/*
 *	A policy item
 */
typedef struct policy_item_t {
	struct policy_item_t	*next;
	policy_type_t		type;
	int			lineno;
} policy_item_t;


/*
 *	A list of attributes to add/replace/whatever in a packet.
 */
typedef struct policy_print_t {
	policy_item_t		item;
	policy_lex_t		rhs_type;
	const char		*rhs;
} policy_print_t;


/*
 *	A list of attributes to add/replace/whatever in a packet.
 */
typedef struct policy_attributes_t {
	policy_item_t		item;
	policy_reserved_word_t	where; /* where to do it */
	policy_lex_t		how; /* how to do */
	policy_item_t		*attributes; /* things to do */
	policy_item_t		*where_loc; /* search for location in list*/
	/* FIXME: VALUE_PAIR *vps; */
} policy_attributes_t;


/*
 *	Holds a named policy
 */
typedef struct policy_named_t {
	policy_item_t	item;
	const char	*name;
	policy_item_t	*policy;
} policy_named_t;


/*
 *	Reference to a named policy
 */
typedef struct policy_call_t {
	policy_item_t	item;
	const char	*name;
} policy_call_t;


/*
 *	Hold a return code
 */
typedef struct policy_return_t {
	policy_item_t	item;
	int		rcode;
} policy_return_t;


/*
 *	Holds an assignment.
 */
typedef struct policy_assignment_t {
	policy_item_t	item;
	char		*lhs;
	policy_lex_t	assign;	/* operator for the assignment */
	policy_lex_t	rhs_type;
	char		*rhs;
} policy_assignment_t;


/*
 *	Condition
 */
typedef struct policy_condition_t {
	policy_item_t	item;

	policy_lex_t	lhs_type;
	char		*lhs;
	policy_lex_t	compare;
	policy_lex_t	rhs_type; /* bare word, quoted string, etc. */
	char		*rhs;
	int		sense;	/* whether to flip match or not */

	policy_lex_t	child_condition;
	policy_item_t	*child;
} policy_condition_t;


/*
 *	Holds an "if" statement.  The "else" may be a block, or another "if"
 */
typedef struct policy_if_t {
	policy_item_t		item;
	policy_item_t		*condition;
	policy_item_t		*if_true;
	policy_item_t		*if_false;	/* assignment, or other 'if' */
} policy_if_t;


/*
 *	Holds a reference to calling other modules... wild.
 */
typedef struct policy_module_t {
	policy_item_t	item;
	int		component; /* authorize, authenticate, etc. */
	CONF_SECTION	*cs;
	modcallable	*mc;
} policy_module_t;


/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct rlm_policy_t {
	char		*filename;
	rbtree_t	*policies;
} rlm_policy_t;


/*
 *	Functions.
 */
extern const FR_NAME_NUMBER rlm_policy_tokens[];
extern const FR_NAME_NUMBER policy_reserved_words[];
extern const FR_NAME_NUMBER policy_return_codes[];
extern const FR_NAME_NUMBER policy_component_names[];

extern int rlm_policy_insert(rbtree_t *head, policy_named_t *policy);
extern policy_named_t *rlm_policy_find(rbtree_t *head, const char *name);

extern int rlm_policy_parse(rbtree_t *policies, const char *filename);
extern void rlm_policy_free_item(policy_item_t *item);
extern void rlm_policy_print(const policy_item_t *item);
extern int rlm_policy_evaluate(rlm_policy_t *inst, REQUEST *request,
			       const char *name);

#endif /* _RLM_POLICY_H */
