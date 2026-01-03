#pragma once
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
 * @file src/lib/unlang/xlat_priv.h
 * @brief String expansion ("translation"). Implements %Attribute -> value
 *
 * Private structures for the xlat tokenizer and xlat eval code.
 *
 * @copyright 2000,2006 The FreeRADIUS server project
 * @copyright 2000 Alan DeKok (aland@freeradius.org)
 */
#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/unlang/xlat_ctx.h>
#include <freeradius-devel/unlang/xlat.h>
#include <freeradius-devel/unlang/xlat_func.h>
#include <freeradius-devel/server/module_ctx.h>
#include <freeradius-devel/io/pair.h>
#include <freeradius-devel/util/talloc.h>
#include <freeradius-devel/build.h>

#ifdef DEBUG_XLAT
#  define XLAT_DEBUG RDEBUG3
#else
#  define XLAT_DEBUG(...)
#endif

/*
 *	Allow public and private versions of the same structures
 */
#ifdef _CONST
#  error _CONST can only be defined in the local header
#endif
#ifndef _XLAT_PRIVATE
#  define _CONST const
#else
#  define _CONST
#endif

typedef struct xlat_s {
	fr_rb_node_t		func_node;		//!< Entry in the xlat function tree.
	fr_dlist_t		mi_entry;		//!< Entry in the list of functions
							///< registered to a module instance.

	char const		*name;			//!< Name of xlat function.
	xlat_func_t		func;			//!< async xlat function (async unsafe).

	bool			internal;		//!< If true, cannot be redefined.
	bool			deprecated;		//!< this function was deprecated
	char const		*replaced_with;		//!< this function was replaced with something else
	fr_token_t		token;			//!< for expressions

	module_inst_ctx_t	*mctx;			//!< Original module instantiation ctx if this
							///< xlat was registered by a module.

	xlat_instantiate_t	instantiate;		//!< Instantiation function.
	xlat_detach_t		detach;			//!< Destructor for when xlat instances are freed.
	char const		*inst_type;		//!< C type of instance structure.
	size_t			inst_size;		//!< Size of instance data to pre-allocate.
	void			*uctx;			//!< uctx to pass to instantiation functions.

	xlat_thread_instantiate_t thread_instantiate;	//!< Thread instantiation function.
	xlat_thread_detach_t	thread_detach;		//!< Destructor for when xlat thread instance data
							///< is freed.
	char const		*thread_inst_type;	//!< C type of thread instance structure.
	size_t			thread_inst_size;	//!< Size of the thread instance data to pre-allocate.
	void			*thread_uctx;		//!< uctx to pass to instantiation functions.

	xlat_print_t		print;			//!< function to call when printing
	xlat_resolve_t		resolve;       		//!< function to call when resolving
	xlat_purify_t		purify;			//!< function to call when purifying the node.

	xlat_flags_t		flags;			//!< various flags

	xlat_arg_parser_t const	*args;			//!< Definition of args consumed.

	call_env_method_t const	*call_env_method;	//!< Optional tmpl expansions performed before calling the
							///< xlat.  Typically used for xlats which refer to tmpls
							///< in their module config.

	fr_value_box_safe_for_t	return_safe_for;	//!< Escaped value to set in output boxes.
	fr_type_t		return_type;		//!< Function is guaranteed to return one or more boxes
							///< of this type.  If the return type is FR_TYPE_VOID
							///< then the xlat function can return any type of output.
} xlat_t;

typedef enum {
	XLAT_INVALID		= 0x0000,		//!< Bad expansion
	XLAT_BOX		= 0x0001,		//!< #fr_value_box_t
	XLAT_ONE_LETTER		= 0x0002,		//!< Special "one-letter" expansion
	XLAT_FUNC		= 0x0004,		//!< xlat module
	XLAT_FUNC_UNRESOLVED	= 0x0008,		//!< func needs resolution during pass2.
	XLAT_TMPL		= 0x0010,		//!< xlat attribute
#ifdef HAVE_REGEX
	XLAT_REGEX		= 0x0020,		//!< regex reference %{1}, etc.
#endif
	XLAT_GROUP		= 0x0100		//!< encapsulated string of xlats
} xlat_type_t;

/** An xlat function call
 *
 */
typedef struct {
	uint64_t		id;			//!< Identifier unique to each permanent xlat node.
							///< This is used by the instantiation code to order
							///< nodes by the time they were created.

	xlat_t const		*func;			//!< The xlat expansion to expand format with.
	xlat_exp_head_t		*args;			//!< arguments to the function call

	fr_dict_t const		*dict;			//!< Records the namespace this xlat call was created in.
							///< Used by the purify code to run fake requests in
							///< the correct namespace, and accessible to instantiation
							///< functions in case the xlat needs to perform runtime
							///< resolution of attributes (as with %eval()).

	xlat_inst_t		*inst;			//!< Instance data for the #xlat_t.
	xlat_thread_inst_t	*thread_inst;		//!< Thread specific instance.
							///< ONLY USED FOR EPHEMERAL XLATS.

	bool			ephemeral;		//!< Instance data is ephemeral (not inserted)
							///< into the instance tree.
} xlat_call_t;

/** An xlat expansion node
 *
 * These nodes form a tree which represents one or more nested expansions.
 */
struct xlat_exp_s {
	fr_dlist_t		entry;

	char const *  _CONST	fmt;		//!< The original format string (a talloced buffer).
	fr_token_t		quote;		//!< Type of quoting around XLAT_GROUP types.

	xlat_flags_t		flags;		//!< Flags that control resolution and evaluation.
	xlat_type_t _CONST	type;		//!< type of this expansion.

#ifndef NDEBUG
	char const * _CONST	file;		//!< File where the xlat was allocated.
	int			line;		//!< Line where the xlat was allocated.
#endif

	union {
		struct {
			xlat_exp_head_t	*group;		//!< children of a group
			unsigned int   	hoist : 1;	//!< it's a group, but we need to hoist the results
		};

		/** An tmpl_t reference
		 *
		 * May be an attribute to expand, or an exec reference, or a value-box, ...
		 */
		tmpl_t		*vpt;

		/** A capture group, i.e. for %{1} and friends
		 */
		int		regex_index;

		/** An xlat function call
		 */
		xlat_call_t	call;

		/** A value box
		 */
		fr_value_box_t	data;
	};
};

struct xlat_exp_head_s {
	fr_dlist_head_t		dlist;
	xlat_flags_t		flags;		//!< Flags that control resolution and evaluation.
	unsigned int		instantiated : 1;  //!< temporary flag until we fix more things
	unsigned int		is_argv : 1;	//!< this thing holds function arguments
	unsigned int		cursor : 1;	//!< otherwise it's too hard to pass xlat_arg_parser_t to the evaluation function.
	unsigned int		is_attr : 1;	//!< the argument is an attribute reference

#ifndef NDEBUG
	char const * _CONST	file;		//!< File where the xlat was allocated.
	int			line;		//!< Line where the xlat was allocated.
#endif
};

typedef struct {
	char const		*out;		//!< Output data.
	size_t			len;		//!< Length of the output string.
} xlat_out_t;
/*
 *	Helper functions
 */

static inline xlat_exp_t *xlat_exp_head(xlat_exp_head_t const *head)
{
	if (!head) return NULL;

	return fr_dlist_head(&head->dlist);
}

/** Iterate over the contents of a list, only one level
 *
 * @param[in] _list_head	to iterate over.
 * @param[in] _iter		Name of iteration variable.
 *				Will be declared in the scope of the loop.
 */
#define xlat_exp_foreach(_list_head, _iter) fr_dlist_foreach(&((_list_head)->dlist), xlat_exp_t, _iter)

/** Merge flags from child to parent
 *
 * For pass2, if either the parent or child is marked up for pass2, then the parent
 * is marked up for pass2.
 */
static inline CC_HINT(nonnull) void xlat_flags_merge(xlat_flags_t *parent, xlat_flags_t const *child)
{
	parent->needs_resolving |= child->needs_resolving;
	parent->pure &= child->pure; /* purity can only be removed, never added */
	parent->can_purify |= child->can_purify; /* there is SOME node under us which can be purified */
	parent->constant &= child->constant;
	parent->impure_func |= child->impure_func;
}

static inline CC_HINT(nonnull) int xlat_exp_insert_tail(xlat_exp_head_t *head, xlat_exp_t *node)
{
	XLAT_VERIFY(node);

	xlat_flags_merge(&head->flags, &node->flags);
	return fr_dlist_insert_tail(&head->dlist, node);
}

static inline xlat_exp_t *xlat_exp_next(xlat_exp_head_t const *head, xlat_exp_t const *node)
{
	if (!head) return NULL;

	return fr_dlist_next(&head->dlist, node);
}

/*
 *	xlat_purify.c
 */
int xlat_purify_list(xlat_exp_head_t *head, request_t *request);

/** Walker callback for xlat_walk()
 *
 * @param[in] exp	being evaluated.
 * @param[in] uctx	passed to xlat_walk.
 * @return
 *	- 1 for "prune walk here".
 *	- 0 on success.
 *	- <0 if node evaluation failed.  Causes xlat_walk to return the negative integer.
 */
typedef int (*xlat_walker_t)(xlat_exp_t *exp, void *uctx);

/*
 *	xlat_alloc.c
 */
xlat_exp_head_t	*_xlat_exp_head_alloc(NDEBUG_LOCATION_ARGS TALLOC_CTX *ctx);
#define		xlat_exp_head_alloc(_ctx) _xlat_exp_head_alloc(NDEBUG_LOCATION_EXP _ctx)

void		_xlat_exp_set_type(NDEBUG_LOCATION_ARGS xlat_exp_t *node, xlat_type_t type);
#define		xlat_exp_set_type(_node, _type) _xlat_exp_set_type(NDEBUG_LOCATION_EXP _node, _type)

xlat_exp_t	*_xlat_exp_alloc_null(NDEBUG_LOCATION_ARGS TALLOC_CTX *ctx);
#define		xlat_exp_alloc_null(_ctx) _xlat_exp_alloc_null(NDEBUG_LOCATION_EXP _ctx)

xlat_exp_t	*_xlat_exp_alloc(NDEBUG_LOCATION_ARGS TALLOC_CTX *ctx, xlat_type_t type, char const *in, size_t inlen);
#define		xlat_exp_alloc(_ctx, _type, _in, _inlen) _xlat_exp_alloc(NDEBUG_LOCATION_EXP _ctx, _type, _in, _inlen)

void		xlat_exp_set_name(xlat_exp_t *node, char const *fmt, size_t len) CC_HINT(nonnull);
void		xlat_exp_set_name_shallow(xlat_exp_t *node, char const *fmt) CC_HINT(nonnull);
void		xlat_exp_set_name_buffer(xlat_exp_t *node, char const *fmt) CC_HINT(nonnull);

void		xlat_exp_set_vpt(xlat_exp_t *node, tmpl_t *vpt) CC_HINT(nonnull);
void		xlat_exp_set_func(xlat_exp_t *node, xlat_t const *func, fr_dict_t const *dict) CC_HINT(nonnull(1,2));
void		xlat_exp_finalize_func(xlat_exp_t *node) CC_HINT(nonnull);

/*
 *	xlat_func.c
 */
xlat_t		*xlat_func_find(char const *name, ssize_t namelen);

/*
 *	xlat_eval.c
 */
extern fr_dict_attr_t const *attr_expr_bool_enum;
extern fr_dict_attr_t const *attr_module_return_code;
extern fr_dict_attr_t const *attr_cast_base;

fr_dict_attr_t const *xlat_time_res_attr(char const *res);

/*
 *	xlat_tokenize.c
 */
extern bool const xlat_func_chars[UINT8_MAX + 1];

int		xlat_tokenize_regex(xlat_exp_head_t *head, xlat_exp_t **out, fr_sbuff_t *in, fr_sbuff_marker_t *m_s) CC_HINT(nonnull);

void		xlat_signal(xlat_func_signal_t signal, xlat_exp_t const *exp,
			    request_t *request, void *rctx, fr_signal_t action);

xlat_action_t	xlat_frame_eval_resume(TALLOC_CTX *ctx, fr_dcursor_t *out,
				       xlat_exp_head_t const **child,
				       request_t *request,  xlat_exp_head_t const *head, xlat_exp_t const **in,
				       fr_value_box_list_t *result, xlat_func_t resume, void *rctx);

xlat_action_t	xlat_frame_eval_repeat(TALLOC_CTX *ctx, fr_dcursor_t *out,
				       xlat_exp_head_t const **child,
				       request_t *request, xlat_exp_head_t const *head, xlat_exp_t const **in,
				       void *env_data, fr_value_box_list_t *result) CC_HINT(nonnull(1,2,3,4));

xlat_action_t	xlat_frame_eval(TALLOC_CTX *ctx, fr_dcursor_t *out, xlat_exp_head_t const **child,
				request_t *request, xlat_exp_head_t const *head, xlat_exp_t const **in);

int		xlat_eval_walk(xlat_exp_head_t *head, xlat_walker_t walker, xlat_type_t type, void *uctx);

int		xlat_eval_init(void);

void		xlat_eval_free(void);

void		unlang_xlat_init(void);

int		unlang_xlat_push_node(TALLOC_CTX *ctx, unlang_result_t *p_result, fr_value_box_list_t *out,
				      request_t *request, xlat_exp_t *node);

int 		xlat_decode_value_box_list(TALLOC_CTX *ctx, fr_pair_list_t *out,
					   request_t *request, void *decode_ctx, fr_pair_decode_t decode,
					   fr_value_box_list_t *in);
/*
 *	xlat_expr.c
 */
int		xlat_register_expressions(void);

/*
 *	xlat_tokenize.c
 */
ssize_t		xlat_print_node(fr_sbuff_t *out, xlat_exp_head_t const *head, xlat_exp_t const *node,
				fr_sbuff_escape_rules_t const *e_rules, char c);

fr_slen_t	xlat_tokenize_word(TALLOC_CTX *ctx, xlat_exp_t **out, fr_sbuff_t *in, fr_token_t quote,
				   fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules) CC_HINT(nonnull);

#ifdef __cplusplus
}
#endif
