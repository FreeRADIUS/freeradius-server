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

#ifdef DEBUG_XLAT
#  define XLAT_DEBUG RDEBUG3
#else
#  define XLAT_DEBUG(...)
#endif

/** Function types
 *
 */
typedef enum {
	XLAT_FUNC_LEGACY,				//!< Ingests and excretes strings.
	XLAT_FUNC_NORMAL				//!< Ingests and excretes value boxes (and may yield)
} xlat_func_legacy_type_t;

typedef struct xlat_s {
	fr_rb_node_t		node;			//!< Entry in the xlat function tree.
	char const		*name;			//!< Name of xlat function.

	union {
		xlat_func_legacy_t	sync;		//!< synchronous xlat function (async safe).
		xlat_func_t		async;		//!< async xlat function (async unsafe).
	} func;
	xlat_func_legacy_type_t	type;			//!< Type of xlat function.

	bool			internal;		//!< If true, cannot be redefined.

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

	bool			needs_async;		//!< If true, then it requires async operation

	size_t			buf_len;		//!< Length of output buffer to pre-allocate.
	void			*mod_inst;		//!< Module instance passed to xlat
	xlat_escape_legacy_t	escape;			//!< Escape function to apply to dynamic input to func.
} xlat_t;

typedef enum {
	XLAT_INVALID		= 0x0000,		//!< Bad expansion
	XLAT_LITERAL		= 0x0001,		//!< Literal string
	XLAT_ONE_LETTER		= 0x0002,		//!< Special "one-letter" expansion
	XLAT_FUNC		= 0x0004,		//!< xlat module
	XLAT_FUNC_UNRESOLVED	= 0x0008,		//!< func needs resolution during pass2.
	XLAT_VIRTUAL		= 0x0010,		//!< virtual attribute
	XLAT_VIRTUAL_UNRESOLVED = 0x0020,		//!< virtual attribute needs resolution during pass2.
	XLAT_ATTRIBUTE		= 0x0040,		//!< xlat attribute
#ifdef HAVE_REGEX
	XLAT_REGEX		= 0x0080,		//!< regex reference
#endif
	XLAT_ALTERNATE		= 0x0100,		//!< xlat conditional syntax :-
	XLAT_GROUP		= 0x0200		//!< encapsulated string of xlats
} xlat_type_t;

/** An xlat function call
 *
 */
typedef struct {
	xlat_t const		*func;			//!< The xlat expansion to expand format with.
	bool			ephemeral;		//!< Instance data is ephemeral (not inserted)
							///< into the instance tree.
	xlat_inst_t		*inst;			//!< Instance data for the #xlat_t.
	xlat_thread_inst_t	*thread_inst;		//!< Thread specific instance.
							///< ONLY USED FOR EPHEMERAL XLATS.
} xlat_call_t;

/** An xlat expansion node
 *
 * These nodes form a tree which represents one or more nested expansions.
 */
struct xlat_exp {
	char const	*fmt;		//!< The original format string.
	size_t		len;		//!< Length of the format string.
	fr_token_t	quote;		//!< Type of quoting around XLAT_GROUP types.

	xlat_flags_t	flags;		//!< Flags that control resolution and evaluation.

	xlat_type_t	type;		//!< type of this expansion.
	xlat_exp_t	*next;		//!< Next in the list.

	xlat_exp_t	*child;		//!< Nested expansion, i.e. arguments for an xlat function.
	xlat_exp_t	*alternate;	//!< Alternative expansion if this expansion produced no values.

	/** An attribute reference
	 *
	 * May be an attribute to expand, or provide context for a call.
	 */
	tmpl_t		*attr;

	/** A capture group, i.e. for %{1} and friends
	 */
	int		regex_index;

	/** An xlat function call
	 */
	xlat_call_t	call;
};

typedef struct {
	char const	*out;		//!< Output data.
	size_t		len;		//!< Length of the output string.
} xlat_out_t;

/** Walker callback for xlat_walk()
 *
 * @param[in] exp	being evaluated.
 * @param[in] uctx	passed to xlat_walk.
 * @return
 *	- 0 on success.
 *	- <0 if node evaluation failed.  Causes xlat_walk to return the negative integer.
 */
typedef int (*xlat_walker_t)(xlat_exp_t *exp, void *uctx);

/*
 *	xlat_func.c
 */
xlat_t	*xlat_func_find(char const *name, ssize_t namelen);

/*
 *	xlat_eval.c
 */
void		xlat_signal(xlat_func_signal_t signal, xlat_exp_t const *exp,
			    request_t *request, void *rctx, fr_state_signal_t action);

xlat_action_t	xlat_frame_eval_resume(TALLOC_CTX *ctx, fr_cursor_t *out,
				       xlat_func_resume_t resume, xlat_exp_t const *exp,
				       request_t *request, fr_value_box_t **result, void *rctx);

xlat_action_t	xlat_frame_eval_repeat(TALLOC_CTX *ctx, fr_cursor_t *out,
				       xlat_exp_t const **child, bool *alternate,
				       request_t *request, xlat_exp_t const **in,
				       fr_value_box_t **result) CC_HINT(nonnull(1,2,3,5,6));

xlat_action_t	xlat_frame_eval(TALLOC_CTX *ctx, fr_cursor_t *out, xlat_exp_t const **child,
				request_t *request, xlat_exp_t const **in);

int		xlat_eval_walk(xlat_exp_t *exp, xlat_walker_t walker, xlat_type_t type, void *uctx);

int		xlat_eval_init(void);

void		xlat_eval_free(void);

void		unlang_xlat_init(void);

#ifdef __cplusplus
}
#endif
