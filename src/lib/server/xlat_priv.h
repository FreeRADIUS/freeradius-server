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
 * @file src/lib/server/xlat_priv.h
 * @brief String expansion ("translation"). Implements %Attribute -> value
 *
 * Private structures for the xlat tokenizer and xlat eval code.
 *
 * @copyright 2000,2006  The FreeRADIUS server project
 * @copyright 2000  Alan DeKok <aland@ox.org>
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
	XLAT_FUNC_SYNC,						//!< Ingests and excretes strings.
	XLAT_FUNC_ASYNC						//!< Ingests and excretes value boxes (and may yield)
} xlat_func_sync_type_t;

typedef struct xlat_t {
	char const		*name;				//!< Name of xlat function.

	union {
		xlat_func_sync_t	sync;			//!< synchronous xlat function (async safe).
		xlat_func_async_t	async;			//!< async xlat function (async unsafe).
	} func;
	xlat_func_sync_type_t	type;				//!< Type of xlat function.

	xlat_instantiate_t	instantiate;			//!< Instantiation function.
	xlat_thread_instantiate_t thread_instantiate;		//!< Thread instantiation function.

	xlat_detach_t		detach;				//!< Destructor for when xlat instances are freed.
	xlat_thread_detach_t	thread_detach;			//!< Destructor for when xlat thread instance data
								///< is freed.

	bool			internal;			//!< If true, cannot be redefined.

	char const		*inst_type;			//!< C name of instance structure.
	size_t			inst_size;			//!< Size of instance data to pre-allocate.

	char const		*thread_inst_type;		//!< C name of thread instance structure.
	size_t			thread_inst_size;		//!< Size of the thread instance data to pre-allocate.

	bool			async_safe;			//!< If true, is async safe
	void			*uctx;				//!< uctx to pass to instantiation functions.

	size_t			buf_len;			//!< Length of output buffer to pre-allocate.
	void			*mod_inst;			//!< Module instance passed to xlat
	xlat_escape_t		escape;				//!< Escape function to apply to dynamic input to func.
} xlat_t;


typedef enum {
	XLAT_LITERAL		= 0x01,		//!< Literal string
	XLAT_ONE_LETTER		= 0x02,		//!< Literal string with %v
	XLAT_FUNC		= 0x04,		//!< xlat module
	XLAT_VIRTUAL		= 0x08,		//!< virtual attribute
	XLAT_ATTRIBUTE		= 0x10,		//!< xlat attribute
#ifdef HAVE_REGEX
	XLAT_REGEX		= 0x11,		//!< regex reference
#endif
	XLAT_ALTERNATE		= 0x12		//!< xlat conditional syntax :-
} xlat_state_t;

/** An xlat expansion node
 *
 * These nodes form a tree which represents one or more nested expansions.
 */
struct xlat_exp {
	char const	*fmt;		//!< The original format string.
	size_t		len;		//!< Length of the format string.

	bool		async_safe;	//!< carried from all of the children

	xlat_state_t	type;		//!< type of this expansion.
	xlat_exp_t	*next;		//!< Next in the list.

	xlat_exp_t	*child;		//!< Nested expansion.

	union {
		xlat_exp_t	*alternate;	//!< Alternative expansion if this one expanded to a zero length string.

		vp_tmpl_t	*attr;		//!< An attribute template.

		int		regex_index;	//!< for %{1} and friends.
	};

	/*
	 *	An xlat function
	 */
	struct {
		xlat_t const		*xlat;		//!< The xlat expansion to expand format with.
		bool			ephemeral;	//!< Instance data is ephemeral (not inserted)
							///< into the instance tree.
		xlat_inst_t		*inst;		//!< Instance data for the #xlat_t.
		xlat_thread_inst_t	*thread_inst;	//!< Thread specific instance.
							///< ONLY USED FOR EPHEMERAL XLATS.
	};
};

typedef struct xlat_out {
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
xlat_t	*xlat_func_find(char const *name);

/*
 *	xlat_eval.c
 */
xlat_action_t	xlat_frame_eval_resume(TALLOC_CTX *ctx, fr_cursor_t *out,
				       xlat_func_resume_t resume, xlat_exp_t const *exp,
				       REQUEST *request, fr_value_box_t **result, void *rctx);

xlat_action_t	xlat_frame_eval_repeat(TALLOC_CTX *ctx, fr_cursor_t *out,
				       xlat_exp_t const **child, bool *alternate,
				       REQUEST *request, xlat_exp_t const **in,
				       fr_value_box_t **result) CC_HINT(nonnull(1,2,3,5,6));

xlat_action_t	xlat_frame_eval(TALLOC_CTX *ctx, fr_cursor_t *out, xlat_exp_t const **child,
				REQUEST *request, xlat_exp_t const **in);

int		xlat_eval_walk(xlat_exp_t *exp, xlat_walker_t walker, xlat_state_t type, void *uctx);

void		unlang_xlat_init(void);

#ifdef __cplusplus
}
#endif
