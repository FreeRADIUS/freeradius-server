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
 * @file main/xlat.h
 * @brief String expansion ("translation"). Implements %Attribute -> value
 *
 * Private structures for the xlat tokenizer and xlat eval code.
 *
 * @copyright 2000,2006  The FreeRADIUS server project
 * @copyright 2000  Alan DeKok <aland@ox.org>
 */

#ifdef DEBUG_XLAT
#  define XLAT_DEBUG RDEBUG3
#else
#  define XLAT_DEBUG(...)
#endif

typedef struct xlat_t {
	char			name[FR_MAX_STRING_LEN];	//!< Name of the xlat expansion.
	int			length;			//!< Length of name.
	void			*mod_inst;		//!< Module instance passed to xlat and escape functions.
	xlat_func_t		func;			//!< xlat function.
	xlat_escape_t		escape;			//!< Escape function to apply to dynamic input to func.
	xlat_instantiate_t	instantiate;		//!< Instantiation function.
	size_t			inst_size;		//!< Length of instance data to pre-allocate.
	size_t			buf_len;		//!< Length of output buffer to pre-allocate.
	bool			internal;		//!< If true, cannot be redefined.
	bool			async_safe;		///!< If true, is async safe
} xlat_t;

typedef enum {
	XLAT_LITERAL,			//!< Literal string
	XLAT_PERCENT,			//!< Literal string with %v
	XLAT_MODULE,			//!< xlat module
	XLAT_VIRTUAL,			//!< virtual attribute
	XLAT_ATTRIBUTE,			//!< xlat attribute
#ifdef HAVE_REGEX
	XLAT_REGEX,			//!< regex reference
#endif
	XLAT_ALTERNATE			//!< xlat conditional syntax :-
} xlat_state_t;

struct xlat_exp {
	char const	*fmt;		//!< The format string.
	size_t		len;		//!< Length of the format string.

	xlat_state_t	type;		//!< type of this expansion.
	xlat_exp_t	*next;		//!< Next in the list.

	xlat_exp_t	*child;		//!< Nested expansion.

	union {
		xlat_exp_t	*alternate;	//!< Alternative expansion if this one expanded to a zero length string.

		vp_tmpl_t	*attr;		//!< An attribute template.

		int		regex_index;	//!< for %{1} and friends.
	};
	xlat_t const	*xlat;		//!< The xlat expansion to expand format with.
};

typedef struct xlat_out {
	char const	*out;		//!< Output data.
	size_t		len;		//!< Length of the output string.
} xlat_out_t;


ssize_t xlat_tokenize_request(TALLOC_CTX *ctx, REQUEST *request, char const *fmt, xlat_exp_t **head);

xlat_t *xlat_find(char const *name);
