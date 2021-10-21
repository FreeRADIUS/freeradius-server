#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @file lib/server/cond.h
 * @brief Condition parser API
 *
 * @copyright 2013 Alan DeKok (aland@freeradius.org)
 */
RCSIDH(cond_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/server/tmpl.h>
#include <freeradius-devel/server/map.h>

#ifndef RADIUSD_H
/*
 *	Also defined in radiusd.h for radius_evalute_cond()
 */
typedef struct fr_cond_s fr_cond_t;
#endif

extern fr_table_num_sorted_t const cond_logical_op_table[];
extern size_t cond_logical_op_table_len;

extern fr_table_num_sorted_t const cond_cmp_op_table[];
extern size_t cond_cmp_op_table_len;

extern fr_table_num_sorted_t const cond_quote_table[];
extern size_t cond_quote_table_len;

typedef enum {
	COND_TYPE_INVALID = 0,
	COND_TYPE_TRUE,
	COND_TYPE_FALSE,
	COND_TYPE_TMPL,
	COND_TYPE_RCODE,
	COND_TYPE_MAP,
	COND_TYPE_AND,
	COND_TYPE_OR,
	COND_TYPE_CHILD
} fr_cond_type_t;

typedef enum {
	PASS2_FIXUP_NONE = 0,
	PASS2_FIXUP_ATTR,
	PASS2_FIXUP_TYPE,
	PASS2_PAIRCOMPARE
} fr_cond_pass2_t;

/*
 *	Allow for the following structures:
 *
 *	FOO			no OP, RHS is NULL
 *	FOO OP BAR
 *	(COND)			no LHS/RHS, child is COND, child OP is true
 *	(!(COND))		no LHS/RHS, child is COND, child OP is NOT
 *	(COND1 OP COND2)	no LHS/RHS, next is COND2, next OP is OP
 */
struct fr_cond_s {
	fr_cond_type_t		type;

	union {
		map_t			*map;		//!< Binary expression.
		tmpl_t			*vpt;		//!< Unary expression.
		fr_cond_t  		*child;		//!< Nested condition.
		rlm_rcode_t		rcode;		//!< Rcode check.   We handle this outside of
							///< tmpls as it doesn't apply anywhere else.
	} data;

	bool			async_required;	//!< is async required?
	bool			negate;		//!< Invert the result of the expression.
	fr_cond_pass2_t		pass2_fixup;

	fr_cond_t		*parent;
	fr_cond_t		*next;
};

typedef struct {
	fr_cond_t	*cond;
} fr_cond_iter_t;

ssize_t	fr_cond_tokenize(CONF_SECTION *cs, fr_cond_t **head, tmpl_rules_t const *rules, fr_sbuff_t *in) CC_HINT(nonnull(1,2,4));

int	fr_cond_promote_types(fr_cond_t *c, fr_sbuff_t *in, fr_sbuff_marker_t *m_lhs, fr_sbuff_marker_t *m_rhs) CC_HINT(nonnull(1));

ssize_t	cond_print(fr_sbuff_t *out, fr_cond_t const *c);

fr_cond_t *fr_cond_iter_init(fr_cond_iter_t *iter, fr_cond_t *head);
fr_cond_t *fr_cond_iter_next(fr_cond_iter_t *iter);

void fr_cond_async_update(fr_cond_t *cond);

#ifdef __cplusplus
}
#endif
