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
typedef struct fr_cond_t fr_cond_t;
#endif

typedef enum {
	COND_NONE = 0,
	COND_AND = '&',
	COND_OR = '|'
} fr_cond_op_t;

typedef enum {
	COND_TYPE_INVALID = 0,
	COND_TYPE_TRUE,
	COND_TYPE_FALSE,
	COND_TYPE_EXISTS,
	COND_TYPE_MAP,
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
struct fr_cond_t {
	fr_cond_type_t		type;

	CONF_ITEM const		*ci;
	union {
		vp_map_t		*map;
		vp_tmpl_t		*vpt;
		fr_cond_t  		*child;
	} data;

	bool			negate;
	fr_cond_pass2_t		pass2_fixup;

	fr_dict_attr_t const	*cast;

	fr_cond_op_t		next_op;
	fr_cond_t		*next;
};

ssize_t fr_cond_tokenize(TALLOC_CTX *ctx, fr_cond_t **head, char const **error,
			 fr_dict_t const *dict,
			 CONF_SECTION *parent, char const *start, char const *filename, int lineno);
size_t cond_snprint(char *buffer, size_t bufsize, fr_cond_t const *c);

bool fr_cond_walk(fr_cond_t *head, bool (*callback)(fr_cond_t *cond, void *uctx), void *uctx);

#ifdef __cplusplus
}
#endif
