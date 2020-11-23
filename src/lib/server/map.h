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
 * @file lib/server/map.h
 * @brief Structures and prototypes for maps
 *
 * @copyright 2015 The FreeRADIUS server project
 * @copyright 2015 Arran Cudbard-bell (a.cudbardb@freeradius.org)
 */
RCSIDH(map_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

typedef struct vp_map_s map_t;
typedef struct vp_list_mod_s vp_list_mod_t;

#ifdef __cplusplus
}
#endif

#include <freeradius-devel/server/cf_util.h>
#include <freeradius-devel/server/tmpl.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Single character tokens used as terminals for the LHS operand
 *
 */
#define MAP_LHS_TERMINALS \
	['-'] = true, \
	[':'] = true, \
	['+'] = true, \
	['<'] = true, \
	['='] = true, \
	['>'] = true, \
	['~'] = true

/** Value pair map
 *
 * Value pair maps contain a pair of templates, that describe a src attribute
 * or value, and a destination attribute.
 *
 * Neither src or dst need to be an FR attribute, and their type can be inferred
 * from whether map->da is NULL (not FR).
 *
 * @see tmpl_t
 */
struct vp_map_s {
	tmpl_t		*lhs;		//!< Typically describes the attribute to add, modify or compare.
	tmpl_t		*rhs;   	//!< Typically describes a literal value or a src attribute
						///< to copy or compare.

	fr_token_t		op; 		//!< The operator that controls insertion of the dst attribute.
	fr_type_t		cast;		//!< Cast value to this type.

	CONF_ITEM		*ci;		//!< Config item that the map was created from. Mainly used for
						//!< logging validation errors.

	map_t		*child;		//!< a child map.  If it exists, `rhs` MUST be NULL
	map_t		*next;		//!< The next valuepair map.
};

/** A list modification
 *
 */
struct vp_list_mod_s {
	map_t const		*map;		//!< Original map describing the change to be made.

	map_t		*mod;		//!< New map containing the destination (LHS) and
						///< values (RHS).
	vp_list_mod_t		*next;
};

#ifndef WITH_VERIFY_PTR
#  define MAP_VERIFY(_x) fr_assert((_x)->lhs)
#else
#  define MAP_VERIFY(_x) do { \
	TMPL_VERIFY((_x)->lhs); \
	if ((_x)->rhs) TMPL_VERIFY((_x)->rhs); \
} while (0)
#endif

typedef int (*map_validate_t)(map_t *map, void *ctx);
typedef int (*radius_map_getvalue_t)(TALLOC_CTX *ctx, fr_pair_t **out, request_t *request,
				     map_t const *map, void *uctx);

int		map_afrom_cp(TALLOC_CTX *ctx, map_t **out, CONF_PAIR *cp,
			     tmpl_rules_t const *lhs_rules, tmpl_rules_t const *rhs_rules);

int		map_afrom_cs(TALLOC_CTX *ctx, map_t **out, CONF_SECTION *cs,
			     tmpl_rules_t const *lhs_rules, tmpl_rules_t const *rhs_rules,
			     map_validate_t validate, void *uctx, unsigned int max) CC_HINT(nonnull(2, 3));

int		map_afrom_value_box(TALLOC_CTX *ctx, map_t **out,
				    char const *lhs, fr_token_t lhs_type, tmpl_rules_t const *lhs_rules,
				    fr_token_t op,
				    fr_value_box_t *rhs, bool steal_rhs_buffs);

int		map_afrom_attr_str(TALLOC_CTX *ctx, map_t **out, char const *raw,
				   tmpl_rules_t const *lhs_rules, tmpl_rules_t const *rhs_rules);

int		map_afrom_vp(TALLOC_CTX *ctx, map_t **out, fr_pair_t *vp,
			     tmpl_rules_t const *rules);

int		map_afrom_sbuff(TALLOC_CTX *ctx, map_t **out, fr_sbuff_t *in,
				fr_table_num_sorted_t const *op_table, size_t op_table_len,
				tmpl_rules_t const *lhs_rules, tmpl_rules_t const *rhs_rules,
				fr_sbuff_parse_rules_t const *rhs_term);

void		map_sort(map_t **maps, fr_cmp_t cmp);

int		map_to_vp(TALLOC_CTX *ctx, fr_pair_t **out, request_t *request,
			  map_t const *map, void *uctx) CC_HINT(nonnull (2,3,4));

int		map_list_mod_apply(request_t *request, vp_list_mod_t const *vlm);

int		map_to_list_mod(TALLOC_CTX *ctx, vp_list_mod_t **out,
				request_t *request, map_t const *map,
				fr_value_box_t **lhs_result, fr_value_box_t **rhs_result);

int		map_to_request(request_t *request, map_t const *map,
			       radius_map_getvalue_t func, void *ctx);

ssize_t		map_print(fr_sbuff_t *out, map_t const *map);

void		map_debug_log(request_t *request, map_t const *map,
			      fr_pair_t const *vp) CC_HINT(nonnull(1, 2));

extern fr_table_num_sorted_t const map_assignment_op_table[];
extern size_t map_assignment_op_table_len;

extern fr_sbuff_parse_rules_t const map_parse_rules_bareword_quoted;

#ifdef __cplusplus
}
#endif
