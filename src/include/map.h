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
#ifndef MAP_H
#define MAP_H
/**
 * $Id$
 *
 * @file map.h
 * @brief Structures and prototypes for maps
 *
 * @copyright 2013  The FreeRADIUS server project
 */

RCSIDH(map_h, "$Id$")

#include <freeradius-devel/conffile.h>
#include <freeradius-devel/tmpl.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Value pair map
 *
 * Value pair maps contain a pair of templates, that describe a src attribute
 * or value, and a destination attribute.
 *
 * Neither src or dst need to be an FR attribute, and their type can be inferred
 * from whether map->da is NULL (not FR).
 *
 * @see vp_tmpl_t
 */
typedef struct value_pair_map {
	vp_tmpl_t	*lhs;	//!< Typically describes the attribute
					//!< to add or modify.
	vp_tmpl_t	*rhs;   //!< Typically describes a value or a
					//!< src attribute to copy.

	FR_TOKEN		op; 	//!< The operator that controls
					//!< insertion of the dst attribute.

	CONF_ITEM		*ci;	//!< Config item that the map was
					//!< created from. Mainly used for
					//!< logging validation errors.

	struct value_pair_map	*next;	//!< The next valuepair map.
} value_pair_map_t;

#ifndef WITH_VERIFY_PTR
#  define VERIFY_MAP(_x) rad_assert((_x)->lhs)
#else
#  define VERIFY_MAP(_x) do { \
	VERIFY_TMPL((_x)->lhs); \
	if ((_x)->rhs) VERIFY_TMPL((_x)->rhs); \
} while (0)
#endif

typedef int (*map_validate_t)(value_pair_map_t *map, void *ctx);
typedef int (*radius_map_getvalue_t)(VALUE_PAIR **out, REQUEST *request, value_pair_map_t const *map, void *ctx);

int		map_afrom_cp(TALLOC_CTX *ctx, value_pair_map_t **out, CONF_PAIR *cp,
			     request_refs_t dst_request_def, pair_lists_t dst_list_def,
			     request_refs_t src_request_def, pair_lists_t src_list_def);

int		map_afrom_fields(TALLOC_CTX *ctx, value_pair_map_t **out, char const *lhs, FR_TOKEN lhs_type,
				 FR_TOKEN op, char const *rhs, FR_TOKEN rhs_type,
				 request_refs_t dst_request_def, pair_lists_t dst_list_def,
				 request_refs_t src_request_def, pair_lists_t src_list_def);

int		map_afrom_cs(value_pair_map_t **out, CONF_SECTION *cs,
			     pair_lists_t dst_list_def, pair_lists_t src_list_def,
			     map_validate_t validate, void *ctx, unsigned int max) CC_HINT(nonnull(1, 2));

int		map_afrom_attr_str(TALLOC_CTX *ctx, value_pair_map_t **out, char const *raw,
				 request_refs_t dst_request_def, pair_lists_t dst_list_def,
				 request_refs_t src_request_def, pair_lists_t src_list_def);

int		map_to_vp(VALUE_PAIR **out, REQUEST *request,
			  value_pair_map_t const *map, void *ctx) CC_HINT(nonnull (1,2,3));

int		map_to_request(REQUEST *request, value_pair_map_t const *map,
			       radius_map_getvalue_t func, void *ctx);

bool		map_dst_valid(REQUEST *request, value_pair_map_t const *map);

size_t		map_prints(char *buffer, size_t bufsize, value_pair_map_t const *map);

void		map_debug_log(REQUEST *request, value_pair_map_t const *map,
			      VALUE_PAIR const *vp) CC_HINT(nonnull(1, 2));

bool map_cast_from_hex(value_pair_map_t *map, FR_TOKEN rhs_type, char const *rhs);
#ifdef __cplusplus
}
#endif

#endif	/* MAP_H */
