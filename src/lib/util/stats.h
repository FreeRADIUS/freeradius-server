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
 * @file lib/util/stats.h
 * @brief Structures and functions for statistics.
 *
 * @copyright 2022 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(stats_h, "$Id$")

#include <freeradius-devel/util/pair.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Define a statistics mapping between dictionary attribute and a field in an internal structure.
 *
 *  Note that the data types used in the internal structure have to match the #fr_type_t.
 */
typedef struct {
	char const	*name;		//!< Attribute name
	fr_type_t	type;		//!< data type for this statistics
	int		number;		//!< attribute number, so that numbers are consistent
	struct {
		bool	counter;	//!< data type is a counter (can add them)
		bool	gauge;		//!< data type is a gauge (take the maximum)
	} flags;

	size_t		offset;		//!< from start of the structure
} fr_stats_entry_t;

#define STATS_ENTRY_TERMINATOR { .attr = NULL }

/** Define a statistics mapping between a public name and an entire internal structure
 *
 */
typedef struct {
	char const	*name;		//!< of this structure for public consumption
	fr_stats_entry_t table[];	//!< of mappings
} fr_stats_struct_t;

int	fr_stats_attr_init(fr_dict_attr_t *parent, fr_stats_struct_t const *stats) CC_HINT(nonnull);

int	fr_stats_pair_add(fr_pair_t *parent, fr_stats_struct_t const *stats, void const *ctx) CC_HINT(nonnull);

#ifdef __cplusplus
}
#endif
