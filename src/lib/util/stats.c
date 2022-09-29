/*
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** Map internal data structures to statistics
 *
 * @file src/lib/util/stats.c
 *
 * @copyright 2022 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/util/stats.h>

/** Define dictionary attributes for a given statistics structure.
 *
 *  @param	parent the parent attribute under which statistics are defined
 *  @param	stats the statistics mapping structure.
 *  @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_stats_attr_init(fr_dict_attr_t *parent, fr_stats_struct_t const *stats)
{
	fr_stats_entry_t const *entry;
	fr_dict_t *dict;

	dict = fr_dict_unconst(fr_dict_by_da(parent));

	for (entry = &stats->table[0]; entry->name != NULL; entry++) {
		fr_dict_attr_flags_t flags = {
			.internal = true,
			.counter = entry->flags.counter,
		};

		fr_assert(entry->number > 0);
		fr_assert((entry->type == FR_TYPE_TIME_DELTA) || (fr_type_is_integer(entry->type)));

		if (fr_dict_attr_add(dict, parent, entry->name, entry->number, entry->type, &flags) < 0) return -1;
	}

	return 0;
}

/** Add statistics VPs for a particular struct / context
 *
 *  @param parent	structural vp where the children will be added
 *  @param stats	structure which maps between #fr_dict_attr_t and internal stats structures
 *  @param ctx		the internal structure holding the stastics
 *  @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_stats_pair_add(fr_pair_t *parent, fr_stats_struct_t const *stats, void const *ctx)
{
	fr_stats_entry_t const *entry;

	fr_assert(fr_type_is_structural(parent->da->type));

	for (entry = &stats->table[0]; entry->name != NULL; entry++) {
		fr_pair_t *vp;
		fr_dict_attr_t const *da;

		da = fr_dict_attr_child_by_num(parent->da, entry->number);
		if (!da) {
			fr_strerror_printf("Unknown child %d for parent %s", entry->number, parent->da->name);
			return -1;
		}

		vp = fr_pair_afrom_da(parent, da);
		if (!vp) return -1;

		if (fr_value_box_memcpy_in(&vp->data, ((uint8_t const *) ctx) + entry->offset) < 0) return -1;

		fr_pair_append(&parent->vp_group, vp);
	}

	return 0;
}
