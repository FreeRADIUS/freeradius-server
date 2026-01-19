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

/** Convert a statistics structure to #fr_pair_t
 *
 * @param[in] ctx	talloc ctx
 * @param[out] out	where the output pairs will be stored
 * @param[in] inst	data structure defining this instance of the statistics
 */
int fr_stats_to_pairs(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_stats_instance_t const *inst)
{
	size_t i;
	fr_stats_link_t const *def = inst->def;
	uint8_t const *in = inst->stats;
	fr_pair_t *parent, *vp;

	parent = fr_pair_afrom_da(ctx, *(def->root_p));
	if (!parent) return -1;

	for (i = 0; i < def->num_elements; i++) {
		uint8_t const *field;

		vp = fr_pair_afrom_da(parent, *(def->entry[i].da_p));
		if (!vp) goto fail;

		field = ((uint8_t const *) in) + def->entry[i].offset;

		/*
		 *	Strings of length 0 are "const char *".
		 *
		 *	Everything else is an in-line field.
		 */
		switch (def->entry[i].type) {
		case FR_TYPE_STRING:
			if (!def->entry[i].size) {
				char const *str;

				memcpy(&str, field, sizeof(str));

				if (fr_pair_value_strdup(vp, str, false) < 0) goto fail;
				break;
			}
			FALL_THROUGH;

		case FR_TYPE_OCTETS:
		case FR_TYPE_UINT16:
		case FR_TYPE_UINT32:
		case FR_TYPE_UINT64:
		case FR_TYPE_IPV4_ADDR:
		case FR_TYPE_IPV6_ADDR:
			fr_assert(def->entry[i].size > 0);

			if (fr_value_box_from_network(vp, &vp->data, def->entry[i].type, vp->da,
						      &FR_DBUFF_TMP(field, def->entry[i].size), def->entry[i].size, false) < 0) {
				goto fail;
			}
			break;

		case FR_TYPE_DATE:
			memcpy(&vp->vp_date, field, sizeof(vp->vp_date));
			break;

		case FR_TYPE_TIME_DELTA:
			memcpy(&vp->vp_time_delta, field, sizeof(vp->vp_time_delta));
			break;

		default:
			fr_strerror_printf("Unsupported data type '%s'", fr_type_to_str(def->entry[i].type));
			return -1;
		}

		if (fr_pair_append(&parent->vp_group, vp) < 0) goto fail;
	}

	if (fr_pair_append(out, parent) < 0) {
	fail:
		talloc_free(parent);
		return -1;
	}

	return 0;
}


/** Convert a statistics structure to #fr_pair_t
 *
 * @param[in] ctx	talloc ctx
 * @param[out] inst	where the output pairs will be stored
 * @param[in] list	pairs where we read the pairs from
 */
int fr_stats_from_pairs(TALLOC_CTX *ctx, fr_stats_instance_t *inst, fr_pair_list_t const *list)
{
	size_t i;
	fr_stats_link_t const *def = inst->def;
	uint8_t *out = inst->stats;
	fr_pair_t const *parent, *vp;

	parent = fr_pair_find_by_da(list, NULL, *(def->root_p));
	if (!parent) return -1;

	memset(out, 0, inst->def->size);

	for (i = 0; i < def->num_elements; i++) {
		uint8_t *field;

		vp = fr_pair_find_by_da(&parent->vp_group, NULL, *(def->entry[i].da_p));
		if (!vp) continue;

		field = ((uint8_t *) out) + def->entry[i].offset;

		/*
		 *	Strings of length 0 are "const char *".
		 *
		 *	Everything else is an in-line field.
		 */
		switch (def->entry[i].type) {
		case FR_TYPE_STRING:
			if (!def->entry[i].size) {
				char const *str;

				str = talloc_bstrndup(ctx, vp->vp_strvalue, vp->vp_length);
				if (!str) return -1;

				memcpy(&field, &str, sizeof(str));
				break;
			}
			FALL_THROUGH;

		case FR_TYPE_OCTETS:
			if (vp->vp_length <= def->entry[i].size) {
				memcpy(field, vp->vp_ptr, vp->vp_length);
			} else {
				memcpy(field, vp->vp_ptr, def->entry[i].size);
			}
			break;

#undef COPY
#define COPY(_type, _field) \
	case _type: \
		memcpy(field, &vp->vp_ ## _field, sizeof(vp->vp_ ##_field)); \
		break

			COPY(FR_TYPE_UINT16, uint16);
			COPY(FR_TYPE_UINT32, uint32);
			COPY(FR_TYPE_UINT64, uint64);

			COPY(FR_TYPE_IPV4_ADDR, ipv4addr); /* struct in_addr, and not vp_ip */
			COPY(FR_TYPE_IPV6_ADDR, ipv6addr); /* struct in6_addr, and not vp_ip */

			COPY(FR_TYPE_DATE, date);
			COPY(FR_TYPE_TIME_DELTA, time_delta);

			default:
				fr_strerror_printf("Unsupported data type '%s'", fr_type_to_str(def->entry[i].type));
				return -1;
		}
	}

	return 0;
}


#undef add
#define add(_type, _out, _in) \
do { \
	_type _a, _b, _sum; \
	memcpy(&_a, &_out, sizeof(_a)); \
	memcpy(&_b, &_in, sizeof(_b)); \
	_sum = _a + _b; \
	memcpy(&_out, &_sum, sizeof(_sum)); \
} while (0)

/** Merge to statistics structures
 *
 *  @todo - ensure that the struct magic is the same as the def magic
 *
 */
static int stats_merge_internal(fr_stats_link_t const *def, void *out, void const *in)
{
	size_t i;

	for (i = 0; i < def->num_elements; i++) {
		uint8_t const *field_in;
		uint8_t const *field_out;

		field_in = ((uint8_t const *) in) + def->entry[i].offset;
		field_out = ((uint8_t const *) out) + def->entry[i].offset;

		switch (def->entry[i].type) {
		case FR_TYPE_UINT16:
			add(uint16_t, field_out, field_in);
			break;

		case FR_TYPE_UINT32:
			add(uint32_t, field_out, field_in);
			break;

		case FR_TYPE_UINT64:
			add(uint64_t, field_out, field_in);
			break;

		default:
			break;
		}
	}

	return 0;
}

/** Public API for merging two statistics structures
 *
 * @param[out] out	where the merged stats are written to
 * @param[in] in	source stats to merge into out
 * @return
 *	- 0 on success
 *	- <0 on the two instances are not compatible.
 */
int fr_stats_merge_instance(fr_stats_instance_t *out, fr_stats_instance_t const *in)
{
	if (out->def != in->def) {
		fr_strerror_printf("Cannot merge stats into structure %s from different structure %s",
				   out->def->name, in->def->name);
		return -1;
	}

	return stats_merge_internal(out->def, out->stats, in->stats);
}

/** Public API for merging two value-boxes based on their enums
 *
 * @param[in,out] dst	where the merged stats are written to
 * @param[in] src	source stats to merge into dst
 * @return
 *	- 0 on success
 *	- <0 on the two boxes are not compatible, or we cannot merge the given data type
 */
int fr_stats_merge_value_box(fr_value_box_t *dst, fr_value_box_t const *src)
{
	if (dst->type != src->type) {
		fr_strerror_const("Cannot merge two different data types");
		return -1;
	}

	if (dst->enumv != src->enumv) {
		fr_strerror_const("Cannot merge two different fields");
		return -1;
	}

	if (!dst->enumv) {
		fr_strerror_const("Unable to determine how to merge the fields");
		return -1;
	}

	/*
	 *	@todo - distinguish counter from gauge.  This also means that we will need to update the
	 *	dictionary.stats to set the "counter" flag.
	 */

	switch (dst->type) {
	case FR_TYPE_UINT16:
		dst->vb_uint16 += src->vb_uint16;
		break;

	case FR_TYPE_UINT32:
		dst->vb_uint32 += src->vb_uint32;
		break;

	case FR_TYPE_UINT64:
		dst->vb_uint64 += src->vb_uint64;
		break;

	default:
		fr_strerror_const("Cannot merge non-integer data types");
		return -1;
	}

	return 0;
}


/** Initialize an iterator over a structure
 *
 * @param[in] inst	data structure defining this instance of the statistics
 * @param[out] iter	the initialized iterator
 */
void fr_stats_iter_init(fr_stats_instance_t const *inst, fr_stats_iter_t *iter)
{
	iter->inst = inst;
	iter->current = 0;
}

/** Go to the next entry in a structure
 *
 * @param[in] iter	the iterator
 * @return
 *	- true for continue the iteration
 *	- false for the iteration is done
 */
bool fr_stats_iter_next(fr_stats_iter_t *iter)
{
	if (iter->current < iter->inst->def->num_elements) {
		iter->current++;
		return true;
	}

	return false;
}


/** Convert the statistic at an index to a value-box
 *
 * @param[in] ctx	the talloc context
 * @param[out] out	the value-box to return
 * @param[in] inst	data structure defining this instance of the statistics
 * @param[in] index	the field index of the structure to use
 * @return
 *	- 0 for success, and *out is non-NULL
 *	- <0 for error (memory allocation failed, index is invalid, etc), and *out is NULL
 */
int fr_stats_index_to_value_box(TALLOC_CTX *ctx, fr_value_box_t **out, fr_stats_instance_t const *inst, unsigned int index)
{
	size_t len;
	fr_value_box_t *box;
	uint8_t const *field;
	fr_dict_attr_t const *da;

	if (index >= inst->def->num_elements) {
	fail:
		*out = NULL;
		return -1;
	}

	da = *(inst->def->entry[index].da_p);
	fr_assert(da != NULL);

	box = fr_value_box_alloc(ctx, inst->def->entry[index].type, da);
	if (!box) goto fail;

	field = ((uint8_t const *) inst->stats) + inst->def->entry[index].offset;

	switch (box->type) {
	case FR_TYPE_STRING:
		if (!inst->def->entry[index].size) {
			char const *str;

			memcpy(&str, field, sizeof(str));
			len = strlen(str);
		} else {
			uint8_t const *end;

			/*
			 *	Find the trailing NUL within the fixed-size field.
			 */
			end = memchr(field, '\0', inst->def->entry[index].size);
			len = (size_t) (end - field);
		}
		break;

	case FR_TYPE_OCTETS:
	case FR_TYPE_UINT16:
	case FR_TYPE_UINT32:
	case FR_TYPE_UINT64:
	case FR_TYPE_IPV4_ADDR:
	case FR_TYPE_IPV6_ADDR:
		len = inst->def->entry[index].size;
		break;
	
	default:
		fr_strerror_printf("Unsupported data type '%s'", fr_type_to_str(box->type));
		goto fail_free;
	}

	if (fr_value_box_from_memory(box, box, box->type, da, field, len) < 0) {
	fail_free:
		talloc_free(box);
		goto fail;
	}

	*out = box;
	return 0;
}


/** Convert the statistic at the current iterator to a value-box
 *
 * @param[in] ctx	the talloc context
 * @param[out] out	the value-box to return
 * @param[in] iter	the iterator, which points to the current entry.
 * @return
 *	- 0 for success, and *out is non-NULL
 *	- <0 for error (memory allocation failed, index is invalid, etc), and *out is NULL
 */
int fr_stats_iter_to_value_box(TALLOC_CTX *ctx, fr_value_box_t **out, fr_stats_iter_t *iter)
{
	fr_assert(iter->inst);
	fr_assert(iter->current < iter->inst->def->num_elements);

	return fr_stats_index_to_value_box(ctx, out, iter->inst, iter->current);
}


/** Convert the statistic of a given name to a value-box
 *
 * @param[in] ctx	the talloc context
 * @param[out] out	the value-box to return
 * @param[in] inst	data structure defining this instance of the statistics
 * @param[in] name	the field name in the structure
 * @return
 *	- 0 for success, and *out is non-NULL
 *	- <0 for error (memory allocation failed, name is invalid, etc), and *out is NULL
 */
int fr_stats_name_to_value_box(TALLOC_CTX *ctx, fr_value_box_t **out, fr_stats_instance_t const *inst, char const *name)
{
	fr_dict_attr_t const *da;

	da = fr_dict_attr_by_name(NULL, *inst->def->root_p, name);
	if (!da) return -1;

	return fr_stats_index_to_value_box(ctx, out, inst, da->attr);
}
