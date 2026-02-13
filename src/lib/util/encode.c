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

/**
 * $Id$
 *
 * @file src/lib/util/encode.c
 * @brief Generic functions for decoding protocols.
 *
 * @copyright 2022 Network RADIUS SAS (legal@networkradius.com)
 */
#include <freeradius-devel/io/test_point.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/encode.h>

/** Encode an array of values from the network
 *
 * @param[out] dbuff		buffer to write the TLV to.
 * @param[in] da_stack		Describing nesting of options.
 * @param[in] depth		in the da_stack.
 * @param[in,out] cursor	Current attribute we're encoding.
 * @param[in] encode_ctx	Containing DHCPv4 dictionary.
 * @param[in] encode_value	Function to perform encoding of a single value.
 * @return
 *	- >0 length of data encoded.
 *	- <= 0 on error.
 */
ssize_t fr_pair_array_to_network(fr_dbuff_t *dbuff, fr_da_stack_t *da_stack, int depth,
				 fr_dcursor_t *cursor, void *encode_ctx, fr_encode_dbuff_t encode_value)
{
	ssize_t			slen;
	fr_dbuff_t		work_dbuff = FR_DBUFF(dbuff);
	fr_pair_t		*vp;
	fr_dict_attr_t const	*da = da_stack->da[depth];

	FR_PROTO_STACK_PRINT(da_stack, depth);

	if (!fr_cond_assert_msg(da->flags.array,
				"%s: Internal sanity check failed, attribute \"%s\" does not have array bit set",
				__FUNCTION__, da->name)) return PAIR_ENCODE_FATAL_ERROR;

	while (fr_dbuff_extend(&work_dbuff)) {
		fr_dbuff_t	element_dbuff = FR_DBUFF(&work_dbuff);

		/*
		 *	Encoding "no data" in an array doesn't make sense.
		 */
		slen = encode_value(&element_dbuff, da_stack, depth, cursor, encode_ctx);
		if (slen <= 0) return slen;

		fr_dbuff_set(&work_dbuff, &element_dbuff);

		vp = fr_dcursor_current(cursor);
		if (!vp || (vp->da != da)) break;		/* Stop if we have an attribute of a different type */
	}

	return fr_dbuff_set(dbuff, &work_dbuff);
}

ssize_t fr_pair_cursor_to_network(fr_dbuff_t *dbuff,
				  fr_da_stack_t *da_stack, unsigned int depth,
				  fr_dcursor_t *cursor, void *encode_ctx, fr_encode_dbuff_t encode_pair)
{
	fr_dbuff_t		work_dbuff = FR_DBUFF(dbuff);
	fr_pair_t const		*vp;
	ssize_t			len;

	while (true) {
		FR_PROTO_STACK_PRINT(da_stack, depth);

		vp = fr_dcursor_current(cursor);
		fr_assert(!vp->da->flags.internal);

		len = encode_pair(&work_dbuff, da_stack, depth + 1, cursor, encode_ctx);
		if (len < 0) return len;

		/*
		 *	If nothing updated the attribute, stop
		 */
		if (!fr_dcursor_current(cursor) || (vp == fr_dcursor_current(cursor))) break;

		vp = fr_dcursor_current(cursor);
		if (!vp) break;

		fr_proto_da_stack_build(da_stack, vp->da);
	}

	FR_PROTO_HEX_DUMP(fr_dbuff_start(&work_dbuff), fr_dbuff_used(&work_dbuff), "Done cursor");

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/** Encode a foreign reference to the network
 *
 * @param[out] dbuff		buffer to write the TLV to.
 * @param[in] da_stack		Describing nesting of options.
 * @param[in] depth		in the da_stack.
 * @param[in,out] cursor	Current attribute we're encoding.
 * @return
 *	- >0 length of data encoded.
 *	- 0 if we ran out of space.
 *	- < 0 on error.
 */
ssize_t fr_pair_ref_to_network(fr_dbuff_t *dbuff, fr_da_stack_t *da_stack, unsigned int depth,
			       fr_dcursor_t *cursor)
{
	ssize_t			slen;
	fr_dict_attr_t const	*da;
	fr_pair_t const		*vp = fr_dcursor_current(cursor);
	fr_dbuff_t		work_dbuff = FR_DBUFF(dbuff);

	fr_dict_attr_t const *ref;
	fr_dict_protocol_t const *proto;

	FR_PROTO_STACK_PRINT(da_stack, depth);

	da = da_stack->da[depth];
	fr_assert(da->type == FR_TYPE_GROUP);

	ref = fr_dict_attr_ref(da);
	if (!ref) {
		fr_strerror_printf("Invalid attribute reference for %s", da->name);
		return 0;
	}

	proto = fr_dict_protocol(ref->dict);
	fr_assert(proto != NULL);

	if (!proto->encode) {
		fr_strerror_printf("Attribute %s -> %s does not have an encoder", da->name, ref->name);
		return 0;
	}

	/*
	 *	The foreign functions don't take a cursor, so we have to update the cursor ourselves.
	 */
	slen = proto->encode(&work_dbuff, &vp->vp_group);
	if (slen < 0) return slen;

	FR_PROTO_HEX_DUMP(fr_dbuff_start(&work_dbuff), fr_dbuff_used(&work_dbuff), "group ref");

	vp = fr_dcursor_next(cursor);
	fr_proto_da_stack_build(da_stack, vp ? vp->da : NULL);

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/** Generic encode value.
 *
 */
ssize_t fr_pair_encode_value(fr_dbuff_t *dbuff, UNUSED fr_da_stack_t *da_stack, UNUSED unsigned int depth,
			      fr_dcursor_t *cursor, UNUSED void *encode_ctx)
{
	fr_pair_t const		*vp = fr_dcursor_current(cursor);
	fr_dbuff_t		work_dbuff = FR_DBUFF(dbuff);

	if (!fr_type_is_leaf(vp->vp_type)) {
		FR_PROTO_TRACE("Cannot use generic encoder for data type %s", fr_type_to_str(vp->vp_type));
		fr_strerror_printf("Cannot encode data type %s", fr_type_to_str(vp->vp_type));
		return PAIR_ENCODE_FATAL_ERROR;
	}

	if (fr_value_box_to_network(&work_dbuff, &vp->data) <= 0) return PAIR_ENCODE_FATAL_ERROR;

	(void) fr_dcursor_next(cursor);

	return fr_dbuff_set(dbuff, &work_dbuff);	
}
