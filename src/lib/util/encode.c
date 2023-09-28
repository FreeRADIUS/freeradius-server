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
 *	- 0 if we ran out of space.
 *	- < 0 on error.
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

		slen = encode_value(&element_dbuff, da_stack, depth, cursor, encode_ctx);
		if (slen < 0) return slen;

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
	fr_dict_attr_t const	*da = da_stack->da[depth];
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

		/*
		 *	We can encode multiple children, if after
		 *	rebuilding the DA Stack, the attribute at this
		 *	depth is the same.
		 */
		if ((da != da_stack->da[depth]) || (da_stack->depth < da->depth)) break;
	}

	FR_PROTO_HEX_DUMP(fr_dbuff_start(&work_dbuff), fr_dbuff_used(&work_dbuff), "Done cursor");

	return fr_dbuff_set(dbuff, &work_dbuff);
}
