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

/** Functions to encode / decode structures on the wire
 *
 * @file src/lib/util/struct.c
 *
 * @copyright 2018 The FreeRADIUS server project
 * @copyright 2018 Alan DeKok (aland@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/util/struct.h>
#include <freeradius-devel/util/encode.h>
#include <freeradius-devel/io/pair.h>

/** Convert a STRUCT to one or more VPs
 *
 */
ssize_t fr_struct_from_network(TALLOC_CTX *ctx, fr_pair_list_t *out,
			       fr_dict_attr_t const *parent, uint8_t const *data, size_t data_len,
			       void *decode_ctx,
			       fr_pair_decode_value_t decode_value, fr_pair_decode_value_t decode_tlv)
{
	unsigned int		child_num;
	uint8_t const		*p = data, *end = data + data_len;
	fr_dict_attr_t const	*child;
	fr_pair_list_t		child_list_head;
	fr_pair_list_t		*child_list;
	fr_pair_t		*vp, *key_vp, *struct_vp = NULL;
	unsigned int		offset = 0;
	TALLOC_CTX		*child_ctx;
	ssize_t			slen;

	if (data_len == 0) {
		fr_strerror_const("struct decoder was passed zero bytes of data");
		return -1; /* at least one byte of data */
	}

	FR_PROTO_HEX_DUMP(data, data_len, "fr_struct_from_network");

	/*
	 *	Start a child list.
	 */
	fr_assert(parent->type == FR_TYPE_STRUCT);

	struct_vp = fr_pair_afrom_da(ctx, parent);
	if (!struct_vp) {
		fr_strerror_const("out of memory");
		return -1;
	}

	fr_pair_list_init(&child_list_head); /* still used elsewhere */
	child_list = &struct_vp->vp_group;
	child_ctx = struct_vp;
	child_num = 1;
	key_vp = NULL;

	/*
	 *	Decode structs with length prefixes.
	 */
	if (da_is_length_field(parent)) {
		size_t claimed_len, field_len, calc_len;

		/*
		 *	Set how many bytes there are in the "length" field.
		 */
		if (parent->flags.subtype == FLAG_LENGTH_UINT8) {
			field_len = 1;
		} else {
			field_len = 2;
		}

		if ((size_t) (end - p) < field_len) {
			FR_PROTO_TRACE("Insufficient room for length field");
			goto unknown;
		}

		claimed_len = p[0];
		if (field_len > 1) {
			claimed_len <<= 8;
			claimed_len |= p[1];
		}
		p += field_len;

		if (claimed_len < da_length_offset(parent)) {
			FR_PROTO_TRACE("Length header (%zu) is smaller than minimum value (%u)",
				       claimed_len, parent->flags.type_size);
			goto unknown;
		}

		/*
		 *	Get the calculated length of the actual data.
		 */
		calc_len = claimed_len - da_length_offset(parent);

		if (calc_len > (size_t) (end - p)) {
			FR_PROTO_TRACE("Length header (%zu) is larger than remaining data (%zu)",
				       claimed_len + field_len, (size_t) (end - p));
			goto unknown;
		}

		/*
		 *	Limit the size of the decoded structure to the correct length.
		 */
		data_len = calc_len;
		end = p + data_len;
	}

	/*
	 *	@todo - If the struct is truncated on a MEMBER boundary, we silently omit
	 *	the trailing members.  Maybe this should be an error?
	 */
	while (p < end) {
		size_t child_length;

		/*
		 *	Go to the next child.  If it doesn't exist, we're done.
		 */
		child = fr_dict_attr_child_by_num(parent, child_num);
		if (!child) break;

		FR_PROTO_HEX_DUMP(p, (end - p), "fr_struct_from_network - child %s (%d)", child->name, child->attr);

		/*
		 *	Check for bit fields.
		 */
		if (da_is_bit_field(child)) {
			uint8_t array[8];
			unsigned int num_bits;
			uint64_t value;

			num_bits = offset + child->flags.length;
			if ((size_t)(end - p) < fr_bytes_from_bits(num_bits)) {
				FR_PROTO_TRACE("not enough data for bit decoder?");
				goto unknown;
			}

			memset(array, 0, sizeof(array));
			memcpy(&array[0], p, fr_bytes_from_bits(num_bits));

			if (offset > 0) array[0] &= (1 << (8 - offset)) - 1; /* mask off bits we don't care about */

			memcpy(&value, &array[0], sizeof(value));
			value = htonll(value);
			value >>= (8 - offset); /* move it to the lower bits */
			value >>= (56 - child->flags.length);

			vp = fr_pair_afrom_da(child_ctx, child);
			if (!vp) {
				FR_PROTO_TRACE("fr_struct_from_network - failed allocating child VP");
				return PAIR_DECODE_OOM;
			}

			switch (child->type) {
				case FR_TYPE_BOOL:
					vp->vp_bool = value;
					break;

				case FR_TYPE_UINT8:
					vp->vp_uint8 = value;
					break;

				case FR_TYPE_UINT16:
					vp->vp_uint16 = value;
					break;

				case FR_TYPE_UINT32:
					vp->vp_uint32 = value;
					break;

				case FR_TYPE_UINT64:
					vp->vp_uint64 = value;
					break;

				default:
					FR_PROTO_TRACE("Can't decode unknown type?");
					goto unknown;
			}

			vp->vp_tainted = true;
			fr_pair_append(child_list, vp);
			p += (num_bits >> 3); /* go to the LAST bit, not the byte AFTER the last bit */
			offset = num_bits & 0x07;
			child_num++;
			continue;
		}
		offset = 0;	/* reset for non-bit-field attributes */

		/*
		 *	Decode child TLVs, according to the parent attribute.
		 */
		if (child->type == FR_TYPE_TLV) {
			fr_assert(!key_vp);

			if (!decode_tlv) {
				fr_strerror_const("Decoding TLVs requires a decode_tlv() function to be passed");
				return -(p - data);
			}

			/*
			 *	Decode EVERYTHING as a TLV.
			 */
			while (p < end) {
				slen = decode_tlv(child_ctx, child_list, child, p, end - p, decode_ctx);
				if (slen < 0) {
					FR_PROTO_TRACE("failed decoding TLV?");
					goto unknown;
				}
				p += slen;
			}

			goto done;
		}

		child_length = child->flags.length;

		/*
		 *	If this field overflows the input, then *all*
		 *	of the input is suspect.
		 */
		if (child_length > (size_t) (end - p)) {
			FR_PROTO_TRACE("fr_struct_from_network - child length %zu overflows buffer", child_length);
			goto unknown;
		}

		/*
		 *	The child is variable sized, OR it's an array.
		 *	Eat up the rest of the data.
		 */
		if (!child_length || (child->flags.array)) {
			child_length = end - p;

		} else if ((size_t) (end - p) < child_length) {
			FR_PROTO_TRACE("fr_struct_from_network - child length %zu underflows buffer", child_length);
			goto unknown;
		}

		/*
		 *	Magic values get the callback called.
		 *
		 *	@todo - if this is an array of DNS labels, we
		 *	need to do decompression checks on the entire
		 *	block, and then decode each field
		 *	individually.
		 */
		if (decode_value) {
			if (child->flags.array) {
				slen = fr_pair_array_from_network(child_ctx, child_list, child, p, child_length, decode_ctx, decode_value);
			} else {
				slen = decode_value(child_ctx, child_list, child, p, child_length, decode_ctx);
			}
			if (slen < 0) {
				FR_PROTO_TRACE("Failed decoding value");
				goto unknown;
			}

			p += slen;   	/* not always the same as child->flags.length */
			child_num++;	/* go to the next child */
			if (fr_dict_attr_is_key_field(child)) key_vp = fr_pair_list_tail(child_list);
			continue;
		}

		/*
		 *	We only allow a limited number of data types
		 *	inside of a struct.
		 */
		switch (child->type) {
		default:
			FR_PROTO_TRACE("fr_struct_from_network - unknown child type");
			goto unknown;

		case FR_TYPE_LEAF:
			break;
		}

		/*
		 *	We don't handle this yet here.
		 */
		fr_assert(!child->flags.array);

		vp = fr_pair_afrom_da(child_ctx, child);
		if (!vp) {
			FR_PROTO_TRACE("fr_struct_from_network - failed allocating child VP");
			goto unknown;
		}

		/*
		 *	No protocol-specific data types here (yet).
		 *
		 *	If we can't decode this field, then the entire
		 *	structure is treated as a raw blob.
		 */
		if (fr_value_box_from_network(vp, &vp->data, vp->vp_type, vp->da,
					      &FR_DBUFF_TMP(p, child_length), child_length, true) < 0) {
			FR_PROTO_TRACE("fr_struct_from_network - failed decoding child VP %s", vp->da->name);
			talloc_free(vp);
		unknown:
			TALLOC_FREE(struct_vp);

			slen = fr_pair_raw_from_network(ctx, out, parent, data, data_len);
			if (slen < 0) return slen;
			return data_len;
		}

		vp->vp_tainted = true;
		fr_pair_append(child_list, vp);

		if (fr_dict_attr_is_key_field(vp->da)) key_vp = vp;

		/*
		 *	Note that we're decoding fixed fields here.
		 *	So we skip the input based on the *known*
		 *	length, and not on the *decoded* length.
		 */
		p += child_length;
		child_num++;	/* go to the next child */
	}

	/*
	 *	Is there a substructure after this one?  If so, go
	 *	decode it.
	 */
	if (key_vp) {
		fr_dict_enum_value_t const *enumv;
		child = NULL;

		FR_PROTO_HEX_DUMP(p, (end - p), "fr_struct_from_network - substruct");

		/*
		 *	Nothing more to decode, don't decode it.
		 */
		if (p >= end) {
			FR_PROTO_TRACE("Expected substruct, but there is none. We're done decoding this structure");
			goto done;
		}

		enumv = fr_dict_enum_by_value(key_vp->da, &key_vp->data);
		if (enumv) child = enumv->child_struct[0];

		if (!child) {
		unknown_child:
			/*
			 *	Always encode the unknown child as
			 *	attribute number 0.  Since the unknown
			 *	children have no "real" number, and
			 *	are all unique da's, they are
			 *	incomparable.  And thus can all be
			 *	given the same number.
			 */
			child = fr_dict_attr_unknown_raw_afrom_num(child_ctx, key_vp->da, 0);
			if (!child) {
				FR_PROTO_TRACE("failed allocating unknown child for key VP %s - %s",
					       key_vp->da->name, fr_strerror());
				goto unknown;
			}

			slen = fr_pair_raw_from_network(child_ctx, child_list, child, p, end - p);
			if (slen < 0) {
				FR_PROTO_TRACE("Failed creating raw VP from malformed or unknown substruct for child %s", child->name);
				fr_dict_attr_unknown_free(&child);
				return slen;
			}

			p = end;
		} else {
			fr_assert(child->type == FR_TYPE_STRUCT);

			slen = fr_struct_from_network(child_ctx, child_list, child, p, end - p,
						      decode_ctx, decode_value, decode_tlv);
			if (slen <= 0) {
				FR_PROTO_TRACE("substruct %s decoding failed", child->name);
				goto unknown_child;
			}
			p += slen;
		}

		fr_dict_attr_unknown_free(&child);
	}

done:
	fr_assert(struct_vp != NULL);
	fr_pair_append(out, struct_vp);

	FR_PROTO_TRACE("used %zu bytes", data_len);
	return p - data;
}


/** Put bits into an output dbuff
 *
 * @param dbuff		where the bytes go
 * @param p		where leftover bits go
 * @param start_bit	start bit in the dbuff where the data goes, 0..7
 * @param num_bits 	number of bits to write to the output, 0..55
 * @param data		data to write, all in the lower "num_bits" of the uint64_t variable
 * @return
 * 	>= 0	the next value to pass in for start_bit
 * 	<  0	no space or invalid start_bit or num_bits parameter
 */
static int put_bits_dbuff(fr_dbuff_t *dbuff, uint8_t *p, int start_bit, uint8_t num_bits, uint64_t data)
{
	uint64_t	used_bits;

	if (start_bit < 0 || start_bit > 7) return -1;
	if (num_bits < 1 || num_bits > 56) return -1;

	/* Get bits buffered in *p */
	used_bits = *p & (-256 >> start_bit);

	/* Mask out all but the least significant num_bits bits of data */
	data &= (((uint64_t) 1) << num_bits) - 1;

	/* Move it towards the most significant end and put used_bits at the top */
	data <<= (64 - (start_bit + num_bits));
	data |= used_bits << 56;

	data = htonll(data);

	start_bit += num_bits;
	if (start_bit > 7) FR_DBUFF_IN_MEMCPY_RETURN(dbuff, (uint8_t const *) &data, (size_t)(start_bit / 8));

	*p = ((uint8_t *) &data)[start_bit / 8];
	return start_bit % 8;
}

static int8_t pair_sort_increasing(void const *a, void const *b)
{
	fr_pair_t const *my_a = a;
	fr_pair_t const *my_b = b;
	int rcode;

	/*
	 *	Deeper attributes come later in the list.
	 */
	rcode = CMP_PREFER_SMALLER(my_a->da->depth, my_b->da->depth);
	if (rcode != 0) return rcode;

	return CMP_PREFER_SMALLER(my_a->da->attr, my_b->da->attr);
}

static void *struct_next_encodable(fr_dlist_head_t *list, void *current, void *uctx)
{
	fr_pair_t	*c = current;
	fr_dict_attr_t	*parent = talloc_get_type_abort(uctx, fr_dict_attr_t);

	while ((c = fr_dlist_next(list, c))) {
		PAIR_VERIFY(c);

		if (c->da->dict != parent->dict || c->da->flags.internal) continue;
		break;
	}

	return c;
}

ssize_t fr_struct_to_network(fr_dbuff_t *dbuff,
			     fr_da_stack_t *da_stack, unsigned int depth,
			     fr_dcursor_t *parent_cursor, void *encode_ctx,
			     fr_encode_dbuff_t encode_value, fr_encode_dbuff_t encode_pair)
{
	fr_dbuff_t		work_dbuff;
	fr_dbuff_marker_t	hdr;
	int			offset = 0;
	unsigned int		child_num = 1;
	bool			do_length = false;
	uint8_t			bit_buffer = 0;
	fr_pair_t const		*vp = fr_dcursor_current(parent_cursor);
	fr_dict_attr_t const   	*key_da, *parent, *tlv = NULL;
	fr_dcursor_t		child_cursor, *cursor;
	size_t			prefix_length = 0;

	if (!vp) {
		fr_strerror_printf("%s: Can't encode empty struct", __FUNCTION__);
		return PAIR_ENCODE_FATAL_ERROR;
	}

	PAIR_VERIFY(vp);
	parent = da_stack->da[depth];

	if (parent->type != FR_TYPE_STRUCT) {
		fr_strerror_printf("%s: Expected type \"struct\" got \"%s\"", __FUNCTION__,
				   fr_type_to_str(parent->type));
		return PAIR_ENCODE_FATAL_ERROR;
	}

	/*
	 *	If we get passed a struct VP, sort its children.
	 */
	if (vp->vp_type == FR_TYPE_STRUCT) {
		fr_pair_t *sorted = fr_dcursor_current(parent_cursor); /* NOT const */

		fr_pair_list_sort(&sorted->vp_group, pair_sort_increasing);
		fr_pair_dcursor_iter_init(&child_cursor, &sorted->vp_group, struct_next_encodable, parent);

		/*
		 *	Build the da_stack for the new structure.
		 */
		vp = fr_dcursor_current(&child_cursor);
		fr_proto_da_stack_build(da_stack, vp ? vp->da : NULL);

		FR_PROTO_TRACE("fr_struct_to_network encoding nested with parent %s", parent->name);
		cursor = &child_cursor;
	} else {
		FR_PROTO_TRACE("fr_struct_to_network encoding flat");
		cursor = parent_cursor;
	}

	/*
	 *	@todo - if we get a child which *eventually* has the
	 *	given parent, then allow encoding of that struct, too.
	 *	This allows us to encode structures automatically,
	 *	even if key fields are omitted.
	 *
	 *	Note that this check catches TLVs which are "flat" and
	 *	not nested.  We could fix that by adding a special
	 *	case, but it's better to just fix everything to handle
	 *	nested attributes.
	 */
	if (vp && (vp->da->parent != parent)) {
		fr_strerror_printf("%s: Asked to encode %s, but its parent %s is not the expected parent %s",
				   __FUNCTION__, vp->da->name, vp->da->parent->name, parent->name);
		return PAIR_ENCODE_FATAL_ERROR;
	}

	key_da = NULL;

	/*
	 *	Some structs are prefixed by a 16-bit length.
	 */
	if (!da_is_length_field(parent)) {
		work_dbuff = FR_DBUFF(dbuff);
	} else {
		if (parent->flags.subtype == FLAG_LENGTH_UINT8) {
			work_dbuff = FR_DBUFF_MAX(dbuff, 256);
			fr_dbuff_marker(&hdr, &work_dbuff);

			FR_DBUFF_ADVANCE_RETURN(&work_dbuff, 1);
			prefix_length = 1;
		} else {
			work_dbuff = FR_DBUFF_MAX(dbuff, 65536);
			fr_dbuff_marker(&hdr, &work_dbuff);

			FR_DBUFF_ADVANCE_RETURN(&work_dbuff, 2);
			prefix_length = 2;
		}
		do_length = true;
	}

	for (;;) {
		fr_dict_attr_t const *child;

		/*
		 *	The child attributes should be in order.  If
		 *	they're not, we fill the struct with zeroes.
		 *
		 *	The caller will encode TLVs.
		 */
		child = fr_dict_attr_child_by_num(parent, child_num);
		if (!child) break;

		FR_PROTO_TRACE("fr_struct_to_network child %s", child->name);

		/*
		 *	Encode child TLVs at the end of a struct.
		 *
		 *	In order to encode the child TLVs, we need to
		 *	know the length of "T" and "L", and we don't.
		 *	So just let the caller do the work.
		 */
		if (child->type == FR_TYPE_TLV) {
			if (offset != 0) goto leftover_bits;

			fr_assert(!key_da);

			tlv = child;
			goto done;
		}

		/*
		 *	The MEMBER may be raw, in which case it is encoded as octets.
		 *
		 *	This can happen for the last MEMBER of a struct, such as when the last member is a TLV
		 *	or GROUP, and the contents are malformed.
		 *
		 *	It can also happen if a middle MEMBER has the right length, but the wrong contents.
		 *	e.g. when the contents have to be a well-formed IP prefix, but the prefix values are
		 *	out of the permitted range.
		 */
		if (vp && (vp->da != child) && (vp->da->parent == parent) && (vp->da->attr == child_num)) {
			fr_assert(vp->vp_raw);
			fr_assert(vp->vp_type == FR_TYPE_OCTETS);
			fr_assert(!da_is_bit_field(child));

			goto raw;
		}

		/*
		 *	Skipped a VP, or left one off at the end, fill the struct with zeros.
		 */
		if (!vp || (vp->da != child)) {
			FR_PROTO_HEX_DUMP(fr_dbuff_start(&work_dbuff), fr_dbuff_used(&work_dbuff), "    no child %s", child->name);

			/*
			 *	Zero out the bit field.
			 */
			if (da_is_bit_field(child)) {
				offset = put_bits_dbuff(&work_dbuff, &bit_buffer, offset, child->flags.length, 0);
				if (offset < 0) {
					fr_strerror_printf("Failed encoding bit field %s", child->name);
					return offset;
				}
				child_num++;
				continue;
			}

			if (fr_dict_attr_is_key_field(child)) {
				key_da = child;
			}

			/*
			 *	Zero out the unused field.
			 */
			FR_DBUFF_MEMSET_RETURN(&work_dbuff, 0, child->flags.length);
			child_num++;
			continue;
		}

		/*
		 *	The 'struct' encoder handles bit fields.
		 *	They're just integers, so there's no need to
		 *	call the protocol encoder.
		 *
		 *	This limitation means that we can't have
		 *	encrypted bit fields, but that's fine.
		 */
		if (da_is_bit_field(child)) {
			uint64_t value;

			switch (child->type) {
				case FR_TYPE_BOOL:
					value = vp->vp_bool;
					break;

				case FR_TYPE_UINT8:
					value = vp->vp_uint8;
					break;

				case FR_TYPE_UINT16:
					value = vp->vp_uint16;
					break;

				case FR_TYPE_UINT32:
					value = vp->vp_uint32;
					break;

				case FR_TYPE_UINT64:
					value = vp->vp_uint64;
					break;

				default:
					fr_strerror_const("Invalid bit field");
					return PAIR_ENCODE_FATAL_ERROR;
			}

			offset = put_bits_dbuff(&work_dbuff, &bit_buffer, offset, child->flags.length, value);
			if (offset < 0) {
				fr_strerror_printf("Failed encoding bit field %s", child->name);
				return offset;
			}

			vp = fr_dcursor_next(cursor);
			/* We need to continue, there may be more fields to encode */

			goto next;
		}

		/* Not a bit field; insist that no buffered bits remain. */
		if (offset != 0) {
		leftover_bits:
			fr_strerror_const("leftover bits");
			return PAIR_ENCODE_FATAL_ERROR;
		}

		/*
		 *	Remember key_da before we do any encoding.
		 */
		if (fr_dict_attr_is_key_field(child)) {
			key_da = child;
		}

		if (encode_value) {
			ssize_t	len;
			/*
			 *	Call the protocol encoder for non-bit fields.
			 */
			fr_proto_da_stack_build(da_stack, child);

			if (child->flags.array) {
				len = fr_pair_array_to_network(&work_dbuff, da_stack, depth + 1, cursor, encode_ctx, encode_value);
			} else {
				len = encode_value(&work_dbuff, da_stack, depth + 1, cursor, encode_ctx);
			}
			if (len < 0) return len;
			vp = fr_dcursor_current(cursor);

		} else {
		redo:
			/*
			 *	Hack until we find all places that don't set data.enumv
			 */
			if (vp->da->flags.length && (vp->data.enumv != vp->da)) {
				fr_dict_attr_t const * const *c = &vp->data.enumv;
				fr_dict_attr_t **u;

				memcpy(&u, &c, sizeof(c)); /* const issues */
				memcpy(u, &vp->da, sizeof(vp->da));
			}

			/*
			 *	Determine the nested type and call the appropriate encoder
			 */
		raw:
			if (fr_value_box_to_network(&work_dbuff, &vp->data) <= 0) return PAIR_ENCODE_FATAL_ERROR;

			vp = fr_dcursor_next(cursor);
			if (!vp) break;

			if (child->flags.array && (vp->da == child)) goto redo;
		}

	next:
		FR_PROTO_HEX_DUMP(fr_dbuff_start(&work_dbuff), fr_dbuff_used(&work_dbuff), "fr_struct_to_network after child %s", child->name);
		child_num++;
	}

	/* Check for leftover bits */
	if (offset != 0) goto leftover_bits;

	/*
	 *	Check for keyed data to encode.
	 */
	if (vp && key_da) {
		FR_PROTO_TRACE("fr_struct_to_network encoding key %s", key_da->name);

		/*
		 *	If our parent is a struct, AND its parent is
		 *	the key_da, then we have a keyed struct for
		 *	the child.  Go encode it.
		 *
		 *	This check is really for "nested" VPs.
		 */
		if ((vp->da->parent == key_da) &&
		    (vp->vp_type == FR_TYPE_STRUCT)) {
			ssize_t	len;
			fr_proto_da_stack_build(da_stack, vp->da);

			len = fr_struct_to_network(&work_dbuff, da_stack, depth + 2, /* note + 2 !!! */
						   cursor, encode_ctx, encode_value, encode_pair);
			if (len < 0) return len;
			goto done;
		}

		/*
		 *	If our parent is a struct, AND its parent is
		 *	the key_da, then we have a keyed struct for
		 *	the child.  Go encode it.
		 *
		 *	This check is really for "flat" VPs.
		 */
		if ((vp->da->parent->parent == key_da) &&
		    (vp->da->parent->type == FR_TYPE_STRUCT)) {
			ssize_t	len;
			fr_proto_da_stack_build(da_stack, vp->da->parent);

			len = fr_struct_to_network(&work_dbuff, da_stack, depth + 2, /* note + 2 !!! */
						   cursor, encode_ctx, encode_value, encode_pair);
			if (len < 0) return len;
			goto done;
		}

		/*
		 *	The next VP is likely octets and unknown.
		 */
		if ((vp->da->parent == key_da) &&
		    (vp->vp_type != FR_TYPE_TLV)) {
			if (fr_value_box_to_network(&work_dbuff, &vp->data) <= 0) return PAIR_ENCODE_FATAL_ERROR;
			(void) fr_dcursor_next(cursor);
			goto done;
		}

		/*
		 *	We have no idea what to do.  Ignore it.
		 */
	}

done:
	vp = fr_dcursor_current(cursor);
	if (tlv && vp && (vp->da == tlv) && encode_pair) {
		ssize_t slen;
		fr_dcursor_t tlv_cursor;

		if (!encode_pair) {
			fr_strerror_printf("Asked to encode child attribute %s, but we were not passed an encoding function",
					   tlv->name);
			return PAIR_ENCODE_FATAL_ERROR;
		}

		fr_assert(fr_type_is_structural(vp->vp_type));

		vp = fr_pair_dcursor_init(&tlv_cursor, &vp->vp_group);
		if (vp) {
			FR_PROTO_TRACE("fr_struct_to_network trailing TLVs of %s", tlv->name);
			fr_proto_da_stack_build(da_stack, vp->da);
			FR_PROTO_STACK_PRINT(da_stack, depth);

			slen = fr_pair_cursor_to_network(&work_dbuff, da_stack, depth + 1, &tlv_cursor, encode_ctx, encode_pair);
			if (slen < 0) return slen;
		}
	}

	if (do_length) {
		size_t length = fr_dbuff_used(&work_dbuff);

#ifdef __COVERITY__
		/*
		 * 	Coverity somehow can't infer that length
		 * 	is at least as long as the prefix, instead
		 * 	thinkings it's zero so that it underflows.
		 * 	We therefore add a Coverity-only check to
		 * 	reassure it.
		 */
		if (length < prefix_length) return PAIR_ENCODE_FATAL_ERROR;
#endif
		if (parent->flags.subtype == FLAG_LENGTH_UINT8) {
			length -= prefix_length;

			length += da_length_offset(parent);

			if (length > UINT8_MAX) return PAIR_ENCODE_FATAL_ERROR;

			(void) fr_dbuff_in(&hdr, (uint8_t) length);
		} else {
			length -= prefix_length;

			length += da_length_offset(parent);

			if (length > UINT16_MAX) return PAIR_ENCODE_FATAL_ERROR;

			(void) fr_dbuff_in(&hdr, (uint16_t) length);
		}
	}

	/*
	 *	We've encoded the children, so tell the parent cursor
	 *	that we've encoded the parent.
	 */
	if (cursor != parent_cursor) (void) fr_dcursor_next(parent_cursor);

	FR_PROTO_HEX_DUMP(fr_dbuff_start(&work_dbuff), fr_dbuff_used(&work_dbuff), "Done fr_struct_to_network");

	return fr_dbuff_set(dbuff, &work_dbuff);
}
