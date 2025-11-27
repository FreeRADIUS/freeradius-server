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
	fr_dict_attr_t const	*child, *substruct_da;
	fr_pair_list_t		child_list_head;
	fr_pair_list_t		*child_list;
	fr_pair_t		*vp, *key_vp, *struct_vp = NULL;
	unsigned int		offset = 0;
	TALLOC_CTX		*child_ctx;
	ssize_t			slen;
	size_t			child_length;

	if (data_len == 0) {
		fr_strerror_const("struct decoder was passed zero bytes of data");
		return -1; /* at least one byte of data */
	}

	FR_PROTO_TRACE("Decoding struct %s", parent->name);
	FR_PROTO_HEX_DUMP(data, data_len, "fr_struct_from_network");

	/*
	 *	Start a child list.
	 */
	fr_assert(parent->type == FR_TYPE_STRUCT);

	struct_vp = fr_pair_afrom_da(ctx, parent);
	if (!struct_vp) {
		return PAIR_DECODE_OOM;
	}

	fr_pair_list_init(&child_list_head); /* still used elsewhere */
	child_list = &struct_vp->vp_group;
	child_ctx = struct_vp;
	key_vp = NULL;

	/*
	 *	Simplify the code by having a generic decode routine.
	 */
	if (!decode_value) decode_value = fr_pair_decode_value;

	/*
	 *	Decode structs with length prefixes.
	 */
	if (da_is_length_field(parent)) {
		size_t claimed_len, field_len, calc_len;

		/*
		 *	Set how many bytes there are in the "length" field.
		 */
		if (da_is_length_field8(parent)) {
			field_len = 1;
		} else {
			fr_assert(da_is_length_field16(parent));
			field_len = 2;
		}

		if ((size_t) (end - p) < field_len) {
			FR_PROTO_TRACE("Insufficient room for length field");

		invalid_struct:
			/*
			 *	Some field could not be decoded.  Nuke the entire struct, and just make the
			 *	whole thing "raw".
			 */
			TALLOC_FREE(struct_vp);

			slen = fr_pair_raw_from_network(ctx, out, parent, data, data_len);
			if (slen < 0) return slen;
			return data_len;
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
			goto invalid_struct;
		}

		/*
		 *	Get the calculated length of the actual data.
		 */
		calc_len = claimed_len - da_length_offset(parent);

		if (calc_len > (size_t) (end - p)) {
			FR_PROTO_TRACE("Length header (%zu) is larger than remaining data (%zu)",
				       claimed_len + field_len, (size_t) (end - p));
			goto invalid_struct;
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
	for (child_num = 1;
	     (p < end) && (child = fr_dict_attr_child_by_num(parent, child_num)) != NULL;
	     child_num++) {
		FR_PROTO_TRACE("Decoding struct %s child %s (%d)", parent->name, child->name, child->attr);
		FR_PROTO_HEX_DUMP(p, (end - p), "fr_struct_from_network - remaining %zu", (size_t) (end - p));

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
				goto remainder_raw;
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
			oom:
				talloc_free(struct_vp);
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
					goto remainder_raw;
			}

			vp->vp_tainted = true;
			fr_pair_append(child_list, vp);

			p += (num_bits >> 3); /* go to the LAST bit, not the byte AFTER the last bit */
			offset = num_bits & 0x07;
			continue;
		}

		fr_assert(offset == 0);
		offset = 0;	/* reset for non-bit-field attributes */

		/*
		 *	The child is either unknown width, OR known width with a length that is too large for
		 *	the "length" field, OR is known width via some kind of protocol-specific length header.
		 */
		if (!child->flags.length || child->flags.array) {
			child_length = end - p;

		} else {
			child_length = child->flags.length;

			/*
			 *	If this field overflows the input, then *all*
			 *	of the input is suspect.
			 */
			if (child_length > (size_t) (end - p)) {
				FR_PROTO_TRACE("fr_struct_from_network - child length %zu overflows buffer", child_length);
				goto remainder_raw;
			}
		}

		/*
		 *	We only allow a limited number of data types
		 *	inside of a struct.
		 */
		switch (child->type) {
		case FR_TYPE_INTERNAL:
		case FR_TYPE_NULL:
			FR_PROTO_TRACE("fr_struct_from_network - unknown child type");
			goto remainder_raw;

		case FR_TYPE_STRUCT:
		case FR_TYPE_VSA:
		case FR_TYPE_VENDOR:
		case FR_TYPE_GROUP:
		case FR_TYPE_LEAF:
			break;

		/*
		 *	Decode child TLVs, according to the parent attribute.
		 */
		case FR_TYPE_TLV:
			fr_assert(!key_vp);

			if (!decode_tlv) {
				fr_strerror_const("Decoding TLVs requires a decode_tlv() function to be passed");
				talloc_free(struct_vp);
				return -(p - data);
			}

			/*
			 *	Decode all of the remaining data as
			 *	TLVs.  Any malformed TLVs are appended
			 *	as raw VP.
			 */
			while (p < end) {
				slen = decode_tlv(child_ctx, child_list, child, p, end - p, decode_ctx);
				if (slen < 0) {
					FR_PROTO_TRACE("failed decoding TLV?");
					goto remainder_raw;
				}
				p += slen;
			}

			goto done;

		/*
		 *	The child is a union, it MUST be at the end of
		 *	the struct, and we must have seen a key before
		 *	we reach the union.  See dict_tokenize.
		 */
		case FR_TYPE_UNION:
			fr_assert(!fr_dict_attr_child_by_num(parent, child_num + 1));
			if (!key_vp) {
			remainder_raw:
				child_length = end - p;
				goto raw;
			}

			/*
			 *	Create the union wrapper, and reset the child_ctx and child_list to it.
			 */
			vp = fr_pair_afrom_da(child_ctx, child);
			if (!vp) goto oom;

			fr_pair_append(child_list, vp);
			substruct_da = child;
			child_ctx = vp;
			child_list = &vp->vp_group;
			goto substruct;
		}

		/*
		 *	Magic values get the callback called.
		 *
		 *	@todo - if this is an array of DNS labels, we
		 *	need to do decompression checks on the entire
		 *	block, and then decode each field
		 *	individually.
		 */
		if (child->flags.array) {
			slen = fr_pair_array_from_network(child_ctx, child_list, child, p, child_length, decode_ctx, decode_value);
		} else {
			slen = decode_value(child_ctx, child_list, child, p, child_length, decode_ctx);
		}
		if (slen < 0) {
			FR_PROTO_TRACE("Failed decoding value");

		raw:
			slen = fr_pair_raw_from_network(child_ctx, child_list, child, p, child_length);
			if (slen < 0) {
				talloc_free(struct_vp);
				return slen;
			}
		}

		p += slen;   	/* not always the same as child->flags.length */

		if (fr_dict_attr_is_key_field(child)) {
			fr_assert(!key_vp);
			key_vp = fr_pair_list_tail(child_list);
		}
	}

	/*
	 *	Is there a substructure after this one?  If so, go
	 *	decode it.
	 */
	if (key_vp) {
		fr_dict_enum_value_t const *enumv;

		substruct_da = key_vp->da;

	substruct:
		child = NULL;

		FR_PROTO_TRACE("Key %s", key_vp->da->name);
		FR_PROTO_HEX_DUMP(p, (end - p), "fr_struct_from_network - child structure");

		/*
		 *	Nothing more to decode, don't decode it.
		 */
		if (p >= end) {
			FR_PROTO_TRACE("Expected substruct, but there is none. We're done decoding this structure");
			goto done;
		}

		enumv = fr_dict_enum_by_value(key_vp->da, &key_vp->data);
		if (enumv) child = fr_dict_enum_attr_ref(enumv);

		if (!child) {
			/*
			 *	Always encode the unknown child as attribute number 0.  Since the unknown
			 *	children have no "real" number, and are all unique da's, they are
			 *	incomparable.  And thus can all be given the same number.
			 */
			uint64_t attr = 0;

			FR_PROTO_TRACE("No matching child structure found");
		unknown_child:

			/*
			 *	But if we have a key field, the unknown attribute number is taken from the
			 *	from the key field.
			 */
			if (fr_type_is_integer(key_vp->vp_type)) {
				attr = fr_value_box_as_uint64(&key_vp->data);
			}

			child = fr_dict_attr_unknown_raw_afrom_num(child_ctx, substruct_da, attr);
			if (!child) {
				FR_PROTO_TRACE("failed allocating unknown child for key VP %s - %s",
					       key_vp->da->name, fr_strerror());
				goto oom;
			}

			slen = fr_pair_raw_from_network(child_ctx, child_list, child, p, end - p);
			if (slen < 0) {
				FR_PROTO_TRACE("Failed creating raw VP from malformed or unknown substruct for child %s", child->name);
				fr_dict_attr_unknown_free(&child);
				return slen;
			}

			p = end;

		} else {
			switch (child->type) {
			case FR_TYPE_STRUCT:
				FR_PROTO_TRACE("Decoding child structure %s", child->name);
				slen = fr_struct_from_network(child_ctx, child_list, child, p, end - p,
							      decode_ctx, decode_value, decode_tlv);
				break;

			case FR_TYPE_TLV:
				if (!decode_tlv) {
					FR_PROTO_TRACE("Failed to pass decode_tlv() for child tlv %s", child->name);
					goto unknown_child;
				}

				FR_PROTO_TRACE("Decoding child tlv %s", child->name);

				slen = decode_tlv(child_ctx, child_list, child, p, end - p, decode_ctx);
				break;

			case FR_TYPE_LEAF:
				fr_assert(decode_value);

				FR_PROTO_TRACE("Decoding child %s", child->name);

				/*
				 *	@todo - unify this code with the code above, but for now copying is
				 *	easier.
				 */

				/*
				 *	The child is either unknown width, OR known width with a length that is too large for
				 *	the "length" field, OR is known width via some kind of protocol-specific length header.
				 */
				if (!child->flags.length || child->flags.array) {
					child_length = end - p;

				} else {
					child_length = child->flags.length;

					/*
					 *	If this field overflows the input, then *all*
					 *	of the input is suspect.
					 */
					if (child_length > (size_t) (end - p)) {
						FR_PROTO_TRACE("fr_struct_from_network - child length %zu overflows buffer", child_length);
						goto remainder_raw;
					}
				}

				if (child->flags.array) {
					slen = fr_pair_array_from_network(child_ctx, child_list, child, p, child_length, decode_ctx, decode_value);
				} else {
					slen = decode_value(child_ctx, child_list, child, p, child_length, decode_ctx);
				}
				break;

			default:
				FR_PROTO_TRACE("Unknown data type %s in child %s", fr_type_to_str(child->type), child->name);
				goto unknown_child;
			}

			if (slen <= 0) {
				FR_PROTO_TRACE("failed decoding child %s", child->name);
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
	int8_t ret;

	/*
	 *	Deeper attributes come later in the list.
	 */
	ret = CMP_PREFER_SMALLER(my_a->da->depth, my_b->da->depth);
	if (ret != 0) return ret;

	return CMP_PREFER_SMALLER(my_a->da->attr, my_b->da->attr);
}

static void *struct_next_encodable(fr_dcursor_t *cursor, void *current, void *uctx)
{
	fr_pair_t	*c = current;
	fr_dict_attr_t	*parent = talloc_get_type_abort(uctx, fr_dict_attr_t);

	while ((c = fr_dlist_next(cursor->dlist, c))) {
		PAIR_VERIFY(c);

		if (c->da->dict != parent->dict || c->da->flags.internal) continue;
		break;
	}

	return c;
}

static ssize_t encode_tlv(fr_dbuff_t *dbuff, fr_dict_attr_t const *tlv,
			  fr_da_stack_t *da_stack, unsigned int depth,
			  fr_dcursor_t *cursor, void *encode_ctx,
			  UNUSED fr_encode_dbuff_t encode_value, fr_encode_dbuff_t encode_pair)

{
	fr_pair_t	*vp;
	fr_dcursor_t	child_cursor;
	fr_dbuff_t	work_dbuff = FR_DBUFF(dbuff);

	if (!encode_pair) {
		fr_strerror_printf("Asked to encode child attribute %s, but we were not passed an encoding function",
				   tlv->name);
		return PAIR_ENCODE_FATAL_ERROR;
	}

	vp = fr_dcursor_current(cursor);
	if (!vp || (vp->da != tlv)) return 0;

	vp = fr_pair_dcursor_init(&child_cursor, &vp->vp_group);
	if (vp) {
		ssize_t slen;

		FR_PROTO_TRACE("fr_struct_to_network trailing TLVs of %s", tlv->name);
		fr_proto_da_stack_build(da_stack, vp->da);
		FR_PROTO_STACK_PRINT(da_stack, depth);

		slen = fr_pair_cursor_to_network(&work_dbuff, da_stack, depth + 1, &child_cursor, encode_ctx, encode_pair);
		if (slen < 0) return slen;
	}

	return fr_dbuff_set(dbuff, &work_dbuff);
}

static ssize_t encode_union(fr_dbuff_t *dbuff, fr_dict_attr_t const *wrapper,
			    fr_dict_attr_t const *key_da, fr_pair_t const *key_vp, fr_dbuff_marker_t *key_m,
			    fr_da_stack_t *da_stack, unsigned int depth,
			    fr_dcursor_t *cursor, void *encode_ctx,
			    UNUSED fr_encode_dbuff_t encode_value, fr_encode_dbuff_t encode_pair)

{
	ssize_t		slen;
	fr_pair_t	*parent, *child, *found = NULL;
	fr_dict_attr_t const *child_ref;
	fr_dcursor_t	child_cursor;
	fr_dbuff_t	work_dbuff = FR_DBUFF(dbuff);

	parent = fr_dcursor_current(cursor);
	if (!parent || (parent->da != wrapper)) return 0;

	fr_assert(key_vp);	/* @todo */

	child = fr_pair_dcursor_init(&child_cursor, &parent->vp_group);
	if (!child) {
		/*
		 *	@todo - do we want to skip encoding the entire parent structure?
		 */
		FR_PROTO_TRACE("fr_struct_to_network union %s has no children", key_da->name);
		return 0;
	}

	/*
	 *	There's a key VP, we find the matching child struct, and then set the cursor to encode just
	 *	that child.
	 */
	if (key_vp) {
		fr_dict_enum_value_t const *enumv;

		enumv = fr_dict_enum_by_value(key_da, &key_vp->data);
		if (enumv && ((child_ref = fr_dict_enum_attr_ref(enumv)) != NULL)) {
			found = fr_pair_find_by_da(&parent->vp_group, NULL, child_ref);
			if (found) {
				(void) fr_dcursor_set_current(&child_cursor, found);
			}
		}
	}

	/*
	 *	No child matching the key vp was found.  Either there's no key_vp, or the key_vp doesn't match
	 *	the chld we have.
	 *
	 *	We then update the key field so that it corresponds to the child that we found.
	 */
	if (!found) {
		fr_dict_enum_value_t const *enumv;
		fr_dict_enum_iter_t iter;
		fr_dbuff_t key_dbuff;

		/*
		 *	Root through the enum values, looking for a child ref which matches the child we
		 *	found.
		 */
		for (enumv = fr_dict_enum_iter_init(key_da, &iter);
		     enumv != NULL;
		     enumv = fr_dict_enum_iter_next(key_da, &iter)) {
			child_ref = fr_dict_enum_attr_ref(enumv);
			if (!child_ref) continue;

			if (child_ref == child->da) break;
		}

		/*
		 *	There's a child, but no matching enum.  That's a fatal error of the dictionary
		 *	tokenizer.
		 */
		if (!fr_cond_assert(enumv)) return PAIR_ENCODE_FATAL_ERROR;

		/*
		 *	Create a dbuff for the key, and encode the key.
		 *
		 *	Note that enumv->value->vb_length is NOT set. That field is really only used for
		 *	string / octet data types.
		 */
		fr_assert(key_da->flags.length >= 1);
		fr_assert(key_da->flags.length <= 4);

		FR_DBUFF_INIT(&key_dbuff, fr_dbuff_current(key_m), (size_t) key_da->flags.length);

		FR_PROTO_TRACE("fr_struct_to_network union %s encoding key %s for child %s",
			       parent->da->name, key_da->name, child->da->name);

		if (fr_value_box_to_network(&key_dbuff, enumv->value) <= 0) return PAIR_ENCODE_FATAL_ERROR;
	}

	/*
	 *	And finally encode the one child.
	 */
	FR_PROTO_TRACE("fr_struct_to_network union %s encoding child %s", parent->da->name, child->da->name);
	fr_proto_da_stack_build(da_stack, child->da);
	FR_PROTO_STACK_PRINT(da_stack, depth);

	switch (child->da->type) {
	case FR_TYPE_STRUCT:
		slen = fr_struct_to_network(&work_dbuff, da_stack, depth + 2,
					    &child_cursor, encode_ctx, encode_value, encode_pair);
		break;

	case FR_TYPE_TLV:
		slen = encode_tlv(&work_dbuff, child->da, da_stack, depth + 2, &child_cursor, encode_ctx, encode_value, encode_pair);
		break;

	case FR_TYPE_LEAF:
		slen = encode_value(&work_dbuff, da_stack, depth + 2, &child_cursor, encode_ctx);
		break;

	default:
		slen = 0;
		break;
	}

	if (slen < 0) return slen;

	/*
	 *	@todo - if there is more than one child of the union, that's an error!
	 */

	return fr_dbuff_set(dbuff, &work_dbuff);
}

static ssize_t encode_keyed_struct(fr_dbuff_t *dbuff, fr_pair_t const *vp,
				   fr_da_stack_t *da_stack, unsigned int depth,
				   fr_dcursor_t *cursor, void *encode_ctx,
				   fr_encode_dbuff_t encode_value, fr_encode_dbuff_t encode_pair)
{
	FR_PROTO_TRACE("fr_struct_to_network encoding key %s", vp->da->name);

	/*
	 *	We usually have a keyed struct for the child.
	 */
	if (vp->vp_type == FR_TYPE_STRUCT) {
		fr_proto_da_stack_build(da_stack, vp->da);
		return fr_struct_to_network(dbuff, da_stack, depth + 2, /* note + 2 !!! */
					    cursor, encode_ctx, encode_value, encode_pair);
	}

	/*
	 *	If it's not a real child, then it's a raw something.
	 */
	fr_assert(vp->vp_type == FR_TYPE_OCTETS);
	fr_assert(vp->da->flags.is_unknown);

	if (fr_value_box_to_network(dbuff, &vp->data) <= 0) return PAIR_ENCODE_FATAL_ERROR;
	(void) fr_dcursor_next(cursor);
	return 0;
}

ssize_t fr_struct_to_network(fr_dbuff_t *dbuff,
			     fr_da_stack_t *da_stack, unsigned int depth,
			     fr_dcursor_t *parent_cursor, void *encode_ctx,
			     fr_encode_dbuff_t encode_value, fr_encode_dbuff_t encode_pair)
{
	fr_dbuff_t		work_dbuff;
	fr_dbuff_marker_t	hdr;
	int			offset = 0;
	unsigned int		child_num;
	bool			do_length = false;
	uint8_t			bit_buffer = 0;
	fr_pair_t const		*vp = fr_dcursor_current(parent_cursor);
	fr_pair_t const		*key_vp = NULL;
	fr_dict_attr_t const   	*child, *parent, *key_da = NULL;
	fr_dcursor_t		child_cursor, *cursor;
	size_t			prefix_length = 0;
	ssize_t			slen;
	fr_dbuff_marker_t	key_m;

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

	/*
	 *	Some structs are prefixed by a 16-bit length.
	 */
	if (!da_is_length_field(parent)) {
		work_dbuff = FR_DBUFF(dbuff);

	} else if (da_is_length_field8(parent)) {
		work_dbuff = FR_DBUFF_MAX(dbuff, UINT8_MAX);
		fr_dbuff_marker(&hdr, &work_dbuff);

		FR_DBUFF_ADVANCE_RETURN(&work_dbuff, 1);
		prefix_length = 1;
		do_length = true;

	} else {
		fr_assert(da_is_length_field16(parent));

		work_dbuff = FR_DBUFF_MAX(dbuff, UINT16_MAX);
		fr_dbuff_marker(&hdr, &work_dbuff);

		FR_DBUFF_ADVANCE_RETURN(&work_dbuff, 2);
		prefix_length = 2;
		do_length = true;
	}

	if (!encode_value) encode_value = fr_pair_encode_value;

	/*
	 *	Loop over all children.
	 */
	for (child_num = 1;
	     (child = fr_dict_attr_child_by_num(parent, child_num)) != NULL;
	     child_num++) {
		/*
		 *	The child attributes should be in order.  If
		 *	they're not, we fill the struct with zeroes.
		 *
		 *	The caller will encode TLVs.
		 */
		FR_PROTO_TRACE("fr_struct_to_network child %s", child->name);

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

			goto encode_data; /* we may have a raw entry in an array :( */
		}

		/*
		 *	Remember the key field.  Note that we ignore raw key fields.
		 */
		if (fr_dict_attr_is_key_field(child)) {
			fr_assert(!key_da);

			key_da = child;
			key_vp = vp;
			fr_dbuff_marker(&key_m, &work_dbuff);
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
				continue;
			}

			/*
			 *	A child TLV is missing, we're done, and we don't encode any data.
			 *
			 *	@todo - mark up the TLVs as required?
			 */
			if (child->type == FR_TYPE_TLV) goto encode_length;

			/*
			 *	Zero out the unused field.
			 */
			FR_DBUFF_MEMSET_RETURN(&work_dbuff, 0, child->flags.length);
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

			FR_PROTO_TRACE("child %s is a bit field", child->name);

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
		 *	Encode child TLVs at the end of a struct.
		 *
		 *	In order to encode the child TLVs, we need to
		 *	know the length of "T" and "L", and we don't.
		 *	So just let the caller do the work.
		 */
		if (child->type == FR_TYPE_TLV) {
			fr_assert(!key_da);

			FR_PROTO_TRACE("child %s is a TLV field", child->name);
			slen = encode_tlv(&work_dbuff, child, da_stack, depth, cursor,
					  encode_ctx, encode_value, encode_pair);
			if (slen < 0) return slen;
			goto encode_length;
		}

		if (child->type == FR_TYPE_UNION) {
			FR_PROTO_TRACE("child %s is a UNION field", child->name);

			if (!key_da) {
				FR_PROTO_TRACE("structure %s is missing key_da", parent->name);
				goto encode_length;
			}

			slen = encode_union(&work_dbuff, child, key_da, key_vp, &key_m, da_stack, depth, cursor,
					    encode_ctx, encode_value, encode_pair);
			if (slen < 0) return slen;
			goto encode_length;
		}

		FR_PROTO_TRACE("child %s encode_value", child->name);

		/*
		 *	Call the protocol encoder for non-bit fields.
		 */
	encode_data:
		fr_proto_da_stack_build(da_stack, child);

		if (child->flags.array) {
			slen = fr_pair_array_to_network(&work_dbuff, da_stack, depth + 1, cursor, encode_ctx, encode_value);
		} else {
			slen = encode_value(&work_dbuff, da_stack, depth + 1, cursor, encode_ctx);
		}
		if (slen < 0) return slen;
		vp = fr_dcursor_current(cursor);

	next:
		FR_PROTO_HEX_DUMP(fr_dbuff_start(&work_dbuff), fr_dbuff_used(&work_dbuff), "fr_struct_to_network after child %s", child->name);
	}

	/* Check for leftover bits */
	if (offset != 0) goto leftover_bits;

	/*
	 *	Check for keyed data to encode.
	 */
	if (vp && key_da) {
		fr_assert((vp->da->parent->type == FR_TYPE_UNION) || (vp->da->parent == key_da) || vp->da->flags.is_unknown || vp->da->flags.is_raw);

		slen = encode_keyed_struct(&work_dbuff, vp, da_stack, depth,
					   cursor, encode_ctx, encode_value, encode_pair);
		if (slen < 0) return slen;
	}

encode_length:
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
		if (da_is_length_field8(parent)) {
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
