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
#include <freeradius-devel/util/proto.h>

/*
 *	Context wrapper to let us, pro tempore, support both dbuff and ptr/len flavored
 *	struct-to-network encoding without code replication.
 */

typedef struct {
     void		*ectx;
     fr_encode_value_t	encoder;
} encode_ctx_wrapper;

fr_pair_t *fr_raw_from_network(TALLOC_CTX *ctx, fr_dict_attr_t const *parent, uint8_t const *data, size_t data_len)
{
	fr_pair_t *vp;
	fr_dict_attr_t *unknown;
	fr_dict_attr_t const *child;

#if defined(__clang_analyzer__) || !defined(NDEBUG)
	if (!parent->parent) return NULL; /* stupid static analyzers */
#endif

	/*
	 *	Build an unknown attr of the entire STRUCT.
	 */
	unknown = fr_dict_unknown_attr_afrom_da(ctx, parent);
	if (!unknown) return NULL;
	unknown->flags.is_raw = 1;

	vp = fr_pair_afrom_da(ctx, unknown); /* makes a copy of 'child' */
	child = unknown;
	fr_dict_unknown_free(&child);
	if (!vp) return NULL;

	if (fr_value_box_from_network(vp, &vp->data, vp->da->type, vp->da, data, data_len, true) < 0) {
		fr_pair_list_free(&vp);
		return NULL;
	}

	vp->type = VT_DATA;
	return vp;
}



/** Convert a STRUCT to one or more VPs
 *
 */
ssize_t fr_struct_from_network(TALLOC_CTX *ctx, fr_cursor_t *cursor,
			       fr_dict_attr_t const *parent, uint8_t const *data, size_t data_len,
			       fr_dict_attr_t const **child_p,
			       fr_decode_value_t decode_value, void *decoder_ctx)
{
	unsigned int		child_num;
	uint8_t const		*p = data, *end = data + data_len;
	fr_dict_attr_t const	*child;
	fr_pair_list_t		head;
	fr_cursor_t		child_cursor;
	fr_pair_t		*vp, *key_vp;
	unsigned int		offset = 0;

	fr_pair_list_init(&head);
	if (data_len < 1) return -1; /* at least one byte of data */

	FR_PROTO_HEX_DUMP(data, data_len, "fr_struct_from_network");

	/*
	 *	Record where we were in the list when this function was called
	 */
	fr_cursor_init(&child_cursor, &head);
	*child_p = NULL;
	child_num = 1;
	key_vp = NULL;

	/*
	 *	Decode structs with length prefixes.
	 */
	if (da_is_length_field(parent)) {
		size_t struct_len;

		struct_len = (p[0] << 8) | p[1];
		if ((struct_len + 2) > data_len) goto unknown;

		data_len = struct_len + 2;
		end = data + data_len;
		p += 2;
	}

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
			if ((end - p) < fr_bytes_from_bits(num_bits)) goto unknown;

			memset(array, 0, sizeof(array));
			memcpy(&array[0], p, fr_bytes_from_bits(num_bits));

			if (offset > 0) array[0] &= (1 << (8 - offset)) - 1; /* mask off bits we don't care about */

			memcpy(&value, &array[0], sizeof(value));
			value = htonll(value);
			value >>= (8 - offset); /* move it to the lower bits */
			value >>= (56 - child->flags.length);

			vp = fr_pair_afrom_da(ctx, child);
			if (!vp) {
				FR_PROTO_TRACE("fr_struct_from_network - failed allocating child VP");
				goto unknown;
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
					goto unknown;
			}

			vp->type = VT_DATA;
			vp->vp_tainted = true;
			fr_cursor_append(&child_cursor, vp);
			p += (num_bits >> 3); /* go to the LAST bit, not the byte AFTER the last bit */
			offset = num_bits & 0x07;
			child_num++;
			continue;
		}
		offset = 0;	/* reset for non-bit-field attributes */

		/*
		 *	Decode child TLVs, according to the parent attribute.
		 *
		 *	Return only PARTIALLY decoded data.  Let the
		 *	caller decode the rest.
		 *
		 *	@todo - pass TLVs to the "decode_value"
		 *	function, so it can decode them.
		 */
		if (child->type == FR_TYPE_TLV) {
			*child_p = child;

			fr_cursor_head(&child_cursor);
			fr_cursor_tail(cursor);
			fr_cursor_merge(cursor, &child_cursor);	/* Wind to the end of the new pairs */
			return (p - data);
		}

		child_length = child->flags.length;

		/*
		 *	If this field overflows the input, then *all*
		 *	of the input is suspect.
		 */
		if ((p + child_length) > end) {
			FR_PROTO_TRACE("fr_struct_from_network - child length %zd overflows buffer", child_length);
			goto unknown;
		}

		if (!child_length) child_length = (end - p);

		/*
		 *	Magic values get the callback called.
		 *
		 *	Note that if this is an *array* of DNS labels,
		 *	the callback should deal with this.
		 */
		if (decode_value) {
			ssize_t slen;

			slen = decode_value(ctx, &child_cursor, fr_dict_by_da(child), child, p, child_length, decoder_ctx);
			if (slen < 0) return slen - (p - data);

			p += slen;   	/* not always the same as child->flags.length */
			child_num++;	/* go to the next child */
			if (da_is_key_field(child)) key_vp = fr_cursor_tail(&child_cursor);
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

		case FR_TYPE_VALUE:
			break;
		}

		vp = fr_pair_afrom_da(ctx, child);
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
		if (fr_value_box_from_network(vp, &vp->data, vp->da->type, vp->da, p, child_length, true) < 0) {
			FR_PROTO_TRACE("fr_struct_from_network - failed decoding child VP");
			fr_pair_list_free(&vp);
		unknown:
			fr_pair_list_free(&head);

			vp = fr_raw_from_network(ctx, parent, data, data_len);
			if (!vp) return -1;

			/*
			 *	And append this one VP to the output cursor.
			 */
			fr_cursor_append(cursor, vp);
			return data_len;
		}

		vp->type = VT_DATA;
		vp->vp_tainted = true;
		fr_cursor_append(&child_cursor, vp);

		if (da_is_key_field(vp->da)) key_vp = vp;

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
		ssize_t slen;
		fr_dict_enum_t const *enumv;
		child = NULL;

		FR_PROTO_HEX_DUMP(p, (end - p), "fr_struct_from_network - substruct");

		/*
		 *	Nothing more to decode, don't decode it.
		 */
		if (p >= end) goto done;

		enumv = fr_dict_enum_by_value(key_vp->da, &key_vp->data);
		if (enumv) child = enumv->child_struct[0];

		if (!child) {
		unknown_child:
			/*
			 *	Encode the unknown child as attribute
			 *	number 0.  This choice means we don't
			 *	have to look up, or keep track of, the
			 *	number of children of the key field.
			 */
			child = fr_dict_unknown_afrom_fields(ctx, key_vp->da,
							     fr_dict_vendor_num_by_da(key_vp->da), 0);
			if (!child) goto unknown;

			vp = fr_raw_from_network(ctx, child, p, end - p);
			if (!vp) {
				fr_dict_unknown_free(&child);
				return -(p - data);
			}

			fr_cursor_append(&child_cursor, vp);
			p = end;
		} else {
			fr_assert(child->type == FR_TYPE_STRUCT);

			slen = fr_struct_from_network(ctx, &child_cursor, child, p, end - p, child_p,
						      decode_value, decoder_ctx);
			if (slen <= 0) goto unknown_child;
			p += slen;
		}

		fr_dict_unknown_free(&child);

		fr_cursor_head(&child_cursor);
		fr_cursor_tail(cursor);
		fr_cursor_merge(cursor, &child_cursor);	/* Wind to the end of the new pairs */

		/*
		 *	Else return whatever we decoded.  Note that if
		 *	the substruct ends in a TLV, we decode only
		 *	the fixed-length portion of the structure.
		 */
		return p - data;
	}

done:
	fr_cursor_head(&child_cursor);
	fr_cursor_tail(cursor);
	fr_cursor_merge(cursor, &child_cursor);	/* Wind to the end of the new pairs */

	return data_len;
}

static ssize_t wrapped_encoder(fr_dbuff_t *dbuff, fr_da_stack_t *da_stack, unsigned int depth,
					   fr_cursor_t *cursor, void *encoder_ctx)
{
	encode_ctx_wrapper	*wrapper = (encode_ctx_wrapper *) encoder_ctx;
	ssize_t			slen;

	slen = wrapper->encoder(dbuff->p, fr_dbuff_remaining(dbuff), da_stack, depth, cursor, wrapper->ectx);
	if (slen < 0) return slen;
	return fr_dbuff_advance(dbuff, slen);
}

ssize_t fr_struct_to_network(uint8_t *out, size_t outlen, fr_da_stack_t *da_stack, unsigned int depth,
			     fr_cursor_t *cursor, void *encoder_ctx,
			     fr_encode_value_t encode_value)
{
	fr_dbuff_t		dbuff = FR_DBUFF_TMP(out, outlen);
	encode_ctx_wrapper	wrapper = {.ectx = encoder_ctx, .encoder = encode_value};

	if (encode_value == NULL) return fr_struct_to_network_dbuff(&dbuff, da_stack, depth, cursor, NULL, NULL);

	return fr_struct_to_network_dbuff(&FR_DBUFF_TMP(out, outlen), da_stack, depth,
					  cursor, (void *) &wrapper, wrapped_encoder);
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

ssize_t fr_struct_to_network_dbuff(fr_dbuff_t *dbuff,
				   fr_da_stack_t *da_stack, unsigned int depth,
				   fr_cursor_t *cursor, void *encoder_ctx,
				   fr_encode_value_dbuff_t encode_value)
{
	fr_dbuff_t		work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);
	fr_dbuff_t		hdr_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);
	int			offset = 0;
	unsigned int		child_num = 1;
	bool			do_length = false;
	uint8_t			bit_buffer = 0;
	fr_pair_t const		*vp = fr_cursor_current(cursor);
	fr_dict_attr_t const   	*key_da, *parent;

	if (!vp) {
		fr_strerror_printf("%s: Can't encode empty struct", __FUNCTION__);
		return -1;
	}

	VP_VERIFY(vp);
	parent = da_stack->da[depth];

	if (parent->type != FR_TYPE_STRUCT) {
		fr_strerror_printf("%s: Expected type \"struct\" got \"%s\"", __FUNCTION__,
				   fr_table_str_by_value(fr_value_box_type_table, parent->type, "?Unknown?"));
		return -1;
	}

	/*
	 *	@todo - if we get a child which *eventually* has the
	 *	given parent, then allow encoding of that struct, too.
	 *	This allows us to encode structures automatically,
	 *	even if key fields are omitted.
	 */
	if (vp->da->parent != parent) {
		fr_strerror_printf("%s: struct encoding is missing previous attributes", __FUNCTION__);
		return -1;
	}

	key_da = NULL;

	/*
	 *	Some structs are prefixed by a 16-bit length.
	 */
	if (da_is_length_field(parent)) {
		FR_DBUFF_ADVANCE_RETURN(dbuff, 2);
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

		/*
		 *	Encode child TLVs at the end of a struct.
		 *
		 *	@todo - just have a loop here looking for
		 *	vp->da->parent == child, and encoding those.
		 */
		if (child->type == FR_TYPE_TLV) {
			break;
		}

		/*
		 *	Skipped a VP, or left one off at the end, fill the struct with zeros.
		 */
		if (!vp || (vp->da != child)) {
			/*
			 *	Zero out the bit field.
			 */
			if (da_is_bit_field(child)) {
				offset = put_bits_dbuff(&work_dbuff, &bit_buffer, offset, child->flags.length, 0);
				if (offset < 0) return offset;
				child_num++;
				continue;
			}

			if (da_is_key_field(child)) {
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
					fr_strerror_printf("Invalid bit field");
					return -1;
			}

			offset = put_bits_dbuff(&work_dbuff, &bit_buffer, offset, child->flags.length, value);
			if (offset < 0) return offset;

			do {
				vp = fr_cursor_next(cursor);
				if (!vp || !vp->da->flags.internal) break;
			} while (vp != NULL);
			goto next;

		}

		/* Not a bit field; insist that no buffered bits remain. */
		if (offset != 0) {
		leftover_bits:
			fr_strerror_printf("leftover bits");
			return -1;
		}

		if (encode_value) {
			ssize_t	len;
			/*
			 *	Call the protocol encoder for non-bit fields.
			 */
			fr_proto_da_stack_build(da_stack, child);
			len = encode_value(&work_dbuff, da_stack, depth + 1, cursor, encoder_ctx);
			if (len < 0) return len;
			vp = fr_cursor_current(cursor);

		} else {
			/*
			 *	Encode fixed-size octets fields so that they
			 *	are exactly the fixed size, UNLESS the entire
			 *	output is truncated.
			 */
			if ((vp->da->type == FR_TYPE_OCTETS) && vp->da->flags.length) {
				size_t mylen = vp->da->flags.length;

				if (vp->vp_length < mylen) {
					FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, (uint8_t const *)(vp->vp_ptr),
								  vp->vp_length);
					FR_DBUFF_MEMSET_RETURN(&work_dbuff, 0, mylen - vp->vp_length);
				} else {
					FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, (uint8_t const *)(vp->vp_ptr), mylen);
				}

			} else {
				/*
				 *	Determine the nested type and call the appropriate encoder
				 */
				if (fr_value_box_to_network(&work_dbuff, &vp->data) <= 0) return -1;
			}

			do {
				vp = fr_cursor_next(cursor);
				if (!vp || !vp->da->flags.internal) break;
			} while (vp != NULL);
		}

		if (da_is_key_field(child)) {
			key_da = child;
		}

	next:
		child_num++;
	}

	/* Check for leftover bits */
	if (offset != 0) goto leftover_bits;

	/*
	 *	Check for keyed data to encode.
	 */
	if (vp && key_da) {
		/*
		 *	If our parent is a struct, AND its parent is
		 *	the key_da, then we have a keyed struct for
		 *	the child.  Go encode it.
		 */
		if ((vp->da->parent->parent == key_da) &&
		    (vp->da->parent->type == FR_TYPE_STRUCT)) {
			ssize_t	len;
			fr_proto_da_stack_build(da_stack, vp->da->parent);
			len = fr_struct_to_network_dbuff(&work_dbuff, da_stack, depth + 2, /* note + 2 !!! */
							 cursor, encoder_ctx, encode_value);
			if (len < 0) return len;
			goto done;
		}

		/*
		 *	The next VP is likely octets and unknown.
		 */
		if ((vp->da->parent == key_da) &&
		    (vp->da->type != FR_TYPE_TLV)) {
			if (fr_value_box_to_network(&work_dbuff, &vp->data) <= 0) return -1;
			(void) fr_cursor_next(cursor);
			goto done;
		}

		/*
		 *	We have no idea what to do.  Ignore it.
		 */
	}

done:
	if (do_length) {
		uint32_t len = fr_dbuff_used(&work_dbuff) - 2;
		if (len > 65535) return -1;
		fr_dbuff_in(&hdr_dbuff, (uint16_t)len);
	}

	return fr_dbuff_set(dbuff, &work_dbuff);
}
