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

VALUE_PAIR *fr_unknown_from_network(TALLOC_CTX *ctx, fr_dict_attr_t const *parent, uint8_t const *data, size_t data_len)
{
	VALUE_PAIR *vp;
	fr_dict_attr_t const *child;

#if defined(__clang_analyzer__) || !defined(NDEBUG)
	if (!parent->parent) return NULL; /* stupid static analyzers */
#endif

	/*
	 *	Build an unknown attr of the entire STRUCT.
	 */
	child = fr_dict_unknown_afrom_fields(ctx, parent->parent,
					     fr_dict_vendor_num_by_da(parent), parent->attr);
	if (!child) return NULL;

	vp = fr_pair_afrom_da(ctx, child); /* makes a copy of 'child' */
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
	VALUE_PAIR		*head = NULL;
	fr_cursor_t		child_cursor;
	VALUE_PAIR		*vp, *key_vp;
	unsigned int		offset = 0;

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

		FR_PROTO_HEX_DUMP(p, (end - p), "fr_struct_from_network - child %d", child->attr);

		/*
		 *	Check for bit fields.
		 */
		if (da_is_bit_field(child)) {
			uint8_t array[8];
			unsigned int num_bits;
			uint64_t value;

			num_bits = offset + child->flags.length;
			if ((end - p) < ((num_bits + 7) >> 3)) goto unknown;

			memset(array, 0, sizeof(array));
			memcpy(&array[0], p, ((num_bits + 7) >> 3)); /* round up to nearest byte */

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
			p += (num_bits >> 3);
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

			slen = decode_value(ctx, &child_cursor, NULL, child, p, child_length, decoder_ctx);
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

		case FR_TYPE_VALUES:
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

			vp = fr_unknown_from_network(ctx, parent, data, data_len);
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

		FR_PROTO_HEX_DUMP(p, (end - p), "fr_struct_from_network - substruct");

		/*
		 *	Nothing more to decode, don't decode it.
		 */
		if (p >= end) goto done;

		switch (key_vp->da->type) {
		default:
			goto done;

		case FR_TYPE_UINT8:
			child_num = key_vp->vp_uint8;
			break;

		case FR_TYPE_UINT16:
			child_num = key_vp->vp_uint16;
			break;

		case FR_TYPE_UINT32:
			child_num = key_vp->vp_uint32;
			break;
		}

		child = fr_dict_attr_child_by_num(key_vp->da, child_num);
		if (!child) {
			child = fr_dict_unknown_afrom_fields(ctx, key_vp->da,
							     fr_dict_vendor_num_by_da(key_vp->da), child_num);
			if (!child) goto unknown;
			goto unknown_child; /* we know it's not a struct */
		}

		if (child->type == FR_TYPE_STRUCT) {
			slen = fr_struct_from_network(ctx, &child_cursor, child, p, end - p, child_p,
				decode_value, decoder_ctx);
			if (slen <= 0) goto unknown_child;
			p += slen;

		} else {
		unknown_child:
			vp = fr_unknown_from_network(ctx, child, p, end - p);
			if (!vp) {
				fr_dict_unknown_free(&child);
				return -(p - data);
			}

			fr_cursor_append(&child_cursor, vp);
			p = end;
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

/** Put bits into an output buffer
 *
 * @param p	where the bits go
 * @param end	end of the output buffer
 * @param start_bit start bit in the output buffer where the data goes, 0..7
 * @param num_bits  number of bits to write to the output
 * @param data	data to write, all in the lower "num_bits" of the uint64_t variable
 */
static int put_bits(uint8_t *p, uint8_t const *end, int start_bit, int num_bits, uint64_t data)
{
	uint8_t old;

	/*
	 *	Jump to the start byte
	 */
	if (start_bit > 7) {
		p += start_bit >> 3;
		start_bit &= 0x07;
	}

	if ((p + ((start_bit + num_bits) >> 3)) > end) return -1;

	if (num_bits > 56) return -1;

	/*
	 *	Too much data? Mask it off.
	 */
	if (data > ((uint64_t) 1) << num_bits) {
		data &= (((uint64_t) 1) << num_bits) - 1;
	}

	/*
	 *	Grab the old byte.  Shift the data so that it's start
	 *	bit is where we want, then convert the data to nework
	 *	byte order.
	 *
	 *	Copy over old as many bytes as we need, and then "or"
	 *	in the original data.
	 */
	old = p[0];
	data <<= (64 - (start_bit + num_bits));
	data = htonll(data);
	memcpy(p, &data, (num_bits + 7) >> 3); /* only copy as much as necessary */
	p[0] |= old;

	return 0;
}


ssize_t fr_struct_to_network(uint8_t *out, size_t outlen,
			     fr_dict_attr_t const **tlv_stack, unsigned int depth,
			     fr_cursor_t *cursor, void *encoder_ctx,
			     fr_encode_value_t encode_value)
{
	ssize_t			len;
	unsigned int		child_num = 1;
	unsigned int		offset = 0;
	bool			do_length = false;
	uint8_t			*p = out;
	VALUE_PAIR const	*vp = fr_cursor_current(cursor);
	fr_dict_attr_t const   	*key_da, *parent;

	if (!vp) {
		fr_strerror_printf("%s: Can't encode empty struct", __FUNCTION__);
		return -1;
	}

	VP_VERIFY(vp);
	parent = tlv_stack[depth];

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
		if (outlen < 2) return 0;

		out[0] = 0;
		out[1] = 0;
		p += 2;
		outlen -= 2;
		do_length = true;
	}

	while (outlen) {
		fr_dict_attr_t const *child;

		/*
		 *	The child attributes should be in order.  If
		 *	they're not, we fill the struct with zeroes.
		 */
		child = vp->da;

		if (!da_is_bit_field(child)) offset = 0;

		if (child->attr != child_num) {
			child = fr_dict_attr_child_by_num(parent, child_num);

			if (!child) break;

			/*
			 *	Zero out the bit field.
			 */
			if (da_is_bit_field(child)) {
				if (offset == 0) *p = 0;

				(void) put_bits(p, p + outlen, offset, child->flags.length, 0);

				offset += child->flags.length;
				if (offset >= 8) {
					p += (offset >> 3);
					outlen -= (offset >> 3);
					offset &= 0x07;
				}

				child_num++;
				continue;
			}

			if (da_is_key_field(child)) {
				key_da = child;
			}

			/*
			 *	Zero out the unused field.
			 */
			if (child->flags.length > outlen) {
				len = outlen;
			} else {
				len = child->flags.length;
			}

			memset(p, 0, len);
			p += len;
			outlen -= len;
			child_num++;
			continue;
		}

		/*
		 *	Call the protocol encoder, but ONLY if there
		 *	are special flags required.
		 */
		if (da_is_bit_field(child)) {
			uint64_t value;

			if (offset == 0) *p = 0;

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

			(void) put_bits(p, p + outlen, offset, child->flags.length, value);

			offset += child->flags.length;
			if (offset >= 8) {
				p += (offset >> 3);
				outlen -= (offset >> 3);
				offset &= 0x07;
			}

			do {
				vp = fr_cursor_next(cursor);
				if (!vp || !vp->da->flags.internal) break;
			} while (vp != NULL);
			goto next;

		} else if (encode_value) {
			ssize_t slen;

			fr_proto_tlv_stack_build(tlv_stack, child);
			slen = encode_value(p, outlen, tlv_stack, depth + 1, cursor, encoder_ctx);
			if (slen < 0) return slen;
			len = slen;
			vp = fr_cursor_current(cursor);

		} else {
			/*
			 *	Encode fixed-size octets fields so that they
			 *	are exactly the fixed size, UNLESS the entire
			 *	output is truncated.
			 */
			if ((vp->da->type == FR_TYPE_OCTETS) && vp->da->flags.length) {
				size_t mylen = vp->da->flags.length;

				if (mylen > outlen) mylen = outlen;

				if (vp->vp_length < mylen) {
					memcpy(p, vp->vp_ptr, vp->vp_length);
					memset(p + vp->vp_length, 0, mylen - vp->vp_length);
				} else {
					memcpy(p, vp->vp_ptr, mylen);
				}
				len = mylen;

			} else {
				/*
				 *	Determine the nested type and call the appropriate encoder
				 */
				len = fr_value_box_to_network(NULL, p, outlen, &vp->data);
				if (len <= 0) return -1;
			}

			do {
				vp = fr_cursor_next(cursor);
				if (!vp || !vp->da->flags.internal) break;
			} while (vp != NULL);
		}

		if (da_is_key_field(child)) {
			key_da = child;
		}

		p += len;
		outlen -= len;				/* Subtract from the buffer we have available */
	next:
		child_num++;

		/*
		 *	Nothing more to do, or we've done all of the
		 *	entries in this structure, stop.
		 *
		 *	Note that TLVs are passed to the
		 *	"encode_value" function, which should encode
		 *	them.  This is currently done for RADIUS, but
		 *	not for DHCPv4 or DHCPv6.
		 */
		if (!vp || (vp->da->parent != parent) || (vp->da->attr < child_num)) {
			break;
		}
	}

	if (!vp || !outlen) return p - out;

	/*
	 *	Check for keyed data to encode.
	 */
	if (key_da) {
		/*
		 *	If our parent is a struct, AND it's parent is
		 *	the key_da, then we have a keyed struct for
		 *	the child.  Go encode it.
		 */
		if ((vp->da->parent->parent == key_da) &&
		    (vp->da->parent->type == FR_TYPE_STRUCT)) {
			fr_proto_tlv_stack_build(tlv_stack, vp->da->parent);
			len = fr_struct_to_network(p, outlen, tlv_stack, depth + 2, /* note + 2 !!! */
						   cursor, encoder_ctx, encode_value);
			if (len < 0) return len;
			p += len;
			goto done;
		}

		/*
		 *	The next VP is likely octets and unknown.
		 */
		if ((vp->da->parent == key_da) &&
		    (vp->da->type != FR_TYPE_TLV)) {
			len = fr_value_box_to_network(NULL, p, outlen, &vp->data);
			if (len <= 0) return -1;
			(void) fr_cursor_next(cursor);
			p += len;
			goto done;
		}

		/*
		 *	We have no idea what to do.  Ignore it.
		 */
	}

done:
	if (do_length) {
		len = (p - (out + 2));
		if (len > 65535) return -1;

		out[0] = (len >> 8) & 0xff;
		out[1] = len & 0xff;
	}

	return p - out;
}
