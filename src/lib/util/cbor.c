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

/** CBPR encoding and decoding
 *
 * @file src/lib/util/cbor.c
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/util/cbor.h>

#define CBOR_INTEGER	(0)
#define CBOR_NEGATIVE	(1)
#define CBOR_OCTETS	(2)
#define CBOR_STRING	(3)
#define CBOR_ARRAY	(4)
#define CBOR_MAP	(5)
#define CBOR_TAG	(6)
#define CBOR_FLOAT	(7)

#define CBOR_1_BYTE ((uint8_t) 24)
#define CBOR_2_BYTE ((uint8_t) 25)
#define CBOR_4_BYTE ((uint8_t) 26)
#define CBOR_8_BYTE ((uint8_t) 27)

static const char *cbor_type_to_str[8] = {
	"integer", "negative", "octets", "string",
	"array", "map", "tag", "float"
};

/*
 *	Some of our data types need tags.
 *
 *	We don't have a tag to data type array.  When decoding, we should usually have the enclosing pair
 *	number, which includes our data type.  If the tag type doesn't match the value here, then something is
 *	wrong.
 */
static const uint64_t cbor_type_to_tag[FR_TYPE_MAX + 1] = {
	[FR_TYPE_DATE] = 1,
	[FR_TYPE_ETHERNET] = 48,
	[FR_TYPE_IPV4_ADDR] = 52,
	[FR_TYPE_IPV4_PREFIX] = 52,
	[FR_TYPE_IPV6_ADDR] = 54,
	[FR_TYPE_IPV6_PREFIX] = 54,
	[FR_TYPE_TIME_DELTA] = 1002,
};

static fr_type_t cbor_guess_type(fr_dbuff_t *dbuff, bool pair);

static ssize_t cbor_encode_integer(fr_dbuff_t *dbuff, uint8_t type, uint64_t data)
{
	fr_dbuff_t	work_dbuff = FR_DBUFF(dbuff);
	uint8_t		value[8];

	fr_assert(type < 8);
	type <<= 5;

	if (data < 24) {
		data |= type;

		FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, (uint8_t) (data & 0xff));
		goto done;
	}

	if (data < (((uint64_t) 1) << 8)) {
		value[0] = data;

		FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, (uint8_t) (type | CBOR_1_BYTE));
		FR_DBUFF_IN_RETURN(&work_dbuff, value[0]);
		goto done;
	}

	if (data < (((uint64_t) 1) << 16)) {
		fr_nbo_from_uint16(value, data);

		FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, (uint8_t) (type | CBOR_2_BYTE));
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, value, 2);
		goto done;
	}

	if (data < (((uint64_t) 1) << 32)) {
		fr_nbo_from_uint32(value, data);

		FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, (uint8_t) (type | CBOR_4_BYTE));
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, value, 4);
		goto done;
	}

	fr_nbo_from_uint64(value, data);

	/*
	 *	Has to be 8 bytes.
	 */
	FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, type | CBOR_8_BYTE);
	FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, value, 8);

done:
	return fr_dbuff_set(dbuff, &work_dbuff);
}

#define cbor_encode_array(_dbuff, _size) cbor_encode_integer(_dbuff, CBOR_ARRAY, _size)

#define cbor_encode_tag(_dbuff, _tag) cbor_encode_integer(_dbuff, CBOR_TAG, _tag)

/*
 *	Make many things easier
 */
#define return_slen return FR_DBUFF_ERROR_OFFSET(slen, fr_dbuff_used(&work_dbuff))

/*
 *	Octets is length + data
 */
static ssize_t cbor_encode_octets(fr_dbuff_t *dbuff, uint8_t const *data, size_t data_len)
{
	fr_dbuff_t	work_dbuff = FR_DBUFF(dbuff);
	ssize_t slen;

	slen = cbor_encode_integer(&work_dbuff, CBOR_OCTETS, data_len);
	if (slen <= 0) return_slen;

	if (data_len > 0) FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, data, data_len);

	return fr_dbuff_set(dbuff, &work_dbuff);
}

static ssize_t cbor_encode_int64(fr_dbuff_t *dbuff, int64_t neg)
{
	fr_dbuff_t	work_dbuff = FR_DBUFF(dbuff);
	ssize_t slen;

	if (neg >= 0) {
		slen = cbor_encode_integer(&work_dbuff, CBOR_INTEGER, neg);
	} else {
		uint64_t data;

		neg++;
		data = -neg;
		slen = cbor_encode_integer(&work_dbuff, CBOR_NEGATIVE, data);
	}
	if (slen <= 0) return_slen;

	return fr_dbuff_set(dbuff, &work_dbuff);
}

#define cbor_encode_key cbor_encode_int64

/** Encode CBOR
 *
 *  Values 0..23 can be encoded in place.  Other values can be encoded using the closest smallest integer
 */
ssize_t fr_cbor_encode_value_box(fr_dbuff_t *dbuff, fr_value_box_t *vb)
{
	fr_dbuff_t	work_dbuff = FR_DBUFF(dbuff);
	uint8_t		type = CBOR_INTEGER;
	uint64_t	data;
	int64_t		neg;
	ssize_t		slen;
	uint8_t		const *p, *end;

	switch (vb->type) {
	case FR_TYPE_BOOL:
		/*
		 *	One byte of FLOAT (i.e. special value), and the boolean as a "simple value".
		 */
		FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, (uint8_t) ((CBOR_FLOAT << 5) | (20 + vb->vb_bool)));
		break;

	case FR_TYPE_UINT8:
		data = vb->vb_uint8;
		goto encode_int;

	case FR_TYPE_UINT16:
		data = vb->vb_uint16;
		goto encode_int;

	case FR_TYPE_UINT32:
		data = vb->vb_uint64;
		goto encode_int;

	case FR_TYPE_UINT64:
		data = vb->vb_uint64;
		goto encode_int;

	/*
	 *	Negative numbers.
	 */
	case FR_TYPE_INT8:
		neg = vb->vb_int8;
		goto encode_neg;

	case FR_TYPE_INT16:
		neg = vb->vb_int16;
		goto encode_neg;

	case FR_TYPE_INT32:
		neg = vb->vb_int64;
		goto encode_neg;

	case FR_TYPE_INT64:
		neg = vb->vb_int64;
	encode_neg:
		if (neg >= 0) {
			type = CBOR_NEGATIVE;
			data = neg;
			goto encode_int;
		}

		/*
		 *	convert -1..-2^63 to 0..-(2^63-1)
		 *	and then it fits into a positive integer.
		 */
		neg++;
		data = -neg;

	encode_int:
		return cbor_encode_integer(dbuff, type, data);

	case FR_TYPE_OCTETS:
		return cbor_encode_octets(dbuff, vb->vb_octets, vb->vb_length);

	case FR_TYPE_STRING:
		slen = cbor_encode_integer(&work_dbuff, CBOR_STRING, vb->vb_length);
		if (slen <= 0) return_slen;

		if (vb->vb_length) FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, vb->vb_strvalue, vb->vb_length);
		break;

		/*
		 *	More complex data types are represented by type "tag", followed by a tag number.  The
		 *	actual data is then encoded as the next item after the tag.
		 */
	case FR_TYPE_ETHERNET:
		slen = cbor_encode_tag(&work_dbuff, cbor_type_to_tag[vb->type]);
		if (slen <= 0) return_slen;

		slen = cbor_encode_octets(&work_dbuff, vb->vb_ether, sizeof(vb->vb_ether));
		if (slen <= 0) return_slen;
		break;

		/*
		 *	Tag 1, with integer seconds since epoch.
		 *
		 *	@todo - if the input has time resolution, then save it in that format.
		 *
		 *	RFC 9581 Section 3.
		 *
		 *	A tag with key 1001, and then: a map with required key 1 (integer epoch seconds) and
		 *	optional key -3 (milliseconds), -6 (microseconds), or -9 (integer nanoseconds).
		 *
		 *	For the encoder, there are a ton of different formats for dates, and we shouldn't
		 *	bother to parse them all. :(
		 */
	case FR_TYPE_DATE:
		slen = cbor_encode_tag(&work_dbuff, cbor_type_to_tag[vb->type]);
		if (slen <= 0) return_slen;

		neg = fr_unix_time_to_sec(vb->vb_date);
		slen = cbor_encode_int64(&work_dbuff, neg);
		if (slen <= 0) return_slen;
		break;

		/*
		 *	RFC 9581 Section 4.
		 *
		 *	A tag with key 1002, and then: a map with required key 1 (integer seconds) and
		 *	optional key -3 (milliseconds), -6 (microseconds), or -9 (integer nanoseconds).
		 */
	case FR_TYPE_TIME_DELTA:
		slen = cbor_encode_tag(&work_dbuff, cbor_type_to_tag[vb->type]);
		if (slen <= 0) return_slen;

		neg = fr_time_delta_unwrap(vb->vb_time_delta) % NSEC;

		slen = cbor_encode_integer(&work_dbuff, CBOR_MAP, 1 + (neg != 0));
		if (slen <= 0) return_slen;

		/*
		 *	1: seconds
		 */
		slen = cbor_encode_key(&work_dbuff, 1);
		if (slen <= 0) return_slen;

		slen = cbor_encode_int64(&work_dbuff, fr_time_delta_to_sec(vb->vb_time_delta));
		if (slen <= 0) return_slen;

		/*
		 *	-9: nanoseconds
		 */
		if (neg) {
			slen = cbor_encode_key(&work_dbuff, -9);
			if (slen <= 0) return_slen;

			slen = cbor_encode_int64(&work_dbuff, neg);
			if (slen <= 0) return_slen;
		}
		break;

		/*
		 *	RFC 9164, Section 3.3
		 *
		 *
		 *	tag=IPv4 + address + optional (prefix + scope)
		 */
	case FR_TYPE_IPV4_ADDR:
		slen = cbor_encode_tag(&work_dbuff, cbor_type_to_tag[vb->type]);
		if (slen <= 0) return_slen;

		if (vb->vb_ip.scope_id != 0) {
			FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, (uint8_t) ((CBOR_ARRAY << 5) | 3));

		}

		slen = cbor_encode_octets(&work_dbuff, (uint8_t const *) &vb->vb_ipv4addr, 4);
		if (slen <= 0) return_slen;

		if (vb->vb_ip.scope_id == 0) break;

		slen = cbor_encode_integer(&work_dbuff, CBOR_INTEGER, (uint8_t) 32);
		if (slen <= 0) return_slen;

		slen = cbor_encode_integer(&work_dbuff, CBOR_INTEGER, vb->vb_ip.scope_id);
		if (slen <= 0) return_slen;
		break;

		/*
		 *	RFC 9164, Section 3.2
		 *
		 *	tag=IPv6 + address + optional (prefix + scope)
		 */
	case FR_TYPE_IPV6_ADDR:
		if (vb->vb_ip.scope_id != 0) {
			FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, (uint8_t) ((CBOR_ARRAY << 5) | 3));

		}

		slen = cbor_encode_tag(&work_dbuff, cbor_type_to_tag[vb->type]);
		if (slen <= 0) return_slen;

		slen = cbor_encode_octets(&work_dbuff, (uint8_t const *) &vb->vb_ipv6addr, 16);
		if (slen <= 0) return_slen;

		if (vb->vb_ip.scope_id == 0) break;

		slen = cbor_encode_integer(&work_dbuff, CBOR_INTEGER, (uint8_t) 32);
		if (slen <= 0) return_slen;

		slen = cbor_encode_integer(&work_dbuff, CBOR_INTEGER, vb->vb_ip.scope_id);
		if (slen <= 0) return_slen;
		break;

		/*
		 *	RFC 9164, Section 3.3
		 *
		 *	tag=IPv4 + array(prefix-length, address)
		 */
	case FR_TYPE_IPV4_PREFIX:
		slen = cbor_encode_tag(&work_dbuff, cbor_type_to_tag[vb->type]);
		if (slen <= 0) return_slen;

		slen = cbor_encode_array(&work_dbuff, 2);
		if (slen <= 0) return_slen;

		slen = cbor_encode_integer(&work_dbuff, CBOR_INTEGER, vb->vb_ip.prefix);
		if (slen <= 0) return_slen;

		p = (uint8_t const *) &vb->vb_ipv4addr;
		end = p + 3;

		/*
		 *	RFC 9164 Section 4.2 - Drop lower octets which are all zero.
		 *
		 *	If this results in a zero-length string, so be it.
		 *
		 *	Note also that "There is no relationship between the number of bytes omitted and the
		 *	prefix length."
		 */
		do {
			if (*end != 0) break;

			end--;
		} while (end != p);

		slen = cbor_encode_octets(&work_dbuff, p, (end - p) + (*end != 0));
		if (slen <= 0) return_slen;
		break;

		/*
		 *	RFC 9164, Section 3.2
		 *
		 *	tag=IPv6 + array(prefix-length, address)
		 */
	case FR_TYPE_IPV6_PREFIX:
		slen = cbor_encode_tag(&work_dbuff, cbor_type_to_tag[vb->type]);
		if (slen <= 0) return_slen;

		slen = cbor_encode_array(&work_dbuff, 2);
		if (slen <= 0) return_slen;

		slen = cbor_encode_integer(&work_dbuff, CBOR_INTEGER, vb->vb_ip.prefix);
		if (slen <= 0) return_slen;

		p = (uint8_t const *) &vb->vb_ipv6addr;
		end = p + 15;

		/*
		 *	RFC 9164 Section 4.2 - Drop lower octets which are all zero.
		 *
		 *	If this results in a zero-length string, so be it.
		 *
		 *	Note also that "There is no relationship between the number of bytes omitted and the
		 *	prefix length."
		 */
		do {
			if (*end != 0) break;

			end--;
		} while (end != p);

		slen = cbor_encode_octets(&work_dbuff, p, (end - p) + (*end != 0));
		if (slen <= 0) return_slen;

		break;

	case FR_TYPE_FLOAT32:
		FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, (uint8_t) ((CBOR_FLOAT << 5) | CBOR_4_BYTE));

		slen = cbor_encode_octets(&work_dbuff, (uint8_t const *) &vb->vb_float32, 4);
		if (slen <= 0) return_slen;
		break;

	case FR_TYPE_FLOAT64:
		FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, (uint8_t) ((CBOR_FLOAT << 5) | CBOR_8_BYTE));

		slen = cbor_encode_octets(&work_dbuff, (uint8_t const *) &vb->vb_float64, 8);
		if (slen <= 0) return_slen;
		break;

	case FR_TYPE_GROUP:
		/*
		 *	Zero-length array.
		 */
		if (fr_value_box_list_num_elements(&vb->vb_group) == 0) {
			FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, (uint8_t) ((CBOR_ARRAY << 5) | 0));
			break;
		}

		/*
		 *	The value is array(children)
		 */
		slen = cbor_encode_integer(&work_dbuff, CBOR_ARRAY,
					   fr_value_box_list_num_elements(&vb->vb_group));
		if (slen <= 0) return_slen;


		fr_value_box_list_foreach(&vb->vb_group, child) {
			slen = fr_cbor_encode_value_box(&work_dbuff, child);
			if (slen <= 0) return_slen;
		}
		break;


	default:
		fr_strerror_printf("Invalid data type %s for cbor encoding", fr_type_to_str(vb->type));
		return -1;
	}

	return fr_dbuff_set(dbuff, &work_dbuff);
}


static ssize_t cbor_decode_integer(uint64_t *out, uint8_t info, fr_dbuff_t *dbuff)
{
	fr_dbuff_t work_dbuff = FR_DBUFF(dbuff);

	if (info < 24) {
		*out = info;
		return 0;
	}

	if (info == CBOR_1_BYTE) {
		uint8_t value;

		FR_DBUFF_OUT_RETURN(&value, &work_dbuff);
		*out = value;
		goto done;
	}

	if (info == CBOR_2_BYTE) {
		uint16_t value;

		FR_DBUFF_OUT_RETURN(&value, &work_dbuff);
		*out = value;
		goto done;
	}

	if (info == CBOR_4_BYTE) {
		uint32_t value;

		FR_DBUFF_OUT_RETURN(&value, &work_dbuff);
		*out = value;
		goto done;
	}

	if (info == CBOR_8_BYTE) {
		uint64_t value;

		FR_DBUFF_OUT_RETURN(&value, &work_dbuff);
		*out = value;
		goto done;
	}

	/*
	 *	28 and greater are invalid according to the RFCs.
	 */

done:
	return fr_dbuff_set(dbuff, &work_dbuff);
}

static ssize_t cbor_decode_count(uint64_t *out, int expected, fr_dbuff_t *dbuff)
{
	fr_dbuff_t work_dbuff = FR_DBUFF(dbuff);
	uint8_t major, info;
	ssize_t slen;

	FR_DBUFF_OUT_RETURN(&major, &work_dbuff);

	info = major & 0x1f;
	major >>= 5;

	if (major != expected) {
		fr_strerror_printf("Expected cbor type '%s', got unexpected type %d ",
				   cbor_type_to_str[expected], major);
		return -1;
	}

	slen = cbor_decode_integer(out, info, &work_dbuff);
	if (slen < 0) return_slen;

	return fr_dbuff_set(dbuff, &work_dbuff);
}

typedef ssize_t (*cbor_decode_type_t)(TALLOC_CTX *ctx, fr_value_box_t *vb, fr_dbuff_t *dbuff);

static ssize_t cbor_decode_octets_memcpy(uint8_t *dst, size_t dst_min, size_t dst_max, fr_dbuff_t *dbuff)
{
	fr_dbuff_t work_dbuff = FR_DBUFF(dbuff);
	ssize_t slen;
	uint64_t value = 0;

	slen = cbor_decode_count(&value, CBOR_OCTETS, &work_dbuff);
	if (slen < 0) return_slen;

	if (value < dst_min) {
		fr_strerror_printf("Invalid length for data - expected at least %zu got %" PRIu64, dst_min, value);
		return -1;
	}

	if (value > dst_max) {
		fr_strerror_printf("Invalid length for data - expected no more than %zu got %" PRIu64, dst_max, value);
		return -1;
	}

	FR_DBUFF_OUT_MEMCPY_RETURN(dst, &work_dbuff, value);

	return fr_dbuff_set(dbuff, &work_dbuff);
}

#if 0
static ssize_t *cbor_decode_octets_memdup(TALLOC_CTX *ctx, uint8_t **out, fr_dbuff_t *dbuff)
{
	fr_dbuff_t work_dbuff = FR_DBUFF(dbuff);
	ssize_t slen;
	uint64_t value;
	uint8_t *ptr;

	slen = cbor_decode_count(&value, CBOR_OCTETS, &work_dbuff);
	if (slen < 0) return_slen;

	if (value > (1 << 20)) {
		fr_strerror_printf("cbor data string is too long (%" PRIu64 ")", value);
		return -1;
	}

	ptr = talloc_array(ctx, uint8_t, value);
	if (!ptr) {
		fr_strerror_const("Out of memory");
		return -1;
	}

	FR_DBUFF_OUT_MEMCPY_RETURN(ptr, &work_dbuff, value);
	*out = ptr;

	return fr_dbuff_set(dbuff, &work_dbuff);
}
#endif

static ssize_t cbor_decode_ethernet(UNUSED TALLOC_CTX *ctx, fr_value_box_t *vb, fr_dbuff_t *dbuff)
{
	return cbor_decode_octets_memcpy(vb->vb_ether, sizeof(vb->vb_ether), sizeof(vb->vb_ether), dbuff);
}

static ssize_t cbor_decode_ipv4_addr(UNUSED TALLOC_CTX *ctx, fr_value_box_t *vb, fr_dbuff_t *dbuff)
{
	fr_dbuff_t work_dbuff = FR_DBUFF(dbuff);
	ssize_t slen;
	uint8_t header;
	size_t count = 0;
	uint64_t value = 0;

	FR_DBUFF_EXTEND_LOWAT_OR_RETURN(&work_dbuff, 1);

	header = *fr_dbuff_current(&work_dbuff);
	if ((header >> 5) == CBOR_ARRAY) {
		count = header & 0x1f;

		if ((count != 2) && (count != 3)) {
			fr_strerror_printf("Invalid IPv4 interface - expected array of 2-3 elements, got %02x",
					   header);
			return -1;
		}

		fr_dbuff_advance(&work_dbuff, 1);
	}

	vb->vb_ip.prefix = 32;

	/*
	 *	Get the IP address.
	 */
	slen = cbor_decode_octets_memcpy((uint8_t *) &vb->vb_ipv4addr,
					 sizeof(vb->vb_ipv4addr),
					 sizeof(vb->vb_ipv4addr), &work_dbuff);
	if (slen <= 0) return_slen;

	if (!count) return fr_dbuff_set(dbuff, &work_dbuff);

	slen = cbor_decode_count(&value, CBOR_INTEGER, &work_dbuff);
	if (slen <= 0) return_slen;

	if (value != 32) {
		fr_strerror_printf("Invalid IPv4 address - expected prefix = 32 got %" PRIu64, value);
		return -fr_dbuff_used(&work_dbuff);
	}

	if (count == 2) return fr_dbuff_set(dbuff, &work_dbuff);

	/*
	 *	Get the scope ID
	 */
	slen = cbor_decode_count(&value, CBOR_INTEGER, &work_dbuff);
	if (slen <= 0) return_slen;

	vb->vb_ip.scope_id = value;

	return fr_dbuff_set(dbuff, &work_dbuff);
}

static ssize_t cbor_decode_ipv6_addr(UNUSED TALLOC_CTX *ctx, fr_value_box_t *vb, fr_dbuff_t *dbuff)
{
	fr_dbuff_t work_dbuff = FR_DBUFF(dbuff);
	ssize_t slen;
	uint8_t header;
	size_t count = 0;
	uint64_t value = 0;

	FR_DBUFF_EXTEND_LOWAT_OR_RETURN(&work_dbuff, 1);

	header = *fr_dbuff_current(&work_dbuff);
	if ((header >> 5) == CBOR_ARRAY) {
		count = header & 0x1f;

		if ((count != 2) && (count != 3)) {
			fr_strerror_printf("Invalid IPv4 interface - expected array of 2-3 elements, got %02x",
					   header);
			return -1;
		}

		fr_dbuff_advance(&work_dbuff, 1);
	}

	vb->vb_ip.prefix = 128;

	/*
	 *	Get the IP address.
	 */
	slen = cbor_decode_octets_memcpy((uint8_t *) &vb->vb_ipv6addr,
					 sizeof(vb->vb_ipv6addr),
					 sizeof(vb->vb_ipv6addr), dbuff);

	if (slen <= 0) return_slen;

	if (!count) return fr_dbuff_set(dbuff, &work_dbuff);

	slen = cbor_decode_count(&value, CBOR_INTEGER, &work_dbuff);
	if (slen <= 0) return_slen;

	if (value != 128) {
		fr_strerror_printf("Invalid IPv6 address - expected prefix = 128 got %" PRIu64, value);
		return -fr_dbuff_used(&work_dbuff);
	}

	vb->vb_ip.prefix = value;

	if (count == 2) return fr_dbuff_set(dbuff, &work_dbuff);

	/*
	 *	Get the scope ID
	 */
	slen = cbor_decode_count(&value, CBOR_INTEGER, &work_dbuff);
	if (slen <= 0) return_slen;

	vb->vb_ip.scope_id = value;

	return fr_dbuff_set(dbuff, &work_dbuff);
}

static ssize_t cbor_decode_ipv4_prefix(UNUSED TALLOC_CTX *ctx, fr_value_box_t *vb, fr_dbuff_t *dbuff)
{
	fr_dbuff_t work_dbuff = FR_DBUFF(dbuff);
	ssize_t slen;
	uint8_t header;
	uint64_t value = 0;
	uint8_t buffer[sizeof(vb->vb_ipv4addr)];

	FR_DBUFF_OUT_RETURN(&header, &work_dbuff);

	if (header != ((CBOR_ARRAY << 5) | 2)) {
		fr_strerror_printf("Invalid IPv4 prefix - expected array of 2 elements, got %02x",
				   header);
		return -1;
	}

	slen = cbor_decode_count(&value, CBOR_INTEGER, &work_dbuff);
	if (slen <= 0) return_slen;

	if (value > 32) {
		fr_strerror_printf("Invalid IPv4 prefix - expected prefix < 32, got %" PRIu64, value);
		return -1;
	}

	/*
	 *	RFC 9164 Section 4.3 - Trailing bytes of zero are omitted, so we
	 *	first copy the data to a fixed-sized buffer which was
	 *	zeroed out, and then (@todo) also check that unused bits in
	 *	the last byte are all zero.
	 */
	memset(buffer, 0, sizeof(buffer));

	slen = cbor_decode_octets_memcpy(buffer, 0, sizeof(buffer), &work_dbuff);
	if (slen <= 0) return_slen;

	memcpy((uint8_t *) &vb->vb_ipv4addr, buffer, sizeof(vb->vb_ipv4addr));
	vb->vb_ip.prefix = value;

	return fr_dbuff_set(dbuff, &work_dbuff);
}

static ssize_t cbor_decode_ipv6_prefix(UNUSED TALLOC_CTX *ctx, fr_value_box_t *vb, fr_dbuff_t *dbuff)
{
	fr_dbuff_t work_dbuff = FR_DBUFF(dbuff);
	ssize_t slen;
	uint8_t header;
	uint64_t value = 0;
	uint8_t buffer[sizeof(vb->vb_ipv6addr)];

	FR_DBUFF_OUT_RETURN(&header, &work_dbuff);

	if (header != ((CBOR_ARRAY << 5) | 2)) {
		fr_strerror_printf("Invalid IPv6 prefix - expected array of 2 elements, got %02x",
				   header);
		return -1;
	}

	slen = cbor_decode_count(&value, CBOR_INTEGER, &work_dbuff);
	if (slen <= 0) return_slen;

	if (value > 128) {
		fr_strerror_printf("Invalid IPv6 prefix - expected prefix < 128, got %" PRIu64, value);
		return -1;
	}

	/*
	 *	RFC 9164 Section 4.3 - Trailing bytes of zero are omitted, so we
	 *	first copy the data to a fixed-sized buffer which was
	 *	zeroed out, and then (@todo) also check that unused bits in
	 *	the last byte are all zero.
	 */
	memset(buffer, 0, sizeof(buffer));

	slen = cbor_decode_octets_memcpy(buffer, 0, sizeof(buffer), &work_dbuff);
	if (slen <= 0) return_slen;

	memcpy((uint8_t *) &vb->vb_ipv6addr, buffer, sizeof(vb->vb_ipv6addr));
	vb->vb_ip.prefix = value;

	return fr_dbuff_set(dbuff, &work_dbuff);
}

static ssize_t cbor_decode_int64(int64_t *out, fr_dbuff_t *dbuff, fr_type_t type)
{
	fr_dbuff_t work_dbuff = FR_DBUFF(dbuff);
	ssize_t slen;
	uint8_t major, info;
	uint64_t value = 0;
	int64_t neg;

	FR_DBUFF_OUT_RETURN(&major, &work_dbuff);

	info = major & 0x1f;
	major >>= 5;

	switch (major) {
	case CBOR_INTEGER:
		slen = cbor_decode_integer(&value, info, &work_dbuff);
		if (slen < 0) return_slen;

		if (value >= ((uint64_t) 1) << 63) { /* equal! */
		invalid:
			fr_strerror_printf("cbor value is too large for output data type %s",
					   fr_type_to_str(type));
			return -1;
		}

		*out = value;
		break;

	case CBOR_NEGATIVE:
		slen = cbor_decode_integer(&value, info, &work_dbuff);
		if (slen < 0) return_slen;

		if (value >= ((uint64_t) 1) << 63) goto invalid; /* greater than! */

		/*
		 *	Convert 0..(2^63-1) into -0..-(2^63-1)
		 *	then conver to -1..-(2^63)
		 */
		neg = -value;
		neg--;

		*out = neg;
		break;

	default:
		fr_strerror_printf("cbor data contains invalid content %d for expected data type %s",
				   major, fr_type_to_str(type));
		return -1;
	}

	return fr_dbuff_set(dbuff, &work_dbuff);

}

static ssize_t cbor_decode_date(UNUSED TALLOC_CTX *ctx, fr_value_box_t *vb, fr_dbuff_t *dbuff)
{
	fr_dbuff_t work_dbuff = FR_DBUFF(dbuff);
	ssize_t slen;
	int64_t neg;

	slen = cbor_decode_int64(&neg, dbuff, FR_TYPE_DATE);
	if (slen <= 0) return_slen;

	vb->vb_date = fr_unix_time_from_sec(neg);

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/*
 *	Tag 1002, followed by map of at least 2 elements
 *	key 1: seconds
 *	key -9: nanoseconds
 */
static ssize_t cbor_decode_time_delta(UNUSED TALLOC_CTX *ctx, fr_value_box_t *vb, fr_dbuff_t *dbuff)
{
	fr_dbuff_t work_dbuff = FR_DBUFF(dbuff);
	uint64_t count;
	ssize_t slen;
	int64_t key, seconds, fraction, scale;

	slen = cbor_decode_count(&count, CBOR_MAP, &work_dbuff);
	if (slen < 0) return_slen;

	if (!count || (count > 2)) {
		fr_strerror_printf("Unexpected count %" PRIu64"  for time_delta, expected map of 1-2 elements", count);
		return -1;
	}

	key = seconds = fraction = 0;

	/*
	 *	Expect key 1:seconds
	 */
	slen = cbor_decode_int64(&key, &work_dbuff, FR_TYPE_TIME_DELTA);
	if (slen < 0) return_slen;

	if (key != 1) {
		fr_strerror_printf("Unexpected key %" PRIi64 " for time_delta, expected key 1", key);
		return -1;
	}

	slen = cbor_decode_int64(&seconds, &work_dbuff, FR_TYPE_TIME_DELTA);
	if (slen < 0) return_slen;

	if (count > 1) {
		slen = cbor_decode_int64(&key, &work_dbuff, FR_TYPE_TIME_DELTA);
		if (slen < 0) return_slen;

		switch (key) {
		case -3:
			scale = MSEC;
			break;

		case -6:
			scale = USEC;
			break;

		case -9:
			scale = NSEC;
			break;

		default:
			fr_strerror_printf("Unsupported time_delta key %" PRIi64, key);
			return -fr_dbuff_used(&work_dbuff); /* point to actual key? */

		}

		slen = cbor_decode_int64(&fraction, &work_dbuff, FR_TYPE_TIME_DELTA);
		if (slen < 0) return_slen;

		if ((fraction < 0) || (fraction > scale)) fraction = 0;
	} else {
		scale = NSEC;
		fraction = 0;
	}

	if (seconds > (INT64_MAX / scale)) {
		vb->vb_time_delta = fr_time_delta_max();

	} else if (seconds < (INT64_MIN / scale)) {
		vb->vb_time_delta = fr_time_delta_min();

	} else {
		seconds *= scale;

		if (seconds < 0) {
			seconds -= fraction;
		} else {
			seconds += fraction;
		}

		vb->vb_time_delta = fr_time_delta_wrap(seconds);
	}

	return fr_dbuff_set(dbuff, &work_dbuff);
}


static cbor_decode_type_t cbor_decode_type[FR_TYPE_MAX] = {
	[FR_TYPE_ETHERNET] = cbor_decode_ethernet,

	[FR_TYPE_DATE] = cbor_decode_date,
	[FR_TYPE_TIME_DELTA] = cbor_decode_time_delta,

	[FR_TYPE_IPV4_ADDR] = cbor_decode_ipv4_addr,
	[FR_TYPE_IPV6_ADDR] = cbor_decode_ipv6_addr,

	[FR_TYPE_IPV4_PREFIX] = cbor_decode_ipv4_prefix,
	[FR_TYPE_IPV6_PREFIX] = cbor_decode_ipv6_prefix,
};

/*
 *	@todo - fr_cbor_encode_pair_list().  And then if we have da->flags.array, we encode the _value_ as an
 *	array of indeterminate length.  This is a little bit of a special case, but not terrible.
 */
ssize_t fr_cbor_decode_value_box(TALLOC_CTX *ctx, fr_value_box_t *vb, fr_dbuff_t *dbuff,
				 fr_type_t type, fr_dict_attr_t const *enumv, bool tainted)
{
	fr_dbuff_t work_dbuff = FR_DBUFF(dbuff);
	bool indefinite;
	uint8_t major, info;
	ssize_t slen;
	int64_t neg;
	uint64_t value;
	uint8_t *ptr;

	FR_DBUFF_OUT_RETURN(&major, &work_dbuff);

	if (type == FR_TYPE_NULL) {
		type = cbor_guess_type(&work_dbuff, false);
		if (type == FR_TYPE_NULL) {
			fr_strerror_const("Unable to determine data type from cbor");
			return -1;
		}
	}

	fr_value_box_init(vb, type, enumv, tainted);

	info = major & 0x1f;
	major >>= 5;

	/*
	 *	Invalid combinations.
	 */
	if (((info >= 28) && (info <= 30)) ||
	    ((info == 31) && ((major == 0) || (major == 1) || (major == 6)))) {
		fr_strerror_const("Invalid cbor data - input is not 'well formed'");
		return -1;
	}

	switch (major) {
	case CBOR_STRING:
		if (type != FR_TYPE_STRING) {
		mismatch:
			fr_strerror_printf("cbor data contains invalid content %d for expected data type %s",
					   major, fr_type_to_str(type));
			return -1;
		}

		if (info == 31) {
		no_chunks:
			fr_strerror_const("Chunked strings are not supported");
			return -1;
		}


		/*
		 *	@todo - undefinite length strings.  Which are really "chunked" strings.
		 */
		slen = cbor_decode_integer(&value, info, &work_dbuff);
		if (slen < 0) return_slen;

		/*
		 *	A little bit of sanity check.
		 */
		if (value > (1 << 20)) {
			fr_strerror_printf("cbor data string is too long (%" PRIu64 ")", value);
			return -1;
		}

		ptr = talloc_array(ctx, uint8_t, value + 1);
		if (!ptr) {
			fr_strerror_const("Out of memory");
			return -1;
		}
		talloc_set_type(ptr, char);
		if (value) FR_DBUFF_OUT_MEMCPY_RETURN(ptr, &work_dbuff, value);
		ptr[value] = '\0';

		fr_value_box_strdup_shallow(vb, NULL, (char const *) ptr, tainted);

		break;

	case CBOR_OCTETS:
		if (type != FR_TYPE_OCTETS) goto mismatch;

		if (info == 31) goto no_chunks;

		/*
		 *	@todo - indefinite length octet strings.  Which are really "chunked" octet strings.
		 */
		slen = cbor_decode_integer(&value, info, &work_dbuff);
		if (slen < 0) return_slen;

		/*
		 *	A little bit of sanity check.
		 */
		if (value > (1 << 20)) {
			fr_strerror_printf("cbor data string is too long (%" PRIu64 ")", value);
			return -1;
		}

		ptr = talloc_array(ctx, uint8_t, value);
		if (!ptr) {
			fr_strerror_const("Out of memory");
			return -1;
		}

		fr_value_box_memdup_shallow(vb, NULL, (uint8_t const *) ptr, value, false); /* tainted? */

		if (value) FR_DBUFF_OUT_MEMCPY_RETURN(ptr, &work_dbuff, value);
		break;

	case CBOR_INTEGER:
		slen = cbor_decode_integer(&value, info, &work_dbuff);
		if (slen < 0) return_slen;

		switch (type) {
		case FR_TYPE_BOOL:
			if (value > 1) goto invalid_bool;
			vb->vb_bool = value;
			break;

		case FR_TYPE_UINT8:
			if (value > UINT8_MAX) {
			invalid:
				fr_strerror_printf("cbor value is too large for output data type %s",
						   fr_type_to_str(type));
				return -1;
			}
			vb->vb_uint8 = value;
			break;

		case FR_TYPE_UINT16:
			if (value > UINT16_MAX) goto invalid;
			vb->vb_uint16 = value;
			break;

		case FR_TYPE_UINT32:
			if (value > UINT32_MAX) goto invalid;
			vb->vb_uint32 = value;
			break;

		case FR_TYPE_UINT64:
			vb->vb_uint64 = value;
			break;

		case FR_TYPE_INT8:
			if (value > INT8_MAX) goto invalid;
			vb->vb_int8 = value;
			break;

		case FR_TYPE_INT16:
			if (value > INT16_MAX) goto invalid;
			vb->vb_int16 = value;
			break;

		case FR_TYPE_INT32:
			if (value > INT32_MAX) goto invalid;
			vb->vb_int32 = value;
			break;

		case FR_TYPE_INT64:
			if (value > INT64_MAX) goto invalid;
			vb->vb_int64 = value;
			break;

		default:
		integer_type_mismatch:
			fr_strerror_printf("Unexpected cbor type 'integer' when decoding data type %s",
					   fr_type_to_str(type));
			return -1;
		}
		break;

	case CBOR_NEGATIVE:
		slen = cbor_decode_integer(&value, info, &work_dbuff);
		if (slen < 0) return_slen;

		/*
		 *	Signed numbers only go down to -2^63
		 *	so value must be less than 2^63
		 */
		if (value >= ((uint64_t) 1) << 63) goto invalid;

		/*
		 *	Convert 0..(2^63-1) into -0..-(2^63-1)
		 *	then conver to -1..-(2^63)
		 */
		neg = -value;
		neg--;

		switch (type) {
		case FR_TYPE_INT8:
			if (neg < INT8_MIN) goto invalid;
			vb->vb_int8 = neg;
			break;

		case FR_TYPE_INT16:
			if (neg < INT16_MIN) goto invalid;
			vb->vb_int16 = neg;
			break;

		case FR_TYPE_INT32:
			if (neg < INT32_MIN) goto invalid;
			vb->vb_int32 = neg;
			break;

		case FR_TYPE_INT64:
			vb->vb_int64 = neg;
			break;

		default:
			goto integer_type_mismatch;
		}
		break;

	case CBOR_FLOAT:
		/*
		 *	Simple values.  See RFC 8489 Section 3.3.
		 *
		 *	20 - false
		 *	21 - true
		 *	22 - NULL
		 */
		if (info < 24) {
			switch (type) {
			case FR_TYPE_BOOL:
				if (info == 20) {
					vb->vb_bool = false;
					break;
				}

				if (info == 21) {
					vb->vb_bool = true;
					break;
				}

			invalid_bool:
				fr_strerror_printf("Invalid cbor - boolean is not encoded as 'true' or 'false'");
				return -fr_dbuff_used(&work_dbuff);

			case FR_TYPE_OCTETS:
			case FR_TYPE_STRING:
			case FR_TYPE_TLV:
			case FR_TYPE_VENDOR:
			case FR_TYPE_GROUP:
			case FR_TYPE_STRUCT:
				/*
				 *	Be a little forgiving.  22 is NULL, so we treat that as "nothing".
				 *
				 *	i.e. empty string, empty set, etc.
				 */
				if (info == 22) break;

				FALL_THROUGH;

			default:
				fr_strerror_printf("Invalid cbor - unexpected 'simple value' %u", info);
				return -fr_dbuff_used(&work_dbuff);
			}
			break;
		}

		/*
		 *	Or as one-byte integers.
		 */
		if (info == CBOR_1_BYTE) {
			uint8_t data;

			FR_DBUFF_OUT_RETURN(&data, &work_dbuff);

			switch (type) {
			case FR_TYPE_FLOAT32:
				vb->vb_float32 = data;
				break;

			case FR_TYPE_FLOAT64:
				vb->vb_float64 = data;
				break;

			default:
			float_type_mismatch:
				fr_strerror_printf("Unexpected cbor type 'float' when decoding data type %s",
						   fr_type_to_str(type));
				return -1;
			}

			break;
		}

		/*
		 *	We don't support float16
		 */

		if (info == CBOR_4_BYTE) {
			float data;

			FR_DBUFF_OUT_RETURN(&data, &work_dbuff);

			switch (type) {
			case FR_TYPE_FLOAT32:
				vb->vb_float32 = data;
				break;

			case FR_TYPE_FLOAT64:
				vb->vb_float64 = (double) data;
				break;

			default:
				goto float_type_mismatch;
			}

			break;
		}

		if (info == CBOR_8_BYTE) {
			double data;

			FR_DBUFF_OUT_RETURN(&data, &work_dbuff);

			switch (type) {
			case FR_TYPE_FLOAT32:
				vb->vb_float32 = data; /* maybe loses precision? */
				break;

			case FR_TYPE_FLOAT64:
				vb->vb_float64 = data;
				break;

			default:
				goto float_type_mismatch;
			}

			break;
		}

		/*
		 *	24 is FLOAT16, which we don't support.
		 *	31 is BREAK, which the caller should have checked for.
		 */
		goto float_type_mismatch;

	case CBOR_TAG:
		/*
		 *	We only support a limited number of tags.
		 */
		slen = cbor_decode_integer(&value, info, &work_dbuff);
		if (slen < 0) return_slen;

		/*
		 *	No tag defined for this data type, that's on us.
		 */
		if (!cbor_type_to_tag[type]) {
			fr_strerror_printf("Unknown cbor tag %" PRIu64 " for expected data type %s",
					   value, fr_type_to_str(type));
			return -fr_dbuff_used(&work_dbuff);
		}

		/*
		 *	Wrong tag for this data type, that's on them.
		 */
		if (cbor_type_to_tag[type] != value) {
			fr_strerror_printf("Invalid cbor tag %" PRIu64 " for expected data type %s",
					   value, fr_type_to_str(type));
			return -fr_dbuff_used(&work_dbuff);
		}

		fr_value_box_init(vb, type, enumv, tainted);

		slen = cbor_decode_type[type](ctx, vb, &work_dbuff);
		if (slen < 0) return_slen;
		break;

	case CBOR_ARRAY:
		if (type != FR_TYPE_GROUP) goto invalid_type;

		/*
		 *	Loop until done.
		 */
		if (info == 31) {
			value = ~0;
			indefinite = true;

		} else {
			slen = cbor_decode_integer(&value, info, &work_dbuff);
			if (slen < 0) return_slen;

			indefinite = false;
		}

#ifdef STATIC_ANALYZER
		if (value > fr_dbuff_remaining(&work_dbuff)) return -1;
#endif

		/*
		 *	Loop until we decode everything.  For simplicity, we handle indefinite and definite
		 *	length arrays in the same loop.
		 */
		for (/* nothing */; value > 0; value--) {
			uint8_t header;
			fr_value_box_t *child;

			/*
			 *	Require at least one byte in the buffer.
			 */
			FR_DBUFF_EXTEND_LOWAT_OR_RETURN(&work_dbuff, 1);

			/*
			 *	Peek ahead for a break.
			 */
			header = *fr_dbuff_current(&work_dbuff);
			if (header == 0xff) {
				if (!indefinite) {
					fr_strerror_const("Unexpected 'break' found in cbor data");
					return -fr_dbuff_used(&work_dbuff);
				}

				/*
				 *	Done!
				 */
				fr_dbuff_advance(&work_dbuff, 1);
				break;
			}

			child = fr_value_box_alloc(ctx, FR_TYPE_NULL, NULL);
			if (!child) {
				fr_strerror_const("Out of memory");
				return -fr_dbuff_used(&work_dbuff);
			}

			/*
			 *	We have to decode at least one value.
			 */
			slen = fr_cbor_decode_value_box(child, child, &work_dbuff, FR_TYPE_NULL, NULL, tainted);
			if (slen <= 0) {
				talloc_free(child);
				return_slen;
			}

			fr_value_box_list_insert_tail(&vb->vb_group, child);
		}
		break;

		/*
		 *	These are not value-box types.
		 */
	case CBOR_MAP:
	invalid_type:
		fr_strerror_printf("Invalid data type %s for cbor to value-box", fr_type_to_str(type));
		return -1;
	}

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/** Encode a pair
 *
 */
ssize_t fr_cbor_encode_pair(fr_dbuff_t *dbuff, fr_pair_t *vp)
{
	fr_dbuff_t	work_dbuff = FR_DBUFF(dbuff);
	ssize_t		slen;
	fr_dict_attr_t const *parent;
	size_t		count;

	FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, (uint8_t) ((CBOR_MAP << 5) | 1)); /* map of 1 item */

	/*
	 *	Key is the attribute number.
	 */
	slen = cbor_encode_integer(&work_dbuff, CBOR_INTEGER, vp->da->attr);
	if (slen <= 0) return_slen;

	/*
	 *	Value is the actual value of the leaf, or the array of children.
	 */
	switch (vp->vp_type) {
	case FR_TYPE_LEAF:
		slen = fr_cbor_encode_value_box(&work_dbuff, &vp->data);
		if (slen <= 0) return_slen;
		break;

		/*
		 *	Groups reparent to the ref.
		 */
	case FR_TYPE_GROUP:
		parent = fr_dict_attr_ref(vp->da);
		fr_assert(parent != NULL);
		goto encode_children;

		/*
		 *	The only difference between TLV and VSA is that the children of VSA are all VENDORs.
		 */
	case FR_TYPE_VENDOR:
	case FR_TYPE_VSA:
	case FR_TYPE_TLV:
		parent = vp->da;

		/*
		 *	The value is array(children)
		 */
encode_children:
		if (fr_pair_list_num_elements(&vp->vp_group) == 0) {
			FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, (uint8_t) ((CBOR_FLOAT << 5) | 22)); /* NULL */
			break;
		}

		/*
		 *	The groups, etc. may contain internal attributes.  We don't yet deal with those.
		 */
		count = 0;
		fr_pair_list_foreach(&vp->vp_group, child) {
			if (child->da->parent != parent) continue;
			count++;
		}

		slen = cbor_encode_integer(&work_dbuff, CBOR_ARRAY, count);
		if (slen <= 0) return_slen;

		fr_pair_list_foreach(&vp->vp_group, child) {
			/*
			 *	We don't allow changing dictionaries here.
			 */
			if (child->da->parent != parent) continue;

			slen = fr_cbor_encode_pair(&work_dbuff, child);
			if (slen <= 0) return_slen;
		}
		break;

	/*
	 *	@todo - struct, except if we hit the end of the struct, check if the next child is the child
	 *	of the key?  That makes it all more annoying :(
	 */

	default:
		fr_strerror_printf("Invalid data type %s for cbor encoding", fr_type_to_str(vp->vp_type));
		return -1;
	}

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/** Guess the data type of the CBOR data.
 *
 *  We've parsed the attribute number, and found that we don't have a dictionary entry for it.  But rather
 *  than create an attribute of type octets, we try to guess the data type.
 */
static fr_type_t cbor_guess_type(fr_dbuff_t *dbuff, bool pair)
{
	fr_dbuff_t work_dbuff = FR_DBUFF(dbuff);
	ssize_t slen;
	uint8_t major, info;
	uint64_t value;

	/*
	 *	get the next byte, which is a CBOR header.
	 */
	slen = fr_dbuff_out(&major, &work_dbuff);
	if (slen <= 0) {
	no_data:
		fr_strerror_const("Invalid cbor - insufficient data");
		return FR_TYPE_NULL;
	}

	info = major & 0x1f;
	major >>= 5;

	switch (major) {
	case CBOR_INTEGER:
		return FR_TYPE_UINT64;

	case CBOR_NEGATIVE:
		return FR_TYPE_UINT64;

	case CBOR_STRING:
		return FR_TYPE_STRING;

	case CBOR_OCTETS:
		return FR_TYPE_OCTETS;

	case CBOR_ARRAY:
		if (!pair) return FR_TYPE_GROUP;
		break;

	case CBOR_MAP:
		return FR_TYPE_TLV;

		/*
		 *	Look at the tag to determine what it is
		 */
	case CBOR_TAG:
		slen = cbor_decode_integer(&value, info, &work_dbuff);
		if (slen < 0) break;

		switch (value) {
		case 1:
		case 1001:
			return FR_TYPE_DATE;

		case 1002:
			return FR_TYPE_TIME_DELTA;

		case 48:
			return FR_TYPE_ETHERNET;

		case 52:
			slen = fr_dbuff_out(&major, &work_dbuff);
			if (slen <= 0) goto no_data;

			major >>= 5;

			if (major == CBOR_ARRAY) {
				return FR_TYPE_IPV4_PREFIX;
			}
			return FR_TYPE_IPV4_ADDR;

		case 54:
			slen = fr_dbuff_out(&major, &work_dbuff);
			if (slen <= 0) goto no_data;

			major >>= 5;

			if (major == CBOR_ARRAY) {
				return FR_TYPE_IPV6_PREFIX;
			}
			return FR_TYPE_IPV6_ADDR;

		default:
			break;
		}

		break;

	case CBOR_FLOAT:
		/*
		 *	In-place values are special. false / true / NULL
		 */
		if (info < 24) {
			if ((info == 20) || (info == 21)) return FR_TYPE_BOOL;

			return FR_TYPE_NULL;
		}

		return FR_TYPE_FLOAT64;
	}


	/*
	 *	No idea.  :(
	 *
	 *	@todo - also check the cbor data, and return the length of cbor data which needs to be
	 *	converted to data type 'octets'.  This work involves mostly parsing the cbor data, which isn't
	 *	trivial.
	 */
	fr_strerror_const("Invalid cbor - unable to determine data type");
	return FR_TYPE_NULL;
}

static ssize_t cbor_decode_pair(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dbuff_t *dbuff,
				fr_dict_attr_t const *parent, bool tainted, int depth)
{
	fr_dbuff_t work_dbuff = FR_DBUFF(dbuff);
	uint8_t header, major, info;
	bool indefinite;
	ssize_t slen;
	fr_pair_t *vp;
	uint64_t value = 0;
	fr_dict_attr_t const *da;

	FR_DBUFF_OUT_RETURN(&header, &work_dbuff);

	/*
	 *	We require a 2-element array(attribute number, value)
	 */
	if (header != (((CBOR_MAP) << 5) | 1)) {
		fr_strerror_printf("Invalid cbor header - expected map of 1 elements, got %02x", header);
		return -1;
	}

	/*
	 *	This should be a CBOR_INTEGER.
	 */
	FR_DBUFF_OUT_RETURN(&major, &work_dbuff);

	info = major & 0x1f;
	major >>= 5;

	if (major != CBOR_INTEGER) {
		fr_strerror_printf("Invalid cbor - expected 'integer', got major type %d",
				   major);
		return -1;
	}

	slen = cbor_decode_integer(&value, info, &work_dbuff);
	if (slen < 0) {
		return_slen;
	}

	/*
	 *	If the nesting is too deep, decode as raw octets.  We have to do this manually in CBOR,
	 *	because the other protocols create a da_stack which limits the depth.
	 */
	if (depth >= FR_DICT_MAX_TLV_STACK) goto raw;

	da = fr_dict_attr_child_by_num(parent, value);
	if (!da) {
		fr_type_t type;

		type = cbor_guess_type(&work_dbuff, true);
		if (type == FR_TYPE_NULL) return -fr_dbuff_used(&work_dbuff);

		if (depth >= FR_DICT_MAX_TLV_STACK) {
		raw:
			type = FR_TYPE_OCTETS;
		}

		/*
		 *	@todo - the value here isn't a cbor octets type, but is instead cbor data.  Since cbor
		 *	is typed, we _could_ perhaps instead discover the type from the cbor data, and then
		 *	use that instead.  This would involve creating a function which maps cbor types to our
		 *	data types.
		 */
		da = fr_dict_attr_unknown_typed_afrom_num(ctx, parent, value, type);
		if (!da) return -fr_dbuff_used(&work_dbuff);
	}

	vp = fr_pair_afrom_da(ctx, da);
	if (!vp) {
		fr_strerror_const("Out of memory");
		return -fr_dbuff_used(&work_dbuff);
	}

	/*
	 *	Leaf values are easy.
	 */
	if (fr_type_is_leaf(da->type)) {
		slen = fr_cbor_decode_value_box(vp, &vp->data, &work_dbuff, da->type, da, tainted);
		if (slen < 0) {
			talloc_free(vp);
			return_slen;
		}

		goto done;
	}

	fr_assert(fr_type_is_structural(da->type));

	switch (da->type) {
		/*
		 *	All of these are essentially the same.
		 */
	case FR_TYPE_VENDOR:
	case FR_TYPE_VSA:
	case FR_TYPE_TLV:
		parent = vp->da;
		break;

		/*
		 *	Groups reparent to the ref.
		 */
	case FR_TYPE_GROUP:
		parent = fr_dict_attr_ref(vp->da);
		fr_assert(parent != NULL);
		break;

	default:
		fr_strerror_printf("Invalid data type %s for child %s of %s",
				   fr_type_to_str(da->type), vp->da->name, parent->name);
		talloc_free(vp);
		return -1;
	}

	/*
	 *	This should be a CBOR_ARRAY.
	 */
	FR_DBUFF_OUT_RETURN(&major, &work_dbuff);

	info = major & 0x1f;
	major >>= 5;

	if (major != CBOR_ARRAY) {
		/*
		 *	Allow NULL as a synonym for "no children".
		 */
		if ((major == CBOR_FLOAT) && (info == 22)) goto done;

		talloc_free(vp);
		fr_strerror_printf("Invalid cbor - expected 'array', got major type %d",
				   major);
		return -1;
	}

	if (info == 31) {
		value = ~0;
		indefinite = true;

	} else {
		slen = cbor_decode_integer(&value, info, &work_dbuff);
		if (slen < 0) {
			talloc_free(vp);
			return_slen;
		}

		indefinite = false;
	}

#ifdef STATIC_ANALYZER
	if (value > fr_dbuff_remaining(&work_dbuff)) return -1;
#endif

	/*
	 *	Loop until we decode everything.  For simplicity, we handle indefinite and definite
	 *	length arrays in the same loop.
	 */
	for (/* nothing */; value > 0; value--) {
		/*
		 *	Require at least one byte in the buffer.
		 */
		if (fr_dbuff_extend_lowat(NULL, &work_dbuff, 1) == 0) {
			talloc_free(vp);
			return -fr_dbuff_used(&work_dbuff);
		}

		/*
		 *	Peek ahead for a break.
		 */
		header = *fr_dbuff_current(&work_dbuff);
		if (header == 0xff) {
			if (!indefinite) {
				talloc_free(vp);
				fr_strerror_const("Unexpected 'break' found in cbor data");
				return -fr_dbuff_used(&work_dbuff);
			}

			/*
			 *	Done!
			 */
			fr_dbuff_advance(&work_dbuff, 1);
			break;
		}

		slen = cbor_decode_pair(vp, &vp->vp_group, &work_dbuff, parent, tainted, depth + 1);
		if (slen <= 0) {
			talloc_free(vp);
			return_slen;
		}
	}

done:
	PAIR_VERIFY(vp);

	fr_pair_append(out, vp);
	return fr_dbuff_set(dbuff, &work_dbuff);
}

ssize_t fr_cbor_decode_pair(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dbuff_t *dbuff,
			    fr_dict_attr_t const *parent, bool tainted)
{
	return cbor_decode_pair(ctx, out, dbuff, parent, tainted, 0);
}

/*
 *	@todo - cbor_print
 *	[] for array
 *	[_...] for indefinite array
 *	{a:b} for map
 *	digits for integer
 *	'string' for string
 *	h'HHHH' for octets
 *
 *	https://datatracker.ietf.org/doc/html/draft-ietf-cbor-edn-literals
 */
