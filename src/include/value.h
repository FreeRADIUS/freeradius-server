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
#ifndef _FR_VALUE_H
#define _FR_VALUE_H
#include <freeradius-devel/inet.h>
#include <freeradius-devel/types.h>
#include <freeradius-devel/dict.h>

extern size_t const fr_value_box_field_sizes[];
extern size_t const fr_value_box_offsets[];

#define fr_value_box_foreach(_v, _iv) for (fr_value_box_t *_iv = v; _iv; _iv = _iv->next)

/** Union containing all data types supported by the server
 *
 * This union contains all data types that can be represented by VALUE_PAIRs. It may also be used in other parts
 * of the server where values of different types need to be stored.
 *
 * fr_type_t should be an enumeration of the values in this union.
 */
typedef struct value_box fr_value_box_t;
struct value_box {
	union {
		/*
		 *	Variable length values
		 */
		struct {
			union {
				char const	*strvalue;	//!< Pointer to UTF-8 string.
				uint8_t const	*octets;	//!< Pointer to binary string.
				void		*ptr;		//!< generic pointer.
				uint8_t		filter[32];	//!< Ascend binary format (a packed data structure).

			};
			size_t length;
		};

		fr_ipaddr_t		ip;			//!< IPv4/6 address/prefix.

		uint8_t			ifid[8];		//!< IPv6 interface ID (should be struct?).
		uint8_t			ether[6];		//!< Ethernet (MAC) address.

		bool			boolean;		//!< A truth value.

		struct {
			union {
				uint8_t		uint8;		//!< 8bit unsigned integer.
				uint16_t	uint16;		//!< 16bit unsigned integer.
				uint32_t	uint32;		//!< 32bit unsigned integer.
				uint64_t	uint64;		//!< 64bit unsigned integer.
				uint128_t	uint128;	//!< 128bit unsigned integer.

				int8_t		int8;		//!< 8bit signed integer.
				int16_t		int16;		//!< 16bit signed integer.
				int32_t		int32;		//!< 32bit signed integer.
				int64_t		int64;		//!< 64bit signed integer;
			};
			fr_dict_attr_t const	*enumv;		//!< Enumeration values for integer type.
		};

		float			float32;		//!< Single precision float.
		double			float64;		//!< Double precision float.

		uint32_t		date;			//!< Date (32bit Unix timestamp).
		uint64_t		date_miliseconds;	//!< milliseconds since the epoch.
		uint64_t		date_microseconds;	//!< microseconds since the epoch.
		uint64_t		date_nanoseconds;	//!< nanoseconds since the epoch.

		/*
		 *	System specific - Used for runtime
		 *	configuration only.
		 */
		size_t			size;			//!< System specific file/memory size.
		struct timeval		timeval;		//!< A time value with usec precision.

	} datum;

	fr_type_t			type;			//!< Type of this value-box.

	bool				tainted;		//!< i.e. did it come from an untrusted source

	fr_value_box_t			*next;			//!< Next in a series of value_box.
};


/*
 *	Argument boxing macros
 *
 *	These macros allow C types to be passed to functions which take
 *	boxed arguments, without needing to declare a fr_value_box_t
 *	explicitly on the stack.
 */
#define _fr_box_with_len(_type, _field, _val, _len) &(fr_value_box_t){ .type = _type, _field = _val, .datum.length = _len }

#define fr_box_strvalue(_val)			-fr_box_with_len(FR_TYPE_STRING, .datum.strvalue, _val, strlen(_val))
#define fr_box_octets(_val, _len)		_fr_box_with_len(FR_TYPE_OCTETS, .datum.octets, _val, _len)
#define fr_box_strvalue_buffer(_val)		_fr_box_with_len(FR_TYPE_STRING, .datum.strvalue, _val, talloc_array_length(_val) - 1)
#define fr_box_octets_buffer(_val)		_fr_box_with_len(FR_TYPE_OCTETS, .datum.octets, _val, talloc_array_length(_val))

#define _fr_box(_type, _field, _val) &(fr_value_box_t){ .type = _type, _field = _val }

#define fr_box_ipv4addr(_val)			_fr_box(FR_TYPE_IPV4_ADDR, .datum.ip, _val)
#define fr_box_ipv4prefix(_val)			_fr_box(FR_TYPE_IPV4_PREFIX, .datum.ip, _val)
#define fr_box_ipv6addr(_val)			_fr_box(FR_TYPE_IPV6_ADDR, .datum.ip, _val)
#define fr_box_ipv6prefix(_val)			_fr_box(FR_TYPE_IPV6_PREFIX, .datum.ip, _val)

#define fr_box_ifid(_val)			_fr_box(FR_TYPE_IFID, .datum.ifid, _val)
#define fr_box_ether(_val)			_fr_box(FR_TYPE_ETHERNET, .datum.ether, _val)

#define fr_box_uint8(_val)			_fr_box(FR_TYPE_UINT8, .datum.uint8, _val)
#define fr_box_uint16(_val)			_fr_box(FR_TYPE_UINT16, .datum.uint16, _val)
#define fr_box_uint32(_val)			_fr_box(FR_TYPE_UINT32, .datum.uint32, _val)
#define fr_box_uint64(_val)			_fr_box(FR_TYPE_UINT64, .datum.uint64, _val)
#define fr_box_uint128(_val)			_fr_box(FR_TYPE_UINT128, .datum.uint128, _val)

#define fr_box_int8(_val)			_fr_box(FR_TYPE_INT8, .datum.int8, _val)
#define fr_box_int16(_val)			_fr_box(FR_TYPE_INT16, .datum.int16, _val)
#define fr_box_int32(_val)			_fr_box(FR_TYPE_INT32, .datum.int32, _val)
#define fr_box_int64(_val)			_fr_box(FR_TYPE_INT64, .datum.int64, _val)

#define fr_box_float32(_val)			_fr_box(FR_TYPE_FLOAT32, .datum.float32, _val)
#define fr_box_float64(_val)			_fr_box(FR_TYPE_FLOAT64, .datum.float64, _val)

#define fr_box_date(_val)			_fr_box(FR_TYPE_DATE, date, _val)
#define fr_box_date_miliseconds(_val)		_fr_box(FR_TYPE_DATE_MILISECONDS, date_miliseconds, _val)
#define fr_box_date_microseconds(_val)		_fr_box(FR_TYPE_DATE_MICROSECONDS, date_microseconds, _val)
#define fr_box_date_nanoseconds(_val)		_fr_box(FR_TYPE_DATE_NANOSECONDS, date_nanoseconds, _val)

/*
 *	Unboxing macros
 *
 *	These macros will in future do type checking in developer builds,
 *	in addition to getting the box value.
 */
#define fr_unbox_strvalue(_box)			_box->datum.strvalue
#define fr_unbox_octets(_box)			_box->datum.octets

#define fr_unbox_ipv4addr(_box)			_box->datum.ip
#define fr_unbox_ipv4prefix(_box)		_box->datum.ip
#define fr_unbox_ipv6addr(_box)			_box->datum.ip
#define fr_unbox_ipv6prefix(_box)		_box->datum.ip

#define fr_unbox_ifid(_box)			_box->datum.ifid
#define fr_unbox_ether(_box)			_box->datum.ether

#define fr_unbox_uint8(_box)			_box->datum.uint8
#define fr_unbox_uint16(_box)			_box->datum.uint16
#define fr_unbox_uint32(_box)			_box->datum.uint32
#define fr_unbox_uint64(_box)			_box->datum.uint64
#define fr_unbox_uint128(_box)			_box->datum.uint128

#define fr_unbox_int8(_box)			_box->datum.int8
#define fr_unbox_int16(_box)			_box->datum.int16
#define fr_unbox_int32(_box)			_box->datum.int32
#define fr_unbox_int64(_box)			_box->datum.int64

#define fr_unbox_float32(_box)			_box->datum.float32
#define fr_unbox_float64(_box)			_box->datum.float64

#define fr_unbox_date(_val)			_box->datum.date
#define fr_unbox_date_miliseconds(_val)		_box->datum.date_miliseconds
#define fr_unbox_date_microseconds(_val)	_box->datum.date_microseconds
#define fr_unbox_date_nanoseconds(_val)		_box->datum.date_nanoseconds

/*
 *	Allocation
 */
fr_value_box_t	*fr_value_box_alloc(TALLOC_CTX *ctx, fr_type_t type);

void		fr_value_box_clear(fr_value_box_t *data);

/*
 *	Comparison
 */
int		fr_value_box_cmp(fr_value_box_t const *a, fr_value_box_t const *b);

int		fr_value_box_cmp_op(FR_TOKEN op, fr_value_box_t const *a, fr_value_box_t const *b);

/*
 *	Conversion
 */
size_t		value_str_unescape(uint8_t *out, char const *in, size_t inlen, char quote);

int		fr_value_box_hton(fr_value_box_t *dst, fr_value_box_t const *src);

int		fr_value_box_cast(TALLOC_CTX *ctx, fr_value_box_t *dst,
				  fr_type_t dst_type, fr_dict_attr_t const *dst_enumv,
				  fr_value_box_t const *src);

/*
 *	Assignment
 */
int		fr_value_box_copy(TALLOC_CTX *ctx, fr_value_box_t *dst,  const fr_value_box_t *src);
void		fr_value_box_copy_shallow(TALLOC_CTX *ctx, fr_value_box_t *dst, const fr_value_box_t *src);
int		fr_value_box_steal(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_value_box_t const *src);

int		fr_value_box_strdup(TALLOC_CTX *ctx, fr_value_box_t *dst, char const *src, bool tainted);
int		fr_value_box_strdup_buffer(TALLOC_CTX *ctx, fr_value_box_t *dst, char const *src, bool tainted);
int		fr_value_box_strsteal(TALLOC_CTX *ctx, fr_value_box_t *dst, char *src, bool tainted);
int		fr_value_box_strdup_shallow(fr_value_box_t *dst, char const *src, bool tainted);
int		fr_value_box_strdup_buffer_shallow(TALLOC_CTX *ctx, fr_value_box_t *dst, char const *src, bool tainted);

int		fr_value_box_memdup(TALLOC_CTX *ctx, fr_value_box_t *dst, uint8_t const *src, size_t len, bool tainted);
int		fr_value_box_memdup_buffer(TALLOC_CTX *ctx, fr_value_box_t *dst, uint8_t *src, bool tainted);
int		fr_value_box_memsteal(TALLOC_CTX *ctx, fr_value_box_t *dst, uint8_t const *src, bool tainted);
int		fr_value_box_memdup_shallow(fr_value_box_t *dst, uint8_t *src, size_t len, bool tainted);
int		fr_value_box_memdup_buffer_shallow(TALLOC_CTX *ctx, fr_value_box_t *dst, uint8_t *src, bool tainted);

/*
 *	Parsing
 */
int		fr_value_box_from_ipaddr(fr_value_box_t *dst, fr_ipaddr_t const *ipaddr);

int		fr_value_box_from_str(TALLOC_CTX *ctx, fr_value_box_t *dst,
				      fr_type_t *src_type, fr_dict_attr_t const *src_enumv,
				      char const *src, ssize_t src_len, char quote);

/*
 *	Printing
 */
size_t		fr_value_box_network_length(fr_value_box_t *value);

char		*fr_value_box_asprint(TALLOC_CTX *ctx, fr_value_box_t const *data, char quote);

size_t		fr_value_box_snprint(char *out, size_t outlen, fr_value_box_t const *data, char quote);
#endif /* _FR_VALUE_H */
