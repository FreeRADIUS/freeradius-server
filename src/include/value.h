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
#include <freeradius-devel/missing.h>		/* For uint128_t */
#include <freeradius-devel/inet.h>
#include <freeradius-devel/types.h>
#include <freeradius-devel/debug.h>

/*
 *	Avoid circular type references.
 */
typedef struct value_box fr_value_box_t;

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
			size_t		length;
		};

		/*
		 *	Fixed length values
		 */
		fr_ipaddr_t		ip;			//!< IPv4/6 address/prefix.

		uint8_t			ifid[8];		//!< IPv6 interface ID (should be struct?).
		uint8_t			ether[6];		//!< Ethernet (MAC) address.

		bool			boolean;		//!< A truth value.

		uint8_t			uint8;			//!< 8bit unsigned integer.
		uint16_t		uint16;			//!< 16bit unsigned integer.
		uint32_t		uint32;			//!< 32bit unsigned integer.
		uint64_t		uint64;			//!< 64bit unsigned integer.
		uint128_t		uint128;		//!< 128bit unsigned integer.

		int8_t			int8;			//!< 8bit signed integer.
		int16_t			int16;			//!< 16bit signed integer.
		int32_t			int32;			//!< 32bit signed integer.
		int64_t			int64;			//!< 64bit signed integer;

		float			float32;		//!< Single precision float.
		double			float64;		//!< Double precision float.

		uint32_t		date;			//!< Date (32bit Unix timestamp).

		uint64_t		date_milliseconds;	//!< milliseconds since the epoch.
		uint64_t		date_microseconds;	//!< microseconds since the epoch.
		uint64_t		date_nanoseconds;	//!< nanoseconds since the epoch.

		/*
		 *	System specific - Used for runtime configuration only.
		 */
		size_t			size;			//!< System specific file/memory size.
		struct timeval		timeval;		//!< A time value with usec precision.
	} datum;

	fr_dict_attr_t const		*enumv;			//!< Enumeration values.

	fr_type_t			type;			//!< Type of this value-box.

	bool				tainted;		//!< i.e. did it come from an untrusted source

	fr_value_box_t			*next;			//!< Next in a series of value_box.
};

/*
 *	Versions of ntho* which expect a binary buffer
 */
#define fr_ntoh16_bin(_p) (uint16_t)((p[0] << 8) | p[1])
#define fr_ntoh24_bin(_p) (uint32_t)((p[0] << 16) | (p[1] << 8) | p[2])
#define fr_ntoh32_bin(_p) (uint32_t)((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3])

/** @name Field accessors for #fr_value_box_t
 *
 * Use these instead of accessing fields directly to make refactoring
 * easier in future.
 *
 * @{
 */
#define vb_strvalue				datum.strvalue
#define vb_octets				datum.octets

#define vb_ip					datum.ip

#define vb_ifid					datum.ifid
#define vb_ether				datum.ether

#define vb_uint8				datum.uint8
#define vb_uint16				datum.uint16
#define vb_uint32				datum.uint32
#define vb_uint64				datum.uint64
#define vb_uint128				datum.uint128

#define vb_int8					datum.int8
#define vb_int16				datum.int16
#define vb_int32				datum.int32
#define vb_int64				datum.int64

#define vb_float32				datum.float32
#define vb_float64				datum.float64

#define vb_date					datum.date
#define vb_date_milliseconds			datum.date_milliseconds
#define vb_date_microseconds			datum.date_microseconds
#define vb_date_nanoseconds			datum.date_nanoseconds

#define vb_size					datum.size
#define vb_timeval				datum.timeval
/* @} **/

/** @name Argument boxing macros
 *
 * These macros allow C types to be passed to functions which take
 * boxed arguments, without needing to declare a fr_value_box_t
 * explicitly on the stack.
 *
 * @{
 */
#define _fr_box_with_len(_type, _field, _val, _len) &(fr_value_box_t){ .type = _type, _field = _val, .datum.length = _len }

#define fr_box_strvalue(_val)			_fr_box_with_len(FR_TYPE_STRING, .vb_strvalue, _val, strlen(_val))
#define fr_box_strvalue_len(_val, _len)		_fr_box_with_len(FR_TYPE_STRING, .vb_strvalue, _val, _len)
#define fr_box_octets(_val, _len)		_fr_box_with_len(FR_TYPE_OCTETS, .vb_octets, _val, _len)
#define fr_box_strvalue_buffer(_val)		_fr_box_with_len(FR_TYPE_STRING, .vb_strvalue, _val, talloc_array_length(_val) - 1)
#define fr_box_octets_buffer(_val)		_fr_box_with_len(FR_TYPE_OCTETS, .vb_octets, _val, talloc_array_length(_val))

#define _fr_box(_type, _field, _val) &(fr_value_box_t){ .type = _type, _field = (_val) }

#define fr_box_ipaddr(_val)			_fr_box(((_val.af == AF_INET) ? \
							((_val.prefix == 32) ?	FR_TYPE_IPV4_ADDR : \
										FR_TYPE_IPV4_PREFIX) : \
							((_val.prefix == 128) ?	FR_TYPE_IPV6_ADDR : \
										FR_TYPE_IPV6_PREFIX)), \
						.vb_ip, _val)
#define fr_box_ipv4addr(_val)			_fr_box(FR_TYPE_IPV4_ADDR, .vb_ip, _val)
#define fr_box_ipv4prefix(_val)			_fr_box(FR_TYPE_IPV4_PREFIX, .vb_ip, _val)
#define fr_box_ipv6addr(_val)			_fr_box(FR_TYPE_IPV6_ADDR, .vb_ip, _val)
#define fr_box_ipv6prefix(_val)			_fr_box(FR_TYPE_IPV6_PREFIX, .vb_ip, _val)

#define fr_box_ifid(_val)			_fr_box(FR_TYPE_IFID, .vb_ifid, _val)
#define fr_box_ether(_val)                      &(fr_value_box_t){ .type = FR_TYPE_ETHERNET, .vb_ether = { _val[0], _val[1], _val[2], _val[3], _val[4], _val[5] } }

#define fr_box_uint8(_val)			_fr_box(FR_TYPE_UINT8, .vb_uint8, _val)
#define fr_box_uint16(_val)			_fr_box(FR_TYPE_UINT16, .vb_uint16, _val)
#define fr_box_uint32(_val)			_fr_box(FR_TYPE_UINT32, .vb_uint32, _val)
#define fr_box_uint64(_val)			_fr_box(FR_TYPE_UINT64, .vb_uint64, _val)
#define fr_box_uint128(_val)			_fr_box(FR_TYPE_UINT128, .vb_uint128, _val)

#define fr_box_int8(_val)			_fr_box(FR_TYPE_INT8, .vb_int8, _val)
#define fr_box_int16(_val)			_fr_box(FR_TYPE_INT16, .vb_int16, _val)
#define fr_box_int32(_val)			_fr_box(FR_TYPE_INT32, .vb_int32, _val)
#define fr_box_int64(_val)			_fr_box(FR_TYPE_INT64, .vb_int64, _val)

#define fr_box_float32(_val)			_fr_box(FR_TYPE_FLOAT32, .vb_float32, _val)
#define fr_box_float64(_val)			_fr_box(FR_TYPE_FLOAT64, .vb_float64, _val)

#define fr_box_date(_val)			_fr_box(FR_TYPE_DATE, .vb_date, _val)
#define fr_box_date_milliseconds(_val)		_fr_box(FR_TYPE_DATE_MILISECONDS, .vb_date_milliseconds, _val)
#define fr_box_date_microseconds(_val)		_fr_box(FR_TYPE_DATE_MICROSECONDS, .vb_date_microseconds, _val)
#define fr_box_date_nanoseconds(_val)		_fr_box(FR_TYPE_DATE_NANOSECONDS, .vb_date_nanoseconds, _val)

#define fr_box_size(_val)			_fr_box(FR_TYPE_SIZE, .vb_size, _val)
#define fr_box_timeval(_val)			_fr_box(FR_TYPE_TIMEVAL, .vb_timeval, _val)
/* @} **/

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

size_t		fr_value_box_network_length(fr_value_box_t *value);

ssize_t		fr_value_box_to_network(size_t *need, uint8_t *out, size_t outlen, fr_value_box_t const *value);

ssize_t		fr_value_box_from_network(TALLOC_CTX *ctx,
					  fr_value_box_t *dst, fr_type_t type, fr_dict_attr_t const *enumv,
				  	  uint8_t const *src, size_t len, bool tainted);

int		fr_value_box_cast(TALLOC_CTX *ctx, fr_value_box_t *dst,
				  fr_type_t dst_type, fr_dict_attr_t const *dst_enumv,
				  fr_value_box_t const *src);

int		fr_value_box_from_ipaddr(fr_value_box_t *dst, fr_dict_attr_t const *enumv,
					 fr_ipaddr_t const *ipaddr, bool tainted);

/*
 *	Assignment
 */
int		fr_value_box_copy(TALLOC_CTX *ctx, fr_value_box_t *dst, const fr_value_box_t *src);
void		fr_value_box_copy_shallow(TALLOC_CTX *ctx, fr_value_box_t *dst, const fr_value_box_t *src);
int		fr_value_box_steal(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_value_box_t const *src);

int		fr_value_box_strdup(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
				    char const *src, bool tainted);
int		fr_value_box_bstrndup(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
				      char const *src, size_t len, bool tainted);
int		fr_value_box_strdup_buffer(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
					   char const *src, bool tainted);
int		fr_value_box_strsteal(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
				      char *src, bool tainted);
int		fr_value_box_strdup_shallow(fr_value_box_t *dst, fr_dict_attr_t const *enumv,
					    char const *src, bool tainted);
int		fr_value_box_strdup_buffer_shallow(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
						   char const *src, bool tainted);

int		fr_value_box_memdup(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
				    uint8_t const *src, size_t len, bool tainted);
int		fr_value_box_memdup_buffer(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
					   uint8_t *src, bool tainted);
int		fr_value_box_memsteal(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
				      uint8_t const *src, bool tainted);
int		fr_value_box_memdup_shallow(fr_value_box_t *dst, fr_dict_attr_t const *enumv,
					    uint8_t *src, size_t len, bool tainted);
int		fr_value_box_memdup_buffer_shallow(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
						   uint8_t *src, bool tainted);

/*
 *	Parsing
 */
int		fr_value_box_from_str(TALLOC_CTX *ctx, fr_value_box_t *dst,
				      fr_type_t *dst_type, fr_dict_attr_t const *dst_enumv,
				      char const *src, ssize_t src_len, char quote, bool tainted);

/*
 *	Printing
 */
char		*fr_value_box_asprint(TALLOC_CTX *ctx, fr_value_box_t const *data, char quote);

size_t		fr_value_box_snprint(char *out, size_t outlen, fr_value_box_t const *data, char quote);
#endif /* _FR_VALUE_H */
