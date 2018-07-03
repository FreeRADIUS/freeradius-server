#pragma once
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

/**
 * $Id$
 *
 * @file include/value.h
 * @brief Boxed values and functions to manipulate them.
 *
 * @copyright 2015-2018 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(value_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/missing.h>		/* For uint128_t */
#include <freeradius-devel/inet.h>
#include <freeradius-devel/types.h>
#include <freeradius-devel/debug.h>
#include <freeradius-devel/fr_log.h>

/*
 *	Avoid circular type references.
 */
typedef struct value_box fr_value_box_t;

#include <freeradius-devel/dict.h>

extern size_t const fr_value_box_field_sizes[];
extern size_t const fr_value_box_offsets[];

#define fr_value_box_foreach(_v, _iv) for (fr_value_box_t *_iv = _v; _iv; _iv = _iv->next)

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

#define vb_bool					datum.boolean
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

#define vb_length				datum.length
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
#define fr_box_date_milliseconds(_val)		_fr_box(FR_TYPE_DATE_MILLISECONDS, .vb_date_milliseconds, _val)
#define fr_box_date_microseconds(_val)		_fr_box(FR_TYPE_DATE_MICROSECONDS, .vb_date_microseconds, _val)
#define fr_box_date_nanoseconds(_val)		_fr_box(FR_TYPE_DATE_NANOSECONDS, .vb_date_nanoseconds, _val)

#define fr_box_size(_val)			_fr_box(FR_TYPE_SIZE, .vb_size, _val)
#define fr_box_timeval(_val)			_fr_box(FR_TYPE_TIMEVAL, .vb_timeval, _val)
/* @} **/


/** @name Value box assignment functions
 *
 * These functions allow C values to be assigned to value boxes.
 * They will work with uninitialised/stack allocated memory.
 *
 * @{
 */

/** Initialise a fr_value_box_t
 *
 * The value should be set later with one of the fr_value_box_* functions.
 *
 * @param[in] box	to initialise.
 * @param[in] type	to set.
 * @param[in] enumv	Enumeration values.
 * @param[in] tainted	Whether data will come from an untrusted source.
 */
static inline void fr_value_box_init(fr_value_box_t *box, fr_type_t type,
				     fr_dict_attr_t const *enumv, bool tainted)
{
	box->type = type;
	box->enumv = enumv;
	box->tainted = tainted;
	box->next = NULL;

	memset(&box->datum, 0, sizeof(box->datum));
}

/** Allocate a value box of a specific type
 *
 * Allocates memory for the box, and sets the length of the value
 * for fixed length types.
 *
 * @param[in] ctx	to allocate the value_box in.
 * @param[in] type	of value.
 * @param[in] enumv	Enumeration values.
 * @param[in] tainted	Whether data will come from an untrusted source.
 * @return
 *	- A new fr_value_box_t.
 *	- NULL on error.
 */
static inline fr_value_box_t *fr_value_box_alloc(TALLOC_CTX *ctx, fr_type_t type,
						 fr_dict_attr_t const *enumv, bool tainted)
{
	fr_value_box_t *value;

	value = talloc_zero(ctx, fr_value_box_t);
	if (!value) return NULL;

	fr_value_box_init(value, type, enumv, tainted);

	return value;
}

/** Allocate a value box for later use with a value assignment function
 *
 * @param[in] ctx	to allocate the value_box in.
 * @return
 *	- A new fr_value_box_t.
 *	- NULL on error.
 */
static inline fr_value_box_t *fr_value_box_alloc_null(TALLOC_CTX *ctx)
{
	fr_value_box_t *value;

	value = talloc_zero(ctx, fr_value_box_t);
	value->type = FR_TYPE_INVALID;

	return value;
}

/** Box an ethernet value (6 bytes, network byte order)
 *
 * @param[in] dst	Where to copy the ethernet address to.
 * @param[in] enumv	Enumeration values.
 * @param[in] src	The ethernet address.
 * @param[in] tainted	Whether data will come from an untrusted source.
 * @return 0 (always successful).
 */
static inline int fr_value_box_ethernet_addr(fr_value_box_t *dst, fr_dict_attr_t const *enumv,
					     uint8_t const src[6], bool tainted)
{
	fr_value_box_init(dst, FR_TYPE_ETHERNET, enumv, tainted);
	memcpy(dst->vb_ether, src, sizeof(dst->vb_ether));
	return 0;
}

#define DEF_BOXING_FUNC(_ctype, _field, _type) \
static inline int fr_value_box_##_field(fr_value_box_t *dst, fr_dict_attr_t const *enumv, _ctype const value, bool tainted) { \
	fr_value_box_init(dst, _type, enumv, tainted); \
	dst->vb_##_field = value; \
	return 0; \
}

DEF_BOXING_FUNC(uint8_t, uint8, FR_TYPE_UINT8)
DEF_BOXING_FUNC(uint16_t, uint16, FR_TYPE_UINT16)
DEF_BOXING_FUNC(uint32_t, uint32, FR_TYPE_UINT32)
DEF_BOXING_FUNC(uint64_t, uint64, FR_TYPE_UINT64)

DEF_BOXING_FUNC(int8_t, int8, FR_TYPE_INT8)
DEF_BOXING_FUNC(int16_t, int16, FR_TYPE_INT16)
DEF_BOXING_FUNC(int32_t, int32, FR_TYPE_INT32)
DEF_BOXING_FUNC(int64_t, int64, FR_TYPE_INT64)

DEF_BOXING_FUNC(float, float32, FR_TYPE_FLOAT32)
DEF_BOXING_FUNC(double, float64, FR_TYPE_FLOAT64)

DEF_BOXING_FUNC(uint64_t, date, FR_TYPE_DATE)
DEF_BOXING_FUNC(uint64_t, date_milliseconds, FR_TYPE_DATE_MILLISECONDS)
DEF_BOXING_FUNC(uint64_t, date_microseconds, FR_TYPE_DATE_MICROSECONDS)
DEF_BOXING_FUNC(uint64_t, date_nanoseconds, FR_TYPE_DATE_NANOSECONDS)

/** Automagically fill in a box, determining the value type from the type of the C variable
 *
 * Simplify boxing for simple C types using the _Generic macro to emit code that
 * fills in the value box based on the type of _var provided.
 *
 * @note Will not set the box value to tainted.  You should do this manually if required.
 *
 * @note Will not work for all box types.  Will default to the 'simpler' box type, if the mapping
 *	 between C type and box type is ambiguous.
 *
 * @param[in] _box	to assign value to.
 * @param[in] _var	C variable to assign value from.
 * @param[in] _tainted	Whether the value came from an untrusted source.
 */
#define fr_value_box_shallow(_box, _var, _tainted) \
_Generic((_var), \
	fr_ipaddr_t *		: fr_value_box_ipaddr, \
	fr_ipaddr_t const *	: fr_value_box_ipaddr, \
	uint8_t			: fr_value_box_uint8, \
	uint8_t const		: fr_value_box_uint8, \
	uint16_t		: fr_value_box_uint16, \
	uint16_t const		: fr_value_box_uint16, \
	uint32_t		: fr_value_box_uint32, \
	uint32_t const		: fr_value_box_uint32, \
	uint64_t		: fr_value_box_uint64, \
	uint64_t const		: fr_value_box_uint64, \
	int8_t			: fr_value_box_int8, \
	int8_t const		: fr_value_box_int8, \
	int16_t			: fr_value_box_int16, \
	int16_t const		: fr_value_box_int16, \
	int32_t			: fr_value_box_int32, \
	int32_t	const		: fr_value_box_int32, \
	int64_t			: fr_value_box_int64, \
	int64_t	const		: fr_value_box_int64, \
	float			: fr_value_box_float32, \
	float const		: fr_value_box_float32, \
	double			: fr_value_box_float64, \
	double const		: fr_value_box_float64 \
)(_box, NULL, _var, _tainted)

/** Unbox an ethernet value (6 bytes, network byte order)
 *
 * @param[in] dst	Where to copy the ethernet address to.
 * @param[in] src	Where to copy the ethernet address from.
 * @return
 *	- 0 on success.
 *	- -1 on type mismatch.
 */
static inline int fr_value_unbox_ethernet_addr(uint8_t dst[6], fr_value_box_t *src)
{
	if (unlikely(src->type != FR_TYPE_ETHERNET)) { \
		fr_strerror_printf("Unboxing failed.  Needed type %s, had type %s",
				   fr_int2str(dict_attr_types, FR_TYPE_ETHERNET, "?Unknown?"),
				   fr_int2str(dict_attr_types, src->type, "?Unknown?"));
		return -1; \
	}
	memcpy(dst, src->vb_ether, sizeof(src->vb_ether));	/* Must be src, dst is a pointer */
	return 0;
}

#define DEF_UNBOXING_FUNC(_ctype, _field, _type) \
static inline int fr_value_unbox_##_field(_ctype *var, fr_value_box_t const *src) { \
	if (unlikely(src->type != _type)) { \
		fr_strerror_printf("Unboxing failed.  Needed type %s, had type %s", \
				   fr_int2str(dict_attr_types, _type, "?Unknown?"), \
				   fr_int2str(dict_attr_types, src->type, "?Unknown?")); \
		return -1; \
	} \
	*var = src->vb_##_field; \
	return 0; \
}

DEF_UNBOXING_FUNC(uint8_t, uint8, FR_TYPE_UINT8)
DEF_UNBOXING_FUNC(uint16_t, uint16, FR_TYPE_UINT16)
DEF_UNBOXING_FUNC(uint32_t, uint32, FR_TYPE_UINT32)
DEF_UNBOXING_FUNC(uint64_t, uint64, FR_TYPE_UINT64)

DEF_UNBOXING_FUNC(int8_t, int8, FR_TYPE_INT8)
DEF_UNBOXING_FUNC(int16_t, int16, FR_TYPE_INT16)
DEF_UNBOXING_FUNC(int32_t, int32, FR_TYPE_INT32)
DEF_UNBOXING_FUNC(int64_t, int64, FR_TYPE_INT64)

DEF_UNBOXING_FUNC(float, float32, FR_TYPE_FLOAT32)
DEF_UNBOXING_FUNC(double, float64, FR_TYPE_FLOAT64)

DEF_UNBOXING_FUNC(uint64_t, date, FR_TYPE_DATE)
DEF_UNBOXING_FUNC(uint64_t, date_milliseconds, FR_TYPE_DATE_MILLISECONDS)
DEF_UNBOXING_FUNC(uint64_t, date_microseconds, FR_TYPE_DATE_MICROSECONDS)
DEF_UNBOXING_FUNC(uint64_t, date_nanoseconds, FR_TYPE_DATE_NANOSECONDS)

/** Unbox simple types peforming type checks
 *
 * @param[out] _var	to write to.
 * @param[in] _box	to unbox.
 */
#define fr_value_unbox_shallow(_var, _box) \
_Generic((_var), \
	uint8_t	*		: fr_value_unbox_uint8, \
	uint16_t *		: fr_value_unbox_uint16, \
	uint32_t *		: fr_value_unbox_uint32, \
	uint64_t *		: fr_value_unbox_uint64, \
	int8_t *		: fr_value_unbox_int8, \
	int16_t	*		: fr_value_unbox_int16, \
	int32_t	*		: fr_value_unbox_int32, \
	int64_t	*		: fr_value_unbox_int64, \
	float *			: fr_value_unbox_float32, \
	double *		: fr_value_unbox_float64 \
)(_var, _box)

/* @} **/

/*
 *	Allocation - init/alloc use static functions (above)
 */
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

int		fr_value_box_cast_in_place(TALLOC_CTX *ctx, fr_value_box_t *vb,
					   fr_type_t dst_type, fr_dict_attr_t const *dst_enumv);

int		fr_value_box_ipaddr(fr_value_box_t *dst, fr_dict_attr_t const *enumv,
					 fr_ipaddr_t const *ipaddr, bool tainted);

int		fr_value_unbox_ipaddr(fr_ipaddr_t *dst, fr_value_box_t *src);

/*
 *	Assignment
 */
int		fr_value_box_copy(TALLOC_CTX *ctx, fr_value_box_t *dst, const fr_value_box_t *src);

void		fr_value_box_copy_shallow(TALLOC_CTX *ctx, fr_value_box_t *dst,
					  const fr_value_box_t *src, bool incr_ref);

int		fr_value_box_steal(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_value_box_t const *src);

int		fr_value_box_strdup(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
				    char const *src, bool tainted);
int		fr_value_box_bstrndup(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
				      char const *src, size_t len, bool tainted);
int		fr_value_box_append_bstr(fr_value_box_t *dst,
					 char const *src, size_t len, bool tainted);

int		fr_value_box_strdup_buffer(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
					   char const *src, bool tainted);
int		fr_value_box_bstrsteal(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
				       char *src, bool tainted);
int		fr_value_box_bstrsnteal(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
				        char **src, size_t inlen, bool tainted);
int		fr_value_box_strdup_shallow(fr_value_box_t *dst, fr_dict_attr_t const *enumv,
					    char const *src, bool tainted);
int		fr_value_box_strdup_buffer_shallow(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
						   char const *src, bool tainted);

int		fr_value_box_memdup(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
				    uint8_t const *src, size_t len, bool tainted);
int		fr_value_box_append_mem(fr_value_box_t *dst,
				       uint8_t const *src, size_t len, bool tainted);
int		fr_value_box_memdup_buffer(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
					   uint8_t *src, bool tainted);
void		fr_value_box_memsteal(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
				      uint8_t const *src, bool tainted);
int		fr_value_box_memdup_shallow(fr_value_box_t *dst, fr_dict_attr_t const *enumv,
					    uint8_t *src, size_t len, bool tainted);
int		fr_value_box_memdup_buffer_shallow(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
						   uint8_t *src, bool tainted);
void		fr_value_box_increment(fr_value_box_t *vb);

/*
 *	Parsing
 */
int		fr_value_box_from_str(TALLOC_CTX *ctx, fr_value_box_t *dst,
				      fr_type_t *dst_type, fr_dict_attr_t const *dst_enumv,
				      char const *src, ssize_t src_len, char quote, bool tainted);

/*
 *	Lists
 */
int		fr_value_box_list_concat(TALLOC_CTX *ctx,
					 fr_value_box_t *out, fr_value_box_t **list,
					 fr_type_t type, bool free_input);

char		*fr_value_box_list_asprint(TALLOC_CTX *ctx, fr_value_box_t const *head, char const *delim, char quote);

int		fr_value_box_list_acopy(TALLOC_CTX *ctx, fr_value_box_t **out, fr_value_box_t const *in);

bool		fr_value_box_list_tainted(fr_value_box_t const *head);

/*
 *	Printing
 */
char		*fr_value_box_asprint(TALLOC_CTX *ctx, fr_value_box_t const *data, char quote);

size_t		fr_value_box_snprint(char *out, size_t outlen, fr_value_box_t const *data, char quote);

#ifdef __cplusplus
}
#endif
