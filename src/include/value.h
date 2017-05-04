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
extern size_t const value_box_field_sizes[];
extern size_t const value_box_offsets[];

#include <freeradius-devel/inet.h>
#include <freeradius-devel/dict.h>

#define value_box_foreach(_v, _iv) for (value_box_t *_iv = v; _iv; _iv = _iv->next)

/** Union containing all data types supported by the server
 *
 * This union contains all data types that can be represented by VALUE_PAIRs. It may also be used in other parts
 * of the server where values of different types need to be stored.
 *
 * PW_TYPE should be an enumeration of the values in this union.
 */
typedef struct value_box value_box_t;
struct value_box {
	union {
		char const	        *strvalue;		//!< Pointer to UTF-8 string.
		uint8_t const		*octets;		//!< Pointer to binary string.
		void			*ptr;			//!< generic pointer.

		fr_ipaddr_t		ip;			//!< IPv4/6 address/prefix.

		uint8_t			ipv4prefix[6];		//!< IPv4 prefix (should be struct?).
		uint8_t			ipv6prefix[18];		//!< IPv6 prefix (should be struct?).


		uint8_t			ifid[8];		//!< IPv6 interface ID (should be struct?).
		uint8_t			ether[6];		//!< Ethernet (MAC) address.

		bool			boolean;		//!< A truth value.

		struct {
			union {
				uint8_t			byte;		//!< 8bit unsigned integer.
				uint16_t		ushort;		//!< 16bit unsigned integer.
				uint32_t		integer;	//!< 32bit unsigned integer.
				uint64_t		integer64;	//!< 64bit unsigned integer.
				size_t			size;		//!< System specific file/memory size.

				int32_t			sinteger;	//!< 32bit signed integer.
			};
			fr_dict_attr_t const		*enumv;		//!< Enumeration values for integer type.
		};

		struct timeval		timeval;		//!< A time value with usec precision.
		double			decimal;		//!< Double precision float.
		uint32_t		date;			//!< Date (32bit Unix timestamp).

		uint8_t			filter[32];		//!< Ascend binary format (a packed data structure).

	} datum;

	PW_TYPE				type;			//!< Type of this value-box.

	size_t				length;			//!< Length of value data.

	bool				tainted;		//!< i.e. did it come from an untrusted source

	value_box_t			*next;			//!< Next in a series of value_box.
};

/*
 *	Allocation
 */
value_box_t	*value_box_alloc(TALLOC_CTX *ctx, PW_TYPE type);

void		value_box_clear(value_box_t *data);

/*
 *	Comparison
 */
int		value_box_cmp(value_box_t const *a, value_box_t const *b);

int		value_box_cmp_op(FR_TOKEN op, value_box_t const *a, value_box_t const *b);

/*
 *	Conversion
 */
size_t		value_str_unescape(uint8_t *out, char const *in, size_t inlen, char quote);

int		value_box_hton(value_box_t *dst, value_box_t const *src);

int		value_box_cast(TALLOC_CTX *ctx, value_box_t *dst,
			       PW_TYPE dst_type, fr_dict_attr_t const *dst_enumv,
			       value_box_t const *src);

/*
 *	Assignment
 */
int		value_box_copy(TALLOC_CTX *ctx, value_box_t *dst,  const value_box_t *src);
void		value_box_copy_shallow(TALLOC_CTX *ctx, value_box_t *dst, const value_box_t *src);
int		value_box_steal(TALLOC_CTX *ctx, value_box_t *dst, value_box_t const *src);

int		value_box_strdup(TALLOC_CTX *ctx, value_box_t *dst, char const *src, bool tainted);
int		value_box_strdup_buffer(TALLOC_CTX *ctx, value_box_t *dst, char const *src, bool tainted);
int		value_box_strsteal(TALLOC_CTX *ctx, value_box_t *dst, char *src, bool tainted);
int		value_box_strdup_shallow(value_box_t *dst, char const *src, bool tainted);
int		value_box_strdup_buffer_shallow(TALLOC_CTX *ctx, value_box_t *dst, char const *src, bool tainted);

int		value_box_memdup(TALLOC_CTX *ctx, value_box_t *dst, uint8_t const *src, size_t len, bool tainted);
int		value_box_memdup_buffer(TALLOC_CTX *ctx, value_box_t *dst, uint8_t *src, bool tainted);
int		value_box_memsteal(TALLOC_CTX *ctx, value_box_t *dst, uint8_t const *src, bool tainted);
int		value_box_memdup_shallow(value_box_t *dst, uint8_t *src, size_t len, bool tainted);
int		value_box_memdup_buffer_shallow(TALLOC_CTX *ctx, value_box_t *dst, uint8_t *src, bool tainted);

/*
 *	Parsing
 */
int		value_box_from_ipaddr(value_box_t *dst, fr_ipaddr_t const *ipaddr);

int		value_box_from_str(TALLOC_CTX *ctx, value_box_t *dst,
				   PW_TYPE *src_type, fr_dict_attr_t const *src_enumv,
				   char const *src, ssize_t src_len, char quote);

/*
 *	Printing
 */
char		*value_box_asprint(TALLOC_CTX *ctx, value_box_t const *data, char quote);

size_t		value_box_snprint(char *out, size_t outlen, value_box_t const *data, char quote);
#endif /* _FR_VALUE_H */
