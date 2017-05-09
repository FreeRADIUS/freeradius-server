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
				uint8_t		byte;		//!< 8bit unsigned integer.
				uint16_t	ushort;		//!< 16bit unsigned integer.
				uint32_t	integer;	//!< 32bit unsigned integer.
				uint64_t	integer64;	//!< 64bit unsigned integer.
				size_t		size;		//!< System specific file/memory size.

				int32_t		sinteger;	//!< 32bit signed integer.
			};
			fr_dict_attr_t const	*enumv;		//!< Enumeration values for integer type.
		};

		struct timeval		timeval;		//!< A time value with usec precision.
		double			decimal;		//!< Double precision float.
		uint32_t		date;			//!< Date (32bit Unix timestamp).


	} datum;

	fr_type_t				type;			//!< Type of this value-box.

	bool				tainted;		//!< i.e. did it come from an untrusted source

	fr_value_box_t			*next;			//!< Next in a series of value_box.
};

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
