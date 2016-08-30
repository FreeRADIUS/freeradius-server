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
#ifndef _FR_PAIR_H
#define _FR_PAIR_H
/**
 * $Id$
 *
 * @file include/pair.h
 * @brief AVP manipulation and search API.
 *
 * @copyright 2015 The FreeRADIUS server project
 */
RCSIDH(pair_h, "$Id$")

#include <freeradius-devel/libradius.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WITH_VERIFY_PTR
#  define VERIFY_VP(_x)		fr_pair_verify(__FILE__,  __LINE__, _x)
#  define VERIFY_LIST(_x)	fr_pair_list_verify(__FILE__,  __LINE__, NULL, _x)
#  define VERIFY_PACKET(_x)	(void) talloc_get_type_abort(_x, RADIUS_PACKET)
#else
/*
 *	Even if were building without WITH_VERIFY_PTR
 *	the pointer must not be NULL when these various macros are used
 *	so we can add some sneaky soft asserts.
 */
#  define VERIFY_VP(_x)		fr_cond_assert(_x)
/*
 *	We don't assert the list head is non-NULL, as it's perfectly
 *	valid to have an empty list.
 */
#  define VERIFY_LIST(_x)
#  define VERIFY_PACKET(_x)	fr_cond_assert(_x)
#endif

/** Union containing all data types supported by the server
 *
 * This union contains all data types that can be represented by VALUE_PAIRs. It may also be used in other parts
 * of the server where values of different types need to be stored.
 *
 * PW_TYPE should be an enumeration of the values in this union.
 */
typedef struct value_data value_data_t;
struct value_data {
	union {
		char const	        *strvalue;		//!< Pointer to UTF-8 string.
		uint8_t const		*octets;		//!< Pointer to binary string.

		struct in_addr		ipaddr;			//!< IPv4 Address.
		uint32_t		date;			//!< Date (32bit Unix timestamp).
		size_t			filter[32/sizeof(size_t)];	//!< Ascend binary format a packed data
									//!< structure.

		uint8_t			ifid[8];		//!< IPv6 interface ID (should be struct?).
		struct in6_addr		ipv6addr;		//!< IPv6 Address.
		uint8_t			ipv6prefix[18];		//!< IPv6 prefix (should be struct?).

		uint8_t			byte;			//!< 8bit unsigned integer.
		uint16_t		ushort;			//!< 16bit unsigned integer.
		uint32_t		integer;		//!< 32bit unsigned integer.
		uint64_t		integer64;		//!< 64bit unsigned integer.
		size_t			size;			//!< System specific file/memory size.
		int32_t			sinteger;		//!< 32bit signed integer.

		uint8_t			ether[6];		//!< Ethernet (MAC) address.

		struct timeval		timeval;		//!< A time value with usec precision.
		double			decimal;		//!< Double precision float.

		uint8_t			ipv4prefix[6];		//!< IPv4 prefix (should be struct?).

		bool			boolean;		//!< A truth value.

		void			*ptr;			//!< generic pointer.
	};

	size_t		length;					//!< Length of value data.
	value_data_t	*next;					//!< Next in a series of value_data.
};

/** The type of value a VALUE_PAIR contains
 *
 * This is used to add structure to nested VALUE_PAIRs and specifies what type of node it is (set, list, data).
 *
 * xlat is another type of data node which must first be expanded before use.
 */
typedef enum value_type {
	VT_NONE = 0,						//!< VALUE_PAIR has no value.
	VT_SET,							//!< VALUE_PAIR has children.
	VT_LIST,						//!< VALUE_PAIR has multiple values.
	VT_DATA,						//!< VALUE_PAIR has a single value.
	VT_XLAT							//!< valuepair value must be xlat expanded when it's
								//!< added to VALUE_PAIR tree.
} value_type_t;

/** Stores an attribute, a value and various bits of other data
 *
 * VALUE_PAIRs are the main data structure used in the server
 *
 * They also specify what behaviour should be used when the attribute is merged into a new list/tree.
 */
typedef struct value_pair {
	fr_dict_attr_t const		*da;				//!< Dictionary attribute defines the attribute
								//!< number, vendor and type of the attribute.

	struct value_pair	*next;

	FR_TOKEN		op;				//!< Operator to use when moving or inserting
								//!< valuepair into a list.

	int8_t			tag;				//!< Tag value used to group valuepairs.

	union {
	//	VALUE_SET	*set;				//!< Set of child attributes.
	//	VALUE_LIST	*list;				//!< List of values for
								//!< multivalued attribute.
	//	value_data_t	*data;				//!< Value data for this attribute.

		char const 	*xlat;				//!< Source string for xlat expansion.
	};

	value_type_t		type;				//!< Type of pointer in value union.
	value_data_t		data;
} VALUE_PAIR;

/** Abstraction to allow iterating over different configurations of VALUE_PAIRs
 *
 * This allows functions which do not care about the structure of collections of VALUE_PAIRs
 * to iterate over all members in a collection.
 *
 * Field within a vp_cursor should not be accessed directly, and vp_cursors should only be
 * manipulated with the pair* functions.
 */
typedef struct vp_cursor {
	VALUE_PAIR	**first;
	VALUE_PAIR	*found;					//!< pairfind marker.
	VALUE_PAIR	*last;					//!< Temporary only used for fr_cursor_append
	VALUE_PAIR	*current;				//!< The current attribute.
	VALUE_PAIR	*next;					//!< Next attribute to process.
} vp_cursor_t;

/** A VALUE_PAIR in string format.
 *
 * Used to represent pairs in the legacy 'users' file format.
 */
typedef struct value_pair_raw {
	char l_opand[256];					//!< Left hand side of the pair.
	char r_opand[1024];					//!< Right hand side of the pair.

	FR_TOKEN quote;						//!< Type of quoting around the r_opand.

	FR_TOKEN op;						//!< Operator.
} VALUE_PAIR_RAW;

#define vp_strvalue	data.strvalue
#define vp_integer	data.integer
#define vp_ipaddr	data.ipaddr.s_addr
#define vp_date		data.date
#define vp_filter	data.filter
#define vp_octets	data.octets
#define vp_ifid		data.ifid
#define vp_ipv6addr	data.ipv6addr
#define vp_ipv6prefix	data.ipv6prefix
#define vp_bool		data.boolean
#define vp_byte		data.byte
#define vp_short	data.ushort
#define vp_ether	data.ether
#define vp_signed	data.sinteger
#define vp_integer64	data.integer64
#define vp_size		data.size
#define vp_ipv4prefix	data.ipv4prefix
#define vp_decimal	data.decimal

#define vp_length	data.length

#  define debug_pair(vp)	do { if (fr_debug_lvl && fr_log_fp) { \
					fr_pair_fprint(fr_log_fp, vp); \
				     } \
				} while(0)

#define TAG_VALID(x)		((x) > 0 && (x) < 0x20)
#define TAG_VALID_ZERO(x)	((x) < 0x20)
#define TAG_ANY			INT8_MIN
#define TAG_NONE		0
/** Check if tags are equal
 *
 * @param _x tag were matching on.
 * @param _y tag belonging to the attribute were checking.
 */
#define TAG_EQ(_x, _y) ((_x == _y) || (_x == TAG_ANY) || ((_x == TAG_NONE) && (_y == TAG_ANY)))
#define ATTRIBUTE_EQ(_x, _y) ((_x && _y) && (_x->da == _y->da) && (!_x->da->flags.has_tag || TAG_EQ(_x->tag, _y->tag)))

#define NUM_ANY			INT_MIN
#define NUM_ALL			(INT_MIN + 1)
#define NUM_COUNT		(INT_MIN + 2)
#define NUM_LAST		(INT_MIN + 3)

/* Allocation and management */
VALUE_PAIR	*fr_pair_afrom_da(TALLOC_CTX *ctx, fr_dict_attr_t const *da);
VALUE_PAIR	*fr_pair_afrom_num(TALLOC_CTX *ctx, unsigned int vendor, unsigned int attr);
VALUE_PAIR	*fr_pair_afrom_child_num(TALLOC_CTX *ctx, fr_dict_attr_t const *parent, unsigned int attr);
VALUE_PAIR	*fr_pair_copy(TALLOC_CTX *ctx, VALUE_PAIR const *vp);
void		fr_pair_steal(TALLOC_CTX *ctx, VALUE_PAIR *vp);
VALUE_PAIR	*fr_pair_make(TALLOC_CTX *ctx, VALUE_PAIR **vps, char const *attribute, char const *value, FR_TOKEN op);
void		fr_pair_list_free(VALUE_PAIR **);
int		fr_pair_to_unknown(VALUE_PAIR *vp);
int 		fr_pair_mark_xlat(VALUE_PAIR *vp, char const *value);

/* Searching and list modification */
VALUE_PAIR	*fr_pair_find_by_da(VALUE_PAIR *head, fr_dict_attr_t const *da, int8_t tag);

VALUE_PAIR	*fr_pair_find_by_num(VALUE_PAIR *head, unsigned int vendor, unsigned int attr, int8_t tag);

VALUE_PAIR	*fr_pair_find_by_child_num(VALUE_PAIR *head, fr_dict_attr_t const *parent,
					   unsigned int attr, int8_t tag);

void		fr_pair_add(VALUE_PAIR **head, VALUE_PAIR *vp);

void		fr_pair_replace(VALUE_PAIR **head, VALUE_PAIR *add);

int		fr_pair_update_by_num(TALLOC_CTX *ctx, VALUE_PAIR **list,
				      unsigned int vendor, unsigned int attr, int8_t tag, PW_TYPE type,
				      value_data_t *value);

void		fr_pair_delete_by_num(VALUE_PAIR **head, unsigned int vendor, unsigned int attr, int8_t tag);

/* Sorting */
typedef		int8_t (*fr_cmp_t)(void const *a, void const *b);

/** Compare two attributes using and operator.
 *
 * @return
 *	- 1 if equal.
 *	- 0 if not equal.
 *	- -1 on failure.
 */
#define		fr_pair_cmp_op(_op, _a, _b)	value_data_cmp_op(_op, _a->da->type, &_a->data, _b->da->type, &_b->data)
int8_t		fr_pair_cmp_by_da_tag(void const *a, void const *b);
int		fr_pair_cmp(VALUE_PAIR *a, VALUE_PAIR *b);
int		fr_pair_list_cmp(VALUE_PAIR *a, VALUE_PAIR *b);
void		fr_pair_list_sort(VALUE_PAIR **vps, fr_cmp_t cmp);

/* Filtering */
void		fr_pair_validate_debug(TALLOC_CTX *ctx, VALUE_PAIR const *failed[2]);
bool		fr_pair_validate(VALUE_PAIR const *failed[2], VALUE_PAIR *filter, VALUE_PAIR *list);
bool 		fr_pair_validate_relaxed(VALUE_PAIR const *failed[2], VALUE_PAIR *filter, VALUE_PAIR *list);

/* Lists */
FR_TOKEN	fr_pair_list_afrom_str(TALLOC_CTX *ctx, char const *buffer, VALUE_PAIR **head);
int		fr_pair_list_afrom_file(TALLOC_CTX *ctx, VALUE_PAIR **out, FILE *fp, bool *pfiledone);
VALUE_PAIR	*fr_pair_list_copy(TALLOC_CTX *ctx, VALUE_PAIR *from);
VALUE_PAIR	*fr_pair_list_copy_by_num(TALLOC_CTX *ctx, VALUE_PAIR *from,
				     unsigned int vendor, unsigned int attr, int8_t tag);
void		fr_pair_list_move(TALLOC_CTX *ctx, VALUE_PAIR **to, VALUE_PAIR **from);
void		fr_pair_list_move_by_num(TALLOC_CTX *ctx, VALUE_PAIR **to, VALUE_PAIR **from,
					 unsigned int vendor, unsigned int attr, int8_t tag);
void		fr_pair_list_mcopy_by_num(TALLOC_CTX *ctx, VALUE_PAIR **to, VALUE_PAIR **from,
					  unsigned int vendor, unsigned int attr, int8_t tag);

/* Value manipulation */
int		fr_pair_value_from_str(VALUE_PAIR *vp, char const *value, size_t len);
void		fr_pair_value_memcpy(VALUE_PAIR *vp, uint8_t const *src, size_t len);
void		fr_pair_value_memsteal(VALUE_PAIR *vp, uint8_t const *src);
void		fr_pair_value_strsteal(VALUE_PAIR *vp, char const *src);
void		fr_pair_value_strnsteal(VALUE_PAIR *vp, char *src, size_t len);
void		fr_pair_value_strcpy(VALUE_PAIR *vp, char const *src);
void		fr_pair_value_bstrncpy(VALUE_PAIR *vp, void const *src, size_t len);
void		fr_pair_value_snprintf(VALUE_PAIR *vp, char const *fmt, ...) CC_HINT(format (printf, 2, 3));

/* Printing functions */
size_t   	fr_pair_value_snprint(char *out, size_t outlen, VALUE_PAIR const *vp, char quote);
char     	*fr_pair_value_asprint(TALLOC_CTX *ctx, VALUE_PAIR const *vp, char quote);
char const	*fr_pair_value_enum(VALUE_PAIR const *vp, char buff[20]);

size_t		fr_pair_snprint(char *out, size_t outlen, VALUE_PAIR const *vp);
void		fr_pair_fprint(FILE *, VALUE_PAIR const *vp);
void		fr_pair_list_fprint(FILE *, VALUE_PAIR const *vp);
char		*fr_pair_type_asprint(TALLOC_CTX *ctx, PW_TYPE type);
char		*fr_pair_asprint(TALLOC_CTX *ctx, VALUE_PAIR const *vp, char quote);

/* Hacky raw pair thing that needs to go away */
FR_TOKEN 	fr_pair_raw_from_str(char const **ptr, VALUE_PAIR_RAW *raw);

#ifdef __cplusplus
}
#endif
#endif /* _PAIR_H */
