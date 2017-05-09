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

#include <freeradius-devel/value.h>

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
	//	fr_value_box_t	*data;				//!< Value data for this attribute.

		char const 	*xlat;				//!< Source string for xlat expansion.
	};

	value_type_t		type;				//!< Type of pointer in value union.
	fr_value_box_t		data;
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
	VALUE_PAIR	*last;					//!< Temporary only used for fr_pair_cursor_append
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

#define vp_strvalue	data.datum.strvalue
#define vp_octets	data.datum.octets
#define vp_ptr		data.datum.ptr				//!< Either octets or strvalue
#define vp_length	data.datum.length

#define vp_ipv4addr	data.datum.ip.addr.v4.s_addr
#define vp_ipv6addr	data.datum.ip.addr.v6.s6_addr
#define vp_ip		data.datum.ip
#define vp_ifid		data.datum.ifid
#define vp_ether	data.datum.ether

#define vp_bool		data.datum.boolean
#define vp_byte		data.datum.byte
#define vp_short	data.datum.uint16
#define vp_integer	data.datum.integer
#define vp_uint64	data.datum.uint64
#define vp_size		data.datum.size

#define vp_signed	data.datum.int32
#define vp_decimal	data.datum.decimal

#define vp_date		data.datum.date
#define vp_filter	data.datum.filter

#define vp_type		data.type
#define vp_tainted	data.tainted

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
				      unsigned int vendor, unsigned int attr, int8_t tag,
				      fr_value_box_t *value);

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
#define		fr_pair_cmp_op(_op, _a, _b)	fr_value_box_cmp_op(_op, &_a->data, &_b->data)
int8_t		fr_pair_cmp_by_da_tag(void const *a, void const *b);
int8_t		fr_pair_cmp_by_parent_num_tag(void const *a, void const *b);
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
char		*fr_pair_type_asprint(TALLOC_CTX *ctx, fr_type_t type);
char		*fr_pair_asprint(TALLOC_CTX *ctx, VALUE_PAIR const *vp, char quote);

void		fr_pair_list_tainted(VALUE_PAIR *vp);

/* Hacky raw pair thing that needs to go away */
FR_TOKEN 	fr_pair_raw_from_str(char const **ptr, VALUE_PAIR_RAW *raw);

#ifdef __cplusplus
}
#endif
#endif /* _PAIR_H */
