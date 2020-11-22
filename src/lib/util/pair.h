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

/** AVP manipulation and search API
 *
 * @file src/lib/util/pair.h
 *
 * @copyright 2015 The FreeRADIUS server project
 */
RCSIDH(pair_h, "$Id$")

#include <freeradius-devel/build.h>
#include <freeradius-devel/missing.h>
#include <freeradius-devel/util/cursor.h>
#include <freeradius-devel/util/value.h>
#include <freeradius-devel/util/token.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WITH_VERIFY_PTR
#  define VP_VERIFY(_x)		fr_pair_verify(__FILE__, __LINE__, _x)
#  define LIST_VERIFY(_x)	fr_pair_list_verify(__FILE__, __LINE__, NULL, _x)
#else
/*
 *	Even if were building without WITH_VERIFY_PTR
 *	the pointer must not be NULL when these various macros are used
 *	so we can add some sneaky soft asserts.
 */
#  define VP_VERIFY(_x)		fr_cond_assert(_x)
/*
 *	We don't assert the list head is non-NULL, as it's perfectly
 *	valid to have an empty list.
 */
#  define LIST_VERIFY(_x)
#endif

#define request_pairs	packet->vps
#define	reply_pairs	reply->vps
#define control_pairs	control
#define state_pairs	state

/** The type of value a fr_pair_t contains
 *
 * This is used to add structure to nested fr_pair_ts and specifies what type of node it is (set, list, data).
 *
 * xlat is another type of data node which must first be expanded before use.
 */
typedef enum value_type {
	VT_NONE = 0,						//!< fr_pair_t has no value.
	VT_SET,							//!< fr_pair_t has children.
	VT_LIST,						//!< fr_pair_t has multiple values.
	VT_DATA,						//!< fr_pair_t has a single value.
	VT_XLAT							//!< valuepair value must be xlat expanded when it's
								//!< added to fr_pair_t tree.
} value_type_t;

typedef struct value_pair_s fr_pair_t;

#ifdef USE_DOUBLE_LIST
typedef struct {
        fr_dlist_head_t head;
} fr_pair_list_t;
#else
typedef fr_pair_t* fr_pair_list_t;
#endif

/** Stores an attribute, a value and various bits of other data
 *
 * fr_pair_ts are the main data structure used in the server
 *
 * They also specify what behaviour should be used when the attribute is merged into a new list/tree.
 */
struct value_pair_s {
	fr_dict_attr_t const	*da;				//!< Dictionary attribute defines the attribute
								//!< number, vendor and type of the attribute.

	fr_pair_t		*next;

	/*
	 *	Legacy stuff that needs to die.
	 */
	struct {
		fr_token_t		op;			//!< Operator to use when moving or inserting
								//!< valuepair into a list.
		char const 		*xlat;			//!< Source string for xlat expansion.
	};

	value_type_t		type;				//!< Type of pointer in value union.

	/*
	 *	Pairs can have children or data but not both.
	 */
	union {
		fr_value_box_t		data;			//!< The value of this pair.
		fr_pair_list_t		children;		//!< Nested attributes of this pair.
	};
};

/** A fr_pair_t in string format.
 *
 * Used to represent pairs in the legacy 'users' file format.
 */
typedef struct {
	char l_opand[256];					//!< Left hand side of the pair.
	char r_opand[1024];					//!< Right hand side of the pair.

	fr_token_t quote;						//!< Type of quoting around the r_opand.

	fr_token_t op;						//!< Operator.
} fr_pair_t_RAW;

#define vp_strvalue		data.vb_strvalue
#define vp_octets		data.vb_octets
#define vp_ptr			data.datum.ptr			//!< Either octets or strvalue
#define vp_length		data.vb_length

#define vp_ipv4addr		data.vb_ip.addr.v4.s_addr
#define vp_ipv6addr		data.vb_ip.addr.v6.s6_addr
#define vp_ip			data.vb_ip
#define vp_ifid			data.vb_ifid
#define vp_ether		data.vb_ether

#define vp_bool			data.datum.boolean
#define vp_uint8		data.vb_uint8
#define vp_uint16		data.vb_uint16
#define vp_uint32		data.vb_uint32
#define vp_uint64		data.vb_uint64

#define vp_int8			data.vb_int8
#define vp_int16		data.vb_int16
#define vp_int32		data.vb_int32
#define vp_int64		data.vb_int64

#define vp_float32		data.vb_float32
#define vp_float64		data.vb_float64

#define vp_date			data.vb_date

#define vp_group		children

#define vp_size			data.datum.size
#define vp_filter		data.datum.filter

#define vp_type			data.type
#define vp_tainted		data.tainted

#define ATTRIBUTE_EQ(_x, _y) ((_x && _y) && (_x->da == _y->da))

#  ifdef WITH_VERIFY_PTR
void		fr_pair_verify(char const *file, int line, fr_pair_t const *vp);
void		fr_pair_list_verify(char const *file, int line, TALLOC_CTX const *expected, fr_pair_list_t const *vps);
#  endif

/*
 *  Temporary hack to (a) get type-checking in macros, and (b) be fast
 */
#define		fr_pair_list_init(_list) (*(_list) = _Generic((_list), \
				fr_pair_list_t *  : NULL, \
				default		  : (fr_pair_list_t *) NULL))

/* Allocation and management */
fr_pair_t	*fr_pair_alloc_null(TALLOC_CTX *ctx);

fr_pair_list_t	*fr_pair_list_alloc(TALLOC_CTX *ctx);

/**
 *
 * @hidecallergraph
 */
fr_pair_t	*fr_pair_afrom_da(TALLOC_CTX *ctx, fr_dict_attr_t const *da);

fr_pair_t	*fr_pair_afrom_child_num(TALLOC_CTX *ctx, fr_dict_attr_t const *parent, unsigned int attr);

fr_pair_t	*fr_pair_copy(TALLOC_CTX *ctx, fr_pair_t const *vp);

void		fr_pair_steal(TALLOC_CTX *ctx, fr_pair_t *vp);

/** @hidecallergraph */
void		fr_pair_list_free(fr_pair_list_t *list);

/* Searching and list modification */
int		fr_pair_to_unknown(fr_pair_t *vp);
void		*fr_pair_iter_next_by_da(void **prev, void *to_eval, void *uctx);

void		*fr_pair_iter_next_by_ancestor(void **prev, void *to_eval, void *uctx);
bool		fr_pair_matches_da(void const *item, void const *uctx);

/** Initialise a cursor that will return only attributes matching the specified #fr_dict_attr_t
 *
 * @param[in] cursor	to initialise.
 * @param[in] list	to iterate over.
 * @param[in] da	to search for.
 * @return
 *	- The first matching pair.
 *	- NULL if no pairs match.
 */
static inline fr_pair_t *fr_cursor_iter_by_da_init(fr_cursor_t *cursor,
						    fr_pair_list_t *list, fr_dict_attr_t const *da)
{
	return fr_cursor_talloc_iter_init(cursor, list, fr_pair_iter_next_by_da, da, fr_pair_t);
}

/** Initialise a cursor that will return only attributes descended from the specified #fr_dict_attr_t
 *
 * @param[in] cursor	to initialise.
 * @param[in] list	to iterate over.
 * @param[in] da	who's decentness to search for.
 * @return
 *	- The first matching pair.
 *	- NULL if no pairs match.
 */
static inline fr_pair_t *fr_cursor_iter_by_ancestor_init(fr_cursor_t *cursor,
							  fr_pair_list_t *list, fr_dict_attr_t const *da)
{
	return fr_cursor_talloc_iter_init(cursor, list, fr_pair_iter_next_by_ancestor, da, fr_pair_t);
}

/**
 * @hidecallergraph
 */
fr_pair_t	*fr_pair_find_by_da(fr_pair_list_t *head, fr_dict_attr_t const *da);

fr_pair_t	*fr_pair_find_by_num(fr_pair_list_t *head, unsigned int vendor, unsigned int attr);

fr_pair_t	*fr_pair_find_by_child_num(fr_pair_list_t *head, fr_dict_attr_t const *parent, unsigned int attr);

void		fr_pair_add(fr_pair_list_t *head, fr_pair_t *vp);

void		fr_pair_replace(fr_pair_list_t *head, fr_pair_t *add);

void		fr_pair_delete_by_child_num(fr_pair_list_t *head, fr_dict_attr_t const *parent, unsigned int attr);

int		fr_pair_add_by_da(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_pair_list_t *list, fr_dict_attr_t const *da);

int		fr_pair_update_by_da(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_pair_list_t *list, fr_dict_attr_t const *da);

int		fr_pair_delete_by_da(fr_pair_list_t *head, fr_dict_attr_t const *da);

void		fr_pair_delete(fr_pair_list_t *list, fr_pair_t const *vp);

/* functions for FR_TYPE_STRUCTURAL */
fr_pair_list_t	*fr_pair_children(fr_pair_t *head);

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
int8_t		fr_pair_cmp_by_da(void const *a, void const *b);
int8_t		fr_pair_cmp_by_parent_num(void const *a, void const *b);
int		fr_pair_cmp(fr_pair_t *a, fr_pair_t *b);
int		fr_pair_list_cmp(fr_pair_list_t const *a, fr_pair_list_t const *b);
void		fr_pair_list_sort(fr_pair_list_t *vps, fr_cmp_t cmp) CC_HINT(nonnull);

/* Filtering */
void		fr_pair_validate_debug(TALLOC_CTX *ctx, fr_pair_t const *failed[2]);
bool		fr_pair_validate(fr_pair_t const *failed[2], fr_pair_list_t *filter, fr_pair_list_t *list) CC_HINT(nonnull(2,3));
bool 		fr_pair_validate_relaxed(fr_pair_t const *failed[2], fr_pair_list_t *filter, fr_pair_list_t *list) CC_HINT(nonnull(2,3));

/* Lists */
int		fr_pair_list_copy(TALLOC_CTX *ctx, fr_pair_list_t *to, fr_pair_list_t const *from);
int		fr_pair_list_copy_by_da(TALLOC_CTX *ctx, fr_pair_list_t *to,
					fr_pair_list_t *from, fr_dict_attr_t const *da, unsigned int count);
int		fr_pair_list_copy_by_ancestor(TALLOC_CTX *ctx, fr_pair_list_t *to,
					      fr_pair_list_t *from, fr_dict_attr_t const *parent_da, unsigned int count);

/** @name Pair to pair copying
 *
 * @{
 */
void		fr_pair_value_clear(fr_pair_t *vp);

int		fr_pair_value_copy(fr_pair_t *dst, fr_pair_t *src);
/** @} */

/** @name Assign and manipulate binary-unsafe C strings
 *
 * @{
 */
int		fr_pair_value_from_str(fr_pair_t *vp, char const *value, ssize_t len, char quote, bool tainted);

int		fr_pair_value_strdup(fr_pair_t *vp, char const *src);

int		fr_pair_value_strdup_shallow(fr_pair_t *vp, char const *src, bool tainted);

int		fr_pair_value_strtrim(fr_pair_t *vp);

int		fr_pair_value_aprintf(fr_pair_t *vp, char const *fmt, ...) CC_HINT(format (printf, 2, 3));
/** @} */

/** @name Assign and manipulate binary-safe strings
 *
 * @{
 */
int		fr_pair_value_bstr_alloc(fr_pair_t *vp, char **out, size_t size, bool tainted);

int		fr_pair_value_bstr_realloc(fr_pair_t *vp, char **out, size_t size);

int		fr_pair_value_bstrndup(fr_pair_t *vp, char const *src, size_t len, bool tainted);

int		fr_pair_value_bstrdup_buffer(fr_pair_t *vp, char const *src, bool tainted);

int		fr_pair_value_bstrndup_shallow(fr_pair_t *vp, char const *src, size_t len, bool tainted);

int		fr_pair_value_bstrdup_buffer_shallow(fr_pair_t *vp, char const *src, bool tainted);

int		fr_pair_value_bstrn_append(fr_pair_t *vp, char const *src, size_t len, bool tainted);

int		fr_pair_value_bstr_append_buffer(fr_pair_t *vp, char const *src, bool tainted);
 /** @} */

/** @name Assign and manipulate octets strings
 *
 * @{
 */
int		fr_pair_value_mem_alloc(fr_pair_t *vp, uint8_t **out, size_t size, bool tainted);

int		fr_pair_value_mem_realloc(fr_pair_t *vp, uint8_t **out, size_t size);

int		fr_pair_value_memdup(fr_pair_t *vp, uint8_t const *src, size_t len, bool tainted);

int		fr_pair_value_memdup_buffer(fr_pair_t *vp, uint8_t const *src, bool tainted);

int		fr_pair_value_memdup_shallow(fr_pair_t *vp, uint8_t const *src, size_t len, bool tainted);

int		fr_pair_value_memdup_buffer_shallow(fr_pair_t *vp, uint8_t const *src, bool tainted);

int		fr_pair_value_mem_append(fr_pair_t *vp, uint8_t *src, size_t len, bool tainted);

int		fr_pair_value_mem_append_buffer(fr_pair_t *vp, uint8_t *src, bool tainted);
 /** @} */

/** @name Enum functions
 *
 * @{
 */
char const		*fr_pair_value_enum(fr_pair_t const *vp, char buff[static 20]);

int			fr_pair_value_enum_box(fr_value_box_t const **out, fr_pair_t *vp);
/** @} */

/** @name Printing functions
 *
 * @{
 */
ssize_t   		fr_pair_print_value_quoted(fr_sbuff_t *out,
						   fr_pair_t const *vp, fr_token_t quote);

static inline size_t	fr_pair_aprint_value_quoted(TALLOC_CTX *ctx, char **out,
						    fr_pair_t const *vp, fr_token_t quote)
{
			SBUFF_OUT_TALLOC_FUNC_NO_LEN_DEF(fr_pair_print_value_quoted, vp, quote)
}

ssize_t			fr_pair_print(fr_sbuff_t *out, fr_pair_t const *parent, fr_pair_t const *vp);

static inline size_t	fr_pair_aprint(TALLOC_CTX *ctx, char **out, fr_pair_t const *parent, fr_pair_t const *vp)
{
			SBUFF_OUT_TALLOC_FUNC_NO_LEN_DEF(fr_pair_print, parent, vp)
}

void			fr_pair_fprint(FILE *, fr_pair_t const *parent, fr_pair_t const *vp);

#define			fr_pair_list_log(_log, _vp) _fr_pair_list_log(_log, 4, _vp, __FILE__, __LINE__);
void			_fr_pair_list_log(fr_log_t const *log, int lvl, fr_pair_t const *vp, char const *file, int line);

void			fr_pair_list_debug(fr_pair_t const *vp);

/** @} */

void			fr_pair_list_tainted(fr_pair_list_t *vps);
fr_pair_t		*fr_pair_list_afrom_box(TALLOC_CTX *ctx, fr_dict_t const *dict, fr_value_box_t *box);

/* Tokenization */
typedef struct {
	TALLOC_CTX		*ctx;			//!< to allocate VPs in
	fr_dict_attr_t	const	*parent;	       	//!< current attribute to allocate VPs in
	fr_cursor_t		*cursor;		//!< of VPs to add
} fr_pair_ctx_t;

ssize_t		fr_pair_ctx_afrom_str(fr_pair_ctx_t *pair_ctx, char const *in, size_t inlen);
void		fr_pair_ctx_reset(fr_pair_ctx_t *pair_ctx, fr_dict_t const *dict);

#ifdef __cplusplus
}
#endif
