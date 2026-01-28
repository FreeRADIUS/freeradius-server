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

/** Functions which we wish were included in the standard talloc distribution
 *
 * @file src/lib/util/talloc.h
 *
 * @copyright 2017 The FreeRADIUS server project
 * @copyright 2017 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(talloc_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef HAVE_WDOCUMENTATION
DIAG_OFF(documentation)
#endif
#include <talloc.h>
#ifdef HAVE_WDOCUMENTATION
DIAG_ON(documentation)
#endif

#include <freeradius-devel/autoconf.h>	/* Very easy to miss including in special builds */
#include <freeradius-devel/build.h>
#include <freeradius-devel/missing.h>
#include <freeradius-devel/util/sbuff.h>

#undef talloc_autofree_context
/** The original function is deprecated, so replace it with our version
 */
#define talloc_autofree_context talloc_autofree_context_global

/** Iterate over a talloced array of elements
 *
@verbatim
talloc_foreach(vpt_m, vpt) {
	tmpl_debug(vpt);
}
@endverbatim
 *
 * There seems to be a limitation in for loop initialiser arguments where they all
 * must be the same type, though we can control the number of layers of pointer
 * indirection on a per variable basis.
 *
 * We declare _p to be a pointer of the specified _type, and initialise it to the
 * start of the array.  We declare _end to be a pointer of the specified type and
 * initialise it to point to the end of the array using talloc_array_length().
 *
 * _iter is only updated in the condition to avoid de-referencing invalid memory.
 *
 * @param[in] _array	to iterate over.  May contain zero elements.
 * @param[in] _iter	Name of iteration variable.
 *			Will be declared in the scope of the loop.
 */
#define talloc_foreach(_array, _iter) \
	for (__typeof__(_array[0]) _iter, *_p = (void *)(_array), *_end = _array ? (void *)((_array) + talloc_array_length(_array)) : NULL; \
	     (_p < _end) && (_iter = *((void **)(uintptr_t)(_p))); \
	     _p = (__typeof__(_p))((__typeof__(_array))_p) + 1)

typedef int(* fr_talloc_free_func_t)(void *fire_ctx, void *uctx);

typedef struct fr_talloc_destructor_s fr_talloc_destructor_t;
typedef struct fr_talloc_destructor_disarm_s fr_talloc_destructor_disarm_t;

/** Structure to record a destructor operation on a specific talloc chunk
 *
 * Provided here so that additional memory can be allocated with talloc pool.
 */
struct fr_talloc_destructor_s {
	void				*fire;			//!< Parent chunk.

	fr_talloc_free_func_t		func;			//!< Free function.
	void				*uctx;			//!< uctx to pass to free function.
	fr_talloc_destructor_disarm_t	*ds;			//!< Chunk to free.
};

/** Structure to record a destructor to disarm if a child talloc chunk is freed
 *
 * Provided here so that additional memory can be allocated with talloc pool.
 */
struct fr_talloc_destructor_disarm_s {
	fr_talloc_destructor_t		*d;	//!< Destructor to disarm.
};

/** Allocate a top level chunk with a constant name
 *
 * @param[in] name	Must be a string literal.
 * @return
 *	- NULL on allocation error.
 *	- A new talloc chunk on success.
 */
static inline TALLOC_CTX *talloc_init_const(char const *name)
{
	TALLOC_CTX *ctx;

	ctx = talloc_new(NULL);
	if (unlikely(!ctx)) return NULL;

	talloc_set_name_const(ctx, name);

	return ctx;
}

/** Convert a talloced string to lowercase
 *
 * @param[in] str	to convert.
 */
static inline void talloc_bstr_tolower(char *str)
{
	char *p, *q;

	for (p = str, q = p + (talloc_array_length(str) - 1); p < q; p++) *p = tolower((uint8_t) *p);
}

void		talloc_free_data(void *data);

void		*talloc_null_ctx(void);

fr_talloc_destructor_t *talloc_destructor_add(TALLOC_CTX *fire_ctx, TALLOC_CTX *disarm_ctx,
					      fr_talloc_free_func_t func, void const *uctx);

void		talloc_destructor_disarm(fr_talloc_destructor_t *d);

int		talloc_link_ctx(TALLOC_CTX *parent, TALLOC_CTX *child);

ssize_t		talloc_hdr_size(void);
TALLOC_CTX	*talloc_page_aligned_pool(TALLOC_CTX *ctx, void **start, size_t *end_len, unsigned int headers, size_t size);
TALLOC_CTX	*talloc_aligned_array(TALLOC_CTX *ctx, void **start, size_t alignment, size_t size);

/*
 *	Add variant that zeroes out newly allocated memory
 */
#if defined(HAVE__TALLOC_POOLED_OBJECT) && defined(talloc_pooled_object)
#  define HAVE_TALLOC_ZERO_POOLED_OBJECT	1
#  define HAVE_TALLOC_POOLED_OBJECT		1

#  define	talloc_zero_pooled_object(_ctx, _type, _num_subobjects, _total_subobjects_size) \
		(_type *)_talloc_zero_pooled_object((_ctx), sizeof(_type), #_type, \
						    (_num_subobjects), (_total_subobjects_size))

static inline TALLOC_CTX *_talloc_zero_pooled_object(const void *ctx,
						     size_t type_size,
						     const char *type_name,
						     unsigned num_subobjects,
						     size_t total_subobjects_size)
{
	TALLOC_CTX *new;
	new = _talloc_pooled_object(ctx, type_size, type_name, num_subobjects, total_subobjects_size);
	if (unlikely(!new)) return NULL;
	memset(new, 0, type_size);
	return new;
}
/*
 *	Fall back to non-pooled variants
 */
#else
#  define	talloc_zero_pooled_object(_ctx, _type, _num_subobjects, _total_subobjects_size) \
		talloc_zero(_ctx, _type)
#undef talloc_pooled_object
#  define	talloc_pooled_object(_ctx, _type, _num_subobjects, _total_subobjects_size) \
		talloc(_ctx, _type)
#endif

void		*_talloc_realloc_zero(const void *ctx, void *ptr, size_t elem_size, unsigned count, const char *name);

#undef talloc_realloc_zero
#define talloc_realloc_zero(_ctx, _ptr, _type, _count) \
    (_type *)_talloc_realloc_zero((_ctx), (_ptr), sizeof(_type), _count, #_type)

/** @hidecallergraph */
char		*talloc_typed_strdup(TALLOC_CTX *ctx, char const *p);

char		*talloc_typed_strdup_buffer(TALLOC_CTX *ctx, char const *p);

char		*talloc_typed_asprintf(TALLOC_CTX *ctx, char const *fmt, ...) CC_HINT(format (printf, 2, 3));

char		*talloc_typed_vasprintf(TALLOC_CTX *ctx, char const *fmt, va_list ap) CC_HINT(format (printf, 2, 0)) CC_HINT(nonnull (2));

uint8_t		*talloc_typed_memdup(TALLOC_CTX *ctx, uint8_t const *in, size_t inlen);

char		*talloc_bstrdup(TALLOC_CTX *ctx, char const *in);

char		*talloc_bstrndup(TALLOC_CTX *ctx, char const *in, size_t inlen);

char		*talloc_bstr_append(TALLOC_CTX *ctx, char *to, char const *from, size_t from_len);

char		*talloc_bstr_realloc(TALLOC_CTX *ctx, char *in, size_t inlen);

char		*talloc_buffer_append_buffer(TALLOC_CTX *ctx, char *to, char const *from);

char		*talloc_buffer_append_variadic_buffer(TALLOC_CTX *ctx, char *to, int argc, ...);

int		talloc_memcmp_array(uint8_t const *a, uint8_t const *b);

int		talloc_memcmp_bstr(char const *a, char const *b);

int		talloc_decrease_ref_count(void const *ptr);

void		**talloc_array_null_terminate(void **array);

void		**talloc_array_null_strip(void **array);

fr_slen_t	talloc_array_concat(fr_sbuff_t *out, char const * const *array, char const *sep);


/** Free const'd memory
 *
 * @param[in] ptr	to free.
 */
static inline int talloc_const_free(void const *ptr)
{
	if (!ptr) return 0;

	return talloc_free(UNCONST(void *, ptr));
}

/*
 *	talloc portability issues.  'const' is not part of the talloc
 *	type, but it is part of the pointer type.  But only if
 *	talloc_get_type_abort() is just a cast.
 */
#ifdef TALLOC_GET_TYPE_ABORT_NOOP
#  define talloc_get_type_abort_const(ptr, type) (const type *)(ptr)
#else
#  define talloc_get_type_abort_const talloc_get_type_abort
#endif

/** Returns the length of a talloc array containing a string
 *
 * @param[in] s	to return the length of.
 */
static inline size_t talloc_strlen(char const *s)
{
	char const *our_s = talloc_get_type_abort_const(s, char);
	return talloc_array_length(our_s) - 1;
}

TALLOC_CTX		*talloc_autofree_context_global(void);
TALLOC_CTX		*talloc_autofree_context_thread_local(void);

typedef struct talloc_child_ctx_s TALLOC_CHILD_CTX;

TALLOC_CHILD_CTX	*talloc_child_ctx_init(TALLOC_CTX *ctx);
TALLOC_CHILD_CTX	*talloc_child_ctx_alloc(TALLOC_CHILD_CTX *parent) CC_HINT(nonnull);

#ifdef __cplusplus
}
#endif
