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

#include <freeradius-devel/autoconf.h>	/* Very easy to miss including in special builds */
#include <freeradius-devel/build.h>
#include <freeradius-devel/missing.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <talloc.h>

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

void		*talloc_null_ctx(void);

int		talloc_link_ctx(TALLOC_CTX *parent, TALLOC_CTX *child);

TALLOC_CTX	*talloc_page_aligned_pool(TALLOC_CTX *ctx, void **start, void **end, size_t size);

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

char		*talloc_typed_strdup(TALLOC_CTX *ctx, char const *p);

char		*talloc_typed_asprintf(TALLOC_CTX *ctx, char const *fmt, ...) CC_HINT(format (printf, 2, 3));

char		*talloc_typed_vasprintf(TALLOC_CTX *ctx, char const *fmt, va_list ap) CC_HINT(format (printf, 2, 0)) CC_HINT(nonnull (2));

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

int		talloc_const_free(void const *ptr);

/** Free a list of talloced structures containing a next field
 *
 * @param[in] _head	of list to free.  Will set memory it points to to be NULL.
 */
#define	talloc_list_free(_head) _talloc_list_free((void **)_head, offsetof(__typeof__(**(_head)), next))

static inline void _talloc_list_free(void **head, size_t offset)
{
	void *v = *head, *n;

	while (v) {
		n = *((void **)(((uint8_t *)(v)) + offset));
		talloc_free(v);
		v = n;
	}
	*head = NULL;
}

/** Verify a list of talloced structures are the correct type and are still valid
 *
 * @param[in] _head	of list to check.
 * @param[in] _type	of talloced chunk we expect.
 */
#ifndef TALLOC_GET_TYPE_ABORT_NOOP
#  define talloc_list_get_type_abort(_head, _type) (_type *)_talloc_list_get_type_abort(_head, offsetof(__typeof__(*(_head)), next), #_type, __location__)
static inline void *_talloc_list_get_type_abort(void *head, size_t offset, char const *type, char const *location)
{
	void *v = head, *n;

	if (!v) _talloc_get_type_abort(v, type, location);	/* Behave like the normal talloc_get_type_abort function */

	while (v) {
		n = *((void **)(((uint8_t *)(v)) + offset));
		_talloc_get_type_abort(v, type, location);
		v = n;
	}

	return head;
}
#else
#  define talloc_list_get_type_abort(_head, _type) (_type *)(_head)
#endif

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

typedef struct talloc_child_ctx_s TALLOC_CHILD_CTX;

TALLOC_CHILD_CTX	*talloc_child_ctx_init(TALLOC_CTX *ctx);
TALLOC_CHILD_CTX	*talloc_child_ctx_alloc(TALLOC_CHILD_CTX *parent) CC_HINT(nonnull);

#ifdef __cplusplus
}
#endif
