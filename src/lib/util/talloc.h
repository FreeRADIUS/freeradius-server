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
 * @copyright 2017 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSIDH(talloc_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/build.h>
#include <freeradius-devel/missing.h>

#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <talloc.h>

void		*talloc_null_ctx(void);

int		talloc_link_ctx(TALLOC_CTX *parent, TALLOC_CTX *child);

TALLOC_CTX	*talloc_page_aligned_pool(TALLOC_CTX *ctx, void **start, void **end, size_t size);

char		*talloc_typed_strdup(void const *t, char const *p);

char		*talloc_typed_asprintf(void const *t, char const *fmt, ...) CC_HINT(format (printf, 2, 3));

char		*talloc_typed_vasprintf(void const *t, char const *fmt, va_list ap) CC_HINT(format (printf, 2, 0)) CC_HINT(nonnull (2));

char		*talloc_bstrndup(void const *t, char const *in, size_t inlen);

char		*talloc_realloc_bstr(char *in, size_t inlen);

char		*talloc_buffer_append_buffer(char *to, char const *from);

char		*talloc_buffer_append_variadic_buffer(char *to, int argc, ...);

int		talloc_memcmp_array(uint8_t const *a, uint8_t const *b);

int		talloc_memcmp_bstr(char const *a, char const *b);

void		talloc_decrease_ref_count(void const *ptr);

void		**talloc_array_null_terminate(void **array);

void		**talloc_array_null_strip(void **array);

void		talloc_const_free(void const *ptr);

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

#ifdef __cplusplus
}
#endif
