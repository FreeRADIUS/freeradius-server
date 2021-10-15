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

/** Structures and prototypes for binary heaps
 *
 * @file src/lib/util/heap.h
 *
 * @copyright 2007 Alan DeKok
 */
RCSIDH(heap_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/build.h>
#include <freeradius-devel/missing.h>
#include <freeradius-devel/util/talloc.h>

#include <stdint.h>
#include <sys/types.h>

typedef unsigned int fr_heap_index_t;
typedef unsigned int fr_heap_iter_t;

/** How many talloc headers need to be pre-allocated for a heap
 */
#define FR_HEAP_TALLOC_HEADERS 2

/** Comparator to order heap elements
 *
 *  Return negative numbers to put 'a' at the top of the heap.
 *  Return positive numbers to put 'b' at the top of the heap.
 */
typedef int8_t (*fr_heap_cmp_t)(void const *a, void const *b);

/** The main heap structure
 *
 */
typedef struct fr_heap_s * fr_heap_t;

size_t fr_heap_pre_alloc_size(unsigned int count);

/** Creates a heap that can be used with non-talloced elements
 *
 * @param[in] _ctx		Talloc ctx to allocate heap in.
 * @param[in] _cmp		Comparator used to compare elements.
 * @param[in] _type		Of elements.
 * @param[in] _field		to store heap indexes in.
 * @param[in] _init		the initial number of elements to allocate.
 *				Pass 0 to use the default.
 */
#define fr_heap_alloc(_ctx, _cmp, _type, _field, _init) \
	_fr_heap_alloc(_ctx, _cmp, NULL, (size_t)offsetof(_type, _field), _init)

/** Creates a heap that verifies elements are of a specific talloc type
 *
 * @param[in] _ctx		Talloc ctx to allocate heap in.
 * @param[in] _cmp		Comparator used to compare elements.
 * @param[in] _talloc_type	of elements.
 * @param[in] _field		to store heap indexes in.
 * @param[in] _init		the initial number of elements to allocate.
 *				Pass 0 to use the default.
 * @return
 *	- A new heap.
 *	- NULL on error.
 */
#define fr_heap_talloc_alloc(_ctx, _cmp, _talloc_type, _field, _init) \
	_fr_heap_alloc(_ctx, _cmp, #_talloc_type, (size_t)offsetof(_talloc_type, _field), _init)

fr_heap_t	*_fr_heap_alloc(TALLOC_CTX *ctx, fr_heap_cmp_t cmp, char const *talloc_type, size_t offset, unsigned int init) CC_HINT(nonnull(2));

/** Check if an entry is inserted into a heap
 *
 */
static inline bool fr_heap_entry_inserted(fr_heap_index_t heap_idx)
{
	return (heap_idx > 0);
}

int		fr_heap_insert(fr_heap_t *hp, void *data) CC_HINT(nonnull);
int		fr_heap_extract(fr_heap_t *hp, void *data) CC_HINT(nonnull);
void		*fr_heap_pop(fr_heap_t *hp) CC_HINT(nonnull);
void		*fr_heap_peek(fr_heap_t *hp) CC_HINT(nonnull);
void		*fr_heap_peek_tail(fr_heap_t *hp) CC_HINT(nonnull);

uint32_t	fr_heap_num_elements(fr_heap_t *hp) CC_HINT(nonnull);

void		*fr_heap_iter_init(fr_heap_t *hp, fr_heap_iter_t *iter) CC_HINT(nonnull);
void		*fr_heap_iter_next(fr_heap_t *hp, fr_heap_iter_t *iter) CC_HINT(nonnull);

/** Iterate over the contents of a heap
 *
 * @note The initializer section of a for loop can't declare variables with distinct
 *	 base types, so we require a containing block, and can't follow the standard
 *	 do {...} while(0) dodge. The code to be run for each item in the heap should
 *	 thus start with one open brace and end with two close braces, and shouldn't
 *	 be followed with a semicolon.
 *	 This may fake out code formatting programs and code-aware editors.
 *
 * @param[in] _heap		to iterate over.
 * @param[in] _type		of item the heap contains.
 * @param[in] _data		Name of variable holding a pointer to the heap element.
 *				Will be declared in the scope of the loop.
 */
#define fr_heap_foreach(_heap, _type, _data) \
{ \
	fr_heap_iter_t _iter; \
	for (_type *_data = fr_heap_iter_init(_heap, &_iter); _data; _data = fr_heap_iter_next(_heap, &_iter))

#ifndef TALLOC_GET_TYPE_ABORT_NOOP
void fr_heap_verify(char const *file, int line, fr_heap_t *hp);
#  define FR_HEAP_VERIFY(_heap) fr_heap_verify(__FILE__, __LINE__, _heap)
#elif !defined(NDEBUG)
#  define FR_HEAP_VERIFY(_heap) fr_assert(_heap)
#else
#  define FR_HEAP_VERIFY(_heap)
#endif

#ifdef __cplusplus
}
#endif
