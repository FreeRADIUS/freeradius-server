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

/*
 *	Allow public and private versions of the same structures
 */
#ifdef _CONST
#  error _CONST can only be defined in the local header
#endif
#ifndef _HEAP_PRIVATE
#  define _CONST const
#else
#  define _CONST
#endif

/** Comparator to order heap elements
 *
 *  Return negative numbers to put 'a' at the top of the heap.
 *  Return positive numbers to put 'b' at the top of the heap.
 */
typedef int8_t (*fr_heap_cmp_t)(void const *a, void const *b);

/** The main heap structure
 *
 * A heap entry is made of a pointer to the object, which
 * contains the key.  The heap itself is an array of pointers.
 *
 * Heaps normally support only ordered insert, and extraction
 * of the minimum element.  The heap entry can contain an "int"
 * field that holds the entries position in the heap.  The offset
 * of the field is held inside of the heap structure.
 */
typedef struct {
	unsigned int	_CONST size;		//!< Number of nodes allocated.
	unsigned int	_CONST min;		//!< Minimum number of elements we allow
						///< the heap to reduce down to.
	size_t		_CONST offset;		//!< Offset of heap index in element structure.

	unsigned int	_CONST num_elements;	//!< Number of nodes used.

	char const	* _CONST type;		//!< Talloc type of elements.
	fr_heap_cmp_t	_CONST cmp;		//!< Comparator function.

	void		* _CONST p[];		//!< Array of nodes.
} fr_heap_t;

typedef unsigned int fr_heap_index_t;
typedef unsigned int fr_heap_iter_t;

/** How many talloc headers need to be pre-allocated for a heap
 */
#define FR_HEAP_TALLOC_HEADERS 2

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
fr_heap_t	*_fr_heap_alloc(TALLOC_CTX *ctx, fr_heap_cmp_t cmp, char const *talloc_type,
				size_t offset, unsigned int init) CC_HINT(nonnull(2));

/** Check if an entry is inserted into a heap
 *
 * @param[in] heap_idx from object to check.
 */
static inline bool fr_heap_entry_inserted(fr_heap_index_t heap_idx)
{
	return (heap_idx > 0);
}

/** Return the item from the top of the heap but don't pop it
 *
 * @param[in] h		to return element from.
 * @return
 *	- Element at the top of the heap.
 *	- NULL if no elements remain in the heap.
 */
static inline void *fr_heap_peek(fr_heap_t *h)
{
	if (h->num_elements == 0) return NULL;

	return h->p[1];
}

/** Peek at a specific index in the heap
 *
 * @param[in] h		to return element from.
 * @param[in] idx	to lookup
 * @return
 *	- Element at the top of the heap.
 *	- NULL if index outside of the range of the heap.
 */
static inline void *fr_heap_peek_at(fr_heap_t *h, fr_heap_index_t idx)
{
	if (unlikely(idx > h->num_elements)) return NULL;

	return h->p[idx];
}

/** Peek at the last element in the heap (not necessarily the bottom)
 *
 * @param[in] h		to return element from.
 * @return
 *	- Last element in the heap.
 *	- NULL if no elements remain in the heap.
 */
static inline void *fr_heap_peek_tail(fr_heap_t *h)
{
	if (h->num_elements == 0) return NULL;

	/*
	 *	If this is NULL, we have a problem.
	 */
	return h->p[h->num_elements];
}

/** Return the number of elements in the heap
 *
 * @param[in] h		to return the number of elements from.
 */
static inline unsigned int fr_heap_num_elements(fr_heap_t *h)
{
	return h->num_elements;
}

int		fr_heap_insert(fr_heap_t **hp, void *data) CC_HINT(nonnull);
int		fr_heap_extract(fr_heap_t **hp, void *data) CC_HINT(nonnull);
void		*fr_heap_pop(fr_heap_t **hp) CC_HINT(nonnull);

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

#undef _CONST
#ifdef __cplusplus
}
#endif
