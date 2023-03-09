/*
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** Functions which we wish were included in the standard talloc distribution
 *
 * @file src/lib/talloc.c
 *
 * @copyright 2017 The FreeRADIUS server project
 * @copyright 2017 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/math.h>
#include <freeradius-devel/libradius.h>
#include <freeradius-devel/talloc.h>

/** Return a page aligned talloc memory array
 *
 * Because we can't intercept talloc's malloc() calls, we need to do some tricks
 * in order to get the first allocation in the array page aligned, and to limit
 * the size of the array to a multiple of the page size.
 *
 * The reason for wanting a page aligned talloc array, is it allows us to
 * mprotect() the pages that belong to the array.
 *
 * Talloc chunks appear to be allocated within the protected region, so this should
 * catch frees too.
 *
 * @param[in] ctx	to allocate array memory in.
 * @param[out] start	The first aligned address in the array.
 * @param[in] alignment	What alignment the memory chunk should have.
 * @param[in] size	How big to make the array.  Will be corrected to a multiple
 *			of the page size.  The actual array size will be size
 *			rounded to a multiple of the (page_size), + page_size
 * @return
 *	- A talloc chunk on success.
 *	- NULL on failure.
 */
TALLOC_CTX *talloc_aligned_array(TALLOC_CTX *ctx, void **start, size_t alignment, size_t size)
{
	size_t		rounded;
	size_t		array_size;
	void		*next;
	TALLOC_CTX	*array;

	rounded = ROUND_UP(size, alignment);		/* Round up to a multiple of the page size */
	if (rounded == 0) rounded = alignment;

	array_size = rounded + alignment;
	array = talloc_array(ctx, uint8_t, array_size);		/* Over allocate */
	if (!array) {
		fr_strerror_printf("Out of memory");
		return NULL;
	}

	next = (void *)ROUND_UP((uintptr_t)array, alignment);		/* Round up address to the next multiple */
	*start = next;

	return array;
}

