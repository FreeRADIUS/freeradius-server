/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** Implementation of a circular buffer with fixed element size
 *
 * This offers similar functionality to ring_buffer.c, but uses a fixed
 * element size, and expects all elements to be talloced.
 *
 * @file src/lib/util/fring.c
 *
 * @copyright 2013 The FreeRADIUS server project
 * @copyright 2013 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/util/fring.h>

#include <pthread.h>

/** Standard thread safe circular buffer
 *
 */
struct fr_fring_buffer {
	void const		*end;			//!< End of allocated memory

	uint32_t		size;
	uint32_t		in;			//!< Write index
	uint32_t		out;			//!< Read index

	void			**data;			//!< Ring buffer data

	bool			lock;			//!< Perform thread synchronisation

	pthread_mutex_t		mutex;			//!< Thread synchronisation mutex
};

/** Destroy mutex associated with ring buffer
 *
 * @param[in] fring being freed.
 * @return 0
 */
static int _fring_free(fr_fring_t *fring)
{
	void *next;

	/*
	 *	Free any data left in the buffer
	 */
	while ((next = fr_fring_next(fring))) talloc_free(next);

	if (fring->lock) pthread_mutex_destroy(&fring->mutex);

	return 0;
}

/** Initialise a ring buffer with fixed element size
 *
 * @param[in] ctx	to allocate the buffer in.
 * @param[in] size	of buffer to allocate.
 * @param[in] lock	If true, insert and next operations will lock the buffer.
 * @return
 *	- New fring.
 *	- NULL on error.
 */
fr_fring_t *fr_fring_alloc(TALLOC_CTX *ctx, uint32_t size, bool lock)
{
	fr_fring_t *fring;

	uint32_t pow;

	/*
	 *	Find the nearest power of 2 (rounding up)
	 */
	for (pow = 0x00000001;
	     pow < size;
	     pow <<= 1);
	size = pow;
	size--;

	fring = talloc_zero(ctx, fr_fring_t);
	if (!fring) return NULL;
	talloc_set_destructor(fring, _fring_free);

	fring->data = talloc_zero_array(fring, void *, size);
	if (!fring->data) {
		talloc_free(fring);
		return NULL;
	}
	fring->size = size;

	if (lock) {
		fring->lock = true;
		pthread_mutex_init(&fring->mutex, NULL);
	}

	return fring;
}

/** Insert a new item into the circular buffer, freeing the tail if we hit it
 *
 * @param[in] fring	to insert item into
 * @param[in] in	item to insert (must have been allocated with talloc).
 * @return
 *	- 0 if we inserted the item without freeing existing items.
 *	- 1 if we inserted the item, but needed to free an existing item.
 */
int fr_fring_overwrite(fr_fring_t *fring, void *in)
{
	bool freed = false;
	if (fring->lock) pthread_mutex_lock(&fring->mutex);

	if (fring->data[fring->in]) {
		freed = true;
		talloc_free(fring->data[fring->in]);
	}

	fring->data[fring->in] = in;
	fring->in = (fring->in + 1) & fring->size;

	/* overwrite - out is advanced ahead of in */
	if (fring->in == fring->out) fring->out = (fring->out + 1) & fring->size;

	if (fring->lock) pthread_mutex_unlock(&fring->mutex);

	return freed ? 1 : 0;
}

/** Insert a new item into the circular buffer if the buffer is not full
 *
 * @param[in] fring	to insert item into.
 * @param[in] in	item to insert.
 * @return
 *	- 0 if we inserted the item.
 *	- -1 if there's no more space in the buffer to insert items
 */
int fr_fring_insert(fr_fring_t *fring, void *in)
{
	if (fring->lock) pthread_mutex_lock(&fring->mutex);

	if (fring->data[fring->in]) {
		if (fring->lock) pthread_mutex_unlock(&fring->mutex);

		return -1;
	}

	fring->data[fring->in] = in;
	fring->in = (fring->in + 1) & fring->size;

	/* overwrite - out is advanced ahead of in */
	if (fring->in == fring->out) fring->out = (fring->out + 1) & fring->size;

	if (fring->lock) pthread_mutex_unlock(&fring->mutex);

	return 0;
}

/** Remove an item from the buffer
 *
 * @param[in] fring	to drain data from.
 * @return
 *	- NULL if no dataents in the buffer.
 *	- An dataent from the buffer reparented to ctx.
 */
void *fr_fring_next(fr_fring_t *fring)
{
	void *out = NULL;

	if (fring->lock) pthread_mutex_lock(&fring->mutex);

	/* Buffer is empty */
	if (fring->out == fring->in) goto done;

	out = fring->data[fring->out];
	fring->data[fring->out] = NULL;
	fring->out = (fring->out + 1) & fring->size;

done:
	if (fring->lock) pthread_mutex_unlock(&fring->mutex);

	return out;
}
