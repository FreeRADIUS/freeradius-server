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

/**
 * @file lib/util/cbuff.c
 * @brief Implementation of a ring buffer
 *
 * @copyright 2013  The FreeRADIUS server project
 * @copyright 2013  Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/libradius.h>
#include <pthread.h>

/** Standard thread safe circular buffer
 *
 */
struct fr_cbuff {
	void const		*end;			//!< End of allocated memory

	uint32_t		size;
	uint32_t		in;			//!< Write index
	uint32_t		out;			//!< Read index

	void			**data;			//!< Ring buffer data

	bool			lock;			//!< Perform thread synchronisation

	pthread_mutex_t		mutex;			//!< Thread synchronisation mutex
};

/** Destroy mutex associated with circular buffer
 *
 * @param[in] cbuff being freed.
 * @return 0
 */
static int _cbuff_free(fr_cbuff_t *cbuff)
{
	void *next;

	if (cbuff->lock) pthread_mutex_destroy(&cbuff->mutex);

	/*
	 *	Free any data left in the buffer
	 */
	while ((next = fr_cbuff_next(cbuff))) talloc_free(next);

	return 0;
}

/** Initialise a new circular buffer
 *
 * @param[in] ctx	to allocate the buffer in.
 * @param[in] size	of buffer to allocate.
 * @param[in] lock	If true, insert and next operations will lock the buffer.
 * @return
 *	- New cbuff.
 *	- NULL on error.
 */
fr_cbuff_t *fr_cbuff_alloc(TALLOC_CTX *ctx, uint32_t size, bool lock)
{
	fr_cbuff_t *cbuff;

	uint32_t pow;

	/*
	 *	Find the nearest power of 2 (rounding up)
	 */
	for (pow = 0x00000001;
	     pow < size;
	     pow <<= 1);
	size = pow;
	size--;

	cbuff = talloc_zero(ctx, fr_cbuff_t);
	if (!cbuff) return NULL;
	talloc_set_destructor(cbuff, _cbuff_free);

	cbuff->data = talloc_zero_array(cbuff, void *, size);
	if (!cbuff->data) {
		talloc_free(cbuff);
		return NULL;
	}
	cbuff->size = size;

	if (lock) {
		cbuff->lock = true;
		pthread_mutex_init(&cbuff->mutex, NULL);
	}

	return cbuff;
}

/** Insert a new item into the circular buffer
 *
 * cbuff will steal obj and insert it into it's own context.
 *
 * @param[in] cbuff	to insert item into
 * @param[in] in	item to insert (must have been allocated with talloc).
 */
void fr_cbuff_insert(fr_cbuff_t *cbuff, void *in)
{
	if (cbuff->lock) pthread_mutex_lock(&cbuff->mutex);

	if (cbuff->data[cbuff->in]) talloc_free(cbuff->data[cbuff->in]);

	cbuff->data[cbuff->in] = in;
	cbuff->in = (cbuff->in + 1) & cbuff->size;

	/* overwrite - out is advanced ahead of in */
	if (cbuff->in == cbuff->out) cbuff->out = (cbuff->out + 1) & cbuff->size;

	if (cbuff->lock) pthread_mutex_unlock(&cbuff->mutex);
}

/** Remove an item from the buffer
 *
 * @param[in] cbuff	to drain data from.
 * @return
 *	- NULL if no dataents in the buffer.
 *	- An dataent from the buffer reparented to ctx.
 */
void *fr_cbuff_next(fr_cbuff_t *cbuff)
{
	void *out = NULL;

	if (cbuff->lock) pthread_mutex_lock(&cbuff->mutex);

	/* Buffer is empty */
	if (cbuff->out == cbuff->in) goto done;

	out = cbuff->data[cbuff->out];
	cbuff->data[cbuff->out] = NULL;
	cbuff->out = (cbuff->out + 1) & cbuff->size;

done:
	if (cbuff->lock) pthread_mutex_unlock(&cbuff->mutex);

	return out;
}
