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
 * @file cbuff.c
 * @brief Implementation of a ring buffer
 *
 * @copyright 2013  The FreeRADIUS server project
 * @copyright 2013  Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/libradius.h>

#ifdef HAVE_PTHREAD_H
#  define PTHREAD_MUTEX_LOCK(_x) if (_x->lock) pthread_mutex_lock(&((_x)->mutex))
#  define PTHREAD_MUTEX_UNLOCK(_x) if (_x->lock) pthread_mutex_unlock(&((_x)->mutex))
#else
#  define PTHREAD_MUTEX_LOCK(_x)
#  define PTHREAD_MUTEX_UNLOCK(_x)
#endif

/** Standard thread safe circular buffer
 *
 */
struct fr_cbuff {
	void const		*end;			//!< End of allocated memory

	uint32_t		size;
	uint32_t		in;			//!< Write index
	uint32_t		out;			//!< Read index

	void			**elem;			//!< Ring buffer data

	bool			lock;			//!< Perform thread synchronisation
	pthread_mutex_t		mutex;			//!< Thread synchronisation mutex
};

/** Initialise a new circular buffer
 *
 * @param ctx to allocate the buffer in.
 * @param size of buffer to allocate.
 * @param lock If true, insert and next operations will lock the buffer.
 * @return new cbuff, or NULL on error.
 */
#ifdef HAVE_PTHREAD_H
fr_cbuff_t *fr_cbuff_alloc(TALLOC_CTX *ctx, uint32_t size, bool lock)
#else
fr_cbuff_t *fr_cbuff_alloc(TALLOC_CTX *ctx, uint32_t size, UNUSED bool lock)
#endif
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
	if (!cbuff) {
		return NULL;
	}
	cbuff->elem = talloc_zero_array(cbuff, void *, size);
	if (!cbuff->elem) {
		return NULL;
	}
	cbuff->size = size;

#ifdef HAVE_PTHREAD_H
	if (lock) {
		cbuff->lock = true;
		pthread_mutex_init(&cbuff->mutex, NULL);
	}
#endif
	return cbuff;
}

/** Insert a new element into the buffer, and steal it from it's original context
 *
 * cbuff will steal obj and insert it into it's own context.
 *
 * @param cbuff to insert element into
 * @param obj to insert, must of been allocated with talloc
 */
void fr_cbuff_rp_insert(fr_cbuff_t *cbuff, void *obj)
{
	PTHREAD_MUTEX_LOCK(cbuff);

	if (cbuff->elem[cbuff->in]) {
		TALLOC_FREE(cbuff->elem[cbuff->in]);
	}

	cbuff->elem[cbuff->in] = talloc_steal(cbuff, obj);

	cbuff->in = (cbuff->in + 1) & cbuff->size;

	/* overwrite - out is advanced ahead of in */
	if (cbuff->in == cbuff->out) {
		cbuff->out = (cbuff->out + 1) & cbuff->size;
	}

	PTHREAD_MUTEX_UNLOCK(cbuff);
}

/** Remove an item from the buffer, and reparent to ctx
 *
 * @param cbuff to remove element from
 * @param ctx to hang obj off.
 * @return NULL if no elements in the buffer, else an element from the buffer reparented to ctx.
 */
void *fr_cbuff_rp_next(fr_cbuff_t *cbuff, TALLOC_CTX *ctx)
{
	void *obj = NULL;

	PTHREAD_MUTEX_LOCK(cbuff);

	/* Buffer is empty */
	if (cbuff->out == cbuff->in) goto done;

	obj = talloc_steal(ctx, cbuff->elem[cbuff->out]);
	cbuff->out = (cbuff->out + 1) & cbuff->size;

done:
	PTHREAD_MUTEX_UNLOCK(cbuff);
	return obj;
}
