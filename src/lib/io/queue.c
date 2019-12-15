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
 * $Id$
 *
 * @brief Thread-unsafe queues
 * @file io/queue.c
 *
 * @copyright 2016 Alan DeKok (aland@freeradius.org)
 */
RCSID("$Id$")

#include <stdint.h>
#include <string.h>

#include <freeradius-devel/server/rad_assert.h>
#include <freeradius-devel/io/queue.h>

struct fr_queue_s {
	int		head;		//!< head of the queue
	int		tail;		//!< tail of the queue

	int		size;		//!< size of the queue
	int		num;		//!< number of elements pushed into the queue

	void		*entry[1];	//!< Array of queue data.
};

/** Create a non-thread-safe queue.
 *
 * @param[in] ctx the talloc ctx
 * @param[in] size the number of entries in the queue
 * @return
 *     - NULL on error
 *     - fr_queue_t *, a pointer to the allocated and initialized queue
 */
fr_queue_t *fr_queue_create(TALLOC_CTX *ctx, int size)
{
	fr_queue_t *fq;

	if (size <= 0) return NULL;

	/*
	 *	Allocate a contiguous blob for the header and queue.
	 *	This helps with memory locality.
	 *
	 *	Since we're allocating a blob, we should also set the
	 *	name of the data, too.
	 */
	fq = talloc_size(ctx, sizeof(*fq) + (size - 1) * sizeof(fq->entry[0]));
	if (!fq) return NULL;

	talloc_set_name(fq, "fr_queue_t");

	memset(fq, 0, sizeof(*fq) + (size - 1) * sizeof(fq->entry[0]));

	fq->size = size;

	return fq;
}


/** Push a pointer into the queue
 *
 * @param[in] fq the queue
 * @param[in] data the data to push
 * @return
 *	- true on successful push
 *	- false on queue full
 */
bool fr_queue_push(fr_queue_t *fq, void *data)
{
	(void) talloc_get_type_abort(fq, fr_queue_t);

	if (fq->num >= fq->size) return false;

	fq->entry[fq->head++] = data;
	if (fq->head >= fq->size) fq->head = 0;
	fq->num++;

	return true;
}


/** Pop a pointer from the queue
 *
 * @param[in] fq the queue
 * @param[in] p_data where to write the data
 * @return
 *	- true on successful pop
 *	- false on queue empty
 */
bool fr_queue_pop(fr_queue_t *fq, void **p_data)
{
	(void) talloc_get_type_abort(fq, fr_queue_t);

	if (fq->num == 0) return false;

	*p_data = fq->entry[fq->tail++];
	if (fq->tail >= fq->size) fq->tail = 0;
	fq->num--;

	return true;
}


/** get the size of a queue
 *
 * @param[in] fq the queue
 * @return
 *	- The size of the queue.
 */
int fr_queue_size(fr_queue_t *fq)
{
	(void) talloc_get_type_abort(fq, fr_queue_t);

	return fq->size;
}


/** get the number of elements in a queue.
 *
 * @param[in] fq the queue
 * @return
 *	- The number of elements in the queue.
 */
int fr_queue_num_elements(fr_queue_t *fq)
{
	(void) talloc_get_type_abort(fq, fr_queue_t);

	return fq->num;
}



/** Resize a queue, and copy the entries over.
 *
 * @param[in] fq the queue
 * @param[in] size the new size of the queue
 * @return
 *	- NULL on error
 *	- fr_queue_t * the new queue, which MAY BE fq.
 */
fr_queue_t *fr_queue_resize(fr_queue_t *fq, int size)
{
	fr_queue_t *nq;
	TALLOC_CTX *ctx;

	(void) talloc_get_type_abort(fq, fr_queue_t);

	if (size <= 0) return NULL;

	if (size <= fq->size) return fq;

	ctx = talloc_parent(fq);

	/*
	 *	If we can't create the new queue, return the old one.
	 */
	nq = fr_queue_create(ctx, size);
	if (!nq) return fq;

	/*
	 *	Empty: we're done.
	 */
	if (!fq->num) {
		goto done;
	}

	/*
	 *	Simple block of used elements, copy it.
	 */
	if (fq->head > fq->tail) {
		rad_assert(fq->num == (fq->head - fq->tail));
		memcpy(&nq->entry[0], &fq->entry[fq->tail], &fq->entry[fq->head] - &fq->entry[fq->tail]);
		nq->head = fq->num;
		nq->num = fq->num;
		goto done;
	}

	/*
	 *	The block of elements is split in two.  Copy the tail
	 *	to the bottom of our array, and then then head.
	 */
	memcpy(&nq->entry[0], &fq->entry[fq->tail], &fq->entry[fq->size] - &fq->entry[fq->tail]);
	nq->head = fq->size - fq->tail;

	rad_assert((nq->head + fq->head) == fq->num);

	memcpy(&nq->entry[nq->head], &fq->entry[0], &fq->entry[fq->head] - &fq->entry[0]);
	nq->head = fq->num;
	nq->num = fq->num;

done:
	talloc_free(fq);

	return nq;
}


/** Pull all entries from an atomic queue into our local queue.
 *
 * @param[in] fq the local queue
 * @param[in] aq the atomic queue
 * @return
 *	- number of entries successfully moved over
 */
int fr_queue_localize_atomic(fr_queue_t *fq, fr_atomic_queue_t *aq)
{
	void *data;
	int i, room;

	(void) talloc_get_type_abort(fq, fr_queue_t);

	/*
	 *	No room to push anything, return an error.
	 */
	room = fq->size - fq->num;
	if (!room) return 0;

	/*
	 *	Pop as many entries as we have room for.
	 */
	for (i = 0; i < room; i++) {
		if (!fr_atomic_queue_pop(aq, &data)) {
			return i;
		}

		fq->entry[fq->head++] = data;
		if (fq->head >= fq->size) fq->head = 0;
		fq->num++;
		rad_assert(fq->num <= fq->size);
	}

	return room;
}

#ifndef NDEBUG
/**  Dump a queue.
 *
 * @param[in] fq the queue
 * @param[in] fp where the debugging information will be printed.
 */
void fr_queue_debug(fr_queue_t *fq, FILE *fp)
{
	int i;

	fprintf(fp, "FQ %p size %d, head %d, tail %d\n",
		fq, fq->size, fq->head, fq->tail);

	for (i = 0; i < fq->size; i++) {
		fprintf(fp, "\t[%d] = { %p }\n",
			i, fq->entry[i]);
	}
}
#endif
