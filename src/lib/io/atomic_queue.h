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

/**
 * $Id$
 *
 * @file io/atomic_queue.h
 * @brief Thread-safe queues.
 *
 * @copyright 2016 Alan DeKok (aland@freeradius.org)
 */
RCSIDH(atomic_queue_h, "$Id$")


#ifdef HAVE_STDATOMIC_H
#  include <stdatomic.h>
#else
#  include <freeradius-devel/util/stdatomic.h>
#endif
#include <freeradius-devel/util/talloc.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct fr_atomic_queue_s fr_atomic_queue_t;

fr_atomic_queue_t	*fr_atomic_queue_talloc(TALLOC_CTX *ctx, size_t size);
fr_atomic_queue_t	*fr_atomic_queue_malloc(size_t size);
void			fr_atomic_queue_free(fr_atomic_queue_t **aq);
bool			fr_atomic_queue_push(fr_atomic_queue_t *aq, void *data);
bool			fr_atomic_queue_pop(fr_atomic_queue_t *aq, void **p_data);
size_t			fr_atomic_queue_size(fr_atomic_queue_t *aq);

/** Unbounded segmented single-producer / single-consumer queue
 *
 * Internally a linked list of fixed-size `fr_atomic_queue_t` segments.
 * When the producer's current segment fills, a new segment is malloc'd
 * and linked in; the consumer drains segments in order and frees them
 * as it advances.  Allocation on the producer side uses raw malloc
 * (not talloc), so the producer thread is free to be one that cannot
 * safely use talloc (e.g. a library-owned callback thread).
 *
 * Exactly one producer and one consumer.  Not safe for MPMC use.
 */
typedef struct fr_atomic_ring_s fr_atomic_ring_t;

fr_atomic_ring_t	*fr_atomic_ring_alloc(TALLOC_CTX *ctx, size_t seg_size);
void			fr_atomic_ring_free(fr_atomic_ring_t **ring);
bool			fr_atomic_ring_push(fr_atomic_ring_t *ring, void *data);
bool			fr_atomic_ring_pop(fr_atomic_ring_t *ring, void **p_data);

#ifdef WITH_VERIFY_PTR
void			fr_atomic_queue_verify(fr_atomic_queue_t *aq);
#endif

#ifndef NDEBUG
void			fr_atomic_queue_debug(FILE *fp, fr_atomic_queue_t *aq);
#endif


#ifdef __cplusplus
}
#endif
