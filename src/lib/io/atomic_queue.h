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
#ifndef _FR_ATOMIC_QUEUE_H
#define _FR_ATOMIC_QUEUE_H
/**
 * $Id$
 *
 * @file io/atomic_queue.h
 * @brief Thread-safe queues.
 *
 * @copyright 2016 Alan DeKok <aland@freeradius.org>
 */
RCSIDH(atomic_queue_h, "$Id$")

#include <talloc.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct fr_atomic_queue_t fr_atomic_queue_t;

fr_atomic_queue_t *fr_atomic_queue_create(TALLOC_CTX *ctx, int size);
bool fr_atomic_queue_push(fr_atomic_queue_t *aq, void *data);
bool fr_atomic_queue_pop(fr_atomic_queue_t *aq, void **p_data);

#ifndef NDEBUG
void fr_atomic_queue_debug(fr_atomic_queue_t *aq, FILE *fp);
#endif


#ifdef __cplusplus
}
#endif

#endif /* _FR_ATOMIC_QUEUE_H */
