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
 * @file io/queue.h
 * @brief Thread-unsafe queues.
 *
 * @copyright 2016 Alan DeKok (aland@freeradius.org)
 */
RCSIDH(queue_h, "$Id$")

#include <talloc.h>
#include <stdbool.h>
#include <freeradius-devel/io/atomic_queue.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct fr_queue_s fr_queue_t;

fr_queue_t *fr_queue_create(TALLOC_CTX *ctx, int size);
fr_queue_t *fr_queue_resize(fr_queue_t *fq, int size) CC_HINT(nonnull);

bool fr_queue_push(fr_queue_t *fq, void *data) CC_HINT(nonnull);
bool fr_queue_pop(fr_queue_t *fq, void **p_data) CC_HINT(nonnull);

int fr_queue_size(fr_queue_t *fq) CC_HINT(nonnull);
int fr_queue_num_elements(fr_queue_t *fq) CC_HINT(nonnull);

int fr_queue_localize_atomic(fr_queue_t *fq, fr_atomic_queue_t *aq) CC_HINT(nonnull);

#ifndef NDEBUG
void fr_queue_debug(fr_queue_t *fq, FILE *fp) CC_HINT(nonnull);
#endif


#ifdef __cplusplus
}
#endif
