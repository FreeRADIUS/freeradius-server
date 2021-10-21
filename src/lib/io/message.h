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
 * @file io/message.h
 * @brief Inter-thread messaging
 *
 * @copyright 2016 Alan DeKok (aland@freeradius.org)
 */
RCSIDH(message_h, "$Id$")

#include <freeradius-devel/util/time.h>
#include <freeradius-devel/io/ring_buffer.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct fr_message_set_s fr_message_set_t;

typedef enum fr_message_status_t {
	FR_MESSAGE_FREE = 0,
	FR_MESSAGE_USED,
	FR_MESSAGE_LOCALIZED,
	FR_MESSAGE_DONE
} fr_message_status_t;

typedef struct {
	fr_message_status_t	status;		//!< free, used, done, etc.

	fr_time_t		when;		//!< when this message was sent
	fr_ring_buffer_t	*rb;		//!< pointer to the ring buffer
	uint8_t			*data;		//!< pointer to the data in the ring buffer
	size_t			data_size;	//!< size of the data in the ring buffer
	size_t			rb_size;	//!< cache-aligned size in the ring buffer
} fr_message_t;

fr_message_set_t *fr_message_set_create(TALLOC_CTX *ctx, int num_messages, size_t message_size, size_t ring_buffer_size) CC_HINT(nonnull);

fr_message_t *fr_message_reserve(fr_message_set_t *ms, size_t reserve_size) CC_HINT(nonnull);
fr_message_t *fr_message_alloc(fr_message_set_t *ms, fr_message_t *m, size_t actual_packet_size) CC_HINT(nonnull(1));
fr_message_t *fr_message_alloc_reserve(fr_message_set_t *ms, fr_message_t *m, size_t actual_packet_size,
				       size_t leftover, size_t reserve_size) CC_HINT(nonnull);
fr_message_t *fr_message_alloc_aligned(fr_message_set_t *ms, fr_message_t *m, size_t actual_packet_size) CC_HINT(nonnull(1));
int fr_message_done(fr_message_t *m) CC_HINT(nonnull);

fr_message_t *fr_message_localize(TALLOC_CTX *ctx, fr_message_t *m, size_t message_size) CC_HINT(nonnull);

int fr_message_set_messages_used(fr_message_set_t *ms) CC_HINT(nonnull);
void fr_message_set_gc(fr_message_set_t *ms) CC_HINT(nonnull);

void fr_message_set_debug(fr_message_set_t *ms, FILE *fp) CC_HINT(nonnull);

#ifdef __cplusplus
}
#endif
