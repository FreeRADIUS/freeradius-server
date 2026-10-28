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
 * @file io/control.h
 * @brief control-plane signaling
 *
 * @copyright 2016 Alan DeKok (aland@freeradius.org)
 */
RCSIDH(control_h, "$Id$")

#include <freeradius-devel/io/atomic_queue.h>
#include <freeradius-devel/io/ring_buffer.h>
#include <freeradius-devel/util/time.h>
#include <freeradius-devel/util/event.h>

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 *  A one-way control plane signal.
 *
 *  Multiple-producer, single consumer.
 */
typedef struct fr_control_s fr_control_t;
typedef	void (*fr_control_callback_t)(void const *data, size_t data_size, fr_time_t now, void *uctx);

/** Who defines control plane events
 *
 *  Each event set has its own dispatch table on every control, and
 *  numbers its own events from zero.  A message is addressed by
 *  event set and event, so the code behind one set never needs to
 *  know what any other set registered.
 */
typedef enum fr_control_eventset_t : uint16_t {
	FR_CONTROL_EVENTSET_NETWORK = 0,	//!< Events the network defines.
	FR_CONTROL_EVENTSET_WORKER,		//!< Events a worker defines.
	FR_CONTROL_EVENTSET_CHANNEL,		//!< Events channels define.
	FR_CONTROL_EVENTSET_COORD,		//!< Events the coordinator defines.
	FR_CONTROL_EVENTSET_MAX
} fr_control_eventset_t;

/*
 *	A suggestion for max # of messages, and max message size.
 */
#define FR_CONTROL_MAX_MESSAGES (1024)
#define FR_CONTROL_MAX_SIZE	(64)

fr_control_t *fr_control_create(TALLOC_CTX *ctx, fr_event_list_t *el, fr_atomic_queue_t *aq) CC_HINT(nonnull(3));

int fr_control_open(fr_control_t *c);

int fr_control_gc(fr_control_t *c, fr_ring_buffer_t *rb) CC_HINT(nonnull);

int fr_control_message_send(fr_control_t *c, fr_ring_buffer_t *rb, fr_control_eventset_t es, uint16_t ev,
			    void *data, size_t data_size) CC_HINT(nonnull);

int fr_control_message_push(fr_control_t *c, fr_ring_buffer_t *rb, fr_control_eventset_t es, uint16_t ev,
			    void *data, size_t data_size) CC_HINT(nonnull);
ssize_t fr_control_message_pop(fr_atomic_queue_t *aq, fr_control_eventset_t *p_es, uint16_t *p_ev,
			       void *data, size_t data_size) CC_HINT(nonnull);

int fr_control_callback_add(fr_control_t *c, fr_control_eventset_t es, uint16_t ev,
			    fr_control_callback_t callback, void *uctx) CC_HINT(nonnull(1,4));
int fr_control_callback_delete(fr_control_t *c, fr_control_eventset_t es, uint16_t ev) CC_HINT(nonnull);

int fr_control_same_thread(fr_control_t *c) CC_HINT(nonnull);

void fr_control_sleeping(fr_control_t *c) CC_HINT(nonnull);
void fr_control_awake(fr_control_t *c) CC_HINT(nonnull);
bool fr_control_is_sleeping(fr_control_t *c) CC_HINT(nonnull);

void fr_control_wait(fr_control_t *c) CC_HINT(nonnull);

#ifdef __cplusplus
}
#endif
