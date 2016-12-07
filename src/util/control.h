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
#ifndef _FR_CONTROL_H
#define _FR_CONTROL_H
/**
 * $Id$
 *
 * @file util/control.h
 * @brief control-plane signaling
 *
 * @copyright 2016 Alan DeKok <aland@freeradius.org>
 */
RCSIDH(control_h, "$Id$")

#include <freeradius-devel/util/atomic_queue.h>

#include <sys/types.h>
#include <sys/event.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 *  A one-way control plane signal.
 *
 *  Multiple-producer, single consumer.
 */
typedef struct fr_control_t fr_control_t;

fr_control_t *fr_control_create(TALLOC_CTX *ctx, int kq, fr_atomic_queue_t *aq);
void fr_control_free(fr_control_t *c);

int fr_control_gc(fr_control_t *c) CC_HINT(nonnull);

int fr_control_message_send(fr_control_t *c, void *data, size_t data_size);
ssize_t fr_control_message_receive(fr_atomic_queue_t *aq, struct kevent *kev, void *data, size_t data_size);

#ifdef __cplusplus
}
#endif

#endif /* _FR_CONTROL_H */
