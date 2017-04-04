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
#ifndef _FR_RECEIVE_H
#define _FR_RECEIVE_H
/**
 * $Id$
 *
 * @file util/receiver.h
 * @brief Receive packets
 *
 * @copyright 2016 Alan DeKok <aland@freeradius.org>
 */
RCSIDH(receiver_h, "$Id$")

#include <freeradius-devel/fr_log.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct fr_receiver_t fr_receiver_t;

fr_receiver_t *fr_receiver_create(TALLOC_CTX *ctx, fr_log_t *logger, uint32_t num_transports, fr_transport_t **transports);
void fr_receiver_exit(fr_receiver_t *rc);
int fr_receiver_destroy(fr_receiver_t *rc) CC_HINT(nonnull);
void fr_receiver(fr_receiver_t *rc) CC_HINT(nonnull);

int fr_receiver_socket_add(fr_receiver_t *rc, int fd, void *ctx, fr_transport_t *transport) CC_HINT(nonnull);
int fr_receiver_worker_add(fr_receiver_t *rc, fr_worker_t *worker) CC_HINT(nonnull);

#ifdef __cplusplus
}
#endif

#endif /* _FR_RECEIVER_H */
