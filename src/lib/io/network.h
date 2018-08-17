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
 * @file io/network.h
 * @brief Receive packets
 *
 * @copyright 2016 Alan DeKok <aland@freeradius.org>
 */
RCSIDH(network_h, "$Id$")

#include <freeradius-devel/util/log.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct fr_network_t fr_network_t;

fr_network_t *fr_network_create(TALLOC_CTX *ctx, fr_event_list_t *el, fr_log_t const *logger, fr_log_lvl_t lvl) CC_HINT(nonnull(2,3));
void fr_network_exit(fr_network_t *nr) CC_HINT(nonnull);
int fr_network_destroy(fr_network_t *nr) CC_HINT(nonnull);
void fr_network(fr_network_t *nr) CC_HINT(nonnull);

int fr_network_listen_add(fr_network_t *nr, fr_listen_t const *io) CC_HINT(nonnull);
int fr_network_socket_delete(fr_network_t *nr, fr_listen_t const *listen);
int fr_network_directory_add(fr_network_t *nr, fr_listen_t const *listen) CC_HINT(nonnull);
int fr_network_worker_add(fr_network_t *nr, fr_worker_t *worker) CC_HINT(nonnull);
void fr_network_listen_read(fr_network_t *nr, fr_listen_t const *listen) CC_HINT(nonnull);
int fr_network_listen_inject(fr_network_t *nr, fr_listen_t *listen, uint8_t const *packet, size_t packet_len, fr_time_t recv_time);
int fr_network_stats(fr_network_t const *nr, int num, uint64_t *stats) CC_HINT(nonnull);
extern fr_cmd_table_t cmd_network_table[];

#ifdef __cplusplus
}
#endif
