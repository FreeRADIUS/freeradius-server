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

/** Structures and functions for packet manipulation
 *
 * @file src/lib/server/packet.h
 *
 * copyright 2023 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(server_packet_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/util/packet.h>
#include <freeradius-devel/util/socket.h>

int fr_packet_pairs_from_packet(TALLOC_CTX *ctx, fr_pair_list_t *list, fr_packet_t const *packet) CC_HINT(nonnull);
void fr_packet_net_from_pairs(fr_packet_t *packet, fr_pair_list_t const *list) CC_HINT(nonnull);

int packet_global_init(void);

#ifdef __cplusplus
}
#endif
