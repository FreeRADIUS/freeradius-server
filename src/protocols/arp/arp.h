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

/*
 * $Id$
 *
 * @file protocols/arp/arp.h
 * @brief Structures and prototypes for base RADIUS functionality.
 *
 * @copyright 2020 Network RADIUS SARL <legal@networkradius.com>
 */
#include <freeradius-devel/util/cursor.h>
#include <freeradius-devel/util/packet.h>
#include <freeradius-devel/util/rand.h>
#include <freeradius-devel/util/log.h>

#include <freeradius-devel/protocol/arp/dictionary.h>
#include <freeradius-devel/protocol/arp/rfc826.h>

#define FR_ARP_PACKET_SIZE (28)

int fr_arp_init(void);
void fr_arp_free(void);

ssize_t fr_arp_encode(uint8_t *packet, size_t packet_len, VALUE_PAIR *vps);
ssize_t fr_arp_decode(TALLOC_CTX *ctx, uint8_t const *packet, size_t packet_len, VALUE_PAIR **vps);
