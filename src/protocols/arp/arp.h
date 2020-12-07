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

/* for SIOCSARP, and fr_arp_entry_add */
#include <sys/ioctl.h>

#define FR_ARP_PACKET_SIZE (28)
#define ETH_TYPE_ARP (0x0806)

int fr_arp_init(void);
void fr_arp_free(void);

ssize_t fr_arp_encode(fr_dbuff_t *dbuff, uint8_t const *original, fr_pair_list_t *vps);
ssize_t fr_arp_decode(TALLOC_CTX *ctx, uint8_t const *packet, size_t packet_len, fr_pair_list_t *list);

int fr_arp_entry_add(int fd, char const *interface, uint8_t ipaddr[static 4], uint8_t macaddr[static 6]);

/*
 *	ARP for ethernet && IPv4.
 */
typedef struct {
	uint8_t		htype[2];	       	//!< Format of hardware address.
	uint8_t		ptype[2];	       	//!< Format of protocol address.
	uint8_t		hlen;			//!< Length of hardware address.
	uint8_t		plen;			//!< Length of protocol address.
	uint8_t		op[2];			//!< 1 - Request, 2 - Reply.
	uint8_t		sha[ETHER_ADDR_LEN];	//!< sender hardware address.
	uint8_t		spa[4];			//!< Sender protocol address.
	uint8_t		tha[ETHER_ADDR_LEN];	//!< Target hardware address.
	uint8_t		tpa[4];			//!< Target protocol address.
} fr_arp_packet_t;

#define FR_ARP_MAX_PACKET_CODE (26)
#define FR_ARP_CODE_DO_NOT_RESPOND (26)

extern char const *fr_arp_packet_codes[FR_ARP_MAX_PACKET_CODE];
