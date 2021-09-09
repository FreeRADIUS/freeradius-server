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
 * @file lib/server/udp_queue.h
 * @brief Handle queues of outgoing UDP packets
 *
 * @copyright 2021 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(udp_queue_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/util/dlist.h>
#include <freeradius-devel/util/inet.h>
#include <freeradius-devel/util/event.h>

typedef struct {
	fr_ipaddr_t		ipaddr;			//!< socket IP address
	uint16_t		port;			//!< socket port

	char const		*interface;		//!< Interface to bind to.

	fr_time_delta_t		max_queued_time;	//!< maximum time a packet can be queued

	uint32_t		max_queued_packets;	//!< maximum queued packets

	uint32_t		send_buff;		//!< How big the kernel's send buffer should be.

	bool			send_buff_is_set;	//!< Whether we were provided with a send_buf
} fr_udp_queue_config_t;

typedef struct fr_udp_queue_s fr_udp_queue_t;

typedef void (*fr_udp_queue_resume_t)(bool written, void *rctx);


fr_udp_queue_t *fr_udp_queue_alloc(TALLOC_CTX *ctx, fr_udp_queue_config_t const *config, fr_event_list_t *el,
				   fr_udp_queue_resume_t resume) CC_HINT(nonnull(2,3));

int fr_udp_queue_write(TALLOC_CTX *ctx, fr_udp_queue_t *uq,
		       uint8_t const *packet, size_t packet_len,
		       fr_ipaddr_t const *ipaddr, int port, void *rctx)  CC_HINT(nonnull(2,3,5));


#ifdef __cplusplus
}
#endif
