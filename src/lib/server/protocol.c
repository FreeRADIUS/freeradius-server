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
 * @file lib/server/protocol.c
 * @brief Protocol module API.
 *
 * @copyright 2013 Alan DeKok
 */
RCSIDH(protocol_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/io/base.h>

#include <freeradius-devel/server/dl_module.h>
#include <freeradius-devel/server/listen.h>

/*
 *	Debug the packet if requested.
 */
void common_packet_debug(REQUEST *request, RADIUS_PACKET *packet, bool received)
{
#if defined(WITH_UDPFROMTO) && defined(WITH_IFINDEX_NAME_RESOLUTION)
	char if_name[IFNAMSIZ];
#endif

	if (!packet) return;
	if (!RDEBUG_ENABLED) return;


	log_request(L_DBG, L_DBG_LVL_1, request, __FILE__, __LINE__, "%s code %u Id %i from %s%pV%s:%i to %s%pV%s:%i "
#if defined(WITH_UDPFROMTO) && defined(WITH_IFINDEX_NAME_RESOLUTION)
		       "%s%s%s"
#endif
		       "length %zu",
		       received ? "Received" : "Sent",
		       packet->code,
		       packet->id,
		       packet->src_ipaddr.af == AF_INET6 ? "[" : "",
		       fr_box_ipaddr(packet->src_ipaddr),
		       packet->src_ipaddr.af == AF_INET6 ? "]" : "",
		       packet->src_port,
		       packet->dst_ipaddr.af == AF_INET6 ? "[" : "",
		       fr_box_ipaddr(packet->dst_ipaddr),
		       packet->dst_ipaddr.af == AF_INET6 ? "]" : "",
		       packet->dst_port,
#if defined(WITH_UDPFROMTO) && defined(WITH_IFINDEX_NAME_RESOLUTION)
		       packet->ifindex ? "via " : "",
		       packet->ifindex ? fr_ifname_from_ifindex(if_name, packet->ifindex) : "",
		       packet->ifindex ? " " : "",
#endif
		       packet->data_len);

	if (received) {
		log_request_pair_list(L_DBG_LVL_1, request, packet->vps, NULL);
	} else {
		log_request_proto_pair_list(L_DBG_LVL_1, request, packet->vps, NULL);
	}
}
