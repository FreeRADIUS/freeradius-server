/*
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @file protocols/dhcpv4/raw.c
 * @brief Send/recv DHCP packets using raw sockets.
 *
 * @copyright 2008,2017 The FreeRADIUS server project
 * @copyright 2008 Alan DeKok (aland@deployingradius.com)
 */
#include "attrs.h"
#include "dhcpv4.h"

#include <freeradius-devel/util/net.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/util/types.h>
#include <freeradius-devel/util/udpfromto.h>

#include <stddef.h>
#include <stdint.h>
#include <talloc.h>
#include <sys/ioctl.h>

#ifdef HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif

#ifdef HAVE_LINUX_IF_PACKET_H
#  include <linux/if_packet.h>
#  include <linux/if_ether.h>
#endif

#include <net/if_arp.h>

#ifdef HAVE_LINUX_IF_PACKET_H
/** Open a raw socket to read/write packets from/to
 *
 * @param[out] link_layer	A sockaddr_ll struct to populate.  Must be passed to other raw
 *				functions.
 * @param[in] if_index		of the interface we're binding to.
 * @return
 *	- >= 0 a file descriptor to read/write packets on.
 *	- <0 an error ocurred.
 */
int fr_dhcpv4_raw_socket_open(struct sockaddr_ll *link_layer, int if_index)
{
	int fd;

	/*
	 * PF_PACKET - packet interface on device level.
	 * using a raw socket allows packet data to be unchanged by the device driver.
	 */
	fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd < 0) {
		fr_strerror_printf("Cannot open socket: %s", fr_syserror(errno));
		return fd;
	}

	/* Set link layer parameters */
	memset(link_layer, 0, sizeof(struct sockaddr_ll));

	link_layer->sll_family = AF_PACKET;
	link_layer->sll_protocol = htons(ETH_P_ALL);
	link_layer->sll_ifindex = if_index;
	link_layer->sll_hatype = ARPHRD_ETHER;
	link_layer->sll_pkttype = PACKET_OTHERHOST;
	link_layer->sll_halen = 6;

	if (bind(fd, (struct sockaddr *)link_layer, sizeof(struct sockaddr_ll)) < 0) {
		close(fd);
		fr_strerror_printf("Cannot bind raw socket: %s", fr_syserror(errno));
		return -1;
	}

	return fd;
}

/** Create the requisite L2/L3 headers, and write a DHCPv4 packet to a raw socket
 *
 * @param[in] sockfd		to write to.
 * @param[in] link_layer	information, as returned by fr_dhcpv4_raw_socket_open.
 * @param[in] packet		to write.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_dhcpv4_raw_packet_send(int sockfd, struct sockaddr_ll *link_layer, RADIUS_PACKET *packet)
{
	uint8_t			dhcp_packet[1518] = { 0 };
	ethernet_header_t	*eth_hdr = (ethernet_header_t *)dhcp_packet;
	ip_header_t		*ip_hdr = (ip_header_t *)(dhcp_packet + ETH_HDR_SIZE);
	udp_header_t		*udp_hdr = (udp_header_t *) (dhcp_packet + ETH_HDR_SIZE + IP_HDR_SIZE);
	dhcp_packet_t		*dhcp = (dhcp_packet_t *)(dhcp_packet + ETH_HDR_SIZE + IP_HDR_SIZE + UDP_HDR_SIZE);

	uint16_t		l4_len = (UDP_HDR_SIZE + packet->data_len);
	VALUE_PAIR		*vp;

	/* set ethernet source address to our MAC address (DHCP-Client-Hardware-Address). */
	uint8_t dhmac[ETH_ADDR_LEN] = { 0 };
	if ((vp = fr_pair_find_by_da(packet->vps, attr_dhcp_client_hardware_address, TAG_ANY))) {
		if (vp->vp_type == FR_TYPE_ETHERNET) memcpy(dhmac, vp->vp_ether, sizeof(vp->vp_ether));
	}

	/* fill in Ethernet layer (L2) */
	memcpy(eth_hdr->ether_dst, eth_bcast, ETH_ADDR_LEN);
	memcpy(eth_hdr->ether_src, dhmac, ETH_ADDR_LEN);
	eth_hdr->ether_type = htons(ETH_TYPE_IP);

	/* fill in IP layer (L3) */
	ip_hdr->ip_vhl = IP_VHL(4, 5);
	ip_hdr->ip_tos = 0;
	ip_hdr->ip_len = htons(IP_HDR_SIZE +  UDP_HDR_SIZE + packet->data_len);
	ip_hdr->ip_id = 0;
	ip_hdr->ip_off = 0;
	ip_hdr->ip_ttl = 64;
	ip_hdr->ip_p = 17;
	ip_hdr->ip_sum = 0; /* Filled later */

	/* saddr: Packet-Src-IP-Address (default: 0.0.0.0). */
	ip_hdr->ip_src.s_addr = packet->src_ipaddr.addr.v4.s_addr;

	/* daddr: packet destination IP addr (should be 255.255.255.255 for broadcast). */
	ip_hdr->ip_dst.s_addr = packet->dst_ipaddr.addr.v4.s_addr;

	/* IP header checksum */
	ip_hdr->ip_sum = fr_ip_header_checksum((uint8_t const *)ip_hdr, 5);

	udp_hdr->src = htons(packet->src_port);
	udp_hdr->dst = htons(packet->dst_port);

	udp_hdr->len = htons(l4_len);
	udp_hdr->checksum = 0; /* UDP checksum will be done after dhcp header */

	/* DHCP layer (L7) */

	/* just copy what FreeRADIUS has encoded for us. */
	memcpy(dhcp, packet->data, packet->data_len);

	/* UDP checksum is done here */
	udp_hdr->checksum = fr_udp_checksum((uint8_t const *)(dhcp_packet + ETH_HDR_SIZE + IP_HDR_SIZE),
					    ntohs(udp_hdr->len), udp_hdr->checksum,
					    packet->src_ipaddr.addr.v4, packet->dst_ipaddr.addr.v4);

	return sendto(sockfd, dhcp_packet, (ETH_HDR_SIZE + IP_HDR_SIZE + UDP_HDR_SIZE + packet->data_len),
		      0, (struct sockaddr *) link_layer, sizeof(struct sockaddr_ll));
}

/*
 *	For a client, receive a DHCP packet from a raw packet
 *	socket. Make sure it matches the ongoing request.
 *
 *	FIXME: split this into two, recv_raw_packet, and verify(packet, original)
 */
RADIUS_PACKET *fr_dhcv4_raw_packet_recv(int sockfd, struct sockaddr_ll *link_layer, RADIUS_PACKET *request)
{
	VALUE_PAIR		*vp;
	RADIUS_PACKET		*packet;
	uint8_t const		*code;
	uint32_t		magic, xid;
	ssize_t			data_len;

	uint8_t			*raw_packet;
	ethernet_header_t	*eth_hdr;
	ip_header_t		*ip_hdr;
	udp_header_t		*udp_hdr;
	dhcp_packet_t		*dhcp_hdr;
	uint16_t		udp_src_port;
	uint16_t		udp_dst_port;
	size_t			dhcp_data_len;
	socklen_t		sock_len;

	packet = fr_radius_alloc(NULL, false);
	if (!packet) {
		fr_strerror_printf("Failed allocating packet");
		return NULL;
	}

	raw_packet = talloc_zero_array(packet, uint8_t, MAX_PACKET_SIZE);
	if (!raw_packet) {
		fr_strerror_printf("Out of memory");
		fr_radius_packet_free(&packet);
		return NULL;
	}

	packet->sockfd = sockfd;

	/* a packet was received (but maybe it is not for us) */
	sock_len = sizeof(struct sockaddr_ll);
	data_len = recvfrom(sockfd, raw_packet, MAX_PACKET_SIZE, 0, (struct sockaddr *)link_layer, &sock_len);

	uint8_t data_offset = ETH_HDR_SIZE + IP_HDR_SIZE + UDP_HDR_SIZE; /* DHCP data datas after Ethernet, IP, UDP */

	if (data_len <= data_offset) DISCARD_RP("Payload (%d) smaller than required for layers 2+3+4", (int)data_len);

	/* map raw packet to packet header of the different layers (Ethernet, IP, UDP) */
	eth_hdr = (ethernet_header_t *)raw_packet;

	/*
	 *	Check Ethernet layer data (L2)
	 */
	if (ntohs(eth_hdr->ether_type) != ETH_TYPE_IP) DISCARD_RP("Ethernet type (%d) != IP",
	    ntohs(eth_hdr->ether_type));

	/*
	 *	If Ethernet destination is not broadcast (ff:ff:ff:ff:ff:ff)
	 *	Check if it matches the source HW address used (DHCP-Client-Hardware-Address = 267)
	 */
	if ((memcmp(&eth_bcast, &eth_hdr->ether_dst, ETH_ADDR_LEN) != 0) &&
	    (vp = fr_pair_find_by_da(request->vps, attr_dhcp_client_hardware_address, TAG_ANY)) &&
	    ((vp->vp_type == FR_TYPE_ETHERNET) && (memcmp(vp->vp_ether, &eth_hdr->ether_dst, ETH_ADDR_LEN) != 0))) {

		/* No match. */
		DISCARD_RP("Ethernet destination (%pV) is not broadcast and doesn't match request source (%pV)",
			   fr_box_ether(eth_hdr->ether_dst), &vp->data);
	}

	/*
	 *	Ethernet is OK.  Now look at IP.
	 */
	ip_hdr = (ip_header_t *)(raw_packet + ETH_HDR_SIZE);

	/*
	 *	Check IPv4 layer data (L3)
	 */
	if (ip_hdr->ip_p != IPPROTO_UDP) DISCARD_RP("IP protocol (%d) != UDP", ip_hdr->ip_p);

	/*
	 *	note: checking the destination IP address is not
	 *	useful (it would be the offered IP address - which we
	 *	don't know beforehand, or the broadcast address).
	 */

	/*
	 *	Now check UDP.
	 */
	udp_hdr = (udp_header_t *)(raw_packet + ETH_HDR_SIZE + IP_HDR_SIZE);

	/*
	 *	Check UDP layer data (L4)
	 */
	udp_src_port = ntohs(udp_hdr->src);
	udp_dst_port = ntohs(udp_hdr->dst);

	/*
	 *	Check DHCP layer data
	 */
	dhcp_data_len = data_len - data_offset;

	if (dhcp_data_len < MIN_PACKET_SIZE) DISCARD_RP("DHCP packet is too small (%zu < %i)",
							dhcp_data_len, MIN_PACKET_SIZE);
	if (dhcp_data_len > MAX_PACKET_SIZE) DISCARD_RP("DHCP packet is too large (%zu > %i)",
							dhcp_data_len, MAX_PACKET_SIZE);

	dhcp_hdr = (dhcp_packet_t *)(raw_packet + ETH_HDR_SIZE + IP_HDR_SIZE + UDP_HDR_SIZE);

	if (dhcp_hdr->htype != 1) DISCARD_RP("DHCP hardware type (%d) != Ethernet (1)", dhcp_hdr->htype);
	if (dhcp_hdr->hlen != 6) DISCARD_RP("DHCP hardware address length (%d) != 6", dhcp_hdr->hlen);

	magic = ntohl(dhcp_hdr->option_format);

	if (magic != DHCP_OPTION_MAGIC_NUMBER) DISCARD_RP("DHCP magic cookie (0x%04x) != DHCP (0x%04x)",
							  magic, DHCP_OPTION_MAGIC_NUMBER);

	/*
	 *	Reply transaction id must match value from request.
	 */
	xid = ntohl(dhcp_hdr->xid);
	if (xid != (uint32_t)request->id) DISCARD_RP("DHCP transaction ID (0x%04x) != xid from request (0x%04x)",
						     xid, request->id)

	/* all checks ok! this is a DHCP reply we're interested in. */
	packet->data_len = dhcp_data_len;
	packet->data = talloc_memdup(packet, raw_packet + data_offset, dhcp_data_len);
	TALLOC_FREE(raw_packet);
	packet->id = xid;

	code = fr_dhcpv4_packet_get_option((dhcp_packet_t const *) packet->data,
					   packet->data_len, attr_dhcp_message_type);
	if (!code) {
		fr_strerror_printf("No message-type option was found in the packet");
		fr_radius_packet_free(&packet);
		return NULL;
	}

	if ((code[1] < 1) || (code[2] == 0) || (code[2] > 8)) {
		fr_strerror_printf("Unknown value for message-type option");
		fr_radius_packet_free(&packet);
		return NULL;
	}

	packet->code = code[2];

	/*
	 *	Create a unique vector from the MAC address and the
	 *	DHCP opcode.  This is a hack for the RADIUS
	 *	infrastructure in the rest of the server.
	 *
	 *	Note: packet->data[2] == 6, which is smaller than
	 *	sizeof(packet->vector)
	 *
	 *	FIXME:  Look for client-identifier in packet,
	 *      and use that, too?
	 */
	memset(packet->vector, 0, sizeof(packet->vector));
	memcpy(packet->vector, packet->data + 28, packet->data[2]);
	packet->vector[packet->data[2]] = packet->code & 0xff;

	packet->src_port = udp_src_port;
	packet->dst_port = udp_dst_port;

	packet->src_ipaddr.af = AF_INET;
	packet->src_ipaddr.addr.v4.s_addr = ip_hdr->ip_src.s_addr;
	packet->dst_ipaddr.af = AF_INET;
	packet->dst_ipaddr.addr.v4.s_addr = ip_hdr->ip_dst.s_addr;

	return packet;
}
#endif
