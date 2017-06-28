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
 * @file dhcp/raw.c
 * @brief Send/recv DHCP packets using raw sockets.
 *
 * @copyright 2008,2017 The FreeRADIUS server project
 * @copyright 2008 Alan DeKok <aland@deployingradius.com>
 */

#include <stdint.h>
#include <stddef.h>
#include <talloc.h>
#include <freeradius-devel/pair.h>
#include <freeradius-devel/types.h>
#include <freeradius-devel/proto.h>
#include <freeradius-devel/udpfromto.h>
#include <freeradius-devel/dhcpv4/dhcpv4.h>

#ifdef SIOCSARP
int fr_dhcp_add_arp_entry(int fd, char const *interface,
			  VALUE_PAIR *macaddr, VALUE_PAIR *ip)
{
	struct sockaddr_in *sin;
	struct arpreq req;

	if (!interface) {
		fr_strerror_printf("No interface specified.  Cannot update ARP table");
		return -1;
	}

	if (!fr_cond_assert(macaddr) ||
	    !fr_cond_assert((macaddr->vp_type == FR_TYPE_ETHERNET) || (macaddr->vp_type == FR_TYPE_OCTETS))) {
		fr_strerror_printf("Wrong VP type (%s) for chaddr",
				   fr_int2str(dict_attr_types, macaddr->vp_type, "<invalid>"));
		return -1;
	}

	if (macaddr->vp_type == FR_TYPE_OCTETS) {
		if (macaddr->vp_length > sizeof(req.arp_ha.sa_data)) {
			fr_strerror_printf("arp sa_data field too small (%zu octets) to contain chaddr (%zu octets)",
					   sizeof(req.arp_ha.sa_data), macaddr->vp_length);
			return -1;
		}
	}

	memset(&req, 0, sizeof(req));
	sin = (struct sockaddr_in *) &req.arp_pa;
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = ip->vp_ipv4addr;

	strlcpy(req.arp_dev, interface, sizeof(req.arp_dev));

	if (macaddr->vp_type == FR_TYPE_ETHERNET) {
		memcpy(&req.arp_ha.sa_data, macaddr->vp_ether, sizeof(macaddr->vp_ether));
	} else {
		memcpy(&req.arp_ha.sa_data, macaddr->vp_octets, macaddr->vp_length);
	}

	req.arp_flags = ATF_COM;
	if (ioctl(fd, SIOCSARP, &req) < 0) {
		fr_strerror_printf("Failed to add entry in ARP cache: %s (%d)", fr_syserror(errno), errno);
		return -1;
	}

	return 0;
}
#else
int fr_dhcp_add_arp_entry(UNUSED int fd, UNUSED char const *interface,
			  UNUSED VALUE_PAIR *macaddr, UNUSED VALUE_PAIR *ip)
{
	fr_strerror_printf("Adding ARP entry is unsupported on this system");
	return -1;
}
#endif


#ifdef HAVE_LINUX_IF_PACKET_H
/*
 *	Open a packet interface raw socket.
 *	Bind it to the specified interface using a device independent physical layer address.
 */
int fr_dhcpv4_raw_socket_open(int if_index, struct sockaddr_ll *link_layer)
{
	int lsock_fd;

	/*
	 * PF_PACKET - packet interface on device level.
	 * using a raw socket allows packet data to be unchanged by the device driver.
	 */
	lsock_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (lsock_fd < 0) {
		fr_strerror_printf("cannot open socket: %s", fr_syserror(errno));
		return lsock_fd;
	}

	/* Set link layer parameters */
	memset(link_layer, 0, sizeof(struct sockaddr_ll));

	link_layer->sll_family = AF_PACKET;
	link_layer->sll_protocol = htons(ETH_P_ALL);
	link_layer->sll_ifindex = if_index;
	link_layer->sll_hatype = ARPHRD_ETHER;
	link_layer->sll_pkttype = PACKET_OTHERHOST;
	link_layer->sll_halen = 6;

	if (bind(lsock_fd, (struct sockaddr *)link_layer, sizeof(struct sockaddr_ll)) < 0) {
		close(lsock_fd);
		fr_strerror_printf("cannot bind raw socket: %s", fr_syserror(errno));
		return -1;
	}

	return lsock_fd;
}

/*
 *	Encode and send a DHCP packet on a raw packet socket.
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
	if ((vp = fr_pair_find_by_num(packet->vps, 267, DHCP_MAGIC_VENDOR, TAG_ANY))) {
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
		fr_radius_free(&packet);
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
	    (vp = fr_pair_find_by_num(request->vps, 267, DHCP_MAGIC_VENDOR, TAG_ANY)) &&
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

	code = fr_dhcpv4_packet_get_option((dhcp_packet_t const *) packet->data, packet->data_len, FR_DHCP_MESSAGE_TYPE);
	if (!code) {
		fr_strerror_printf("No message-type option was found in the packet");
		fr_radius_free(&packet);
		return NULL;
	}

	if ((code[1] < 1) || (code[2] == 0) || (code[2] > 8)) {
		fr_strerror_printf("Unknown value for message-type option");
		fr_radius_free(&packet);
		return NULL;
	}

	packet->code = code[2] | FR_DHCP_OFFSET;

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


/** Send DHCP packet using socket
 *
 * @param packet to send
 * @return
 *	- >= 0 if successful.
 *	- < 0 if failed.
 */
int fr_dhcp_send_socket(RADIUS_PACKET *packet)
{
	int ret;
	struct sockaddr_storage	dst;
	socklen_t		sizeof_dst;
#ifdef WITH_UDPFROMTO
	struct sockaddr_storage	src;
	socklen_t		sizeof_src;

	fr_ipaddr_to_sockaddr(&packet->src_ipaddr, packet->src_port, &src, &sizeof_src);
#endif

	fr_ipaddr_to_sockaddr(&packet->dst_ipaddr, packet->dst_port, &dst, &sizeof_dst);
	if (packet->data_len == 0) {
		fr_strerror_printf("No data to send");
		return -1;
	}

	errno = 0;

#ifndef WITH_UDPFROMTO
	/*
	 *	Assume that the packet is encoded before sending it.
	 */
	ret = sendto(packet->sockfd, packet->data, packet->data_len, 0, (struct sockaddr *)&dst, sizeof_dst);
#else

	ret = sendfromto(packet->sockfd, packet->data, packet->data_len, 0, (struct sockaddr *)&src, sizeof_src,
			 (struct sockaddr *)&dst, sizeof_dst, packet->if_index);
#endif
	if ((ret < 0) && errno) fr_strerror_printf("dhcp_send_socket: %s", fr_syserror(errno));

	return ret;
}


/** Receive DHCP packet using socket
 *
 * @param sockfd handle.
 * @return
 *	- pointer to RADIUS_PACKET if successful.
 *	- NULL if failed.
 */
RADIUS_PACKET *fr_dhcp_recv_socket(int sockfd)
{
	struct sockaddr_storage	src;
	struct sockaddr_storage	dst;
	socklen_t		sizeof_src;
	socklen_t		sizeof_dst;
	RADIUS_PACKET		*packet;
	uint8_t			*data;
	ssize_t			data_len;
	fr_ipaddr_t		src_ipaddr, dst_ipaddr;
	uint16_t		src_port, dst_port;
	int			if_index = 0;
	struct timeval		when;

	data = talloc_zero_array(NULL, uint8_t, MAX_PACKET_SIZE);
	if (!data) {
		fr_strerror_printf("Out of memory");
		return NULL;
	}

	sizeof_src = sizeof(src);
#ifdef WITH_UDPFROMTO
	sizeof_dst = sizeof(dst);
	data_len = recvfromto(sockfd, data, MAX_PACKET_SIZE, 0,
			      (struct sockaddr *)&src, &sizeof_src,
			      (struct sockaddr *)&dst, &sizeof_dst, &if_index, &when);
#else
	data_len = recvfrom(sockfd, data, MAX_PACKET_SIZE, 0,
			    (struct sockaddr *)&src, &sizeof_src);
#endif

	if (data_len <= 0) {
		fr_strerror_printf("Failed reading data from DHCP socket: %s", fr_syserror(errno));
		talloc_free(data);
		return NULL;
	}

	if (!fr_cond_assert(data_len <= (ssize_t)talloc_array_length(data))) {
		talloc_free(data);	/* Bounds check for tainted scalar (Coverity) */
		return NULL;
	}
	sizeof_dst = sizeof(dst);

#ifndef WITH_UDPFROMTO
	/*
	*	This should never fail...
	*/
	if (getsockname(sockfd, (struct sockaddr *) &dst, &sizeof_dst) < 0) {
		fr_strerror_printf("getsockname failed: %s", fr_syserror(errno));
		talloc_free(data);
		return NULL;
	}
#endif

	fr_ipaddr_from_sockaddr(&dst, sizeof_dst, &dst_ipaddr, &dst_port);
	fr_ipaddr_from_sockaddr(&src, sizeof_src, &src_ipaddr, &src_port);

	packet = fr_dhcp_packet_ok(data, data_len, src_ipaddr, src_port, dst_ipaddr, dst_port);
	if (packet) {
		talloc_steal(packet, data);
		packet->data = data;
		packet->sockfd = sockfd;
		packet->if_index = if_index;
		packet->timestamp = when;
		return packet;
	}

	return NULL;
}
