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
 * @file protocols/dhcpv4/pcap.c
 * @brief Alternative mechanism to send/recv DHCP packets using libpcap.
 *
 * @copyright 2008,2017 The FreeRADIUS server project
 * @copyright 2008 Alan DeKok (aland@deployingradius.com)
 */

#ifdef HAVE_LIBPCAP
#include <freeradius-devel/util/pcap.h>
#include "dhcpv4.h"

/** Send DHCP packet using PCAP
 *
 * @param pcap handle
 * @param dst_ether_addr MAC address to send packet to
 * @param packet to send
 * @return
 *	- -1 on failure.
 *	- 0 on success.
 */
int fr_dhcpv4_pcap_send(fr_pcap_t *pcap, uint8_t *dst_ether_addr, RADIUS_PACKET *packet)
{
	int			ret;
	uint8_t			dhcp_packet[1518] = { 0 };
	ethernet_header_t	*eth_hdr;
	ip_header_t		*ip_hdr;
	udp_header_t		*udp_hdr;
	dhcp_packet_t		*dhcp;
	/* Pointer to the current position in the frame */
	uint8_t			*end = dhcp_packet;
	uint16_t		l4_len;

	/* fill in Ethernet layer (L2) */
	eth_hdr = (ethernet_header_t *)dhcp_packet;
	memcpy(eth_hdr->src_addr, pcap->ether_addr, ETH_ADDR_LEN);
	memcpy(eth_hdr->dst_addr, dst_ether_addr, ETH_ADDR_LEN);
	eth_hdr->ether_type = htons(ETH_TYPE_IP);
	end += ETH_ADDR_LEN + ETH_ADDR_LEN + sizeof(eth_hdr->ether_type);

	/* fill in IP layer (L3) */
	ip_hdr = (ip_header_t *)(end);
	ip_hdr->ip_vhl = IP_VHL(4, 5);
	ip_hdr->ip_tos = 0;
	ip_hdr->ip_len = htons(IP_HDR_SIZE +  UDP_HDR_SIZE + packet->data_len);
	ip_hdr->ip_id = 0;
	ip_hdr->ip_off = 0;
	ip_hdr->ip_ttl = 64;
	ip_hdr->ip_p = 17;
	ip_hdr->ip_sum = 0; /* Filled later */

	ip_hdr->ip_src.s_addr = packet->src_ipaddr.addr.v4.s_addr;
	ip_hdr->ip_dst.s_addr = packet->dst_ipaddr.addr.v4.s_addr;

	/* IP header checksum */
	ip_hdr->ip_sum = fr_ip_header_checksum((uint8_t const *)ip_hdr, 5);
	end += IP_HDR_SIZE;

	/* fill in UDP layer (L4) */
	udp_hdr = (udp_header_t *)end;

	udp_hdr->src = htons(packet->src_port);
	udp_hdr->dst = htons(packet->dst_port);
	l4_len = (UDP_HDR_SIZE + packet->data_len);
	udp_hdr->len = htons(l4_len);
	udp_hdr->checksum = 0; /* UDP checksum will be done after dhcp header */
	end += UDP_HDR_SIZE;

	/* DHCP layer (L7) */
	dhcp = (dhcp_packet_t *)end;
	/* just copy what FreeRADIUS has encoded for us. */
	memcpy(dhcp, packet->data, packet->data_len);

	/* UDP checksum is done here */
	udp_hdr->checksum = fr_udp_checksum((uint8_t const *)udp_hdr, ntohs(udp_hdr->len), udp_hdr->checksum,
					    packet->src_ipaddr.addr.v4,
					    packet->dst_ipaddr.addr.v4);

	ret = pcap_inject(pcap->handle, dhcp_packet, (end - dhcp_packet + packet->data_len));
	if (ret < 0) {
		fr_strerror_printf("Error sending packet with pcap: %d, %s", ret, pcap_geterr(pcap->handle));
		return -1;
	}

	return 0;
}

/** Receive DHCP packet using PCAP
 *
 * @param pcap handle
 * @return
 *	- pointer to RADIUS_PACKET if successful.
 *	- NULL if failed.
 */
RADIUS_PACKET *fr_dhcpv4_pcap_recv(fr_pcap_t *pcap)
{
	int			ret;

	uint8_t const		*data;
	ssize_t			data_len;
	fr_ipaddr_t		src_ipaddr, dst_ipaddr;
	uint16_t		src_port, dst_port;
	struct pcap_pkthdr	*header;
	ssize_t			link_len, len;
	RADIUS_PACKET		*packet;

	/*
	 *	Pointers into the packet data we just received
	 */
	uint8_t const		*p;

	ip_header_t const	*ip = NULL;	/* The IP header */
	udp_header_t const	*udp;		/* The UDP header */
	uint8_t			version;	/* IP header version */

	ret = pcap_next_ex(pcap->handle, &header, &data);
	if (ret == 0) {
		fr_strerror_printf("No packet received from libpcap");
		return NULL; /* no packet */
	}
	if (ret < 0) {
		fr_strerror_printf("Error requesting next packet, got (%i): %s", ret, pcap_geterr(pcap->handle));
		return NULL;
	}

	link_len = fr_pcap_link_layer_offset(data, header->caplen, pcap->link_layer);
	if (link_len < 0) {
		fr_strerror_printf_push("Failed determining link layer header offset");
		return NULL;
	}

	p = data;

	/* Skip ethernet header */
	p += link_len;

	version = (p[0] & 0xf0) >> 4;
	switch (version) {
	case 4:
		ip = (ip_header_t const *)p;
		len = (0x0f & ip->ip_vhl) * 4;	/* ip_hl specifies length in 32bit words */
		p += len;
		break;

	case 6:
		fr_strerror_printf("IPv6 packets not supported by DHCPv4");
		return NULL;

	default:
		fr_strerror_printf("Invalid IP version field (%i)", version);
		return NULL;
	}

	/* Check IPv4 layer data (L3) */
	if (ip->ip_p != IPPROTO_UDP) {
		fr_strerror_printf("Expected IP protocol field value UDP (%i), got field value %i",
				   IPPROTO_UDP, ip->ip_p);
		return NULL;
	}

	/*
	 *	End of variable length bits, do basic check now to see if packet looks long enough
	 */
	len = (p - data) + UDP_HDR_SIZE;	/* length value */
	if ((size_t) len > header->caplen) {
		fr_strerror_printf("Payload (%zu) smaller than required for layers 2+3+4", len);
		return NULL;
	}

	/*
	 *	UDP header validation.
	 */
	ret = fr_udp_header_check(p, (header->caplen - (p - data)), ip);
	if (ret < 0) return NULL;

	udp = (udp_header_t const *)p;
	p += sizeof(udp_header_t);

	data_len = ntohs(udp->len);

	dst_port = ntohs(udp->dst);
	src_port = ntohs(udp->src);

	src_ipaddr.af = AF_INET;
	src_ipaddr.addr.v4 = ip->ip_src;
	src_ipaddr.prefix = 32;
	src_ipaddr.scope_id = 0;
	dst_ipaddr.af = AF_INET;
	dst_ipaddr.addr.v4 = ip->ip_dst;
	dst_ipaddr.prefix = 32;
	dst_ipaddr.scope_id = 0;

	if (!fr_dhcpv4_ok(p, data_len, NULL, NULL)) return NULL;

	packet = fr_dhcpv4_packet_alloc(p, data_len);
	if (!packet) return NULL;

	packet->dst_port = dst_port;
	packet->src_port = src_port;

	packet->src_ipaddr = src_ipaddr;
	packet->dst_ipaddr = dst_ipaddr;

	packet->data = talloc_memdup(packet, p, packet->data_len);
	packet->timestamp = fr_time_from_timeval(&header->ts);
	packet->if_index = pcap->if_index;
	return packet;
}
#endif	/* HAVE_LIBPCAP */
