/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2 of the
 *   License as published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** Functions for parsing raw network packets
 *
 * @file src/lib/util/net.c
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2014-2015 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
#include <freeradius-devel/util/net.h>

/** Strings for L4 protocols
 *
 */
fr_table_num_sorted_t const fr_net_ip_proto_table[] = {
	{ "TCP",	IPPROTO_TCP },
	{ "UDP",	IPPROTO_UDP }
};
size_t fr_net_ip_proto_table_len = NUM_ELEMENTS(fr_net_ip_proto_table);

/** Strings for socket types
 *
 */
fr_table_num_sorted_t const fr_net_sock_type_table[] = {
	{ "TCP",	SOCK_STREAM	},
	{ "UDP",	SOCK_DGRAM	}
};
size_t fr_net_sock_type_table_len = NUM_ELEMENTS(fr_net_sock_type_table);

/** Strings for address families
 *
 */
fr_table_num_sorted_t const fr_net_af_table[] = {
	{ "IPv4",	AF_INET		},
	{ "IPv6",	AF_INET6	}
};
size_t fr_net_af_table_len = NUM_ELEMENTS(fr_net_af_table);

/** Check UDP header is valid
 *
 * @param data Pointer to the start of the UDP header
 * @param remaining bits of received packet
 * @param ip pointer to IP header structure
 * @return
 *	- 1 if checksum is incorrect.
 *	- 0 if UDP payload length and checksum are correct
 *	- -1 on validation error.
 */
 int fr_udp_header_check(uint8_t const *data, uint16_t remaining, ip_header_t const * ip)
 {
	int ret = 0;
	udp_header_t const	*udp;

	/*
	 *	UDP header validation.
	 */
	udp = (udp_header_t const *)data;
	uint16_t udp_len;
	ssize_t diff;
	uint16_t expected;

	udp_len = ntohs(udp->len);
	diff = udp_len - remaining;
	/* Truncated data */
	if (diff > 0) {
		fr_strerror_printf("packet too small by %zi bytes, UDP header + Payload should be %hu bytes",
				   diff, udp_len);
		return -1;
	}
	/* Trailing data */
	else if (diff < 0) {
		fr_strerror_printf("Packet too big by %zi bytes, UDP header + Payload should be %hu bytes",
				   diff * -1, udp_len);
		return -1;
	}

	expected = fr_udp_checksum((uint8_t const *) udp, ntohs(udp->len), udp->checksum,
				   ip->ip_src, ip->ip_dst);
	if (udp->checksum != expected) {
		fr_strerror_printf("UDP checksum invalid, packet: 0x%04hx calculated: 0x%04hx",
				   ntohs(udp->checksum), ntohs(expected));
		/* Not a fatal error */
		ret = 1;
	}

	return ret;
 }

/** Calculate UDP checksum
 *
 * Zero out UDP checksum in UDP header before calling #fr_udp_checksum to get 'expected' checksum.
 *
 * @param data Pointer to the start of the UDP header
 * @param len value of udp length field in host byte order. Must be validated to make
 *	  sure it won't overrun data buffer.
 * @param checksum current checksum, leave as 0 to just enable validation.
 * @param src_addr in network byte order.
 * @param dst_addr in network byte order.
 * @return
 *	- 0 if the checksum is correct.
 *	- !0 if checksum is incorrect.
 */
uint16_t fr_udp_checksum(uint8_t const *data, uint16_t len, uint16_t checksum,
			 struct in_addr const src_addr, struct in_addr const dst_addr)
{
	uint64_t sum = 0;	/* using 64bits avoids overflow check */
	uint16_t const *p = (uint16_t const *)data;

	uint16_t const *ip_src = (void const *) &src_addr.s_addr;
	uint16_t const *ip_dst = (void const *) &dst_addr.s_addr;
	uint16_t i;

	sum += *(ip_src++);
	sum += *ip_src;
	sum += *(ip_dst++);
	sum += *ip_dst;

	sum += htons(IPPROTO_UDP);
	sum += htons(len);

	for (i = len; i > 1; i -= 2) sum += *p++;
	if (i) sum += (0xff & *(uint8_t const *)p) << 8;

	sum -= checksum;

	while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);

	return ((uint16_t) ~sum);
}

/** Calculate IP header checksum.
 *
 * Zero out IP header checksum in IP header before calling fr_ip_header_checksum to get 'expected' checksum.
 *
 * @param data Pointer to the start of the IP header
 * @param ihl value of ip header length field (number of 32 bit words)
 */
uint16_t fr_ip_header_checksum(uint8_t const *data, uint8_t ihl)
{
	uint64_t sum = 0;
	uint16_t const *p = (uint16_t const *)data;

	uint8_t nwords = (ihl << 1); /* number of 16-bit words */

	for (sum = 0; nwords > 0; nwords--) {
		sum += *p++;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ((uint16_t) ~sum);
}

uint16_t fr_ip6_pesudo_header_checksum(struct in6_addr *src, struct in6_addr *dst, uint16_t ip_len, uint8_t ip_next)
{
	uint64_t sum = 0;
	ip_pseudo_header6_t ip6; /* Keep correct alignment for the pointer */
	uint8_t const *p = (uint8_t const *) &ip6;
	int8_t nwords = sizeof(ip6) >> 1; /* number of 16-bit words */

	memcpy(&ip6.ip_src, src, sizeof(ip6.ip_src));
	memcpy(&ip6.ip_dst, dst, sizeof(ip6.ip_dst));
	ip6.ip_len = ip_len;
	ip6.ip_next = ip_next;

	for (sum = 0; nwords > 0; nwords--) {
	        uint16_t word;
	        memcpy(&word, p, sizeof(word)); /* Can't use a uint16_t * as GCC flags this for unaligned access */
	        sum += word;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ((uint16_t) ~sum);
}
