/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2 if the
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

/**
 * $Id$
 * @file net.c
 * @brief Functions to parse raw packets.
 *
 * @author Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2014 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
 #include <freeradius-devel/libradius.h>
 #include <freeradius-devel/net.h>

/** Returns the length of the link layer header
 *
 * Libpcap does not include a decoding function to skip the L2 header, but it does
 * at least inform us of the type.
 *
 * Unfortunately some headers are of variable length (like ethernet), so additional
 * decoding logic is required.
 *
 * @note No header data is returned, this is only meant to be used to determine how
 * data to consume before attempting to parse the IP header.
 *
 * @param data start of packet data.
 * @param len caplen.
 * @param link_type value returned from pcap_linktype.
 * @return the length of the header, or -1 on error.
 */
ssize_t fr_link_layer_offset(uint8_t const *data, size_t len, int link_type)
{
	uint8_t const *p = data;

	switch (link_type) {
	case DLT_RAW:
		break;

	case DLT_NULL:
	case DLT_LOOP:
		p += 4;
		if (((size_t)(p - data)) > len) {
			goto ood;
		}
		break;

	case DLT_EN10MB:
	{
		uint16_t ether_type;	/* Ethernet type */
		int i;

		p += 12;		/* SRC/DST Mac-Addresses */
		if (((size_t)(p - data)) > len) {
			goto ood;
		}

		for (i = 0; i < 3; i++) {
			ether_type = ntohs(*((uint16_t const *) p));
			switch (ether_type) {
			/*
			 *	There are a number of devices out there which
			 *	double tag with 0x8100 *sigh*
			 */
			case 0x8100:	/* CVLAN */
			case 0x9100:	/* SVLAN */
			case 0x9200:	/* SVLAN */
			case 0x9300:	/* SVLAN */
				p += 4;
				if (((size_t)(p - data)) > len) {
					goto ood;
				}
				break;

			default:
				p += 2;
				if (((size_t)(p - data)) > len) {
					goto ood;
				}
				goto done;
			}
		}
		fr_strerror_printf("Exceeded maximum level of VLAN tag nesting (2)");
		return -1;
	}

	case DLT_LINUX_SLL:
		p += 16;
		if (((size_t)(p - data)) > len) {
			goto ood;
		}
		break;

	case DLT_PFLOG:
		p += 28;
		if (((size_t)(p - data)) > len) {
			goto ood;
		}
		break;

	default:
		fr_strerror_printf("Unsupported link layer type %i", link_type);
	}

	done:
	return p - data;

	ood:
	fr_strerror_printf("Out of data, needed %zu bytes, have %zu bytes", (size_t)(p - data), len);

	return -1;
}

/** Calculate UDP checksum
 *
 * Zero out UDP checksum in UDP header before calling fr_udp_checksum to get 'expected' checksum.
 *
 * @param data Pointer to the start of the UDP header
 * @param len value of udp length field in host byte order. Must be validated to make
 *	  sure it won't overrun data buffer.
 * @param checksum current checksum, leave as 0 to just enable validation.
 * @param src_addr in network byte order.
 * @param dst_addr in network byte order.
 * @return 0 if the checksum is correct, else another number.
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

	for (i = len; i > 1; i -= 2) {
		sum += *p++;
	}

	if (i) {
		sum += (0xff & *(uint8_t const *)p) << 8;
	}

	sum -= checksum;

	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	return ((uint16_t) ~sum);
}
