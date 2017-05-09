/*
 * dhcp.c	Functions to send/receive dhcp packets.
 *
 * Version:	$Id$
 *
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
 *
 * Copyright 2008 The FreeRADIUS server project
 * Copyright 2008 Alan DeKok <aland@deployingradius.com>
 */

RCSID("$Id$")

#include <freeradius-devel/libradius.h>
#include <freeradius-devel/udpfromto.h>
#include <freeradius-devel/dhcp.h>
#include <freeradius-devel/net.h>
#include <freeradius-devel/pcap.h>

#ifndef __MINGW32__
#  include <sys/ioctl.h>
#endif

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

#ifndef __MINGW32__
#  include <net/if_arp.h>
#endif

#define DHCP_CHADDR_LEN	(16)
#define DHCP_SNAME_LEN	(64)
#define DHCP_FILE_LEN	(128)
#define DHCP_VEND_LEN	(308)
#define DHCP_OPTION_MAGIC_NUMBER (0x63825363)

#ifndef INADDR_BROADCAST
#  define INADDR_BROADCAST INADDR_NONE
#endif

static fr_dict_attr_t const *dhcp_option_82;

/* @todo: this is a hack */
#  define DEBUG			if (fr_debug_lvl && fr_log_fp) fr_printf_log

#if defined(HAVE_PCAP_H) || defined(HAVE_LINUX_IF_PACKET_H)
#  define ETH_TYPE_IP    0x0800
#  define IP_HDR_SIZE    20
#  define UDP_HDR_SIZE   8
#  define ETH_ADDR_LEN   6
#endif

#ifdef HAVE_LINUX_IF_PACKET_H
#  define ETH_HDR_SIZE   14
static uint8_t eth_bcast[ETH_ADDR_LEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

/* Discard raw packets which we are not interested in. Allow to trace why we discard. */
#  define DISCARD_RP(...) { \
	if (fr_debug_lvl > 2) { \
		fprintf(stdout, "dhcpclient: discarding received packet: "); \
		fprintf(stdout, ## __VA_ARGS__); \
		fprintf(stdout, "\n"); \
	} \
	fr_radius_free(&packet); \
	return NULL; \
}
#endif

static RADIUS_PACKET *fr_dhcp_packet_ok(uint8_t const *data, ssize_t data_len, fr_ipaddr_t src_ipaddr,
					uint16_t src_port, fr_ipaddr_t dst_ipaddr, uint16_t dst_port);

typedef struct dhcp_packet_t {
	uint8_t		opcode;
	uint8_t		htype;
	uint8_t		hlen;
	uint8_t		hops;
	uint32_t	xid;	/* 4 */
	uint16_t	secs;	/* 8 */
	uint16_t	flags;
	uint32_t	ciaddr;	/* 12 */
	uint32_t	yiaddr;	/* 16 */
	uint32_t	siaddr;	/* 20 */
	uint32_t	giaddr;	/* 24 */
	uint8_t		chaddr[DHCP_CHADDR_LEN]; /* 28 */
	uint8_t		sname[DHCP_SNAME_LEN]; /* 44 */
	uint8_t		file[DHCP_FILE_LEN]; /* 108 */
	uint32_t	option_format; /* 236 */
	uint8_t		options[DHCP_VEND_LEN];
} dhcp_packet_t;

typedef struct dhcp_option_t {
	uint8_t		code;
	uint8_t		length;
} dhcp_option_t;

/*
 *	INADDR_ANY : 68 -> INADDR_BROADCAST : 67	DISCOVER
 *	INADDR_BROADCAST : 68 <- SERVER_IP : 67		OFFER
 *	INADDR_ANY : 68 -> INADDR_BROADCAST : 67	REQUEST
 *	INADDR_BROADCAST : 68 <- SERVER_IP : 67		ACK
 */
char const *dhcp_header_names[] = {
	"DHCP-Opcode",
	"DHCP-Hardware-Type",
	"DHCP-Hardware-Address-Length",
	"DHCP-Hop-Count",
	"DHCP-Transaction-Id",
	"DHCP-Number-of-Seconds",
	"DHCP-Flags",
	"DHCP-Client-IP-Address",
	"DHCP-Your-IP-Address",
	"DHCP-Server-IP-Address",
	"DHCP-Gateway-IP-Address",
	"DHCP-Client-Hardware-Address",
	"DHCP-Server-Host-Name",
	"DHCP-Boot-Filename",

	NULL
};

char const *dhcp_message_types[] = {
	"invalid",
	"DHCP-Discover",
	"DHCP-Offer",
	"DHCP-Request",
	"DHCP-Decline",
	"DHCP-Ack",
	"DHCP-NAK",
	"DHCP-Release",
	"DHCP-Inform",
	"DHCP-Force-Renew",
	"DHCP-Lease-Query",
	"DHCP-Lease-Unassigned",
	"DHCP-Lease-Unknown",
	"DHCP-Lease-Active",
	"DHCP-Bulk-Lease-Query",
	"DHCP-Lease-Query-Done"
};

#define DHCP_MAX_MESSAGE_TYPE (sizeof(dhcp_message_types) / sizeof(dhcp_message_types[0]))

static int dhcp_header_sizes[] = {
	1, 1, 1, 1,
	4, 2, 2, 4,
	4, 4, 4,
	DHCP_CHADDR_LEN,
	DHCP_SNAME_LEN,
	DHCP_FILE_LEN
};


/*
 *	Some clients silently ignore responses less than 300 bytes.
 */
#define MIN_PACKET_SIZE		(244)
#define DEFAULT_PACKET_SIZE	(300)
#define MAX_PACKET_SIZE		(1500 - 40)

#define DHCP_OPTION_FIELD	(0)
#define DHCP_FILE_FIELD	  	(1)
#define DHCP_SNAME_FIELD  	(2)

static uint8_t const *dhcp_get_option(dhcp_packet_t const *packet, size_t packet_size, unsigned int option)
{
	int overload = 0;
	int field = DHCP_OPTION_FIELD;
	size_t where, size;
	uint8_t const *data;

	where = 0;
	size = packet_size - offsetof(dhcp_packet_t, options);
	data = &packet->options[where];

	while (where < size) {
		if (data[0] == 0) { /* padding */
			where++;
			continue;
		}

		if (data[0] == 255) { /* end of options */
			if ((field == DHCP_OPTION_FIELD) &&
			    (overload & DHCP_FILE_FIELD)) {
				data = packet->file;
				where = 0;
				size = sizeof(packet->file);
				field = DHCP_FILE_FIELD;
				continue;

			} else if ((field == DHCP_FILE_FIELD) &&
				   (overload & DHCP_SNAME_FIELD)) {
				data = packet->sname;
				where = 0;
				size = sizeof(packet->sname);
				field = DHCP_SNAME_FIELD;
				continue;
			}

			return NULL;
		}

		/*
		 *	We MUST have a real option here.
		 */
		if ((where + 2) > size) {
			fr_strerror_printf("Options overflow field at %u",
					   (unsigned int) (data - (uint8_t const *) packet));
			return NULL;
		}

		if ((where + 2 + data[1]) > size) {
			fr_strerror_printf("Option length overflows field at %u",
					   (unsigned int) (data - (uint8_t const *) packet));
			return NULL;
		}

		if (data[0] == option) return data;

		if (data[0] == 52) { /* overload sname and/or file */
			overload = data[3];
		}

		where += data[1] + 2;
		data += data[1] + 2;
	}

	return NULL;
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

/** Check reveived DHCP request is valid and build RADIUS_PACKET structure if it is
 *
 * @param data pointer to received packet.
 * @param data_len length of received data.
 * @param src_ipaddr source ip address.
 * @param src_port source port address.
 * @param dst_ipaddr destination ip address.
 * @param dst_port destination port address.
 *
 * @return
 *	- RADIUS_PACKET pointer if valid
 *	- NULL if invalid
 */
RADIUS_PACKET *fr_dhcp_packet_ok(uint8_t const *data, ssize_t data_len, fr_ipaddr_t src_ipaddr,
				 uint16_t src_port, fr_ipaddr_t dst_ipaddr, uint16_t dst_port)
{
	uint32_t	magic;
	uint8_t const	*code;
	int		pkt_id;
	RADIUS_PACKET	*packet;

	if (data_len < MIN_PACKET_SIZE) {
		fr_strerror_printf("DHCP packet is too small (%zu < %d)", data_len, MIN_PACKET_SIZE);
		return NULL;
	}

	if (data_len > MAX_PACKET_SIZE) {
		fr_strerror_printf("DHCP packet is too large (%zx > %d)", data_len, MAX_PACKET_SIZE);
		return NULL;
	}

	if (data[1] > 1) {
		fr_strerror_printf("DHCP can only process ethernet requests, not type %02x", data[1]);
		return NULL;
	}

	if ((data[2] != 0) && (data[2] != 6)) {
		fr_strerror_printf("Ethernet HW length incorrect.  Expected 6 got %d", data[2]);
		return NULL;
	}

	memcpy(&magic, data + 236, 4);
	magic = ntohl(magic);
	if (magic != DHCP_OPTION_MAGIC_NUMBER) {
		fr_strerror_printf("BOOTP not supported");
		return NULL;
	}

	/*
	 *	Create unique keys for the packet.
	 */
	memcpy(&magic, data + 4, 4);
	pkt_id = ntohl(magic);

	code = dhcp_get_option((dhcp_packet_t const *) data, data_len, PW_DHCP_MESSAGE_TYPE);
	if (!code) {
		fr_strerror_printf("No message-type option was found in the packet");
		return NULL;
	}

	if ((code[1] < 1) || (code[2] == 0) || (code[2] >= DHCP_MAX_MESSAGE_TYPE)) {
		fr_strerror_printf("Unknown value %d for message-type option", code[2]);
		return NULL;
	}

	/* Now that checks are done, allocate packet */
	packet = fr_radius_alloc(NULL, false);
	if (!packet) {
		fr_strerror_printf("Failed allocating packet");
		return NULL;
	}

	packet->data_len = data_len;
	packet->code = code[2] | PW_DHCP_OFFSET;
	packet->id = pkt_id;

	packet->dst_port = dst_port;
	packet->src_port = src_port;

	packet->src_ipaddr = src_ipaddr;
	packet->dst_ipaddr = dst_ipaddr;

	/*
	 *	Create a unique vector from the MAC address and the
	 *	DHCP opcode.  This is a hack for the RADIUS
	 *	infrastructure in the rest of the server.
	 *
	 *	Note: data[2] == 6, which is smaller than
	 *	sizeof(packet->vector)
	 *
	 *	FIXME:  Look for client-identifier in packet,
	 *      and use that, too?
	 */
	memset(packet->vector, 0, sizeof(packet->vector));
	memcpy(packet->vector, data + 28, data[2]);
	packet->vector[data[2]] = packet->code & 0xff;

	/*
	 *	FIXME: for DISCOVER / REQUEST: src_port == dst_port + 1
	 *	FIXME: for OFFER / ACK       : src_port = dst_port - 1
	 */

	/*
	 *	Unique keys are xid, client mac, and client ID?
	 */
	return packet;
}

#ifdef HAVE_PCAP_H
/** Receive DHCP packet using PCAP
 *
 * @param pcap handle
 * @return
 *	- pointer to RADIUS_PACKET if successful.
 *	- NULL if failed.
 */
RADIUS_PACKET *fr_dhcp_recv_pcap(fr_pcap_t *pcap)
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
		DEBUG("DHCP: No packet received");
		return NULL; /* no packet */
	}
	if (ret < 0) {
		fr_strerror_printf("Error requesting next packet, got (%i): %s", ret, pcap_geterr(pcap->handle));
		return NULL;
	}

	link_len = fr_link_layer_offset(data, header->caplen, pcap->link_layer);
	if (link_len < 0) {
		fr_strerror_printf("Failed determining link layer header offset: %s", fr_strerror());
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
		DEBUG("DHCP: IPv6 not supported");
		return NULL;

	default:
		DEBUG("DHCP: IP version invalid %i", version);
		return NULL;
	}

	/* Check IPv4 layer data (L3) */
	if (ip->ip_p != IPPROTO_UDP) {
		DEBUG("DHCP: IP protocol (%d) != UDP", ip->ip_p);
		return NULL;
	}

	/*
	 *	End of variable length bits, do basic check now to see if packet looks long enough
	 */
	len = (p - data) + UDP_HDR_SIZE;	/* length value */
	if ((size_t) len > header->caplen) {
		DEBUG("DHCP: Payload (%d) smaller than required for layers 2+3+4", (int)len);
		return NULL;
	}

	/*
	 *	UDP header validation.
	 */
	ret = fr_udp_header_check(p, (header->caplen - (p - data)), ip);
	if (ret < 0) {
		DEBUG("DHCP: %s", fr_strerror());
		return NULL;
	} else if (ret > 0) {
		/* Not a fatal error */
		DEBUG("DHCP: %s", fr_strerror());
	}

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

	packet = fr_dhcp_packet_ok(p, data_len, src_ipaddr, src_port, dst_ipaddr, dst_port);
	if (packet) {
		packet->data = talloc_memdup(packet, p, packet->data_len);
		packet->timestamp = header->ts;
		packet->if_index = pcap->if_index;
		return packet;
	}

	return NULL;
}
#endif	/* HAVE_PCAP_H */

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

#ifdef HAVE_PCAP_H
/** Send DHCP packet using PCAP
 *
 * @param pcap handle
 * @param dst_ether_addr MAC address to send packet to
 * @param packet to send
 * @return
 *	- -1 on failure.
 *	- 0 on success.
 */
int fr_dhcp_send_pcap(fr_pcap_t *pcap, uint8_t *dst_ether_addr, RADIUS_PACKET *packet)
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
	memcpy(eth_hdr->ether_dst, dst_ether_addr, ETH_ADDR_LEN);
	memcpy(eth_hdr->ether_src, pcap->ether_addr, ETH_ADDR_LEN);
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
		fr_strerror_printf("DHCP: Error sending packet with pcap: %d, %s", ret, pcap_geterr(pcap->handle));
		return -1;
	}

	return 0;
}
#endif	/* HAVE_PCAP_H */

static ssize_t decode_tlv(TALLOC_CTX *ctx, vp_cursor_t *cursor, fr_dict_attr_t const *parent,
			  uint8_t const *data, size_t data_len);

static ssize_t decode_value(TALLOC_CTX *ctx, vp_cursor_t *cursor,
			    fr_dict_attr_t const *parent, uint8_t const *data, size_t data_len);

/** Returns the number of array members for arrays with fixed element sizes
 *
 */
static int fr_dhcp_array_members(size_t *out, size_t len, fr_dict_attr_t const *da)
{
	int num_entries = 1;

	*out = len;

	/*
	 *	Could be an array of bytes, integers, etc.
	 */
	if (da->flags.array) switch (da->type) {
	case PW_TYPE_BYTE:
		num_entries = len;
		*out = 1;
		break;

	case PW_TYPE_SHORT: /* ignore any trailing data */
		num_entries = len >> 1;
		*out = 2;
		break;

	case PW_TYPE_IPV4_ADDR:
	case PW_TYPE_INTEGER:
	case PW_TYPE_DATE: /* ignore any trailing data */
		num_entries = len >> 2;
		*out = 4;
		break;

	case PW_TYPE_IPV6_ADDR:
		num_entries = len >> 4;
		*out = 16;
		break;

	default:
		break;
	}

	return num_entries;
}

/*
 *	Decode ONE value into a VP
 */
static ssize_t decode_value_internal(TALLOC_CTX *ctx, vp_cursor_t *cursor, fr_dict_attr_t const *da,
				     uint8_t const *data, size_t data_len)
{
	VALUE_PAIR *vp;
	uint8_t const *p = data;

	FR_PROTO_TRACE("%s called to parse %zu bytes", __FUNCTION__, data_len);
	FR_PROTO_HEX_DUMP(NULL, data, data_len);

	vp = fr_pair_afrom_da(ctx, da);
	if (!vp) return -1;

	/*
	 *	Unknown attributes always get converted to
	 *	octet types, so there's no way there could
	 *	be multiple attributes, so its safe to
	 *	steal the unknown attribute into the context
	 *	of the pair.
	 */
	if (da->flags.is_unknown) talloc_steal(vp, da);

	switch (da->type) {
	case PW_TYPE_BYTE:
		if (data_len != 1) goto raw;
		vp->vp_byte = p[0];
		p++;
		break;

	case PW_TYPE_SHORT:
		if (data_len != 2) goto raw;
		memcpy(&vp->vp_short, p, 2);
		vp->vp_short = ntohs(vp->vp_short);
		p += 2;
		break;

	case PW_TYPE_INTEGER:
		if (data_len != 4) goto raw;
		memcpy(&vp->vp_integer, p, 4);
		vp->vp_integer = ntohl(vp->vp_integer);
		p += 4;
		break;

	case PW_TYPE_IPV4_ADDR:
		if (data_len != 4) goto raw;
		/*
		 *	Keep value in Network Order!
		 */
		vp->vp_ip.af = AF_INET;
		vp->vp_ip.prefix = 32;
		vp->vp_ip.scope_id = 0;
		memcpy(&vp->vp_ipv4addr, p, 4);
		p += 4;
		break;

	case PW_TYPE_IPV6_ADDR:
		if (data_len != 16) goto raw;
		/*
		 *	Keep value in Network Order!
		 */
		vp->vp_ip.af = AF_INET6;
		vp->vp_ip.prefix = 128;
		vp->vp_ip.scope_id = 0;
		memcpy(&vp->vp_ipv6addr, p, 16);
		p += 16;
		break;

	/*
	 *	In DHCPv4, string options which can also be arrays,
	 *	have their values '\0' delimited.
	 */
	case PW_TYPE_STRING:
	{
		uint8_t const *q, *end;

		q = end = data + data_len;

		/*
		 *	Not allowed to be an array, copy the whole value
		 */
		if (!vp->da->flags.array) {
			fr_pair_value_bstrncpy(vp, (char const *)p, end - p);
			p = end;
			break;
		}

		for (;;) {
			q = memchr(p, '\0', q - p);

			/* Malformed but recoverable */
			if (!q) q = end;

			fr_pair_value_bstrncpy(vp, (char const *)p, q - p);
			p = q + 1;

			/* Need another VP for the next round */
			if (p < end) {
				fr_pair_cursor_append(cursor, vp);

				vp = fr_pair_afrom_da(ctx, da);
				if (!vp) return -1;
				continue;
			}
			break;
		}
	}
		break;

	case PW_TYPE_ETHERNET:
		memcpy(vp->vp_ether, data, sizeof(vp->vp_ether));
		p += sizeof(vp->vp_ether);
		break;

	/*
	 *	Value doesn't match up with attribute type, overwrite the
	 *	vp's original fr_dict_attr_t with an unknown one.
	 */
	raw:
		FR_PROTO_TRACE("decoding as unknown type");
		if (fr_pair_to_unknown(vp) < 0) return -1;

	case PW_TYPE_OCTETS:
		if (data_len > UINT8_MAX) return -1;
		fr_pair_value_memcpy(vp, data, data_len);
		p += data_len;
		break;

	default:
		fr_strerror_printf("Internal sanity check %d %d", vp->vp_type, __LINE__);
		talloc_free(vp);
		return -1;
	} /* switch over type */

	FR_PROTO_TRACE("decoding value complete, adding new pair and returning %zu byte(s)", p - data);
	vp->vp_tainted = true;
	fr_pair_cursor_append(cursor, vp);

	return p - data;
}


/** RFC 4243 Vendor Specific Suboptions
 *
 * Vendor specific suboptions are in the format.
 @verbatim
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                     Enterprise Number 0                       |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |    Len 0      |                                               /
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     /                      Suboption Data 0                         /
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                     Enterprise Number n                       |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |    Len n      |                                               /
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     /                      Suboption Data n                         /
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 @endverbatim
 *
 * So although the vendor is identified, the format of the data isn't
 * specified so we can't actually resolve the suboption to an
 * attribute.  For now, we just convert it to an attribute of
 * DHCP-Vendor-Specific-Information with raw octets contents.
 */

/** Decode DHCP suboptions
 *
 * @param[in] ctx context to alloc new attributes in.
 * @param[in,out] cursor Where to write the decoded options.
 * @param[in] parent of sub TLVs.
 * @param[in] data to parse.
 * @param[in] data_len of data parsed.
 */
static ssize_t decode_tlv(TALLOC_CTX *ctx, vp_cursor_t *cursor, fr_dict_attr_t const *parent,
			  uint8_t const *data, size_t data_len)
{
	uint8_t const		*p = data;
	uint8_t const		*end = data + data_len;
	fr_dict_attr_t const	*child;

	if (data_len < 3) return -1; /* type, length, value */

	FR_PROTO_TRACE("%s called to parse %zu byte(s)", __FUNCTION__, data_len);
	FR_PROTO_HEX_DUMP(NULL, data, data_len);

	/*
	 *	Each TLV may contain multiple children
	 */
	while (p < end) {
		ssize_t tlv_len;

		if (p[0] == 0) {
			p++;
			continue;
		}

		/*
		 *	RFC 3046 is very specific about not allowing termination
		 *	with a 255 sub-option. But it's required for decoding
		 *	option 43, and vendors will probably screw it up
		 *	anyway.
		 */
		if (p[0] == 255) {
			p++;
			return p - data;
		}

		/*
		 *	Everything else should be real options
		 */
		if ((end - p) < 2) {
			fr_strerror_printf("%s: Insufficient data: Needed at least 2 bytes, got %zu",
					   __FUNCTION__, (end - p));
			return -1;
		}

		if (p[1] > (end - p)) {
			fr_strerror_printf("%s: Suboption would overflow option.  Remaining option data %zu byte(s) "
					   "(from %zu), Suboption length %u", __FUNCTION__, (end - p), data_len, p[1]);
			return -1;
		}

		child = fr_dict_attr_child_by_num(parent, p[0]);
		if (!child) {
			fr_dict_attr_t const *unknown_child;

			FR_PROTO_TRACE("failed to find child %u of TLV %s", p[0], parent->name);

			/*
			 *	Build an unknown attr
			 */
			unknown_child = fr_dict_unknown_afrom_fields(ctx, parent, parent->vendor, p[0]);
			if (!unknown_child) return -1;
			child = unknown_child;
		}
		FR_PROTO_TRACE("decode context changed %s:%s -> %s:%s",
			       fr_int2str(dict_attr_types, parent->type, "<invalid>"), parent->name,
			       fr_int2str(dict_attr_types, child->type, "<invalid>"), child->name);

		tlv_len = decode_value(ctx, cursor, child, p + 2, p[1]);
		if (tlv_len <= 0) {
			fr_dict_unknown_free(&child);
			return tlv_len;
		}
		p += tlv_len + 2;
		FR_PROTO_TRACE("decode_value returned %zu, adding 2 (for header)", tlv_len);
		FR_PROTO_TRACE("remaining TLV data %zu byte(s)" , end - p);
	}
	FR_PROTO_TRACE("tlv parsing complete, returning %zu byte(s)", p - data);

	return p - data;
}

static ssize_t decode_value(TALLOC_CTX *ctx, vp_cursor_t *cursor,
			    fr_dict_attr_t const *parent, uint8_t const *data, size_t data_len)
{
	unsigned int	values, i;		/* How many values we need to decode */
	uint8_t const	*p = data;
	size_t		value_len;
	ssize_t		len;

	FR_PROTO_TRACE("%s called to parse %zu byte(s)", __FUNCTION__, data_len);
	FR_PROTO_HEX_DUMP(NULL, data, data_len);

	/*
	 *	TLVs can't be coalesced as they're variable length
	 */
	if (parent->type == PW_TYPE_TLV) return decode_tlv(ctx, cursor, parent, data, data_len);

	/*
	 *	Values with a fixed length may be coalesced into a single option
	 */
	values = fr_dhcp_array_members(&value_len, data_len, parent);
	if (values) {
		FR_PROTO_TRACE("found %u coalesced values (%zu bytes each)", values, value_len);

		if ((values * value_len) != data_len) {
			fr_strerror_printf("Option length not divisible by its fixed value "
					  "length (probably trailing garbage)");
			return -1;
		}
	}

	/*
	 *	Decode each of the (maybe) coalesced values as its own
	 *	attribute.
	 */
	for (i = 0, p = data; i < values; i++) {
		len = decode_value_internal(ctx, cursor, parent, p, value_len);
		if (len <= 0) return len;
		if (len != (ssize_t)value_len) {
			fr_strerror_printf("Failed decoding complete option value");
			return -1;
		}
		p += len;
	}

	return p - data;
}

/** Decode DHCP option
 *
 * @param[in] ctx context to alloc new attributes in.
 * @param[in,out] cursor Where to write the decoded options.
 * @param[in] parent The root of the protocol dictionary used to decode DHCP attributes.
 * @param[in] data to parse.
 * @param[in] data_len of data to parse.
 * @param[in] decoder_ctx Unused.
 */
ssize_t fr_dhcp_decode_option(TALLOC_CTX *ctx, vp_cursor_t *cursor,
			      fr_dict_attr_t const *parent, uint8_t const *data, size_t data_len,
			      UNUSED void *decoder_ctx)
{
	ssize_t			ret;
	uint8_t const		*p = data;
	fr_dict_attr_t const	*child;

	FR_PROTO_TRACE("%s called to parse %zu byte(s)", __FUNCTION__, data_len);

	if (data_len == 0) return 0;

	FR_PROTO_HEX_DUMP(NULL, data, data_len);

	/*
	 *	Stupid hacks until we have protocol specific dictionaries
	 */
	parent = fr_dict_attr_child_by_num(parent, PW_VENDOR_SPECIFIC);
	if (!parent) {
		fr_strerror_printf("Can't find Vendor-Specific (26)");
		return -1;
	}

	parent = fr_dict_attr_child_by_num(parent, DHCP_MAGIC_VENDOR);
	if (!parent) {
		fr_strerror_printf("Can't find DHCP vendor");
		return -1;
	}

	/*
	 *	Padding / End of options
	 */
	if (p[0] == 0) return 1;		/* 0x00 - Padding option */
	if (p[0] == 255) {			/* 0xff - End of options signifier */
		size_t i;

		for (i = 1; i < data_len; i++) {
			if (p[i] != 0) {
				FR_PROTO_HEX_DUMP("ignoring trailing junk at end of packet", p + i, data_len - i);
				break;
			}
		}
		return data_len;
	}

	/*
	 *	Everything else should be real options
	 */
	if ((data_len < 2) || (data[1] > data_len)) {
		fr_strerror_printf("%s: Insufficient data", __FUNCTION__);
		return -1;
	}

	child = fr_dict_attr_child_by_num(parent, p[0]);
	if (!child) {
		/*
		 *	Unknown attribute, create an octets type
		 *	attribute with the contents of the sub-option.
		 */
		child = fr_dict_unknown_afrom_fields(ctx, parent, DHCP_MAGIC_VENDOR, p[0]);
		if (!child) return -1;
	}
	FR_PROTO_TRACE("decode context changed %s:%s -> %s:%s",
		       fr_int2str(dict_attr_types, parent->type, "<invalid>"), parent->name,
		       fr_int2str(dict_attr_types, child->type, "<invalid>"), child->name);

	ret = decode_value(ctx, cursor, child, data + 2, data[1]);
	if (ret < 0) {
		fr_dict_unknown_free(&child);
		return ret;
	}
	ret += 2; /* For header */
	FR_PROTO_TRACE("decoding option complete, returning %zu byte(s)", ret);
	return ret;
}

int fr_dhcp_decode(RADIUS_PACKET *packet)
{
	size_t i;
	uint8_t *p;
	uint32_t giaddr;
	vp_cursor_t cursor;
	VALUE_PAIR *head = NULL, *vp;
	VALUE_PAIR *maxms, *mtu;

	fr_pair_cursor_init(&cursor, &head);
	p = packet->data;

	if (packet->data[1] > 1) {
		fr_strerror_printf("Packet is not Ethernet: %u",
		      packet->data[1]);
		return -1;
	}

	/*
	 *	Decode the header.
	 */
	for (i = 0; i < 14; i++) {

		vp = fr_pair_make(packet, NULL, dhcp_header_names[i], NULL, T_OP_EQ);
		if (!vp) {
			char buffer[256];
			strlcpy(buffer, fr_strerror(), sizeof(buffer));
			fr_strerror_printf("Cannot decode packet due to internal error: %s", buffer);
			fr_pair_list_free(&head);
			return -1;
		}

		/*
		 *	If chaddr != 6 bytes it's probably not ethernet, and we should store
		 *	it as an opaque type (octets).
		 */
		if (i == 11) {
			/*
			 *	Skip chaddr if it doesn't exist.
			 */
			if ((packet->data[1] == 0) || (packet->data[2] == 0)) continue;

			if ((packet->data[1] == 1) && (packet->data[2] != sizeof(vp->vp_ether))) {
				fr_dict_attr_t const *da;

				da = fr_dict_unknown_afrom_fields(packet, fr_dict_root(fr_dict_internal),
								  vp->da->vendor, vp->da->attr);
				if (!da) {
					return -1;
				}
				vp->da = da;
			}
		}

		switch (vp->vp_type) {
		case PW_TYPE_BYTE:
			vp->vp_byte = p[0];
			break;

		case PW_TYPE_SHORT:
			vp->vp_short = (p[0] << 8) | p[1];
			break;

		case PW_TYPE_INTEGER:
			memcpy(&vp->vp_integer, p, 4);
			vp->vp_integer = ntohl(vp->vp_integer);
			break;

		case PW_TYPE_IPV4_ADDR:
			memcpy(&vp->vp_ipv4addr, p, 4);
			break;

		case PW_TYPE_STRING:
			/*
			 *	According to RFC 2131, these are null terminated strings.
			 *	We don't trust everyone to abide by the RFC, though.
			 */
			if (*p != '\0') {
				uint8_t *end;
				int len;
				end = memchr(p, '\0', dhcp_header_sizes[i]);
				len = end ? end - p : dhcp_header_sizes[i];
				fr_pair_value_bstrncpy(vp, p, len);
			}
			if (vp->vp_length == 0) fr_pair_list_free(&vp);
			break;

		case PW_TYPE_OCTETS:
			if (packet->data[2] == 0) break;

			fr_pair_value_memcpy(vp, p, packet->data[2]);
			break;

		case PW_TYPE_ETHERNET:
			memcpy(vp->vp_ether, p, sizeof(vp->vp_ether));
			break;

		default:
			fr_strerror_printf("BAD TYPE %d", vp->vp_type);
			fr_pair_list_free(&vp);
			break;
		}
		p += dhcp_header_sizes[i];

		if (!vp) continue;

		fr_pair_cursor_append(&cursor, vp);
	}

	/*
	 *	Loop over the options.
	 */

	/*
	 * 	Nothing uses tail after this call, if it does in the future
	 *	it'll need to find the new tail...
	 */
	{
		uint8_t const *end;
		ssize_t len;

		p = packet->data + 240;
		end = p + (packet->data_len - 240);

		/*
		 *	Loop over all the options data
		 */
		while (p < end) {
			len = fr_dhcp_decode_option(packet, &cursor, fr_dict_root(fr_dict_internal),
						    p, ((end - p) > UINT8_MAX) ? UINT8_MAX : (end - p), NULL);
			if (len <= 0) {
				fr_pair_list_free(&head);
				return len;
			}
			p += len;
		}
	}

	/*
	 *	If DHCP request, set ciaddr to zero.
	 */

	/*
	 *	Set broadcast flag for broken vendors, but only if
	 *	giaddr isn't set.
	 */
	memcpy(&giaddr, packet->data + 24, sizeof(giaddr));
	if (giaddr == htonl(INADDR_ANY)) {
		/*
		 *	DHCP Opcode is request
		 */
		vp = fr_pair_find_by_num(head, DHCP_MAGIC_VENDOR, 256, TAG_ANY);
		if (vp && vp->vp_integer == 3) {
			/*
			 *	Vendor is "MSFT 98"
			 */
			vp = fr_pair_find_by_num(head, DHCP_MAGIC_VENDOR, 63, TAG_ANY);
			if (vp && (strcmp(vp->vp_strvalue, "MSFT 98") == 0)) {
				vp = fr_pair_find_by_num(head, DHCP_MAGIC_VENDOR, 262, TAG_ANY);

				/*
				 *	Reply should be broadcast.
				 */
				if (vp) vp->vp_short |= 0x8000;
				packet->data[10] |= 0x80;
			}
		}
	}

	/*
	 *	FIXME: Nuke attributes that aren't used in the normal
	 *	header for discover/requests.
	 */
	packet->vps = head;

	/*
	 *	Client can request a LARGER size, but not a smaller
	 *	one.  They also cannot request a size larger than MTU.
	 */
	maxms = fr_pair_find_by_num(packet->vps, DHCP_MAGIC_VENDOR, 57, TAG_ANY);
	mtu = fr_pair_find_by_num(packet->vps, DHCP_MAGIC_VENDOR, 26, TAG_ANY);

	if (mtu && (mtu->vp_integer < DEFAULT_PACKET_SIZE)) {
		fr_strerror_printf("Client says MTU is smaller than minimum permitted by the specification");
		return -1;
	}

	/*
	 *	Client says maximum message size is smaller than minimum permitted
	 *	by the specification: fixing it.
	 */
	if (maxms && (maxms->vp_integer < DEFAULT_PACKET_SIZE)) maxms->vp_integer = DEFAULT_PACKET_SIZE;

	/*
	 *	Client says MTU is smaller than maximum message size: fixing it
	 */
	if (maxms && mtu && (maxms->vp_integer > mtu->vp_integer)) maxms->vp_integer = mtu->vp_integer;

	return 0;
}

int8_t fr_dhcp_attr_cmp(void const *a, void const *b)
{
	VALUE_PAIR const *my_a = a;
	VALUE_PAIR const *my_b = b;
	fr_dict_attr_t const *a_82, *b_82;

	VERIFY_VP(my_a);
	VERIFY_VP(my_b);

	/*
	 *	We can only use attribute numbers if we know they're
	 *	not nested attributes.
	 *
	 *	@fixme We should be able to use my_a->da->parent->flags.is_root,
	 *	but the DHCP attributes are hacked into the server under a vendor
	 *	dictionary, so we can't.
	 */

	/*
	 *	DHCP-Message-Type is first, for simplicity.
	 */
	if (((my_a->da->parent->type != PW_TYPE_TLV) && (my_a->da->attr == PW_DHCP_MESSAGE_TYPE)) &&
	    ((my_b->da->parent->type == PW_TYPE_TLV) || (my_b->da->attr != PW_DHCP_MESSAGE_TYPE))) return -1;
	if (((my_a->da->parent->type == PW_TYPE_TLV) || (my_a->da->attr != PW_DHCP_MESSAGE_TYPE)) &&
	    ((my_b->da->parent->type != PW_TYPE_TLV) && (my_b->da->attr == PW_DHCP_MESSAGE_TYPE))) return +1;

	/*
	 *	Relay-Agent is last.
	 *
	 *	Check if either of the options are descended from option 82.
	 */
	a_82 = fr_dict_parent_common(dhcp_option_82, my_a->da, true);
	b_82 = fr_dict_parent_common(dhcp_option_82, my_b->da, true);
	if (a_82 && !b_82) return +1;
	if (!a_82 && !b_82) return -1;

	return fr_pair_cmp_by_parent_num_tag(my_a, my_b);
}

/** Write DHCP option value into buffer
 *
 * Does not include DHCP option length or number.
 *
 * @param[in,out] out buffer to write the option to.
 * @param[out] outlen length of the output buffer.
 * @param[in] tlv_stack	Describing nesting of options.
 * @param[in] depth in tlv_stack.
 * @param[in,out] cursor Current attribute we're encoding.
 * @return
 *	- The length of data writen.
 *	- -1 if out of buffer.
 *	- -2 if unsupported type.
 */
static ssize_t encode_value(uint8_t *out, size_t outlen,
			    fr_dict_attr_t const **tlv_stack, unsigned int depth,
			    vp_cursor_t *cursor)
{
	uint32_t lvalue;

	VALUE_PAIR *vp = fr_pair_cursor_current(cursor);
	uint8_t *p = out;

	FR_PROTO_STACK_PRINT(tlv_stack, depth);
	FR_PROTO_TRACE("%zu byte(s) available for value", outlen);

	if (outlen < vp->vp_length) return 0;

	switch (tlv_stack[depth]->type) {
	case PW_TYPE_BYTE:
		p[0] = vp->vp_byte;
		p ++;
		break;

	case PW_TYPE_SHORT:
		p[0] = (vp->vp_short >> 8) & 0xff;
		p[1] = vp->vp_short & 0xff;
		p += 2;
		break;

	case PW_TYPE_INTEGER:
		lvalue = htonl(vp->vp_integer);
		memcpy(p, &lvalue, 4);
		p += 4;
		break;

	case PW_TYPE_IPV4_ADDR:
		memcpy(p, &vp->vp_ipv4addr, 4);
		p += 4;
		break;

	case PW_TYPE_IPV6_ADDR:
		memcpy(p, &vp->vp_ipv6addr, 16);
		p += 16;
		break;

	case PW_TYPE_ETHERNET:
		memcpy(p, vp->vp_ether, 6);
		p += 6;
		break;

	case PW_TYPE_STRING:
		memcpy(p, vp->vp_strvalue, vp->vp_length);
		p += vp->vp_length;
		break;

	case PW_TYPE_OCTETS:
		memcpy(p, vp->vp_octets, vp->vp_length);
		p += vp->vp_length;
		break;

	default:
		fr_strerror_printf("Unsupported option type %d", vp->vp_type);
		(void)fr_pair_cursor_next(cursor);
		return -2;
	}
	vp = fr_pair_cursor_next(cursor);	/* We encoded a leaf, advance the cursor */
	fr_proto_tlv_stack_build(tlv_stack, vp ? vp->da : NULL);

	FR_PROTO_STACK_PRINT(tlv_stack, depth);
	FR_PROTO_HEX_DUMP("Value", out, (p - out));

	return p - out;
}

/** Write out an RFC option header and option data
 *
 * @note May coalesce options with fixed width values
 *
 * @param[in,out] out buffer to write the TLV to.
 * @param[out] outlen length of the output buffer.
 * @param[in] tlv_stack	Describing nesting of options.
 * @param[in] depth in the tlv_stack.
 * @param[in,out] cursor Current attribute we're encoding.
 * @return
 *	- >0 length of data encoded.
 *	- 0 if we ran out of space.
 *	- < 0 on error.
 */
static ssize_t encode_rfc_hdr(uint8_t *out, ssize_t outlen,
			      fr_dict_attr_t const **tlv_stack, unsigned int depth, vp_cursor_t *cursor)
{
	ssize_t			len;
	uint8_t			*p = out;
	fr_dict_attr_t const	*da = tlv_stack[depth];
	VALUE_PAIR		*vp = fr_pair_cursor_current(cursor);

	if (outlen < 3) return 0;	/* No space */

	FR_PROTO_STACK_PRINT(tlv_stack, depth);

	/*
	 *	Write out the option number
	 */
	out[0] = da->attr & 0xff;
	out[1] = 0;	/* Length of the value only (unlike RADIUS) */

	outlen -= 2;
	p += 2;

	/*
	 *	Check here so we get the full 255 bytes
	 */
	if (outlen > UINT8_MAX) outlen = UINT8_MAX;

	/*
	 *	DHCP options with the same number (and array flag set)
	 *	get coalesced into a single option.
	 *
	 *	Note: This only works with fixed length attributes,
	 *	because there's no separate length fields.
	 */
	do {
		VALUE_PAIR *next;

		len = encode_value(p, outlen - out[1], tlv_stack, depth, cursor);
		if (len < 0) return len;
		if (len == 0) {
			FR_PROTO_TRACE("No more space in option");
			break; /* Packed as much as we can */
		}

		FR_PROTO_STACK_PRINT(tlv_stack, depth);
		FR_PROTO_TRACE("Encoded value is %zu byte(s)", len);
		FR_PROTO_HEX_DUMP(NULL, out, (p - out));

		p += len;
		out[1] += len;

		FR_PROTO_TRACE("%zu byte(s) available in option", outlen - out[1]);

		next = fr_pair_cursor_current(cursor);
		if (!next || (vp->da != next->da)) break;
		vp = next;
	} while (vp->da->flags.array);

	return p - out;
}

/** Write out a TLV header (and any sub TLVs or values)
 *
 * @param[in,out] out buffer to write the TLV to.
 * @param[out] outlen length of the output buffer.
 * @param[in] tlv_stack Describing nesting of options.
 * @param[in] depth in the tlv_stack.
 * @param[in,out] cursor Current attribute we're encoding.
 * @return
 *	- >0 length of data encoded.
 *	- 0 if we ran out of space.
 *	- < 0 on error.
 */
static ssize_t encode_tlv_hdr(uint8_t *out, ssize_t outlen,
			      fr_dict_attr_t const **tlv_stack, unsigned int depth, vp_cursor_t *cursor)
{
	ssize_t			len;
	uint8_t			*p = out;
	VALUE_PAIR const	*vp = fr_pair_cursor_current(cursor);
	fr_dict_attr_t const	*da = tlv_stack[depth];

	if (outlen < 5) return 0;	/* No space */

	FR_PROTO_STACK_PRINT(tlv_stack, depth);

	/*
	 *	Write out the option number
	 */
	out[0] = da->attr & 0xff;
	out[1] = 0;	/* Length of the value only (unlike RADIUS) */

	outlen -= 2;
	p += 2;

	/*
	 *	Check here so we get the full 255 bytes
	 */
	if (outlen > UINT8_MAX) outlen = UINT8_MAX;

	/*
	 *	Encode any sub TLVs or values
	 */
	while (outlen >= 3) {
		/*
		 *	Determine the nested type and call the appropriate encoder
		 */
		if (tlv_stack[depth + 1]->type == PW_TYPE_TLV) {
			len = encode_tlv_hdr(p, outlen - out[1], tlv_stack, depth + 1, cursor);
		} else {
			len = encode_rfc_hdr(p, outlen - out[1], tlv_stack, depth + 1, cursor);
		}
		if (len < 0) return len;
		if (len == 0) break;		/* Insufficient space */

		p += len;
		out[1] += len;

		FR_PROTO_STACK_PRINT(tlv_stack, depth);
		FR_PROTO_HEX_DUMP("TLV header and sub TLVs", out, (p - out));

		/*
		 *	If nothing updated the attribute, stop
		 */
		if (!fr_pair_cursor_current(cursor) || (vp == fr_pair_cursor_current(cursor))) break;

		/*
	 	 *	We can encode multiple sub TLVs, if after
	 	 *	rebuilding the TLV Stack, the attribute
	 	 *	at this depth is the same.
	 	 */
		if (da != tlv_stack[depth]) break;
		vp = fr_pair_cursor_current(cursor);
	}

	return p - out;
}

/** Encode a DHCP option and any sub-options.
 *
 * @param out Where to write encoded DHCP attributes.
 * @param outlen Length of out buffer.
 * @param cursor with current VP set to the option to be encoded. Will be advanced to the next option to encode.
 * @param encoder_ctx Unused.
 * @return
 *	- > 0 length of data written.
 *	- < 0 error.
 *	- 0 not valid option for DHCP (skipping).
 */
ssize_t fr_dhcp_encode_option(uint8_t *out, size_t outlen, vp_cursor_t *cursor, UNUSED void *encoder_ctx)
{
	VALUE_PAIR		*vp;
	unsigned int		depth = 0;
	fr_dict_attr_t const	*tlv_stack[FR_DICT_MAX_TLV_STACK + 1];
	ssize_t			len;

	vp = fr_pair_cursor_current(cursor);
	if (!vp) return -1;

	if (vp->da->vendor != DHCP_MAGIC_VENDOR) goto next; /* not a DHCP option */
	if (vp->da->attr == PW_DHCP_MESSAGE_TYPE) goto next; /* already done */
	if ((vp->da->attr > 255) && (DHCP_BASE_ATTR(vp->da->attr) != PW_DHCP_OPTION_82)) {
	next:
		fr_strerror_printf("Attribute \"%s\" is not a DHCP option", vp->da->name);
		fr_pair_cursor_next(cursor);
		return 0;
	}

	fr_proto_tlv_stack_build(tlv_stack, vp->da);

	/*
	 *	Because of the stupid DHCP vendor hack we use,
	 *	we've got to jump a few places up in the stack
	 *	before starting.  Once we have protocol dictionaries
	 *	this must be removed.
	 */
	depth += 2;
	FR_PROTO_STACK_PRINT(tlv_stack, depth);

	/*
	 *	We only have two types of options in DHCPv4
	 */
	switch (tlv_stack[depth]->type) {
	case PW_TYPE_TLV:
		len = encode_tlv_hdr(out, outlen, tlv_stack, depth, cursor);
		break;

	default:
		len = encode_rfc_hdr(out, outlen, tlv_stack, depth, cursor);
		break;
	}

	if (len < 0) return len;

	FR_PROTO_TRACE("Complete option is %zu byte(s)", len);
	FR_PROTO_HEX_DUMP(NULL, out, len);

	return len;
}

int fr_dhcp_encode(RADIUS_PACKET *packet)
{
	uint8_t		*p;
	vp_cursor_t	cursor;
	VALUE_PAIR	*vp;
	uint32_t	lvalue;
	uint16_t	svalue;
	size_t		dhcp_size;
	ssize_t		len;

	if (packet->data) return 0;

	packet->data_len = MAX_PACKET_SIZE;
	packet->data = talloc_zero_array(packet, uint8_t, packet->data_len);

	/* XXX Ugly ... should be set by the caller */
	if (packet->code == 0) packet->code = PW_DHCP_NAK;

	/* store xid */
	if ((vp = fr_pair_find_by_num(packet->vps, DHCP_MAGIC_VENDOR, 260, TAG_ANY))) {
		packet->id = vp->vp_integer;
	} else {
		packet->id = fr_rand();
	}

	p = packet->data;

	/*
	 *	@todo: Make this work again.
	 */
#if 0
	mms = DEFAULT_PACKET_SIZE; /* maximum message size */

	/*
	 *	Clients can request a LARGER size, but not a
	 *	smaller one.  They also cannot request a size
	 *	larger than MTU.
	 */

	/* DHCP-DHCP-Maximum-Msg-Size */
	vp = fr_pair_find_by_num(packet->vps, 57, DHCP_MAGIC_VENDOR, TAG_ANY);
	if (vp && (vp->vp_integer > mms)) {
		mms = vp->vp_integer;

		if (mms > MAX_PACKET_SIZE) mms = MAX_PACKET_SIZE;
	}
#endif

	vp = fr_pair_find_by_num(packet->vps, DHCP_MAGIC_VENDOR, 256, TAG_ANY);
	if (vp) {
		*p++ = vp->vp_integer & 0xff;
	} else {
		*p++ = 1;	/* client message */
	}

	/* DHCP-Hardware-Type */
	if ((vp = fr_pair_find_by_num(packet->vps, DHCP_MAGIC_VENDOR, 257, TAG_ANY))) {
		*p++ = vp->vp_byte;
	} else {
		*p++ = 1;		/* hardware type = ethernet */
	}

	/* DHCP-Hardware-Address-len */
	if ((vp = fr_pair_find_by_num(packet->vps, DHCP_MAGIC_VENDOR, 258, TAG_ANY))) {
		*p++ = vp->vp_byte;
	} else {
		*p++ = 6;		/* 6 bytes of ethernet */
	}

	/* DHCP-Hop-Count */
	if ((vp = fr_pair_find_by_num(packet->vps, DHCP_MAGIC_VENDOR, 259, TAG_ANY))) {
		*p = vp->vp_byte;
	}
	p++;

	/* DHCP-Transaction-Id */
	lvalue = htonl(packet->id);
	memcpy(p, &lvalue, 4);
	p += 4;

	/* DHCP-Number-of-Seconds */
	if ((vp = fr_pair_find_by_num(packet->vps, DHCP_MAGIC_VENDOR, 261, TAG_ANY))) {
		svalue = htons(vp->vp_short);
		memcpy(p, &svalue, 2);
	}
	p += 2;

	/* DHCP-Flags */
	if ((vp = fr_pair_find_by_num(packet->vps, DHCP_MAGIC_VENDOR, 262, TAG_ANY))) {
		svalue = htons(vp->vp_short);
		memcpy(p, &svalue, 2);
	}
	p += 2;

	/* DHCP-Client-IP-Address */
	if ((vp = fr_pair_find_by_num(packet->vps, DHCP_MAGIC_VENDOR, 263, TAG_ANY))) {
		memcpy(p, &vp->vp_ipv4addr, 4);
	}
	p += 4;

	/* DHCP-Your-IP-address */
	if ((vp = fr_pair_find_by_num(packet->vps, DHCP_MAGIC_VENDOR, 264, TAG_ANY))) {
		lvalue = vp->vp_ipv4addr;
	} else {
		lvalue = htonl(INADDR_ANY);
	}
	memcpy(p, &lvalue, 4);
	p += 4;

	/* DHCP-Server-IP-Address */
	vp = fr_pair_find_by_num(packet->vps, DHCP_MAGIC_VENDOR, 265, TAG_ANY);
	if (vp) {
		lvalue = vp->vp_ipv4addr;
	} else {
		lvalue = htonl(INADDR_ANY);
	}
	memcpy(p, &lvalue, 4);
	p += 4;

	/*
	 *	DHCP-Gateway-IP-Address
	 */
	if ((vp = fr_pair_find_by_num(packet->vps, DHCP_MAGIC_VENDOR, 266, TAG_ANY))) {
		lvalue = vp->vp_ipv4addr;
	} else {
		lvalue = htonl(INADDR_ANY);
	}
	memcpy(p, &lvalue, 4);
	p += 4;

	/* DHCP-Client-Hardware-Address */
	if ((vp = fr_pair_find_by_num(packet->vps, DHCP_MAGIC_VENDOR, 267, TAG_ANY))) {
		if (vp->vp_type == PW_TYPE_ETHERNET) {
			/*
			 *	Ensure that we mark the packet as being Ethernet.
			 *	This is mainly for DHCP-Lease-Query responses.
			 */
			packet->data[1] = 1;
			packet->data[2] = 6;

			memcpy(p, vp->vp_ether, sizeof(vp->vp_ether));
		} /* else ignore it */
	}
	p += DHCP_CHADDR_LEN;

	/* DHCP-Server-Host-Name */
	if ((vp = fr_pair_find_by_num(packet->vps, DHCP_MAGIC_VENDOR, 268, TAG_ANY))) {
		if (vp->vp_length > DHCP_SNAME_LEN) {
			memcpy(p, vp->vp_strvalue, DHCP_SNAME_LEN);
		} else {
			memcpy(p, vp->vp_strvalue, vp->vp_length);
		}
	}
	p += DHCP_SNAME_LEN;

	/*
	 *	Copy over DHCP-Boot-Filename.
	 *
	 *	FIXME: This copy should be delayed until AFTER the options
	 *	have been processed.  If there are too many options for
	 *	the packet, then they go into the sname && filename fields.
	 *	When that happens, the boot filename is passed as an option,
	 *	instead of being placed verbatim in the filename field.
	 */

	/* DHCP-Boot-Filename */
	vp = fr_pair_find_by_num(packet->vps, DHCP_MAGIC_VENDOR, 269, TAG_ANY);
	if (vp) {
		if (vp->vp_length > DHCP_FILE_LEN) {
			memcpy(p, vp->vp_strvalue, DHCP_FILE_LEN);
		} else {
			memcpy(p, vp->vp_strvalue, vp->vp_length);
		}
	}
	p += DHCP_FILE_LEN;

	/* DHCP magic number */
	lvalue = htonl(DHCP_OPTION_MAGIC_NUMBER);
	memcpy(p, &lvalue, 4);
	p += 4;

	p[0] = 0x35;		/* DHCP-Message-Type */
	p[1] = 1;
	p[2] = packet->code - PW_DHCP_OFFSET;
	p += 3;

	/*
	 *  Pre-sort attributes into contiguous blocks so that fr_dhcp_encode_option
	 *  operates correctly. This changes the order of the list, but never mind...
	 */
	fr_pair_list_sort(&packet->vps, fr_dhcp_attr_cmp);
	fr_pair_cursor_init(&cursor, &packet->vps);

	/*
	 *  Each call to fr_dhcp_encode_option will encode one complete DHCP option,
	 *  and sub options.
	 */
	while ((vp = fr_pair_cursor_current(&cursor))) {
		len = fr_dhcp_encode_option(p, packet->data_len - (p - packet->data), &cursor, NULL);
		if (len < 0) break;
		p += len;
	};

	p[0] = 0xff;		/* end of option option */
	p[1] = 0x00;
	p += 2;
	dhcp_size = p - packet->data;

	/*
	 *	FIXME: if (dhcp_size > mms),
	 *	  then we put the extra options into the "sname" and "file"
	 *	  fields, AND set the "end option option" in the "options"
	 *	  field.  We also set the "overload option",
	 *	  and put options into the "file" field, followed by
	 *	  the "sname" field.  Where each option is completely
	 *	  enclosed in the "file" and/or "sname" field, AND
	 *	  followed by the "end of option", and MUST be followed
	 *	  by padding option.
	 *
	 *	Yuck.  That sucks...
	 */
	packet->data_len = dhcp_size;

	if (packet->data_len < DEFAULT_PACKET_SIZE) {
		memset(packet->data + packet->data_len, 0,
		       DEFAULT_PACKET_SIZE - packet->data_len);
		packet->data_len = DEFAULT_PACKET_SIZE;
	}

	return 0;
}

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

	/*
	 *	Seems to be a bug in older versions of clang scan
	 */
#ifdef __clang_analyzer__
	if (!macaddr) return -1;
#endif

	if (!fr_cond_assert(macaddr) ||
	    !fr_cond_assert((macaddr->vp_type == PW_TYPE_ETHERNET) || (macaddr->vp_type == PW_TYPE_OCTETS))) {
		fr_strerror_printf("Wrong VP type (%s) for chaddr",
				   fr_int2str(dict_attr_types, macaddr->vp_type, "<invalid>"));
		return -1;
	}

	if (macaddr->vp_type == PW_TYPE_OCTETS) {
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

	if (macaddr->vp_type == PW_TYPE_ETHERNET) {
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
int fr_socket_packet(int if_index, struct sockaddr_ll *link_layer)
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
int fr_dhcp_send_raw_packet(int sockfd, struct sockaddr_ll *link_layer, RADIUS_PACKET *packet)
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
		if (vp->vp_type == PW_TYPE_ETHERNET) memcpy(dhmac, vp->vp_ether, sizeof(vp->vp_ether));
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
 *	print an ethernet address in a buffer
 */
static char *ether_addr_print(const uint8_t *addr, char *buf)
{
	sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
	return buf;
}

/*
 *	For a client, receive a DHCP packet from a raw packet
 *	socket. Make sure it matches the ongoing request.
 *
 *	FIXME: split this into two, recv_raw_packet, and verify(packet, original)
 */
RADIUS_PACKET *fr_dhcp_recv_raw_packet(int sockfd, struct sockaddr_ll *link_layer, RADIUS_PACKET *request)
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
	    ((vp->vp_type == PW_TYPE_ETHERNET) && (memcmp(vp->vp_ether, &eth_hdr->ether_dst, ETH_ADDR_LEN) != 0))) {
		char eth_dest[17 + 1];
		char eth_req_src[17 + 1];

		/* No match. */
		DISCARD_RP("Ethernet destination (%s) is not broadcast and doesn't match request source (%s)",
			   ether_addr_print(eth_hdr->ether_dst, eth_dest),
			   ether_addr_print(vp->vp_ether, eth_req_src));
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

	code = dhcp_get_option((dhcp_packet_t const *) packet->data, packet->data_len, PW_DHCP_MESSAGE_TYPE);
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

	packet->code = code[2] | PW_DHCP_OFFSET;

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

/** Resolve/cache attributes in the DHCP dictionary
 *
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int dhcp_init(void)
{
	dhcp_option_82 = fr_dict_attr_by_num(NULL, DHCP_MAGIC_VENDOR, PW_DHCP_OPTION_82);
	if (!dhcp_option_82) {
		fr_strerror_printf("Missing dictionary attribute for DHCP-Option-82");
		return -1;
	}

	return 0;
}
