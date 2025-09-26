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

#ifndef __MINGW32__
#include <sys/ioctl.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifndef __MINGW32__
#include <net/if_arp.h>
#endif

#define DHCP_CHADDR_LEN	(16)
#define DHCP_SNAME_LEN	(64)
#define DHCP_FILE_LEN	(128)
#define DHCP_VEND_LEN	(308)
#define DHCP_OPTION_MAGIC_NUMBER (0x63825363)

#ifndef INADDR_BROADCAST
#define INADDR_BROADCAST INADDR_NONE
#endif

/* @todo: this is a hack */
#  define DEBUG			if (fr_debug_lvl && fr_log_fp) fr_printf_log
#  define debug_pair(vp)	do { if (fr_debug_lvl && fr_log_fp) { \
					vp_print(fr_log_fp, vp); \
				     } \
				} while(0)

#ifdef HAVE_LINUX_IF_PACKET_H
#define ETH_HDR_SIZE   14
#define IP_HDR_SIZE    20
#define UDP_HDR_SIZE   8
#define ETH_ADDR_LEN   6
#define ETH_TYPE_IP    0x0800
#define ETH_P_ALL      0x0003

static uint8_t eth_bcast[ETH_ADDR_LEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

/* Discard raw packets which we are not interested in. Allow to trace why we discard. */
#define DISCARD_RP(...) { \
	if (fr_debug_lvl > 2) { \
		fprintf(stdout, "dhcpclient: discarding received packet: "); \
		fprintf(stdout, ## __VA_ARGS__); \
		fprintf(stdout, "\n"); \
	} \
	rad_free(&packet); \
	return NULL; \
}
#endif

#define VENDORPEC_ADSL 3561

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
static char const *dhcp_header_names[] = {
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

static char const *dhcp_message_types[] = {
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
#define MIN_PACKET_SIZE (244)
#define DEFAULT_PACKET_SIZE (300)
#define MAX_PACKET_SIZE (1500 - 40)

#define DHCP_OPTION_FIELD (0)
#define DHCP_FILE_FIELD	  (1)
#define DHCP_SNAME_FIELD  (2)

static uint8_t *dhcp_get_option(dhcp_packet_t *packet, size_t packet_size,
				unsigned int option)
{
	int overload = 0;
	int field = DHCP_OPTION_FIELD;
	size_t where, size;
	uint8_t *data;

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
					   (unsigned int) (data - (uint8_t *) packet));
			return NULL;
		}

		if ((where + 2 + data[1]) > size) {
			fr_strerror_printf("Option length overflows field at %u",
					   (unsigned int) (data - (uint8_t *) packet));
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

/*
 *	DHCPv4 is only for IPv4.  Broadcast only works if udpfromto is
 *	defined.
 */
RADIUS_PACKET *fr_dhcp_recv(int sockfd)
{
	uint32_t		magic;
	struct sockaddr_storage	src;
	struct sockaddr_storage	dst;
	socklen_t		sizeof_src;
	socklen_t		sizeof_dst;
	RADIUS_PACKET		*packet;
	uint16_t		port;
	uint8_t			*code;
	ssize_t			data_len;

	packet = rad_alloc(NULL, false);
	if (!packet) {
		fr_strerror_printf("Failed allocating packet");
		return NULL;
	}

	packet->data = talloc_zero_array(packet, uint8_t, MAX_PACKET_SIZE);
	if (!packet->data) {
		fr_strerror_printf("Out of memory");
		rad_free(&packet);
		return NULL;
	}

	packet->sockfd = sockfd;
	sizeof_src = sizeof(src);
#ifdef WITH_UDPFROMTO
	sizeof_dst = sizeof(dst);
	data_len = recvfromto(sockfd, packet->data, MAX_PACKET_SIZE, 0,
			      (struct sockaddr *)&src, &sizeof_src,
			      (struct sockaddr *)&dst, &sizeof_dst);
#else
	data_len = recvfrom(sockfd, packet->data, MAX_PACKET_SIZE, 0,
			    (struct sockaddr *)&src, &sizeof_src);
#endif

	if (data_len <= 0) {
		fr_strerror_printf("Failed reading DHCP socket: %s", fr_syserror(errno));
		rad_free(&packet);
		return NULL;
	}

	packet->data_len = data_len;
	if (packet->data_len < MIN_PACKET_SIZE) {
		fr_strerror_printf("DHCP packet is too small (%zu < %d)",
				   packet->data_len, MIN_PACKET_SIZE);
		rad_free(&packet);
		return NULL;
	}

	if (packet->data_len > MAX_PACKET_SIZE) {
		fr_strerror_printf("DHCP packet is too large (%zx > %d)",
				   packet->data_len, MAX_PACKET_SIZE);
		rad_free(&packet);
		return NULL;
	}

	if (packet->data[1] > 1) {
		fr_strerror_printf("DHCP can only receive ethernet requests, not type %02x",
		      packet->data[1]);
		rad_free(&packet);
		return NULL;
	}

	if ((packet->data[2] != 0) && (packet->data[2] != 6)) {
		fr_strerror_printf("Ethernet HW length is wrong length %d",
			packet->data[2]);
		rad_free(&packet);
		return NULL;
	}

	memcpy(&magic, packet->data + 236, 4);
	magic = ntohl(magic);
	if (magic != DHCP_OPTION_MAGIC_NUMBER) {
		fr_strerror_printf("Cannot do BOOTP");
		rad_free(&packet);
		return NULL;
	}

	/*
	 *	Create unique keys for the packet.
	 */
	memcpy(&magic, packet->data + 4, 4);
	packet->id = ntohl(magic);

	code = dhcp_get_option((dhcp_packet_t *) packet->data,
			       packet->data_len, PW_DHCP_MESSAGE_TYPE);
	if (!code) {
		fr_strerror_printf("No message-type option was found in the packet");
		rad_free(&packet);
		return NULL;
	}

	if ((code[1] < 1) || (code[2] == 0) || (code[2] >= DHCP_MAX_MESSAGE_TYPE)) {
		fr_strerror_printf("Unknown value %d for message-type option", code[2]);
		rad_free(&packet);
		return NULL;
	}

	packet->code = code[2] | PW_DHCP_OFFSET;

	/*
	 *	Create a unique vector from the xid and the client
	 *	hardware address.  This is a hack for the RADIUS
	 *	infrastructure in the rest of the server.
	 *	It is also used for de-duplicating DHCP packets
	 */
	memcpy(packet->vector, packet->data + 4, 4); /* xid */
	memcpy(packet->vector + 4, packet->data + 24, 4); /* giaddr */
	packet->vector[8] = packet->code & 0xff;	/* message type */
	memcpy(packet->vector + 9, packet->data + 28, 6); /* chaddr is always 6 for us */

	/*
	 *	FIXME: for DISCOVER / REQUEST: src_port == dst_port + 1
	 *	FIXME: for OFFER / ACK       : src_port = dst_port - 1
	 */

	sizeof_dst = sizeof(dst);

#ifndef WITH_UDPFROMTO
	/*
	 *	This should never fail...
	 */
	if (getsockname(sockfd, (struct sockaddr *) &dst, &sizeof_dst) < 0) {
		fr_strerror_printf("getsockname failed: %s", fr_syserror(errno));
		rad_free(&packet);
		return NULL;
	}
#endif

	fr_sockaddr2ipaddr(&dst, sizeof_dst, &packet->dst_ipaddr, &port);
	packet->dst_port = port;

	fr_sockaddr2ipaddr(&src, sizeof_src, &packet->src_ipaddr, &port);
	packet->src_port = port;

	if (fr_debug_lvl > 1) {
		char type_buf[64];
		char const *name = type_buf;
		char src_ip_buf[256], dst_ip_buf[256];

		if ((packet->code >= PW_DHCP_DISCOVER) &&
		    (packet->code < (1024 + DHCP_MAX_MESSAGE_TYPE))) {
			name = dhcp_message_types[packet->code - PW_DHCP_OFFSET];
		} else {
			snprintf(type_buf, sizeof(type_buf), "%d",
				 packet->code - PW_DHCP_OFFSET);
		}

		DEBUG("Received %s of Id %08x from %s:%d to %s:%d\n",
		       name, (unsigned int) packet->id,
		       inet_ntop(packet->src_ipaddr.af,
				 &packet->src_ipaddr.ipaddr,
				 src_ip_buf, sizeof(src_ip_buf)),
		       packet->src_port,
		       inet_ntop(packet->dst_ipaddr.af,
				 &packet->dst_ipaddr.ipaddr,
				 dst_ip_buf, sizeof(dst_ip_buf)),
		       packet->dst_port);
	}

	return packet;
}


/*
 *	Send a DHCP packet.
 */
int fr_dhcp_send(RADIUS_PACKET *packet)
{
	struct sockaddr_storage	dst;
	socklen_t		sizeof_dst;
#ifdef WITH_UDPFROMTO
	struct sockaddr_storage	src;
	socklen_t		sizeof_src;

	fr_ipaddr2sockaddr(&packet->src_ipaddr, packet->src_port,
	    &src, &sizeof_src);
#endif

	fr_ipaddr2sockaddr(&packet->dst_ipaddr, packet->dst_port,
			   &dst, &sizeof_dst);

	if (packet->data_len == 0) {
		fr_strerror_printf("No data to send");
		return -1;
	}

	if (fr_debug_lvl > 1) {
		char type_buf[64];
		char const *name = type_buf;
#ifdef WITH_UDPFROMTO
		char src_ip_buf[INET6_ADDRSTRLEN];
#endif
		char dst_ip_buf[INET6_ADDRSTRLEN];

		if ((packet->code >= PW_DHCP_DISCOVER) &&
		    (packet->code < (1024 + DHCP_MAX_MESSAGE_TYPE))) {
			name = dhcp_message_types[packet->code - PW_DHCP_OFFSET];
		} else {
			snprintf(type_buf, sizeof(type_buf), "%d",
			    packet->code - PW_DHCP_OFFSET);
		}

		DEBUG(
#ifdef WITH_UDPFROMTO
		"Sending %s Id %08x from %s:%d to %s:%d\n",
#else
		"Sending %s Id %08x to %s:%d\n",
#endif
		   name, (unsigned int) packet->id,
#ifdef WITH_UDPFROMTO
		   inet_ntop(packet->src_ipaddr.af, &packet->src_ipaddr.ipaddr, src_ip_buf, sizeof(src_ip_buf)),
		   packet->src_port,
#endif
		   inet_ntop(packet->dst_ipaddr.af, &packet->dst_ipaddr.ipaddr, dst_ip_buf, sizeof(dst_ip_buf)),
		   packet->dst_port);
	}

#ifndef WITH_UDPFROMTO
	/*
	 *	Assume that the packet is encoded before sending it.
	 */
	return sendto(packet->sockfd, packet->data, packet->data_len, 0,
		      (struct sockaddr *)&dst, sizeof_dst);
#else

	return sendfromto(packet->sockfd, packet->data, packet->data_len, 0,
			  (struct sockaddr *)&src, sizeof_src,
			  (struct sockaddr *)&dst, sizeof_dst);
#endif
}

static int fr_dhcp_attr2vp(TALLOC_CTX *ctx, VALUE_PAIR **vp_p, uint8_t const *p, size_t alen);

/** Returns the number of array members for arrays with fixed element sizes
 *
 */
static int fr_dhcp_array_members(size_t *len, DICT_ATTR const *da)
{
	int num_entries = 1;

	if (!len || !da) return -1;

	/*
	 *	Could be an array of bytes, integers, etc.
	 */
	if (da->flags.array) switch (da->type) {
	case PW_TYPE_BYTE:
		num_entries = *len;
		*len = 1;
		break;

	case PW_TYPE_SHORT: /* ignore any trailing data */
		num_entries = *len >> 1;
		*len = 2;
		break;

	case PW_TYPE_IPV4_ADDR:
	case PW_TYPE_INTEGER:
	case PW_TYPE_DATE: /* ignore any trailing data */
		num_entries = *len >> 2;
		*len = 4;
		break;

	case PW_TYPE_IPV6_ADDR:
		num_entries = *len >> 4;
		*len = 16;
		break;

	default:
		break;
	}

	return num_entries;
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
 * @param[in,out] tlv to decode. *tlv will be set to the head of the list of suboptions and original will be freed.
 * @param[in] ctx context to alloc new attributes in.
 * @param[in] data to parse.
 * @param[in] len length of data to parse.
 */
static int fr_dhcp_decode_suboption(TALLOC_CTX *ctx, VALUE_PAIR **tlv, uint8_t const *data, size_t len)
{
	uint8_t const *p, *q;
	VALUE_PAIR *head, *vp;
	vp_cursor_t cursor;

	/*
	 *	TLV must already point to a VALUE_PAIR.
	 */
	VERIFY_VP(*tlv);

	/*
	 *	Take a pass at parsing it.
	 */
	p = data;
	q = data + len;
	while (p < q) {
		/*
		 *	RFC 3046 is very specific about not allowing termination
		 *	with a 255 sub-option. But it's required for decoding
		 *	option 43, and vendors will probably screw it up
		 *	anyway.
		 */
		if (*p == 0) {
			p++;
			continue;
		}
		if (*p == 255) {
			q--;
			break;
		}

		/*
		 *	Check if reading length would take us past the end of the buffer
		 */
		if (++p >= q) goto malformed;
		p += p[0];

		/*
		 *	Check if length > the length of the buffer we have left
		 */
		if (p >= q) goto malformed;
		p++;
	}

	/*
	 *	Got here... must be well formed.
	 */
	head = NULL;
	fr_cursor_init(&cursor, &head);

	p = data;
	while (p < q) {
		uint8_t const	*a_p;
		size_t		a_len;
		int		num_entries, i;

		DICT_ATTR const	*da;
		uint32_t	attr;

		/*
		 *	Not enough room for the option header, it's a
		 *	bad packet.
		 */
		if ((p + 2) > (data + len)) {
			fr_pair_list_free(&head);
			return -1;
		}

		/*
		 *	Not enough room for the option header + data,
		 *	it's a bad packet.
		 */
		if ((p + 2 + p[1]) > (data + len)) {
			fr_pair_list_free(&head);
			return -1;
		}

		/*
		 *	The initial OID string looks like:
		 *	<iana>.0
		 *
		 *	If <iana>.0 is type TLV then we attempt to decode its contents as more
		 *	DHCP suboptions, which gives us:
		 *	<iana>.<attr>
		 *
		 *	If <iana>.0 is not defined in the dictionary or is type octets, we leave
		 *	the attribute as is.
		 */
		attr = (*tlv)->da->attr ? ((*tlv)->da->attr | (p[0] << 8)) : p[0];

		/*
		 *	Use the vendor of the parent TLV which is not necessarily
		 *	DHCP_MAGIC_VENDOR.
		 *
		 *	Note: This does not deal with dictionary numbering clashes. If
		 *	the vendor uses different numbers for DHCP suboptions and RADIUS
		 *	attributes then it's time to break out %{hex:} and regular
		 *	expressions.
		 */
		da = dict_attrbyvalue(attr, (*tlv)->da->vendor);
		if (!da) {
			da = dict_unknown_afrom_fields(ctx, attr, (*tlv)->da->vendor);
			if (!da) {
				fr_pair_list_free(&head);
				return -1;
			}
		}

		a_len = p[1];
		a_p = p + 2;
		num_entries = fr_dhcp_array_members(&a_len, da);
		for (i = 0; i < num_entries; i++) {
			vp = fr_pair_afrom_da(ctx, da);
			if (!vp) {
				fr_pair_list_free(&head);
				return -1;
			}
			vp->op = T_OP_EQ;
			fr_pair_steal(ctx, vp); /* for unknown attributes hack */

			if (fr_dhcp_attr2vp(ctx, &vp, a_p, a_len) < 0) {
				dict_attr_free(&da);
				fr_pair_list_free(&head);
				goto malformed;
			}
			fr_cursor_merge(&cursor, vp);

			a_p += a_len;
		}

		dict_attr_free(&da); /* for unknown attributes hack */

		p += 2 + p[1];	/* code (1) + len (1) + suboption len (n)*/
	}

	/*
	 *	The caller allocated a TLV, if decoding it generated
	 *	additional attributes, we now need to free it, and write
	 *	the HEAD of our new list of attributes in its place.
	 */
	if (head) {
		vp_cursor_t tlv_cursor;

		/*
		 *	Free the old TLV attribute
		 */
		TALLOC_FREE(*tlv);

		/*
		 *	Cursor not necessary but means we don't have to set
		 *	->next directly.
		 */
		fr_cursor_init(&tlv_cursor, tlv);
		fr_cursor_merge(&tlv_cursor, head);
	}

	return 0;

malformed:
	fr_pair_to_unknown(*tlv);
	fr_pair_value_memcpy(*tlv, data, len);

	return 0;
}

/*
 *	Decode ONE value into a VP
 */
static int fr_dhcp_attr2vp(TALLOC_CTX *ctx, VALUE_PAIR **vp_p, uint8_t const *data, size_t len)
{
	VALUE_PAIR *vp = *vp_p;
	VERIFY_VP(vp);

	switch (vp->da->type) {
	case PW_TYPE_BYTE:
		if (len != 1) goto raw;
		vp->vp_byte = data[0];
		break;

	case PW_TYPE_SHORT:
		if (len != 2) goto raw;
		memcpy(&vp->vp_short, data, 2);
		vp->vp_short = ntohs(vp->vp_short);
		break;

	case PW_TYPE_INTEGER:
		if (len != 4) goto raw;
		memcpy(&vp->vp_integer, data, 4);
		vp->vp_integer = ntohl(vp->vp_integer);
		break;

	case PW_TYPE_IPV4_ADDR:
		if (len != 4) goto raw;
		/*
		 *	Keep value in Network Order!
		 */
		memcpy(&vp->vp_ipaddr, data, 4);
		vp->vp_length = 4;
		break;

	/*
	 *	In DHCPv4, string options which can also be arrays,
	 *	have their values '\0' delimited.
	 */
	case PW_TYPE_STRING:
	{
		uint8_t const *p;
		uint8_t const *q, *end;
		vp_cursor_t cursor;

		p = data;
		q = end = data + len;

		if (!vp->da->flags.array) {
			fr_pair_value_bstrncpy(vp, (char const *)p, q - p);
			break;
		}

		/*
		 *	Initialise the cursor as we may be inserting
		 *	multiple additional VPs
		 */
		fr_cursor_init(&cursor, vp_p);
		while (p < end) {
			q = memchr(p, '\0', end - p);
			/* Malformed but recoverable */
			if (!q) q = end;

			fr_pair_value_bstrncpy(vp, (char const *)p, q - p);
			p = q + 1;

			if (p >= end) break;

			/* Need another VP for the next round */
			vp = fr_pair_afrom_da(ctx, vp->da);
			if (!vp) {
				fr_pair_list_free(vp_p);
				return -1;
			}
			fr_cursor_insert(&cursor, vp);
		}
	}
		break;

	case PW_TYPE_ETHERNET:
		memcpy(vp->vp_ether, data, sizeof(vp->vp_ether));
		vp->vp_length = sizeof(vp->vp_ether);
		break;

	/*
	 *	Value doesn't match up with attribute type, overwrite the
	 *	vp's original DICT_ATTR with an unknown one.
	 */
	raw:
		if (fr_pair_to_unknown(vp) < 0) return -1;
		/* FALL-THROUGH */

	case PW_TYPE_OCTETS:
		if (len > 255) return -1;
		fr_pair_value_memcpy(vp, data, len);
		break;

	/*
	 *	For option 82 et al...
	 */
	case PW_TYPE_TLV:
		return fr_dhcp_decode_suboption(ctx, vp_p, data, len);

	default:
		fr_strerror_printf("Internal sanity check %d %d", vp->da->type, __LINE__);
		return -1;
	} /* switch over type */

	vp->vp_length = len;
	return 0;
}

/** Decode DHCP options
 *
 * @param[in,out] out Where to write the decoded options.
 * @param[in] ctx context to alloc new attributes in.
 * @param[in] data to parse.
 * @param[in] len of data to parse.
 */
ssize_t fr_dhcp_decode_options(TALLOC_CTX *ctx, VALUE_PAIR **out, uint8_t const *data, size_t len)
{
	VALUE_PAIR *vp;
	vp_cursor_t cursor;
	uint8_t const *p, *q;

	*out = NULL;
	fr_cursor_init(&cursor, out);

	/*
	 *	FIXME: This should also check sname && file fields.
	 *	See the dhcp_get_option() function above.
	 */
	p = data;
	q = data + len;
	while (p < q) {
		uint8_t const	*a_p;
		size_t		a_len;
		int		num_entries, i;

		DICT_ATTR const	*da;

		if (*p == 0) {		/* 0x00 - Padding option */
			p++;
			continue;
		}

		if (*p == 255) {	/* 0xff - End of options signifier */
			break;
		}

		if ((p + 2) > q) break;

		a_len = p[1];
		a_p = p + 2;

		/*
		 *	Ensure we've not been given a bad length value
		 */
		if ((a_p + a_len) > q) {
			fr_strerror_printf("Length field value of option %u is incorrect.  "
					   "Got %u bytes, expected <= %zu bytes", p[0], p[1], q - a_p);
			fr_pair_list_free(out);
			return -1;
		}

		/*
		 *	Unknown attribute, create an octets type
		 *	attribute with the contents of the sub-option.
		 */
		da = dict_attrbyvalue(p[0], DHCP_MAGIC_VENDOR);
		if (!da) {
			da = dict_unknown_afrom_fields(ctx, p[0], DHCP_MAGIC_VENDOR);
			if (!da) {
				fr_pair_list_free(out);
				return -1;
			}
			vp = fr_pair_afrom_da(ctx, da);
			if (!vp) {
				fr_pair_list_free(out);
				return -1;
			}
			fr_pair_value_memcpy(vp, a_p, a_len);
			fr_cursor_insert(&cursor, vp);

			goto next;
		}

		/*
		 *	Decode ADSL Forum vendor-specific options.
		 */
		if ((p[0] == 125) && (p[1] > 6) && (p[2] == 0) && (p[3] == 0) && (p[4] == 0x0d) && (p[5] == 0xe9) &&
		    (p[6] + 5 == p[1])) {
			da = dict_attrbyvalue(255, VENDORPEC_ADSL);
			if (!da) goto normal;

			vp = fr_pair_afrom_da(ctx, da);
			if (!vp) {
				fr_pair_list_free(out);
				return -1;
			}

			(void) fr_dhcp_decode_suboption(ctx, &vp, p + 7, p[6]);
			if (vp) fr_cursor_merge(&cursor, vp);
			goto next;
		}

	normal:
		/*
		 *	Array type sub-option create a new VALUE_PAIR
		 *	for each array element.
		 */
		num_entries = fr_dhcp_array_members(&a_len, da);
		for (i = 0; i < num_entries; i++) {
			vp = fr_pair_afrom_da(ctx, da);
			if (!vp) {
				fr_pair_list_free(out);
				return -1;
			}
			vp->op = T_OP_EQ;

			if (fr_dhcp_attr2vp(ctx, &vp, a_p, a_len) < 0) {
				fr_pair_list_free(&vp);
				fr_pair_list_free(out);
				return -1;
			}
			fr_cursor_merge(&cursor, vp);
			a_p += a_len;
		} /* loop over array entries */
	next:
		p += 2 + p[1];	/* code (1) + len (1) + option len (n)*/
	} /* loop over the entire packet */

	return p - data;
}

int fr_dhcp_decode(RADIUS_PACKET *packet)
{
	size_t i;
	uint8_t *p;
	uint32_t giaddr;
	vp_cursor_t cursor;
	VALUE_PAIR *head = NULL, *vp;
	VALUE_PAIR *maxms, *mtu, *netaddr;

	fr_cursor_init(&cursor, &head);
	p = packet->data;

	if ((fr_debug_lvl > 2) && fr_log_fp) {
		for (i = 0; i < packet->data_len; i++) {
			if ((i & 0x0f) == 0x00) fprintf(fr_log_fp, "%d: ", (int) i);
			fprintf(fr_log_fp, "%02x ", packet->data[i]);
			if ((i & 0x0f) == 0x0f) fprintf(fr_log_fp, "\n");
		}
		fprintf(fr_log_fp, "\n");
	}

	if (packet->data[1] > 1) {
		fr_strerror_printf("Packet is not Ethernet: %u",
		      packet->data[1]);
		return -1;
	}

	/*
	 *	Decode the header.
	 */
	for (i = 0; i < 14; i++) {

		vp = fr_pair_afrom_num(packet, 256 + i, DHCP_MAGIC_VENDOR);
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
				DICT_ATTR const *da = dict_unknown_afrom_fields(packet, vp->da->attr, vp->da->vendor);
				if (!da) {
					return -1;
				}
				vp->da = da;
			}
		}

		switch (vp->da->type) {
		case PW_TYPE_BYTE:
			vp->vp_byte = p[0];
			vp->vp_length = 1;
			break;

		case PW_TYPE_SHORT:
			vp->vp_short = (p[0] << 8) | p[1];
			vp->vp_length = 2;
			break;

		case PW_TYPE_INTEGER:
			memcpy(&vp->vp_integer, p, 4);
			vp->vp_integer = ntohl(vp->vp_integer);
			vp->vp_length = 4;
			break;

		case PW_TYPE_IPV4_ADDR:
			memcpy(&vp->vp_ipaddr, p, 4);
			vp->vp_length = 4;
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
			vp->vp_length = sizeof(vp->vp_ether);
			break;

		default:
			fr_strerror_printf("BAD TYPE %d", vp->da->type);
			fr_pair_list_free(&vp);
			break;
		}
		p += dhcp_header_sizes[i];

		if (!vp) continue;

		debug_pair(vp);
		fr_cursor_insert(&cursor, vp);
	}

	/*
	 *	Loop over the options.
	 */

	/*
	 * 	Nothing uses tail after this call, if it does in the future
	 *	it'll need to find the new tail...
	 */
	{
		VALUE_PAIR *options = NULL;
		vp_cursor_t options_cursor;

		if (fr_dhcp_decode_options(packet, &options, packet->data + 240, packet->data_len - 240) < 0) {
			return -1;
		}

		if (options) {
			for (vp = fr_cursor_init(&options_cursor, &options);
			     vp;
			     vp = fr_cursor_next(&options_cursor)) {
			 	debug_pair(vp);
			}
			fr_cursor_merge(&cursor, options);
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
		 *	DHCP-Message-Type is request
		 */
		vp = fr_pair_find_by_num(head, 53, DHCP_MAGIC_VENDOR, TAG_ANY);
		if (vp && vp->vp_byte == 3) {
			/*
			 *	Vendor is "MSFT 98"
			 */
			vp = fr_pair_find_by_num(head, 60, DHCP_MAGIC_VENDOR, TAG_ANY);
			if (vp && (vp->vp_length >= 7) && (memcmp(vp->vp_octets, "MSFT 98", 7) == 0)) {
				vp = fr_pair_find_by_num(head, 262, DHCP_MAGIC_VENDOR, TAG_ANY);

				/*
				 *	Reply should be broadcast.
				 */
				if (vp) vp->vp_short |= 0x8000;
				packet->data[10] |= 0x80;
			}
		}
	}

	/*
	 *	Determine the address to use in looking up which subnet the
	 *	client belongs to based on packet data.  The sequence here
	 *	is based on ISC DHCP behaviour and RFCs 3527 and 3011.  We
	 *	store the found address in an internal attribute of 274 -
	 *	DHCP-Network-Subnet.  This is stored as an IPv4 prefix
	 *	with a /32 netmask allowing "closest containing subnet"
	 *	matching in rlm_files
	 */
	vp = fr_pair_afrom_num(packet, 274, DHCP_MAGIC_VENDOR);
	/*
	 *	First look for Relay-Link-Selection - option 82, suboption 5
	 */
	netaddr = fr_pair_find_by_num(head, (82 | (5 << 8)), DHCP_MAGIC_VENDOR, TAG_ANY);
	if (!netaddr) {
		/*
		 *	Next try Subnet-Selection-Option - option 118
		 */
		netaddr = fr_pair_find_by_num(head, 118, DHCP_MAGIC_VENDOR, TAG_ANY);
	}
	if (!netaddr) {
		if (giaddr != htonl(INADDR_ANY)) {
			/*
			 *	Gateway address is set - use that one
			 */
			memcpy(&vp->vp_ipv4prefix[2], packet->data + 24, 4);
		} else {
			/*
			 *	else, store client address whatever it is
			 */
			memcpy(&vp->vp_ipv4prefix[2], packet->data + 12, 4);
		}
	} else {
		/*
		 *	Store whichever address we've found from options
		 */
		memcpy(&vp->vp_ipv4prefix[2], &netaddr->vp_ipaddr, 4);
	}
	/*
	 *	Set the netmask to /32
	 */
	vp->vp_ipv4prefix[0] = 0;
	vp->vp_ipv4prefix[1] = 32;

	debug_pair(vp);
	fr_cursor_insert(&cursor, vp);

	/*
	 *	FIXME: Nuke attributes that aren't used in the normal
	 *	header for discover/requests.
	 */
	packet->vps = head;

	/*
	 *	Client can request a LARGER size, but not a smaller
	 *	one.  They also cannot request a size larger than MTU.
	 */
	maxms = fr_pair_find_by_num(packet->vps, 57, DHCP_MAGIC_VENDOR, TAG_ANY);
	mtu = fr_pair_find_by_num(packet->vps, 26, DHCP_MAGIC_VENDOR, TAG_ANY);

	if (mtu && (mtu->vp_integer < DEFAULT_PACKET_SIZE)) {
		fr_strerror_printf("DHCP Fatal: Client says MTU is smaller than minimum permitted by the specification");
		return -1;
	}

	if (maxms && (maxms->vp_integer < DEFAULT_PACKET_SIZE)) {
		fr_strerror_printf("DHCP WARNING: Client says maximum message size is smaller than minimum permitted by the specification: fixing it");
		maxms->vp_integer = DEFAULT_PACKET_SIZE;
	}

	if (maxms && mtu && (maxms->vp_integer > mtu->vp_integer)) {
		fr_strerror_printf("DHCP WARNING: Client says MTU is smaller than maximum message size: fixing it");
		maxms->vp_integer = mtu->vp_integer;
	}

	if (fr_debug_lvl) fflush(stdout);

	return 0;
}


int8_t fr_dhcp_attr_cmp(void const *a, void const *b)
{
	VALUE_PAIR const *my_a = a;
	VALUE_PAIR const *my_b = b;
	unsigned int base_a, base_b;
	uint8_t child_a, child_b;

	VERIFY_VP(my_a);
	VERIFY_VP(my_b);

	/*
	 *	ADSL Forum vendor-specific options after others to remain grouped
	 */
	if ((my_a->da->vendor == VENDORPEC_ADSL) && (my_b->da->vendor != VENDORPEC_ADSL)) return +1;
	if ((my_a->da->vendor != VENDORPEC_ADSL) && (my_b->da->vendor == VENDORPEC_ADSL)) return -1;

	/*
	 *	DHCP-Message-Type is first, for simplicity.
	 */
	if ((my_a->da->attr == PW_DHCP_MESSAGE_TYPE) && (my_b->da->attr != PW_DHCP_MESSAGE_TYPE)) return -1;
	if ((my_a->da->attr != PW_DHCP_MESSAGE_TYPE) && (my_b->da->attr == PW_DHCP_MESSAGE_TYPE)) return +1;

	/*
	 *	If the attr is a TLV, first compare on the parent
	 */
	base_a = my_a->da->flags.is_tlv ? DHCP_BASE_ATTR(my_a->da->attr) : my_a->da->attr;
	base_b = my_b->da->flags.is_tlv ? DHCP_BASE_ATTR(my_b->da->attr) : my_a->da->attr;

	/*
	 *	Relay-Agent is last
	 */
	if ((base_a == PW_DHCP_OPTION_82) && (base_b != PW_DHCP_OPTION_82)) return +1;
	if ((base_a != PW_DHCP_OPTION_82) && (my_b->da->attr == base_b)) return -1;

	if (base_a < base_b) return -1;
	if (base_a > base_b) return 1;

	if (!my_a->da->flags.is_tlv) return 0;

	/*
	 *	If this is a TLV, sort the sub options
	 */
	child_a = DHCP_UNPACK_OPTION1(my_a->da->attr);
	child_b = DHCP_UNPACK_OPTION1(my_b->da->attr);

	if (child_a < child_b) return -1;
	if (child_a > child_b) return 1;

	return 0;
}

/** Write DHCP option value into buffer
 *
 * Does not include DHCP option length or number.
 *
 * @param out where to write the DHCP option.
 * @param outlen length of output buffer.
 * @param vp option to encode.
 * @return the length of data writen, -1 if out of buffer, -2 if unsupported type.
 */
static ssize_t fr_dhcp_vp2data(uint8_t *out, size_t outlen, VALUE_PAIR *vp)
{
	uint32_t lvalue;
	uint8_t *p = out;

	if (outlen < vp->vp_length) {
		return -1;
	}

	switch (vp->da->type) {
	case PW_TYPE_BYTE:
		*p = vp->vp_byte;
		break;

	case PW_TYPE_SHORT:
		p[0] = (vp->vp_short >> 8) & 0xff;
		p[1] = vp->vp_short & 0xff;
		break;

	case PW_TYPE_INTEGER:
		lvalue = htonl(vp->vp_integer);
		memcpy(p, &lvalue, 4);
		break;

	case PW_TYPE_IPV4_ADDR:
		memcpy(p, &vp->vp_ipaddr, 4);
		break;

	case PW_TYPE_ETHERNET:
		memcpy(p, vp->vp_ether, 6);
		break;

	case PW_TYPE_STRING:
		memcpy(p, vp->vp_strvalue, vp->vp_length);
		break;

	case PW_TYPE_OCTETS:
		memcpy(p, vp->vp_octets, vp->vp_length);
		break;

	default:
		fr_strerror_printf("Unsupported option type %d", vp->da->type);
		return -2;
	}

	return vp->vp_length;
}

/** Create a new TLV attribute from multiple sub options
 *
 * @param[in,out] out buffer to write the data
 * @param[out] outlen length of the output buffer
 * @param[in,out] cursor should be set to the start of the list of TLV attributes.
 *   Will be advanced to the first non-TLV attribute.
 * @return length of data encoded, or -1 on error
 */
static ssize_t fr_dhcp_vp2data_tlv(uint8_t *out, ssize_t outlen, vp_cursor_t *cursor)
{
	ssize_t len;
	unsigned int parent; 	/* Parent attribute of suboption */
	uint8_t attr = 0;
	uint8_t *p, *opt_len;
	vp_cursor_t tlv_cursor;
	VALUE_PAIR *vp;

#define SUBOPTION_PARENT(_x) (_x & 0xffff00ff)
#define SUBOPTION_ATTR(_x) ((_x & 0xff00) >> 8)

	vp = fr_cursor_current(cursor);
	if (!vp) return -1;

	parent = SUBOPTION_PARENT(vp->da->attr);

	/*
	 *	Remember where we started off.
	 */
	fr_cursor_copy(&tlv_cursor, cursor);

	/*
	 *	Loop over TLVs to determine how much memory we need to allocate
	 *
	 *	We advanced the tlv_cursor we were passed, so if we
	 *	fail encoding, the tlv_cursor is at the right position
	 *	for the next potentially encodable attr.
	 */
	len = 0;
	for (vp = fr_cursor_current(&tlv_cursor);
	     vp && vp->da->flags.is_tlv && (SUBOPTION_PARENT(vp->da->attr) == parent);
	     vp = fr_cursor_next(&tlv_cursor)) {
		if (SUBOPTION_ATTR(vp->da->attr) == 0) {
			fr_strerror_printf("Invalid attribute number 0");
			return -1;
		}

		/*
		 *	If it's not an array type or is an array type,
		 *	but is not the same as the previous attribute,
		 *	we add 2 for the additional sub-option header
		 *	bytes.
		 */
		if (!vp->da->flags.array || (SUBOPTION_ATTR(vp->da->attr) != attr)) {
			attr = SUBOPTION_ATTR(vp->da->attr);
			len += 2;
		}
		len += vp->vp_length;
	}

	if (len > outlen) {
		fr_strerror_printf("Insufficient room for suboption");
		return -1;
	}

	attr = 0;
	opt_len = NULL;
	p = out;

	for (vp = fr_cursor_current(cursor);
	     vp && vp->da->flags.is_tlv && (SUBOPTION_PARENT(vp->da->attr) == parent);
	     vp = fr_cursor_next(cursor)) {
		/* Don't write out the header, were packing array options */
		if (!opt_len || !vp->da->flags.array || (attr != SUBOPTION_ATTR(vp->da->attr))) {
			attr = SUBOPTION_ATTR(vp->da->attr);
			*p++ = attr;
			opt_len = p++;
			*opt_len = 0;
		}

		len = fr_dhcp_vp2data(p, out + outlen - p, vp);
		if ((len < 0) || (len > 255)) {
			return -1;
		}

		debug_pair(vp);
		*opt_len += len;
		p += len;
	};

	return p - out;
}

static ssize_t fr_dhcp_encode_adsl(uint8_t *out, size_t outlen, vp_cursor_t *cursor)
{
	VALUE_PAIR *vp;
	uint8_t *p;
	size_t room;

	if (outlen <= (2 + 4 + 1)) return -1;

	out[0] = 125;		/* Vendor-Specific */
	out[1] = 5;		/* vendorpec + 1 octet of length */
	out[2] = 0;
	out[3] = 0;
	out[4] = 0x0d;
	out[5] = 0xe9;		/* ADSL forum vendorpec */
	out[6] = 0;		/* vendor-specific length */

	p = out + 7;
	room = outlen - 7;

	for (vp = fr_cursor_current(cursor);
	     ((vp != NULL) && (vp->da->vendor == VENDORPEC_ADSL) &&
	      (vp->da->attr > 255) && ((vp->da->attr & 0xff) == 0xff));
	     vp = fr_cursor_next(cursor)) {
		ssize_t length;

		/*
		 *	Silently discard options when there isn't enough room.
		 */
		if (room < 2) break;

		p[0] = (vp->da->attr >> 8) & 0xff;

		length = fr_dhcp_vp2data(p + 2, room - 2, vp);
		if (length < 0) break; /* not enough room */
		if (length > 255) break; /* too much data */

		p[1] = length;

		length += 2;	/* include the attribute header */

		/*
		 *	We don't (yet) split Vendor-Specific.  So if
		 *	there's too much data, just discard the extra
		 *	data.
		 */
		if ((out[1] + length) > 255) break;

		out[1] += length;
		out[6] += length;
		p += length;
		room -= length;
	}

	/*
	 *	Don't encode options with no data.
	 */
	if (out[1] == 5) return 0;

	return out[1] + 2;
}

/** Encode a DHCP option and any sub-options.
 *
 * @param out Where to write encoded DHCP attributes.
 * @param outlen Length of out buffer.
 * @param ctx to use for any allocated memory.
 * @param cursor with current VP set to the option to be encoded. Will be advanced to the next option to encode.
 * @return > 0 length of data written, < 0 error, 0 not valid option (skipping).
 */
ssize_t fr_dhcp_encode_option(UNUSED TALLOC_CTX *ctx, uint8_t *out, size_t outlen, vp_cursor_t *cursor)
{
	VALUE_PAIR *vp;
	DICT_ATTR const *previous;
	uint8_t *opt_len, *p = out;
	size_t freespace = outlen;
	ssize_t len;

	vp = fr_cursor_current(cursor);
	if (!vp) return -1;

	if (vp->da->vendor != DHCP_MAGIC_VENDOR) {
		if ((vp->da->vendor == VENDORPEC_ADSL) &&
		    (vp->da->attr > 255) && ((vp->da->attr & 0xff) == 0xff)) {
			return fr_dhcp_encode_adsl(out, outlen, cursor);
		}
		goto next; /* not a DHCP option */
	}
	if (vp->da->attr == PW_DHCP_MESSAGE_TYPE) goto next; /* already done */
	if ((vp->da->attr > 255) && (DHCP_BASE_ATTR(vp->da->attr) != PW_DHCP_OPTION_82)) goto next;

	if (vp->da->flags.extended) {
	next:
		fr_strerror_printf("Attribute \"%s\" is not a DHCP option", vp->da->name);
		fr_cursor_next(cursor);
		return 0;
	}

	/* Write out the option number */
	*(p++) = vp->da->attr & 0xff;

	/* Pointer to the length field of the option */
	opt_len = p++;

	/* Zero out the option's length field */
	*opt_len = 0;

	/* We just consumed two bytes for the header */
	freespace -= 2;

	/* DHCP options with the same number get coalesced into a single option */
	do {
		/*
		 *	Sub-option encoder will encode the data and
		 *	advance the cursor.
		 */
		if (vp->da->flags.is_tlv) {
			len = fr_dhcp_vp2data_tlv(p, freespace, cursor);
			previous = NULL;

		} else {
			len = fr_dhcp_vp2data(p, freespace, vp);
			if (len >= 0) debug_pair(vp);
			fr_cursor_next(cursor);
			previous = vp->da;
		}

		if (len < 0) return len;

		if ((*opt_len + len) > 255) {
			fr_strerror_printf("Skipping \"%s\": Option splitting not supported "
					   "(option > 255 bytes)", vp->da->name);
			return 0;
		}

		p += len;
		*opt_len += len;
		freespace -= len;

	} while ((vp = fr_cursor_current(cursor)) && previous && (previous == vp->da) && vp->da->flags.array);

	return p - out;
}

int fr_dhcp_encode(RADIUS_PACKET *packet)
{
	unsigned int i;
	uint8_t *p;
	vp_cursor_t cursor;
	VALUE_PAIR *vp;
	uint32_t lvalue;
	uint16_t	svalue;
	size_t dhcp_size;
	ssize_t len;
#ifndef NDEBUG
	char const *name;
#  ifdef WITH_UDPFROMTO
	char src_ip_buf[256];
#  endif
	char dst_ip_buf[256];
#endif

	if (packet->data) return 0;

	packet->data_len = MAX_PACKET_SIZE;
	packet->data = talloc_zero_array(packet, uint8_t, packet->data_len);

	/* XXX Ugly ... should be set by the caller */
	if (packet->code == 0) packet->code = PW_DHCP_NAK;

	/* store xid */
	if ((vp = fr_pair_find_by_num(packet->vps, 260, DHCP_MAGIC_VENDOR, TAG_ANY))) {
		packet->id = vp->vp_integer;
	} else {
		packet->id = fr_rand();
	}

#ifndef NDEBUG
	if ((packet->code >= PW_DHCP_DISCOVER) &&
	    (packet->code < (1024 + DHCP_MAX_MESSAGE_TYPE))) {
		name = dhcp_message_types[packet->code - PW_DHCP_OFFSET];
	} else {
		name = "?Unknown?";
	}

	DEBUG(
#  ifdef WITH_UDPFROMTO
	      "Encoding %s of id %08x from %s:%d to %s:%d\n",
#  else
	      "Encoding %s of id %08x to %s:%d\n",
#  endif
	      name, (unsigned int) packet->id,
#  ifdef WITH_UDPFROMTO
	      inet_ntop(packet->src_ipaddr.af,
			&packet->src_ipaddr.ipaddr,
			src_ip_buf, sizeof(src_ip_buf)),
	      packet->src_port,
#  endif
	      inet_ntop(packet->dst_ipaddr.af,
			&packet->dst_ipaddr.ipaddr,
		     dst_ip_buf, sizeof(dst_ip_buf)),
	      packet->dst_port);
#endif

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

	vp = fr_pair_find_by_num(packet->vps, 256, DHCP_MAGIC_VENDOR, TAG_ANY);
	if (vp) {
		*p++ = vp->vp_integer & 0xff;
	} else {
		*p++ = 1;	/* client message */
	}

	/* DHCP-Hardware-Type */
	if ((vp = fr_pair_find_by_num(packet->vps, 257, DHCP_MAGIC_VENDOR, TAG_ANY))) {
		*p++ = vp->vp_byte;
	} else {
		*p++ = 1;		/* hardware type = ethernet */
	}

	/* DHCP-Hardware-Address-Length */
	if ((vp = fr_pair_find_by_num(packet->vps, 258, DHCP_MAGIC_VENDOR, TAG_ANY))) {
		*p++ = vp->vp_byte;
	} else {
		*p++ = 6;		/* 6 bytes of ethernet */
	}

	/* DHCP-Hop-Count */
	if ((vp = fr_pair_find_by_num(packet->vps, 259, DHCP_MAGIC_VENDOR, TAG_ANY))) {
		*p = vp->vp_byte;
	}
	p++;

	/* DHCP-Transaction-Id */
	lvalue = htonl(packet->id);
	memcpy(p, &lvalue, 4);
	p += 4;

	/* DHCP-Number-of-Seconds */
	if ((vp = fr_pair_find_by_num(packet->vps, 261, DHCP_MAGIC_VENDOR, TAG_ANY))) {
		svalue = htons(vp->vp_short);
		memcpy(p, &svalue, 2);
	}
	p += 2;

	/* DHCP-Flags */
	if ((vp = fr_pair_find_by_num(packet->vps, 262, DHCP_MAGIC_VENDOR, TAG_ANY))) {
		svalue = htons(vp->vp_short);
		memcpy(p, &svalue, 2);
	}
	p += 2;

	/* DHCP-Client-IP-Address */
	if ((vp = fr_pair_find_by_num(packet->vps, 263, DHCP_MAGIC_VENDOR, TAG_ANY))) {
		memcpy(p, &vp->vp_ipaddr, 4);
	}
	p += 4;

	/* DHCP-Your-IP-address */
	if ((vp = fr_pair_find_by_num(packet->vps, 264, DHCP_MAGIC_VENDOR, TAG_ANY))) {
		lvalue = vp->vp_ipaddr;
	} else {
		lvalue = htonl(INADDR_ANY);
	}
	memcpy(p, &lvalue, 4);
	p += 4;

	/* DHCP-Server-IP-Address */
	vp = fr_pair_find_by_num(packet->vps, 265, DHCP_MAGIC_VENDOR, TAG_ANY);
	if (vp) {
		lvalue = vp->vp_ipaddr;
	} else {
		lvalue = htonl(INADDR_ANY);
	}
	memcpy(p, &lvalue, 4);
	p += 4;

	/*
	 *	DHCP-Gateway-IP-Address
	 */
	if ((vp = fr_pair_find_by_num(packet->vps, 266, DHCP_MAGIC_VENDOR, TAG_ANY))) {
		lvalue = vp->vp_ipaddr;
	} else {
		lvalue = htonl(INADDR_ANY);
	}
	memcpy(p, &lvalue, 4);
	p += 4;

	/* DHCP-Client-Hardware-Address */
	if ((vp = fr_pair_find_by_num(packet->vps, 267, DHCP_MAGIC_VENDOR, TAG_ANY))) {
		if (vp->vp_length == sizeof(vp->vp_ether)) {
			/*
			 *	Ensure that we mark the packet as being Ethernet.
			 *	This is mainly for DHCP-Lease-Query responses.
			 */
			packet->data[1] = 1;
			packet->data[2] = 6;

			memcpy(p, vp->vp_ether, vp->vp_length);
		} /* else ignore it */
	}
	p += DHCP_CHADDR_LEN;

	/* DHCP-Server-Host-Name */
	if ((vp = fr_pair_find_by_num(packet->vps, 268, DHCP_MAGIC_VENDOR, TAG_ANY))) {
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
	vp = fr_pair_find_by_num(packet->vps, 269, DHCP_MAGIC_VENDOR, TAG_ANY);
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

	/*
	 *	Print the header.
	 */
	if (fr_debug_lvl > 1) {
		uint8_t *pp = p;

		p = packet->data;

		for (i = 0; i < 14; i++) {
			char *q;

			vp = fr_pair_make(packet, NULL,
				      dhcp_header_names[i], NULL, T_OP_EQ);
			if (!vp) {
				char buffer[256];
				strlcpy(buffer, fr_strerror(), sizeof(buffer));
				fr_strerror_printf("Cannot decode packet due to internal error: %s", buffer);
				return -1;
			}

			switch (vp->da->type) {
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
				memcpy(&vp->vp_ipaddr, p, 4);
				break;

			case PW_TYPE_STRING:
				vp->vp_strvalue = q = talloc_array(vp, char, dhcp_header_sizes[i] + 1);
				vp->type = VT_DATA;
				memcpy(q, p, dhcp_header_sizes[i]);
				q[dhcp_header_sizes[i]] = '\0';
				vp->vp_length = strlen(vp->vp_strvalue);
				break;

			case PW_TYPE_OCTETS: /* only for Client HW Address */
				fr_pair_value_memcpy(vp, p, packet->data[2]);
				break;

			case PW_TYPE_ETHERNET: /* only for Client HW Address */
				memcpy(vp->vp_ether, p, sizeof(vp->vp_ether));
				break;

			default:
				fr_strerror_printf("Internal sanity check failed %d %d", vp->da->type, __LINE__);
				fr_pair_list_free(&vp);
				break;
			}

			p += dhcp_header_sizes[i];

			debug_pair(vp);
			fr_pair_list_free(&vp);
		}

		/*
		 *	Jump over DHCP magic number, response, etc.
		 */
		p = pp;
	}

	p[0] = 0x35;		/* DHCP-Message-Type */
	p[1] = 1;
	p[2] = packet->code - PW_DHCP_OFFSET;
	p += 3;

	/*
	 *  Pre-sort attributes into contiguous blocks so that fr_dhcp_encode_option
	 *  operates correctly. This changes the order of the list, but never mind...
	 */
	fr_pair_list_sort(&packet->vps, fr_dhcp_attr_cmp);
	fr_cursor_init(&cursor, &packet->vps);

	/*
	 *  Each call to fr_dhcp_encode_option will encode one complete DHCP option,
	 *  and sub options.
	 */
	while ((vp = fr_cursor_current(&cursor))) {
		len = fr_dhcp_encode_option(packet, p, packet->data_len - (p - packet->data), &cursor);
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

	if ((fr_debug_lvl > 2) && fr_log_fp) {
		fprintf(fr_log_fp, "DHCP Sending %zu bytes\n", packet->data_len);
		for (i = 0; i < packet->data_len; i++) {
			if ((i & 0x0f) == 0x00) fprintf(fr_log_fp, "%d: ", (int) i);
			fprintf(fr_log_fp, "%02x ", packet->data[i]);
			if ((i & 0x0f) == 0x0f) fprintf(fr_log_fp, "\n");
		}
		fprintf(fr_log_fp, "\n");
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

	if (!fr_assert(macaddr) ||
	    !fr_assert((macaddr->da->type == PW_TYPE_ETHERNET) || (macaddr->da->type == PW_TYPE_OCTETS))) {
		fr_strerror_printf("Wrong VP type (%s) for chaddr",
				   fr_int2str(dict_attr_types, macaddr->da->type, "<invalid>"));
		return -1;
	}

	if (macaddr->vp_length > sizeof(req.arp_ha.sa_data)) {
		fr_strerror_printf("arp sa_data field too small (%zu octets) to contain chaddr (%zu octets)",
				   sizeof(req.arp_ha.sa_data), macaddr->vp_length);
		return -1;
	}

	memset(&req, 0, sizeof(req));
	sin = (struct sockaddr_in *) &req.arp_pa;
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = ip->vp_ipaddr;

	strlcpy(req.arp_dev, interface, sizeof(req.arp_dev));

	if (macaddr->da->type == PW_TYPE_ETHERNET) {
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
int fr_socket_packet(int iface_index, struct sockaddr_ll *p_ll)
{
	int lsockfd;

	/* PF_PACKET - packet interface on device level.
	   using a raw socket allows packet data to be unchanged by the device driver.
	 */
	lsockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (lsockfd < 0) {
		fr_strerror_printf("cannot open socket: %s", fr_syserror(errno));
		return lsockfd;
	}

	/* Set link layer parameters */
	memset(p_ll, 0, sizeof(struct sockaddr_ll));

	p_ll->sll_family = AF_PACKET;
	p_ll->sll_protocol = htons(ETH_P_ALL);
	p_ll->sll_ifindex = iface_index;
	p_ll->sll_hatype = ARPHRD_ETHER;
	p_ll->sll_pkttype = PACKET_OTHERHOST;
	p_ll->sll_halen = 6;

	if (bind(lsockfd, (struct sockaddr *)p_ll, sizeof(struct sockaddr_ll)) < 0) {
		close(lsockfd);
		fr_strerror_printf("cannot bind raw socket: %s", fr_syserror(errno));
		return -1;
	}

	return lsockfd;
}

/*
 *	Encode and send a DHCP packet on a raw packet socket.
 */
int fr_dhcp_send_raw_packet(int sockfd, struct sockaddr_ll *p_ll, RADIUS_PACKET *packet)
{
	VALUE_PAIR *vp;
	u_char dhcp_packet[1518] = { 0 };

	/* set ethernet source address to our MAC address (DHCP-Client-Hardware-Address). */
	u_char dhmac[ETH_ADDR_LEN] = { 0 };
	if ((vp = fr_pair_find_by_num(packet->vps, 267, DHCP_MAGIC_VENDOR, TAG_ANY))) {
		if (vp->length == sizeof(vp->vp_ether)) {
			memcpy(dhmac, vp->vp_ether, vp->length);
		}
	}

	/* fill in Ethernet layer (L2) */
	struct ethernet_header *ethhdr = (struct ethernet_header *)dhcp_packet;
	memcpy(ethhdr->ether_dst, eth_bcast, ETH_ADDR_LEN);
	memcpy(ethhdr->ether_src, dhmac, ETH_ADDR_LEN);
	ethhdr->ether_type = htons(ETH_TYPE_IP);

	/* fill in IP layer (L3) */
	struct ip_header *iph = (struct ip_header *)(dhcp_packet + ETH_HDR_SIZE);
	iph->ip_vhl = IP_VHL(4, 5);
	iph->ip_tos = 0;
	iph->ip_len = htons(IP_HDR_SIZE +  UDP_HDR_SIZE + packet->data_len);
	iph->ip_id = 0;
	iph->ip_off = 0;
	iph->ip_ttl = 64;
	iph->ip_p = 17;
	iph->ip_sum = 0; /* Filled later */

	/* saddr: Packet-Src-IP-Address (default: 0.0.0.0). */
	iph->ip_src.s_addr = packet->src_ipaddr.ipaddr.ip4addr.s_addr;

	/* daddr: packet destination IP addr (should be 255.255.255.255 for broadcast). */
	iph->ip_dst.s_addr = packet->dst_ipaddr.ipaddr.ip4addr.s_addr;

	/* IP header checksum */
	iph->ip_sum = fr_iph_checksum((uint8_t const *)iph, 5);

	/* fill in UDP layer (L4) */
	udp_header_t *uh = (udp_header_t *) (dhcp_packet + ETH_HDR_SIZE + IP_HDR_SIZE);

	uh->src = htons(68);
	uh->dst = htons(67);
	u_int16_t l4_len = (UDP_HDR_SIZE + packet->data_len);
	uh->len = htons(l4_len);
	uh->checksum = 0; /* UDP checksum will be done after dhcp header */

	/* DHCP layer (L7) */
	dhcp_packet_t *dhpointer = (dhcp_packet_t *)(dhcp_packet + ETH_HDR_SIZE + IP_HDR_SIZE + UDP_HDR_SIZE);
	/* just copy what FreeRADIUS has encoded for us. */
	memcpy(dhpointer, packet->data, packet->data_len);

	/* UDP checksum is done here */
	uh->checksum = fr_udp_checksum((uint8_t const *)(dhcp_packet + ETH_HDR_SIZE + IP_HDR_SIZE), ntohs(uh->len), uh->checksum,
					packet->src_ipaddr.ipaddr.ip4addr, packet->dst_ipaddr.ipaddr.ip4addr);

	if (fr_debug_lvl > 1) {
		char type_buf[64];
		char const *name = type_buf;
		char src_ip_buf[INET6_ADDRSTRLEN];
		char dst_ip_buf[INET6_ADDRSTRLEN];

		if ((packet->code >= PW_DHCP_DISCOVER) &&
		    (packet->code < (1024 + DHCP_MAX_MESSAGE_TYPE))) {
			name = dhcp_message_types[packet->code - PW_DHCP_OFFSET];
		} else {
			snprintf(type_buf, sizeof(type_buf), "%d",
			    packet->code - PW_DHCP_OFFSET);
		}

		DEBUG(
		"Sending %s Id %08x from %s:%d to %s:%d\n",
		   name, (unsigned int) packet->id,
		   inet_ntop(packet->src_ipaddr.af, &packet->src_ipaddr.ipaddr, src_ip_buf, sizeof(src_ip_buf)), packet->src_port,
		   inet_ntop(packet->dst_ipaddr.af, &packet->dst_ipaddr.ipaddr, dst_ip_buf, sizeof(dst_ip_buf)), packet->dst_port);
	}

	return sendto(sockfd, dhcp_packet,
		(ETH_HDR_SIZE + IP_HDR_SIZE + UDP_HDR_SIZE + packet->data_len),
		0, (struct sockaddr *) p_ll, sizeof(struct sockaddr_ll));
}

/*
 *	print an ethernet address in a buffer
 */
static char * ether_addr_print(const uint8_t *addr, char *buf)
{
	sprintf (buf, "%02x:%02x:%02x:%02x:%02x:%02x",
		addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
	return buf;
}

/*
 *	For a client, receive a DHCP packet from a raw packet
 *	socket. Make sure it matches the ongoing request.
 *
 *	FIXME: split this into two, recv_raw_packet, and verify(packet, original)
 */
RADIUS_PACKET *fr_dhcp_recv_raw_packet(int sockfd, struct sockaddr_ll *p_ll, RADIUS_PACKET *request)
{
	VALUE_PAIR		*vp;
	RADIUS_PACKET		*packet;
	uint8_t			*code;
	uint32_t		magic, xid;
	ssize_t			data_len;

	uint8_t			*raw_packet;
	ethernet_header_t	*eth_hdr;
	struct ip_header	*ip_hdr;
	udp_header_t		*udp_hdr;
	dhcp_packet_t		*dhcp_hdr;
	uint16_t		udp_src_port;
	uint16_t		udp_dst_port;
	size_t			dhcp_data_len;
	socklen_t		sock_len;

	packet = rad_alloc(NULL, false);
	if (!packet) {
		fr_strerror_printf("Failed allocating packet");
		return NULL;
	}

	raw_packet = talloc_zero_array(packet, uint8_t, MAX_PACKET_SIZE);
	if (!raw_packet) {
		fr_strerror_printf("Out of memory");
		rad_free(&packet);
		return NULL;
	}

	packet->sockfd = sockfd;

	/* a packet was received (but maybe it is not for us) */
	sock_len = sizeof(struct sockaddr_ll);
	data_len = recvfrom(sockfd, raw_packet, MAX_PACKET_SIZE, 0,
			    (struct sockaddr *)p_ll, &sock_len);

	uint8_t data_offset = ETH_HDR_SIZE + IP_HDR_SIZE + UDP_HDR_SIZE; // DHCP data starts after Ethernet, IP, UDP.

	if (data_len <= data_offset) DISCARD_RP("Payload (%d) smaller than required for layers 2+3+4", (int)data_len);

	/* map raw packet to packet header of the different layers (Ethernet, IP, UDP) */
	eth_hdr = (ethernet_header_t *)raw_packet;

	/* a. Check Ethernet layer data (L2) */
	if (ntohs(eth_hdr->ether_type) != ETH_TYPE_IP) DISCARD_RP("Ethernet type (%d) != IP", ntohs(eth_hdr->ether_type));

	/* If Ethernet destination is not broadcast (ff:ff:ff:ff:ff:ff)
	 * Check if it matches the source HW address used (DHCP-Client-Hardware-Address = 267)
	 */
	if ( (memcmp(&eth_bcast, &eth_hdr->ether_dst, ETH_ADDR_LEN) != 0) &&
			(vp = fr_pair_find_by_num(request->vps, 267, DHCP_MAGIC_VENDOR, TAG_ANY)) &&
			(vp->length == sizeof(vp->vp_ether)) &&
			(memcmp(vp->vp_ether, &eth_hdr->ether_dst, ETH_ADDR_LEN) != 0) ) {
		/* No match. */
		char eth_dest[17+1];
		char eth_req_src[17+1];
		DISCARD_RP("Ethernet destination (%s) is not broadcast and doesn't match request source (%s)",
			ether_addr_print(eth_hdr->ether_dst, eth_dest),
			ether_addr_print(vp->vp_ether, eth_req_src));
	}

	/*
	 *	Ethernet is OK.  Now look at IP.
	 */
	ip_hdr = (struct ip_header *)(raw_packet + ETH_HDR_SIZE);

	/* b. Check IPv4 layer data (L3) */
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

	/* c. Check UDP layer data (L4) */
	udp_src_port = ntohs(udp_hdr->src);
	udp_dst_port = ntohs(udp_hdr->dst);

	/*
	 *	A DHCP server will always respond to port 68 (to a
	 *	client) or 67 (to a relay).  Just check that both
	 *	ports are 67 or 68.
	 */
	if (udp_src_port != 67 && udp_src_port != 68) DISCARD_RP("UDP src port (%d) != DHCP (67 or 68)", udp_src_port);
	if (udp_dst_port != 67 && udp_dst_port != 68) DISCARD_RP("UDP dst port (%d) != DHCP (67 or 68)", udp_dst_port);

	/* d. Check DHCP layer data */
	dhcp_data_len = data_len - data_offset;

	if (dhcp_data_len < MIN_PACKET_SIZE) DISCARD_RP("DHCP packet is too small (%zu < %d)", dhcp_data_len, MIN_PACKET_SIZE);
	if (dhcp_data_len > MAX_PACKET_SIZE) DISCARD_RP("DHCP packet is too large (%zu > %d)", dhcp_data_len, MAX_PACKET_SIZE);

	dhcp_hdr = (dhcp_packet_t *)(raw_packet + ETH_HDR_SIZE + IP_HDR_SIZE + UDP_HDR_SIZE);

	if (dhcp_hdr->htype != 1) DISCARD_RP("DHCP hardware type (%d) != Ethernet (1)", dhcp_hdr->htype);
	if (dhcp_hdr->hlen != 6) DISCARD_RP("DHCP hardware address length (%d) != 6", dhcp_hdr->hlen);

	magic = ntohl(dhcp_hdr->option_format);

	if (magic != DHCP_OPTION_MAGIC_NUMBER) DISCARD_RP("DHCP magic cookie (0x%04x) != DHCP (0x%04x)", magic, DHCP_OPTION_MAGIC_NUMBER);

	/*
	 *	Reply transaction id must match value from request.
	 */
	xid = ntohl(dhcp_hdr->xid);
	if (xid != (uint32_t)request->id) DISCARD_RP("DHCP transaction ID (0x%04x) != xid from request (0x%04x)", xid, request->id)

	/* all checks ok! this is a DHCP reply we're interested in. */
	packet->data_len = dhcp_data_len;
	packet->data = talloc_memdup(packet, raw_packet + data_offset, dhcp_data_len);
	TALLOC_FREE(raw_packet);
	packet->id = xid;

	code = dhcp_get_option((dhcp_packet_t *) packet->data,
			       packet->data_len, PW_DHCP_MESSAGE_TYPE);
	if (!code) {
		fr_strerror_printf("No message-type option was found in the packet");
		rad_free(&packet);
		return NULL;
	}

	if ((code[1] < 1) || (code[2] == 0) || (code[2] > 8)) {
		fr_strerror_printf("Unknown value for message-type option");
		rad_free(&packet);
		return NULL;
	}

	packet->code = code[2] | PW_DHCP_OFFSET;

	/*
	 *	Create a unique vector from the xid and the client
	 *	hardware address.  This is a hack for the RADIUS
	 *	infrastructure in the rest of the server.
	 *	It is also used for de-duplicating DHCP packets
	 */
	memcpy(packet->vector, packet->data + 4, 4); /* xid */
	memcpy(packet->vector + 4, packet->data + 24, 4); /* giaddr */
	packet->vector[8] = packet->code & 0xff;	/* message type */
	memcpy(packet->vector + 9, packet->data + 28, 6); /* chaddr is always 6 for us */

	packet->src_port = udp_src_port;
	packet->dst_port = udp_dst_port;

	packet->src_ipaddr.af = AF_INET;
	packet->src_ipaddr.ipaddr.ip4addr.s_addr = ip_hdr->ip_src.s_addr;
	packet->dst_ipaddr.af = AF_INET;
	packet->dst_ipaddr.ipaddr.ip4addr.s_addr = ip_hdr->ip_dst.s_addr;

	if (fr_debug_lvl > 1) {
		char type_buf[64];
		char const *name = type_buf;
		char src_ip_buf[256], dst_ip_buf[256];

		if ((packet->code >= PW_DHCP_DISCOVER) &&
		    (packet->code < (1024 + DHCP_MAX_MESSAGE_TYPE))) {
			name = dhcp_message_types[packet->code - PW_DHCP_OFFSET];
		} else {
			snprintf(type_buf, sizeof(type_buf), "%d", packet->code - PW_DHCP_OFFSET);
		}

		DEBUG("Received %s of Id %08x from %s:%d to %s:%d\n",
		       name, (unsigned int) packet->id,
		       inet_ntop(packet->src_ipaddr.af, &packet->src_ipaddr.ipaddr, src_ip_buf, sizeof(src_ip_buf)),
		       packet->src_port,
		       inet_ntop(packet->dst_ipaddr.af, &packet->dst_ipaddr.ipaddr, dst_ip_buf, sizeof(dst_ip_buf)),
		       packet->dst_port);
	}

	return packet;
}
#endif
