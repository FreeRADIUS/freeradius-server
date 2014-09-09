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
#  define DEBUG			if (fr_debug_flag && fr_log_fp) fr_printf_log
#  define debug_pair(vp)	do { if (fr_debug_flag && fr_log_fp) { \
					vp_print(fr_log_fp, vp); \
				     } \
				} while(0)

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
};

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

	if (packet->data[1] != 1) {
		fr_strerror_printf("DHCP can only receive ethernet requests, not type %02x",
		      packet->data[1]);
		rad_free(&packet);
		return NULL;
	}

	if (packet->data[2] != 6) {
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
			       packet->data_len, 53);
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

	/*
	 *	FIXME: for DISCOVER / REQUEST: src_port == dst_port + 1
	 *	FIXME: for OFFER / ACK       : src_port = dst_port - 1
	 */

	/*
	 *	Unique keys are xid, client mac, and client ID?
	 */

	/*
	 *	FIXME: More checks, like DHCP packet type?
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

	if (fr_debug_flag > 1) {
		char type_buf[64];
		char const *name = type_buf;
		char src_ip_buf[256], dst_ip_buf[256];

		if ((packet->code >= PW_DHCP_DISCOVER) &&
		    (packet->code <= PW_DHCP_INFORM)) {
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

	if (fr_debug_flag > 1) {
		char type_buf[64];
		char const *name = type_buf;
#ifdef WITH_UDPFROMTO
		char src_ip_buf[INET6_ADDRSTRLEN];
#endif
		char dst_ip_buf[INET6_ADDRSTRLEN];

		if ((packet->code >= PW_DHCP_DISCOVER) &&
		    (packet->code <= PW_DHCP_INFORM)) {
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

static int fr_dhcp_attr2vp(VALUE_PAIR **vp_p, TALLOC_CTX *ctx, uint8_t const *p, size_t alen);

/** Returns the number of array members for arrays with fixed element sizes
 *
 */
static int fr_dhcp_array_members(size_t *len, DICT_ATTR const *da)
{
	int num_entries = 1;

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
 * So although the vendor is identified, the format of the data isn't specified
 * so we can't actually resolve the suboption to an attribute.
 *
 * To get around that, we create an attribute with a vendor matching the
 * enterprise number, and attr 0.
 *
 * How the suboption data is then processed, is dependent on what type
 * \<iana\>.0 is defined as in the dictionary.
 *
 * @param[in,out] tlv to decode. *tlv will be set to the head of the list of suboptions and original will be freed.
 * @param[in] ctx context to alloc new attributes in.
 * @param[in] data to parse.
 * @param[in] len length of data to parse.
 */
static int fr_dhcp_decode_vsa(VALUE_PAIR **tlv, TALLOC_CTX *ctx, uint8_t const *data, size_t len)
{
	uint8_t const *p, *q;
	vp_cursor_t cursor;

	VALUE_PAIR *head;

	if (len < 4) goto malformed;

	p = data;
	q = p + len;
	while (p < q) {
		if (p + 5 >= q) goto malformed;
		p += sizeof(uint32_t);
		p += p[0];

		/*
		 *	Check if length > the length of the buffer we have left
		 */
		if (p >= q) goto malformed;
		p++;
	}

	head = NULL;
	fr_cursor_init(&cursor, &head);

	/*
	 *	Now we know its sane, start decoding!
	 */
	p = data;
	while (p < q) {
		uint32_t vendor;
		DICT_ATTR const *da;
		VALUE_PAIR *vp;

		vendor = ntohl(*((uint32_t const *) p));
		/*
		 *	This is pretty much all we can do.  RFC 4243 doesn't specify
		 *	an attribute field, so it's up to vendors to figure out how
		 *	they want to encode their attributes.
		 */
		da = dict_attrbyvalue(0, vendor);
		if (!da) {
			da = dict_attrunknown(0, vendor, true);
			if (!da) {
				pairfree(&head);
				goto malformed;
			}
		}
		vp = pairalloc(ctx, da);
		if (!vp) {
			pairfree(&head);
			return -1;
		}
		vp->op = T_OP_ADD;

		if (fr_dhcp_attr2vp(&vp, ctx, p + 5, p[4]) < 0) {
			pairfree(&head);
			return -1;
		}

		fr_cursor_merge(&cursor, vp);

		p += 4 + 1 + p[4];	/* vendor id (4) + len (1) + vsa len (n) */
	}

	/*
	 *	The caller allocated TLV, if decoding it generated additional
	 *	attributes, we now need to free it, and write the HEAD of our
	 *	new list of attributes in its place.
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
	(*tlv)->vp_tlv = talloc_array(*tlv, uint8_t, len);
	if (!(*tlv)->vp_tlv) {
		fr_strerror_printf("No memory");
		return -1;
	}
	memcpy((*tlv)->vp_tlv, data, len);
	(*tlv)->length = len;

	return 0;
}

/** Decode DHCP suboptions
 *
 * @param[in,out] tlv to decode. *tlv will be set to the head of the list of suboptions and original will be freed.
 * @param[in] ctx context to alloc new attributes in.
 * @param[in] data to parse.
 * @param[in] len length of data to parse.
 */
static int fr_dhcp_decode_suboption(VALUE_PAIR **tlv, TALLOC_CTX *ctx, uint8_t const *data, size_t len)
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
			da = dict_attrunknown(attr, (*tlv)->da->vendor, true);
			if (!da) {
				pairfree(&head);
				return -1;
			}
		}

		a_len = p[1];
		a_p = p + 2;
		num_entries = fr_dhcp_array_members(&a_len, da);
		for (i = 0; i < num_entries; i++) {
			vp = pairalloc(ctx, da);
			if (!vp) {
				pairfree(&head);
				return -1;
			}
			vp->op = T_OP_ADD;

			if (fr_dhcp_attr2vp(&vp, ctx, a_p, a_len) < 0) {
				pairfree(&head);
				goto malformed;
			}
			fr_cursor_merge(&cursor, vp);

			a_p += a_len;
		}
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
	(*tlv)->vp_tlv = talloc_array(*tlv, uint8_t, len);
	if (!(*tlv)->vp_tlv) {
		fr_strerror_printf("No memory");
		return -1;
	}
	memcpy((*tlv)->vp_tlv, data, len);
	(*tlv)->length = len;

	return 0;
}

/*
 *	Decode ONE value into a VP
 */
static int fr_dhcp_attr2vp(VALUE_PAIR **vp_p, TALLOC_CTX *ctx, uint8_t const *data, size_t len)
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
		vp->length = 4;
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
			pairstrncpy(vp, (char const *)p, q - p);
			break;
		}

		/*
		 *	Initialise the cursor as we may be inserting
		 *	multiple additional VPs
		 */
		fr_cursor_init(&cursor, vp_p);
		for (;;) {
			q = memchr(p, '\0', q - p);
			/* Malformed but recoverable */
			if (!q) q = end;

			pairstrncpy(vp, (char const *)p, q - p);
			p = q + 1;

			/* Need another VP for the next round */
			if (p < end) {
				vp = pairalloc(ctx, vp->da);
				if (!vp) {
					pairfree(vp_p);
					return -1;
				}
				fr_cursor_insert(&cursor, vp);
				continue;
			}
			break;
		}
	}
		break;

	case PW_TYPE_ETHERNET:
		memcpy(vp->vp_ether, data, sizeof(vp->vp_ether));
		vp->length = sizeof(vp->vp_ether);
		break;

	/*
	 *	Value doesn't match up with attribute type, overwrite the
	 *	vp's original DICT_ATTR with an unknown one.
	 */
	raw:
		if (pair2unknown(vp) < 0) return -1;

	case PW_TYPE_OCTETS:
		if (len > 255) return -1;
		pairmemcpy(vp, data, len);
		break;

	/*
	 *	For option 82 et al...
	 */
	case PW_TYPE_TLV:
		return fr_dhcp_decode_suboption(vp_p, ctx, data, len);

	/*
	 *	For option 82.9
	 */
	case PW_TYPE_VSA:
		return fr_dhcp_decode_vsa(vp_p, ctx, data, len);

	default:
		fr_strerror_printf("Internal sanity check %d %d", vp->da->type, __LINE__);
		return -1;
	} /* switch over type */

	vp->length = len;
	return 0;
}

/** Decode DHCP options
 *
 * @param[in,out] out Where to write the decoded options.
 * @param[in] ctx context to alloc new attributes in.
 * @param[in] data to parse.
 * @param[in] len of data to parse.
 */
ssize_t fr_dhcp_decode_options(VALUE_PAIR **out, TALLOC_CTX *ctx, uint8_t const *data, size_t len)
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
		 *	Unknown attribute, create an octets type
		 *	attribute with the contents of the sub-option.
		 */
		da = dict_attrbyvalue(p[0], DHCP_MAGIC_VENDOR);
		if (!da) {
			da = dict_attrunknown(p[0], DHCP_MAGIC_VENDOR, true);
			if (!da) {
				pairfree(out);
				return -1;
			}
			vp = pairalloc(ctx, da);
			if (!vp) {
				pairfree(out);
				return -1;
			}
			pairmemcpy(vp, a_p, a_len);
			fr_cursor_insert(&cursor, vp);

			goto next;
		}

		/*
		 *	Array type sub-option create a new VALUE_PAIR
		 *	for each array element.
		 */
		num_entries = fr_dhcp_array_members(&a_len, da);
		for (i = 0; i < num_entries; i++) {
			vp = pairalloc(ctx, da);
			if (!vp) {
				pairfree(out);
				return -1;
			}
			vp->op = T_OP_ADD;

			if (fr_dhcp_attr2vp(&vp, ctx, a_p, a_len) < 0) {
				pairfree(&vp);
				pairfree(out);
				return -1;
			}
			fr_cursor_insert(&cursor, vp);

			for (vp = fr_cursor_current(&cursor);
			     vp;
			     vp = fr_cursor_next(&cursor)) {
				debug_pair(vp);
			}
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
	VALUE_PAIR *maxms, *mtu;

	fr_cursor_init(&cursor, &head);
	p = packet->data;

	if ((fr_debug_flag > 2) && fr_log_fp) {
		for (i = 0; i < packet->data_len; i++) {
			if ((i & 0x0f) == 0x00) fprintf(fr_log_fp, "%d: ", (int) i);
			fprintf(fr_log_fp, "%02x ", packet->data[i]);
			if ((i & 0x0f) == 0x0f) fprintf(fr_log_fp, "\n");
		}
		fprintf(fr_log_fp, "\n");
	}

	if (packet->data[1] != 1) {
		fr_strerror_printf("Packet is not Ethernet: %u",
		      packet->data[1]);
		return -1;
	}

	/*
	 *	Decode the header.
	 */
	for (i = 0; i < 14; i++) {
		char *q;

		vp = pairmake(packet, NULL, dhcp_header_names[i], NULL, T_OP_EQ);
		if (!vp) {
			char buffer[256];
			strlcpy(buffer, fr_strerror(), sizeof(buffer));
			fr_strerror_printf("Cannot decode packet due to internal error: %s", buffer);
			pairfree(&head);
			return -1;
		}

		/*
		 *	If chaddr does != 6 bytes it's probably not ethernet, and we should store
		 *	it as an opaque type (octets).
		 */
		if ((i == 11) && (packet->data[1] == 1) && (packet->data[2] != sizeof(vp->vp_ether))) {
			DICT_ATTR const *da = dict_attrunknown(vp->da->attr, vp->da->vendor, true);
			if (!da) {
				return -1;
			}
			vp->da = da;
		}

		switch (vp->da->type) {
		case PW_TYPE_BYTE:
			vp->vp_byte = p[0];
			vp->length = 1;
			break;

		case PW_TYPE_SHORT:
			vp->vp_short = (p[0] << 8) | p[1];
			vp->length = 2;
			break;

		case PW_TYPE_INTEGER:
			memcpy(&vp->vp_integer, p, 4);
			vp->vp_integer = ntohl(vp->vp_integer);
			vp->length = 4;
			break;

		case PW_TYPE_IPV4_ADDR:
			memcpy(&vp->vp_ipaddr, p, 4);
			vp->length = 4;
			break;

		case PW_TYPE_STRING:
			vp->vp_strvalue = q = talloc_array(vp, char, dhcp_header_sizes[i] + 1);
			vp->type = VT_DATA;
			memcpy(q, p, dhcp_header_sizes[i]);
			q[dhcp_header_sizes[i]] = '\0';
			vp->length = strlen(vp->vp_strvalue);
			if (vp->length == 0) {
				pairfree(&vp);
			}
			break;

		case PW_TYPE_OCTETS:
			pairmemcpy(vp, p, packet->data[2]);
			break;

		case PW_TYPE_ETHERNET:
			memcpy(vp->vp_ether, p, sizeof(vp->vp_ether));
			vp->length = sizeof(vp->vp_ether);
			break;

		default:
			fr_strerror_printf("BAD TYPE %d", vp->da->type);
			pairfree(&vp);
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

		if (fr_dhcp_decode_options(&options, packet, packet->data + 240, packet->data_len - 240) < 0) {
			return -1;
		}

		if (options) fr_cursor_merge(&cursor, options);
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
		vp = pairfind(head, 256, DHCP_MAGIC_VENDOR, TAG_ANY);
		if (vp && vp->vp_integer == 3) {
			/*
			 *	Vendor is "MSFT 98"
			 */
			vp = pairfind(head, 63, DHCP_MAGIC_VENDOR, TAG_ANY);
			if (vp && (strcmp(vp->vp_strvalue, "MSFT 98") == 0)) {
				vp = pairfind(head, 262, DHCP_MAGIC_VENDOR, TAG_ANY);

				/*
				 *	Reply should be broadcast.
				 */
				if (vp) vp->vp_integer |= 0x8000;
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
	maxms = pairfind(packet->vps, 57, DHCP_MAGIC_VENDOR, TAG_ANY);
	mtu = pairfind(packet->vps, 26, DHCP_MAGIC_VENDOR, TAG_ANY);

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

	if (fr_debug_flag) fflush(stdout);

	return 0;
}


int8_t fr_dhcp_attr_cmp(void const *a, void const *b)
{
	VALUE_PAIR const *my_a = a;
	VALUE_PAIR const *my_b = b;

	VERIFY_VP(my_a);
	VERIFY_VP(my_b);

	/*
	 *	DHCP-Message-Type is first, for simplicity.
	 */
	if ((my_a->da->attr == 53) && (my_b->da->attr != 53)) return -1;

	/*
	 *	Relay-Agent is last
	 */
	if ((my_a->da->attr == 82) && (my_b->da->attr != 82)) return 1;

	if (my_a->da->attr < my_b->da->attr) return -1;
	if (my_a->da->attr > my_b->da->attr) return 1;

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
static ssize_t fr_dhcp_vp2attr(uint8_t *out, size_t outlen, VALUE_PAIR *vp)
{
	uint32_t lvalue;
	uint8_t *p = out;

	if (outlen < vp->length) {
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
		memcpy(p, &vp->vp_ether, 6);
		break;

	case PW_TYPE_STRING:
		memcpy(p, vp->vp_strvalue, vp->length);
		break;

	case PW_TYPE_TLV:	/* FIXME: split it on 255? */
		memcpy(p, vp->vp_tlv, vp->length);
		break;

	case PW_TYPE_OCTETS:
		memcpy(p, vp->vp_octets, vp->length);
		break;

	default:
		fr_strerror_printf("Unsupported option type %d", vp->da->type);
		return -2;
	}

	return vp->length;
}

/** Create a new TLV attribute from multiple sub options
 *
 * @param[in,out] ctx to allocate new attribute in.
 * @param[in,out] cursor should be set to the start of the list of TLV attributes.
 *   Will be advanced to the first non-TLV attribute.
 * @return attribute holding the concatenation of the values of the sub options.
 */
static VALUE_PAIR *fr_dhcp_vp2suboption(TALLOC_CTX *ctx, vp_cursor_t *cursor)
{
	ssize_t length;
	unsigned int parent; 	/* Parent attribute of suboption */
	uint8_t attr = 0;
	uint8_t *p, *opt_len = NULL;
	vp_cursor_t to_pack;
	VALUE_PAIR *vp, *tlv;

#define SUBOPTION_PARENT(_x) (_x & 0xffff00ff)
#define SUBOPTION_ATTR(_x) ((_x & 0xff00) >> 8)

	vp = fr_cursor_current(cursor);
	if (!vp) return NULL;

	parent = SUBOPTION_PARENT(vp->da->attr);
	tlv = paircreate(ctx, parent, DHCP_MAGIC_VENDOR);
	if (!tlv) return NULL;

	fr_cursor_copy(&to_pack, cursor);

	/*
	 *  Loop over TLVs to determine how much memory we need to allocate
	 *
	 *  We advanced the cursor we were passed, so if we fail encoding,
	 *  the cursor is at the right position for the next potentially
	 *  encodable attr.
	 */
	for (vp = fr_cursor_current(cursor);
	     vp && vp->da->flags.is_tlv && !vp->da->flags.extended && (SUBOPTION_PARENT(vp->da->attr) == parent);
	     vp = fr_cursor_next(cursor)) {
		/*
		 *  If it's not an array type or is an array type, but is not the same
		 *  as the previous attribute, we add 2 for the additional sub-option
		 *  header bytes.
		 */
		if (!vp->da->flags.array || (SUBOPTION_ATTR(vp->da->attr) != attr)) {
			attr = SUBOPTION_ATTR(vp->da->attr);
			tlv->length += 2;
		}
		tlv->length += vp->length;
	}

	tlv->vp_tlv = talloc_zero_array(tlv, uint8_t, tlv->length);
	if (!tlv->vp_tlv) {
		talloc_free(tlv);
		return NULL;
	}
	p = tlv->vp_tlv;

	attr = 0;
	for (vp = fr_cursor_current(&to_pack);
	     vp && vp->da->flags.is_tlv && !vp->da->flags.extended && (SUBOPTION_PARENT(vp->da->attr) == parent);
	     vp = fr_cursor_next(&to_pack)) {
		if (SUBOPTION_ATTR(vp->da->attr) == 0) {
			fr_strerror_printf("Invalid attribute number 0");
			return NULL;
		}

		/* Don't write out the header, were packing array options */
		if (!vp->da->flags.array || (attr != SUBOPTION_ATTR(vp->da->attr))) {
			attr = SUBOPTION_ATTR(vp->da->attr);
			*p++ = attr;
			opt_len = p++;
		}

		length = fr_dhcp_vp2attr(p, (tlv->vp_tlv + tlv->length) - p, vp);
		if ((length < 0) || (length > 255)) {
			talloc_free(tlv);
			return NULL;
		}

		fr_assert(opt_len);
		*opt_len += length;
		p += length;
	};

	return tlv;
}

/** Encode a DHCP option and any sub-options.
 *
 * @param out Where to write encoded DHCP attributes.
 * @param outlen Length of out buffer.
 * @param ctx to use for any allocated memory.
 * @param cursor with current VP set to the option to be encoded. Will be advanced to the next option to encode.
 * @return > 0 length of data written, < 0 error, 0 not valid option (skipping).
 */
ssize_t fr_dhcp_encode_option(uint8_t *out, size_t outlen, TALLOC_CTX *ctx, vp_cursor_t *cursor)
{
	VALUE_PAIR *vp;
	DICT_ATTR const *previous;
	uint8_t *opt_len, *p = out;
	size_t freespace = outlen;
	ssize_t len;

	vp = fr_cursor_current(cursor);
	if (!vp) return -1;

	if (vp->da->vendor != DHCP_MAGIC_VENDOR) goto next; /* not a DHCP option */
	if (vp->da->attr == 53) goto next; /* already done */
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
		VALUE_PAIR *tlv = NULL;

		/* Sub option */
		if (vp->da->flags.is_tlv) {
			/*
			 *  Coalesce TLVs into one sub-option.
			 *  Cursor will be advanced to next non-TLV attribute.
			 */
			tlv = vp = fr_dhcp_vp2suboption(ctx, cursor);

			/*
			 *  Skip if there's an issue coalescing the sub-options.
			 *  Cursor will still have been advanced to next non-TLV attribute.
			 */
			if (!tlv) return 0;
		/*
		 *  If not calling fr_dhcp_vp2suboption() advance the cursor, so fr_cursor_current()
		 *  returns the next attribute.
		 */
		} else {
			fr_cursor_next(cursor);
		}

		if ((*opt_len + vp->length) > 255) {
			fr_strerror_printf("Skipping \"%s\": Option splitting not supported "
					   "(option > 255 bytes)", vp->da->name);
			talloc_free(tlv);
			return 0;
		}

		len = fr_dhcp_vp2attr(p, freespace, vp);
		talloc_free(tlv);
		if (len < 0) {
			/* Failed encoding option */
			return len;
		}

		p += len;
		*opt_len += len;
		freespace -= len;

		previous = vp->da;
	} while ((vp = fr_cursor_current(cursor)) && (previous == vp->da) && vp->da->flags.array);

	return p - out;
}

int fr_dhcp_encode(RADIUS_PACKET *packet)
{
	unsigned int i;
	uint8_t *p;
	vp_cursor_t cursor;
	VALUE_PAIR *vp;
	uint32_t lvalue;
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
	if ((vp = pairfind(packet->vps, 260, DHCP_MAGIC_VENDOR, TAG_ANY))) {
		packet->id = vp->vp_integer;
	} else {
		packet->id = fr_rand();
	}

#ifndef NDEBUG
	if ((packet->code >= PW_DHCP_DISCOVER) &&
	    (packet->code <= PW_DHCP_INFORM)) {
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
	vp = pairfind(packet->vps, 57, DHCP_MAGIC_VENDOR, TAG_ANY);
	if (vp && (vp->vp_integer > mms)) {
		mms = vp->vp_integer;

		if (mms > MAX_PACKET_SIZE) mms = MAX_PACKET_SIZE;
	}
#endif

	vp = pairfind(packet->vps, 256, DHCP_MAGIC_VENDOR, TAG_ANY);
	if (vp) {
		*p++ = vp->vp_integer & 0xff;
	} else {
		*p++ = 1;	/* client message */
	}

	/* DHCP-Hardware-Type */
	if ((vp = pairfind(packet->vps, 257, DHCP_MAGIC_VENDOR, TAG_ANY))) {
		*p++ = vp->vp_integer & 0xFF;
	} else {
		*p++ = 1;		/* hardware type = ethernet */
	}

	/* DHCP-Hardware-Address-Length */
	if ((vp = pairfind(packet->vps, 258, DHCP_MAGIC_VENDOR, TAG_ANY))) {
		*p++ = vp->vp_integer & 0xFF;
	} else {
		*p++ = 6;		/* 6 bytes of ethernet */
	}

	/* DHCP-Hop-Count */
	if ((vp = pairfind(packet->vps, 259, DHCP_MAGIC_VENDOR, TAG_ANY))) {
		*p = vp->vp_integer & 0xff;
	}
	p++;

	/* DHCP-Transaction-Id */
	lvalue = htonl(packet->id);
	memcpy(p, &lvalue, 4);
	p += 4;

	/* DHCP-Number-of-Seconds */
	if ((vp = pairfind(packet->vps, 261, DHCP_MAGIC_VENDOR, TAG_ANY))) {
		lvalue = htonl(vp->vp_integer);
		memcpy(p, &lvalue, 2);
	}
	p += 2;

	/* DHCP-Flags */
	if ((vp = pairfind(packet->vps, 262, DHCP_MAGIC_VENDOR, TAG_ANY))) {
		lvalue = htons(vp->vp_integer);
		memcpy(p, &lvalue, 2);
	}
	p += 2;

	/* DHCP-Client-IP-Address */
	if ((vp = pairfind(packet->vps, 263, DHCP_MAGIC_VENDOR, TAG_ANY))) {
		memcpy(p, &vp->vp_ipaddr, 4);
	}
	p += 4;

	/* DHCP-Your-IP-address */
	if ((vp = pairfind(packet->vps, 264, DHCP_MAGIC_VENDOR, TAG_ANY))) {
		lvalue = vp->vp_ipaddr;
	} else {
		lvalue = htonl(INADDR_ANY);
	}
	memcpy(p, &lvalue, 4);
	p += 4;

	/* DHCP-Server-IP-Address */
	vp = pairfind(packet->vps, 265, DHCP_MAGIC_VENDOR, TAG_ANY);

	/* DHCP-DHCP-Server-Identifier */
	if (!vp && (vp = pairfind(packet->vps, 54, DHCP_MAGIC_VENDOR, TAG_ANY))) {
		lvalue = vp->vp_ipaddr;
	} else {
		lvalue = htonl(INADDR_ANY);
	}
	memcpy(p, &lvalue, 4);
	p += 4;

	/*
	 *	DHCP-Gateway-IP-Address
	 */
	if ((vp = pairfind(packet->vps, 266, DHCP_MAGIC_VENDOR, TAG_ANY))) {
		lvalue = vp->vp_ipaddr;
	} else {
		lvalue = htonl(INADDR_ANY);
	}
	memcpy(p, &lvalue, 4);
	p += 4;

	/* DHCP-Client-Hardware-Address */
	if ((vp = pairfind(packet->vps, 267, DHCP_MAGIC_VENDOR, TAG_ANY))) {
		if (vp->length == sizeof(vp->vp_ether)) {
			memcpy(p, vp->vp_ether, vp->length);
		} /* else ignore it */
	}
	p += DHCP_CHADDR_LEN;

	/* DHCP-Server-Host-Name */
	if ((vp = pairfind(packet->vps, 268, DHCP_MAGIC_VENDOR, TAG_ANY))) {
		if (vp->length > DHCP_SNAME_LEN) {
			memcpy(p, vp->vp_strvalue, DHCP_SNAME_LEN);
		} else {
			memcpy(p, vp->vp_strvalue, vp->length);
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
	vp = pairfind(packet->vps, 269, DHCP_MAGIC_VENDOR, TAG_ANY);
	if (vp) {
		if (vp->length > DHCP_FILE_LEN) {
			memcpy(p, vp->vp_strvalue, DHCP_FILE_LEN);
		} else {
			memcpy(p, vp->vp_strvalue, vp->length);
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
	if (fr_debug_flag > 1) {
		uint8_t *pp = p;

		p = packet->data;

		for (i = 0; i < 14; i++) {
			char *q;

			vp = pairmake(packet, NULL,
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
				vp->length = strlen(vp->vp_strvalue);
				break;

			case PW_TYPE_OCTETS: /* only for Client HW Address */
				pairmemcpy(vp, p, packet->data[2]);
				break;

			case PW_TYPE_ETHERNET: /* only for Client HW Address */
				memcpy(vp->vp_ether, p, sizeof(vp->vp_ether));
				break;

			default:
				fr_strerror_printf("Internal sanity check failed %d %d", vp->da->type, __LINE__);
				pairfree(&vp);
				break;
			}

			p += dhcp_header_sizes[i];

			debug_pair(vp);
			pairfree(&vp);
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
	pairsort(&packet->vps, fr_dhcp_attr_cmp);
	fr_cursor_init(&cursor, &packet->vps);

	/*
	 *  Each call to fr_dhcp_encode_option will encode one complete DHCP option,
	 *  and sub options.
	 */
	while ((vp = fr_cursor_current(&cursor))) {
		len = fr_dhcp_encode_option(p, packet->data_len - (p - packet->data), packet, &cursor);
		if (len < 0) break;
		if (len > 0) debug_pair(vp);
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

	if ((fr_debug_flag > 2) && fr_log_fp) {
		fprintf(fr_log_fp, "DHCP Sending %zu bytes\n", packet->data_len);
		for (i = 0; i < packet->data_len; i++) {
			if ((i & 0x0f) == 0x00) fprintf(fr_log_fp, "%d: ", i);
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

	if (macaddr->length > sizeof(req.arp_ha.sa_data)) {
		fr_strerror_printf("arp sa_data field too small (%zu octets) to contain chaddr (%zu octets)",
				   sizeof(req.arp_ha.sa_data), macaddr->length);
		return -1;
	}

	memset(&req, 0, sizeof(req));
	sin = (struct sockaddr_in *) &req.arp_pa;
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = ip->vp_ipaddr;

	strlcpy(req.arp_dev, interface, sizeof(req.arp_dev));

	if (macaddr->da->type == PW_TYPE_ETHERNET) {
		memcpy(&req.arp_ha.sa_data, &macaddr->vp_ether, sizeof(macaddr->vp_ether));
	} else {
		memcpy(&req.arp_ha.sa_data, macaddr->vp_octets, macaddr->length);
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
