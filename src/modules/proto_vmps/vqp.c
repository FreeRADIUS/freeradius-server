/*
 * vqp.c	Functions to send/receive VQP packets.
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
 * Copyright 2007 Alan DeKok <aland@deployingradius.com>
 */

RCSID("$Id$")

#include <freeradius-devel/libradius.h>
#include <freeradius-devel/udp.h>

#include "vqp.h"

#define MAX_VMPS_LEN (FR_MAX_STRING_LEN - 1)

/* @todo: this is a hack */
#  define debug_pair(vp)	do { if (fr_debug_lvl && fr_log_fp) { \
					fr_pair_fprint(fr_log_fp, vp); \
				     } \
				} while(0)
/*
 *  http://www.openbsd.org/cgi-bin/cvsweb/src/usr.sbin/tcpdump/print-vqp.c
 *
 *  Some of how it works:
 *
 *  http://www.hackingciscoexposed.com/pdf/chapter12.pdf
 *
 * VLAN Query Protocol (VQP)
 *
 *    0		   1		   2		   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |    Version    |    Opcode     | Response Code |  Data Count   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |			 Transaction ID			|
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |			    Type (1)			   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |	     Length	    |	    Data	       /
 *   /							       /
 *   /							       /
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |			    Type (n)			   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |	     Length	    |	    Data	       /
 *   /							       /
 *   /							       /
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * VQP is layered over UDP.  The default destination port is 1589.
 *
 */
#define VQP_HDR_LEN (8)
#define VQP_VERSION (1)
#define VQP_MAX_ATTRIBUTES (12)

static size_t const fr_vqp_attr_sizes[FR_TYPE_MAX + 1][2] = {
	[FR_TYPE_INVALID]	= {~0, 0},	//!< Ensure array starts at 0 (umm?)

	[FR_TYPE_STRING]	= {0, ~0},
	[FR_TYPE_OCTETS]	= {0, ~0},

	[FR_TYPE_IPV4_ADDR]	= {4, 4},
	[FR_TYPE_ETHERNET]	= {6, 6},

	[FR_TYPE_MAX]		= {~0, 0}	//!< Ensure array covers all types.
};

static ssize_t vqp_recv_header(int sockfd)
{
	ssize_t			data_len;
	uint8_t			header[VQP_HDR_LEN];

	/*
	 *	Read the length of the packet, from the packet.
	 *	This lets us allocate the buffer to use for
	 *	reading the rest of the packet.
	 */
	data_len = udp_recv_peek(sockfd, header, sizeof(header), UDP_FLAGS_PEEK, NULL, NULL);
	if (data_len < 0) return -1;

	/*
	 *	Too little data is available, discard the packet.
	 */
	if (data_len < VQP_HDR_LEN) {
		(void) udp_recv_discard(sockfd);
		return 0;
	}

	/*
	 *	Invalid version, packet type, or too many
	 *	attributes.  Die.
	 */
	if ((header[0] != VQP_VERSION) ||
	    (header[1] < 1) ||
	    (header[1] > 4) ||
	    (header[3] > VQP_MAX_ATTRIBUTES)) {
		(void) udp_recv_discard(sockfd);
		return 0;
	}

	/*
	 *	Hard-coded maximum size.  Because the header doesn't
	 *	have a packet length.
	 */
	return (12 * (4 + 4 + MAX_VMPS_LEN));
}

RADIUS_PACKET *vqp_recv(TALLOC_CTX *ctx, int sockfd)
{
	uint8_t		*ptr;
	ssize_t		data_len;
	uint32_t	id;
	int		attrlen;
	RADIUS_PACKET	*packet;

	data_len = vqp_recv_header(sockfd);
	if (data_len < 0) {
		fr_strerror_printf("Error receiving packet: %s", fr_syserror(errno));
		return NULL;
	}

	/*
	 *	Allocate the new request data structure
	 */
	packet = fr_radius_alloc(ctx, false);
	if (!packet) {
		fr_strerror_printf("out of memory");
		return NULL;
	}

	packet->data_len = data_len;
	packet->data = talloc_array(packet, uint8_t, data_len);
	if (!packet->data_len) {
		fr_radius_free(&packet);
		return NULL;
	}

	data_len = udp_recv(sockfd, packet->data, packet->data_len, 0,
			    &packet->src_ipaddr, &packet->src_port,
			    &packet->dst_ipaddr, &packet->dst_port,
			    &packet->if_index, &packet->timestamp);
	if (data_len <= 0) {
		fr_radius_free(&packet);
		return NULL;
	}

	/*
	 *	Save the real length of the packet.
	 */
	packet->data_len = data_len;

	/*
	 *	Set up the fields in the packet.
	 */
	packet->sockfd = sockfd;
	packet->vps = NULL;

	packet->code = packet->data[1];
	memcpy(&id, packet->data + 4, 4);
	packet->id = ntohl(id);

	if (packet->data_len == VQP_HDR_LEN) {
		return packet;
	}

	/*
	 *	Skip the header.
	 */
	ptr = packet->data + VQP_HDR_LEN;
	data_len = packet->data_len - VQP_HDR_LEN;

	while (data_len > 0) {
		if (data_len < 7) {
			fr_strerror_printf("Packet contains malformed attribute");
			fr_radius_free(&packet);
			return NULL;
		}

		/*
		 *	Attributes are 4 bytes
		 *	0x00000c01 ... 0x00000c08
		 */
		if ((ptr[0] != 0) || (ptr[1] != 0) ||
		    (ptr[2] != 0x0c) || (ptr[3] < 1) || (ptr[3] > 8)) {
			fr_strerror_printf("Packet contains invalid attribute");
			fr_radius_free(&packet);
			return NULL;
		}

		/*
		 *	Length is 2 bytes
		 *
		 *	We support short lengths, as there's no reason
		 *	for bigger lengths to exist... admins won't be
		 *	typing in a 32K vlan name.
		 *
		 *	It's OK for ethernet frames to be longer.
		 */
		if ((ptr[3] != 5) &&
		    ((ptr[4] != 0) || (ptr[5] > MAX_VMPS_LEN))) {
			fr_strerror_printf("Packet contains attribute with invalid length %02x %02x", ptr[4], ptr[5]);
			fr_radius_free(&packet);
			return NULL;
		}

		attrlen = (ptr[4] << 8) | ptr[5];
		ptr += 6 + attrlen;
		data_len -= (6 + attrlen);
	}

	return packet;
}

/*
 *	We do NOT  mirror the old-style RADIUS code  that does encode,
 *	sign && send in one function.  For VQP, the caller MUST perform
 *	each task manually, and separately.
 */
int vqp_send(RADIUS_PACKET *packet)
{
	if (!packet || !packet->data || (packet->data_len < VQP_HDR_LEN)) return -1;

	/*
	 *	Don't print out the attributes, they were printed out
	 *	when it was encoded.
	 */

	/*
	 *	And send it on it's way.
	 */
	return udp_send(packet->sockfd, packet->data, packet->data_len, 0,
			&packet->src_ipaddr, packet->src_port, packet->if_index,
			&packet->dst_ipaddr, packet->dst_port);
}


int vqp_decode(RADIUS_PACKET *packet)
{
	uint8_t		*ptr, *end;
	int		attr;
	size_t		attr_len;
	vp_cursor_t	cursor;
	VALUE_PAIR	*vp;

	if (!packet || !packet->data) return -1;

	if (packet->data_len < VQP_HDR_LEN) return -1;

	fr_pair_cursor_init(&cursor, &packet->vps);
	vp = fr_pair_afrom_num(packet, 0, PW_VQP_PACKET_TYPE);
	if (!vp) {
		fr_strerror_printf("No memory");
		return -1;
	}
	vp->vp_uint32 = packet->data[1];
	vp->vp_tainted = true;
	debug_pair(vp);
	fr_pair_cursor_append(&cursor, vp);

	vp = fr_pair_afrom_num(packet, 0, PW_VQP_ERROR_CODE);
	if (!vp) {
		fr_strerror_printf("No memory");
		return -1;
	}
	vp->vp_uint32 = packet->data[2];
	vp->vp_tainted = true;
	debug_pair(vp);
	fr_pair_cursor_append(&cursor, vp);

	vp = fr_pair_afrom_num(packet, 0, PW_VQP_SEQUENCE_NUMBER);
	if (!vp) {
		fr_strerror_printf("No memory");
		return -1;
	}
	vp->vp_uint32 = packet->id; /* already set by vqp_recv */
	vp->vp_tainted = true;
	debug_pair(vp);
	fr_pair_cursor_append(&cursor, vp);

	ptr = packet->data + VQP_HDR_LEN;
	end = packet->data + packet->data_len;

	/*
	 *	Note that vqp_recv() MUST ensure that the packet is
	 *	formatted in a way we expect, and that vqp_recv() MUST
	 *	be called before vqp_decode().
	 */
	while (ptr < end) {
		attr = (ptr[2] << 8) | ptr[3];
		attr_len = (ptr[4] << 8) | ptr[5];
		ptr += 6;

		/*
		 *	Hack to get the dictionaries to work correctly.
		 */
		attr |= 0x2000;
		vp = fr_pair_afrom_num(packet, 0, attr);
		if (!vp) {
			fr_pair_list_free(&packet->vps);

			fr_strerror_printf("No memory");
			return -1;
		}

		switch (vp->vp_type) {
		case FR_TYPE_ETHERNET:
			if (attr_len != fr_vqp_attr_sizes[vp->vp_type][0]) goto unknown;

			memcpy(&vp->vp_ether, ptr, 6);
			break;

		case FR_TYPE_IPV4_ADDR:
			if (attr_len == fr_vqp_attr_sizes[vp->vp_type][0]) {
				memcpy(&vp->vp_ipv4addr, ptr, 4);
				break;
			}

			/*
			 *	Value doesn't match the type we have for the
			 *	valuepair so we must change it's da to an
			 *	unknown attr.
			 */
		unknown:
			fr_pair_to_unknown(vp);
			/* FALL-THROUGH */

		default:
		case FR_TYPE_OCTETS:
			fr_pair_value_memcpy(vp, ptr, attr_len);
			break;

		case FR_TYPE_STRING:
			fr_pair_value_bstrncpy(vp, ptr, attr_len);
			break;
		}
		ptr += attr_len;
		vp->vp_tainted = true;
		debug_pair(vp);
		fr_pair_cursor_append(&cursor, vp);
	}

	/*
	 *	FIXME: Map attributes to Calling-Station-Id, etc...
	 */

	return 0;
}

/*
 *	These are the MUST HAVE contents for a VQP packet.
 *
 *	We don't allow the caller to give less than these, because
 *	it won't work.  We don't encode more than these, because the
 *	clients will ignore it.
 *
 *	FIXME: Be more generous?  Look for CISCO + VQP attributes?
 */
static int contents[5][VQP_MAX_ATTRIBUTES] = {
	{ 0,      0,      0,      0,      0,      0 },
	{ 0x0c01, 0x0c02, 0x0c03, 0x0c04, 0x0c07, 0x0c05 }, /* Join request */
	{ 0x0c03, 0x0c08, 0,      0,      0,      0 },	/* Join Response */
	{ 0x0c01, 0x0c02, 0x0c03, 0x0c04, 0x0c07, 0x0c08 }, /* Reconfirm */
	{ 0x0c03, 0x0c08, 0,      0,      0,      0 }
};

int vqp_encode(RADIUS_PACKET *packet, RADIUS_PACKET *original)
{
	int		i, code, length;
	VALUE_PAIR	*vp;
	uint8_t		*out;
	VALUE_PAIR	*vps[VQP_MAX_ATTRIBUTES];

	if (!packet) {
		fr_strerror_printf("Failed encoding VQP");
		return -1;
	}

	if (packet->data) return 0;


	code = packet->code;
	if (!code) {
		vp = fr_pair_find_by_num(packet->vps, 0, PW_VQP_PACKET_TYPE, TAG_ANY);
		if (!vp) {
			fr_strerror_printf("Failed to find VQP-Packet-Type in response packet");
			return -1;
		}

		code = vp->vp_uint32;
		if ((code < 1) || (code > 4)) {
			fr_strerror_printf("Invalid value %d for VQP-Packet-Type", code);
			return -1;
		}
	}

	length = VQP_HDR_LEN;

	vp = fr_pair_find_by_num(packet->vps, 0, PW_VQP_ERROR_CODE, TAG_ANY);
	if (vp) {
		packet->data = talloc_array(packet, uint8_t, length);
		if (!packet->data) {
			fr_strerror_printf("No memory");
			return -1;
		}
		packet->data_len = length;

		out = packet->data;

		out[0] = VQP_VERSION;
		out[1] = code;

		out[2] = vp->vp_uint32 & 0xff;
		return 0;
	}

	/*
	 *	FIXME: Map attributes from calling-station-Id, etc.
	 *
	 *	Maybe do this via rlm_vqp?  That's probably the
	 *	best place to add the code...
	 */

	memset(vps, 0, sizeof(vps));

	/*
	 *	Determine how long the packet is.
	 */
	for (i = 0; i < VQP_MAX_ATTRIBUTES; i++) {
		if (!contents[code][i]) break;

		vps[i] = fr_pair_find_by_num(packet->vps, 0, contents[code][i] | 0x2000, TAG_ANY);

		/*
		 *	FIXME: Print the name...
		 */
		if (!vps[i]) {
			fr_strerror_printf("Failed to find VQP attribute %02x", contents[code][i]);
			return -1;
		}

		length += 6;	/* header */
		length += fr_vqp_attr_sizes[vps[i]->vp_type][0];
	}

	packet->data = talloc_array(packet, uint8_t, length);
	if (!packet->data) {
		fr_strerror_printf("No memory");
		return -1;
	}
	packet->data_len = length;

	out = packet->data;

	out[0] = VQP_VERSION;
	out[1] = code;
	out[2] = 0;

	/*
	 *	The number of attributes is hard-coded.
	 */
	if ((code == 1) || (code == 3)) {
		uint32_t sequence;

		out[3] = VQP_MAX_ATTRIBUTES;

		sequence = htonl(packet->id);
		memcpy(out + 4, &sequence, 4);
	} else {
		if (!original) {
			fr_strerror_printf("Cannot send VQP response without request");
			return -1;
		}

		/*
		 *	Packet Sequence Number
		 */
		memcpy(out + 4, original->data + 4, 4);

		out[3] = 2;
	}

	out += 8;

	/*
	 *	Encode the VP's.
	 */
	for (i = 0; i < VQP_MAX_ATTRIBUTES; i++) {
		size_t len;

		if (!vps[i]) break;
		if (out >= (packet->data + packet->data_len)) break;

		vp = vps[i];

		debug_pair(vp);

		switch (vp->vp_type) {
		case FR_TYPE_IPV4_ADDR:
			len = fr_vqp_attr_sizes[vp->vp_type][0];
			break;

		case FR_TYPE_ETHERNET:
			len = fr_vqp_attr_sizes[vp->vp_type][0];
			break;

		case FR_TYPE_OCTETS:
		case FR_TYPE_STRING:
			len = vp->vp_length;
			break;

		default:
			return -1;
		}

		/*
		 *	Type.  Note that we look at only the lower 8
		 *	bits, as the upper 8 bits have been hacked.
		 *	See also dictionary.vqp
		 */
		out[0] = 0;
		out[1] = 0;
		out[2] = 0x0c;
		out[3] = vp->da->attr & 0xff;

		/* Length */
		out[4] = 0;
		out[5] = len & 0xff;

		out += 6;

		/* Data */
		switch (vp->vp_type) {
		case FR_TYPE_IPV4_ADDR:
			memcpy(out, &vp->vp_ipv4addr, len);
			out += len;
			break;

		case FR_TYPE_ETHERNET:
			memcpy(out, vp->vp_ether, len);
			out += len;
			break;

		case FR_TYPE_OCTETS:
		case FR_TYPE_STRING:
			memcpy(out, vp->vp_octets, len);
			out += len;
			break;

		default:
			return -1;
		}

	}

	return 0;
}

/** See how big of a packet is in the buffer.
 *
 * Packet is not 'const * const' because we may update data_len, if there's more data
 * in the UDP packet than in the VMPS packet.
 *
 * @param data pointer to the packet buffer
 * @param data_len length of the packet buffer
 * @return
 *	<= 0 packet is bad.
 *      >0 how much of the data is a packet (can be larger than data_len)
 */
ssize_t vqp_packet_size(uint8_t const *data, size_t data_len)
{
	int attributes;
	uint8_t const *ptr, *end;

	if (data_len < VQP_HDR_LEN) return VQP_HDR_LEN;

	/*
	 *	No attributes.
	 */
	if (data[3] == 0) return VQP_HDR_LEN;

	/*
	 *	Too many attributes.  Return an error indicating that
	 *	there's a problem with octet 3.
	 */
	if (data[3] > VQP_MAX_ATTRIBUTES) return -3;

	/*
	 *	Look for attributes.
	 */
	ptr = data + VQP_HDR_LEN;
	attributes = data[3];

	end = data + data_len;

	while (attributes > 0) {
		size_t attr_len;

		/*
		 *	Not enough room for the attribute headers, we
		 *	want at least those.
		 */
		if ((end - ptr) < 6) {
			return 6 * attributes;
		}

		/*
		 *	Length of the data NOT including the header.
		 */
		attr_len = (ptr[4] << 8) | ptr[5];

		ptr += 6 + attr_len;

		/*
		 *	We don't want to read infinite amounts of data.
		 *
		 *	Return an error indicating that there's a
		 *	problem with the final octet
		 */
		if ((ptr - data) > 4096) {
			return -(ptr - data);
		}

		/*
		 *	This attribute has been checked.
		 */
		attributes--;

		/*
		 *	The packet we want is larger than the input
		 *	buffer, so we return the length of the current
		 *	attribute, plus the length of the remaining
		 *	headers.
		 */
		if (ptr > end) return (6 * attributes) + ptr - data;
	}

	/*
	 *	We've reached the end of the packet.
	 */
	return ptr - data;
}
