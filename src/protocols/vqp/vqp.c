/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
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
 *
 * @file src/protocols/vqp/vqp.c
 * @brief Functions to send/receive VQP packets.
 *
 * @copyright 2007 Alan DeKok (aland@deployingradius.com)
 */

RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/util/udp.h>
#include <freeradius-devel/protocol/vmps/vmps.h>

#include "vqp.h"
#include "attrs.h"

#define MAX_VMPS_LEN (FR_MAX_STRING_LEN - 1)

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

char const *fr_vmps_codes[FR_VMPS_MAX_CODE] = {
	[FR_PACKET_TYPE_VALUE_JOIN_REQUEST] = "Join-Request",
	[FR_PACKET_TYPE_VALUE_JOIN_RESPONSE] = "Join-Response",
	[FR_PACKET_TYPE_VALUE_RECONFIRM_REQUEST] = "Reconfirm-Request",
	[FR_PACKET_TYPE_VALUE_RECONFIRM_RESPONSE] = "Reconfirm-Response",
};


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

bool fr_vqp_ok(uint8_t const *packet, size_t *packet_len)
{
	uint8_t	const	*ptr;
	ssize_t		data_len;
	int		attrlen;

	if (*packet_len == VQP_HDR_LEN) return true;

	/*
	 *	Skip the header.
	 */
	ptr = packet + VQP_HDR_LEN;
	data_len = *packet_len - VQP_HDR_LEN;

	while (data_len > 0) {
		if (data_len < 7) {
			fr_strerror_printf("Packet contains malformed attribute");
			false;
		}

		/*
		 *	Attributes are 4 bytes
		 *	0x00000c01 ... 0x00000c08
		 */
		if ((ptr[0] != 0) || (ptr[1] != 0) ||
		    (ptr[2] != 0x0c) || (ptr[3] < 1) || (ptr[3] > 8)) {
			fr_strerror_printf("Packet contains invalid attribute");
			return false;
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
			return false;
		}

		attrlen = (ptr[4] << 8) | ptr[5];
		ptr += 6 + attrlen;
		data_len -= (6 + attrlen);
	}

	/*
	 *	UDP reads may return too much data, so we truncate it.
	 */
	*packet_len = ptr - packet;

	return true;
}

RADIUS_PACKET *vqp_recv(TALLOC_CTX *ctx, int sockfd)
{
	ssize_t		data_len;
	uint32_t	id;
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
		fr_radius_packet_free(&packet);
		return NULL;
	}

	data_len = udp_recv(sockfd, packet->data, packet->data_len, 0,
			    &packet->src_ipaddr, &packet->src_port,
			    &packet->dst_ipaddr, &packet->dst_port,
			    &packet->if_index, &packet->timestamp);
	if (data_len <= 0) {
		fr_radius_packet_free(&packet);
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

	if (!fr_vqp_ok(packet->data, &packet->data_len)) {
		fr_radius_packet_free(&packet);
		return NULL;
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


int fr_vqp_decode(TALLOC_CTX *ctx, uint8_t const *data, size_t data_len, VALUE_PAIR **vps, unsigned int *code)
{
	uint8_t const  	*ptr, *end;
	int		attr;
	size_t		attr_len;
	fr_cursor_t	cursor;
	VALUE_PAIR	*vp;

	if (data_len < VQP_HDR_LEN) return -1;

	fr_cursor_init(&cursor, vps);

	vp = fr_pair_afrom_da(ctx, attr_packet_type);
	if (!vp) {
	oom:
		fr_strerror_printf("Out of Memory");
		return -1;
	}
	vp->vp_uint32 = data[1];
	if (code) *code = data[1];
	vp->vp_tainted = true;
	DEBUG2("&%pP", vp);
	fr_cursor_append(&cursor, vp);

	vp = fr_pair_afrom_da(ctx, attr_error_code);
	if (!vp) goto oom;
	vp->vp_uint32 = data[2];
	vp->vp_tainted = true;
	DEBUG2("&%pP", vp);
	fr_cursor_append(&cursor, vp);

	vp = fr_pair_afrom_da(ctx, attr_sequence_number);
	if (!vp) goto oom;

	memcpy(&vp->vp_uint32, data + 4, 4);
	vp->vp_uint32 = ntohl(vp->vp_uint32);
	vp->vp_tainted = true;
	DEBUG2("&%pP", vp);
	fr_cursor_append(&cursor, vp);

	ptr = data + VQP_HDR_LEN;
	end = data + data_len;

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
		 *	fr_vmps_ok() should have checked this already,
		 *	but it doesn't hurt to do it again.
		 */
		if (attr_len > (size_t) (end - ptr)) {
			fr_strerror_printf("Attribute length exceeds received data");
			goto error;
		}

		/*
		 *	Create the VP.
		 */
		vp = fr_pair_afrom_child_num(ctx, fr_dict_root(dict_vmps), attr);
		if (!vp) {
			fr_strerror_printf("No memory");

		error:
			fr_pair_list_free(vps);
			return -1;
		}

		/*
		 *	Rely on value_box to do the work.
		 *
		 *	@todo - if the attribute is malformed, create a "raw" one.
		 */
		if (fr_value_box_from_network(vp, &vp->data, vp->da->type, vp->da, ptr, attr_len, true) < 0) {
			talloc_free(vp);
			return -1;
		}

		ptr += attr_len;
		vp->vp_tainted = true;
		DEBUG2("&%pP", vp);
		fr_cursor_append(&cursor, vp);
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


ssize_t fr_vmps_encode(uint8_t *buffer, size_t buflen, uint8_t const *original,
		       int code, uint32_t id, VALUE_PAIR *vps)
{
	uint8_t *attr;
	VALUE_PAIR *vp;
	fr_cursor_t cursor;

	if (buflen < 8) {
		fr_strerror_printf("Output buffer is too small for VMPS header.");
		return -1;
	}

	buffer[0] = VQP_VERSION;
	buffer[1] = code;
	buffer[2] = 0;

	/*
	 *	The number of attributes is hard-coded.
	 */
	if ((code == 1) || (code == 3)) {
		uint32_t sequence;

		buffer[3] = VQP_MAX_ATTRIBUTES;

		sequence = htonl(id);
		memcpy(buffer + 4, &sequence, 4);
	} else {
		if (!original) {
			fr_strerror_printf("Cannot send VQP response without request");
			return -1;
		}

		/*
		 *	Packet Sequence Number
		 */
		memcpy(buffer + 4, original + 4, 4);

		buffer[3] = 2;
	}

	attr = buffer + 8;

	/*
	 *	Encode the VP's.
	 */
	fr_cursor_init(&cursor, &vps);
	while ((vp = fr_cursor_current(&cursor))) {
		size_t len;

		if (vp->da->flags.internal) goto next;

		/*
		 *	Skip non-VMPS attributes/
		 */
		if (!((vp->da->attr >= 0x2c01) && (vp->da->attr <= 0x2c08))) goto next;

		if (attr >= (buffer + buflen)) break;

		DEBUG2("&%pP", vp);

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
		 *	If the attribute overflows the buffer, stop.
		 */
		if ((attr + 6 + len) >= (buffer + buflen)) break;

		/*
		 *	Type.  Note that we look at only the lower 8
		 *	bits, as the upper 8 bits have been hacked.
		 *	See also dictionary.vqp
		 */
		attr[0] = 0;
		attr[1] = 0;
		attr[2] = 0x0c;
		attr[3] = vp->da->attr & 0xff;

		/* Length */
		attr[4] = (len >> 8) & 0xff;
		attr[5] = len & 0xff;

		attr += 6;

		/* Data */
		switch (vp->vp_type) {
		case FR_TYPE_IPV4_ADDR:
			memcpy(attr, &vp->vp_ipv4addr, len);
			attr += len;
			break;

		case FR_TYPE_ETHERNET:
			memcpy(attr, vp->vp_ether, len);
			attr += len;
			break;

		case FR_TYPE_OCTETS:
		case FR_TYPE_STRING:
			memcpy(attr, vp->vp_octets, len);
			attr += len;
			break;

		default:
			return -1;
		}

next:
		fr_cursor_next(&cursor);
	}

	return attr - buffer;
}


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
		vp = fr_pair_find_by_da(packet->vps, attr_packet_type, TAG_ANY);
		if (!vp) {
			fr_strerror_printf("Failed to find %s in response packet", attr_packet_type->name);
			return -1;
		}

		code = vp->vp_uint32;
		if ((code < 1) || (code > 4)) {
			fr_strerror_printf("Invalid value %d for %s", code, attr_packet_type->name);
			return -1;
		}
	}

	length = VQP_HDR_LEN;

	vp = fr_pair_find_by_da(packet->vps, attr_error_code, TAG_ANY);
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

		vps[i] = fr_pair_find_by_child_num(packet->vps, fr_dict_root(dict_vmps),
						   contents[code][i], TAG_ANY);

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

		DEBUG2("&%pP", vp);

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

static void print_hex_data(uint8_t const *ptr, int attrlen, int depth)
{
	int i;
	static char const tabs[] = "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t";

	for (i = 0; i < attrlen; i++) {
		if ((i > 0) && ((i & 0x0f) == 0x00))
			fprintf(fr_log_fp, "%.*s", depth, tabs);
		fprintf(fr_log_fp, "%02x ", ptr[i]);
		if ((i & 0x0f) == 0x0f) fprintf(fr_log_fp, "\n");
	}
	if ((i & 0x0f) != 0) fprintf(fr_log_fp, "\n");
}


/** Print a raw VMPS packet as hex.
 *
 */
void fr_vmps_print_hex(FILE *fp, uint8_t const *packet, size_t packet_len)
{
	int length;
	uint8_t const *attr, *end;
	uint32_t id;

	if (packet_len < 8) return;

	fprintf(fp, "  Version:\t\t%u\n", packet[0]);

	if ((packet[1] > 0) && (packet[1] < FR_VMPS_MAX_CODE) && fr_vmps_codes[packet[1]]) {
		fprintf(fp, "  OpCode:\t\t%s\n", fr_vmps_codes[packet[1]]);
	} else {
		fprintf(fp, "  OpCode:\t\t%u\n", packet[1]);
	}

	if ((packet[2] > 0) && (packet[2] < FR_VMPS_MAX_CODE) && fr_vmps_codes[packet[2]]) {
		fprintf(fp, "  OpCode:\t\t%s\n", fr_vmps_codes[packet[2]]);
	} else {
		fprintf(fp, "  OpCode:\t\t%u\n", packet[2]);
	}

	fprintf(fp, "  Data Count:\t\t%u\n", packet[3]);

	memcpy(&id, packet + 4, 4);
	id = ntohl(id);

	fprintf(fp, "  ID:\t%08x\n", id);

	if (packet_len == 8) return;

	for (attr = packet + 8, end = packet + packet_len;
	     attr < end;
	     attr += length) {
		memcpy(&id, attr, 4);
		id = ntohl(id);

		length = (attr[4] << 8) | attr[5];
		if ((attr + length) > end) break;

		fprintf(fp, "\t\t%08x  %04x  ", id, length);

		print_hex_data(attr + 5, length, 3);
	}
}
