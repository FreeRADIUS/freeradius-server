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
 * @file src/protocols/vmps/vmps.c
 * @brief Functions to send/receive VQP packets.
 *
 * @copyright 2007 Alan DeKok (aland@deployingradius.com)
 */

RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/util/dbuff.h>
#include <freeradius-devel/util/udp.h>
#include <freeradius-devel/protocol/vmps/vmps.h>
#include <freeradius-devel/io/test_point.h>

#include "vmps.h"
#include "attrs.h"

/*
 *  http://www.openbsd.org/cgi-bin/cvsweb/src/usr.sbin/tcpdump/print-vqp.c
 *
 *  Some of how it works:
 *
 *  http://www.hackingciscoexposed.com/pdf/chapter12.pdf
 *
 * VLAN Query Protocol (VQP)
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |    Version    |    Opcode     | Response Code |  Data Count   |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                         Transaction ID                        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                            Type (1)                           |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |             Length            |            Data               /
 *  /                                                               /
 *  /                                                               /
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                            Type (n)                           |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |             Length            |            Data               /
 *  /                                                               /
 *  /                                                               /
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * VQP is layered over UDP.  The default destination port is 1589.
 *
 */
char const *fr_vmps_codes[FR_VQP_MAX_CODE] = {
	[FR_PACKET_TYPE_VALUE_JOIN_REQUEST] = "Join-Request",
	[FR_PACKET_TYPE_VALUE_JOIN_RESPONSE] = "Join-Response",
	[FR_PACKET_TYPE_VALUE_RECONFIRM_REQUEST] = "Reconfirm-Request",
	[FR_PACKET_TYPE_VALUE_RECONFIRM_RESPONSE] = "Reconfirm-Response",
};


static size_t const fr_vmps_attr_sizes[FR_TYPE_MAX + 1][2] = {
	[FR_TYPE_INVALID]	= {~0, 0},	//!< Ensure array starts at 0 (umm?)

	[FR_TYPE_STRING]	= {0, ~0},
	[FR_TYPE_OCTETS]	= {0, ~0},

	[FR_TYPE_IPV4_ADDR]	= {4, 4},
	[FR_TYPE_ETHERNET]	= {6, 6},

	[FR_TYPE_MAX]		= {~0, 0}	//!< Ensure array covers all types.
};


bool fr_vmps_ok(uint8_t const *packet, size_t *packet_len)
{
	uint8_t	const	*ptr;
	ssize_t		data_len;
	int		attrlen;

	if (*packet_len == FR_VQP_HDR_LEN) return true;

	/*
	 *	Skip the header.
	 */
	ptr = packet + FR_VQP_HDR_LEN;
	data_len = *packet_len - FR_VQP_HDR_LEN;

	while (data_len > 0) {
		if (data_len < 7) {
			fr_strerror_printf("Packet contains malformed attribute");
			return false;
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
		    ((ptr[4] != 0) || (ptr[5] > 250))) {
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


int fr_vmps_decode(TALLOC_CTX *ctx, uint8_t const *data, size_t data_len, fr_cursor_t *cursor, unsigned int *code)
{
	uint8_t const  	*ptr, *end;
	int		attr;
	size_t		attr_len;
	fr_pair_t	*vp;

	if (data_len < FR_VQP_HDR_LEN) return -1;

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
	fr_cursor_append(cursor, vp);

	vp = fr_pair_afrom_da(ctx, attr_error_code);
	if (!vp) goto oom;
	vp->vp_uint32 = data[2];
	vp->vp_tainted = true;
	DEBUG2("&%pP", vp);
	fr_cursor_append(cursor, vp);

	vp = fr_pair_afrom_da(ctx, attr_sequence_number);
	if (!vp) goto oom;

	memcpy(&vp->vp_uint32, data + 4, 4);
	vp->vp_uint32 = ntohl(vp->vp_uint32);
	vp->vp_tainted = true;
	DEBUG2("&%pP", vp);
	fr_cursor_append(cursor, vp);

	ptr = data + FR_VQP_HDR_LEN;
	end = data + data_len;

	/*
	 *	Note that vmps_recv() MUST ensure that the packet is
	 *	formatted in a way we expect, and that vmps_recv() MUST
	 *	be called before vmps_decode().
	 */
	while (ptr < end) {
		if ((end - ptr) < 6) {
			fr_strerror_printf("Packet is too small. (%ld < 6)", (end - ptr));
			return -1;
		}

		attr = (ptr[2] << 8) | ptr[3];
		attr_len = (ptr[4] << 8) | ptr[5];
		ptr += 6;

		/*
		 *	fr_vmps_ok() should have checked this already,
		 *	but it doesn't hurt to do it again.
		 */
		if (attr_len > (size_t) (end - ptr)) {
			fr_strerror_printf("Attribute length exceeds received data");
			return -1;
		}

		/*
		 *	Create the VP.
		 */
		vp = fr_pair_afrom_child_num(ctx, fr_dict_root(dict_vmps), attr);
		if (!vp) {
			fr_strerror_printf("No memory");
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
		fr_cursor_append(cursor, vp);
	}

	/*
	 *	FIXME: Map attributes to Calling-Station-Id, etc...
	 */

	return data_len;
}

#if 0
/*
 *	These are the MUST HAVE contents for a VQP packet.
 *
 *	We don't allow the caller to give less than these, because
 *	it won't work.  We don't encode more than these, because the
 *	clients will ignore it.
 *
 *	FIXME: Be more generous?  Look for CISCO + VQP attributes?
 *
 *	@todo - actually use these again...
 */
static int contents[5][VQP_MAX_ATTRIBUTES] = {
	{ 0,      0,      0,      0,      0,      0 },
	{ 0x0c01, 0x0c02, 0x0c03, 0x0c04, 0x0c07, 0x0c05 }, /* Join request */
	{ 0x0c03, 0x0c08, 0,      0,      0,      0 },	/* Join Response */
	{ 0x0c01, 0x0c02, 0x0c03, 0x0c04, 0x0c07, 0x0c08 }, /* Reconfirm */
	{ 0x0c03, 0x0c08, 0,      0,      0,      0 }
};
#endif

ssize_t fr_vmps_encode(fr_dbuff_t *dbuff, uint8_t const *original,
		       int code, uint32_t seq_no, fr_cursor_t *cursor)
{
	fr_dbuff_t		work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);
	fr_pair_t 		*vp;
	fr_dbuff_marker_t	hdr;
	uint32_t 		sequence;

	/*
	 *	Let's keep reference for packet header.
	 */
	fr_dbuff_marker(&hdr, &work_dbuff);

	/*
	 *	Create the header
	 */
	fr_dbuff_bytes_in(&work_dbuff, FR_VQP_VERSION,			/* Version */
					code,				/* Opcode */
					FR_ERROR_CODE_VALUE_NO_ERROR,	/* Response Code */
					0);				/* Data Count */

	if (original) {
		fr_dbuff_memcpy_in(&work_dbuff, original + 4, 4);
	} else {
		fr_dbuff_in(&work_dbuff, seq_no);
	}

	/*
	 *	Encode the VP's.
	 */
	while ((vp = fr_cursor_current(cursor))) {
		size_t len;

		if (vp->da == attr_packet_type) {
			fr_dbuff_marker_current(&hdr)[1] = (uint8_t)vp->vp_uint32;
			fr_cursor_next(cursor);
			continue;
		}

		if (vp->da == attr_error_code) {
			fr_dbuff_marker_current(&hdr)[2] = vp->vp_uint8;
			fr_cursor_next(cursor);
			continue;
		}

		if (!original && (vp->da == attr_sequence_number)) {
			sequence = htonl(vp->vp_uint32);
			memcpy(&fr_dbuff_marker_current(&hdr)[4], &sequence, sizeof(sequence));
			fr_cursor_next(cursor);
			continue;
		}

		DEBUG2("&%pP", vp);

		switch (vp->vp_type) {
		case FR_TYPE_IPV4_ADDR:
			len = fr_vmps_attr_sizes[vp->vp_type][0];
			break;

		case FR_TYPE_ETHERNET:
			len = fr_vmps_attr_sizes[vp->vp_type][0];
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
		 *	See also dictionary.vmps
		 */

		/* Type */
		fr_dbuff_bytes_in(&work_dbuff, 0x00, 0x00, 0x0c, (vp->da->attr & 0xff));

		/* Length */
		fr_dbuff_in(&work_dbuff, (uint16_t)len);

		/* Data */
		switch (vp->vp_type) {
		case FR_TYPE_IPV4_ADDR:
			FR_DBUFF_MEMCPY_IN_RETURN(&work_dbuff, (uint8_t *)&vp->vp_ipv4addr, len);
			break;

		case FR_TYPE_ETHERNET:
			FR_DBUFF_MEMCPY_IN_RETURN(&work_dbuff, vp->vp_ether, len);
			break;

		case FR_TYPE_OCTETS:
		case FR_TYPE_STRING:
			FR_DBUFF_MEMCPY_IN_RETURN(&work_dbuff, vp->vp_octets, len);
			break;

		default:
			return -1;
		}
		fr_dbuff_marker_current(&hdr)[3]++;	/* Update the Data Count */

		fr_cursor_next(cursor);
	}

	return fr_dbuff_set(dbuff, &work_dbuff);
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
ssize_t fr_vmps_packet_size(uint8_t const *data, size_t data_len)
{
	int attributes;
	uint8_t const *ptr, *end;

	if (data_len < FR_VQP_HDR_LEN) return FR_VQP_HDR_LEN;

	/*
	 *	No attributes.
	 */
	if (data[3] == 0) return FR_VQP_HDR_LEN;

	/*
	 *	Too many attributes.  Return an error indicating that
	 *	there's a problem with octet 3.
	 */
	if (data[3] > 30) return -3;

	/*
	 *	Look for attributes.
	 */
	ptr = data + FR_VQP_HDR_LEN;
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

	if ((packet[1] > 0) && (packet[1] < FR_VQP_MAX_CODE) && fr_vmps_codes[packet[1]]) {
		fprintf(fp, "  OpCode:\t\t%s\n", fr_vmps_codes[packet[1]]);
	} else {
		fprintf(fp, "  OpCode:\t\t%u\n", packet[1]);
	}

	if ((packet[2] > 0) && (packet[2] < FR_VQP_MAX_CODE) && fr_vmps_codes[packet[2]]) {
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

/*
 *	Test points for protocol decode
 */
static ssize_t fr_vmps_decode_proto(TALLOC_CTX *ctx, fr_pair_list_t *list, uint8_t const *data, size_t data_len, UNUSED void *proto_ctx)
{
	fr_cursor_t cursor;

	fr_pair_list_init(list);
	fr_cursor_init(&cursor, list);

	return fr_vmps_decode(ctx, data, data_len, &cursor, NULL);
}

static int _decode_test_ctx(UNUSED fr_vmps_ctx_t *proto_ctx)
{
	fr_vmps_free();

	return 0;
}

static int decode_test_ctx(void **out, TALLOC_CTX *ctx)
{
	fr_vmps_ctx_t *test_ctx;

	if (fr_vmps_init() < 0) return -1;

	test_ctx = talloc_zero(ctx, fr_vmps_ctx_t);
	if (!test_ctx) return -1;

	test_ctx->root = fr_dict_root(dict_vmps);
	talloc_set_destructor(test_ctx, _decode_test_ctx);

	*out = test_ctx;

	return 0;
}

extern fr_test_point_proto_decode_t vmps_tp_decode_proto;
fr_test_point_proto_decode_t vmps_tp_decode_proto = {
	.test_ctx	= decode_test_ctx,
	.func		= fr_vmps_decode_proto
};

/*
 *	Test points for protocol encode
 */
static ssize_t fr_vmps_encode_proto(UNUSED TALLOC_CTX *ctx, fr_pair_t *vps, uint8_t *data, size_t data_len, UNUSED void *proto_ctx)
{
	fr_cursor_t cursor;

	fr_cursor_talloc_iter_init(&cursor, &vps, fr_proto_next_encodable, dict_vmps, fr_pair_t);

	return fr_vmps_encode(&FR_DBUFF_TMP(data, data_len), NULL, -1, -1, &cursor);
}

static int _encode_test_ctx(UNUSED fr_vmps_ctx_t *proto_ctx)
{
	fr_vmps_free();

	return 0;
}

static int encode_test_ctx(void **out, TALLOC_CTX *ctx)
{
	fr_vmps_ctx_t *test_ctx;

	if (fr_vmps_init() < 0) return -1;

	test_ctx = talloc_zero(ctx, fr_vmps_ctx_t);
	if (!test_ctx) return -1;

	test_ctx->root = fr_dict_root(dict_vmps);
	talloc_set_destructor(test_ctx, _encode_test_ctx);

	*out = test_ctx;

	return 0;
}

extern fr_test_point_proto_encode_t vmps_tp_encode_proto;
fr_test_point_proto_encode_t vmps_tp_encode_proto = {
	.test_ctx	= encode_test_ctx,
	.func		= fr_vmps_encode_proto
};
