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
 *   Foundation, inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 * @file ethernet.c
 * @brief Functions to parse and construct ethernet headers.
 *
 * @copyright 2017 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
#include "ethernet.h"
#include <string.h>
#include <arpa/inet.h>
#include <freeradius-devel/io/proto.h>

/** Decodes an ethernet header with up to two levels of VLAN nesting
 *
 * Technically this should be a .1Q protocol, but because of how .1Q subsumes the
 * ether_type field, it's just easier to munge it together with the ethernet
 * decoder.
 *
 * @param[out] proto_ctx	Header information extracted from the ethernet frame,
 *				and any additional VLAN tags discovered.
 *				Must point to memory of the size indicated by the
 *				#fr_proto_lib_t struct exported by this library.
 * @param[in] data		Start of packet data.
 * @param[in] data_len		of the data.
 * @return
 *	- >0 Length of the header.
 *	- <=0 on failure.
 */
static ssize_t fr_ethernet_decode(void *proto_ctx, uint8_t const *data, size_t data_len)
{
	uint8_t const			*p = data, *end = p + data_len;
	ethernet_header_t const 	*ether_hdr = (void const *)p;
	vlan_header_t const		*vlan_hdr;
	int				i = 0;
	uint16_t			ether_type;
	fr_ethernet_proto_ctx_t	*ether_ctx = proto_ctx;

	p += sizeof(*ether_hdr);
	if (unlikely(p >= end)) {
	ood:
		fr_strerror_printf("Ethernet header length (%zu bytes) is greater than remaining "
				   "data in buffer (%zu bytes)", sizeof(*ether_hdr), data_len);
		return 0;
	}

	memcpy(ether_ctx->dst_addr, ether_hdr->dst_addr, sizeof(ether_ctx->dst_addr));
	memcpy(ether_ctx->src_addr, ether_hdr->src_addr, sizeof(ether_ctx->src_addr));
	ether_type = ntohs(ether_hdr->ether_type);

	p -= sizeof(ether_hdr->ether_type);	/* reverse */
	vlan_hdr = (void const *)p;
	for (i = 0; i < 3; i++) {
		switch (ether_type) {
		/*
		 *	There are a number of devices out there which
		 *	double tag with 0x8100 *sigh*
		 */
		case 0x8100:	/* CVLAN */
		case 0x9100:	/* SVLAN */
		case 0x9200:	/* SVLAN */
		case 0x9300:	/* SVLAN */
			if ((uint8_t const *)(++vlan_hdr) >= end) goto ood;
			ether_type = ntohs(vlan_hdr->tag_type);
			continue;

		default:
			break;
		}

		break;
	}
	vlan_hdr = (void const *)p;		/* reset */

	/*
	 *	We don't explicitly memset the ctx
	 *	so se these to zero now.
	 */
	ether_ctx->svlan_tpid = 0;
	ether_ctx->cvlan_tpid = 0;

	switch (i) {
	/*
	 *	SVLAN
	 */
	case 2:
		ether_ctx->svlan_tpid = ntohs(vlan_hdr->tag_type);
		ether_ctx->svlan_pcp = VLAN_PCP_UNPACK(vlan_hdr);
		ether_ctx->svlan_dei = VLAN_DEI_UNPACK(vlan_hdr);
		ether_ctx->svlan_vid = VLAN_VID_UNPACK(vlan_hdr);
		vlan_hdr++;
		/* FALL-THROUGH */

	/*
	 *	CVLAN
	 */
	case 1:
		ether_ctx->cvlan_tpid = ntohs(vlan_hdr->tag_type);
		ether_ctx->cvlan_pcp = VLAN_PCP_UNPACK(vlan_hdr);
		ether_ctx->cvlan_dei = VLAN_DEI_UNPACK(vlan_hdr);
		ether_ctx->cvlan_vid = VLAN_VID_UNPACK(vlan_hdr);
		vlan_hdr++;
		/* FALL-THROUGH */

	/*
	 *	Naked
	 */
	case 0:
		ether_ctx->ether_type = ether_type;	/* Always ends up being the payload type */
		break;

	default:
		fr_strerror_printf("Exceeded maximum level of VLAN tag nesting (2)");
		break;
	}
	p = ((uint8_t const *)vlan_hdr) + sizeof(ether_hdr->ether_type);

	ether_ctx->payload_len = data_len - (p - data);

	return p - data;
}

/** Encodes an ethernet header and up to two levels of VLAN nesting
 *
 * @param[in] proto_ctx	produced by #fr_ethernet_decode, or by the code
 *			creating a new packet.
 * @param[out] data	Where to write output data.
 * @param[in] data_len	Length of the output buffer.
 * @return
 *	- >0 The length of data written to the buffer.
 *	- 0 an error occurred.
 *	- <0 The amount of buffer space we would have needed (as a negative integer).
 */
static ssize_t fr_ethernet_encode(void *proto_ctx, uint8_t *data, size_t data_len)
{
	fr_ethernet_proto_ctx_t	*ether_ctx = proto_ctx;

	uint8_t			*p = data, *end = p + data_len;

	ethernet_header_t 	*ether_hdr = (void *)p;

	p += sizeof(ether_hdr->src_addr) + sizeof(ether_hdr->dst_addr);
	if (unlikely(p >= end)) {
	oob:
		fr_strerror_printf("insufficient buffer space, needed %zu bytes, have %zu bytes",
				   p - data, data_len);
		return data - p;
	}

	memcpy(ether_hdr->dst_addr, ether_ctx->dst_addr, sizeof(ether_hdr->dst_addr));
	memcpy(ether_hdr->src_addr, ether_ctx->src_addr, sizeof(ether_hdr->src_addr));

	/*
	 *	Encode the SVLAN, CVLAN and ether type.
	 */
	if (ether_ctx->svlan_tpid) {
		vlan_header_t	*svlan_hdr, *cvlan_hdr;
		uint16_t	*ether_type;

		svlan_hdr = (void *)p;
		p += sizeof(*svlan_hdr);

		cvlan_hdr = (void *)p;
		p += sizeof(*cvlan_hdr);

		ether_type = (void *)p;
		p += sizeof(*ether_type);

		if (unlikely(p >= end)) goto oob;

		svlan_hdr->tag_type = htons(ether_ctx->svlan_tpid);
		svlan_hdr->tag_control = VLAN_TCI_PACK(ether_ctx->svlan_pcp, ether_ctx->svlan_dei,
						       ether_ctx->svlan_vid);

		cvlan_hdr->tag_type = htons(ether_ctx->cvlan_tpid);
		cvlan_hdr->tag_control = VLAN_TCI_PACK(ether_ctx->cvlan_pcp, ether_ctx->cvlan_dei,
						       ether_ctx->cvlan_vid);

		*ether_type = htons(ether_ctx->ether_type);

		return p - data;
	}

	/*
	 *	Just encode the CVLAN and ether type.
	 */
	if (ether_ctx->cvlan_tpid) {
		vlan_header_t	*cvlan_hdr;
		uint16_t	*ether_type;

		cvlan_hdr = (void *)p;
		p += sizeof(*cvlan_hdr);

		ether_type = (void *)p;
		p += sizeof(*ether_type);

		if (unlikely(p >= end)) goto oob;

		cvlan_hdr->tag_type = htons(ether_ctx->cvlan_tpid);
		cvlan_hdr->tag_control = VLAN_TCI_PACK(ether_ctx->cvlan_pcp, ether_ctx->cvlan_dei,
						       ether_ctx->cvlan_vid);

		*ether_type = htons(ether_ctx->ether_type);

		return p - data;
	}

	/*
	 *	Just encode the ether type.
	 */
	p += sizeof(ether_hdr->ether_type);
	if (unlikely(p >= end)) goto oob;

	ether_hdr->ether_type = htons(ether_ctx->ether_type);

	return p - data;
}

/** Inverts addresses, so that a decoder proto_ctx can be used for encoding
 *
 * @param[in] proto_ctx	created by the user or decoder.
 */
static void fr_ethernet_invert(void *proto_ctx)
{
	fr_ethernet_proto_ctx_t	*ether_ctx = proto_ctx;
	uint8_t			tmp_addr[ETHER_ADDR_LEN];

	/*
	 *	VLANs stay the same, we just need to swap the mac addresses
	 */
	memcpy(tmp_addr, ether_ctx->dst_addr, sizeof(tmp_addr));
	memcpy(ether_ctx->dst_addr, ether_ctx->src_addr, sizeof(ether_ctx->dst_addr));
	memcpy(ether_ctx->src_addr, tmp_addr, sizeof(ether_ctx->src_addr));
}

/** Retrieve an option value from the proto_ctx
 *
 * @param[out] out		value box to place option value into.
 * @param[in] proto_ctx		to retrieve value from.
 * @param[in] group		Option group.  Which collection of options to query.
 * @param[in] opt		Option to retrieve.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int fr_ethernet_get_option(fr_value_box_t *out, void const *proto_ctx, fr_proto_opt_group_t group, int opt)
{
	fr_ethernet_proto_ctx_t const *ether_ctx = proto_ctx;

	switch (group) {
	case PROTO_OPT_GROUP_CUSTOM:
		switch (opt) {
		case PROTO_OPT_ETHERNET_SVLAN_TPID:
			return fr_value_box_shallow(out, ether_ctx->svlan_tpid, true);

		case PROTO_OPT_ETHERNET_SVLAN_PCP:
			return fr_value_box_shallow(out, ether_ctx->svlan_pcp, true);

		case PROTO_OPT_ETHERNET_SVLAN_DEI:
			return fr_value_box_shallow(out, ether_ctx->svlan_dei, true);

		case PROTO_OPT_ETHERNET_SVLAN_VID:
			return fr_value_box_shallow(out, ether_ctx->svlan_vid, true);

		case PROTO_OPT_ETHERNET_CVLAN_TPID:
			return fr_value_box_shallow(out, ether_ctx->cvlan_tpid, true);

		case PROTO_OPT_ETHERNET_CVLAN_PCP:
			return fr_value_box_shallow(out, ether_ctx->cvlan_pcp, true);

		case PROTO_OPT_ETHERNET_CVLAN_DEI:
			return fr_value_box_shallow(out, ether_ctx->cvlan_dei, true);

		case PROTO_OPT_ETHERNET_CVLAN_VID:
			return fr_value_box_shallow(out, ether_ctx->cvlan_vid, true);

		default:
			fr_strerror_printf("Option %i group %i not implemented", opt, group);
			return -1;
		}

	case PROTO_OPT_GROUP_L2:
		switch (opt) {
		case PROTO_OPT_L2_PAYLOAD_LEN:
			fr_value_box_init(out, FR_TYPE_SIZE, NULL, true);
			out->vb_size = ether_ctx->payload_len;
			return 0;

		case PROTO_OPT_L2_SRC_ADDRESS:
			return fr_value_box_ethernet_addr(out, NULL, ether_ctx->src_addr, true);

		case PROTO_OPT_L2_DST_ADDRESS:
			return fr_value_box_ethernet_addr(out, NULL, ether_ctx->dst_addr, true);

		case PROTO_OPT_L2_NEXT_PROTOCOL:
			return fr_value_box_shallow(out, ether_ctx->ether_type, true);

		default:
			fr_strerror_printf("Option %i group %i not implemented", opt, group);
			return -1;
		}

	default:
		fr_strerror_printf("Option group %i not implemented", group);
		return -1;
	}
}

/** Set an option in the proto_ctx
 *
 * @param[in] proto_ctx		to set value in.
 * @param[in] group		Option group.  Which collection of options opt exists in.
 * @param[in] opt		Option to set.
 * @param[in] in		value to set.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int fr_ethernet_set_option(void *proto_ctx, fr_proto_opt_group_t group, int opt, fr_value_box_t *in)
{
	fr_ethernet_proto_ctx_t	*ether_ctx = proto_ctx;

	switch (group) {
	case PROTO_OPT_GROUP_CUSTOM:
		switch (opt) {
		case PROTO_OPT_ETHERNET_SVLAN_TPID:
			return fr_value_unbox_shallow(&ether_ctx->svlan_tpid, in);

		case PROTO_OPT_ETHERNET_SVLAN_PCP:
			return fr_value_unbox_shallow(&ether_ctx->svlan_pcp, in);

		case PROTO_OPT_ETHERNET_SVLAN_DEI:
			return fr_value_unbox_shallow(&ether_ctx->svlan_dei, in);

		case PROTO_OPT_ETHERNET_SVLAN_VID:
			return fr_value_unbox_shallow(&ether_ctx->svlan_vid, in);

		case PROTO_OPT_ETHERNET_CVLAN_TPID:
			return fr_value_unbox_shallow(&ether_ctx->cvlan_tpid, in);

		case PROTO_OPT_ETHERNET_CVLAN_PCP:
			return fr_value_unbox_shallow(&ether_ctx->cvlan_pcp, in);

		case PROTO_OPT_ETHERNET_CVLAN_DEI:
			return fr_value_unbox_shallow(&ether_ctx->cvlan_dei, in);

		case PROTO_OPT_ETHERNET_CVLAN_VID:
			return fr_value_unbox_shallow(&ether_ctx->cvlan_vid, in);

		default:
			fr_strerror_printf("Option %i group %i not implemented", opt, group);
			return -1;
		}

	case PROTO_OPT_GROUP_L2:
		switch (opt) {
		case PROTO_OPT_L2_PAYLOAD_LEN:
			if (in->type != FR_TYPE_SIZE) {
				fr_strerror_printf("Unboxing failed.  Needed type %s, had type %s",
						   fr_table_str_by_value(fr_value_box_type_table, FR_TYPE_SIZE, "?Unknown?"),
						   fr_table_str_by_value(fr_value_box_type_table, in->type, "?Unknown?"));
				return -1;
			}
			ether_ctx->payload_len = in->vb_size;
			return 0;

		case PROTO_OPT_L2_SRC_ADDRESS:
			return fr_value_unbox_ethernet_addr(ether_ctx->src_addr, in);

		case PROTO_OPT_L2_DST_ADDRESS:
			return fr_value_unbox_ethernet_addr(ether_ctx->dst_addr, in);

		case PROTO_OPT_L2_NEXT_PROTOCOL:
			return fr_value_unbox_shallow(&ether_ctx->ether_type, in);

		default:
			fr_strerror_printf("Option %i group %i not implemented", opt, group);
			return -1;
		}

	default:
		fr_strerror_printf("Option group %i not implemented", group);
		return -1;
	}

}

extern fr_proto_lib_t const libfreeradius_ethernet;
fr_proto_lib_t const libfreeradius_ethernet = {
	.magic		= RLM_MODULE_INIT,
	.name		= "ethernet",
	.inst_size	= sizeof(fr_ethernet_proto_ctx_t),

	.opt_group	= PROTO_OPT_GROUP_CUSTOM | PROTO_OPT_GROUP_L2,

	.decode		= fr_ethernet_decode,
	.encode		= fr_ethernet_encode,
	.invert		= fr_ethernet_invert,
	.get_option	= fr_ethernet_get_option,
	.set_option	= fr_ethernet_set_option
};
