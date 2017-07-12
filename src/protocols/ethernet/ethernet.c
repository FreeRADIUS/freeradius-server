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

/** Decodes an ethernet header with up to two levels of VLAN nesting
 *
 * Technically this should be a .1Q protocol, but because of how .1Q subsumes the
 * ether_type field, it's just easier to munge it together with the ethernet
 * decoder.
 *
 * @param[out] ctx		Header information extracted from the ethernet frame,
 *				and any additional VLAN tags discovered.
 *				Must point to memory of the size indicated by the
 *				#fr_proto_lib_t struct exported by this library.
 * @param[in] data		Start of packet data.
 * @param[in] data_len		of the data.
 * @return
 *	- >0 Length of the header.
 *	- <=0 on failure.
 */
ssize_t fr_ethernet_decode(void *packet_ctx, uint8_t const *data, size_t data_len)
{
	uint8_t const			*p = data, *end = p + data_len;
	ethernet_header_t const 	ether_hdr = (void const *)p;
	vlan_header_t const		*vlan_hdr;
	int				i = 0;
	uint16_t			ether_type;
	fr_ethernet_packet_ctx_t	*out = packet_ctx;

	memset(out, 0, sizeof(*out));

	p += sizeof(*ether_hdr);
	if (unlikely(p >= end)) {
		fr_strerror_printf("Ethernet header length (%zu bytes) is greater than remaining "
				   "data in buffer (%zu bytes)", sizeof(*ether_hdr), data_len);
		return 0;
	}

	memcpy(out->dst_addr, ether_hdr->dst_addr, sizeof(out->dst_addr));
	memcpy(out->src_addr, ether_hdr->src_addr, sizeof(out->src_addr));
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

	switch (i) {
	/*
	 *	SVLAN
	 */
	case 2:
		out->svlan_tpid = ntohs(vlan_hdr->tag_type);
		out->svlan_pcp = VLAN_PCP(vlan_hdr);
		out->svlan_dei = VLAN_DEI(vlan_hdr);
		out->svlan_vid = VLAN_VID(vlan_hdr);
		vlan_hdr++;
		/* FALL-THROUGH */

	/*
	 *	CVLAN
	 */
	case 1:
		out->cvlan_tpid = ntohs(vlan_hdr->tag_type);
		out->cvlan_pcp = VLAN_PCP(vlan_hdr);
		out->cvlan_dei = VLAN_DEI(vlan_hdr);
		out->cvlan_vid = VLAN_VID(vlan_hdr);
		vlan_hdr++;
		/* FALL-THROUGH */

	/*
	 *	Naked
	 */
	case 0:
		out->ether_type = ether_type;	/* Always ends up being the payload type */
		break;

	default:
		fr_strerror_printf("Exceeded maximum level of VLAN tag nesting (2)");
		break;
	}
	p = ((uint8_t const *)vlan_hdr) + sizeof(ether_hdr->ether_type);

	return p - data;
}

/** Encodes an ethernet header and up to two levels of VLAN nesting
 *
 * @param[in] ctx	produced by #fr_ethernet_decode, or by the code
 *			creating a new packet.
 * @param[out] data	Where to write output data.
 * @param[in] data_len	Length of the output buffer.
 * @return
 *	- >0 The length of data written to the buffer.
 *	- 0 an error occurred.
 *	- <0 The amount of buffer space we would have needed (as a negative integer).
 */
ssize_t fr_ethernet_encode(void *packet_ctx, uint8_t *data, size_t data_len)
{
	fr_ethernet_packet_ctx_t	*ether_ctx = packet_ctx;

	uint8_t				*p = data, *end = p + data_len;

	ethernet_header_t const 	ether_hdr = (void *)p;

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
		vlan_header_t const	*svlan_hdr, *cvlan_hdr;
		uint16_t		*ether_type;

		svlan_hdr = (void *)p;
		p += sizeof(*svlan_hdr);

		cvlan_hdr = (void *)p;
		p += sizeof(*cvlan_hdr);

		ether_type = (void *)p;
		p += sizeof(*ether_type);

		if (unlikely(p >= end)) goto oob;

		svlan_hdr->tag_type = htons(ether_ctx->svlan_tpid);
		svlan_hdr->tag_control = VLAN_TCI_PACK(ether_ctx->svlan_pcp, ether_ctx->svlan_dei, ether_ctx->svlan_vid);

		cvlan_hdr->tag_type = htons(ether_ctx->cvlan_tpid);
		cvlan_hdr->tag_control = VLAN_TCI_PACK(ether_ctx->cvlan_pcp, ether_ctx->cvlan_dei, ether_ctx->cvlan_vid);

		*ether_type = htons(ether_ctx->ether_type);

		return p - data;
	}

	/*
	 *	Just encode the CVLAN and ether type.
	 */
	if (ether_ctx->cvlan_tpid) {
		vlan_header_t const	*cvlan_hdr;
		uether_ctxt16_t		*ether_type;

		cvlan_hdr = (void *)p;
		p += sizeof(*cvlan_hdr);

		ether_type = (void *)p;
		p += sizeof(*ether_type);

		if (unlikely(p >= end)) goto oo

		cvlan_hdr->tag_type = htons(ether_ctx->cvlan_tpid);
		cvlan_hdr->tag_control = VLAN_TCI_PACK(ether_ctx->cvlan_pcp, ether_ctx->cvlan_dei, ether_ctx->cvlan_vid);

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

/** ether_ctxverts addresses, so that a decoder packet_ctx can be used for encodether_ctxg
 *
 * @param[in] packet_ctx	created by the user or decoder.
 */
void fr_ethernet_invert(void *packet_ctx)
{
	fr_ethernet_packet_ctx_t	*ether_ctx = packet_ctx;
	uether_ctxt8_t			tmp_addr[ETHER_ADDR_LEN];

	/*
	 *	VLANs stay the same, we just need to swap the mac addresses
	 */
	memcpy(tmp_addr, ether_ctx->dst_addr, sizeof(tmp_addr));
	memcpy(ether_ctx->dst_addr, ether_ctx->src_addr, sizeof(ether_ctx->dst_addr));
	memcpy(ether_ctx->src_addr, tmp_addr, sizeof(ether_ctx->src_addr));
}

int fr_ethernet_get_option(void *packet_ctx, fr_proto_opt_group_t group, int opt, fr_value_box_t *out)
{
	switch (group) {
	case PROTO_OPT_GROUP_CUSTOM:
		switch (opt) {

		}
		break;

	case PROTO_OPT_GROUP_L2:
		switch (opt) {

		}
		break;

	default:
		fr_strerror_printf("Option group %i not implemented", group);
		return -1;
	}
}

int fr_ethernet_set_option(void *packet_ctx, fr_proto_opt_group_t group, int opt, fr_value_box_t *in)
{
	switch (group) {
	case PROTO_OPT_GROUP_CUSTOM:
		switch (opt) {

		}
		break;

	case PROTO_OPT_GROUP_L2:
		switch (opt) {

		}
		break;

	default:
		fr_strerror_printf("Option group %i not implemented", group);
		return -1;
	}
}

extern fr_proto_lib_t const ethernet;
fr_proto_lib_t const libfreeradius-ethernet {
	.magic		= RLM_MODULE_INIT,
	.name		= "ethernet",
	.packet_ctx_size = sizeof(fr_ethernet_packet_ctx_t);

	.opt_group	= PROTO_OPT_GROUP_CUSTOM | PROTO_OPT_GROUP_L2;

	.decode		= fr_ethernet_decode,
	.encode		= fr_ethernet_encode,
	.invert		= fr_ethernet_invert
}
