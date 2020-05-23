/*
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
 */

/**
 * $Id$
 *
 * @file protocols/dhcpv4/packet.c
 * @brief Functions to encode/decode DHCP packets.
 *
 * @copyright 2008,2017 The FreeRADIUS server project
 * @copyright 2008 Alan DeKok (aland@deployingradius.com)
 */
#include <stdint.h>
#include <stddef.h>
#include <talloc.h>
#include <freeradius-devel/util/base.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/types.h>
#include <freeradius-devel/protocol/dhcpv4/rfc2131.h>
#include "dhcpv4.h"
#include "attrs.h"

/** Retrieve a DHCP option from a raw packet buffer
 *
 *
 */
uint8_t const *fr_dhcpv4_packet_get_option(dhcp_packet_t const *packet, size_t packet_size, fr_dict_attr_t const *da)
{
	int overload = 0;
	int field = DHCP_OPTION_FIELD;
	size_t where, size;
	uint8_t const *data;

	if (packet_size < MIN_PACKET_SIZE) return NULL;

	where = 0;
	size = packet_size - offsetof(dhcp_packet_t, options);
	data = &packet->options[where];

	while (where < size) {
		if (data[0] == 0) { /* padding */
			where++;
			continue;
		}

		if (data[0] == 255) { /* end of options */
			if ((field == DHCP_OPTION_FIELD) && (overload & DHCP_FILE_FIELD)) {
				data = packet->file;
				where = 0;
				size = sizeof(packet->file);
				field = DHCP_FILE_FIELD;
				continue;

			} else if ((field == DHCP_FILE_FIELD || field == DHCP_OPTION_FIELD) && (overload & DHCP_SNAME_FIELD)) {
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

		if (data[0] == da->attr) return data;

		if ((data[0] == 52) && (data[1] > 0)) { /* overload sname and/or file */
			overload = data[2];
		}

		where += data[1] + 2;
		data += data[1] + 2;
	}

	return NULL;
}

int fr_dhcpv4_decode(TALLOC_CTX *ctx, uint8_t const *data, size_t data_len, VALUE_PAIR **vps, unsigned int *code)
{
	size_t		i;
	uint8_t const  	*p = data;
	uint32_t	giaddr;
	fr_cursor_t	cursor;
	VALUE_PAIR	*head = NULL, *vp;
	VALUE_PAIR	*maxms, *mtu;

	fr_cursor_init(&cursor, &head);

	if (data[1] > 1) {
		fr_strerror_printf("Packet is not Ethernet: %u",
		      data[1]);
		return -1;
	}

	/*
	 *	Decode the header.
	 */
	for (i = 0; i < 14; i++) {
		vp = fr_pair_afrom_da(ctx, *dhcp_header_attrs[i]);
		if (!vp) {
			fr_strerror_printf_push("Cannot decode packet due to internal error");
		error:
			talloc_free(vp);
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
			if ((data[1] == 0) || (data[2] == 0)) continue;

			if ((data[1] == 1) && (data[2] != sizeof(vp->vp_ether))) {
				fr_pair_to_unknown(vp);
			}
		}

		switch (vp->vp_type) {
		case FR_TYPE_STRING:
			/*
			 *	According to RFC 2131, these are null terminated strings.
			 *	We don't trust everyone to abide by the RFC, though.
			 */
			if (*p != '\0') {
				uint8_t *q;

				q = memchr(p, '\0', dhcp_header_sizes[i]);
				fr_pair_value_bstrncpy(vp, p, q ? q - p : dhcp_header_sizes[i]);
			}
			if (vp->vp_length == 0) TALLOC_FREE(vp);
			break;

		case FR_TYPE_OCTETS:
			if (data[2] == 0) break;

			fr_pair_value_memdup(vp, p, data[2], true);
			break;

			/*
			 *	The DHCP header size for CHADDR is not
			 *	6, so the value_box function doesn't
			 *	like it.  Just do the copy manually.
			 */
		case FR_TYPE_ETHERNET:
			memcpy(vp->vp_ether, p, sizeof(vp->vp_ether));
			break;

		default:
			if (fr_value_box_from_network(vp, &vp->data, vp->vp_type, vp->da,
						      p, dhcp_header_sizes[i], true) < 0) goto error;
			break;
		}
		p += dhcp_header_sizes[i];

		if (!vp) continue;

		fr_cursor_append(&cursor, vp);
	}

	/*
	 *	Loop over the options.
	 */

	/*
	 * 	Nothing uses tail after this call, if it does in the future
	 *	it'll need to find the new tail...
	 */
	{
		uint8_t const		*end;
		ssize_t			len;

		p = data + 240;
		end = p + (data_len - 240);

		/*
		 *	Loop over all the options data
		 */
		while (p < end) {
			len = fr_dhcpv4_decode_option(ctx, &cursor, dict_dhcpv4, p, (end - p), NULL);
			if (len <= 0) {
				fr_pair_list_free(&head);
				return len;
			}
			p += len;
		}

		if (code) {
			vp = fr_pair_find_by_da(head, attr_dhcp_message_type, TAG_ANY);
			if (vp) {
				*code = vp->vp_uint8;
			}
		}

		/*
		 *	If option Overload is present in the 'options' field, then fields 'file' and/or 'sname'
		 *	are used to hold more options. They are partitioned and must be interpreted in sequence.
		 */
		vp = fr_pair_find_by_da(head, attr_dhcp_overload, TAG_ANY);
		if (vp) {
			if ((vp->vp_uint8 & 1) == 1) {
				/*
				 *	The 'file' field is used to hold options.
				 *	It must be interpreted before 'sname'.
				 */
				p = data + 44;
				end = p + 64;
				while (p < end) {
					len = fr_dhcpv4_decode_option(ctx, &cursor, dict_dhcpv4,
								      p, end - p, NULL);
					if (len <= 0) {
						fr_pair_list_free(&head);
						return len;
					}
					p += len;
				}
				fr_pair_delete_by_da(&head, attr_dhcp_boot_filename);
			}
			if ((vp->vp_uint8 & 2) == 2) {
				/*
				 *	The 'sname' field is used to hold options.
				 */
				p = data + 108;
				end = p + 128;
				while (p < end) {
					len = fr_dhcpv4_decode_option(ctx, &cursor, dict_dhcpv4,
								      p, end - p, NULL);
					if (len <= 0) {
						fr_pair_list_free(&head);
						return len;
					}
					p += len;
				}
				fr_pair_delete_by_da(&head, attr_dhcp_server_host_name);
			}
		}
	}

	/*
	 *	If DHCP request, set ciaddr to zero.
	 */

	/*
	 *	Set broadcast flag for broken vendors, but only if
	 *	giaddr isn't set.
	 */
	memcpy(&giaddr, data + 24, sizeof(giaddr));
	if (giaddr == htonl(INADDR_ANY)) {
		/*
		 *	DHCP Opcode is request
		 */
		vp = fr_pair_find_by_da(head, attr_dhcp_opcode, TAG_ANY);
		if (vp && vp->vp_uint8 == 1) {
			/*
			 *	Vendor is "MSFT 98"
			 */
			vp = fr_pair_find_by_da(head, attr_dhcp_vendor_class_identifier, TAG_ANY);
			if (vp && (vp->vp_length == 7) && (memcmp(vp->vp_strvalue, "MSFT 98", 7) == 0)) {
				vp = fr_pair_find_by_da(head, attr_dhcp_flags, TAG_ANY);

				/*
				 *	Reply should be broadcast.
				 */
				if (vp) vp->vp_uint16 |= 0x8000;
			}
		}
	}

	/*
	 *	Client can request a LARGER size, but not a smaller
	 *	one.  They also cannot request a size larger than MTU.
	 */
	maxms = fr_pair_find_by_da(head, attr_dhcp_dhcp_maximum_msg_size, TAG_ANY);
	mtu = fr_pair_find_by_da(head, attr_dhcp_interface_mtu_size, TAG_ANY);

	if (mtu && (mtu->vp_uint16 < DEFAULT_PACKET_SIZE)) {
		fr_strerror_printf("Client says MTU is smaller than minimum permitted by the specification");
		return -1;
	}

	/*
	 *	Client says maximum message size is smaller than minimum permitted
	 *	by the specification: fixing it.
	 */
	if (maxms && (maxms->vp_uint16 < DEFAULT_PACKET_SIZE)) maxms->vp_uint16 = DEFAULT_PACKET_SIZE;

	/*
	 *	Client says MTU is smaller than maximum message size: fixing it
	 */
	if (maxms && mtu && (maxms->vp_uint16 > mtu->vp_uint16)) maxms->vp_uint16 = mtu->vp_uint16;

	/*
	 *	FIXME: Nuke attributes that aren't used in the normal
	 *	header for discover/requests.
	 */
	*vps = head;

	return 0;
}

int fr_dhcpv4_packet_encode(RADIUS_PACKET *packet)
{
	ssize_t		len;
	VALUE_PAIR	*vp;

	if (packet->data) return 0;

	packet->data_len = MAX_PACKET_SIZE;
	packet->data = talloc_zero_array(packet, uint8_t, packet->data_len);

	/* XXX Ugly ... should be set by the caller */
	if (packet->code == 0) packet->code = FR_DHCP_NAK;

	/* store xid */
	if ((vp = fr_pair_find_by_da(packet->vps, attr_dhcp_transaction_id, TAG_ANY))) {
		packet->id = vp->vp_uint32;
	} else {
		packet->id = fr_rand();
	}

	len = fr_dhcpv4_encode(packet->data, packet->data_len, NULL, packet->code, packet->id, packet->vps);
	if (len < 0) return -1;

	packet->data_len = len;

	return 0;
}

RADIUS_PACKET *fr_dhcpv4_packet_alloc(uint8_t const *data, ssize_t data_len)
{
	RADIUS_PACKET *packet;
	uint32_t	magic;
	uint8_t const	*code;

	code = fr_dhcpv4_packet_get_option((dhcp_packet_t const *) data, data_len, attr_dhcp_message_type);
	if (!code) return NULL;

	if (data_len < MIN_PACKET_SIZE) return NULL;

	/* Now that checks are done, allocate packet */
	packet = fr_radius_alloc(NULL, false);
	if (!packet) {
		fr_strerror_printf("Failed allocating packet");
		return NULL;
	}

	/*
	 *	Get XID.
	 */
	memcpy(&magic, data + 4, 4);

	packet->data_len = data_len;
	packet->code = code[2];
	packet->id = ntohl(magic);

	/*
	 *	FIXME: for DISCOVER / REQUEST: src_port == dst_port + 1
	 *	FIXME: for OFFER / ACK       : src_port = dst_port - 1
	 */

	/*
	 *	Unique keys are xid, client mac, and client ID?
	 */
	return packet;
}
