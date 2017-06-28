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
 * @file dhcpv4/packet.c
 * @brief Functions to encode/decode DHCP packets.
 *
 * @copyright 2008,2017 The FreeRADIUS server project
 * @copyright 2008 Alan DeKok <aland@deployingradius.com>
 */
#include <stdint.h>
#include <stddef.h>
#include <talloc.h>
#include <freeradius-devel/pair.h>
#include <freeradius-devel/types.h>
#include <freeradius-devel/dhcpv4/dhcpv4.h>

/** Retrieve a DHCP option from a raw packet buffer
 *
 *
 */
uint8_t const *fr_dhcpv4_packet_get_option(dhcp_packet_t const *packet, size_t packet_size, unsigned int option)
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
			if ((field == DHCP_OPTION_FIELD) && (overload & DHCP_FILE_FIELD)) {
				data = packet->file;
				where = 0;
				size = sizeof(packet->file);
				field = DHCP_FILE_FIELD;
				continue;

			} else if ((field == DHCP_FILE_FIELD) && (overload & DHCP_SNAME_FIELD)) {
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

int fr_dhcpv4_packet_decode(RADIUS_PACKET *packet)
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
				fr_pair_to_unknown(vp);
			}
		}

		switch (vp->vp_type) {
		case FR_TYPE_UINT8:
			vp->vp_uint8 = p[0];
			break;

		case FR_TYPE_UINT16:
			vp->vp_uint16 = (p[0] << 8) | p[1];
			break;

		case FR_TYPE_UINT32:
			memcpy(&vp->vp_uint32, p, 4);
			vp->vp_uint32 = ntohl(vp->vp_uint32);
			break;

		case FR_TYPE_IPV4_ADDR:
			memcpy(&vp->vp_ipv4addr, p, 4);
			break;

		case FR_TYPE_STRING:
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

		case FR_TYPE_OCTETS:
			if (packet->data[2] == 0) break;

			fr_pair_value_memcpy(vp, p, packet->data[2]);
			break;

		case FR_TYPE_ETHERNET:
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
			len = fr_dhcpv4_decode_option(packet, &cursor, fr_dict_root(fr_dict_internal),
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
		if (vp && vp->vp_uint32 == 3) {
			/*
			 *	Vendor is "MSFT 98"
			 */
			vp = fr_pair_find_by_num(head, DHCP_MAGIC_VENDOR, 63, TAG_ANY);
			if (vp && (strcmp(vp->vp_strvalue, "MSFT 98") == 0)) {
				vp = fr_pair_find_by_num(head, DHCP_MAGIC_VENDOR, 262, TAG_ANY);

				/*
				 *	Reply should be broadcast.
				 */
				if (vp) vp->vp_uint16 |= 0x8000;
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

	if (mtu && (mtu->vp_uint32 < DEFAULT_PACKET_SIZE)) {
		fr_strerror_printf("Client says MTU is smaller than minimum permitted by the specification");
		return -1;
	}

	/*
	 *	Client says maximum message size is smaller than minimum permitted
	 *	by the specification: fixing it.
	 */
	if (maxms && (maxms->vp_uint32 < DEFAULT_PACKET_SIZE)) maxms->vp_uint32 = DEFAULT_PACKET_SIZE;

	/*
	 *	Client says MTU is smaller than maximum message size: fixing it
	 */
	if (maxms && mtu && (maxms->vp_uint32 > mtu->vp_uint32)) maxms->vp_uint32 = mtu->vp_uint32;

	return 0;
}

int fr_dhcpv4_packet_encode(RADIUS_PACKET *packet)
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
	if (packet->code == 0) packet->code = FR_DHCPV4_NAK;

	/* store xid */
	if ((vp = fr_pair_find_by_num(packet->vps, DHCP_MAGIC_VENDOR, 260, TAG_ANY))) {
		packet->id = vp->vp_uint32;
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
	if (vp && (vp->vp_uint32 > mms)) {
		mms = vp->vp_uint32;

		if (mms > MAX_PACKET_SIZE) mms = MAX_PACKET_SIZE;
	}
#endif

	vp = fr_pair_find_by_num(packet->vps, DHCP_MAGIC_VENDOR, 256, TAG_ANY);
	if (vp) {
		*p++ = vp->vp_uint32 & 0xff;
	} else {
		*p++ = 1;	/* client message */
	}

	/* DHCP-Hardware-Type */
	if ((vp = fr_pair_find_by_num(packet->vps, DHCP_MAGIC_VENDOR, 257, TAG_ANY))) {
		*p++ = vp->vp_uint8;
	} else {
		*p++ = 1;		/* hardware type = ethernet */
	}

	/* DHCP-Hardware-Address-len */
	if ((vp = fr_pair_find_by_num(packet->vps, DHCP_MAGIC_VENDOR, 258, TAG_ANY))) {
		*p++ = vp->vp_uint8;
	} else {
		*p++ = 6;		/* 6 bytes of ethernet */
	}

	/* DHCP-Hop-Count */
	if ((vp = fr_pair_find_by_num(packet->vps, DHCP_MAGIC_VENDOR, 259, TAG_ANY))) {
		*p = vp->vp_uint8;
	}
	p++;

	/* DHCP-Transaction-Id */
	lvalue = htonl(packet->id);
	memcpy(p, &lvalue, 4);
	p += 4;

	/* DHCP-Number-of-Seconds */
	if ((vp = fr_pair_find_by_num(packet->vps, DHCP_MAGIC_VENDOR, 261, TAG_ANY))) {
		svalue = htons(vp->vp_uint16);
		memcpy(p, &svalue, 2);
	}
	p += 2;

	/* DHCP-Flags */
	if ((vp = fr_pair_find_by_num(packet->vps, DHCP_MAGIC_VENDOR, 262, TAG_ANY))) {
		svalue = htons(vp->vp_uint16);
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
		if (vp->vp_type == FR_TYPE_ETHERNET) {
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
	p[2] = packet->code - FR_DHCPV4_OFFSET;
	p += 3;

	/*
	 *  Pre-sort attributes into contiguous blocks so that fr_dhcpv4_encode_option
	 *  operates correctly. This changes the order of the list, but never mind...
	 */
	fr_pair_list_sort(&packet->vps, fr_dhcpv4_attr_cmp);
	fr_pair_cursor_init(&cursor, &packet->vps);

	/*
	 *  Each call to fr_dhcpv4_encode_option will encode one complete DHCP option,
	 *  and sub options.
	 */
	while ((vp = fr_pair_cursor_current(&cursor))) {
		len = fr_dhcpv4_encode_option(p, packet->data_len - (p - packet->data), &cursor, NULL);
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
