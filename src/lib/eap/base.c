/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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
 * @file lib/eap/base.c
 * @brief Code common to clients and to servers.
 *
 * @copyright 2000-2003,2006 The FreeRADIUS server project
 * @copyright 2001 hereUare Communications, Inc. (raghud@hereuare.com)
 * @copyright 2003 Alan DeKok (aland@freeradius.org)
 * @copyright 2003 Michael Richardson (mcr@sandelman.ottawa.on.ca)
 */

/*
 *  EAP PACKET FORMAT
 *  --- ------ ------
 *  0		   1		   2		   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Code      |  Identifier   |	    Length	     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |    Data ...
 * +-+-+-+-+
 *
 *
 * EAP Request and Response Packet Format
 * --- ------- --- -------- ------ ------
 *  0		   1		   2		   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Code      |  Identifier   |	    Length	     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |  Type-Data ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
 *
 *
 * EAP Success and Failure Packet Format
 * --- ------- --- ------- ------ ------
 *  0		   1		   2		   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Code      |  Identifier   |	    Length	     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

RCSID("$Id$")

#define LOG_PREFIX "rlm_eap - "

#include <freeradius-devel/util/base.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/eap/base.h>
#include "types.h"
#include "attrs.h"

fr_dict_t const *dict_freeradius;
fr_dict_t const *dict_radius;

extern fr_dict_autoload_t eap_base_dict[];
fr_dict_autoload_t eap_base_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

fr_dict_attr_t const *attr_chbind_response_code;
fr_dict_attr_t const *attr_eap_session_id;
fr_dict_attr_t const *attr_eap_type;
fr_dict_attr_t const *attr_virtual_server;

fr_dict_attr_t const *attr_message_authenticator;
fr_dict_attr_t const *attr_eap_channel_binding_message;
fr_dict_attr_t const *attr_eap_message;
fr_dict_attr_t const *attr_eap_msk;
fr_dict_attr_t const *attr_eap_emsk;
fr_dict_attr_t const *attr_freeradius_proxied_to;
fr_dict_attr_t const *attr_ms_mppe_send_key;
fr_dict_attr_t const *attr_ms_mppe_recv_key;
fr_dict_attr_t const *attr_state;
fr_dict_attr_t const *attr_user_name;

extern fr_dict_attr_autoload_t eap_base_dict_attr[];
fr_dict_attr_autoload_t eap_base_dict_attr[] = {
	{ .out = &attr_chbind_response_code, .name = "Chbind-Response-Code", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_eap_session_id, .name = "EAP-Session-Id", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_eap_type, .name = "EAP-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_state, .name = "State", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_virtual_server, .name = "Virtual-Server", .type = FR_TYPE_STRING, .dict = &dict_freeradius },

	{ .out = &attr_message_authenticator, .name = "Message-Authenticator", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_eap_channel_binding_message, .name = "Vendor-Specific.UKERNA.EAP-Channel-Binding-Message", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_eap_message, .name = "EAP-Message", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_eap_msk, .name = "EAP-MSK", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_eap_emsk, .name = "EAP-EMSK", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_freeradius_proxied_to, .name = "Vendor-Specific.FreeRADIUS.Proxied-To", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_radius },
	{ .out = &attr_ms_mppe_send_key, .name = "Vendor-Specific.Microsoft.MPPE-Send-Key", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_ms_mppe_recv_key, .name = "Vendor-Specific.Microsoft.MPPE-Recv-Key", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_radius },

	{ NULL }
};

fr_pair_t *eap_packet_to_vp(fr_radius_packet_t *packet, eap_packet_raw_t const *eap)
{
	int		total, size;
	uint8_t const *ptr;
	fr_pair_list_t	head;
	fr_pair_t	*vp;
	fr_cursor_t	out;

	fr_pair_list_init(&head);
	total = eap->length[0] * 256 + eap->length[1];

	if (total == 0) {
		DEBUG("Asked to encode empty EAP-Message!");
		return NULL;
	}

	ptr = (uint8_t const *) eap;

	fr_cursor_init(&out, &head);
	do {
		size = total;
		if (size > 253) size = 253;

		MEM(vp = fr_pair_afrom_da(packet, attr_eap_message));
		fr_pair_value_memdup(vp, ptr, size, false);

		fr_cursor_append(&out, vp);

		ptr += size;
		total -= size;
	} while (total > 0);

	return head;
}

/** Basic EAP packet verifications & validations
 *
 * @param[in] eap_packet_p	to validate.
 * @return
 *	- true the packet is valid.
 *	- false the packet is invalid.
 */
static bool eap_is_valid(eap_packet_raw_t **eap_packet_p)
{
	uint16_t		len;
	size_t			packet_len;
	eap_packet_raw_t	*eap_packet = *eap_packet_p;

	/*
	 *	These length checks are also done by eap_packet_from_vp(),
	 *	but that's OK.  The static analysis tools aren't smart
	 *	enough to figure that out.
	 */
	packet_len = talloc_array_length((uint8_t *) eap_packet);
	if (packet_len <= EAP_HEADER_LEN) {
		fr_strerror_printf("Invalid EAP data lenth %zd <= 4", packet_len);
		return false;
	}

	memcpy(&len, eap_packet->length, sizeof(uint16_t));
	len = ntohs(len);

	if ((len <= EAP_HEADER_LEN) || (len > packet_len)) {
		fr_strerror_printf("Invalid EAP length field.  Expected value in range %u-%zu, was %u bytes",
				   EAP_HEADER_LEN, packet_len, len);
		return false;
	}

	/*
	 *	High level EAP packet checks
	 */
	switch (eap_packet->code) {
	case FR_EAP_CODE_RESPONSE:
	case FR_EAP_CODE_REQUEST:
		break;

	default:
		fr_strerror_printf("Invalid EAP code %d: Ignoring the packet", eap_packet->code);
		return false;
	}

	if ((eap_packet->data[0] == 0) ||
	    (eap_packet->data[0] >= FR_EAP_METHOD_MAX)) {
		/*
		 *	Handle expanded types by smashing them to
		 *	normal types.
		 */
		if (eap_packet->data[0] == FR_EAP_EXPANDED_TYPE) {
			uint8_t *p, *q;

			if (len <= (EAP_HEADER_LEN + 1 + 3 + 4)) {
				fr_strerror_printf("Expanded EAP type is too short: ignoring the packet");
				return false;
			}

			if ((eap_packet->data[1] != 0) ||
			    (eap_packet->data[2] != 0) ||
			    (eap_packet->data[3] != 0)) {
				fr_strerror_printf("Expanded EAP type has unknown Vendor-ID: ignoring the packet");
				return false;
			}

			if ((eap_packet->data[4] != 0) ||
			    (eap_packet->data[5] != 0) ||
			    (eap_packet->data[6] != 0)) {
				fr_strerror_printf("Expanded EAP type has unknown Vendor-Type: ignoring the packet");
				return false;
			}

			if ((eap_packet->data[7] == 0) ||
			    (eap_packet->data[7] >= FR_EAP_METHOD_MAX)) {
				fr_strerror_printf("Unsupported Expanded EAP type %s (%u): ignoring the packet",
						   eap_type2name(eap_packet->data[7]), eap_packet->data[7]);
				return false;
			}

			if (eap_packet->data[7] == FR_EAP_METHOD_NAK) {
				fr_strerror_printf("Unsupported Expanded EAP-NAK: ignoring the packet");
				return false;
			}

			/*
			 *	Re-write the EAP packet to NOT have the expanded type.
			 */
			q = (uint8_t *) eap_packet;
			memmove(q + EAP_HEADER_LEN, q + EAP_HEADER_LEN + 7, len - 7 - EAP_HEADER_LEN);

			p = talloc_realloc(talloc_parent(eap_packet), eap_packet, uint8_t, len - 7);
			if (!p) {
				fr_strerror_printf("Unsupported EAP type %s (%u): ignoring the packet",
						   eap_type2name(eap_packet->data[0]), eap_packet->data[0]);
				return false;
			}

			len -= 7;
			p[2] = (len >> 8) & 0xff;
			p[3] = len & 0xff;

			*eap_packet_p = (eap_packet_raw_t *)p;

			return true;
		}

		fr_strerror_printf("Unsupported EAP type %s (%u): ignoring the packet",
				   eap_type2name(eap_packet->data[0]), eap_packet->data[0]);
		return false;
	}

	/* we don't expect notification, but we send it */
	if (eap_packet->data[0] == FR_EAP_METHOD_NOTIFICATION) {
		fr_strerror_printf("Got NOTIFICATION, Ignoring the packet");
		return false;
	}

	return true;
}

/*
 * Handles multiple EAP-Message attrs
 * ie concatenates all to get the complete EAP packet.
 *
 * NOTE: Sometimes Framed-MTU might contain the length of EAP-Message,
 *      refer fragmentation in rfc2869.
 */
eap_packet_raw_t *eap_packet_from_vp(TALLOC_CTX *ctx, fr_pair_t *vps)
{
	fr_pair_t		*vp;
	eap_packet_raw_t	*eap_packet;
	unsigned char		*ptr;
	uint16_t		len;
	int			total_len;
	fr_cursor_t		cursor;

	/*
	 *	Get only EAP-Message attribute list
	 */
	vp = fr_cursor_iter_by_da_init(&cursor, &vps, attr_eap_message);
	if (!vp) {
		fr_strerror_printf("EAP-Message not found");
		return NULL;
	}

	/*
	 *	Sanity check the length before doing anything.
	 */
	if (vp->vp_length < 4) {
		fr_strerror_printf("EAP packet is too short");
		return NULL;
	}

	/*
	 *	Get the Actual length from the EAP packet
	 *	First EAP-Message contains the EAP packet header
	 */
	memcpy(&len, vp->vp_strvalue + 2, sizeof(len));
	len = ntohs(len);

	/*
	 *	Take out even more weird things.
	 */
	if (len < 4) {
		fr_strerror_printf("EAP packet has invalid length (less than 4 bytes)");
		return NULL;
	}

	/*
	 *	Sanity check the length, BEFORE allocating  memory.
	 */
	total_len = 0;
	for (vp = fr_cursor_head(&cursor);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		total_len += vp->vp_length;

		if (total_len > len) {
			fr_strerror_printf("Malformed EAP packet.  Length in packet header %i, "
					   "does not match actual length %i", len, total_len);
			return NULL;
		}
	}

	/*
	 *	If the length is SMALLER, die, too.
	 */
	if (total_len < len) {
		fr_strerror_printf("Malformed EAP packet.  Length in packet header does not "
				   "match actual length");
		return NULL;
	}

	/*
	 *	Now that we know the lengths are OK, allocate memory.
	 */
	eap_packet = (eap_packet_raw_t *) talloc_zero_array(ctx, uint8_t, len);
	if (!eap_packet) return NULL;

	/*
	 *	Copy the data from EAP-Message's over to our EAP packet.
	 */
	ptr = (unsigned char *)eap_packet;

	/* RADIUS ensures order of attrs, so just concatenate all */
	for (vp = fr_cursor_head(&cursor);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		memcpy(ptr, vp->vp_strvalue, vp->vp_length);
		ptr += vp->vp_length;
	}

	if (!eap_is_valid(&eap_packet)) {
		talloc_free(eap_packet);
		return NULL;
	}

	return eap_packet;
}

/*
 *	Add raw hex data to the reply.
 */
void eap_add_reply(request_t *request, fr_dict_attr_t const *da, uint8_t const *value, int len)
{
	fr_pair_t *vp;

	MEM(pair_update_reply(&vp, da) >= 0);
	fr_pair_value_memdup(vp, value, len, false);

	RINDENT();
	RDEBUG2("&reply.%pP", vp);
	REXDENT();
}

/** Run a subrequest through a virtual server, managing the eap_session_t of the child
 *
 * If eap_session_t has a child, inject that into the request.
 *
 * If after the request has run, the child eap_session_t is no longer present,
 * we assume it has been freed, and fixup the parent eap_session_t.
 *
 * If the eap_session_t pointer changes, this is considered a fatal error.
 *
 * @param[in] request		the current (real) request.
 * @param[in] eap_session	representing the outer eap method.
 * @param[in] virtual_server	The default virtual server to send the request to.
 * @return the rcode of the last executed section in the virtual server.
 */
rlm_rcode_t eap_virtual_server(request_t *request, eap_session_t *eap_session, char const *virtual_server)
{
	eap_session_t	*eap_session_inner;
	rlm_rcode_t	rcode;
	fr_pair_t	*vp;

	vp = fr_pair_find_by_da(&request->control_pairs, attr_virtual_server);
	request->server_cs = vp ? virtual_server_find(vp->vp_strvalue) : virtual_server_find(virtual_server);

	if (request->server_cs) {
		RDEBUG2("Running request through virtual server \"%s\"", cf_section_name2(request->server_cs));
	} else {
		RDEBUG2("Running request in virtual server");
	}

	/*
	 *	Add a previously recorded inner eap_session_t back
	 *	to the request.  This in theory allows infinite
	 *	nesting, but this is probably limited somewhere.
	 */
	if (eap_session->child) {
		RDEBUG4("Adding eap_session_t %p to child request", eap_session->child);
		request_data_talloc_add(request, NULL, REQUEST_DATA_EAP_SESSION,
					eap_session_t, eap_session->child, false, false, false);
	}

	rad_virtual_server(&rcode, request);
	eap_session_inner = request_data_get(request, NULL, REQUEST_DATA_EAP_SESSION);
	if (eap_session_inner) {
		/*
		 *	We assume if the inner eap session has changed
		 *	then the old one has been freed.
		 */
		if (!eap_session->child || (eap_session->child != eap_session_inner)) {
			RDEBUG4("Binding lifetime of child eap_session %p to parent eap_session %p",
				eap_session_inner, eap_session);
			talloc_link_ctx(eap_session, eap_session_inner);
			eap_session->child = eap_session_inner;
		} else {
			RDEBUG4("Got eap_session_t %p back unmolested", eap_session->child);
		}
	/*
	 *	Assume the inner server freed the
	 *	eap_session_t and remove our reference to it.
	 *
	 *	If it didn't actually free the child (due to error)
	 *	the call to talloc_link_ctx (above) ensures it will
	 *	be freed when the parent is.
	 */
	} else if (eap_session->child) {
		RDEBUG4("Inner server freed eap_session %p", eap_session->child);
		eap_session->child = NULL;
	}

	return rcode;
}

/** Initialise the lib eap base library
 *
 */
int eap_base_init(void)
{
	if (fr_dict_autoload(eap_base_dict) < 0) {
		PERROR("%s", __FUNCTION__);
		return -1;
	}

	/*
	 *	But main_config.c does read the dictionaries before
	 *	loading modules, so these have to exist.
	 */
	if (fr_dict_attr_autoload(eap_base_dict_attr) < 0) {
		PERROR("%s", __FUNCTION__);
		fr_dict_autofree(eap_base_dict);
		return -1;
	}

	return 0;
}

/** De-init the lib eap base library
 *
 */
void eap_base_free(void)
{
	fr_dict_autofree(eap_base_dict);
}
