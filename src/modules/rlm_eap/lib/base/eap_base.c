/*
 * eapcommon.c    rfc2284 & rfc2869 implementation
 *
 * code common to clients and to servers.
 *
 * Version:     $Id$
 *
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
 *
 * @copyright 2000-2003,2006  The FreeRADIUS server project
 * @copyright 2001  hereUare Communications, Inc. <raghud@hereuare.com>
 * @copyright 2003  Alan DeKok <aland@freeradius.org>
 * @copyright 2003  Michael Richardson <mcr@sandelman.ottawa.on.ca>
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
#include <freeradius-devel/server/rad_assert.h>
#include "eap_types.h"
#include "eap_attrs.h"
#include "eap.h"

static fr_dict_t *dict_freeradius;
static fr_dict_t *dict_radius;

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

extern fr_dict_attr_autoload_t eap_base_dict_attr[];
fr_dict_attr_autoload_t eap_base_dict_attr[] = {
	{ .out = &attr_chbind_response_code, .name = "Chbind-Response-Code", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_eap_session_id, .name = "EAP-Session-Id", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_eap_type, .name = "EAP-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_virtual_server, .name = "Virtual-Server", .type = FR_TYPE_STRING, .dict = &dict_freeradius },

	{ .out = &attr_message_authenticator, .name = "Message-Authenticator", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_eap_channel_binding_message, .name = "EAP-Channel-Binding-Message", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_eap_message, .name = "EAP-Message", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_eap_msk, .name = "EAP-MSK", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_eap_emsk, .name = "EAP-EMSK", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_freeradius_proxied_to, .name = "FreeRADIUS-Proxied-To", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_radius },
	{ .out = &attr_ms_mppe_send_key, .name = "MS-MPPE-Send-Key", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_ms_mppe_recv_key, .name = "MS-MPPE-Recv-Key", .type = FR_TYPE_OCTETS, .dict = &dict_radius },

	{ NULL }
};

/** Return an EAP-Type for a particular name
 *
 * Converts a name into an IANA EAP type.
 *
 * @param name to convert.
 * @return
 *	- IANA EAP type.
 *	- #FR_EAP_INVALID if the name doesn't match any known types.
 */
eap_type_t eap_name2type(char const *name)
{
	fr_dict_enum_t	*dv;

	dv = fr_dict_enum_by_alias(attr_eap_type, name, -1);
	if (!dv) return FR_EAP_INVALID;

	if (dv->value->vb_uint32 >= FR_EAP_MAX_TYPES) return FR_EAP_INVALID;

	return dv->value->vb_uint32;
}

/** Return an EAP-name for a particular type
 *
 * Resolve
 */
char const *eap_type2name(eap_type_t method)
{
	fr_dict_enum_t	*dv;

	dv = fr_dict_enum_by_value(attr_eap_type, fr_box_uint32(method));
	if (dv) return dv->alias;

	return "unknown";
}

/*
 *	EAP packet format to be sent over the wire
 *
 *	i.e. code+id+length+data where data = null/type+typedata
 *	based on code.
 *
 * INPUT to function is reply->code
 *		      reply->id
 *		      reply->type   - setup with data
 *
 * OUTPUT reply->packet is setup with wire format, and will
 *		      be allocated to the right size.
 *
 */
int eap_wireformat(eap_packet_t *reply)
{
	eap_packet_raw_t	*header;
	uint16_t total_length = 0;

	if (!reply) return 0;

	/*
	 *	If reply->packet is set, then the wire format
	 *	has already been calculated, just succeed.
	 */
	if(reply->packet != NULL) return 0;

	total_length = EAP_HEADER_LEN;
	if (reply->code < 3) {
		total_length += 1/* EAP Method */;
		if (reply->type.data && reply->type.length > 0) {
			total_length += reply->type.length;
		}
	}

	reply->packet = talloc_array(reply, uint8_t, total_length);
	header = (eap_packet_raw_t *)reply->packet;
	if (!header) {
		return -1;
	}

	header->code = (reply->code & 0xFF);
	header->id = (reply->id & 0xFF);

	total_length = htons(total_length);
	memcpy(header->length, &total_length, sizeof(total_length));

	/*
	 *	Request and Response packets are special.
	 */
	if ((reply->code == FR_EAP_CODE_REQUEST) ||
	    (reply->code == FR_EAP_CODE_RESPONSE)) {
		header->data[0] = (reply->type.num & 0xFF);

		/*
		 * Here since we cannot know the typedata format and length
		 *
		 * Type_data is expected to be wired by each EAP-Type
		 *
		 * Zero length/No typedata is supported as long as
		 * type is defined
		 */
		if (reply->type.data && reply->type.length > 0) {
			memcpy(&header->data[1], reply->type.data, reply->type.length);
			talloc_free(reply->type.data);
			reply->type.data = reply->packet + EAP_HEADER_LEN + 1/*EAPtype*/;
		}
	}

	return 0;
}

VALUE_PAIR *eap_packet2vp(RADIUS_PACKET *packet, eap_packet_raw_t const *eap)
{
	int		total, size;
	uint8_t const *ptr;
	VALUE_PAIR	*head = NULL;
	VALUE_PAIR	*vp;
	fr_cursor_t	out;

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

		vp = fr_pair_afrom_da(packet, attr_eap_message);
		if (!vp) {
			fr_pair_list_free(&head);
			return NULL;
		}
		fr_pair_value_memcpy(vp, ptr, size);

		fr_cursor_append(&out, vp);

		ptr += size;
		total -= size;
	} while (total > 0);

	return head;
}


/*
 * Handles multiple EAP-Message attrs
 * ie concatenates all to get the complete EAP packet.
 *
 * NOTE: Sometimes Framed-MTU might contain the length of EAP-Message,
 *      refer fragmentation in rfc2869.
 */
eap_packet_raw_t *eap_vp2packet(TALLOC_CTX *ctx, VALUE_PAIR *vps)
{
	VALUE_PAIR		*vp;
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

	return eap_packet;
}

/*
 *	Add raw hex data to the reply.
 */
void eap_add_reply(REQUEST *request, fr_dict_attr_t const *da, uint8_t const *value, int len)
{
	VALUE_PAIR *vp;

	MEM(pair_update_reply(&vp, da) >= 0);
	fr_pair_value_memcpy(vp, value, len);

	RINDENT();
	RDEBUG2("&reply:%pP", vp);
	REXDENT();
}

/** Send a fake request to a virtual server, managing the eap_session_t of the child
 *
 * If eap_session_t has a child, inject that into the fake request.
 *
 * If after the request has run, the child eap_session_t is no longer present,
 * we assume it has been freed, and fixup the parent eap_session_t.
 *
 * If the eap_session_t pointer changes, this is considered a fatal error.
 *
 * @param request the current (real) request.
 * @param eap_session representing the outer eap method.
 * @param fake request we're going to send.
 * @param virtual_server The default virtual server to send the request to.
 * @return the rcode of the last executed section in the virtual server.
 */
rlm_rcode_t eap_virtual_server(REQUEST *request, REQUEST *fake,
			       eap_session_t *eap_session, char const *virtual_server)
{
	eap_session_t	*eap_session_inner;
	rlm_rcode_t	rcode;
	VALUE_PAIR	*vp;

	vp = fr_pair_find_by_da(request->control, attr_virtual_server, TAG_ANY);
	fake->server_cs = vp ? virtual_server_find(vp->vp_strvalue) : virtual_server_find(virtual_server);

	if (fake->server_cs) {
		RDEBUG2("Proxying tunneled request to virtual server \"%s\"", cf_section_name2(fake->server_cs));
	} else {
		RDEBUG2("Proxying tunneled request");
	}

	/*
	 *	Add a previously recorded inner eap_session_t back
	 *	to the request.  This in theory allows infinite
	 *	nesting, but this is probably limited somewhere.
	 */
	if (eap_session->child) {
		RDEBUG4("Adding eap_session_t %p to fake request", eap_session->child);
		request_data_talloc_add(fake, NULL, REQUEST_DATA_EAP_SESSION,
					eap_session_t, eap_session->child, false, false, false);
	}

	rcode = rad_virtual_server(fake);

	eap_session_inner = request_data_get(fake, NULL, REQUEST_DATA_EAP_SESSION);
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
		PERROR("Failed initialising protocol library");
		return -1;
	}

	/*
	 *	But mainconfig.c does read the dictionaries before
	 *	loading modules, so these have to exist.
	 */
	if (fr_dict_attr_autoload(eap_base_dict_attr) < 0) {
		PERROR("Failed resolving attributes");
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
