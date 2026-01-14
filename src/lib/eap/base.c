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

#define LOG_PREFIX "eap"

#include <freeradius-devel/eap/base.h>
#include <freeradius-devel/radius/defs.h>
#include <freeradius-devel/server/state.h>
#include <freeradius-devel/server/virtual_servers.h>
#include <freeradius-devel/server/pair.h>
#include <freeradius-devel/server/auth.h>
#include <freeradius-devel/unlang/call.h>
#include <freeradius-devel/unlang/interpret.h>
#include <freeradius-devel/unlang/function.h>
#include "types.h"
#include "attrs.h"

fr_dict_t const *dict_freeradius;
fr_dict_t const *dict_radius;
static fr_dict_t const *dict_tls;

extern fr_dict_autoload_t eap_base_dict[];
fr_dict_autoload_t eap_base_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ .out = &dict_tls, .proto = "tls" },
	DICT_AUTOLOAD_TERMINATOR
};

fr_dict_attr_t const *attr_chbind_response_code;
fr_dict_attr_t const *attr_eap_session_id;
fr_dict_attr_t const *attr_eap_identity;
fr_dict_attr_t const *attr_eap_type;
fr_dict_attr_t const *attr_packet_type;
fr_dict_attr_t const *attr_message_authenticator;
fr_dict_attr_t const *attr_eap_channel_binding_message;
fr_dict_attr_t const *attr_eap_message;
fr_dict_attr_t const *attr_eap_msk;
fr_dict_attr_t const *attr_eap_emsk;
fr_dict_attr_t const *attr_framed_mtu;
fr_dict_attr_t const *attr_freeradius_proxied_to;
fr_dict_attr_t const *attr_ms_mppe_send_key;
fr_dict_attr_t const *attr_ms_mppe_recv_key;
fr_dict_attr_t const *attr_state;
fr_dict_attr_t const *attr_user_name;
fr_dict_attr_t const *attr_tls_min_version;
fr_dict_attr_t const *attr_tls_max_version;

extern fr_dict_attr_autoload_t eap_base_dict_attr[];
fr_dict_attr_autoload_t eap_base_dict_attr[] = {
	{ .out = &attr_chbind_response_code, .name = "Chbind-Response-Code", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_eap_identity, .name = "EAP-Identity", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_eap_session_id, .name = "EAP-Session-Id", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_eap_type, .name = "EAP-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_state, .name = "State", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_message_authenticator, .name = "Message-Authenticator", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_eap_channel_binding_message, .name = "Vendor-Specific.UKERNA.EAP-Channel-Binding-Message", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_eap_message, .name = "EAP-Message", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_eap_msk, .name = "EAP-MSK", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_eap_emsk, .name = "EAP-EMSK", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_framed_mtu, .name = "Framed-MTU", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_freeradius_proxied_to, .name = "Vendor-Specific.FreeRADIUS.Proxied-To", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_radius },
	{ .out = &attr_ms_mppe_send_key, .name = "Vendor-Specific.Microsoft.MPPE-Send-Key", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_ms_mppe_recv_key, .name = "Vendor-Specific.Microsoft.MPPE-Recv-Key", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_tls_min_version, .name = "Min-Version", .type = FR_TYPE_FLOAT32, .dict = &dict_tls },
	{ .out = &attr_tls_max_version, .name = "Max-Version", .type = FR_TYPE_FLOAT32, .dict = &dict_tls },

	DICT_AUTOLOAD_TERMINATOR
};

void eap_packet_to_vp(TALLOC_CTX *ctx, fr_pair_list_t *list, eap_packet_raw_t const *eap)
{
	int		total, size;
	uint8_t const *ptr;
	fr_pair_t	*vp;

	total = eap->length[0] * 256 + eap->length[1];

	if (total == 0) {
		DEBUG("Asked to encode empty EAP-Message!");
		return;
	}

	ptr = (uint8_t const *) eap;

	do {
		size = total;
		if (size > 253) size = 253;

		MEM(vp = fr_pair_afrom_da(ctx, attr_eap_message));
		fr_pair_value_memdup(vp, ptr, size, false);

		fr_pair_append(list, vp);

		ptr += size;
		total -= size;
	} while (total > 0);
}

/** Basic EAP packet verifications & validations
 *
 * @param[in] ctx		talloc ctx for the eap packet.
 * @param[in] eap_packet_p	to validate.
 * @return
 *	- true the packet is valid.
 *	- false the packet is invalid.
 */
static bool eap_is_valid(TALLOC_CTX *ctx, eap_packet_raw_t **eap_packet_p)
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
		fr_strerror_printf("Invalid EAP data length %zu <= 4", packet_len);
		return false;
	}

	memcpy(&len, eap_packet->length, sizeof(uint16_t));
	len = ntohs(len);

	if ((len <= EAP_HEADER_LEN) || (len > packet_len)) {
		fr_strerror_printf("Invalid EAP length field.  Expected value in range %d-%zu, was %u bytes",
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
				fr_strerror_const("Expanded EAP type is too short: ignoring the packet");
				return false;
			}

			if ((eap_packet->data[1] != 0) ||
			    (eap_packet->data[2] != 0) ||
			    (eap_packet->data[3] != 0)) {
				fr_strerror_const("Expanded EAP type has unknown Vendor-ID: ignoring the packet");
				return false;
			}

			if ((eap_packet->data[4] != 0) ||
			    (eap_packet->data[5] != 0) ||
			    (eap_packet->data[6] != 0)) {
				fr_strerror_const("Expanded EAP type has unknown Vendor-Type: ignoring the packet");
				return false;
			}

			if ((eap_packet->data[7] == 0) ||
			    (eap_packet->data[7] >= FR_EAP_METHOD_MAX)) {
				fr_strerror_printf("Unsupported Expanded EAP type %s (%u): ignoring the packet",
						   eap_type2name(eap_packet->data[7]), eap_packet->data[7]);
				return false;
			}

			if (eap_packet->data[7] == FR_EAP_METHOD_NAK) {
				fr_strerror_const("Unsupported Expanded EAP-NAK: ignoring the packet");
				return false;
			}

			/*
			 *	Re-write the EAP packet to NOT have the expanded type.
			 */
			q = (uint8_t *) eap_packet;
			memmove(q + EAP_HEADER_LEN, q + EAP_HEADER_LEN + 7, len - 7 - EAP_HEADER_LEN);

			p = talloc_realloc(ctx, eap_packet, uint8_t, len - 7);
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
		fr_strerror_const("Got NOTIFICATION, Ignoring the packet");
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
eap_packet_raw_t *eap_packet_from_vp(TALLOC_CTX *ctx, fr_pair_list_t *vps)
{
	fr_pair_t		*vp;
	eap_packet_raw_t	*eap_packet;
	unsigned char		*ptr;
	uint16_t		len;
	int			total_len;
	fr_dcursor_t		cursor;

	/*
	 *	Get only EAP-Message attribute list
	 */
	vp = fr_pair_dcursor_by_da_init(&cursor, vps, attr_eap_message);
	if (!vp) {
		fr_strerror_const("EAP-Message not found");
		return NULL;
	}

	/*
	 *	Sanity check the length before doing anything.
	 */
	if (vp->vp_length < EAP_HEADER_LEN) {
		fr_strerror_const("EAP packet is too short");
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
	if (len < EAP_HEADER_LEN) {
		fr_strerror_const("EAP packet has invalid length (less than 4 bytes)");
		return NULL;
	}

	/*
	 *	Sanity check the length, BEFORE allocating  memory.
	 */
	total_len = 0;
	for (vp = fr_dcursor_head(&cursor);
	     vp;
	     vp = fr_dcursor_next(&cursor)) {
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
	for (vp = fr_dcursor_head(&cursor);
	     vp;
	     vp = fr_dcursor_next(&cursor)) {
		memcpy(ptr, vp->vp_strvalue, vp->vp_length);
		ptr += vp->vp_length;
	}

	if (!eap_is_valid(ctx, &eap_packet)) {
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
	RDEBUG2("reply.%pP", vp);
	REXDENT();
}

/** Handle the result of running a subrequest through a virtual server
 *
 * Storing the value of the State attribute in readiness for the next round.
 */
static unlang_action_t eap_virtual_server_resume(UNUSED unlang_result_t *p_result,
						 request_t *request, void *uctx)
{
	eap_session_t	*eap_session = talloc_get_type_abort(uctx, eap_session_t);

	/*
	 *	Grab the child's session state for re-use in the next round
	 */
	fr_state_store_in_parent(request, eap_session->identity, REQUEST_DATA_EAP_SESSION);

	return UNLANG_ACTION_CALCULATE_RESULT;
}

/** Run a subrequest through a virtual server
 *
 * If eap_session_t has a child_state, inject that as an attribute in the request.
 *
 * @param[in] request		the current (real) request.
 * @param[in] eap_session	representing the outer eap method.
 * @param[in] virtual_server	The virtual server to send the request to.
 * @return
 * 	- UNLANG_ACTION_PUSHED_CHILD on success
 *	- UNLANG_ACTION_FAIL on error
 */
unlang_action_t eap_virtual_server(request_t *request, eap_session_t *eap_session, virtual_server_t *virtual_server)
{
	fr_pair_t	*vp;

	fr_assert(request->parent);
	fr_assert(virtual_server);

	RDEBUG2("Running request through virtual server \"%s\"", cf_section_name2(virtual_server_cs(virtual_server)));

	/*
	 *	Re-present the previously stored child's session state if there is one
	 */
	fr_state_restore_to_child(request, eap_session->identity, REQUEST_DATA_EAP_SESSION);

	if (fr_pair_prepend_by_da(request->request_ctx, &vp, &request->request_pairs,
				  attr_packet_type) < 0) return UNLANG_ACTION_FAIL;
	vp->vp_uint32 = FR_RADIUS_CODE_ACCESS_REQUEST;

	if (unlang_function_push_with_result(/* transparent */ unlang_interpret_result(request),
					     request,
					     NULL,
					     eap_virtual_server_resume,
					     NULL, 0,
					     UNLANG_SUB_FRAME,
					     eap_session) < 0) return UNLANG_ACTION_FAIL;

	if (unlang_call_push(NULL, request, virtual_server_cs(virtual_server), UNLANG_SUB_FRAME) < 0) return UNLANG_ACTION_FAIL;

	return UNLANG_ACTION_PUSHED_CHILD;
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
