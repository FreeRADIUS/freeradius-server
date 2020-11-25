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
 * @file lib/eap/chbind.c
 * @brief Channel binding
 *
 * @copyright 2014 Network RADIUS SARL
 * @copyright 2014 The FreeRADIUS server project
 */

RCSID("$Id$")

#include <freeradius-devel/radius/defs.h>
#include <freeradius-devel/radius/radius.h>

#include <freeradius-devel/io/pair.h>
#include "chbind.h"
#include "attrs.h"

static bool chbind_build_response(request_t *request, CHBIND_REQ *chbind)
{
	ssize_t			slen;
	size_t			total;
	uint8_t			*ptr, *end;
	fr_pair_t		const *vp;
	fr_cursor_t		cursor;

	total = 0;
	for (vp = fr_cursor_init(&cursor, &request->reply_pairs);
	     vp != NULL;
	     vp = fr_cursor_next(&cursor)) {
		/*
		 *	Skip things which shouldn't be in channel bindings.
		 */
		if (vp->da->flags.internal || (!vp->da->flags.extra && vp->da->flags.subtype)) continue;
		if (vp->da == attr_message_authenticator) continue;

		total += 2 + vp->vp_length;
	}

	/*
	 *	No attributes: just send a 1-byte response code.
	 */
	if (!total) {
		ptr = talloc_zero_array(chbind, uint8_t, 1);
	} else {
		ptr = talloc_zero_array(chbind, uint8_t, total + 4);
	}
	if (!ptr) return false;
	chbind->response = (chbind_packet_t *) ptr;

	/*
	 *	Set the response code.  Default to "fail" if none was
	 *	specified.
	 */
	vp = fr_pair_find_by_da(&request->control_pairs, attr_chbind_response_code);
	if (vp) {
		ptr[0] = vp->vp_uint32;
	} else {
		ptr[0] = CHBIND_CODE_FAILURE;
	}

	if (!total) return true; /* nothing to encode */

	/* Write the length field into the header */
	ptr[1] = (total >> 8) & 0xff;
	ptr[2] = total & 0xff;
	ptr[3] = CHBIND_NSID_RADIUS;

	RDEBUG2("Sending chbind response: code %i", (int )(ptr[0]));
	log_request_pair_list(L_DBG_LVL_1, request, request->reply_pairs, NULL);

	/* Encode the chbind attributes into the response */
	ptr += 4;
	end = ptr + total;

	fr_cursor_init(&cursor, &request->reply_pairs);
	while ((vp = fr_cursor_current(&cursor)) && (ptr < end)) {
		/*
		 *	Skip things which shouldn't be in channel bindings.
		 *	i.e. tagged, encrypted, or extended attributes
		 */
		if (vp->da->flags.subtype) {
		next:
			fr_cursor_next(&cursor);
			continue;
		}
		if (vp->da == attr_message_authenticator) goto next;

		slen = fr_radius_encode_pair(&FR_DBUFF_TMP(ptr, end), &cursor, NULL);
		if (slen < 0) {
			if (slen == PAIR_ENCODE_SKIPPED) goto next;

			RPERROR("Failed encoding chbind response");

			talloc_free(ptr);
			return false;
		}
		ptr += slen;
	}

	return true;
}


/*
 *	Parse channel binding packet to obtain data for a specific
 *	NSID.
 *
 *	See:
 *	http://tools.ietf.org/html/draft-ietf-emu-chbind-13#section-5.3.2
 */
static size_t chbind_get_data(chbind_packet_t const *packet,
			      int desired_nsid,
			      uint8_t const **data)
{
	uint8_t const *ptr;
	uint8_t const *end;

	if (packet->code != CHBIND_CODE_REQUEST) {
		return 0;
	}

	ptr = (uint8_t const *) packet;
	end = ptr + talloc_array_length((uint8_t const *) packet);

	ptr++;			/* skip the code at the start of the packet */
	while (ptr < end) {
		uint8_t nsid;
		size_t length;

		/*
		 *	Need room for length(2) + NSID + data.
		 */
		if ((end - ptr) < 4) return 0;

		length = (ptr[0] << 8) | ptr[1];
		if (length == 0) return 0;

		if ((ptr + length + 3) > end) return 0;

		nsid = ptr[2];
		if (nsid == desired_nsid) {
			ptr += 3;
			*data = ptr;
			return length;
		}

		ptr += 3 + length;
	}

	return 0;
}


FR_CODE chbind_process(request_t *request, CHBIND_REQ *chbind)
{
	FR_CODE		code;
	rlm_rcode_t	rcode;
	request_t		*fake = NULL;
	uint8_t const	*attr_data;
	size_t		data_len = 0;
	fr_pair_t	*vp;

	/* check input parameters */
	fr_assert((request != NULL) &&
		   (chbind != NULL) &&
		   (chbind->request != NULL) &&
		   (chbind->response == NULL));

	/* Set-up the fake request */
	fake = request_alloc_fake(request, NULL);
	MEM(fr_pair_add_by_da(fake->packet, &vp, &fake->request_pairs, attr_freeradius_proxied_to) >= 0);
	fr_pair_value_from_str(vp, "127.0.0.1", sizeof("127.0.0.1"), '\0', false);

	/* Add the username to the fake request */
	if (chbind->username) {
		vp = fr_pair_copy(fake->packet, chbind->username);
		fr_pair_add(&fake->request_pairs, vp);
	}

	/*
	 *	Maybe copy the State over, too?
	 */

	/* Add the channel binding attributes to the fake packet */
	data_len = chbind_get_data(chbind->request, CHBIND_NSID_RADIUS, &attr_data);
	if (data_len) {
		fr_cursor_t cursor;

		fr_assert(data_len <= talloc_array_length((uint8_t const *) chbind->request));

		fr_cursor_init(&cursor, &fake->request_pairs);
		while (data_len > 0) {
			ssize_t attr_len;

			attr_len = fr_radius_decode_pair(fake->packet, &cursor, dict_radius,
							 attr_data, data_len, NULL);
			if (attr_len <= 0) {
				/*
				 *	If fr_radius_decode_pair fails, return NULL string for
				 *	channel binding response.
				 */
				talloc_free(fake);

				return FR_CODE_ACCESS_ACCEPT;
			}
			attr_data += attr_len;
			data_len -= attr_len;
		}
	}

	/*
	 *	Set virtual server based on configuration for channel
	 *	bindings, this is hard-coded for now.
	 */
	fake->server_cs = virtual_server_find("channel_bindings");
	fake->packet->code = FR_CODE_ACCESS_REQUEST;

	rad_virtual_server(&rcode, fake);
	switch (rcode) {
		/* If the virtual server succeeded, build a reply */
	case RLM_MODULE_OK:
	case RLM_MODULE_HANDLED:
		if (chbind_build_response(fake, chbind)) {
			code = FR_CODE_ACCESS_ACCEPT;
			break;
		}
		FALL_THROUGH;

		/* If we got any other response from the virtual server, it maps to a reject */
	default:
		code = FR_CODE_ACCESS_REJECT;
		break;
	}

	talloc_free(fake);

	return code;
}

/*
 *	Handles multiple EAP-channel-binding Message attrs
 *	ie concatenates all to get the complete EAP-channel-binding packet.
 */
chbind_packet_t *eap_chbind_vp2packet(TALLOC_CTX *ctx, fr_pair_t *vps)
{
	size_t			length;
	uint8_t 		*ptr;
	fr_pair_t		*vp;
	chbind_packet_t		*packet;
	fr_cursor_t		cursor;

	if (!fr_cursor_iter_by_da_init(&cursor, &vps, attr_eap_channel_binding_message)) return NULL;

	/*
	 *	Compute the total length of the channel binding data.
	 */
	length = 0;
	for (vp = fr_cursor_current(&cursor);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		length += vp->vp_length;
	}

	if (length < 4) {
		DEBUG("Invalid length %u for channel binding data", (unsigned int) length);
		return NULL;
	}

	/*
	 *	Now that we know the length, allocate memory for the packet.
	 */
	ptr = talloc_zero_array(ctx, uint8_t, length);
	if (!ptr) return NULL;

	/*
	 *	Copy the data over to our packet.
	 */
	packet = (chbind_packet_t *) ptr;
	for (vp = fr_cursor_head(&cursor);
	     vp != NULL;
	     vp = fr_cursor_next(&cursor)) {
		memcpy(ptr, vp->vp_octets, vp->vp_length);
		ptr += vp->vp_length;
	}

	return packet;
}

fr_pair_t *eap_chbind_packet2vp(fr_radius_packet_t *packet, chbind_packet_t *chbind)
{
	fr_pair_t	*vp;

	if (!chbind) return NULL; /* don't produce garbage */

	MEM(vp = fr_pair_afrom_da(packet, attr_eap_channel_binding_message));
	fr_pair_value_memdup(vp, (uint8_t *) chbind, talloc_array_length((uint8_t *)chbind), false);

	return vp;
}
