/*
 * eap_chbind.c
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
 * Copyright 2014  Network RADIUS SARL
 * Copyright 2014  The FreeRADIUS server project
 */


RCSID("$Id$")

#include "eap_chbind.h"

static bool chbind_build_response(REQUEST *request, CHBIND_REQ *chbind)
{
	int length;
	size_t total;
	uint8_t *ptr, *end;
	VALUE_PAIR const *vp;
	vp_cursor_t cursor;

	total = 0;
	for (vp = fr_cursor_init(&cursor, &request->reply->vps);
	     vp != NULL;
	     vp = fr_cursor_next(&cursor)) {
		/*
		 *	Skip things which shouldn't be in channel bindings.
		 */
		if (vp->da->flags.encrypt != FLAG_ENCRYPT_NONE) continue;
		if (!vp->da->vendor && (vp->da->attr == PW_MESSAGE_AUTHENTICATOR)) continue;

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
	vp = fr_pair_find_by_num(request->config, PW_CHBIND_RESPONSE_CODE, 0, TAG_ANY);
	if (vp) {
		ptr[0] = vp->vp_integer;
	} else {
		ptr[0] = CHBIND_CODE_FAILURE;
	}

	if (!total) return true; /* nothing to encode */

	/* Write the length field into the header */
	ptr[1] = (total >> 8) & 0xff;
	ptr[2] = total & 0xff;
	ptr[3] = CHBIND_NSID_RADIUS;

	RDEBUG("Sending chbind response: code %i", (int )(ptr[0]));
	rdebug_pair_list(L_DBG_LVL_1, request, request->reply->vps, NULL);

	/* Encode the chbind attributes into the response */
	ptr += 4;
	end = ptr + total;
	for (vp = fr_cursor_init(&cursor, &request->reply->vps);
	     vp != NULL;
	     vp = fr_cursor_next(&cursor)) {
		/*
		 *	Skip things which shouldn't be in channel bindings.
		 */
		if (vp->da->flags.encrypt != FLAG_ENCRYPT_NONE) continue;
		if (!vp->da->vendor && (vp->da->attr == PW_MESSAGE_AUTHENTICATOR)) continue;

		length = rad_vp2attr(NULL, NULL, NULL, &vp, ptr, end - ptr);
		if (length < 0) continue;
		ptr += length;
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


PW_CODE chbind_process(REQUEST *request, CHBIND_REQ *chbind)
{
	PW_CODE rcode;
	REQUEST *fake = NULL;
	VALUE_PAIR *vp = NULL;
	uint8_t const *attr_data;
	size_t data_len = 0;

	/* check input parameters */
	rad_assert((request != NULL) &&
		   (chbind != NULL) &&
		   (chbind->request != NULL) &&
		   (chbind->response == NULL));

	/* Set-up the fake request */
	fake = request_alloc_fake(request);
	fr_pair_make(fake->packet, &fake->packet->vps, "Freeradius-Proxied-To", "127.0.0.1", T_OP_EQ);

	/* Add the username to the fake request */
	if (chbind->username) {
		vp = fr_pair_copy(fake->packet, chbind->username);
		fr_pair_add(&fake->packet->vps, vp);
		fake->username = vp;
	}

	/*
	 *	Maybe copy the State over, too?
	 */

	/* Add the channel binding attributes to the fake packet */
	data_len = chbind_get_data(chbind->request, CHBIND_NSID_RADIUS, &attr_data);
	if (data_len) {
		rad_assert(data_len <= talloc_array_length((uint8_t const *) chbind->request));

		while (data_len > 0) {
			int attr_len = rad_attr2vp(fake->packet, NULL, NULL, NULL, attr_data, data_len, &vp);
			if (attr_len <= 0) {
				/* If radaddr2vp fails, return NULL string for
				   channel binding response */
				talloc_free(fake);
				return PW_CODE_ACCESS_ACCEPT;
			}
			if (vp) {
				fr_pair_add(&fake->packet->vps, vp);
			}
			attr_data += attr_len;
			data_len -= attr_len;
		}
	}

	/*
	 *	Set virtual server based on configuration for channel
	 *	bindings, this is hard-coded for now.
	 */
	fake->server = "channel_bindings";
	fake->packet->code = PW_CODE_ACCESS_REQUEST;

	switch (rad_virtual_server(fake)) {
		/* If rad_authenticate succeeded, build a reply */
	case RLM_MODULE_OK:
	case RLM_MODULE_HANDLED:
		if (chbind_build_response(fake, chbind)) {
			rcode = PW_CODE_ACCESS_ACCEPT;
			break;
		}
		/* FALL-THROUGH */

		/* If we got any other response from rad_authenticate, it maps to a reject */
	default:
		rcode = PW_CODE_ACCESS_REJECT;
		break;
	}

	talloc_free(fake);

	return rcode;
}

/*
 *	Handles multiple EAP-channel-binding Message attrs
 *	ie concatenates all to get the complete EAP-channel-binding packet.
 */
chbind_packet_t *eap_chbind_vp2packet(TALLOC_CTX *ctx, VALUE_PAIR *vps)
{
	size_t length;
	uint8_t *ptr;
	VALUE_PAIR *first, *vp;
	chbind_packet_t *packet;
	vp_cursor_t cursor;

	first = fr_pair_find_by_num(vps, PW_UKERNA_CHBIND, VENDORPEC_UKERNA, TAG_ANY);
	if (!first) return NULL;

	/*
	 *	Compute the total length of the channel binding data.
	 */
	length = 0;
	for (vp =fr_cursor_init(&cursor, &first);
	     vp != NULL;
	     vp = fr_cursor_next_by_num(&cursor, PW_UKERNA_CHBIND, VENDORPEC_UKERNA, TAG_ANY)) {
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
	for (vp = fr_cursor_init(&cursor, &first);
	     vp != NULL;
	     vp = fr_cursor_next_by_num(&cursor, PW_UKERNA_CHBIND, VENDORPEC_UKERNA, TAG_ANY)) {
		memcpy(ptr, vp->vp_octets, vp->vp_length);
		ptr += vp->vp_length;
	}

	return packet;
}

VALUE_PAIR *eap_chbind_packet2vp(RADIUS_PACKET *packet, chbind_packet_t *chbind)
{
	VALUE_PAIR	*vp;

	if (!chbind) return NULL; /* don't produce garbage */

	vp = fr_pair_afrom_num(packet, PW_UKERNA_CHBIND, VENDORPEC_UKERNA);
	if (!vp) return NULL;
	fr_pair_value_memcpy(vp, (uint8_t *) chbind, talloc_array_length((uint8_t *)chbind));

	return vp;
}
