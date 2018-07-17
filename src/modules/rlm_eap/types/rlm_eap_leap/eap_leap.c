/*
 * eap_leap.c  EAP LEAP functionality.
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
 * @copyright 2003 Alan DeKok <aland@freeradius.org>
 * @copyright 2006 The FreeRADIUS server project
 */

/*
 *
 *  LEAP Packet Format in EAP Type-Data
 *  --- ------ ------ -- --- ---------
 *    0		   1		   2			3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     Type 0x11 |  Version 0x01 | Unused 0x00   | Count 0x08    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |	       Peer Challenge				   |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |	       Peer Challenge				   |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |   User Name .....
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-
 *
 *  Count is 8 octets since the Peer challenge is 8 bytes.
 *  Count is 24 for EAP response, with MSCHAP response.
 *  Length is the total number of octets in the EAP-Message.
 *
 *  The LEAP type (0x11) is *not* included in the type data...
 */

RCSID("$Id$")

#include <stdio.h>
#include <stdlib.h>
#include "eap.h"
#include "eap_leap.h"

#include <freeradius-devel/util/md5.h>

/*
 *   Extract the data from the LEAP packet.
 */
leap_packet_t *eap_leap_extract(REQUEST *request, eap_round_t *eap_round)
{
	leap_packet_raw_t	*data;
	leap_packet_t		*packet;
	int			name_len;

	/*
	 *	LEAP can have EAP-Response or EAP-Request (step 5)
	 *	messages sent to it.
	 */
	if (!eap_round || !eap_round->response ||
	    ((eap_round->response->code != FR_EAP_CODE_RESPONSE) && (eap_round->response->code != FR_EAP_CODE_REQUEST)) ||
	     (eap_round->response->type.num != FR_EAP_LEAP) || !eap_round->response->type.data ||
	     (eap_round->response->length < LEAP_HEADER_LEN) ||
	     (eap_round->response->type.data[0] != 0x01)) {	/* version 1 */
		REDEBUG("Corrupted data");
		return NULL;
	}

	/*
	 *	Hmm... this cast isn't the best thing to do.
	 */
	data = (leap_packet_raw_t *)eap_round->response->type.data;

	/*
	 *	Some simple sanity checks on the incoming packet.
	 *
	 *	See 'leap.txt' in this directory for a description
	 *	of the stages.
	 */
	switch (eap_round->response->code) {
	case FR_EAP_CODE_RESPONSE:
		if (data->count != 24) {
			REDEBUG("Bad NTChallengeResponse in LEAP stage 3");
			return NULL;
		}
		break;

	case FR_EAP_CODE_REQUEST:
		if (data->count != 8) {
			REDEBUG("Bad AP Challenge in LEAP stage 5");
			return NULL;
		}
		break;

	default:
		REDEBUG("Invalid EAP code %d", eap_round->response->code);
		return NULL;
	}

	packet = talloc(eap_round, leap_packet_t);
	if (!packet) return NULL;

	/*
	 *	Remember code, length, and id.
	 */
	packet->code = eap_round->response->code;
	packet->id = eap_round->response->id;

	/*
	 *	The size of the LEAP portion of the packet, not
	 *	counting the EAP header and the type.
	 */
	packet->length = eap_round->response->length - EAP_HEADER_LEN - 1;

	/*
	 *	Remember the length of the challenge.
	 */
	packet->count = data->count;

	packet->challenge = talloc_array(packet, uint8_t, packet->count);
	if (!packet->challenge) {
		talloc_free(packet);
		return NULL;
	}
	memcpy(packet->challenge, data->challenge, packet->count);

	/*
	 *	The User-Name comes after the challenge.
	 *
	 *	Length of the EAP-LEAP portion of the packet, minus
	 *	3 octets for data, minus the challenge size, is the
	 *	length of the user name.
	 */
	name_len = packet->length - 3 - packet->count;
	if (name_len > 0) {
		packet->name = talloc_array(packet, char, name_len + 1);
		if (!packet->name) {
			talloc_free(packet);
			return NULL;
		}
		memcpy(packet->name, &data->challenge[packet->count], name_len);
		packet->name[name_len] = '\0';
		packet->name_len = name_len;
	}

	return packet;
}

/*
 *  Get the NT-Password hash.
 */
static int eap_leap_ntpwdhash(uint8_t *out, REQUEST *request, VALUE_PAIR *password)
{
	if ((password->da == attr_user_password) ||
	    (password->da == attr_cleartext_password)) {
		ssize_t len;
		uint8_t ucs2_password[512];

		/*
		 *	Convert the password to NT's weird Unicode format.
		 */
		len = fr_utf8_to_ucs2(ucs2_password, sizeof(ucs2_password), password->vp_strvalue, password->vp_length);
		if (len < 0) {
			REDEBUG("Error converting password to UCS2");
			return 0;
		}

		/*
		 *  Get the NT Password hash.
		 */
		fr_md4_calc(out, ucs2_password, len);
	} else {		/* MUST be NT-Password */
		uint8_t *p = NULL;

		if (password->vp_length == 32) {
			p = talloc_array(password, uint8_t, 16);
			password->vp_length = fr_hex2bin(p, 16, password->vp_strvalue, password->vp_length);
		}
		if (password->vp_length != 16) {
			REDEBUG("Bad NT-Password");
			return 0;
		}

		if (p) {
			fr_pair_value_memcpy(password, p, 16);
			talloc_free(p);
		}

		memcpy(out, password->vp_octets, 16);
	}
	return 1;
}


/*
 *	Verify the MS-CHAP response from the user.
 */
int eap_leap_stage4(REQUEST *request, leap_packet_t *packet, VALUE_PAIR *password, leap_session_t *session)
{
	uint8_t hash[16];
	uint8_t response[24];

	/*
	 *	No password or previous packet.  Die.
	 */
	if ((!password) || (!session)) {
		return 0;
	}

	if (!eap_leap_ntpwdhash(hash, request, password)) {
		return 0;
	}

	/*
	 *	Calculate and verify the CHAP challenge.
	 */
	eap_leap_mschap(hash, session->peer_challenge, response);
	if (memcmp(response, packet->challenge, 24) == 0) {
		RDEBUG2("NTChallengeResponse from AP is valid");
		memcpy(session->peer_response, response, sizeof(response));
		return 1;
	}
	REDEBUG("FAILED incorrect NtChallengeResponse from AP");

	return 0;
}

/*
 *	Verify ourselves to the AP
 */
leap_packet_t *eap_leap_stage6(REQUEST *request, leap_packet_t *packet, VALUE_PAIR *user_name, VALUE_PAIR *password,
			      leap_session_t *session)
{
	size_t		i;
	uint8_t 	hash[16], mppe[16];
	uint8_t		*p, buffer[256];
	leap_packet_t	*reply;
	char		*q;
	VALUE_PAIR	*vp;

	/*
	 *	No password or previous packet.  Die.
	 */
	if ((!password) || (!session)) {
		return NULL;
	}

	reply = talloc(session, leap_packet_t);
	if (!reply) return NULL;

	reply->code = FR_EAP_CODE_RESPONSE;
	reply->length = LEAP_HEADER_LEN + 24 + user_name->vp_length;
	reply->count = 24;

	reply->challenge = talloc_array(reply, uint8_t, reply->count);
	if (!reply->challenge) {
		talloc_free(reply);
		return NULL;
	}

	/*
	 *	The LEAP packet also contains the user name.
	 */
	reply->name = talloc_array(reply, char, user_name->vp_length + 1);
	if (!reply->name) {
		talloc_free(reply);
		return NULL;
	}

	/*
	 *	Copy the name over, and ensure it's NUL terminated.
	 */
	memcpy(reply->name, user_name->vp_strvalue, user_name->vp_length);
	reply->name[user_name->vp_length] = '\0';
	reply->name_len = user_name->vp_length;

	/*
	 *  MPPE hash = ntpwdhash(ntpwdhash(unicode(pw)))
	 */
	if (!eap_leap_ntpwdhash(hash, request, password)) {
		talloc_free(reply);
		return NULL;
	}
	fr_md4_calc(mppe, hash, 16);

	/*
	 *	Calculate our response, to authenticate ourselves to the AP.
	 */
	eap_leap_mschap(mppe, packet->challenge, reply->challenge);

	/*
	 *	Calculate the leap:session-key attribute
	 */
	MEM(pair_add_reply(&vp, attr_cisco_avpair) >= 0);

	/*
	 *	And calculate the MPPE session key.
	 */
	p = buffer;
	memcpy(p, mppe, 16); /* MPPEHASH */
	p += 16;
	memcpy(p, packet->challenge, 8); /* APC */
	p += 8;
	memcpy(p, reply->challenge, 24); /* APR */
	p += 24;
	memcpy(p, session->peer_challenge, 8); /* PC */
	p += 8;
	memcpy(p, session->peer_response, 24); /* PR */

	/*
	 *	These 16 bytes are the session key to use.
	 */
	fr_md5_calc(hash, buffer, 16 + 8 + 24 + 8 + 24);

	q = talloc_array(vp, char, FR_TUNNEL_FR_ENC_LENGTH(16) + sizeof("leap:session-key="));
	strcpy(q, "leap:session-key=");

	memcpy(q + 17, hash, 16);

	i = 16;
	fr_radius_encode_tunnel_password(q + 17, &i, request->client->secret, request->packet->vector);
	fr_pair_value_strsteal(vp, q);
	vp->vp_length = 17 + i;

	return reply;
}

/*
 *	If an EAP LEAP request needs to be initiated then
 *	create such a packet.
 */
leap_packet_t *eap_leap_initiate(REQUEST *request, eap_round_t *eap_round, VALUE_PAIR *user_name)
{
	int i;
	leap_packet_t 	*reply;

	reply = talloc(eap_round, leap_packet_t);
	if (!reply)  {
		return NULL;
	}

	reply->code = FR_EAP_CODE_REQUEST;
	reply->length = LEAP_HEADER_LEN + 8 + user_name->vp_length;
	reply->count = 8;	/* random challenge */

	reply->challenge = talloc_array(reply, uint8_t, reply->count);
	if (!reply->challenge) {
		talloc_free(reply);
		return NULL;
	}

	/*
	 *	Fill the challenge with random bytes.
	 */
	for (i = 0; i < reply->count; i++) {
		reply->challenge[i] = fr_rand();
	}
	RDEBUG2("Issuing AP Challenge");

	/*
	 *	The LEAP packet also contains the user name.
	 */
	reply->name = talloc_array(reply, char, user_name->vp_length + 1);
	if (!reply->name) {
		talloc_free(reply);
		return NULL;
	}

	/*
	 *	Copy the name over, and ensure it's NUL terminated.
	 */
	memcpy(reply->name, user_name->vp_strvalue, user_name->vp_length);
	reply->name[user_name->vp_length] = '\0';
	reply->name_len = user_name->vp_length;

	return reply;
}

/*
 * compose the LEAP reply packet in the EAP reply typedata
 */
int eap_leap_compose(REQUEST *request, eap_round_t *eap_round, leap_packet_t *reply)
{
	leap_packet_raw_t *data;

	rad_assert(eap_round->request);
	rad_assert(reply);

	/*
	 *  We need the name and the challenge.
	 */
	switch (reply->code) {
	case FR_EAP_CODE_REQUEST:
	case FR_EAP_CODE_RESPONSE:
		eap_round->request->type.num = FR_EAP_LEAP;
		eap_round->request->type.length = reply->length;

		eap_round->request->type.data = talloc_array(eap_round->request, uint8_t, reply->length);
		if (!eap_round->request->type.data) return 0;

		data = (leap_packet_raw_t *) eap_round->request->type.data;
		data->version = 0x01;
		data->unused = 0;
		data->count = reply->count;

		/*
		 *	N bytes of the challenge, followed by the user name.
		 */
		memcpy(&data->challenge[0], reply->challenge, reply->count);
		memcpy(&data->challenge[reply->count], reply->name, reply->name_len);
		break;

		/*
		 *	EAP-Success packets don't contain any data
		 *	other than the header.
		 */
	case FR_EAP_CODE_SUCCESS:
		eap_round->request->type.length = 0;
		break;

	default:
		REDEBUG("Internal sanity check failed");
		return 0;
	}

	/*
	 *	Set the EAP code.
	 */
	eap_round->request->code = reply->code;

	return 1;
}
