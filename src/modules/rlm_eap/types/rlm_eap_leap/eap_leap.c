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
 * Copyright 2003 Alan DeKok <aland@freeradius.org>
 * Copyright 2006 The FreeRADIUS server project
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

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <stdio.h>
#include <stdlib.h>
#include "eap.h"
#include "eap_leap.h"
/*
 *   Extract the data from the LEAP packet.
 */
leap_packet_t *eapleap_extract(EAP_DS *eap_ds)
{
	leap_packet_raw_t	*data;
	leap_packet_t	*packet;
	int		name_len;

	/*
	 *	LEAP can have EAP-Response or EAP-Request (step 5)
	 *	messages sent to it.
	 */
	if (!eap_ds ||
	    !eap_ds->response ||
	    ((eap_ds->response->code != PW_EAP_RESPONSE) &&
	     (eap_ds->response->code != PW_EAP_REQUEST)) ||
	    eap_ds->response->type.num != PW_EAP_LEAP ||
	    !eap_ds->response->type.data ||
	    (eap_ds->response->length < LEAP_HEADER_LEN) ||
	    (eap_ds->response->type.data[0] != 0x01)) {	/* version 1 */
		radlog(L_ERR, "rlm_eap_leap: corrupted data");
		return NULL;
	}

	/*
	 *	Hmm... this cast isn't the best thing to do.
	 */
	data = (leap_packet_raw_t *)eap_ds->response->type.data;

	/*
	 *	Some simple sanity checks on the incoming packet.
	 *
	 *	See 'leap.txt' in this directory for a description
	 *	of the stages.
	 */
	switch (eap_ds->response->code) {
	case PW_EAP_RESPONSE:
		if (data->count != 24) {
			radlog(L_ERR, "rlm_eap_leap: Bad NTChallengeResponse in LEAP stage 3");
			return NULL;
		}
		break;

	case PW_EAP_REQUEST:
		if (data->count != 8) {
			radlog(L_ERR, "rlm_eap_leap: Bad AP Challenge in LEAP stage 5");
			return NULL;
		}
		break;

	default:
		radlog(L_ERR, "rlm_eap_leap: Invalid EAP code %d",
		       eap_ds->response->code);
		return NULL;
		break;
	}

	packet = talloc(eap_ds, leap_packet_t);
	if (!packet) return NULL;

	/*
	 *	Remember code, length, and id.
	 */
	packet->code = eap_ds->response->code;
	packet->id = eap_ds->response->id;

	/*
	 *	The size of the LEAP portion of the packet, not
	 *	counting the EAP header and the type.
	 */
	packet->length = eap_ds->response->length - EAP_HEADER_LEN - 1;

	/*
	 *	Remember the length of the challenge.
	 */
	packet->count = data->count;

	packet->challenge = talloc_array(packet, uint8_t, packet->count);
	if (packet->challenge == NULL) {
		radlog(L_ERR, "rlm_eap_leap: out of memory");
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
			radlog(L_ERR, "rlm_eap_leap: out of memory");
			talloc_free(packet);
			return NULL;
		}
		memcpy(packet->name, &data->challenge[packet->count],
		       name_len);
		packet->name[name_len] = '\0';
		packet->name_len = name_len;
	}

	return packet;
}

/*
 *  Get the NT-Password hash.
 */
static int eapleap_ntpwdhash(unsigned char *ntpwdhash, VALUE_PAIR *password)
{
	if ((password->da->attr == PW_USER_PASSWORD) ||
	    (password->da->attr == PW_CLEARTEXT_PASSWORD)) {
		size_t i;
		unsigned char unicode[512];

		/*
		 *	Convert the password to NT's weird Unicode format.
		 */
		memset(unicode, 0, sizeof(unicode));
		for (i = 0; i < password->length; i++) {
			/*
			 *  Yes, the *even* bytes have the values,
			 *  and the *odd* bytes are zero.
			 */
			unicode[(i << 1)] = password->vp_strvalue[i];
		}

		/*
		 *  Get the NT Password hash.
		 */
		fr_md4_calc(ntpwdhash, unicode, password->length * 2);

	} else {		/* MUST be NT-Password */
		if (password->length == 32) {
			password->length = fr_hex2bin(password->vp_strvalue,
							password->vp_octets,
							16);
		}
		if (password->length != 16) {
			radlog(L_ERR, "rlm_eap_leap: Bad NT-Password");
			return 0;
		}

		memcpy(ntpwdhash, password->vp_strvalue, 16);
	}
	return 1;
}


/*
 *	Verify the MS-CHAP response from the user.
 */
int eapleap_stage4(leap_packet_t *packet, VALUE_PAIR* password,
		   leap_session_t *session)
{
	unsigned char ntpwdhash[16];
	unsigned char response[24];


	/*
	 *	No password or previous packet.  Die.
	 */
	if ((password == NULL) || (session == NULL)) {
		return 0;
	}

	if (!eapleap_ntpwdhash(ntpwdhash, password)) {
		return 0;
	}

	/*
	 *	Calculate and verify the CHAP challenge.
	 */
	eapleap_mschap(ntpwdhash, session->peer_challenge, response);
	if (memcmp(response, packet->challenge, 24) == 0) {
		DEBUG2("  rlm_eap_leap: NtChallengeResponse from AP is valid");
		memcpy(session->peer_response, response, sizeof(response));
		return 1;
	}

	DEBUG2("  rlm_eap_leap: FAILED incorrect NtChallengeResponse from AP");
	return 0;
}

/*
 *	Verify ourselves to the AP
 */
leap_packet_t *eapleap_stage6(leap_packet_t *packet, REQUEST *request,
			    VALUE_PAIR *user_name, VALUE_PAIR* password,
			    leap_session_t *session)
{
	size_t i;
	unsigned char ntpwdhash[16], ntpwdhashhash[16];
	unsigned char buffer[256];
	leap_packet_t *reply;
	unsigned char *p;
	VALUE_PAIR *vp;

	/*
	 *	No password or previous packet.  Die.
	 */
	if ((password == NULL) || (session == NULL)) {
		return NULL;
	}

	reply = talloc(session, leap_packet_t);
	if (!reply) return NULL;

	reply->code = PW_EAP_RESPONSE;
	reply->length = LEAP_HEADER_LEN + 24 + user_name->length;
	reply->count = 24;

	reply->challenge = talloc_array(reply, uint8_t, reply->count);
	if (reply->challenge == NULL) {
		radlog(L_ERR, "rlm_eap_leap: out of memory");
		talloc_free(reply);
		return NULL;
	}

	/*
	 *	The LEAP packet also contains the user name.
	 */
	reply->name = talloc_array(reply, char, user_name->length + 1);
	if (reply->name == NULL) {
		radlog(L_ERR, "rlm_eap_leap: out of memory");
		talloc_free(reply);
		return NULL;
	}

	/*
	 *	Copy the name over, and ensure it's NUL terminated.
	 */
	memcpy(reply->name, user_name->vp_strvalue, user_name->length);
	reply->name[user_name->length] = '\0';
	reply->name_len = user_name->length;

	/*
	 *  MPPE hash = ntpwdhash(ntpwdhash(unicode(pw)))
	 */
	if (!eapleap_ntpwdhash(ntpwdhash, password)) {
		talloc_free(reply);
		return NULL;
	}
	fr_md4_calc(ntpwdhashhash, ntpwdhash, 16);

	/*
	 *	Calculate our response, to authenticate ourselves
	 *	to the AP.
	 */
	eapleap_mschap(ntpwdhashhash, packet->challenge, reply->challenge);

	/*
	 *  Calculate the leap:session-key attribute
	 */
	vp = pairmake_reply("Cisco-AVPair", "leap:session-key=", T_OP_ADD);
	if (!vp) {
		radlog(L_ERR, "rlm_eap_leap: Failed to create Cisco-AVPair attribute.  LEAP cancelled.");
		talloc_free(reply);
		return NULL;
	}

	/*
	 *	And calculate the MPPE session key.
	 */
	p = buffer;
	memcpy(p, ntpwdhashhash, 16); /* MPPEHASH */
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
	fr_md5_calc(ntpwdhash, buffer, 16 + 8 + 24 + 8 + 24);

	memcpy(vp->vp_strvalue + vp->length, ntpwdhash, 16);
	memset(vp->vp_strvalue + vp->length + 16, 0,
	       sizeof(vp->vp_strvalue) - (vp->length + 16));

	i = 16;
	rad_tunnel_pwencode(vp->vp_strvalue + vp->length, &i,
			    request->client->secret, request->packet->vector);
	vp->length += i;

	return reply;
}

/*
 *	If an EAP LEAP request needs to be initiated then
 *	create such a packet.
 */
leap_packet_t *eapleap_initiate(EAP_DS *eap_ds, VALUE_PAIR *user_name)
{
	int i;
	leap_packet_t 	*reply;

	reply = talloc(eap_ds, leap_packet_t);
	if (reply == NULL)  {
		radlog(L_ERR, "rlm_eap_leap: out of memory");
		return NULL;
	}

	reply->code = PW_EAP_REQUEST;
	reply->length = LEAP_HEADER_LEN + 8 + user_name->length;
	reply->count = 8;	/* random challenge */

	reply->challenge = talloc_array(reply, uint8_t, reply->count);
	if (reply->challenge == NULL) {
		radlog(L_ERR, "rlm_eap_leap: out of memory");
		talloc_free(reply);
		return NULL;
	}

	/*
	 *	Fill the challenge with random bytes.
	 */
	for (i = 0; i < reply->count; i++) {
		reply->challenge[i] = fr_rand();
	}

	DEBUG2("  rlm_eap_leap: Issuing AP Challenge");

	/*
	 *	The LEAP packet also contains the user name.
	 */
	reply->name = talloc_array(reply, char, user_name->length + 1);
	if (reply->name == NULL) {
		radlog(L_ERR, "rlm_eap_leap: out of memory");
		talloc_free(reply);
		return NULL;
	}

	/*
	 *	Copy the name over, and ensure it's NUL terminated.
	 */
	memcpy(reply->name, user_name->vp_strvalue, user_name->length);
	reply->name[user_name->length] = '\0';
	reply->name_len = user_name->length;

	return reply;
}

/*
 * compose the LEAP reply packet in the EAP reply typedata
 */
int eapleap_compose(EAP_DS *eap_ds, leap_packet_t *reply)
{
	leap_packet_raw_t *data;

	/*
	 *  We need the name and the challenge.
	 */
	switch (reply->code) {
	case PW_EAP_REQUEST:
	case PW_EAP_RESPONSE:
		eap_ds->request->type.num = PW_EAP_LEAP;
		eap_ds->request->type.length = reply->length;

		eap_ds->request->type.data = talloc_array(eap_ds->request,
							  uint8_t,
							  reply->length);
		if (eap_ds->request->type.data == NULL) {
			radlog(L_ERR, "rlm_eap_leap: out of memory");
			return 0;
		}
		data = (leap_packet_raw_t *) eap_ds->request->type.data;
		data->version = 0x01;
		data->unused = 0;
		data->count = reply->count;

		/*
		 *	N bytes of the challenge, followed by the user name.
		 */
		memcpy(&data->challenge[0], reply->challenge, reply->count);
		memcpy(&data->challenge[reply->count],
		       reply->name, reply->name_len);
		break;

		/*
		 *	EAP-Success packets don't contain any data
		 *	other than the header.
		 */
	case PW_EAP_SUCCESS:
		eap_ds->request->type.length = 0;
		break;

	default:
		radlog(L_ERR, "rlm_eap_leap: Internal sanity check failed");
		return 0;
		break;
	}

	/*
	 *	Set the EAP code.
	 */
	eap_ds->request->code = reply->code;

	return 1;
}
