/*
 * eap_md5.c  EAP MD5 functionality.
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
 * @copyright 2000,2001,2006  The FreeRADIUS server project
 * @copyright 2001  hereUare Communications, Inc. <raghud@hereuare.com>
 */

/*
 *
 *  MD5 Packet Format in EAP Type-Data
 *  --- ------ ------ -- --- ---------
 *  0		   1		   2		   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Value-Size   |  Value ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Name ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
RCSID("$Id$")

#define LOG_PREFIX "rlm_eap_md5 - "

#include <stdio.h>
#include <stdlib.h>
#include "eap.h"

#include "eap_md5.h"
#include <freeradius-devel/util/md5.h>

/*
 *	We expect only RESPONSE for which SUCCESS or FAILURE is sent back
 */
MD5_PACKET *eap_md5_extract(eap_round_t *eap_round)
{
	md5_packet_t	*data;
	MD5_PACKET	*packet;
	unsigned short	name_len;

	/*
	 *	We need a response, of type EAP-MD5, with at least
	 *	one byte of type data (EAP-MD5) following the 4-byte
	 *	EAP-Packet header.
	 */
	if (!eap_round 					 ||
	    !eap_round->response 				 ||
	    (eap_round->response->code != FR_MD5_RESPONSE)	 ||
	    eap_round->response->type.num != FR_EAP_MD5	 ||
	    !eap_round->response->type.data 		 ||
	    (eap_round->response->length <= MD5_HEADER_LEN) ||
	    (eap_round->response->type.data[0] <= 0)) {
		ERROR("corrupted data");
		return NULL;
	}

	packet = talloc_zero(eap_round, MD5_PACKET);
	if (!packet) return NULL;

	/*
	 *	Code & id for MD5 & EAP are same
	 *
	 *	but md5_length = length of the EAP-MD5 data, which
	 *	doesn't include the EAP header, or the octet saying
	 *	EAP-MD5.
	 */
	packet->code = eap_round->response->code;
	packet->id = eap_round->response->id;
	packet->length = eap_round->response->length - (MD5_HEADER_LEN + 1);

	/*
	 *	Sanity check the EAP-MD5 packet sent to us
	 *	by the client.
	 */
	data = (md5_packet_t *)eap_round->response->type.data;

	/*
	 *	Already checked the size above.
	 */
	packet->value_size = data->value_size;

	/*
	 *	Allocate room for the data, and copy over the data.
	 */
	packet->value = talloc_array(packet, uint8_t, packet->value_size);
	if (!packet->value) {
		talloc_free(packet);
		return NULL;
	}
	memcpy(packet->value, data->value_name, packet->value_size);

	/*
	 *	Name is optional and is present after Value, but we
	 *	need to check for it, as eap_md5_compose()
	 */
	name_len =  packet->length - (packet->value_size + 1);
	if (name_len) {
	  packet->name = talloc_array(packet, char, name_len + 1);
		if (!packet->name) {
			talloc_free(packet);
			return NULL;
		}
		memcpy(packet->name, data->value_name + packet->value_size,
		       name_len);
		packet->name[name_len] = 0;
	}

	return packet;
}


/*
 * verify = MD5(id+password+challenge_sent)
 */
int eap_md5_verify(MD5_PACKET *packet, VALUE_PAIR* password,
		  uint8_t *challenge)
{
	char	*ptr;
	char	string[1 + FR_MAX_STRING_LEN*2];
	uint8_t digest[16];
	unsigned short len;

	/*
	 *	Sanity check it.
	 */
	if (packet->value_size != 16) {
		ERROR("Expected 16 bytes of response to challenge, got %d", packet->value_size);
		return 0;
	}

	len = 0;
	ptr = string;

	/*
	 *	This is really rad_chap_pwencode()...
	 */
	*ptr++ = packet->id;
	len++;
	memcpy(ptr, password->vp_strvalue, password->vp_length);
	ptr += password->vp_length;
	len += password->vp_length;

	/*
	 *	The challenge size is hard-coded.
	 */
	memcpy(ptr, challenge, MD5_CHALLENGE_LEN);
	len += MD5_CHALLENGE_LEN;

	fr_md5_calc(digest, (uint8_t *)string, len);

	/*
	 *	The length of the response is always 16 for MD5.
	 */
	if (fr_digest_cmp(digest, packet->value, 16) != 0) {
		return 0;
	}

	return 1;
}

/*
 *	Compose the portions of the reply packet specific to the
 *	EAP-MD5 protocol, in the EAP reply typedata
 */
int eap_md5_compose(eap_round_t *eap_round, MD5_PACKET *reply)
{
	uint8_t *ptr;
	unsigned short name_len;

	/*
	 *	We really only send Challenge (EAP-Identity),
	 *	and EAP-Success, and EAP-Failure.
	 */
	if (reply->code < 3) {
		eap_round->request->type.num = FR_EAP_MD5;

		rad_assert(reply->length > 0);

		eap_round->request->type.data = talloc_array(eap_round->request,
							  uint8_t,
							  reply->length);
		if (!eap_round->request->type.data) {
			talloc_free(reply);
			return 0;
		}
		ptr = eap_round->request->type.data;
		*ptr++ = (uint8_t)(reply->value_size & 0xFF);
		memcpy(ptr, reply->value, reply->value_size);

		/* Just the Challenge length */
		eap_round->request->type.length = reply->value_size + 1;

		/*
		 *	Return the name, if necessary.
		 *
		 *	Don't see why this is *ever* necessary...
		 */
		name_len = reply->length - (reply->value_size + 1);
		if (name_len && reply->name) {
			ptr += reply->value_size;
			memcpy(ptr, reply->name, name_len);
			/* Challenge length + Name length */
			eap_round->request->type.length += name_len;
		}
	} else {
		eap_round->request->type.length = 0;
		/* TODO: In future we might add message here wrt rfc1994 */
	}
	eap_round->request->code = reply->code;
	talloc_free(reply);

	return 1;
}
