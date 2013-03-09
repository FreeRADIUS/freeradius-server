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
 * Copyright 2000-2003,2006  The FreeRADIUS server project
 * Copyright 2001  hereUare Communications, Inc. <raghud@hereuare.com>
 * Copyright 2003  Alan DeKok <aland@freeradius.org>
 * Copyright 2003  Michael Richardson <mcr@sandelman.ottawa.on.ca>
 */
/*
 *  EAP PACKET FORMAT
 *  --- ------ ------
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Code      |  Identifier   |            Length             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |    Data ...
 * +-+-+-+-+
 *
 *
 * EAP Request and Response Packet Format
 * --- ------- --- -------- ------ ------
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Code      |  Identifier   |            Length             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |  Type-Data ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
 *
 *
 * EAP Success and Failure Packet Format
 * --- ------- --- ------- ------ ------
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Code      |  Identifier   |            Length             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/libradius.h>
#include "eap_types.h"

static const char *eap_types[] = {
  "",
  "identity",
  "notification",
  "nak",			/* NAK */
  "md5",
  "otp",
  "gtc",
  "7",
  "8",
  "9",
  "10",
  "11",
  "12",
  "tls",			/* 13 */
  "14",
  "15",
  "16",
  "leap",			/* 17 */
  "sim",                        /* 18 GSM-SIM authentication */
  "19",
  "20",
  "ttls",			/* 21 */
  "22",
  "23",
  "24",
  "peap",			/* 25 */
  "mschapv2",			/* 26 */
  "27",
  "28",
  "cisco_mschapv2",		/* 29 */
  "30",
  "31",
  "32",
  "33",
  "34",
  "35",
  "36",
  "37",
  "tnc",			/* 38 */
  "39",
  "40",
  "41",
  "42",
  "fast",
  "44",
  "45",
  "pax",
  "psk",
  "sake",
  "ikev2",
  "50",
  "51",
  "pwd"
};				/* MUST have PW_EAP_MAX_TYPES */

/*
 *	Return an EAP-Type for a particular name.
 */
int eaptype_name2type(const char *name)
{
	int i;

	for (i = 0; i <= PW_EAP_MAX_TYPES; i++) {
		if (strcmp(name, eap_types[i]) == 0) {
			return i;
		}
	}

	return -1;
}

/*
 *	Returns a text string containing the name of the EAP type.
 */
const char *eaptype_type2name(unsigned int type, char *buffer, size_t buflen)
{
	DICT_VALUE	*dval;

	if (type > PW_EAP_MAX_TYPES) {
		/*
		 *	Prefer the dictionary name over a number,
		 *	if it exists.
		 */
		dval = dict_valbyattr(PW_EAP_TYPE, 0, type);
		if (dval) {
			snprintf(buffer, buflen, "%s", dval->name);
		}

		snprintf(buffer, buflen, "%d", type);
		return buffer;
	} else if ((*eap_types[type] >= '0') && (*eap_types[type] <= '9')) {
		/*
		 *	Prefer the dictionary name, if it exists.
		 */
		dval = dict_valbyattr(PW_EAP_TYPE, 0, type);
		if (dval) {
			snprintf(buffer, buflen, "%s", dval->name);
			return buffer;
		} /* else it wasn't in the dictionary */
	} /* else the name in the array was non-numeric */

	/*
	 *	Return the name, whatever it is.
	 */
	return eap_types[type];
}

/*
 *	EAP packet format to be sent over the wire
 *
 *	i.e. code+id+length+data where data = null/type+typedata
 *	based on code.
 *
 * INPUT to function is reply->code
 *                      reply->id
 *                      reply->type   - setup with data
 *
 * OUTPUT reply->packet is setup with wire format, and will
 *                      be malloc()'ed to the right size.
 *
 */
int eap_wireformat(EAP_PACKET *reply)
{
	eap_packet_t	*hdr;
	uint16_t total_length = 0;

	if (reply == NULL) return EAP_INVALID;

	/*
	 *	If reply->packet is set, then the wire format
	 *	has already been calculated, just succeed.
	 */
	if(reply->packet != NULL) return EAP_VALID;

	total_length = EAP_HEADER_LEN;
	if (reply->code < 3) {
		total_length += 1/*EAPtype*/;
		if (reply->type.data && reply->type.length > 0) {
			total_length += reply->type.length;
		}
	}

	reply->packet = (unsigned char *)malloc(total_length);
	hdr = (eap_packet_t *)reply->packet;
	if (!hdr) {
		radlog(L_ERR, "rlm_eap: out of memory");
		return EAP_INVALID;
	}

	hdr->code = (reply->code & 0xFF);
	hdr->id = (reply->id & 0xFF);
	total_length = htons(total_length);
	memcpy(hdr->length, &total_length, sizeof(total_length));

	/*
	 *	Request and Response packets are special.
	 */
	if ((reply->code == PW_EAP_REQUEST) ||
	    (reply->code == PW_EAP_RESPONSE)) {
		hdr->data[0] = (reply->type.type & 0xFF);

		/*
		 * Here since we cannot know the typedata format and length
		 *
		 * Type_data is expected to be wired by each EAP-Type
		 *
		 * Zero length/No typedata is supported as long as
		 * type is defined
		 */
		if (reply->type.data && reply->type.length > 0) {
			memcpy(&hdr->data[1], reply->type.data, reply->type.length);
			free(reply->type.data);
			reply->type.data = reply->packet + EAP_HEADER_LEN + 1/*EAPtype*/;
		}
	}

	return EAP_VALID;
}


/*
 *	compose EAP reply packet in EAP-Message attr of RADIUS.  If
 *	EAP exceeds 253, frame it in multiple EAP-Message attrs.
 */
int eap_basic_compose(RADIUS_PACKET *packet, EAP_PACKET *reply)
{
	VALUE_PAIR *vp;
	eap_packet_t *eap_packet;
	int rcode;

	if (eap_wireformat(reply) == EAP_INVALID) {
		return RLM_MODULE_INVALID;
	}
	eap_packet = (eap_packet_t *)reply->packet;

	pairdelete(&(packet->vps), PW_EAP_MESSAGE, 0, TAG_ANY);

	vp = eap_packet2vp(packet, eap_packet);
	if (!vp) return RLM_MODULE_INVALID;
	pairadd(&(packet->vps), vp);

	/*
	 *	EAP-Message is always associated with
	 *	Message-Authenticator but not vice-versa.
	 *
	 *	Don't add a Message-Authenticator if it's already
	 *	there.
	 */
	vp = pairfind(packet->vps, PW_MESSAGE_AUTHENTICATOR, 0, TAG_ANY);
	if (!vp) {
	  vp = paircreate(packet, PW_MESSAGE_AUTHENTICATOR, 0);
		memset(vp->vp_strvalue, 0, AUTH_VECTOR_LEN);
		vp->length = AUTH_VECTOR_LEN;
		pairadd(&(packet->vps), vp);
	}

	/* Set request reply code, but only if it's not already set. */
	rcode = RLM_MODULE_OK;
	if (!packet->code) switch(reply->code) {
	case PW_EAP_RESPONSE:
	case PW_EAP_SUCCESS:
		packet->code = PW_AUTHENTICATION_ACK;
		rcode = RLM_MODULE_HANDLED;
		break;
	case PW_EAP_FAILURE:
		packet->code = PW_AUTHENTICATION_REJECT;
		rcode = RLM_MODULE_REJECT;
		break;
	case PW_EAP_REQUEST:
		packet->code = PW_ACCESS_CHALLENGE;
		rcode = RLM_MODULE_HANDLED;
		break;
	default:
		/* Should never enter here */
		radlog(L_ERR, "rlm_eap: reply code %d is unknown, Rejecting the request.", reply->code);
		packet->code = PW_AUTHENTICATION_REJECT;
		break;
	}

	return rcode;
}


VALUE_PAIR *eap_packet2vp(RADIUS_PACKET *packet, const eap_packet_t *eap)
{
	int		total, size;
	const uint8_t	*ptr;
	VALUE_PAIR	*head = NULL;
	VALUE_PAIR	**tail = &head;
	VALUE_PAIR	*vp;

	total = eap->length[0] * 256 + eap->length[1];

	ptr = (const uint8_t *) eap;

	do {
		size = total;
		if (size > 253) size = 253;

		vp = paircreate(packet, PW_EAP_MESSAGE, 0);
		if (!vp) {
			pairfree(&head);
			return NULL;
		}
		memcpy(vp->vp_octets, ptr, size);
		vp->length = size;

		*tail = vp;
		tail = &(vp->next);

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
eap_packet_t *eap_vp2packet(VALUE_PAIR *vps)
{
	VALUE_PAIR *first, *vp;
	eap_packet_t *eap_packet;
	unsigned char *ptr;
	uint16_t len;
	int total_len;

	/*
	 *	Get only EAP-Message attribute list
	 */
	first = pairfind(vps, PW_EAP_MESSAGE, 0, TAG_ANY);
	if (first == NULL) {
		DEBUG("rlm_eap: EAP-Message not found");
		return NULL;
	}

	/*
	 *	Sanity check the length before doing anything.
	 */
	if (first->length < 4) {
		DEBUG("rlm_eap: EAP packet is too short.");
		return NULL;
	}

	/*
	 *	Get the Actual length from the EAP packet
	 *	First EAP-Message contains the EAP packet header
	 */
	memcpy(&len, first->vp_strvalue + 2, sizeof(len));
	len = ntohs(len);

	/*
	 *	Take out even more weird things.
	 */
	if (len < 4) {
		DEBUG("rlm_eap: EAP packet has invalid length.");
		return NULL;
	}

	/*
	 *	Sanity check the length, BEFORE malloc'ing memory.
	 */
	total_len = 0;
	for (vp = first; vp; vp = pairfind(vp->next, PW_EAP_MESSAGE, 0, TAG_ANY)) {
		total_len += vp->length;

		if (total_len > len) {
			DEBUG("rlm_eap: Malformed EAP packet.  Length in packet header does not match actual length");
			return NULL;
		}
	}

	/*
	 *	If the length is SMALLER, die, too.
	 */
	if (total_len < len) {
		DEBUG("rlm_eap: Malformed EAP packet.  Length in packet header does not match actual length");
		return NULL;
	}

	/*
	 *	Now that we know the lengths are OK, allocate memory.
	 */
	eap_packet = (eap_packet_t *) malloc(len);
	if (eap_packet == NULL) {
		radlog(L_ERR, "rlm_eap: out of memory");
		return NULL;
	}

	/*
	 *	Copy the data from EAP-Message's over to our EAP packet.
	 */
	ptr = (unsigned char *)eap_packet;

	/* RADIUS ensures order of attrs, so just concatenate all */
	for (vp = first; vp; vp = pairfind(vp->next, PW_EAP_MESSAGE, 0, TAG_ANY)) {
		memcpy(ptr, vp->vp_strvalue, vp->length);
		ptr += vp->length;
	}

	return eap_packet;
}
