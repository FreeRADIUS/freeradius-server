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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2000-2003  The FreeRADIUS server project
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

#include "libradius.h"
#include "eap_types.h"

static const char rcsid[] = "$Id$";

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
  "cisco_mschapv2"		/* 29 */
};
#define MAX_EAP_TYPE_NAME 29

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

	if (type > MAX_EAP_TYPE_NAME) {
		/*
		 *	Prefer the dictionary name over a number,
		 *	if it exists.
		 */
		dval = dict_valbyattr(PW_EAP_TYPE, type);
		if (dval) {
			snprintf(buffer, buflen, "%s", dval->name);
		}

		snprintf(buffer, buflen, "%d", type);
		return buffer;
	} else if ((eap_types[type] >= '0') && (eap_types[type] <= '9')) {
		/*
		 *	Prefer the dictionary name, if it exists.
		 */
		dval = dict_valbyattr(PW_EAP_TYPE, type);
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
static int eap_wireformat(EAP_PACKET *reply)
{

	eap_packet_t	*hdr;
	uint16_t total_length = 0;

	if (reply == NULL) return EAP_INVALID;

	/*
	 * if reply->packet is set, then the wire format
	 * has already been calculated, just succeed!
	 */
	if(reply->packet != NULL)
	{
		return EAP_VALID;
	}

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
	memcpy(hdr->length, &total_length, sizeof(uint16_t));

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
	uint16_t eap_len, len;
	VALUE_PAIR *eap_msg;
	VALUE_PAIR *vp;
	eap_packet_t *eap_packet;
	unsigned char 	*ptr;
	int rcode;

	if (eap_wireformat(reply) == EAP_INVALID) {
		return RLM_MODULE_INVALID;
	}
	eap_packet = (eap_packet_t *)reply->packet;

	memcpy(&eap_len, &(eap_packet->length), sizeof(uint16_t));
	len = eap_len = ntohs(eap_len);
	ptr = (unsigned char *)eap_packet;

	pairdelete(&(packet->vps), PW_EAP_MESSAGE);

	do {
		if (eap_len > 253) {
			len = 253;
			eap_len -= 253;
		} else {
			len = eap_len;
			eap_len = 0;
		}

		/*
		 * create a value pair & append it to the packet list
		 * This memory gets freed up when packet is freed up
		 */
		eap_msg = paircreate(PW_EAP_MESSAGE, PW_TYPE_OCTETS);
		memcpy(eap_msg->strvalue, ptr, len);
		eap_msg->length = len;
		pairadd(&(packet->vps), eap_msg);
		ptr += len;
		eap_msg = NULL;
	} while (eap_len);

	/*
	 *	EAP-Message is always associated with
	 *	Message-Authenticator but not vice-versa.
	 *
	 *	Don't add a Message-Authenticator if it's already
	 *	there.
	 */
	vp = pairfind(packet->vps, PW_MESSAGE_AUTHENTICATOR);
	if (!vp) {
		vp = paircreate(PW_MESSAGE_AUTHENTICATOR, PW_TYPE_OCTETS);
		memset(vp->strvalue, 0, AUTH_VECTOR_LEN);
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

/*
 * given a radius request with some attributes in the EAP range, build
 * them all into a single EAP-Message body.
 *
 * Note that this function will build multiple EAP-Message bodies
 * if there are multiple eligible EAP-types. This is incorrect, as the
 * recipient will in fact concatenate them.
 *
 * XXX - we could break the loop once we process one type. Maybe this
 *       just deserves an assert?
 *
 */
void map_eap_types(RADIUS_PACKET *req)
{
	VALUE_PAIR *vp, *vpnext;
	int id, eapcode;
	EAP_PACKET ep;
	int eap_type;

	vp = pairfind(req->vps, ATTRIBUTE_EAP_ID);
	if(vp == NULL) {
		id = ((int)getpid() & 0xff);
	} else {
		id = vp->lvalue;
	}

	vp = pairfind(req->vps, ATTRIBUTE_EAP_CODE);
	if(vp == NULL) {
		eapcode = PW_EAP_REQUEST;
	} else {
		eapcode = vp->lvalue;
	}


	for(vp = req->vps; vp != NULL; vp = vpnext) {
		/* save it in case it changes! */
		vpnext = vp->next;

		if(vp->attribute >= ATTRIBUTE_EAP_BASE &&
		   vp->attribute < ATTRIBUTE_EAP_BASE+256) {
			break;
		}
	}

	if(vp == NULL) {
		return;
	}

	eap_type = vp->attribute - ATTRIBUTE_EAP_BASE;

	switch(eap_type) {
	case PW_EAP_IDENTITY:
	case PW_EAP_NOTIFICATION:
	case PW_EAP_NAK:
	case PW_EAP_MD5:
	case PW_EAP_OTP:
	case PW_EAP_GTC:
	case PW_EAP_TLS:
	case PW_EAP_LEAP:
	case PW_EAP_TTLS:
	case PW_EAP_PEAP:
	default:
		/*
		 * no known special handling, it is just encoded as an
		 * EAP-message with the given type.
		 */

		/* nuke any existing EAP-Messages */
		pairdelete(&req->vps, PW_EAP_MESSAGE);

		memset(&ep, 0, sizeof(ep));
		ep.code = eapcode;
		ep.id   = id;
		ep.type.type = eap_type;
		ep.type.length = vp->length;
		ep.type.data = vp->strvalue;
		eap_basic_compose(req, &ep);
	}
}

/*
 * Handles multiple EAP-Message attrs
 * ie concatenates all to get the complete EAP packet.
 *
 * NOTE: Sometimes Framed-MTU might contain the length of EAP-Message,
 *      refer fragmentation in rfc2869.
 */
eap_packet_t *eap_attribute(VALUE_PAIR *vps)
{
	VALUE_PAIR *first, *vp;
	eap_packet_t *eap_packet;
	unsigned char *ptr;
	uint16_t len;
	int total_len;

	/*
	 *	Get only EAP-Message attribute list
	 */
	first = pairfind(vps, PW_EAP_MESSAGE);
	if (first == NULL) {
		radlog(L_ERR, "rlm_eap: EAP-Message not found");
		return NULL;
	}

	/*
	 *	Sanity check the length before doing anything.
	 */
	if (first->length < 4) {
		radlog(L_ERR, "rlm_eap: EAP packet is too short.");
		return NULL;
	}

	/*
	 *	Get the Actual length from the EAP packet
	 *	First EAP-Message contains the EAP packet header
	 */
	memcpy(&len, first->strvalue + 2, sizeof(len));
	len = ntohs(len);

	/*
	 *	Take out even more weird things.
	 */
	if (len < 4) {
		radlog(L_ERR, "rlm_eap: EAP packet has invalid length.");
		return NULL;
	}

	/*
	 *	Sanity check the length, BEFORE malloc'ing memory.
	 */
	total_len = 0;
	for (vp = first; vp; vp = pairfind(vp->next, PW_EAP_MESSAGE)) {
		total_len += vp->length;

		if (total_len > len) {
			radlog(L_ERR, "rlm_eap: Malformed EAP packet.  Length in packet header does not match actual length");
			return NULL;
		}
	}

	/*
	 *	If the length is SMALLER, die, too.
	 */
	if (total_len < len) {
		radlog(L_ERR, "rlm_eap: Malformed EAP packet.  Length in packet header does not match actual length");
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
	 *	Copy the data from EAP-Message's over to out EAP packet.
	 */
	ptr = (unsigned char *)eap_packet;

	/* RADIUS ensures order of attrs, so just concatenate all */
	for (vp = first; vp; vp = pairfind(vp->next, PW_EAP_MESSAGE)) {
		memcpy(ptr, vp->strvalue, vp->length);
		ptr += vp->length;
	}

	return eap_packet;
}

/*
 * given a radius request with an EAP-Message body, decode it specific
 * attributes.
 */
void unmap_eap_types(RADIUS_PACKET *rep)
{
	VALUE_PAIR *eap1;
	eap_packet_t *e;
	int len;
	int type;

	/* find eap message */
	e = eap_attribute(rep->vps);

	/* nothing to do! */
	if(e == NULL) return;

	/* create EAP-ID and EAP-CODE attributes to start */
	eap1 = paircreate(ATTRIBUTE_EAP_ID, PW_TYPE_INTEGER);
	eap1->lvalue = e->id;
	pairadd(&(rep->vps), eap1);

	eap1 = paircreate(ATTRIBUTE_EAP_CODE, PW_TYPE_INTEGER);
	eap1->lvalue = e->code;
	pairadd(&(rep->vps), eap1);

	switch(e->code)
	{
	default:
	case PW_EAP_SUCCESS:
	case PW_EAP_FAILURE:
		/* no data */
		break;

	case PW_EAP_REQUEST:
	case PW_EAP_RESPONSE:
		/* there is a type field, which we use to create
		 * a new attribute */

		/* the length was decode already into the attribute
		 * length, and was checked already. Network byte
		 * order, just pull it out using math.
		 */
		len = e->length[0]*256 + e->length[1];

		/* verify the length is big enough to hold type */
		if(len < 5)
		{
			return;
		}

		type = e->data[0];

		type += ATTRIBUTE_EAP_BASE;
		len -= 5;

		if(len > MAX_STRING_LEN) {
			len = MAX_STRING_LEN;
		}

		eap1 = paircreate(type, PW_TYPE_OCTETS);
		memcpy(eap1->strvalue, &e->data[1], len);
		eap1->length = len;
		pairadd(&(rep->vps), eap1);
		break;
	}

	return;
}

