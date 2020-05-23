/*
 * eap.c    rfc2284 & rfc2869 implementation
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
 * @copyright 2000-2003,2006 The FreeRADIUS server project
 * @copyright 2001 hereUare Communications, Inc. (raghud@hereuare.com)
 * @copyright 2003 Alan DeKok (aland@freeradius.org)
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
#define LOG_PREFIX "rlm_eap - "
#include <freeradius-devel/server/modpriv.h>
#include <freeradius-devel/server/pair.h>
#include <freeradius-devel/radius/radius.h>
#include <ctype.h>

#include "attrs.h"
#include "compose.h"

RCSID("$Id$")

static char const *eap_codes[] = {
	 "",				/* 0 is invalid */
	"Request",
	"Response",
	"Success",
	"Failure"
};

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
static int eap_wireformat(eap_packet_t *reply)
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

/*
 *	compose EAP reply packet in EAP-Message attr of RADIUS.
 *
 *	Set the RADIUS reply codes based on EAP request codes.  Append
 *	any additional VPs to RADIUS reply
 */
rlm_rcode_t eap_compose(eap_session_t *eap_session)
{
	VALUE_PAIR *vp;
	eap_packet_raw_t *eap_packet;
	REQUEST *request;
	eap_round_t *eap_round;
	eap_packet_t *reply;
	int rcode;

	eap_session = talloc_get_type_abort(eap_session, eap_session_t);
	request = talloc_get_type_abort(eap_session->request, REQUEST);
	eap_round = talloc_get_type_abort(eap_session->this_round, eap_round_t);
	reply = talloc_get_type_abort(eap_round->request, eap_packet_t);

	/*
	 *	The Id for the EAP packet to the NAS wasn't set.
	 *	Do so now.
	 */
	if (!eap_round->set_request_id) {
		/*
		 *	Id serves to suppport request/response
		 *	retransmission in the EAP layer and as such
		 *	must be different for 'adjacent' packets
		 *	except in case of success/failure-replies.
		 *
		 *	RFC2716 (EAP-TLS) requires this to be
		 *	incremented, RFC2284 only makes the above-
		 *	mentioned restriction.
		 */
		reply->id = eap_session->this_round->response->id;

		switch (reply->code) {
		/*
		 *	The Id is a simple "ack" for success
		 *	and failure.
		 *
		 *	RFC 3748 section 4.2 says
		 *
		 *	... The Identifier field MUST match
		 *	the Identifier field of the Response
		 *	packet that it is sent in response
		 *	to.
		 */
		case FR_EAP_CODE_SUCCESS:
		case FR_EAP_CODE_FAILURE:
			break;

		/*
		 *	We've sent a response to their
		 *	request, the Id is incremented.
		 */
		default:
			++reply->id;
		}
	}

	/*
	 *	For Request & Response packets, set the EAP sub-type,
	 *	if the EAP sub-module didn't already set it.
	 *
	 *	This allows the TLS module to be "morphic", and means
	 *	that the TTLS and PEAP modules can call it to do most
	 *	of their dirty work.
	 */
	if (((eap_round->request->code == FR_EAP_CODE_REQUEST) ||
	     (eap_round->request->code == FR_EAP_CODE_RESPONSE)) &&
	    (eap_round->request->type.num == 0)) {
		fr_assert(eap_session->type >= FR_EAP_METHOD_MD5);
		fr_assert(eap_session->type < FR_EAP_METHOD_MAX);

		eap_round->request->type.num = eap_session->type;
	}

	if (eap_wireformat(reply) < 0) return RLM_MODULE_INVALID;

	eap_packet = (eap_packet_raw_t *)reply->packet;

	MEM(pair_add_reply(&vp, attr_eap_message) >= 0);
	vp->vp_length = eap_packet->length[0] * 256 + eap_packet->length[1];
	vp->vp_octets = talloc_steal(vp, reply->packet);
	reply->packet = NULL;

	/*
	 *	EAP-Message is always associated with
	 *	Message-Authenticator but not vice-versa.
	 *
	 *	Don't add a Message-Authenticator if
	 *	it's already there.
	 */
	vp = fr_pair_find_by_da(request->reply->vps, attr_message_authenticator, TAG_ANY);
	if (!vp) {
		static uint8_t auth_vector[RADIUS_AUTH_VECTOR_LENGTH] = { 0x00 };

		MEM(pair_add_reply(&vp, attr_message_authenticator) >= 0);
		fr_pair_value_memdup(vp, auth_vector, sizeof(auth_vector), false);
	}

	/* Set request reply code, but only if it's not already set. */
	rcode = RLM_MODULE_OK;
	if (!request->reply->code) switch (reply->code) {
	case FR_EAP_CODE_RESPONSE:
		request->reply->code = FR_CODE_ACCESS_ACCEPT;
		rcode = RLM_MODULE_HANDLED;
		break;

	case FR_EAP_CODE_SUCCESS:
		request->reply->code = FR_CODE_ACCESS_ACCEPT;
		rcode = RLM_MODULE_OK;
		break;

	case FR_EAP_CODE_FAILURE:
		request->reply->code = FR_CODE_ACCESS_REJECT;
		rcode = RLM_MODULE_REJECT;
		break;

	case FR_EAP_CODE_REQUEST:
		request->reply->code = FR_CODE_ACCESS_CHALLENGE;
		rcode = RLM_MODULE_HANDLED;
		break;

	default:
		/*
		 *	When we're pulling MS-CHAPv2 out of EAP-MS-CHAPv2,
		 *	we do so WITHOUT setting a reply code, as the
		 *	request is being proxied.
		 */
		if (request->options & RAD_REQUEST_OPTION_PROXY_EAP) return RLM_MODULE_HANDLED;

		/* Should never enter here */
		REDEBUG("Reply code %d is unknown, rejecting the request", reply->code);
		request->reply->code = FR_CODE_ACCESS_REJECT;
		reply->code = FR_EAP_CODE_FAILURE;
		rcode = RLM_MODULE_REJECT;
		break;
	}

	RDEBUG2("Sending EAP %s (code %i) ID %d length %i",
		eap_codes[eap_packet->code], eap_packet->code, reply->id,
		eap_packet->length[0] * 256 + eap_packet->length[1]);

	return rcode;
}

/*
 * Radius criteria, EAP-Message is invalid without Message-Authenticator
 * For EAP_START, send Access-Challenge with EAP Identity request.
 */
int eap_start(REQUEST *request, rlm_eap_method_t const methods[], bool ignore_unknown_types)
{
	VALUE_PAIR *vp;
	VALUE_PAIR *eap_msg;

	eap_msg = fr_pair_find_by_da(request->packet->vps, attr_eap_message, TAG_ANY);
	if (!eap_msg) {
		RDEBUG2("No EAP-Message, not doing EAP");
		return RLM_MODULE_NOOP;
	}

	/*
	 *	Look for EAP-Type = None (FreeRADIUS specific attribute)
	 *	this allows you to NOT do EAP for some users.
	 */
	vp = fr_pair_find_by_da(request->packet->vps, attr_eap_type, TAG_ANY);
	if (vp && vp->vp_uint32 == 0) {
		RDEBUG2("Found EAP-Message, but EAP-Type = None, so we're not doing EAP");
		return RLM_MODULE_NOOP;
	}

	/*
	 *	http://www.freeradius.org/rfc/rfc2869.html#EAP-Message
	 *
	 *	Checks for Message-Authenticator are handled by fr_radius_packet_recv().
	 */

	/*
	 *	Check the length before de-referencing the contents.
	 *
	 *	Lengths of zero are required by the RFC for EAP-Start,
	 *	but we've never seen them in practice.
	 *
	 *	Lengths of two are what we see in practice as
	 *	EAP-Starts.
	 */
	if ((eap_msg->vp_length == 0) || (eap_msg->vp_length == 2)) {
		uint8_t *p;

		RDEBUG2("Got EAP_START message");

		MEM(pair_add_reply(&vp, attr_eap_message) >= 0);

		/*
		 *	Manually create an EAP Identity request
		 */
		p = talloc_array(vp, uint8_t, 5);
		p[0] = FR_EAP_CODE_REQUEST;
		p[1] = 0; /* ID */
		p[2] = 0;
		p[3] = 5; /* length */
		p[4] = FR_EAP_METHOD_IDENTITY;
		fr_pair_value_memsteal(vp, p, false);

		return RLM_MODULE_HANDLED;
	} /* end of handling EAP-Start */

	/*
	 *	Supplicants don't usually send EAP-Failures to the
	 *	server, but they're not forbidden from doing so.
	 *	This behaviour was observed with a Spirent Avalanche test server.
	 */
	if ((eap_msg->vp_length == EAP_HEADER_LEN) && (eap_msg->vp_octets[0] == FR_EAP_CODE_FAILURE)) {
		REDEBUG("Peer sent EAP %s (code %i) ID %d length %zu",
		        eap_codes[eap_msg->vp_octets[0]],
		        eap_msg->vp_octets[0],
		        eap_msg->vp_octets[1],
		        eap_msg->vp_length);
		return RLM_MODULE_FAIL;
	/*
	 *	The EAP packet header is 4 bytes, plus one byte of
	 *	EAP sub-type.  Short packets are discarded.
	 */
	} else if (eap_msg->vp_length < (EAP_HEADER_LEN + 1)) {
		RDEBUG2("Ignoring EAP-Message which is too short to be meaningful");
		return RLM_MODULE_FAIL;
	}

	/*
	 *	Create an EAP-Type containing the EAP-type
	 *	from the packet.
	 */
	MEM(pair_add_request(&vp, attr_eap_type) >= 0);
	vp->vp_uint32 = eap_msg->vp_octets[4];

	/*
	 *	From now on, we're supposed to be handling the
	 *	EAP packet.  We better understand it...
	 */

	/*
	 *	We're allowed only a few codes.  Request, Response,
	 *	Success, or Failure.
	 */
	if ((eap_msg->vp_octets[0] == 0) ||
	    (eap_msg->vp_octets[0] >= FR_EAP_CODE_MAX)) {
		RDEBUG2("Peer sent EAP packet with unknown code %i", eap_msg->vp_octets[0]);
	} else {
		RDEBUG2("Peer sent EAP %s (code %i) ID %d length %zu",
		        eap_codes[eap_msg->vp_octets[0]],
		        eap_msg->vp_octets[0],
		        eap_msg->vp_octets[1],
		        eap_msg->vp_length);
	}

	/*
	 *	We handle request and responses.  The only other defined
	 *	codes are success and fail.  The client SHOULD NOT be
	 *	sending success/fail packets to us, as it doesn't make
	 *	sense.
	 */
	if ((eap_msg->vp_octets[0] != FR_EAP_CODE_REQUEST) &&
	    (eap_msg->vp_octets[0] != FR_EAP_CODE_RESPONSE)) {
		RDEBUG2("Ignoring EAP packet which we don't know how to handle");
		return RLM_MODULE_FAIL;
	}

	/*
	 *	We've been told to ignore unknown EAP types, AND it's
	 *	an unknown type.  Return "NOOP", which will cause the
	 *	mod_authorize() to return NOOP.
	 *
	 *	EAP-Identity, Notification, and NAK are all handled
	 *	internally, so they never have eap_sessions.
	 */
	if ((eap_msg->vp_octets[4] >= FR_EAP_METHOD_MD5) &&
	    ignore_unknown_types &&
	    ((eap_msg->vp_octets[4] == 0) ||
	     (eap_msg->vp_octets[4] >= FR_EAP_METHOD_MAX) ||
	     (!methods[eap_msg->vp_octets[4]].submodule))) {
		RDEBUG2("Ignoring Unknown EAP type");
		return RLM_MODULE_NOOP;
	}

	/*
	 *	They're NAKing the EAP type we wanted to use, and
	 *	asking for one which we don't support.
	 *
	 *	NAK is code + id + length1 + length + NAK
	 *	     + requested EAP type(s).
	 *
	 *	We know at this point that we can't handle the
	 *	request.  We could either return an EAP-Fail here, but
	 *	it's not too critical.
	 *
	 *	By returning "noop", we can ensure that authorize()
	 *	returns NOOP, and another module may choose to proxy
	 *	the request.
	 */
	if ((eap_msg->vp_octets[4] == FR_EAP_METHOD_NAK) &&
	    (eap_msg->vp_length >= (EAP_HEADER_LEN + 2)) &&
	    ignore_unknown_types &&
	    ((eap_msg->vp_octets[5] == 0) ||
	     (eap_msg->vp_octets[5] >= FR_EAP_METHOD_MAX) ||
	     (!methods[eap_msg->vp_octets[5]].submodule))) {
		RDEBUG2("Ignoring NAK with request for unknown EAP type");
		return RLM_MODULE_NOOP;
	}

	if ((eap_msg->vp_octets[4] == FR_EAP_METHOD_TTLS) ||
	    (eap_msg->vp_octets[4] == FR_EAP_METHOD_PEAP)) {
		RDEBUG2("Continuing tunnel setup");
		return RLM_MODULE_OK;
	}
	/*
	 * We return ok in response to EAP identity
	 * This means we can write:
	 *
	 * eap {
	 *   ok = return
	 * }
	 * ldap
	 * sql
	 *
	 * ...in the inner-tunnel, to avoid expensive and unnecessary SQL/LDAP lookups
	 */
	if (eap_msg->vp_octets[4] == FR_EAP_METHOD_IDENTITY) {
		RDEBUG2("Peer sent EAP-Identity.  Returning 'ok' so we can short-circuit the rest of authorize");
		return RLM_MODULE_OK;
	}

	/*
	 *	Later EAP messages are longer than the 'start'
	 *	message, so if everything is OK, this function returns
	 *	'no start found', so that the rest of the EAP code can
	 *	use the State attribute to match this EAP-Message to
	 *	an ongoing conversation.
	 */
	RDEBUG2("Continuing on-going EAP conversation");

	return RLM_MODULE_NOTFOUND;
}

rlm_rcode_t eap_continue(eap_session_t *eap_session)
{
	eap_session->this_round->request->code = FR_EAP_CODE_REQUEST;
	eap_session->finished = false;

	return eap_compose(eap_session);
}

/*
 *	compose EAP FAILURE packet in EAP-Message
 */
rlm_rcode_t eap_fail(eap_session_t *eap_session)
{
	/*
	 *	Delete any previous replies.
	 */
	fr_pair_delete_by_da(&eap_session->request->reply->vps, attr_eap_message);
	fr_pair_delete_by_da(&eap_session->request->reply->vps, attr_state);

	talloc_free(eap_session->this_round->request);
	eap_session->this_round->request = talloc_zero(eap_session->this_round, eap_packet_t);
	eap_session->this_round->request->code = FR_EAP_CODE_FAILURE;
	eap_session->finished = true;

	return eap_compose(eap_session);
}

/*
 *	compose EAP SUCCESS packet in EAP-Message
 */
rlm_rcode_t eap_success(eap_session_t *eap_session)
{
	eap_session->this_round->request->code = FR_EAP_CODE_SUCCESS;
	eap_session->finished = true;

	return eap_compose(eap_session);
}

/*
 * Allocate a new eap_packet_t
 */
static eap_round_t *eap_round_alloc(eap_session_t *eap_session)
{
	eap_round_t	*eap_round;

	eap_round = talloc_zero(eap_session, eap_round_t);
	if (!eap_round) return NULL;

	eap_round->response = talloc_zero(eap_round, eap_packet_t);
	if (!eap_round->response) {
		talloc_free(eap_round);
		return NULL;
	}
	eap_round->request = talloc_zero(eap_round, eap_packet_t);
	if (!eap_round->request) {
		talloc_free(eap_round);
		return NULL;
	}

	return eap_round;
}

/*
 *	Create our Request-Response data structure with the eap packet
 */
eap_round_t *eap_round_build(eap_session_t *eap_session, eap_packet_raw_t **eap_packet_p)
{
	eap_round_t		*eap_round = NULL;
	int			typelen;
	eap_packet_raw_t	*eap_packet = *eap_packet_p;
	uint16_t		len;

	eap_round = eap_round_alloc(eap_session);
	if (eap_round == NULL) return NULL;

	eap_round->response->packet = (uint8_t *)eap_packet;
	(void) talloc_steal(eap_round, eap_packet);
	eap_round->response->code = eap_packet->code;
	eap_round->response->id = eap_packet->id;
	eap_round->response->type.num = eap_packet->data[0];

	memcpy(&len, eap_packet->length, sizeof(uint16_t));
	len = ntohs(len);
	eap_round->response->length = len;

	/*
	 *	We've eaten the eap packet into the eap_round.
	 */
	*eap_packet_p = NULL;

	/*
	 *	First 5 bytes in eap, are code + id + length(2) + type.
	 *
	 *	The rest is type-specific data.  We skip type while
	 *	getting typedata from data.
	 */
	typelen = len - 5/*code + id + length + type */;
	if (typelen > 0) {
		/*
		 *	Since the packet contains the complete
		 *	eap_packet, typedata will be a ptr in packet
		 *	to its typedata
		 */
		eap_round->response->type.data = eap_round->response->packet + 5/*code+id+length+type*/;
		eap_round->response->type.length = typelen;
	} else {
		eap_round->response->type.length = 0;
		eap_round->response->type.data = NULL;
	}

	return eap_round;
}
