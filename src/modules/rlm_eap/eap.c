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
 * @copyright 2000-2003,2006  The FreeRADIUS server project
 * @copyright 2001  hereUare Communications, Inc. <raghud@hereuare.com>
 * @copyright 2003  Alan DeKok <aland@freeradius.org>
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

RCSID("$Id$")

#include "rlm_eap.h"
#include <ctype.h>

static char const *eap_codes[] = {
	 "",				/* 0 is invalid */
	"Request",
	"Response",
	"Success",
	"Failure"
};


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
	 *
	 *	LEAP requires the Id to be incremented on EAP-Success
	 *	in Stage 4, so that we can carry on the conversation
	 *	where the client asks us to authenticate ourselves
	 *	in stage 5.
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
		rad_assert(eap_session->type >= FR_EAP_MD5);
		rad_assert(eap_session->type < FR_EAP_MAX_TYPES);

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
		static uint8_t auth_vector[AUTH_VECTOR_LEN] = { 0x00 };

		MEM(pair_add_reply(&vp, attr_message_authenticator) >= 0);
		fr_pair_value_memcpy(vp, auth_vector, sizeof(auth_vector));
	}

	/* Set request reply code, but only if it's not already set. */
	rcode = RLM_MODULE_OK;
	if (!request->reply->code) switch (reply->code) {
	case FR_EAP_CODE_RESPONSE:
		request->reply->code = FR_CODE_ACCESS_ACCEPT;
		rcode = RLM_MODULE_HANDLED; /* leap weirdness */
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
int eap_start(rlm_eap_t const *inst, REQUEST *request)
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
		p[4] = FR_EAP_IDENTITY;
		fr_pair_value_memsteal(vp, p);

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
	if ((eap_msg->vp_octets[4] >= FR_EAP_MD5) &&
	    inst->ignore_unknown_types &&
	    ((eap_msg->vp_octets[4] == 0) ||
	     (eap_msg->vp_octets[4] >= FR_EAP_MAX_TYPES) ||
	     (!inst->methods[eap_msg->vp_octets[4]].submodule))) {
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
	if ((eap_msg->vp_octets[4] == FR_EAP_NAK) &&
	    (eap_msg->vp_length >= (EAP_HEADER_LEN + 2)) &&
	    inst->ignore_unknown_types &&
	    ((eap_msg->vp_octets[5] == 0) ||
	     (eap_msg->vp_octets[5] >= FR_EAP_MAX_TYPES) ||
	     (!inst->methods[eap_msg->vp_octets[5]].submodule))) {
		RDEBUG2("Ignoring NAK with request for unknown EAP type");
		return RLM_MODULE_NOOP;
	}

	if ((eap_msg->vp_octets[4] == FR_EAP_TTLS) ||
	    (eap_msg->vp_octets[4] == FR_EAP_PEAP)) {
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
	if (eap_msg->vp_octets[4] == FR_EAP_IDENTITY) {
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
 * Basic EAP packet verifications & validations
 */
static int eap_validation(REQUEST *request, eap_packet_raw_t **eap_packet_p)
{
	uint16_t		len;
	size_t			packet_len;
	eap_packet_raw_t	*eap_packet = *eap_packet_p;

	/*
	 *	These length checks are also done by eap_vp2packet(),
	 *	but that's OK.  The static analysis tools aren't smart
	 *	enough to figure that out.
	 */
	packet_len = talloc_array_length((uint8_t *) eap_packet);
	if (packet_len <= EAP_HEADER_LEN) {
		REDEBUG("Invalid EAP data lenth %zd <= 4", packet_len);
		return -1;
	}

	memcpy(&len, eap_packet->length, sizeof(uint16_t));
	len = ntohs(len);

	if ((len <= EAP_HEADER_LEN) || (len > packet_len)) {
		REDEBUG("Invalid EAP length field.  Expected value in range %u-%zu, was %u bytes",
			EAP_HEADER_LEN, packet_len, len);
		return -1;
	}

	/*
	 *	High level EAP packet checks
	 */
	switch (eap_packet->code) {
	case FR_EAP_CODE_RESPONSE:
	case FR_EAP_CODE_REQUEST:
		break;

	default:
		REDEBUG("Invalid EAP code %d: Ignoring the packet", eap_packet->code);
		return -1;
	}

	if ((eap_packet->data[0] <= 0) ||
	    (eap_packet->data[0] >= FR_EAP_MAX_TYPES)) {
		/*
		 *	Handle expanded types by smashing them to
		 *	normal types.
		 */
		if (eap_packet->data[0] == FR_EAP_EXPANDED_TYPE) {
			uint8_t *p, *q;

			if (len <= (EAP_HEADER_LEN + 1 + 3 + 4)) {
				REDEBUG("Expanded EAP type is too short: ignoring the packet");
				return -1;
			}

			if ((eap_packet->data[1] != 0) ||
			    (eap_packet->data[2] != 0) ||
			    (eap_packet->data[3] != 0)) {
				REDEBUG("Expanded EAP type has unknown Vendor-ID: ignoring the packet");
				return -1;
			}

			if ((eap_packet->data[4] != 0) ||
			    (eap_packet->data[5] != 0) ||
			    (eap_packet->data[6] != 0)) {
				REDEBUG("Expanded EAP type has unknown Vendor-Type: ignoring the packet");
				return -1;
			}

			if ((eap_packet->data[7] == 0) ||
			    (eap_packet->data[7] >= FR_EAP_MAX_TYPES)) {
				REDEBUG("Unsupported Expanded EAP type %s (%u): ignoring the packet",
					eap_type2name(eap_packet->data[7]), eap_packet->data[7]);
				return -1;
			}

			if (eap_packet->data[7] == FR_EAP_NAK) {
				REDEBUG("Unsupported Expanded EAP-NAK: ignoring the packet");
				return -1;
			}

			/*
			 *	Re-write the EAP packet to NOT have the expanded type.
			 */
			q = (uint8_t *) eap_packet;
			memmove(q + EAP_HEADER_LEN, q + EAP_HEADER_LEN + 7, len - 7 - EAP_HEADER_LEN);

			p = talloc_realloc(talloc_parent(eap_packet), eap_packet, uint8_t, len - 7);
			if (!p) {
				REDEBUG("Unsupported EAP type %s (%u): ignoring the packet",
					eap_type2name(eap_packet->data[0]), eap_packet->data[0]);
				return -1;
			}

			len -= 7;
			p[2] = (len >> 8) & 0xff;
			p[3] = len & 0xff;

			*eap_packet_p = (eap_packet_raw_t *) p;
			RWARN("Converting Expanded EAP to normal EAP.");
			RWARN("Unnecessary use of Expanded EAP types is not recommened.");

			return 0;
		}

		REDEBUG("Unsupported EAP type %s (%u): ignoring the packet",
			eap_type2name(eap_packet->data[0]), eap_packet->data[0]);
		return -1;
	}

	/* we don't expect notification, but we send it */
	if (eap_packet->data[0] == FR_EAP_NOTIFICATION) {
		REDEBUG("Got NOTIFICATION, Ignoring the packet");
		return -1;
	}

	return 0;
}

/** Extract the EAP identity from EAP-Identity-Response packets
 *
 * @param[in] request		The current request.
 * @param[in] eap_session	EAP-Session to associate identity with.
 * @param[in] eap_packet	To extract the identity from.
 * @return
 *	- The user's EAP-Identity.
 *	- or NULL on error.
 */
static char *eap_identity(REQUEST *request, eap_session_t *eap_session, eap_packet_raw_t *eap_packet)
{
	uint16_t 	len;

	if (!eap_packet ||
	    (eap_packet->code != FR_EAP_CODE_RESPONSE) ||
	    (eap_packet->data[0] != FR_EAP_IDENTITY)) return NULL;

	memcpy(&len, eap_packet->length, sizeof(uint16_t));
	len = ntohs(len);

	if ((len <= 5) || (eap_packet->data[1] == 0x00)) {
		REDEBUG("EAP-Identity Unknown");
		return NULL;
	}

	if (len > 1024) {
		REDEBUG("EAP-Identity too long");
		return NULL;
	}

	return talloc_bstrndup(eap_session, (char *)&eap_packet->data[1], len - 5);
}

/*
 *	Create our Request-Response data structure with the eap packet
 */
static eap_round_t *eap_round_build(eap_session_t *eap_session, eap_packet_raw_t **eap_packet_p)
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

/** 'destroy' an EAP session and dissasociate it from the current request
 *
 * @note This could be done in the eap_session_t destructor (and was done previously)
 *	but this made the code too hard to follow, and too fragile.
 *
 * @see eap_session_continue
 * @see eap_session_freeze
 * @see eap_session_thaw
 *
 * @param eap_session to destroy (disassociate and free).
 */
void eap_session_destroy(eap_session_t **eap_session)
{
	if (!*eap_session) return;

	if (!(*eap_session)->request) {
		TALLOC_FREE(*eap_session);
		return;
	}

#ifndef NDEBUG
	{
		eap_session_t *in_request;

		in_request = request_data_get((*eap_session)->request, NULL, REQUEST_DATA_EAP_SESSION);

		/*
		 *	Additional sanity check.  Either there's no eap_session
		 *	associated with the request, or it matches the one we're
		 *	about to free.
		 */
		rad_assert(!in_request || (*eap_session == in_request));
	}
#else
	(void) request_data_get((*eap_session)->request, NULL, REQUEST_DATA_EAP_SESSION);
#endif

	TALLOC_FREE(*eap_session);
}

/** Freeze an #eap_session_t so that it can continue later
 *
 * Sets the request and pointer to the eap_session to NULL. Primarily here to help track
 * the lifecycle of an #eap_session_t.
 *
 * The actual freezing/thawing and management (ensuring it's available during multiple
 * rounds of EAP) of the #eap_session_t associated with REQUEST_DATA_EAP_SESSION, is
 * done by the state API.
 *
 * @note must be called before mod_* functions in rlm_eap return.
 *
 * @see eap_session_continue
 * @see eap_session_thaw
 * @see eap_session_destroy
 *
 * @param eap_session to freeze.
 */
void eap_session_freeze(eap_session_t **eap_session)
{
	if (!*eap_session) return;

	rad_assert((*eap_session)->request);
	(*eap_session)->request = NULL;
	*eap_session = NULL;
}

/** Thaw an eap_session_t so it can be continued
 *
 * Retrieve an #eap_session_t from the request data, and set relevant fields. Primarily
 * here to help track the lifecycle of an #eap_session_t.
 *
 * The actual freezing/thawing and management (ensuring it's available during multiple
 * rounds of EAP) of the #eap_session_t associated with REQUEST_DATA_EAP_SESSION, is
 * done by the state API.
 *
 * @note #eap_session_continue should be used instead if ingesting an #eap_packet_raw_t.
 *
 * @see eap_session_continue
 * @see eap_session_freeze
 * @see eap_session_destroy
 *
 * @param request to retrieve session from.
 * @return
 *	- The #eap_session_t associated with this request.
 *	  MUST be freed with #eap_session_destroy if being disposed of, OR
 *	  MUST be re-frozen with #eap_session_freeze if the authentication session will
 *	  continue when a future request is received.
 *	- NULL if no #eap_session_t associated with this request.
 */
eap_session_t *eap_session_thaw(REQUEST *request)
{
	eap_session_t *eap_session;

	eap_session = request_data_reference(request, NULL, REQUEST_DATA_EAP_SESSION);
	if (!eap_session) {
		/* Either send EAP_Identity or EAP-Fail */
		REDEBUG("No EAP session matching state");
		return NULL;
	}

	if (!fr_cond_assert(eap_session->inst)) return NULL;

	rad_assert(!eap_session->request);	/* If triggered, something didn't freeze the session */
	eap_session->request = request;
	eap_session->updated = request->packet->timestamp.tv_sec;

	return eap_session;
}

/** Ingest an eap_packet into a thawed or newly allocated session
 *
 * If eap_packet is an Identity-Response then allocate a new eap_session and fill the identity.
 *
 * If eap_packet is not an identity response, retrieve the pre-existing eap_session_t from request
 * data.
 *
 * If no User-Name attribute is present in the request, one will be created from the
 * Identity-Response received when the eap_session was allocated.
 *
 * @see eap_session_freeze
 * @see eap_session_thaw
 * @see eap_session_destroy
 *
 * @param[in] eap_packet_p extracted from the RADIUS Access-Request.  Consumed or freed by this
 *	function.  Do not access after calling this function. Is a **so the packet pointer can be
 *	set to NULL.
 * @param[in] inst of the rlm_eap module.
 * @param[in] request The current request.
 * @return
 *	- A newly allocated eap_session_t, or the one associated with the current request.
 *	  MUST be freed with #eap_session_destroy if being disposed of, OR
 *	  MUST be re-frozen with #eap_session_freeze if the authentication session will
 *	  continue when a future request is received.
 *	- NULL on error.
 */
eap_session_t *eap_session_continue(eap_packet_raw_t **eap_packet_p, rlm_eap_t const *inst, REQUEST *request)
{
	eap_session_t	*eap_session = NULL;
	eap_packet_raw_t *eap_packet;
	VALUE_PAIR	*vp;

	/*
	 *	Ensure it's a valid EAP-Request, or EAP-Response.
	 */
	if (eap_validation(request, eap_packet_p) < 0) {
	error_round:
		talloc_free(*eap_packet_p);
		*eap_packet_p = NULL;
		return NULL;
	}

	eap_packet = *eap_packet_p;

	/*
	 *	eap_session_t MUST be found in the list if it is not
	 *	EAP-Identity response
	 */
	if (eap_packet->data[0] != FR_EAP_IDENTITY) {
		eap_session = eap_session_thaw(request);
		if (!eap_session) {
			vp = fr_pair_find_by_da(request->packet->vps, attr_state, TAG_ANY);
			if (!vp) {
				REDEBUG("EAP requires the State attribute to work, but no State exists in the Access-Request packet.");
				REDEBUG("The RADIUS client is broken.  No amount of changing FreeRADIUS will fix the RADIUS client.");
			}

			goto error_round;
		}

		RDEBUG4("Got eap_session_t %p from request data", eap_session);
		(void) talloc_get_type_abort(eap_session, eap_session_t);
		eap_session->rounds++;
		if (eap_session->rounds >= 50) {
			RERROR("Failing EAP session due to too many round trips");
		error_session:
			eap_session_destroy(&eap_session);
			goto error_round;
		}

		/*
		 *	Even more paranoia.  Without this, some weird
		 *	clients could do crazy things.
		 *
		 *	It's ok to send EAP sub-type NAK in response
		 *	to a request for a particular type, but it's NOT
		 *	OK to blindly return data for another type.
		 */
		if ((eap_packet->data[0] != FR_EAP_NAK) &&
		    (eap_packet->data[0] != eap_session->type)) {
			RERROR("Response appears to match a previous request, but the EAP type is wrong");
			RERROR("We expected EAP type %s, but received type %s",
			       eap_type2name(eap_session->type),
			       eap_type2name(eap_packet->data[0]));
			RERROR("Your Supplicant or NAS is probably broken");
			goto error_round;
		}
	/*
	 *	Packet was EAP identity, allocate a new eap_session.
	 */
	} else {
		eap_session = eap_session_alloc(inst, request);
		if (!eap_session) goto error_round;

		RDEBUG4("New eap_session_t %p", eap_session);

		/*
		 *	All fields in the eap_session are set to zero.
		 */
		eap_session->identity = eap_identity(request, eap_session, eap_packet);
		if (!eap_session->identity) {
			RDEBUG("Identity Unknown, authentication failed");
			goto error_session;
		}

		/*
		 *	If the index is removed by something else
		 *	like the state being cleaned up, then we
		 *	still want the eap_session to be freed, which
		 *	is why we set free_opaque to true.
		 *
		 *	We must pass a NULL pointer to associate the
		 *	the EAP_SESSION data with, else we'll break
		 *	tunneled EAP, where the inner EAP module is
		 *	a different instance to the outer one.
		 */
		request_data_talloc_add(request, NULL, REQUEST_DATA_EAP_SESSION, eap_session_t,
					eap_session, true, true, true);
	}

	vp = fr_pair_find_by_da(request->packet->vps, attr_user_name, TAG_ANY);
	if (!vp) {
		/*
		 *	NAS did not set the User-Name
		 *	attribute, so we set it here and
		 *	prepend it to the beginning of the
		 *	request vps so that autz's work
		 *	correctly
		 */
		RDEBUG2("Broken NAS did not set User-Name, setting from EAP Identity");
		MEM(pair_add_request(&vp, attr_user_name) >= 0);
		fr_pair_value_bstrncpy(vp, eap_session->identity, talloc_array_length(eap_session->identity) - 1);
	} else {
		/*
		 *      A little more paranoia.  If the NAS
		 *      *did* set the User-Name, and it doesn't
		 *      match the identity, (i.e. If they
		 *      change their User-Name part way through
		 *      the EAP transaction), then reject the
		 *      request as the NAS is doing something
		 *      funny.
		 */
		if (talloc_memcmp_bstr(eap_session->identity, vp->vp_strvalue) != 0) {
			REDEBUG("Identity from EAP Identity-Response \"%s\" does not match User-Name attribute \"%s\"",
				eap_session->identity, vp->vp_strvalue);
			goto error_round;
		}
	}

	eap_session->this_round = eap_round_build(eap_session, eap_packet_p);
	if (!eap_session->this_round) {
		REDEBUG("Failed allocating memory for round");
		goto error_session;
	}

	return eap_session;
}
