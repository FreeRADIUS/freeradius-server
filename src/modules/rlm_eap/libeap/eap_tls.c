/*
 * eap_tls.c
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
 * Copyright 2001  hereUare Communications, Inc. <raghud@hereuare.com>
 * Copyright 2003  Alan DeKok <aland@freeradius.org>
 * Copyright 2006  The FreeRADIUS server project
 */

/*
 *
 *  TLS Packet Format in EAP
 *  --- ------ ------ -- ---
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Code      |   Identifier  |            Length             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |     Flags     |      TLS Message Length
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     TLS Message Length        |       TLS Data...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/autoconf.h>
#include <assert.h>
#include "eap_tls.h"

/*
 *      Allocate a new TLS_PACKET
 */
EAPTLS_PACKET *eaptls_alloc(void)
{
	EAPTLS_PACKET   *rp;

	if ((rp = malloc(sizeof(EAPTLS_PACKET))) == NULL) {
		radlog(L_ERR, "rlm_eap_tls: out of memory");
		return NULL;
	}
	memset(rp, 0, sizeof(EAPTLS_PACKET));
	return rp;
}

/*
 *      Free EAPTLS_PACKET
 */
void eaptls_free(EAPTLS_PACKET **eaptls_packet_ptr)
{
	EAPTLS_PACKET *eaptls_packet;

	if (!eaptls_packet_ptr) return;
	eaptls_packet = *eaptls_packet_ptr;
	if (eaptls_packet == NULL) return;

	if (eaptls_packet->data) {
		free(eaptls_packet->data);
		eaptls_packet->data = NULL;
	}

	free(eaptls_packet);
	*eaptls_packet_ptr = NULL;
}

/*
   The S flag is set only within the EAP-TLS start message
   sent from the EAP server to the peer.
*/
int eaptls_start(EAP_DS *eap_ds, int peap_flag)
{
	EAPTLS_PACKET 	reply;

	reply.code = FR_TLS_START;
	reply.length = TLS_HEADER_LEN + 1/*flags*/;

	reply.flags = peap_flag;
	reply.flags = SET_START(reply.flags);

	reply.data = NULL;
	reply.dlen = 0;

	eaptls_compose(eap_ds, &reply);

	return 1;
}

int eaptls_success(EAP_HANDLER *handler, int peap_flag)
{
	EAPTLS_PACKET	reply;
	VALUE_PAIR *vp, *vps = NULL;
	REQUEST *request = handler->request;
	tls_session_t *tls_session = handler->opaque;

	handler->finished = TRUE;
	reply.code = FR_TLS_SUCCESS;
	reply.length = TLS_HEADER_LEN;
	reply.flags = peap_flag;
	reply.data = NULL;
	reply.dlen = 0;

	/*
	 *	If there's no session resumption, delete the entry
	 *	from the cache.  This means either it's disabled
	 *	globally for this SSL context, OR we were told to
	 *	disable it for this user.
	 *
	 *	This also means you can't turn it on just for one
	 *	user.
	 */
	if ((!tls_session->allow_session_resumption) ||
	    (((vp = pairfind(request->config_items, 1127, 0)) != NULL) &&
	     (vp->vp_integer == 0))) {
		SSL_CTX_remove_session(tls_session->ctx,
				       tls_session->ssl->session);
		tls_session->allow_session_resumption = 0;

		/*
		 *	If we're in a resumed session and it's
		 *	not allowed, 
		 */
		if (SSL_session_reused(tls_session->ssl)) {
			RDEBUG("FAIL: Forcibly stopping session resumption as it is not allowed.");
			return eaptls_fail(handler, peap_flag);
		}
		
		/*
		 *	Else resumption IS allowed, so we store the
		 *	user data in the cache.
		 */
	} else if (!SSL_session_reused(tls_session->ssl)) {
		RDEBUG2("Saving response in the cache");
		
		vp = paircopy2(request->reply->vps, PW_USER_NAME, 0);
		if (vp) pairadd(&vps, vp);
		
		vp = paircopy2(request->packet->vps, PW_STRIPPED_USER_NAME, 0);
		if (vp) pairadd(&vps, vp);
		
		vp = paircopy2(request->reply->vps, PW_CACHED_SESSION_POLICY, 0);
		if (vp) pairadd(&vps, vp);
		
		if (vps) {
			SSL_SESSION_set_ex_data(tls_session->ssl->session,
						FR_TLS_EX_INDEX_VPS, vps);
		} else {
			RDEBUG2("WARNING: No information to cache: session caching will be disabled for this session.");
			SSL_CTX_remove_session(tls_session->ctx,
					       tls_session->ssl->session);
		}

		/*
		 *	Else the session WAS allowed.  Copy the cached
		 *	reply.
		 */
	} else {
	       
		vp = SSL_SESSION_get_ex_data(tls_session->ssl->session,
					     FR_TLS_EX_INDEX_VPS);
		if (!vp) {
			RDEBUG("WARNING: No information in cached session!");
			return eaptls_fail(handler, peap_flag);
		} else {
			RDEBUG("Adding cached attributes to the reply:");
			debug_pair_list(vp);
			pairadd(&request->reply->vps, paircopy(vp));

			/*
			 *	Mark the request as resumed.
			 */
			vp = pairmake("EAP-Session-Resumed", "1", T_OP_SET);
			if (vp) pairadd(&request->packet->vps, vp);
		}
	}

	/*
	 *	Call compose AFTER checking for cached data.
	 */
	eaptls_compose(handler->eap_ds, &reply);

	/*
	 *	Automatically generate MPPE keying material.
	 */
	if (tls_session->prf_label) {
		eaptls_gen_mppe_keys(&handler->request->reply->vps,
				     tls_session->ssl, tls_session->prf_label);
	} else {
		RDEBUG("WARNING: Not adding MPPE keys because there is no PRF label");
	}

	return 1;
}

int eaptls_fail(EAP_HANDLER *handler, int peap_flag)
{
	EAPTLS_PACKET	reply;
	tls_session_t *tls_session = handler->opaque;

	handler->finished = TRUE;
	reply.code = FR_TLS_FAIL;
	reply.length = TLS_HEADER_LEN;
	reply.flags = peap_flag;
	reply.data = NULL;
	reply.dlen = 0;

	/*
	 *	Force the session to NOT be cached.
	 */
	SSL_CTX_remove_session(tls_session->ctx, tls_session->ssl->session);

	eaptls_compose(handler->eap_ds, &reply);

	return 1;
}

/*
   A single TLS record may be up to 16384 octets in length, but a TLS
   message may span multiple TLS records, and a TLS certificate message
   may in principle be as long as 16MB.
*/

/*
 *	Frame the Dirty data that needs to be send to the client in an
 *	EAP-Request.  We always embed the TLS-length in all EAP-TLS
 *	packets that we send, for easy reference purpose.  Handle
 *	fragmentation and sending the next fragment etc.
 */
int eaptls_request(EAP_DS *eap_ds, tls_session_t *ssn)
{
	EAPTLS_PACKET	reply;
	unsigned int	size;
	unsigned int 	nlen;
	unsigned int 	lbit = 0;

	/* This value determines whether we set (L)ength flag for
		EVERY packet we send and add corresponding
		"TLS Message Length" field.

	length_flag = TRUE;
		This means we include L flag and "TLS Msg Len" in EVERY
		packet we send out.

	length_flag = FALSE;
		This means we include L flag and "TLS Msg Len" **ONLY**
		in First packet of a fragment series. We do not use
		it anywhere else.

		Having L flag in every packet is prefered.

	*/
	if (ssn->length_flag) {
		lbit = 4;
	}
	if (ssn->fragment == 0) {
		ssn->tls_msg_len = ssn->dirty_out.used;
	}

	reply.code = FR_TLS_REQUEST;
	reply.flags = ssn->peap_flag;

	/* Send data, NOT more than the FRAGMENT size */
	if (ssn->dirty_out.used > ssn->offset) {
		size = ssn->offset;
		reply.flags = SET_MORE_FRAGMENTS(reply.flags);
		/* Length MUST be included if it is the First Fragment */
		if (ssn->fragment == 0) {
			lbit = 4;
		}
		ssn->fragment = 1;
	} else {
		size = ssn->dirty_out.used;
		ssn->fragment = 0;
	}

	reply.dlen = lbit + size;
	reply.length = TLS_HEADER_LEN + 1/*flags*/ + reply.dlen;

	reply.data = malloc(reply.dlen);
	if (lbit) {
		nlen = htonl(ssn->tls_msg_len);
		memcpy(reply.data, &nlen, lbit);
		reply.flags = SET_LENGTH_INCLUDED(reply.flags);
	}
	(ssn->record_minus)(&ssn->dirty_out, reply.data + lbit, size);

	eaptls_compose(eap_ds, &reply);
	free(reply.data);
	reply.data = NULL;

	return 1;
}

/*
 * Acknowledge received is for one of the following messages sent earlier
 * 1. Handshake completed Message, so now send, EAP-Success
 * 2. Alert Message, now send, EAP-Failure
 * 3. Fragment Message, now send, next Fragment
 */
static fr_tls_status_t eaptls_ack_handler(EAP_HANDLER *handler)
{
	tls_session_t *tls_session;
	REQUEST *request = handler->request;

	tls_session = (tls_session_t *)handler->opaque;
	if (tls_session == NULL){
		radlog_request(L_ERR, 0, request, "FAIL: Unexpected ACK received.  Could not obtain session information.");
		return FR_TLS_FAIL;
	}
	if (tls_session->info.initialized == 0) {
		RDEBUG("No SSL info available. Waiting for more SSL data.");
		return FR_TLS_REQUEST;
	}
	if ((tls_session->info.content_type == handshake) &&
	    (tls_session->info.origin == 0)) {
		radlog_request(L_ERR, 0, request, "FAIL: ACK without earlier message.");
		return FR_TLS_FAIL;
	}

	switch (tls_session->info.content_type) {
	case alert:
		RDEBUG2("ACK alert");
		eaptls_fail(handler, tls_session->peap_flag);
		return FR_TLS_FAIL;

	case handshake:
		if ((tls_session->info.handshake_type == finished) &&
		    (tls_session->dirty_out.used == 0)) {
			RDEBUG2("ACK handshake is finished");

			/* 
			 *	From now on all the content is
			 *	application data set it here as nobody else
			 *	sets it.
			 */
			tls_session->info.content_type = application_data;
			return FR_TLS_SUCCESS;
		} /* else more data to send */

		RDEBUG2("ACK handshake fragment handler");
		/* Fragmentation handler, send next fragment */
		return FR_TLS_REQUEST;

	case application_data:
		RDEBUG2("ACK handshake fragment handler in application data");
		return FR_TLS_REQUEST;
						
		/*
		 *	For the rest of the conditions, switch over
		 *	to the default section below.
		 */
	default:
		RDEBUG2("ACK default");
		radlog_request(L_ERR, 0, request, "Invalid ACK received: %d",
		       tls_session->info.content_type);
		return FR_TLS_FAIL;
	}
}

/*
 *	Similarly, when the EAP server receives an EAP-Response with
 *	the M bit set, it MUST respond with an EAP-Request with
 *	EAP-Type=EAP-TLS and no data. This serves as a fragment ACK.
 *
 *	In order to prevent errors in the processing of fragments, the
 *	EAP server MUST use increment the Identifier value for each
 *	fragment ACK contained within an EAP-Request, and the peer
 *	MUST include this Identifier value in the subsequent fragment
 *	contained within an EAP- Reponse.
 *
 *	EAP server sends an ACK when it determines there are More
 *	fragments to receive to make the complete
 *	TLS-record/TLS-Message
 */
static int eaptls_send_ack(EAP_DS *eap_ds, int peap_flag)
{
	EAPTLS_PACKET 	reply;

	reply.code = FR_TLS_ACK;
	reply.length = TLS_HEADER_LEN + 1/*flags*/;
	reply.flags = peap_flag;
	reply.data = NULL;
	reply.dlen = 0;

	eaptls_compose(eap_ds, &reply);

	return 1;
}

/*
 *	The S flag is set only within the EAP-TLS start message sent
 *	from the EAP server to the peer.
 *
 *	Similarly, when the EAP server receives an EAP-Response with
 *	the M bit set, it MUST respond with an EAP-Request with
 *	EAP-Type=EAP-TLS and no data. This serves as a fragment
 *	ACK. The EAP peer MUST wait.
 */
static fr_tls_status_t eaptls_verify(EAP_HANDLER *handler)
{
	EAP_DS *eap_ds = handler->eap_ds;
	EAP_DS *prev_eap_ds = handler->prev_eapds;
	eaptls_packet_t	*eaptls_packet, *eaptls_prev = NULL;
	REQUEST *request = handler->request;

	/*
	 *	We don't check ANY of the input parameters.  It's all
	 *	code which works together, so if something is wrong,
	 *	we SHOULD core dump.
	 *
	 *	e.g. if eap_ds is NULL, of if eap_ds->response is
	 *	NULL, of if it's NOT an EAP-Response, or if the packet
	 *	is too short.  See eap_validation()., in ../../eap.c
	 *
	 *	Also, eaptype_select() takes care of selecting the
	 *	appropriate type, so we don't need to check
	 *	eap_ds->response->type.type == PW_EAP_TLS, or anything
	 *	else.
	 */
	eaptls_packet = (eaptls_packet_t *)eap_ds->response->type.data;
	if (prev_eap_ds && prev_eap_ds->response)
		eaptls_prev = (eaptls_packet_t *)prev_eap_ds->response->type.data;

	/*
	 *	check for ACK
	 *
	 *	If there's no TLS data, or there's 1 byte of TLS data,
	 *	with the flags set to zero, then it's an ACK.
	 *
	 *	Find if this is a reply to the previous request sent
	 */
	if ((eaptls_packet == NULL) ||
	    ((eap_ds->response->length == EAP_HEADER_LEN + 2) &&
	     ((eaptls_packet->flags & 0xc0) == 0x00))) {

#if 0
		/*
		 *	Un-comment this for TLS inside of TTLS/PEAP
		 */
		RDEBUG2("Received EAP-TLS ACK message");
		return eaptls_ack_handler(handler);
#else
		if (prev_eap_ds &&
		    (prev_eap_ds->request->id == eap_ds->response->id)) {
			/*
			 *	Run the ACK handler directly from here.
			 */
			RDEBUG2("Received TLS ACK");
			return eaptls_ack_handler(handler);
		} else {
			radlog_request(L_ERR, 0, request, "Received Invalid TLS ACK");
			return FR_TLS_INVALID;
		}
#endif
	}

	/*
	 *	We send TLS_START, but do not receive it.
	 */
	if (TLS_START(eaptls_packet->flags)) {
		RDEBUG("Received unexpected EAP-TLS Start message");
		return FR_TLS_INVALID;
	}

	/*
	 *	The L bit (length included) is set to indicate the
	 *	presence of the four octet TLS Message Length field,
	 *	and MUST be set for the first fragment of a fragmented
	 *	TLS message or set of messages.
	 *
	 *	The M bit (more fragments) is set on all but the last
	 *	fragment.
	 *
	 *	The S bit (EAP-TLS start) is set in an EAP-TLS Start
	 *	message. This differentiates the EAP-TLS Start message
	 *	from a fragment acknowledgement.
	 */
	if (TLS_LENGTH_INCLUDED(eaptls_packet->flags)) {
		DEBUG2("  TLS Length %d",
		       eaptls_packet->data[2] * 256 | eaptls_packet->data[3]);
		if (TLS_MORE_FRAGMENTS(eaptls_packet->flags)) {
			/*
			 * FIRST_FRAGMENT is identified
			 * 1. If there is no previous EAP-response received.
			 * 2. If EAP-response received, then its M bit not set.
			 * 	(It is because Last fragment will not have M bit set)
			 */
			if (!prev_eap_ds ||
			    (prev_eap_ds->response == NULL) ||
			    (eaptls_prev == NULL) ||
			    !TLS_MORE_FRAGMENTS(eaptls_prev->flags)) {

				RDEBUG2("Received EAP-TLS First Fragment of the message");
				return FR_TLS_FIRST_FRAGMENT;
			} else {

				RDEBUG2("More Fragments with length included");
				return FR_TLS_MORE_FRAGMENTS_WITH_LENGTH;
			}
		} else {
			RDEBUG2("Length Included");
			return FR_TLS_LENGTH_INCLUDED;
		}
	}

	if (TLS_MORE_FRAGMENTS(eaptls_packet->flags)) {
		RDEBUG2("More fragments to follow");
		return FR_TLS_MORE_FRAGMENTS;
	}

	/*
	 *	None of the flags are set, but it's still a valid
	 *	EAPTLS packet.
	 */
	return FR_TLS_OK;
}

/*
 * EAPTLS_PACKET
 * code   =  EAP-code
 * id     =  EAP-id
 * length = code + id + length + flags + tlsdata
 *        =  1   +  1 +   2    +  1    +  X
 * length = EAP-length - 1(EAP-Type = 1 octet)
 * flags  = EAP-typedata[0] (1 octet)
 * dlen   = EAP-typedata[1-4] (4 octets), if L flag set
 *        = length - 5(code+id+length+flags), otherwise
 * data   = EAP-typedata[5-n], if L flag set
 *        = EAP-typedata[1-n], otherwise
 * packet = EAP-typedata (complete typedata)
 *
 * Points to consider during EAP-TLS data extraction
 * 1. In the received packet, No data will be present incase of ACK-NAK
 * 2. Incase if more fragments need to be received then ACK after retreiving this fragment.
 *
 *  RFC 2716 Section 4.2.  PPP EAP TLS Request Packet
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     Code      |   Identifier  |            Length             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     Type      |     Flags     |      TLS Message Length
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     TLS Message Length        |       TLS Data...
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *  The Length field is two octets and indicates the length of the EAP
 *  packet including the Code, Identifir, Length, Type, and TLS data
 *  fields.
 */
static EAPTLS_PACKET *eaptls_extract(REQUEST *request, EAP_DS *eap_ds, fr_tls_status_t status)
{
	EAPTLS_PACKET	*tlspacket;
	uint32_t	data_len = 0;
	uint32_t	len = 0;
	uint8_t		*data = NULL;

	if (status  == FR_TLS_INVALID)
		return NULL;

	/*
	 *	The main EAP code & eaptls_verify() take care of
	 *	ensuring that the packet is OK, and that we can
	 *	extract the various fields we want.
	 *
	 *	e.g. a TLS packet with zero data is allowed as an ACK,
	 *	but we will never see it here, as we will simply
	 *	send another fragment, instead of trying to extract
	 *	the data.
	 *
	 *	MUST have TLS type octet, followed by flags, followed
	 *	by data.
	 */
	assert(eap_ds->response->length > 2);

	tlspacket = eaptls_alloc();
	if (tlspacket == NULL) return NULL;

	/*
	 *	Code & id for EAPTLS & EAP are same
	 *	but eaptls_length = eap_length - 1(EAP-Type = 1 octet)
	 *
	 *	length = code + id + length + type + tlsdata
	 *	       =  1   +  1 +   2    +  1    +  X
	 */
	tlspacket->code = eap_ds->response->code;
	tlspacket->id = eap_ds->response->id;
	tlspacket->length = eap_ds->response->length - 1; /* EAP type */
	tlspacket->flags = eap_ds->response->type.data[0];

	/*
	 *	A quick sanity check of the flags.  If we've been told
	 *	that there's a length, and there isn't one, then stop.
	 */
	if (TLS_LENGTH_INCLUDED(tlspacket->flags) &&
	    (tlspacket->length < 5)) { /* flags + TLS message length */
		RDEBUG("Invalid EAP-TLS packet received.  (Length bit is set, but no length was found.)");
		eaptls_free(&tlspacket);
		return NULL;
	}

	/*
	 *	If the final TLS packet is larger than we can handle, die
	 *	now.
	 *
	 *	Likewise, if the EAP packet says N bytes, and the TLS
	 *	packet says there's fewer bytes, it's a problem.
	 *
	 *	FIXME: Try to ensure that the claimed length is
	 *	consistent across multiple TLS fragments.
	 */
	if (TLS_LENGTH_INCLUDED(tlspacket->flags)) {
		memcpy(&data_len, &eap_ds->response->type.data[1], 4);
		data_len = ntohl(data_len);
		if (data_len > MAX_RECORD_SIZE) {
			RDEBUG("The EAP-TLS packet will contain more data than we can process.");
			eaptls_free(&tlspacket);
			return NULL;
		}

#if 0
		DEBUG2(" TLS: %d %d\n", data_len, tlspacket->length);

		if (data_len < tlspacket->length) {
			RDEBUG("EAP-TLS packet claims to be smaller than the encapsulating EAP packet.");
			eaptls_free(&tlspacket);
			return NULL;
		}
#endif
	}

	switch (status) {
	/*
	 *	The TLS Message Length field is four octets, and
	 *	provides the total length of the TLS message or set of
	 *	messages that is being fragmented; this simplifies
	 *	buffer allocation.
	 *
	 *	Dynamic allocation of buffers as & when we know the
	 *	length should solve the problem.
	 */
	case FR_TLS_FIRST_FRAGMENT:
	case FR_TLS_LENGTH_INCLUDED:
	case FR_TLS_MORE_FRAGMENTS_WITH_LENGTH:
		if (tlspacket->length < 5) { /* flags + TLS message length */
			RDEBUG("Invalid EAP-TLS packet received.  (Expected length, got none.)");
			eaptls_free(&tlspacket);
			return NULL;
		}

		/*
		 *	Extract all the TLS fragments from the
		 *	previous eap_ds Start appending this
		 *	fragment to the above ds
		 */
		memcpy(&data_len, &eap_ds->response->type.data[1], sizeof(uint32_t));
		data_len = ntohl(data_len);
		data = (eap_ds->response->type.data + 5/*flags+TLS-Length*/);
		len = eap_ds->response->type.length - 5/*flags+TLS-Length*/;

		/*
		 *	Hmm... this should be an error, too.
		 */
		if (data_len > len) {
			data_len = len;
		}
		break;

		/*
		 *	Data length is implicit, from the EAP header.
		 */
	case FR_TLS_MORE_FRAGMENTS:
	case FR_TLS_OK:
		data_len = eap_ds->response->type.length - 1/*flags*/;
		data = eap_ds->response->type.data + 1/*flags*/;
		break;

	default:
		RDEBUG("Invalid EAP-TLS packet received");
		eaptls_free(&tlspacket);
		return NULL;
	}

	tlspacket->dlen = data_len;
	if (data_len) {
		tlspacket->data = (unsigned char *)malloc(data_len);
		if (tlspacket->data == NULL) {
			RDEBUG("out of memory");
			eaptls_free(&tlspacket);
			return NULL;
		}
		memcpy(tlspacket->data, data, data_len);
	}

	return tlspacket;
}



/*
 * To process the TLS,
 *  INCOMING DATA:
 * 	1. EAP-TLS should get the compelete TLS data from the peer.
 * 	2. Store that data in a data structure with any other required info
 *	3. Handle that data structure to the TLS module.
 *	4. TLS module will perform its operations on the data and
 *	handle back to EAP-TLS
 *
 *  OUTGOING DATA:
 * 	1. EAP-TLS if necessary will fragment it and send it to the
 * 	destination.
 *
 *	During EAP-TLS initialization, TLS Context object will be
 *	initialized and stored.  For every new authentication
 *	requests, TLS will open a new session object and that session
 *	object should be maintained even after the session is
 *	completed for session resumption. (Probably later as a feature
 *	as we donot know who maintains these session objects ie,
 *	SSL_CTX (internally) or TLS module(explicitly). If TLS module,
 *	then how to let SSL API know about these sessions.)
 */
static fr_tls_status_t eaptls_operation(fr_tls_status_t status,
					EAP_HANDLER *handler)
{
	tls_session_t *tls_session;

	tls_session = (tls_session_t *)handler->opaque;

	if ((status == FR_TLS_MORE_FRAGMENTS) ||
	    (status == FR_TLS_MORE_FRAGMENTS_WITH_LENGTH) ||
	    (status == FR_TLS_FIRST_FRAGMENT)) {
		/*
		 *	Send the ACK.
		 */
		eaptls_send_ack(handler->eap_ds, tls_session->peap_flag);
		return FR_TLS_HANDLED;

	}

	/*
	 *	We have the complete TLS-data or TLS-message.
	 *
	 *	Clean the dirty message.
	 *
	 *	Authenticate the user and send
	 *	Success/Failure.
	 *
	 *	If more info
	 *	is required then send another request.
	 */
	if (!tls_handshake_recv(handler->request, tls_session)) {
		DEBUG2("TLS receive handshake failed during operation");
		eaptls_fail(handler, tls_session->peap_flag);
		return FR_TLS_FAIL;
	}

	/*
	 *	FIXME: return success/fail.
	 *
	 *	TLS proper can decide what to do, then.
	 */
	if (tls_session->dirty_out.used > 0) {
		eaptls_request(handler->eap_ds, tls_session);
		return FR_TLS_HANDLED;
	}
		
	/* 
	 *	If there is no data to send i.e
	 *	dirty_out.used <=0 and if the SSL
	 *	handshake is finished, then return a
	 *	EPTLS_SUCCESS
	 */
	
	if (SSL_is_init_finished(tls_session->ssl)) {
		/*
		 *	Init is finished.  The rest is
		 *	application data.
		 */
		tls_session->info.content_type = application_data; 
		return FR_TLS_SUCCESS;
	}
	
	/*
	 *	Who knows what happened...
	 */
	DEBUG2("TLS failed during operation");
	return FR_TLS_FAIL;
}


/*
 * In the actual authentication first verify the packet and then create the data structure
 */
/*
 * To process the TLS,
 *  INCOMING DATA:
 * 	1. EAP-TLS should get the compelete TLS data from the peer.
 * 	2. Store that data in a data structure with any other required info
 *	3. Hand this data structure to the TLS module.
 *	4. TLS module will perform its operations on the data and hands back to EAP-TLS
 *  OUTGOING DATA:
 * 	1. EAP-TLS if necessary will fragment it and send it to the destination.
 *
 *	During EAP-TLS initialization, TLS Context object will be
 *	initialized and stored.  For every new authentication
 *	requests, TLS will open a new session object and that
 *	session object SHOULD be maintained even after the session
 *	is completed, for session resumption. (Probably later as a
 *	feature, as we do not know who maintains these session
 *	objects ie, SSL_CTX (internally) or TLS module (explicitly). If
 *	TLS module, then how to let SSL API know about these
 *	sessions.)
 */

/*
 *	Process an EAP request
 */
fr_tls_status_t eaptls_process(EAP_HANDLER *handler)
{
	tls_session_t *tls_session = (tls_session_t *) handler->opaque;
	EAPTLS_PACKET	*tlspacket;
	fr_tls_status_t	status;
	REQUEST *request = handler->request;

	if (!request) return FR_TLS_FAIL;

	RDEBUG2("processing EAP-TLS");
	SSL_set_ex_data(tls_session->ssl, FR_TLS_EX_INDEX_REQUEST, request);

	if (handler->certs) pairadd(&request->packet->vps,
				    paircopy(handler->certs));

	/* This case is when SSL generates Alert then we
	 * send that alert to the client and then send the EAP-Failure
	 */
	status = eaptls_verify(handler);
	RDEBUG2("eaptls_verify returned %d\n", status);

	switch (status) {
	default:
	case FR_TLS_INVALID:
	case FR_TLS_FAIL:

		/*
		 *	Success means that we're done the initial
		 *	handshake.  For TTLS, this means send stuff
		 *	back to the client, and the client sends us
		 *	more tunneled data.
		 */
	case FR_TLS_SUCCESS:
		goto done;

		/*
		 *	Normal TLS request, continue with the "get rest
		 *	of fragments" phase.
		 */
	case FR_TLS_REQUEST:
		eaptls_request(handler->eap_ds, tls_session);
		status = FR_TLS_HANDLED;
		goto done;

		/*
		 *	The handshake is done, and we're in the "tunnel
		 *	data" phase.
		 */
	case FR_TLS_OK:
		RDEBUG2("Done initial handshake");

		/*
		 *	Get the rest of the fragments.
		 */
	case FR_TLS_FIRST_FRAGMENT:
	case FR_TLS_MORE_FRAGMENTS:
	case FR_TLS_LENGTH_INCLUDED:
	case FR_TLS_MORE_FRAGMENTS_WITH_LENGTH:
		break;
	}

	/*
	 *	Extract the TLS packet from the buffer.
	 */
	if ((tlspacket = eaptls_extract(request, handler->eap_ds, status)) == NULL) {
		status = FR_TLS_FAIL;
		goto done;
	}

	/*
	 *	Get the session struct from the handler
	 *
	 *	update the dirty_in buffer
	 *
	 *	NOTE: This buffer will contain partial data when M bit is set.
	 *
	 * 	CAUTION while reinitializing this buffer, it should be
	 * 	reinitialized only when this M bit is NOT set.
	 */
	if (tlspacket->dlen !=
	    (tls_session->record_plus)(&tls_session->dirty_in, tlspacket->data, tlspacket->dlen)) {
		eaptls_free(&tlspacket);
		RDEBUG("Exceeded maximum record size");
		status =FR_TLS_FAIL;
		goto done;
	}

	/*
	 *	No longer needed.
	 */
	eaptls_free(&tlspacket);

	/*
	 *	SSL initalization is done.  Return.
	 *
	 *	The TLS data will be in the tls_session structure.
	 */
	if (SSL_is_init_finished(tls_session->ssl)) {
		int err;

		/*
		 *	The initialization may be finished, but if
		 *	there more fragments coming, then send ACK,
		 *	and get the caller to continue the
		 *	conversation.
		 */	
	        if ((status == FR_TLS_MORE_FRAGMENTS) ||
        	    (status == FR_TLS_MORE_FRAGMENTS_WITH_LENGTH) ||
            	    (status == FR_TLS_FIRST_FRAGMENT)) {
			/*
			 *	Send the ACK.
			 */
			eaptls_send_ack(handler->eap_ds,
					tls_session->peap_flag);
			RDEBUG2("Init is done, but tunneled data is fragmented");
			status = FR_TLS_HANDLED;
			goto done;
		}

		/*	
		 *	Decrypt the complete record.
		 */
		BIO_write(tls_session->into_ssl, tls_session->dirty_in.data,
			  tls_session->dirty_in.used);

		/*
		 *      Clear the dirty buffer now that we are done with it
		 *      and init the clean_out buffer to store decrypted data
		 */
		(tls_session->record_init)(&tls_session->dirty_in);
		(tls_session->record_init)(&tls_session->clean_out);

		/*
		 *      Read (and decrypt) the tunneled data from the
		 *      SSL session, and put it into the decrypted
		 *      data buffer.
		 */
		err = SSL_read(tls_session->ssl, tls_session->clean_out.data,
			       sizeof(tls_session->clean_out.data));

		if (err < 0) {
			RDEBUG("SSL_read Error");

			switch (SSL_get_error(tls_session->ssl, err)) {
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
				RDEBUG("Error in fragmentation logic");
				break;
			default:
				/*
				 *	FIXME: Call int_ssl_check?
				 */
				break;
			}
			status = FR_TLS_FAIL;
			goto done;
		}

		if (err == 0) {
			RDEBUG("WARNING: No data inside of the tunnel.");
		}
	
		/*
		 *	Passed all checks, successfully decrypted data
		 */
		tls_session->clean_out.used = err;
		
		status = FR_TLS_OK;
		goto done;
	}

	/*
	 *	Continue the handshake.
	 */
	status = eaptls_operation(status, handler);

 done:
	SSL_set_ex_data(tls_session->ssl, FR_TLS_EX_INDEX_REQUEST, NULL);

	return status;
}


/*
 *	compose the TLS reply packet in the EAP reply typedata
 */
int eaptls_compose(EAP_DS *eap_ds, EAPTLS_PACKET *reply)
{
	uint8_t *ptr;

	/*
	 *	Don't set eap_ds->request->type.type, as the main EAP
	 *	handler will do that for us.  This allows the TLS
	 *	module to be called from TTLS & PEAP.
	 */

	/*
	 * 	When the EAP server receives an EAP-Response with the
	 * 	M bit set, it MUST respond with an EAP-Request with
	 * 	EAP-Type=EAP-TLS and no data. This serves as a
	 * 	fragment ACK. The EAP peer MUST wait until it receives
	 * 	the EAP-Request before sending another fragment.
	 *
	 *	In order to prevent errors in the processing of
	 *	fragments, the EAP server MUST use increment the
	 *	Identifier value for each fragment ACK contained
	 *	within an EAP-Request, and the peer MUST include this
	 *	Identifier value in the subsequent fragment contained
	 *	within an EAP- Reponse.
	 */
	eap_ds->request->type.data = malloc(reply->length - TLS_HEADER_LEN + 1);
	if (eap_ds->request->type.data == NULL) {
		radlog(L_ERR, "out of memory");
		return 0;
	}

	/* EAPTLS Header length is excluded while computing EAP typelen */
	eap_ds->request->type.length = reply->length - TLS_HEADER_LEN;

	ptr = eap_ds->request->type.data;
	*ptr++ = (uint8_t)(reply->flags & 0xFF);

	if (reply->dlen) memcpy(ptr, reply->data, reply->dlen);

	switch (reply->code) {
	case FR_TLS_ACK:
	case FR_TLS_START:
	case FR_TLS_REQUEST:
		eap_ds->request->code = PW_EAP_REQUEST;
		break;
	case FR_TLS_SUCCESS:
		eap_ds->request->code = PW_EAP_SUCCESS;
		break;
	case FR_TLS_FAIL:
		eap_ds->request->code = PW_EAP_FAILURE;
		break;
	default:
		/* Should never enter here */
		eap_ds->request->code = PW_EAP_FAILURE;
		break;
	}

	return 1;
}
