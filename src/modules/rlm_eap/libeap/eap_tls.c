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
 * 0		   1		   2		   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Code      |   Identifier  |	    Length	     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |     Flags     |      TLS Message Length
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     TLS Message Length	|       TLS Data...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#include <assert.h>

#include "eap_tls.h"
/*
 *	Send an initial eap-tls request to the peer.
 *
 *	Frame eap reply packet.
 *	len = header + type + tls_typedata
 *	tls_typedata = flags(Start (S) bit set, and no data)
 *
 *	Once having received the peer's Identity, the EAP server MUST
 *	respond with an EAP-TLS/Start packet, which is an
 *	EAP-Request packet with EAP-Type=EAP-TLS, the Start (S) bit
 *	set, and no data.  The EAP-TLS conversation will then begin,
 *	with the peer sending an EAP-Response packet with
 *	EAP-Type = EAP-TLS.  The data field of that packet will
 *	be the TLS data.
 *
 *	Fragment length is Framed-MTU - 4.
 */
tls_session_t *eaptls_session(eap_handler_t *handler, fr_tls_server_conf_t *tls_conf, bool client_cert)
{
	tls_session_t	*ssn;
	REQUEST		*request = handler->request;

	handler->tls = true;

	/*
	 *	Every new session is started only from EAP-TLS-START.
	 *	Before Sending EAP-TLS-START, open a new SSL session.
	 *	Create all the required data structures & store them
	 *	in Opaque.  So that we can use these data structures
	 *	when we get the response
	 */
	ssn = tls_new_session(handler, tls_conf, request, client_cert);
	if (!ssn) return NULL;

	/*
	 *	Create a structure for all the items required to be
	 *	verified for each client and set that as opaque data
	 *	structure.
	 *
	 *	NOTE: If we want to set each item sepearately then
	 *	this index should be global.
	 */
	SSL_set_ex_data(ssn->ssl, FR_TLS_EX_INDEX_HANDLER, (void *)handler);
	SSL_set_ex_data(ssn->ssl, FR_TLS_EX_INDEX_CONF, (void *)tls_conf);
	SSL_set_ex_data(ssn->ssl, FR_TLS_EX_INDEX_IDENTITY, (void *)&(handler->identity));
#ifdef HAVE_OPENSSL_OCSP_H
	SSL_set_ex_data(ssn->ssl, FR_TLS_EX_INDEX_STORE, (void *)tls_conf->ocsp_store);
#endif
	SSL_set_ex_data(ssn->ssl, FR_TLS_EX_INDEX_SSN, (void *)ssn);

	return talloc_steal(handler, ssn); /* ssn */
}

/*
   The S flag is set only within the EAP-TLS start message
   sent from the EAP server to the peer.
*/
int eaptls_start(EAP_DS *eap_ds, int peap_flag)
{
	eap_tls_packet_t 	reply;

	reply.code = FR_TLS_START;
	reply.length = TLS_HEADER_LEN + 1/*flags*/;

	reply.flags = peap_flag;
	reply.flags = SET_START(reply.flags);

	reply.data = NULL;
	reply.dlen = 0;

	eaptls_compose(eap_ds, &reply);

	return 1;
}

int eaptls_success(eap_handler_t *handler, int peap_flag)
{
	eap_tls_packet_t	reply;
	REQUEST *request = handler->request;
	tls_session_t *tls_session = handler->opaque;

	handler->finished = true;
	reply.code = FR_TLS_SUCCESS;
	reply.length = TLS_HEADER_LEN;
	reply.flags = peap_flag;
	reply.data = NULL;
	reply.dlen = 0;

	tls_success(tls_session, request);

	/*
	 *	Call compose AFTER checking for cached data.
	 */
	eaptls_compose(handler->eap_ds, &reply);

	/*
	 *	Automatically generate MPPE keying material.
	 */
	if (tls_session->prf_label) {
		eaptls_gen_mppe_keys(handler->request,
				     tls_session->ssl, tls_session->prf_label);
	} else {
		RWDEBUG("Not adding MPPE keys because there is no PRF label");
	}

	eaptls_gen_eap_key(handler->request->reply, tls_session->ssl,
			   handler->type);
	return 1;
}

int eaptls_fail(eap_handler_t *handler, int peap_flag)
{
	eap_tls_packet_t	reply;
	tls_session_t *tls_session = handler->opaque;

	handler->finished = true;
	reply.code = FR_TLS_FAIL;
	reply.length = TLS_HEADER_LEN;
	reply.flags = peap_flag;
	reply.data = NULL;
	reply.dlen = 0;

	tls_fail(tls_session);

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
	eap_tls_packet_t	reply;
	unsigned int	size;
	unsigned int 	nlen;
	unsigned int 	lbit = 0;

	/* This value determines whether we set (L)ength flag for
		EVERY packet we send and add corresponding
		"TLS Message Length" field.

	length_flag = true;
		This means we include L flag and "TLS Msg Len" in EVERY
		packet we send out.

	length_flag = false;
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
	if (ssn->dirty_out.used > ssn->mtu) {
		size = ssn->mtu;
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

	reply.data = talloc_array(eap_ds, uint8_t, reply.length);
	if (!reply.data) return 0;

	if (lbit) {
		nlen = htonl(ssn->tls_msg_len);
		memcpy(reply.data, &nlen, lbit);
		reply.flags = SET_LENGTH_INCLUDED(reply.flags);
	}
	(ssn->record_minus)(&ssn->dirty_out, reply.data + lbit, size);

	eaptls_compose(eap_ds, &reply);
	talloc_free(reply.data);
	reply.data = NULL;

	return 1;
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
static int eaptls_send_ack(eap_handler_t *handler, int peap_flag)
{
	eap_tls_packet_t 	reply;
	REQUEST		*request = handler->request;

	RDEBUG2("ACKing Peer's TLS record fragment");
	reply.code = FR_TLS_ACK;
	reply.length = TLS_HEADER_LEN + 1/*flags*/;
	reply.flags = peap_flag;
	reply.data = NULL;
	reply.dlen = 0;

	eaptls_compose(handler->eap_ds, &reply);

	return 1;
}

/** Check that this eaptls_packet and the progression of eaptls packets is sane
 *
 * @note In the received packet, No data will be present incase of ACK or NAK
 *	in this case the packet->data pointer will be NULL.
 *
 *  RFC 2716 Section 4.2.  PPP EAP TLS Request Packet
 @verbatim
    0		   1		   2		   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Code      |   Identifier  |	    Length	     |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |     Flags     |      TLS Message Length
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     TLS Message Length	|       TLS Data...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 @endverbatim
 *
 *  Structure of an EAP-TLS packet
 *
 @verbatim
   code    = EAP-code
   id      = EAP-id
   length  = code + id + length + flags + tlsdata
  	   =  1   +  1 +   2    +  1    +  X
   length  = EAP-length - 1(EAP-Type = 1 octet)
   flags   = EAP-typedata[0] (1 octet)
   dlen    = EAP-typedata[1-4] (4 octets), if L flag set
  	   = length - 5(code+id+length+flags), otherwise
   data    = EAP-typedata[5-n], if L flag set
  	   = EAP-typedata[1-n], otherwise
   packet  = EAP-typedata (complete typedata)
 @endverbatim
 *
 * The S flag is set only within the EAP-TLS start message sent from the EAP
 * server to the peer.
 *
 * Similarly, when the EAP server receives an EAP-Response with the M bit set,
 * it MUST respond with an EAP-Request with EAP-Type=EAP-TLS and no data.
 * This serves as a fragment ACK. The EAP peer MUST wait.
 *
 * The Length field is two octets and indicates the length of the EAP
 * packet including the Code, Identifier, Length, Type, and TLS data
 * fields.
 *
 * The TLS Message Length field is four octets and indicates the
 * complete reassembled length of the TLS record fragment.
 *
 * @param[in] handler the current EAP session state.
 * @return
 *	- FR_TLS_INVALID if the TLS record or progression is invalid.
 *	- FR_TLS_FAIL handshake failed.
 *	- FR_TLS_RECORD_FRAGMENT_INIT this is the start of a new sequence of record fragments.
 *	- FR_TLS_RECORD_FRAGMENT_MORE this is a continuation of a sequence of fragments.
 *	- FR_TLS_REQUEST send more data to peer.
 *	- FR_TLS_RECORD_COMPLETE we received a completed record.
 *	- FR_TLS_SUCCESS handshake is complete, TLS session has been established.
 */
static fr_tls_status_t eaptls_verify(eap_handler_t *handler)
{
	EAP_DS			*eap_ds = handler->eap_ds;
	tls_session_t		*tls_session = handler->opaque;
	EAP_DS			*prev_eap_ds = handler->prev_eap_ds;
	eap_tls_data_t		*eap_tls_data;
	REQUEST			*request = handler->request;
	size_t			frag_len, header_len;

	/*
	 *	All EAP-TLS packets must contain type and flags fields.
	 */
	if (eap_ds->response->length < (EAP_HEADER_LEN + 2)) {
		REDEBUG("Invalid EAP-TLS packet: Expected at least %zu bytes got %zu bytes",
			(size_t)EAP_HEADER_LEN + 2, eap_ds->response->length);
		return FR_TLS_INVALID;
	}

	/*
	 *	We don't check ANY of the input parameters.  It's all
	 *	code which works together, so if something is wrong,
	 *	we SHOULD core dump.
	 *
	 *	e.g. if eap_ds is NULL, of if eap_ds->response is
	 *	NULL, of if it's NOT an EAP-Response, or if the packet
	 *	is too short.  See eap_validation()., in ../../eap.c
	 */
	eap_tls_data = (eap_tls_data_t *)eap_ds->response->type.data;

	/*
	 *	First output the flags (for debugging)
	 */
	RDEBUG3("Peer sent flags %c%c%c",
		TLS_START(eap_tls_data->flags) ? 'S' : '-',
		TLS_MORE_FRAGMENTS(eap_tls_data->flags) ? 'M' : '-',
		TLS_LENGTH_INCLUDED(eap_tls_data->flags) ? 'L' : '-');

	/*
	 *	This length includes the type and flags field and
	 *	the message length field if the flags indicate it's present.
	 */
	header_len = EAP_HEADER_LEN + (TLS_LENGTH_INCLUDED(eap_tls_data->flags) ? 6 : 2);
	if (eap_ds->response->length < header_len) {
		REDEBUG("Invalid EAP-TLS packet: Expected at least %zu bytes got %zu bytes",
			header_len, eap_ds->response->length);
		return FR_TLS_INVALID;
	}

	/*
	 *	check for ACK
	 *
	 *	If there's no TLS data, or there's 1 byte of TLS data,
	 *	with the flags set to zero, then it's an ACK.
	 *
	 *	Find if this is a reply to the previous request sent
	 */
	if ((!eap_tls_data) ||
	    ((eap_ds->response->length == EAP_HEADER_LEN + 2) &&
	     ((eap_tls_data->flags & 0xc0) == 0x00))) {
		if (!prev_eap_ds || (prev_eap_ds->request->id != eap_ds->response->id)) {
			REDEBUG("Received Invalid TLS ACK");
			return FR_TLS_INVALID;
		}
		return tls_ack_handler(handler->opaque, request);
	}

	/*
	 *	We send TLS_START, but do not receive it.
	 */
	if (TLS_START(eap_tls_data->flags)) {
		REDEBUG("Peer sent EAP-TLS Start message (only the server is allowed to do this)");
		return FR_TLS_INVALID;
	}

	/*
	 *	Calculate this fragment's length
	 */
	frag_len = eap_ds->response->length - header_len;

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
	if (TLS_LENGTH_INCLUDED(eap_tls_data->flags)) {
		size_t total_len;

		total_len = eap_tls_data->data[2] * 256 | eap_tls_data->data[3];
		if (frag_len > total_len) {
			REDEBUG("TLS fragment length (%zu bytes) greater than TLS record length (%zu bytes)",
				frag_len, total_len);
			return FR_TLS_INVALID;
		}

		if (total_len > MAX_RECORD_SIZE) {
			REDEBUG("Reassembled TLS record will be %zu bytes, "
				"greater than our maximum record size (" STRINGIFY(MAX_RECORD_SIZE) " bytes)",
				total_len);
			return FR_TLS_INVALID;
		}

		/*
		 *	wpa_supplicant's implementation of PEAPv0, and likely other
		 *	implementations of PEAPv0 will always include a Length flag
		 *	for every record fragment if performing mutual TLS auth.
		 *
		 *	If the handler says this is not the first fragment, then
		 *	don't count this as a new record, and continue as if we
		 *	hadn't seen the length flag.
		 */
		if (tls_session->tls_record_transfer_started) goto ignore_length;

		/*
		 *	This is the first fragment of a fragmented TLS record transfer.
		 */
		RDEBUG2("Peer indicated complete TLS record size will be %zu bytes", total_len);
		if (TLS_MORE_FRAGMENTS(eap_tls_data->flags)) {
			/*
			 *	The supplicant is free to send fragments of wildly varying
			 *	lengths, but the vast majority won't.
			 *
			 *	In this calculation we take into account the fact that the future
			 *	fragments are likely to be 4 bytes larger than the initial one
			 *	as they won't contain the length field.
			 */
			if (frag_len + 4) {	/* check for wrap, else clang scan gets excited */
				RDEBUG2("Expecting %i TLS record fragments",
					(int)((((total_len - frag_len) + ((frag_len + 4) - 1)) / (frag_len + 4)) + 1));
			}

			/*
			 *	First fragment. tls_record_transfer_started bool was false,
			 *	and we received a length included + more fragments packet.
			 */
			RDEBUG2("Got first TLS record fragment (%zu bytes).  Peer indicated more fragments "
				"to follow", frag_len);
			tls_session->tls_record_in_total_len = total_len;
			tls_session->tls_record_in_recvd_len = frag_len;
			tls_session->tls_record_transfer_started = true;

			return FR_TLS_RECORD_FRAGMENT_INIT;
		}

		/*
		 *	Else this is the complete TLS record.
		 */
		if (total_len != frag_len) {
			REDEBUG("Peer indicated no more fragments, but TLS record length (%zu bytes) "
				"does not match EAP-TLS data length (%zu bytes)", total_len, frag_len);
			return FR_TLS_INVALID;
		}

		/*
		 *	RFC5216 doesn't specify explicitly whether a non-fragmented
		 *	packet should include the length or not.
		 *
		 *	We support both options for maximum compatibility.
		 */
		RDEBUG2("Got complete TLS record, with length (%zu bytes)", frag_len);
		return FR_TLS_RECORD_COMPLETE;
	}

ignore_length:
	if (TLS_MORE_FRAGMENTS(eap_tls_data->flags)) {
		/*
		 *	If this is not an ongoing transfer, and we have the M flag
		 *	then this record transfer is invalid.
		 */
		if (!tls_session->tls_record_transfer_started) {
			REDEBUG("TLS More (M) flag set, but no fragmented record transfer was in progress");
			return FR_TLS_INVALID;
		}

		/*
		 *	If this is an ongoing transfer, and we have the M flag,
		 *	then this is just an additional fragment.
		 */
		RDEBUG2("Got additional TLS record fragment (%zu bytes).  Peer indicated more fragments to follow",
			frag_len);
		tls_session->tls_record_in_recvd_len += frag_len;
		if (tls_session->tls_record_in_recvd_len > tls_session->tls_record_in_total_len) {
			REDEBUG("Total received TLS record fragments (%zu bytes), exceeds "
				"indicated TLS record length (%zu bytes)",
				tls_session->tls_record_in_recvd_len, tls_session->tls_record_in_total_len);
			return FR_TLS_INVALID;
		}
		return FR_TLS_RECORD_FRAGMENT_MORE;
	}

	/*
	 *	No L flag and no M flag. This is either the final fragment,
	 *	or a new transfer that was not started with a L flag, which
	 *	RFC5216 hints, may be acceptable.
	 *
	 *	If it's an in-progress record transfer, check we now have
	 *	the complete record.
	 */
	if (tls_session->tls_record_transfer_started) {
		tls_session->tls_record_transfer_started = false;

		RDEBUG2("Got final TLS record fragment (%zu bytes)", frag_len);
		tls_session->tls_record_in_recvd_len += frag_len;
		if (tls_session->tls_record_in_recvd_len != tls_session->tls_record_in_total_len) {
			REDEBUG("Total received TLS record fragments (%zu bytes), does not equal indicated "
				"TLS record length (%zu bytes)",
				tls_session->tls_record_in_recvd_len, tls_session->tls_record_in_total_len);
			return FR_TLS_INVALID;
		}
		return FR_TLS_RECORD_COMPLETE;
	}

	/*
	 *	None of the flags are set, it wasn't an in progress transfer,
	 *	but it's still a valid EAP-TLS packet.
	 */
	RDEBUG2("Got complete TLS record (%zu bytes)", frag_len);

	return FR_TLS_RECORD_COMPLETE;
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
static fr_tls_status_t eaptls_operation(fr_tls_status_t status, eap_handler_t *handler)
{
	REQUEST		*request = handler->request;
	tls_session_t	*tls_session = handler->opaque;

	if ((status == FR_TLS_RECORD_FRAGMENT_MORE) ||
	    (status == FR_TLS_RECORD_FRAGMENT_INIT)) {
		/*
		 *	Send the ACK.
		 */
		eaptls_send_ack(handler, tls_session->peap_flag);
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
		REDEBUG("TLS receive handshake failed during operation");
		tls_fail(tls_session);
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
	REDEBUG("TLS failed during operation");
	return FR_TLS_FAIL;
}

/** Process EAP TLS request
 *
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
fr_tls_status_t eaptls_process(eap_handler_t *handler)
{
	tls_session_t		*tls_session = (tls_session_t *) handler->opaque;
	EAP_DS			*eap_ds = handler->eap_ds;
	fr_tls_status_t		status;
	REQUEST			*request = handler->request;

	eap_tls_data_t		*eap_tls_data;
	uint8_t			*data;
	size_t			data_len;

	if (!request) return FR_TLS_FAIL;

	RDEBUG2("Continuing EAP-TLS");

	SSL_set_ex_data(tls_session->ssl, FR_TLS_EX_INDEX_REQUEST, request);

	if (handler->cert_vps) fr_pair_add(&request->packet->vps,
				    fr_pair_list_copy(request->packet, handler->cert_vps));

	/*
	 *	eaptls_verify sanity checks the incoming EAP data.
	 */
	status = eaptls_verify(handler);
	switch (status) {
	case FR_TLS_INVALID:
	case FR_TLS_FAIL:
		REDEBUG("[eaptls verify] = %s", fr_int2str(fr_tls_status_table, status, "<INVALID>"));
		break;

	default:
		RDEBUG2("[eaptls verify] = %s", fr_int2str(fr_tls_status_table, status, "<INVALID>"));
		break;
	}

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
	 *	We've received a complete TLS record
	 */
	case FR_TLS_RECORD_COMPLETE:
		RDEBUG2("Done initial handshake");

	/*
	 *	We've received a fragment of a TLS record
	 */
	case FR_TLS_RECORD_FRAGMENT_INIT:
	case FR_TLS_RECORD_FRAGMENT_MORE:
		break;
	}

	/*
	 *	Determine where the TLS record starts.
	 *
	 *	If the length included flag is set, we need
	 *	to skip over the 4 bytes message length field.
	 */
 	eap_tls_data = (eap_tls_data_t *)eap_ds->response->type.data;
	if (TLS_LENGTH_INCLUDED(eap_tls_data->flags)) {
		data = (eap_ds->response->type.data + 5);	/* flags + TLS-Length */
		data_len = eap_ds->response->type.length - 5;	/* flags + TLS-Length */
	} else {
		data = eap_ds->response->type.data + 1;		/* flags */
		data_len = eap_ds->response->type.length - 1;	/* flags */
	}

	/*
	 *	Update the dirty_in buffer (data for reading by OpenSSL)
	 *
	 *	This buffer will contain partial data when M bit is set, and should
	 * 	should only be reinitialized when M but is not set.
	 */
	if ((tls_session->record_plus)(&tls_session->dirty_in, data, data_len) != data_len) {
		REDEBUG("Exceeded maximum record size");
		status = FR_TLS_FAIL;
		goto done;
	}

	/*
	 *	SSL initalization is done.  Return.
	 *
	 *	The TLS data will be in the tls_session structure.
	 */
	if (SSL_is_init_finished(tls_session->ssl)) switch (status) {

	/*
	 *	The initialization may be finished, but if
	 *	there more fragments coming, then send ACK,
	 *	and get the caller to continue the conversation.
	 */
	case FR_TLS_RECORD_FRAGMENT_MORE:
	case FR_TLS_RECORD_FRAGMENT_INIT:
		eaptls_send_ack(handler, tls_session->peap_flag);
		RDEBUG2("Init is done, but tunneled data is fragmented");
		status = FR_TLS_HANDLED;
		goto done;

	default:
		status = tls_application_data(tls_session, request);
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
int eaptls_compose(EAP_DS *eap_ds, eap_tls_packet_t *reply)
{
	uint8_t *ptr;

	/*
	 *	Don't set eap_ds->request->type.num, as the main EAP
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
	eap_ds->request->type.data = talloc_array(eap_ds->request, uint8_t,
						  reply->length - TLS_HEADER_LEN + 1);
	if (!eap_ds->request->type.data) return 0;

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
		rad_assert(0);
		break;
	}

	return 1;
}

/*
 *	Parse TLS configuration
 *
 *	If the option given by 'attr' is set, we find the config section
 *	of that name and use that for the TLS configuration. If not, we
 *	fall back to compatibility mode and read the TLS options from
 *	the 'tls' section.
 */
fr_tls_server_conf_t *eaptls_conf_parse(CONF_SECTION *cs, char const *attr)
{
	char const 		*tls_conf_name;
	CONF_PAIR		*cp;
	CONF_SECTION		*parent;
	CONF_SECTION		*tls_cs;
	fr_tls_server_conf_t	*tls_conf;

	if (!cs)
		return NULL;

	rad_assert(attr != NULL);

	parent = cf_item_parent(cf_section_to_item(cs));

	cp = cf_pair_find(cs, attr);
	if (cp) {
		tls_conf_name = cf_pair_value(cp);

		tls_cs = cf_section_sub_find_name2(parent, TLS_CONFIG_SECTION, tls_conf_name);

		if (!tls_cs) {
			ERROR("Cannot find tls config \"%s\"", tls_conf_name);
			return NULL;
		}
	} else {
		/*
		 *	If we can't find the section given by the 'attr', we
		 *	fall-back to looking for the "tls" section, as in
		 *	previous versions.
		 *
		 *	We don't fall back if the 'attr' is specified, but we can't
		 *	find the section - that is just a config error.
		 */
		INFO("TLS section \"%s\" missing, trying to use legacy configuration", attr);
		tls_cs = cf_section_sub_find(parent, "tls");
	}

	if (!tls_cs)
		return NULL;

	tls_conf = tls_server_conf_parse(tls_cs);

	if (!tls_conf)
		return NULL;

	/*
	 *	The EAP RFC's say 1020, but we're less picky.
	 */
	if (tls_conf->fragment_size < 100) {
		ERROR("Configured fragment size is too small, must be >= 100");
		return NULL;
	}

	/*
	 *	The maximum size for a RADIUS packet is 4096,
	 *	minus the header (20), Message-Authenticator (18),
	 *	and State (18), etc. results in about 4000 bytes of data
	 *	that can be devoted *solely* to EAP.
	 */
	if (tls_conf->fragment_size > 4000) {
		ERROR("Configured fragment size is too large, must be <= 4000");
		return NULL;
	}

	/*
	 *	Account for the EAP header (4), and the EAP-TLS header
	 *	(6), as per Section 4.2 of RFC 2716.  What's left is
	 *	the maximum amount of data we read from a TLS buffer.
	 */
	tls_conf->fragment_size -= 10;

	return tls_conf;
}

