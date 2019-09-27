/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 * @file lib/eap/tls.c
 * @brief Implements the EAP part of EAP-TLS
 *
 * RFC 2716 Section 4.2.  PPP EAP TLS Request Packet
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
   data_len    = EAP-typedata[1-4] (4 octets), if L flag set
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
 * it MUST respond with an EAP-Request with EAP-Type = EAP-TLS and no data.
 * This serves as a fragment ACK. The EAP peer MUST wait.
 *
 * The Length field is two octets and indicates the length of the EAP
 * packet including the Code, Identifier, Length, Type, and TLS data
 * fields.
 *
 * The TLS Message Length field is four octets and indicates the
 * complete reassembled length of the TLS record fragment.
 *
 * @copyright 2001 hereUare Communications, Inc. (raghud@hereuare.com)
 * @copyright 2003 Alan DeKok (aland@freeradius.org)
 * @copyright 2006,2015 The FreeRADIUS server project
 * @copyright 2015 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */

RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#include "tls.h"
#include "attrs.h"

fr_table_num_ordered_t const eap_tls_status_table[] = {
	{ "invalid",			EAP_TLS_INVALID			},
	{ "established",		EAP_TLS_ESTABLISHED		},
	{ "fail",			EAP_TLS_FAIL			},
	{ "handled",			EAP_TLS_HANDLED			},

	{ "start",			EAP_TLS_START_SEND		},
	{ "request",			EAP_TLS_RECORD_SEND		},
	{ "ack",			EAP_TLS_ACK_SEND		},

	{ "first",			EAP_TLS_RECORD_RECV_FIRST	},
	{ "more",			EAP_TLS_RECORD_RECV_MORE	},
	{ "complete",			EAP_TLS_RECORD_RECV_COMPLETE	}
};
size_t eap_tls_status_table_len = NUM_ELEMENTS(eap_tls_status_table);

/** Convert the EAP-TLS reply packet into an EAP packet
 *
 * The EAP packet will be written to eap_round->request, with the original reply
 * being untouched.
 *
 * @param[in] request		The current subrequest.
 * @param[in] eap_session	to continue.
 * @param[in] status		What type of packet we're sending.
 * @param[in] flags		to set.  This is checked to determine if
 *				we need to include a length field.
 * @param[in] record 		The record buffer to read from.  This
 *				most only be set for EAP_TLS_RECORD_SEND packets.
 * @param[in] record_len 	the length of the record we're sending.
 * @param[in] frag_len		the length of the fragment we're sending.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int eap_tls_compose(REQUEST *request, eap_session_t *eap_session, eap_tls_status_t status, uint8_t flags,
		    tls_record_t *record, size_t record_len, size_t frag_len)
{
	eap_round_t		*eap_round = eap_session->this_round;
	eap_tls_session_t	*eap_tls_session = talloc_get_type_abort(eap_session->opaque, eap_tls_session_t);
	tls_session_t		*tls_session = eap_tls_session->tls_session;
	uint8_t			*p;
	size_t			len = 1;	/* Flags */

	rad_assert(request->parent);	/* must be a subrequest */

	/*
	 *	First output the flags (for debugging)
	 */
	RDEBUG3("Setting flags %c%c%c%c%c%c%c%c",
		TLS_START(flags) ? 'S' : '-',
		TLS_MORE_FRAGMENTS(flags) ? 'M' : '-',
		TLS_LENGTH_INCLUDED(flags) ? 'L' : '-',
		TLS_RESERVED0(flags) ? 'R' : '-',
		TLS_RESERVED1(flags) ? 'R' : '-',
		TLS_RESERVED2(flags) ? 'R' : '-',
		TLS_RESERVED3(flags) ? 'R' : '-',
		TLS_RESERVED4(flags) ? 'R' : '-');

	/*
	 *	Determine the length (sans header) of our EAP-TLS
	 *	packet.  The reason for not including the length is
	 *	that the fields are the same as normal EAP messages.
	 */
	switch (status) {
	case EAP_TLS_RECORD_SEND:
		if (TLS_LENGTH_INCLUDED(flags)) len += TLS_HEADER_LENGTH_FIELD_LEN;	/* TLS record length field */
		if (record) len += frag_len;
		break;

	case EAP_TLS_START_SEND:
		if (record_len != 0) len += frag_len;
		break;

	default:
		break;
	}

	/*
	 * 	When the EAP server receives an EAP-Response with the
	 * 	M bit set, it MUST respond with an EAP-Request with
	 * 	EAP-Type = EAP-TLS and no data. This serves as a
	 * 	fragment ACK. The EAP peer MUST wait until it receives
	 * 	the EAP-Request before sending another fragment.
	 *
	 *	In order to prevent errors in the processing of
	 *	fragments, the EAP server MUST use increment the
	 *	Identifier value for each fragment ACK contained
	 *	within an EAP-Request, and the peer MUST include this
	 *	Identifier value in the subsequent fragment contained
	 *	within an EAP-Reponse.
	 */
	eap_round->request->type.data = p = talloc_array(eap_round->request, uint8_t, len);
	if (!p) return -1;
	eap_round->request->type.length = len;

	*p++ = flags;

	if (TLS_LENGTH_INCLUDED(flags)) {
		uint32_t net_record_len;

		/*
		 *	If we need to add the length field,
		 *	convert the total record length to
		 *	network byte order and copy it in at the
		 *	start of the packet.
		 */
		net_record_len = htonl(record_len);
		memcpy(p, &net_record_len, sizeof(net_record_len));
		p += sizeof(net_record_len);
	}

	if (record) tls_session->record_to_buff(record, p, frag_len);

	switch (status) {
	case EAP_TLS_ACK_SEND:
	case EAP_TLS_START_SEND:
	case EAP_TLS_RECORD_SEND:
		eap_round->request->code = FR_EAP_CODE_REQUEST;
		break;

	case EAP_TLS_ESTABLISHED:
		eap_round->request->code = FR_EAP_CODE_SUCCESS;
		break;

	case EAP_TLS_FAIL:
		eap_round->request->code = FR_EAP_CODE_FAILURE;
		break;

	default:
		/* Should never enter here */
		rad_assert(0);
		break;
	}

	return 0;
}

/** Send an initial EAP-TLS request to the peer.
 *
 * Once having received the peer's Identity, the EAP server MUST respond with an
 * EAP-TLS/Start packet, which is an EAP-Request packet with EAP-Type = EAP-TLS,
 * the Start (S) bit set, and no data.
 *
 * The EAP-TLS conversation will then begin, with the peer sending an EAP-Response
 * packet with EAP-Type = EAP-TLS.  The data field of that packet will be the TLS data.
 *
 * The S flag is set only within the EAP-TLS start message sent from the EAP server to the peer.
 *
 * - len = header + type + tls_typedata
 * - tls_typedata = flags(Start (S) bit set, and no data)
 *
 * Fragment length is Framed-MTU - 4.
 *
 * @param[in] request			The current subrequest.
 * @param[in] eap_session		to initiate.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int eap_tls_start(REQUEST *request, eap_session_t *eap_session)
{
	eap_tls_session_t	*eap_tls_session = talloc_get_type_abort(eap_session->opaque, eap_tls_session_t);

	rad_assert(request->parent);	/* must be a subrequest */

	return eap_tls_compose(request, eap_session, EAP_TLS_START_SEND,
			       SET_START(eap_tls_session->base_flags), NULL, 0, 0);
}

/** Send an EAP-TLS success
 *
 * Composes an EAP-TLS-Success.  This is a message with code EAP_TLS_ESTABLISHED.
 * It contains no cryptographic material, and is not protected.
 *
 * We add the MPPE keys here.  These are used by the NAS.  The supplicant
 * will derive the same keys separately.
 *
 * @param[in] request			The current subrequest.
 * @param[in] eap_session		that completed successfully.
 * @param[in] keying_prf_label		PRF label to use for generating keying material.
 *					If NULL, no MPPE keys will be generated.
 * @param[in] keying_prf_label_len	Length of the keying PRF label.
 * @param[in] sessid_prf_label		PRF label to use when generating the session ID.
 *					If NULL, session ID will be based on client/server randoms.
 * @param[in] sessid_prf_label_len	Length of the session ID PRF label.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int eap_tls_success(REQUEST *request, eap_session_t *eap_session,
		    char const *keying_prf_label, size_t keying_prf_label_len,
		    char const *sessid_prf_label, size_t sessid_prf_label_len)
{
	eap_tls_session_t	*eap_tls_session = talloc_get_type_abort(eap_session->opaque, eap_tls_session_t);
	tls_session_t		*tls_session = eap_tls_session->tls_session;

	rad_assert(request->parent);	/* must be a subrequest */

	eap_session->finished = true;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	/*
	 *	Check session resumption is allowed, disabling it
	 *	if it's not.
	 */
	SSL_set_ex_data(tls_session->ssl, FR_TLS_EX_INDEX_REQUEST, request);
	tls_cache_disable_cb(tls_session->ssl, -1);
	SSL_set_ex_data(tls_session->ssl, FR_TLS_EX_INDEX_REQUEST, NULL);	//-V575
#endif

	/*
	 *	Write the session to the session cache
	 *
	 *	We do this here (instead of relying on OpenSSL to call the
	 *	session caching callback), because we only want to write
	 *	session data to the cache if all phases were successful.
	 *
	 *	If we wrote out the cache data earlier, and the server
	 *	exited whilst the session was in progress, the supplicant
	 *	could resume the session (and get access) even if phase2
	 *	never completed.
	 */
	tls_cache_write(request, tls_session);

	/*
	 *	Build the success packet
	 */
	if (eap_tls_compose(request, eap_session, EAP_TLS_ESTABLISHED,
			    eap_tls_session->base_flags, NULL, 0, 0) < 0) return -1;

	/*
	 *	Automatically generate MPPE keying material.
	 */
	if (keying_prf_label) if (eap_crypto_mppe_keys(request->parent, tls_session->ssl,
						       keying_prf_label, keying_prf_label_len) < 0) return -1;

	/*
	 *	Add the EAP session ID to the request
	 */
	{
		uint8_t		*session_id;
		VALUE_PAIR	*vp;

		if (eap_crypto_tls_session_id(request->parent->reply, request, tls_session->ssl,
					      &session_id, eap_session->type,
					      sessid_prf_label, sessid_prf_label_len) < 0) return -1;

		MEM(pair_add_reply(&vp, attr_eap_session_id) >= 0);
		fr_pair_value_memsteal(vp, session_id, true);

		RINDENT();
		RDEBUG2("&reply:%pP", vp);
		REXDENT();
	}

	return 0;
}

/** Send an EAP-TLS failure
 *
 * Composes an EAP-TLS-Failure.  This is a message with code EAP_TLS_FAILURE.
 * It contains no cryptographic material, and is not protected.
 *
 * In addition to sending the failure, will destroy any cached session data.
 *
 * @param[in] request		The current subrequest.
 * @param[in] eap_session	that failed.
 * @return
 *	- 0 on success.
 *	- -1 on failure (to compose a valid packet).
 */
int eap_tls_fail(REQUEST *request, eap_session_t *eap_session)
{
	eap_tls_session_t	*eap_tls_session = talloc_get_type_abort(eap_session->opaque, eap_tls_session_t);
	tls_session_t		*tls_session = eap_tls_session->tls_session;

	rad_assert(request->parent);	/* must be a subrequest */

	eap_session->finished = true;

	/*
	 *	Destroy any cached session data
	 */
	tls_cache_deny(tls_session);

	if (eap_tls_compose(request, eap_session, EAP_TLS_FAIL,
			    eap_tls_session->base_flags, NULL, 0, 0) < 0) return -1;
	return 0;
}

/** Frames the OpenSSL data that needs to be sent to the client in an EAP-Request
 *
 * A single TLS record may be up to 16384 octets in length, but a TLS message
 * may span multiple TLS records, and a TLS certificate message may theoretically,
 * be as big as 16MB.
 *
 * In EAP-TLS with no inner method, this is used primarily to send our certificate
 * chain to the peer.
 *
 * In other methods this function is also called to package up application data
 * for the inner tunnel method.
 *
 * The eap_tls_session->length_included flag determines whether we include the extra
 * four byte length field in the request and set the L flag.
 *
 * If present, the tls_length field indicates the total length of the reassembled
 * TLS record.
 *
 * If eap_tls_session->length_included this means we include L flag and the tls_length
 * field in EVERY packet we send out.
 *
 * If !eap_tls_session->length_included this means we include L flag and tls_length
 * field **ONLY** in First packet of a fragment series. We do not use it anywhere
 * else.
 *
 * @param request	the request
 * @param eap_session	that's continuing.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int eap_tls_request(REQUEST *request, eap_session_t *eap_session)
{
	eap_tls_session_t	*eap_tls_session = talloc_get_type_abort(eap_session->opaque, eap_tls_session_t);
	tls_session_t		*tls_session = eap_tls_session->tls_session;
	uint8_t			flags = eap_tls_session->base_flags;
	size_t			frag_len;
	bool			length_included;

	/*
	 *	We don't need to always include the length
	 *	(just in the first fragment) but it is
	 *	configurable for compatibility.
	 */
	length_included = eap_tls_session->include_length;

	/*
	 *	If this is the first fragment, record the complete
	 *	TLS record length.
	 */
	if (eap_tls_session->record_out_started  == false) {
		eap_tls_session->record_out_total_len = tls_session->dirty_out.used;
	}

	/*
	 *	If the data we're sending is greater than the MTU
	 *	then we need to fragment it.
	 */
	if ((tls_session->dirty_out.used +
	    (length_included ? TLS_HEADER_LENGTH_FIELD_LEN : 0)) > tls_session->mtu) {
		if (eap_tls_session->record_out_started == false) length_included = true;

		frag_len = length_included ? tls_session->mtu - TLS_HEADER_LENGTH_FIELD_LEN:
					     tls_session->mtu;

		flags = SET_MORE_FRAGMENTS(flags);

		/*
		 *	Length MUST be included if we're record_out_started
		 *	and this is the first fragment.
		 */
		if (eap_tls_session->record_out_started == false) {
			RDEBUG2("Complete TLS record (%zu bytes) larger than MTU (%zu bytes), will fragment",
				eap_tls_session->record_out_total_len, frag_len);	/* frag_len is correct here */
			RDEBUG2("Sending first TLS record fragment (%zu bytes), %zu bytes remaining",
				frag_len, tls_session->dirty_out.used - frag_len);
		} else {
			RDEBUG2("Sending additional TLS record fragment (%zu bytes), %zu bytes remaining",
				frag_len, tls_session->dirty_out.used - frag_len);
		}
		eap_tls_session->record_out_started  = true;	/* Start a new series of fragments */
	/*
	 *	Otherwise, we're either sending a record smaller
	 *	than the MTU or this is the final fragment.
	 */
	} else {
		frag_len = tls_session->dirty_out.used;	/* Remaining data to drain */

		if (eap_tls_session->record_out_started  == false) {
			RDEBUG2("Sending complete TLS record (%zu bytes)", frag_len);
		} else {
			RDEBUG2("Sending final TLS record fragment (%zu bytes)", frag_len);
		}
		eap_tls_session->record_out_started  = false;
	}

	/*
	 *	Update the flags to say we're including the
	 *	TLS record length.
	 */
	if (length_included) flags = SET_LENGTH_INCLUDED(flags);

	return eap_tls_compose(request, eap_session, EAP_TLS_RECORD_SEND, flags,
			       &tls_session->dirty_out, eap_tls_session->record_out_total_len, frag_len);
}

/** ACK a fragment of the TLS record from the peer
 *
 * EAP server sends an ACK when it determines there are More fragments to
 * receive to make the complete TLS-record.
 *
 * When the EAP server receives an EAP-Response with the M bit set, it MUST
 * respond with an EAP-Request with EAP-Type = EAP-TLS and no data. This serves
 * as a fragment ACK.
 *
 * In order to prevent errors in the processing of fragments, the EAP server
 * MUST use increment the Identifier value for each fragment ACK contained
 * within an EAP-Request, and the peer MUST include this Identifier value in
 * the subsequent fragment contained within an EAP-Reponse.
 *
 * @param[in] request		The current subrequest.
 * @param[in] eap_session	that we're acking the fragment for.
 */
static int eap_tls_ack(REQUEST *request, eap_session_t *eap_session)
{
	eap_tls_session_t	*eap_tls_session = talloc_get_type_abort(eap_session->opaque, eap_tls_session_t);

	rad_assert(request->parent);	/* must be a subrequest */

	RDEBUG2("ACKing Peer's TLS record fragment");
	return eap_tls_compose(request, eap_session, EAP_TLS_ACK_SEND,
			       eap_tls_session->base_flags, NULL, 0, 0);
}

/** Reduce session states down into an easy to use status
 *
 * @param[in] request		The current subrequest.
 * @param[in] eap_session	that we're acking the fragment for.
 * @return
 *	- EAP_TLS_ESTABLISHED - Handshake completed.
 *	- EAP_TLS_FAIL - Fatal alert from the client.
 *	- EAP_TLS_RECORD_SEND - Need more data, or previous fragment was acked.
 */
static eap_tls_status_t eap_tls_session_status(REQUEST *request, eap_session_t *eap_session)
{
	eap_tls_session_t	*eap_tls_session = talloc_get_type_abort(eap_session->opaque, eap_tls_session_t);
	tls_session_t		*tls_session = eap_tls_session->tls_session;

	if (tls_session == NULL){
		REDEBUG("Unexpected ACK received:  No ongoing SSL tls_session");
		return EAP_TLS_INVALID;
	}
	if (!tls_session->info.initialized) {
		RDEBUG2("No SSL info available.  Waiting for more SSL data");
		return EAP_TLS_RECORD_SEND;
	}

	if ((tls_session->info.content_type == SSL3_RT_HANDSHAKE) && (tls_session->info.origin == 0)) {
		REDEBUG("Unexpected ACK received:  We sent no previous messages");
		return EAP_TLS_INVALID;
	}

	switch (tls_session->info.content_type) {
	case SSL3_RT_ALERT:
		RDEBUG2("Peer ACKed our alert");
		return EAP_TLS_FAIL;

	case SSL3_RT_HANDSHAKE:
		if (SSL_is_init_finished(tls_session->ssl) && (tls_session->dirty_out.used == 0)) {
			RDEBUG2("Peer ACKed our handshake fragment.  handshake is finished");

			/*
			 *	From now on all the content is
			 *	application data set it here as nobody else
			 *	sets it.
			 */
			tls_session->info.content_type = SSL3_RT_APPLICATION_DATA;
			return EAP_TLS_ESTABLISHED;
		} /* else more data to send */

		RDEBUG2("Peer ACKed our handshake fragment");
		/* Fragmentation handler, send next fragment */
		return EAP_TLS_RECORD_SEND;

	case SSL3_RT_APPLICATION_DATA:
		RDEBUG2("Peer ACKed our application data fragment");
		return EAP_TLS_RECORD_SEND;

		/*
		 *	For the rest of the conditions, switch over
		 *	to the default section below.
		 */
	default:
		REDEBUG("Invalid ACK received: %d", tls_session->info.content_type);
		return EAP_TLS_INVALID;
	}
}

/** Check that this EAP-TLS packet is correct and the progression of EAP-TLS packets is sane
 *
 * @note In the received packet, No data will be present incase of ACK or NAK
 *	in this case the packet->data pointer will be NULL.
 *
 * @param[in] request		the current subrequest.
 * @param[in] eap_session	the current EAP session state.
 * @return
 *	- EAP_TLS_INVALID if the TLS record or progression is invalid.
 *	- EAP_TLS_FAIL handshake failed.
 *	- EAP_TLS_RECORD_RECV_FIRST this is the start of a new sequence of record fragments.
 *	- EAP_TLS_RECORD_RECV_MORE this is a continuation of a sequence of fragments.
 *	- EAP_TLS_RECORD_RECV_COMPLETE we received a completed record.
 *	- EAP_TLS_RECORD_SEND send more data to peer.
 *	- EAP_TLS_ESTABLISHED handshake is complete, TLS session has been established.
 */
static eap_tls_status_t eap_tls_verify(REQUEST *request, eap_session_t *eap_session)
{
	eap_round_t		*this_round = eap_session->this_round;
	eap_round_t		*prev_round = eap_session->prev_round;
	eap_tls_session_t	*eap_tls_session = talloc_get_type_abort(eap_session->opaque, eap_tls_session_t);

	eap_tls_data_t		*eap_tls_data;
	size_t			frag_len, header_len;

	rad_assert(request->parent);	/* must be a subrequest */

	/*
	 *	All EAP-TLS packets must contain type and flags fields.
	 */
	if (this_round->response->length < (EAP_HEADER_LEN + 2)) {
		REDEBUG("Invalid EAP-TLS packet: Expected at least %zu bytes got %zu bytes",
			(size_t)EAP_HEADER_LEN + 2, this_round->response->length);
		return EAP_TLS_INVALID;
	}

	/*
	 *	We don't check ANY of the input parameters.  It's all
	 *	code which works together, so if something is wrong,
	 *	we SHOULD core dump.
	 *
	 *	e.g. if this_round is NULL, of if this_round->response is
	 *	NULL, of if it's NOT an EAP-Response, or if the packet
	 *	is too short.  See eap_validate()., in ../../eap.c
	 */
	eap_tls_data = (eap_tls_data_t *)this_round->response->type.data;
	if (!eap_tls_data) {
		REDEBUG("Invalid EAP-TLS packet; no data");
		return EAP_TLS_INVALID;
	}

	/*
	 *	First output the flags (for debugging)
	 */
	RDEBUG3("Peer sent flags %c%c%c%c%c%c%c%c",
		TLS_START(eap_tls_data->flags) ? 'S' : '-',
		TLS_MORE_FRAGMENTS(eap_tls_data->flags) ? 'M' : '-',
		TLS_LENGTH_INCLUDED(eap_tls_data->flags) ? 'L' : '-',
		TLS_RESERVED0(eap_tls_data->flags) ? 'R' : '-',
		TLS_RESERVED1(eap_tls_data->flags) ? 'R' : '-',
		TLS_RESERVED2(eap_tls_data->flags) ? 'R' : '-',
		TLS_RESERVED3(eap_tls_data->flags) ? 'R' : '-',
		TLS_RESERVED4(eap_tls_data->flags) ? 'R' : '-');

	/*
	 *	This length includes the type and flags field and
	 *	the message length field if the flags indicate it's present.
	 */
	header_len = EAP_HEADER_LEN + (TLS_LENGTH_INCLUDED(eap_tls_data->flags) ? 6 : 2);
	if (this_round->response->length < header_len) {
		REDEBUG("Invalid EAP-TLS packet: Expected at least %zu bytes got %zu bytes",
			header_len, this_round->response->length);
		return EAP_TLS_INVALID;
	}

	/*
	 *	check for ACK
	 *
	 *	If there's no TLS data, or there's 1 byte of TLS data,
	 *	with the flags set to zero, then it's an ACK.
	 *
	 *	Find if this is a reply to the previous request sent
	 */
	if ((this_round->response->length == EAP_HEADER_LEN + 2) &&
	    ((eap_tls_data->flags & 0xc0) == 0x00)) {
		if (!prev_round || (prev_round->request->id != this_round->response->id)) {
			REDEBUG("Received Invalid TLS ACK");
			return EAP_TLS_INVALID;
		}
		return eap_tls_session_status(request, eap_session);
	}

	/*
	 *	We send TLS_START, but do not receive it.
	 */
	if (TLS_START(eap_tls_data->flags)) {
		REDEBUG("Peer sent EAP-TLS Start message (only the server is allowed to do this)");
		return EAP_TLS_INVALID;
	}

	/*
	 *	Calculate this fragment's length
	 */
	frag_len = this_round->response->length - header_len;

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
			return EAP_TLS_INVALID;
		}

		if (total_len > FR_TLS_MAX_RECORD_SIZE) {
			REDEBUG("Reassembled TLS record will be %zu bytes, "
				"greater than our maximum record size (" STRINGIFY(FR_TLS_MAX_RECORD_SIZE) " bytes)",
				total_len);
			return EAP_TLS_INVALID;
		}

		/*
		 *	wpa_supplicant's implementation of PEAPv0, and likely other
		 *	implementations of PEAPv0 will always include a Length flag
		 *	for every record fragment if performing mutual TLS auth.
		 *
		 *	If the eap_session says this is not the first fragment, then
		 *	don't count this as a new record, and continue as if we
		 *	hadn't seen the length flag.
		 */
		if (eap_tls_session->record_in_started) goto ignore_length;

		/*
		 *	This is the first fragment of a fragmented TLS record transfer.
		 */
		RDEBUG2("Peer indicated complete TLS record size will be %zu bytes", total_len);
		if (TLS_MORE_FRAGMENTS(eap_tls_data->flags)) {
			/*
			 *	The peer is free to send fragments of wildly varying
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
			 *	First fragment. record_in_started bool was false,
			 *	and we received a length included + more fragments packet.
			 */
			RDEBUG2("Got first TLS record fragment (%zu bytes).  Peer indicated more fragments "
				"to follow", frag_len);
			eap_tls_session->record_in_total_len = total_len;
			eap_tls_session->record_in_recvd_len = frag_len;
			eap_tls_session->record_in_started = true;

			return EAP_TLS_RECORD_RECV_FIRST;
		}

		/*
		 *	Else this is the complete TLS record.
		 */
		if (total_len != frag_len) {
			REDEBUG("Peer indicated no more fragments, but TLS record length (%zu bytes) "
				"does not match EAP-TLS data length (%zu bytes)", total_len, frag_len);
			return EAP_TLS_INVALID;
		}

		/*
		 *	RFC5216 doesn't specify explicitly whether a non-fragmented
		 *	packet should include the length or not.
		 *
		 *	We support both options for maximum compatibility.
		 */
		RDEBUG2("Got complete TLS record, with length field (%zu bytes)", frag_len);
		return EAP_TLS_RECORD_RECV_COMPLETE;
	}

ignore_length:
	if (TLS_MORE_FRAGMENTS(eap_tls_data->flags)) {
		/*
		 *	If this is not an ongoing transfer, and we have the M flag
		 *	then this record transfer is invalid.
		 */
		if (!eap_tls_session->record_in_started) {
			REDEBUG("TLS More (M) flag set, but no fragmented record transfer was in progress");
			return EAP_TLS_INVALID;
		}

		/*
		 *	If this is an ongoing transfer, and we have the M flag,
		 *	then this is just an additional fragment.
		 */
		RDEBUG2("Got additional TLS record fragment (%zu bytes).  Peer indicated more fragments to follow",
			frag_len);
		eap_tls_session->record_in_recvd_len += frag_len;
		if (eap_tls_session->record_in_recvd_len > eap_tls_session->record_in_total_len) {
			REDEBUG("Total received TLS record fragments (%zu bytes), exceeds "
				"indicated TLS record length (%zu bytes)",
				eap_tls_session->record_in_recvd_len, eap_tls_session->record_in_total_len);
			return EAP_TLS_INVALID;
		}
		return EAP_TLS_RECORD_RECV_MORE;
	}

	/*
	 *	No L flag and no M flag. This is either the final fragment,
	 *	or a new transfer that was not started with a L flag, which
	 *	RFC5216 hints, may be acceptable.
	 *
	 *	If it's an in-progress record transfer, check we now have
	 *	the complete record.
	 */
	if (eap_tls_session->record_in_started) {
		eap_tls_session->record_in_started = false;

		RDEBUG2("Got final TLS record fragment (%zu bytes)", frag_len);
		eap_tls_session->record_in_recvd_len += frag_len;
		if (eap_tls_session->record_in_recvd_len != eap_tls_session->record_in_total_len) {
			REDEBUG("Total received TLS record fragments (%zu bytes), does not equal indicated "
				"TLS record length (%zu bytes)",
				eap_tls_session->record_in_recvd_len, eap_tls_session->record_in_total_len);
			return EAP_TLS_INVALID;
		}
		return EAP_TLS_RECORD_RECV_COMPLETE;
	}

	/*
	 *	None of the flags are set, it wasn't an in progress transfer,
	 *	but it's still a valid EAP-TLS packet.
	 */
	RDEBUG2("Got complete TLS record (%zu bytes)", frag_len);

	return EAP_TLS_RECORD_RECV_COMPLETE;
}

/** Continue with the handshake
 *
 * @param[in] request		the current subrequest.
 * @param[in] eap_session	to continue.
 * @return
 *	- EAP_TLS_FAIL if the message is invalid.
 *	- EAP_TLS_HANDLED if we need to send an additional request to the peer.
 *	- EAP_TLS_ESTABLISHED if the handshake completed successfully, and there's
 *	  no more data to send.
 */
static eap_tls_status_t eap_tls_handshake(REQUEST *request, eap_session_t *eap_session)
{
	eap_tls_session_t	*eap_tls_session = talloc_get_type_abort(eap_session->opaque, eap_tls_session_t);
	tls_session_t		*tls_session = eap_tls_session->tls_session;

	/*
	 *	Continue the TLS handshake
	 */
	if (tls_session_handshake(request, tls_session) < 0) {
		REDEBUG("TLS receive handshake failed during operation");
		tls_cache_deny(tls_session);
		return EAP_TLS_FAIL;
	}

	/*
	 *	FIXME: return success/fail.
	 *
	 *	TLS proper can decide what to do, then.
	 */
	if (tls_session->dirty_out.used > 0) {
		eap_tls_request(request, eap_session);
		return EAP_TLS_HANDLED;
	}

	/*
	 *	If there is no data to send i.e dirty_out.used <=0 and
	 *	if the SSL handshake is finished, then return
	 *	EAP_TLS_ESTABLISHED.
	 *
	 *	For EAP-TLS this translates to an EAP-Success, for others
	 *	this begins phase2.
	 */
	if (eap_tls_session->phase2 || SSL_is_init_finished(tls_session->ssl)) {
		eap_tls_session->phase2 = true;

		/*
		 *	Init is finished.  The rest is
		 *	application data.
		 */
		tls_session->info.content_type = SSL3_RT_APPLICATION_DATA;
		return EAP_TLS_ESTABLISHED;
	}

	/*
	 *	Who knows what happened...
	 */
	REDEBUG("TLS failed during operation");
	return EAP_TLS_FAIL;
}

/** Process an EAP TLS request
 *
 * Here we implement a basic state machine.  The state machine is implicit and
 * is driven by the state of the TLS session and the flags sent.
 * INCOMING DATA:
 *   1. EAP-TLS should get the compelete TLS data from the peer.
 *   2. Store that data in a data structure with any other required info
 *   3. Hand this data structure to the TLS module.
 *   4. TLS module will perform its operations on the data and hands back to EAP-TLS
 * OUTGOING DATA:
 *   1. EAP-TLS if necessary will fragment it and send it to the destination.
 *
 * During EAP-TLS initialization, TLS Context object will be initialised and stored.
 * For every new authentication request, TLS will open a new session object and that
 * session object SHOULD be maintained even after the session is completed, for session
 * resumption.
 *
 * @param request	the request
 * @param eap_session	to continue.
 * @return
 *	- EAP_TLS_ESTABLISHED
 *	- EAP_TLS_HANDLED
 */
eap_tls_status_t eap_tls_process(REQUEST *request, eap_session_t *eap_session)
{
	eap_tls_session_t	*eap_tls_session = talloc_get_type_abort(eap_session->opaque, eap_tls_session_t);
	tls_session_t		*tls_session = eap_tls_session->tls_session;

	eap_round_t		*this_round = eap_session->this_round;
	eap_tls_status_t	status;

	eap_tls_data_t		*eap_tls_data;
	uint8_t			*data;
	size_t			data_len;

	rad_assert(request->parent);	/* must be a subrequest */

	RDEBUG2("Continuing EAP-TLS");

	/*
	 *	Call eap_tls_verify to sanity check the incoming EAP data.
	 */
	status = eap_tls_verify(request, eap_session);
	switch (status) {
	case EAP_TLS_INVALID:
	case EAP_TLS_FAIL:
		REDEBUG("[eap-tls verify] = %s", fr_table_str_by_value(eap_tls_status_table, status, "<INVALID>"));
		break;

	default:
		RDEBUG2("[eap-tls verify] = %s", fr_table_str_by_value(eap_tls_status_table, status, "<INVALID>"));
		break;
	}

	/*
	 *	Status in this here means 'state'.  Our state is determined passively
	 *	for EAP-TLS, based on what state OpenSSL reported the TLS session
	 *	to be in, and what flags were last received from the peer.
	 */
	switch (status) {
	/*
	 *	We've received a complete TLS record, this is the same as receiving a
	 *	fragment, except we also process the complete record.
	 */
	case EAP_TLS_RECORD_RECV_COMPLETE:
	/*
	 *	We've received a fragment of a TLS record
	 *
	 *	Determine where the TLS record starts.
	 *
	 *	If the length included flag is set, we need to skip over the 4 byte
	 *	message length field.
	 *
	 *	Next - Copy the fragment data into OpenSSL's dirty in buffer so that it
	 *	can process it in a later call.
	 */
	case EAP_TLS_RECORD_RECV_FIRST:
	case EAP_TLS_RECORD_RECV_MORE:
		eap_tls_data = (eap_tls_data_t *)this_round->response->type.data;
		if (TLS_LENGTH_INCLUDED(eap_tls_data->flags)) {
			data = (this_round->response->type.data + 5);		/* flags + TLS-Length */
			data_len = this_round->response->type.length - 5;	/* flags + TLS-Length */
		} else {
			data = this_round->response->type.data + 1;		/* flags */
			data_len = this_round->response->type.length - 1;	/* flags */
		}

		/*
		 *	Update the dirty_in buffer (data for reading by OpenSSL)
		 *
		 *	This buffer will contain partial data when M bit is set, and should
		 * 	should only be reinitialized when M bit is not set.
		 */
		if ((tls_session->record_from_buff)(&tls_session->dirty_in, data, data_len) != data_len) {
			REDEBUG("Exceeded maximum record size");
			status = EAP_TLS_FAIL;
			goto done;
		}

		/*
		 *	ACK fragments until we get a complete TLS record.
		 */
		if (status != EAP_TLS_RECORD_RECV_COMPLETE) {
			eap_tls_ack(request, eap_session);
			status = EAP_TLS_HANDLED;
			goto done;
		}

		/*
		 *	We have a complete record.  If the handshake is finished
		 *	process it as application data, otherwise continue
		 *	the handshake.
		 */
		if (eap_tls_session->phase2 || SSL_is_init_finished(tls_session->ssl)) {
			int ret;

			eap_tls_session->phase2 = true;

			ret = tls_session_recv(request, tls_session);
			switch (ret) {
			case 0:
				status = EAP_TLS_RECORD_RECV_COMPLETE;
				break;

			case 1:
				status = EAP_TLS_RECORD_RECV_MORE;
				break;

			default:
				status = EAP_TLS_FAIL;
				break;
			}
		} else {
			status = eap_tls_handshake(request, eap_session);
		}
		break;
	/*
	 *	We have fragments or records to send to the peer
	 */
	case EAP_TLS_RECORD_SEND:
		/*
		 *	Return a "yes we're done" if there's no more data to send,
		 *	and we've just managed to finish the SSL session initialization.
		 */
		if (!eap_tls_session->phase2 && (tls_session->dirty_out.used == 0) &&
		    SSL_is_init_finished(tls_session->ssl)) {
			eap_tls_session->phase2 = true;
			return EAP_TLS_RECORD_RECV_COMPLETE;
		}

		eap_tls_request(request, eap_session);
		status = EAP_TLS_HANDLED;
		goto done;

	/*
	 *	Bad things happened and we're unable to continue.
	 */
	case EAP_TLS_INVALID:
	case EAP_TLS_FAIL:
	/*
	 *	Established means that we're done the initial handshake.
	 *
	 *	For TTLS and PEAP that means begin phase2
	 */
	case EAP_TLS_ESTABLISHED:
	default:
		goto done;
	}

 done:
	return status;
}

/** Create a new tls_session_t associated with an #eap_session_t
 *
 * Creates a new server tls_session_t and associates it with an #eap_session_t
 * adding EAP specific opaque data to the SSL session created during tls_session_t
 * initialisation.
 *
 * @param[in] request		The current subrequest.
 * @param[in] eap_session	to use as a context for the eap_tls_session_t
 * @param[in] tls_conf		to use to configure the tls_session_t.
 * @param[in] client_cert	Whether we require the peer to prevent a certificate.
 * @return
 *	- A new eap_tls_session on success.
 *	- NULL on error.
 */
eap_tls_session_t *eap_tls_session_init(REQUEST *request, eap_session_t *eap_session,
					fr_tls_conf_t *tls_conf, bool client_cert)
{
	eap_tls_session_t	*eap_tls_session;
	tls_session_t		*tls_session;

	rad_assert(request->parent);	/* must be a subrequest */

	/*
	 *	This EAP session is associated with a TLS session
	 */
	eap_session->tls = true;
	eap_tls_session = talloc_zero(eap_session, eap_tls_session_t);

	/*
	 *	Initial state.
	 */
	eap_tls_session->state = EAP_TLS_START_SEND;

	/*
	 *	As per the RFC...
	 *
	 *	Broken protocols like PEAPv0 need this set to false.
	 */
	eap_tls_session->include_length = true;

	/*
	 *	Every new session is started only from EAP-TLS-START.
	 *	Before Sending our initial EAP-TLS start open a new
	 *	SSL session.
	 *	Create all the required data structures & store them
	 *	in the SSL session's opaque data so that we can use
	 *	these data structures when we get the response.
	 */
	eap_tls_session->tls_session = tls_session = tls_session_init_server(eap_tls_session, tls_conf,
									     request, client_cert);
	if (!tls_session) return NULL;

	/*
	 *	Associate various bits of opaque data with the session.
	 */
	SSL_set_ex_data(tls_session->ssl, FR_TLS_EX_INDEX_EAP_SESSION, (void *)eap_session);
	SSL_set_ex_data(tls_session->ssl, FR_TLS_EX_INDEX_TLS_SESSION, (void *)tls_session);
	SSL_set_ex_data(tls_session->ssl, FR_TLS_EX_INDEX_CONF, (void *)tls_conf);
	SSL_set_ex_data(tls_session->ssl, FR_TLS_EX_INDEX_IDENTITY, (void *)&(eap_session->identity));
#ifdef HAVE_OPENSSL_OCSP_H
	SSL_set_ex_data(tls_session->ssl, FR_TLS_EX_INDEX_STORE, (void *)tls_conf->ocsp.store);
#endif

	return eap_tls_session;
}

/** Parse TLS configuration
 *
 * If the option given by 'attr' is set, we find the config section of that name and use
 * that for the TLS configuration. If not, we fall back to compatibility mode and read
 * the TLS options from the 'tls' section.
 *
 * @param cs to derive the configuration from.
 * @param attr identifier for common TLS configuration.
 * @return
 *	- NULL on error.
 *	- A new fr_tls_conf_t on success.
 */
fr_tls_conf_t *eap_tls_conf_parse(CONF_SECTION *cs, char const *attr)
{
	char const 		*tls_conf_name;
	CONF_PAIR		*cp;
	CONF_SECTION		*parent;
	CONF_SECTION		*tls_cs;
	fr_tls_conf_t		*tls_conf;

	parent = cf_item_to_section(cf_parent(cs));

	cp = cf_pair_find(cs, attr);
	if (cp) {
		tls_conf_name = cf_pair_value(cp);

		tls_cs = cf_section_find(parent, TLS_CONFIG_SECTION, tls_conf_name);
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
		tls_cs = cf_section_find(parent, "tls", NULL);
	}

	if (!tls_cs) return NULL;

	tls_conf = tls_conf_parse_server(tls_cs);
	if (!tls_conf) return NULL;

	/*
	 *	The EAP RFC's say 1020, but we're less picky.
	 */
	FR_INTEGER_BOUND_CHECK("fragment_size", tls_conf->fragment_size, >=, 100);
	/*
	 *	The maximum size for a RADIUS packet is 4096, but we're
	 *	not just a RADIUS server.
	 *
	 *	Maximum size for a TLS record is 16K, so little point in
	 *	setting it higher than that.
	 */
	FR_INTEGER_BOUND_CHECK("fragment_size", tls_conf->fragment_size, <=, FR_TLS_MAX_RECORD_SIZE);

	/*
	 *	Account for the EAP header (4), and the EAP-TLS header
	 *	(6), as per Section 4.2 of RFC 2716.  What's left is
	 *	the maximum amount of data we read from a TLS buffer.
	 */
	tls_conf->fragment_size -= 10;

	return tls_conf;
}

