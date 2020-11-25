/*
 * peap.c contains the interfaces that are called from eap
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
 *   @copyright 2003 Alan DeKok (aland@freeradius.org)
 *   @copyright 2006 The FreeRADIUS server project
 */

RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/radius/defs.h>

#include "eap_peap.h"

static int setup_fake_request(request_t *request, request_t *fake, peap_tunnel_t *t);

/*
 *	Send protected EAP-Failure
 *
 *       Result-TLV = Failure
 */
static int eap_peap_failure(request_t *request, eap_session_t *eap_session, fr_tls_session_t *tls_session)
{
	uint8_t tlv_packet[11];

	RDEBUG2("FAILURE");

	tlv_packet[0] = FR_EAP_CODE_REQUEST;
	tlv_packet[1] = eap_session->this_round->response->id +1;
	tlv_packet[2] = 0;
	tlv_packet[3] = 11;	/* length of this packet */
	tlv_packet[4] = FR_PEAP_EXTENSIONS_TYPE;
	tlv_packet[5] = 0x80;
	tlv_packet[6] = EAP_TLV_ACK_RESULT;
	tlv_packet[7] = 0;
	tlv_packet[8] = 2;	/* length of the data portion */
	tlv_packet[9] = 0;
	tlv_packet[10] = EAP_TLV_FAILURE;

	(tls_session->record_from_buff)(&tls_session->clean_in, tlv_packet, 11);

	/*
	 *	FIXME: Check the return code.
	 */
	fr_tls_session_send(request, tls_session);

	return 1;
}


/*
 *	Send protected EAP-Success
 *
 *       Result-TLV = Success
 */
static int eap_peap_success(request_t *request, eap_session_t *eap_session, fr_tls_session_t *tls_session)
{
	uint8_t tlv_packet[11];

	RDEBUG2("SUCCESS");

	tlv_packet[0] = FR_EAP_CODE_REQUEST;
	tlv_packet[1] = eap_session->this_round->response->id +1;
	tlv_packet[2] = 0;
	tlv_packet[3] = 11;	/* length of this packet */
	tlv_packet[4] = FR_PEAP_EXTENSIONS_TYPE;
	tlv_packet[5] = 0x80;	/* mandatory AVP */
	tlv_packet[6] = EAP_TLV_ACK_RESULT;
	tlv_packet[7] = 0;
	tlv_packet[8] = 2;	/* length of the data portion */
	tlv_packet[9] = 0;
	tlv_packet[10] = EAP_TLV_SUCCESS;

	(tls_session->record_from_buff)(&tls_session->clean_in, tlv_packet, 11);

	/*
	 *	FIXME: Check the return code.
	 */
	fr_tls_session_send(request, tls_session);

	return 1;
}


static int eap_peap_identity(request_t *request, eap_session_t *eap_session, fr_tls_session_t *tls_session)
{
	eap_packet_raw_t eap_packet;

	eap_packet.code = FR_EAP_CODE_REQUEST;
	eap_packet.id = eap_session->this_round->response->id + 1;
	eap_packet.length[0] = 0;
	eap_packet.length[1] = EAP_HEADER_LEN + 1;
	eap_packet.data[0] = FR_EAP_METHOD_IDENTITY;

	(tls_session->record_from_buff)(&tls_session->clean_in, &eap_packet, sizeof(eap_packet));
	fr_tls_session_send(request, tls_session);
	(tls_session->record_init)(&tls_session->clean_in);

	return 1;
}

/*
 * Send an MS SoH request
 */
static int eap_peap_soh(request_t *request,fr_tls_session_t *tls_session)
{
	uint8_t tlv_packet[20];

	tlv_packet[0] = 254;	/* extended type */

	tlv_packet[1] = 0;
	tlv_packet[2] = 0x01;	/* ms vendor */
	tlv_packet[3] = 0x37;

	tlv_packet[4] = 0;	/* ms soh eap */
	tlv_packet[5] = 0;
	tlv_packet[6] = 0;
	tlv_packet[7] = 0x21;

	tlv_packet[8] = 0;	/* vendor-spec tlv */
	tlv_packet[9] = 7;

	tlv_packet[10] = 0;
	tlv_packet[11] = 8;	/* payload len */

	tlv_packet[12] = 0;	/* ms vendor */
	tlv_packet[13] = 0;
	tlv_packet[14] = 0x01;
	tlv_packet[15] = 0x37;

	tlv_packet[16] = 0;
	tlv_packet[17] = 2;
	tlv_packet[18] = 0;
	tlv_packet[19] = 0;

	(tls_session->record_from_buff)(&tls_session->clean_in, tlv_packet, 20);
	fr_tls_session_send(request, tls_session);
	return 1;
}

static void eap_peap_soh_verify(request_t *request, fr_radius_packet_t *packet,
			  	uint8_t const *data, unsigned int data_len) {

	fr_pair_t *vp;
	uint8_t eap_method_base;
	uint32_t eap_vendor;
	uint32_t eap_method;
	int rv;

	MEM(vp = fr_pair_afrom_da(packet, attr_soh_supported));
	vp->vp_bool = false;
	fr_pair_add(&request->request_pairs, vp);

	if (data && data[0] == FR_EAP_METHOD_NAK) {
		REDEBUG("SoH - client NAKed");
		return;
	}

	if (!data || data_len < 8) {
		REDEBUG("SoH - eap payload too short");
		return;
	}

	eap_method_base = *data++;
	if (eap_method_base != 254) {
		REDEBUG("SoH - response is not extended EAP: %i", eap_method_base);
		return;
	}

	eap_vendor = soh_pull_be_24(data); data += 3;
	if (eap_vendor != 0x137) {
		REDEBUG("SoH - extended eap vendor %08x is not Microsoft", eap_vendor);
		return;
	}

	eap_method = soh_pull_be_32(data); data += 4;
	if (eap_method != 0x21) {
		REDEBUG("SoH - response eap type %08x is not EAP-SoH", eap_method);
		return;
	}

	rv = soh_verify(request, data, data_len - 8);
	if (rv < 0) {
		RPEDEBUG("SoH - error decoding payload");
	} else {
		vp->vp_uint32 = 1;
	}
}


/*
 *	Verify the tunneled EAP message.
 */
static int eap_peap_verify(request_t *request, peap_tunnel_t *peap_tunnel,
			   uint8_t const *data, size_t data_len)
{
	eap_packet_raw_t const	*eap_packet = (eap_packet_raw_t const *) data;
	eap_type_t		eap_method;

	/*
	 *	No data, OR only 1 byte of EAP type.
	 */
	if (!data || (data_len == 0) || ((data_len <= 1) && (data[0] != FR_EAP_METHOD_IDENTITY))) return 0;

	/*
	 *  Since the full EAP header is sent for the EAP Extensions type (Type 33),
	 *  but not for other Types, it is difficult for the implementation to distinguish
	 *  an Extensions Request (Code 1) from an EAP Type 1 (Identity) Request packet.
	 *
	 *  i.e. The only way to validate PEAP inner method packets properly is to know
	 *  we just send a protected success/failure.
	 */
	switch (peap_tunnel->status) {
	case PEAP_STATUS_SENT_TLV_SUCCESS:
	case PEAP_STATUS_SENT_TLV_FAILURE:
		if (eap_packet->data[0] != FR_PEAP_EXTENSIONS_TYPE) {
			REDEBUG("Invalid inner tunnel data, expected method (%u), got (%u)",
				FR_PEAP_EXTENSIONS_TYPE, eap_packet->data[0]);
			return -1;
		}
		return 0;

	default:
		break;
	}

	eap_method = data[0];	/* Inner EAP header misses off code and identifier */
	switch (eap_method) {
	case FR_EAP_METHOD_IDENTITY:
		RDEBUG2("Received EAP-Identity-Response");
		return 0;

	/*
	 *	We normally do Microsoft MS-CHAPv2 (26), versus
	 *	Cisco MS-CHAPv2 (29).
	 */
	case FR_EAP_METHOD_MSCHAPV2:
	default:
		RDEBUG2("EAP method %s (%d)", eap_type2name(eap_method), eap_method);
		return 0;
	}

}

/*
 *	Convert a pseudo-EAP packet to a list of fr_pair_t's.
 */
static fr_pair_t *eap_peap_inner_to_pairs(UNUSED request_t *request, fr_radius_packet_t *packet,
			  		   eap_round_t *eap_round,
			  		   uint8_t const *data, size_t data_len)
{
	size_t 		total;
	uint8_t		*p;
	fr_pair_t	*vp = NULL;
	fr_pair_list_t	head;
	fr_cursor_t	cursor;

	fr_pair_list_init(&head);
	if (data_len > 65535) return NULL; /* paranoia */

	MEM(vp = fr_pair_afrom_da(packet, attr_eap_message));
	total = data_len;
	if (total > 249) total = 249;

	/*
	 *	Hand-build an EAP packet from the crap in PEAP version 0.
	 */
	MEM(fr_pair_value_mem_alloc(vp, &p, EAP_HEADER_LEN + total, false) == 0);
	p[0] = FR_EAP_CODE_RESPONSE;
	p[1] = eap_round->response->id;
	p[2] = (data_len + EAP_HEADER_LEN) >> 8;
	p[3] = (data_len + EAP_HEADER_LEN) & 0xff;
	memcpy(p + EAP_HEADER_LEN, data, total);

	fr_cursor_init(&cursor, &head);
	fr_cursor_append(&cursor, vp);
	while (total < data_len) {
		MEM(vp = fr_pair_afrom_da(packet, attr_eap_message));
		fr_pair_value_memdup(vp, data + total, (data_len - total), false);

		total += vp->vp_length;

		fr_cursor_append(&cursor, vp);
	}

	return head;
}


/*
 *	Convert a list of fr_pair_t's to an EAP packet, through the
 *	simple expedient of dumping the EAP message
 */
static int eap_peap_inner_from_pairs(request_t *request, fr_tls_session_t *tls_session, fr_pair_t *vp)
{
	fr_assert(vp != NULL);
	fr_pair_t *this;
	fr_cursor_t cursor;

	/*
	 *	Send the EAP data in the first attribute, WITHOUT the
	 *	header.
	 */
	(tls_session->record_from_buff)(&tls_session->clean_in, vp->vp_octets + EAP_HEADER_LEN,
					vp->vp_length - EAP_HEADER_LEN);

	/*
	 *	Send the rest of the EAP data, but skipping the first VP.
	 */
	fr_cursor_init(&cursor, &vp);
	for (this = fr_cursor_next(&cursor);
	     this;
	     this = fr_cursor_next(&cursor)) {
		(tls_session->record_from_buff)(&tls_session->clean_in, this->vp_octets, this->vp_length);
	}

	fr_tls_session_send(request, tls_session);

	return 1;
}


/*
 *	See if there's a TLV in the response.
 */
static int eap_peap_check_tlv(request_t *request, uint8_t const *data, size_t data_len)
{
	eap_packet_raw_t const *eap_packet = (eap_packet_raw_t const *) data;

	if (data_len < 11) return 0;

	/*
	 *	Look for success or failure.
	 */
	if ((eap_packet->code == FR_EAP_CODE_RESPONSE) &&
	    (eap_packet->data[0] == FR_PEAP_EXTENSIONS_TYPE)) {
		if (data[10] == EAP_TLV_SUCCESS) {
			return 1;
		}

		if (data[10] == EAP_TLV_FAILURE) {
			RDEBUG2("Client rejected our response.  The password is probably incorrect");
			return 0;
		}
	}

	RDEBUG2("Unknown TLV %02x", data[10]);

	return 0;
}


/*
 *	Use a reply packet to determine what to do.
 */
static rlm_rcode_t CC_HINT(nonnull) process_reply(eap_session_t *eap_session, fr_tls_session_t *tls_session,
						  request_t *request, fr_radius_packet_t *reply)
{
	rlm_rcode_t rcode = RLM_MODULE_REJECT;
	fr_pair_t *vp;
	peap_tunnel_t *t = tls_session->opaque;

	if (RDEBUG_ENABLED2) {

		/*
		 *	Note that we don't do *anything* with the reply
		 *	attributes.
		 */
		if (is_radius_code(reply->code)) {
			RDEBUG2("Got tunneled reply %s", fr_packet_codes[reply->code]);
		} else {
			RDEBUG2("Got tunneled reply code %i", reply->code);
		}
		log_request_pair_list(L_DBG_LVL_2, request, reply->vps, NULL);
	}

	switch (reply->code) {
	case FR_CODE_ACCESS_ACCEPT:
		RDEBUG2("Tunneled authentication was successful");
		t->status = PEAP_STATUS_SENT_TLV_SUCCESS;
		eap_peap_success(request, eap_session, tls_session);
		rcode = RLM_MODULE_HANDLED;
		break;

	case FR_CODE_ACCESS_REJECT:
		RDEBUG2("Tunneled authentication was rejected");
		t->status = PEAP_STATUS_SENT_TLV_FAILURE;
		eap_peap_failure(request, eap_session, tls_session);
		rcode = RLM_MODULE_HANDLED;
		break;

	case FR_CODE_ACCESS_CHALLENGE:
		RDEBUG2("Got tunneled Access-Challenge");

		/*
		 *	PEAP takes only EAP-Message attributes inside
		 *	of the tunnel.  Any Reply-Message in the
		 *	Access-Challenge is ignored.
		 */
		vp = NULL;
		fr_pair_list_copy_by_da(t, &vp, &reply->vps, attr_eap_message, 0);

		/*
		 *	Handle the ACK, by tunneling any necessary reply
		 *	VP's back to the client.
		 */
		if (vp) {
			eap_peap_inner_from_pairs(request, tls_session, vp);
			fr_pair_list_free(&vp);
		}

		rcode = RLM_MODULE_HANDLED;
		break;

	default:
		RDEBUG2("Unknown RADIUS packet type %d: rejecting tunneled user", reply->code);
		rcode = RLM_MODULE_REJECT;
		break;
	}

	return rcode;
}


static char const *peap_state(peap_tunnel_t *t)
{
	switch (t->status) {
	case PEAP_STATUS_TUNNEL_ESTABLISHED:
		return "TUNNEL ESTABLISHED";

	case PEAP_STATUS_WAIT_FOR_SOH_RESPONSE:
		return "WAITING FOR SOH RESPONSE";

	case PEAP_STATUS_INNER_IDENTITY_REQ_SENT:
		return "WAITING FOR INNER IDENTITY";

	case PEAP_STATUS_SENT_TLV_SUCCESS:
		return "send tlv success";

	case PEAP_STATUS_SENT_TLV_FAILURE:
		return "send tlv failure";

	case PEAP_STATUS_PHASE2_INIT:
		return "phase2_init";

	case PEAP_STATUS_PHASE2:
		return "phase2";

	default:
		break;
	}
	return "?";
}

/*
 *	Process the pseudo-EAP contents of the tunneled data.
 */
unlang_action_t eap_peap_process(rlm_rcode_t *p_result, request_t *request,
				 eap_session_t *eap_session, fr_tls_session_t *tls_session)
{
	peap_tunnel_t	*t = tls_session->opaque;
	request_t	*fake = NULL;
	fr_pair_t	*vp;
	rlm_rcode_t	rcode = RLM_MODULE_REJECT;
	uint8_t const	*data;
	size_t		data_len;
	eap_round_t	*eap_round = eap_session->this_round;

	/*
	 *	Just look at the buffer directly, without doing
	 *	record_to_buff.  This lets us avoid another data copy.
	 */
	data_len = tls_session->clean_out.used;
	tls_session->clean_out.used = 0;
	data = tls_session->clean_out.data;

	RDEBUG2("PEAP state %s", peap_state(t));

	if ((t->status != PEAP_STATUS_TUNNEL_ESTABLISHED) && (eap_peap_verify(request, t, data, data_len) < 0)) {
		REDEBUG("Tunneled data is invalid");
		RETURN_MODULE_REJECT;
	}

	switch (t->status) {
	case PEAP_STATUS_TUNNEL_ESTABLISHED:
		/* FIXME: should be no data in the buffer here, check & assert? */

		if (SSL_session_reused(tls_session->ssl)) {
			RDEBUG2("Skipping Phase2 because of session resumption");
			t->session_resumption_state = PEAP_RESUMPTION_YES;
			if (t->soh) {
				t->status = PEAP_STATUS_WAIT_FOR_SOH_RESPONSE;
				RDEBUG2("Requesting SoH from client");
				eap_peap_soh(request, tls_session);

				rcode = RLM_MODULE_HANDLED;
				goto finish;
			}
			/* we're good, send success TLV */
			t->status = PEAP_STATUS_SENT_TLV_SUCCESS;
			eap_peap_success(request, eap_session, tls_session);

		} else {
			/* send an identity request */
			t->session_resumption_state = PEAP_RESUMPTION_NO;
			t->status = PEAP_STATUS_INNER_IDENTITY_REQ_SENT;
			eap_peap_identity(request, eap_session, tls_session);
		}
		rcode = RLM_MODULE_HANDLED;
		goto finish;

	case PEAP_STATUS_INNER_IDENTITY_REQ_SENT:
		/* we're expecting an identity response */
		if (data[0] != FR_EAP_METHOD_IDENTITY) {
			REDEBUG("Expected EAP-Identity, got something else");
			rcode = RLM_MODULE_REJECT;
			goto finish;
		}

		/*
		 *	Save it for later.
		 */
		MEM(t->username = fr_pair_afrom_da(t, attr_user_name));
		t->username->vp_tainted = true;

		fr_pair_value_bstrndup(t->username, (char const *)data + 1, data_len - 1, true);

		RDEBUG2("Got inner identity \"%pV\"", &t->username->data);
		if (t->soh) {
			t->status = PEAP_STATUS_WAIT_FOR_SOH_RESPONSE;
			RDEBUG2("Requesting SoH from client");
			eap_peap_soh(request, tls_session);
			rcode = RLM_MODULE_HANDLED;
			goto finish;
		}
		t->status = PEAP_STATUS_PHASE2_INIT;
		break;

	case PEAP_STATUS_WAIT_FOR_SOH_RESPONSE:
		fake = request_alloc_fake(request, NULL);
		fr_assert(!fake->request_pairs);
		eap_peap_soh_verify(fake, fake->packet, data, data_len);
		setup_fake_request(request, fake, t);

		if (t->soh_virtual_server) fake->server_cs = virtual_server_find(t->soh_virtual_server);

		RDEBUG2("Sending SoH request to server %s",
		       fake->server_cs ? cf_section_name2(fake->server_cs) : "NULL");
		rad_virtual_server(&rcode, fake);

		if (fake->reply->code != FR_CODE_ACCESS_ACCEPT) {
			RDEBUG2("SoH was rejected");
			TALLOC_FREE(fake);
			t->status = PEAP_STATUS_SENT_TLV_FAILURE;
			eap_peap_failure(request, eap_session, tls_session);
			rcode = RLM_MODULE_HANDLED;
			goto finish;
		}

		/* save the SoH VPs */
		fr_assert(!t->soh_reply_vps);
		MEM(fr_pair_list_copy(t, &t->soh_reply_vps, &fake->reply->vps) >= 0);
		fr_assert(!fake->reply->vps);
		TALLOC_FREE(fake);

		if (t->session_resumption_state == PEAP_RESUMPTION_YES) {
			/* we're good, send success TLV */
			t->status = PEAP_STATUS_SENT_TLV_SUCCESS;
			eap_peap_success(request, eap_session, tls_session);
			rcode = RLM_MODULE_HANDLED;
			goto finish;
		}

		t->status = PEAP_STATUS_PHASE2_INIT;
		break;


	/*
	 *	If we authenticated the user, then it's OK.
	 */
	case PEAP_STATUS_SENT_TLV_SUCCESS:
		if (eap_peap_check_tlv(request, data, data_len)) {
			RDEBUG2("Success");
			rcode = RLM_MODULE_OK;
			goto finish;
		}

		/*
		 *	Otherwise, the client rejected the session
		 *	resumption.  If the session is being re-used,
		 *	we need to do a full authentication.
		 *
		 *	We do this by sending an EAP-Identity request
		 *	inside of the PEAP tunnel.
		 */
		if (t->session_resumption_state == PEAP_RESUMPTION_YES) {
			RDEBUG2("Client rejected session resumption.  Re-starting full authentication");

			/*
			 *	Mark session resumption status.
			 */
			t->status = PEAP_STATUS_INNER_IDENTITY_REQ_SENT;
			t->session_resumption_state = PEAP_RESUMPTION_NO;

			eap_peap_identity(request, eap_session, tls_session);
			rcode = RLM_MODULE_HANDLED;
			goto finish;
		}

		REDEBUG("Sent a success, but received something weird in return");
		rcode = RLM_MODULE_REJECT;
		goto finish;

	/*
	 *	Supplicant ACKs our failure.
	 */
	case PEAP_STATUS_SENT_TLV_FAILURE:
		RINDENT();
		REDEBUG("The users session was previously rejected: returning reject (again.)");
		RIDEBUG("This means you need to read the PREVIOUS messages in the debug output");
		RIDEBUG("to find out the reason why the user was rejected");
		RIDEBUG("Look for \"reject\" or \"fail\".  Those earlier messages will tell you");
		RIDEBUG("what went wrong, and how to fix the problem");
		REXDENT();

		RETURN_MODULE_REJECT;

		case PEAP_STATUS_PHASE2_INIT:
			RDEBUG2("In state machine in phase2 init?");
			break;

		case PEAP_STATUS_PHASE2:
			break;

		default:
			REDEBUG("Unhandled state in peap");
			rcode = RLM_MODULE_REJECT;
			goto finish;
	}

	fake = request_alloc_fake(request, NULL);
	fr_assert(!fake->request_pairs);

	switch (t->status) {
	/*
	 *	If we're in PHASE2_INIT, the phase2 method hasn't been
	 *	sent an Identity packet yet; do so from the stored
	 *	username and this will kick off the phase2 eap method
	 */
	case PEAP_STATUS_PHASE2_INIT:
	{
		size_t len;
		uint8_t *q;

		fr_assert(t->username);

		len = t->username->vp_length + EAP_HEADER_LEN + 1;
		t->status = PEAP_STATUS_PHASE2;

		MEM(vp = fr_pair_afrom_da(fake->packet, attr_eap_message));
		MEM(fr_pair_value_mem_alloc(vp, &q, len, false) == 0);
		q[0] = FR_EAP_CODE_RESPONSE;
		q[1] = eap_round->response->id;
		q[2] = (len >> 8) & 0xff;
		q[3] = len & 0xff;
		q[4] = FR_EAP_METHOD_IDENTITY;
		memcpy(q + EAP_HEADER_LEN + 1,
		       t->username->vp_strvalue, t->username->vp_length);
		fr_pair_add(&fake->request_pairs, vp);
	}
		break;

	case PEAP_STATUS_PHASE2:
		fake->request_pairs = eap_peap_inner_to_pairs(request, fake->packet,
							    eap_round, data, data_len);
		if (!fake->request_pairs) {
			talloc_free(fake);
			RDEBUG2("Unable to convert tunneled EAP packet to internal server data structures");
			rcode = RLM_MODULE_REJECT;
			goto finish;
		}
		break;

	default:
		REDEBUG("Invalid state change in PEAP");
		rcode = RLM_MODULE_REJECT;
		goto finish;
	}

	RDEBUG2("Got tunneled request");
	log_request_pair_list(L_DBG_LVL_2, request, fake->request_pairs, NULL);

	/*
	 *	Update other items in the request_t data structure.
	 */
	if (!t->username) {
		/*
		 *	There's no User-Name in the tunneled session,
		 *	so we add one here, by pulling it out of the
		 *	EAP-Identity packet.
		 */
		if ((data[0] == FR_EAP_METHOD_IDENTITY) && (data_len > 1)) {
			MEM(t->username = fr_pair_afrom_da(t, attr_user_name));
			fr_assert(t->username != NULL);
			t->username->vp_tainted = true;

			fr_pair_value_bstrndup(t->username, (char const *)data + 1, data_len - 1, true);

			RDEBUG2("Got tunneled identity of %pV", &t->username->data);
		}
	} /* else there WAS a t->username */

	setup_fake_request(request, fake, t);

	/*
	 *	Call authentication recursively, which will
	 *	do PAP, CHAP, MS-CHAP, etc.
	 */
	eap_virtual_server(request, eap_session, t->virtual_server);

	/*
	 *	Decide what to do with the reply.
	 */
	if (!fake->reply->code) {
		REDEBUG("Unknown RADIUS packet type %d: rejecting tunneled user", fake->reply->code);
		rcode = RLM_MODULE_REJECT;
	} else {
		rcode = process_reply(eap_session, tls_session, request, fake->reply);
	}

finish:
	talloc_free(fake);

	RETURN_MODULE_RCODE(rcode);
}

static int CC_HINT(nonnull) setup_fake_request(request_t *request, request_t *fake, peap_tunnel_t *t) {

	fr_pair_t *vp;

	/*
	 *	Tell the request that it's a fake one.
	 */
	MEM(fr_pair_add_by_da(fake->packet, &vp, &fake->request_pairs, attr_freeradius_proxied_to) >= 0);
	fr_pair_value_from_str(vp, "127.0.0.1", sizeof("127.0.0.1"), '\0', false);

	if (t->username) {
		vp = fr_pair_copy(fake->packet, t->username);
		fr_pair_add(&fake->request_pairs, vp);
		RDEBUG2("Setting &request.User-Name from tunneled (inner) identity \"%s\"",
			vp->vp_strvalue);
	} else {
		RDEBUG2("No tunnel username (SSL resumption?)");
	}

	return 0;
}
