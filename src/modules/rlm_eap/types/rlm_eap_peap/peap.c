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
 *   @copyright 2003 Alan DeKok <aland@freeradius.org>
 *   @copyright 2006 The FreeRADIUS server project
 */

RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#include <freeradius-devel/unlang/base.h>
#include "eap_peap.h"

static int setup_fake_request(REQUEST *request, REQUEST *fake, peap_tunnel_t *t);

/*
 *	Send protected EAP-Failure
 *
 *       Result-TLV = Failure
 */
static int eap_peap_failure(eap_session_t *eap_session, tls_session_t *tls_session)
{
	uint8_t tlv_packet[11];
	REQUEST *request = eap_session->request;

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
	tls_session_send(request, tls_session);

	return 1;
}


/*
 *	Send protected EAP-Success
 *
 *       Result-TLV = Success
 */
static int eap_peap_success(eap_session_t *eap_session, tls_session_t *tls_session)
{
	uint8_t tlv_packet[11];
	REQUEST *request = eap_session->request;

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
	tls_session_send(request, tls_session);

	return 1;
}


static int eap_peap_identity(eap_session_t *eap_session, tls_session_t *tls_session)
{
	eap_packet_raw_t eap_packet;

	eap_packet.code = FR_EAP_CODE_REQUEST;
	eap_packet.id = eap_session->this_round->response->id + 1;
	eap_packet.length[0] = 0;
	eap_packet.length[1] = EAP_HEADER_LEN + 1;
	eap_packet.data[0] = FR_EAP_IDENTITY;

	(tls_session->record_from_buff)(&tls_session->clean_in, &eap_packet, sizeof(eap_packet));
	tls_session_send(eap_session->request, tls_session);
	(tls_session->record_init)(&tls_session->clean_in);

	return 1;
}

/*
 * Send an MS SoH request
 */
static int eap_peap_soh(eap_session_t *eap_session, tls_session_t *tls_session)
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
	tls_session_send(eap_session->request, tls_session);
	return 1;
}

static void eap_peap_soh_verify(REQUEST *request, RADIUS_PACKET *packet,
			  	uint8_t const *data, unsigned int data_len) {

	VALUE_PAIR *vp;
	uint8_t eap_method_base;
	uint32_t eap_vendor;
	uint32_t eap_method;
	int rv;

	MEM(vp = fr_pair_afrom_da(packet, attr_soh_supported));
	vp->vp_bool = false;
	fr_pair_add(&packet->vps, vp);

	if (data && data[0] == FR_EAP_NAK) {
		RDEBUG("SoH - client NAKed");
		return;
	}

	if (!data || data_len < 8) {
		RDEBUG("SoH - eap payload too short");
		return;
	}

	eap_method_base = *data++;
	if (eap_method_base != 254) {
		RDEBUG("SoH - response is not extended EAP: %i", eap_method_base);
		return;
	}

	eap_vendor = soh_pull_be_24(data); data += 3;
	if (eap_vendor != 0x137) {
		RDEBUG("SoH - extended eap vendor %08x is not Microsoft", eap_vendor);
		return;
	}

	eap_method = soh_pull_be_32(data); data += 4;
	if (eap_method != 0x21) {
		RDEBUG("SoH - response eap type %08x is not EAP-SoH", eap_method);
		return;
	}


	rv = soh_verify(request, data, data_len - 8);
	if (rv<0) {
		RDEBUG("SoH - error decoding payload: %s", fr_strerror());
	} else {
		vp->vp_uint32 = 1;
	}
}


/*
 *	Verify the tunneled EAP message.
 */
static int eap_peap_verify(REQUEST *request, peap_tunnel_t *peap_tunnel,
			   uint8_t const *data, size_t data_len)
{
	eap_packet_raw_t const	*eap_packet = (eap_packet_raw_t const *) data;
	eap_type_t		eap_method;

	/*
	 *	No data, OR only 1 byte of EAP type.
	 */
	if (!data || (data_len == 0) || ((data_len <= 1) && (data[0] != FR_EAP_IDENTITY))) return 0;

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
	case FR_EAP_IDENTITY:
		RDEBUG2("Received EAP-Identity-Response");
		return 0;

	/*
	 *	We normally do Microsoft MS-CHAPv2 (26), versus
	 *	Cisco MS-CHAPv2 (29).
	 */
	case FR_EAP_MSCHAPV2:
	default:
		RDEBUG2("EAP method %s (%d)", eap_type2name(eap_method), eap_method);
		return 0;
	}

}

/*
 *	Convert a pseudo-EAP packet to a list of VALUE_PAIR's.
 */
static VALUE_PAIR *eap_peap_inner_to_pairs(UNUSED REQUEST *request, RADIUS_PACKET *packet,
			  		   eap_round_t *eap_round,
			  		   uint8_t const *data, size_t data_len)
{
	size_t 		total;
	uint8_t		*p;
	VALUE_PAIR	*vp = NULL, *head = NULL;
	fr_cursor_t	cursor;

	if (data_len > 65535) return NULL; /* paranoia */

	vp = fr_pair_afrom_da(packet, attr_eap_message);
	if (!vp) {
		return NULL;
	}

	total = data_len;
	if (total > 249) total = 249;

	/*
	 *	Hand-build an EAP packet from the crap in PEAP version 0.
	 */
	p = talloc_array(vp, uint8_t, EAP_HEADER_LEN + total);
	p[0] = FR_EAP_CODE_RESPONSE;
	p[1] = eap_round->response->id;
	p[2] = (data_len + EAP_HEADER_LEN) >> 8;
	p[3] = (data_len + EAP_HEADER_LEN) & 0xff;
	memcpy(p + EAP_HEADER_LEN, data, total);
	fr_pair_value_memsteal(vp, p);

	fr_cursor_init(&cursor, &head);
	fr_cursor_append(&cursor, vp);
	while (total < data_len) {
		vp = fr_pair_afrom_da(packet, attr_eap_message);
		if (!vp) {
			fr_pair_list_free(&head);
			return NULL;
		}

		fr_pair_value_memcpy(vp, data + total, (data_len - total));

		total += vp->vp_length;

		fr_cursor_append(&cursor, vp);
	}

	return head;
}


/*
 *	Convert a list of VALUE_PAIR's to an EAP packet, through the
 *	simple expedient of dumping the EAP message
 */
static int eap_peap_inner_from_pairs(REQUEST *request, tls_session_t *tls_session, VALUE_PAIR *vp)
{
	rad_assert(vp != NULL);
	VALUE_PAIR *this;
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

	tls_session_send(request, tls_session);

	return 1;
}


/*
 *	See if there's a TLV in the response.
 */
static int eap_peap_check_tlv(REQUEST *request, uint8_t const *data, size_t data_len)
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

	RDEBUG("Unknown TLV %02x", data[10]);

	return 0;
}


/*
 *	Use a reply packet to determine what to do.
 */
static rlm_rcode_t CC_HINT(nonnull) process_reply(eap_session_t *eap_session, tls_session_t *tls_session,
						  REQUEST *request, RADIUS_PACKET *reply)
{
	rlm_rcode_t rcode = RLM_MODULE_REJECT;
	VALUE_PAIR *vp;
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
		eap_peap_success(eap_session, tls_session);
		rcode = RLM_MODULE_HANDLED;
		break;

	case FR_CODE_ACCESS_REJECT:
		RDEBUG2("Tunneled authentication was rejected");
		t->status = PEAP_STATUS_SENT_TLV_FAILURE;
		eap_peap_failure(eap_session, tls_session);
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
		fr_pair_list_copy_by_da(t, &vp, reply->vps, attr_eap_message);

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

#ifdef WITH_PROXY
/*
 *	Do post-proxy processing,
 */
static int CC_HINT(nonnull) eap_peap_postproxy(eap_session_t *eap_session, void *data)
{
	int rcode;
	tls_session_t *tls_session = talloc_get_type_abort(data, tls_session_t);
	REQUEST *fake, *request = eap_session->request;

	RDEBUG2("Passing reply from proxy back into the tunnel");

	/*
	 *	If there was a fake request associated with the proxied
	 *	request, do more processing of it.
	 */
	fake = (REQUEST *) request_data_get(eap_session->request,
					    eap_session->request->proxy,
					    REQUEST_DATA_EAP_MSCHAP_TUNNEL_CALLBACK);

	/*
	 *	Do the callback, if it exists, and if it was a success.
	 */
	if (fake && (eap_session->request->proxy->reply->code == FR_CODE_ACCESS_ACCEPT)) {
		peap_tunnel_t *t = tls_session->opaque;

		t->home_access_accept = true;

		/*
		 *	Terrible hacks.
		 */
		rad_assert(!fake->packet);
		fake->packet = talloc_steal(fake, request->proxy->packet);
		fake->packet->src_ipaddr = request->packet->src_ipaddr;
		request->proxy->packet = NULL;

		rad_assert(!fake->reply);
		fake->reply = talloc_steal(fake, request->proxy->reply);
		request->proxy->reply = NULL;

		if ((rad_debug_lvl > 0) && fr_log_fp) {
			fprintf(fr_log_fp, "server %s {\n", cf_section_name2(fake->server_cs));
		}

		/*
		 *	Perform a post-auth stage, which will get the EAP
		 *	eap_session, too...
		 */
		fake->options &= ~RAD_REQUEST_OPTION_PROXY_EAP;
		RDEBUG2("Passing reply back for EAP-MS-CHAP-V2");
		process_post_proxy(0, fake);

		/*
		 *	FIXME: If rcode returns fail, do something
		 *	intelligent...
		 */
		rcode = rad_postauth(fake);

		if ((rad_debug_lvl > 0) && fr_log_fp) {
			fprintf(fr_log_fp, "} # server %s\n", cf_section_name2(fake->server_cs));

			RDEBUG("Final reply from tunneled session code %d", fake->reply->code);
			log_request_pair_list(L_DBG_LVL_1, request, fake->reply->vps, NULL);
		}

		/*
		 *	Terrible hacks.
		 */
		request->proxy->packet = talloc_steal(request->proxy, fake->packet);
		fake->packet = NULL;
		request->proxy->reply = talloc_steal(request->proxy, fake->reply);
		fake->reply = NULL;

		/*
		 *	And we're done with this request.
		 */

		switch (rcode) {
		case RLM_MODULE_FAIL:
			talloc_free(fake);
			eap_tls_fail(eap_session);
			return 0;

		default:  /* Don't Do Anything */
			RDEBUG2("Got reply %d", request->proxy->reply->code);
			break;
		}
	}
	talloc_free(fake);	/* robust if !fake */

	/*
	 *	If there was no EAP-Message in the reply packet, then
	 *	we know that we're supposed to re-run the "authenticate"
	 *	stage, in order to get the right kind of handling...
	 */

	/*
	 *	Process the reply from the home server.
	 */

	rcode = process_reply(eap_session, tls_session, eap_session->request,
			      eap_session->request->proxy->reply);

	/*
	 *	The proxy code uses the reply from the home server as
	 *	the basis for the reply to the NAS.  We don't want that,
	 *	so we toss it, after we've had our way with it.
	 */
	fr_pair_list_free(&eap_session->request->proxy->reply->vps);

	switch (rcode) {
	case RLM_MODULE_REJECT:
		RDEBUG2("Reply was rejected");
		eap_tls_fail(eap_session);
		return 0;

	case RLM_MODULE_HANDLED:
		RDEBUG2("Reply was handled");
		eap_tls_request(eap_session);
		request->proxy->reply->code = FR_CODE_ACCESS_CHALLENGE;
		return 1;

	case RLM_MODULE_OK:
		RDEBUG2("Reply was OK");

		/*
		 *	Success: Automatically return MPPE keys.
		 */
		if (eap_tls_success(eap_session) < 0) return 0;
		return 1;

	default:
		RDEBUG2("Reply was unknown");
		break;
	}

	eap_tls_fail(eap_session);
	return 0;
}
#endif


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
rlm_rcode_t eap_peap_process(eap_session_t *eap_session, tls_session_t *tls_session, fr_dict_enum_t const *enumv)
{
	peap_tunnel_t	*t = tls_session->opaque;
	REQUEST		*fake = NULL;
	VALUE_PAIR	*vp;
	rlm_rcode_t	rcode = RLM_MODULE_REJECT;
	uint8_t const	*data;
	size_t		data_len;

	REQUEST *request = eap_session->request;
	eap_round_t *eap_round = eap_session->this_round;

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
		return RLM_MODULE_REJECT;
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
				eap_peap_soh(eap_session, tls_session);

				rcode = RLM_MODULE_HANDLED;
				goto finish;
			}
			/* we're good, send success TLV */
			t->status = PEAP_STATUS_SENT_TLV_SUCCESS;
			eap_peap_success(eap_session, tls_session);

		} else {
			/* send an identity request */
			t->session_resumption_state = PEAP_RESUMPTION_NO;
			t->status = PEAP_STATUS_INNER_IDENTITY_REQ_SENT;
			eap_peap_identity(eap_session, tls_session);
		}
		rcode = RLM_MODULE_HANDLED;
		goto finish;

	case PEAP_STATUS_INNER_IDENTITY_REQ_SENT:
		/* we're expecting an identity response */
		if (data[0] != FR_EAP_IDENTITY) {
			REDEBUG("Expected EAP-Identity, got something else");
			rcode = RLM_MODULE_REJECT;
			goto finish;
		}

		/*
		 *	Save it for later.
		 */
		t->username = fr_pair_afrom_da(t, attr_user_name);
		rad_assert(t->username != NULL);
		t->username->vp_tainted = true;

		fr_pair_value_bstrncpy(t->username, data + 1, data_len - 1);

		RDEBUG("Got inner identity \"%pV\"", &t->username->data);
		if (t->soh) {
			t->status = PEAP_STATUS_WAIT_FOR_SOH_RESPONSE;
			RDEBUG2("Requesting SoH from client");
			eap_peap_soh(eap_session, tls_session);
			rcode = RLM_MODULE_HANDLED;
			goto finish;
		}
		t->status = PEAP_STATUS_PHASE2_INIT;
		break;

	case PEAP_STATUS_WAIT_FOR_SOH_RESPONSE:
		fake = request_alloc_fake(request);
		rad_assert(!fake->packet->vps);
		eap_peap_soh_verify(fake, fake->packet, data, data_len);
		setup_fake_request(request, fake, t);

		if (t->soh_virtual_server) fake->server_cs = virtual_server_find(t->soh_virtual_server);

		RDEBUG("Sending SoH request to server %s",
		       fake->server_cs ? cf_section_name2(fake->server_cs) : "NULL");
		rad_virtual_server(fake);

		if (fake->reply->code != FR_CODE_ACCESS_ACCEPT) {
			RDEBUG2("SoH was rejected");
			TALLOC_FREE(fake);
			t->status = PEAP_STATUS_SENT_TLV_FAILURE;
			eap_peap_failure(eap_session, tls_session);
			rcode = RLM_MODULE_HANDLED;
			goto finish;
		}

		/* save the SoH VPs */
		rad_assert(!t->soh_reply_vps);
		MEM(fr_pair_list_copy(t, &t->soh_reply_vps, fake->reply->vps) >= 0);
		rad_assert(!fake->reply->vps);
		TALLOC_FREE(fake);

		if (t->session_resumption_state == PEAP_RESUMPTION_YES) {
			/* we're good, send success TLV */
			t->status = PEAP_STATUS_SENT_TLV_SUCCESS;
			eap_peap_success(eap_session, tls_session);
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

			eap_peap_identity(eap_session, tls_session);
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

		return RLM_MODULE_REJECT;

		case PEAP_STATUS_PHASE2_INIT:
			RDEBUG("In state machine in phase2 init?");

		case PEAP_STATUS_PHASE2:
			break;

		default:
			REDEBUG("Unhandled state in peap");
			rcode = RLM_MODULE_REJECT;
			goto finish;
	}

	fake = request_alloc_fake(request);
	rad_assert(!fake->packet->vps);

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

		rad_assert(t->username);

		len = t->username->vp_length + EAP_HEADER_LEN + 1;
		t->status = PEAP_STATUS_PHASE2;

		vp = fr_pair_afrom_da(fake->packet, attr_eap_message);

		q = talloc_array(vp, uint8_t, len);
		q[0] = FR_EAP_CODE_RESPONSE;
		q[1] = eap_round->response->id;
		q[2] = (len >> 8) & 0xff;
		q[3] = len & 0xff;
		q[4] = FR_EAP_IDENTITY;
		memcpy(q + EAP_HEADER_LEN + 1,
		       t->username->vp_strvalue, t->username->vp_length);

		fr_pair_value_memsteal(vp, q);
		fr_pair_add(&fake->packet->vps, vp);
	}
		break;

	case PEAP_STATUS_PHASE2:
		fake->packet->vps = eap_peap_inner_to_pairs(request, fake->packet,
							    eap_round, data, data_len);
		if (!fake->packet->vps) {
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
	log_request_pair_list(L_DBG_LVL_2, request, fake->packet->vps, NULL);

	/*
	 *	Update other items in the REQUEST data structure.
	 */
	if (!t->username) {
		/*
		 *	There's no User-Name in the tunneled session,
		 *	so we add one here, by pulling it out of the
		 *	EAP-Identity packet.
		 */
		if ((data[0] == FR_EAP_IDENTITY) && (data_len > 1)) {
			t->username = fr_pair_afrom_da(t, attr_user_name);
			rad_assert(t->username != NULL);
			t->username->vp_tainted = true;

			fr_pair_value_bstrncpy(t->username, data + 1, data_len - 1);

			RDEBUG2("Got tunneled identity of %s", t->username->vp_strvalue);
		}
	} /* else there WAS a t->username */

	setup_fake_request(request, fake, t);

	/*
	 *	Call authentication recursively, which will
	 *	do PAP, CHAP, MS-CHAP, etc.
	 */
	eap_virtual_server(request, fake, eap_session, t->virtual_server);

	/*
	 *	Decide what to do with the reply.
	 */
	switch (fake->reply->code) {
	case 0:			/* No reply code, must be proxied... */
#ifdef WITH_PROXY
		vp = fr_pair_find_by_da(fake->control, attr_proxy_to_realm, TAG_ANY);

		if (vp) {
			eap_tunnel_data_t *tunnel;
			int ret;

			/*
			 *	The tunneled request was NOT handled,
			 *	it has to be proxied.  This means that
			 *	the "authenticate" stage was never
			 *	performed.
			 *
			 *	If we are told to NOT proxy the
			 *	tunneled request as EAP, then this
			 *	means that we've got to decode it,
			 *	which means that we MUST run the
			 *	"authenticate" portion by hand, here.
			 *
			 *	Once the tunneled EAP session is ALMOST
			 *	done, THEN we proxy it...
			 */
			if (!t->proxy_tunneled_request_as_eap) {
				CONF_SECTION *unlang;
				fake->options |= RAD_REQUEST_OPTION_PROXY_EAP;

				/*
				 *	Hmm... should we check for
				 *	Auth-Type & EAP-Message here?
				 */

				if (!enumv) {
					RERROR("You must set 'inner_eap_module' in the 'peap' configuration");
					RERROR("This is required in order to proxy the inner EAP session.");
					rcode = RLM_MODULE_REJECT;
					goto finish;
				}

				/*
				 *	Run the EAP authentication.
				 */
				RDEBUG2("Calling authenticate in order to initiate tunneled EAP session");

				unlang = cf_section_find(request->server_cs, "authenticate", enumv->alias);
				if (!unlang) {
					rcode = process_authenticate(enumv->value->vb_uint32, fake);
				} else {
					unlang_push_section(request, unlang, RLM_MODULE_FAIL, UNLANG_TOP_FRAME);
					rcode = unlang_interpret_continue(request);
				}

				if (rcode == RLM_MODULE_OK) {
					/*
					 *	Authentication succeeded! Rah!
					 */
					fake->reply->code = FR_CODE_ACCESS_ACCEPT;
					goto do_process;
				}

				if (rcode != RLM_MODULE_HANDLED) {
					RDEBUG("Can't handle the return code %d", rcode);
					rcode = RLM_MODULE_REJECT;
					goto finish;
				}

				/*
				 *	The module decided it wasn't
				 *	finish.  Handle it like normal.
				 */
				if ((fake->options & RAD_REQUEST_OPTION_PROXY_EAP) == 0) {
					RDEBUG2("Cancelling proxy to realm %s until the tunneled EAP session "
						"has been established", vp->vp_strvalue);
					goto do_process;
				}

				/*
				 *	The module has decoded the
				 *	EAP-Message into another set
				 *	of attributes.
				 */
				fr_pair_delete_by_da(&fake->packet->vps, attr_eap_message);
			}

			RDEBUG2("Tunnelled authentication will be proxied to %s", vp->vp_strvalue);

			/*
			 *	Tell the original request that it's going
			 *	to be proxied.
			 */
			fr_pair_list_copy_by_da(request, &request->control, fake->control, attr_proxy_to_realm);

			/*
			 *	Seed the proxy packet with the
			 *	tunneled request.
			 */
			rad_assert(!request->proxy);

			request->proxy = request_alloc_proxy(request);

			request->proxy->packet = talloc_steal(request->proxy, fake->packet);
			memset(&request->proxy->packet->src_ipaddr, 0, sizeof(request->proxy->packet->src_ipaddr));
			memset(&request->proxy->packet->dst_ipaddr, 0, sizeof(request->proxy->packet->dst_ipaddr));
			request->proxy->packet->src_port = 0;
			request->proxy->packet->dst_port = 0;
			fake->packet = NULL;
			fr_radius_packet_free(&fake->reply);
			fake->reply = NULL;

			/*
			 *	Set up the callbacks for the tunnel
			 */
			tunnel = talloc_zero(request, eap_tunnel_data_t);
			tunnel->tls_session = tls_session;
			tunnel->callback = eap_peap_postproxy;

			/*
			 *	Associate the callback with the request.
			 */
			ret = request_data_add(request, request->proxy, REQUEST_DATA_EAP_TUNNEL_CALLBACK,
					       tunnel, false, false, false);
			fr_cond_assert(ret == 0);

			/*
			 *	We're not proxying it as EAP, so we've got
			 *	to do the callback later.
			 */
			if ((fake->options & RAD_REQUEST_OPTION_PROXY_EAP) != 0) {
				RDEBUG2("Remembering to do EAP-MS-CHAP-V2 post-proxy");

				/*
				 *	rlm_eap.c has taken care of associating
				 *	the eap_session with the fake request.
				 *
				 *	So we associate the fake request with
				 *	this request.
				 */
				ret = request_data_add(request, request->proxy,
						       REQUEST_DATA_EAP_MSCHAP_TUNNEL_CALLBACK,
						       fake, true, false, false);
				fr_cond_assert(ret == 0);

				/*
				 *	Do NOT free the fake request!
				 */
				rcode = RLM_MODULE_UPDATED;
				goto finish;
			}

			/*
			 *	Didn't authenticate the packet, but
			 *	we're proxying it.
			 */
			rcode = RLM_MODULE_UPDATED;

		} else
#endif	/* WITH_PROXY */
		{
			REDEBUG("Unknown RADIUS packet type %d: rejecting tunneled user", fake->reply->code);
			rcode = RLM_MODULE_REJECT;
		}
		break;

	default:
#ifdef WITH_PROXY
	do_process:
#endif
		rcode = process_reply(eap_session, tls_session, request, fake->reply);
		break;
	}

finish:
	talloc_free(fake);

	return rcode;
}

static int CC_HINT(nonnull) setup_fake_request(REQUEST *request, REQUEST *fake, peap_tunnel_t *t) {

	VALUE_PAIR *vp;

	/*
	 *	Tell the request that it's a fake one.
	 */
	MEM(fr_pair_add_by_da(fake->packet, &vp, &fake->packet->vps, attr_freeradius_proxied_to) >= 0);
	fr_pair_value_from_str(vp, "127.0.0.1", sizeof("127.0.0.1"), '\0', false);

	if (t->username) {
		vp = fr_pair_copy(fake->packet, t->username);
		fr_pair_add(&fake->packet->vps, vp);
		fake->username = vp;
		RDEBUG2("Setting &request:User-Name from tunneled (inner) identity \"%s\"",
			fake->username->vp_strvalue);
	} else {
		RDEBUG2("No tunnel username (SSL resumption?)");
	}

	return 0;
}
