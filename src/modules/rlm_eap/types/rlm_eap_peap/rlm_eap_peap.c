/*
 * rlm_eap_peap.c  contains the interfaces that are called from eap
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
 * @copyright 2003 Alan DeKok (aland@freeradius.org)
 * @copyright 2006 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/eap/tls.h>

typedef struct {
	SSL_CTX		*ssl_ctx;			//!< Thread local SSL_CTX.
} rlm_eap_peap_thread_t;

typedef struct {
	char const		*tls_conf_name;		//!< TLS configuration.
	fr_tls_conf_t		*tls_conf;

	bool			use_tunneled_reply;	//!< Use the reply attributes from the tunneled session in
							//!< the non-tunneled reply to the client.

	bool			copy_request_to_tunnel;	//!< Use SOME of the request attributes from outside of the
							//!< tunneled session in the tunneled request.

	virtual_server_t	*virtual_server;	//!< Virtual server for inner tunnel session.
	CONF_SECTION		*server_cs;

	bool			req_client_cert;	//!< Do we do require a client cert?
} rlm_eap_peap_t;

typedef enum {
	PEAP_STATUS_INVALID,
	PEAP_STATUS_SENT_TLV_SUCCESS,
	PEAP_STATUS_SENT_TLV_FAILURE,
	PEAP_STATUS_TUNNEL_ESTABLISHED,
	PEAP_STATUS_INNER_IDENTITY_REQ_SENT,
	PEAP_STATUS_PHASE2_INIT,
	PEAP_STATUS_PHASE2,
} peap_status;

typedef enum {
	PEAP_RESUMPTION_NO,
	PEAP_RESUMPTION_YES,
	PEAP_RESUMPTION_MAYBE
} peap_resumption;

typedef struct {
	fr_pair_t	*username;
	peap_status	status;
	bool		home_access_accept;
	int		default_method;
	peap_resumption	session_resumption_state;
} peap_tunnel_t;

#define EAP_TLV_SUCCESS (1)
#define EAP_TLV_FAILURE (2)
#define EAP_TLV_ACK_RESULT (3)

#define FR_PEAP_EXTENSIONS_TYPE 33

static conf_parser_t submodule_config[] = {
	{ FR_CONF_OFFSET("tls", rlm_eap_peap_t, tls_conf_name) },

	{ FR_CONF_DEPRECATED("copy_request_to_tunnel", rlm_eap_peap_t, NULL), .dflt = "no" },

	{ FR_CONF_DEPRECATED("use_tunneled_reply", rlm_eap_peap_t, NULL), .dflt = "no" },

	{ FR_CONF_OFFSET_TYPE_FLAGS("virtual_server", FR_TYPE_VOID, CONF_FLAG_REQUIRED | CONF_FLAG_NOT_EMPTY, rlm_eap_peap_t, virtual_server),
				    .func = virtual_server_cf_parse,
				    .uctx = &(virtual_server_cf_parse_uctx_t){ .process_module_name = "radius"} },
	{ FR_CONF_OFFSET("require_client_cert", rlm_eap_peap_t, req_client_cert), .dflt = "no" },

	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t rlm_eap_peap_dict[];
fr_dict_autoload_t rlm_eap_peap_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	DICT_AUTOLOAD_TERMINATOR
};

static fr_dict_attr_t const *attr_auth_type;
static fr_dict_attr_t const *attr_eap_tls_require_client_cert;

static fr_dict_attr_t const *attr_eap_message;
static fr_dict_attr_t const *attr_user_name;

extern fr_dict_attr_autoload_t rlm_eap_peap_dict_attr[];
fr_dict_attr_autoload_t rlm_eap_peap_dict_attr[] = {
	{ .out = &attr_auth_type, .name = "Auth-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_eap_tls_require_client_cert, .name = "EAP-TLS-Require-Client-Cert", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },

	{ .out = &attr_eap_message, .name = "EAP-Message", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_radius },
	DICT_AUTOLOAD_TERMINATOR
};


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
static void eap_peap_inner_to_pairs(TALLOC_CTX *ctx, fr_pair_list_t *pairs,
			  	    eap_round_t *eap_round,
				    uint8_t const *data, size_t data_len)
{
	size_t 		total;
	uint8_t		*p;
	fr_pair_t	*vp = NULL;

	if (data_len > 65535) return; /* paranoia */

	MEM(vp = fr_pair_afrom_da(ctx, attr_eap_message));
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

	fr_pair_append(pairs, vp);
	while (total < data_len) {
		MEM(vp = fr_pair_afrom_da(ctx, attr_eap_message));
		fr_pair_value_memdup(vp, data + total, (data_len - total), false);

		total += vp->vp_length;

		fr_pair_append(pairs, vp);
	}
}


/*
 *	Convert a list of fr_pair_t's to an EAP packet, through the
 *	simple expedient of dumping the EAP message
 */
static int eap_peap_inner_from_pairs(request_t *request, fr_tls_session_t *tls_session, fr_pair_list_t *vps)
{
	fr_pair_t *this;

	fr_assert(!fr_pair_list_empty(vps));

	/*
	 *	Send the EAP data in the first attribute, WITHOUT the
	 *	header.
	 */
	this = fr_pair_list_head(vps);
	(tls_session->record_from_buff)(&tls_session->clean_in, this->vp_octets + EAP_HEADER_LEN,
					this->vp_length - EAP_HEADER_LEN);

	/*
	 *	Send the rest of the EAP data, but skipping the first VP.
	 */
	for (this = fr_pair_list_next(vps, this);
	     this;
	     this = fr_pair_list_next(vps, this)) {
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
static unlang_action_t process_reply(unlang_result_t *p_result, request_t *request, UNUSED void *uctx)
{
	eap_session_t		*eap_session = talloc_get_type_abort(uctx, eap_session_t);
	eap_tls_session_t	*eap_tls_session = talloc_get_type_abort(eap_session->opaque, eap_tls_session_t);
	fr_tls_session_t	*tls_session = eap_tls_session->tls_session;
	fr_pair_list_t		vps;
	peap_tunnel_t		*t = tls_session->opaque;
	request_t		*parent = request->parent;
	fr_packet_t		*reply = request->reply;

	p_result->priority = MOD_PRIORITY_MAX;

	if (RDEBUG_ENABLED2) {

		/*
		 *	Note that we don't do *anything* with the reply
		 *	attributes.
		 */
		if (FR_RADIUS_PACKET_CODE_VALID(reply->code)) {
			RDEBUG2("Got tunneled reply %s", fr_radius_packet_name[reply->code]);
		} else {
			RDEBUG2("Got tunneled reply code %i", reply->code);
		}
		log_request_pair_list(L_DBG_LVL_2, request, NULL, &request->reply_pairs, NULL);
	}

	switch (reply->code) {
	case FR_RADIUS_CODE_ACCESS_ACCEPT:
		RDEBUG2("Tunneled authentication was successful");
		t->status = PEAP_STATUS_SENT_TLV_SUCCESS;
		eap_peap_success(request, eap_session, tls_session);
		RETURN_UNLANG_HANDLED;

	case FR_RADIUS_CODE_ACCESS_REJECT:
		RDEBUG2("Tunneled authentication was rejected");
		t->status = PEAP_STATUS_SENT_TLV_FAILURE;
		eap_peap_failure(request, eap_session, tls_session);
		RETURN_UNLANG_HANDLED;

	case FR_RADIUS_CODE_ACCESS_CHALLENGE:
		RDEBUG2("Got tunneled Access-Challenge");

		/*
		 *	PEAP takes only EAP-Message attributes inside
		 *	of the tunnel.  Any Reply-Message in the
		 *	Access-Challenge is ignored.
		 */
		fr_pair_list_init(&vps);
		MEM(fr_pair_list_copy_by_da(t, &vps, &request->reply_pairs, attr_eap_message, 0) >= 0);

		/*
		 *	Handle the ACK, by tunneling any necessary reply
		 *	VP's back to the client.
		 */
		if (!fr_pair_list_empty(&vps)) {
			eap_peap_inner_from_pairs(parent, tls_session, &vps);
			fr_pair_list_free(&vps);
		}
		RETURN_UNLANG_HANDLED;

	default:
		RDEBUG2("Unknown RADIUS packet type %d: rejecting tunneled user", reply->code);
		RETURN_UNLANG_REJECT;
	}
}


static char const *peap_state(peap_tunnel_t *t)
{
	switch (t->status) {
	case PEAP_STATUS_TUNNEL_ESTABLISHED:
		return "TUNNEL ESTABLISHED";

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
static unlang_action_t eap_peap_process(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request,
					eap_session_t *eap_session, fr_tls_session_t *tls_session)
{
	peap_tunnel_t	*t = tls_session->opaque;
	request_t	*child = NULL;
	fr_pair_t	*vp;
	rlm_rcode_t	rcode = RLM_MODULE_REJECT;
	uint8_t const	*data;
	size_t		data_len;
	eap_round_t	*eap_round = eap_session->this_round;
	rlm_eap_peap_t	*inst = talloc_get_type_abort(mctx->mi->data, rlm_eap_peap_t);

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
		RETURN_UNLANG_REJECT;
	}

	switch (t->status) {
	case PEAP_STATUS_TUNNEL_ESTABLISHED:
		/* FIXME: should be no data in the buffer here, check & assert? */

		if (SSL_session_reused(tls_session->ssl)) {
			RDEBUG2("Skipping Phase2 because of session resumption");
			t->session_resumption_state = PEAP_RESUMPTION_YES;
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

		RETURN_UNLANG_REJECT;

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

	MEM(child = unlang_subrequest_alloc(request, request->proto_dict));
	fr_assert(fr_pair_list_empty(&child->request_pairs));

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

		MEM(vp = fr_pair_afrom_da(child->request_ctx, attr_eap_message));
		MEM(fr_pair_value_mem_alloc(vp, &q, len, false) == 0);
		q[0] = FR_EAP_CODE_RESPONSE;
		q[1] = eap_round->response->id;
		q[2] = (len >> 8) & 0xff;
		q[3] = len & 0xff;
		q[4] = FR_EAP_METHOD_IDENTITY;
		memcpy(q + EAP_HEADER_LEN + 1,
		       t->username->vp_strvalue, t->username->vp_length);
		fr_pair_append(&child->request_pairs, vp);
	}
		break;

	case PEAP_STATUS_PHASE2:
		eap_peap_inner_to_pairs(child->request_ctx, &child->request_pairs,
					eap_round, data, data_len);
		if (fr_pair_list_empty(&child->request_pairs)) {
			TALLOC_FREE(child);
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
	log_request_pair_list(L_DBG_LVL_2, request, NULL, &child->request_pairs, NULL);

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

	if (t->username) {
		vp = fr_pair_copy(child->request_ctx, t->username);
		fr_pair_append(&child->request_pairs, vp);
		RDEBUG2("Setting request.User-Name from tunneled (inner) identity \"%s\"",
			vp->vp_strvalue);
	} else {
		RDEBUG2("No tunnel username (SSL resumption?)");
	}

	/*
	 *	Set the child up for execution.  This represents
	 *	a pseudo protocol inside of PEAPs inner EAP method.
	 */
	if (unlang_subrequest_child_push(&eap_session->submodule_result, child,
					 child,
					 false, UNLANG_SUB_FRAME) < 0) goto finish;

	/*
	 *	Setup a function in thie child to process the
	 *	result of the subrequest.
	 */
	if (unlang_function_push_with_result(NULL,
				 	     child,
					     NULL,
					     /*
					      *	Run in the child after the virtual sever executes.
					      *	This sets the rcode for the subrequest, which is
					      *	written to eap_session->submodule_result.
					      */
					     process_reply,
					     NULL, 0,
					     UNLANG_SUB_FRAME, eap_session) != UNLANG_ACTION_PUSHED_CHILD) goto finish;

	/*
	 *	Run inner tunnel in the context of the child
	 */
	if (unlikely(eap_virtual_server(child, eap_session, inst->virtual_server) == UNLANG_ACTION_FAIL)) {
		rcode = RLM_MODULE_FAIL;
		goto finish;
	}

	/*
	 *	We now yield to the subrequest.  unlang_subrequest_child_push
	 *	pushed a new frame in the context of the parent which'll start
	 *	the subrequest.
	 */
	return UNLANG_ACTION_PUSHED_CHILD;

finish:
	if (child) {
		/*
		 *	We can't just free the child, we need to detach it
		 *	and then let the interpreter to unwind and eventually
		 *	free the request.
		 */
		request_detach(child);
		unlang_interpret_signal(child, FR_SIGNAL_CANCEL);
	}

	RETURN_UNLANG_RCODE(rcode);
}

/*
 *	Allocate the PEAP per-session data
 */
static peap_tunnel_t *peap_alloc(TALLOC_CTX *ctx)
{
	peap_tunnel_t *t;

	t = talloc_zero(ctx, peap_tunnel_t);
	t->session_resumption_state = PEAP_RESUMPTION_MAYBE;

	return t;
}

/*
 *	Construct the reply appropriately based on the rcode from PEAP processing.
 */
static unlang_action_t process_rcode(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	eap_session_t		*eap_session = talloc_get_type_abort(mctx->rctx, eap_session_t);
	eap_tls_session_t	*eap_tls_session = talloc_get_type_abort(eap_session->opaque, eap_tls_session_t);
	fr_tls_session_t	*tls_session = eap_tls_session->tls_session;

	RDEBUG3("Tunneled request complete");

	switch (eap_session->submodule_result.rcode) {
	case RLM_MODULE_REJECT:
		eap_tls_fail(request, eap_session);
		break;

	case RLM_MODULE_HANDLED:
		eap_tls_request(request, eap_session);
		break;

	case RLM_MODULE_OK:
	{
		eap_tls_prf_label_t prf_label;

		eap_crypto_prf_label_init(&prf_label, eap_session,
					  "client EAP encryption",
					  sizeof("client EAP encryption") - 1);

		/*
		 *	Success: Automatically return MPPE keys.
		 */
		if (eap_tls_success(request, eap_session, &prf_label) > 0) RETURN_UNLANG_FAIL;
		p_result->rcode = RLM_MODULE_OK;

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
		return fr_tls_cache_pending_push(request, tls_session);
	}

	/*
	 *	No response packet, MUST be proxying it.
	 *	The main EAP module will take care of discovering
	 *	that the request now has a "proxy" packet, and
	 *	will proxy it, rather than returning an EAP packet.
	 */
	case RLM_MODULE_UPDATED:
		break;

	default:
		eap_tls_fail(request, eap_session);
		break;
	}

	RETURN_UNLANG_RCODE(eap_session->submodule_result.rcode);
}

static unlang_action_t mod_handshake_resume(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	eap_session_t		*eap_session = talloc_get_type_abort(mctx->rctx, eap_session_t);
	eap_tls_session_t	*eap_tls_session = talloc_get_type_abort(eap_session->opaque, eap_tls_session_t);
	fr_tls_session_t	*tls_session = eap_tls_session->tls_session;
	peap_tunnel_t		*peap = talloc_get_type_abort(tls_session->opaque, peap_tunnel_t);

	if ((eap_tls_session->state == EAP_TLS_INVALID) || (eap_tls_session->state == EAP_TLS_FAIL)) {
		REDEBUG("[eap-tls process] = %s", fr_table_str_by_value(eap_tls_status_table, eap_tls_session->state, "<INVALID>"));
	} else {
		RDEBUG2("[eap-tls process] = %s", fr_table_str_by_value(eap_tls_status_table, eap_tls_session->state, "<INVALID>"));
	}

	switch (eap_tls_session->state) {
	/*
	 *	EAP-TLS handshake was successful, tell the
	 *	client to keep talking.
	 *
	 *	If this was EAP-TLS, we would just return
	 *	an EAP-TLS-Success packet here.
	 */
	case EAP_TLS_ESTABLISHED:
		peap->status = PEAP_STATUS_TUNNEL_ESTABLISHED;
		break;

	/*
	 *	The TLS code is still working on the TLS
	 *	exchange, and it's a valid TLS request.
	 *	do nothing.
	 */
	case EAP_TLS_HANDLED:
		/*
		 *	FIXME: If the SSL session is established, grab the state
		 *	and EAP id from the inner tunnel, and update it with
		 *	the expected EAP id!
		 */
		RETURN_UNLANG_HANDLED;

	/*
	 *	Handshake is done, proceed with decoding tunneled
	 *	data.
	 */
	case EAP_TLS_RECORD_RECV_COMPLETE:
                /*
                 *     TLSv1.3 makes application data immediately
                 *     available when the handshake is finished.
                 */
		if (SSL_is_init_finished(tls_session->ssl) && (peap->status == PEAP_STATUS_INVALID)) {
			peap->status = PEAP_STATUS_TUNNEL_ESTABLISHED;
		}
		break;

	/*
	 *	Anything else: fail.
	 */
	default:
		RETURN_UNLANG_FAIL;
	}

	/*
	 *	Session is established, proceed with decoding
	 *	tunneled data.
	 */
	RDEBUG2("Session established.  Decoding tunneled data");

	/*
	 *	We may need PEAP data associated with the session, so
	 *	allocate it here, if it wasn't already alloacted.
	 */
	if (!tls_session->opaque) tls_session->opaque = peap_alloc(tls_session);

	/*
	 *	Setup the resume point to prepare the correct reply based on
	 *	the rcode coming back from PEAP processing.
	 */
	(void) unlang_module_yield(request, process_rcode, NULL, 0, eap_session);

	/*
	 *	Process the PEAP portion of the request.
	 */
	return eap_peap_process(&eap_session->submodule_result, mctx, request, eap_session, tls_session);
}

/*
 *	Do authentication, by letting EAP-TLS do most of the work.
 */
static unlang_action_t mod_handshake_process(UNUSED unlang_result_t *p_result, UNUSED module_ctx_t const *mctx,
					     request_t *request)
{
	eap_session_t		*eap_session = eap_session_get(request->parent);

	/*
	 *	Setup the resumption frame to process the result
	 */
	(void)unlang_module_yield(request, mod_handshake_resume, NULL, 0, eap_session);

	/*
	 *	Process TLS layer until done.
	 */
	return eap_tls_process(request, eap_session);
}

static unlang_action_t mod_session_init_resume(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_eap_peap_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_eap_peap_t);
	rlm_eap_peap_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_eap_peap_thread_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);
	eap_tls_session_t	*eap_tls_session;
	fr_tls_session_t	*tls_session;

	fr_pair_t		*vp;
	bool			client_cert;

	/*
	 *	EAP-TLS-Require-Client-Cert attribute will override
	 *	the require_client_cert configuration option.
	 */
	vp = fr_pair_find_by_da(&request->control_pairs, NULL, attr_eap_tls_require_client_cert);
	if (vp) {
		client_cert = vp->vp_uint32 ? true : false;
	} else {
		client_cert = inst->req_client_cert;
	}

	eap_session->opaque = eap_tls_session = eap_tls_session_init(request, eap_session, t->ssl_ctx, client_cert);
	if (!eap_tls_session) RETURN_UNLANG_FAIL;

 	tls_session = eap_tls_session->tls_session;

	/*
	 *	As it is a poorly designed protocol, PEAP uses
	 *	bits in the TLS header to indicate PEAP
	 *	version numbers.  For now, we only support
	 *	PEAP version 0, so it doesn't matter too much.
	 *	However, if we support later versions of PEAP,
	 *	we will need this flag to indicate which
	 *	version we're currently dealing with.
	 */
	eap_tls_session->base_flags = 0x00;

	/*
	 *	PEAP version 0 requires 'include_length = no',
	 *	so rather than hoping the user figures it out,
	 *	we force it here.
	 */
	eap_tls_session->include_length = false;

	/*
	 *	TLS session initialization is over.  Now handle TLS
	 *	related handshaking or application data.
	 */
	if (eap_tls_start(request, eap_session) < 0) {
		talloc_free(eap_tls_session);
		RETURN_UNLANG_FAIL;
	}

	/*
	 *	Session resumption requires the storage of data, so
	 *	allocate it if it doesn't already exist.
	 */
	tls_session->opaque = peap_alloc(tls_session);

	eap_session->process = mod_handshake_process;

	RETURN_UNLANG_HANDLED;
}

/*
 *	Send an initial eap-tls request to the peer, using the libeap functions.
 */
static unlang_action_t mod_session_init(UNUSED unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_eap_peap_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_eap_peap_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);

	eap_session->tls = true;

	(void) unlang_module_yield(request, mod_session_init_resume, NULL, 0, NULL);

	if (inst->tls_conf->new_session) return fr_tls_new_session_push(request, inst->tls_conf);

	return UNLANG_ACTION_CALCULATE_RESULT;
}

static int mod_thread_instantiate(module_thread_inst_ctx_t const *mctx)
{
	rlm_eap_peap_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_eap_peap_t);
	rlm_eap_peap_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_eap_peap_thread_t);

	t->ssl_ctx = fr_tls_ctx_alloc(inst->tls_conf, false);
	if (!t->ssl_ctx) return -1;

	return 0;
}

static int mod_thread_detach(module_thread_inst_ctx_t const *mctx)
{
	rlm_eap_peap_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_eap_peap_thread_t);

	if (likely(t->ssl_ctx != NULL)) SSL_CTX_free(t->ssl_ctx);
	t->ssl_ctx = NULL;

	return 0;
}

/*
 *	Attach the module.
 */
static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_eap_peap_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_eap_peap_t);
	CONF_SECTION		*conf = mctx->mi->conf;

	fr_assert(inst->virtual_server);

	inst->server_cs = virtual_server_cs(inst->virtual_server);

	/*
	 *	Read tls configuration, either from group given by 'tls'
	 *	option, or from the eap-tls configuration.
	 */
	inst->tls_conf = eap_tls_conf_parse(conf);
	if (!inst->tls_conf) {
		cf_log_err(conf, "Failed initializing SSL context");
		return -1;
	}

	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
extern rlm_eap_submodule_t rlm_eap_peap;
rlm_eap_submodule_t rlm_eap_peap = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "eap_peap",
		.inst_size		= sizeof(rlm_eap_peap_t),
		.config			= submodule_config,
		.instantiate		= mod_instantiate,

		.thread_inst_size	= sizeof(rlm_eap_peap_thread_t),
		.thread_instantiate	= mod_thread_instantiate,
		.thread_detach		= mod_thread_detach,
	},
	.provides		= { FR_EAP_METHOD_PEAP },
	.session_init		= mod_session_init,	/* Initialise a new EAP session */
};
