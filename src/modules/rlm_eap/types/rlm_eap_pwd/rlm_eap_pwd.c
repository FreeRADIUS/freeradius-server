/*
 * Copyright (c) Dan Harkins, 2012
 *
 *  Copyright holder grants permission for redistribution and use in source
 *  and binary forms, with or without modification, provided that the
 *  following conditions are met:
 *     1. Redistribution of source code must retain the above copyright
 *	notice, this list of conditions, and the following disclaimer
 *	in all source files.
 *     2. Redistribution in binary form must retain the above copyright
 *	notice, this list of conditions, and the following disclaimer
 *	in the documentation and/or other materials provided with the
 *	distribution.
 *
 *  "DISCLAIMER OF LIABILITY
 *
 *  THIS SOFTWARE IS PROVIDED BY DAN HARKINS ``AS IS'' AND
 *  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 *  THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 *  PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INDUSTRIAL LOUNGE BE LIABLE
 *  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 *  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 *  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 *  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 *  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 *  SUCH DAMAGE."
 *
 * This license and distribution terms cannot be changed. In other words,
 * this code cannot simply be copied and put under a different distribution
 * license (including the GNU public license).
 */

RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#include "rlm_eap_pwd.h"

#include "eap_pwd.h"

#define MPPE_KEY_LEN    32
#define MSK_EMSK_LEN    (2*MPPE_KEY_LEN)

static CONF_PARSER pwd_module_config[] = {
	{ "group", FR_CONF_OFFSET(PW_TYPE_INTEGER, eap_pwd_t, group), "19" },
	{ "fragment_size", FR_CONF_OFFSET(PW_TYPE_INTEGER, eap_pwd_t, fragment_size), "1020" },
	{ "server_id", FR_CONF_OFFSET(PW_TYPE_STRING, eap_pwd_t, server_id), NULL },
	{ "virtual_server", FR_CONF_OFFSET(PW_TYPE_STRING, eap_pwd_t, virtual_server), NULL },
	CONF_PARSER_TERMINATOR
};

static int mod_detach (void *arg)
{
	eap_pwd_t *inst;

	inst = (eap_pwd_t *) arg;

	if (inst->bnctx) BN_CTX_free(inst->bnctx);

	return 0;
}

static int mod_instantiate (CONF_SECTION *cs, void **instance)
{
	eap_pwd_t *inst;

	*instance = inst = talloc_zero(cs, eap_pwd_t);
	if (!inst) return -1;

	if (cf_section_parse(cs, inst, pwd_module_config) < 0) {
		return -1;
	}

	if (inst->fragment_size < 100) {
		cf_log_err_cs(cs, "Fragment size is too small");
		return -1;
	}

	if ((inst->bnctx = BN_CTX_new()) == NULL) {
		cf_log_err_cs(cs, "Failed to get BN context");
		return -1;
	}

	return 0;
}

static int _free_pwd_session (pwd_session_t *session)
{
	BN_clear_free(session->private_value);
	BN_clear_free(session->peer_scalar);
	BN_clear_free(session->my_scalar);
	BN_clear_free(session->k);
	EC_POINT_clear_free(session->my_element);
	EC_POINT_clear_free(session->peer_element);
	EC_GROUP_free(session->group);
	EC_POINT_clear_free(session->pwe);
	BN_clear_free(session->order);
	BN_clear_free(session->prime);

	return 0;
}

static int send_pwd_request (pwd_session_t *session, EAP_DS *eap_ds)
{
	size_t len;
	uint16_t totlen;
	pwd_hdr *hdr;

	len = (session->out_len - session->out_pos) + sizeof(pwd_hdr);
	rad_assert(len > 0);
	eap_ds->request->code = PW_EAP_REQUEST;
	eap_ds->request->type.num = PW_EAP_PWD;
	eap_ds->request->type.length = (len > session->mtu) ? session->mtu : len;
	eap_ds->request->type.data = talloc_zero_array(eap_ds->request, uint8_t, eap_ds->request->type.length);
	hdr = (pwd_hdr *)eap_ds->request->type.data;

	switch (session->state) {
	case PWD_STATE_ID_REQ:
		EAP_PWD_SET_EXCHANGE(hdr, EAP_PWD_EXCH_ID);
		break;

	case PWD_STATE_COMMIT:
		EAP_PWD_SET_EXCHANGE(hdr, EAP_PWD_EXCH_COMMIT);
		break;

	case PWD_STATE_CONFIRM:
		EAP_PWD_SET_EXCHANGE(hdr, EAP_PWD_EXCH_CONFIRM);
		break;

	default:
		ERROR("rlm_eap_pwd: PWD state is invalid.  Can't send request");
		return 0;
	}
	/*
	 * are we fragmenting?
	 */
	if (((session->out_len - session->out_pos) + sizeof(pwd_hdr)) > session->mtu) {
		EAP_PWD_SET_MORE_BIT(hdr);
		if (session->out_pos == 0) {
			/*
			 * the first fragment, add the total length
			 */
			EAP_PWD_SET_LENGTH_BIT(hdr);
			totlen = ntohs(session->out_len);
			memcpy(hdr->data, (char *)&totlen, sizeof(totlen));
			memcpy(hdr->data + sizeof(uint16_t),
			       session->out,
			       session->mtu - sizeof(pwd_hdr) - sizeof(uint16_t));
			session->out_pos += (session->mtu - sizeof(pwd_hdr) - sizeof(uint16_t));
		} else {
			/*
			 * an intermediate fragment
			 */
			memcpy(hdr->data, session->out + session->out_pos, (session->mtu - sizeof(pwd_hdr)));
			session->out_pos += (session->mtu - sizeof(pwd_hdr));
		}
	} else {
		/*
		 * either it's not a fragment or it's the last fragment.
		 * The out buffer isn't needed anymore though so get rid of it.
		 */
		memcpy(hdr->data, session->out + session->out_pos,
		(session->out_len - session->out_pos));
		talloc_free(session->out);
		session->out = NULL;
		session->out_pos = session->out_len = 0;
	}
	return 1;
}

static int mod_session_init (void *instance, eap_handler_t *handler)
{
	pwd_session_t *session;
	eap_pwd_t *inst = (eap_pwd_t *)instance;
	VALUE_PAIR *vp;
	pwd_id_packet_t *packet;

	if (!inst || !handler) {
		ERROR("rlm_eap_pwd: Initiate, NULL data provided");
		return 0;
	}

	/*
	* make sure the server's been configured properly
	*/
	if (!inst->server_id) {
		ERROR("rlm_eap_pwd: Server ID is not configured");
		return 0;
	}
	switch (inst->group) {
	case 19:
	case 20:
	case 21:
	case 25:
	case 26:
		break;

	default:
		ERROR("rlm_eap_pwd: Group is not supported");
		return 0;
	}

	if ((session = talloc_zero(handler, pwd_session_t)) == NULL) return 0;
	talloc_set_destructor(session, _free_pwd_session);
	/*
	 * set things up so they can be free'd reliably
	 */
	session->group_num = inst->group;
	session->private_value = NULL;
	session->peer_scalar = NULL;
	session->my_scalar = NULL;
	session->k = NULL;
	session->my_element = NULL;
	session->peer_element = NULL;
	session->group = NULL;
	session->pwe = NULL;
	session->order = NULL;
	session->prime = NULL;

	/*
	 *	The admin can dynamically change the MTU.
	 */
	session->mtu = inst->fragment_size;
	vp = fr_pair_find_by_num(handler->request->packet->vps, PW_FRAMED_MTU, 0, TAG_ANY);

	/*
	 *	session->mtu is *our* MTU.  We need to subtract off the EAP
	 *	overhead.
	 *
	 *	9 = 4 (EAPOL header) + 4 (EAP header) + 1 (EAP type)
	 *
	 *	The fragmentation code deals with the included length
	 *	so we don't need to subtract that here.
	 */
	if (vp && (vp->vp_integer > 100) && (vp->vp_integer < session->mtu)) {
		session->mtu = vp->vp_integer - 9;
	}

	session->state = PWD_STATE_ID_REQ;
	session->in = NULL;
	session->out_pos = 0;
	handler->opaque = session;

	/*
	 * construct an EAP-pwd-ID/Request
	 */
	session->out_len = sizeof(pwd_id_packet_t) + strlen(inst->server_id);
	if ((session->out = talloc_zero_array(session, uint8_t, session->out_len)) == NULL) {
		return 0;
	}

	packet = (pwd_id_packet_t *)session->out;
	packet->group_num = htons(session->group_num);
	packet->random_function = EAP_PWD_DEF_RAND_FUN;
	packet->prf = EAP_PWD_DEF_PRF;
	session->token = fr_rand();
	memcpy(packet->token, (char *)&session->token, 4);
	packet->prep = EAP_PWD_PREP_NONE;
	memcpy(packet->identity, inst->server_id, session->out_len - sizeof(pwd_id_packet_t) );

	handler->stage = PROCESS;

	return send_pwd_request(session, handler->eap_ds);
}

static int mod_process(void *arg, eap_handler_t *handler)
{
	pwd_session_t *session;
	pwd_hdr *hdr;
	pwd_id_packet_t *packet;
	eap_packet_t *response;
	REQUEST *request, *fake;
	VALUE_PAIR *pw, *vp;
	EAP_DS *eap_ds;
	size_t in_len;
	int ret = 0;
	eap_pwd_t *inst = (eap_pwd_t *)arg;
	uint16_t offset;
	uint8_t exch, *in, *ptr, msk[MSK_EMSK_LEN], emsk[MSK_EMSK_LEN];
	uint8_t peer_confirm[SHA256_DIGEST_LENGTH];
	BIGNUM *x = NULL, *y = NULL;

	if (((eap_ds = handler->eap_ds) == NULL) || !inst) return 0;

	session = (pwd_session_t *)handler->opaque;
	request = handler->request;
	response = handler->eap_ds->response;
	hdr = (pwd_hdr *)response->type.data;

	/*
	 *	The header must be at least one byte.
	 */
	if (!hdr || (response->type.length < sizeof(pwd_hdr))) {
		RDEBUG("Packet with insufficient data");
		return 0;
	}

	in = hdr->data;
	in_len = response->type.length - sizeof(pwd_hdr);

	/*
	* see if we're fragmenting, if so continue until we're done
	*/
	if (session->out_pos) {
		if (in_len) RDEBUG2("pwd got something more than an ACK for a fragment");

		return send_pwd_request(session, eap_ds);
	}

	/*
	* the first fragment will have a total length, make a
	* buffer to hold all the fragments
	*/
	if (EAP_PWD_GET_LENGTH_BIT(hdr)) {
		if (session->in) {
			RDEBUG2("pwd already alloced buffer for fragments");
			return 0;
		}

		if (in_len < 2) {
			RDEBUG("Invalid packet: length bit set, but no length field");
			return 0;
		}

		session->in_len = ntohs(in[0] * 256 | in[1]);
		if ((session->in = talloc_zero_array(session, uint8_t, session->in_len)) == NULL) {
			RDEBUG2("pwd cannot allocate %zd buffer to hold fragments",
				session->in_len);
			return 0;
		}
		memset(session->in, 0, session->in_len);
		session->in_pos = 0;
		in += sizeof(uint16_t);
		in_len -= sizeof(uint16_t);
	}

	/*
	 * all fragments, including the 1st will have the M(ore) bit set,
	 * buffer those fragments!
	 */
	if (EAP_PWD_GET_MORE_BIT(hdr)) {
		rad_assert(session->in != NULL);

		if ((session->in_pos + in_len) > session->in_len) {
			RDEBUG2("Fragment overflows packet.");
			return 0;
		}

		memcpy(session->in + session->in_pos, in, in_len);
		session->in_pos += in_len;

		/*
		 * send back an ACK for this fragment
		 */
		exch = EAP_PWD_GET_EXCHANGE(hdr);
		eap_ds->request->code = PW_EAP_REQUEST;
		eap_ds->request->type.num = PW_EAP_PWD;
		eap_ds->request->type.length = sizeof(pwd_hdr);
		if ((eap_ds->request->type.data = talloc_array(eap_ds->request, uint8_t, sizeof(pwd_hdr))) == NULL) {
			return 0;
		}
		hdr = (pwd_hdr *)eap_ds->request->type.data;
		EAP_PWD_SET_EXCHANGE(hdr, exch);
		return 1;
	}


	if (session->in) {
		/*
		 * the last fragment...
		 */
		if ((session->in_pos + in_len) > session->in_len) {
			RDEBUG2("pwd will not overflow a fragment buffer. Nope, not prudent");
			return 0;
		}
		memcpy(session->in + session->in_pos, in, in_len);
		in = session->in;
		in_len = session->in_len;
	}

	switch (session->state) {
	case PWD_STATE_ID_REQ:
		if (EAP_PWD_GET_EXCHANGE(hdr) != EAP_PWD_EXCH_ID) {
			RDEBUG2("pwd exchange is incorrect: not ID");
			return 0;
		}

		packet = (pwd_id_packet_t *) in;
		if (in_len < sizeof(*packet)) {
			RDEBUG("Packet is too small (%zd < %zd).", in_len, sizeof(*packet));
			return 0;
		}

		if ((packet->prf != EAP_PWD_DEF_PRF) ||
		    (packet->random_function != EAP_PWD_DEF_RAND_FUN) ||
		    (packet->prep != EAP_PWD_PREP_NONE) ||
		    (CRYPTO_memcmp(packet->token, &session->token, 4)) ||
		    (packet->group_num != ntohs(session->group_num))) {
			RDEBUG2("pwd id response is invalid");
			return 0;
		}
		/*
		 * we've agreed on the ciphersuite, record it...
		 */
		ptr = (uint8_t *)&session->ciphersuite;
		memcpy(ptr, (char *)&packet->group_num, sizeof(uint16_t));
		ptr += sizeof(uint16_t);
		*ptr = EAP_PWD_DEF_RAND_FUN;
		ptr += sizeof(uint8_t);
		*ptr = EAP_PWD_DEF_PRF;

		session->peer_id_len = in_len - sizeof(pwd_id_packet_t);
		if (session->peer_id_len >= sizeof(session->peer_id)) {
			RDEBUG2("pwd id response is malformed");
			return 0;
		}

		memcpy(session->peer_id, packet->identity, session->peer_id_len);
		session->peer_id[session->peer_id_len] = '\0';

		/*
		 * make fake request to get the password for the usable ID
		 */
		if ((fake = request_alloc_fake(handler->request)) == NULL) {
			RDEBUG("pwd unable to create fake request!");
			return 0;
		}
		fake->username = fr_pair_afrom_num(fake->packet, PW_USER_NAME, 0);
		if (!fake->username) {
			RDEBUG("Failed creating pair for peer id");
			talloc_free(fake);
			return 0;
		}
		fr_pair_value_bstrncpy(fake->username, session->peer_id, session->peer_id_len);
		fr_pair_add(&fake->packet->vps, fake->username);

		if ((vp = fr_pair_find_by_num(request->config, PW_VIRTUAL_SERVER, 0, TAG_ANY)) != NULL) {
			fake->server = vp->vp_strvalue;
		} else if (inst->virtual_server) {
			fake->server = inst->virtual_server;
		} /* else fake->server == request->server */

		RDEBUG("Sending tunneled request");
		rdebug_pair_list(L_DBG_LVL_1, request, fake->packet->vps, NULL);

		if (fake->server) {
			RDEBUG("server %s {", fake->server);
		} else {
			RDEBUG("server {");
		}

		/*
		 *	Call authorization recursively, which will
		 *	get the password.
		 */
		RINDENT();
		process_authorize(0, fake);
		REXDENT();

		/*
		 *	Note that we don't do *anything* with the reply
		 *	attributes.
		 */
		if (fake->server) {
			RDEBUG("} # server %s", fake->server);
		} else {
			RDEBUG("}");
		}

		RDEBUG("Got tunneled reply code %d", fake->reply->code);
		rdebug_pair_list(L_DBG_LVL_1, request, fake->reply->vps, NULL);

		if ((pw = fr_pair_find_by_num(fake->config, PW_CLEARTEXT_PASSWORD, 0, TAG_ANY)) == NULL) {
			DEBUG2("failed to find password for %s to do pwd authentication",
			session->peer_id);
			talloc_free(fake);
			return 0;
		}

		if (compute_password_element(session, session->group_num,
			     		     pw->data.strvalue, strlen(pw->data.strvalue),
					     inst->server_id, strlen(inst->server_id),
					     session->peer_id, strlen(session->peer_id),
					     &session->token)) {
			DEBUG2("failed to obtain password element");
			talloc_free(fake);
			return 0;
		}
		TALLOC_FREE(fake);

		/*
		 * compute our scalar and element
		 */
		if (compute_scalar_element(session, inst->bnctx)) {
			DEBUG2("failed to compute server's scalar and element");
			return 0;
		}

		if (((x = BN_new()) == NULL) || ((y = BN_new()) == NULL)) {
			DEBUG2("server point allocation failed");
			return 0;
		}

		/*
		 * element is a point, get both coordinates: x and y
		 */
		if (!EC_POINT_get_affine_coordinates_GFp(session->group, session->my_element, x, y,
							 inst->bnctx)) {
			DEBUG2("server point assignment failed");
			BN_clear_free(x);
			BN_clear_free(y);
			return 0;
		}

		/*
		 * construct request
		 */
		session->out_len = BN_num_bytes(session->order) + (2 * BN_num_bytes(session->prime));
		if ((session->out = talloc_array(session, uint8_t, session->out_len)) == NULL) {
			return 0;
		}
		memset(session->out, 0, session->out_len);

		ptr = session->out;
		offset = BN_num_bytes(session->prime) - BN_num_bytes(x);
		BN_bn2bin(x, ptr + offset);

		ptr += BN_num_bytes(session->prime);
		offset = BN_num_bytes(session->prime) - BN_num_bytes(y);
		BN_bn2bin(y, ptr + offset);

		ptr += BN_num_bytes(session->prime);
		offset = BN_num_bytes(session->order) - BN_num_bytes(session->my_scalar);
		BN_bn2bin(session->my_scalar, ptr + offset);

		session->state = PWD_STATE_COMMIT;
		ret = send_pwd_request(session, eap_ds);
		break;

		case PWD_STATE_COMMIT:
		if (EAP_PWD_GET_EXCHANGE(hdr) != EAP_PWD_EXCH_COMMIT) {
			RDEBUG2("pwd exchange is incorrect: not commit!");
			return 0;
		}

		/*
		 * process the peer's commit and generate the shared key, k
		 */
		if (process_peer_commit(session, in, in_len, inst->bnctx)) {
			RDEBUG2("failed to process peer's commit");
			return 0;
		}

		/*
		 * compute our confirm blob
		 */
		if (compute_server_confirm(session, session->my_confirm, inst->bnctx)) {
			ERROR("rlm_eap_pwd: failed to compute confirm!");
			return 0;
		}

		/*
		 * construct a response...which is just our confirm blob
		 */
		session->out_len = SHA256_DIGEST_LENGTH;
		if ((session->out = talloc_array(session, uint8_t, session->out_len)) == NULL) {
			return 0;
		}

		memset(session->out, 0, session->out_len);
		memcpy(session->out, session->my_confirm, SHA256_DIGEST_LENGTH);

		session->state = PWD_STATE_CONFIRM;
		ret = send_pwd_request(session, eap_ds);
		break;

	case PWD_STATE_CONFIRM:
		if (in_len < SHA256_DIGEST_LENGTH) {
			RDEBUG("Peer confirm is too short (%zd < %d)",
			       in_len, SHA256_DIGEST_LENGTH);
			return 0;
		}

		if (EAP_PWD_GET_EXCHANGE(hdr) != EAP_PWD_EXCH_CONFIRM) {
			RDEBUG2("pwd exchange is incorrect: not commit!");
			return 0;
		}
		if (compute_peer_confirm(session, peer_confirm, inst->bnctx)) {
			RDEBUG2("pwd exchange cannot compute peer's confirm");
			return 0;
		}
		if (CRYPTO_memcmp(peer_confirm, in, SHA256_DIGEST_LENGTH)) {
			RDEBUG2("pwd exchange fails: peer confirm is incorrect!");
			return 0;
		}
		if (compute_keys(session, peer_confirm, msk, emsk)) {
			RDEBUG2("pwd exchange cannot generate (E)MSK!");
			return 0;
		}
		eap_ds->request->code = PW_EAP_SUCCESS;
		/*
		 * return the MSK (in halves)
		 */
		eap_add_reply(handler->request, "MS-MPPE-Recv-Key", msk, MPPE_KEY_LEN);
		eap_add_reply(handler->request, "MS-MPPE-Send-Key", msk + MPPE_KEY_LEN, MPPE_KEY_LEN);

		ret = 1;
		break;

	default:
		RDEBUG2("unknown PWD state");
		return 0;
	}

	/*
	 * we processed the buffered fragments, get rid of them
	 */
	if (session->in) {
		talloc_free(session->in);
		session->in = NULL;
	}

	return ret;
}

extern rlm_eap_module_t rlm_eap_pwd;
rlm_eap_module_t rlm_eap_pwd = {
	.name		= "eap_pwd",
	.instantiate	= mod_instantiate,	/* Create new submodule instance */
	.session_init	= mod_session_init,		/* Create the initial request */
	.process	= mod_process,		/* Process next round of EAP method */
	.detach		= mod_detach		/* Destroy the submodule instance */
};

