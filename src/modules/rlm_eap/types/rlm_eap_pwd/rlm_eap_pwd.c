/*
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
 *
 * @copyright (c) Dan Harkins, 2012
 */
RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#define LOG_PREFIX "rlm_eap_pwd - "

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/tls/base.h>

#include "eap_pwd.h"

typedef struct {
    BN_CTX *bnctx;

    uint32_t	group;
    uint32_t	fragment_size;
    char const	*server_id;
    char const	*virtual_server;
} rlm_eap_pwd_t;

#define MPPE_KEY_LEN    32
#define MSK_EMSK_LEN    (2 * MPPE_KEY_LEN)

static CONF_PARSER submodule_config[] = {
	{ FR_CONF_OFFSET("group", FR_TYPE_UINT32, rlm_eap_pwd_t, group), .dflt = "19" },
	{ FR_CONF_OFFSET("fragment_size", FR_TYPE_UINT32, rlm_eap_pwd_t, fragment_size), .dflt = "1020" },
	{ FR_CONF_OFFSET("server_id", FR_TYPE_STRING | FR_TYPE_REQUIRED, rlm_eap_pwd_t, server_id) },
	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t rlm_eap_pwd_dict[];
fr_dict_autoload_t rlm_eap_pwd_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_cleartext_password;
static fr_dict_attr_t const *attr_framed_mtu;
static fr_dict_attr_t const *attr_ms_mppe_send_key;
static fr_dict_attr_t const *attr_ms_mppe_recv_key;

extern fr_dict_attr_autoload_t rlm_eap_pwd_dict_attr[];
fr_dict_attr_autoload_t rlm_eap_pwd_dict_attr[] = {
	{ .out = &attr_cleartext_password, .name = "Cleartext-Password", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_framed_mtu, .name = "Framed-MTU", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_ms_mppe_send_key, .name = "Vendor-Specific.Microsoft.MPPE-Send-Key", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_ms_mppe_recv_key, .name = "Vendor-Specific.Microsoft.MPPE-Recv-Key", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ NULL }
};

static int send_pwd_request(request_t *request, pwd_session_t *session, eap_round_t *eap_round)
{
	size_t		len;
	uint16_t	totlen;
	pwd_hdr		*hdr;

	len = (session->out_len - session->out_pos) + sizeof(pwd_hdr);
	fr_assert(len > 0);
	eap_round->request->code = FR_EAP_CODE_REQUEST;
	eap_round->request->type.num = FR_EAP_METHOD_PWD;
	eap_round->request->type.length = (len > session->mtu) ? session->mtu : len;
	eap_round->request->type.data = talloc_zero_array(eap_round->request, uint8_t, eap_round->request->type.length);
	hdr = (pwd_hdr *)eap_round->request->type.data;

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
		REDEBUG("PWD state is invalid.  Can't send request");
		return -1;
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
	return 0;
}

static unlang_action_t mod_process(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_eap_pwd_t	*inst = talloc_get_type_abort(mctx->instance, rlm_eap_pwd_t);
	eap_session_t	*eap_session = eap_session_get(request->parent);

	pwd_session_t	*session;

	pwd_hdr		*hdr;
	pwd_id_packet_t	*packet;
	eap_packet_t	*response;

	eap_round_t	*eap_round;
	size_t		in_len;
	rlm_rcode_t	rcode = RLM_MODULE_OK;
	uint16_t	offset;
	uint8_t		exch, *in, *ptr, msk[MSK_EMSK_LEN], emsk[MSK_EMSK_LEN];
	uint8_t		peer_confirm[SHA256_DIGEST_LENGTH];

	if (((eap_round = eap_session->this_round) == NULL) || !inst) return 0;

	session = talloc_get_type_abort(eap_session->opaque, pwd_session_t);
	response = eap_session->this_round->response;
	hdr = (pwd_hdr *)response->type.data;

	/*
	 *	The header must be at least one byte.
	 */
	if (!hdr || (response->type.length < sizeof(pwd_hdr))) {
		REDEBUG("Packet with insufficient data");
		RETURN_MODULE_INVALID;
	}

	in = hdr->data;
	in_len = response->type.length - sizeof(pwd_hdr);

	/*
	 *	See if we're fragmenting, if so continue until we're done
	 */
	if (session->out_pos) {
		if (in_len) REDEBUG("PWD got something more than an ACK for a fragment");
		if (send_pwd_request(request, session, eap_round) < 0) RETURN_MODULE_FAIL;

		RETURN_MODULE_OK;
	}

	/*
	 *	The first fragment will have a total length, make a
	 *	buffer to hold all the fragments
	 */
	if (EAP_PWD_GET_LENGTH_BIT(hdr)) {
		if (session->in) {
			REDEBUG("PWD already alloced buffer for fragments");
			RETURN_MODULE_FAIL;
		}

		if (in_len < 2) {
			REDEBUG("Invalid packet: length bit set, but no length field");
			RETURN_MODULE_INVALID;
		}

		session->in_len = ntohs(in[0] * 256 | in[1]);
		if (!session->in_len) {
			DEBUG("EAP-PWD malformed packet (input length)");
			RETURN_MODULE_FAIL;
		}

		MEM(session->in = talloc_zero_array(session, uint8_t, session->in_len));

		session->in_pos = 0;
		in += sizeof(uint16_t);
		in_len -= sizeof(uint16_t);
	}

	/*
	 *	All fragments, including the 1st will have the M(ore) bit set,
	 *	buffer those fragments!
	 */
	if (EAP_PWD_GET_MORE_BIT(hdr)) {
		if (!session->in) {
			RDEBUG2("Unexpected fragment.");
			return 0;
		}

		if ((session->in_pos + in_len) > session->in_len) {
			REDEBUG("Fragment overflows packet");
			RETURN_MODULE_INVALID;
		}

		memcpy(session->in + session->in_pos, in, in_len);
		session->in_pos += in_len;

		/*
		 * send back an ACK for this fragment
		 */
		exch = EAP_PWD_GET_EXCHANGE(hdr);
		eap_round->request->code = FR_EAP_CODE_REQUEST;
		eap_round->request->type.num = FR_EAP_METHOD_PWD;
		eap_round->request->type.length = sizeof(pwd_hdr);

		MEM(eap_round->request->type.data = talloc_array(eap_round->request, uint8_t, sizeof(pwd_hdr)));

		hdr = (pwd_hdr *)eap_round->request->type.data;
		EAP_PWD_SET_EXCHANGE(hdr, exch);
		RETURN_MODULE_OK;
	}


	if (session->in) {
		/*
		 *	The last fragment...
		 */
		if ((session->in_pos + in_len) > session->in_len) {
			REDEBUG("PWD will overflow a fragment buffer");
			RETURN_MODULE_INVALID;
		}
		memcpy(session->in + session->in_pos, in, in_len);
		in = session->in;
		in_len = session->in_len;
	}

	switch (session->state) {
	case PWD_STATE_ID_REQ:
	{
		fr_pair_t		*known_good;
		fr_dict_attr_t const	*allowed_passwords[] = { attr_cleartext_password };
		int			ret;
		bool			ephemeral;
		BIGNUM			*x = NULL, *y = NULL;

		if (EAP_PWD_GET_EXCHANGE(hdr) != EAP_PWD_EXCH_ID) {
			REDEBUG("PWD exchange is incorrect, Not ID");
			RETURN_MODULE_INVALID;
		}

		packet = (pwd_id_packet_t *) in;
		if (in_len < sizeof(*packet)) {
			REDEBUG("Packet is too small (%zd < %zd).", in_len, sizeof(*packet));
			RETURN_MODULE_INVALID;
		}

		if ((packet->prf != EAP_PWD_DEF_PRF) ||
		    (packet->random_function != EAP_PWD_DEF_RAND_FUN) ||
		    (packet->prep != EAP_PWD_PREP_NONE) ||
		    (CRYPTO_memcmp(packet->token, &session->token, 4)) ||
		    (packet->group_num != ntohs(session->group_num))) {
			REDEBUG("PWD ID response is malformed");
			RETURN_MODULE_INVALID;
		}

		/*
		 *	We've agreed on the ciphersuite, record it...
		 */
		ptr = (uint8_t *)&session->ciphersuite;
		memcpy(ptr, (char *)&packet->group_num, sizeof(uint16_t));
		ptr += sizeof(uint16_t);
		*ptr = EAP_PWD_DEF_RAND_FUN;
		ptr += sizeof(uint8_t);
		*ptr = EAP_PWD_DEF_PRF;

		session->peer_id_len = in_len - sizeof(pwd_id_packet_t);
		if (session->peer_id_len >= sizeof(session->peer_id)) {
			REDEBUG("PWD ID response is malformed");
			RETURN_MODULE_INVALID;
		}

		memcpy(session->peer_id, packet->identity, session->peer_id_len);
		session->peer_id[session->peer_id_len] = '\0';

		known_good = password_find(&ephemeral, request, request->parent,
					   allowed_passwords, NUM_ELEMENTS(allowed_passwords), false);
		if (!known_good) {
			REDEBUG("No \"known good\" password found for user");
			RETURN_MODULE_FAIL;
		}

		ret = compute_password_element(request, session, session->group_num,
					       known_good->vp_strvalue, known_good->vp_length,
					       inst->server_id, strlen(inst->server_id),
					       session->peer_id, strlen(session->peer_id),
					       &session->token, inst->bnctx);
		if (ephemeral) talloc_list_free(&known_good);
		if (ret < 0) {
			REDEBUG("Failed to obtain password element");
			RETURN_MODULE_FAIL;
		}

		/*
		 *	Compute our scalar and element
		 */
		if (compute_scalar_element(request, session, inst->bnctx)) {
			REDEBUG("Failed to compute server's scalar and element");
			RETURN_MODULE_FAIL;
		}

		MEM(x = BN_new());
		MEM(y = BN_new());

		/*
		 *	Element is a point, get both coordinates: x and y
		 */
		if (!EC_POINT_get_affine_coordinates_GFp(session->group, session->my_element, x, y, inst->bnctx)) {
			REDEBUG("Server point assignment failed");
			BN_clear_free(x);
			BN_clear_free(y);
			RETURN_MODULE_FAIL;
		}

		/*
		 *	Construct request
		 */
		session->out_len = BN_num_bytes(session->order) + (2 * BN_num_bytes(session->prime));
		MEM(session->out = talloc_zero_array(session, uint8_t, session->out_len));

		ptr = session->out;
		offset = BN_num_bytes(session->prime) - BN_num_bytes(x);
		BN_bn2bin(x, ptr + offset);
		BN_clear_free(x);

		ptr += BN_num_bytes(session->prime);
		offset = BN_num_bytes(session->prime) - BN_num_bytes(y);
		BN_bn2bin(y, ptr + offset);
		BN_clear_free(y);

		ptr += BN_num_bytes(session->prime);
		offset = BN_num_bytes(session->order) - BN_num_bytes(session->my_scalar);
		BN_bn2bin(session->my_scalar, ptr + offset);

		session->state = PWD_STATE_COMMIT;
		rcode = send_pwd_request(request, session, eap_round) < 0 ? RLM_MODULE_FAIL : RLM_MODULE_OK;
	}
		break;

	case PWD_STATE_COMMIT:
		if (EAP_PWD_GET_EXCHANGE(hdr) != EAP_PWD_EXCH_COMMIT) {
			REDEBUG("PWD exchange is incorrect, not commit!");
			RETURN_MODULE_INVALID;
		}

		/*
		 *	Process the peer's commit and generate the shared key, k
		 */
		if (process_peer_commit(request, session, in, in_len, inst->bnctx)) {
			REDEBUG("Failed processing peer's commit");
			RETURN_MODULE_FAIL;
		}

		/*
		 *	Compute our confirm blob
		 */
		if (compute_server_confirm(request, session, session->my_confirm, inst->bnctx)) {
			REDEBUG("Failed computing confirm");
			RETURN_MODULE_FAIL;
		}

		/*
		 *	Construct a response...which is just our confirm blob
		 */
		session->out_len = SHA256_DIGEST_LENGTH;
		MEM(session->out = talloc_array(session, uint8_t, session->out_len));

		memset(session->out, 0, session->out_len);
		memcpy(session->out, session->my_confirm, SHA256_DIGEST_LENGTH);

		session->state = PWD_STATE_CONFIRM;
		rcode = send_pwd_request(request, session, eap_round) < 0 ? RLM_MODULE_FAIL : RLM_MODULE_OK;
		break;

	case PWD_STATE_CONFIRM:
		if (in_len < SHA256_DIGEST_LENGTH) {
			REDEBUG("Peer confirm is too short (%zd < %d)", in_len, SHA256_DIGEST_LENGTH);
			RETURN_MODULE_INVALID;
		}

		if (EAP_PWD_GET_EXCHANGE(hdr) != EAP_PWD_EXCH_CONFIRM) {
			REDEBUG("PWD exchange is incorrect, not commit");
			RETURN_MODULE_INVALID;
		}
		if (compute_peer_confirm(request, session, peer_confirm, inst->bnctx)) {
			REDEBUG("Cannot compute peer's confirm");
			RETURN_MODULE_FAIL;
		}
		if (CRYPTO_memcmp(peer_confirm, in, SHA256_DIGEST_LENGTH)) {
			REDEBUG("PWD exchange failed, peer confirm is incorrect");
			RETURN_MODULE_FAIL;
		}
		if (compute_keys(request, session, peer_confirm, msk, emsk)) {
			REDEBUG("Failed generating (E)MSK");
			RETURN_MODULE_FAIL;
		}
		eap_round->request->code = FR_EAP_CODE_SUCCESS;

		/*
		 *	Return the MSK (in halves).
		 */
		eap_add_reply(request->parent, attr_ms_mppe_recv_key, msk, MPPE_KEY_LEN);
		eap_add_reply(request->parent, attr_ms_mppe_send_key, msk + MPPE_KEY_LEN, MPPE_KEY_LEN);

		rcode = RLM_MODULE_OK;
		break;

	default:
		REDEBUG("Unknown PWD state");
		RETURN_MODULE_FAIL;
	}

	/*
	 *	We processed the buffered fragments, get rid of them.
	 */
	if (session->in) {
		talloc_free(session->in);
		session->in = NULL;
	}

	RETURN_MODULE_RCODE(rcode);
}

static int _free_pwd_session(pwd_session_t *session)
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

static unlang_action_t mod_session_init(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_eap_pwd_t		*inst = talloc_get_type_abort(mctx->instance, rlm_eap_pwd_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);
	pwd_session_t		*session;
	fr_pair_t		*vp;
	pwd_id_packet_t		*packet;

	MEM(session = talloc_zero(eap_session, pwd_session_t));
	talloc_set_destructor(session, _free_pwd_session);
	/*
	 * set things up so they can be free'd reliably
	 */
	session->group_num = inst->group;

	/*
	 *	The admin can dynamically change the MTU.
	 */
	session->mtu = inst->fragment_size;
	vp = fr_pair_find_by_da(&request->request_pairs, attr_framed_mtu);

	/*
	 *	session->mtu is *our* MTU.  We need to subtract off the EAP
	 *	overhead.
	 *
	 *	9 = 4 (EAPOL header) + 4 (EAP header) + 1 (EAP type)
	 *
	 *	The fragmentation code deals with the included length
	 *	so we don't need to subtract that here.
	 */
	if (vp && (vp->vp_uint32 > 100) && (vp->vp_uint32 < session->mtu)) session->mtu = vp->vp_uint32 - 9;

	session->state = PWD_STATE_ID_REQ;
	session->out_pos = 0;
	eap_session->opaque = session;

	/*
	 * construct an EAP-pwd-ID/Request
	 */
	session->out_len = sizeof(pwd_id_packet_t) + strlen(inst->server_id);
	MEM(session->out = talloc_zero_array(session, uint8_t, session->out_len));

	packet = (pwd_id_packet_t *)session->out;
	packet->group_num = htons(session->group_num);
	packet->random_function = EAP_PWD_DEF_RAND_FUN;
	packet->prf = EAP_PWD_DEF_PRF;
	session->token = fr_rand();
	memcpy(packet->token, (char *)&session->token, 4);
	packet->prep = EAP_PWD_PREP_NONE;
	memcpy(packet->identity, inst->server_id, session->out_len - sizeof(pwd_id_packet_t) );

	if (send_pwd_request(request, session, eap_session->this_round) < 0) RETURN_MODULE_FAIL;

	eap_session->process = mod_process;

	RETURN_MODULE_HANDLED;
}

static int mod_detach(void *arg)
{
	rlm_eap_pwd_t *inst;

	inst = (rlm_eap_pwd_t *) arg;

	if (inst->bnctx) BN_CTX_free(inst->bnctx);

	return 0;
}

static int mod_instantiate(void *instance, CONF_SECTION *cs)
{
	rlm_eap_pwd_t *inst = talloc_get_type_abort(instance, rlm_eap_pwd_t);

	if (inst->fragment_size < 100) {
		cf_log_err(cs, "Fragment size is too small");
		return -1;
	}

	switch (inst->group) {
	case 19:
	case 20:
	case 21:
	case 25:
	case 26:
		break;

	default:
		cf_log_err_by_child(cs, "group", "Group %i is not supported", inst->group);
		return -1;
	}

	inst->bnctx = BN_CTX_new();
	if (!inst->bnctx) {
		ERROR("Failed to get BN context");
		return -1;
	}

	return 0;
}

extern rlm_eap_submodule_t rlm_eap_pwd;
rlm_eap_submodule_t rlm_eap_pwd = {
	.name		= "eap_pwd",
	.magic		= RLM_MODULE_INIT,

	.provides	= { FR_EAP_METHOD_PWD },
	.inst_size	= sizeof(rlm_eap_pwd_t),
	.config		= submodule_config,
	.instantiate	= mod_instantiate,	/* Create new submodule instance */
	.detach		= mod_detach,

	.session_init	= mod_session_init,	/* Create the initial request */
	.entry_point	= mod_process,		/* Process next round of EAP method */
};

