/*
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
 */

/**
 * $Id$
 * @file src/process/eap_psk/base.c
 * @brief The EAP-PSK (RFC 4764) state machine
 *
 * Runs the four-message EAP-PSK exchange on a request in the eap-psk
 * namespace, yielding to the virtual server's policy sections between
 * protocol steps:
 *
 *   - send Identity-Request      - before the first message; may override
 *                                  Server-Identity (ID_S).
 *   - recv Identity-Response     - after the second message; must supply
 *                                  control.Password.PSK for the asserted
 *                                  Identity (ID_P).
 *   - send Result-Indication     - before the third message.
 *   - recv Result-Acknowledgement- after the fourth message.
 *   - send Success / send Failure- before the final EAP result.
 *
 * Messages which fail validation are not processed, and the reply
 * Packet-Type is set to Do-Not-Respond.  RFC 4764 Section 4.1 calls for
 * such messages to be silently discarded; a true silent discard cannot
 * be expressed through the EAP module, which fails the session for any
 * unhandled round, so an invalid message ends the session with an
 * EAP-Failure, as with every other EAP method.  The Do-Not-Respond
 * reply code preserves the distinction from a policy-driven Failure
 * for logging.
 *
 * @copyright 2026 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
#include <freeradius-devel/eap/base.h>
#include <freeradius-devel/eap/types.h>
#include <freeradius-devel/server/process_types.h>
#include <freeradius-devel/server/virtual_servers.h>
#include <freeradius-devel/server/pair.h>
#include <freeradius-devel/unlang/module.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/protocol/eap/psk/freeradius.h>

#include <openssl/rand.h>

#include "crypto.h"

static fr_dict_t const *dict_eap_psk;
static fr_dict_t const *dict_freeradius;

extern fr_dict_autoload_t process_eap_psk_dict[];
fr_dict_autoload_t process_eap_psk_dict[] = {
	{ .out = &dict_eap_psk, .base_dir = "eap/psk", .proto = "eap-psk" },
	{ .out = &dict_freeradius, .proto = "freeradius" },
	DICT_AUTOLOAD_TERMINATOR
};

static fr_dict_attr_t const *attr_packet_type;
static fr_dict_attr_t const *attr_identity;
static fr_dict_attr_t const *attr_server_identity;
static fr_dict_attr_t const *attr_rand_server;
static fr_dict_attr_t const *attr_rand_peer;
static fr_dict_attr_t const *attr_psk_password;

extern fr_dict_attr_autoload_t process_eap_psk_dict_attr[];
fr_dict_attr_autoload_t process_eap_psk_dict_attr[] = {
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_eap_psk },
	{ .out = &attr_identity, .name = "Identity", .type = FR_TYPE_STRING, .dict = &dict_eap_psk },
	{ .out = &attr_server_identity, .name = "Server-Identity", .type = FR_TYPE_STRING, .dict = &dict_eap_psk },
	{ .out = &attr_rand_server, .name = "RAND-Server", .type = FR_TYPE_OCTETS, .dict = &dict_eap_psk },
	{ .out = &attr_rand_peer, .name = "RAND-Peer", .type = FR_TYPE_OCTETS, .dict = &dict_eap_psk },
	{ .out = &attr_psk_password, .name = "Password.PSK", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	DICT_AUTOLOAD_TERMINATOR
};

typedef struct {
	CONF_SECTION	*send_identity_request;
	CONF_SECTION	*recv_identity_response;
	CONF_SECTION	*send_result_indication;
	CONF_SECTION	*recv_result_acknowledgement;
	CONF_SECTION	*send_success;
	CONF_SECTION	*send_failure;
} process_eap_psk_sections_t;

typedef struct {
	char const			*identity;	//!< Default ID_S sent in the first message.
	process_eap_psk_sections_t	sections;
} process_eap_psk_t;

static conf_parser_t submodule_config[] = {
	{ FR_CONF_OFFSET("identity", process_eap_psk_t, identity), .dflt = "FreeRADIUS" },

	CONF_PARSER_TERMINATOR
};

/*
 *	Yield to a policy section if the virtual server defines one,
 *	otherwise call the resume function directly.  Either way the
 *	resume function sees the session as mctx->rctx.
 */
#define YIELD_OR_RESUME(_section, _resume) \
	do { \
		module_ctx_t our_mctx; \
		if (inst->sections._section) { \
			return unlang_module_yield_to_section(&session->section_result, request, \
							      inst->sections._section, RLM_MODULE_NOOP, \
							      _resume, NULL, 0, session); \
		} \
		session->section_result.rcode = RLM_MODULE_NOOP; \
		our_mctx = *mctx; \
		our_mctx.rctx = session; \
		return _resume(p_result, &our_mctx, request); \
	} while (0)

/*
 *	Write the EAP-PSK message fields into the outgoing eap_round->request.
 */
static int eap_psk_compose(eap_round_t *eap_round, uint8_t flags,
			   uint8_t const rand_s[static EAP_PSK_RAND_LEN],
			   uint8_t const *body, size_t body_len)
{
	uint8_t	*p;

	eap_round->request->code = FR_EAP_CODE_REQUEST;
	eap_round->request->type.num = FR_EAP_METHOD_PSK;
	eap_round->request->type.length = 1 + EAP_PSK_RAND_LEN + body_len;

	MEM(eap_round->request->type.data = talloc_array(eap_round->request, uint8_t,
							 eap_round->request->type.length));

	p = eap_round->request->type.data;
	*p++ = flags;

	memcpy(p, rand_s, EAP_PSK_RAND_LEN);
	p += EAP_PSK_RAND_LEN;
	if (body_len > 0) memcpy(p, body, body_len);

	return 0;
}

/*
 *	Reconstruct the 22-byte EAX Header H for an EAP-PSK packet.  H is the
 *	first 22 bytes of the EAP packet on the wire.  The 4-byte EAP header
 *	(Code, Id, Length), the 1-byte EAP Type, the 1-byte EAP-PSK Flags,
 *	and the 16-byte RAND_S.
 */
static void eap_psk_header(uint8_t header[static EAP_PSK_HEADER_LEN],
			   uint8_t code, uint8_t id, size_t type_length,
			   uint8_t flags, uint8_t const rand_s[static EAP_PSK_RAND_LEN])
{
	/*
	 *	The EAP Length is the 4-byte header + 1-byte Type + the
	 *	type-specific data.  See eap_wireformat().
	 */
	uint16_t eap_len = (uint16_t) (4 + 1 + type_length);

	header[0] = code;
	header[1] = id;
	header[2] = (uint8_t) (eap_len >> 8);
	header[3] = (uint8_t) (eap_len & 0xff);
	header[4] = FR_EAP_METHOD_PSK;
	header[5] = flags;

	memcpy(header + 6, rand_s, EAP_PSK_RAND_LEN);
}

/*
 *	Reject an invalid message.  The message is not processed, and the
 *	reply Packet-Type is set to Do-Not-Respond, which rlm_eap_psk
 *	translates into session failure (see the file header for why a
 *	true RFC 4764 Section 4.1 silent discard is not possible here).
 *
 *	If policy has already set reply.Packet-Type := ::Failure, report
 *	the explicit failure code instead.
 */
static unlang_action_t eap_psk_discard(unlang_result_t *p_result, request_t *request, eap_psk_session_t *session)
{
	fr_pair_t *vp;

	vp = fr_pair_find_by_da(&request->reply_pairs, NULL, attr_packet_type);
	if (vp && (vp->vp_uint32 == FR_PACKET_TYPE_VALUE_FAILURE)) {
		RDEBUG2("Policy overrides the silent discard, failing explicitly");
		session->state = EAP_PSK_STATE_FAILED;
		request->reply->code = FR_PACKET_TYPE_VALUE_FAILURE;
		RETURN_UNLANG_REJECT;
	}

	RDEBUG2("Silently discarding invalid message");
	request->reply->code = FR_PACKET_TYPE_VALUE_DO_NOT_RESPOND;
	RETURN_UNLANG_HANDLED;
}

/*
 *	Fail the authentication explicitly: run 'send Failure' if the
 *	virtual server defines one, then report Failure to the submodule.
 */
static unlang_action_t resume_send_failure(unlang_result_t *p_result, module_ctx_t const *mctx,
					   request_t *request)
{
	eap_psk_session_t *session = talloc_get_type_abort(mctx->rctx, eap_psk_session_t);

	session->state = EAP_PSK_STATE_FAILED;
	request->reply->code = FR_PACKET_TYPE_VALUE_FAILURE;
	RETURN_UNLANG_REJECT;
}

static unlang_action_t eap_psk_failure(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request,
				       process_eap_psk_t const *inst, eap_psk_session_t *session)
{
	YIELD_OR_RESUME(send_failure, resume_send_failure);
}

/** Compose the first message once 'send Identity-Request' has run
 *
 * Policy may override the ID_S sent to the peer by setting
 * reply.Server-Identity.
 */
static unlang_action_t resume_send_identity_request(unlang_result_t *p_result, module_ctx_t const *mctx,
						    request_t *request)
{
	process_eap_psk_t const	*inst = talloc_get_type_abort_const(mctx->mi->data, process_eap_psk_t);
	eap_psk_session_t	*session = talloc_get_type_abort(mctx->rctx, eap_psk_session_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);
	fr_pair_t		*vp;
	char const		*id_s;

	/*
	 *	If policy didn't provide a Server-Identity, seed the reply
	 *	pair with the configured default, then always read the
	 *	reply pair.  Same pattern as network_name / KDF-Input in
	 *	EAP-AKA'.
	 */
	vp = fr_pair_find_by_da(&request->reply_pairs, NULL, attr_server_identity);
	if (!vp) {
		MEM(pair_append_reply(&vp, attr_server_identity) >= 0);
		fr_pair_value_strdup(vp, inst->identity, false);
	}
	id_s = vp->vp_strvalue;

	if (id_s[0] == '\0') {
		REDEBUG("Server-Identity (ID_S) must not be empty");
		RETURN_UNLANG_FAIL;
	}

	MEM(session->id_s = talloc_strdup(session, id_s));

	RDEBUG2("Sending first message as \"%s\"", session->id_s);

	if (eap_psk_compose(eap_session->this_round, EAP_PSK_FLAGS_FIRST, session->rand_s,
			    (uint8_t const *) session->id_s, strlen(session->id_s)) < 0) RETURN_UNLANG_FAIL;

	session->state = EAP_PSK_STATE_IDENTITY_REQUEST_SENT;
	request->reply->code = FR_PACKET_TYPE_VALUE_SUCCESS;

	RETURN_UNLANG_OK;
}

/** Start the conversation: generate RAND_S and run 'send Identity-Request'
 *
 */
static unlang_action_t state_identity_request(unlang_result_t *p_result, module_ctx_t const *mctx,
					      request_t *request)
{
	process_eap_psk_t const	*inst = talloc_get_type_abort_const(mctx->mi->data, process_eap_psk_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);
	eap_psk_session_t	*session;
	fr_pair_t		*vp;

	MEM(session = talloc_zero(eap_session, eap_psk_session_t));
	eap_session->opaque = session;

	/*
	 *	Get a fresh random server nonce.  RFC 4764 requires a
	 *	cryptographic-quality RNG here, so we use OpenSSL.
	 */
	if (RAND_bytes(session->rand_s, sizeof(session->rand_s)) != 1) {
		REDEBUG("Failed generating RAND_S");
		RETURN_UNLANG_FAIL;
	}

	MEM(pair_update_request(&vp, attr_rand_server) >= 0);
	fr_pair_value_memdup(vp, session->rand_s, sizeof(session->rand_s), false);

	YIELD_OR_RESUME(send_identity_request, resume_send_identity_request);
}

/** Compose the third message once 'send Result-Indication' has run
 *
 */
static unlang_action_t resume_send_result_indication(unlang_result_t *p_result, module_ctx_t const *mctx,
						     request_t *request)
{
	eap_psk_session_t	*session = talloc_get_type_abort(mctx->rctx, eap_psk_session_t);
	fr_pair_t		*vp;

	vp = fr_pair_find_by_da(&request->reply_pairs, NULL, attr_packet_type);
	if (vp && (vp->vp_uint32 == FR_PACKET_TYPE_VALUE_FAILURE)) {
		process_eap_psk_t const *inst = talloc_get_type_abort_const(mctx->mi->data, process_eap_psk_t);

		RDEBUG2("Policy rejected the peer");
		return eap_psk_failure(p_result, mctx, request, inst, session);
	}

	session->state = EAP_PSK_STATE_RESULT_INDICATION_SENT;
	request->reply->code = FR_PACKET_TYPE_VALUE_SUCCESS;

	RETURN_UNLANG_OK;
}

/** Verify MAC_P and build the third message once 'recv Identity-Response' has run
 *
 * The policy section is responsible for populating control.Password.PSK
 * for the asserted Identity (ID_P).
 */
static unlang_action_t resume_recv_identity_response(unlang_result_t *p_result, module_ctx_t const *mctx,
						     request_t *request)
{
	process_eap_psk_t const	*inst = talloc_get_type_abort_const(mctx->mi->data, process_eap_psk_t);
	eap_psk_session_t	*session = talloc_get_type_abort(mctx->rctx, eap_psk_session_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);
	eap_round_t		*eap_round = eap_session->this_round;
	fr_pair_t		*known_good;

	uint8_t			ak[EAP_PSK_AK_LEN], kdk[EAP_PSK_KDK_LEN];
	uint8_t			expected[EAP_PSK_MAC_LEN], mac_s[EAP_PSK_MAC_LEN];
	uint8_t			body[EAP_PSK_MAC_LEN + EAP_PSK_PCHANNEL_LEN];
	uint8_t			header[EAP_PSK_HEADER_LEN];
	uint8_t			plain, cipher;
	uint8_t			*p;
	uint32_t		nonce = 0;

	switch (session->section_result.rcode) {
	case RLM_MODULE_REJECT:
	case RLM_MODULE_DISALLOW:
		RDEBUG2("Policy rejected the peer");
		return eap_psk_failure(p_result, mctx, request, inst, session);

	case RLM_MODULE_FAIL:
		RETURN_UNLANG_FAIL;

	default:
		break;
	}

	/*
	 *	No PSK for the asserted identity.  Discard by default so
	 *	that identity probing is not possible; policy may override
	 *	with reply.Packet-Type := ::Failure.
	 */
	known_good = fr_pair_find_by_da_nested(&request->control_pairs, attr_psk_password);
	if (!known_good) {
		RDEBUG2("No control.Password.PSK for Identity \"%pV\"",
			fr_box_strvalue_len((char const *) session->id_p, session->id_p_len));
		return eap_psk_discard(p_result, request, session);
	}

	/*
	 *	RFC 4764 Section 1.2 - the PSK is exactly 16 octets.  Anything
	 *	else is a misconfiguration, and must not be silently padded
	 *	or truncated.
	 */
	if (known_good->vp_length != EAP_PSK_PSK_LEN) {
		REDEBUG("Password.PSK must be exactly %d octets, got %zu octets",
			EAP_PSK_PSK_LEN, known_good->vp_length);
		return eap_psk_failure(p_result, mctx, request, inst, session);
	}

	/*
	 *	Key setup, then verify MAC_P before doing anything else.
	 */
	if (eap_psk_derive_ak_kdk(ak, kdk, known_good->vp_octets) < 0) {
		REDEBUG("Key setup failed");
		RETURN_UNLANG_FAIL;
	}

	if (eap_psk_mac_p(expected, ak,
			  session->id_p, session->id_p_len,
			  (uint8_t const *) session->id_s, strlen(session->id_s),
			  session->rand_s, session->rand_p) < 0) {
		REDEBUG("MAC_P computation failed");
		RETURN_UNLANG_FAIL;
	}

	if (fr_digest_cmp(expected, session->mac_p, EAP_PSK_MAC_LEN) != 0) {
		RDEBUG2("MAC_P is incorrect: the peer used the wrong key");
		return eap_psk_discard(p_result, request, session);
	}

	RDEBUG2("Peer authenticated (MAC_P valid)");

	/*
	 *	Derive the session keys and compute MAC_S for the peer.
	 */
	if (eap_psk_derive_keys(session->tek, session->msk, session->emsk,
				kdk, session->rand_p) < 0) {
		REDEBUG("Session-key derivation failed");
		RETURN_UNLANG_FAIL;
	}

	if (eap_psk_mac_s(mac_s, ak,
			  (uint8_t const *) session->id_s, strlen(session->id_s),
			  session->rand_p) < 0) {
		REDEBUG("MAC_S computation failed");
		RETURN_UNLANG_FAIL;
	}

	/*
	 *	Build the third message body: MAC_S || PCHANNEL.
	 *
	 *	The PCHANNEL protects the 22-byte header H, which depends on
	 *	the EAP Id and Length of THIS reply.  Pin the Id so that the
	 *	value we authenticate matches what goes on the wire.
	 */
	eap_round->request->id = eap_round->response->id + 1;
	eap_round->set_request_id = true;

	eap_psk_header(header, FR_EAP_CODE_REQUEST, eap_round->request->id,
		       1 + EAP_PSK_RAND_LEN + EAP_PSK_MAC_LEN + EAP_PSK_PCHANNEL_LEN,
		       EAP_PSK_FLAGS_THIRD, session->rand_s);

	/*
	 *	The single protected byte carries R = DONE_SUCCESS, E = 0.
	 */
	plain = EAP_PSK_PAYLOAD(EAP_PSK_R_DONE_SUCCESS);

	p = body;
	memcpy(p, mac_s, EAP_PSK_MAC_LEN);
	p += EAP_PSK_MAC_LEN;

	/*
	 *	PCHANNEL = Nonce(4, big-endian) || Tag(16) || EncryptedPayload(1)
	 */
	*p++ = (uint8_t) (nonce >> 24);
	*p++ = (uint8_t) (nonce >> 16);
	*p++ = (uint8_t) (nonce >> 8);
	*p++ = (uint8_t) (nonce);

	if (eap_psk_pchannel_encrypt(&cipher, p, session->tek, nonce,
				     header, sizeof(header), &plain, 1) < 0) {
		REDEBUG("Protected-channel encryption failed");
		RETURN_UNLANG_FAIL;
	}
	p += EAP_PSK_TAG_LEN;
	*p++ = cipher;

	if (eap_psk_compose(eap_round, EAP_PSK_FLAGS_THIRD, session->rand_s,
			    body, EAP_PSK_MAC_LEN + EAP_PSK_PCHANNEL_LEN) < 0) RETURN_UNLANG_FAIL;

	YIELD_OR_RESUME(send_result_indication, resume_send_result_indication);
}

/** Parse the second message and run 'recv Identity-Response'
 *
 */
static unlang_action_t state_identity_response(unlang_result_t *p_result, module_ctx_t const *mctx,
					       request_t *request)
{
	process_eap_psk_t const	*inst = talloc_get_type_abort_const(mctx->mi->data, process_eap_psk_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);
	eap_psk_session_t	*session = talloc_get_type_abort(eap_session->opaque, eap_psk_session_t);
	eap_round_t		*eap_round = eap_session->this_round;
	uint8_t const		*in = eap_round->response->type.data;
	size_t			in_len = eap_round->response->type.length;

	uint8_t const		*rand_s_echo, *rand_p, *mac_p, *id_p;
	size_t			id_p_len;
	fr_pair_t		*vp;

	/*
	 *	Flags(1) || RAND_S(16) || RAND_P(16) || MAC_P(16) || ID_P(*)
	 */
	if (in_len < (size_t) (1 + EAP_PSK_RAND_LEN + EAP_PSK_RAND_LEN + EAP_PSK_MAC_LEN)) {
		RDEBUG2("Second message is too short");
		return eap_psk_discard(p_result, request, session);
	}

	if ((in[0] & EAP_PSK_T_MASK) != EAP_PSK_FLAGS_SECOND) {
		RDEBUG2("Second message has the wrong T flag");
		return eap_psk_discard(p_result, request, session);
	}

	rand_s_echo = in + 1;
	rand_p      = rand_s_echo + EAP_PSK_RAND_LEN;
	mac_p       = rand_p + EAP_PSK_RAND_LEN;
	id_p        = mac_p + EAP_PSK_MAC_LEN;
	id_p_len    = in_len - (1 + EAP_PSK_RAND_LEN + EAP_PSK_RAND_LEN + EAP_PSK_MAC_LEN);

	/*
	 *	The peer must echo the RAND_S we sent.  Constant-time compare.
	 */
	if (fr_digest_cmp(rand_s_echo, session->rand_s, EAP_PSK_RAND_LEN) != 0) {
		RDEBUG2("Second message did not echo RAND_S");
		return eap_psk_discard(p_result, request, session);
	}

	if (id_p_len > EAP_PSK_MAX_ID_P_LEN) {
		RDEBUG2("ID_P is longer than the %u bytes allowed by RFC 4764", EAP_PSK_MAX_ID_P_LEN);
		return eap_psk_discard(p_result, request, session);
	}

	memcpy(session->rand_p, rand_p, sizeof(session->rand_p));
	memcpy(session->mac_p, mac_p, sizeof(session->mac_p));
	talloc_free(session->id_p);
	MEM(session->id_p = talloc_memdup(session, id_p, id_p_len));
	session->id_p_len = id_p_len;

	/*
	 *	Expose the exchange to policy.
	 */
	MEM(pair_update_request(&vp, attr_identity) >= 0);
	fr_pair_value_bstrndup(vp, (char const *) id_p, id_p_len, true);

	MEM(pair_update_request(&vp, attr_server_identity) >= 0);
	fr_pair_value_strdup(vp, session->id_s, false);

	MEM(pair_update_request(&vp, attr_rand_server) >= 0);
	fr_pair_value_memdup(vp, session->rand_s, sizeof(session->rand_s), false);

	MEM(pair_update_request(&vp, attr_rand_peer) >= 0);
	fr_pair_value_memdup(vp, session->rand_p, sizeof(session->rand_p), false);

	YIELD_OR_RESUME(recv_identity_response, resume_recv_identity_response);
}

/** Finish successfully once 'send Success' has run
 *
 */
static unlang_action_t resume_send_success(unlang_result_t *p_result, module_ctx_t const *mctx,
					   request_t *request)
{
	eap_psk_session_t	*session = talloc_get_type_abort(mctx->rctx, eap_psk_session_t);

	session->state = EAP_PSK_STATE_DONE;
	request->reply->code = FR_PACKET_TYPE_VALUE_SUCCESS;

	RETURN_UNLANG_OK;
}

/** Verify the protected result once 'recv Result-Acknowledgement' has run
 *
 */
static unlang_action_t resume_recv_result_acknowledgement(unlang_result_t *p_result, module_ctx_t const *mctx,
							  request_t *request)
{
	process_eap_psk_t const	*inst = talloc_get_type_abort_const(mctx->mi->data, process_eap_psk_t);
	eap_psk_session_t	*session = talloc_get_type_abort(mctx->rctx, eap_psk_session_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);
	eap_round_t		*eap_round = eap_session->this_round;
	uint8_t const		*in = eap_round->response->type.data;
	size_t			in_len = eap_round->response->type.length;

	uint8_t const		*pchannel, *tag, *cipher;
	uint8_t			header[EAP_PSK_HEADER_LEN];
	uint8_t			plain;
	uint32_t		nonce = 1;
	int			r;

	switch (session->section_result.rcode) {
	case RLM_MODULE_REJECT:
	case RLM_MODULE_DISALLOW:
		RDEBUG2("Policy rejected the peer");
		return eap_psk_failure(p_result, mctx, request, inst, session);

	case RLM_MODULE_FAIL:
		RETURN_UNLANG_FAIL;

	default:
		break;
	}

	pchannel = in + 1 + EAP_PSK_RAND_LEN;
	tag      = pchannel + EAP_PSK_NONCE_LEN;
	cipher   = tag + EAP_PSK_TAG_LEN;

	/*
	 *	Reconstruct the header H over the RECEIVED packet, then verify
	 *	the tag and decrypt the single result byte.
	 */
	eap_psk_header(header, FR_EAP_CODE_RESPONSE, eap_round->response->id,
		       in_len, in[0], session->rand_s);

	if (eap_psk_pchannel_decrypt(&plain, session->tek, nonce,
				     header, sizeof(header), cipher, 1, tag) < 0) {
		RDEBUG2("Protected-channel verification failed: mutual authentication failed");
		return eap_psk_discard(p_result, request, session);
	}

	r = EAP_PSK_R(plain);
	if (r != EAP_PSK_R_DONE_SUCCESS) {
		RDEBUG2("Peer reported result %d (not success)", r);
		return eap_psk_failure(p_result, mctx, request, inst, session);
	}

	RDEBUG2("Mutual authentication succeeded");

	/*
	 *	The rlm_eap_psk submodule delivers the keying material
	 *	(session->msk) to the outer protocol once the session
	 *	reaches EAP_PSK_STATE_DONE.
	 */
	eap_round->request->code = FR_EAP_CODE_SUCCESS;
	eap_round->request->type.length = 0;

	YIELD_OR_RESUME(send_success, resume_send_success);
}

/** Parse the fourth message and run 'recv Result-Acknowledgement'
 *
 */
static unlang_action_t state_result_acknowledgement(unlang_result_t *p_result, module_ctx_t const *mctx,
						    request_t *request)
{
	process_eap_psk_t const	*inst = talloc_get_type_abort_const(mctx->mi->data, process_eap_psk_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);
	eap_psk_session_t	*session = talloc_get_type_abort(eap_session->opaque, eap_psk_session_t);
	eap_round_t		*eap_round = eap_session->this_round;
	uint8_t const		*in = eap_round->response->type.data;
	size_t			in_len = eap_round->response->type.length;
	uint8_t const		*pchannel;

	/*
	 *	Flags(1) || RAND_S(16) || PCHANNEL(21)
	 */
	if (in_len < (size_t) (1 + EAP_PSK_RAND_LEN + EAP_PSK_PCHANNEL_LEN)) {
		RDEBUG2("Fourth message is too short");
		return eap_psk_discard(p_result, request, session);
	}

	if ((in[0] & EAP_PSK_T_MASK) != EAP_PSK_FLAGS_FOURTH) {
		RDEBUG2("Fourth message has the wrong T flag");
		return eap_psk_discard(p_result, request, session);
	}

	if (fr_digest_cmp(in + 1, session->rand_s, EAP_PSK_RAND_LEN) != 0) {
		RDEBUG2("Fourth message did not echo RAND_S");
		return eap_psk_discard(p_result, request, session);
	}

	/*
	 *	The peer's PCHANNEL nonce for the fourth message is 1.
	 *	RFC 4764 Section 3.3.
	 */
	pchannel = in + 1 + EAP_PSK_RAND_LEN;
	if ((pchannel[0] != 0) || (pchannel[1] != 0) || (pchannel[2] != 0) || (pchannel[3] != 1)) {
		RDEBUG2("Fourth message has an unexpected Nonce");
		return eap_psk_discard(p_result, request, session);
	}

	YIELD_OR_RESUME(recv_result_acknowledgement, resume_recv_result_acknowledgement);
}

/** Dispatch to the state matching the packet type set by rlm_eap_psk
 *
 */
static unlang_action_t mod_process(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	eap_session_t		*eap_session;
	eap_psk_session_t	*session;

	(void)talloc_get_type_abort_const(mctx->mi->data, process_eap_psk_t);

	request->component = "eap-psk";
	request->module = NULL;
	fr_assert(request->proto_dict == dict_eap_psk);

	if (!request->parent || !(eap_session = eap_session_get(request->parent))) {
		REDEBUG("EAP-PSK requests must be run from within the EAP module");
		RETURN_UNLANG_FAIL;
	}

	switch (request->packet->code) {
	case FR_PACKET_TYPE_VALUE_IDENTITY_REQUEST:
		if (eap_session->opaque) goto bad_state;
		return state_identity_request(p_result, mctx, request);

	case FR_PACKET_TYPE_VALUE_IDENTITY_RESPONSE:
		session = talloc_get_type_abort(eap_session->opaque, eap_psk_session_t);
		if (session->state != EAP_PSK_STATE_IDENTITY_REQUEST_SENT) goto bad_state;
		return state_identity_response(p_result, mctx, request);

	case FR_PACKET_TYPE_VALUE_RESULT_ACKNOWLEDGEMENT:
		session = talloc_get_type_abort(eap_session->opaque, eap_psk_session_t);
		if (session->state != EAP_PSK_STATE_RESULT_INDICATION_SENT) goto bad_state;
		return state_result_acknowledgement(p_result, mctx, request);

	default:
	bad_state:
		REDEBUG("Invalid packet code %u for the current session state", request->packet->code);
		RETURN_UNLANG_FAIL;
	}
}

static const virtual_server_compile_t compile_list[] = {
	{
		.section = SECTION_NAME("send", "Identity-Request"),
		.actions = &mod_actions_authorize,
		.offset = offsetof(process_eap_psk_t, sections.send_identity_request)
	},
	{
		.section = SECTION_NAME("recv", "Identity-Response"),
		.actions = &mod_actions_authorize,
		.offset = offsetof(process_eap_psk_t, sections.recv_identity_response)
	},
	{
		.section = SECTION_NAME("send", "Result-Indication"),
		.actions = &mod_actions_authorize,
		.offset = offsetof(process_eap_psk_t, sections.send_result_indication)
	},
	{
		.section = SECTION_NAME("recv", "Result-Acknowledgement"),
		.actions = &mod_actions_authorize,
		.offset = offsetof(process_eap_psk_t, sections.recv_result_acknowledgement)
	},
	{
		.section = SECTION_NAME("send", "Success"),
		.actions = &mod_actions_authorize,
		.offset = offsetof(process_eap_psk_t, sections.send_success)
	},
	{
		.section = SECTION_NAME("send", "Failure"),
		.actions = &mod_actions_authorize,
		.offset = offsetof(process_eap_psk_t, sections.send_failure)
	},
	COMPILE_TERMINATOR
};

extern fr_process_module_t process_eap_psk;
fr_process_module_t process_eap_psk = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "eap_psk",
		.inst_size	= sizeof(process_eap_psk_t),
		.inst_type	= "process_eap_psk_t",
		.config		= submodule_config,
	},
	.process	= mod_process,
	.compile_list	= compile_list,
	.dict		= &dict_eap_psk,
	.packet_type	= &attr_packet_type
};
