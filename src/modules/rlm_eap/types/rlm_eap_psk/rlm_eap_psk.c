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
 *
 * @file rlm_eap_psk.c
 * @brief EAP-PSK (RFC 4764) authentication, server side
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/server/password.h>

#include "eap_psk.h"

#include <openssl/rand.h>
#include <openssl/crypto.h>

/*
 *	The MSK is split into a 32-byte MS-MPPE-Recv-Key and a 32-byte
 *	MS-MPPE-Send-Key, as is done with all other EAP methods.
 */
#define EAP_PSK_MPPE_KEY_LEN	32

typedef struct {
	char const	*identity;	//!< The server NAI (ID_S) sent in the first message.
} rlm_eap_psk_t;

static conf_parser_t submodule_config[] = {
	{ FR_CONF_OFFSET("identity", rlm_eap_psk_t, identity), .dflt = "FreeRADIUS" },

	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t rlm_eap_psk_dict[];
fr_dict_autoload_t rlm_eap_psk_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	DICT_AUTOLOAD_TERMINATOR
};

static fr_dict_attr_t const *attr_psk_password;
static fr_dict_attr_t const *attr_ms_mppe_send_key;
static fr_dict_attr_t const *attr_ms_mppe_recv_key;

extern fr_dict_attr_autoload_t rlm_eap_psk_dict_attr[];
fr_dict_attr_autoload_t rlm_eap_psk_dict_attr[] = {
	{ .out = &attr_psk_password, .name = "Password.PSK", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_ms_mppe_send_key, .name = "Vendor-Specific.Microsoft.MPPE-Send-Key", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_ms_mppe_recv_key, .name = "Vendor-Specific.Microsoft.MPPE-Recv-Key", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	DICT_AUTOLOAD_TERMINATOR
};

static unlang_action_t mod_process(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request);

/*
 *	Write the EAP-PSK message fields into the outgoing eap_round->request.
 *	'flags' is the 1-byte EAP-PSK Flags field, and 'body'/'body_len' are
 *	the bytes that follow RAND_S (MAC and PCHANNEL, or ID_S).
 */
static void eap_psk_compose(eap_round_t *eap_round, uint8_t flags,
			    uint8_t const rand_s[EAP_PSK_RAND_LEN],
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
}

/*
 *	Reconstruct the 22-byte EAX Header H for an EAP-PSK packet.  H is the
 *	first 22 bytes of the EAP packet on the wire.  The 4-byte EAP header
 *	(Code, Id, Length), the 1-byte EAP Type, the 1-byte EAP-PSK Flags,
 *	and the 16-byte RAND_S.
 */
static void eap_psk_header(uint8_t header[EAP_PSK_HEADER_LEN],
			   uint8_t code, uint8_t id, size_t type_length,
			   uint8_t flags, uint8_t const rand_s[EAP_PSK_RAND_LEN])
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
 *	Initiate the EAP-PSK session by sending the first message:
 *	Flags(T=0) || RAND_S || ID_S.  RFC 4764 Section 5.1.
 */
static unlang_action_t mod_session_init(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_eap_psk_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_eap_psk_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);
	eap_psk_session_t	*session;
	size_t			id_s_len;

	fr_assert(eap_session != NULL);

	MEM(session = talloc_zero(eap_session, eap_psk_session_t));

	/*
	 *	Get a fresh random server nonce.  RFC 4764 requires a
	 *	cryptographic-quality RNG here, so we use OpenSSL.
	 */
	if (RAND_bytes(session->rand_s, sizeof(session->rand_s)) != 1) {
		REDEBUG("Failed generating RAND_S");
		RETURN_UNLANG_FAIL;
	}

	session->state = EAP_PSK_STATE_INIT;
	eap_session->opaque = session;

	id_s_len = strlen(inst->identity);

	RDEBUG2("Sending EAP-PSK first message as \"%s\"", inst->identity);

	eap_psk_compose(eap_session->this_round, EAP_PSK_FLAGS_FIRST, session->rand_s,
			(uint8_t const *) inst->identity, id_s_len);

	eap_session->process = mod_process;

	RETURN_UNLANG_HANDLED;
}

/*
 *	Process the peer's second message and, if it passes the PSK
 *	checks, send the third message.  RFC 4764 Sections 5.2 and 5.3.
 */
static unlang_action_t process_msg2(unlang_result_t *p_result, rlm_eap_psk_t *inst,
				    eap_session_t *eap_session, request_t *request)
{
	eap_psk_session_t	*session = talloc_get_type_abort(eap_session->opaque, eap_psk_session_t);
	eap_round_t		*eap_round = eap_session->this_round;
	uint8_t			*in = eap_round->response->type.data;
	size_t			in_len = eap_round->response->type.length;
	fr_pair_t		*known_good;
	fr_dict_attr_t const	*allowed_passwords[] = { attr_psk_password };
	bool			ephemeral;

	uint8_t const		*rand_s_echo, *rand_p, *mac_p, *id_p;
	size_t			id_p_len, id_s_len;
	uint8_t			psk[EAP_PSK_PSK_LEN];
	uint8_t			ak[EAP_PSK_AK_LEN], kdk[EAP_PSK_KDK_LEN];
	uint8_t			expected[EAP_PSK_MAC_LEN], mac_s[EAP_PSK_MAC_LEN];
	uint8_t			body[EAP_PSK_MAC_LEN + EAP_PSK_PCHANNEL_LEN];
	uint8_t			header[EAP_PSK_HEADER_LEN];
	uint8_t			plain, cipher;
	uint8_t			*p;
	uint32_t		nonce = 0;

	/*
	 *	Flags(1) || RAND_S(16) || RAND_P(16) || MAC_P(16) || ID_P(*)
	 */
	if (in_len < (size_t) (1 + EAP_PSK_RAND_LEN + EAP_PSK_RAND_LEN + EAP_PSK_MAC_LEN)) {
		REDEBUG("Second message is too short");
		RETURN_UNLANG_INVALID;
	}

	if ((in[0] & EAP_PSK_T_MASK) != EAP_PSK_FLAGS_SECOND) {
		REDEBUG("Second message has the wrong T flag");
		RETURN_UNLANG_INVALID;
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
		REDEBUG("Second message did not echo RAND_S");
		RETURN_UNLANG_INVALID;
	}

	/*
	 *	The pre-shared key is the (exactly 16-byte) Password.PSK.
	 *
	 *	The easiest way to set that is to use a hex string, or
	 *	to MD5 the actual password.
	 */
	known_good = password_find(&ephemeral, request, request->parent,
				   allowed_passwords, NUM_ELEMENTS(allowed_passwords),
				   false);
	if (!known_good) {
		REDEBUG("Password.PSK is required for EAP-PSK authentication");
		RETURN_UNLANG_FAIL;
	}

	/*
	 *	RFC 4764 Section 1.2 - the PSK is exactly 16 octets.  Anything
	 *	else is a misconfiguration, and must not be silently padded
	 *	or truncated.
	 */
	if (known_good->vp_length != EAP_PSK_PSK_LEN) {
		REDEBUG("Password.PSK must be exactly %d octets, got %zu octets",
			EAP_PSK_PSK_LEN, known_good->vp_length);
		if (ephemeral) TALLOC_FREE(known_good);
		RETURN_UNLANG_FAIL;
	}

	memcpy(psk, known_good->vp_octets, EAP_PSK_PSK_LEN);

	if (ephemeral) TALLOC_FREE(known_good);

	id_s_len = strlen(inst->identity);

	/*
	 *	Key setup, then verify MAC_P before doing anything else.
	 */
	if (eap_psk_derive_ak_kdk(ak, kdk, psk) < 0) {
		REDEBUG("Key setup failed");
		RETURN_UNLANG_FAIL;
	}

	if (eap_psk_mac_p(expected, ak,
			  id_p, id_p_len,
			  (uint8_t const *) inst->identity, id_s_len,
			  session->rand_s, rand_p) < 0) {
		REDEBUG("MAC_P computation failed");
		RETURN_UNLANG_FAIL;
	}

	if (fr_digest_cmp(expected, mac_p, EAP_PSK_MAC_LEN) != 0) {
		REDEBUG("MAC_P is incorrect: the peer used the wrong key");
		RETURN_UNLANG_REJECT;
	}

	RDEBUG2("Peer authenticated (MAC_P valid)");

	/*
	 *	Derive the session keys and compute MAC_S for the peer.
	 */
	if (eap_psk_derive_keys(session->tek, session->msk, session->emsk, kdk, rand_p) < 0) {
		REDEBUG("Session-key derivation failed");
		RETURN_UNLANG_FAIL;
	}

	if (eap_psk_mac_s(mac_s, ak,
			  (uint8_t const *) inst->identity, id_s_len, rand_p) < 0) {
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

	eap_psk_compose(eap_round, EAP_PSK_FLAGS_THIRD, session->rand_s,
			body, EAP_PSK_MAC_LEN + EAP_PSK_PCHANNEL_LEN);

	session->state = EAP_PSK_STATE_MSG3_SENT;

	RETURN_UNLANG_OK;
}

/*
 *	Process the peer's fourth message.  On success, deliver the keying
 *	material in MPPE keys, and return an EAP-Success.  RFC 4764
 *	Sections 5.4 (message format) and 2.1 (MSK export).
 */
static unlang_action_t process_msg4(unlang_result_t *p_result, UNUSED rlm_eap_psk_t *inst,
				    eap_session_t *eap_session, request_t *request)
{
	eap_psk_session_t	*session = talloc_get_type_abort(eap_session->opaque, eap_psk_session_t);
	eap_round_t		*eap_round = eap_session->this_round;
	uint8_t			*in = eap_round->response->type.data;
	size_t			in_len = eap_round->response->type.length;

	uint8_t const		*rand_s_echo, *pchannel, *tag, *cipher;
	uint8_t			header[EAP_PSK_HEADER_LEN];
	uint8_t			plain;
	uint32_t		nonce = 1;
	int			r;

	/*
	 *	Flags(1) || RAND_S(16) || PCHANNEL(21)
	 */
	if (in_len < (size_t) (1 + EAP_PSK_RAND_LEN + EAP_PSK_PCHANNEL_LEN)) {
		REDEBUG("Fourth message is too short");
		RETURN_UNLANG_INVALID;
	}

	if ((in[0] & EAP_PSK_T_MASK) != EAP_PSK_FLAGS_FOURTH) {
		REDEBUG("Fourth message has the wrong T flag");
		RETURN_UNLANG_INVALID;
	}

	rand_s_echo = in + 1;
	pchannel    = rand_s_echo + EAP_PSK_RAND_LEN;

	if (fr_digest_cmp(rand_s_echo, session->rand_s, EAP_PSK_RAND_LEN) != 0) {
		REDEBUG("Fourth message did not echo RAND_S");
		RETURN_UNLANG_INVALID;
	}

	/*
	 *	The peer's PCHANNEL nonce for the fourth message is 1.
	 *	RFC 4764 Section 3.3.
	 */
	if ((pchannel[0] != 0) || (pchannel[1] != 0) || (pchannel[2] != 0) ||
	    (pchannel[3] != (uint8_t) nonce)) {
		REDEBUG("Fourth message has an unexpected Nonce");
		RETURN_UNLANG_INVALID;
	}

	tag    = pchannel + EAP_PSK_NONCE_LEN;
	cipher = tag + EAP_PSK_TAG_LEN;

	/*
	 *	Reconstruct the header H over the RECEIVED packet, then verify
	 *	the tag and decrypt the single result byte.
	 */
	eap_psk_header(header, FR_EAP_CODE_RESPONSE, eap_round->response->id,
		       in_len, in[0], session->rand_s);

	if (eap_psk_pchannel_decrypt(&plain, session->tek, nonce,
				     header, sizeof(header), cipher, 1, tag) < 0) {
		REDEBUG("Protected-channel verification failed: mutual authentication failed");
		RETURN_UNLANG_REJECT;
	}

	r = EAP_PSK_R(plain);
	if (r != EAP_PSK_R_DONE_SUCCESS) {
		REDEBUG("Peer reported result %d (not success)", r);
		RETURN_UNLANG_REJECT;
	}

	RDEBUG2("Mutual authentication succeeded");

	/*
	 *	Deliver the keying material.  The MSK is split into the
	 *	MS-MPPE-Recv-Key and MS-MPPE-Send-Key halves.
	 */
	eap_add_reply(request->parent, attr_ms_mppe_recv_key, session->msk, EAP_PSK_MPPE_KEY_LEN);
	eap_add_reply(request->parent, attr_ms_mppe_send_key, session->msk + EAP_PSK_MPPE_KEY_LEN,
		      EAP_PSK_MPPE_KEY_LEN);

	eap_round->request->code = FR_EAP_CODE_SUCCESS;
	eap_round->request->type.length = 0;

	RETURN_UNLANG_OK;
}

/*
 *	Continue an EAP-PSK session: dispatch on which message we are
 *	expecting next.
 */
static unlang_action_t mod_process(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_eap_psk_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_eap_psk_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);
	eap_psk_session_t	*session = talloc_get_type_abort(eap_session->opaque, eap_psk_session_t);
	eap_round_t		*eap_round = eap_session->this_round;

	/*
	 *	Every EAP-PSK message from the peer must be of type EAP-PSK,
	 *	and carry at least a Flags byte.
	 */
	if ((eap_round->response->type.num != FR_EAP_METHOD_PSK) ||
	    !eap_round->response->type.data ||
	    (eap_round->response->type.length < 1)) {
		REDEBUG("Invalid EAP-PSK response");
		RETURN_UNLANG_INVALID;
	}

	switch (session->state) {
	case EAP_PSK_STATE_INIT:
		return process_msg2(p_result, inst, eap_session, request);

	case EAP_PSK_STATE_MSG3_SENT:
		return process_msg4(p_result, inst, eap_session, request);

	default:
		REDEBUG("Unexpected EAP-PSK state");
		RETURN_UNLANG_FAIL;
	}
}

static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_eap_psk_t	*inst = talloc_get_type_abort(mctx->mi->data, rlm_eap_psk_t);
	CONF_SECTION	*conf = mctx->mi->conf;

	if (!inst->identity || (inst->identity[0] == '\0')) {
		cf_log_err(conf, "The 'identity' (server NAI) must not be empty");
		return -1;
	}

	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
extern rlm_eap_submodule_t rlm_eap_psk;
rlm_eap_submodule_t rlm_eap_psk = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "eap_psk",
		.inst_size	= sizeof(rlm_eap_psk_t),
		.config		= submodule_config,
		.instantiate	= mod_instantiate,	/* Create a new submodule instance */
	},
	.provides	= { FR_EAP_METHOD_PSK },
	.session_init	= mod_session_init,		/* Initialise a new EAP session */
};
