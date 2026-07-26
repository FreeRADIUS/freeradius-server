/*
 * rlm_eap_psk.c    Implements EAP-PSK
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
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */

RCSID("$Id$")

#include <stdio.h>
#include <stdlib.h>

#include "eap_psk.h"

#include <freeradius-devel/rad_assert.h>

#include <openssl/rand.h>
#include <openssl/crypto.h>

/*
 *	The MSK is split into a 32-byte MS-MPPE-Recv-Key and a 32-byte
 *	MS-MPPE-Send-Key, as is done with all other EAP methods.
 */
#define EAP_PSK_MPPE_KEY_LEN	32

typedef struct rlm_eap_psk_t {
	char const	*identity;	//!< The server NAI (ID_S) sent in the first message.
} rlm_eap_psk_t;

static CONF_PARSER module_config[] = {
	{ "identity", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_eap_psk_t, identity), "FreeRADIUS" },

	CONF_PARSER_TERMINATOR
};

static int mod_instantiate(CONF_SECTION *cs, void **instance)
{
	rlm_eap_psk_t	*inst;

	*instance = inst = talloc_zero(cs, rlm_eap_psk_t);
	if (!inst) return -1;

	if (cf_section_parse(cs, inst, module_config) < 0) return -1;

	if (!inst->identity || (inst->identity[0] == '\0')) {
		cf_log_err_cs(cs, "The 'identity' (server NAI) must not be empty");
		return -1;
	}

	return 0;
}

/*
 *	Write the EAP-PSK message fields into the outgoing eap_ds->request.
 *	'flags' is the 1-byte EAP-PSK Flags field, and 'body'/'body_len' are
 *	the bytes that follow RAND_S (MAC and PCHANNEL, or ID_S).
 */
static int eap_psk_compose(EAP_DS *eap_ds, uint8_t flags,
			   uint8_t const rand_s[EAP_PSK_RAND_LEN],
			   uint8_t const *body, size_t body_len)
{
	uint8_t	*p;

	eap_ds->request->code = PW_EAP_REQUEST;
	eap_ds->request->type.num = PW_EAP_PSK;
	eap_ds->request->type.length = 1 + EAP_PSK_RAND_LEN + body_len;

	eap_ds->request->type.data = talloc_array(eap_ds->request, uint8_t,
						  eap_ds->request->type.length);
	if (!eap_ds->request->type.data) return 0;

	p = eap_ds->request->type.data;
	*p++ = flags;

	memcpy(p, rand_s, EAP_PSK_RAND_LEN);
	p += EAP_PSK_RAND_LEN;
	if (body_len > 0) memcpy(p, body, body_len);

	return 1;
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
	header[4] = PW_EAP_PSK;
	header[5] = flags;

	memcpy(header + 6, rand_s, EAP_PSK_RAND_LEN);
}

/*
 *	Initiate the EAP-PSK session by sending the first message:
 *	Flags(T=0) || RAND_S || ID_S.
 */
static int mod_session_init(void *instance, eap_handler_t *handler)
{
	rlm_eap_psk_t		*inst = talloc_get_type_abort(instance, rlm_eap_psk_t);
	eap_psk_session_t	*session;
	REQUEST			*request = handler->request;
	size_t			id_s_len;

	session = talloc_zero(handler, eap_psk_session_t);
	if (!session) return 0;

	/*
	 *	Get a fresh random server nonce.  RFC 4764 requires a
	 *	cryptographic-quality RNG here, so we use OpenSSL.
	 */
	if (RAND_bytes(session->rand_s, sizeof(session->rand_s)) != 1) {
		REDEBUG("Failed generating RAND_S");
		talloc_free(session);
		return 0;
	}

	session->state = EAP_PSK_STATE_INIT;

	handler->opaque = session;
	handler->free_opaque = NULL;		/* talloc'd from handler */

	id_s_len = strlen(inst->identity);

	RDEBUG2("Sending EAP-PSK first message as \"%s\"", inst->identity);

	if (!eap_psk_compose(handler->eap_ds, EAP_PSK_FLAGS_FIRST, session->rand_s,
			     (uint8_t const *) inst->identity, id_s_len)) {
		return 0;
	}

	handler->stage = PROCESS;

	return 1;
}

/*
 *	Process the peer's second message and, if it passes the PSK
 *	checks, send the third message.
 */
static int process_msg2(rlm_eap_psk_t *inst, eap_handler_t *handler,
			eap_psk_session_t *session)
{
	REQUEST		*request = handler->request;
	EAP_DS		*eap_ds = handler->eap_ds;
	uint8_t		*in = eap_ds->response->type.data;
	size_t		in_len = eap_ds->response->type.length;
	VALUE_PAIR	*password;

	uint8_t const	*rand_s_echo, *rand_p, *mac_p, *id_p;
	size_t		id_p_len, id_s_len;
	uint8_t		psk[EAP_PSK_PSK_LEN];
	uint8_t		ak[EAP_PSK_AK_LEN], kdk[EAP_PSK_KDK_LEN];
	uint8_t		expected[EAP_PSK_MAC_LEN], mac_s[EAP_PSK_MAC_LEN];
	uint8_t		body[EAP_PSK_MAC_LEN + EAP_PSK_PCHANNEL_LEN];
	uint8_t		header[EAP_PSK_HEADER_LEN];
	uint8_t		plain, cipher;
	uint8_t		*p;
	uint32_t	nonce = 0;

	/*
	 *	Flags(1) || RAND_S(16) || RAND_P(16) || MAC_P(16) || ID_P(*)
	 */
	if (in_len < (size_t) (1 + EAP_PSK_RAND_LEN + EAP_PSK_RAND_LEN + EAP_PSK_MAC_LEN)) {
		REDEBUG("EAP-PSK second message is too short");
		return 0;
	}

	if ((in[0] & EAP_PSK_T_MASK) != EAP_PSK_FLAGS_SECOND) {
		REDEBUG("EAP-PSK second message has the wrong T flag");
		return 0;
	}

	rand_s_echo = in + 1;
	rand_p      = rand_s_echo + EAP_PSK_RAND_LEN;
	mac_p       = rand_p + EAP_PSK_RAND_LEN;
	id_p        = mac_p + EAP_PSK_MAC_LEN;
	id_p_len    = in_len - (1 + EAP_PSK_RAND_LEN + EAP_PSK_RAND_LEN + EAP_PSK_MAC_LEN);

	/*
	 *	The peer must echo the RAND_S we sent.  Constant-time compare.
	 */
	if (rad_digest_cmp(rand_s_echo, session->rand_s, EAP_PSK_RAND_LEN) != 0) {
		REDEBUG("EAP-PSK second message did not echo RAND_S");
		return 0;
	}

	/*
	 *	The pre-shared key is the (exactly 16-byte) Cleartext-Password.
	 *
	 *	The easiest way to set that is to use a hex string, or
	 *	to MD5 the actual password.
	 */
	password = fr_pair_find_by_num(request->config, PW_PSK_PASSWORD, 0, TAG_ANY);
	if (!password) {
		REDEBUG("PSK-Password is required for EAP-PSK authentication");
		return 0;
	}

	if (password->vp_length != EAP_PSK_PSK_LEN) {
		REDEBUG("EAP-PSK requires a %d-byte PSK-Password, got %zu bytes",
			EAP_PSK_PSK_LEN, password->vp_length);
		return 0;
	}
	memcpy(psk, password->vp_octets, EAP_PSK_PSK_LEN);

	id_s_len = strlen(inst->identity);

	/*
	 *	Key setup, then verify MAC_P before doing anything else.
	 */
	if (eap_psk_derive_ak_kdk(psk, ak, kdk) < 0) {
		REDEBUG("EAP-PSK key setup failed");
		return 0;
	}

	if (eap_psk_mac_p(ak, id_p, id_p_len,
			  (uint8_t const *) inst->identity, id_s_len,
			  session->rand_s, rand_p, expected) < 0) {
		REDEBUG("EAP-PSK MAC_P computation failed");
		return 0;
	}

	if (rad_digest_cmp(expected, mac_p, EAP_PSK_MAC_LEN) != 0) {
		REDEBUG("EAP-PSK MAC_P is incorrect: the peer used the wrong key");
		return 0;
	}

	RDEBUG2("EAP-PSK peer authenticated (MAC_P valid)");

	/*
	 *	Derive the session keys and compute MAC_S for the peer.
	 */
	if (eap_psk_derive_keys(kdk, rand_p, session->tek, session->msk, session->emsk) < 0) {
		REDEBUG("EAP-PSK session-key derivation failed");
		return 0;
	}

	if (eap_psk_mac_s(ak, (uint8_t const *) inst->identity, id_s_len,
			  rand_p, mac_s) < 0) {
		REDEBUG("EAP-PSK MAC_S computation failed");
		return 0;
	}

	/*
	 *	Build the third message body: MAC_S || PCHANNEL.
	 *
	 *	The PCHANNEL protects the 22-byte header H, which depends on
	 *	the EAP Id and Length of THIS reply.  Pin the Id so that the
	 *	value we authenticate matches what goes on the wire.
	 */
	eap_ds->request->id = eap_ds->response->id + 1;
	eap_ds->set_request_id = 1;

	eap_psk_header(header, PW_EAP_REQUEST, eap_ds->request->id,
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

	if (eap_psk_pchannel_encrypt(session->tek, nonce, header, sizeof(header),
				     &plain, 1, &cipher, p) < 0) {
		REDEBUG("EAP-PSK protected-channel encryption failed");
		return 0;
	}
	p += EAP_PSK_TAG_LEN;
	*p++ = cipher;

	if (!eap_psk_compose(eap_ds, EAP_PSK_FLAGS_THIRD, session->rand_s,
			     body, EAP_PSK_MAC_LEN + EAP_PSK_PCHANNEL_LEN)) {
		return 0;
	}

	session->state = EAP_PSK_STATE_MSG3_SENT;

	return 1;
}

/*
 *	Process the peer's fourth message.  On success, deliver the keying
 *	material in MPPE keys, and return an EAP-Success.
 */
static int process_msg4(UNUSED rlm_eap_psk_t *inst, eap_handler_t *handler,
			eap_psk_session_t *session)
{
	REQUEST		*request = handler->request;
	EAP_DS		*eap_ds = handler->eap_ds;
	uint8_t		*in = eap_ds->response->type.data;
	size_t		in_len = eap_ds->response->type.length;

	uint8_t const	*rand_s_echo, *pchannel, *tag, *cipher;
	uint8_t		header[EAP_PSK_HEADER_LEN];
	uint8_t		plain;
	uint32_t	nonce = 1;
	int		r;

	/*
	 *	Flags(1) || RAND_S(16) || PCHANNEL(21)
	 */
	if (in_len < (size_t) (1 + EAP_PSK_RAND_LEN + EAP_PSK_PCHANNEL_LEN)) {
		REDEBUG("EAP-PSK fourth message is too short");
		return 0;
	}

	if ((in[0] & EAP_PSK_T_MASK) != EAP_PSK_FLAGS_FOURTH) {
		REDEBUG("EAP-PSK fourth message has the wrong T flag");
		return 0;
	}

	rand_s_echo = in + 1;
	pchannel    = rand_s_echo + EAP_PSK_RAND_LEN;

	if (rad_digest_cmp(rand_s_echo, session->rand_s, EAP_PSK_RAND_LEN) != 0) {
		REDEBUG("EAP-PSK fourth message did not echo RAND_S");
		return 0;
	}

	/*
	 *	The peer's PCHANNEL nonce for the fourth message is 1.
	 */
	if ((pchannel[0] != 0) || (pchannel[1] != 0) || (pchannel[2] != 0) ||
	    (pchannel[3] != (uint8_t) nonce)) {
		REDEBUG("EAP-PSK fourth message has an unexpected Nonce");
		return 0;
	}

	tag    = pchannel + EAP_PSK_NONCE_LEN;
	cipher = tag + EAP_PSK_TAG_LEN;

	/*
	 *	Reconstruct the header H over the RECEIVED packet, then verify
	 *	the tag and decrypt the single result byte.
	 */
	eap_psk_header(header, PW_EAP_RESPONSE, eap_ds->response->id,
		       in_len, in[0], session->rand_s);

	if (eap_psk_pchannel_decrypt(session->tek, nonce, header, sizeof(header),
				     cipher, 1, tag, &plain) < 0) {
		REDEBUG("EAP-PSK protected-channel verification failed: mutual authentication failed");
		return 0;
	}

	r = EAP_PSK_R(plain);
	if (r != EAP_PSK_R_DONE_SUCCESS) {
		REDEBUG("EAP-PSK peer reported result %d (not success)", r);
		return 0;
	}

	RDEBUG2("EAP-PSK mutual authentication succeeded");

	/*
	 *	Deliver the keying material.  The MSK is split into the
	 *	MS-MPPE-Recv-Key and MS-MPPE-Send-Key halves.
	 */
	eap_add_reply(request, "MS-MPPE-Recv-Key", session->msk, EAP_PSK_MPPE_KEY_LEN);
	eap_add_reply(request, "MS-MPPE-Send-Key", session->msk + EAP_PSK_MPPE_KEY_LEN,
		      EAP_PSK_MPPE_KEY_LEN);

	eap_ds->request->code = PW_EAP_SUCCESS;
	eap_ds->request->type.length = 0;

	return 1;
}

/*
 *	Continue an EAP-PSK session: dispatch on which message we are
 *	expecting next.
 */
static int mod_process(void *instance, eap_handler_t *handler)
{
	rlm_eap_psk_t		*inst = talloc_get_type_abort(instance, rlm_eap_psk_t);
	eap_psk_session_t	*session;
	REQUEST			*request = handler->request;

	rad_assert(handler->request != NULL);
	rad_assert(handler->stage == PROCESS);

	session = talloc_get_type_abort(handler->opaque, eap_psk_session_t);

	/*
	 *	Every EAP-PSK message from the peer must be of type EAP-PSK,
	 *	and carry at least a Flags byte.
	 */
	if ((handler->eap_ds->response->type.num != PW_EAP_PSK) ||
	    !handler->eap_ds->response->type.data ||
	    (handler->eap_ds->response->type.length < 1)) {
		REDEBUG("Invalid EAP-PSK response");
		return 0;
	}

	switch (session->state) {
	case EAP_PSK_STATE_INIT:
		return process_msg2(inst, handler, session);

	case EAP_PSK_STATE_MSG3_SENT:
		return process_msg4(inst, handler, session);

	default:
		REDEBUG("Unexpected EAP-PSK state");
		return 0;
	}
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
extern rlm_eap_module_t rlm_eap_psk;
rlm_eap_module_t rlm_eap_psk = {
	.name		= "eap_psk",
	.instantiate	= mod_instantiate,	/* Create a new submodule instance */
	.session_init	= mod_session_init,	/* Initialise a new EAP session */
	.process	= mod_process		/* Process next round of EAP method */
};
