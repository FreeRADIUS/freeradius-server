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

/* EAP-PWD can use different preprocessing (prep) modes to mangle the password
 * before proving to both parties that they both know the same (mangled) password.
 *
 * The server advertises a preprocessing mode to the client. Only "none" is
 * mandatory to implement.
 *
 * What is a good selection on the preprocessing mode?
 *
 * a) the server uses a hashed password
 * b) the client uses a hashed password
 *
 * a | b | result
 * --+---+---------------------------------------
 * n | n | none
 * n | y | hint needed (cannot know automatically)
 * y | n | select by hash given
 * y | y | only works if both have the same hash; select by hash given
 *
 * Which hash functions does the server or client need to implement?
 *
 * a | b | server                 | client
 * --+---+------------------------+----------------------
 * n | n | none                   | none
 * n | y | as configured          | none
 * y | n | none                   | as selected by server
 * y | y | none                   | none
 *
 * RFC 5931 defines 3 and RFC 8146 another 8 hash functions to implement.
 * Can we avoid implementing them all? Only if they are provided as hash by some
 * other module, e.g. in SQL or statically in password database.
 *
 * Therefore we select the preprocessing mode by the type of password given if
 * in automatic mode:
 * a) Cleartext-Password or User-Password: None.
 *    If the client only supports a hash (e.g. on Windows it might only have an
 *    NT-Password), do not provide a Cleartext-Password attribute but instead
 *    preprocess the password externally (e.g. hash the Cleartext-Password
 *    into an NT-Password and drop the Cleartext-Password).
 * b) NT-Password: rfc2759 (prep=MS).
 *    The NT-Password Hash is hashed into a HashNTPasswordHash hash.
 * c) EAP-Pwd-Password-Hash - provides hash as binary
 *    EAP-Pwd-Password-Salt - (optional) salt to be transmitted to client
 *                            (RFC 8146)
 *    EAP-Pwd-Password-Prep - constant to transmit to client in prep field
 *
 * Though, there is one issue left. The method needs to be selected in
 * EAP-PWD-ID/Request, that is the first message from server and thus before
 * the client sent its peer-id. This is feasable using the EAP-Identity frame
 * (outer identity); EAP-PWD does transmit its peer-id in plaintext anyway.
 * So we need a toggle for this, in case anybody needs rlm_eap_pwd to use
 * only the peer_id (inner identity). This toogle is an integer to also support
 * setting currently unknown nor not implemented preprocessing methods.
 *
 * The toogle is named "prep", is a module configuration item, and accepts the
 * following values:
 *   prep | meaning
 * -------+--------------------------------------------------------------------
 * -1     | [automatic] discover using method described above from EAP-Identity
 *        |             as User-Name before EAP-PWD-Id/Request
 * 0..255 | [static]    Fixed password preprocessing method. Expects virtual
 *        |             server to provide matching password given EAP-PWD
 *        |             peer-id as User-Name. The virtual server is provided
 *        |             with EAP-Pwd-Password-Prep containing the configured
 *        |             prep value.
 * else   | reserved/invalid
 *
 * Attributes to provide Password/Password-Hash and possibly salt.
 *   prep | accepted attributes
 * -------+--------------------------------------------------------------------
 * -1     | see above for automatic discovery
 * 0      | Use Cleartext-Password or give cleartext in EAP-Pwd-Password-Hash
 * 1      | Use NT-Password, Cleartext-Password, User-Password or
 *        | give hashed NT-Password hash in EAP-Pwd-Password-Hash
 * 2..255 | Use EAP-Pwd-Password-Hash and possibly EAP-Pwd-Pasword-Salt.
 *
 * To be able to pass EAP-Pwd-Password-Hash and EAP-Pwd-Password-Salt als hex
 * string, they are decoded as hex if module config option unhex=1 (default).
 * Set it to zero if you provide binary input.
 */

static CONF_PARSER pwd_module_config[] = {
	{ "group", FR_CONF_OFFSET(PW_TYPE_INTEGER, eap_pwd_t, group), "19" },
	{ "fragment_size", FR_CONF_OFFSET(PW_TYPE_INTEGER, eap_pwd_t, fragment_size), "1020" },
	{ "server_id", FR_CONF_OFFSET(PW_TYPE_STRING, eap_pwd_t, server_id), NULL },
	{ "virtual_server", FR_CONF_OFFSET(PW_TYPE_STRING, eap_pwd_t, virtual_server), NULL },
	{ "prep", FR_CONF_OFFSET(PW_TYPE_SIGNED, eap_pwd_t, prep), "0" },
	{ "unhex", FR_CONF_OFFSET(PW_TYPE_SIGNED, eap_pwd_t, unhex), "1" },
	CONF_PARSER_TERMINATOR
};

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

	if (inst->prep < -1 || inst->prep > 255) {
		cf_log_err_cs(cs, "Invalid value for password preparation method: %d", inst->prep);
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
	BN_CTX_free(session->bnctx);

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

static void normify(REQUEST *request, VALUE_PAIR *vp)
{
	size_t decoded;
	size_t expected_len;
	uint8_t *buffer;

	rad_assert((vp->da->type == PW_TYPE_OCTETS) || (vp->da->type == PW_TYPE_STRING));

	if (vp->vp_length % 2 != 0 || vp->vp_length == 0) return;

	expected_len = vp->vp_length / 2;
	buffer = talloc_zero_array(request, uint8_t, expected_len);
	rad_assert(buffer);

	decoded = fr_hex2bin(buffer, expected_len, vp->vp_strvalue, vp->vp_length);
	if (decoded == expected_len) {
		RDEBUG2("Normalizing %s from hex encoding, %zu bytes -> %zu bytes",
			vp->da->name, vp->vp_length, decoded);
		fr_pair_value_memcpy(vp, buffer, decoded);
	} else {
		RDEBUG2("Normalizing %s from hex encoding, %zu bytes -> %zu bytes failed, got %zu bytes",
			vp->da->name, vp->vp_length, expected_len, decoded);
	}

	talloc_free(buffer);
}

static int fetch_and_process_password(pwd_session_t *session, REQUEST *request, eap_pwd_t *inst) {
	REQUEST *fake;
	VALUE_PAIR *vp, *pw;
	const char *pwbuf;
	int pw_len;
	uint8_t nthash[MD4_DIGEST_LENGTH];
	uint8_t nthashash[MD4_DIGEST_LENGTH];
	int ret = -1;
	eap_type_t old_eap_type;

	if ((fake = request_alloc_fake(request)) == NULL) {
		RDEBUG("pwd unable to create fake request!");
		return ret;
	}
	fake->username = fr_pair_afrom_num(fake->packet, PW_USER_NAME, 0);
	if (!fake->username) {
		RDEBUG("Failed creating pair for peer id");
		goto out;
	}
	fr_pair_value_bstrncpy(fake->username, session->peer_id, session->peer_id_len);
	fr_pair_add(&fake->packet->vps, fake->username);

	if (inst->prep >= 0) {
		vp = fr_pair_afrom_num(fake, PW_EAP_PWD_PASSWORD_PREP, 0);
		rad_assert(vp != NULL);
		vp->vp_byte = inst->prep;
		fr_pair_add(&fake->packet->vps, vp);
	}

	if ((vp = fr_pair_find_by_num(request->config, PW_VIRTUAL_SERVER, 0, TAG_ANY)) != NULL) {
		fake->server = vp->vp_strvalue;
	} else if (inst->virtual_server) {
		fake->server = inst->virtual_server;
	} /* else fake->server == request->server */

	if ((vp = fr_pair_find_by_num(request->packet->vps, PW_EAP_TYPE, 0, TAG_ANY)) != NULL) {
		/* EAP-Type = NAK here if inst->prep == -1.
		 * But this does not help the virtual server to differentiate
		 * based on which EAP method was selected, that is to property
		 * prepare session-state: for PWD.
		 * So fake EAP-Type = PWD here for the time of the inner request.
		 */
		old_eap_type = vp->vp_integer;
		vp->vp_integer = PW_EAP_PWD;
	}
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

	if ((vp = fr_pair_find_by_num(request->packet->vps, PW_EAP_TYPE, 0, TAG_ANY)) != NULL) {
		vp->vp_integer = old_eap_type;
	}

	pw = fr_pair_find_by_num(fake->config, PW_CLEARTEXT_PASSWORD, 0, TAG_ANY);
	if (!pw) {
		pw = fr_pair_find_by_num(fake->config, PW_USER_PASSWORD, 0, TAG_ANY);
	}

	if (pw && (inst->prep < 0 || inst->prep == EAP_PWD_PREP_NONE)) {
		VERIFY_VP(pw);
		session->prep = EAP_PWD_PREP_NONE;

		RDEBUG("Use Cleartext-Password or User-Password for %s to do pwd authentication",
			session->peer_id);

		pwbuf = pw->vp_strvalue;
		pw_len = pw->vp_length;

		goto success;
	}

	pw = fr_pair_find_by_num(fake->config, PW_NT_PASSWORD, 0, TAG_ANY);

	if (pw && (inst->prep < 0 || inst->prep == EAP_PWD_PREP_MS)) {
		VERIFY_VP(pw);
		session->prep = EAP_PWD_PREP_MS;

		RDEBUG("Use NT-Password for %s to do pwd authentication",
			session->peer_id);

		if (pw->vp_length != MD4_DIGEST_LENGTH) {
			RDEBUG("NT-Password invalid length");
			goto out;
		}

		fr_md4_calc(nthashash, pw->vp_octets, pw->vp_length);
		pwbuf = (const char*) nthashash;
		pw_len = MD4_DIGEST_LENGTH;

		goto success;
	}

	pw = fr_pair_find_by_num(fake->config, PW_CLEARTEXT_PASSWORD, 0, TAG_ANY);
	if (!pw) {
		pw = fr_pair_find_by_num(fake->config, PW_USER_PASSWORD, 0, TAG_ANY);
	}

	if (pw && inst->prep == EAP_PWD_PREP_MS) {
		VERIFY_VP(pw);
		session->prep = EAP_PWD_PREP_NONE;

		RDEBUG("Use Cleartext-Password or User-Password as NT-Password for %s to do pwd authentication",
			session->peer_id);

		// compute NT-Hash from Cleartext-Password
		ssize_t len;
		uint8_t ucs2_password[512];
		len = fr_utf8_to_ucs2(ucs2_password, sizeof(ucs2_password), pw->vp_strvalue, pw->vp_length);
		if (len < 0) {
			ERROR("rlm_eap_pwd: Error converting password to UCS2");
			goto out;
		}
		fr_md4_calc(nthash, ucs2_password, len);

		fr_md4_calc(nthashash, nthash, MD4_DIGEST_LENGTH);
		pwbuf = (const char*) nthashash;
		pw_len = MD4_DIGEST_LENGTH;

		goto success;
	}

	vp = fr_pair_find_by_num(fake->config, PW_EAP_PWD_PASSWORD_PREP, 0, TAG_ANY);
	if (vp) {
		VERIFY_VP(vp);
	}
	if (vp && inst->prep < 0) {
		RDEBUG("Use EAP-Pwd-Password-Prep %u for %s to do pwd authentication",
			vp->vp_byte, session->peer_id);
		session->prep = vp->vp_byte;
	} else if (vp && inst->prep != vp->vp_byte) {
		RDEBUG2("Mismatch of configured password preparation method and provided EAP-Pwd-Password-Prep attribute type for %s",
			session->peer_id);
		goto out;
	} else if (inst->prep < 0) {
		RDEBUG2("Missing EAP-Pwd-Password-Prep for %s",
			session->peer_id);
		goto out;
	}

	pw = fr_pair_find_by_num(fake->config, PW_EAP_PWD_PASSWORD_SALT, 0, TAG_ANY);
	if (pw) {
		VERIFY_VP(pw);

		RDEBUG("Use EAP-Pwd-Password-Salt for %s to do pwd authentication",
			session->peer_id);

		if (inst->unhex) normify(request, pw);

		if (pw->vp_length > 255) {
			/* salt len is 1 byte */
			RDEBUG("EAP-Pwd-Password-Salt too long (more than 255 octets)");
			goto out;
		}
		rad_assert(pw->vp_length <= sizeof(session->salt));

		session->salt_present = 1;
		session->salt_len = pw->vp_length;
		memcpy(session->salt, pw->vp_octets, pw->vp_length);
	}

	pw = fr_pair_find_by_num(fake->config, PW_EAP_PWD_PASSWORD_HASH, 0, TAG_ANY);
	if (pw) {
		VERIFY_VP(pw);

		RDEBUG("Use EAP-Pwd-Password-Hash for %s to do pwd authentication",
			session->peer_id);

		if (inst->unhex) normify(request, pw);

		pwbuf = (const char*) pw->vp_octets;
		pw_len = pw->vp_length;

		goto success;
	}

	RDEBUG2("Mismatch of password preparation method and provided password attribute type for %s",
		session->peer_id);
	goto out;

success:
	if (RDEBUG_ENABLED4) {
		char outbuf[1024];
		char *p = outbuf;
		for (int i = 0; i < pw_len && p < outbuf + sizeof(outbuf) - 3; i++) {
			p += sprintf(p, "%02hhX", pwbuf[i]);
		}
		RDEBUG4("hex pw data: %s (%d)", outbuf, pw_len);
	}

	if (compute_password_element(session, session->group_num,
				     pwbuf, pw_len,
				     inst->server_id, strlen(inst->server_id),
				     session->peer_id, strlen(session->peer_id),
				     &session->token)) {
		RDEBUG("failed to obtain password element");
		goto out;
	}

	ret = 0;
out:
	talloc_free(fake);
	return ret;
}

static int mod_session_init (void *instance, eap_handler_t *handler)
{
	pwd_session_t *session;
	eap_pwd_t *inst = (eap_pwd_t *)instance;
	VALUE_PAIR *vp;
	pwd_id_packet_t *packet;
	REQUEST *request;

	if (!inst || !handler) {
		ERROR("rlm_eap_pwd: Initiate, NULL data provided");
		return 0;
	}

	request = handler->request;
	if (!request) {
		ERROR("rlm_eap_pwd: NULL request provided");
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

	session->bnctx = BN_CTX_new();
	if (session->bnctx == NULL) {
		ERROR("rlm_eap_pwd: Failed to get BN context");
		return 0;
	}

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

	session->token = fr_rand();
	if (inst->prep < 0) {
		RDEBUG2("using outer identity %s to configure EAP-PWD", handler->identity);
		session->peer_id_len = strlen(handler->identity);
		if (session->peer_id_len >= sizeof(session->peer_id)) {
			RDEBUG("identity is malformed");
			return 0;
		}
		memcpy(session->peer_id, handler->identity, session->peer_id_len);
		session->peer_id[session->peer_id_len] = '\0';

		/*
		 * make fake request to get the password for the usable ID
		 * in order to identity prep
		 */
		if (fetch_and_process_password(session, handler->request, inst) < 0) {
			RDEBUG("failed to find password for %s to do pwd authentication (init)",
				session->peer_id);
			return 0;
		}
	} else {
		session->prep = inst->prep;
	}

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
	memcpy(packet->token, (char *)&session->token, 4);
	packet->prep = session->prep;
	memcpy(packet->identity, inst->server_id, session->out_len - sizeof(pwd_id_packet_t) );

	handler->stage = PROCESS;

	return send_pwd_request(session, handler->eap_ds);
}

static int mod_process(void *arg, eap_handler_t *handler)
{
	pwd_session_t *session;
	pwd_hdr *hdr;
	pwd_id_packet_t *packet;
	REQUEST *request;
	eap_packet_t *response;
	EAP_DS *eap_ds;
	size_t in_len, peer_id_len;
	int ret = 0;
	eap_pwd_t *inst = (eap_pwd_t *)arg;
	uint16_t offset;
	uint8_t exch, *in, *ptr, msk[MSK_EMSK_LEN], emsk[MSK_EMSK_LEN];
	uint8_t peer_confirm[SHA256_DIGEST_LENGTH];
	char *peer_id;

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
		if (!session->in) {
			RDEBUG2("Unexpected fragment.");
			return 0;
		}

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
	{
		BIGNUM	*x = NULL, *y = NULL;

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
		    (packet->prep != session->prep) ||
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

		peer_id_len = in_len - sizeof(pwd_id_packet_t);
		if (peer_id_len >= sizeof(session->peer_id)) {
			RDEBUG2("pwd id response is malformed");
			return 0;
		}
		peer_id = packet->identity;

		if (inst->prep >= 0) {
			/*
			 * make fake request to get the password for the usable ID
			 */

			session->peer_id_len = peer_id_len;
			memcpy(session->peer_id, peer_id, peer_id_len);
			session->peer_id[peer_id_len] = '\0';

			if (fetch_and_process_password(session, request, inst) < 0) {
				RDEBUG2("failed to find password for %s to do pwd authentication",
				session->peer_id);
				return 0;
			}
		} else {
			/* verify inner identity == outer identity */
			if (session->peer_id_len != peer_id_len ||
			    memcmp(session->peer_id, peer_id, peer_id_len) != 0) {
				char buf[sizeof(session->peer_id)];
				memcpy(buf, peer_id, peer_id_len);
				buf[peer_id_len] = '\0';

				RDEBUG2("inner identity(peer_id) %s does not match outer identity %s",
				buf, session->peer_id);
				return 0;
			}
			RDEBUG2("inner identity matched for %s", session->peer_id);
		}

		/*
		 * compute our scalar and element
		 */
		if (compute_scalar_element(session, session->bnctx)) {
			DEBUG2("failed to compute server's scalar and element");
			return 0;
		}

		MEM(x = BN_new());
		MEM(y = BN_new());

		/*
		 * element is a point, get both coordinates: x and y
		 */
		if (!EC_POINT_get_affine_coordinates_GFp(session->group, session->my_element, x, y,
							 session->bnctx)) {
			DEBUG2("server point assignment failed");
			BN_clear_free(x);
			BN_clear_free(y);
			return 0;
		}

		/*
		 * construct request
		 */
		session->out_len = BN_num_bytes(session->order) + (2 * BN_num_bytes(session->prime));
		if (session->salt_present)
			session->out_len += 1 + session->salt_len;

		if ((session->out = talloc_array(session, uint8_t, session->out_len)) == NULL) {
			return 0;
		}
		memset(session->out, 0, session->out_len);

		ptr = session->out;
		if (session->salt_present) {
			*ptr = session->salt_len;
			ptr++;

			memcpy(ptr, session->salt, session->salt_len);
			ptr += session->salt_len;
		}

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
		ret = send_pwd_request(session, eap_ds);
	}
		break;

	case PWD_STATE_COMMIT:
		if (EAP_PWD_GET_EXCHANGE(hdr) != EAP_PWD_EXCH_COMMIT) {
			RDEBUG2("pwd exchange is incorrect: not commit!");
			return 0;
		}

		/*
		 * process the peer's commit and generate the shared key, k
		 */
		if (process_peer_commit(session, in, in_len, session->bnctx)) {
			RDEBUG2("failed to process peer's commit");
			return 0;
		}

		/*
		 * compute our confirm blob
		 */
		if (compute_server_confirm(session, session->my_confirm, session->bnctx)) {
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
		if (compute_peer_confirm(session, peer_confirm, session->bnctx)) {
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
};

