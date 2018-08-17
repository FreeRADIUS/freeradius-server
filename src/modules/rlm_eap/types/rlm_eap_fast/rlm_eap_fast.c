/*
 * rlm_eap_fast.c  contains the interfaces that are called from eap
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
 * Copyright 2016 Alan DeKok <aland@freeradius.org>
 * Copyright 2016 The FreeRADIUS server project
 */

RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */


#include "eap_fast.h"
#include "eap_fast_crypto.h"


#include <freeradius-devel/md5.h>

/*
 *	An instance of EAP-FAST
 */
typedef struct rlm_eap_fast_t {
	char const		*tls_conf_name;				//!< Name of shared TLS config.
	fr_tls_server_conf_t *tls_conf;

	char const		*default_method_name;
	int			default_method;

	char const		*virtual_server;			//!< Virtual server to use for processing
									//!< inner EAP method.
	char const		*cipher_list;				//!< cipher list specific to EAP-FAST
	bool			req_client_cert;			//!< Whether we require a client cert
									//!< in the outer tunnel.

	int			stage;					//!< Processing stage.

	uint32_t pac_lifetime;				//!< seconds to add to current time to describe PAC lifetime
	char const		*authority_identity;			//!< The identity we present in the EAP-TLS
	uint8_t			a_id[PAC_A_ID_LENGTH];			//!< The identity we present in the EAP-TLS
	char const		*pac_opaque_key;			//!< The key used to encrypt PAC-Opaque
	bool use_tunneled_reply;		//!< Use the reply attributes from the tunneled session in
						//!< the non-tunneled reply to the client.

	bool copy_request_to_tunnel;		//!< Use SOME of the request attributes from outside of the
} rlm_eap_fast_t;


static CONF_PARSER module_config[] = {
	{ "tls", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_eap_fast_t, tls_conf_name), NULL },

	{ "default_eap_type", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_eap_fast_t, default_method_name), "mschapv2" },

	{ "virtual_server", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED | PW_TYPE_NOT_EMPTY, rlm_eap_fast_t, virtual_server) , NULL},
	{ "cipher_list", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_eap_fast_t, cipher_list) , NULL},

	{ "require_client_cert", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_eap_fast_t, req_client_cert), "no" },

	{ "pac_lifetime", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_eap_fast_t, pac_lifetime), "604800" },
	{ "authority_identity", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED, rlm_eap_fast_t, authority_identity), NULL },
	{ "pac_opaque_key", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED, rlm_eap_fast_t, pac_opaque_key), NULL },
	{ "copy_request_to_tunnel", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_eap_fast_t, copy_request_to_tunnel), "no" },

	{ "use_tunneled_reply", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_eap_fast_t, use_tunneled_reply), "no" },

	CONF_PARSER_TERMINATOR
};

/*
 *	Attach the module.
 */
static int mod_instantiate(CONF_SECTION *cs, void **instance)
{
	rlm_eap_fast_t *inst;

	*instance = inst = talloc_zero(cs, rlm_eap_fast_t);
	if (!inst) return -1;

	/*
	 *	Parse the configuration attributes.
	 */
	if (cf_section_parse(cs, inst, module_config) < 0) {
		return -1;
	}

	if (!cf_section_sub_find_name2(main_config.config, "server", inst->virtual_server)) {
		ERROR("rlm_eap_fast.virtual_server: Unknown virtual server '%s'", inst->virtual_server);
		return -1;
	}

	inst->default_method = eap_name2type(inst->default_method_name);
	if (!inst->default_method) {
		ERROR("rlm_eap_fast.default_provisioning_eap_type: "
			  "Unknown EAP type %s",
				   inst->default_method_name);
		return -1;
	}

	/*
	 *	Read tls configuration, either from group given by 'tls'
	 *	option, or from the eap-tls configuration.
	 */
	inst->tls_conf = eaptls_conf_parse(cs, "tls");

	if (!inst->tls_conf) {
		ERROR("rlm_eap_fast.tls: Failed initializing SSL context");
		return -1;
	}

	if (talloc_array_length(inst->pac_opaque_key) - 1 != 32) {
		ERROR("rlm_eap_fast.pac_opaque_key: Must be 32 bytes long");
		return -1;
	}

	if (!inst->pac_lifetime) {
		ERROR("rlm_eap_fast.pac_lifetime: must be non-zero");
		return -1;
	}

	rad_assert(PAC_A_ID_LENGTH == MD5_DIGEST_LENGTH);
	FR_MD5_CTX ctx;
	fr_md5_init(&ctx);
	fr_md5_update(&ctx, inst->authority_identity, talloc_array_length(inst->authority_identity) - 1);
	fr_md5_final(inst->a_id, &ctx);

	return 0;
}

/** Allocate the FAST per-session data
 *
 */
static eap_fast_tunnel_t *eap_fast_alloc(TALLOC_CTX *ctx, rlm_eap_fast_t *inst)
{
	eap_fast_tunnel_t *t = talloc_zero(ctx, eap_fast_tunnel_t);

	t->mode = EAP_FAST_UNKNOWN;
	t->stage = TLS_SESSION_HANDSHAKE;

	t->default_method = inst->default_method;
	t->copy_request_to_tunnel = inst->copy_request_to_tunnel;
	t->use_tunneled_reply = inst->use_tunneled_reply;

	t->pac_lifetime = inst->pac_lifetime;
	t->authority_identity = inst->authority_identity;
	t->a_id = inst->a_id;
	t->pac_opaque_key = (const uint8_t *)inst->pac_opaque_key;

	t->virtual_server = inst->virtual_server;

	return t;
}

static void eap_fast_session_ticket(tls_session_t *tls_session, uint8_t *client_random,
					uint8_t *server_random, uint8_t *secret, int *secret_len)
{
	eap_fast_tunnel_t	*t = (eap_fast_tunnel_t *) tls_session->opaque;
	uint8_t			seed[2 * SSL3_RANDOM_SIZE];

	rad_assert(t->pac.key);

	memcpy(seed, server_random, SSL3_RANDOM_SIZE);
	memcpy(&seed[SSL3_RANDOM_SIZE], client_random, SSL3_RANDOM_SIZE);

	T_PRF(t->pac.key, PAC_KEY_LENGTH, "PAC to master secret label hash",
		  seed, sizeof(seed), secret, SSL_MAX_MASTER_KEY_LENGTH);
	*secret_len = SSL_MAX_MASTER_KEY_LENGTH;
}

// hostap:src/crypto/tls_openssl.c:tls_sess_sec_cb()
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
static int _session_secret(SSL *s, void *secret, int *secret_len,
			   UNUSED STACK_OF(SSL_CIPHER) *peer_ciphers,
			   UNUSED SSL_CIPHER **cipher, void *arg)
#else
static int _session_secret(SSL *s, void *secret, int *secret_len,
			   UNUSED STACK_OF(SSL_CIPHER) *peer_ciphers,
			   UNUSED const SSL_CIPHER **cipher, void *arg)
#endif
{
	// FIXME enforce non-anon cipher

	REQUEST		*request = (REQUEST *)SSL_get_ex_data(s, FR_TLS_EX_INDEX_REQUEST);
	tls_session_t	*tls_session = arg;
	eap_fast_tunnel_t	*t;

	if (!tls_session) return 0;

	t = (eap_fast_tunnel_t *) tls_session->opaque;

	if (!t->pac.key) return 0;

	RDEBUG("processing PAC-Opaque");

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
	eap_fast_session_ticket(tls_session, s->s3->client_random, s->s3->server_random, secret, secret_len);
#else
	uint8_t client_random[SSL3_RANDOM_SIZE];
	uint8_t server_random[SSL3_RANDOM_SIZE];

	SSL_get_client_random(s, client_random, sizeof(client_random));
	SSL_get_server_random(s, server_random, sizeof(server_random));

	eap_fast_session_ticket(tls_session, client_random, server_random, secret, secret_len);
#endif

	memset(t->pac.key, 0, PAC_KEY_LENGTH);
	talloc_free(t->pac.key);
	t->pac.key = NULL;

	return 1;
}

/*
 * hints from hostap:src/crypto/tls_openssl.c:tls_session_ticket_ext_cb()
 *
 * N.B. we actually always tell OpenSSL we have digested the ticket so that
 *      it does not cause a fail loop and enables us to update the PAC easily
 *
 */
static int _session_ticket(SSL *s, uint8_t const *data, int len, void *arg)
{
	tls_session_t		*tls_session = arg;
	REQUEST			*request = (REQUEST *)SSL_get_ex_data(s, FR_TLS_EX_INDEX_REQUEST);
	eap_fast_tunnel_t	*t;
	VALUE_PAIR		*fast_vps = NULL;
	vp_cursor_t		cursor;
	DICT_ATTR const	*fast_da;
	char const		*errmsg;
	int			dlen, plen;
	uint16_t		length;
	eap_fast_attr_pac_opaque_t const	*opaque = (eap_fast_attr_pac_opaque_t const *) data;
	eap_fast_attr_pac_opaque_t		opaque_plaintext;

	if (!tls_session) return 0;

	t = (eap_fast_tunnel_t *) tls_session->opaque;

	RDEBUG("PAC provided via ClientHello SessionTicket extension");

	if ((ntohs(opaque->hdr.type) & EAP_FAST_TLV_TYPE) != PAC_INFO_PAC_OPAQUE) {
		errmsg = "PAC is not of type Opaque";
error:
		RERROR("%s, sending alert to client", errmsg);
		/*
		if (tls_session_handshake_alert(request, tls_session, SSL3_AL_FATAL, SSL_AD_BAD_CERTIFICATE)) {
			RERROR("too many alerts");
			return 0;
		}
		*/
		if (t->pac.key) talloc_free(t->pac.key);

		memset(&t->pac, 0, sizeof(t->pac));
		if (fast_vps) fr_pair_list_free(&fast_vps);
		return 1;
	}

	/*
	 * we would like to use the length of the SessionTicket
	 * but Cisco hates everyone and sends a zero padding payload
	 * so we have to use the length in the PAC-Opaque header
	 */
	length = ntohs(opaque->hdr.length);
	if (len - sizeof(opaque->hdr) < length) {
		errmsg = "PAC has bad length in header";
		goto error;
	}

	if (length < PAC_A_ID_LENGTH + EVP_MAX_IV_LENGTH + EVP_GCM_TLS_TAG_LEN + 1) {
		errmsg = "PAC file too short";
		goto error;
	}

	if (memcmp(opaque->aad, t->a_id, PAC_A_ID_LENGTH)) {
		errmsg = "PAC has incorrect A_ID";
		goto error;
	}

	dlen = length - sizeof(opaque->aad) - sizeof(opaque->iv) - sizeof(opaque->tag);
	plen = eap_fast_decrypt(opaque->data, dlen, opaque->aad, PAC_A_ID_LENGTH,
					(uint8_t const *) opaque->tag, t->pac_opaque_key, opaque->iv,
					(uint8_t *)&opaque_plaintext);
	if (plen == -1) {
		errmsg = "PAC failed to decrypt";
		goto error;
	}

	fast_da = dict_attrbyname("FreeRADIUS-EAP-FAST-PAC-Opaque-TLV");
	rad_assert(fast_da != NULL);

	fast_vps = eap_fast_fast2vp((REQUEST *)tls_session, s, (uint8_t *)&opaque_plaintext, plen, fast_da, NULL);
	if (!fast_vps) return 0;

	for (VALUE_PAIR *vp = fr_cursor_init(&cursor, &fast_vps); vp; vp = fr_cursor_next(&cursor)) {
		char *value;

		switch ((vp->da->attr >> fr_attr_shift[3]) & fr_attr_mask[3]) {
		case PAC_INFO_PAC_TYPE:
			rad_assert(t->pac.type == 0);
			t->pac.type = vp->vp_integer;
			break;
		case PAC_INFO_PAC_LIFETIME:
			rad_assert(t->pac.expires == 0);
			t->pac.expires = vp->vp_integer;
			t->pac.expired = (vp->vp_integer <= time(NULL));
			break;
		case PAC_INFO_PAC_KEY:
			rad_assert(t->pac.key == NULL);
			rad_assert(vp->vp_length == PAC_KEY_LENGTH);
			t->pac.key = talloc_size(t, PAC_KEY_LENGTH);
			rad_assert(t->pac.key != NULL);
			memcpy(t->pac.key, vp->vp_octets, PAC_KEY_LENGTH);
			break;
		default:
			value = vp_aprints(tls_session, vp, '"');
			RERROR("unknown TLV: %s", value);
			talloc_free(value);
			errmsg = "unknown TLV";
			goto error;
		}
	}

	fr_pair_list_free(&fast_vps);

	if (!t->pac.type) {
		errmsg = "PAC missing type TLV";
		goto error;
	}

	if (t->pac.type != PAC_TYPE_TUNNEL) {
		errmsg = "PAC is of not of tunnel type";
		goto error;
	}

	if (!t->pac.expires) {
		errmsg = "PAC missing lifetime TLV";
		goto error;
	}

	if (!t->pac.key) {
		errmsg = "PAC missing key TLV";
		goto error;
	}

	if (!SSL_set_session_secret_cb(tls_session->ssl, _session_secret, tls_session)) {
		RERROR("Failed setting SSL session secret callback");
		return 0;
	}

	return 1;
}


/*
 *	Do authentication, by letting EAP-TLS do most of the work.
 */
static int mod_process(void *arg, eap_handler_t *handler)
{
	int rcode;
	int ret = 0;
	fr_tls_status_t	status;
	rlm_eap_fast_t *inst = (rlm_eap_fast_t *) arg;
	tls_session_t *tls_session = (tls_session_t *) handler->opaque;
	eap_fast_tunnel_t *t = (eap_fast_tunnel_t *) tls_session->opaque;
	REQUEST *request = handler->request;

	RDEBUG2("Authenticate");

	/*
	 *	We need FAST data associated with the session, so
	 *	allocate it here, if it wasn't already alloacted.
	 */
	if (!t) t = tls_session->opaque = eap_fast_alloc(tls_session, inst);

	/*
	 *	Process TLS layer until done.
	 */
	status = eaptls_process(handler);
	if ((status == FR_TLS_INVALID) || (status == FR_TLS_FAIL)) {
		REDEBUG("[eaptls process] = %s", fr_int2str(fr_tls_status_table, status, "<INVALID>"));
	} else {
		RDEBUG2("[eaptls process] = %s", fr_int2str(fr_tls_status_table, status, "<INVALID>"));
	}

	/*
	 *	Make request available to any SSL callbacks
	 */
	SSL_set_ex_data(tls_session->ssl, FR_TLS_EX_INDEX_REQUEST, request);
	switch (status) {
	/*
	 *	EAP-TLS handshake was successful, tell the
	 *	client to keep talking.
	 *
	 *	If this was EAP-TLS, we would just return
	 *	an EAP-TLS-Success packet here.
	 */
	case FR_TLS_SUCCESS:
		tls_handshake_send(request, tls_session);
		rad_assert(t != NULL);
		break;

	/*
	 *	The TLS code is still working on the TLS
	 *	exchange, and it's a valid TLS request.
	 *	do nothing.
	 */
	case FR_TLS_HANDLED:
		ret = 1;
		goto done;

	/*
	 *	Handshake is done, proceed with decoding tunneled
	 *	data.
	 */
	case FR_TLS_OK:
		break;

	/*
	 *	Anything else: fail.
	 */
	default:
		ret = 0;
		goto done;
	}

	/*
	 *	Session is established, proceed with decoding
	 *	tunneled data.
	 */
	RDEBUG2("Session established.  Proceeding to decode tunneled attributes");

	/*
	 *	Process the FAST portion of the request.
	 */
	rcode = eap_fast_process(handler, tls_session);

	switch (rcode) {
	case PW_CODE_ACCESS_REJECT:
		RDEBUG("Reject");
		eaptls_fail(handler, EAP_FAST_VERSION);
		ret = 0;
		goto done;

		/*
		 *	Access-Challenge, continue tunneled conversation.
		 */
	case PW_CODE_ACCESS_CHALLENGE:
		RDEBUG("Challenge");
		tls_handshake_send(request, tls_session);
		eaptls_request(handler->eap_ds, tls_session);
		ret = 1;
		goto done;

		/*
		 *	Success: Automatically return MPPE keys.
		 */
	case PW_CODE_ACCESS_ACCEPT:
		if (t->accept_vps) {
			RDEBUG2("Using saved attributes from the original Access-Accept");
			rdebug_pair_list(L_DBG_LVL_2, request, t->accept_vps, NULL);
			fr_pair_list_mcopy_by_num(handler->request->reply,
				  &handler->request->reply->vps,
				  &t->accept_vps, 0, 0, TAG_ANY);
		} else if (t->use_tunneled_reply) {
			RDEBUG2("No saved attributes in the original Access-Accept");
		}
		ret = eaptls_success(handler, EAP_FAST_VERSION);
		goto done;

		/*
		 *	No response packet, MUST be proxying it.
		 *	The main EAP module will take care of discovering
		 *	that the request now has a "proxy" packet, and
		 *	will proxy it, rather than returning an EAP packet.
		 */
	case PW_CODE_STATUS_CLIENT:
#ifdef WITH_PROXY
		rad_assert(handler->request->proxy != NULL);
#endif
		ret = 1;
		goto done;

	default:
		break;
	}

	/*
	 *	Something we don't understand: Reject it.
	 */
	eaptls_fail(handler, EAP_FAST_VERSION);

done:
	SSL_set_ex_data(tls_session->ssl, FR_TLS_EX_INDEX_REQUEST, NULL);

	return ret;
}

static int eap_fast_tls_start(EAP_DS * eap_ds,tls_session_t *tls_session)
{
	EAPTLS_PACKET	reply;

	reply.code = FR_TLS_START;
	reply.length = TLS_HEADER_LEN + 1 + tls_session->clean_in.used;/*flags*/

	reply.flags = tls_session->peap_flag;
	reply.flags = SET_START(reply.flags);

	reply.data = tls_session->clean_in.data;
	reply.dlen = tls_session->clean_in.used;

	eaptls_compose(eap_ds, &reply);

	return 1;
}


/*
 *	Send an initial eap-tls request to the peer, using the libeap functions.
 */
static int mod_session_init(void *type_arg, eap_handler_t *handler)
{
	int			rcode;
	tls_session_t		*tls_session;
	rlm_eap_fast_t		*inst;
	VALUE_PAIR		*vp;
	bool			client_cert;
	REQUEST			*request = handler->request;

	inst = type_arg;

	handler->tls = true;

	/*
	 *	EAP-TLS-Require-Client-Cert attribute will override
	 *	the require_client_cert configuration option.
	 */
	vp = fr_pair_find_by_num(handler->request->config, PW_EAP_TLS_REQUIRE_CLIENT_CERT, 0, TAG_ANY);
	if (vp) {
		client_cert = vp->vp_integer ? true : false;
	} else {
		client_cert = inst->req_client_cert;
	}
	handler->opaque = tls_session = eaptls_session(handler, inst->tls_conf, client_cert);

	if (!tls_session) return 0;

	if (inst->cipher_list) {
		RDEBUG("Over-riding main cipher list with '%s'", inst->cipher_list);

		if (!SSL_set_cipher_list(tls_session->ssl, inst->cipher_list)) {
			REDEBUG("Failed over-riding cipher list to '%s'.  EAP-FAST will likely not work",
				inst->cipher_list);
		}
	}

// FIXME TLSv1.2 uses a different PRF and SSL_export_keying_material("key expansion") is forbidden
#ifdef SSL_OP_NO_TLSv1_2
	/*
	 *	Forcibly disable TLSv1.2
	 */
	SSL_set_options(tls_session->ssl, SSL_OP_NO_TLSv1_2);
#endif

	/*
	 *	Push TLV of authority_identity into tls_record
	 *	call eap_tls_compose() with args
	 *
	 *	RFC 4851 section 4.1.1
	 *	N.B. mandatory/reserved flags are not applicable here
	 */
	eap_fast_tlv_append(tls_session, PAC_INFO_A_ID, false, PAC_A_ID_LENGTH, inst->a_id);
	tls_session->peap_flag = EAP_FAST_VERSION;
	tls_session->length_flag = false;
	rcode = eap_fast_tls_start(handler->eap_ds, tls_session);

	if (rcode < 0) {
		talloc_free(tls_session);
		return 0;
	}

	tls_session->record_init(&tls_session->clean_in);

	if (!SSL_set_session_ticket_ext_cb(tls_session->ssl, _session_ticket, tls_session)) {
		RERROR("Failed setting SSL session ticket callback");
		return 0;
	}

	handler->stage = PROCESS;

	return 1;
}


/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
extern rlm_eap_module_t rlm_eap_fast;
rlm_eap_module_t rlm_eap_fast = {
	.name		= "eap_fast",
	.instantiate	= mod_instantiate,	/* Create new submodule instance */
	.session_init	= mod_session_init,	/* Initialise a new EAP session */
	.process	= mod_process		/* Process next round of EAP method */
};
