/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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
 * @file rlm_eap_fast.c
 * @brief contains the interfaces that are called from eap
 *
 * @author Alexander Clouter (alex@digriz.org.uk)
 *
 * @copyright 2016 Alan DeKok (aland@freeradius.org)
 * @copyright 2016 The FreeRADIUS server project
 */
RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#include <freeradius-devel/util/md5.h>

#include "eap_fast.h"
#include "eap_fast_crypto.h"

/*
 *	An instance of EAP-FAST
 */
typedef struct {
	char const		*tls_conf_name;				//!< Name of shared TLS config.
	fr_tls_conf_t		*tls_conf;				//!< TLS config pointer.

	char const		*default_provisioning_method_name;
	int			default_provisioning_method;

	char const		*virtual_server;			//!< Virtual server to use for processing
									//!< inner EAP method.
	char const		*cipher_list;				//!< cipher list specific to EAP-FAST
	bool			req_client_cert;			//!< Whether we require a client cert
									//!< in the outer tunnel.

	int			stage;					//!< Processing stage.

	uint32_t		pac_lifetime;				//!< seconds to add to current time to describe PAC lifetime
	char const		*authority_identity;			//!< The identity we present in the EAP-TLS
	uint8_t			a_id[PAC_A_ID_LENGTH];			//!< The identity we present in the EAP-TLS
	char const		*pac_opaque_key;			//!< The key used to encrypt PAC-Opaque
} rlm_eap_fast_t;


static CONF_PARSER submodule_config[] = {
	{ FR_CONF_OFFSET("tls", FR_TYPE_STRING, rlm_eap_fast_t, tls_conf_name) },

	{ FR_CONF_OFFSET("default_provisioning_eap_type", FR_TYPE_STRING, rlm_eap_fast_t, default_provisioning_method_name), .dflt = "mschapv2" },

	{ FR_CONF_OFFSET("virtual_server", FR_TYPE_STRING | FR_TYPE_REQUIRED | FR_TYPE_NOT_EMPTY, rlm_eap_fast_t, virtual_server) },
	{ FR_CONF_OFFSET("cipher_list", FR_TYPE_STRING, rlm_eap_fast_t, cipher_list) },

	{ FR_CONF_OFFSET("require_client_cert", FR_TYPE_BOOL, rlm_eap_fast_t, req_client_cert), .dflt = "no" },

	{ FR_CONF_OFFSET("pac_lifetime", FR_TYPE_UINT32, rlm_eap_fast_t, pac_lifetime), .dflt = "604800" },
	{ FR_CONF_OFFSET("authority_identity", FR_TYPE_STRING | FR_TYPE_REQUIRED, rlm_eap_fast_t, authority_identity) },
	{ FR_CONF_OFFSET("pac_opaque_key", FR_TYPE_STRING | FR_TYPE_REQUIRED, rlm_eap_fast_t, pac_opaque_key) },

	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;
static fr_dict_t const *dict_eap_fast;

extern fr_dict_autoload_t rlm_eap_fast_dict[];
fr_dict_autoload_t rlm_eap_fast_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ .out = &dict_eap_fast, .proto = "eap-fast" },
	{ NULL }
};

fr_dict_attr_t const *attr_eap_emsk;
fr_dict_attr_t const *attr_eap_msk;
fr_dict_attr_t const *attr_eap_tls_require_client_cert;
fr_dict_attr_t const *attr_eap_type;
fr_dict_attr_t const *attr_ms_chap_challenge;
fr_dict_attr_t const *attr_ms_chap_peer_challenge;
fr_dict_attr_t const *attr_proxy_to_realm;

fr_dict_attr_t const *attr_eap_message;
fr_dict_attr_t const *attr_freeradius_proxied_to;
fr_dict_attr_t const *attr_ms_mppe_send_key;
fr_dict_attr_t const *attr_ms_mppe_recv_key;
fr_dict_attr_t const *attr_user_name;
fr_dict_attr_t const *attr_user_password;

fr_dict_attr_t const *attr_eap_fast_crypto_binding;
fr_dict_attr_t const *attr_eap_fast_eap_payload;
fr_dict_attr_t const *attr_eap_fast_error;
fr_dict_attr_t const *attr_eap_fast_intermediate_result;
fr_dict_attr_t const *attr_eap_fast_nak;
fr_dict_attr_t const *attr_eap_fast_pac_a_id;
fr_dict_attr_t const *attr_eap_fast_pac_a_id_info;
fr_dict_attr_t const *attr_eap_fast_pac_acknowledge;
fr_dict_attr_t const *attr_eap_fast_pac_i_id;
fr_dict_attr_t const *attr_eap_fast_pac_info_a_id;
fr_dict_attr_t const *attr_eap_fast_pac_info_a_id_info;
fr_dict_attr_t const *attr_eap_fast_pac_info_i_id;
fr_dict_attr_t const *attr_eap_fast_pac_info_pac_lifetime;
fr_dict_attr_t const *attr_eap_fast_pac_info_pac_type;
fr_dict_attr_t const *attr_eap_fast_pac_info_tlv;
fr_dict_attr_t const *attr_eap_fast_pac_key;
fr_dict_attr_t const *attr_eap_fast_pac_lifetime;
fr_dict_attr_t const *attr_eap_fast_pac_opaque_i_id;
fr_dict_attr_t const *attr_eap_fast_pac_opaque_pac_key;
fr_dict_attr_t const *attr_eap_fast_pac_opaque_pac_lifetime;
fr_dict_attr_t const *attr_eap_fast_pac_opaque_pac_type;
fr_dict_attr_t const *attr_eap_fast_pac_opaque_tlv;
fr_dict_attr_t const *attr_eap_fast_pac_tlv;
fr_dict_attr_t const *attr_eap_fast_pac_type;
fr_dict_attr_t const *attr_eap_fast_result;
fr_dict_attr_t const *attr_eap_fast_tlv;
fr_dict_attr_t const *attr_eap_fast_vendor_specific;

extern fr_dict_attr_autoload_t rlm_eap_fast_dict_attr[];
fr_dict_attr_autoload_t rlm_eap_fast_dict_attr[] = {
	{ .out = &attr_eap_emsk, .name = "EAP-EMSK", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_eap_msk, .name = "EAP-MSK", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_eap_tls_require_client_cert, .name = "EAP-TLS-Require-Client-Cert", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_eap_type, .name = "EAP-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_ms_chap_challenge, .name = "Vendor-Specific.Microsoft.CHAP-Challenge", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_ms_chap_peer_challenge, .name = "MS-CHAP-Peer-Challenge", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_proxy_to_realm, .name = "Proxy-To-Realm", .type = FR_TYPE_STRING, .dict = &dict_freeradius },

	{ .out = &attr_eap_message, .name = "EAP-Message", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_freeradius_proxied_to, .name = "Vendor-Specific.FreeRADIUS.Proxied-To", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_radius },
	{ .out = &attr_ms_mppe_send_key, .name = "Vendor-Specific.Microsoft.MPPE-Send-Key", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_ms_mppe_recv_key, .name = "Vendor-Specific.Microsoft.MPPE-Recv-Key", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_user_password, .name = "User-Password", .type = FR_TYPE_STRING, .dict = &dict_radius },

	{ .out = &attr_eap_fast_crypto_binding, .name = "EAP-FAST-Crypto-Binding", .type = FR_TYPE_OCTETS, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_eap_payload, .name = "EAP-FAST-EAP-Payload", .type = FR_TYPE_OCTETS, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_error, .name = "EAP-FAST-Error", .type = FR_TYPE_UINT32, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_intermediate_result, .name = "EAP-FAST-Intermediate-Result", .type = FR_TYPE_OCTETS, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_nak, .name = "EAP-FAST-NAK", .type = FR_TYPE_OCTETS, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_pac_a_id, .name = "EAP-FAST-PAC-A-ID", .type = FR_TYPE_OCTETS, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_pac_a_id_info, .name = "EAP-FAST-PAC-A-ID-Info", .type = FR_TYPE_OCTETS, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_pac_acknowledge, .name = "EAP-FAST-PAC-Acknowledge", .type = FR_TYPE_UINT16, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_pac_i_id, .name = "EAP-FAST-PAC-I-ID", .type = FR_TYPE_OCTETS, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_pac_info_a_id, .name = "EAP-FAST-PAC-Info-A-ID", .type = FR_TYPE_OCTETS, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_pac_info_a_id_info, .name = "EAP-FAST-PAC-Info-A-ID-Info", .type = FR_TYPE_OCTETS, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_pac_info_i_id, .name = "EAP-FAST-PAC-Info-I-ID", .type = FR_TYPE_OCTETS, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_pac_info_pac_lifetime, .name = "EAP-FAST-PAC-Info-PAC-Lifetime", .type = FR_TYPE_UINT32, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_pac_info_pac_type, .name = "EAP-FAST-PAC-Info-PAC-Type", .type = FR_TYPE_UINT16, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_pac_info_tlv, .name = "EAP-FAST-PAC-Info-TLV", .type = FR_TYPE_TLV, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_pac_key, .name = "EAP-FAST-PAC-Key", .type = FR_TYPE_OCTETS, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_pac_lifetime, .name = "EAP-FAST-PAC-Lifetime", .type = FR_TYPE_UINT32, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_pac_opaque_i_id, .name = "EAP-FAST-PAC-Opaque-I-ID", .type = FR_TYPE_OCTETS, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_pac_opaque_pac_key, .name = "EAP-FAST-PAC-Opaque-PAC-Key", .type = FR_TYPE_OCTETS, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_pac_opaque_pac_lifetime, .name = "EAP-FAST-PAC-Opaque-PAC-Lifetime", .type = FR_TYPE_UINT32, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_pac_opaque_pac_type, .name = "EAP-FAST-PAC-Opaque-PAC-Type", .type = FR_TYPE_UINT16, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_pac_opaque_tlv, .name = "EAP-FAST-PAC-Opaque-TLV", .type = FR_TYPE_TLV, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_pac_tlv, .name = "EAP-FAST-PAC-TLV", .type = FR_TYPE_TLV, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_pac_type, .name = "EAP-FAST-PAC-Type", .type = FR_TYPE_UINT16, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_result, .name = "EAP-FAST-Result", .type = FR_TYPE_UINT16, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_tlv, .name = "EAP-FAST-TLV", .type = FR_TYPE_TLV, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_vendor_specific, .name = "EAP-FAST-Vendor-Specific", .type = FR_TYPE_OCTETS, .dict = &dict_eap_fast },

	{ NULL }
};

/*
 *	Attach the module.
 */
static int mod_instantiate(void *instance, CONF_SECTION *cs)
{
	rlm_eap_fast_t		*inst = talloc_get_type_abort(instance, rlm_eap_fast_t);

	if (!virtual_server_find(inst->virtual_server)) {
		cf_log_err_by_child(cs, "virtual_server", "Unknown virtual server '%s'", inst->virtual_server);
		return -1;
	}

	inst->default_provisioning_method = eap_name2type(inst->default_provisioning_method_name);
	if (!inst->default_provisioning_method) {
		cf_log_err_by_child(cs, "default_provisioning_eap_type", "Unknown EAP type %s",
				   inst->default_provisioning_method_name);
		return -1;
	}

	/*
	 *	Read tls configuration, either from group given by 'tls'
	 *	option, or from the eap-tls configuration.
	 */
	inst->tls_conf = eap_tls_conf_parse(cs, "tls");

	if (!inst->tls_conf) {
		cf_log_err_by_child(cs, "tls", "Failed initializing SSL context");
		return -1;
	}

	if (talloc_array_length(inst->pac_opaque_key) - 1 != 32) {
		cf_log_err_by_child(cs, "pac_opaque_key", "Must be 32 bytes long");
		return -1;
	}

	/*
	 *	Allow anything for the TLS version, we try to forcibly
	 *	disable TLSv1.2 later.
	 */
	if (inst->tls_conf->tls_min_version > (float) 1.1) {
		cf_log_err_by_child(cs, "tls_min_version", "require tls_min_version <= 1.1");
		return -1;
	}

	if (!inst->pac_lifetime) {
		cf_log_err_by_child(cs, "pac_lifetime", "must be non-zero");
		return -1;
	}

	fr_assert(PAC_A_ID_LENGTH == MD5_DIGEST_LENGTH);

	fr_md5_calc(inst->a_id, (uint8_t const *)inst->authority_identity,
		    talloc_array_length(inst->authority_identity) - 1);

	return 0;
}

/** Allocate the FAST per-session data
 *
 */
static eap_fast_tunnel_t *eap_fast_alloc(TALLOC_CTX *ctx, rlm_eap_fast_t const *inst)
{
	eap_fast_tunnel_t *t = talloc_zero(ctx, eap_fast_tunnel_t);

	t->mode = EAP_FAST_UNKNOWN;
	t->stage = EAP_FAST_TLS_SESSION_HANDSHAKE;

	t->default_provisioning_method = inst->default_provisioning_method;

	t->pac_lifetime = inst->pac_lifetime;
	t->authority_identity = inst->authority_identity;
	t->a_id = inst->a_id;
	t->pac_opaque_key = (uint8_t const *)inst->pac_opaque_key;

	t->virtual_server = inst->virtual_server;

	return t;
}

static void eap_fast_session_ticket(fr_tls_session_t *tls_session, const SSL *s,
				    uint8_t *secret, int *secret_len)
{
	eap_fast_tunnel_t	*t = talloc_get_type_abort(tls_session->opaque, eap_fast_tunnel_t);
	uint8_t			seed[2 * SSL3_RANDOM_SIZE];

	fr_assert(t->pac.key);

	SSL_get_server_random(s, seed, SSL3_RANDOM_SIZE);
	SSL_get_client_random(s, &seed[SSL3_RANDOM_SIZE], SSL3_RANDOM_SIZE);

	T_PRF(t->pac.key, PAC_KEY_LENGTH, "PAC to master secret label hash",
	      seed, sizeof(seed), secret, SSL_MAX_MASTER_KEY_LENGTH);
	*secret_len = SSL_MAX_MASTER_KEY_LENGTH;
}

// hostap:src/crypto/tls_openssl.c:tls_sess_sec_cb()
#if OPENSSL_VERSION_NUMBER < 0x10100000L
static int _session_secret(SSL *s, void *secret, int *secret_len,
			   UNUSED STACK_OF(SSL_CIPHER) *peer_ciphers,
			   UNUSED SSL_CIPHER **cipher, void *arg)
#else
static int _session_secret(SSL *s, void *secret, int *secret_len,
			   UNUSED STACK_OF(SSL_CIPHER) *peer_ciphers,
			   UNUSED SSL_CIPHER const **cipher, void *arg)
#endif
{
	// FIXME enforce non-anon cipher

	request_t		*request = (request_t *)SSL_get_ex_data(s, FR_TLS_EX_INDEX_REQUEST);
	fr_tls_session_t	*tls_session = arg;
	eap_fast_tunnel_t	*t;

	if (!tls_session) return 0;

	t = talloc_get_type_abort(tls_session->opaque, eap_fast_tunnel_t);

	if (!t->pac.key) return 0;

	RDEBUG2("processing PAC-Opaque");

	eap_fast_session_ticket(tls_session, s, secret, secret_len);

	memset(t->pac.key, 0, PAC_KEY_LENGTH);
	talloc_free(t->pac.key);
	t->pac.key = NULL;

	return 1;
}

/*
 * hints from hostap:src/crypto/tls_openssl.c:fr_tls_session_ticket_ext_cb()
 *
 * N.B. we actually always tell OpenSSL we have digested the ticket so that
 *      it does not cause a fail loop and enables us to update the PAC easily
 *
 */
static int _session_ticket(SSL *s, uint8_t const *data, int len, void *arg)
{
	fr_tls_session_t		*tls_session = talloc_get_type_abort(arg, fr_tls_session_t);
	request_t			*request = talloc_get_type_abort(SSL_get_ex_data(s, FR_TLS_EX_INDEX_REQUEST), request_t);
	eap_fast_tunnel_t	*t;
	fr_pair_list_t		fast_vps;
	fr_pair_t		*vp;
	fr_cursor_t		cursor;
	char const		*errmsg;
	int			dlen, plen;
	uint16_t		length;
	eap_fast_attr_pac_opaque_t const	*opaque = (eap_fast_attr_pac_opaque_t const *) data;
	eap_fast_attr_pac_opaque_t		opaque_plaintext;

	if (!tls_session) return 0;

	fr_pair_list_init(&fast_vps);
	t = talloc_get_type_abort(tls_session->opaque, eap_fast_tunnel_t);

	RDEBUG2("PAC provided via ClientHello SessionTicket extension");
	RHEXDUMP3(data, len, "PAC-Opaque");

	if ((ntohs(opaque->hdr.type) & EAP_FAST_TLV_TYPE) != attr_eap_fast_pac_opaque_tlv->attr) {
		errmsg = "PAC is not of type Opaque";
error:
		RERROR("%s, sending alert to client", errmsg);
		if (fr_tls_session_alert(request, tls_session, SSL3_AL_FATAL, SSL_AD_BAD_CERTIFICATE)) {
			RERROR("too many alerts");
			return 0;
		}
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

	RHEXDUMP3((uint8_t const *)&opaque_plaintext, plen, "PAC-Opaque plaintext data section");

	fr_cursor_init(&cursor, &fast_vps);
	if (eap_fast_decode_pair(tls_session, &cursor, attr_eap_fast_pac_opaque_tlv, (uint8_t *)&opaque_plaintext, plen, NULL) < 0) {
		errmsg = fr_strerror();
		goto error;
	}

	for (vp = fr_cursor_head(&cursor);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		if (vp->da == attr_eap_fast_pac_info_pac_type) {
			fr_assert(t->pac.type == 0);
			t->pac.type = vp->vp_uint32;
		} else if (vp->da == attr_eap_fast_pac_info_pac_lifetime) {
			fr_assert(t->pac.expires == 0);
			t->pac.expires = vp->vp_uint32;
			t->pac.expired = (vp->vp_uint32 <= time(NULL));
		/*
		 *	Not sure if this is the correct attr
		 *	The original enum didn't match a specific TLV nesting level
		 */
		} else if (vp->da == attr_eap_fast_pac_key) {
			fr_assert(t->pac.key == NULL);
			fr_assert(vp->vp_length == PAC_KEY_LENGTH);
			t->pac.key = talloc_array(t, uint8_t, PAC_KEY_LENGTH);
			fr_assert(t->pac.key != NULL);
			memcpy(t->pac.key, vp->vp_octets, PAC_KEY_LENGTH);
		} else {
			RERROR("unknown TLV: %pP", vp);
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
static unlang_action_t mod_process(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_eap_fast_t const	*inst = talloc_get_type_abort_const(mctx->instance, rlm_eap_fast_t);
	eap_tls_status_t	status;

	eap_session_t		*eap_session = eap_session_get(request->parent);
	eap_tls_session_t	*eap_tls_session = talloc_get_type_abort(eap_session->opaque, eap_tls_session_t);
	fr_tls_session_t	*tls_session = eap_tls_session->tls_session;

	/*
	 *	We need FAST data associated with the session, so
	 *	allocate it here, if it wasn't already alloacted.
	 */
	if (!tls_session->opaque) tls_session->opaque = eap_fast_alloc(tls_session, inst);

	/*
	 *	Process TLS layer until done.
	 */
	status = eap_tls_process(request, eap_session);
	if ((status == EAP_TLS_INVALID) || (status == EAP_TLS_FAIL)) {
		REDEBUG("[eap-tls process] = %s", fr_table_str_by_value(eap_tls_status_table, status, "<INVALID>"));
	} else {
		RDEBUG2("[eap-tls process] = %s", fr_table_str_by_value(eap_tls_status_table, status, "<INVALID>"));
	}

	switch (status) {
	/*
	 *	EAP-TLS handshake was successful, tell the
	 *	client to keep talking.
	 *
	 *	If this was EAP-TLS, we would just return
	 *	an EAP-TLS-Success packet here.
	 */
	case EAP_TLS_ESTABLISHED:
		fr_tls_session_send(request, tls_session);
		fr_assert(tls_session->opaque != NULL);
		break;

	/*
	 *	The TLS code is still working on the TLS
	 *	exchange, and it's a valid TLS request.
	 *	do nothing.
	 */
	case EAP_TLS_HANDLED:
		RETURN_MODULE_HANDLED;

	/*
	 *	Handshake is done, proceed with decoding tunneled
	 *	data.
	 */
	case EAP_TLS_RECORD_RECV_COMPLETE:
		break;

	/*
	 *	Anything else: fail.
	 */
	default:
		RETURN_MODULE_FAIL;
	}

	/*
	 *	Session is established, proceed with decoding
	 *	tunneled data.
	 */
	RDEBUG2("Session established.  Proceeding to decode tunneled attributes");

	/*
	 *	Process the FAST portion of the request.
	 */
	switch (eap_fast_process(request, eap_session, tls_session)) {
	case FR_CODE_ACCESS_REJECT:
		eap_tls_fail(request, eap_session);
		RETURN_MODULE_FAIL;

		/*
		 *	Access-Challenge, continue tunneled conversation.
		 */
	case FR_CODE_ACCESS_CHALLENGE:
		fr_tls_session_send(request, tls_session);
		eap_tls_request(request, eap_session);
		RETURN_MODULE_HANDLED;

		/*
		 *	Success: Automatically return MPPE keys.
		 */
	case FR_CODE_ACCESS_ACCEPT:
		if (eap_tls_success(request, eap_session, NULL, 0, NULL, 0) < 0) RETURN_MODULE_FAIL;
		RETURN_MODULE_OK;

		/*
		 *	No response packet, MUST be proxying it.
		 *	The main EAP module will take care of discovering
		 *	that the request now has a "proxy" packet, and
		 *	will proxy it, rather than returning an EAP packet.
		 */
	case FR_CODE_STATUS_CLIENT:
		RETURN_MODULE_OK;

	default:
		break;
	}

	/*
	 *	Something we don't understand: Reject it.
	 */
	eap_tls_fail(request, eap_session);
	RETURN_MODULE_FAIL;
}

/*
 *	Send an initial eap-tls request to the peer, using the libeap functions.
 */
static unlang_action_t mod_session_init(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_eap_fast_t const	*inst = talloc_get_type_abort_const(mctx->instance, rlm_eap_fast_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);
	eap_tls_session_t 	*eap_tls_session;
	fr_tls_session_t	*tls_session;

	fr_pair_t		*vp;
	bool			client_cert;

	eap_session->tls = true;

	/*
	 *	EAP-TLS-Require-Client-Cert attribute will override
	 *	the require_client_cert configuration option.
	 */
	vp = fr_pair_find_by_da(&request->control_pairs, attr_eap_tls_require_client_cert);
	if (vp) {
		client_cert = vp->vp_uint32 ? true : false;
	} else {
		client_cert = inst->req_client_cert;
	}

	eap_session->opaque = eap_tls_session = eap_tls_session_init(request, eap_session, inst->tls_conf, client_cert);
	if (!eap_tls_session) RETURN_MODULE_FAIL;

	tls_session = eap_tls_session->tls_session;

	if (inst->cipher_list) {
		RDEBUG2("Over-riding main cipher list with '%s'", inst->cipher_list);

		if (!SSL_set_cipher_list(tls_session->ssl, inst->cipher_list)) {
			REDEBUG("Failed over-riding cipher list to '%s'.  EAP-FAST will likely not work",
				inst->cipher_list);
		}
	}

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
	eap_fast_tlv_append(tls_session, attr_eap_fast_pac_info_a_id, false, PAC_A_ID_LENGTH, inst->a_id);

	/*
	 *	TLS session initialization is over.  Now handle TLS
	 *	related handshaking or application data.
	 */
	if (eap_tls_compose(request, eap_session, EAP_TLS_START_SEND,
			    SET_START(eap_tls_session->base_flags) | EAP_FAST_VERSION,
			    &tls_session->clean_in, tls_session->clean_in.used,
			    tls_session->clean_in.used) < 0) {
		talloc_free(tls_session);
		RETURN_MODULE_FAIL;
	}

	tls_session->record_init(&tls_session->clean_in);
	eap_session->process = mod_process;

	if (!SSL_set_session_ticket_ext_cb(tls_session->ssl, _session_ticket, tls_session)) {
		RERROR("Failed setting SSL session ticket callback");
		RETURN_MODULE_FAIL;
	}

	RETURN_MODULE_HANDLED;
}


/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
extern rlm_eap_submodule_t rlm_eap_fast;
rlm_eap_submodule_t rlm_eap_fast = {
	.name		= "eap_fast",
	.magic		= RLM_MODULE_INIT,

	.provides	= { FR_EAP_METHOD_FAST },
	.inst_size	= sizeof(rlm_eap_fast_t),
	.config		= submodule_config,
	.instantiate	= mod_instantiate,	/* Create new submodule instance */

	.session_init	= mod_session_init,	/* Initialise a new EAP session */
	.entry_point	= mod_process		/* Process next round of EAP method */
};
