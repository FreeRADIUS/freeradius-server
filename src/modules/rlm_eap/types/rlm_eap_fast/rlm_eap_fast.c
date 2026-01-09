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
#include <freeradius-devel/tls/utils.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include "eap_fast.h"
#include "eap_fast_crypto.h"

typedef struct {
	SSL_CTX		*ssl_ctx;		//!< Thread local SSL_CTX.
} rlm_eap_fast_thread_t;

/*
 *	An instance of EAP-FAST
 */
typedef struct {
	char const		*tls_conf_name;				//!< Name of shared TLS config.
	fr_tls_conf_t		*tls_conf;				//!< TLS config pointer.

	char const		*default_provisioning_method_name;
	int			default_provisioning_method;

	virtual_server_t	*virtual_server;			//!< Virtual server to use for processing
									//!< inner EAP method.
	char const		*cipher_list;				//!< cipher list specific to EAP-FAST
	bool			req_client_cert;			//!< Whether we require a client cert
									//!< in the outer tunnel.

	int			stage;					//!< Processing stage.

	fr_time_delta_t		pac_lifetime;				//!< seconds to add to current time to describe PAC lifetime
	char const		*authority_identity;			//!< The identity we present in the EAP-TLS
	uint8_t			a_id[PAC_A_ID_LENGTH];			//!< The identity we present in the EAP-TLS
	char const		*pac_opaque_key;			//!< The key used to encrypt PAC-Opaque
} rlm_eap_fast_t;


static conf_parser_t submodule_config[] = {
	{ FR_CONF_OFFSET("tls", rlm_eap_fast_t, tls_conf_name) },

	{ FR_CONF_OFFSET("default_provisioning_eap_type", rlm_eap_fast_t, default_provisioning_method_name), .dflt = "mschapv2" },

	{ FR_CONF_OFFSET_TYPE_FLAGS("virtual_server", FR_TYPE_VOID, CONF_FLAG_REQUIRED | CONF_FLAG_NOT_EMPTY, rlm_eap_fast_t, virtual_server),
				    .func = virtual_server_cf_parse,
				    .uctx = &(virtual_server_cf_parse_uctx_t){ .process_module_name = "eap_fast"} },

	{ FR_CONF_OFFSET("cipher_list", rlm_eap_fast_t, cipher_list) },

	{ FR_CONF_OFFSET("require_client_cert", rlm_eap_fast_t, req_client_cert), .dflt = "no" },

	{ FR_CONF_OFFSET("pac_lifetime", rlm_eap_fast_t, pac_lifetime), .dflt = "604800" },
	{ FR_CONF_OFFSET_FLAGS("authority_identity", CONF_FLAG_REQUIRED, rlm_eap_fast_t, authority_identity) },
	{ FR_CONF_OFFSET_FLAGS("pac_opaque_key", CONF_FLAG_REQUIRED, rlm_eap_fast_t, pac_opaque_key) },

	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;
static fr_dict_t const *dict_eap_fast;

extern fr_dict_autoload_t rlm_eap_fast_dict[];
fr_dict_autoload_t rlm_eap_fast_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ .out = &dict_eap_fast, .base_dir = "eap/fast", .proto = "eap-fast" },
	DICT_AUTOLOAD_TERMINATOR
};

static fr_dict_attr_t const *attr_eap_emsk;
static fr_dict_attr_t const *attr_eap_msk;
static fr_dict_attr_t const *attr_eap_tls_require_client_cert;
static fr_dict_attr_t const *attr_eap_type;
static fr_dict_attr_t const *attr_ms_chap_challenge;
static fr_dict_attr_t const *attr_ms_chap_peer_challenge;
static fr_dict_attr_t const *attr_proxy_to_realm;

static fr_dict_attr_t const *attr_eap_message;
static fr_dict_attr_t const *attr_freeradius_proxied_to;
static fr_dict_attr_t const *attr_ms_mppe_send_key;
static fr_dict_attr_t const *attr_ms_mppe_recv_key;
static fr_dict_attr_t const *attr_user_name;
static fr_dict_attr_t const *attr_user_password;

static fr_dict_attr_t const *attr_eap_fast_crypto_binding;
static fr_dict_attr_t const *attr_eap_fast_eap_payload;
static fr_dict_attr_t const *attr_eap_fast_error;
static fr_dict_attr_t const *attr_eap_fast_intermediate_result;
static fr_dict_attr_t const *attr_eap_fast_nak;
static fr_dict_attr_t const *attr_eap_fast_pac_a_id;
static fr_dict_attr_t const *attr_eap_fast_pac_a_id_info;
static fr_dict_attr_t const *attr_eap_fast_pac_acknowledge;
static fr_dict_attr_t const *attr_eap_fast_pac_i_id;
static fr_dict_attr_t const *attr_eap_fast_pac_info_a_id;
static fr_dict_attr_t const *attr_eap_fast_pac_info_a_id_info;
static fr_dict_attr_t const *attr_eap_fast_pac_info_i_id;
static fr_dict_attr_t const *attr_eap_fast_pac_info_pac_lifetime;
static fr_dict_attr_t const *attr_eap_fast_pac_info_pac_type;
static fr_dict_attr_t const *attr_eap_fast_pac_info_tlv;
static fr_dict_attr_t const *attr_eap_fast_pac_key;
static fr_dict_attr_t const *attr_eap_fast_pac_lifetime;
static fr_dict_attr_t const *attr_eap_fast_pac_opaque_i_id;
static fr_dict_attr_t const *attr_eap_fast_pac_opaque_pac_key;
static fr_dict_attr_t const *attr_eap_fast_pac_opaque_pac_lifetime;
static fr_dict_attr_t const *attr_eap_fast_pac_opaque_pac_type;
static fr_dict_attr_t const *attr_eap_fast_pac_opaque_tlv;
static fr_dict_attr_t const *attr_eap_fast_pac_tlv;
static fr_dict_attr_t const *attr_eap_fast_pac_type;
static fr_dict_attr_t const *attr_eap_fast_result;
static fr_dict_attr_t const *attr_eap_fast_vendor_specific;

extern fr_dict_attr_autoload_t rlm_eap_fast_dict_attr[];
fr_dict_attr_autoload_t rlm_eap_fast_dict_attr[] = {
	{ .out = &attr_eap_emsk, .name = "EAP-EMSK", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_eap_msk, .name = "EAP-MSK", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_eap_tls_require_client_cert, .name = "EAP-TLS-Require-Client-Cert", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_eap_type, .name = "EAP-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_ms_chap_challenge, .name = "Vendor-Specific.Microsoft.CHAP-Challenge", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_ms_chap_peer_challenge, .name = "MS-CHAP-Peer-Challenge", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_proxy_to_realm, .name = "Proxy-To-Realm", .type = FR_TYPE_STRING, .dict = &dict_freeradius },

	{ .out = &attr_eap_message, .name = "EAP-Message", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_freeradius_proxied_to, .name = "Vendor-Specific.FreeRADIUS.Proxied-To", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_radius },
	{ .out = &attr_ms_mppe_send_key, .name = "Vendor-Specific.Microsoft.MPPE-Send-Key", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_ms_mppe_recv_key, .name = "Vendor-Specific.Microsoft.MPPE-Recv-Key", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_user_password, .name = "User-Password", .type = FR_TYPE_STRING, .dict = &dict_radius },

	{ .out = &attr_eap_fast_crypto_binding, .name = "Crypto-Binding", .type = FR_TYPE_OCTETS, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_eap_payload, .name = "EAP-Payload", .type = FR_TYPE_OCTETS, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_error, .name = "Error", .type = FR_TYPE_UINT32, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_intermediate_result, .name = "Intermediate-Result", .type = FR_TYPE_OCTETS, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_nak, .name = "NAK", .type = FR_TYPE_OCTETS, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_pac_a_id, .name = "PAC.A-ID", .type = FR_TYPE_OCTETS, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_pac_a_id_info, .name = "PAC.A-ID-Info", .type = FR_TYPE_OCTETS, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_pac_acknowledge, .name = "PAC.Acknowledge", .type = FR_TYPE_UINT16, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_pac_i_id, .name = "PAC.I-ID", .type = FR_TYPE_OCTETS, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_pac_info_a_id, .name = "PAC.Info.A-ID", .type = FR_TYPE_OCTETS, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_pac_info_a_id_info, .name = "PAC.Info.A-ID-Info", .type = FR_TYPE_OCTETS, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_pac_info_i_id, .name = "PAC.Info.I-ID", .type = FR_TYPE_OCTETS, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_pac_info_pac_lifetime, .name = "PAC.Info.PAC-Lifetime", .type = FR_TYPE_UINT32, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_pac_info_pac_type, .name = "PAC.Info.PAC-Type", .type = FR_TYPE_UINT16, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_pac_info_tlv, .name = "PAC.Info", .type = FR_TYPE_TLV, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_pac_key, .name = "PAC.Key", .type = FR_TYPE_OCTETS, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_pac_lifetime, .name = "PAC.Lifetime", .type = FR_TYPE_UINT32, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_pac_opaque_i_id, .name = "PAC.Opaque.I-ID", .type = FR_TYPE_OCTETS, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_pac_opaque_pac_key, .name = "PAC.Opaque.PAC-Key", .type = FR_TYPE_OCTETS, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_pac_opaque_pac_lifetime, .name = "PAC.Opaque.PAC-Lifetime", .type = FR_TYPE_UINT32, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_pac_opaque_pac_type, .name = "PAC.Opaque.PAC-Type", .type = FR_TYPE_UINT16, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_pac_opaque_tlv, .name = "PAC.Opaque", .type = FR_TYPE_TLV, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_pac_tlv, .name = "PAC", .type = FR_TYPE_TLV, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_pac_type, .name = "PAC.Type", .type = FR_TYPE_UINT16, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_result, .name = "Result", .type = FR_TYPE_UINT16, .dict = &dict_eap_fast },
	{ .out = &attr_eap_fast_vendor_specific, .name = "Vendor-Specific", .type = FR_TYPE_OCTETS, .dict = &dict_eap_fast },

	DICT_AUTOLOAD_TERMINATOR
};

#define RANDFILL(x) do { fr_assert(sizeof(x) % sizeof(uint32_t) == 0); for (size_t i = 0; i < sizeof(x); i += sizeof(uint32_t)) *((uint32_t *)&x[i]) = fr_rand(); } while(0)

/**
 * RFC 4851 section 5.1 - EAP-FAST Authentication Phase 1: Key Derivations
 */
static void eap_fast_init_keys(request_t *request, fr_tls_session_t *tls_session)
{
	eap_fast_tunnel_t *t = talloc_get_type_abort(tls_session->opaque, eap_fast_tunnel_t);
	uint8_t *buf;
	uint8_t *scratch;
	size_t ksize;

	RDEBUG2("Deriving EAP-FAST keys");

	fr_assert(t->s_imck == NULL);

	ksize = fr_tls_utils_keyblock_size_get(request, tls_session->ssl);
	fr_assert(ksize > 0);
	buf = talloc_array(request, uint8_t, ksize + sizeof(*t->keyblock));
	scratch = talloc_array(request, uint8_t, ksize + sizeof(*t->keyblock));

	t->keyblock = talloc(t, eap_fast_keyblock_t);

	eap_fast_tls_gen_challenge(tls_session->ssl, buf, scratch, ksize + sizeof(*t->keyblock), "key expansion");
	memcpy(t->keyblock, &buf[ksize], sizeof(*t->keyblock));
	memset(buf, 0, ksize + sizeof(*t->keyblock));

	t->s_imck = talloc_array(t, uint8_t, EAP_FAST_SIMCK_LEN);
	memcpy(t->s_imck, t->keyblock, EAP_FAST_SKS_LEN);	/* S-IMCK[0] = session_key_seed */

	t->cmk = talloc_array(t, uint8_t, EAP_FAST_CMK_LEN);	/* note that CMK[0] is not defined */
	t->imck_count = 0;

	talloc_free(buf);
	talloc_free(scratch);
}

/**
 * RFC 4851 section 5.2 - Intermediate Compound Key Derivations
 */
static void eap_fast_update_icmk(request_t *request, fr_tls_session_t *tls_session, uint8_t *msk)
{
	eap_fast_tunnel_t *t = talloc_get_type_abort(tls_session->opaque, eap_fast_tunnel_t);
	uint8_t imck[EAP_FAST_SIMCK_LEN + EAP_FAST_CMK_LEN];

	RDEBUG2("Updating ICMK");

	T_PRF(t->s_imck, EAP_FAST_SIMCK_LEN, "Inner Methods Compound Keys", msk, 32, imck, sizeof(imck));	//-V512

	memcpy(t->s_imck, imck, EAP_FAST_SIMCK_LEN);
	RHEXDUMP3(t->s_imck, EAP_FAST_SIMCK_LEN, "S-IMCK[j]");

	memcpy(t->cmk, &imck[EAP_FAST_SIMCK_LEN], EAP_FAST_CMK_LEN);
	RHEXDUMP3(t->cmk, EAP_FAST_CMK_LEN, "CMK[j]");

	t->imck_count++;

	/*
         * Calculate MSK/EMSK at the same time as they are coupled to ICMK
         *
         * RFC 4851 section 5.4 - EAP Master Session Key Generation
         */
	t->msk = talloc_array(t, uint8_t, EAP_FAST_KEY_LEN);
	T_PRF(t->s_imck, EAP_FAST_SIMCK_LEN, "Session Key Generating Function", NULL, 0, t->msk, EAP_FAST_KEY_LEN);
	RHEXDUMP3(t->msk, EAP_FAST_KEY_LEN, "MSK");

	t->emsk = talloc_array(t, uint8_t, EAP_EMSK_LEN);
	T_PRF(t->s_imck, EAP_FAST_SIMCK_LEN, "Extended Session Key Generating Function", NULL, 0, t->emsk, EAP_EMSK_LEN);
	RHEXDUMP3(t->emsk, EAP_EMSK_LEN, "EMSK");
}

static void eap_fast_tlv_append(fr_tls_session_t *tls_session, fr_dict_attr_t const *tlv, bool mandatory, int length, void const *data)
{
	uint16_t hdr[2];

	hdr[0] = (mandatory) ? htons(tlv->attr | EAP_FAST_TLV_MANDATORY) : htons(tlv->attr);
	hdr[1] = htons(length);

	tls_session->record_from_buff(&tls_session->clean_in, &hdr, 4);
	tls_session->record_from_buff(&tls_session->clean_in, data, length);
}

static void eap_fast_send_error(fr_tls_session_t *tls_session, int error)
{
	uint32_t value;
	value = htonl(error);

	eap_fast_tlv_append(tls_session, attr_eap_fast_error, true, sizeof(value), &value);
}

static void eap_fast_append_result(fr_tls_session_t *tls_session, fr_radius_packet_code_t code)
{
	eap_fast_tunnel_t	*t = talloc_get_type_abort(tls_session->opaque, eap_fast_tunnel_t);
	uint16_t		state;
	fr_dict_attr_t const	*da;


	da = (t->result_final) ? attr_eap_fast_result : attr_eap_fast_intermediate_result;
	state = htons((code == FR_RADIUS_CODE_ACCESS_REJECT) ? EAP_FAST_TLV_RESULT_FAILURE : EAP_FAST_TLV_RESULT_SUCCESS);

	eap_fast_tlv_append(tls_session, da, true, sizeof(state), &state);
}

static void eap_fast_send_identity_request(request_t *request, fr_tls_session_t *tls_session, eap_session_t *eap_session)
{
	eap_packet_hdr_t eap_packet;

	RDEBUG2("Sending EAP-Identity");

	eap_packet.code = FR_EAP_CODE_REQUEST;
	eap_packet.id = eap_session->this_round->response->id + 1;
	eap_packet.length[0] = 0;
	eap_packet.length[1] = EAP_HEADER_LEN + 1;
	eap_packet.data[0] = FR_EAP_METHOD_IDENTITY;

	eap_fast_tlv_append(tls_session, attr_eap_fast_eap_payload, true, sizeof(eap_packet), &eap_packet);
}

static void eap_fast_send_pac_tunnel(request_t *request, fr_tls_session_t *tls_session)
{
	eap_fast_tunnel_t			*t = talloc_get_type_abort(tls_session->opaque, eap_fast_tunnel_t);
	eap_fast_pac_t				pac;
	eap_fast_attr_pac_opaque_plaintext_t	opaque_plaintext;
	int					alen, dlen;

	memset(&pac, 0, sizeof(pac));
	memset(&opaque_plaintext, 0, sizeof(opaque_plaintext));

	RDEBUG2("Sending Tunnel PAC");

	pac.key.hdr.type = htons(EAP_FAST_TLV_MANDATORY | attr_eap_fast_pac_key->attr);
	pac.key.hdr.length = htons(sizeof(pac.key.data));
	fr_assert(sizeof(pac.key.data) % sizeof(uint32_t) == 0);
	RANDFILL(pac.key.data);

	pac.info.lifetime.hdr.type = htons(attr_eap_fast_pac_info_pac_lifetime->attr);
	pac.info.lifetime.hdr.length = htons(sizeof(pac.info.lifetime.data));
	pac.info.lifetime.data = htonl(fr_time_to_sec(fr_time_add(request->packet->timestamp, t->pac_lifetime)));

	pac.info.a_id.hdr.type = htons(EAP_FAST_TLV_MANDATORY | attr_eap_fast_pac_a_id->attr);
	pac.info.a_id.hdr.length = htons(sizeof(pac.info.a_id.data));
	memcpy(pac.info.a_id.data, t->a_id, sizeof(pac.info.a_id.data));

	pac.info.a_id_info.hdr.type = htons(attr_eap_fast_pac_a_id->attr);
	pac.info.a_id_info.hdr.length = htons(sizeof(pac.info.a_id_info.data));

#define MIN(a,b) (((a)>(b)) ? (b) : (a))
	alen = MIN(talloc_array_length(t->authority_identity) - 1, sizeof(pac.info.a_id_info.data));
	memcpy(pac.info.a_id_info.data, t->authority_identity, alen);

	pac.info.type.hdr.type = htons(EAP_FAST_TLV_MANDATORY | attr_eap_fast_pac_info_pac_type->attr);
	pac.info.type.hdr.length = htons(sizeof(pac.info.type.data));
	pac.info.type.data = htons(PAC_TYPE_TUNNEL);

	pac.info.hdr.type = htons(EAP_FAST_TLV_MANDATORY | attr_eap_fast_pac_info_tlv->attr);
	pac.info.hdr.length = htons(sizeof(pac.info.lifetime)
				+ sizeof(pac.info.a_id)
				+ sizeof(pac.info.a_id_info)
				+ sizeof(pac.info.type));

	memcpy(&opaque_plaintext.type, &pac.info.type, sizeof(opaque_plaintext.type));
	memcpy(&opaque_plaintext.lifetime, &pac.info.lifetime, sizeof(opaque_plaintext.lifetime));
	memcpy(&opaque_plaintext.key, &pac.key, sizeof(opaque_plaintext.key));

	RHEXDUMP3((uint8_t const *)&opaque_plaintext, sizeof(opaque_plaintext), "PAC-Opaque plaintext data section");

	fr_assert(PAC_A_ID_LENGTH <= EVP_GCM_TLS_TAG_LEN);
	memcpy(pac.opaque.aad, t->a_id, PAC_A_ID_LENGTH);
	fr_assert(RAND_bytes(pac.opaque.iv, sizeof(pac.opaque.iv)) != 0);
	dlen = eap_fast_encrypt((unsigned const char *)&opaque_plaintext, sizeof(opaque_plaintext),
				    t->a_id, PAC_A_ID_LENGTH, t->pac_opaque_key, pac.opaque.iv,
				    pac.opaque.data, pac.opaque.tag);

	pac.opaque.hdr.type = htons(EAP_FAST_TLV_MANDATORY | attr_eap_fast_pac_opaque_tlv->attr);
	pac.opaque.hdr.length = htons(sizeof(pac.opaque) - sizeof(pac.opaque.hdr) - sizeof(pac.opaque.data) + dlen);
	RHEXDUMP3((uint8_t const *)&pac.opaque, sizeof(pac.opaque) - sizeof(pac.opaque.data) + dlen, "PAC-Opaque");

	eap_fast_tlv_append(tls_session, attr_eap_fast_pac_tlv, true, sizeof(pac) - sizeof(pac.opaque.data) + dlen, &pac);
}

static void eap_fast_append_crypto_binding(request_t *request, fr_tls_session_t *tls_session)
{
	eap_fast_tunnel_t		*t = talloc_get_type_abort(tls_session->opaque, eap_fast_tunnel_t);
	eap_tlv_crypto_binding_tlv_t	binding = {0};
	int const			len = sizeof(binding) - (&binding.reserved - (uint8_t *)&binding);

	RDEBUG2("Sending Cryptobinding");

	binding.tlv_type = htons(EAP_FAST_TLV_MANDATORY | attr_eap_fast_crypto_binding->attr);
	binding.length = htons(len);
	binding.version = EAP_FAST_VERSION;
	binding.received_version = EAP_FAST_VERSION;	/* FIXME use the clients value */
	binding.subtype = EAP_FAST_TLV_CRYPTO_BINDING_SUBTYPE_REQUEST;

	fr_assert(sizeof(binding.nonce) % sizeof(uint32_t) == 0);
	RANDFILL(binding.nonce);
	binding.nonce[sizeof(binding.nonce) - 1] &= ~0x01; /* RFC 4851 section 4.2.8 */
	RHEXDUMP3(binding.nonce, sizeof(binding.nonce), "NONCE");

	RHEXDUMP3((uint8_t const *) &binding, sizeof(binding), "Crypto-Binding TLV for Compound MAC calculation");

	fr_hmac_sha1(binding.compound_mac, (uint8_t *)&binding, sizeof(binding), t->cmk, EAP_FAST_CMK_LEN);
	RHEXDUMP3(binding.compound_mac, sizeof(binding.compound_mac), "Compound MAC");

	eap_fast_tlv_append(tls_session, attr_eap_fast_crypto_binding, true, len, &binding.reserved);
}

#define EAP_FAST_TLV_MAX 11

static int eap_fast_verify(request_t *request, fr_tls_session_t *tls_session, uint8_t const *data, unsigned int data_len)
{
	uint16_t attr;
	uint16_t length;
	unsigned int remaining = data_len;
	int	total = 0;
	int	num[EAP_FAST_TLV_MAX] = {0};
	eap_fast_tunnel_t *t = talloc_get_type_abort(tls_session->opaque, eap_fast_tunnel_t);
	uint32_t present = 0;

	fr_assert(sizeof(present) * 8 > EAP_FAST_TLV_MAX);

	while (remaining > 0) {
		if (remaining < 4) {
			RDEBUG2("EAP-FAST TLV is too small (%u) to contain a EAP-FAST TLV header", remaining);
			return 0;
		}

		memcpy(&attr, data, sizeof(attr));
		attr = ntohs(attr) & EAP_FAST_TLV_TYPE;

		if ((attr == attr_eap_fast_result->attr) ||
		    (attr == attr_eap_fast_nak->attr) ||
		    (attr == attr_eap_fast_error->attr) ||
		    (attr == attr_eap_fast_vendor_specific->attr) ||
		    (attr == attr_eap_fast_eap_payload->attr) ||
		    (attr == attr_eap_fast_intermediate_result->attr) ||
		    (attr == attr_eap_fast_pac_tlv->attr) ||
		    (attr == attr_eap_fast_crypto_binding->attr)) {
			num[attr]++;
			present |= 1 << attr;

			if (num[attr_eap_fast_eap_payload->attr] > 1) {
				REDEBUG("Too many EAP-Payload TLVs");
unexpected:
				for (int i = 0; i < EAP_FAST_TLV_MAX; i++) {
					if (present & (1 << i)) RDEBUG2(" - attribute %d is present", i);
				}
				eap_fast_send_error(tls_session, EAP_FAST_ERR_UNEXPECTED_TLV);
				return 0;
			}

			if (num[attr_eap_fast_intermediate_result->attr] > 1) {
				REDEBUG("Too many Intermediate-Result TLVs");
				goto unexpected;
			}
		} else {
			if ((data[0] & 0x80) != 0) {
				REDEBUG("Unknown mandatory TLV %02x", attr);
				goto unexpected;
			}

			num[0]++;
		}

		total++;

		memcpy(&length, data + 2, sizeof(length));
		length = ntohs(length);

		data += 4;
		remaining -= 4;

		if (length > remaining) {
			RDEBUG2("EAP-FAST TLV %u is longer than room remaining in the packet (%u > %u).", attr,
				length, remaining);
			return 0;
		}

		/*
		 * If the rest of the TLVs are larger than
		 * this attribute, continue.
		 *
		 * Otherwise, if the attribute over-flows the end
		 * of the TLCs, die.
		 */
		if (remaining < length) {
			RDEBUG2("EAP-FAST TLV overflows packet!");
			return 0;
		}

		/*
		 * If there's an error, we bail out of the
		 * authentication process before allocating
		 * memory.
		 */
		if ((attr == attr_eap_fast_intermediate_result->attr) || (attr == attr_eap_fast_result->attr)) {
			uint16_t status;

			if (length < 2) {
				REDEBUG("EAP-FAST TLV %u is too short.  Expected 2, got %d", attr, length);
				return 0;
			}

			memcpy(&status, data, 2);
			status = ntohs(status);

			if (status == EAP_FAST_TLV_RESULT_FAILURE) {
				REDEBUG("EAP-FAST TLV %u indicates failure.  Rejecting request", attr);
				return 0;
			}

			if (status != EAP_FAST_TLV_RESULT_SUCCESS) {
				REDEBUG("EAP-FAST TLV %u contains unknown value.  Rejecting request", attr);
				goto unexpected;
			}
		}

		/*
		 * remaining > length, continue.
		 */
		remaining -= length;
		data += length;
	}

	/*
	 * Check if the peer mixed & matched TLVs.
	 */
	if ((num[attr_eap_fast_nak->attr] > 0) && (num[attr_eap_fast_nak->attr] != total)) {
		REDEBUG("NAK TLV sent with non-NAK TLVs.  Rejecting request");
		goto unexpected;
	}

	if (num[attr_eap_fast_intermediate_result->attr] > 0) {
		REDEBUG("NAK TLV sent with non-NAK TLVs.  Rejecting request");
		goto unexpected;
	}

	/*
	 * Check mandatory or not mandatory TLVs.
	 */
	switch (t->stage) {
	case EAP_FAST_TLS_SESSION_HANDSHAKE:
		if (present) {
			REDEBUG("Unexpected TLVs in TLS Session Handshake stage");
			goto unexpected;
		}
		break;
	case EAP_FAST_AUTHENTICATION:
		if (present != (uint32_t)(1 << attr_eap_fast_eap_payload->attr)) {
			REDEBUG("Unexpected TLVs in authentication stage");
			goto unexpected;
		}
		break;
	case EAP_FAST_CRYPTOBIND_CHECK:
	{
		uint32_t bits = (t->result_final)
				? 1 << attr_eap_fast_result->attr
				: 1 << attr_eap_fast_intermediate_result->attr;
		if (present & ~(bits | (1 << attr_eap_fast_crypto_binding->attr) | (1 << attr_eap_fast_pac_tlv->attr))) {
			REDEBUG("Unexpected TLVs in cryptobind checking stage");
			goto unexpected;
		}
		break;
	}
	case EAP_FAST_PROVISIONING:
		if (present & ~((1 << attr_eap_fast_pac_tlv->attr) | (1 << attr_eap_fast_result->attr))) {
			REDEBUG("Unexpected TLVs in provisioning stage");
			goto unexpected;
		}
		break;
	case EAP_FAST_COMPLETE:
		if (present) {
			REDEBUG("Unexpected TLVs in complete stage");
			goto unexpected;
		}
		break;
	default:
		REDEBUG("Unexpected stage %d", t->stage);
		return 0;
	}

	/*
	 * We got this far.  It looks OK.
	 */
	return 1;
}

/**
 *
 * FIXME do something with mandatory
 */
static ssize_t eap_fast_decode_pair(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
				    uint8_t const *data, size_t data_len,
				    void *decode_ctx)
{
	fr_dict_attr_t const	*da;
	uint8_t	const		*p = data, *end = p + data_len;

	/*
	 *	Decode the TLVs
	 */
	while (p < end) {
		ssize_t		ret;
		uint16_t	attr;
		uint16_t	len;
		fr_pair_t	*vp;

		attr = fr_nbo_to_uint16(p) & EAP_FAST_TLV_TYPE;
		p += 2;
		len = fr_nbo_to_uint16(p);
		p += 2;

		da = fr_dict_attr_child_by_num(parent, attr);
		if (!da) {
			MEM(vp = fr_pair_afrom_child_num(ctx, parent, attr));

		} else if (da->type == FR_TYPE_TLV) {
			p += (size_t) eap_fast_decode_pair(ctx, out, parent, p, len, decode_ctx);
			continue;

		} else {
			MEM(vp = fr_pair_afrom_da(ctx, da));
		}

		ret = fr_value_box_from_network(vp, &vp->data, vp->vp_type, vp->da,
						&FR_DBUFF_TMP(p, (size_t)len), len, true);
		if (ret != len) {
			fr_pair_raw_afrom_pair(vp, p, len);
		}
		fr_pair_append(out, vp);
		p += len;
	}

	return p - data;
}


/*
 * Use a reply packet to determine what to do.
 */
static rlm_rcode_t CC_HINT(nonnull) process_reply(UNUSED eap_session_t *eap_session,
						  fr_tls_session_t *tls_session,
						  request_t *request,
						  fr_packet_t *reply, fr_pair_list_t *reply_list)
{
	rlm_rcode_t			rcode = RLM_MODULE_REJECT;
	fr_pair_t			*vp;
	fr_dcursor_t			cursor;

	eap_fast_tunnel_t		*t = talloc_get_type_abort(tls_session->opaque, eap_fast_tunnel_t);

	/*
	 * If the response packet was Access-Accept, then
	 * we're OK.  If not, die horribly.
	 *
	 * FIXME: EAP-Messages can only start with 'identity',
	 * NOT 'eap start', so we should check for that....
	 */
	switch (reply->code) {
	case FR_RADIUS_CODE_ACCESS_ACCEPT:
		RDEBUG2("Got tunneled Access-Accept");

		rcode = RLM_MODULE_OK;

		/*
		 * Copy what we need into the TTLS tunnel and leave
		 * the rest to be cleaned up.
		 */
		for (vp = fr_pair_list_head(reply_list); vp; vp = fr_pair_list_next(reply_list, vp)) {
			if (fr_dict_vendor_num_by_da(vp->da) != VENDORPEC_MICROSOFT) continue;

			/* FIXME must be a better way to capture/re-derive this later for ISK */
			switch (vp->da->attr) {
			case FR_MSCHAP_MPPE_SEND_KEY:
				if (vp->vp_length != MD5_DIGEST_LENGTH) {
				wrong_length:
					REDEBUG("Found %s with incorrect length.  Expected %u, got %zu",
						vp->da->name, MD5_DIGEST_LENGTH, vp->vp_length);
					rcode = RLM_MODULE_INVALID;
					break;
				}

				memcpy(t->isk.mppe_send, vp->vp_octets, MD5_DIGEST_LENGTH);
				break;

			case FR_MSCHAP_MPPE_RECV_KEY:
				if (vp->vp_length != MD5_DIGEST_LENGTH) goto wrong_length;
				memcpy(t->isk.mppe_recv, vp->vp_octets, MD5_DIGEST_LENGTH);
				break;

			case FR_MSCHAP2_SUCCESS:
				RDEBUG2("Got %s, tunneling it to the client in a challenge", vp->da->name);
				rcode = RLM_MODULE_HANDLED;
				t->authenticated = true;
				break;

			default:
				break;
			}
		}
		RHEXDUMP3((uint8_t *)&t->isk, 2 * MD5_DIGEST_LENGTH, "ISK[j]"); /* FIXME (part of above) */
		break;

	case FR_RADIUS_CODE_ACCESS_REJECT:
		REDEBUG("Got tunneled Access-Reject");
		rcode = RLM_MODULE_REJECT;
		break;

	case FR_RADIUS_CODE_ACCESS_CHALLENGE:
		RDEBUG2("Got tunneled Access-Challenge");

		/*
		 *	Copy the EAP-Message back to the tunnel.
		 */

		for (vp = fr_pair_dcursor_by_da_init(&cursor, reply_list, attr_eap_message);
		     vp;
		     vp = fr_dcursor_next(&cursor)) {
			eap_fast_tlv_append(tls_session, attr_eap_fast_eap_payload, true, vp->vp_length, vp->vp_octets);
		}

		rcode = RLM_MODULE_HANDLED;
		break;

	default:
		REDEBUG("Unknown RADIUS packet type %d: rejecting tunneled user", reply->code);
		rcode = RLM_MODULE_INVALID;
		break;
	}

	return rcode;
}

static fr_radius_packet_code_t eap_fast_eap_payload(request_t *request, module_ctx_t const *mctx, eap_session_t *eap_session,
				    fr_tls_session_t *tls_session, fr_pair_t *tlv_eap_payload)
{
	fr_radius_packet_code_t		code = FR_RADIUS_CODE_ACCESS_REJECT;
	rlm_rcode_t			rcode;
	fr_pair_t			*vp;
	eap_fast_tunnel_t		*t;
	request_t			*fake;
	rlm_eap_fast_t			*inst = talloc_get_type_abort(mctx->mi->data, rlm_eap_fast_t);

	RDEBUG2("Processing received EAP Payload");

	/*
	 *	Allocate a fake request_t structure.
	 */
	fake = request_local_alloc_internal(request, &(request_init_args_t){ .parent = request });
	fr_assert(fr_pair_list_empty(&fake->request_pairs));

	t = talloc_get_type_abort(tls_session->opaque, eap_fast_tunnel_t);

	/*
	 *	Add the tunneled attributes to the fake request.
	 */

	MEM(vp = fr_pair_afrom_da(fake->request_ctx, attr_eap_message));
	fr_pair_append(&fake->request_pairs, vp);
	fr_pair_value_memdup(vp, tlv_eap_payload->vp_octets, tlv_eap_payload->vp_length, false);

	RDEBUG2("Got tunneled request");
	log_request_pair_list(L_DBG_LVL_1, fake, NULL, &fake->request_pairs, NULL);

	/*
	 *	Tell the request that it's a fake one.
	 */
	MEM(fr_pair_prepend_by_da(fake->request_ctx, &vp, &fake->request_pairs, attr_freeradius_proxied_to) >= 0);
	(void)fr_pair_value_from_str(vp, "127.0.0.1", sizeof("127.0.0.1") - 1, NULL, false);

	/*
	 *	If there's no User-Name in the stored data, look for
	 *	an EAP-Identity, and pull it out of there.
	 */
	if (!t->username) {
		fr_assert(vp->da == attr_eap_message); /* cached from above */

		if ((vp->vp_length >= EAP_HEADER_LEN + 2) &&
		    (vp->vp_strvalue[0] == FR_EAP_CODE_RESPONSE) &&
		    (vp->vp_strvalue[EAP_HEADER_LEN] == FR_EAP_METHOD_IDENTITY) &&
		    (vp->vp_strvalue[EAP_HEADER_LEN + 1] != 0)) {
			/*
			 *	Create and remember a User-Name
			 */
			MEM(t->username = fr_pair_afrom_da(t, attr_user_name));
			t->username->vp_tainted = true;
			fr_pair_value_bstrndup(t->username, (char const *)vp->vp_octets + 5, vp->vp_length - 5, true);

			RDEBUG2("Got tunneled identity of %pV", &t->username->data);
		} else {
			/*
			 * Don't reject the request outright,
			 * as it's permitted to do EAP without
			 * user-name.
			 */
			RWDEBUG2("No EAP-Identity found to start EAP conversation");
		}
	} /* else there WAS a t->username */

	if (t->username) {
		vp = fr_pair_copy(fake->request_ctx, t->username);
		fr_pair_append(&fake->request_pairs, vp);
	}

	if (t->stage == EAP_FAST_AUTHENTICATION) {	/* FIXME do this only for MSCHAPv2 */
		fr_pair_t *tvp;

		MEM(tvp = fr_pair_afrom_da(fake, attr_eap_type));
		tvp->vp_uint32 = t->default_provisioning_method;
		fr_pair_append(&fake->control_pairs, tvp);

		/*
		 * RFC 5422 section 3.2.3 - Authenticating Using EAP-FAST-MSCHAPv2
		 */
		if (t->mode == EAP_FAST_PROVISIONING_ANON) {
			MEM(tvp = fr_pair_afrom_da(fake, attr_ms_chap_challenge));
			fr_pair_value_memdup(tvp, t->keyblock->server_challenge, MD5_DIGEST_LENGTH, false);
			fr_pair_append(&fake->control_pairs, tvp);
			RHEXDUMP3(t->keyblock->server_challenge, MD5_DIGEST_LENGTH, "MSCHAPv2 auth_challenge");

			MEM(tvp = fr_pair_afrom_da(fake, attr_ms_chap_peer_challenge));
			fr_pair_value_memdup(tvp, t->keyblock->client_challenge, MD5_DIGEST_LENGTH, false);
			fr_pair_append(&fake->control_pairs, tvp);
			RHEXDUMP3(t->keyblock->client_challenge, MD5_DIGEST_LENGTH, "MSCHAPv2 peer_challenge");
		}
	}

	/*
	 * Call authentication recursively, which will
	 * do PAP, CHAP, MS-CHAP, etc.
	 */
	eap_virtual_server(request, eap_session, inst->virtual_server);

	/*
	 * Decide what to do with the reply.
	 */
	switch (fake->reply->code) {
	case 0:			/* No reply code, must be proxied... */
#ifdef WITH_PROXY
		vp = fr_pair_find_by_da(&fake->control, NULL, attr_proxy_to_realm);
		if (vp) {
			int			ret;
			eap_tunnel_data_t	*tunnel;

			RDEBUG2("Tunneled authentication will be proxied to %pV", &vp->data);

			/*
			 *	Tell the original request that it's going to be proxied.
			 */
			fr_pair_list_copy_by_da(request->control_ctx, &request->control_pairs,
						&fake->control_pairs, attr_proxy_to_realm, 0);

			/*
			 *	Seed the proxy packet with the tunneled request.
			 */
			fr_assert(!request->proxy);

			/*
			 *	FIXME: Actually proxy stuff
			 */
			request->proxy = request_alloc_internal(request, &(request_init_args_t){ .parent = request });

			request->proxy->packet = talloc_steal(request->proxy, fake->packet);
			memset(&request->proxy->packet->src_ipaddr, 0,
			       sizeof(request->proxy->packet->src_ipaddr));
			memset(&request->proxy->packet->src_ipaddr, 0,
			       sizeof(request->proxy->packet->src_ipaddr));
			request->proxy->packet->src_port = 0;
			request->proxy->packet->dst_port = 0;
			fake->packet = NULL;
			fr_packet_free(&fake->reply);
			fake->reply = NULL;

			/*
			 *	Set up the callbacks for the tunnel
			 */
			tunnel = talloc_zero(request, eap_tunnel_data_t);
			tunnel->tls_session = tls_session;

			/*
			 *	Associate the callback with the request.
			 */
			ret = request_data_add(request, request->proxy, REQUEST_DATA_EAP_TUNNEL_CALLBACK,
					       tunnel, false, false, false);
			fr_cond_assert(ret == 0);

			/*
			 *	rlm_eap.c has taken care of associating the eap_session
			 *	with the fake request.
			 *
			 *	So we associate the fake request with this request.
			 */
			ret = request_data_add(request, request->proxy, REQUEST_DATA_EAP_MSCHAP_TUNNEL_CALLBACK,
					       fake, true, false, false);
			fr_cond_assert(ret == 0);

			fake = NULL;

			/*
			 *	Didn't authenticate the packet, but we're proxying it.
			 */
			code = FR_RADIUS_CODE_STATUS_CLIENT;

		} else
#endif	/* WITH_PROXY */
		  {
			  REDEBUG("No tunneled reply was found, and the request was not proxied: rejecting the user");
			  code = FR_RADIUS_CODE_ACCESS_REJECT;
		  }
		break;

	default:
		/*
		 *	Returns RLM_MODULE_FOO, and we want to return FR_FOO
		 */
		rcode = process_reply(eap_session, tls_session, request, fake->reply, &fake->reply_pairs);
		switch (rcode) {
		case RLM_MODULE_REJECT:
			code = FR_RADIUS_CODE_ACCESS_REJECT;
			break;

		case RLM_MODULE_HANDLED:
			code = FR_RADIUS_CODE_ACCESS_CHALLENGE;
			break;

		case RLM_MODULE_OK:
			code = FR_RADIUS_CODE_ACCESS_ACCEPT;
			break;

		default:
			code = FR_RADIUS_CODE_ACCESS_REJECT;
			break;
		}
		break;
	}

	talloc_free(fake);

	return code;
}

static fr_radius_packet_code_t eap_fast_crypto_binding(request_t *request, UNUSED eap_session_t *eap_session,
				       fr_tls_session_t *tls_session, eap_tlv_crypto_binding_tlv_t *binding)
{
	uint8_t			cmac[sizeof(binding->compound_mac)];
	eap_fast_tunnel_t	*t = talloc_get_type_abort(tls_session->opaque, eap_fast_tunnel_t);

	memcpy(cmac, binding->compound_mac, sizeof(cmac));
	memset(binding->compound_mac, 0, sizeof(binding->compound_mac));

	RHEXDUMP3((uint8_t const *) binding, sizeof(*binding), "Crypto-Binding TLV for Compound MAC calculation");
	RHEXDUMP3(cmac, sizeof(cmac), "Received Compound MAC");

	fr_hmac_sha1(binding->compound_mac, (uint8_t *)binding, sizeof(*binding), t->cmk, EAP_FAST_CMK_LEN);
	if (memcmp(binding->compound_mac, cmac, sizeof(cmac))) {
		RDEBUG2("Crypto-Binding TLV mismatch");
		RHEXDUMP3((uint8_t const *) binding->compound_mac,
                sizeof(binding->compound_mac), "Calculated Compound MAC");
		return FR_RADIUS_CODE_ACCESS_REJECT;
	}

	return FR_RADIUS_CODE_ACCESS_ACCEPT;
}

static fr_radius_packet_code_t eap_fast_process_tlvs(request_t *request, module_ctx_t const *mctx, eap_session_t *eap_session,
				     fr_tls_session_t *tls_session, fr_pair_list_t *fast_vps)
{
	eap_fast_tunnel_t		*t = talloc_get_type_abort(tls_session->opaque, eap_fast_tunnel_t);
	fr_pair_t			*vp;
	eap_tlv_crypto_binding_tlv_t	my_binding, *binding = NULL;

	memset(&my_binding, 0, sizeof(my_binding));

	for (vp = fr_pair_list_head(fast_vps);
	     vp;
	     vp = fr_pair_list_next(fast_vps, vp)) {
		fr_radius_packet_code_t code = FR_RADIUS_CODE_ACCESS_REJECT;
		if (vp->da->parent == fr_dict_root(dict_eap_fast)) {
			if (vp->da == attr_eap_fast_eap_payload) {
				code = eap_fast_eap_payload(request, mctx, eap_session, tls_session, vp);
				if (code == FR_RADIUS_CODE_ACCESS_ACCEPT) t->stage = EAP_FAST_CRYPTOBIND_CHECK;
			} else if ((vp->da == attr_eap_fast_result) ||
				   (vp->da == attr_eap_fast_intermediate_result)) {
				code = FR_RADIUS_CODE_ACCESS_ACCEPT;
				t->stage = EAP_FAST_PROVISIONING;
			} else {
				RDEBUG2("ignoring unknown %pP", vp);
				continue;
			}
		} else if (vp->da->parent == attr_eap_fast_crypto_binding) {
			binding = &my_binding;

			/*
			 *	fr_radius_encode_pair() does not work for structures
			 */
			switch (vp->da->attr) {
			case 1:	/* FR_EAP_FAST_CRYPTO_BINDING_RESERVED */
				binding->reserved = vp->vp_uint8;
				break;
			case 2:	/* FR_EAP_FAST_CRYPTO_BINDING_VERSION */
				binding->version = vp->vp_uint8;
				break;
			case 3:	/* FR_EAP_FAST_CRYPTO_BINDING_RECV_VERSION */
				binding->received_version = vp->vp_uint8;
				break;
			case 4:	/* FR_EAP_FAST_CRYPTO_BINDING_SUB_TYPE */
				binding->subtype = vp->vp_uint8;
				break;
			case 5:	/* FR_EAP_FAST_CRYPTO_BINDING_NONCE */
				if (vp->vp_length >= sizeof(binding->nonce)) {
					memcpy(binding->nonce, vp->vp_octets, vp->vp_length);
				}
				break;
			case 6:	/* FR_EAP_FAST_CRYPTO_BINDING_COMPOUND_MAC */
				if (vp->vp_length >= sizeof(binding->compound_mac)) {
					memcpy(binding->compound_mac, vp->vp_octets, sizeof(binding->compound_mac));
				}
				break;
			}
			continue;
		} else if (vp->da->parent == attr_eap_fast_pac_tlv) {
			if (vp->da == attr_eap_fast_pac_acknowledge) {
				if (vp->vp_uint32 == EAP_FAST_TLV_RESULT_SUCCESS) {
					code = FR_RADIUS_CODE_ACCESS_ACCEPT;
					t->pac.expires = fr_time_max();
					t->pac.expired = false;
					t->stage = EAP_FAST_COMPLETE;
				}
			} else if (vp->da == attr_eap_fast_pac_info_pac_type) {
				if (vp->vp_uint32 != PAC_TYPE_TUNNEL) {
					RDEBUG2("only able to serve Tunnel PAC's, ignoring request");
					continue;
				}
				t->pac.send = true;
				continue;
			} else {
				RDEBUG2("ignoring unknown EAP-FAST-PAC-TLV %pP", vp);
				continue;
			}
		} else {
			RDEBUG2("ignoring non-EAP-FAST TLV %pP", vp);
			continue;
		}

		if (code == FR_RADIUS_CODE_ACCESS_REJECT) return FR_RADIUS_CODE_ACCESS_REJECT;
	}

	if (binding) {
		fr_radius_packet_code_t code = eap_fast_crypto_binding(request, eap_session, tls_session, binding);
		if (code == FR_RADIUS_CODE_ACCESS_ACCEPT) {
			t->stage = EAP_FAST_PROVISIONING;
		}
		return code;
	}

	return FR_RADIUS_CODE_ACCESS_ACCEPT;
}


/*
 * Process the inner tunnel data
 */
static fr_radius_packet_code_t eap_fast_process(request_t *request, module_ctx_t const *mctx, eap_session_t *eap_session, fr_tls_session_t *tls_session)
{
	fr_radius_packet_code_t			code;
	fr_pair_list_t		fast_vps;
	uint8_t const		*data;
	size_t			data_len;
	eap_fast_tunnel_t	*t;

	fr_pair_list_init(&fast_vps);
	/*
	 * Just look at the buffer directly, without doing
	 * record_to_buff.
	 */
	data_len = tls_session->clean_out.used;
	tls_session->clean_out.used = 0;
	data = tls_session->clean_out.data;

	t = talloc_get_type_abort(tls_session->opaque, eap_fast_tunnel_t);

	/*
	 * See if the tunneled data is well formed.
	 */
	if (!eap_fast_verify(request, tls_session, data, data_len)) return FR_RADIUS_CODE_ACCESS_REJECT;

	if (t->stage == EAP_FAST_TLS_SESSION_HANDSHAKE) {
		char buf[256];

		fr_assert(t->mode == EAP_FAST_UNKNOWN);

		if (strstr(SSL_CIPHER_description(SSL_get_current_cipher(tls_session->ssl),
						  buf, sizeof(buf)), "Au=None")) {
			/* FIXME enforce MSCHAPv2 - RFC 5422 section 3.2.2 */
			RDEBUG2("Using anonymous provisioning");
			t->mode = EAP_FAST_PROVISIONING_ANON;
			t->pac.send = true;
		} else {
			fr_time_t renew;

			if (SSL_session_reused(tls_session->ssl)) {
				RDEBUG2("Session Resumed from PAC");
				t->mode = EAP_FAST_NORMAL_AUTH;
			} else {
				RDEBUG2("Using authenticated provisioning");
				t->mode = EAP_FAST_PROVISIONING_AUTH;
			}

			/*
			 *	Send a new pac at 60% of the lifetime,
			 *	or if the PAC has expired, or if no lifetime was set.
			 */
			renew = fr_time_add(request->packet->timestamp,
					    fr_time_delta_wrap((fr_time_delta_unwrap(t->pac_lifetime) * 3) / 5));

			if (t->pac.expired || fr_time_eq(t->pac.expires, fr_time_wrap(0)) ||
			     fr_time_lteq(t->pac.expires, renew)) {
				t->pac.send = true;
			}
		}

		eap_fast_init_keys(request, tls_session);

		eap_fast_send_identity_request(request, tls_session, eap_session);

		t->stage = EAP_FAST_AUTHENTICATION;
		return FR_RADIUS_CODE_ACCESS_CHALLENGE;
	}

	if (eap_fast_decode_pair(request, &fast_vps, fr_dict_root(dict_eap_fast),
				 data, data_len, NULL) < 0) return FR_RADIUS_CODE_ACCESS_REJECT;

	RDEBUG2("Got Tunneled FAST TLVs");
	log_request_pair_list(L_DBG_LVL_1, request, NULL, &fast_vps, NULL);
	code = eap_fast_process_tlvs(request, mctx, eap_session, tls_session, &fast_vps);
	fr_pair_list_free(&fast_vps);

	if (code == FR_RADIUS_CODE_ACCESS_REJECT) return FR_RADIUS_CODE_ACCESS_REJECT;

	switch (t->stage) {
	case EAP_FAST_AUTHENTICATION:
		code = FR_RADIUS_CODE_ACCESS_CHALLENGE;
		break;

	case EAP_FAST_CRYPTOBIND_CHECK:
	{
		if (t->mode != EAP_FAST_PROVISIONING_ANON && !t->pac.send)
			t->result_final = true;

		eap_fast_append_result(tls_session, code);

		eap_fast_update_icmk(request, tls_session, (uint8_t *)&t->isk);
		eap_fast_append_crypto_binding(request, tls_session);

		code = FR_RADIUS_CODE_ACCESS_CHALLENGE;
		break;
	}
	case EAP_FAST_PROVISIONING:
		t->result_final = true;

		eap_fast_append_result(tls_session, code);

		if (t->pac.send) {
			RDEBUG2("Peer requires new PAC");
			eap_fast_send_pac_tunnel(request, tls_session);
			code = FR_RADIUS_CODE_ACCESS_CHALLENGE;
			break;
		}

		t->stage = EAP_FAST_COMPLETE;
		FALL_THROUGH;

	case EAP_FAST_COMPLETE:
		/*
		 * RFC 5422 section 3.5 - Network Access after EAP-FAST Provisioning
		 */
		if (t->pac.type && t->pac.expired) {
			REDEBUG("Rejecting expired PAC.");
			code = FR_RADIUS_CODE_ACCESS_REJECT;
			break;
		}

		if (t->mode == EAP_FAST_PROVISIONING_ANON) {
			REDEBUG("Rejecting unauthenticated provisioning");
			code = FR_RADIUS_CODE_ACCESS_REJECT;
			break;
		}

		/*
		 * eap_crypto_mppe_keys() is unsuitable for EAP-FAST as Cisco decided
		 * it would be a great idea to flip the recv/send keys around
		 */
		#define EAPTLS_MPPE_KEY_LEN 32
		eap_add_reply(request, attr_ms_mppe_recv_key, t->msk, EAPTLS_MPPE_KEY_LEN);
		eap_add_reply(request, attr_ms_mppe_send_key, &t->msk[EAPTLS_MPPE_KEY_LEN], EAPTLS_MPPE_KEY_LEN);
		eap_add_reply(request, attr_eap_msk, t->msk, EAP_FAST_KEY_LEN);
		eap_add_reply(request, attr_eap_emsk, t->emsk, EAP_EMSK_LEN);

		break;

	default:
		RERROR("Internal sanity check failed in EAP-FAST at %d", t->stage);
		code = FR_RADIUS_CODE_ACCESS_REJECT;
	}

	return code;
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

static int _session_secret(SSL *s, void *secret, int *secret_len,
			   UNUSED STACK_OF(SSL_CIPHER) *peer_ciphers,
			   UNUSED SSL_CIPHER const **cipher, void *arg)
{
	// FIXME enforce non-anon cipher

	request_t		*request = fr_tls_session_request(s);
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
	fr_tls_session_t	*tls_session = talloc_get_type_abort(arg, fr_tls_session_t);
	request_t		*request = fr_tls_session_request(s);
	eap_fast_tunnel_t	*t;
	fr_pair_list_t		fast_vps;
	fr_pair_t		*vp;
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
		if (!fr_pair_list_empty(&fast_vps)) fr_pair_list_free(&fast_vps);
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

	if (eap_fast_decode_pair(tls_session, &fast_vps, attr_eap_fast_pac_opaque_tlv, (uint8_t *)&opaque_plaintext, plen, NULL) < 0) {
		errmsg = fr_strerror();
		goto error;
	}

	for (vp = fr_pair_list_head(&fast_vps);
	     vp;
	     vp = fr_pair_list_next(&fast_vps, vp)) {
		if (vp->da == attr_eap_fast_pac_info_pac_type) {
			fr_assert(t->pac.type == 0);
			t->pac.type = vp->vp_uint16;
		} else if (vp->da == attr_eap_fast_pac_info_pac_lifetime) {
			fr_assert(fr_time_eq(t->pac.expires, fr_time_wrap(0)));
			t->pac.expires = fr_time_add(request->packet->timestamp, vp->vp_time_delta);
			t->pac.expired = false;
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

	if (fr_time_eq(t->pac.expires, fr_time_wrap(0))) {
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

static unlang_action_t mod_handshake_resume(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	eap_session_t		*eap_session = talloc_get_type_abort(mctx->rctx, eap_session_t);
	eap_tls_session_t	*eap_tls_session = talloc_get_type_abort(eap_session->opaque, eap_tls_session_t);
	fr_tls_session_t	*tls_session = eap_tls_session->tls_session;

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
		fr_tls_session_send(request, tls_session);
		fr_assert(tls_session->opaque != NULL);
		break;

	/*
	 *	The TLS code is still working on the TLS
	 *	exchange, and it's a valid TLS request.
	 *	do nothing.
	 */
	case EAP_TLS_HANDLED:
		RETURN_UNLANG_HANDLED;

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
		RETURN_UNLANG_FAIL;
	}

	/*
	 *	Session is established, proceed with decoding
	 *	tunneled data.
	 */
	RDEBUG2("Session established.  Proceeding to decode tunneled attributes");

	/*
	 *	Process the FAST portion of the request.
	 */
	switch (eap_fast_process(request, mctx, eap_session, tls_session)) {
	case FR_RADIUS_CODE_ACCESS_REJECT:
		eap_tls_fail(request, eap_session);
		RETURN_UNLANG_FAIL;

		/*
		 *	Access-Challenge, continue tunneled conversation.
		 */
	case FR_RADIUS_CODE_ACCESS_CHALLENGE:
		fr_tls_session_send(request, tls_session);
		eap_tls_request(request, eap_session);
		RETURN_UNLANG_HANDLED;

	/*
	 *	Success.
	 */
	case FR_RADIUS_CODE_ACCESS_ACCEPT:
		if (eap_tls_success(request, eap_session, NULL) < 0) RETURN_UNLANG_FAIL;

		/*
		 *	@todo - generate MPPE keys, which have their own magical deriviation.
		 */

		/*
		 *	Result is always OK, even if we fail to persist the
		 *	session data.
		 */
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

	/*
	 *	No response packet, MUST be proxying it.
	 *	The main EAP module will take care of discovering
	 *	that the request now has a "proxy" packet, and
	 *	will proxy it, rather than returning an EAP packet.
	 */
	case FR_RADIUS_CODE_STATUS_CLIENT:
		RETURN_UNLANG_OK;

	default:
		break;
	}

	/*
	 *	Something we don't understand: Reject it.
	 */
	eap_tls_fail(request, eap_session);
	RETURN_UNLANG_FAIL;
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

/*
 *	Send an initial eap-tls request to the peer, using the libeap functions.
 */
static unlang_action_t mod_session_init(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_eap_fast_t const	*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_eap_fast_t);
	rlm_eap_fast_thread_t	*thread = talloc_get_type_abort(mctx->thread, rlm_eap_fast_thread_t);
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
	vp = fr_pair_find_by_da(&request->control_pairs, NULL, attr_eap_tls_require_client_cert);
	if (vp) {
		client_cert = vp->vp_uint32 ? true : false;
	} else {
		client_cert = inst->req_client_cert;
	}

	eap_session->opaque = eap_tls_session = eap_tls_session_init(request, eap_session, thread->ssl_ctx, client_cert);
	if (!eap_tls_session) RETURN_UNLANG_FAIL;

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
		RETURN_UNLANG_FAIL;
	}

	tls_session->record_init(&tls_session->clean_in);
	tls_session->opaque = eap_fast_alloc(tls_session, inst);
	eap_session->process = mod_handshake_process;

	if (!SSL_set_session_ticket_ext_cb(tls_session->ssl, _session_ticket, tls_session)) {
		RERROR("Failed setting SSL session ticket callback");
		RETURN_UNLANG_FAIL;
	}

	RETURN_UNLANG_HANDLED;
}

static int mod_thread_instantiate(module_thread_inst_ctx_t const *mctx)
{
	rlm_eap_fast_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_eap_fast_t);
	rlm_eap_fast_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_eap_fast_thread_t);

	t->ssl_ctx = fr_tls_ctx_alloc(inst->tls_conf, false);
	if (!t->ssl_ctx) return -1;

	return 0;
}

static int mod_thread_detach(module_thread_inst_ctx_t const *mctx)
{
	rlm_eap_fast_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_eap_fast_thread_t);

	if (likely(t->ssl_ctx != NULL)) SSL_CTX_free(t->ssl_ctx);
	t->ssl_ctx = NULL;

	return 0;
}

/*
 *	Attach the module.
 */
static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_eap_fast_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_eap_fast_t);
	CONF_SECTION		*conf = mctx->mi->conf;

	inst->default_provisioning_method = eap_name2type(inst->default_provisioning_method_name);
	if (!inst->default_provisioning_method) {
		cf_log_err_by_child(conf, "default_provisioning_eap_type", "Unknown EAP type %s",
				   inst->default_provisioning_method_name);
		return -1;
	}

	/*
	 *	Read tls configuration, either from group given by 'tls'
	 *	option, or from the eap-tls configuration.
	 */
	inst->tls_conf = eap_tls_conf_parse(conf);

	if (!inst->tls_conf) {
		cf_log_err_by_child(conf, "tls", "Failed initializing SSL context");
		return -1;
	}

	if (talloc_array_length(inst->pac_opaque_key) - 1 != 32) {
		cf_log_err_by_child(conf, "pac_opaque_key", "Must be 32 bytes long");
		return -1;
	}

	/*
	 *	Allow anything for the TLS version, we try to forcibly
	 *	disable TLSv1.2 later.
	 */
	if (inst->tls_conf->tls_min_version > (float) 1.1) {
		cf_log_err_by_child(conf, "tls_min_version", "require tls_min_version <= 1.1");
		return -1;
	}

	if (!fr_time_delta_ispos(inst->pac_lifetime)) {
		cf_log_err_by_child(conf, "pac_lifetime", "must be non-zero");
		return -1;
	}

	fr_assert(PAC_A_ID_LENGTH == MD5_DIGEST_LENGTH);

	fr_md5_calc(inst->a_id, (uint8_t const *)inst->authority_identity,
		    talloc_array_length(inst->authority_identity) - 1);

	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
extern rlm_eap_submodule_t rlm_eap_fast;
rlm_eap_submodule_t rlm_eap_fast = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "eap_fast",

		.inst_size		= sizeof(rlm_eap_fast_t),
		.config			= submodule_config,
		.instantiate		= mod_instantiate,	/* Create new submodule instance */

		.thread_inst_size	= sizeof(rlm_eap_fast_thread_t),
		.thread_instantiate	= mod_thread_instantiate,
		.thread_detach		= mod_thread_detach,
	},
	.provides		= { FR_EAP_METHOD_FAST },
	.session_init		= mod_session_init,	/* Initialise a new EAP session */
};
