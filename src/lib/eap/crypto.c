/*
 *   This program is is free software; you can redistribute it and/or modify
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
 * @file lib/eap/crypto.c
 * @brief MPPE key calculation API
 *
 * @author Henrik Eriksson (henriken@axis.com)
 * @author Lars Viklund (larsv@axis.com)
 *
 * @copyright 2002 Axis Communications AB
 * @copyright 2006 The FreeRADIUS server project
 */

RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#define __STDC_WANT_LIB_EXT1__ 1
#include <string.h>

#include <freeradius-devel/util/sha1.h>
#include <freeradius-devel/tls/base.h>
#include <freeradius-devel/tls/log.h>

#include "tls.h"
#include "base.h"
#include "attrs.h"

#include <openssl/hmac.h>

/** Initialize the PRF label fields
 *
 */
void eap_crypto_prf_label_init(eap_tls_prf_label_t *prf_label, eap_session_t *eap_session,
			      char const *keying_prf_label, size_t keying_prf_label_len)
{
#ifdef TLS1_3_VERSION
	eap_tls_session_t	*eap_tls_session = talloc_get_type_abort(eap_session->opaque, eap_tls_session_t);

	if (eap_tls_session->tls_session->info.version == TLS1_3_VERSION) {
		prf_label->keying_prf_label = "EXPORTER_EAP_TLS_Key_Material";
		prf_label->keying_prf_label_len = sizeof("EXPORTER_EAP_TLS_Key_Material") - 1;

		prf_label->sessid_prf_label = "EXPORTER_EAP_TLS_Method-Id";
		prf_label->sessid_prf_label_len = sizeof("EXPORTER_EAP_TLS_Method-Id") - 1;

		prf_label->context[0] = eap_session->type;
		prf_label->context_len = 1;
		prf_label->use_context = 1;
		return;
	}
#endif

	prf_label->keying_prf_label = keying_prf_label;
	prf_label->keying_prf_label_len = keying_prf_label_len;

	prf_label->sessid_prf_label = NULL;
	prf_label->sessid_prf_label_len = 0;

	prf_label->context[0] = 0;
	prf_label->context_len = 0;
	prf_label->use_context = 0;
}


#define EAP_TLS_MPPE_KEY_LEN     32

/** Generate keys according to RFC 5216 and add to the reply
 *
 */
int eap_crypto_mppe_keys(request_t *request, SSL *ssl, eap_tls_prf_label_t *prf_label)
{
	uint8_t		out[4 * EAP_TLS_MPPE_KEY_LEN];
	uint8_t		*p;

	if (!prf_label->keying_prf_label) return 0;

	if (SSL_export_keying_material(ssl, out, sizeof(out),
				       prf_label->keying_prf_label,
				       prf_label->keying_prf_label_len,
				       prf_label->context,
				       prf_label->context_len,
				       prf_label->use_context) != 1) {
		fr_tls_log(request, "Failed generating MPPE keys");
		return -1;
	}

	if (RDEBUG_ENABLED3) {
		uint8_t	random[SSL3_RANDOM_SIZE];
		size_t random_len;
		uint8_t	master_key[SSL_MAX_MASTER_KEY_LENGTH];
		size_t master_key_len;

		RDEBUG3("Key Derivation Function input");
		RINDENT();
		RDEBUG3("prf label          : %s", prf_label->keying_prf_label);
		master_key_len = SSL_SESSION_get_master_key(SSL_get_session(ssl), master_key, sizeof(master_key));
		RDEBUG3("master session key : %pH", fr_box_octets(master_key, master_key_len));
		random_len = SSL_get_client_random(ssl, random, SSL3_RANDOM_SIZE);
		RDEBUG3("client random      : %pH", fr_box_octets(random, random_len));
		random_len = SSL_get_server_random(ssl, random, SSL3_RANDOM_SIZE);
		RDEBUG3("server random      : %pH", fr_box_octets(random, random_len));
		REXDENT();
	}

	RDEBUG2("Adding session keys");
	p = out;
	eap_add_reply(request, attr_ms_mppe_recv_key, p, EAP_TLS_MPPE_KEY_LEN);
	p += EAP_TLS_MPPE_KEY_LEN;
	eap_add_reply(request, attr_ms_mppe_send_key, p, EAP_TLS_MPPE_KEY_LEN);

	eap_add_reply(request, attr_eap_msk, out, 64);
	eap_add_reply(request, attr_eap_emsk, out + 64, 64);

	return 0;
}

int eap_crypto_tls_session_id(TALLOC_CTX *ctx,
			      request_t *request, SSL *ssl, eap_tls_prf_label_t *prf_label,
			      uint8_t **out, uint8_t eap_type)
{
	uint8_t		*buff = NULL, *p;

	*out = NULL;

	if (!prf_label->sessid_prf_label) goto random_based_session_id;

	switch (SSL_SESSION_get_protocol_version(SSL_get_session(ssl))) {
	case SSL2_VERSION:	/* Should never happen */
	case SSL3_VERSION:	/* Should never happen */
		return - 1;

	case TLS1_VERSION:	/* No Method ID */
	case TLS1_1_VERSION:	/* No Method ID */
	case TLS1_2_VERSION:	/* No Method ID */
	random_based_session_id:
		MEM(buff = p = talloc_array(ctx, uint8_t, sizeof(eap_type) + (2 * SSL3_RANDOM_SIZE)));
		*p++ = eap_type;

		SSL_get_client_random(ssl, p, SSL3_RANDOM_SIZE);
		p += SSL3_RANDOM_SIZE;
		SSL_get_server_random(ssl, p, SSL3_RANDOM_SIZE);
		break;

	/*
	 *	Method-Id = TLS-Exporter("EXPORTER_EAP_TLS_Method-Id", "", 64)
	 *	Session-Id = <EAP-Type> || Method-Id
	 */
	case TLS1_3_VERSION:
	default:
	{
		MEM(buff = p = talloc_array(ctx, uint8_t, sizeof(eap_type) + 64));
		*p++ = eap_type;
		if (SSL_export_keying_material(ssl, p, 64,
					       prf_label->sessid_prf_label,
					       prf_label->sessid_prf_label_len,
					       prf_label->context,
					       prf_label->context_len,
					       prf_label->use_context) != 1) {
			talloc_free(buff);
			fr_tls_log(request, "Failed generating TLS session ID");
			return -1;
		}
	}
		break;
	}
	*out = buff;

	return 0;
}
