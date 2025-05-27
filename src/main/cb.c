/*
 * cb.c
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
 * Copyright 2001  hereUare Communications, Inc. <raghud@hereuare.com>
 * Copyright 2006  The FreeRADIUS server project
 */

RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#include <freeradius-devel/radiusd.h>
#include <ctype.h>

#ifdef WITH_TLS
void cbtls_info(SSL const *s, int where, int ret)
{
	char const *role, *state;
	REQUEST *request = SSL_get_ex_data(s, FR_TLS_EX_INDEX_REQUEST);
	fr_tls_server_conf_t *conf = (fr_tls_server_conf_t *) SSL_get_ex_data(s, FR_TLS_EX_INDEX_CONF);

	if ((where & ~SSL_ST_MASK) & SSL_ST_CONNECT) {
		role = "Client ";
	} else if (((where & ~SSL_ST_MASK)) & SSL_ST_ACCEPT) {
		role = "Server ";
	} else {
		role = "";
	}

	state = SSL_state_string_long(s);
	state = state ? state : "<none>";

	if ((where & SSL_CB_LOOP) || (where & SSL_CB_HANDSHAKE_START) || (where & SSL_CB_HANDSHAKE_DONE)) {
		if (RDEBUG_ENABLED3) {
			char const *abbrv = SSL_state_string(s);
			size_t len;

			/*
			 *	Trim crappy OpenSSL state strings...
			 */
			len = strlen(abbrv);
			if ((len > 1) && (abbrv[len - 1] == ' ')) len--;

			RDEBUG3("(TLS) %s - Handshake state [%.*s] - %s%s (%d)", conf->name,
				(int)len, abbrv, role, state, SSL_get_state(s));

			/*
			 *	After a ClientHello, list all the proposed ciphers from the client
			 */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
			if (SSL_get_state(s) == TLS_ST_SR_CLNT_HELLO) {
				int i;
				int num_ciphers;
				const SSL_CIPHER *this_cipher;
				STACK_OF(SSL_CIPHER) *client_ciphers;
				STACK_OF(SSL_CIPHER) *server_ciphers;

			report_ciphers:
				server_ciphers = SSL_get_ciphers(s);
				if (server_ciphers) {
					RDEBUG3("Server preferred ciphers (by priority)");
					num_ciphers = sk_SSL_CIPHER_num(server_ciphers);
					for (i = 0; i < num_ciphers; i++) {
						this_cipher = sk_SSL_CIPHER_value(server_ciphers, i);
						RDEBUG3("(TLS)    [%i] %s", i, SSL_CIPHER_get_name(this_cipher));
					}
				}

				client_ciphers = SSL_get_client_ciphers(s);
				if (client_ciphers) {
					RDEBUG3("(TLS) %s - Client preferred ciphers (by priority)", conf->name);
					num_ciphers = sk_SSL_CIPHER_num(client_ciphers);
					for (i = 0; i < num_ciphers; i++) {
						this_cipher = sk_SSL_CIPHER_value(client_ciphers, i);
						RDEBUG3("(TLS)    [%i] %s", i, SSL_CIPHER_get_name(this_cipher));
					}
				}
			}
#endif
		} else {
			RDEBUG2("(TLS) %s - Handshake state - %s%s", conf->name, role, state);
		}
		return;
	}

	if (where & SSL_CB_ALERT) {
		if ((ret & 0xff) == SSL_AD_CLOSE_NOTIFY) return;

		RERROR("(TLS) %s - Alert %s:%s:%s", conf->name, (where & SSL_CB_READ) ? "read": "write",
		       SSL_alert_type_string_long(ret), SSL_alert_desc_string_long(ret));
		return;
	}

	if (where & SSL_CB_EXIT) {
		if (ret == 0) {
			RERROR("(TLS) %s - %s: Failed in %s", conf->name, role, state);
			return;
		}

		if (ret < 0) {
			if (SSL_want_read(s)) {
				RDEBUG2("(TLS) %s - %s: Need to read more data: %s", conf->name, role, state);
				return;
			}
			if (SSL_want_write(s)) {
				RDEBUG2("(TLS) %s - %s: Need to write more data: %s", conf->name, role, state);
				return;
			}
			RERROR("(TLS) %s - %s: Error in %s", conf->name, role, state);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
			if (RDEBUG_ENABLED3 && (SSL_get_state(s) == TLS_ST_SR_CLNT_HELLO)) goto report_ciphers;
#endif
		}
	}
}

/*
 *	Fill in our 'info' with TLS data.
 */
void cbtls_msg(int write_p, int msg_version, int content_type,
	       void const *inbuf, size_t len,
	       SSL *ssl UNUSED, void *arg)
{
	uint8_t const *buf = inbuf;
	tls_session_t *state = (tls_session_t *)arg;

	/*
	 *	OpenSSL 1.0.2 calls this function with 'pseudo'
	 *	content types.  Which breaks our tracking of
	 *	the SSL Session state.
	 */
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	if ((msg_version == 0) && (content_type > UINT8_MAX)) {
#else
	/*
         *      "...we do not see the need to resolve application breakage
         *      just because the documentation now is incorrect."
         *
         *      https://github.com/openssl/openssl/issues/17262
	 */
	if ((content_type > UINT8_MAX) && (content_type != SSL3_RT_INNER_CONTENT_TYPE)) {
#endif
		DEBUG4("(TLS) Ignoring cbtls_msg call with pseudo content type %i, version %08x",
		       content_type, msg_version);
		return;
	}

	if ((write_p != 0) && (write_p != 1)) {
		DEBUG4("(TLS) Ignoring cbtls_msg call with invalid write_p %d", write_p);
		return;
	}

	/*
	 *	Work around bug #298, where we may be called with a NULL
	 *	argument.  We should really log a serious error
	 */
	if (!state) return;

	if (rad_debug_lvl > 3) {
		size_t i, j, data_len = len;
		char buffer[3*16 + 1];
		uint8_t const *in = inbuf;

		DEBUG("(TLS) Received %zu bytes of TLS data", len);
		if (data_len > 256) data_len = 256;

		for (i = 0; i < data_len; i += 16) {
			for (j = 0; j < 16; j++) {
				if ((i + j) >= data_len) break;

				sprintf(buffer + 3 * j, "%02x ", in[i + j]);
			}

			DEBUG("(TLS)        %s", buffer);
		}
	}

	/*
	 *	0 - received (from peer)
	 *	1 - sending (to peer)
	 */
	state->info.origin = write_p;
	state->info.content_type = content_type;
	state->info.record_len = len;
	state->info.initialized = true;

	if (content_type == SSL3_RT_ALERT) {
		state->info.alert_level = buf[0];
		state->info.alert_description = buf[1];
		state->info.handshake_type = 0x00;

	} else if (content_type == SSL3_RT_HANDSHAKE) {
		state->info.handshake_type = buf[0];
		state->info.alert_level = 0x00;
		state->info.alert_description = 0x00;

#if OPENSSL_VERSION_NUMBER >= 0x10101000L
	} else if (content_type == SSL3_RT_INNER_CONTENT_TYPE && buf[0] == SSL3_RT_APPLICATION_DATA) {
		/* let tls_ack_handler set application_data */
		state->info.content_type = SSL3_RT_HANDSHAKE;
#endif

#ifdef SSL3_RT_HEARTBEAT
	} else if (content_type == TLS1_RT_HEARTBEAT) {
		uint8_t *p = buf;

		if ((len >= 3) && (p[0] == 1)) {
			size_t payload_len;

			payload_len = (p[1] << 8) | p[2];

			if ((payload_len + 3) > len) {
				state->invalid_hb_used = true;
				ERROR("OpenSSL Heartbeat attack detected.  Closing connection");
				return;
			}
		}
#endif
	}

	tls_session_information(state);
}

int cbtls_password(char *buf,
		   int num,
		   int rwflag UNUSED,
		   void *userdata)
{
	size_t len;

	len = strlcpy(buf, (char *)userdata, num);
	if (len >= (size_t) num) {
		ERROR("Password too long.  Maximum length is %i bytes", num - 1);
		return 0;
	}

	return len;
}

#ifdef PSK_MAX_IDENTITY_LEN
static bool identity_is_safe(const char *identity)
{
	char c;

	if (!identity) return true;

	while ((c = *(identity++)) != '\0') {
		if (isalpha((uint8_t) c) || isdigit((uint8_t) c) || isspace((uint8_t) c) ||
		    (c == '@') || (c == '-') || (c == '_') || (c == '.')) {
			continue;
		}

		return false;
	}

	return true;
}

static size_t psk_query_run(unsigned char *psk, REQUEST *request, SSL *ssl, fr_tls_server_conf_t *conf,
			    char const *identity, unsigned int max_psk_len)
{
	size_t hex_len;
	VALUE_PAIR *vp, **certs;
	TALLOC_CTX *talloc_ctx;
	char buffer[2 * PSK_MAX_PSK_LEN + 4]; /* allow for too-long keys */

	/*
	 *	The passed identity is weird.  Deny it.
	 */
	if (!identity_is_safe(identity)) {
		RWDEBUG("(TLS) %s - Invalid characters in PSK identity %s", conf->name, identity);
		return 0;
	}

	vp = pair_make_request("TLS-PSK-Identity", identity, T_OP_SET);
	if (!vp) return 0;

	certs = (VALUE_PAIR **)SSL_get_ex_data(ssl, fr_tls_ex_index_certs);
	talloc_ctx = SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_TALLOC);
	fr_assert(certs != NULL); /* pointer to sock->certs */
	fr_assert(talloc_ctx != NULL); /* sock */

	fr_pair_add(certs, fr_pair_copy(talloc_ctx, vp));

	hex_len = radius_xlat(buffer, sizeof(buffer), request, conf->psk_query, NULL, NULL);
	if (!hex_len) {
		RWDEBUG("(TLS) %s - PSK expansion returned an empty string.", conf->name);
		return 0;
	}

	/*
	 *	The returned key is truncated at MORE than
	 *	OpenSSL can handle.  That way we can detect
	 *	the truncation, and complain about it.
	 */
	if (hex_len > (2 * max_psk_len)) {
		RWDEBUG("(TLS) %s - Returned PSK is too long (%u > %u)", conf->name,
			(unsigned int) hex_len, 2 * max_psk_len);
		return 0;
	}

	/*
	 *	Leave the TLS-PSK-Identity in the request, and
	 *	convert the expansion from printable string
	 *	back to hex.
	 */
	return fr_hex2bin(psk, max_psk_len, buffer, hex_len);
}

/*
 *	When a client uses TLS-PSK to talk to a server, this callback
 *	is used by the server to determine the PSK to use.
 */
unsigned int psk_server_callback(SSL *ssl, const char *identity, unsigned char *psk, unsigned int max_psk_len)
{
	unsigned int psk_len = 0;
	fr_tls_server_conf_t *conf;
	REQUEST *request;

	conf = (fr_tls_server_conf_t *)SSL_get_ex_data(ssl,
						       FR_TLS_EX_INDEX_CONF);
	if (!conf) return 0;

	request = (REQUEST *)SSL_get_ex_data(ssl,
					     FR_TLS_EX_INDEX_REQUEST);
	if (request && conf->psk_query) {
		return psk_query_run(psk, request, ssl, conf, identity, max_psk_len);
	}

	if (!conf->psk_identity) {
		DEBUG("No static PSK identity set.  Rejecting the user");
		return 0;
	}

	/*
	 *	No REQUEST, or no dynamic query.  Just look for a
	 *	static identity.
	 */
	if (strcmp(identity, conf->psk_identity) != 0) {
		ERROR("(TKS) Supplied PSK identity %s does not match configuration.  Rejecting.",
		      identity);
		return 0;
	}

	psk_len = strlen(conf->psk_password);
	if (psk_len > (2 * max_psk_len)) return 0;

	return fr_hex2bin(psk, max_psk_len, conf->psk_password, psk_len);
}

#if OPENSSL_VERSION_NUMBER >= 0x10101000
/** Check that a whole string is valid utf8
 * @param str input string.
 * @param inlen length of input string.
 */
static bool utf8_validate(uint8_t const *str, size_t inlen) {
	size_t used, remaining = inlen;
	uint8_t const *p = str;

	while (remaining > 0) {
		used = fr_utf8_char(p, remaining);
		if (used == 0) return false;
		remaining -= used;
		p += used;
	}
	return true;
}

int cbtls_psk_find_session(SSL *ssl, const unsigned char *id, size_t idlen, SSL_SESSION **sess) {
	fr_tls_server_conf_t	*conf = (fr_tls_server_conf_t *) SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_CONF);
	REQUEST			*request = (REQUEST *)SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_REQUEST);
	SSL_CIPHER const	*cipher;
	uint8_t			psk_key[PSK_MAX_PSK_LEN];
	size_t			key_len = 0;

	if (!utf8_validate(id, idlen)) {
        	DEBUG2("Id is not a valid utf-8 string, assuming session resumption");
		*sess = NULL;
		return 1;
	} else if (idlen > PSK_MAX_IDENTITY_LEN) {
		WARN("id is longer than %d bytes", PSK_MAX_IDENTITY_LEN);
		*sess = NULL;
		return 0;
	}

	if (!conf) {
		ERROR("No configuration for client with PSK id %s found, rejecting connection", id);
		*sess = NULL;
		return 0;
	}

	if (conf->psk_password) {
		key_len = fr_hex2bin(psk_key, sizeof(psk_key), conf->psk_password,
				     talloc_array_length(conf->psk_password) - 1);
	} else {
		if (request && conf->psk_query) {
			key_len = psk_query_run(psk_key, request, ssl, conf, (char const *)id, sizeof(psk_key));
		}
	}

	if (key_len == 0) {
		ERROR("No PSK for client with id %s found, rejecting connection", id);
		*sess = NULL;
		return 0;
	}

	*sess = SSL_SESSION_new();
	if (!*sess) {
		ERROR("Failed to create new SSL session");
		return 0;
	}
	if (!SSL_SESSION_set1_master_key(*sess, psk_key, key_len)) {
		ERROR("Failed to set PSK key");
		return 0;
	}

	if (!SSL_SESSION_set_protocol_version(*sess, TLS1_3_VERSION)) {
		ERROR("Failed to set tls version 1.3, mandatory for PSK!");
		return 0;
	}

	cipher = SSL_get_pending_cipher(ssl);
	if (!cipher) {
		ERROR("Failed to get pending cipher");
		return 0;
	}

	DEBUG2("Setting session cipher %s", SSL_CIPHER_get_name(cipher));
	if (!SSL_SESSION_set_cipher(*sess, cipher)) {
        	ERROR("Failed to set session cipher");
		return 0;
	}

	SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);

	return 1;
}
#endif
#endif
#endif
