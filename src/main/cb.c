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

#ifdef WITH_TLS
void cbtls_info(SSL const *s, int where, int ret)
{
	char const *role, *state;
	REQUEST *request = SSL_get_ex_data(s, FR_TLS_EX_INDEX_REQUEST);

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
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
			STACK_OF(SSL_CIPHER) *client_ciphers;
			STACK_OF(SSL_CIPHER) *server_ciphers;
#endif

			/*
			 *	Trim crappy OpenSSL state strings...
			 */
			len = strlen(abbrv);
			if ((len > 1) && (abbrv[len - 1] == ' ')) len--;

			RDEBUG3("(TLS) Handshake state [%.*s] - %s%s (%d)",
				(int)len, abbrv, role, state, SSL_get_state(s));

			/*
			 *	After a ClientHello, list all the proposed ciphers from the client
			 */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
			if (SSL_get_state(s) == TLS_ST_SR_CLNT_HELLO) {
				int i;
				int num_ciphers;
				const SSL_CIPHER *this_cipher;

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
					RDEBUG3("Client preferred ciphers (by priority)");
					num_ciphers = sk_SSL_CIPHER_num(client_ciphers);
					for (i = 0; i < num_ciphers; i++) {
						this_cipher = sk_SSL_CIPHER_value(client_ciphers, i);
						RDEBUG3("(TLS)    [%i] %s", i, SSL_CIPHER_get_name(this_cipher));
					}
				}
			}
#endif
		} else {
			RDEBUG2("(TLS) Handshake state - %s%s", role, state);
		}
		return;
	}

	if (where & SSL_CB_ALERT) {
		if ((ret & 0xff) == SSL_AD_CLOSE_NOTIFY) return;

		RERROR("(TLS) Alert %s:%s:%s", (where & SSL_CB_READ) ? "read": "write",
		       SSL_alert_type_string_long(ret), SSL_alert_desc_string_long(ret));
		return;
	}

	if (where & SSL_CB_EXIT) {
		if (ret == 0) {
			RERROR("(TLS) %s: Failed in %s", role, state);
			return;
		}

		if (ret < 0) {
			if (SSL_want_read(s)) {
				RDEBUG2("(TLS) %s: Need to read more data: %s", role, state);
				return;
			}
			RERROR("(TLS) %s: Error in %s", role, state);
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
		DEBUG4("(TLS) Ignoring cbtls_msg call with pseudo content type %i, version %i",
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

#endif
