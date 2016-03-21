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
 * @file tls/session.c
 * @brief Initialise OpenSSL sessions, and read/write data to/from them.
 *
 * @Copyright 2001 hereUare Communications, Inc. <raghud@hereuare.com>
 * @Copyright 2003  Alan DeKok <aland@freeradius.org>
 * @copyright 2006-2016 The FreeRADIUS server project
 */

#ifdef HAVE_OPENSSL_OCSP_H
#define LOG_PREFIX "tls - "

#include <ctype.h>
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>

FR_NAME_NUMBER const fr_tls_status_table[] = {
	{ "invalid",			FR_TLS_INVALID },
	{ "request",			FR_TLS_REQUEST },
	{ "response",			FR_TLS_RESPONSE },
	{ "success",			FR_TLS_SUCCESS },
	{ "fail",			FR_TLS_FAIL },
	{ "noop",			FR_TLS_NOOP },

	{ "start",			FR_TLS_START },
	{ "ok",				FR_TLS_RECORD_COMPLETE },
	{ "ack",			FR_TLS_ACK },
	{ "first fragment",		FR_TLS_RECORD_FRAGMENT_INIT },
	{ "more fragments",		FR_TLS_RECORD_FRAGMENT_MORE },
	{ "handled",			FR_TLS_HANDLED },
	{  NULL , 			-1},
};

static void record_init(tls_record_t *record)
{
	record->used = 0;
}

static void record_close(tls_record_t *record)
{
	record->used = 0;
}

/** Copy data to the intermediate buffer, before we send it somewhere
 *
 */
static unsigned int record_from_buff(tls_record_t *record, void const *in, unsigned int inlen)
{
	unsigned int added = FR_TLS_MAX_RECORD_SIZE - record->used;

	if (added > inlen) added = inlen;
	if (added == 0) return 0;

	memcpy(record->data + record->used, in, added);
	record->used += added;

	return added;
}

/** Take data from the buffer, and give it to the caller
 *
 */
static unsigned int record_to_buff(tls_record_t *record, void *out, unsigned int outlen)
{
	unsigned int taken = record->used;

	if (taken > outlen) taken = outlen;
	if (taken == 0) return 0;
	if (out) memcpy(out, record->data, taken);

	record->used -= taken;

	/*
	 *	This is pretty bad...
	 */
	if (record->used > 0) memmove(record->data, record->data + taken, record->used);

	return taken;
}

/** Return the static private key password we have configured
 *
 */
int tls_session_password_cb(char *buf, int num UNUSED, int rwflag UNUSED, void *userdata)
{
	/*
	 *	We do this instead of not registering the callback
	 *	to ensure OpenSSL doesn't try and read a password
	 *	from stdin (causes server to block).
	 */
	if (!userdata) {
		ERROR("Certificate encrypted but no private_key_password configured");
		return 0;
	}

	strcpy(buf, (char *)userdata);
	return(strlen((char *)userdata));
}

#ifdef PSK_MAX_IDENTITY_LEN
/** Verify the PSK identity contains no reserved chars
 *
 * @param identity to check.
 * @return
 *	- true identity does not contain reserved chars.
 *	- false identity contains reserved chars.
 */
static bool session_psk_identity_is_safe(const char *identity)
{
	char c;

	if (!identity) return true;

	while ((c = *(identity++)) != '\0') {
		if (isalpha((int) c) || isdigit((int) c) || isspace((int) c) ||
		    (c == '@') || (c == '-') || (c == '_') || (c == '.')) {
			continue;
		}

		return false;
	}

	return true;
}

unsigned int tls_session_psk_client_cb(SSL *ssl, UNUSED char const *hint,
				       char *identity, unsigned int max_identity_len,
				       unsigned char *psk, unsigned int max_psk_len)
{
	unsigned int psk_len;
	fr_tls_conf_t *conf;

	conf = (fr_tls_conf_t *)SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_CONF);
	if (!conf) return 0;

	psk_len = strlen(conf->psk_password);
	if (psk_len > (2 * max_psk_len)) return 0;

	strlcpy(identity, conf->psk_identity, max_identity_len);

	return fr_hex2bin(psk, max_psk_len, conf->psk_password, psk_len);
}

/** Determine the PSK to use
 *
 */
unsigned int tls_session_psk_server_cb(SSL *ssl, const char *identity,
				       unsigned char *psk, unsigned int max_psk_len)
{
	unsigned int	psk_len = 0;
	fr_tls_conf_t	*conf;
	REQUEST		*request;

	conf = (fr_tls_conf_t *)SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_CONF);
	if (!conf) return 0;

	request = (REQUEST *)SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_REQUEST);
	if (request && conf->psk_query) {
		size_t hex_len;
		VALUE_PAIR *vp;
		char buffer[2 * PSK_MAX_PSK_LEN + 4]; /* allow for too-long keys */

		/*
		 *	The passed identity is weird.  Deny it.
		 */
		if (!session_psk_identity_is_safe(identity)) {
			RWDEBUG("Invalid characters in PSK identity %s", identity);
			return 0;
		}

		vp = pair_make_request("TLS-PSK-Identity", identity, T_OP_SET);
		if (!vp) return 0;

		hex_len = radius_xlat(buffer, sizeof(buffer), request, conf->psk_query,
				      NULL, NULL);
		if (!hex_len) {
			RWDEBUG("PSK expansion returned an empty string.");
			return 0;
		}

		/*
		 *	The returned key is truncated at MORE than
		 *	OpenSSL can handle.  That way we can detect
		 *	the truncation, and complain about it.
		 */
		if (hex_len > (2 * max_psk_len)) {
			RWDEBUG("Returned PSK is too long (%u > %u)", (unsigned int) hex_len, 2 * max_psk_len);
			return 0;
		}

		/*
		 *	Leave the TLS-PSK-Identity in the request, and
		 *	convert the expansion from printable string
		 *	back to hex.
		 */
		return fr_hex2bin(psk, max_psk_len, buffer, hex_len);
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
		ERROR("Supplied PSK identity %s does not match configuration.  Rejecting.",
		      identity);
		return 0;
	}

	psk_len = strlen(conf->psk_password);
	if (psk_len > (2 * max_psk_len)) return 0;

	return fr_hex2bin(psk, max_psk_len, conf->psk_password, psk_len);
}
#endif

void tls_session_info_cb(SSL const *ssl, int where, int ret)
{
	char const *str, *state;
	REQUEST *request = SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_REQUEST);

	if ((where & ~SSL_ST_MASK) & SSL_ST_CONNECT) {
		str = "connect";
	} else if (((where & ~SSL_ST_MASK)) & SSL_ST_ACCEPT) {
		str = "accept";
	} else {
		str = NULL;
	}

	state = SSL_state_string_long(ssl);
	state = state ? state : "<none>";

	if ((where & SSL_CB_LOOP) || (where & SSL_CB_HANDSHAKE_START) || (where & SSL_CB_HANDSHAKE_DONE)) {
		if (str) {
			RDEBUG2("%s: Handshake state \"%s\"", str, state);
		} else {
			RDEBUG2("Handshake state \"%s\"", state);
		}
		return;
	}

	if (where & SSL_CB_ALERT) {
		if ((ret & 0xff) == SSL_AD_CLOSE_NOTIFY) return;

		if (where & SSL_CB_READ) {
			REDEBUG("Client sent %s TLS alert: %s", SSL_alert_type_string_long(ret),
			       SSL_alert_desc_string_long(ret));

			/*
			 *	Offer helpful advice... Should be expanded.
			 */
			switch (ret & 0xff) {
			case TLS1_AD_UNKNOWN_CA:
				REDEBUG("Verify client has copy of CA certificate, and trusts CA");
				break;

			default:
				break;
			}
		} else {
			REDEBUG("Sending client %s TLS alert: %s %i",  SSL_alert_type_string_long(ret),
			       SSL_alert_desc_string_long(ret), ret & 0xff);
		}
		return;
	}

	if (where & SSL_CB_EXIT) {
		if (ret == 0) {
			REDEBUG("%s: Handshake exit state \"%s\"", str, state);
			return;
		}

		if (ret < 0) {
			if (SSL_want_read(ssl)) {
				RDEBUG2("%s: Need to read more data: %s", str, state);
				return;
			}
			REDEBUG("tls: %s: Handshake exit state \"%s\"", str, state);
		}
	}
}

static void session_msg_log(tls_session_t *tls_session)
{
	char const *str_write_p, *str_version, *str_content_type = "";
	char const *str_details1 = "", *str_details2= "";
	REQUEST *request;
	char buffer[32];
	char content_type[20];

	/*
	 *	Don't print this out in the normal course of
	 *	operations.
	 */
	if (rad_debug_lvl == 0) return;

	str_write_p = tls_session->info.origin ? ">>> send" : "<<< recv";

	switch (tls_session->info.version) {
	case SSL2_VERSION:
		str_version = "SSL 2.0 ";
		break;

	case SSL3_VERSION:
		str_version = "SSL 3.0 ";
		break;

	case TLS1_VERSION:
		str_version = "TLS 1.0 ";
		break;

#ifdef TLS1_1_VERSION
	case TLS1_1_VERSION:
		str_version = "TLS 1.1 ";
		break;
#endif
#ifdef TLS1_2_VERSION
	case TLS1_2_VERSION:
		str_version = "TLS 1.2 ";
		break;
#endif
#ifdef TLS1_3_VERSON
	case TLS1_3_VERSION:
		str_version = "TLS 1.3 ";
		break;
#endif

	default:
		if (tls_session->info.version) {
			sprintf(buffer, "UNKNOWN TLS VERSION 0x%04x", tls_session->info.version);
			str_version = buffer;
		} else {
			str_version = "";
		}
		break;
	}

	/*
	 *	TLS 1.0, 1.1, 1.2 content types are the same as SSLv3
	 */
	switch (tls_session->info.content_type) {
	case SSL3_RT_CHANGE_CIPHER_SPEC:
		str_content_type = "change_cipher_spec ";
		break;

	case SSL3_RT_ALERT:
		str_content_type = "alert ";
		break;

	case SSL3_RT_HANDSHAKE:
		str_content_type = "handshake ";
		break;

	case SSL3_RT_APPLICATION_DATA:
		str_content_type = "application_data ";
		break;

	case TLS1_RT_HEARTBEAT:
		str_content_type = "heartbeat ";
		break;

#ifdef TLS1_RT_CRYPTO
	case TLS1_RT_CRYPTO:
		str_content_type = "crypto ";
		break;
#endif

#ifdef TLS1_RT_CRYPTO_PREMASTER
	case TLS1_RT_CRYPTO_PREMASTER:
		str_content_type = "crypto_premaster ";
		break;
#endif

#ifdef TLS1_RT_CRYPTO_CLIENT_RANDOM
	case TLS1_RT_CRYPTO_CLIENT_RANDOM:
		str_content_type = "client_random ";
		break;
#endif

#ifdef TLS1_RT_CRYPTO_SERVER_RANDOM
	case TLS1_RT_CRYPTO_SERVER_RANDOM:
		str_content_type = "server_random ";
		break;
#endif

#ifdef TLS1_RT_CRYPTO_MASTER
	case TLS1_RT_CRYPTO_MASTER:
		str_content_type = "crypto_master ";
		break;
#endif

#ifdef TLS1_RT_CRYPTO_READ
	case TLS1_RT_CRYPTO_READ:
		str_content_type = "crypto_read ";
		break;
#endif

#ifdef TLS1_RT_CRYPTO_WRITE
	case TLS1_RT_CRYPTO_WRITE:
		str_content_type = "crypto_write ";
		break;
#endif

#ifdef TLS1_RT_CRYPTO_MAC
	case TLS1_RT_CRYPTO_MAC:
		str_content_type = "crypto_mac ";
		break;
#endif

#ifdef TLS1_RT_CRYPTO_KEY
	case TLS1_RT_CRYPTO_KEY:
		str_content_type = "crypto_key ";
		break;
#endif

#ifdef TLS1_RT_CRYPTO_IV
	case TLS1_RT_CRYPTO_IV:
		str_content_type = "crypto_iv ";
		break;
#endif

#ifdef TLS1_RT_CRYPTO_FIXED_IV
	case TLS1_RT_CRYPTO_FIXED_IV:
		str_content_type = "crypto_fixed_iv ";
		break;
#endif

	default:
		snprintf(content_type, sizeof(content_type), "unknown content type %i", tls_session->info.content_type );
		str_content_type = content_type;
		break;
	}

	if (tls_session->info.content_type == SSL3_RT_ALERT) {
		str_details1 = ", ???";

		if (tls_session->info.record_len == 2) {

			switch (tls_session->info.alert_level) {
			case SSL3_AL_WARNING:
				str_details1 = ", warning";
				break;
			case SSL3_AL_FATAL:
				str_details1 = ", fatal";
				break;
			}

			str_details2 = " ???";
			switch (tls_session->info.alert_description) {
			case SSL3_AD_CLOSE_NOTIFY:
				str_details2 = " close_notify";
				break;

			case SSL3_AD_UNEXPECTED_MESSAGE:
				str_details2 = " unexpected_message";
				break;

			case SSL3_AD_BAD_RECORD_MAC:
				str_details2 = " bad_record_mac";
				break;

			case TLS1_AD_DECRYPTION_FAILED:
				str_details2 = " decryption_failed";
				break;

			case TLS1_AD_RECORD_OVERFLOW:
				str_details2 = " record_overflow";
				break;

			case SSL3_AD_DECOMPRESSION_FAILURE:
				str_details2 = " decompression_failure";
				break;

			case SSL3_AD_HANDSHAKE_FAILURE:
				str_details2 = " handshake_failure";
				break;

			case SSL3_AD_BAD_CERTIFICATE:
				str_details2 = " bad_certificate";
				break;

			case SSL3_AD_UNSUPPORTED_CERTIFICATE:
				str_details2 = " unsupported_certificate";
				break;

			case SSL3_AD_CERTIFICATE_REVOKED:
				str_details2 = " certificate_revoked";
				break;

			case SSL3_AD_CERTIFICATE_EXPIRED:
				str_details2 = " certificate_expired";
				break;

			case SSL3_AD_CERTIFICATE_UNKNOWN:
				str_details2 = " certificate_unknown";
				break;

			case SSL3_AD_ILLEGAL_PARAMETER:
				str_details2 = " illegal_parameter";
				break;

			case TLS1_AD_UNKNOWN_CA:
				str_details2 = " unknown_ca";
				break;

			case TLS1_AD_ACCESS_DENIED:
				str_details2 = " access_denied";
				break;

			case TLS1_AD_DECODE_ERROR:
				str_details2 = " decode_error";
				break;

			case TLS1_AD_DECRYPT_ERROR:
				str_details2 = " decrypt_error";
				break;

			case TLS1_AD_EXPORT_RESTRICTION:
				str_details2 = " export_restriction";
				break;

			case TLS1_AD_PROTOCOL_VERSION:
				str_details2 = " protocol_version";
				break;

			case TLS1_AD_INSUFFICIENT_SECURITY:
				str_details2 = " insufficient_security";
				break;

			case TLS1_AD_INTERNAL_ERROR:
				str_details2 = " internal_error";
				break;

			case TLS1_AD_USER_CANCELLED:
				str_details2 = " user_canceled";
				break;

			case TLS1_AD_NO_RENEGOTIATION:
				str_details2 = " no_renegotiation";
				break;
			}
		}
	}

	if (tls_session->info.content_type == SSL3_RT_HANDSHAKE) {
		str_details1 = "???";

		if (tls_session->info.record_len > 0) switch (tls_session->info.handshake_type) {
		case SSL3_MT_HELLO_REQUEST:
			str_details1 = ", hello_request";
			break;

		case SSL3_MT_CLIENT_HELLO:
			str_details1 = ", client_hello";
			break;

		case SSL3_MT_SERVER_HELLO:
			str_details1 = ", server_hello";
			break;

		case SSL3_MT_CERTIFICATE:
			str_details1 = ", certificate";
			break;

		case SSL3_MT_SERVER_KEY_EXCHANGE:
			str_details1 = ", server_key_exchange";
			break;

		case SSL3_MT_CERTIFICATE_REQUEST:
			str_details1 = ", certificate_request";
			break;

		case SSL3_MT_SERVER_DONE:
			str_details1 = ", server_hello_done";
			break;

		case SSL3_MT_CERTIFICATE_VERIFY:
			str_details1 = ", certificate_verify";
			break;

		case SSL3_MT_CLIENT_KEY_EXCHANGE:
			str_details1 = ", client_key_exchange";
			break;

		case SSL3_MT_FINISHED:
			str_details1 = ", finished";
			break;
		}
	}

	snprintf(tls_session->info.info_description,
		 sizeof(tls_session->info.info_description),
		 "%s %s%s[length %lu]%s%s\n",
		 str_write_p, str_version, str_content_type,
		 (unsigned long)tls_session->info.record_len,
		 str_details1, str_details2);

	request = SSL_get_ex_data(tls_session->ssl, FR_TLS_EX_INDEX_REQUEST);
	ROPTIONAL(RDEBUG2, DEBUG2, "%s", tls_session->info.info_description);
}

/*
 *	Fill in our 'info' with TLS data.
 */
void tls_session_msg_cb(int write_p, int msg_version, int content_type,
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
	if ((msg_version == 0) && (content_type > UINT8_MAX)) {
		DEBUG4("Ignoring tls_session_msg_cb call with pseudo content type %i, version %i",
		       content_type, msg_version);
		return;
	}

	if ((write_p != 0) && (write_p != 1)) {
		DEBUG4("Ignoring tls_session_msg_cb call with invalid write_p %d", write_p);
		return;
	}

	/*
	 *	Work around bug #298, where we may be called with a NULL
	 *	argument.  We should really log a serious error
	 */
	if (!state) return;

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
	session_msg_log(state);
}

/** Decrypt application data
 *
 * @note Handshake must have completed before this function may be called.
 *
 * Feed data from dirty_in to OpenSSL, and read the clean data into clean_out.
 *
 * @param request The current request.
 * @param session The current TLS session.
 * @return
 *	- FR_TLS_FAIL on error.
 *	- FR_TLS_RECORD_FRAGMENT_MORE if more fragments are required to fully
 *	  reassemble the record for decryption.
 *	- FR_TLS_RECORD_COMPLETE if we decrypted a complete record.
 */
fr_tls_status_t tls_session_recv(REQUEST *request, tls_session_t *session)
{
	int ret;

	if (!SSL_is_init_finished(session->ssl)) {
		REDEBUG("Attempted to read application data before handshake completed");
		return FR_TLS_FAIL;
	}

	/*
	 *	Decrypt the complete record.
	 */
	ret = BIO_write(session->into_ssl, session->dirty_in.data, session->dirty_in.used);
	if (ret != (int) session->dirty_in.used) {
		record_init(&session->dirty_in);
		REDEBUG("Failed writing %zd bytes to SSL BIO: %d", session->dirty_in.used, ret);
		return FR_TLS_FAIL;
	}

	/*
	 *      Clear the dirty buffer now that we are done with it
	 *      and init the clean_out buffer to store decrypted data
	 */
	record_init(&session->dirty_in);
	record_init(&session->clean_out);

	/*
	 *      Read (and decrypt) the tunneled data from the
	 *      SSL session, and put it into the decrypted
	 *      data buffer.
	 */
	ret = SSL_read(session->ssl, session->clean_out.data, sizeof(session->clean_out.data));
	if (ret < 0) {
		int code;

		code = SSL_get_error(session->ssl, ret);
		switch (code) {
		case SSL_ERROR_WANT_READ:
			RWDEBUG("Peer indicated record was complete, but OpenSSL returned SSL_WANT_READ. "
				"Attempting to continue");
			return FR_TLS_RECORD_FRAGMENT_MORE;

		case SSL_ERROR_WANT_WRITE:
			REDEBUG("Error in fragmentation logic: SSL_WANT_WRITE");
			break;

		default:
			REDEBUG("Error in fragmentation logic");
			tls_log_io_error(request, session, ret, "Failed in SSL_read");
			break;
		}
		return FR_TLS_FAIL;
	}

	if (ret == 0) RWDEBUG("No data inside of the tunnel");

	/*
	 *	Passed all checks, successfully decrypted data
	 */
	session->clean_out.used = ret;

	RDEBUG2("Decrypted TLS application data (%zu bytes)", session->clean_out.used);
	radlog_request_hex(L_DBG, L_DBG_LVL_3, request, session->clean_out.data, session->clean_out.used);

	return FR_TLS_RECORD_COMPLETE;
}

/** Encrypt application data
 *
 * @note Handshake must have completed before this function may be called.
 *
 * Take cleartext data from clean_in, and feed it to OpenSSL, reading
 * the encrypted data into dirty_out.
 *
 * @param request The current request.
 * @param session The current TLS session.
 * @return
 *	- 0 on failure.
 *	- 1 on success.
 */
int tls_session_send(REQUEST *request, tls_session_t *session)
{
	if (!SSL_is_init_finished(session->ssl)) {
		REDEBUG("Attempted to write application data before handshake completed");
		return FR_TLS_FAIL;
	}

	/*
	 *	If there's un-encrypted data in 'clean_in', then write
	 *	that data to the SSL session, and then call the BIO function
	 *	to get that encrypted data from the SSL session, into
	 *	a buffer which we can then package into an EAP packet.
	 *
	 *	Based on Server's logic this clean_in is expected to
	 *	contain the data to send to the client.
	 */
	if (session->clean_in.used > 0) {
		int ret;

		RDEBUG2("TLS application data to encrypt (%zu bytes)", session->clean_in.used);
		radlog_request_hex(L_DBG, L_DBG_LVL_3, request, session->clean_in.data, session->clean_in.used);

		ret = SSL_write(session->ssl, session->clean_in.data, session->clean_in.used);
		record_to_buff(&session->clean_in, NULL, ret);

		/* Get the dirty data from Bio to send it */
		ret = BIO_read(session->from_ssl, session->dirty_out.data,
			       sizeof(session->dirty_out.data));
		if (ret > 0) {
			session->dirty_out.used = ret;
		} else {
			if (!tls_log_io_error(request, session, ret, "Failed in SSL_write")) return 0;
		}
	}

	return 1;
}

/** Continue a TLS handshake
 *
 * Advance the TLS handshake by feeding OpenSSL data from dirty_in,
 * and reading data from OpenSSL into dirty_out.
 *
 * @param request The current request.
 * @param session The current TLS session.
 * @return
 *	- 0 on error.
 *	- 1 on success.
 */
int tls_session_handshake(REQUEST *request, tls_session_t *session)
{
	int ret;

	/*
	 *	This is a logic error.  tls_session_handshake
	 *	must not be called if the handshake is
	 *	complete tls_session_recv must be
	 *	called instead.
	 */
	if (SSL_is_init_finished(session->ssl)) {
		REDEBUG("Attempted to continue TLS handshake, but handshake has completed");
		return 0;
	}

	if (session->invalid_hb_used) return 0;

	/*
	 *	Feed dirty data into OpenSSL, so that is can either
	 *	process it as Application data (decrypting it)
	 *	or continue the TLS handshake.
	 */
	ret = BIO_write(session->into_ssl, session->dirty_in.data, session->dirty_in.used);
	if (ret != (int)session->dirty_in.used) {
		REDEBUG("Failed writing %zd bytes to TLS BIO: %d", session->dirty_in.used, ret);
		record_init(&session->dirty_in);
		return 0;
	}
	record_init(&session->dirty_in);

	/*
	 *	Magic/More magic? Although SSL_read is normally
	 *	used to read application data, it will also
	 *	continue the TLS handshake.  Removing this call will
	 *	cause the handshake to fail.
	 *
	 *	We don't ever expect to actually *receive* application
	 *	data here.
	 *
	 *	The reason why we call SSL_read instead of SSL_accept,
	 *	or SSL_connect, as it allows this function
	 *	to be used, irrespective or whether we're acting
	 *	as a client or a server.
	 *
	 *	If acting as a client SSL_set_connect_state must have
	 *	been called before this function.
	 *
	 *	If acting as a server SSL_set_accept_state must have
	 *	been called before this function.
	 */
	ret = SSL_read(session->ssl, session->clean_out.data + session->clean_out.used,
		       sizeof(session->clean_out.data) - session->clean_out.used);
	if (ret > 0) {
		session->clean_out.used += ret;
		return 1;
	}
	if (!tls_log_io_error(request, session, ret, "Failed in SSL_read")) return 0;

	/*
	 *	This only occurs once per session, where calling
	 *	SSL_read updates the state of the SSL session, setting
	 *	this flag to true.
	 */
	if (SSL_is_init_finished(session->ssl)) {
		SSL_CIPHER const *cipher;
		char buffer[256];

		cipher = SSL_get_current_cipher(session->ssl);

		RDEBUG2("TLS established with cipher suite: %s",
			SSL_CIPHER_description(cipher, buffer, sizeof(buffer)));
	} else if (SSL_in_init(session->ssl)) {
		RDEBUG2("In TLS handshake phase");
	} else if (SSL_in_before(session->ssl)) {
		RDEBUG2("Before TLS handshake phase");
	}

	if (SSL_in_accept_init(session->ssl)) {
		RDEBUG2("In server (accept) mode");
	} else if (SSL_in_connect_init(session->ssl)) {
		RDEBUG2("In client (connect) mode");
	}

#if OPENSSL_VERSION_NUMBER >= 0x10001000L
	/*
	 *	Cache the SSL_SESSION pointer.
	 */
	if (!session->ssl_session && SSL_is_init_finished(session->ssl)) {
		session->ssl_session = SSL_get_session(session->ssl);
		if (!session->ssl_session) {
			RDEBUG("Failed getting TLS session");
			return 0;
		}
	}
#endif

	/*
	 *	Get data to pack and send back to the TLS peer.
	 */
	ret = BIO_ctrl_pending(session->from_ssl);
	if (ret > 0) {
		ret = BIO_read(session->from_ssl, session->dirty_out.data,
			       sizeof(session->dirty_out.data));
		if (ret > 0) {
			session->dirty_out.used = ret;
		} else if (BIO_should_retry(session->from_ssl)) {
			record_init(&session->dirty_in);
			RDEBUG2("Asking for more data in tunnel");
			return 1;

		} else {
			tls_log_error(NULL, NULL);
			record_init(&session->dirty_in);
			return 0;
		}
	} else {
		/* Its clean application data, do whatever we want */
		record_init(&session->clean_out);
	}

	/* We are done with dirty_in, reinitialize it */
	record_init(&session->dirty_in);
	return 1;
}

/** Reduce session states down into an easy to use status
 *
 * @return
 *	- FR_TLS_SUCCESS - Handshake completed Message.
 *	- FR_TLS_FAIL - Fatal alert from the client.
 *	- FR_TLS_REQUEST - Need more data, or previous fragment was acked.
 */
fr_tls_status_t tls_session_status(REQUEST *request, tls_session_t *session)
{
	if (session == NULL){
		REDEBUG("Unexpected ACK received:  No ongoing SSL session");
		return FR_TLS_INVALID;
	}
	if (!session->info.initialized) {
		RDEBUG("No SSL info available.  Waiting for more SSL data");
		return FR_TLS_REQUEST;
	}

	if ((session->info.content_type == handshake) && (session->info.origin == 0)) {
		REDEBUG("Unexpected ACK received:  We sent no previous messages");
		return FR_TLS_INVALID;
	}

	switch (session->info.content_type) {
	case alert:
		RDEBUG2("Peer ACKed our alert");
		return FR_TLS_FAIL;

	case handshake:
		if ((session->info.handshake_type == handshake_finished) && (session->dirty_out.used == 0)) {
			RDEBUG2("Peer ACKed our handshake fragment.  handshake is finished");

			/*
			 *	From now on all the content is
			 *	application data set it here as nobody else
			 *	sets it.
			 */
			session->info.content_type = application_data;
			return FR_TLS_SUCCESS;
		} /* else more data to send */

		RDEBUG2("Peer ACKed our handshake fragment");
		/* Fragmentation handler, send next fragment */
		return FR_TLS_REQUEST;

	case application_data:
		RDEBUG2("Peer ACKed our application data fragment");
		return FR_TLS_REQUEST;

		/*
		 *	For the rest of the conditions, switch over
		 *	to the default section below.
		 */
	default:
		REDEBUG("Invalid ACK received: %d", session->info.content_type);
		return FR_TLS_INVALID;
	}
}

/** Free a TLS session and any associated OpenSSL data
 *
 * @param session to free.
 * @return 0.
 */
static int _tls_session_free(tls_session_t *session)
{
	SSL_set_quiet_shutdown(session->ssl, 1);
	SSL_shutdown(session->ssl);

	if (session->ssl) {
		SSL_free(session->ssl);
		session->ssl = NULL;
	}

	return 0;
}

static void session_init(tls_session_t *session)
{
	session->ssl = NULL;
	session->into_ssl = session->from_ssl = NULL;
	record_init(&session->clean_in);
	record_init(&session->clean_out);
	record_init(&session->dirty_in);
	record_init(&session->dirty_out);

	memset(&session->info, 0, sizeof(session->info));

	session->mtu = 0;
	session->record_out_started = false;
	session->record_out_total_len = 0;
	session->length_flag = false;
	session->opaque = NULL;
}

/** Create a new client TLS session
 *
 * Configures a new client TLS session, configuring options, setting callbacks etc...
 *
 * @param ctx to alloc session data in. Should usually be NULL unless the lifetime of the
 *	session is tied to another talloc'd object.
 * @param conf to use to configure the tls session.
 * @param fd OpenSSL should read from/write to.
 * @return
 *	- A new session on success.
 *	- NULL on error.
 */
tls_session_t *tls_session_init_client(TALLOC_CTX *ctx, fr_tls_conf_t *conf, int fd)
{
	int		ret;
	int		verify_mode;
	tls_session_t	*session = NULL;
	REQUEST		*request;

	session = talloc_zero(ctx, tls_session_t);
	if (!session) return NULL;

	talloc_set_destructor(session, _tls_session_free);

	session->ctx = conf->ctx[(conf->ctx_count == 1) ? 0 : conf->ctx_next++ % conf->ctx_count];	/* mutex not needed */
	rad_assert(session->ctx);

	SSL_CTX_set_mode(session->ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_AUTO_RETRY);

	session->ssl = SSL_new(session->ctx);
	if (!session->ssl) {
		talloc_free(session);
		return NULL;
	}

	request = request_alloc(session);
	SSL_set_ex_data(session->ssl, FR_TLS_EX_INDEX_REQUEST, (void *)request);

	/*
	 *	Add the message callback to identify what type of
	 *	message/handshake is passed
	 */
	SSL_set_msg_callback(session->ssl, tls_session_msg_cb);
	SSL_set_msg_callback_arg(session->ssl, session);
	SSL_set_info_callback(session->ssl, tls_session_info_cb);

	/*
	 *	Always verify the peer certificate.
	 */
	DEBUG2("Requiring Server certificate");
	verify_mode = SSL_VERIFY_PEER;
	verify_mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
	SSL_set_verify(session->ssl, verify_mode, tls_validate_cert_cb);

	SSL_set_ex_data(session->ssl, FR_TLS_EX_INDEX_CONF, (void *)conf);
	SSL_set_ex_data(session->ssl, FR_TLS_EX_INDEX_TLS_SESSION, (void *)session);
	SSL_set_fd(session->ssl, fd);

	ret = SSL_connect(session->ssl);
	if (ret <= 0) {
		tls_log_io_error(NULL, session, ret, "Failed in SSL_connect");
		talloc_free(session);

		return NULL;
	}

	session->mtu = conf->fragment_size;

	return session;
}

/** Create a new server TLS session
 *
 * Configures a new server TLS session, configuring options, setting callbacks etc...
 *
 * @param ctx to alloc session data in. Should usually be NULL unless the lifetime of the
 *	session is tied to another talloc'd object.
 * @param conf to use to configure the tls session.
 * @param request The current #REQUEST.
 * @param client_cert Whether to require a client_cert.
 * @return
 *	- A new session on success.
 *	- NULL on error.
 */
tls_session_t *tls_session_init_server(TALLOC_CTX *ctx, fr_tls_conf_t *conf, REQUEST *request, bool client_cert)
{
	tls_session_t	*session = NULL;
	SSL		*new_tls = NULL;
	int		verify_mode = 0;
	VALUE_PAIR	*vp;
	SSL_CTX		*ssl_ctx;

	rad_assert(request != NULL);
	rad_assert(conf->ctx_count > 0);

	RDEBUG2("Initiating new EAP-TLS session");

	ssl_ctx = conf->ctx[(conf->ctx_count == 1) ? 0 : conf->ctx_next++ % conf->ctx_count];	/* mutex not needed */
	rad_assert(ssl_ctx);

	new_tls = SSL_new(ssl_ctx);
	if (new_tls == NULL) {
		tls_log_error(request, "Error creating new TLS session");
		return NULL;
	}

	/* We use the SSL's "app_data" to indicate a call-back */
	SSL_set_app_data(new_tls, NULL);

	session = talloc_zero(ctx, tls_session_t);
	if (session == NULL) {
		RERROR("Error allocating memory for TLS session");
		SSL_free(new_tls);

		return NULL;
	}
	session_init(session);
	session->ctx = ssl_ctx;
	session->ssl = new_tls;

	talloc_set_destructor(session, _tls_session_free);

	/*
	 *	Initialize callbacks
	 */
	session->record_init = record_init;
	session->record_close = record_close;
	session->record_from_buff = record_from_buff;
	session->record_to_buff = record_to_buff;

	/*
	 *	Create & hook the BIOs to handle the dirty side of the
	 *	SSL.  This is *very important* as we want to handle
	 *	the transmission part.  Now the only IO interface
	 *	that SSL is aware of, is our defined BIO buffers.
	 *
	 *	This means that all SSL IO is done to/from memory,
	 *	and we can update those BIOs from the packets we've
	 *	received.
	 */
	session->into_ssl = BIO_new(BIO_s_mem());
	session->from_ssl = BIO_new(BIO_s_mem());
	SSL_set_bio(session->ssl, session->into_ssl, session->from_ssl);

	/*
	 *	Add the message callback to identify what type of
	 *	message/handshake is passed
	 */
	SSL_set_msg_callback(new_tls, tls_session_msg_cb);
	SSL_set_msg_callback_arg(new_tls, session);
	SSL_set_info_callback(new_tls, tls_session_info_cb);

#ifdef WITH_TLS_SESSION_CERTS
	/*
	 *	Add the session certificate to the session.
	 */
	vp = fr_pair_find_by_num(request->state, 0, PW_TLS_SESSION_CERT_FILE, TAG_ANY);
	if (vp) {
		RDEBUG2("Loading TLS session certificate \"%s\"", vp->vp_strvalue);

		if (SSL_use_certificate_file(session->ssl, vp->vp_strvalue, SSL_FILETYPE_PEM) != 1) {
			tls_log_error(request, "Failed loading TLS session certificate",
				      vp->vp_strvalue);
			talloc_free(session);
			return NULL;
		}

		if (SSL_use_PrivateKey_file(session->ssl, vp->vp_strvalue, SSL_FILETYPE_PEM) != 1) {
			tls_log_error(request, "Failed loading TLS session certificate",
				      vp->vp_strvalue);
			talloc_free(session);
			return NULL;
		}

		if (SSL_check_private_key(session->ssl) != 1) {
			tls_log_error(request, "Failed validating TLS session certificate",
				      vp->vp_strvalue);
			talloc_free(session);
			return NULL;
		}
	}
#endif

	/*
	 *	In Server mode we only accept.
	 */
	SSL_set_accept_state(session->ssl);

	/*
	 *	Verify the peer certificate, if asked.
	 */
	if (client_cert) {
		RDEBUG2("Setting verify mode to require certificate from client");
		verify_mode = SSL_VERIFY_PEER;
		verify_mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
		verify_mode |= SSL_VERIFY_CLIENT_ONCE;
	}
	SSL_set_verify(session->ssl, verify_mode, tls_validate_cert_cb);

	SSL_set_ex_data(session->ssl, FR_TLS_EX_INDEX_CONF, (void *)conf);
	SSL_set_ex_data(session->ssl, FR_TLS_EX_INDEX_TLS_SESSION, (void *)session);
	session->length_flag = conf->include_length;

	/*
	 *	We use default fragment size, unless the Framed-MTU
	 *	tells us it's too big.  Note that we do NOT account
	 *	for the EAP-TLS headers if conf->fragment_size is
	 *	large, because that config item looks to be confusing.
	 *
	 *	i.e. it should REALLY be called MTU, and the code here
	 *	should figure out what that means for TLS fragment size.
	 *	asking the administrator to know the internal details
	 *	of EAP-TLS in order to calculate fragment sizes is
	 *	just too much.
	 */
	session->mtu = conf->fragment_size;
	vp = fr_pair_find_by_num(request->packet->vps, 0, PW_FRAMED_MTU, TAG_ANY);
	if (vp && (vp->vp_integer > 100) && (vp->vp_integer < session->mtu)) {
		RDEBUG2("Setting fragment_len from &Framed-MTU");
		session->mtu = vp->vp_integer;
	}

	if (conf->session_cache_server) session->allow_session_resumption = true; /* otherwise it's false */

	return session;
}
#endif /* WITH_TLS */
