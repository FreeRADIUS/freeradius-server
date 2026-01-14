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
 * @copyright 2001 hereUare Communications, Inc. (raghud@hereuare.com)
 * @copyright 2003 Alan DeKok (aland@freeradius.org)
 * @copyright 2006-2016 The FreeRADIUS server project
 */
#ifdef WITH_TLS
#define LOG_PREFIX "tls"

#include <freeradius-devel/server/pair.h>
#include <freeradius-devel/server/log.h>

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/base16.h>
#include <freeradius-devel/util/skip.h>
#include <freeradius-devel/util/pair_legacy.h>

#include <freeradius-devel/protocol/freeradius/freeradius.internal.h>

#include <freeradius-devel/unlang/call.h>
#include <freeradius-devel/unlang/subrequest.h>
#include <freeradius-devel/unlang/interpret.h>

#include <sys/stat.h>
#include <ctype.h>
#include <fcntl.h>

#include "attrs.h"
#include "base.h"
#include "log.h"

#include <openssl/x509v3.h>
#include <openssl/ssl.h>

static char const *tls_version_str[] = {
	[SSL2_VERSION]				= "SSL 2.0",
	[SSL3_VERSION]				= "SSL 3.0",
	[TLS1_VERSION]				= "TLS 1.0",
#ifdef TLS1_1_VERSION
	[TLS1_1_VERSION]			= "TLS 1.1",
#endif
#ifdef TLS1_2_VERSION
	[TLS1_2_VERSION]			= "TLS 1.2",
#endif
#ifdef TLS1_3_VERSION
	[TLS1_3_VERSION]			= "TLS 1.3",
#endif
#ifdef TLS1_4_VERSION
	[TLS1_4_VERSION]			= "TLS 1.4",
#endif
};

static char const *tls_content_type_str[] = {
	[SSL3_RT_CHANGE_CIPHER_SPEC]		= "change_cipher_spec",
	[SSL3_RT_ALERT]				= "alert",
	[SSL3_RT_HANDSHAKE]			= "handshake",
	[SSL3_RT_APPLICATION_DATA]		= "application_data",
#ifdef SSL3_RT_HEADER
	[SSL3_RT_HEADER]			= "header",
#endif
#ifdef SSL3_RT_INNER_CONTENT_TYPE
	[SSL3_RT_INNER_CONTENT_TYPE]		= "inner_content_type",
#endif
};

static char const *tls_alert_description_str[] = {
	[SSL3_AD_CLOSE_NOTIFY]			= "close_notify",
	[SSL3_AD_UNEXPECTED_MESSAGE]		= "unexpected_message",
	[SSL3_AD_BAD_RECORD_MAC]		= "bad_record_mac",
	[TLS1_AD_DECRYPTION_FAILED]		= "decryption_failed",
	[TLS1_AD_RECORD_OVERFLOW]		= "record_overflow",
	[SSL3_AD_DECOMPRESSION_FAILURE]		= "decompression_failure",
	[SSL3_AD_HANDSHAKE_FAILURE]		= "handshake_failure",
	[SSL3_AD_BAD_CERTIFICATE]		= "bad_certificate",
	[SSL3_AD_UNSUPPORTED_CERTIFICATE]	= "unsupported_certificate",
	[SSL3_AD_CERTIFICATE_REVOKED]		= "certificate_revoked",
	[SSL3_AD_CERTIFICATE_EXPIRED]		= "certificate_expired",
	[SSL3_AD_CERTIFICATE_UNKNOWN]		= "certificate_unknown",
	[SSL3_AD_ILLEGAL_PARAMETER]		= "illegal_parameter",
	[TLS1_AD_UNKNOWN_CA]			= "unknown_ca",
	[TLS1_AD_ACCESS_DENIED]			= "access_denied",
	[TLS1_AD_DECODE_ERROR]			= "decode_error",
	[TLS1_AD_DECRYPT_ERROR]			= "decrypt_error",
	[TLS1_AD_EXPORT_RESTRICTION]		= "export_restriction",
	[TLS1_AD_PROTOCOL_VERSION]		= "protocol_version",
	[TLS1_AD_INSUFFICIENT_SECURITY]		= "insufficient_security",
	[TLS1_AD_INTERNAL_ERROR]		= "internal_error",
	[TLS1_AD_USER_CANCELLED]		= "user_cancelled",
	[TLS1_AD_NO_RENEGOTIATION]		= "no_renegotiation",
#ifdef TLS13_AD_MISSING_EXTENSION
	[TLS13_AD_MISSING_EXTENSION]		= "missing_extension",
#endif
#ifdef TLS13_AD_CERTIFICATE_REQUIRED
	[TLS13_AD_CERTIFICATE_REQUIRED]		= "certificate_required",
#endif
#ifdef TLS1_AD_UNSUPPORTED_EXTENSION
	[TLS1_AD_UNSUPPORTED_EXTENSION]		= "unsupported_extension",
#endif
#ifdef TLS1_AD_CERTIFICATE_UNOBTAINABLE
	[TLS1_AD_CERTIFICATE_UNOBTAINABLE]	= "certificate_unobtainable",
#endif
#ifdef  TLS1_AD_UNRECOGNIZED_NAME
	[TLS1_AD_UNRECOGNIZED_NAME]		= "unrecognised_name",
#endif
#ifdef TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE
	[TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE] = "bad_certificate_status_response",
#endif
#ifdef TLS1_AD_BAD_CERTIFICATE_HASH_VALUE
	[TLS1_AD_BAD_CERTIFICATE_HASH_VALUE]	= "bad_certificate_hash_value",
#endif
#ifdef TLS1_AD_UNKNOWN_PSK_IDENTITY
	[TLS1_AD_UNKNOWN_PSK_IDENTITY]		= "unknown_psk_identity",
#endif
#ifdef TLS1_AD_NO_APPLICATION_PROTOCOL
	[TLS1_AD_NO_APPLICATION_PROTOCOL]	= "no_application_protocol",
#endif
};

static char const *tls_handshake_type_str[] = {
	[SSL3_MT_HELLO_REQUEST]			= "hello_request",
	[SSL3_MT_CLIENT_HELLO]			= "client_hello",
	[SSL3_MT_SERVER_HELLO]			= "server_hello",
#ifdef SSL3_MT_NEWSESSION_TICKET
	[SSL3_MT_NEWSESSION_TICKET]		= "new_session_ticket",
#endif
#ifdef SSL3_MT_END_OF_EARLY_DATA
	[SSL3_MT_END_OF_EARLY_DATA]		= "end_of_early_data",
#endif
#ifdef SSL3_MT_ENCRYPTED_EXTENSIONS
	[SSL3_MT_ENCRYPTED_EXTENSIONS]		= "encrypted_extensions",
#endif
	[SSL3_MT_CERTIFICATE]			= "certificate",
	[SSL3_MT_SERVER_KEY_EXCHANGE]		= "server_key_exchange",
	[SSL3_MT_CERTIFICATE_REQUEST]		= "certificate_request",
	[SSL3_MT_SERVER_DONE]			= "server_hello_done",
	[SSL3_MT_CERTIFICATE_VERIFY]		= "certificate_verify",
	[SSL3_MT_CLIENT_KEY_EXCHANGE]		= "client_key_exchange",
	[SSL3_MT_FINISHED]			= "finished",
#ifdef SSL3_MT_CERTIFICATE_URL
	[SSL3_MT_CERTIFICATE_URL]		= "certificate_url",
#endif
#ifdef SSL3_MT_CERTIFICATE_STATUS
	[SSL3_MT_CERTIFICATE_STATUS]		= "certificate_status",
#endif
#ifdef SSL3_MT_SUPPLEMENTAL_DATA
	[SSL3_MT_SUPPLEMENTAL_DATA]		= "supplemental_data",
#endif
#ifdef SSL3_MT_KEY_UPDATE
	[SSL3_MT_KEY_UPDATE]			= "key_update",
#endif
#ifdef SSL3_MT_NEXT_PROTO
	[SSL3_MT_NEXT_PROTO]			= "next_proto",
#endif
#ifdef SSL3_MT_MESSAGE_HASH
	[SSL3_MT_MESSAGE_HASH]			= "message_hash",
#endif
#ifdef DTLS1_MT_HELLO_VERIFY_REQUEST
	[DTLS1_MT_HELLO_VERIFY_REQUEST]		= "hello_verify_request",
#endif
#ifdef SSL3_MT_CHANGE_CIPHER_SPEC
	[SSL3_MT_CHANGE_CIPHER_SPEC]		= "change_cipher_spec",
#endif
};

/** Clear a record buffer
 *
 * @param record buffer to clear.
 */
inline static void record_init(fr_tls_record_t *record)
{
	record->used = 0;
}

/** Destroy a record buffer
 *
 * @param record buffer to destroy clear.
 */
inline static void record_close(fr_tls_record_t *record)
{
	record->used = 0;
}

/** Copy data to the intermediate buffer, before we send it somewhere
 *
 * @param[in] record	buffer to write to.
 * @param[in] in	data to write.
 * @param[in] inlen	Length of data to write.
 * @return the amount of data written to the record buffer.
 */
inline static unsigned int record_from_buff(fr_tls_record_t *record, void const *in, unsigned int inlen)
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
 * @param[in] record	buffer to read from.
 * @param[out] out	where to write data from record buffer.
 * @param[in] outlen	The length of the output buffer.
 * @return the amount of data written to the output buffer.
 */
inline static unsigned int record_to_buff(fr_tls_record_t *record, void *out, unsigned int outlen)
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
 * @param[out] buf	Where to write the password to.
 * @param[in] size	The length of buf.
 * @param[in] rwflag
 *			- 0 if password used for decryption.
 *			- 1 if password used for encryption.
 * @param[in] u	The static password.
 * @return
 *	- 0 on error.
 *	- >0 on success (the length of the password).
 */
int fr_tls_session_password_cb(char *buf, int size, int rwflag UNUSED, void *u)
{
	size_t len;

	/*
	 *	We do this instead of not registering the callback
	 *	to ensure OpenSSL doesn't try and read a password
	 *	from stdin (causes server to block).
	 */
	if (!u) {
		ERROR("Private key encrypted but no private_key_password configured");
		return 0;
	}

	len = strlcpy(buf, (char *)u, size);
	if (len > (size_t)size) {
		ERROR("Password too long.  Maximum length is %i bytes", size - 1);
		return 0;
	}

	return len;
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
		if (isalpha((uint8_t) c) || isdigit((uint8_t) c) || isspace((uint8_t) c) ||
		    (c == '@') || (c == '-') || (c == '_') || (c == '.')) {
			continue;
		}

		return false;
	}

	return true;
}

/** Determine the PSK to use for an outgoing connection
 *
 * @param[in] ssl		session.
 * @param[in] identity		The identity of the PSK to search for.
 * @param[out] psk		Where to write the PSK we found (if any).
 * @param[in] max_psk_len	The length of the buffer provided for PSK.
 * @return
 *	- 0 if no PSK matching identity was found.
 *	- >0 if a PSK matching identity was found (the length of bytes written to psk).
 */
unsigned int fr_tls_session_psk_client_cb(SSL *ssl, UNUSED char const *hint,
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

	return fr_base16_decode(NULL,
			  &FR_DBUFF_TMP((uint8_t *)psk, (size_t)max_psk_len),
			  &FR_SBUFF_IN(conf->psk_password, (size_t)psk_len), false);
}

/** Determine the PSK to use for an incoming connection
 *
 * @param[in] ssl		session.
 * @param[in] identity		The identity of the PSK to search for.
 * @param[out] psk		Where to write the PSK we found (if any).
 * @param[in] max_psk_len	The length of the buffer provided for PSK.
 * @return
 *	- 0 if no PSK matching identity was found.
 *	- >0 if a PSK matching identity was found (the length of bytes written to psk).
 */
unsigned int fr_tls_session_psk_server_cb(SSL *ssl, const char *identity,
					  unsigned char *psk, unsigned int max_psk_len)
{
	size_t		psk_len = 0;
	fr_tls_conf_t	*conf;
	request_t	*request;

	conf = (fr_tls_conf_t *)SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_CONF);
	if (!conf) return 0;

	request = fr_tls_session_request(ssl);
	if (request && conf->psk_query) {
		size_t hex_len;
		fr_pair_t *vp;
		char buffer[2 * PSK_MAX_PSK_LEN + 4]; /* allow for too-long keys */

		/*
		 *	The passed identity is weird.  Deny it.
		 */
		if (!session_psk_identity_is_safe(identity)) {
			RWDEBUG("Invalid characters in PSK identity %s", identity);
			return 0;
		}

		MEM(pair_update_request(&vp, attr_tls_psk_identity) >= 0);
		if (fr_pair_value_from_str(vp, identity, strlen(identity), NULL, true) < 0) {
			RPWDEBUG2("Failed parsing TLS PSK Identity");
			talloc_free(vp);
			return 0;
		}

		hex_len = xlat_eval(buffer, sizeof(buffer), request, conf->psk_query, NULL, NULL);
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
		return fr_base16_decode(NULL,
				  &FR_DBUFF_TMP((uint8_t *)psk, (size_t)max_psk_len),
				  &FR_SBUFF_IN(buffer, hex_len), false);
	}

	if (!conf->psk_identity) {
		DEBUG("No static PSK identity set.  Rejecting the user");
		return 0;
	}

	/*
	 *	No request_t, or no dynamic query.  Just look for a
	 *	static identity.
	 */
	if (strcmp(identity, conf->psk_identity) != 0) {
		ERROR("Supplied PSK identity %s does not match configuration.  Rejecting.",
		      identity);
		return 0;
	}

	psk_len = strlen(conf->psk_password);
	if (psk_len > (2 * max_psk_len)) return 0;

	return fr_base16_decode(NULL,
			  &FR_DBUFF_TMP((uint8_t *)psk, (size_t)max_psk_len),
			  &FR_SBUFF_IN(conf->psk_password, psk_len), false);
}
#endif /* PSK_MAX_IDENTITY_LEN */

DIAG_OFF(DIAG_UNKNOWN_PRAGMAS)
DIAG_OFF(used-but-marked-unused)	/* Fix spurious warnings for sk_ macros */
/** Record session state changes
 *
 * Called by OpenSSL whenever the session state changes, an alert is received or an error occurs.
 *
 * @param[in] ssl	session.
 * @param[in] where	Which context the callback is being called in.
 *			See https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set_info_callback.html
 *			for additional info.
 * @param[in] ret	0 if an error occurred, or the alert type if an alert was received.
 */
void fr_tls_session_info_cb(SSL const *ssl, int where, int ret)
{
	char const	*role, *state;
	request_t	*request = SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_REQUEST);

	if ((where & ~SSL_ST_MASK) & SSL_ST_CONNECT) {
		role = "Client ";
	} else if (((where & ~SSL_ST_MASK)) & SSL_ST_ACCEPT) {
		role = "Server ";
	} else {
		role = "";
	}

	state = SSL_state_string_long(ssl);
	state = state ? state : "<INVALID>";

	if ((where & SSL_CB_LOOP) || (where & SSL_CB_HANDSHAKE_START) || (where & SSL_CB_HANDSHAKE_DONE)) {
		if (ROPTIONAL_ENABLED(RDEBUG_ENABLED3, DEBUG_ENABLED3)) {
			char const *abbrv = SSL_state_string(ssl);
			size_t len;

			/*
			 *	Trim crappy OpenSSL state strings...
			 */
			len = strlen(abbrv);
			if ((len > 1) && (abbrv[len - 1] == ' ')) len--;

			ROPTIONAL(RDEBUG3, DEBUG3, "Handshake state [%.*s] - %s%s", (int)len, abbrv, role, state);

#ifdef OPENSSL_NO_SSL_TRACE
	        	{
				STACK_OF(SSL_CIPHER) *server_ciphers;
				STACK_OF(SSL_CIPHER) *client_ciphers;

				/*
				 *	After a ClientHello, list all the proposed ciphers
				 *	from the client.
				 *
				 *	Only do this if we don't have SSL_trace() as
				 *	SSL_trace() prints this information and we don't
				 *      want to duplicate it.
				 */
				if (SSL_get_state(ssl) == TLS_ST_SR_CLNT_HELLO &&
				    (client_ciphers = SSL_get_client_ciphers(ssl))) {
					int i;
					int num_ciphers;
					const SSL_CIPHER *this_cipher;

					server_ciphers = SSL_get_ciphers(ssl);
					/*
					 *	These are printed on startup, so not usually
					 *      required.
					 */
					ROPTIONAL(RDEBUG4, DEBUG4, "Our preferred ciphers (by priority)");
					if (ROPTIONAL_ENABLED(RDEBUG_ENABLED4, DEBUG_ENABLED4)) {
						if (request) RINDENT();
						num_ciphers = sk_SSL_CIPHER_num(server_ciphers);
						for (i = 0; i < num_ciphers; i++) {
							this_cipher = sk_SSL_CIPHER_value(server_ciphers, i);
							ROPTIONAL(RDEBUG4, DEBUG4, "[%i] %s", i, SSL_CIPHER_get_name(this_cipher));
						}
						if (request) REXDENT();
					}

					/*
					 *	Print information about the client's
					 *      handshake message.
					 */
					if (ROPTIONAL_ENABLED(RDEBUG_ENABLED3, DEBUG_ENABLED3)) {
						ROPTIONAL(RDEBUG3, DEBUG3, "Client's preferred ciphers (by priority)");
						if (request) RINDENT();
						num_ciphers = sk_SSL_CIPHER_num(client_ciphers);
						for (i = 0; i < num_ciphers; i++) {
							this_cipher = sk_SSL_CIPHER_value(client_ciphers, i);
							ROPTIONAL(RDEBUG3, DEBUG3, "[%i] %s", i, SSL_CIPHER_get_name(this_cipher));
						}
						if (request) REXDENT();
					}
				}
			}
#  endif
		} else {
			ROPTIONAL(RDEBUG2, DEBUG2, "Handshake state - %s%s (%u)", role, state, SSL_get_state(ssl));
		}
		return;
	}

	if (where & SSL_CB_ALERT) {
		if ((ret & 0xff) == SSL_AD_CLOSE_NOTIFY) return;

		/*
		 *	We got an alert...
		 */
		if (where & SSL_CB_READ) {
			fr_pair_t *vp;

			ROPTIONAL(REDEBUG, ERROR, "Client sent %s TLS alert (%i) - %s", SSL_alert_type_string_long(ret),
			          ret & 0xff, SSL_alert_desc_string_long(ret));

			/*
			 *	Offer helpful advice... Should be expanded.
			 */
			switch (ret & 0xff) {
			case TLS1_AD_UNKNOWN_CA:
				REDEBUG("Verify the client has a copy of the server's Certificate "
					"Authority (CA) installed, and trusts that CA");
				break;

			default:
				break;
			}

			MEM(pair_update_request(&vp, attr_tls_client_error_code) >= 0);
			vp->vp_uint8 = ret & 0xff;
			ROPTIONAL(RDEBUG2, DEBUG2, "TLS-Client-Error-Code := %pV", &vp->data);
		/*
		 *	We're sending the client an alert.
		 */
		} else {
			ROPTIONAL(REDEBUG, ERROR, "Sending client %s TLS alert (%i) - %s",
				  SSL_alert_type_string_long(ret), ret & 0xff, SSL_alert_desc_string_long(ret));

			/*
			 *	Offer helpful advice... Should be expanded.
			 */
			switch (ret & 0xff) {
			case TLS1_AD_PROTOCOL_VERSION:
				ROPTIONAL(REDEBUG, ERROR, "Client requested a TLS protocol version that is not "
					  "enabled or not supported. Upgrade FreeRADIUS + OpenSSL to their latest "
					  "versions and/or adjust 'tls_max_version'/'tls_min_version' if you want "
					  "authentication to succeed");
				break;

			default:
				break;
			}
		}
		return;
	}

	if (where & SSL_CB_EXIT) {
		if (ret == 0) {
			ROPTIONAL(REDEBUG, ERROR, "Handshake exit state %s%s", role, state);
			return;
		}

		if (ret < 0) {
			if (SSL_want_read(ssl)) {
				RDEBUG2("Need more data from client"); /* State same as previous call, don't print */
				return;
			}
			ROPTIONAL(REDEBUG, ERROR, "Handshake exit state %s%s", role, state);
		}
	}
}
DIAG_ON(used-but-marked-unused)
DIAG_ON(DIAG_UNKNOWN_PRAGMAS)

/** Print a message to the request or global log detailing handshake state
 *
 * @param[in] request	The current #request_t.
 * @param[in] tls_session	The current TLS session.
 */
static void session_msg_log(request_t *request, fr_tls_session_t *tls_session, uint8_t const *data, size_t data_len)
{
	char const	*version, *content_type;
	char const	*str_details1 = NULL;
	char const	*str_details2 = NULL;
	char		unknown_version[32];
	char		unknown_content_type[32];
	char		unknown_alert_level[32];
	char		unknown_alert_description[32];
	char		unknown_handshake_type[32];

	/*
	 *	Don't print this out in the normal course of
	 *	operations.
	 */
	if (!ROPTIONAL_ENABLED(RDEBUG_ENABLED2, DEBUG_ENABLED2)) return;

	if (((size_t)tls_session->info.version >= NUM_ELEMENTS(tls_version_str)) ||
	    !tls_version_str[tls_session->info.version]) {
		snprintf(unknown_version, sizeof(unknown_version), "unknown_tls_version_0x%04x",
			 (unsigned int) tls_session->info.version);
		version = unknown_version;
	} else {
		version = tls_version_str[tls_session->info.version];
	}

	/*
	 *	TLS 1.0, 1.1, 1.2 content types are the same as SSLv3
	 */
	if (((size_t)tls_session->info.content_type >= NUM_ELEMENTS(tls_content_type_str)) ||
	    !tls_content_type_str[tls_session->info.content_type]) {
		snprintf(unknown_content_type, sizeof(unknown_content_type),
			 "unknown_content_type_0x%04x", (unsigned int) tls_session->info.content_type);
		content_type = unknown_content_type;
	} else {
		content_type = tls_content_type_str[tls_session->info.content_type];
	}

	if (tls_session->info.content_type == SSL3_RT_ALERT) {
		if (tls_session->info.record_len == 2) {
			switch (tls_session->info.alert_level) {
			case SSL3_AL_WARNING:
				str_details1 = "warning";
				break;
			case SSL3_AL_FATAL:
				str_details1 = "fatal";
				break;

			default:
				snprintf(unknown_alert_level, sizeof(unknown_alert_level),
					 "unknown_alert_level_0x%04x", tls_session->info.alert_level);
				str_details1 = unknown_alert_level;
				break;
			}

			if (((size_t)tls_session->info.alert_description >= NUM_ELEMENTS(tls_alert_description_str)) ||
			    !tls_alert_description_str[tls_session->info.alert_description]) {
				snprintf(unknown_alert_description, sizeof(unknown_alert_description),
					 "unknown_alert_0x%04x", tls_session->info.alert_description);
				str_details2 = unknown_alert_description;
			} else {
				str_details2 = tls_alert_description_str[tls_session->info.alert_description];
			}
		} else {
			str_details1 = "unknown_alert_level";
			str_details2 = "unknown_alert";
		}
	}

	if ((size_t)tls_session->info.content_type == SSL3_RT_HANDSHAKE) {
		if (tls_session->info.record_len > 0) {
			/*
			 *	Range guard not needed due to size of array
			 *	and underlying type.
			 */
			if (!tls_handshake_type_str[tls_session->info.handshake_type]) {
				snprintf(unknown_handshake_type, sizeof(unknown_handshake_type),
					 "unknown_handshake_type_0x%02x", tls_session->info.handshake_type);
				str_details1 = unknown_handshake_type;
			} else {
				str_details1 = tls_handshake_type_str[tls_session->info.handshake_type];
			}
		}
	}

	snprintf(tls_session->info.info_description, sizeof(tls_session->info.info_description),
		 "%s %s, %s[length %lu]%s%s%s%s",
		 tls_session->info.origin ? ">>> send" : "<<< recv",
		 version,
		 content_type,
		 (unsigned long)tls_session->info.record_len,
		 str_details1 ? ", " : "",
		 str_details1 ? str_details1 : "",
		 str_details2 ? ", " : "",
		 str_details2 ? str_details2 : "");

	/*
	 *	Print out information about the record and print the
	 *	data at higher debug levels.
	 */
	if (ROPTIONAL_ENABLED(RDEBUG_ENABLED4, DEBUG_ENABLED4)) {
		ROPTIONAL(RHEXDUMP4, HEXDUMP4, data, data_len, "%s", tls_session->info.info_description);
	} else {
		ROPTIONAL(RDEBUG2, DEBUG2, "%s", tls_session->info.info_description);
	}
}

/** Record the progression of the TLS handshake
 *
 * This callback is called by OpenSSL whenever a protocol message relating to a handshake is sent
 * or received.
 *
 * This function copies state information from the various arguments into the state->info
 * structure of the #fr_tls_session_t, to allow us to track the progression of the handshake.
 *
 * @param[in] write_p
 *				- 0 when a message has been received.
 *				- 1 when a message has been sent.
 *
 * @param[in] msg_version	The TLS version negotiated, should be one of:
 *				- TLS1_VERSION
 *				- TLS1_1_VERSION
 *				- TLS1_2_VERSION
 *				- TLS1_3_VERSION
 *
 * @param[in] content_type	One of the contentType values defined for TLS:
 *				- SSL3_RT_CHANGE_CIPHER_SPEC (20)
 *				- SSL3_RT_ALERT (21)
 *				- SSL3_RT_HANDSHAKE (22)
 *				- TLS1_RT_HEARTBEAT (24)
 *
 * @param[in] inbuf		The raw protocol message.
 * @param[in] len		Length of the raw protocol message.
 * @param[in] ssl		The SSL session.
 * @param[in] arg		The #fr_tls_session_t holding the SSL session.
 */
void fr_tls_session_msg_cb(int write_p, int msg_version, int content_type,
			   void const *inbuf, size_t len,
			   SSL *ssl, void *arg)
{
	uint8_t const		*buf = inbuf;
	fr_tls_session_t	*tls_session = talloc_get_type_abort(arg, fr_tls_session_t);
	request_t		*request = fr_tls_session_request(tls_session->ssl);

	/*
	 *	Mostly to check for memory corruption...
	 */
	if (!fr_cond_assert(tls_session->ssl = ssl)) {
		ROPTIONAL(REDEBUG, ERROR, "fr_tls_session_t and ssl arg do not match in fr_tls_session_msg_cb");
		tls_session->invalid = true;
		return;
	}

	/*
	 *	As per https://tools.ietf.org/html/rfc7568
	 *
	 *	We explicitly disable SSLv2/v3, hence the asserts.
	 */
#ifdef SSL2_VERSION
	if (!fr_cond_assert(msg_version != SSL2_VERSION)) {
		ROPTIONAL(REDEBUG, ERROR, "Invalid version (SSLv2) in handshake");
		tls_session->invalid = true;
		return;
	}
#endif

#ifdef SSL3_VERSION
	if (!fr_cond_assert(msg_version != SSL3_VERSION)) {
		ROPTIONAL(REDEBUG, ERROR, "Invalid version (SSLv3) in handshake");
		tls_session->invalid = true;
		return;
	}
#endif

	/*
	 *	OpenSSL >= 1.0.2 calls this function with 'pseudo'
	 *	content types.  Which breaks our tracking of
	 *	the SSL Session state.
	 */
	if ((msg_version == 0) && (content_type > UINT8_MAX)) {
		ROPTIONAL(REDEBUG4, DEBUG4, "Ignoring fr_tls_session_msg_cb call with pseudo content type %i, version %i",
		          content_type, msg_version);
		return;
	}

	if ((write_p != 0) && (write_p != 1)) {
		ROPTIONAL(REDEBUG4, DEBUG4, "Ignoring fr_tls_session_msg_cb call with invalid write_p %d", write_p);
		return;
	}

	/*
	 *	0 - received (from peer)
	 *	1 - sending (to peer)
	 */
	tls_session->info.origin = write_p;
	tls_session->info.content_type = content_type;
	tls_session->info.record_len = len;
	tls_session->info.version = msg_version;
	tls_session->info.initialized = true;

	switch (content_type) {
	case SSL3_RT_ALERT:
		tls_session->info.alert_level = buf[0];
		tls_session->info.alert_description = buf[1];
		tls_session->info.handshake_type = 0x00;
		break;

	case SSL3_RT_HANDSHAKE:
		tls_session->info.handshake_type = buf[0];
		tls_session->info.alert_level = 0x00;
		tls_session->info.alert_description = 0x00;
		break;

#ifdef SSL3_RT_HEARTBEAT
	case TLS1_RT_HEARTBEAT:
		uint8_t *p = buf;

		if ((len >= 3) && (p[0] == 1)) {
			size_t payload_len;

			payload_len = fr_nbo_to_uint16(p + 1);
			if ((payload_len + 3) > len) {
				tls_session->invalid = true;
				ROPTIONAL(REDEBUG, ERROR, "OpenSSL Heartbeat attack detected.  Closing connection");
				return;
			}
		}
		break;
#endif
	default:
		break;
	}

	session_msg_log(request, tls_session, (uint8_t const *)inbuf, len);

#ifndef OPENSSL_NO_SSL_TRACE
	if (ROPTIONAL_ENABLED(RDEBUG_ENABLED3, DEBUG_ENABLED3)) {
		SSL_trace(tls_session->info.origin,
			  tls_session->info.version,
			  tls_session->info.content_type,
			  inbuf, len,
			  ssl,
			  request ?
			  	fr_tls_request_log_bio(request, L_DBG, L_DBG_LVL_3) :
				fr_tls_global_log_bio(L_DBG, L_DBG_LVL_3));
	}
#endif
}

/*
 *  By setting the environment variable SSLKEYLOGFILE to a filename keying
 *  material will be exported that you may use with Wireshark to decode any
 *  TLS flows. Please see the following for more details:
 *
 *	https://gitlab.com/wireshark/wireshark/-/wikis/TLS#tls-decryption
 *
 *  An example logging session is (you should delete the file on each run):
 *
 *	rm -f /tmp/sslkey.log; env SSLKEYLOGFILE=/tmp/sslkey.log freeradius -X | tee /tmp/debug
 *
 *  Note that we rely on the OS to check file permissions.  If the
 *  caller can run radiusd, then they can only write to files which
 *  they own.  If radiusd is running as root, then only root can
 *  change the environment variables for radiusd.
 */
void fr_tls_session_keylog_cb(const SSL *ssl, const char *line)
{
	int fd;
	size_t len;
	const char *filename;
	char buffer[64 + 2*SSL3_RANDOM_SIZE + 2*SSL_MAX_MASTER_KEY_LENGTH];

	/*
	 *	Prefer the environment variable definition to the
	 *	configuration file.  This allows for "one-shot"
	 *	dumping of EAP keys when you know you're not using
	 *	RadSec, and you don't want to edit the configuration.
	 */
	filename = getenv("SSLKEYLOGFILE");
	if (!filename) {
		fr_tls_conf_t *conf;

		conf = (fr_tls_conf_t *)SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_CONF);
		if (!conf || !conf->keylog_file || !*conf->keylog_file) return;

		filename = conf->keylog_file;
	}

	/*
	 *	We write all of the data at once.  This is *generally*
	 *	atomic on most systems.
	 */
	len = strlen(line);
	if ((len + 1) > sizeof(buffer)) {
		DEBUG("SSLKEYLOGFILE buffer not large enough, max %lu, required %lu", sizeof(buffer), len + 1);
		return;
	}

	/*
	 *	Add a \n, which means that in order to write() the
	 *	buffer AND the trailing \n, we have to place both
	 *	strings into the same buffer.
	 */
	memcpy(buffer, line, len);
	buffer[len] = '\n';

	fd = open(filename, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		DEBUG("Failed to open file %s: %s", filename, strerror(errno));
		return;
	}

	/*
	 *	This should work in most situations.
	 */
	if (write(fd, buffer, len + 1) < 0) {
		DEBUG("Failed to write to file %s: %s", filename, strerror(errno));
	}

	close(fd);
}

/** Decrypt application data
 *
 * @note Handshake must have completed before this function may be called.
 *
 * Feed data from dirty_in to OpenSSL, and read the clean data into clean_out.
 *
 * @param[in] request		The current #request_t.
 * @param[in] tls_session	The current TLS session.
 * @return
 *	- -1 on error.
 *	- 1 if more fragments are required to fully reassemble the record for decryption.
 *	- 0 if we decrypted a complete record.
 */
int fr_tls_session_recv(request_t *request, fr_tls_session_t *tls_session)
{
	int ret;

	fr_tls_session_request_bind(tls_session->ssl, request);

	if (!SSL_is_init_finished(tls_session->ssl)) {
		REDEBUG("Attempted to read application data before handshake completed");
	error:
		ret = -1;
		goto finish;
	}

	/*
	 *	Decrypt the complete record.
	 */
	if (tls_session->dirty_in.used) {
		ret = BIO_write(tls_session->into_ssl, tls_session->dirty_in.data, tls_session->dirty_in.used);
		if (ret != (int) tls_session->dirty_in.used) {
			record_init(&tls_session->dirty_in);
			REDEBUG("Failed writing %zu bytes to SSL BIO: %d", tls_session->dirty_in.used, ret);
			goto error;
		}

		record_init(&tls_session->dirty_in);
	}

	/*
	 *      Clear the dirty buffer now that we are done with it
	 *      and init the clean_out buffer to store decrypted data
	 */
	record_init(&tls_session->clean_out);

	/*
	 *	Prevent spurious errors on the thread local error
	 *	stack causing SSL_get_error() to return SSL_ERROR_SSL
	 *	instead of what of the SSL_ERROR_WANT_* values.
	 */
	ERR_clear_error();

	/*
	 *      Read (and decrypt) the tunneled data from the
	 *      SSL session, and put it into the decrypted
	 *      data buffer.
	 */
	ret = SSL_read(tls_session->ssl, tls_session->clean_out.data, sizeof(tls_session->clean_out.data));
	if (ret < 0) {
		int code;

		code = SSL_get_error(tls_session->ssl, ret);
		switch (code) {
		case SSL_ERROR_WANT_READ:
			RWDEBUG("Peer indicated record was complete, but OpenSSL returned SSL_WANT_READ. "
				"Attempting to continue");
			ret = 1;
			goto finish;

		case SSL_ERROR_WANT_WRITE:
			REDEBUG("Error in fragmentation logic: SSL_WANT_WRITE");
			goto error;

		case SSL_ERROR_NONE:
			RDEBUG2("No application data received.  Assuming handshake is continuing...");
			ret = 0;
			break;

		default:
			REDEBUG("Error in fragmentation logic");
			fr_tls_log_io_error(request, code, "SSL_read (%s)", __FUNCTION__);
			goto error;
		}
	}

	/*
	 *	Passed all checks, successfully decrypted data
	 */
	tls_session->clean_out.used = ret;
	ret = 0;

	if (RDEBUG_ENABLED3) {
		RHEXDUMP3(tls_session->clean_out.data, tls_session->clean_out.used,
			 "Decrypted TLS application data (%zu bytes)", tls_session->clean_out.used);
	} else {
		RDEBUG2("Decrypted TLS application data (%zu bytes)", tls_session->clean_out.used);
	}
finish:
	fr_tls_session_request_unbind(tls_session->ssl);

	return ret;
}

/** Encrypt application data
 *
 * @note Handshake must have completed before this function may be called.
 *
 * Take cleartext data from clean_in, and feed it to OpenSSL, reading
 * the encrypted data into dirty_out.
 *
 * @param[in] request The current request.
 * @param[in] tls_session The current TLS session.
 * @return
 *	- -1 on failure.
 *	- 0 on success.
 */
int fr_tls_session_send(request_t *request, fr_tls_session_t *tls_session)
{
	int ret = 0;

	fr_tls_session_request_bind(tls_session->ssl, request);

	if (!SSL_is_init_finished(tls_session->ssl)) {
		REDEBUG("Attempted to write application data before handshake completed");
		ret = -1;
		goto finish;
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
	if (tls_session->clean_in.used > 0) {
		/*
		 *	Ensure spurious errors aren't printed
		 */
		ERR_clear_error();

		if (RDEBUG_ENABLED3) {
			RHEXDUMP3(tls_session->clean_in.data, tls_session->clean_in.used,
				 "TLS application data to encrypt (%zu bytes)", tls_session->clean_in.used);
		} else {
			RDEBUG2("TLS application data to encrypt (%zu bytes)", tls_session->clean_in.used);
		}

		ret = SSL_write(tls_session->ssl, tls_session->clean_in.data, tls_session->clean_in.used);
		record_to_buff(&tls_session->clean_in, NULL, ret);

		/* Get the dirty data from Bio to send it */
		ret = BIO_read(tls_session->from_ssl, tls_session->dirty_out.data,
			       sizeof(tls_session->dirty_out.data));
		if (ret > 0) {
			tls_session->dirty_out.used = ret;
			ret = 0;
		} else {
			if (fr_tls_log_io_error(request, SSL_get_error(tls_session->ssl, ret),
						"SSL_write (%s)", __FUNCTION__) < 0) ret = -1;
		}
	}

finish:
	fr_tls_session_request_unbind(tls_session->ssl);

	return ret;
}

/** Instruct fr_tls_session_async_handshake to create a synthesised TLS alert record and send it to the peer
 *
 */
int fr_tls_session_alert(UNUSED request_t *request, fr_tls_session_t *session, uint8_t level, uint8_t description)
{
	if (session->alerts_sent > 3) return -1;		/* Some kind of state machine brokenness */

	/*
	 *	Ignore less severe alerts
	 */
	if (session->pending_alert && (level < session->pending_alert_level)) return 0;

	session->pending_alert = true;
	session->pending_alert_level = level;
	session->pending_alert_description = description;

	return 0;
}

static void fr_tls_session_alert_send(request_t *request, fr_tls_session_t *session)
{
	/*
	 *	Update our internal view of the session
	 */
	session->info.origin = TLS_INFO_ORIGIN_RECORD_SENT;
	session->info.content_type = SSL3_RT_ALERT;
	session->info.alert_level = session->pending_alert_level;
	session->info.alert_description = session->pending_alert_description;

	session->dirty_out.data[0] = session->info.content_type;
	session->dirty_out.data[1] = 3;
	session->dirty_out.data[2] = 1;
	session->dirty_out.data[3] = 0;
	session->dirty_out.data[4] = 2;
	session->dirty_out.data[5] = session->pending_alert_level;
	session->dirty_out.data[6] = session->pending_alert_description;

	session->dirty_out.used = 7;

	session->pending_alert = false;
	session->alerts_sent++;

	SSL_clear(session->ssl);	/* Reset the SSL *, to allow the client to restart the session */

	session_msg_log(request, session, session->dirty_out.data, session->dirty_out.used);
}

/** Process the result of `establish session { ... }`
 *
 * As this is just a logging session, it's result doesn't affect the parent.
 */
static unlang_action_t tls_establish_session_result(UNUSED request_t *request, UNUSED void *uctx)
{
	return UNLANG_ACTION_CALCULATE_RESULT;
}

/** Push an `establish session { ... }` call into the current request, using a subrequest
 *
 * @param[in] request		The current request.
 * @param[in] conf		TLS configuration.
 * @param[in] tls_session	The current TLS session.
 * @return
 *	- UNLANG_ACTION_PUSHED_CHILD on success.
 *      - UNLANG_ACTION_FAIL on failure.
 */
static inline CC_HINT(always_inline)
unlang_action_t tls_establish_session_push(request_t *request, fr_tls_conf_t *conf, fr_tls_session_t *tls_session)
{
	request_t	*child;
	fr_pair_t	*vp;
	unlang_action_t	ua;
	uint8_t const	*session_id;
	unsigned int	len;

	MEM(child = unlang_subrequest_alloc(request, dict_tls));
	request = child;

	/*
	 *	Setup the child request for reporting session
	 */
	MEM(pair_prepend_request(&vp, attr_tls_packet_type) >= 0);
	vp->vp_uint32 = enum_tls_packet_type_establish_session->vb_uint32;

	session_id = SSL_SESSION_get_id(tls_session->session, &len);
	if (session_id && (len > 0)) {
		MEM(pair_append_request(&vp, attr_tls_session_id) >= 0);
		fr_pair_value_memdup(vp, session_id, len, false);
	}

	/*
	 *	Allocate a child, and set it up to call
	 *      the TLS virtual server.
	 */
	ua = fr_tls_call_push(child, tls_establish_session_result, conf, tls_session, false);
	if (ua < 0) {
		talloc_free(child);
		return UNLANG_ACTION_FAIL;
	}

	return ua;
}

/** Finish off a handshake round, possibly adding attributes to the request
 *
 */
static unlang_action_t tls_session_async_handshake_done_round(request_t *request, void *uctx)
{
	fr_tls_session_t	*tls_session = talloc_get_type_abort(uctx, fr_tls_session_t);
	int			ret;

	RDEBUG3("entered state %s", __FUNCTION__);

	/*
	 *	This only occurs once per session, where calling
	 *	SSL_read updates the state of the SSL session, setting
	 *	this flag to true.
	 *
	 *	Callbacks provide enough info so we don't need to
	 *	print debug statements when the handshake is in other
	 *	states.
	 */
	if (SSL_is_init_finished(tls_session->ssl)) {
		SSL_CIPHER const	*cipher;
		fr_pair_t		*vp;
		char const		*version;

		char cipher_desc[256], cipher_desc_clean[256];
		char *p = cipher_desc, *q = cipher_desc_clean;

		cipher = SSL_get_current_cipher(tls_session->ssl);
		SSL_CIPHER_description(cipher, cipher_desc, sizeof(cipher_desc));

		/*
		 *	Cleanup the output from OpenSSL
		 *	Seems to print info in a tabular format.
		 */
		while (*p != '\0') {
			if (isspace((uint8_t) *p)) {
				*q++ = *p;
				fr_skip_whitespace(p);
				continue;
			}
			*q++ = *p++;
		}
		*q = '\0';

		RDEBUG2("Cipher suite: %s", cipher_desc_clean);

		RDEBUG2("Adding TLS session information to request");
		RINDENT();
		MEM(pair_update_session_state(&vp, attr_tls_session_cipher_suite) >= 0);
		fr_pair_value_strdup(vp,  SSL_CIPHER_get_name(cipher), false);
		RDEBUG2("session-state.%pP", vp);

		if (((size_t)tls_session->info.version >= NUM_ELEMENTS(tls_version_str)) ||
		    !tls_version_str[tls_session->info.version]) {
			version = "UNKNOWN";
		} else {
			version = tls_version_str[tls_session->info.version];
		}

		MEM(pair_update_session_state(&vp, attr_tls_session_version) >= 0);
		fr_pair_value_strdup(vp, version, false);
		RDEBUG2("session-state.%pP", vp);
		REXDENT();

		/*
		 *	Cache the SSL_SESSION pointer.
		 *
		 *	Which contains all the data we need for session resumption.
		 */
		if (!tls_session->session) {
			tls_session->session = SSL_get_session(tls_session->ssl);
			if (!tls_session->session) {
				REDEBUG("Failed getting TLS session");
			error:
				tls_session->result = FR_TLS_RESULT_ERROR;
				fr_tls_session_request_unbind(tls_session->ssl);
				return UNLANG_ACTION_CALCULATE_RESULT;
			}
		}

		if (RDEBUG_ENABLED3) {
			if (SSL_SESSION_print(fr_tls_request_log_bio(request, L_DBG, L_DBG_LVL_3),
					      tls_session->session) != 1) {
			} else {
				RDEBUG3("Failed retrieving session data");
			}
		}

		/*
		 *	Session was resumed, add attribute to mark it as such.
		 */
		if (SSL_session_reused(tls_session->ssl)) {
			/*
			 *	Mark the request as resumed.
			 */
			MEM(pair_update_request(&vp, attr_session_resumed) >= 0);
			vp->vp_bool = true;
		}
	}

	/*
	 *	Get data to pack and send back to the TLS peer.
	 */
	ret = BIO_ctrl_pending(tls_session->from_ssl);
	if (ret > 0) {
		ret = BIO_read(tls_session->from_ssl, tls_session->dirty_out.data,
			       sizeof(tls_session->dirty_out.data));
		if (ret > 0) {
			tls_session->dirty_out.used = ret;
		} else if (BIO_should_retry(tls_session->from_ssl)) {
			record_init(&tls_session->dirty_in);
			RDEBUG2("Asking for more data in tunnel");

		} else {
			fr_tls_log(NULL, NULL);
			record_init(&tls_session->dirty_in);
			goto error;
		}
	} else {
		/* Its clean application data, do whatever we want */
		record_init(&tls_session->clean_out);
	}

	/*
	 *	Trash the current data in dirty_out, and synthesize
	 *	a TLS error record.
	 *
	 *	OpensSL annoyingly provides no mechanism for us to
	 *	send alerts, and we need to send alerts as part of
	 *	RFC 5216, so this is our only option.
	 */
	if (tls_session->pending_alert) fr_tls_session_alert_send(request, tls_session);

	/* We are done with dirty_in, reinitialize it */
	record_init(&tls_session->dirty_in);

	tls_session->result = FR_TLS_RESULT_SUCCESS;
	fr_tls_session_request_unbind(tls_session->ssl);
	if (SSL_is_init_finished(tls_session->ssl)) {
		fr_tls_conf_t	*conf = fr_tls_session_conf(tls_session->ssl);
		if (conf->establish_session) return tls_establish_session_push(request, conf, tls_session);
	}
	return UNLANG_ACTION_CALCULATE_RESULT;
}

/** Try very hard to get the SSL * into a consistent state where it's not yielded
 *
 * ...because if it's yielded, we'll probably leak thread contexts and all kinds of memory.
 *
 * @param[in] request	being cancelled.
 * @param[in] action	we're being signalled with.
 * @param[in] uctx	the SSL * to cancel.
 */
static void tls_session_async_handshake_signal(UNUSED request_t *request, UNUSED fr_signal_t action, void *uctx)
{
	fr_tls_session_t	*tls_session = talloc_get_type_abort(uctx, fr_tls_session_t);
	int			ret;

	/*
	 *	We might want to set can_pause = false here
	 *	but that would trigger asserts in the
	 *	cache code.
	 */

	/*
	 *	If SSL_get_error returns SSL_ERROR_WANT_ASYNC
	 *	it means we're yielded in the middle of a
	 *      callback.
	 *
	 *	Keep calling SSL_read() in a loop until we
	 *	no longer get SSL_ERROR_WANT_ASYNC, then
	 *	shut it down so it's in a consistent state.
	 *
	 *	It'll get freed later when the request is
	 *	freed.
	 */
	for (ret = tls_session->last_ret;
	     SSL_get_error(tls_session->ssl, ret) == SSL_ERROR_WANT_ASYNC;
	     ret = SSL_read(tls_session->ssl, tls_session->clean_out.data + tls_session->clean_out.used,
        		    sizeof(tls_session->clean_out.data) - tls_session->clean_out.used));

	/*
	 *	Unbind the cancelled request from the SSL *
	 */
	fr_tls_session_request_unbind(tls_session->ssl);
}

/** Call SSL_read() to continue the TLS state machine
 *
 * This function may be called multiple times, once after every asynchronous request.
 *
 * @param[in] request		The current request.
 * @param[in] uctx		#fr_tls_session_t to continue.
 * @return
 *	- UNLANG_ACTION_CALCULATE_RESULT - We're done with this round.
 *	- UNLANG_ACTION_PUSHED_CHILD - Need to perform more asynchronous actions.
 */
static unlang_action_t tls_session_async_handshake_cont(request_t *request, void *uctx)
{
	fr_tls_session_t	*tls_session = talloc_get_type_abort(uctx, fr_tls_session_t);
	int			err;

	RDEBUG3("(re-)entered state %s", __FUNCTION__);

	/*
	 *	Clear OpenSSL's thread local error stack.
	 *
	 *	Why do we need to do this here?  Although SSL_get_error
	 *	takes an `SSL *`, which would make you _think_ it was
	 *	operating on the error stack for that SSL, it will also
	 *	return SSL_ERROR_SSL if there are any errors in the stack.
	 *
	 *	When operating normally SSL_read() can return < 0, to
	 *	indicate it wants more data, or that we need to perform
	 *	asynchronous processing.
	 *
	 *	If spurious errors have been left on the thread local
	 *	stack they MUST be cleared before we can call SSL_get_error
	 *	otherwise stale errors mask the async notifications
	 *	and cause random handshake failures.
	 */
	ERR_clear_error();

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
	tls_session->can_pause = true;
	tls_session->last_ret = SSL_read(tls_session->ssl, tls_session->clean_out.data + tls_session->clean_out.used,
					 sizeof(tls_session->clean_out.data) - tls_session->clean_out.used);
	tls_session->can_pause = false;
	if (tls_session->last_ret > 0) {
		tls_session->clean_out.used += tls_session->last_ret;

		/*
		 *	Round successful, and we don't need to do any
		 *	further processing.
		 */
		tls_session->result = FR_TLS_RESULT_SUCCESS;
	finish:
		/*
		 *	Was bound by caller
		 */
		fr_tls_session_request_unbind(tls_session->ssl);
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	/*
	 *	Bug in OpenSSL 3.0 - Normal handshaking behaviour
	 *	results in spurious "BIO_R_UNSUPPORTED_METHOD"
	 *	errors.
	 *
	 *	SSL_get_error apparently returns SSL_ERROR_SSL if
	 *	there are any errors in the stack.  This masks
	 *	SSL_ERROR_WANT_ASYNC and causes the handshake to
	 *	fail.
	 *
	 *	Note: We may want some version of this code
	 *	included for all OpenSSL versions.
	 *
	 *	It would call ERR_GET_FATAL() on each of the errors
	 *	in the stack to drain non-fatal errors and prevent
	 *	the other (more useful) return codes of
	 *	SSL_get_error from being masked.  I guess we'll see
	 *	if this occurs in other scenarios.
	 */
	if (SSL_get_error(tls_session->ssl, tls_session->last_ret) == SSL_ERROR_SSL) {
		unsigned long ssl_err;

		/*
		 *	Some weird OpenSSL thing marking ERR_GET_REASON
		 *	as "unused".  Unclear why this is done as it's
		 *	not deprecated.
		 */
DIAG_OFF(DIAG_UNKNOWN_PRAGMAS)
DIAG_OFF(used-but-marked-unused)
		while ((ssl_err = ERR_peek_error()) && (ERR_GET_REASON(ssl_err) == BIO_R_UNSUPPORTED_METHOD)) {
			(void) ERR_get_error();
		}
DIAG_ON(used-but-marked-unused)
DIAG_ON(DIAG_UNKNOWN_PRAGMAS)
	}

	/*
	 *	Deal with asynchronous requests from OpenSSL.
	 *      These aren't actually errors, they're the
	 *	result of one of our callbacks indicating that
	 *	it'd like to perform the operation
	 *	asynchronously.
	 */
	switch (err = SSL_get_error(tls_session->ssl, tls_session->last_ret)) {
	case SSL_ERROR_WANT_ASYNC:	/* Certification validation or cache loads */
	{
		unlang_action_t ua;

		RDEBUG3("Performing async action for libssl");

		/*
		 *	Call this function again once we're done
		 *	asynchronously satisfying the load request.
		 */
		if (unlikely(unlang_function_repeat_set(request, tls_session_async_handshake_cont) < 0)) {
		error:
			tls_session->result = FR_TLS_RESULT_ERROR;
			goto finish;
		}

		/*
		 *	First service any pending cache actions
		 */
		ua = fr_tls_cache_pending_push(request, tls_session);
		switch (ua) {
		case UNLANG_ACTION_FAIL:
			IGNORE(unlang_function_clear(request), int);
			goto error;

		case UNLANG_ACTION_PUSHED_CHILD:
			return ua;

		default:
			break;
		}

		/*
		 *	Next service any pending certificate
		 *	validation actions.
		 */
		ua = fr_tls_verify_cert_pending_push(request, tls_session);
		switch (ua) {
		case UNLANG_ACTION_FAIL:
			IGNORE(unlang_function_clear(request), int);
			goto error;

		default:
			return ua;
		}
	}

	case SSL_ERROR_WANT_ASYNC_JOB:
		RERROR("No async jobs available in pool, increase thread.openssl_async_pool_max");
		goto error;

	default:
		/*
		 *	Returns 0 if we can continue processing the handshake
		 *	Returns -1 if we encountered a fatal error.
		 */
		if (fr_tls_log_io_error(request,
					err, "SSL_read (%s)", __FUNCTION__) < 0) goto error;
		return tls_session_async_handshake_done_round(request, uctx);
	}
}

/** Ingest data for another handshake round
 *
 * Advance the TLS handshake by feeding OpenSSL data from dirty_in,
 * and reading data from OpenSSL into dirty_out.
 *
 * Calls #tls_session_async_handshake_read to perform the actual ingestion.
 * #tls_session_async_handshake_read is split out because we may need to call
 * it multiple times, once after every async action.
 *
 * @param[in] request		The current request.
 * @param[in] uctx		#fr_tls_session_t to continue.
 * @return
 *	- UNLANG_ACTION_CALCULATE_RESULT - We're done with this round.
 *	- UNLANG_ACTION_PUSHED_CHILD - Need to perform more asynchronous actions.
 */
static unlang_action_t tls_session_async_handshake(request_t *request, void *uctx)
{
	fr_tls_session_t *tls_session = talloc_get_type_abort(uctx, fr_tls_session_t);
	int ret;

	RDEBUG3("entered state %s", __FUNCTION__);

	tls_session->result = FR_TLS_RESULT_IN_PROGRESS;

	fr_tls_session_request_bind(tls_session->ssl, request);		/* May be unbound in this function or asynchronously */

	/*
	 *	This is a logic error.  fr_tls_session_async_handshake
	 *	must not be called if the handshake is
	 *	complete fr_tls_session_recv must be
	 *	called instead.
	 */
	if (SSL_is_init_finished(tls_session->ssl)) {
		REDEBUG("Attempted to continue TLS handshake, but handshake has completed");
	error:
		tls_session->result = FR_TLS_RESULT_ERROR;
		fr_tls_session_request_unbind(tls_session->ssl);	/* Was bound in this function */
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	if (tls_session->invalid) {
		REDEBUG("Preventing invalid session from continuing");
		goto error;
	}

	/*
	 *	Feed dirty data into OpenSSL, so that is can either
	 *	process it as Application data (decrypting it)
	 *	or continue the TLS handshake.
	 */
	if (tls_session->dirty_in.used) {
		ret = BIO_write(tls_session->into_ssl, tls_session->dirty_in.data, tls_session->dirty_in.used);
		if (ret != (int)tls_session->dirty_in.used) {
			REDEBUG("Failed writing %zu bytes to TLS BIO: %d", tls_session->dirty_in.used, ret);
			record_init(&tls_session->dirty_in);
			goto error;
		}
		record_init(&tls_session->dirty_in);
	}

	return tls_session_async_handshake_cont(request, uctx);	/* Must unbind request, possibly asynchronously */
}

/** Push a handshake call onto the stack
 *
 * We push the handshake frame (as opposed to having the caller do it),
 * so that we guarantee there's a frame that the handshake function can
 * manipulate to manage its own state.
 *
 * The result of processing this handshake round can be found in
 * tls_session->result.
 *
 * @param[in] request		The current request.
 * @param[in] tls_session	to continue handshaking.
 * @return
 *	- UNLANG_ACTION_PUSHED_CHILD on success.
 *	- UNLANG_ACTION_FAIL on failure.
 */
unlang_action_t fr_tls_session_async_handshake_push(request_t *request, fr_tls_session_t *tls_session)
{
	return unlang_function_push(request,
				    tls_session_async_handshake,
				    NULL,
				    tls_session_async_handshake_signal,
				    ~FR_SIGNAL_CANCEL,
				    UNLANG_SUB_FRAME,
				    tls_session);
}

/** Free a TLS session and any associated OpenSSL data
 *
 * @param session to free.
 * @return 0.
 */
static int _fr_tls_session_free(fr_tls_session_t *session)
{
	if (session->ssl) {
		/*
		 *  The OpenSSL docs state:
		 *
		 *	SSL_shutdown() can be modified to only set the
		 *	connection to "shutdown" state but not actually
		 *	send the "close notify" alert messages, see
		 *	SSL_CTX_set_quiet_shutdown(3). When "quiet shutdown"
		 *	is enabled, SSL_shutdown() will always succeed and
		 *	return 1.
		 *
		 *  This is only partially correct.  This call does mean
		 *  we don't notify the other party, but the SSL_shutdown
		 *  call can still fail if the handshake hasn't begun, leaving
		 *  spurious errors on the thread local error stack.
		 */
		SSL_set_quiet_shutdown(session->ssl, 1);

		/*
		 *  Don't leave spurious errors raised by SSL_shutdown on
		 *  the error stack.
		 */
		if (SSL_shutdown(session->ssl) != 1) ERR_clear_error();

		SSL_free(session->ssl);
		session->ssl = NULL;
	}

	return 0;
}

static void session_init(fr_tls_session_t *session)
{
	session->ssl = NULL;
	session->into_ssl = session->from_ssl = NULL;
	record_init(&session->clean_in);
	record_init(&session->clean_out);
	record_init(&session->dirty_in);
	record_init(&session->dirty_out);

	memset(&session->info, 0, sizeof(session->info));

	session->mtu = 0;
	session->opaque = NULL;
}

/** Create a new client TLS session
 *
 * Configures a new client TLS session, configuring options, setting callbacks etc...
 *
 * @param[in] ctx 	to alloc session data in. Should usually be NULL unless the lifetime of the
 *			session is tied to another talloc'd object.
 * @param[in] ssl_ctx	containing the base configuration for this session.
 * @return
 *	- A new session on success.
 *	- NULL on error.
 */
fr_tls_session_t *fr_tls_session_alloc_client(TALLOC_CTX *ctx, SSL_CTX *ssl_ctx)
{
	int			verify_mode;
	fr_tls_session_t	*tls_session = NULL;
	fr_tls_conf_t		*conf = fr_tls_ctx_conf(ssl_ctx);

	MEM(tls_session = talloc_zero(ctx, fr_tls_session_t));
	talloc_set_destructor(tls_session, _fr_tls_session_free);
	fr_pair_list_init(&tls_session->extra_pairs);

	tls_session->ssl = SSL_new(ssl_ctx);
	if (!tls_session->ssl) {
		talloc_free(tls_session);
		return NULL;
	}

	/*
	 *	Add the message callback to identify what type of
	 *	message/handshake is passed
	 */
	SSL_set_msg_callback(tls_session->ssl, fr_tls_session_msg_cb);
	SSL_set_msg_callback_arg(tls_session->ssl, tls_session);
	SSL_set_info_callback(tls_session->ssl, fr_tls_session_info_cb);

	/*
	 *	In Client mode we only accept.
	 *
	 *	This sets up the SSL session to work correctly with
	 *	fr_tls_session_handshake.
	 */
	SSL_set_connect_state(tls_session->ssl);

	/*
	 *	Always verify the peer certificate.
	 */
	DEBUG2("Requiring Server certificate");
	verify_mode = SSL_VERIFY_PEER;
	verify_mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;

	/*
	 *	Callback should be fr_tls_verify_cert_cb but this
	 *	requires support around SSL_connect for dealing
	 *	with async.
	 *
	 *	If the callback is NULL OpenSSL uses its own validation
	 *	function, and the flags modifies that function's
	 *	behaviour.
	 */
	SSL_set_verify(tls_session->ssl, verify_mode, NULL);
	SSL_set_ex_data(tls_session->ssl, FR_TLS_EX_INDEX_CONF, (void *)conf);
	SSL_set_ex_data(tls_session->ssl, FR_TLS_EX_INDEX_TLS_SESSION, (void *)tls_session);

	tls_session->mtu = conf->fragment_size;

	return tls_session;
}

/** Create a new server TLS session
 *
 * Configures a new server TLS session, configuring options, setting callbacks etc...
 *
 * @param[in] ctx		to alloc session data in. Should usually be NULL
 *				unless the lifetime of the session is tied to another
 *				talloc'd object.
 * @param[in] ssl_ctx		containing the base configuration for this session.
 * @param[in] request		The current #request_t.
 * @param[in] dynamic_mtu	If greater than 100, overrides the MTU configured for the SSL_CTX.
 * @param[in] client_cert	Whether to require a client_cert.
 * @return
 *	- A new session on success.
 *	- NULL on error.
 */
fr_tls_session_t *fr_tls_session_alloc_server(TALLOC_CTX *ctx, SSL_CTX *ssl_ctx, request_t *request, size_t dynamic_mtu, bool client_cert)
{
	fr_tls_session_t	*tls_session = NULL;
	SSL			*ssl = NULL;
	int			verify_mode = 0;
	fr_pair_t		*vp;
	fr_tls_conf_t		*conf = fr_tls_ctx_conf(ssl_ctx);

	RDEBUG2("Initiating new TLS session");

	MEM(tls_session = talloc_zero(ctx, fr_tls_session_t));

	ssl = SSL_new(ssl_ctx);
	if (ssl == NULL) {
		fr_tls_log(request, "Error creating new TLS session");
		return NULL;
	}
	fr_pair_list_init(&tls_session->extra_pairs);

	session_init(tls_session);
	tls_session->ctx = ssl_ctx;
	tls_session->ssl = ssl;
	talloc_set_destructor(tls_session, _fr_tls_session_free);

	fr_tls_session_request_bind(tls_session->ssl, request);	/* Is unbound in this function */

	/*
	 *	Initialize callbacks
	 */
	tls_session->record_init = record_init;
	tls_session->record_close = record_close;
	tls_session->record_from_buff = record_from_buff;
	tls_session->record_to_buff = record_to_buff;

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
	MEM(tls_session->into_ssl = BIO_new(BIO_s_mem()));
	MEM(tls_session->from_ssl = BIO_new(BIO_s_mem()));
	SSL_set_bio(tls_session->ssl, tls_session->into_ssl, tls_session->from_ssl);

	/*
	 *	Add the message callback to identify what type of
	 *	message/handshake is passed
	 */
	SSL_set_msg_callback(ssl, fr_tls_session_msg_cb);
	SSL_set_msg_callback_arg(ssl, tls_session);
	SSL_set_info_callback(ssl, fr_tls_session_info_cb);

	/*
	 *	This sets the context sessions can be resumed in.
	 *	This is to prevent sessions being created by one application
	 *	and used by another.  In our case it prevents sessions being
	 *	reused between modules, or TLS server components such as
	 *	RADSEC.
	 *
	 *	A context must always be set when doing session resumption
	 *	otherwise session resumption will fail.
	 *
	 *	As the context ID must be <= 32, we digest the context
	 *	data with sha256.
	 *
	 *	This seems to only be used for stateful session resumption
	 *	not session-tickets
	 */
	if (conf->cache.mode != FR_TLS_CACHE_DISABLED) {
		char		*context_id;
		EVP_MD_CTX	*md_ctx;
		uint8_t		digest[SHA256_DIGEST_LENGTH];

		static_assert(sizeof(digest) <= SSL_MAX_SSL_SESSION_ID_LENGTH,
			      "SSL_MAX_SSL_SESSION_ID_LENGTH must be >= SHA256_DIGEST_LENGTH");
		fr_assert(conf->cache.id_name);

		if (tmpl_aexpand(tls_session, &context_id, request, conf->cache.id_name, NULL, NULL) < 0) {
			RPEDEBUG("Failed expanding session ID");
		error:
			fr_tls_session_request_unbind(tls_session->ssl);	/* Was bound in this function */
			talloc_free(tls_session);
			return NULL;
		}

		MEM(md_ctx = EVP_MD_CTX_create());
		EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL);
		EVP_DigestUpdate(md_ctx, context_id, talloc_array_length(context_id) - 1);
		EVP_DigestFinal_ex(md_ctx, digest, NULL);
		EVP_MD_CTX_destroy(md_ctx);
		talloc_free(context_id);

		if (!fr_cond_assert(SSL_set_session_id_context(tls_session->ssl,
							       digest, sizeof(digest)) == 1)) goto error;
	}

	/*
	 *	Add the session certificate to the session.
	 */
	vp = fr_pair_find_by_da(&request->control_pairs, NULL, attr_tls_session_cert_file);
	if (vp) {
		RDEBUG2("Loading TLS session certificate \"%pV\"", &vp->data);

		if (SSL_use_certificate_file(tls_session->ssl, vp->vp_strvalue, SSL_FILETYPE_PEM) != 1) {
			fr_tls_log(request, "Failed loading TLS session certificate \"%s\"",
				      vp->vp_strvalue);
			goto error;
		}

		if (SSL_use_PrivateKey_file(tls_session->ssl, vp->vp_strvalue, SSL_FILETYPE_PEM) != 1) {
			fr_tls_log(request, "Failed loading TLS session certificate \"%s\"",
				      vp->vp_strvalue);
			goto error;
		}

		if (SSL_check_private_key(tls_session->ssl) != 1) {
			fr_tls_log(request, "Failed validating TLS session certificate \"%s\"",
				      vp->vp_strvalue);
			goto error;
		}
	/*
	 *	Better to perform explicit checks, than rely
	 *	on OpenSSL's opaque error messages.
	 */
	} else {
		if (!conf->chains || !conf->chains[0]->private_key_file) {
			ERROR("TLS Server requires a private key file");
			goto error;
		}

		if (!conf->chains || !conf->chains[0]->certificate_file) {
			ERROR("TLS Server requires a certificate file");
			goto error;
		}
	}

	/** Dynamic toggle for allowing disallowing client certs
	 *
	 * This is mainly used for testing in environments where we can't
	 * get test credentials for the host.
	 */
	vp = fr_pair_find_by_da(&request->control_pairs, NULL, attr_tls_session_require_client_cert);
	if (vp) client_cert = vp->vp_bool;

	/*
	 *	In Server mode we only accept.
	 *
	 *	This sets up the SSL session to work correctly with
	 *	fr_tls_session_handshake.
	 */
	SSL_set_accept_state(tls_session->ssl);

	/*
	 *	Verify the peer certificate, if asked.
	 */
	if (client_cert) {
		RDEBUG2("Setting verify mode to require certificate from client");
		verify_mode = SSL_VERIFY_PEER;
		verify_mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
		verify_mode |= SSL_VERIFY_CLIENT_ONCE;
	}
	tls_session->verify_client_cert = client_cert;

	SSL_set_verify(tls_session->ssl, verify_mode, fr_tls_verify_cert_cb);
	SSL_set_ex_data(tls_session->ssl, FR_TLS_EX_INDEX_CONF, (void *)conf);
	SSL_set_ex_data(tls_session->ssl, FR_TLS_EX_INDEX_TLS_SESSION, (void *)tls_session);

	if (conf->client_hello_parse) {
		SSL_CTX_set_client_hello_cb(ssl_ctx, fr_tls_session_client_hello_cb, NULL);
	}

	tls_session->mtu = conf->fragment_size;
	if (dynamic_mtu > 100 && dynamic_mtu < tls_session->mtu) {
		RDEBUG2("Setting fragment_len to %zu from dynamic_mtu", dynamic_mtu);
		tls_session->mtu = dynamic_mtu;
	}

	if (conf->cache.mode != FR_TLS_CACHE_DISABLED) {
		tls_session->allow_session_resumption = true;	/* otherwise it's false */
		fr_tls_cache_session_alloc(tls_session);
	}

	fr_tls_session_request_unbind(tls_session->ssl);	/* Was bound in this function */

	return tls_session;
}

static unlang_action_t tls_new_session_result(request_t *request, UNUSED void *uctx)
{
	request_t	*parent = request->parent;

	fr_assert(parent);

	/*
	 *	Copy control attributes back to the parent.
	 */
	if (fr_pair_list_copy(parent->control_ctx, &parent->control_pairs, &request->control_pairs) < 0) return UNLANG_ACTION_FAIL;

	return UNLANG_ACTION_CALCULATE_RESULT;
}

unlang_action_t fr_tls_new_session_push(request_t *request, fr_tls_conf_t const *tls_conf) {
	request_t	*child;
	fr_pair_t	*vp;

	MEM(child = unlang_subrequest_alloc(request, dict_tls));
	request = child;

	MEM(pair_prepend_request(&vp, attr_tls_packet_type) >= 0);
	vp->vp_uint32 = enum_tls_packet_type_new_session->vb_uint32;

	if (unlang_subrequest_child_push(NULL, child, child->parent, true, UNLANG_SUB_FRAME) < 0) {
		return UNLANG_ACTION_FAIL;
	}
	if (unlang_function_push(child,
				 NULL,
				 tls_new_session_result,
				 NULL, 0,
				 UNLANG_SUB_FRAME, NULL) < 0) return UNLANG_ACTION_FAIL;

	if (unlang_call_push(NULL, child, tls_conf->virtual_server, UNLANG_SUB_FRAME) < 0) {
		return UNLANG_ACTION_FAIL;
	}
	return UNLANG_ACTION_PUSHED_CHILD;
}
#endif /* WITH_TLS */
