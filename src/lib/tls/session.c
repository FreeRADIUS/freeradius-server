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
 * @copyright 2001 hereUare Communications, Inc. <raghud@hereuare.com>
 * @copyright 2003  Alan DeKok <aland@freeradius.org>
 * @copyright 2006-2016 The FreeRADIUS server project
 */

#ifdef HAVE_OPENSSL_OCSP_H
#define LOG_PREFIX "tls - "

#include <ctype.h>
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/rad_assert.h>
#include <openssl/x509v3.h>
#include "base.h"
#include "tls_attrs.h"

/*
 *	For creating certificate attributes.
 */
static fr_dict_attr_t const **cert_attr_names[][2] = {
	{ &attr_tls_client_cert_common_name,			&attr_tls_cert_common_name },
	{ &attr_tls_client_cert_expiration,			&attr_tls_cert_expiration },
	{ &attr_tls_client_cert_issuer,				&attr_tls_cert_issuer },
	{ &attr_tls_client_cert_serial,				&attr_tls_cert_serial },
	{ &attr_tls_client_cert_subject,			&attr_tls_cert_subject },
	{ &attr_tls_client_cert_subject_alt_name_dns,		&attr_tls_cert_subject_alt_name_dns },
	{ &attr_tls_client_cert_subject_alt_name_email,		&attr_tls_cert_subject_alt_name_email },
	{ &attr_tls_client_cert_subject_alt_name_upn,		&attr_tls_cert_subject_alt_name_upn }
};

#define IDX_COMMON_NAME			(0)
#define IDX_EXPIRATION			(1)
#define IDX_ISSUER			(2)
#define IDX_SERIAL			(3)
#define IDX_SUBJECT			(4)
#define IDX_SUBJECT_ALT_NAME_DNS	(5)
#define IDX_SUBJECT_ALT_NAME_EMAIL	(6)
#define IDX_SUBJECT_ALT_NAME_UPN	(7)

/** Clear a record buffer
 *
 * @param record buffer to clear.
 */
inline static void record_init(tls_record_t *record)
{
	record->used = 0;
}

/** Destroy a record buffer
 *
 * @param record buffer to destroy clear.
 */
inline static void record_close(tls_record_t *record)
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
inline static unsigned int record_from_buff(tls_record_t *record, void const *in, unsigned int inlen)
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
inline static unsigned int record_to_buff(tls_record_t *record, void *out, unsigned int outlen)
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
int tls_session_password_cb(char *buf, int size, int rwflag UNUSED, void *u)
{
	size_t len;

	/*
	 *	We do this instead of not registering the callback
	 *	to ensure OpenSSL doesn't try and read a password
	 *	from stdin (causes server to block).
	 */
	if (!u) {
		ERROR("Certificate encrypted but no private_key_password configured");
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
		if (isalpha((int) c) || isdigit((int) c) || isspace((int) c) ||
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

		MEM(pair_update_request(&vp, attr_tls_psk_identity) >= 0);
		if (fr_pair_value_from_str(vp, identity, -1, '\0', true) < 0) {
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
#endif /* PSK_MAX_IDENTITY_LEN */

/** Record session state changes
 *
 * Called by OpenSSL whenever the session state changes, an alert is received or an error occurs.
 *
 * @param[in] ssl	session.
 * @param[in] where	Which context the callback is being called in.
 *			See https://www.openssl.org/docs/manmaster/ssl/SSL_CTX_set_info_callback.html
 *			for additional info.
 * @param[in] ret	0 if an error occurred, or the alert type if an alert was received.
 */
void tls_session_info_cb(SSL const *ssl, int where, int ret)
{
	char const	*role, *state;
	REQUEST		*request = SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_REQUEST);

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
		if (RDEBUG_ENABLED3) {
			char const *abbrv = SSL_state_string(ssl);
			size_t len;

			/*
			 *	Trim crappy OpenSSL state strings...
			 */
			len = strlen(abbrv);
			if ((len > 1) && (abbrv[len - 1] == ' ')) len--;

			RDEBUG3("Handshake state [%.*s] - %s%s", (int)len, abbrv, role, state);
		} else {
			RDEBUG2("Handshake state - %s%s", role, state);
		}
		return;
	}

	if (where & SSL_CB_ALERT) {
		if ((ret & 0xff) == SSL_AD_CLOSE_NOTIFY) return;

		if (where & SSL_CB_READ) {
			VALUE_PAIR *vp;

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

			MEM(pair_update_request(&vp, attr_tls_client_error_code) >= 0);
			vp->vp_uint8 = ret & 0xff;
			RDEBUG2("&TLS-Client-Error-Code := %pV", &vp->data);
		} else {
			REDEBUG("Sending client %s TLS alert: %s %i", SSL_alert_type_string_long(ret),
				SSL_alert_desc_string_long(ret), ret & 0xff);
		}
		return;
	}

	if (where & SSL_CB_EXIT) {
		if (ret == 0) {
			REDEBUG("Handshake exit state %s%s", role, state);
			return;
		}

		if (ret < 0) {
			if (SSL_want_read(ssl)) {
				RDEBUG2("Need more data from client"); /* State same as previous call, don't print */
				return;
			}
			REDEBUG("Handshake exit state %s%s", role, state);
		}
	}
}

/** Print a message to the request or global log detailing handshake state
 *
 * @param[in] request	The current #REQUEST.
 * @param[in] tls_session	The current TLS session.
 */
static void session_msg_log(REQUEST *request, tls_session_t *tls_session)
{
	char const	*str_write_p, *str_version, *str_content_type = "";
	char const	*str_details1 = "", *str_details2= "";
	char		buffer[32];
	char		content_type[64];

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

#ifdef TLS1_RT_HEARTBEAT
	case TLS1_RT_HEARTBEAT:
		str_content_type = "heartbeat ";
		break;
#endif

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

	ROPTIONAL(RDEBUG2, DEBUG2, "%s", tls_session->info.info_description);
}

/** Record the progression of the TLS handshake
 *
 * This callback is called by OpenSSL whenever a protocol message relating to a handshake is sent
 * or received.
 *
 * This function copies state information from the various arguments into the state->info
 * structure of the #tls_session_t, to allow us to track the progression of the handshake.
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
 * @param[in] arg		The #tls_session_t holding the SSL session.
 */
void tls_session_msg_cb(int write_p, int msg_version, int content_type,
			void const *inbuf, size_t len,
			SSL *ssl, void *arg)
{
	uint8_t const	*buf = inbuf;
	tls_session_t	*session = talloc_get_type_abort(arg, tls_session_t);
	REQUEST		*request = SSL_get_ex_data(session->ssl, FR_TLS_EX_INDEX_REQUEST);

	/*
	 *	Mostly to check for memory corruption...
	 */
	if (!fr_cond_assert(session->ssl = ssl)) {
		ERROR("tls_session_t and ssl arg do not match in tls_session_msg_cb");
		session->invalid = true;
		return;
	}

	/*
	 *	As per https://tools.ietf.org/html/rfc7568
	 *
	 *	We explicitly disable SSLv2/v3, hence the asserts.
	 */
#ifdef SSL2_VERSION
	if (!fr_cond_assert(msg_version != SSL2_VERSION)) {
		ERROR("Invalid version (SSLv2) in handshake");
		session->invalid = true;
		return;
	}
#endif

#ifdef SSL3_VERSION
	if (!fr_cond_assert(msg_version != SSL3_VERSION)) {
		ERROR("Invalid version (SSLv3) in handshake");
		session->invalid = true;
		return;
	}
#endif

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
	 *	0 - received (from peer)
	 *	1 - sending (to peer)
	 */
	session->info.origin = write_p;
	session->info.content_type = content_type;
	session->info.record_len = len;
	session->info.version = msg_version;
	session->info.initialized = true;

	switch (content_type) {
	case SSL3_RT_ALERT:
		session->info.alert_level = buf[0];
		session->info.alert_description = buf[1];
		session->info.handshake_type = 0x00;
		break;

	case SSL3_RT_HANDSHAKE:
		session->info.handshake_type = buf[0];
		session->info.alert_level = 0x00;
		session->info.alert_description = 0x00;
		break;

#ifdef SSL3_RT_HEARTBEAT
	case TLS1_RT_HEARTBEAT:
		uint8_t *p = buf;

		if ((len >= 3) && (p[0] == 1)) {
			size_t payload_len;

			payload_len = (p[1] << 8) | p[2];
			if ((payload_len + 3) > len) {
				session->invalid = true;
				ERROR("OpenSSL Heartbeat attack detected.  Closing connection");
				return;
			}
		}
		break;
#endif
	default:
		break;
	}

	session_msg_log(request, session);
}

static inline VALUE_PAIR *tls_session_cert_attr_add(TALLOC_CTX *ctx, REQUEST *request, fr_cursor_t *cursor,
					    	    int attr, int attr_index, char const *value)
{
	VALUE_PAIR *vp;
	fr_dict_attr_t const *da = *(cert_attr_names[attr][attr_index]);

	MEM(vp = fr_pair_afrom_da(ctx, da));
	if (value) {
		if (fr_pair_value_from_str(vp, value, -1, '\0', true) < 0) {
			RPWDEBUG("Failed creating attribute %s", da->name);
			talloc_free(vp);
			return NULL;
		}
	}
	RINDENT();
	RDEBUG3("%pP", vp);
	REXDENT();
	fr_cursor_append(cursor, vp);

	return vp;
}

/** Extract attributes from an X509 certificate
 *
 * @param cursor	to copy attributes to.
 * @param ctx		to allocate attributes in.
 * @param session	current TLS session.
 * @param cert		to validate.
 * @param depth		the certificate is in the certificate chain (0 == leaf).
 * @return
 *	- 0 on success.
 *	- < 0 on failure.
 */
int tls_session_pairs_from_x509_cert(fr_cursor_t *cursor, TALLOC_CTX *ctx,
				     tls_session_t *session, X509 *cert, int depth)
{
	char		buffer[1024];
	char		attribute[256];
	char		**identity;
	int		attr_index, loc;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	STACK_OF(X509_EXTENSION) const *ext_list = NULL;
#else
	STACK_OF(X509_EXTENSION) *ext_list = NULL;
#endif

	ASN1_INTEGER	*sn = NULL;
	ASN1_TIME	*asn_time = NULL;

	VALUE_PAIR	*vp = NULL;

	REQUEST		*request;

#define CERT_ATTR_ADD(_attr, _attr_index, _value) tls_session_cert_attr_add(ctx, request, cursor, _attr, _attr_index, _value)

	attr_index = depth;
	if (attr_index > 1) attr_index = 1;

	request = (REQUEST *)SSL_get_ex_data(session->ssl, FR_TLS_EX_INDEX_REQUEST);
	rad_assert(request != NULL);

	identity = (char **)SSL_get_ex_data(session->ssl, FR_TLS_EX_INDEX_IDENTITY);

	if (RDEBUG_ENABLED3) {
		buffer[0] = '\0';
		X509_NAME_oneline(X509_get_subject_name(cert), buffer, sizeof(buffer));
		buffer[sizeof(buffer) - 1] = '\0';
		RDEBUG3("Creating attributes for \"%s\":", buffer[0] ? buffer : "Cert missing subject OID");
	}

	/*
	 *	Get the Serial Number
	 */
	sn = X509_get_serialNumber(cert);
	if (sn && ((size_t) sn->length < (sizeof(buffer) / 2))) {
		char *p = buffer;
		int i;

		for (i = 0; i < sn->length; i++) {
			sprintf(p, "%02x", (unsigned int)sn->data[i]);
			p += 2;
		}

		CERT_ATTR_ADD(IDX_SERIAL, attr_index, buffer);
	}

	/*
	 *	Get the Expiration Date
	 */
	buffer[0] = '\0';
	asn_time = X509_get_notAfter(cert);
	if (identity && asn_time && (asn_time->length < (int)sizeof(buffer))) {
		time_t expires;

		/*
		 *	Add expiration as a time since the epoch
		 */
		if (tls_utils_asn1time_to_epoch(&expires, asn_time) < 0) {
			RPWDEBUG("Failed parsing certificate expiry time");
		} else {
			vp = CERT_ATTR_ADD(IDX_EXPIRATION, attr_index, NULL);
			vp->vp_date = expires;
		}
	}

	/*
	 *	Get the Subject & Issuer
	 */
	buffer[0] = '\0';
	X509_NAME_oneline(X509_get_subject_name(cert), buffer, sizeof(buffer));
	buffer[sizeof(buffer) - 1] = '\0';
	if (identity && buffer[0]) {
		CERT_ATTR_ADD(IDX_SUBJECT, attr_index, buffer);

		/*
		 *	Get the Common Name, if there is a subject.
		 */
		X509_NAME_get_text_by_NID(X509_get_subject_name(cert),
					  NID_commonName, buffer, sizeof(buffer));
		buffer[sizeof(buffer) - 1] = '\0';

		if (buffer[0]) {
			CERT_ATTR_ADD(IDX_COMMON_NAME, attr_index, buffer);
		}
	}

	X509_NAME_oneline(X509_get_issuer_name(cert), buffer, sizeof(buffer));
	buffer[sizeof(buffer) - 1] = '\0';
	if (identity && buffer[0]) {
		CERT_ATTR_ADD(IDX_ISSUER, attr_index, buffer);
	}

	/*
	 *	Get the RFC822 Subject Alternative Name
	 */
	loc = X509_get_ext_by_NID(cert, NID_subject_alt_name, 0);
	if (loc >= 0) {
		X509_EXTENSION	*ext = NULL;
		GENERAL_NAMES	*names = NULL;
		int		i;

		ext = X509_get_ext(cert, loc);
		if (ext && (names = X509V3_EXT_d2i(ext))) {
			for (i = 0; i < sk_GENERAL_NAME_num(names); i++) {
				GENERAL_NAME *name = sk_GENERAL_NAME_value(names, i);

				switch (name->type) {
#ifdef GEN_EMAIL
				case GEN_EMAIL: {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
					char const *rfc822Name = (char const *)ASN1_STRING_get0_data(name->d.rfc822Name);
#else
					char *rfc822Name = (char *)ASN1_STRING_data(name->d.rfc822Name);
#endif

					CERT_ATTR_ADD(IDX_SUBJECT_ALT_NAME_EMAIL, attr_index, rfc822Name);
					break;
				}
#endif	/* GEN_EMAIL */
#ifdef GEN_DNS
				case GEN_DNS: {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
					char const *dNSName = (char const *)ASN1_STRING_get0_data(name->d.dNSName);
#else
					char *dNSName = (char *)ASN1_STRING_data(name->d.dNSName);
#endif
					CERT_ATTR_ADD(IDX_SUBJECT_ALT_NAME_DNS, attr_index, dNSName);
					break;
				}
#endif	/* GEN_DNS */
#ifdef GEN_OTHERNAME
				case GEN_OTHERNAME:
					/* look for a MS UPN */
					if (NID_ms_upn != OBJ_obj2nid(name->d.otherName->type_id)) break;

					/* we've got a UPN - Must be ASN1-encoded UTF8 string */
					if (name->d.otherName->value->type == V_ASN1_UTF8STRING) {
						CERT_ATTR_ADD(IDX_SUBJECT_ALT_NAME_UPN, attr_index,
								  (char *)name->d.otherName->value->value.utf8string);
						break;
					}

					RWARN("Invalid UPN in Subject Alt Name (should be UTF-8)");
					break;
#endif	/* GEN_OTHERNAME */
				default:
					/* XXX TODO handle other SAN types */
					break;
				}
			}
		}
		if (names != NULL) GENERAL_NAMES_free(names);
	}

	/*
	 *	Only add extensions for the actual client certificate
	 */
	if (attr_index == 0) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
		ext_list = X509_get0_extensions(cert);
#else
		ext_list = cert->cert_info->extensions;
#endif

		/*
		 *	Grab the X509 extensions, and create attributes out of them.
		 *	For laziness, we re-use the OpenSSL names
		 */
		if (sk_X509_EXTENSION_num(ext_list) > 0) {
			int i, len;
			char *p;
			BIO *out;

			out = BIO_new(BIO_s_mem());
			strlcpy(attribute, "TLS-Client-Cert-", sizeof(attribute));

			for (i = 0; i < sk_X509_EXTENSION_num(ext_list); i++) {
				char			value[1024];
				ASN1_OBJECT		*obj;
				X509_EXTENSION		*ext;
				fr_dict_attr_t const	*da;

				ext = sk_X509_EXTENSION_value(ext_list, i);

				obj = X509_EXTENSION_get_object(ext);
				i2a_ASN1_OBJECT(out, obj);

				len = BIO_read(out, attribute + 16 , sizeof(attribute) - 16 - 1);
				if (len <= 0) continue;

				attribute[16 + len] = '\0';

				for (p = attribute + 16; *p != '\0'; p++) if (*p == ' ') *p = '-';

				X509V3_EXT_print(out, ext, 0, 0);
				len = BIO_read(out, value , sizeof(value) - 1);
				if (len <= 0) continue;

				value[len] = '\0';

				da = fr_dict_attr_by_name(dict_freeradius, attribute);
				if (!da) {
					RWDEBUG3("Skipping attribute %s: "
						 "Add dictionary definition if you want to access it", attribute);
					continue;
				}

				MEM(vp = fr_pair_afrom_da(request, da));
				if (fr_pair_value_from_str(vp, value, -1, '\0', true) < 0) {
					RPWDEBUG3("Skipping: %s += '%s'", attribute, value);
					talloc_free(vp);
					continue;
				}

				fr_cursor_append(cursor, vp);
			}
			BIO_free_all(out);
		}
	}

	return 0;
}

/** Decrypt application data
 *
 * @note Handshake must have completed before this function may be called.
 *
 * Feed data from dirty_in to OpenSSL, and read the clean data into clean_out.
 *
 * @param[in] request	The current #REQUEST.
 * @param[in] session	The current TLS session.
 * @return
 *	- -1 on error.
 *	- 1 if more fragments are required to fully reassemble the record for decryption.
 *	- 0 if we decrypted a complete record.
 */
int tls_session_recv(REQUEST *request, tls_session_t *session)
{
	int ret;

	if (!SSL_is_init_finished(session->ssl)) {
		REDEBUG("Attempted to read application data before handshake completed");
		return -1;
	}

	/*
	 *	Decrypt the complete record.
	 */
	ret = BIO_write(session->into_ssl, session->dirty_in.data, session->dirty_in.used);
	if (ret != (int) session->dirty_in.used) {
		record_init(&session->dirty_in);
		REDEBUG("Failed writing %zd bytes to SSL BIO: %d", session->dirty_in.used, ret);
		return -1;
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
			return 1;

		case SSL_ERROR_WANT_WRITE:
			REDEBUG("Error in fragmentation logic: SSL_WANT_WRITE");
			break;

		default:
			REDEBUG("Error in fragmentation logic");
			tls_log_io_error(request, session, ret, "Failed in SSL_read");
			break;
		}
		return -1;
	}

	if (ret == 0) RWDEBUG("No data inside of the tunnel");

	/*
	 *	Passed all checks, successfully decrypted data
	 */
	session->clean_out.used = ret;

	RDEBUG2("Decrypted TLS application data (%zu bytes)", session->clean_out.used);
	log_request_hex(L_DBG, L_DBG_LVL_3, request, session->clean_out.data, session->clean_out.used);

	return 0;
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
		return 0;
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
		log_request_hex(L_DBG, L_DBG_LVL_3, request, session->clean_in.data, session->clean_in.used);

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

int tls_session_handshake_alert(UNUSED REQUEST *request, tls_session_t *session, uint8_t level, uint8_t description)
{
	rad_assert(session->handshake_alert.level == 0);

	session->handshake_alert.count++;
	if (session->handshake_alert.count > 3)
		return -1;

	session->handshake_alert.level = level;
	session->handshake_alert.description = description;

	return 0;
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

	if (session->invalid) {
		REDEBUG("Preventing invalid session from continuing");
		return 0;
	}

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
	 *
	 *	Callbacks provide enough info so we don't need to
	 *	print debug statements when the handshake is in other
	 *	states.
	 */
	if (SSL_is_init_finished(session->ssl)) {
		SSL_CIPHER const *cipher;

		char cipher_desc[256], cipher_desc_clean[256];
		char *p = cipher_desc, *q = cipher_desc_clean;

		cipher = SSL_get_current_cipher(session->ssl);
		SSL_CIPHER_description(cipher, cipher_desc, sizeof(cipher_desc));
		/*
		 *	Cleanup the output from OpenSSL
		 *	Seems to print info in a tabular format.
		 */
		while (*p != '\0') {
			if (isspace(*p)) {
				*q++ = *p;
				while (isspace(*++p));
				continue;
			}
			*q++ = *p++;
		}
		*q = '\0';

		RDEBUG2("Cipher suite: %s", cipher_desc_clean);
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
		/*
		 *	Cache the SSL_SESSION pointer.
		 *
		 *	Which contains all the data we need for session resumption.
		 */
		if (!session->ssl_session) {
			session->ssl_session = SSL_get_session(session->ssl);
			if (!session->ssl_session) {
				REDEBUG("Failed getting TLS session");
				return 0;
			}
		}

		if (RDEBUG_ENABLED3) {
			BIO *ssl_log = BIO_new(BIO_s_mem());

			if (ssl_log) {
				if (SSL_SESSION_print(ssl_log, session->ssl_session) == 1) {
					SSL_DRAIN_ERROR_QUEUE(RDEBUG3, "", ssl_log);
				} else {
					RDEBUG3("Failed retrieving session data");
				}
				BIO_free(ssl_log);
			}
		}
#endif

		/*
		 *	Session was resumed, add attribute to mark it as such.
		 */
		if (SSL_session_reused(session->ssl)) {
			VALUE_PAIR *vp;

			/*
			 *	Mark the request as resumed.
			 */
			MEM(pair_update_request(&vp, attr_eap_session_resumed) >= 0);
			vp->vp_bool = true;
		}
	}

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

	/*
	 *	W would prefer to latch on info.content_type but
	 *	(I think its...) tls_session_msg_cb() updates it
	 *	after the call to tls_session_handshake_alert()
	 */
	if (session->handshake_alert.level) {
		/*
		 * FIXME RFC 4851 section 3.6.1 - peer might ACK alert and include a restarted ClientHello
		 *                                 which eap_tls_session_status() will fail on
		 */
		session->info.content_type = SSL3_RT_ALERT;

		session->dirty_out.data[0] = session->info.content_type;
		session->dirty_out.data[1] = 3;
		session->dirty_out.data[2] = 1;
		session->dirty_out.data[3] = 0;
		session->dirty_out.data[4] = 2;
		session->dirty_out.data[5] = session->handshake_alert.level;
		session->dirty_out.data[6] = session->handshake_alert.description;

		session->dirty_out.used = 7;

		session->handshake_alert.level = 0;
	}

	/* We are done with dirty_in, reinitialize it */
	record_init(&session->dirty_in);
	return 1;
}

/** Free a TLS session and any associated OpenSSL data
 *
 * @param session to free.
 * @return 0.
 */
static int _tls_session_free(tls_session_t *session)
{
	if (session->ssl) {
		SSL_set_quiet_shutdown(session->ssl, 1);
		SSL_shutdown(session->ssl);
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
	session->opaque = NULL;
}

/** Create a new client TLS session
 *
 * Configures a new client TLS session, configuring options, setting callbacks etc...
 *
 * @param ctx 	to alloc session data in. Should usually be NULL unless the lifetime of the
 *		session is tied to another talloc'd object.
 * @param conf	values for this TLS session.
 * @return
 *	- A new session on success.
 *	- NULL on error.
 */
tls_session_t *tls_session_init_client(TALLOC_CTX *ctx, fr_tls_conf_t *conf)
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
 * @param ctx		to alloc session data in. Should usually be NULL unless the lifetime of the
 *			session is tied to another talloc'd object.
 * @param conf		values for this TLS session.
 * @param request	The current #REQUEST.
 * @param client_cert	Whether to require a client_cert.
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

	RDEBUG2("Initiating new TLS session");

	ssl_ctx = conf->ctx[(conf->ctx_count == 1) ? 0 : conf->ctx_next++ % conf->ctx_count];	/* mutex not needed */
	rad_assert(ssl_ctx);

	new_tls = SSL_new(ssl_ctx);
	if (new_tls == NULL) {
		tls_log_error(request, "Error creating new TLS session");
		return NULL;
	}

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
	 */
	rad_assert(conf->session_id_name);
	{
		char		*context_id;
		EVP_MD_CTX	*md_ctx;
		uint8_t		digest[SHA256_DIGEST_LENGTH];

		static_assert(sizeof(digest) <= SSL_MAX_SSL_SESSION_ID_LENGTH,
			      "SSL_MAX_SSL_SESSION_ID_LENGTH must be >= SHA256_DIGEST_LENGTH");

		if (tmpl_aexpand(session, &context_id, request, conf->session_id_name, NULL, NULL) < 0) {
			RPEDEBUG("Failed expanding session ID");
			talloc_free(session);
		}

		MEM(md_ctx = EVP_MD_CTX_create());
		EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL);
		EVP_DigestUpdate(md_ctx, context_id, talloc_array_length(context_id) - 1);
		EVP_DigestFinal_ex(md_ctx, digest, NULL);
		EVP_MD_CTX_destroy(md_ctx);
		talloc_free(context_id);

		if (!fr_cond_assert(SSL_set_session_id_context(session->ssl, digest, sizeof(digest)) == 1)) {
			talloc_free(session);
			return NULL;
		}
	}

	/*
	 *	Add the session certificate to the session.
	 */
	vp = fr_pair_find_by_da(request->control, attr_tls_session_cert_file, TAG_ANY);
	if (vp) {
		RDEBUG2("Loading TLS session certificate \"%s\"", vp->vp_strvalue);

		if (SSL_use_certificate_file(session->ssl, vp->vp_strvalue, SSL_FILETYPE_PEM) != 1) {
			tls_log_error(request, "Failed loading TLS session certificate \"%s\"",
				      vp->vp_strvalue);
			talloc_free(session);
			return NULL;
		}

		if (SSL_use_PrivateKey_file(session->ssl, vp->vp_strvalue, SSL_FILETYPE_PEM) != 1) {
			tls_log_error(request, "Failed loading TLS session certificate \"%s\"",
				      vp->vp_strvalue);
			talloc_free(session);
			return NULL;
		}

		if (SSL_check_private_key(session->ssl) != 1) {
			tls_log_error(request, "Failed validating TLS session certificate \"%s\"",
				      vp->vp_strvalue);
			talloc_free(session);
			return NULL;
		}
	/*
	 *	Better to perform explicit checks, than rely
	 *	on OpenSSL's opaque error messages.
	 */
	} else {
		if (!conf->chains || !conf->chains[0]->private_key_file) {
			ERROR("TLS Server requires a private key file");
			talloc_free(session);
			return NULL;
		}

		if (!conf->chains || !conf->chains[0]->certificate_file) {
			ERROR("TLS Server requires a certificate file");
			talloc_free(session);
			return NULL;
		}
	}

	/*
	 *	In Server mode we only accept.
	 *
	 *	This sets up the SSL session to work correctly with
	 *	tls_session_handhsake.
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
	vp = fr_pair_find_by_da(request->packet->vps, attr_framed_mtu, TAG_ANY);
	if (vp && (vp->vp_uint32 > 100) && (vp->vp_uint32 < session->mtu)) {
		RDEBUG2("Setting fragment_len to %u from &Framed-MTU", vp->vp_uint32);
		session->mtu = vp->vp_uint32;
	}

	if (conf->session_cache_server) session->allow_session_resumption = true; /* otherwise it's false */

	return session;
}
#endif /* WITH_TLS */
