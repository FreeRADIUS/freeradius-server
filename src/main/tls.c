/*
 * tls.c
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
 * Copyright 2003  Alan DeKok <aland@freeradius.org>
 * Copyright 2006  The FreeRADIUS server project
 */

RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/process.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_UTIME_H
#include <utime.h>
#endif
#include <ctype.h>

#ifdef WITH_TLS
#  ifdef HAVE_OPENSSL_RAND_H
#    include <openssl/rand.h>
#  endif

#  ifdef HAVE_OPENSSL_OCSP_H
#    include <openssl/ocsp.h>
#  endif

#  ifdef HAVE_OPENSSL_EVP_H
#    include <openssl/evp.h>
#  endif
#  include <openssl/ssl.h>

#define LOG_PREFIX "tls"

#ifdef ENABLE_OPENSSL_VERSION_CHECK
typedef struct libssl_defect {
	uint64_t	high;		//!< The last version number this defect affected.
	uint64_t	low;		//!< The first version this defect affected.

	char const	*id;		//!< CVE (or other ID)
	char const	*name;		//!< As known in the media...
	char const	*comment;	//!< Where to get more information.
} libssl_defect_t;

/* Record critical defects in libssl here (newest first)*/
static libssl_defect_t libssl_defects[] =
{
	{
		.low		= 0x010001000,		/* 1.0.1  */
		.high		= 0x01000106f,		/* 1.0.1f */
		.id		= "CVE-2014-0160",
		.name		= "Heartbleed",
		.comment	= "For more information see http://heartbleed.com"
	}
};
#endif /* ENABLE_OPENSSL_VERSION_CHECK */

#ifdef WITH_TLS
static bool tls_done_init = false;
#endif

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

/* Session */
static void 		session_close(tls_session_t *session);
static void 		session_init(tls_session_t *session);

/* record */
static void 		record_init(tls_record_t *record);
static void 		record_close(tls_record_t *record);
static unsigned int 	record_from_buff(tls_record_t *record, void const *in, unsigned int inlen);
static unsigned int 	record_to_buff(tls_record_t *record, void *out, unsigned int outlen);

#ifdef PSK_MAX_IDENTITY_LEN
/** Verify the PSK identity contains no reserved chars
 *
 * @param identity to check.
 * @return
 *	- true identity does not contain reserved chars.
 *	- false identity contains reserved chars.
 */
static bool tls_psk_identity_is_safe(const char *identity)
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


/** Determine the PSK to use
 *
 *
 */
static unsigned int tls_psk_server_cb(SSL *ssl, const char *identity,
				      unsigned char *psk,
				      unsigned int max_psk_len)
{
	unsigned int psk_len = 0;
	fr_tls_server_conf_t *conf;
	REQUEST *request;

	conf = (fr_tls_server_conf_t *)SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_CONF);
	if (!conf) return 0;

	request = (REQUEST *)SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_REQUEST);
	if (request && conf->psk_query) {
		size_t hex_len;
		VALUE_PAIR *vp;
		char buffer[2 * PSK_MAX_PSK_LEN + 4]; /* allow for too-long keys */

		/*
		 *	The passed identity is weird.  Deny it.
		 */
		if (!tls_psk_identity_is_safe(identity)) {
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

static unsigned int tls_psk_client_cb(SSL *ssl, UNUSED char const *hint,
				      char *identity, unsigned int max_identity_len,
				      unsigned char *psk, unsigned int max_psk_len)
{
	unsigned int psk_len;
	fr_tls_server_conf_t *conf;

	conf = (fr_tls_server_conf_t *)SSL_get_ex_data(ssl,
						       FR_TLS_EX_INDEX_CONF);
	if (!conf) return 0;

	psk_len = strlen(conf->psk_password);
	if (psk_len > (2 * max_psk_len)) return 0;

	strlcpy(identity, conf->psk_identity, max_identity_len);

	return fr_hex2bin(psk, max_psk_len, conf->psk_password, psk_len);
}

#endif

#define MAX_SESSION_SIZE (256)

void tls_session_id(SSL_SESSION *session, char *buffer, size_t bufsize)
{
#if OPENSSL_VERSION_NUMBER < 0x10001000L
	size_t size;

	size = session->session_id_length;
	if (size > bufsize) size = bufsize;

	fr_bin2hex(buffer, session->session_id, size);
#else
	unsigned int size;
	uint8_t const *p;

	p = SSL_SESSION_get_id(session, &size);
	if (size > bufsize) size = bufsize;

	fr_bin2hex(buffer, p, size);

#endif
}


static int _tls_session_free(tls_session_t *session)
{
	session_close(session);

	return 0;
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
tls_session_t *tls_session_init_client(TALLOC_CTX *ctx, fr_tls_server_conf_t *conf, int fd)
{
	int		verify_mode;
	tls_session_t	*session = NULL;
	REQUEST		*request;

	session = talloc_zero(ctx, tls_session_t);
	if (!session) return NULL;

	talloc_set_destructor(session, _tls_session_free);

	session->ctx = conf->ctx[(conf->ctx_count == 1) ? 1 : conf->ctx_next++ % conf->ctx_count];	/* mutex not needed */
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
	SSL_set_msg_callback(session->ssl, cbtls_msg);
	SSL_set_msg_callback_arg(session->ssl, session);
	SSL_set_info_callback(session->ssl, cbtls_info);

	/*
	 *	Always verify the peer certificate.
	 */
	DEBUG2("Requiring Server certificate");
	verify_mode = SSL_VERIFY_PEER;
	verify_mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
	SSL_set_verify(session->ssl, verify_mode, cbtls_verify);

	SSL_set_ex_data(session->ssl, FR_TLS_EX_INDEX_CONF, (void *)conf);
	SSL_set_ex_data(session->ssl, FR_TLS_EX_INDEX_TLS_SESSION, (void *)session);
	SSL_set_fd(session->ssl, fd);
	if (SSL_connect(session->ssl) <= 0) {
		int err;
		while ((err = ERR_get_error())) ERROR("tls: %s", ERR_error_string(err, NULL));
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
tls_session_t *tls_session_init_server(TALLOC_CTX *ctx, fr_tls_server_conf_t *conf, REQUEST *request, bool client_cert)
{
	tls_session_t	*session = NULL;
	SSL		*new_tls = NULL;
	int		verify_mode = 0;
	VALUE_PAIR	*vp;
	SSL_CTX		*ssl_ctx;

	rad_assert(request != NULL);
	rad_assert(conf->ctx_count > 0);

	RDEBUG2("Initiating new EAP-TLS session");

	ssl_ctx = conf->ctx[(conf->ctx_count == 1) ? 1 : conf->ctx_next++ % conf->ctx_count];	/* mutex not needed */

	/*
	 *	Manually flush the sessions every so often.  If HALF
	 *	of the session lifetime has passed since we last
	 *	flushed, then flush it again.
	 *
	 *	FIXME: Also do it every N sessions?
	 */
	if (conf->session_cache_enable && !conf->session_cache_server &&
	    ((conf->session_last_flushed + ((int)conf->session_timeout * 1800)) <= request->timestamp)){
		RDEBUG2("Flushing TLS sessions (of #%ld)", SSL_CTX_sess_number(ssl_ctx));

		SSL_CTX_flush_sessions(ssl_ctx, request->timestamp);
		conf->session_last_flushed = request->timestamp;
	}

	new_tls = SSL_new(ssl_ctx);
	if (new_tls == NULL) {
		RERROR("Error creating new TLS session: %s", ERR_error_string(ERR_get_error(), NULL));

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
	talloc_set_destructor(session, _tls_session_free);

	session->ctx = ssl_ctx;
	session->ssl = new_tls;

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
	SSL_set_msg_callback(new_tls, cbtls_msg);
	SSL_set_msg_callback_arg(new_tls, session);
	SSL_set_info_callback(new_tls, cbtls_info);

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
	SSL_set_verify(session->ssl, verify_mode, cbtls_verify);

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
	vp = fr_pair_find_by_num(request->packet->vps, PW_FRAMED_MTU, 0, TAG_ANY);
	if (vp && (vp->vp_integer > 100) && (vp->vp_integer < session->mtu)) {
		session->mtu = vp->vp_integer;
	}

	if (conf->session_cache_enable) session->allow_session_resumption = true; /* otherwise it's false */

	return session;
}

/*
 *	Print out some text describing the error.
 */
static int tls_error_log(REQUEST *request, SSL *s, int ret, char const *text)
{
	int e;
	unsigned long l;

	if ((l = ERR_get_error()) != 0) {
		char const *p = ERR_error_string(l, NULL);

		if (p) ROPTIONAL(REDEBUG, ERROR, "TLS says: %s", p);
	}

	e = SSL_get_error(s, ret);
	switch (e) {
	/*
	 *	These seem to be harmless and already "dealt
	 *	with" by our non-blocking environment. NB:
	 *	"ZERO_RETURN" is the clean "error"
	 *	indicating a successfully closed SSL
	 *	tunnel. We let this happen because our IO
	 *	loop should not appear to have broken on
	 *	this condition - and outside the IO loop, the
	 *	"shutdown" state is checked.
	 *
	 *	Don't print anything if we ignore the error.
	 */
	case SSL_ERROR_NONE:
	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
	case SSL_ERROR_WANT_X509_LOOKUP:
	case SSL_ERROR_ZERO_RETURN:
		break;

	/*
	 *	These seem to be indications of a genuine
	 *	error that should result in the SSL tunnel
	 *	being regarded as "dead".
	 */
	case SSL_ERROR_SYSCALL:
		ROPTIONAL(REDEBUG, ERROR, "%s failed in a system call (%d), TLS session failed", text, ret);
		return 0;

	case SSL_ERROR_SSL:
		ROPTIONAL(REDEBUG, ERROR, "%s failed inside of TLS (%d), TLS session failed", text, ret);
		return 0;

	/*
	 *	For any other errors that (a) exist, and (b)
	 *	crop up - we need to interpret what to do with
	 *	them - so "politely inform" the caller that
	 *	the code needs updating here.
	 */
	default:
		ROPTIONAL(REDEBUG, ERROR, "FATAL TLS error: %d", e);
		return 0;
	}

	return 1;
}

/*
 * We are the server, we always get the dirty data
 * (Handshake data is also considered as dirty data)
 * During handshake, since SSL API handles itself,
 * After clean-up, dirty_out will be filled with
 * the data required for handshaking. So we check
 * if dirty_out is empty then we simply send it back.
 * As of now, if handshake is successful, then we keep going,
 * otherwise we fail.
 *
 * Fill the Bio with the dirty data to clean it
 * Get the cleaned data from SSL, if it is not Handshake data
 */
int tls_handshake_recv(REQUEST *request, tls_session_t *session)
{
	int err;

	if (session->invalid_hb_used) return 0;

	err = BIO_write(session->into_ssl, session->dirty_in.data, session->dirty_in.used);
	if (err != (int) session->dirty_in.used) {
		REDEBUG("Failed writing %zd bytes to TLS BIO: %d", session->dirty_in.used, err);
		record_init(&session->dirty_in);
		return 0;
	}
	record_init(&session->dirty_in);

	err = SSL_read(session->ssl, session->clean_out.data + session->clean_out.used,
		       sizeof(session->clean_out.data) - session->clean_out.used);
	if (err > 0) {
		session->clean_out.used += err;
		return 1;
	}

	if (!tls_error_log(request, session->ssl, err, "TLS_read")) return 0;

	/* Some Extra STATE information for easy debugging */
	if (SSL_is_init_finished(session->ssl)) {
		SSL_CIPHER const *cipher;
		char buffer[256];

		cipher = SSL_get_current_cipher(session->ssl);

		RDEBUG2("TLS established with cipher suite: %s",
			SSL_CIPHER_description(cipher, buffer, sizeof(buffer)));
	}
	if (SSL_in_init(session->ssl)) RDEBUG2("In TLS handshake phase");
	if (SSL_in_before(session->ssl)) RDEBUG2("Before TLS handshake phase");
	if (SSL_in_accept_init(session->ssl)) RDEBUG2("In TLS accept mode");
	if (SSL_in_connect_init(session->ssl)) RDEBUG2("In TLS connect mode");

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

	err = BIO_ctrl_pending(session->from_ssl);
	if (err > 0) {
		err = BIO_read(session->from_ssl, session->dirty_out.data,
			       sizeof(session->dirty_out.data));
		if (err > 0) {
			session->dirty_out.used = err;

		} else if (BIO_should_retry(session->from_ssl)) {
			record_init(&session->dirty_in);
			RDEBUG2("Asking for more data in tunnel");
			return 1;

		} else {
			tls_error_log(request, session->ssl, err, "BIO_read");
			record_init(&session->dirty_in);
			return 0;
		}
	} else {
		RDEBUG2("TLS Application Data");
		/* Its clean application data, do whatever we want */
		record_init(&session->clean_out);
	}

	/* We are done with dirty_in, reinitialize it */
	record_init(&session->dirty_in);
	return 1;
}

/*
 *	Take cleartext user data, and encrypt it into the output buffer,
 *	to send to the client at the other end of the SSL connection.
 */
int tls_handshake_send(REQUEST *request, tls_session_t *session)
{
	int err;

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
		int written;

		written = SSL_write(session->ssl, session->clean_in.data, session->clean_in.used);
		record_to_buff(&session->clean_in, NULL, written);

		/* Get the dirty data from Bio to send it */
		err = BIO_read(session->from_ssl, session->dirty_out.data,
			       sizeof(session->dirty_out.data));
		if (err > 0) {
			session->dirty_out.used = err;
		} else {
			tls_error_log(request, session->ssl, err, "handshake_send");
		}
	}

	return 1;
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

static void session_close(tls_session_t *session)
{
	SSL_set_quiet_shutdown(session->ssl, 1);
	SSL_shutdown(session->ssl);

	if (session->ssl) {
		SSL_free(session->ssl);
		session->ssl = NULL;
	}

	record_close(&session->clean_in);
	record_close(&session->clean_out);
	record_close(&session->dirty_in);
	record_close(&session->dirty_out);
	session_init(session);
}

static void record_init(tls_record_t *rec)
{
	rec->used = 0;
}

static void record_close(tls_record_t *rec)
{
	rec->used = 0;
}


/** Copy data to the intermediate buffer, before we send it somewhere
 *
 */
static unsigned int record_from_buff(tls_record_t *record, void const *in, unsigned int inlen)
{
	unsigned int added = MAX_RECORD_SIZE - record->used;

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

void tls_session_information(tls_session_t *tls_session)
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
	if (request) {
		RDEBUG2("%s", tls_session->info.info_description);
	} else {
		DEBUG2("%s", tls_session->info.info_description);
	}
}

static CONF_PARSER cache_config[] = {
	{ FR_CONF_OFFSET("enable", PW_TYPE_BOOLEAN, fr_tls_server_conf_t, session_cache_enable), .dflt = "no" },

	{ FR_CONF_OFFSET("name", PW_TYPE_STRING, fr_tls_server_conf_t, session_id_name) },

	{ FR_CONF_OFFSET("virtual_server", PW_TYPE_STRING, fr_tls_server_conf_t, session_cache_server) },

	{ FR_CONF_OFFSET("lifetime", PW_TYPE_INTEGER, fr_tls_server_conf_t, session_timeout), .dflt = "24" },
	{ FR_CONF_OFFSET("max_entries", PW_TYPE_INTEGER, fr_tls_server_conf_t, session_cache_size), .dflt = "255" },
	{ FR_CONF_DEPRECATED("persist_dir", PW_TYPE_STRING | PW_TYPE_DEPRECATED, fr_tls_server_conf_t, NULL) },

	CONF_PARSER_TERMINATOR
};

static CONF_PARSER verify_config[] = {
	{ FR_CONF_OFFSET("tmpdir", PW_TYPE_STRING, fr_tls_server_conf_t, verify_tmp_dir) },
	{ FR_CONF_OFFSET("client", PW_TYPE_STRING, fr_tls_server_conf_t, verify_client_cert_cmd) },
	CONF_PARSER_TERMINATOR
};

#ifdef HAVE_OPENSSL_OCSP_H
static CONF_PARSER ocsp_config[] = {
	{ FR_CONF_OFFSET("enable", PW_TYPE_BOOLEAN, fr_tls_server_conf_t, ocsp_enable), .dflt = "no" },

	{ FR_CONF_OFFSET("virtual_server", PW_TYPE_STRING, fr_tls_server_conf_t, ocsp_cache_server) },

	{ FR_CONF_OFFSET("override_cert_url", PW_TYPE_BOOLEAN, fr_tls_server_conf_t, ocsp_override_url), .dflt = "no" },
	{ FR_CONF_OFFSET("url", PW_TYPE_STRING, fr_tls_server_conf_t, ocsp_url) },
	{ FR_CONF_OFFSET("use_nonce", PW_TYPE_BOOLEAN, fr_tls_server_conf_t, ocsp_use_nonce), .dflt = "yes" },
	{ FR_CONF_OFFSET("timeout", PW_TYPE_INTEGER, fr_tls_server_conf_t, ocsp_timeout), .dflt = "yes" },
	{ FR_CONF_OFFSET("softfail", PW_TYPE_BOOLEAN, fr_tls_server_conf_t, ocsp_softfail), .dflt = "no" },
	CONF_PARSER_TERMINATOR
};
#endif

static CONF_PARSER tls_server_config[] = {
	{ FR_CONF_OFFSET("verify_depth", PW_TYPE_INTEGER, fr_tls_server_conf_t, verify_depth), .dflt = "0" },
	{ FR_CONF_OFFSET("CA_path", PW_TYPE_FILE_INPUT | PW_TYPE_DEPRECATED, fr_tls_server_conf_t, ca_path) },
	{ FR_CONF_OFFSET("ca_path", PW_TYPE_FILE_INPUT, fr_tls_server_conf_t, ca_path) },
	{ FR_CONF_OFFSET("pem_file_type", PW_TYPE_BOOLEAN, fr_tls_server_conf_t, file_type), .dflt = "yes" },
	{ FR_CONF_OFFSET("private_key_file", PW_TYPE_FILE_INPUT, fr_tls_server_conf_t, private_key_file) },
	{ FR_CONF_OFFSET("certificate_file", PW_TYPE_FILE_INPUT, fr_tls_server_conf_t, certificate_file) },
	{ FR_CONF_OFFSET("CA_file", PW_TYPE_FILE_INPUT | PW_TYPE_DEPRECATED, fr_tls_server_conf_t, ca_file) },
	{ FR_CONF_OFFSET("ca_file", PW_TYPE_FILE_INPUT, fr_tls_server_conf_t, ca_file) },
	{ FR_CONF_OFFSET("private_key_password", PW_TYPE_STRING | PW_TYPE_SECRET, fr_tls_server_conf_t, private_key_password) },
#ifdef PSK_MAX_IDENTITY_LEN
	{ FR_CONF_OFFSET("psk_identity", PW_TYPE_STRING, fr_tls_server_conf_t, psk_identity) },
	{ FR_CONF_OFFSET("psk_hexphrase", PW_TYPE_STRING | PW_TYPE_SECRET, fr_tls_server_conf_t, psk_password) },
	{ FR_CONF_OFFSET("psk_query", PW_TYPE_STRING, fr_tls_server_conf_t, psk_query) },
#endif
	{ FR_CONF_OFFSET("dh_file", PW_TYPE_STRING, fr_tls_server_conf_t, dh_file) },
	{ FR_CONF_OFFSET("random_file", PW_TYPE_STRING, fr_tls_server_conf_t, random_file) },
	{ FR_CONF_OFFSET("fragment_size", PW_TYPE_INTEGER, fr_tls_server_conf_t, fragment_size), .dflt = "1024" },
	{ FR_CONF_OFFSET("include_length", PW_TYPE_BOOLEAN, fr_tls_server_conf_t, include_length), .dflt = "yes" },
	{ FR_CONF_OFFSET("auto_chain", PW_TYPE_BOOLEAN, fr_tls_server_conf_t, auto_chain), .dflt = "yes" },
	{ FR_CONF_OFFSET("disable_single_dh_use", PW_TYPE_BOOLEAN, fr_tls_server_conf_t, disable_single_dh_use) },
	{ FR_CONF_OFFSET("check_crl", PW_TYPE_BOOLEAN, fr_tls_server_conf_t, check_crl), .dflt = "no" },
#ifdef X509_V_FLAG_CRL_CHECK_ALL
	{ FR_CONF_OFFSET("check_all_crl", PW_TYPE_BOOLEAN, fr_tls_server_conf_t, check_all_crl), .dflt = "no" },
#endif
	{ FR_CONF_OFFSET("allow_expired_crl", PW_TYPE_BOOLEAN, fr_tls_server_conf_t, allow_expired_crl) },
	{ FR_CONF_OFFSET("check_cert_cn", PW_TYPE_STRING, fr_tls_server_conf_t, check_cert_cn) },
	{ FR_CONF_OFFSET("cipher_list", PW_TYPE_STRING, fr_tls_server_conf_t, cipher_list) },
	{ FR_CONF_OFFSET("check_cert_issuer", PW_TYPE_STRING, fr_tls_server_conf_t, check_cert_issuer) },
	{ FR_CONF_OFFSET("require_client_cert", PW_TYPE_BOOLEAN, fr_tls_server_conf_t, require_client_cert) },

#if OPENSSL_VERSION_NUMBER >= 0x0090800fL
#ifndef OPENSSL_NO_ECDH
	{ FR_CONF_OFFSET("ecdh_curve", PW_TYPE_STRING, fr_tls_server_conf_t, ecdh_curve), .dflt = "prime256v1" },
#endif
#endif

#ifdef SSL_OP_NO_TLSv1
	{ FR_CONF_OFFSET("disable_tlsv1", PW_TYPE_BOOLEAN, fr_tls_server_conf_t, disable_tlsv1) },
#endif

#ifdef SSL_OP_NO_TLSv1_1
	{ FR_CONF_OFFSET("disable_tlsv1_1", PW_TYPE_BOOLEAN, fr_tls_server_conf_t, disable_tlsv1_1) },
#endif

#ifdef SSL_OP_NO_TLSv1_2
	{ FR_CONF_OFFSET("disable_tlsv1_2", PW_TYPE_BOOLEAN, fr_tls_server_conf_t, disable_tlsv1_2) },
#endif

	{ FR_CONF_POINTER("cache", PW_TYPE_SUBSECTION, NULL), .dflt = (void const *) cache_config },

	{ FR_CONF_POINTER("verify", PW_TYPE_SUBSECTION, NULL), .dflt = (void const *) verify_config },

#ifdef HAVE_OPENSSL_OCSP_H
	{ FR_CONF_POINTER("ocsp", PW_TYPE_SUBSECTION, NULL), .dflt = (void const *) ocsp_config },
#endif
	CONF_PARSER_TERMINATOR
};


static CONF_PARSER tls_client_config[] = {
	{ FR_CONF_OFFSET("verify_depth", PW_TYPE_INTEGER, fr_tls_server_conf_t, verify_depth), .dflt = "0" },
	{ FR_CONF_OFFSET("ca_path", PW_TYPE_FILE_INPUT, fr_tls_server_conf_t, ca_path) },
	{ FR_CONF_OFFSET("pem_file_type", PW_TYPE_BOOLEAN, fr_tls_server_conf_t, file_type), .dflt = "yes" },
	{ FR_CONF_OFFSET("private_key_file", PW_TYPE_FILE_INPUT, fr_tls_server_conf_t, private_key_file) },
	{ FR_CONF_OFFSET("certificate_file", PW_TYPE_FILE_INPUT, fr_tls_server_conf_t, certificate_file) },
	{ FR_CONF_OFFSET("ca_file", PW_TYPE_FILE_INPUT, fr_tls_server_conf_t, ca_file) },
	{ FR_CONF_OFFSET("private_key_password", PW_TYPE_STRING | PW_TYPE_SECRET, fr_tls_server_conf_t, private_key_password) },
	{ FR_CONF_OFFSET("dh_file", PW_TYPE_STRING, fr_tls_server_conf_t, dh_file) },
	{ FR_CONF_OFFSET("random_file", PW_TYPE_STRING, fr_tls_server_conf_t, random_file) },
	{ FR_CONF_OFFSET("fragment_size", PW_TYPE_INTEGER, fr_tls_server_conf_t, fragment_size), .dflt = "1024" },
	{ FR_CONF_OFFSET("include_length", PW_TYPE_BOOLEAN, fr_tls_server_conf_t, include_length), .dflt = "yes" },
	{ FR_CONF_OFFSET("check_crl", PW_TYPE_BOOLEAN, fr_tls_server_conf_t, check_crl), .dflt = "no" },
	{ FR_CONF_OFFSET("check_cert_cn", PW_TYPE_STRING, fr_tls_server_conf_t, check_cert_cn) },
	{ FR_CONF_OFFSET("cipher_list", PW_TYPE_STRING, fr_tls_server_conf_t, cipher_list) },
	{ FR_CONF_OFFSET("check_cert_issuer", PW_TYPE_STRING, fr_tls_server_conf_t, check_cert_issuer) },

#if OPENSSL_VERSION_NUMBER >= 0x0090800fL
#ifndef OPENSSL_NO_ECDH
	{ FR_CONF_OFFSET("ecdh_curve", PW_TYPE_STRING, fr_tls_server_conf_t, ecdh_curve), .dflt = "prime256v1" },
#endif
#endif

#ifdef SSL_OP_NO_TLSv1
	{ FR_CONF_OFFSET("disable_tlsv1", PW_TYPE_BOOLEAN, fr_tls_server_conf_t, disable_tlsv1) },
#endif

#ifdef SSL_OP_NO_TLSv1_1
	{ FR_CONF_OFFSET("disable_tlsv1_1", PW_TYPE_BOOLEAN, fr_tls_server_conf_t, disable_tlsv1_1) },
#endif

#ifdef SSL_OP_NO_TLSv1_2
	{ FR_CONF_OFFSET("disable_tlsv1_2", PW_TYPE_BOOLEAN, fr_tls_server_conf_t, disable_tlsv1_2) },
#endif
	CONF_PARSER_TERMINATOR
};


/*
 *	TODO: Check for the type of key exchange * like conf->dh_key
 */
static int load_dh_params(SSL_CTX *ctx, char *file)
{
	DH *dh = NULL;
	BIO *bio;

	if (!file) return 0;

	if ((bio = BIO_new_file(file, "r")) == NULL) {
		ERROR(LOG_PREFIX ": Unable to open DH file - %s", file);
		return -1;
	}

	dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
	BIO_free(bio);
	if (!dh) {
		WARN(LOG_PREFIX ": Unable to set DH parameters.  DH cipher suites may not work!");
		WARN(LOG_PREFIX ": Fix this by generating the DH parameter file");
		return 0;
	}

	if (SSL_CTX_set_tmp_dh(ctx, dh) < 0) {
		ERROR(LOG_PREFIX ": Unable to set DH parameters");
		DH_free(dh);
		return -1;
	}

	DH_free(dh);
	return 0;
}

/** Macros that match the hardcoded values of the TLS-Session-Cache-Attribute
 */
typedef enum {
	CACHE_ACTION_SESSION_READ = 1,		//!< Retrieve session data from the cache.
	CACHE_ACTION_SESSION_WRITE = 2,		//!< Write session data to the cache.
	CACHE_ACTION_SESSION_DELETE = 3,	//!< Delete session data from the cache.
	CACHE_ACTION_OCSP_READ = 4,		//!< Read cached OCSP status.
	CACHE_ACTION_OCSP_WRITE = 5		//!< Write OCSP status.
} tls_cache_action_t;

/** Add attributes identifying the TLS session to be acted upon, and the action to be performed
 *
 * Adds the following attributes to the request:
 *
 *	- &control:TLS-Session-Identity
 *	- &control:TLS-Session-Cache-Action
 *
 * Session identity will contain the binary session key used to create, retrieve
 * and delete cache entries related to the SSL session.
 *
 * Session-Cache-Action will contain the action to be performed.  This is then
 * utilised by unlang policy (in a virtual server called with these attributes)
 * to perform different actions.
 *
 * @todo Add attribute representing session validity period.
 * @todo Move adding TLS-Session-Cache-Action to cache_process and remove it again after calling
 *	the virtual server.
 *
 * @param[in] request The current request.
 * @param[in] key Identifier for the session.
 * @param[in] key_len Length of the key.
 * @param[in] action being performed (written to &control:TLS-Session-Cache-Action).
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int cache_key_add(REQUEST *request, uint8_t *key, size_t key_len, tls_cache_action_t action)
{
	VALUE_PAIR *vp;

	fr_pair_delete_by_num(&request->config, PW_TLS_SESSION_IDENTITY, 0, TAG_ANY);
	fr_pair_delete_by_num(&request->config, PW_TLS_SESSION_CACHE_ACTION, 0, TAG_ANY);

	vp = fr_pair_afrom_num(request, PW_TLS_SESSION_IDENTITY, 0);
	if (!vp) return -1;

	fr_pair_value_memcpy(vp, key, key_len);
	fr_pair_add(&request->config, vp);

	vp = fr_pair_afrom_num(request, PW_TLS_SESSION_CACHE_ACTION, 0);
	if (!vp) return -1;

	vp->vp_integer = action;
	fr_pair_add(&request->config, vp);

	return 0;
}

/** Execute the virtual server configured to perform cache actions
 *
 * @param[in] request The current request.
 * @param[in] virtual_server Name of the virtual server to execute.
 * @param[in] autz_type The authorize sub-section to execute.
 * @return the rcode from the virtual server.
 */
static rlm_rcode_t cache_process(REQUEST *request, char const *virtual_server, int autz_type)
{
	rlm_rcode_t rcode;

	/*
	 *	Save the current status of the request.
	 */
	char const *server = request->server;
	char const *module = request->module;
	char const *component = request->component;

	/*
	 *	Run it through the appropriate virtual server.
	 */
	request->server = virtual_server;
	request->module = "cache";

	rcode = process_authorize(autz_type + 1000, request);

	/*
	 *	Restore the original status of the request.
	 */
	request->server = server;
	request->module = module;
	request->component = component;

	fr_pair_delete_by_num(&request->config, PW_TLS_SESSION_CACHE_ACTION, 0, TAG_ANY);

	return rcode;
}

/** Write a newly created session to the cache
 *
 * @param[in] ssl session state.
 * @param[in] sess to serialise and write to the cache.
 * @return 0.  What we return is not used by OpenSSL to indicate success or failure,
 *	but to indicate whether it should free its copy of the session data.
 */
static int cache_write_session(SSL *ssl, SSL_SESSION *sess)
{
	fr_tls_server_conf_t	*conf;
	REQUEST			*request;
	size_t			len, rcode;
	uint8_t			*p, *data = NULL;
	VALUE_PAIR		*vp;
	char			buffer[2 * MAX_SESSION_SIZE + 1];

	request = SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_REQUEST);
	conf = SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_CONF);

	tls_session_id(sess, buffer, MAX_SESSION_SIZE);

	if (cache_key_add(request, (uint8_t *) buffer, strlen(buffer), CACHE_ACTION_SESSION_WRITE) < 0) {
		RWDEBUG("Failed adding session key to the request");
		return 0;
	}

	/* find out what length data we need */
	len = i2d_SSL_SESSION(sess, NULL);
	if (len < 1) {
		/* something went wrong */
		RWDEBUG("Session serialisation failed, couldn't determine required buffer length");
		return 0;
	}

	/* alloc and convert to ASN.1 */
	data = talloc_array(NULL, uint8_t, len);
	if (!data) {
		RWDEBUG("Session serialisation failed, couldn't allocate buffer (%zd bytes)", len);
		return 0;
	}

	/* openssl mutates &p */
	p = data;
	rcode = i2d_SSL_SESSION(sess, &p);
	if (rcode != len) {
		RWDEBUG("Session serialisation failed");
		goto error;
	}

	/*
	 *	Put the SSL data into an attribute.
	 */
	vp = fr_pair_afrom_num(request->packet, PW_TLS_SESSION_DATA, 0);
	if (!vp) goto error;

	fr_pair_value_memsteal(vp, data);
	rdebug_pair(L_DBG_LVL_2, request, vp, "&request:");
	fr_pair_add(&request->packet->vps, vp);
	data = NULL;

	/*
	 *	Call the virtual server to write the session
	 */
	switch (cache_process(request, conf->session_cache_server, CACHE_ACTION_SESSION_WRITE)) {
	case RLM_MODULE_OK:
	case RLM_MODULE_UPDATED:
		break;

	default:
		RWDEBUG("Failed storing session data");
		break;
	}

	/*
	 *	Ensure that the session data can't be used by anyone else.
	 */
	fr_pair_delete_by_num(&request->config, PW_TLS_SESSION_DATA, 0, TAG_ANY);

error:
	if (data) talloc_free(data);

	return 0;
}

/** Read session data from the cache
 *
 * @param[in] ssl session state.
 * @param[in] key to retrieve session data for.
 * @param[in] key_len The length of the key.
 * @param[out] copy Indicates whether OpenSSL should increment the reference
 *	count on SSL_SESSION to prevent it being automatically freed.  We always
 *	set this to 0.
 * @return
 *	- Deserialised session data on success.
 *	- NULL on error.
 */
static SSL_SESSION *cache_read_session(SSL *ssl, unsigned char *key, int key_len, int *copy)
{
	fr_tls_server_conf_t	*conf;
	REQUEST			*request;
	unsigned char const	**p;
	uint8_t const		*q;
	VALUE_PAIR		*vp;
	SSL_SESSION		*sess;

	request = SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_REQUEST);
	conf = SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_CONF);

	if (cache_key_add(request, key, key_len, CACHE_ACTION_SESSION_READ) < 0) {
		RWDEBUG("Failed adding session key to the request");
		return NULL;
	}

	*copy = 0;

	/*
	 *	Call the virtual server to read the session
	 */
	switch (cache_process(request, conf->session_cache_server, CACHE_ACTION_SESSION_READ)) {
	case RLM_MODULE_OK:
	case RLM_MODULE_UPDATED:
		return NULL;

	default:
		RWDEBUG("Failed acquiring session data");
		break;
	}

	vp = fr_pair_find_by_num(request->config, PW_TLS_SESSION_DATA, 0, TAG_ANY);
	if (!vp) {
		RWDEBUG("No cached session found");
		return NULL;
	}

	q = vp->vp_octets;	/* openssl will mutate q, so we can't use vp_octets directly */
	p = (unsigned char const **)&q;

	sess = d2i_SSL_SESSION(NULL, p, vp->vp_length);
	if (!sess) {
		RWDEBUG("Failed loading persisted session: %s", ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}

	/*
	 *	Ensure that the session data can't be used by anyone else.
	 */
	fr_pair_delete_by_num(&request->config, PW_TLS_SESSION_DATA, 0, TAG_ANY);

	return sess;
}

/** Delete session data from the cache
 *
 * @param[in] ctx Current ssl context.
 * @param[in] sess to be deleted.
 */
static void cache_delete_session(SSL_CTX *ctx, SSL_SESSION *sess)
{
	fr_tls_server_conf_t	*conf;
	REQUEST			*request;
	char			buffer[2 * MAX_SESSION_SIZE + 1];

	conf = SSL_CTX_get_app_data(ctx);

	/*
	 *	We need a fake request for the virtual server, but we
	 *	don't have a parent request to base it on.  So just
	 *	invent one.
	 */
	request = request_alloc(NULL);
	request->packet = rad_alloc(request, false);
	request->reply = rad_alloc(request, false);

	tls_session_id(sess, buffer, MAX_SESSION_SIZE);

	if (cache_key_add(request, (uint8_t *) buffer, strlen(buffer), CACHE_ACTION_SESSION_DELETE) < 0) {
		RWDEBUG("Failed adding session key to the request");
	error:
		talloc_free(request);
		return;
	}

	/*
	 *	Call the virtual server to delete the session
	 */
	switch (cache_process(request, conf->session_cache_server, CACHE_ACTION_SESSION_DELETE)) {
	case RLM_MODULE_OK:
	case RLM_MODULE_UPDATED:
	case RLM_MODULE_NOTFOUND:
	case RLM_MODULE_NOOP:
		break;

	default:
		RWDEBUG("Failed deleting session data");
		goto error;
	}

	/*
	 *	Delete the fake request we created.
	 */
	talloc_free(request);
}

#define MAX_SESSION_SIZE (256)

#ifdef HAVE_OPENSSL_OCSP_H
/** Convert OpenSSL's ASN1_TIME to an epoch time
 *
 * @param asn1 The ASN1_TIME to convert.
 * @return The ASN1_TIME converted to epoch time.
 */
static time_t ocsp_asn1time_to_epoch(ASN1_TIME const *asn1){
	struct tm t;
	const char *str = (const char *)asn1->data;
	size_t i = 0;

	memset(&t, 0, sizeof(t));

	if (asn1->type == V_ASN1_UTCTIME) {/* two digit year */
		t.tm_year = (str[i++] - '0') * 10;
		t.tm_year += (str[i++] - '0');
		if (t.tm_year < 70) t.tm_year += 100;
	} else if (asn1->type == V_ASN1_GENERALIZEDTIME) {/* four digit year */
		t.tm_year = (str[i++] - '0') * 1000;
		t.tm_year += (str[i++] - '0') * 100;
		t.tm_year += (str[i++] - '0') * 10;
		t.tm_year += (str[i++] - '0');
		t.tm_year -= 1900;
	}

	t.tm_mon = (str[i++] - '0') * 10;
	t.tm_mon += (str[i++] - '0') - 1; // -1 since January is 0 not 1.
	t.tm_mday = (str[i++] - '0') * 10;
	t.tm_mday += (str[i++] - '0');
	t.tm_hour = (str[i++] - '0') * 10;
	t.tm_hour += (str[i++] - '0');
	t.tm_min = (str[i++] - '0') * 10;
	t.tm_min += (str[i++] - '0');
	t.tm_sec = (str[i++] - '0') * 10;
	t.tm_sec += (str[i++] - '0');

	/* Apparently OpenSSL converts all timestamps to UTC? Maybe? */
	return mktime(&t);
}

/** Extract components of OCSP responser URL from a certificate
 *
 * @param[in] cert to extract URL from.
 * @param[out] host_out Portion of the URL (must be freed with free()).
 * @param[out] port_out Port portion of the URL (must be freed with free()).
 * @param[out] path_out Path portion of the URL (must be freed with free()).
 * @param[out] is_https Whether the responder should be contacted using https.
 * @return
 *	- 0 if no valid URL is contained in the certificate.
 *	- 1 if a URL was found and parsed.
 *	- -1 if at least one URL was found, but none could be parsed.
 */
static int ocsp_parse_cert_url(X509 *cert, char **host_out, char **port_out, char **path_out, int *is_https)
{
	int			i;
	bool			found_uri = false;

	AUTHORITY_INFO_ACCESS	*aia;
	ACCESS_DESCRIPTION	*ad;

	aia = X509_get_ext_d2i(cert, NID_info_access, NULL, NULL);

	for (i = 0; i < sk_ACCESS_DESCRIPTION_num(aia); i++) {
		ad = sk_ACCESS_DESCRIPTION_value(aia, i);
		if (OBJ_obj2nid(ad->method) != NID_ad_OCSP) continue;
		if (ad->location->type != GEN_URI) continue;
		found_uri = true;

		if (OCSP_parse_url((char *) ad->location->d.ia5->data, host_out,
				   port_out, path_out, is_https)) return 1;
	}
	return found_uri ? -1 : 0;
}

/** Drain errors from an OpenSSL bio and print them to the error log
 *
 * @param _macro Logging macro e.g. RDEBUG.
 * @param _prefix Prefix, should be "" if not used.
 * @param _queue OpenSSL BIO.
 */
#define SSL_DRAIN_LOG_QUEUE(_macro, _prefix, _queue) \
do {\
	char const *_p, *_q; \
	size_t _len; \
	ERR_print_errors(_queue); \
	_len = BIO_get_mem_data(_queue, &_p); \
	if (_p && _len) for (_q = strchr(_p, '\n'); _q; _p = _q + 1, _q = strchr(_p, '\n')) { \
		_macro(_prefix "%.*s", (int)(_q - _p), _p); \
	} \
} while (0)

/* Maximum leeway in validity period: default 5 minutes */
#define MAX_VALIDITY_PERIOD     (5 * 60)

typedef enum {
	OCSP_STATUS_FAILED	= 0,
	OCSP_STATUS_OK		= 1,
	OCSP_STATUS_SKIPPED	= 2,
} ocsp_status_t;

/*
 * This function sends a OCSP request to a defined OCSP responder
 * and checks the OCSP response for correctness.
 */
static int ocsp_check(REQUEST *request, X509_STORE *store,
		      X509 *issuer_cert, X509 *client_cert,
		      fr_tls_server_conf_t *conf)
{
	OCSP_CERTID	*certid;
	OCSP_REQUEST	*req;
	OCSP_RESPONSE	*resp = NULL;
	OCSP_BASICRESP	*bresp = NULL;
	char		*host = NULL;
	char		*port = NULL;
	char		*path = NULL;
	char		host_header[1024];
	int		use_ssl = -1;
	long		this_fudge = MAX_VALIDITY_PERIOD, this_max_age = -1;
	BIO		*conn, *ssl_log = NULL;
	int		ocsp_status = 0;
	ocsp_status_t	status;
	ASN1_GENERALIZEDTIME *rev, *this_update, *next_update;
	int		reason;
#if OPENSSL_VERSION_NUMBER >= 0x1000003f
	OCSP_REQ_CTX	*ctx;
	int		rc;
	struct timeval	when;
#endif
	struct timeval	now = { 0, 0 };
	time_t		next;
	VALUE_PAIR	*vp;

	if (conf->ocsp_cache_server) switch (cache_process(request, conf->ocsp_cache_server,
							   CACHE_ACTION_OCSP_READ)) {
	case RLM_MODULE_REJECT:
		REDEBUG("Told to force OCSP validation failure by virtual server");
		return OCSP_STATUS_FAILED;

	case RLM_MODULE_OK:
	case RLM_MODULE_UPDATED:
	/*
	 *	These are fine for OCSP too, we dont' *expect* to always
	 *	have a cached OCSP status.
	 */
	case RLM_MODULE_NOTFOUND:
	case RLM_MODULE_NOOP:
		break;

	default:
		RWDEBUG("Failed retrieving cached OCSP status");
		break;
	}

	/*
	 *	Allow us to cache the OCSP verified state externally
	 */
	vp = fr_pair_find_by_num(request->config, PW_TLS_OCSP_CERT_VALID, 0, TAG_ANY);
	if (vp) switch (vp->vp_integer) {
	case 0:	/* no */
		RDEBUG2("Found &control:TLS-OCSP-Cert-Valid = no, forcing OCSP failure");
		return OCSP_STATUS_FAILED;

	case 1: /* yes */
		RDEBUG2("Found &control:TLS-OCSP-Cert-Valid = yes, forcing OCSP success");
		return OCSP_STATUS_OK;

	case 2: /* skipped */
		RDEBUG2("Found &control:TLS-OCSP-Cert-Valid = skipped, skipping OCSP check");
		return conf->ocsp_softfail ? OCSP_STATUS_OK : OCSP_STATUS_FAILED;

	case 3: /* unknown */
	default:
		break;
	}

	/*
	 *	Setup logging for this OCSP operation
	 */
	ssl_log = BIO_new(BIO_s_mem());

	/*
	 *	Create OCSP Request
	 */
	certid = OCSP_cert_to_id(NULL, client_cert, issuer_cert);
	req = OCSP_REQUEST_new();
	OCSP_request_add0_id(req, certid);
	if (conf->ocsp_use_nonce) OCSP_request_add1_nonce(req, NULL, 8);

	/*
	 * Send OCSP Request and get OCSP Response
	 */

	/* Get OCSP responder URL */
	if (conf->ocsp_override_url) {
		char *url;

	use_ocsp_url:
		memcpy(&url, &conf->ocsp_url, sizeof(url));
		/* Reading the libssl src, they do a strdup on the URL, so it could of been const *sigh* */
		OCSP_parse_url(url, &host, &port, &path, &use_ssl);
		if (!host || !port || !path) {
			RWDEBUG("ocsp: Host or port or path missing from configured URL \"%s\".  Not doing OCSP", url);
			goto skipped;
		}
	} else {
		int ret;

		ret = ocsp_parse_cert_url(client_cert, &host, &port, &path, &use_ssl);
		switch (ret) {
		case -1:
			RWDEBUG("ocsp: Invalid URL in certificate.  Not doing OCSP");
			break;

		case 0:
			if (conf->ocsp_url) {
				RWDEBUG("ocsp: No OCSP URL in certificate, falling back to configured URL");
				goto use_ocsp_url;
			}
			RWDEBUG("ocsp: No OCSP URL in certificate.  Not doing OCSP");
			goto skipped;

		case 1:
			rad_assert(host && port && path);
			break;
		}
	}

	RDEBUG2("ocsp: Using responder URL \"http://%s:%s%s\"", host, port, path);

	/* Check host and port length are sane, then create Host: HTTP header */
	if ((strlen(host) + strlen(port) + 2) > sizeof(host_header)) {
		RWDEBUG("ocsp: Host and port too long");
		goto skipped;
	}
	snprintf(host_header, sizeof(host_header), "%s:%s", host, port);

	/* Setup BIO socket to OCSP responder */
	conn = BIO_new_connect(host);
	BIO_set_conn_port(conn, port);

#if OPENSSL_VERSION_NUMBER < 0x1000003f
	BIO_do_connect(conn);

	/* Send OCSP request and wait for response */
	resp = OCSP_sendreq_bio(conn, path, req);
	if (!resp) {
		REDEBUG("ocsp: Couldn't get OCSP response");
		ocsp_status = OCSP_STATUS_SKIPPED;
		goto finish;
	}
#else
	if (conf->ocsp_timeout) BIO_set_nbio(conn, 1);

	rc = BIO_do_connect(conn);
	if ((rc <= 0) && ((!conf->ocsp_timeout) || !BIO_should_retry(conn))) {
		REDEBUG("ocsp: Couldn't connect to OCSP responder");
		SSL_DRAIN_LOG_QUEUE(REDEBUG, "ocsp: ", ssl_log);
		ocsp_status = OCSP_STATUS_SKIPPED;
		goto finish;
	}

	ctx = OCSP_sendreq_new(conn, path, NULL, -1);
	if (!ctx) {
		REDEBUG("ocsp: Couldn't create OCSP request");
		ocsp_status = OCSP_STATUS_SKIPPED;
		goto finish;
	}

	if (!OCSP_REQ_CTX_add1_header(ctx, "Host", host_header)) {
		REDEBUG("ocsp: Couldn't set Host header");
		ocsp_status = OCSP_STATUS_SKIPPED;
		goto finish;
	}

	if (!OCSP_REQ_CTX_set1_req(ctx, req)) {
		REDEBUG("ocsp: Couldn't add data to OCSP request");
		ocsp_status = OCSP_STATUS_SKIPPED;
		goto finish;
	}

	gettimeofday(&when, NULL);
	when.tv_sec += conf->ocsp_timeout;

	do {
		rc = OCSP_sendreq_nbio(&resp, ctx);
		if (conf->ocsp_timeout) {
			gettimeofday(&now, NULL);
			if (!timercmp(&now, &when, <)) break;
		}
	} while ((rc == -1) && BIO_should_retry(conn));

	if (conf->ocsp_timeout && (rc == -1) && BIO_should_retry(conn)) {
		REDEBUG("ocsp: Response timed out");
		ocsp_status = OCSP_STATUS_SKIPPED;
		goto finish;
	}

	OCSP_REQ_CTX_free(ctx);

	if (rc == 0) {
		REDEBUG("ocsp: Couldn't get OCSP response");
		SSL_DRAIN_LOG_QUEUE(REDEBUG, "ocsp: ", ssl_log);
		ocsp_status = OCSP_STATUS_SKIPPED;
		goto finish;
	}
#endif

	/* Verify OCSP response status */
	status = OCSP_response_status(resp);
	if (status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
		REDEBUG("ocsp: Response status: %s", OCSP_response_status_str(status));
		goto finish;
	}
	bresp = OCSP_response_get1_basic(resp);
	if (conf->ocsp_use_nonce && OCSP_check_nonce(req, bresp)!=1) {
		REDEBUG("ocsp: Response has wrong nonce value");
		goto finish;
	}
	if (OCSP_basic_verify(bresp, NULL, store, 0)!=1){
		REDEBUG("ocsp: Couldn't verify OCSP basic response");
		goto finish;
	}

	/*	Verify OCSP cert status */
	if (!OCSP_resp_find_status(bresp, certid, (int *)&status, &reason, &rev, &this_update, &next_update)) {
		REDEBUG("ocsp: No Status found");
		goto finish;
	}

	/*
	 *	Here we check the fields 'thisUpdate' and 'nextUpdate'
	 *	from the OCSP response against the server's time.
	 *
	 *	this_fudge is the number of seconds +- between the current
	 *	time and this_update.
	 *
	 *	The default for this_fudge is 300, defined by MAX_VALIDITY_PERIOD.
	 */
	if (!OCSP_check_validity(this_update, next_update, this_fudge, this_max_age)) {
		/*
		 *	We want this to show up in the global log
		 *	so someone will fix it...
		 */
		RATE_LIMIT(RERROR("ocsp: Delta +/- between OCSP response time and our time is greater than %li "
				  "seconds.  Check servers are synchronised to a common time source",
				  this_fudge));
		SSL_DRAIN_LOG_QUEUE(REDEBUG, "ocsp: ", ssl_log);
		goto finish;
	}

	/*
	 *	Print any messages we may have accumulated
	 */
	SSL_DRAIN_LOG_QUEUE(RDEBUG, "ocsp: ", ssl_log);
	if (RDEBUG_ENABLED) {
		RDEBUG2("ocsp: OCSP response valid from:");
		ASN1_GENERALIZEDTIME_print(ssl_log, this_update);
		RINDENT();
		SSL_DRAIN_LOG_QUEUE(RDEBUG2, "", ssl_log);
		REXDENT();

		RDEBUG2("ocsp: New information available at:");
		ASN1_GENERALIZEDTIME_print(ssl_log, next_update);
		RINDENT();
		SSL_DRAIN_LOG_QUEUE(RDEBUG2, "", ssl_log);
		REXDENT();
	}

	/*
	 *	Sometimes we already know what 'now' is depending
	 *	on the code path, other times we don't.
	 */
	if (now.tv_sec == 0) gettimeofday(&now, NULL);
	next = ocsp_asn1time_to_epoch(next_update);
	if (now.tv_sec < next){
		vp = pair_make_reply("TLS-OCSP-Next-Update", NULL, T_OP_SET);
		vp->vp_integer = next - now.tv_sec;
		rdebug_pair(L_DBG_LVL_2, request, vp, "ocsp:");
	} else {
		RDEBUG2("ocsp: Update time is in the past.  Not adding &reply:TLS-OCSP-Next-Update");
	}

	switch (status) {
	case V_OCSP_CERTSTATUS_GOOD:
		RDEBUG2("ocsp: Cert status: good");
		ocsp_status = OCSP_STATUS_OK;
		break;

	default:
		/* REVOKED / UNKNOWN */
		REDEBUG("ocsp: Cert status: %s", OCSP_cert_status_str(status));
		if (reason != -1) REDEBUG("ocsp: Reason: %s", OCSP_crl_reason_str(reason));

		/*
		 *	Print any messages we may have accumulated
		 */
		SSL_DRAIN_LOG_QUEUE(RDEBUG, "ocsp: ", ssl_log);
		if (RDEBUG_ENABLED) {
			RDEBUG2("ocsp: Revocation time:");
			ASN1_GENERALIZEDTIME_print(ssl_log, rev);
			RINDENT();
			SSL_DRAIN_LOG_QUEUE(RDEBUG2, "", ssl_log);
			REXDENT();
		}
		break;
	}

finish:
	/* Free OCSP Stuff */
	OCSP_REQUEST_free(req);
	OCSP_RESPONSE_free(resp);
	free(host);
	free(port);
	free(path);
	BIO_free_all(conn);
	BIO_free(ssl_log);
	OCSP_BASICRESP_free(bresp);

	switch (ocsp_status) {
	case OCSP_STATUS_OK:
		RDEBUG2("ocsp: Certificate is valid");
		vp = pair_make_request("TLS-OCSP-Cert-Valid", NULL, T_OP_SET);
		vp->vp_integer = 1;	/* yes */
		ocsp_status = OCSP_STATUS_OK;
		break;

	case OCSP_STATUS_SKIPPED:
	skipped:
		vp = pair_make_request("TLS-OCSP-Cert-Valid", NULL, T_OP_SET);
		vp->vp_integer = 2;	/* skipped */
		if (conf->ocsp_softfail) {
			RWDEBUG("ocsp: Unable to check certificate, assuming it's valid");
			RWDEBUG("ocsp: This may be insecure");
			ocsp_status = OCSP_STATUS_OK;
		} else {
			REDEBUG("ocsp: Unable to check certificate, failing");
			ocsp_status = OCSP_STATUS_FAILED;
		}
		break;

	default:
		vp = pair_make_request("TLS-OCSP-Cert-Valid", NULL, T_OP_SET);
		vp->vp_integer = 0;	/* no */
		REDEBUG("ocsp: Failed to validate certificate");
		break;
	}

	if (conf->ocsp_cache_server) switch (cache_process(request, conf->ocsp_cache_server, CACHE_ACTION_OCSP_WRITE)) {
	case RLM_MODULE_OK:
	case RLM_MODULE_UPDATED:
		break;

	default:
		RWDEBUG("Failed writing cached OCSP status");
		break;
	}

	return ocsp_status;
}
#endif	/* HAVE_OPENSSL_OCSP_H */

/*
 *	For creating certificate attributes.
 */
static char const *cert_attr_names[8][2] = {
	{ "TLS-Client-Cert-Serial",			"TLS-Cert-Serial" },
	{ "TLS-Client-Cert-Expiration",			"TLS-Cert-Expiration" },
	{ "TLS-Client-Cert-Subject",			"TLS-Cert-Subject" },
	{ "TLS-Client-Cert-Issuer",			"TLS-Cert-Issuer" },
	{ "TLS-Client-Cert-Common-Name",		"TLS-Cert-Common-Name" },
	{ "TLS-Client-Cert-Subject-Alt-Name-Email",	"TLS-Cert-Subject-Alt-Name-Email" },
	{ "TLS-Client-Cert-Subject-Alt-Name-Dns",	"TLS-Cert-Subject-Alt-Name-Dns" },
	{ "TLS-Client-Cert-Subject-Alt-Name-Upn",	"TLS-Cert-Subject-Alt-Name-Upn" }
};

#define FR_TLS_SERIAL		(0)
#define FR_TLS_EXPIRATION	(1)
#define FR_TLS_SUBJECT		(2)
#define FR_TLS_ISSUER		(3)
#define FR_TLS_CN		(4)
#define FR_TLS_SAN_EMAIL       	(5)
#define FR_TLS_SAN_DNS          (6)
#define FR_TLS_SAN_UPN          (7)

/*
 *	Before trusting a certificate, you must make sure that the
 *	certificate is 'valid'. There are several steps that your
 *	application can take in determining if a certificate is
 *	valid. Commonly used steps are:
 *
 *	1.Verifying the certificate's signature, and verifying that
 *	the certificate has been issued by a trusted Certificate
 *	Authority.
 *
 *	2.Verifying that the certificate is valid for the present date
 *	(i.e. it is being presented within its validity dates).
 *
 *	3.Verifying that the certificate has not been revoked by its
 *	issuing Certificate Authority, by checking with respect to a
 *	Certificate Revocation List (CRL).
 *
 *	4.Verifying that the credentials presented by the certificate
 *	fulfill additional requirements specific to the application,
 *	such as with respect to access control lists or with respect
 *	to OCSP (Online Certificate Status Processing).
 *
 *	NOTE: This callback will be called multiple times based on the
 *	depth of the root certificate chain
 */
int cbtls_verify(int ok, X509_STORE_CTX *ctx)
{
	char		subject[1024]; /* Used for the subject name */
	char		issuer[1024]; /* Used for the issuer name */
	char		attribute[1024];
	char		value[1024];
	char		common_name[1024];
	char		cn_str[1024];
	char		buf[64];
	X509		*client_cert;
	X509_CINF	*client_inf;
	STACK_OF(X509_EXTENSION) *ext_list;
	SSL		*ssl;
	int		err, depth, lookup, loc;
	fr_tls_server_conf_t *conf;
	int		my_ok = ok;

	ASN1_INTEGER	*sn = NULL;
	ASN1_TIME	*asn_time = NULL;
	VALUE_PAIR	*cert_vps = NULL;
	vp_cursor_t	cursor;

	char **identity;
#ifdef HAVE_OPENSSL_OCSP_H
	X509_STORE	*ocsp_store = NULL;
	X509		*issuer_cert;
#endif
	VALUE_PAIR	*vp;

	REQUEST		*request;

#define ADD_CERT_ATTR(_name, _value) \
do { \
	VALUE_PAIR *_vp; \
	_vp = fr_pair_make(request, NULL, _name, _value, T_OP_SET); \
	if (_vp) { \
		fr_cursor_insert(&cursor, _vp); \
	} else { \
		RWDEBUG("Failed creating attribute %s: %s", _name, fr_strerror()); \
	} \
} while (0)

	client_cert = X509_STORE_CTX_get_current_cert(ctx);
	err = X509_STORE_CTX_get_error(ctx);
	depth = X509_STORE_CTX_get_error_depth(ctx);

	lookup = depth;

	/*
	 *	Log client/issuing cert.  If there's an error, log
	 *	issuing cert.
	 */
	if ((lookup > 1) && !my_ok) lookup = 1;

	/*
	 *	Retrieve the pointer to the SSL of the connection currently treated
	 *	and the application specific data stored into the SSL object.
	 */
	ssl = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
	conf = (fr_tls_server_conf_t *)SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_CONF);
	if (!conf) return 1;

	request = (REQUEST *)SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_REQUEST);
	rad_assert(request != NULL);

	fr_cursor_init(&cursor, &cert_vps);

	identity = (char **)SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_IDENTITY);
#ifdef HAVE_OPENSSL_OCSP_H
	ocsp_store = (X509_STORE *)SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_STORE);
#endif

	/*
	 *	Get the Serial Number
	 */
	buf[0] = '\0';
	sn = X509_get_serialNumber(client_cert);

	RDEBUG2("Creating attributes from certificate OIDs");

	/*
	 *	For this next bit, we create the attributes *only* if
	 *	we're at the client or issuing certificate, AND we
	 *	have a user identity.  i.e. we don't create the
	 *	attributes for RadSec connections.
	 */
	if (identity && (lookup <= 1) && sn && ((size_t) sn->length < (sizeof(buf) / 2))) {
		char *p = buf;
		int i;

		for (i = 0; i < sn->length; i++) {
			sprintf(p, "%02x", (unsigned int)sn->data[i]);
			p += 2;
		}
		ADD_CERT_ATTR(cert_attr_names[FR_TLS_SERIAL][lookup], buf);
	}


	/*
	 *	Get the Expiration Date
	 */
	buf[0] = '\0';
	asn_time = X509_get_notAfter(client_cert);
	if (identity && (lookup <= 1) && asn_time && (asn_time->length < (int) sizeof(buf))) {
		memcpy(buf, (char*) asn_time->data, asn_time->length);
		buf[asn_time->length] = '\0';
		ADD_CERT_ATTR(cert_attr_names[FR_TLS_EXPIRATION][lookup], buf);
	}

	/*
	 *	Get the Subject & Issuer
	 */
	subject[0] = issuer[0] = '\0';
	X509_NAME_oneline(X509_get_subject_name(client_cert), subject,
			  sizeof(subject));
	subject[sizeof(subject) - 1] = '\0';
	if (identity && (lookup <= 1) && subject[0]) {
		ADD_CERT_ATTR(cert_attr_names[FR_TLS_SUBJECT][lookup], subject);
	}

	X509_NAME_oneline(X509_get_issuer_name(ctx->current_cert), issuer,
			  sizeof(issuer));
	issuer[sizeof(issuer) - 1] = '\0';
	if (identity && (lookup <= 1) && issuer[0]) {
		ADD_CERT_ATTR(cert_attr_names[FR_TLS_ISSUER][lookup], issuer);
	}

	/*
	 *	Get the Common Name, if there is a subject.
	 */
	X509_NAME_get_text_by_NID(X509_get_subject_name(client_cert),
				  NID_commonName, common_name, sizeof(common_name));
	common_name[sizeof(common_name) - 1] = '\0';
	if (identity && (lookup <= 1) && common_name[0] && subject[0]) {
		ADD_CERT_ATTR(cert_attr_names[FR_TLS_CN][lookup], common_name);
	}

	/*
	 *	Get the RFC822 Subject Alternative Name
	 */
	loc = X509_get_ext_by_NID(client_cert, NID_subject_alt_name, 0);
	if ((lookup <= 1) && (loc >= 0)) {
		X509_EXTENSION *ext = NULL;
		GENERAL_NAMES *names = NULL;
		int i;

		if ((ext = X509_get_ext(client_cert, loc)) &&
		    (names = X509V3_EXT_d2i(ext))) {
			for (i = 0; i < sk_GENERAL_NAME_num(names); i++) {
				GENERAL_NAME *name = sk_GENERAL_NAME_value(names, i);

				switch (name->type) {
#ifdef GEN_EMAIL
				case GEN_EMAIL:
					ADD_CERT_ATTR(cert_attr_names[FR_TLS_SAN_EMAIL][lookup],
						      (char *) ASN1_STRING_data(name->d.rfc822Name));
					break;
#endif	/* GEN_EMAIL */
#ifdef GEN_DNS
				case GEN_DNS:
					ADD_CERT_ATTR(cert_attr_names[FR_TLS_SAN_DNS][lookup],
						      (char *) ASN1_STRING_data(name->d.dNSName));
					break;
#endif	/* GEN_DNS */
#ifdef GEN_OTHERNAME
				case GEN_OTHERNAME:
					/* look for a MS UPN */
					if (NID_ms_upn != OBJ_obj2nid(name->d.otherName->type_id)) break;

					/* we've got a UPN - Must be ASN1-encoded UTF8 string */
					if (name->d.otherName->value->type == V_ASN1_UTF8STRING) {
						ADD_CERT_ATTR(cert_attr_names[FR_TLS_SAN_UPN][lookup],
							      (char *) name->d.otherName->value->value.utf8string);
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
		if (names != NULL) sk_GENERAL_NAME_free(names);
	}

	/*
	 *	If the CRL has expired, that might still be OK.
	 */
	if (!my_ok &&
	    (conf->allow_expired_crl) &&
	    (err == X509_V_ERR_CRL_HAS_EXPIRED)) {
		my_ok = 1;
		X509_STORE_CTX_set_error( ctx, 0 );
	}

	if (!my_ok) {
		char const *p = X509_verify_cert_error_string(err);
		RERROR("TLS error: %s (%i)", p, err);
		REXDENT();
		fr_pair_list_free(&cert_vps);
		return my_ok;
	}

	if (lookup == 0) {
		client_inf = client_cert->cert_info;
		ext_list = client_inf->extensions;
	} else {
		ext_list = NULL;
	}

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
			ASN1_OBJECT *obj;
			X509_EXTENSION *ext;

			ext = sk_X509_EXTENSION_value(ext_list, i);

			obj = X509_EXTENSION_get_object(ext);
			i2a_ASN1_OBJECT(out, obj);
			len = BIO_read(out, attribute + 16 , sizeof(attribute) - 16 - 1);
			if (len <= 0) continue;

			attribute[16 + len] = '\0';

			for (p = attribute + 16; *p != '\0'; p++) {
				if (*p == ' ') *p = '-';
			}

			X509V3_EXT_print(out, ext, 0, 0);
			len = BIO_read(out, value , sizeof(value) - 1);
			if (len <= 0) continue;

			value[len] = '\0';

			vp = fr_pair_make(request, NULL, attribute, value, T_OP_ADD);
			if (!vp) {
				RDEBUG3("Skipping %s += '%s'.  Please check that both the "
					"attribute and value are defined in the dictionaries",
					attribute, value);
			} else {
				fr_cursor_insert(&cursor, vp);
			}
		}

		BIO_free_all(out);
	}

	/*
	 *	Add a copy of the cert_vps to session state.
	 */
	if (cert_vps) {
		/*
		 *	Print out all the pairs we have so far
		 */
		rdebug_pair_list(L_DBG_LVL_2, request, cert_vps, "&session-state:");

		/*
		 *	cert_vps have a different talloc parent, so we
		 *	can't just reference them.
		 */
		fr_pair_list_mcopy_by_num(request->state_ctx, &request->state, &cert_vps, 0, 0, TAG_ANY);
		fr_pair_list_free(&cert_vps);
	}

	switch (ctx->error) {
	case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
		RERROR("issuer=%s", issuer);
		break;

	case X509_V_ERR_CERT_NOT_YET_VALID:
	case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
		RERROR("notBefore=");
#if 0
		ASN1_TIME_print(bio_err, X509_get_notBefore(ctx->current_cert));
#endif
		break;

	case X509_V_ERR_CERT_HAS_EXPIRED:
	case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
		RERROR("notAfter=");
#if 0
		ASN1_TIME_print(bio_err, X509_get_notAfter(ctx->current_cert));
#endif
		break;
	}

	/*
	 *	If we're at the actual client cert, apply additional
	 *	checks.
	 */
	if (depth == 0) {
		/*
		 *	If the conf tells us to, check cert issuer
		 *	against the specified value and fail
		 *	verification if they don't match.
		 */
		if (conf->check_cert_issuer &&
		    (strcmp(issuer, conf->check_cert_issuer) != 0)) {
			AUTH(LOG_PREFIX ": Certificate issuer (%s) does not match specified value (%s)!",
			     issuer, conf->check_cert_issuer);
			my_ok = 0;
		}

		/*
		 *	If the conf tells us to, check the CN in the
		 *	cert against xlat'ed value, but only if the
		 *	previous checks passed.
		 */
		if (my_ok && conf->check_cert_cn) {
			if (radius_xlat(cn_str, sizeof(cn_str), request, conf->check_cert_cn, NULL, NULL) < 0) {
				/* if this fails, fail the verification */
				my_ok = 0;
			} else {
				RDEBUG2("checking certificate CN (%s) with xlat'ed value (%s)", common_name, cn_str);
				if (strcmp(cn_str, common_name) != 0) {
					AUTH(LOG_PREFIX ": Certificate CN (%s) does not match specified value (%s)!",
					     common_name, cn_str);
					my_ok = 0;
				}
			}
		} /* check_cert_cn */

		while (conf->verify_client_cert_cmd) {
			char filename[256];
			int fd;
			FILE *fp;

			snprintf(filename, sizeof(filename), "%s/%s.client.XXXXXXXX",
				 conf->verify_tmp_dir, progname);
			fd = mkstemp(filename);
			if (fd < 0) {
				RDEBUG("Failed creating file in %s: %s",
				       conf->verify_tmp_dir, fr_syserror(errno));
				break;
			}

			fp = fdopen(fd, "w");
			if (!fp) {
				close(fd);
				RDEBUG("Failed opening file %s: %s",
				       filename, fr_syserror(errno));
				break;
			}

			if (!PEM_write_X509(fp, client_cert)) {
				fclose(fp);
				RDEBUG("Failed writing certificate to file");
				goto do_unlink;
			}
			fclose(fp);

			if (!pair_make_request("TLS-Client-Cert-Filename",
					     filename, T_OP_SET)) {
				RDEBUG("Failed creating TLS-Client-Cert-Filename");

				goto do_unlink;
			}

			RDEBUG("Verifying client certificate: %s", conf->verify_client_cert_cmd);
			if (radius_exec_program(request, NULL, 0, NULL, request, conf->verify_client_cert_cmd,
						request->packet->vps,
						true, true, EXEC_TIMEOUT) != 0) {
				AUTH(LOG_PREFIX ": Certificate CN (%s) fails external verification!", common_name);
				my_ok = 0;
			} else {
				RDEBUG("Client certificate CN %s passed external validation", common_name);
			}

		do_unlink:
			unlink(filename);
			break;
		}

#ifdef HAVE_OPENSSL_OCSP_H
		/*
		 *	Do OCSP last, so we have the complete set of attributes
		 *	available for the virtual server.
		 *
		 *	Fixme: Do we want to store the matching TLS-Client-cert-Filename?
		 */
		if (my_ok && conf->ocsp_enable){
			RDEBUG2("Starting OCSP Request");
			if (X509_STORE_CTX_get1_issuer(&issuer_cert, ctx, client_cert) != 1) {
				RERROR("Couldn't get issuer_cert for %s", common_name);
			} else {
				my_ok = ocsp_check(request, ocsp_store, issuer_cert, client_cert, conf);
			}
		}
#endif
	} /* depth == 0 */

	if (RDEBUG_ENABLED3) {
		RDEBUG3("chain-depth   : %d", depth);
		RDEBUG3("error         : %d", err);

		if (identity) RDEBUG3("identity      : %s", *identity);
		RDEBUG3("common name   : %s", common_name);
		RDEBUG3("subject       : %s", subject);
		RDEBUG3("issuer        : %s", issuer);
		RDEBUG3("verify return : %d", my_ok);
	}
	return my_ok;
}


#ifdef HAVE_OPENSSL_OCSP_H
/*
 * 	Create Global X509 revocation store and use it to verify
 * 	OCSP responses
 *
 * 	- Load the trusted CAs
 * 	- Load the trusted issuer certificates
 */
static X509_STORE *init_revocation_store(fr_tls_server_conf_t *conf)
{
	X509_STORE *store = NULL;

	store = X509_STORE_new();

	/* Load the CAs we trust */
	if (conf->ca_file || conf->ca_path)
		if(!X509_STORE_load_locations(store, conf->ca_file, conf->ca_path)) {
			ERROR(LOG_PREFIX ": X509_STORE error %s", ERR_error_string(ERR_get_error(), NULL));
			ERROR(LOG_PREFIX ": Error reading Trusted root CA list %s",conf->ca_file );
			return NULL;
		}

#ifdef X509_V_FLAG_CRL_CHECK
	if (conf->check_crl)
		X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
#endif
#ifdef X509_V_FLAG_CRL_CHECK_ALL
	if (conf->check_all_crl)
		X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK_ALL);
#endif
	return store;
}
#endif	/* HAVE_OPENSSL_OCSP_H */

#if OPENSSL_VERSION_NUMBER >= 0x0090800fL
#ifndef OPENSSL_NO_ECDH
static int set_ecdh_curve(SSL_CTX *ctx, char const *ecdh_curve, bool disable_single_dh_use)
{
	int      nid;
	EC_KEY  *ecdh;

	if (!ecdh_curve || !*ecdh_curve) return 0;

	nid = OBJ_sn2nid(ecdh_curve);
	if (!nid) {
		ERROR(LOG_PREFIX ": Unknown ecdh_curve \"%s\"", ecdh_curve);
		return -1;
	}

	ecdh = EC_KEY_new_by_curve_name(nid);
	if (!ecdh) {
		ERROR(LOG_PREFIX ": Unable to create new curve \"%s\"", ecdh_curve);
		return -1;
	}

	SSL_CTX_set_tmp_ecdh(ctx, ecdh);

	if (!disable_single_dh_use) {
		SSL_CTX_set_options(ctx, SSL_OP_SINGLE_ECDH_USE);
	}

	EC_KEY_free(ecdh);

	return 0;
}
#endif
#endif

/** Add all the default ciphers and message digests reate our context.
 *
 * This should be called exactly once from main, before reading the main config
 * or initialising any modules.
 */
void tls_global_init(void)
{
	ENGINE *rand_engine;

	if (tls_done_init) return;

	SSL_load_error_strings();	/* Readable error messages (examples show call before library_init) */
	SSL_library_init();		/* Initialize library */
	OpenSSL_add_all_algorithms();	/* Required for SHA2 in OpenSSL < 0.9.8o and 1.0.0.a */
	ENGINE_load_builtin_engines();	/* Needed to load AES-NI engine (also loads rdrand, boo) */

	/*
	 *	SHA256 is in all versions of OpenSSL, but isn't
	 *	initialized by default.  It's needed for WiMAX
	 *	certificates.
	 */
#ifdef HAVE_OPENSSL_EVP_SHA256
	EVP_add_digest(EVP_sha256());
#endif
	OPENSSL_config(NULL);

	/*
	 *	Mirror the paranoia found elsewhere on the net,
	 *	and disable rdrand as the default random number
	 *	generator.
	 */
	rand_engine = ENGINE_get_default_RAND();
	if (rand_engine && (strcmp(ENGINE_get_id(rand_engine), "rdrand") == 0)) ENGINE_unregister_RAND(rand_engine);
	ENGINE_register_all_complete();

	tls_done_init = true;
}

#ifdef ENABLE_OPENSSL_VERSION_CHECK
/** Check for vulnerable versions of libssl
 *
 * @param acknowledged The highest CVE number a user has confirmed is not present in the system's
 *	libssl.
 * @return 0 if the CVE specified by the user matches the most recent CVE we have, else -1.
 */
int tls_global_version_check(char const *acknowledged)
{
	uint64_t v;

	if ((strcmp(acknowledged, libssl_defects[0].id) != 0) && (strcmp(acknowledged, "yes") != 0)) {
		bool bad = false;
		size_t i;

		/* Check for bad versions */
		v = (uint64_t) SSLeay();

		for (i = 0; i < (sizeof(libssl_defects) / sizeof(*libssl_defects)); i++) {
			libssl_defect_t *defect = &libssl_defects[i];

			if ((v >= defect->low) && (v <= defect->high)) {
				ERROR("Refusing to start with libssl version %s (in range %s)",
				      ssl_version(), ssl_version_range(defect->low, defect->high));
				ERROR("Security advisory %s (%s)", defect->id, defect->name);
				ERROR("%s", defect->comment);

				bad = true;
			}
		}

		if (bad) {
			INFO("Once you have verified libssl has been correctly patched, "
			     "set security.allow_vulnerable_openssl = '%s'", libssl_defects[0].id);
			return -1;
		}
	}

	return 0;
}
#endif

/** Free any memory alloced by libssl
 *
 */
void tls_global_cleanup(void)
{
	ERR_remove_state(0);
	ENGINE_cleanup();
	CONF_modules_unload(1);
	ERR_free_strings();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();

	tls_done_init = false;
}

#ifdef __APPLE__
/** Use certadmin to retrieve the password for the private key
 *
 */
static int tls_certadmin_password(fr_tls_server_conf_t *conf)
{
	if (!conf->private_key_password) return 0;

	/*
	 * Set the password to load private key
	 */

	/*
	 * We don't want to put the private key password in eap.conf, so  check
	 * for our special string which indicates we should get the password
	 * programmatically.
	 */
	char const* special_string = "Apple:UseCertAdmin";
	if (strncmp(conf->private_key_password, special_string, strlen(special_string)) == 0) {
		char cmd[256];
		char *password;
		long const max_password_len = 128;
		snprintf(cmd, sizeof(cmd) - 1, "/usr/sbin/certadmin --get-private-key-passphrase \"%s\"",
			 conf->private_key_file);

		DEBUG2(LOG_PREFIX ":  Getting private key passphrase using command \"%s\"", cmd);

		FILE* cmd_pipe = popen(cmd, "r");
		if (!cmd_pipe) {
			ERROR(LOG_PREFIX ": %s command failed: Unable to get private_key_password", cmd);
			ERROR(LOG_PREFIX ": Error reading private_key_file %s", conf->private_key_file);
			return -1;
		}

		rad_const_free(conf->private_key_password);
		password = talloc_array(conf, char, max_password_len);
		if (!password) {
			ERROR(LOG_PREFIX ": Can't allocate space for private_key_password");
			ERROR(LOG_PREFIX ": Error reading private_key_file %s", conf->private_key_file);
			pclose(cmd_pipe);
			return -1;
		}

		fgets(password, max_password_len, cmd_pipe);
		pclose(cmd_pipe);

		/* Get rid of newline at end of password. */
		password[strlen(password) - 1] = '\0';

		DEBUG3(LOG_PREFIX ": Password from command = \"%s\"", password);
		conf->private_key_password = password;
	}

	return 0;
}
#endif

/** Create SSL context
 *
 * - Load the trusted CAs
 * - Load the Private key & the certificate
 * - Set the Context options & Verify options
 */
SSL_CTX *tls_init_ctx(fr_tls_server_conf_t const *conf, bool client)
{
	SSL_CTX		*ctx;
	X509_STORE	*cert_vpstore;
	int		verify_mode = SSL_VERIFY_NONE;
	int		ctx_options = 0;
	int		ctx_tls_versions = 0;
	int		type;
	void		*app_data_index;

	ctx = SSL_CTX_new(SSLv23_method()); /* which is really "all known SSL / TLS methods".  Idiots. */
	if (!ctx) {
		int err;
		while ((err = ERR_get_error())) {
			ERROR(LOG_PREFIX ": Failed creating TLS context: %s", ERR_error_string(err, NULL));
			return NULL;
		}
	}

	/*
	 * Save the config on the context so that callbacks which
	 * only get SSL_CTX* e.g. session persistence, can get it
	 */
	memcpy(&app_data_index, &conf, sizeof(app_data_index));
	SSL_CTX_set_app_data(ctx, app_data_index);

	/*
	 * Identify the type of certificates that needs to be loaded
	 */
	if (conf->file_type) {
		type = SSL_FILETYPE_PEM;
	} else {
		type = SSL_FILETYPE_ASN1;
	}

	/*
	 *	Set the private key password (this should have been retrieved earlier)
	 */
	{
		char *password;

		memcpy(&password, &conf->private_key_password, sizeof(password));
		SSL_CTX_set_default_passwd_cb_userdata(ctx, password);
		SSL_CTX_set_default_passwd_cb(ctx, cbtls_password);
	}

#ifdef PSK_MAX_IDENTITY_LEN
	if (!client) {
		/*
		 *	No dynamic query exists.  There MUST be a
		 *	statically configured identity and password.
		 */
		if (conf->psk_query && !*conf->psk_query) {
			ERROR(LOG_PREFIX ": Invalid PSK Configuration: psk_query cannot be empty");
			return NULL;
		}

		/*
		 *	Set the callback only if we can check things.
		 */
		if (conf->psk_identity || conf->psk_query) {
			SSL_CTX_set_psk_server_callback(ctx, tls_psk_server_cb);
		}

	} else if (conf->psk_query) {
		ERROR(LOG_PREFIX ": Invalid PSK Configuration: psk_query cannot be used for outgoing connections");
		return NULL;
	}

	/*
	 *	Now check that if PSK is being used, the config is valid.
	 */
	if ((conf->psk_identity && !conf->psk_password) ||
	    (!conf->psk_identity && conf->psk_password) ||
	    (conf->psk_identity && !*conf->psk_identity) ||
	    (conf->psk_password && !*conf->psk_password)) {
		ERROR(LOG_PREFIX ": Invalid PSK Configuration: psk_identity or psk_password are empty");
		return NULL;
	}

	if (conf->psk_identity) {
		size_t psk_len, hex_len;
		uint8_t buffer[PSK_MAX_PSK_LEN];

		if (conf->certificate_file ||
		    conf->private_key_password || conf->private_key_file ||
		    conf->ca_file || conf->ca_path) {
			ERROR(LOG_PREFIX ": When PSKs are used, No certificate configuration is permitted");
			return NULL;
		}

		if (client) {
			SSL_CTX_set_psk_client_callback(ctx, tls_psk_client_cb);
		}

		psk_len = strlen(conf->psk_password);
		if (strlen(conf->psk_password) > (2 * PSK_MAX_PSK_LEN)) {
			ERROR(LOG_PREFIX ": psk_hexphrase is too long (max %d)", PSK_MAX_PSK_LEN);
			return NULL;
		}

		/*
		 *	Check the password now, so that we don't have
		 *	errors at run-time.
		 */
		hex_len = fr_hex2bin(buffer, sizeof(buffer), conf->psk_password, psk_len);
		if (psk_len != (2 * hex_len)) {
			ERROR(LOG_PREFIX ": psk_hexphrase is not all hex");
			return NULL;
		}

		goto post_ca;
	}
#else
	(void) client;	/* -Wunused */
#endif

	/*
	 *	Load our keys and certificates
	 *
	 *	If certificates are of type PEM then we can make use
	 *	of cert chain authentication using openssl api call
	 *	SSL_CTX_use_certificate_chain_file.  Please see how
	 *	the cert chain needs to be given in PEM from
	 *	openSSL.org
	 */
	if (!conf->certificate_file) goto load_ca;

	if (type == SSL_FILETYPE_PEM) {
		if (!(SSL_CTX_use_certificate_chain_file(ctx, conf->certificate_file))) {
			ERROR(LOG_PREFIX ": Error reading certificate file %s:%s", conf->certificate_file,
			      ERR_error_string(ERR_get_error(), NULL));
			return NULL;
		}

	} else if (!(SSL_CTX_use_certificate_file(ctx, conf->certificate_file, type))) {
		ERROR(LOG_PREFIX ": Error reading certificate file %s:%s",
		      conf->certificate_file,
		      ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}

	/* Load the CAs we trust */
load_ca:
	if (conf->ca_file || conf->ca_path) {
		if (!SSL_CTX_load_verify_locations(ctx, conf->ca_file, conf->ca_path)) {
			ERROR(LOG_PREFIX ": TLS error: %s", ERR_error_string(ERR_get_error(), NULL));
			ERROR(LOG_PREFIX ": Error reading Trusted root CA list %s",conf->ca_file );
			return NULL;
		}
	}
	if (conf->ca_file && *conf->ca_file) SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(conf->ca_file));

	if (conf->private_key_file) {
		if (!(SSL_CTX_use_PrivateKey_file(ctx, conf->private_key_file, type))) {
			ERROR(LOG_PREFIX ": Failed reading private key file %s:%s",
			      conf->private_key_file,
			      ERR_error_string(ERR_get_error(), NULL));
			return NULL;
		}

		/*
		 * Check if the loaded private key is the right one
		 */
		if (!SSL_CTX_check_private_key(ctx)) {
			ERROR(LOG_PREFIX ": Private key does not match the certificate public key");
			return NULL;
		}
	}

#ifdef PSK_MAX_IDENTITY_LEN
post_ca:
#endif

	/*
	 *	We never want SSLv2 or SSLv3.
	 */
	ctx_options |= SSL_OP_NO_SSLv2;
	ctx_options |= SSL_OP_NO_SSLv3;

	/*
	 *	As of 3.0.5, we always allow TLSv1.1 and TLSv1.2.
	 *	Though they can be *globally* disabled if necessary.x
	 */
#ifdef SSL_OP_NO_TLSv1
	if (conf->disable_tlsv1) ctx_options |= SSL_OP_NO_TLSv1;

	ctx_tls_versions |= SSL_OP_NO_TLSv1;
#endif
#ifdef SSL_OP_NO_TLSv1_1
	if (conf->disable_tlsv1_1) ctx_options |= SSL_OP_NO_TLSv1_1;

	ctx_tls_versions |= SSL_OP_NO_TLSv1_1;
#endif
#ifdef SSL_OP_NO_TLSv1_2
	if (conf->disable_tlsv1_2) ctx_options |= SSL_OP_NO_TLSv1_2;

	ctx_tls_versions |= SSL_OP_NO_TLSv1_2;
#endif

	if ((ctx_options & ctx_tls_versions) == ctx_tls_versions) {
		ERROR(LOG_PREFIX ": You have disabled all available TLS versions.  EAP will not work");
		return NULL;
	}

#ifdef SSL_OP_NO_TICKET
	ctx_options |= SSL_OP_NO_TICKET;
#endif

	if (!conf->disable_single_dh_use) {
		/*
		 *	SSL_OP_SINGLE_DH_USE must be used in order to prevent
		 *	small subgroup attacks and forward secrecy. Always
		 *	using SSL_OP_SINGLE_DH_USE has an impact on the
		 *	computer time needed during negotiation, but it is not
		 *	very large.
		 */
		ctx_options |= SSL_OP_SINGLE_DH_USE;
	}

	/*
	 *	SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS to work around issues
	 *	in Windows Vista client.
	 *	http://www.openssl.org/~bodo/tls-cbc.txt
	 *	http://www.nabble.com/(RADIATOR)-Radiator-Version-3.16-released-t2600070.html
	 */
	ctx_options |= SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS;

	SSL_CTX_set_options(ctx, ctx_options);

	/*
	 *	TODO: Set the RSA & DH
	 *	SSL_CTX_set_tmp_rsa_callback(ctx, cbtls_rsa);
	 *	SSL_CTX_set_tmp_dh_callback(ctx, cbtls_dh);
	 */

	/*
	 *	set the message callback to identify the type of
	 *	message.  For every new session, there can be a
	 *	different callback argument.
	 *
	 *	SSL_CTX_set_msg_callback(ctx, cbtls_msg);
	 */

	/*
	 *	Set eliptical curve crypto configuration.
	 */
#if OPENSSL_VERSION_NUMBER >= 0x0090800fL
#ifndef OPENSSL_NO_ECDH
	if (set_ecdh_curve(ctx, conf->ecdh_curve, conf->disable_single_dh_use) < 0) {
		return NULL;
	}
#endif
#endif

	/*
	 *	OpenSSL will automatically create certificate chains,
	 *	unless we tell it to not do that.  The problem is that
	 *	it sometimes gets the chains right from a certificate
	 *	signature view, but wrong from the clients view.
	 */
	if (!conf->auto_chain) {
		SSL_CTX_set_mode(ctx, SSL_MODE_NO_AUTO_CHAIN);
	}

	/* Set Info callback */
	SSL_CTX_set_info_callback(ctx, cbtls_info);

	/*
	 *	Callbacks, etc. for session resumption.
	 */
	if (conf->session_cache_enable) {
		if (conf->session_cache_server) {
			SSL_CTX_sess_set_new_cb(ctx, cache_write_session);
			SSL_CTX_sess_set_get_cb(ctx, cache_read_session);
			SSL_CTX_sess_set_remove_cb(ctx, cache_delete_session);
		}

		SSL_CTX_set_quiet_shutdown(ctx, 1);
	}

	/*
	 *	Check the certificates for revocation.
	 */
#ifdef X509_V_FLAG_CRL_CHECK
	if (conf->check_crl) {
		cert_vpstore = SSL_CTX_get_cert_store(ctx);
		if (cert_vpstore == NULL) {
			ERROR(LOG_PREFIX ": SSL error %s", ERR_error_string(ERR_get_error(), NULL));
			ERROR(LOG_PREFIX ": Error reading Certificate Store");
	    		return NULL;
		}
		X509_STORE_set_flags(cert_vpstore, X509_V_FLAG_CRL_CHECK);

#ifdef X509_V_FLAG_CRL_CHECK_ALL
		if (conf->check_all_crl)
			X509_STORE_set_flags(cert_vpstore, X509_V_FLAG_CRL_CHECK_ALL);
#endif
	}
#endif

	/*
	 *	Set verify modes
	 *	Always verify the peer certificate
	 */
	verify_mode |= SSL_VERIFY_PEER;
	verify_mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
	verify_mode |= SSL_VERIFY_CLIENT_ONCE;
	SSL_CTX_set_verify(ctx, verify_mode, cbtls_verify);

	if (conf->verify_depth) {
		SSL_CTX_set_verify_depth(ctx, conf->verify_depth);
	}

	/* Load randomness */
	if (conf->random_file) {
		if (!(RAND_load_file(conf->random_file, 1024*10))) {
			ERROR(LOG_PREFIX ": SSL error %s", ERR_error_string(ERR_get_error(), NULL));
			ERROR(LOG_PREFIX ": Error loading randomness");
			return NULL;
		}
	}

	/*
	 * Set the cipher list if we were told to
	 */
	if (conf->cipher_list) {
		if (!SSL_CTX_set_cipher_list(ctx, conf->cipher_list)) {
			ERROR(LOG_PREFIX ": Error setting cipher list");
			return NULL;
		}
	}

	/*
	 *	Setup session caching
	 */
	if (conf->session_cache_enable) {
		/*
		 *	If a virtual server is caching the TLS
		 *	sessions, then don't use the internal cache.
		 */
		if (conf->session_cache_server) {
			SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_NO_INTERNAL);
		} else {	/* in-memory cache. */
			/*
			 *	Cache it, and DON'T auto-clear it.
			 */
			SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER | SSL_SESS_CACHE_NO_AUTO_CLEAR);

			SSL_CTX_set_session_id_context(ctx,
						       (unsigned char const *) conf->session_context_id,
						       (unsigned int) strlen(conf->session_context_id));

			/*
			 *	Our timeout is in hours, this is in seconds.
			 */
			SSL_CTX_set_timeout(ctx, conf->session_timeout * 3600);

			/*
			 *	Set the maximum number of entries in the
			 *	session cache.
			 */
			SSL_CTX_sess_set_cache_size(ctx, conf->session_cache_size);
		}
	} else {
		SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
	}

	/*
	 *	Load dh params
	 */
	if (conf->dh_file) {
		char *dh_file;

		memcpy(&dh_file, &conf->dh_file, sizeof(dh_file));
		if (load_dh_params(ctx, dh_file) < 0) return NULL;
	}

	return ctx;
}


/*
 *	Free TLS client/server config
 *	Should not be called outside this code, as a callback is
 *	added to automatically free the data when the CONF_SECTION
 *	is freed.
 */
static int _tls_server_conf_free(fr_tls_server_conf_t *conf)
{
	uint32_t i;

	for (i = 0; i < conf->ctx_count; i++) SSL_CTX_free(conf->ctx[i]);

#ifdef HAVE_OPENSSL_OCSP_H
	if (conf->ocsp_store) X509_STORE_free(conf->ocsp_store);
	conf->ocsp_store = NULL;
#endif

#ifndef NDEBUG
	memset(conf, 0, sizeof(*conf));
#endif
	return 0;
}

static fr_tls_server_conf_t *tls_server_conf_alloc(TALLOC_CTX *ctx)
{
	fr_tls_server_conf_t *conf;

	conf = talloc_zero(ctx, fr_tls_server_conf_t);
	if (!conf) {
		ERROR(LOG_PREFIX ": Out of memory");
		return NULL;
	}

	talloc_set_destructor(conf, _tls_server_conf_free);

	return conf;
}

fr_tls_server_conf_t *tls_server_conf_parse(CONF_SECTION *cs)
{
	fr_tls_server_conf_t *conf;
	uint32_t i;

	/*
	 *	If cs has already been parsed there should be a cached copy
	 *	of conf already stored, so just return that.
	 */
	conf = cf_data_find(cs, "tls-conf");
	if (conf) {
		DEBUG(LOG_PREFIX ": Using cached TLS configuration from previous invocation");
		return conf;
	}

	conf = tls_server_conf_alloc(cs);

	if (cf_section_parse(cs, conf, tls_server_config) < 0) {
	error:
		talloc_free(conf);
		return NULL;
	}

	/*
	 *	Save people from their own stupidity.
	 */
	if (conf->fragment_size < 100) conf->fragment_size = 100;

	if (!conf->private_key_file) {
		ERROR(LOG_PREFIX ": TLS Server requires a private key file");
		goto error;
	}

	if (!conf->certificate_file) {
		ERROR(LOG_PREFIX ": TLS Server requires a certificate file");
		goto error;
	}

	/*
	 *	Setup session caching
	 */
	if (conf->session_cache_enable && conf->session_cache_server) {
		/*
		 *	Create a unique context Id per EAP-TLS configuration.
		 */
		if (conf->session_id_name) {
			snprintf(conf->session_context_id, sizeof(conf->session_context_id),
				 "FR eap %s", conf->session_id_name);
		} else {
			snprintf(conf->session_context_id, sizeof(conf->session_context_id),
				 "FR eap %p", conf);
		}
	}

#ifdef __APPLE__
	if (tls_certadmin_password(conf) < 0) goto error;
#endif

	if (!main_config.spawn_workers) {
		conf->ctx_count = 1;
	} else {
		conf->ctx_count = thread_pool_max_threads() * 2; /* Reduce contention */
		rad_assert(conf->ctx_count);
	}

	/*
	 *	Initialize TLS
	 */
	conf->ctx = talloc_array(conf, SSL_CTX *, conf->ctx_count);
	for (i = 0; i < conf->ctx_count; i++) {
		conf->ctx[i] = tls_init_ctx(conf, false);
		if (conf->ctx == NULL) goto error;
	}

#ifdef HAVE_OPENSSL_OCSP_H
	/*
	 * 	Initialize OCSP Revocation Store
	 */
	if (conf->ocsp_enable) {
		conf->ocsp_store = init_revocation_store(conf);
		if (conf->ocsp_store == NULL) goto error;
	}
#endif /*HAVE_OPENSSL_OCSP_H*/

	if (conf->verify_tmp_dir) {
		if (chmod(conf->verify_tmp_dir, S_IRWXU) < 0) {
			ERROR(LOG_PREFIX ": Failed changing permissions on %s: %s",
			      conf->verify_tmp_dir, fr_syserror(errno));
			goto error;
		}
	}

	if (conf->verify_client_cert_cmd && !conf->verify_tmp_dir) {
		ERROR(LOG_PREFIX ": You MUST set the verify directory in order to use verify_client_cmd");
		goto error;
	}

	if (conf->session_cache_server &&
	    !cf_section_sub_find_name2(main_config.config, "server", conf->session_cache_server)) {
		ERROR(LOG_PREFIX ": No such virtual server '%s'", conf->session_cache_server);
		goto error;
	}

	if (conf->ocsp_cache_server &&
	    !cf_section_sub_find_name2(main_config.config, "server", conf->ocsp_cache_server)) {
		ERROR(LOG_PREFIX ": No such virtual server '%s'", conf->ocsp_cache_server);
		goto error;
	}

	/*
	 *	Cache conf in cs in case we're asked to parse this again.
	 */
	cf_data_add(cs, "tls-conf", conf, NULL);

	return conf;
}

fr_tls_server_conf_t *tls_client_conf_parse(CONF_SECTION *cs)
{
	fr_tls_server_conf_t *conf;
	uint32_t i;

	conf = cf_data_find(cs, "tls-conf");
	if (conf) {
		DEBUG2(LOG_PREFIX ": Using cached TLS configuration from previous invocation");
		return conf;
	}

	conf = tls_server_conf_alloc(cs);

	if (cf_section_parse(cs, conf, tls_client_config) < 0) {
	error:
		talloc_free(conf);
		return NULL;
	}

	/*
	 *	Save people from their own stupidity.
	 */
	if (conf->fragment_size < 100) conf->fragment_size = 100;

	/*
	 *	Initialize TLS
	 */
	if (!main_config.spawn_workers) {
		conf->ctx_count = 1;
	} else {
		conf->ctx_count = thread_pool_max_threads() * 2; /* Even one context per thread will lead to contention */
		rad_assert(conf->ctx_count);
	}

#ifdef __APPLE__
	if (tls_certadmin_password(conf) < 0) goto error;
#endif

	conf->ctx = talloc_array(conf, SSL_CTX *, conf->ctx_count);
	for (i = 0; i < conf->ctx_count; i++) {
		conf->ctx[i] = tls_init_ctx(conf, true);
		if (conf->ctx[i] == NULL) goto error;
	}

	cf_data_add(cs, "tls-conf", conf, NULL);

	return conf;
}

/** Sets up TLS session so that it can later be resumed
 *
 */
int tls_success(tls_session_t *session, REQUEST *request)
{
	VALUE_PAIR		*vp;
	fr_tls_server_conf_t	*conf;

	conf = (fr_tls_server_conf_t *)SSL_get_ex_data(session->ssl, FR_TLS_EX_INDEX_CONF);
	rad_assert(conf != NULL);

	/*
	 *	If there's no session resumption, delete the entry
	 *	from the cache.  This means either it's disabled
	 *	globally for this SSL context, OR we were told to
	 *	disable it for this user.
	 *
	 *	This also means you can't turn it on just for one
	 *	user.
	 */
	if ((!session->allow_session_resumption) ||
	    (((vp = fr_pair_find_by_num(request->config, PW_ALLOW_SESSION_RESUMPTION, 0, TAG_ANY)) != NULL) &&
	     (vp->vp_integer == 0))) {
		SSL_CTX_remove_session(session->ctx, session->ssl->session);
		session->allow_session_resumption = false;

		/*
		 *	If we're in a resumed session and it's
		 *	not allowed,
		 */
		if (SSL_session_reused(session->ssl)) {
			RDEBUG("Forcibly stopping session resumption as it is not allowed");
			return -1;
		}

	/*
	 *	Else resumption IS allowed, so we store the
	 *	user data in the cache.
	 */
	} else if (SSL_session_reused(session->ssl)) {
		/*
		 *	Mark the request as resumed.
		 */
		pair_make_request("EAP-Session-Resumed", "1", T_OP_SET);
	}

	return 0;
}


void tls_fail(tls_session_t *session)
{
	/*
	 *	Force the session to NOT be cached.
	 */
	SSL_CTX_remove_session(session->ctx, session->ssl->session);
}

fr_tls_status_t tls_application_data(tls_session_t *session, REQUEST *request)
{
	int err;

	/*
	 *	Decrypt the complete record.
	 */
	err = BIO_write(session->into_ssl, session->dirty_in.data, session->dirty_in.used);
	if (err != (int) session->dirty_in.used) {
		record_init(&session->dirty_in);
		RDEBUG("Failed writing %zd bytes to SSL BIO: %d", session->dirty_in.used, err);
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
	err = SSL_read(session->ssl, session->clean_out.data, sizeof(session->clean_out.data));
	if (err < 0) {
		int code;

		code = SSL_get_error(session->ssl, err);
		switch (code) {
		case SSL_ERROR_WANT_READ:
			RWDEBUG("Peer indicated record was complete, but OpenSSL returned SSL_WANT_READ. "
				"Attempting to continue");
			return FR_TLS_RECORD_FRAGMENT_MORE;

		case SSL_ERROR_WANT_WRITE:
			DEBUG("Error in fragmentation logic: SSL_WANT_WRITE");
			break;

		default:
			DEBUG("Error in fragmentation logic: %s", ERR_error_string(code, NULL));

			/*
			 *	FIXME: Call tls_error_log?
			 */
			break;
		}
		return FR_TLS_FAIL;
	}

	if (err == 0) RWDEBUG("No data inside of the tunnel");

	/*
	 *	Passed all checks, successfully decrypted data
	 */
	session->clean_out.used = err;

	return FR_TLS_RECORD_COMPLETE;
}


/*
 * Acknowledge received is for one of the following messages sent earlier
 * 1. Handshake completed Message, so now send, EAP-Success
 * 2. Alert Message, now send, EAP-Failure
 * 3. Fragment Message, now send, next Fragment
 */
fr_tls_status_t tls_ack_handler(tls_session_t *session, REQUEST *request)
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
#endif	/* WITH_TLS */
