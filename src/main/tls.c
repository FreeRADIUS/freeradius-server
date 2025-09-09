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

#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif

#ifdef HAVE_UTIME_H
#include <utime.h>
#endif

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

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#  include <openssl/provider.h>

static OSSL_PROVIDER *openssl_default_provider = NULL;

#ifndef WITH_FIPS
static OSSL_PROVIDER *openssl_legacy_provider = NULL;
#endif
#endif

#define LOG_PREFIX "tls"

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#define ERR_get_error_line(_file, _line) ERR_get_error_all(_file, _line, NULL, NULL, NULL)

#define FIPS_mode(_x) EVP_default_properties_is_fips_enabled(NULL)
#define PEM_read_bio_DHparams(_bio, _x, _y, _z) PEM_read_bio_Parameters(_bio, &dh)
#define SSL_CTX_set0_tmp_dh_pkey(_ctx, _dh) SSL_CTX_set_tmp_dh(_ctx, _dh)
#define DH EVP_PKEY
#define DH_free(_dh)
#endif

#ifdef ENABLE_OPENSSL_VERSION_CHECK
typedef struct libssl_defect {
	uint64_t	high;
	uint64_t	low;

	char const	*id;
	char const	*name;
	char const	*comment;
} libssl_defect_t;

/* Record critical defects in libssl here, new versions of OpenSSL to older versions of OpenSSL.  */
static libssl_defect_t libssl_defects[] =
{
	{
		.low		= 0x01010001f,		/* 1.1.0a */
		.high		= 0x01010001f,		/* 1.1.0a */
		.id		= "CVE-2016-6309",
		.name		= "OCSP status request extension",
		.comment	= "For more information see https://www.openssl.org/news/secadv/20160926.txt"
	},
	{
		.low		= 0x01010000f,		/* 1.1.0  */
		.high		= 0x01010000f,		/* 1.1.0  */
		.id		= "CVE-2016-6304",
		.name		= "OCSP status request extension",
		.comment	= "For more information see https://www.openssl.org/news/secadv/20160922.txt"
	},
	{
		.low		= 0x01000209f,		/* 1.0.2i */
		.high		= 0x01000209f,		/* 1.0.2i */
		.id		= "CVE-2016-7052",
		.name		= "OCSP status request extension",
		.comment	= "For more information see https://www.openssl.org/news/secadv/20160926.txt"
	},
	{
		.low		= 0x01000200f,		/* 1.0.2  */
		.high		= 0x01000208f,		/* 1.0.2h */
		.id		= "CVE-2016-6304",
		.name		= "OCSP status request extension",
		.comment	= "For more information see https://www.openssl.org/news/secadv/20160922.txt"
	},
	{
		.low		= 0x01000100f,		/* 1.0.1  */
		.high		= 0x01000114f,		/* 1.0.1t */
		.id		= "CVE-2016-6304",
		.name		= "OCSP status request extension",
		.comment	= "For more information see https://www.openssl.org/news/secadv/20160922.txt"
	},
	{
		.low		= 0x010001000,		/* 1.0.1  */
		.high		= 0x01000106f,		/* 1.0.1f */
		.id		= "CVE-2014-0160",
		.name		= "Heartbleed",
		.comment	= "For more information see http://heartbleed.com"
	},
};
#endif /* ENABLE_OPENSSL_VERSION_CHECK */

FR_NAME_NUMBER const fr_tls_status_table[] = {
	{ "invalid",			FR_TLS_INVALID },
	{ "request",			FR_TLS_REQUEST },
	{ "response",			FR_TLS_RESPONSE },
	{ "success",			FR_TLS_SUCCESS },
	{ "fail",			FR_TLS_FAIL },
	{ "noop",			FR_TLS_NOOP },

	{ "start",			FR_TLS_START },
	{ "ok",				FR_TLS_OK },
	{ "ack",			FR_TLS_ACK },
	{ "first fragment",		FR_TLS_FIRST_FRAGMENT },
	{ "more fragments",		FR_TLS_MORE_FRAGMENTS },
	{ "length included",		FR_TLS_LENGTH_INCLUDED },
	{ "more fragments with length",	FR_TLS_MORE_FRAGMENTS_WITH_LENGTH },
	{ "handled",			FR_TLS_HANDLED },
	{  NULL , 			-1},
};

/* index we use to store cached session VPs
 * needs to be dynamic so we can supply a "free" function
 */
int fr_tls_ex_index_vps = -1;
int fr_tls_ex_index_certs = -1;

/* Session */
static void 		session_close(tls_session_t *ssn);
static void 		session_init(tls_session_t *ssn);

/* record */
static void 		record_init(record_t *buf);
static void 		record_close(record_t *buf);
static unsigned int 	record_plus(record_t *buf, void const *ptr,
				    unsigned int size);
static unsigned int 	record_minus(record_t *buf, void *ptr,
				     unsigned int size);

typedef struct {
	char const	*name;
	SSL_CTX		*ctx;
} fr_realm_ctx_t;

DIAG_OFF(format-nonliteral)
/** Print errors in the TLS thread local error stack
 *
 * Drains the thread local OpenSSL error queue, and prints out errors.
 *
 * @param[in] request	The current request (may be NULL).
 * @param[in] msg	Error message describing the operation being attempted.
 * @param[in] ap	Arguments for msg.
 * @return the number of errors drained from the stack.
 */
static int tls_verror_log(REQUEST *request, char const *msg, va_list ap)
{
	unsigned long	error;
	char		*p;
	int		in_stack = 0;
	char		buffer[256];

	int		line;
	char const	*file;

	/*
	 *	Pop the first error, so ERR_peek_error()
	 *	can be used to determine if there are
	 *	multiple errors.
	 */
	error = ERR_get_error_line(&file, &line);

	if (msg) {
		p = talloc_vasprintf(request, msg, ap);

		/*
		 *	Single line mode (there's only one error)
		 */
		if (error && !ERR_peek_error()) {
			ERR_error_string_n(error, buffer, sizeof(buffer));

			/* Extra verbose */
			if ((request && RDEBUG_ENABLED3) || DEBUG_ENABLED3) {
				ROPTIONAL(REDEBUG, ERROR, "(TLS) %s: %s[%i]:%s", p, file, line, buffer);
			} else {
				ROPTIONAL(REDEBUG, ERROR, "(TLS) %s: %s", p, buffer);
			}

			talloc_free(p);

			return 1;
		}

		/*
		 *	Print the error we were given, irrespective
		 *	of whether there were any OpenSSL errors.
		 */
		ROPTIONAL(RERROR, ERROR, "(TLS) %s", p);
		talloc_free(p);
	}

	/*
	 *	Stack mode (there are multiple errors)
	 */
	if (!error) return 0;
	do {
		ERR_error_string_n(error, buffer, sizeof(buffer));
		/* Extra verbose */
		if ((request && RDEBUG_ENABLED3) || DEBUG_ENABLED3) {
			ROPTIONAL(REDEBUG, ERROR, "(TLS) %s[%i]:%s", file, line, buffer);
		} else {
			ROPTIONAL(REDEBUG, ERROR, "(TLS) %s", buffer);
		}
		in_stack++;
	} while ((error = ERR_get_error_line(&file, &line)));

	return in_stack;
}
DIAG_ON(format-nonliteral)

/** Print errors in the TLS thread local error stack
 *
 * Drains the thread local OpenSSL error queue, and prints out errors.
 *
 * @param[in] request	The current request (may be NULL).
 * @param[in] msg	Error message describing the operation being attempted.
 * @param[in] ...	Arguments for msg.
 * @return the number of errors drained from the stack.
 */
int tls_error_log(REQUEST *request, char const *msg, ...)
{
	va_list ap;
	int ret;

	va_start(ap, msg);
	ret = tls_verror_log(request, msg, ap);
	va_end(ap);

	return ret;
}

/** Print errors raised by OpenSSL I/O functions
 *
 * Drains the thread local OpenSSL error queue, and prints out errors
 * based on the SSL handle and the return code of the I/O  function.
 *
 * OpenSSL lists I/O functions to be:
 *   - SSL_connect
 *   - SSL_accept
 *   - SSL_do_handshake
 *   - SSL_read
 *   - SSL_peek
 *   - SSL_write
 *
 * @param request	The current request (may be NULL).
 * @param session	The current tls_session.
 * @param ret		from the I/O operation.
 * @param msg		Error message describing the operation being attempted.
 * @param ...		Arguments for msg.
 * @return
 *	- 0 TLS session cannot continue.
 *	- 1 TLS session may still be viable.
 */
int tls_error_io_log(REQUEST *request, tls_session_t *session, int ret, char const *msg, ...)
{
	int	error;
	va_list	ap;

	if (ERR_peek_error()) {
		va_start(ap, msg);
		tls_verror_log(request, msg, ap);
		va_end(ap);
	}

	error = SSL_get_error(session->ssl, ret);
	switch (error) {
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
		ROPTIONAL(REDEBUG, ERROR, "(TLS) System call (I/O) error (%i)", ret);
		return 0;

	case SSL_ERROR_SSL:
		ROPTIONAL(REDEBUG, ERROR, "(TLS) Protocol error (%i)", ret);
		return 0;

	/*
	 *	For any other errors that (a) exist, and (b)
	 *	crop up - we need to interpret what to do with
	 *	them - so "politely inform" the caller that
	 *	the code needs updating here.
	 */
	default:
		ROPTIONAL(REDEBUG, ERROR, "(TLS) Session error %i (%i)", error, ret);
		return 0;
	}

	return 1;
}

#ifdef PSK_MAX_IDENTITY_LEN
static unsigned int psk_client_callback(SSL *ssl, UNUSED char const *hint,
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


void tls_session_id(SSL_SESSION *ssn, char *buffer, size_t bufsize)
{
#if OPENSSL_VERSION_NUMBER < 0x10001000L
	size_t size;

	size = ssn->session_id_length;
	if (size > bufsize) size = bufsize;

	fr_bin2hex(buffer, ssn->session_id, size);
#else
	unsigned int size;
	uint8_t const *p;

	p = SSL_SESSION_get_id(ssn, &size);
	if (size > bufsize) size = bufsize;

	fr_bin2hex(buffer, p, size);

#endif
}

static int _tls_session_free(tls_session_t *ssn)
{
	/*
	 *	Free any opaque TTLS or PEAP data.
	 */
	if ((ssn->opaque) && (ssn->free_opaque)) {
		ssn->free_opaque(ssn->opaque);
		ssn->opaque = NULL;
	}

	session_close(ssn);

	return 0;
}

#if OPENSSL_VERSION_NUMBER >= 0x10101000L && !defined(LIBRESSL_VERSION_NUMBER)
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
 */
static void tls_keylog_cb(UNUSED const SSL *ssl, const char *line)
{
	int fd;
	size_t len;
	const char *filename;
	// less than _POSIX_PIPE_BUF (512) guarantees writes are atomic for O_APPEND
	char buffer[64 + 2*SSL3_RANDOM_SIZE + 2*SSL_MAX_MASTER_KEY_LENGTH];

	filename = getenv("SSLKEYLOGFILE");
	if (!filename) return;

	len = strlen(line);
	if ((len + 1) > sizeof(buffer)) {
		DEBUG("SSLKEYLOGFILE buffer not large enough, max %lu, required %lu", sizeof(buffer), len + 1);
		return;
	}

	memcpy(buffer, line, len);
	buffer[len] = '\n';

	fd = open(filename, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		fr_strerror_printf("Failed to open file %s: %s", filename, strerror(errno));
		return;
	}

	if (write(fd, buffer, len + 1) == -1) {
		DEBUG("Failed to write to file %s: %s", filename, strerror(errno));
	}

	close(fd);
}
#endif

tls_session_t *tls_new_client_session(TALLOC_CTX *ctx, fr_tls_server_conf_t *conf, int fd, VALUE_PAIR **certs)
{
	int ret;
	int verify_mode;
	tls_session_t *ssn = NULL;
	REQUEST *request;

	ssn = talloc_zero(ctx, tls_session_t);
	if (!ssn) return NULL;

	talloc_set_destructor(ssn, _tls_session_free);

	ssn->ctx = conf->ctx;
	ssn->mtu = conf->fragment_size;
	ssn->conf = conf;

	SSL_CTX_set_mode(ssn->ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_AUTO_RETRY);

	ssn->ssl = SSL_new(ssn->ctx);
	if (!ssn->ssl) {
		talloc_free(ssn);
		return NULL;
	}

	request = request_alloc(ssn);
	request->packet = rad_alloc(request, false);
	request->reply = rad_alloc(request, false);

	SSL_set_ex_data(ssn->ssl, FR_TLS_EX_INDEX_REQUEST, (void *)request);

	if (conf->fix_cert_order) {
		SSL_set_ex_data(ssn->ssl, FR_TLS_EX_INDEX_FIX_CERT_ORDER, (void *) &conf->fix_cert_order);
	}

	/*
	 *	Set SNI, if configured.
	 *
	 *	The OpenSSL API says the filename is "char
	 *	const *", but some versions have it as "void
	 *	*", without the "const".  So we un-const it
	 *	here through various C magic.
	 */
	if (conf->client_hostname) {
		(void) SSL_set_tlsext_host_name(ssn->ssl, (void *) (uintptr_t) conf->client_hostname);
	}

	/*
	 *	Add the message callback to identify what type of
	 *	message/handshake is passed
	 */
	SSL_set_msg_callback(ssn->ssl, cbtls_msg);
	SSL_set_msg_callback_arg(ssn->ssl, ssn);
	SSL_set_info_callback(ssn->ssl, cbtls_info);

	/*
	 *	Always verify the peer certificate.
	 */
	DEBUG2("Requiring Server certificate");
	verify_mode = SSL_VERIFY_PEER;
	verify_mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
	SSL_set_verify(ssn->ssl, verify_mode, cbtls_verify);

	SSL_set_ex_data(ssn->ssl, FR_TLS_EX_INDEX_CONF, (void *)conf);
	SSL_set_ex_data(ssn->ssl, FR_TLS_EX_INDEX_SSN, (void *)ssn);
	if (certs) SSL_set_ex_data(ssn->ssl, fr_tls_ex_index_certs, (void *)certs);

	SSL_set_fd(ssn->ssl, fd);

	ret = SSL_connect(ssn->ssl);
	if (ret < 0) {
		switch (SSL_get_error(ssn->ssl, ret)) {
		default:
			break;

		case SSL_ERROR_WANT_READ:
			ssn->connected = false;
			RDEBUG("(TLS) %s - tls_new_client_session WANT_READ", conf->name);
			return ssn;

		case SSL_ERROR_WANT_WRITE:
			RDEBUG("(TLS) %s - tls_new_client_session WANT_WRITE", conf->name);
			ssn->connected = false;
			return ssn;
		}
	}

	if (ret <= 0) {
		tls_error_io_log(NULL, ssn, ret, "Failed in connecting TLS session.");
		talloc_free(ssn);

		return NULL;
	}

	ssn->connected = true;
	return ssn;
}


/** Create a new TLS session
 *
 * Configures a new TLS session, configuring options, setting callbacks etc...
 *
 * @param ctx to alloc session data in. Should usually be NULL unless the lifetime of the
 *	session is tied to another talloc'd object.
 * @param conf to use to configure the tls session.
 * @param request The current #REQUEST.
 * @param client_cert Whether to require a client_cert.
 * @param allow_tls13 Whether to allow or forbid TLS 1.3.
 * @return a new session on success, or NULL on error.
 */
tls_session_t *tls_new_session(TALLOC_CTX *ctx, fr_tls_server_conf_t *conf, REQUEST *request, bool client_cert,
#ifndef TLS1_3_VERSION
			       UNUSED
#endif
			       bool allow_tls13)
{
	tls_session_t	*state = NULL;
	SSL		*new_tls = NULL;
	int		verify_mode = 0;
	VALUE_PAIR	*vp;
	X509_STORE	*new_cert_store;

	rad_assert(request != NULL);

	RDEBUG2("(TLS) %s -Initiating new session", conf->name);

	/*
	 *	Replace X509 store if it is time to update CRLs/certs in ca_path
	 */
	if (conf->ca_path_reload_interval > 0 && conf->ca_path_last_reload + conf->ca_path_reload_interval <= request->timestamp) {
		pthread_mutex_lock(&conf->mutex);
		/* recheck conf->ca_path_last_reload because it may be inaccurate without mutex */
		if (conf->ca_path_last_reload + conf->ca_path_reload_interval <= request->timestamp) {
			RDEBUG2("(TLS) Flushing X509 store to re-read data from ca_path dir");

			if ((new_cert_store = fr_init_x509_store(conf)) == NULL) {
				RERROR("(TLS) %s - Error replacing X509 store, out of memory (?)", conf->name);
			} else {
				if (conf->old_x509_store) X509_STORE_free(conf->old_x509_store);
				/*
				 * Swap empty store with the old one.
				 */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
				conf->old_x509_store = SSL_CTX_get_cert_store(conf->ctx);
				/* Bump refcnt so the store is kept allocated till next store replacement */
				X509_STORE_up_ref(conf->old_x509_store);
				SSL_CTX_set_cert_store(conf->ctx, new_cert_store);
#else
				/*
				 * We do not use SSL_CTX_set_cert_store() call here because
				 * we are not sure that old X509 store is not in the use by some
				 * thread (i.e. cert check in progress).
				 * Keep it allocated till next store replacement.
				 */
				conf->old_x509_store = conf->ctx->cert_store;
				conf->ctx->cert_store = new_cert_store;
#endif
				conf->ca_path_last_reload = request->timestamp;
			}
		}
		pthread_mutex_unlock(&conf->mutex);
	}

	new_tls = SSL_new(conf->ctx);
	if (new_tls == NULL) {
		tls_error_log(request, "Error creating new TLS session");
		return NULL;
	}

#ifdef TLS1_3_VERSION
	/*
	 *	Disallow TLS 1.3 for FAST.
	 *
	 *	We need another magic configuration option to allow
	 *	it.
	 */
	if (!allow_tls13 && (conf->max_version == TLS1_3_VERSION)) {
		WARN("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
		WARN("!!                    FORCING MAXIMUM TLS VERSION TO TLS 1.2                  !!");
		WARN("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
		WARN("!! There is no standard for using this EAP method with TLS 1.3");
		WARN("!! Please set tls_max_version = \"1.2\"");
		WARN("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");

		if (SSL_set_max_proto_version(new_tls, TLS1_2_VERSION) == 0) {
			tls_error_log(request, "Failed limiting maximum version to TLS 1.2");
			return NULL;
		}
	}
#endif

	/* We use the SSL's "app_data" to indicate a call-back */
	SSL_set_app_data(new_tls, NULL);

	if ((state = talloc_zero(ctx, tls_session_t)) == NULL) {
		RERROR("(TLS) %s - Error allocating memory for SSL state", conf->name);
		return NULL;
	}
	session_init(state);
	talloc_set_destructor(state, _tls_session_free);

	state->ctx = conf->ctx;
	state->ssl = new_tls;
	state->conf = conf;

#if OPENSSL_VERSION_NUMBER >= 0x10101000L && !defined(LIBRESSL_VERSION_NUMBER)
	/*
	 *	Set the keylog file if the admin requested it.
	 */
	if (getenv("SSLKEYLOGFILE") != NULL) SSL_CTX_set_keylog_callback(state->ctx, tls_keylog_cb);
#endif

	/*
	 *	Initialize callbacks
	 */
	state->record_init = record_init;
	state->record_close = record_close;
	state->record_plus = record_plus;
	state->record_minus = record_minus;

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
	state->into_ssl = BIO_new(BIO_s_mem());
	state->from_ssl = BIO_new(BIO_s_mem());
	SSL_set_bio(state->ssl, state->into_ssl, state->from_ssl);

	/*
	 *	Add the message callback to identify what type of
	 *	message/handshake is passed
	 */
	SSL_set_msg_callback(new_tls, cbtls_msg);
	SSL_set_msg_callback_arg(new_tls, state);
	SSL_set_info_callback(new_tls, cbtls_info);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	/*
	 *	Allow policies to load context-specific certificate chains.
	 */
	vp = fr_pair_find_by_num(request->config, PW_TLS_SESSION_CERT_FILE, 0, TAG_ANY);
	if (vp) {
		VALUE_PAIR *key = fr_pair_find_by_num(request->config, PW_TLS_SESSION_CERT_PRIVATE_KEY_FILE, 0, TAG_ANY);
		if (!key) key = vp;

		RDEBUG2("(TLS) %s - Loading session certificate file \"%s\"", conf->name, vp->vp_strvalue);

		if (conf->realms) {
			fr_realm_ctx_t my_r, *r;

			/*
			 *	Use a pre-existing SSL CTX, if
			 *	available.  Note that due to OpenSSL
			 *	issues, this really changes only the
			 *	certificate files, and leaves all
			 *	other fields alone.  e.g. you can't
			 *	select a different TLS version.
			 *
			 *	This is fine for our purposes in v3.
			 *	Due to how we build them, the various
			 *	additional SSL_CTXs are identical to
			 *	the main one, except for certs.
			 */
			my_r.name = vp->vp_strvalue;
			r = fr_hash_table_finddata(conf->realms, &my_r);
			if (r) {
				(void) SSL_set_SSL_CTX(state->ssl, r->ctx);
				goto after_chain;
			}

			/*
			 *	Else fall through to trying to dynamically load the certs.
			 */
		}

		if (conf->file_type) {
			if (SSL_use_certificate_chain_file(state->ssl, vp->vp_strvalue) != 1) {
				tls_error_log(request, "Failed loading TLS session certificate \"%s\"",
					      vp->vp_strvalue);
			error:
				talloc_free(state);
				return NULL;
			}
		} else {
			if (SSL_use_certificate_file(state->ssl, vp->vp_strvalue, SSL_FILETYPE_ASN1) != 1) {
				tls_error_log(request, "Failed loading TLS session certificate \"%s\"",
					      vp->vp_strvalue);
				goto error;
			}
		}

		/*
		 *	Note that there is either no password, or it
		 *	has to be the same as what's in the
		 *	configuration.
		 *
		 *	There is just no additional security to
		 *	putting a password into the same file system
		 *	as the private key.
		 */
		if (SSL_use_PrivateKey_file(state->ssl, key->vp_strvalue, SSL_FILETYPE_PEM) != 1) {
			tls_error_log(request, "Failed loading TLS session certificate \"%s\"",
				      key->vp_strvalue);
			goto error;
		}

		if (SSL_check_private_key(state->ssl) != 1) {
			tls_error_log(request, "Failed validating TLS session certificate \"%s\"",
				      vp->vp_strvalue);
			goto error;
		}
	}
after_chain:
#endif

	/*
	 *	In Server mode we only accept.
	 */
	SSL_set_accept_state(state->ssl);

	/*
	 *	Verify the peer certificate, if asked.
	 */
	if (client_cert) {
		RDEBUG2("(TLS) %s - Setting verify mode to require certificate from client", conf->name);
		verify_mode = SSL_VERIFY_PEER;
		verify_mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
		verify_mode |= SSL_VERIFY_CLIENT_ONCE;
	}
#ifdef PSK_MAX_IDENTITY_LEN
	else if (conf->psk_identity) {
		RDEBUG2("(TLS) %s - Setting verify peer mode due to PSK", conf->name);
		verify_mode = SSL_VERIFY_PEER;
		verify_mode |= SSL_VERIFY_CLIENT_ONCE;
	}
#endif
	SSL_set_verify(state->ssl, verify_mode, cbtls_verify);

	SSL_set_ex_data(state->ssl, FR_TLS_EX_INDEX_CONF, (void *)conf);
	SSL_set_ex_data(state->ssl, FR_TLS_EX_INDEX_SSN, (void *)state);
	state->length_flag = conf->include_length;

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
	state->mtu = conf->fragment_size;
#define EAP_TLS_MAGIC_OVERHEAD (63)

	/*
	 *	If the packet contains an MTU, then use that.  We
	 *	trust the admin!
	 */
	vp = fr_pair_find_by_num(request->packet->vps, PW_FRAMED_MTU, 0, TAG_ANY);
	if (vp) {
		if ((vp->vp_integer > 100) && (vp->vp_integer < state->mtu)) {
			state->mtu = vp->vp_integer;
		}

	} else if (request->parent) {
		/*
		 *	If there's a parent request, we look for what
		 *	MTU was set there.  Then, we use an MTU which
		 *	accounts for the extra overhead of nesting EAP
		 *	+ TLS inside of EAP + TLS.
		 */
		vp = fr_pair_find_by_num(request->parent->state, PW_FRAMED_MTU, 0, TAG_ANY);
		if (vp && (vp->vp_integer > (100 + EAP_TLS_MAGIC_OVERHEAD)) && (vp->vp_integer <= state->mtu)) {
			state->mtu = vp->vp_integer - EAP_TLS_MAGIC_OVERHEAD;
		}
	}

	/*
	 *	Cache / update the Framed-MTU in the session-state
	 *	list.
	 */
	vp = fr_pair_find_by_num(request->state, PW_FRAMED_MTU, 0, TAG_ANY);
	if (!vp) {
		vp = fr_pair_afrom_num(request->state_ctx, PW_FRAMED_MTU, 0);
		fr_pair_add(&request->state, vp);
	}
	if (vp) vp->vp_integer = state->mtu;

	if (conf->session_cache_enable) state->allow_session_resumption = true; /* otherwise it's false */

	return state;
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
int tls_handshake_recv(REQUEST *request, tls_session_t *ssn)
{
	int err;

	if (ssn->invalid_hb_used) {
		REDEBUG("(TLS) %s - OpenSSL Heartbeat attack detected.  Closing connection", ssn->conf->name);
		return 0;
	}

	if (ssn->dirty_in.used > 0) {
		err = BIO_write(ssn->into_ssl, ssn->dirty_in.data, ssn->dirty_in.used);
		if (err != (int) ssn->dirty_in.used) {
			REDEBUG("(TLS) %s - Failed writing %zd bytes to SSL BIO: %d", ssn->conf->name, ssn->dirty_in.used, err);
			record_init(&ssn->dirty_in);
			return 0;
		}
		record_init(&ssn->dirty_in);
	}

	err = SSL_read(ssn->ssl, ssn->clean_out.data + ssn->clean_out.used,
		       sizeof(ssn->clean_out.data) - ssn->clean_out.used);
	if (err > 0) {
		ssn->clean_out.used += err;
		return 1;
	}

	if (!tls_error_io_log(request, ssn, err, "Failed reading from OpenSSL")) return 0;

	/* Some Extra STATE information for easy debugging */
	if (!ssn->is_init_finished && SSL_is_init_finished(ssn->ssl)) {
		VALUE_PAIR *vp;
		char const *str_version;

		RDEBUG2("(TLS) %s - Connection Established", ssn->conf->name);
		ssn->is_init_finished = true;

		vp = fr_pair_afrom_num(request->state_ctx, PW_TLS_SESSION_CIPHER_SUITE, 0);
		if (vp) {
			fr_pair_value_strcpy(vp, SSL_CIPHER_get_name(SSL_get_current_cipher(ssn->ssl)));
			fr_pair_add(&request->state, vp);
			RINDENT();
			rdebug_pair(L_DBG_LVL_2, request, vp, NULL);
			REXDENT();
		}

		switch (SSL_version(ssn->ssl)) {
		case SSL2_VERSION:
			str_version = "SSL 2.0";
			break;
		case SSL3_VERSION:
			str_version = "SSL 3.0";
			break;
		case TLS1_VERSION:
			str_version = "TLS 1.0";
			break;
#ifdef TLS1_1_VERSION
		case TLS1_1_VERSION:
			str_version = "TLS 1.1";
			break;
#endif
#ifdef TLS1_2_VERSION
		case TLS1_2_VERSION:
			str_version = "TLS 1.2";
			break;
#endif
#ifdef TLS1_3_VERSION
		case TLS1_3_VERSION:
			str_version = "TLS 1.3";
			break;
#endif
		default:
			str_version = "UNKNOWN";
			break;
		}

		vp = fr_pair_afrom_num(request->state_ctx, PW_TLS_SESSION_VERSION, 0);
		if (vp) {
			fr_pair_value_strcpy(vp, str_version);
			fr_pair_add(&request->state, vp);
			RINDENT();
			rdebug_pair(L_DBG_LVL_2, request, vp, NULL);
			REXDENT();
		}
	}
	else if (SSL_in_init(ssn->ssl)) { RDEBUG2("(TLS) %s - In Handshake Phase", ssn->conf->name); }
	else if (SSL_in_before(ssn->ssl)) { RDEBUG2("(TLS) %s - Before Handshake Phase", ssn->conf->name); }
	else if (SSL_in_accept_init(ssn->ssl)) { RDEBUG2("(TLS) %s- In Accept mode", ssn->conf->name); }
	else if (SSL_in_connect_init(ssn->ssl)) { RDEBUG2("(TLS) %s - In Connect mode", ssn->conf->name); }

#if OPENSSL_VERSION_NUMBER >= 0x10001000L
	/*
	 *	Cache the SSL_SESSION pointer.
	 */
	if (!ssn->ssl_session) {
		ssn->ssl_session = SSL_get_session(ssn->ssl);

		/*
		 *	Some versions of OpenSSL don't allow you to
		 *	get the session before the init is finished.
		 *	In that case, this error is a soft fail.
		 *
		 *	If the session init is finished, then failure
		 *	to get the session is a hard fail.
		 */
		if (!ssn->ssl_session && ssn->is_init_finished) {
			RDEBUG("(TLS) %s - Failed getting session", ssn->conf->name);
			return 0;
		}
	}

#else
#error You must use a newer version of OpenSSL
#endif

	err = BIO_ctrl_pending(ssn->from_ssl);
	if (err > 0) {
		err = BIO_read(ssn->from_ssl, ssn->dirty_out.data,
			       sizeof(ssn->dirty_out.data));
		if (err > 0) {
			RDEBUG3("(TLS) %s- got %d bytes of data", ssn->conf->name, err);
			ssn->dirty_out.used = err;

		} else if (BIO_should_retry(ssn->from_ssl)) {
			record_init(&ssn->dirty_in);
			RDEBUG2("(TLS) %s - Asking for more data in tunnel.", ssn->conf->name);
			return 1;

		} else {
			tls_error_log(NULL, "Error reading from OpenSSL");
			record_init(&ssn->dirty_in);
			return 0;
		}
	} else {
		RDEBUG2("(TLS) %s - Application data.", ssn->conf->name);
		/* Its clean application data, leave whatever is in the buffer */
#if 0
		record_init(&ssn->clean_out);
#endif
	}

	/* We are done with dirty_in, reinitialize it */
	record_init(&ssn->dirty_in);
	return 1;
}

/*
 *	Take cleartext user data, and encrypt it into the output buffer,
 *	to send to the client at the other end of the SSL connection.
 */
int tls_handshake_send(REQUEST *request, tls_session_t *ssn)
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
	if (ssn->clean_in.used > 0) {
		int written;

		written = SSL_write(ssn->ssl, ssn->clean_in.data, ssn->clean_in.used);
		record_minus(&ssn->clean_in, NULL, written);

		/* Get the dirty data from Bio to send it */
		err = BIO_read(ssn->from_ssl, ssn->dirty_out.data + ssn->dirty_out.used,
			       sizeof(ssn->dirty_out.data) - ssn->dirty_out.used);
		if (err > 0) {
			ssn->dirty_out.used += err;
		} else {
			if (!tls_error_io_log(request, ssn, err, "Failed writing to OpenSSL")) {
				return 0;
			}
		}
	}

	return 1;
}

static void session_init(tls_session_t *ssn)
{
	ssn->ssl = NULL;
	ssn->into_ssl = ssn->from_ssl = NULL;
	record_init(&ssn->clean_in);
	record_init(&ssn->clean_out);
	record_init(&ssn->dirty_in);
	record_init(&ssn->dirty_out);

	memset(&ssn->info, 0, sizeof(ssn->info));

	ssn->mtu = 0;
	ssn->fragment = false;
	ssn->tls_msg_len = 0;
	ssn->length_flag = false;
	ssn->opaque = NULL;
	ssn->free_opaque = NULL;
}

static void session_close(tls_session_t *ssn)
{
	if (ssn->ssl) {
		SSL_set_quiet_shutdown(ssn->ssl, 1);
		SSL_shutdown(ssn->ssl);

		SSL_free(ssn->ssl);
		ssn->ssl = NULL;
	}

	record_close(&ssn->clean_in);
	record_close(&ssn->clean_out);
	record_close(&ssn->dirty_in);
	record_close(&ssn->dirty_out);
	session_init(ssn);
}

static void record_init(record_t *rec)
{
	rec->used = 0;
}

static void record_close(record_t *rec)
{
	rec->used = 0;
}


/*
 *	Copy data to the intermediate buffer, before we send
 *	it somewhere.
 */
static unsigned int record_plus(record_t *rec, void const *ptr,
				unsigned int size)
{
	unsigned int added = MAX_RECORD_SIZE - rec->used;

	if(added > size)
		added = size;
	if(added == 0)
		return 0;
	memcpy(rec->data + rec->used, ptr, added);
	rec->used += added;
	return added;
}

/*
 *	Take data from the buffer, and give it to the caller.
 */
static unsigned int record_minus(record_t *rec, void *ptr,
				 unsigned int size)
{
	unsigned int taken = rec->used;

	if(taken > size)
		taken = size;
	if(taken == 0)
		return 0;
	if(ptr)
		memcpy(ptr, rec->data, taken);
	rec->used -= taken;

	/*
	 *	This is pretty bad...
	 */
	if (rec->used > 0) memmove(rec->data, rec->data + taken, rec->used);

	return taken;
}

void tls_session_information(tls_session_t *tls_session)
{
	char const *str_write_p, *str_version, *str_content_type;
	char const *str_details1 = "", *str_details2= "";
	char const *details = NULL;
	REQUEST *request;
	VALUE_PAIR *vp;
	char content_type[16], alert_buf[16];
	char name_buf[128];
	char buffer[32];

	/*
	 *	Don't print this out in the normal course of
	 *	operations.
	 */
	if (rad_debug_lvl == 0) return;

	/*
	 *	OpenSSL calls this function with 'pseudo' content
	 *	types.  The user doesn't care about them, so suppress them.
	 */
	if (tls_session->info.content_type > UINT8_MAX) return;

	request = SSL_get_ex_data(tls_session->ssl, FR_TLS_EX_INDEX_REQUEST);
	if (!request) return;

	if (tls_session->info.origin) {
		snprintf(name_buf, sizeof(name_buf), "(TLS) %s - send", tls_session->conf->name);
	} else {
		snprintf(name_buf, sizeof(name_buf), "(TLS) %s - recv", tls_session->conf->name);
	}
	str_write_p = name_buf;

#define FROM_CLIENT (tls_session->info.origin == 0)

	switch (SSL_version(tls_session->ssl)) {
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
#ifdef TLS1_3_VERSION
	case TLS1_3_VERSION:
		str_version = "TLS 1.3 ";
		break;
#endif

	default:
		sprintf(buffer, "UNKNOWN TLS VERSION '%04X'", SSL_version(tls_session->ssl));
		str_version = buffer;
		break;
	}

	if (1) {
		switch (tls_session->info.content_type) {
		case SSL3_RT_CHANGE_CIPHER_SPEC:
			str_content_type = "ChangeCipherSpec";
			break;

		case SSL3_RT_ALERT:
			str_content_type = "Alert";
			break;

		case SSL3_RT_HANDSHAKE:
			str_content_type = "Handshake";
			break;

		case SSL3_RT_APPLICATION_DATA:
			str_content_type = "ApplicationData";
			break;

		default:
			snprintf(content_type, sizeof(content_type), "content=%d", tls_session->info.content_type);
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
				details = "there is a failure inside the TLS protocol exchange";

				switch (tls_session->info.alert_description) {
				case SSL3_AD_CLOSE_NOTIFY:
					str_details2 = " close_notify";
					details = "the connection has been closed, and no further TLS exchanges will take place";
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

				case SSL3_AD_NO_CERTIFICATE:
					str_details2 = " no_certificate";
					details = "the server did not present a certificate to the client";
					break;

				case SSL3_AD_BAD_CERTIFICATE:
					str_details2 = " bad_certificate";
					details = "it believes the server certificate is invalid or malformed";
					break;

				case SSL3_AD_UNSUPPORTED_CERTIFICATE:
					str_details2 = " unsupported_certificate";
					details = "it does not understand the certificate presented by the server";
					break;

				case SSL3_AD_CERTIFICATE_REVOKED:
					str_details2 = " certificate_revoked";
					details = "it believes that the server certificate has been revoked";
					break;

				case SSL3_AD_CERTIFICATE_EXPIRED:
					str_details2 = " certificate_expired";
					details = "it believes that the server certificate has expired.  Either renew the server certificate, or check the time on the client";
					break;

				case SSL3_AD_CERTIFICATE_UNKNOWN:
					str_details2 = " certificate_unknown";
					details = "it does not recognize the server certificate";
					break;

				case SSL3_AD_ILLEGAL_PARAMETER:
					str_details2 = " illegal_parameter";
#ifdef PSK_MAX_IDENTITY_LEN
					if (tls_session->conf->psk_identity || tls_session->conf->psk_query) {
						details = "the client and server have different values for the PSK";
					}
#endif
					break;

				case TLS1_AD_UNKNOWN_CA:
					str_details2 = " unknown_ca";
					details = "it does not recognize the CA used to issue the server certificate.  Please update the client so that it knows about the CA";
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
					details = "the client does not accept the version of TLS negotiated by the server";

#ifdef TLS1_3_VERSION
					/*
					 *	Complain about OpenSSL bugs.
					 */
					if ((SSL_version(tls_session->ssl) > tls_session->conf->max_version) &&
					    (rad_debug_lvl > 0)) {
						WARN("TLS 1.3 has been negotiated even though it was disabled.  This is an OpenSSL Bug.");
						WARN("Please set: cipher_list = \"DEFAULT@SECLEVEL=1\" in the tls {...} section.");
					}
#endif
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

#ifdef TLS13_AD_MISSING_EXTENSIONS
				case TLS13_AD_MISSING_EXTENSIONS:
					str_details2 = " missing_extensions";
					details = "the server did not present a TLS extension which the client expected to be present.  Please check the TLS libraries on the client and server for compatibility";
					break;
#endif

#ifdef TLS13_AD_CERTIFICATE_REQUIRED
				case TLS13_AD_CERTIFICATE_REQUIRED:
					str_details2 = " certificate_required";
					details = "the server did not present a certificate";
					break;
#endif

#ifdef TLS1_AD_UNSUPPORTED_EXTENSION
				case TLS1_AD_UNSUPPORTED_EXTENSION:
					str_details2 = " unsupported_extension";
					details = "the server has sent a TLS message which the client does not recognize.  Please check the TLS libraries on the client and server for compatibility";
					break;
#endif

#ifdef TLS1_AD_CERTIFICATE_UNOBTAINABLE
				case TLS1_AD_CERTIFICATE_UNOBTAINABLE:
					str_details2 = " certificate_unobtainable";
					break;
#endif

#ifdef TLS1_AD_UNRECOGNIZED_NAME
				case TLS1_AD_UNRECOGNIZED_NAME:
					str_details2 = " unrecognized_name";
					break;
#endif

#ifdef TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE
				case TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE:
					str_details2 = " bad_certificate_status_response";
					break;
#endif

#ifdef TLS1_AD_BAD_CERTIFICATE_HASH_VALUE
				case TLS1_AD_BAD_CERTIFICATE_HASH_VALUE:
					str_details2 = " bad_certificate_hash_value";
					break;
#endif

#ifdef TLS1_AD_UNKNOWN_PSK_IDENTITY
				case TLS1_AD_UNKNOWN_PSK_IDENTITY:
					str_details2 = " unknown_psk_identity";
					break;
#endif

#ifdef TLS1_AD_NO_APPLICATION_PROTOCOL
				case TLS1_AD_NO_APPLICATION_PROTOCOL:
					str_details2 = " no_application_protocol";
					break;
#endif
				}
			}
		}

		if (tls_session->info.content_type == SSL3_RT_HANDSHAKE) {
			str_details1 = "";

			if (tls_session->info.record_len > 0) switch (tls_session->info.handshake_type) {
			case SSL3_MT_HELLO_REQUEST:
				str_details1 = ", HelloRequest";
				break;

			case SSL3_MT_CLIENT_HELLO:
				str_details1 = ", ClientHello";
				break;

			case SSL3_MT_SERVER_HELLO:
				str_details1 = ", ServerHello";
				break;

#ifdef SSL3_MT_NEWSESSION_TICKET
			case SSL3_MT_NEWSESSION_TICKET:
				str_details1 = ", NewSessionTicket";
				break;
#endif

#ifdef SSL3_MT_ENCRYPTED_EXTENSIONS
			case SSL3_MT_ENCRYPTED_EXTENSIONS:
				str_details1 = ", EncryptedExtensions";
				break;
#endif

			case SSL3_MT_CERTIFICATE:
				str_details1 = ", Certificate";
				break;

			case SSL3_MT_SERVER_KEY_EXCHANGE:
				str_details1 = ", ServerKeyExchange";
				break;

			case SSL3_MT_CERTIFICATE_REQUEST:
				str_details1 = ", CertificateRequest";
				break;

			case SSL3_MT_SERVER_DONE:
				str_details1 = ", ServerHelloDone";
				break;

			case SSL3_MT_CERTIFICATE_VERIFY:
				str_details1 = ", CertificateVerify";
				break;

			case SSL3_MT_CLIENT_KEY_EXCHANGE:
				str_details1 = ", ClientKeyExchange";
				break;

			case SSL3_MT_FINISHED:
				str_details1 = ", Finished";
				break;

#ifdef SSL3_MT_KEY_UPDATE
			case SSL3_MT_KEY_UPDATE:
				str_content_type = "KeyUpdate";
				break;
#endif

			default:
				snprintf(alert_buf, sizeof(alert_buf), ", type=%d", tls_session->info.handshake_type);
				str_details1 = alert_buf;
				break;
			}
		}
	}

	snprintf(tls_session->info.info_description,
		 sizeof(tls_session->info.info_description),
		 "%s %s%s%s%s",
		 str_write_p, str_version, str_content_type,
		 str_details1, str_details2);

	/*
	 *	Cache the TLS session information in the session-state
	 *	list, so it can be accessed by Post-Auth-Type
	 *	Client-Lost { ... }
	 */
	vp = fr_pair_afrom_num(request->state_ctx, PW_TLS_SESSION_INFORMATION, 0);
	if (vp) {
		fr_pair_value_strcpy(vp, tls_session->info.info_description);
		fr_pair_add(&request->state, vp);
	}

	RDEBUG2("%s", tls_session->info.info_description);

	if (FROM_CLIENT && details) RDEBUG2("(TLS) %s - The client is informing us that %s.", tls_session->conf->name, details);
}

static CONF_PARSER cache_config[] = {
	{ "enable", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, fr_tls_server_conf_t, session_cache_enable), "no" },

	{ "lifetime", FR_CONF_OFFSET(PW_TYPE_INTEGER, fr_tls_server_conf_t, session_lifetime), "24" },
	{ "name", FR_CONF_OFFSET(PW_TYPE_STRING, fr_tls_server_conf_t, session_id_name), NULL },

	{ "max_entries", FR_CONF_OFFSET(PW_TYPE_INTEGER, fr_tls_server_conf_t, session_cache_size), "255" },
	{ "persist_dir", FR_CONF_OFFSET(PW_TYPE_STRING, fr_tls_server_conf_t, session_cache_path), NULL },
	{ "virtual_server", FR_CONF_OFFSET(PW_TYPE_STRING, fr_tls_server_conf_t, session_cache_server), NULL },
	CONF_PARSER_TERMINATOR
};

static CONF_PARSER verify_config[] = {
	{ "skip_if_ocsp_ok", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, fr_tls_server_conf_t, verify_skip_if_ocsp_ok), "no" },
	{ "tmpdir", FR_CONF_OFFSET(PW_TYPE_STRING, fr_tls_server_conf_t, verify_tmp_dir), NULL },
	{ "client", FR_CONF_OFFSET(PW_TYPE_STRING, fr_tls_server_conf_t, verify_client_cert_cmd), NULL },
	CONF_PARSER_TERMINATOR
};

#ifdef HAVE_OPENSSL_OCSP_H
static CONF_PARSER ocsp_config[] = {
	{ "enable", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, fr_tls_server_conf_t, ocsp_enable), "no" },
	{ "override_cert_url", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, fr_tls_server_conf_t, ocsp_override_url), "no" },
	{ "url", FR_CONF_OFFSET(PW_TYPE_STRING, fr_tls_server_conf_t, ocsp_url), NULL },
	{ "use_nonce", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, fr_tls_server_conf_t, ocsp_use_nonce), "yes" },
	{ "timeout", FR_CONF_OFFSET(PW_TYPE_INTEGER, fr_tls_server_conf_t, ocsp_timeout), "yes" },
	{ "softfail", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, fr_tls_server_conf_t, ocsp_softfail), "no" },
	CONF_PARSER_TERMINATOR
};
#endif

static CONF_PARSER tls_server_config[] = {
	{ "verify_depth", FR_CONF_OFFSET(PW_TYPE_INTEGER, fr_tls_server_conf_t, verify_depth), "0" },
	{ "CA_path", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT | PW_TYPE_DEPRECATED, fr_tls_server_conf_t, ca_path), NULL },
	{ "ca_path", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT, fr_tls_server_conf_t, ca_path), NULL },
	{ "pem_file_type", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, fr_tls_server_conf_t, file_type), "yes" },
	{ "private_key_file", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT, fr_tls_server_conf_t, private_key_file), NULL },
	{ "certificate_file", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT, fr_tls_server_conf_t, certificate_file), NULL },
	{ "CA_file", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT | PW_TYPE_DEPRECATED, fr_tls_server_conf_t, ca_file), NULL },
	{ "ca_file", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT, fr_tls_server_conf_t, ca_file), NULL },
	{ "private_key_password", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_SECRET, fr_tls_server_conf_t, private_key_password), NULL },
#ifdef PSK_MAX_IDENTITY_LEN
	{ "psk_identity", FR_CONF_OFFSET(PW_TYPE_STRING, fr_tls_server_conf_t, psk_identity), NULL },
	{ "psk_hexphrase", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_SECRET, fr_tls_server_conf_t, psk_password), NULL },
	{ "psk_query", FR_CONF_OFFSET(PW_TYPE_STRING, fr_tls_server_conf_t, psk_query), NULL },
#endif
	{ "dh_file", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT, fr_tls_server_conf_t, dh_file), NULL },
	{ "random_file", FR_CONF_OFFSET(PW_TYPE_FILE_EXISTS, fr_tls_server_conf_t, random_file), NULL },
	{ "fragment_size", FR_CONF_OFFSET(PW_TYPE_INTEGER, fr_tls_server_conf_t, fragment_size), "1024" },
	{ "include_length", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, fr_tls_server_conf_t, include_length), "yes" },
	{ "auto_chain", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, fr_tls_server_conf_t, auto_chain), "yes" },
	{ "disable_single_dh_use", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, fr_tls_server_conf_t, disable_single_dh_use), NULL },
	{ "check_crl", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, fr_tls_server_conf_t, check_crl), "no" },
#ifdef X509_V_FLAG_CRL_CHECK_ALL
	{ "check_all_crl", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, fr_tls_server_conf_t, check_all_crl), "no" },
#endif
	{ "ca_path_reload_interval", FR_CONF_OFFSET(PW_TYPE_INTEGER, fr_tls_server_conf_t, ca_path_reload_interval), "0" },
	{ "allow_expired_crl", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, fr_tls_server_conf_t, allow_expired_crl), NULL },
	{ "check_cert_cn", FR_CONF_OFFSET(PW_TYPE_STRING, fr_tls_server_conf_t, check_cert_cn), NULL },
	{ "cipher_list", FR_CONF_OFFSET(PW_TYPE_STRING, fr_tls_server_conf_t, cipher_list), NULL },
	{ "cipher_server_preference", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, fr_tls_server_conf_t, cipher_server_preference), NULL },
	{ "check_cert_issuer", FR_CONF_OFFSET(PW_TYPE_STRING, fr_tls_server_conf_t, check_cert_issuer), NULL },
	{ "require_client_cert", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, fr_tls_server_conf_t, require_client_cert), NULL },

#if OPENSSL_VERSION_NUMBER >= 0x10101000L
	{ "sigalgs_list", FR_CONF_OFFSET(PW_TYPE_STRING, fr_tls_server_conf_t, sigalgs_list), NULL },
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	{ "reject_unknown_intermediate_ca", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, fr_tls_server_conf_t, disallow_untrusted), .dflt = "no", },
#endif

#if OPENSSL_VERSION_NUMBER >= 0x0090800fL
#ifndef OPENSSL_NO_ECDH
	{ "ecdh_curve", FR_CONF_OFFSET(PW_TYPE_STRING, fr_tls_server_conf_t, ecdh_curve), "prime256v1" },
#endif
#endif

#ifdef SSL_OP_NO_TLSv1
	{ "disable_tlsv1", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, fr_tls_server_conf_t, disable_tlsv1), NULL },
#endif

#ifdef SSL_OP_NO_TLSv1_1
	{ "disable_tlsv1_1", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, fr_tls_server_conf_t, disable_tlsv1_1), NULL },
#endif

#ifdef SSL_OP_NO_TLSv1_2
	{ "disable_tlsv1_2", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, fr_tls_server_conf_t, disable_tlsv1_2), NULL },
#endif

	{ "tls_max_version", FR_CONF_OFFSET(PW_TYPE_STRING, fr_tls_server_conf_t, tls_max_version), NULL },

	{ "tls_min_version", FR_CONF_OFFSET(PW_TYPE_STRING, fr_tls_server_conf_t, tls_min_version),
#if defined(TLS1_2_VERSION)
	  "1.2"
#elif defined(TLS1_1_VERSION)
	  "1.1"
#else
	  "1.0"
#endif
	},

#ifdef WITH_RADIUSV11
	{ "radiusv1_1", FR_CONF_OFFSET(PW_TYPE_STRING, fr_tls_server_conf_t, radiusv11_name), NULL },
#endif

	{ "realm_dir", FR_CONF_OFFSET(PW_TYPE_STRING, fr_tls_server_conf_t, realm_dir), NULL },

	{ "cache", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const *) cache_config },

	{ "verify", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const *) verify_config },

#ifdef HAVE_OPENSSL_OCSP_H
	{ "ocsp", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const *) ocsp_config },
#endif
	CONF_PARSER_TERMINATOR
};


static CONF_PARSER tls_client_config[] = {
	{ "verify_depth", FR_CONF_OFFSET(PW_TYPE_INTEGER, fr_tls_server_conf_t, verify_depth), "0" },
	{ "ca_path", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT, fr_tls_server_conf_t, ca_path), NULL },
	{ "pem_file_type", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, fr_tls_server_conf_t, file_type), "yes" },
	{ "private_key_file", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT, fr_tls_server_conf_t, private_key_file), NULL },
	{ "certificate_file", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT, fr_tls_server_conf_t, certificate_file), NULL },
	{ "ca_file", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT, fr_tls_server_conf_t, ca_file), NULL },
	{ "private_key_password", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_SECRET, fr_tls_server_conf_t, private_key_password), NULL },
#ifdef PSK_MAX_IDENTITY_LEN
	{ "psk_identity", FR_CONF_OFFSET(PW_TYPE_STRING, fr_tls_server_conf_t, psk_identity), NULL },
	{ "psk_hexphrase", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_SECRET, fr_tls_server_conf_t, psk_password), NULL },
#endif
	{ "dh_file", FR_CONF_OFFSET(PW_TYPE_STRING, fr_tls_server_conf_t, dh_file), NULL },
	{ "random_file", FR_CONF_OFFSET(PW_TYPE_STRING, fr_tls_server_conf_t, random_file), NULL },
	{ "fragment_size", FR_CONF_OFFSET(PW_TYPE_INTEGER, fr_tls_server_conf_t, fragment_size), "1024" },
	{ "include_length", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, fr_tls_server_conf_t, include_length), "yes" },
	{ "check_crl", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, fr_tls_server_conf_t, check_crl), "no" },
	{ "check_cert_cn", FR_CONF_OFFSET(PW_TYPE_STRING, fr_tls_server_conf_t, check_cert_cn), NULL },
	{ "cipher_list", FR_CONF_OFFSET(PW_TYPE_STRING, fr_tls_server_conf_t, cipher_list), NULL },
	{ "check_cert_issuer", FR_CONF_OFFSET(PW_TYPE_STRING, fr_tls_server_conf_t, check_cert_issuer), NULL },
	{ "ca_path_reload_interval", FR_CONF_OFFSET(PW_TYPE_INTEGER, fr_tls_server_conf_t, ca_path_reload_interval), "0" },

	{ "fix_cert_order", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, fr_tls_server_conf_t, fix_cert_order), NULL },

#if OPENSSL_VERSION_NUMBER >= 0x0090800fL
#ifndef OPENSSL_NO_ECDH
	{ "ecdh_curve", FR_CONF_OFFSET(PW_TYPE_STRING, fr_tls_server_conf_t, ecdh_curve), "prime256v1" },
#endif
#endif

#ifdef SSL_OP_NO_TLSv1
	{ "disable_tlsv1", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, fr_tls_server_conf_t, disable_tlsv1), NULL },
#endif

#ifdef SSL_OP_NO_TLSv1_1
	{ "disable_tlsv1_1", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, fr_tls_server_conf_t, disable_tlsv1_1), NULL },
#endif

#ifdef SSL_OP_NO_TLSv1_2
	{ "disable_tlsv1_2", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, fr_tls_server_conf_t, disable_tlsv1_2), NULL },
#endif

	{ "tls_max_version", FR_CONF_OFFSET(PW_TYPE_STRING, fr_tls_server_conf_t, tls_max_version), NULL },

	{ "tls_min_version", FR_CONF_OFFSET(PW_TYPE_STRING, fr_tls_server_conf_t, tls_min_version),
#if defined(TLS1_2_VERSION)
	  "1.2"
#elif defined(TLS1_1_VERSION)
	  "1.1"
#else
	  "1.0"
#endif
	},

#ifdef WITH_RADIUSV11
	{ "radiusv1_1", FR_CONF_OFFSET(PW_TYPE_STRING, fr_tls_server_conf_t, radiusv11_name), NULL },
#endif

	{ "hostname", FR_CONF_OFFSET(PW_TYPE_STRING, fr_tls_server_conf_t, client_hostname), NULL },

	CONF_PARSER_TERMINATOR
};


/*
 *	TODO: Check for the type of key exchange * like conf->dh_key
 */
static int load_dh_params(SSL_CTX *ctx, char *file)
{
	DH *dh = NULL;
	BIO *bio;

	/*
	 * Prior to trying to load the file, check what OpenSSL will do with it.
	 *
	 * Certain downstreams (such as RHEL) will ignore user-provided dhparams
	 * in FIPS mode, unless the specified parameters are FIPS-approved.
	 * However, since OpenSSL >= 1.1.1 will automatically select parameters
	 * anyways, there's no point in attempting to load them.
	 *
	 * Change suggested by @t8m
	 */
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
	if (FIPS_mode() > 0) {
		WARN(LOG_PREFIX ": Ignoring user-selected DH parameters in FIPS mode. Using defaults.");
		file = NULL;
	}

	/*
	 *	No dh file, set auto context.
	 */
	if (!file) {
		if (!SSL_CTX_set_dh_auto(ctx, 1)) {
			ERROR(LOG_PREFIX ": Unable to set DH parameters");
			return -1;
		}

		return 0;
	}

	WARN(LOG_PREFIX ": Setting DH parameters from %s - this is no longer necessary.", file);
	WARN(LOG_PREFIX ": You should comment out the 'dh_file' configuration item.");

#else
	if (!file) {
		WARN(LOG_PREFIX ": Cannot set DH parameters.  DH cipher suites may not work.");
		return 0;
	}
#endif


	if ((bio = BIO_new_file(file, "r")) == NULL) {
		ERROR(LOG_PREFIX ": Unable to open DH file - %s", file);
		return -1;
	}

	dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
	BIO_free(bio);
	if (!dh) {
		WARN(LOG_PREFIX ": Unable to set DH parameters.  DH cipher suites may not work!");
		WARN(LOG_PREFIX ": Fix this by running the OpenSSL command listed in eap.conf");
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


/*
 *	Print debugging messages, and free data.
 */
static void cbtls_remove_session(SSL_CTX *ctx, SSL_SESSION *sess)
{
	char			buffer[2 * MAX_SESSION_SIZE + 1];
	fr_tls_server_conf_t	*conf;

	tls_session_id(sess, buffer, MAX_SESSION_SIZE);

	conf = (fr_tls_server_conf_t *)SSL_CTX_get_app_data(ctx);
	if (!conf) {
		DEBUG(LOG_PREFIX ": Failed to find TLS configuration in session");
		return;
	}

	{
		int rv;
		char filename[3 * MAX_SESSION_SIZE + 1];

		DEBUG2(LOG_PREFIX ": Removing session %s from the cache", buffer);

		/* remove session and any cached VPs */
		snprintf(filename, sizeof(filename), "%s%c%s.asn1",
			 conf->session_cache_path, FR_DIR_SEP, buffer);
		rv = unlink(filename);
		if (rv != 0) {
			DEBUG2(LOG_PREFIX ": Could not remove persisted session file %s: %s",
			       filename, fr_syserror(errno));
		}
		/* VPs might be absent; might not have been written to disk yet */
		snprintf(filename, sizeof(filename), "%s%c%s.vps",
			 conf->session_cache_path, FR_DIR_SEP, buffer);
		unlink(filename);
	}

	return;
}

static int cbtls_new_session(SSL *ssl, SSL_SESSION *sess)
{
	char			buffer[2 * MAX_SESSION_SIZE + 1];
	fr_tls_server_conf_t	*conf;
	unsigned char		*sess_blob = NULL;

	REQUEST			*request = SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_REQUEST);

	conf = (fr_tls_server_conf_t *)SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_CONF);
	if (!conf) {
		RWDEBUG("(TLS) Failed to find TLS configuration in session");
		return 0;
	}

	tls_session_id(sess, buffer, MAX_SESSION_SIZE);

	{
		int fd, rv, todo, blob_len;
		char filename[3 * MAX_SESSION_SIZE + 1];
		unsigned char *p;

		RDEBUG2("Serialising session %s, and storing in cache", buffer);

		/* find out what length data we need */
		blob_len = i2d_SSL_SESSION(sess, NULL);
		if (blob_len < 1) {
			/* something went wrong */
			if (request) RWDEBUG("(TLS) %s - Session serialisation failed, could not determine required buffer length", conf->name);
			return 0;
		}

		/* Do not convert to TALLOC - Thread safety */
		/* alloc and convert to ASN.1 */
		sess_blob = malloc(blob_len);
		if (!sess_blob) {
			RWDEBUG("(TLS) %s - Session serialisation failed, couldn't allocate buffer (%d bytes)", conf->name, blob_len);
			return 0;
		}
		/* openssl mutates &p */
		p = sess_blob;
		rv = i2d_SSL_SESSION(sess, &p);
		if (rv != blob_len) {
			if (request) RWDEBUG("(TLS) %s - Session serialisation failed", conf->name);
			goto error;
		}

		/* open output file */
		snprintf(filename, sizeof(filename), "%s%c%s.asn1",
			 conf->session_cache_path, FR_DIR_SEP, buffer);
		fd = open(filename, O_RDWR|O_CREAT|O_EXCL, S_IWUSR);
		if (fd < 0) {
			if (request) RERROR("(TLS) %s - Session serialisation failed, failed opening session file %s: %s",
					    conf->name, filename, fr_syserror(errno));
			goto error;
		}

		/*
		 *	Set the filename to be temporarily write-only.
		 */
		if (request) {
			VALUE_PAIR *vp;

			vp = fr_pair_afrom_num(request->state_ctx, PW_TLS_CACHE_FILENAME, 0);
			if (vp) {
				fr_pair_value_strcpy(vp, filename);
				fr_pair_add(&request->state, vp);
			}
		}

		todo = blob_len;
		p = sess_blob;
		while (todo > 0) {
			rv = write(fd, p, todo);
			if (rv < 1) {
				if (request) RWDEBUG("(TLS) %s - Failed writing session: %s", conf->name, fr_syserror(errno));
				close(fd);
				goto error;
			}
			p += rv;
			todo -= rv;
		}
		close(fd);
		if (request) RWDEBUG("(TLS) %s - Wrote session %s to %s (%d bytes)", conf->name, buffer, filename, blob_len);
	}

error:
	free(sess_blob);

	return 0;
}

/** Convert OpenSSL's ASN1_TIME to an epoch time
 *
 * @param[out] out	Where to write the time_t.
 * @param[in] asn1	The ASN1_TIME to convert.
 * @return
 *	- 0 success.
 *	- -1 on failure.
 */
static int ocsp_asn1time_to_epoch(time_t *out, char const *asn1)
{
	struct		tm t;
	char const	*p = asn1, *end = p + strlen(p);

	memset(&t, 0, sizeof(t));

	if ((end - p) <= 13) {
		if ((end - p) < 2) {
			fr_strerror_printf("ASN1 date string too short, expected 2 additional bytes, got %zu bytes",
					   end - p);
			return -1;
		}

		t.tm_year = (*(p++) - '0') * 10;
		t.tm_year += (*(p++) - '0');
		if (t.tm_year < 70) t.tm_year += 100;
	} else {
		t.tm_year = (*(p++) - '0') * 1000;
		t.tm_year += (*(p++) - '0') * 100;
		t.tm_year += (*(p++) - '0') * 10;
		t.tm_year += (*(p++) - '0');
		t.tm_year -= 1900;
	}

	if ((end - p) < 4) {
		fr_strerror_printf("ASN1 string too short, expected 10 additional bytes, got %zu bytes",
				   end - p);
		return -1;
	}

	t.tm_mon = (*(p++) - '0') * 10;
	t.tm_mon += (*(p++) - '0') - 1; // -1 since January is 0 not 1.
	t.tm_mday = (*(p++) - '0') * 10;
	t.tm_mday += (*(p++) - '0');

	if ((end - p) < 2) goto done;
	t.tm_hour = (*(p++) - '0') * 10;
	t.tm_hour += (*(p++) - '0');

	if ((end - p) < 2) goto done;
	t.tm_min = (*(p++) - '0') * 10;
	t.tm_min += (*(p++) - '0');

	if ((end - p) < 2) goto done;
	t.tm_sec = (*(p++) - '0') * 10;
	t.tm_sec += (*(p++) - '0');

	/* Apparently OpenSSL converts all timestamps to UTC? Maybe? */
done:
	*out = timegm(&t);
	return 0;
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
static SSL_SESSION *cbtls_get_session(SSL *ssl, unsigned char *data, int len, int *copy)
#else
static SSL_SESSION *cbtls_get_session(SSL *ssl, const unsigned char *data, int len, int *copy)
#endif
{
	size_t			size;
	char			buffer[2 * MAX_SESSION_SIZE + 1];
	fr_tls_server_conf_t	*conf;
	TALLOC_CTX		*talloc_ctx;

	SSL_SESSION		*sess = NULL;
	unsigned char		*sess_data = NULL;
	PAIR_LIST		*pairlist = NULL;

	REQUEST			*request = SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_REQUEST);

	rad_assert(request != NULL);

	size = len;
	if (size > MAX_SESSION_SIZE) size = MAX_SESSION_SIZE;

	fr_bin2hex(buffer, data, size);

	RDEBUG2("Peer requested cached session: %s", buffer);

	*copy = 0;

	conf = (fr_tls_server_conf_t *)SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_CONF);
	if (!conf) {
		RWDEBUG("(TLS) Failed to find TLS configuration in session");
		return NULL;
	}

	talloc_ctx = SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_TALLOC);

	{
		int		rv, fd, todo;
		char		filename[3 * MAX_SESSION_SIZE + 1];

		unsigned char const	**o;
		unsigned char		**p;
		uint8_t			*q;

		struct stat	st;
		VALUE_PAIR	*vps = NULL;
		VALUE_PAIR	*vp;

		/* load the actual SSL session */
		snprintf(filename, sizeof(filename), "%s%c%s.asn1", conf->session_cache_path, FR_DIR_SEP, buffer);
		fd = open(filename, O_RDONLY);
		if (fd < 0) {
			RWDEBUG("(TLS) %s - No persisted session file %s: %s", conf->name, filename, fr_syserror(errno));
			goto error;
		}

		rv = fstat(fd, &st);
		if (rv < 0) {
			RWDEBUG("(TLS) %s - Failed stating persisted session file %s: %s", conf->name, filename, fr_syserror(errno));
			close(fd);
			goto error;
		}

		sess_data = talloc_array(NULL, unsigned char, st.st_size);
		if (!sess_data) {
			RWDEBUG("(TLS) %s- Failed allocating buffer for persisted session (%d bytes)", conf->name, (int) st.st_size);
			close(fd);
			goto error;
		}

		q = sess_data;
		todo = st.st_size;
		while (todo > 0) {
			rv = read(fd, q, todo);
			if (rv < 1) {
				RWDEBUG("(TLS) %s - Failed reading persisted session: %s", conf->name, fr_syserror(errno));
				close(fd);
				goto error;
			}
			todo -= rv;
			q += rv;
		}
		close(fd);

		/*
		 *	OpenSSL mutates what's passed in, so we assign sess_data to q,
		 *	so the value of q gets mutated, and not the value of sess_data.
		 *
		 *	We then need a pointer to hold &q, but it can't be const, because
		 *	clang complains about lack of consting in nested pointer types.
		 *
		 *	So we memcpy the value of that pointer, to one that
		 *	does have a const, which we then pass into d2i_SSL_SESSION *sigh*.
		 */
		q = sess_data;
		p = &q;
		memcpy(&o, &p, sizeof(o));
		sess = d2i_SSL_SESSION(NULL, o, st.st_size);
		if (!sess) {
			RWDEBUG("(TLS) %s - Failed loading persisted session: %s", conf->name, ERR_error_string(ERR_get_error(), NULL));
			goto error;
		}

		/* read in the cached VPs from the .vps file */
		snprintf(filename, sizeof(filename), "%s%c%s.vps",
			 conf->session_cache_path, FR_DIR_SEP, buffer);
		rv = pairlist_read(talloc_ctx, filename, &pairlist, 1);
		if (rv < 0) {
			/* not safe to un-persist a session w/o VPs */
			RWDEBUG("(TLS) %s - Failed loading persisted VPs for session %s", conf->name, buffer);
			SSL_SESSION_free(sess);
			sess = NULL;
			goto error;
		}

		/*
		 *	Enforce client certificate expiration.
		 */
		vp = fr_pair_find_by_num(pairlist->reply, PW_TLS_CLIENT_CERT_EXPIRATION, 0, TAG_ANY);
		if (vp) {
			time_t expires;

			if (ocsp_asn1time_to_epoch(&expires, vp->vp_strvalue) < 0) {
				RDEBUG2("(TLS) %s - Failed getting certificate expiration, removing cache entry for session %s - %s", conf->name, buffer, fr_strerror());
				SSL_SESSION_free(sess);
				sess = NULL;
				goto error;
			}

			if (expires <= request->timestamp) {
				RDEBUG2("Certificate has expired, removing cache entry for session %s", buffer);
				SSL_SESSION_free(sess);
				sess = NULL;
				goto error;
			}

			/*
			 *	Account for Session-Timeout, if it's available.
			 */
			vp = fr_pair_find_by_num(request->reply->vps, PW_SESSION_TIMEOUT, 0, TAG_ANY);
			if (vp) {
				if ((request->timestamp + vp->vp_integer) > expires) {
					vp->vp_integer = expires - request->timestamp;
					RWDEBUG2("(TLS) %s - Updating Session-Timeout to %u, due to impending certificate expiration",
						 conf->name, vp->vp_integer);
				}
			}
		}

		/*
		 *	Resumption MUST use the same EAP type as from
		 *	the original packet.
		 */
		vp = fr_pair_find_by_num(pairlist->reply, PW_EAP_TYPE, 0, TAG_ANY);
		if (vp) {
			VALUE_PAIR *type = fr_pair_find_by_num(request->packet->vps, PW_EAP_TYPE, 0, TAG_ANY);

			if (type && (type->vp_integer != vp->vp_integer)) {
				REDEBUG("(TLS) %s - Resumption has changed EAP types for session %s", conf->name, buffer);
				REDEBUG("(TLS) %s - Rejecting session due to protocol violations", conf->name);
				goto error;
			}
		}

		/* move the cached VPs into the session */
		fr_pair_list_mcopy_by_num(talloc_ctx, &vps, &pairlist->reply, 0, 0, TAG_ANY);

		SSL_SESSION_set_ex_data(sess, fr_tls_ex_index_vps, vps);
		RDEBUG("Successfully restored session %s", buffer);
		rdebug_pair_list(L_DBG_LVL_2, request, vps, "reply:");

		/*
		 *	The "restore VPs from OpenSSL cache" code is
		 *	now in eaptls_process()
		 */
	}
error:
	if (sess_data) talloc_free(sess_data);
	if (pairlist) pairlist_free(&pairlist);

	return sess;
}

static size_t tls_session_id_binary(SSL_SESSION *ssn, uint8_t *buffer, size_t bufsize)
{
#if OPENSSL_VERSION_NUMBER < 0x10001000L
	size_t size;

	size = ssn->session_id_length;
	if (size > bufsize) size = bufsize;

	memcpy(buffer, ssn->session_id, size);
	return size;
#else
	unsigned int size;
	uint8_t const *p;

	p = SSL_SESSION_get_id(ssn, &size);
	if (size > bufsize) size = bufsize;

	memcpy(buffer, p, size);
	return size;
#endif
}

/*
 *	From TLS-Cache-Method
 *
 *	All of the save / clear / load callbacks are done with any
 *	OpenSSL locks *unlocked*.  So says the OpenSSL code.
 */
#define CACHE_SAVE (1)
#define CACHE_LOAD (2)
#define CACHE_CLEAR (3)
#define CACHE_REFRESH (4)

static REQUEST *cache_init_fake_request(fr_tls_server_conf_t const *conf, SSL_SESSION *sess, SSL *ssl,
					uint8_t const *data, size_t size)
{
	VALUE_PAIR		*vp;
	REQUEST			*fake, *request = NULL;
	uint8_t			buffer[MAX_SESSION_SIZE];

	if (sess) {
		size = tls_session_id_binary(sess, buffer, sizeof(buffer));
		data = buffer;
	}

	/*
	 *	We get called essentially at random by OpenSSL, with
	 *	no information other than the session ID.  As a
	 *	result, we have to manually set up our own request.
	 */
	if (ssl) request = SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_REQUEST);

	if (request) {
		fake = request_alloc_fake(request);
	} else {
		fake = request_alloc(NULL);
		fake->packet = rad_alloc(fake, false);
		fake->reply = rad_alloc(fake, false);
	}

	vp = fr_pair_afrom_num(fake->packet, PW_TLS_SESSION_ID, 0);
	if (!vp) {
		talloc_free(fake);
		return NULL;
	}

	fr_pair_value_memcpy(vp, data, size);
	fr_pair_add(&fake->packet->vps, vp);

	fake->server = conf->session_cache_server;

	return fake;
}

/*
 *	Clear cached data
 */
static void cbtls_cache_clear(SSL_CTX *ctx, SSL_SESSION *sess)
{
	fr_tls_server_conf_t	*conf;
	REQUEST			*fake;

	conf = (fr_tls_server_conf_t *)SSL_CTX_get_app_data(ctx);
	if (!conf) {
		DEBUG(LOG_PREFIX ": Failed to find TLS configuration in session");
		return;
	}

	/*
	 *	Find the SSL ID from the session, and delete it.
	 *
	 *	Don't bother with any parent request.  We're in a
	 *	timer callback, and there is no request available.
	 */
	fake = cache_init_fake_request(conf, sess, NULL, NULL, 0);
	if (!fake) return;

	/*
	 *	Use &request:TLS-Session-Id to clear the cache entry.
	 */
	(void) process_post_auth(CACHE_CLEAR, fake);
	talloc_free(fake);
	return;
}

/*
 *	OpenSSL calls this function in order to save the session
 *	BEFORE it has sent the final TLS success.  So our process here
 *	is to say "yes, we saved it", and then do the *actual* saving
 *	after the TLS success has been sent.
 */
static int cbtls_cache_save(UNUSED SSL *ssl, UNUSED SSL_SESSION *sess)
{
	return 0;
}

static int cbtls_cache_save_vps(SSL *ssl, SSL_SESSION *sess, VALUE_PAIR *vps)
{
	fr_tls_server_conf_t	*conf;
	VALUE_PAIR		*vp;
	REQUEST			*fake = NULL;
	size_t			size, rv;
	uint8_t			*p, *sess_blob = NULL;

	conf = (fr_tls_server_conf_t *)SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_CONF);
	if (!conf) return 0;

	/*
	 *	Find the SSL ID from the session, and save it.
	 *
	 *	Save anything from the parent request.
	 */
	fake = cache_init_fake_request(conf, sess, ssl, NULL, 0);
	if (!fake) return 0;

	/* find out what length data we need */
	size = i2d_SSL_SESSION(sess, NULL);
	if (size < 1) return 0;

	/* Do not convert to TALLOC - it's passed to OpenSSL */
	/* alloc and convert to ASN.1 */
	MEM(sess_blob = malloc(size));

	/* openssl mutates &p */
	p = sess_blob;
	rv = i2d_SSL_SESSION(sess, &p);
	if (rv != size) goto error;

	vp = fr_pair_afrom_num(fake->state_ctx, PW_TLS_SESSION_DATA, 0);
	if (!vp) goto error;

	fr_pair_value_memcpy(vp, sess_blob, size);
	fr_pair_add(&fake->state, vp);

	if (vps) fr_pair_add(&fake->reply->vps, fr_pair_list_copy(fake->reply, vps));

	/*
	 *	Use &request:TLS-Session-Id to save the
	 *	&session-state:TLS-Session-Data values.
	 *
	 *	The current &reply: list is the list of VPs which
	 *	should be cached.
	 *
	 *	Any other attributes which need to be saved can be
	 *	read from the &outer.reply: list.
	 */
	(void) process_post_auth(CACHE_SAVE, fake);

error:
	if (fake) talloc_free(fake);
	free(sess_blob);

	return 0;
}

static int cbtls_cache_refresh(SSL *ssl, SSL_SESSION *sess)
{
	fr_tls_server_conf_t	*conf;
	REQUEST			*fake = NULL;

	conf = (fr_tls_server_conf_t *)SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_CONF);
	if (!conf) return 0;

	/*
	 *	Find the SSL ID from the session, and save it.
	 *
	 *	Save anything from the parent request.
	 */
	fake = cache_init_fake_request(conf, sess, ssl, NULL, 0);
	if (!fake) return 0;
	/*
	 *	Use &request:TLS-Session-Id to update the cache
	 *	entry so that it doesn't not expire.
	 */
	(void) process_post_auth(CACHE_REFRESH, fake);

	talloc_free(fake);

	return 0;
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
static SSL_SESSION *cbtls_cache_load(SSL *ssl, unsigned char *data, int len, int *copy)
#else
static SSL_SESSION *cbtls_cache_load(SSL *ssl, const unsigned char *data, int len, int *copy)
#endif
{
	fr_tls_server_conf_t	*conf;
	size_t			size;
	uint8_t const  		*p;
	VALUE_PAIR		*vp, *vps;
	TALLOC_CTX		*talloc_ctx;
	SSL_SESSION		*sess = NULL;
	REQUEST			*fake = NULL;
	REQUEST			*request = SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_REQUEST);
	char			buffer[2 * MAX_SESSION_SIZE + 1];

	conf = (fr_tls_server_conf_t *)SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_CONF);
	if (!conf) return NULL;

	rad_assert(request);

	size = len;
	if (size > MAX_SESSION_SIZE) size = MAX_SESSION_SIZE;

	if (fr_debug_lvl > 1) {
		fr_bin2hex(buffer, data, size);
		RDEBUG2("Peer requested cached session: %s", buffer);
	}

	*copy = 0;

	/*
	 *	Take the given SSL ID, and create a fake request.
	 *
	 *	Don't bother parenting it from another request.  We do
	 *	this for a number of reasons.
	 *
	 *	One is that rest of the code expects that the VPs will
	 *	be added to fr_tls_ex_index_vps.  So we don't want to
	 *	be poking the request directly, as that will result in
	 *	a change of behavior.
	 *
	 *	The larger reason is that we do _not_ want to actually
	 *	update the reply, until such time as we know that the
	 *	user has been authenticated.
	 */
	fake = cache_init_fake_request(conf, NULL, NULL, data, size);
	if (!fake) return 0;

	/*
	 *	Use &request:TLS-Session-Id to load the cached
	 *	session.
	 *
	 *	The "cache load { ...}" section should put the reply
	 *	attributes into the &reply: list, and the
	 *	&session-state:TLS-Session-Data attribute.
	 *
	 *	Why?  Because v4 does it that way, and there aren't
	 *	really good reasons for doing it differently.
	 */
	(void) process_post_auth(CACHE_LOAD, fake);

	/*
	 *	Enforce client certificate expiration.
	 */
	vp = fr_pair_find_by_num(fake->reply->vps, PW_TLS_CLIENT_CERT_EXPIRATION, 0, TAG_ANY);
	if (vp) {
		time_t expires;

		if (ocsp_asn1time_to_epoch(&expires, vp->vp_strvalue) < 0) {
			RDEBUG2("Failed getting certificate expiration, removing cache entry for session %s - %s", buffer, fr_strerror());
			SSL_SESSION_free(sess);
			sess = NULL;
			goto error;
		}

		if (expires <= request->timestamp) {
			RDEBUG2("Certificate has expired, removing cache entry for session %s", buffer);
			SSL_SESSION_free(sess);
			sess = NULL;
			goto error;
		}

		/*
		 *	Account for Session-Timeout, if it's available.
		 */
		vp = fr_pair_find_by_num(request->reply->vps, PW_SESSION_TIMEOUT, 0, TAG_ANY);
		if (vp) {
			if ((request->timestamp + vp->vp_integer) > expires) {
				vp->vp_integer = expires - request->timestamp;
				RWDEBUG2("(TLS) %s - Updating Session-Timeout to %u, due to impending certificate expiration",
					 conf->name, vp->vp_integer);
			}
		}
	}

	/*
	 *	Try to de-serialize the session data.
	 */
	vp = fr_pair_find_by_num(fake->state, PW_TLS_SESSION_DATA, 0, TAG_ANY);
	if (!vp) {
		RWDEBUG("(TLS) %s - Failed to find TLS-Session-Data in 'session-state' list for session %s", conf->name, buffer);
		goto error;
	}

	/*
	 *	OpenSSL mutates what's passed in, so we assign sess_data to q,
	 *	so the value of q gets mutated, and not the value of sess_data.
	 *
	 *	We then need a pointer to hold &q, but it can't be const, because
	 *	clang complains about lack of consting in nested pointer types.
	 *
	 *	So we memcpy the value of that pointer, to one that
	 *	does have a const, which we then pass into d2i_SSL_SESSION *sigh*.
	 */
	p = vp->vp_octets;
	sess = d2i_SSL_SESSION(NULL, &p, vp->vp_length);
	if (!sess) {
		RWDEBUG("(TLS) %s - Failed loading persisted session: %s", conf->name, ERR_error_string(ERR_get_error(), NULL));
		goto error;
	}

	talloc_ctx = SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_TALLOC);
	vps = NULL;

	/* move the cached VPs into the session */
	fr_pair_list_mcopy_by_num(talloc_ctx, &vps, &fake->reply->vps, 0, 0, TAG_ANY);

	SSL_SESSION_set_ex_data(sess, fr_tls_ex_index_vps, vps);
	RDEBUG("Successfully restored session %s", buffer);
	rdebug_pair_list(L_DBG_LVL_2, request, vps, "reply:");

	/*
	 *	The "restore VPs from OpenSSL cache" code is
	 *	now in eaptls_process()
	 */

error:
	if (fake) talloc_free(fake);

	return sess;
}

#ifdef HAVE_OPENSSL_OCSP_H

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
static int ocsp_parse_cert_url(X509 *cert, char **host_out, char **port_out,
			       char **path_out, int *is_https)
{
	int			i;

	AUTHORITY_INFO_ACCESS	*aia;
	ACCESS_DESCRIPTION	*ad;
	int			ret = -1;

	aia = X509_get_ext_d2i(cert, NID_info_access, NULL, NULL);

	if (!aia) return 0;

	for (i = 0; i < sk_ACCESS_DESCRIPTION_num(aia); i++) {
		ad = sk_ACCESS_DESCRIPTION_value(aia, i);
		if (OBJ_obj2nid(ad->method) != NID_ad_OCSP) continue;
		if (ad->location->type != GEN_URI) continue;

		if (OCSP_parse_url((char *) ad->location->d.ia5->data, host_out,
				   port_out, path_out, is_https)) {
			ret = 1;
			break;
		}
	}
	AUTHORITY_INFO_ACCESS_free(aia);
	return ret;
}

/*
 * This function sends a OCSP request to a defined OCSP responder
 * and checks the OCSP response for correctness.
 */

/* Maximum leeway in validity period: default 5 minutes */
#define MAX_VALIDITY_PERIOD     (5 * 60)

typedef enum {
	OCSP_STATUS_FAILED	= 0,
	OCSP_STATUS_OK		= 1,
	OCSP_STATUS_SKIPPED	= 2,
} ocsp_status_t;

static ocsp_status_t ocsp_check(REQUEST *request, X509_STORE *store, X509 *issuer_cert, X509 *client_cert,
				STACK_OF(X509) *untrusted, fr_tls_server_conf_t *conf)
{
	OCSP_CERTID	*certid;
	OCSP_REQUEST	*req;
	OCSP_RESPONSE	*resp = NULL;
	OCSP_BASICRESP	*bresp = NULL;
	char		*host = NULL;
	char		*port = NULL;
	char		*path = NULL;
	char		hostheader[1024];
	int		use_ssl = -1;
	long		nsec = MAX_VALIDITY_PERIOD, maxage = -1;
	BIO		*cbio, *bio_out;
	ocsp_status_t	ocsp_status = OCSP_STATUS_FAILED;
	int		status;
	ASN1_GENERALIZEDTIME *rev = NULL, *thisupd, *nextupd;
	int		reason;
#if OPENSSL_VERSION_NUMBER >= 0x1000003f
	OCSP_REQ_CTX	*ctx;
	int		rc;
	struct timeval	now;
	struct timeval	when;
#endif
	VALUE_PAIR	*vp;

	if (issuer_cert == NULL) {
		RWDEBUG("(TLS) Could not get issuer certificate");
		goto skipped;
	}

	/*
	 * Create OCSP Request
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
			RWDEBUG("(TLS) ocsp: Host or port or path missing from configured URL \"%s\".  Not doing OCSP", url);
			goto skipped;
		}
	} else {
		int ret;

		ret = ocsp_parse_cert_url(client_cert, &host, &port, &path, &use_ssl);
		switch (ret) {
		case -1:
			RWDEBUG("(TLS) ocsp: Invalid URL in certificate.  Not doing OCSP");
			goto skipped;

		case 0:
			if (conf->ocsp_url) {
				RWDEBUG("(TLS) ocsp: No OCSP URL in certificate, falling back to configured URL");
				goto use_ocsp_url;
			}
			RWDEBUG("(TLS) ocsp: No OCSP URL in certificate.  Not doing OCSP");
			goto skipped;

		case 1:
			break;
		}
	}

	RDEBUG2("ocsp: Using responder URL \"http://%s:%s%s\"", host, port, path);

	/* Check host and port length are sane, then create Host: HTTP header */
	if ((strlen(host) + strlen(port) + 2) > sizeof(hostheader)) {
		RWDEBUG("(TLS) ocsp: Host and port too long");
		goto skipped;
	}
	snprintf(hostheader, sizeof(hostheader), "%s:%s", host, port);

	/* Setup BIO socket to OCSP responder */
	cbio = BIO_new_connect(host);

	bio_out = NULL;
	if (rad_debug_lvl) {
		if (default_log.dst == L_DST_STDOUT) {
			bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
		} else if (default_log.dst == L_DST_STDERR) {
			bio_out = BIO_new_fp(stderr, BIO_NOCLOSE);
		}
	}

	BIO_set_conn_port(cbio, port);
#if OPENSSL_VERSION_NUMBER < 0x1000003f
	BIO_do_connect(cbio);

	/* Send OCSP request and wait for response */
	resp = OCSP_sendreq_bio(cbio, path, req);
	if (!resp) {
		REDEBUG("ocsp: Couldn't get OCSP response");
		ocsp_status = OCSP_STATUS_SKIPPED;
		goto ocsp_end;
	}
#else
	if (conf->ocsp_timeout)
		BIO_set_nbio(cbio, 1);

	rc = BIO_do_connect(cbio);
	if ((rc <= 0) && ((!conf->ocsp_timeout) || !BIO_should_retry(cbio))) {
		REDEBUG("ocsp: Couldn't connect to OCSP responder");
		ocsp_status = OCSP_STATUS_SKIPPED;
		goto ocsp_end;
	}

	ctx = OCSP_sendreq_new(cbio, path, NULL, -1);
	if (!ctx) {
		REDEBUG("ocsp: Couldn't create OCSP request");
		ocsp_status = OCSP_STATUS_SKIPPED;
		goto ocsp_end;
	}

	if (!OCSP_REQ_CTX_add1_header(ctx, "Host", hostheader)) {
		REDEBUG("ocsp: Couldn't set Host header");
		ocsp_status = OCSP_STATUS_SKIPPED;
		goto ocsp_end;
	}

	if (!OCSP_REQ_CTX_set1_req(ctx, req)) {
		REDEBUG("ocsp: Couldn't add data to OCSP request");
		ocsp_status = OCSP_STATUS_SKIPPED;
		goto ocsp_end;
	}

	gettimeofday(&when, NULL);
	when.tv_sec += conf->ocsp_timeout;

	do {
		rc = OCSP_sendreq_nbio(&resp, ctx);
		if (conf->ocsp_timeout) {
			gettimeofday(&now, NULL);
			if (!timercmp(&now, &when, <))
				break;
		}
	} while ((rc == -1) && BIO_should_retry(cbio));

	if (conf->ocsp_timeout && (rc == -1) && BIO_should_retry(cbio)) {
		REDEBUG("ocsp: Response timed out");
		ocsp_status = OCSP_STATUS_SKIPPED;
		goto ocsp_end;
	}

	OCSP_REQ_CTX_free(ctx);

	if (rc == 0) {
		REDEBUG("ocsp: Couldn't get OCSP response");
		ocsp_status = OCSP_STATUS_SKIPPED;
		goto ocsp_end;
	}
#endif

	/* Verify OCSP response status */
	status = OCSP_response_status(resp);
	if (status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
		REDEBUG("ocsp: Response status: %s", OCSP_response_status_str(status));
		goto ocsp_end;
	}
	bresp = OCSP_response_get1_basic(resp);
	if (!bresp) {
		tls_error_log(request, "ocsp: Failed parsing response");
		goto ocsp_end;
	}

	if (conf->ocsp_use_nonce && OCSP_check_nonce(req, bresp)!=1) {
		REDEBUG("ocsp: Response has wrong nonce value");
		goto ocsp_end;
	}
	if (OCSP_basic_verify(bresp, untrusted, store, 0)!=1){
		tls_error_log(request, "ocsp: Couldn't verify OCSP basic response");
		goto ocsp_end;
	}

	/*	Verify OCSP cert status */
	if (!OCSP_resp_find_status(bresp, certid, &status, &reason, &rev, &thisupd, &nextupd)) {
		tls_error_log(request, "ocsp: No Status found");
		goto ocsp_end;
	}

	if (!OCSP_check_validity(thisupd, nextupd, nsec, maxage)) {
		if (bio_out) {
			BIO_puts(bio_out, "WARNING: Status times invalid.\n");
			ERR_print_errors(bio_out);
		}
		goto ocsp_end;
	}

	if (bio_out) {
		BIO_puts(bio_out, "\tThis Update: ");
		ASN1_GENERALIZEDTIME_print(bio_out, thisupd);
		BIO_puts(bio_out, "\n");
		if (nextupd) {
			BIO_puts(bio_out, "\tNext Update: ");
			ASN1_GENERALIZEDTIME_print(bio_out, nextupd);
			BIO_puts(bio_out, "\n");
		}
	}

	switch (status) {
	case V_OCSP_CERTSTATUS_GOOD:
		RDEBUG2("ocsp: Cert status: good");
		vp = pair_make_request("TLS-OCSP-Cert-Valid", NULL, T_OP_SET);
		vp->vp_integer = 1;	/* yes */
		ocsp_status = OCSP_STATUS_OK;
		break;

	default:
		/* REVOKED / UNKNOWN */
		REDEBUG("ocsp: Cert status: %s", OCSP_cert_status_str(status));
		if (reason != -1) REDEBUG("ocsp: Reason: %s", OCSP_crl_reason_str(reason));

		if (bio_out && rev) {
			BIO_puts(bio_out, "\tRevocation Time: ");
			ASN1_GENERALIZEDTIME_print(bio_out, rev);
			BIO_puts(bio_out, "\n");
		}
		break;
	}

ocsp_end:
	/* Free OCSP Stuff */
	OCSP_REQUEST_free(req);
	OCSP_RESPONSE_free(resp);
	free(host);
	free(port);
	free(path);
	BIO_free_all(cbio);
	if (bio_out) BIO_free(bio_out);
	OCSP_BASICRESP_free(bresp);

	switch (ocsp_status) {
	case OCSP_STATUS_OK:
		RDEBUG2("ocsp: Certificate is valid");
		break;

	case OCSP_STATUS_SKIPPED:
	skipped:
		vp = pair_make_request("TLS-OCSP-Cert-Valid", NULL, T_OP_SET);
		vp->vp_integer = 2;	/* skipped */
		if (conf->ocsp_softfail) {
			RWDEBUG("(TLS) ocsp: Unable to check certificate, assuming it's valid");
			RWDEBUG("(TLS) ocsp: This may be insecure");

			/* Remove OpenSSL errors from queue or handshake will fail */
			while (ERR_get_error());

			ocsp_status = OCSP_STATUS_SKIPPED;
		} else {
			REDEBUG("(TLS) ocsp: Unable to check certificate, failing");
			ocsp_status = OCSP_STATUS_FAILED;
		}
		break;

	default:
		vp = pair_make_request("TLS-OCSP-Cert-Valid", NULL, T_OP_SET);
		vp->vp_integer = 0;	/* no */
		REDEBUG("(TLS) ocsp: Certificate has been expired/revoked");
		break;
	}

	return ocsp_status;
}
#endif	/* HAVE_OPENSSL_OCSP_H */

/*
 *	For creating certificate attributes.
 */
static char const *cert_attr_names[11][2] = {
	{ "TLS-Client-Cert-Serial",			"TLS-Cert-Serial" },
	{ "TLS-Client-Cert-Expiration",			"TLS-Cert-Expiration" },
	{ "TLS-Client-Cert-Subject",			"TLS-Cert-Subject" },
	{ "TLS-Client-Cert-Issuer",			"TLS-Cert-Issuer" },
	{ "TLS-Client-Cert-Common-Name",		"TLS-Cert-Common-Name" },
	{ "TLS-Client-Cert-Subject-Alt-Name-Email",	"TLS-Cert-Subject-Alt-Name-Email" },
	{ "TLS-Client-Cert-Subject-Alt-Name-Dns",	"TLS-Cert-Subject-Alt-Name-Dns" },
	{ "TLS-Client-Cert-Subject-Alt-Name-Upn",	"TLS-Cert-Subject-Alt-Name-Upn" },
	{ "TLS-Client-Cert-Valid-Since",		"TLS-Cert-Valid-Since" },
	{ "TLS-Client-Cert-Subject-Alt-Name-Uri",	"TLS-Cert-Subject-Alt-Name-Uri" },
	{ "TLS-Client-Cert-CRL-Distribution-Points",	"TLS-Cert-CRL-Distribution-Points"},
};

#define FR_TLS_SERIAL		(0)
#define FR_TLS_EXPIRATION	(1)
#define FR_TLS_SUBJECT		(2)
#define FR_TLS_ISSUER		(3)
#define FR_TLS_CN		(4)
#define FR_TLS_SAN_EMAIL       	(5)
#define FR_TLS_SAN_DNS          (6)
#define FR_TLS_SAN_UPN          (7)
#define FR_TLS_VALID_SINCE	(8)
#define FR_TLS_SAN_URI		(9)
#define FR_TLS_CDP		(10)

/*
 *	Extract Certification Distribution point URL from the certificate
 */
static const char *get_cdp_url(DIST_POINT *dp)
{
	GENERAL_NAMES *gens;
	GENERAL_NAME *gen;
	int i, gtype;
	ASN1_STRING *uri;

	if (!dp->distpoint || (dp->distpoint->type != 0)) {
		return NULL;
	}

	gens = dp->distpoint->name.fullname;

	for (i = 0; i < sk_GENERAL_NAME_num(gens); i++) {
		gen = sk_GENERAL_NAME_value(gens, i);
		uri = GENERAL_NAME_get0_value(gen, &gtype);

		if ((gtype == GEN_URI) && (ASN1_STRING_length(uri) > 6)) {
			return (const char *) ASN1_STRING_get0_data(uri);
		}
	}

	return NULL;
}


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
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
	const STACK_OF(X509_EXTENSION) *ext_list;
#else
	STACK_OF(X509_EXTENSION) *ext_list;
#endif
	SSL		*ssl;
	int		err, depth, lookup, loc;
	fr_tls_server_conf_t *conf;
	int		my_ok = ok;

	ASN1_INTEGER	*sn = NULL;
	ASN1_TIME	*asn_time = NULL;
	VALUE_PAIR	**certs;
	char **identity;
#ifdef HAVE_OPENSSL_OCSP_H
	X509_STORE	*ocsp_store = NULL;
	X509		*issuer_cert;
	bool		do_verify = false;
#endif
	VALUE_PAIR	*vp;
	TALLOC_CTX	*talloc_ctx;
	STACK_OF(DIST_POINT) *crl_dp;

	REQUEST		*request;

	client_cert = X509_STORE_CTX_get_current_cert(ctx);
	err = X509_STORE_CTX_get_error(ctx);
	depth = X509_STORE_CTX_get_error_depth(ctx);

	lookup = depth;

	/*
	 * Retrieve the pointer to the SSL of the connection currently treated
	 * and the application specific data stored into the SSL object.
	 */
	ssl = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
	conf = (fr_tls_server_conf_t *)SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_CONF);
	if (!conf) return 1;

	request = (REQUEST *)SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_REQUEST);
	rad_assert(request != NULL);
	certs = (VALUE_PAIR **)SSL_get_ex_data(ssl, fr_tls_ex_index_certs);

	identity = (char **)SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_IDENTITY);
#ifdef HAVE_OPENSSL_OCSP_H
	ocsp_store = conf->ocsp_store;
#endif

	talloc_ctx = SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_TALLOC);

	/*
	 *	Log client/issuing cert.  If there's an error, log
	 *	issuing cert.
	 *
	 *	Inbound:   0 = client, 1 = server (intermediate CA), 2 = issuing CA
	 *	Outbound:  0 = server, 2 = issuing CA.
	 *
	 *	Our array of certificates uses 0 for client, and 1 for server.  We
	 *	also ignore subsequent certs.
	 */
	if (lookup > 1) {
		if (!my_ok) lookup = 1;

	} else if (lookup == 0) {
		/*
		 *	This flag is only set for outbound
		 *	connections.  And then allows us to remap SSL
		 *	offset 0 (server) to our offset 1 (also
		 *	server).
		 */
		lookup = (SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_FIX_CERT_ORDER) != NULL);
	}

	/*
	 *	Get the Serial Number
	 */
	buf[0] = '\0';
	sn = X509_get_serialNumber(client_cert);

	RDEBUG2("(TLS) %s - Creating attributes from certificate %d in chain", conf->name, lookup + 1);
 	RINDENT();

	/*
	 *	For this next bit, we create the attributes *only* if
	 *	we're at the client or issuing certificate.
	 */
	if (certs &&
	    (lookup <= 1) && sn && ((size_t) sn->length < (sizeof(buf) / 2))) {
		char *p = buf;
		int i;

		for (i = 0; i < sn->length; i++) {
			sprintf(p, "%02x", (unsigned int)sn->data[i]);
			p += 2;
		}
		vp = fr_pair_make(talloc_ctx, certs, cert_attr_names[FR_TLS_SERIAL][lookup], buf, T_OP_SET);
		rdebug_pair(L_DBG_LVL_2, request, vp, NULL);
	}

	/*
	 *	Get the Expiration Date
	 */
	buf[0] = '\0';
	asn_time = X509_get_notAfter(client_cert);
	if (certs && (lookup <= 1) && asn_time &&
	    (asn_time->length < (int) sizeof(buf))) {
		memcpy(buf, (char*) asn_time->data, asn_time->length);
		buf[asn_time->length] = '\0';
		vp = fr_pair_make(talloc_ctx, certs, cert_attr_names[FR_TLS_EXPIRATION][lookup], buf, T_OP_SET);
		rdebug_pair(L_DBG_LVL_2, request, vp, NULL);
	}

	/*
	 *	Get the Valid Since Date
	 */
	buf[0] = '\0';
	asn_time = X509_get_notBefore(client_cert);
	if (certs && (lookup <= 1) && asn_time &&
	    (asn_time->length < (int) sizeof(buf))) {
		memcpy(buf, (char*) asn_time->data, asn_time->length);
		buf[asn_time->length] = '\0';
		vp = fr_pair_make(talloc_ctx, certs, cert_attr_names[FR_TLS_VALID_SINCE][lookup], buf, T_OP_SET);
		rdebug_pair(L_DBG_LVL_2, request, vp, NULL);
	}

	/*
	 *	Get the Subject & Issuer
	 */
	subject[0] = issuer[0] = '\0';
	X509_NAME_oneline(X509_get_subject_name(client_cert), subject,
			  sizeof(subject));
	subject[sizeof(subject) - 1] = '\0';
	if (certs && (lookup <= 1) && subject[0]) {
		vp = fr_pair_make(talloc_ctx, certs, cert_attr_names[FR_TLS_SUBJECT][lookup], subject, T_OP_SET);
		rdebug_pair(L_DBG_LVL_2, request, vp, NULL);
	}

	X509_NAME_oneline(X509_get_issuer_name(client_cert), issuer,
			  sizeof(issuer));
	issuer[sizeof(issuer) - 1] = '\0';
	if (certs && (lookup <= 1) && issuer[0]) {
		vp = fr_pair_make(talloc_ctx, certs, cert_attr_names[FR_TLS_ISSUER][lookup], issuer, T_OP_SET);
		rdebug_pair(L_DBG_LVL_2, request, vp, NULL);
	}

	/*
	 *	Get the Common Name, if there is a subject.
	 */
	X509_NAME_get_text_by_NID(X509_get_subject_name(client_cert),
				  NID_commonName, common_name, sizeof(common_name));
	common_name[sizeof(common_name) - 1] = '\0';
	if (certs && (lookup <= 1) && common_name[0] && subject[0]) {
		vp = fr_pair_make(talloc_ctx, certs, cert_attr_names[FR_TLS_CN][lookup], common_name, T_OP_SET);
		rdebug_pair(L_DBG_LVL_2, request, vp, NULL);
	}

	/*
	 *	Get the Certificate Distribution points
	 */
	if (certs && (lookup <= 1)) {
		crl_dp = X509_get_ext_d2i(client_cert, NID_crl_distribution_points, NULL, NULL);

		if (crl_dp) {
			DIST_POINT *dp;
			const char *url_ptr;

			for (int i = 0; i < sk_DIST_POINT_num(crl_dp); i++) {
				size_t len;
				char cdp[1024];

				dp = sk_DIST_POINT_value(crl_dp, i);
				if (!dp) continue;

				url_ptr = get_cdp_url(dp);
				if (!url_ptr) continue;

				len = strlen(url_ptr);
				if (len >= sizeof(cdp)) continue;

				memcpy(cdp, url_ptr, len + 1);

				vp = fr_pair_make(talloc_ctx, certs, cert_attr_names[FR_TLS_CDP][lookup], cdp, T_OP_ADD);
				rdebug_pair(L_DBG_LVL_2, request, vp, NULL);
			}
			sk_DIST_POINT_pop_free(crl_dp, DIST_POINT_free);
		}
	}

	/*
	 *	Get the RFC822 Subject Alternative Name
	 */
	loc = X509_get_ext_by_NID(client_cert, NID_subject_alt_name, -1);
	if (certs && (lookup <= 1) && (loc >= 0)) {
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
					vp = fr_pair_make(talloc_ctx, certs, cert_attr_names[FR_TLS_SAN_EMAIL][lookup],
						      (char const *) ASN1_STRING_get0_data(name->d.rfc822Name), T_OP_SET);
					rdebug_pair(L_DBG_LVL_2, request, vp, NULL);
					break;
#endif	/* GEN_EMAIL */
#ifdef GEN_DNS
				case GEN_DNS:
					vp = fr_pair_make(talloc_ctx, certs, cert_attr_names[FR_TLS_SAN_DNS][lookup],
						      (char const *) ASN1_STRING_get0_data(name->d.dNSName), T_OP_SET);
					rdebug_pair(L_DBG_LVL_2, request, vp, NULL);
					break;
#endif	/* GEN_DNS */
#ifdef GEN_OTHERNAME
				case GEN_OTHERNAME:
					/* look for a MS UPN */
					if (NID_ms_upn == OBJ_obj2nid(name->d.otherName->type_id)) {
					    /* we've got a UPN - Must be ASN1-encoded UTF8 string */
					    if (name->d.otherName->value->type == V_ASN1_UTF8STRING) {
						    vp = fr_pair_make(talloc_ctx, certs, cert_attr_names[FR_TLS_SAN_UPN][lookup],
								  (char const *) ASN1_STRING_get0_data(name->d.otherName->value->value.utf8string), T_OP_SET);
						    rdebug_pair(L_DBG_LVL_2, request, vp, NULL);
						break;
					    } else {
						RWARN("Invalid UPN in Subject Alt Name (should be UTF-8)");
						break;
					    }
					}
					break;
#endif	/* GEN_OTHERNAME */
#ifdef GEN_URI
				case GEN_URI:
					vp = fr_pair_make(talloc_ctx, certs, cert_attr_names[FR_TLS_SAN_URI][lookup],
						      (char const *) ASN1_STRING_get0_data(name->d.uniformResourceIdentifier), T_OP_SET);
					rdebug_pair(L_DBG_LVL_2, request, vp, NULL);
					break;
#endif /* GEN_URI */
				default:
					/* XXX TODO handle other SAN types */
					break;
				}
			}
		}
		if (names != NULL)
			GENERAL_NAMES_free(names);
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
		RERROR("(TLS) OpenSSL says error %d : %s", err, p);
		REXDENT();

		/*
		 *	Copy certs even on failure so that they can be logged.
		 */
		if (certs && request) fr_pair_add(&request->packet->vps, fr_pair_list_copy(request->packet, *certs));

		return my_ok;
	}

	if (lookup == 0) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
		ext_list = X509_get0_extensions(client_cert);
#else
		X509_CINF	*client_inf;
		client_inf = client_cert->cert_info;
		ext_list = client_inf->extensions;
#endif
	} else {
		ext_list = NULL;
	}

	/*
	 *	Grab the X509 extensions, and create attributes out of them.
	 *	For laziness, we re-use the OpenSSL names
	 */
	if (certs && (sk_X509_EXTENSION_num(ext_list) > 0)) {
		int i, len;
		EXTENDED_KEY_USAGE *eku;
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

			if (X509V3_EXT_get(ext)) { /* Known extension, converting value into plain string */
				X509V3_EXT_print(out, ext, 0, 0);
				len = BIO_read(out, value, sizeof(value) - 1);
				if (len <= 0) continue;
				value[len] = '\0';
			} else {
				/*
				 * An extension not known to OpenSSL, dump it's value as a value of an unknown attribute.
				 */
				value[0] = '0';
				value[1] = 'x';
				const unsigned char *srcp;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
				const ASN1_STRING *srcasn1p;
				srcasn1p = X509_EXTENSION_get_data(ext);
				srcp = ASN1_STRING_get0_data(srcasn1p);
#else
				ASN1_STRING *srcasn1p;
				srcasn1p = X509_EXTENSION_get_data(ext);
				srcp = ASN1_STRING_data(srcasn1p);
#endif
				int asn1len = ASN1_STRING_length(srcasn1p);
				/* 3 comes from '0x' + \0 */
				if ((size_t)(asn1len << 1) >= sizeof(value) - 3) {
					RDEBUG("Value of '%s' attribute is too long to be stored, it will be truncated", attribute);
					asn1len = (sizeof(value) - 3) >> 1;
				}
				fr_bin2hex(value + 2, srcp, asn1len);
			}

			vp = fr_pair_make(talloc_ctx, certs, attribute, value, T_OP_ADD);
			if (!vp) {
				RDEBUG3("Skipping %s += '%s'.  Please check that both the "
					"attribute and value are defined in the dictionaries",
					attribute, value);
			} else {
				/*
				 *	rdebug_pair_list indents (so pre REXDENT())
				 */
				REXDENT();
				rdebug_pair_list(L_DBG_LVL_2, request, vp, NULL);
				RINDENT();
			}
		}

		BIO_free_all(out);

		/* Export raw EKU OIDs to allow matching a single OID regardless of its name */
		eku = X509_get_ext_d2i(client_cert, NID_ext_key_usage, NULL, NULL);
		if (eku != NULL) {
			for (i = 0; i < sk_ASN1_OBJECT_num(eku); i++) {
				len = OBJ_obj2txt(value, sizeof(value), sk_ASN1_OBJECT_value(eku, i), 1);
				if ((len > 0) && ((unsigned) len < sizeof(value))) {
					vp = fr_pair_make(talloc_ctx, certs,
							  "TLS-Client-Cert-X509v3-Extended-Key-Usage-OID",
							  value, T_OP_ADD);
					rdebug_pair(L_DBG_LVL_2, request, vp, NULL);
				}
				else {
					RDEBUG("Failed to get EKU OID at index %d", i);
				}
			}
			EXTENDED_KEY_USAGE_free(eku);
		}
	}

	REXDENT();

	switch (X509_STORE_CTX_get_error(ctx)) {
	case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
		RERROR("(TLS) unable to get issuer certificate for issuer=%s", issuer);
		break;

	case X509_V_ERR_CERT_NOT_YET_VALID:
		RERROR("(TLS) Failed with certificate not yet valid.");
		break;

	case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
		RERROR("(TLS) Failed with error in certificate 'not before' field.");
#if 0
		ASN1_TIME_print(bio_err, X509_get_notBefore(ctx->current_cert));
#endif
		break;

	case X509_V_ERR_CERT_HAS_EXPIRED:
		RERROR("(TLS) Failed with certificate has expired.");
		break;

	case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
		RERROR("(TLS) Failed with err in certificate 'no after' field..");
		break;

#if 0
		ASN1_TIME_print(bio_err, X509_get_notAfter(ctx->current_cert));
		break;
#endif
	}

	/*
	 *	If we're at the actual client cert, apply additional
	 *	checks.
	 */
	if (depth == 0) {
		tls_session_t *ssn = SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_SSN);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		STACK_OF(X509)* untrusted = NULL;
		int num_untrusted = X509_STORE_CTX_get_num_untrusted(ctx);
#endif

		rad_assert(ssn != NULL);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		/*
		 *	"Untrusted" certificates are those presented by the client
		 *	so we always expect there to be one.
		 *
		 *	If there's more than one, then the client is presenting
		 *	intermediate CAs as well.
		 */
		if (num_untrusted > 1) {
			untrusted = X509_STORE_CTX_get0_untrusted(ctx);
			if (conf->disallow_untrusted || RDEBUG_ENABLED2) {
				int  i;

				WARN("Certificate chain - %i intermediate CA cert(s) untrusted",
				     num_untrusted - 1);
				if (!conf->disallow_untrusted) WARN("To forbid these certificates set 'reject_unknown_intermediate_ca'");

				for (i = num_untrusted; i > 1 ; i--) {
					X509 *this_cert = sk_X509_value(untrusted, i - 1);

					X509_NAME_oneline(X509_get_subject_name(this_cert), subject, sizeof(subject));
					subject[sizeof(subject) - 1] = '\0';

					WARN("(TLS) untrusted certificate with depth [%i] subject name %s",
					     i - 1, subject);
				}
			}

			if (conf->disallow_untrusted) {
				AUTH(LOG_PREFIX ": There are untrusted certificates in the certificate chain.  Rejecting.");
				my_ok = 0;
			}
		}
#endif

		/*
		 *	If the conf tells us to, check cert issuer
		 *	against the specified value and fail
		 *	verification if they don't match.
		 */
		if (my_ok && conf->check_cert_issuer &&
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

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && defined(HAVE_OPENSSL_OCSP_H)
		if (my_ok) {
			/*
			 *	No OCSP, allow external verification.
			 */
			if (!conf->ocsp_enable) {
				do_verify = true;

			} else {
				RDEBUG2("Starting OCSP Request");

				/*
				 *	If we don't have an issuer, then we can't send
				 *	and OCSP request, but pass the NULL issuer in
				 *	so ocsp_check can decide on the correct
				 *	return code.
				 */
				issuer_cert = X509_STORE_CTX_get0_current_issuer(ctx);

				/*
				 *	Do the full OCSP checks.
				 *
				 *	If they fail, don't run the external verify.  We don't want
				 *	to allow admins to force authentication success for bad
				 *	certificates.
				 *
				 *	If the OCSP checks succeed, check whether we still want to
				 *	run the external verification routine.  If it's marked as
				 *	"skip verify on OK", then we don't do verify.
				 */
				my_ok = ocsp_check(request, ocsp_store, issuer_cert, client_cert, untrusted, conf);
				if (my_ok != OCSP_STATUS_FAILED) {
					do_verify = !conf->verify_skip_if_ocsp_ok;
				}
			}
		}
#endif

		if ((my_ok != OCSP_STATUS_FAILED)
#ifdef HAVE_OPENSSL_OCSP_H
		    && do_verify
#endif
			) while (conf->verify_client_cert_cmd) {
			char filename[3 * MAX_SESSION_SIZE + 1];
			int fd;
			FILE *fp;

			snprintf(filename, sizeof(filename), "%s/%s.client.XXXXXXXX",
				 conf->verify_tmp_dir, main_config.name);
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

			} else  if (request) {
				RDEBUG("Client certificate CN %s passed external validation", common_name);
			}

		do_unlink:
			unlink(filename);
			break;
		}

		/*
		 *	Track that we've verified the client certificate.
		 */
		ssn->client_cert_ok = (my_ok == 1);
	} /* depth == 0 */

	/*
	 *	Copy certs to request even on failure, so that the
	 *	user can log them.
	 */
	if (certs && request && !my_ok) {
		fr_pair_add(&request->packet->vps, fr_pair_list_copy(request->packet, *certs));
	}

	if (RDEBUG_ENABLED3) {
		RDEBUG3("(TLS) chain-depth   : %d", depth);
		RDEBUG3("(TLS) error         : %d", err);

		if (identity) RDEBUG3("identity      : %s", *identity);
		RDEBUG3("(TLS) common name   : %s", common_name);
		RDEBUG3("(TLS) subject       : %s", subject);
		RDEBUG3("(TLS) issuer        : %s", issuer);
		RDEBUG3("(TLS) verify return : %d", my_ok);
	}

	return (my_ok != 0);
}


/*
 * 	Configure a X509 CA store to verify OCSP or client repsonses
 *
 * 	- Load the trusted CAs
 * 	- Load the trusted issuer certificates
 *	- Configure CRLs check if needed
 */
X509_STORE *fr_init_x509_store(fr_tls_server_conf_t *conf)
{
	X509_STORE *store = X509_STORE_new();

	if (store == NULL) return NULL;

	/* Load the CAs we trust */
	if (conf->ca_file || conf->ca_path)
		if (!X509_STORE_load_locations(store, conf->ca_file, conf->ca_path)) {
			tls_error_log(NULL, "Error reading Trusted root CA list \"%s\"", conf->ca_file);
			X509_STORE_free(store);
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

#if defined(X509_V_FLAG_PARTIAL_CHAIN)
	X509_STORE_set_flags(store, X509_V_FLAG_PARTIAL_CHAIN);
#endif

	return store;
}

#if OPENSSL_VERSION_NUMBER >= 0x0090800fL
#ifndef OPENSSL_NO_ECDH
static int set_ecdh_curve(SSL_CTX *ctx, char const *ecdh_curve, bool disable_single_dh_use)
{
	if (!disable_single_dh_use) {
		SSL_CTX_set_options(ctx, SSL_OP_SINGLE_ECDH_USE);
	}

	if (!ecdh_curve) return 0;

#if OPENSSL_VERSION_NUMBER >= 0x1000200fL
	/*
	 *	A colon-separated list of curves.
	 */
	if (*ecdh_curve) {
		char *list;

		memcpy(&list, &ecdh_curve, sizeof(list)); /* const issues */

		if (SSL_CTX_set1_curves_list(ctx, list) == 0) {
			ERROR(LOG_PREFIX ": Unknown ecdh_curve \"%s\"", ecdh_curve);
			return -1;
		}
	}

	(void) SSL_CTX_set_ecdh_auto(ctx, 1);
#else
	/*
	 *	Use APIs for older versions of OpenSSL.
	 */
	{
		int      nid;
		EC_KEY  *ecdh;

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

		EC_KEY_free(ecdh);
	}
#endif

	return 0;
}
#endif
#endif

#if defined(HAVE_OPENSSL_CRYPTO_H) && defined(HAVE_CRYPTO_SET_LOCKING_CALLBACK)
#define TLS_UNUSED
#else
#define TLS_UNUSED UNUSED
#endif

/** Add all the default ciphers and message digests reate our context.
 *
 * This should be called exactly once from main, before reading the main config
 * or initialising any modules.
 */
int tls_global_init(TLS_UNUSED bool spawn_flag, TLS_UNUSED bool check)
{
	SSL_load_error_strings();	/* readable error messages (examples show call before library_init) */
	SSL_library_init();		/* initialize library */
	OpenSSL_add_all_algorithms();	/* required for SHA2 in OpenSSL < 0.9.8o and 1.0.0.a */
	CONF_modules_load_file(NULL, NULL, 0);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	EVP_set_default_properties(NULL, "-fips");
#endif

	/*
	 *	Initialize the index for the certificates.
	 */
	fr_tls_ex_index_certs = SSL_SESSION_get_ex_new_index(0, NULL, NULL, NULL, NULL);

#if defined(HAVE_OPENSSL_CRYPTO_H) && defined(HAVE_CRYPTO_SET_LOCKING_CALLBACK)
	/*
	 *	If we're linking with OpenSSL too, then we need
	 *	to set up the mutexes and enable the thread callbacks.
	 *
	 *	'check' and not 'check_config' because it's a global,
	 *	and we don't want to have tls.c depend on globals.
	 */
	if (spawn_flag && !check && (tls_mutexes_init() < 0)) {
		ERROR("(TLS) FATAL: Failed to set up SSL mutexes");
		return -1;
	}
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	/*
	 *	Load the default provider for most algorithms
	 */
	openssl_default_provider = OSSL_PROVIDER_load(NULL, "default");
	if (!openssl_default_provider) {
		ERROR("(TLS) Failed loading default provider");
		return -1;
	}

#ifndef WITH_FIPS
	/*
	 *	Needed for MD4
	 *
	 *	https://www.openssl.org/docs/man3.0/man7/migration_guide.html#Legacy-Algorithms
	 */
	openssl_legacy_provider = OSSL_PROVIDER_load(NULL, "legacy");
	if (!openssl_legacy_provider) {
		ERROR("(TLS) Failed loading legacy provider");
		return -1;
	}
#endif
#endif

	return 0;
}

#ifdef ENABLE_OPENSSL_VERSION_CHECK
/** Check for vulnerable versions of libssl
 *
 * @param acknowledged The highest CVE number a user has confirmed is not present in the system's libssl.
 * @return 0 if the CVE specified by the user matches the most recent CVE we have, else -1.
 */
int tls_global_version_check(char const *acknowledged)
{
	uint64_t v;
	bool bad = false;
	size_t i;

	if (strcmp(acknowledged, "yes") == 0) return 0;

	/* Check for bad versions */
	v = (uint64_t) SSLeay();

	for (i = 0; i < (sizeof(libssl_defects) / sizeof(*libssl_defects)); i++) {
		libssl_defect_t *defect = &libssl_defects[i];

		if ((v >= defect->low) && (v <= defect->high)) {
			/*
			 *	If the CVE is acknowledged, allow it.
			 */
			if (!bad && (strcmp(acknowledged, defect->id) == 0)) return 0;

			ERROR("Refusing to start with libssl version %s (in range %s)",
			      ssl_version(), ssl_version_range(defect->low, defect->high));
			ERROR("Security advisory %s (%s)", defect->id, defect->name);
			ERROR("%s", defect->comment);

			/*
			 *	Only warn about the first one...
			 */
			if (!bad) {
				INFO("Once you have verified libssl has been correctly patched, "
				     "set security.allow_vulnerable_openssl = '%s'", defect->id);

				bad = true;
			}
		}
	}

	if (bad) return -1;

	return 0;
}
#endif

/** Free any memory alloced by libssl
 *
 */
void tls_global_cleanup(void)
{
#if OPENSSL_VERSION_NUMBER < 0x10000000L
	ERR_remove_state(0);
#elif OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
	ERR_remove_thread_state(NULL);
#endif
#ifndef OPENSSL_NO_ENGINE
	ENGINE_cleanup();
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	if (openssl_default_provider && !OSSL_PROVIDER_unload(openssl_default_provider)) {
		ERROR("Failed unloading default provider");
	}
	openssl_default_provider = NULL;

#ifndef WITH_FIPS
	if (openssl_legacy_provider && !OSSL_PROVIDER_unload(openssl_legacy_provider)) {
		ERROR("Failed unloading legacy provider");
	}
	openssl_legacy_provider = NULL;
#endif
#endif

	CONF_modules_unload(1);
	ERR_free_strings();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
}


/*
 *	Map version strings to OpenSSL macros.
 */
static const FR_NAME_NUMBER version2int[] = {
	{ "1.0",    TLS1_VERSION },
#ifdef TLS1_1_VERSION
	{ "1.1",    TLS1_1_VERSION },
#endif
#ifdef TLS1_2_VERSION
	{ "1.2",    TLS1_2_VERSION },
#endif
#ifdef TLS1_3_VERSION
	{ "1.3",    TLS1_3_VERSION },
#endif
	{ NULL, 0 }
};

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#ifdef TLS1_3_VERSION
#define CHECK_FOR_PSK_CERTS (1)
#endif
#endif

/** Create SSL context
 *
 * - Load the trusted CAs
 * - Load the Private key & the certificate
 * - Set the Context options & Verify options
 */
SSL_CTX *tls_init_ctx(fr_tls_server_conf_t *conf, int client, char const *chain_file, char const *private_key_file)
{
	SSL_CTX		*ctx;
	X509_STORE	*certstore;
	int		verify_mode = SSL_VERIFY_NONE;
	int		ctx_options = 0, ctx_available = 0;
	int		type;
#ifdef CHECK_FOR_PSK_CERTS
	bool		psk_and_certs = false;
#endif
	int		min_version;
	int		max_version;

	/*
	 *	SHA256 is in all versions of OpenSSL, but isn't
	 *	initialized by default.  It's needed for WiMAX
	 *	certificates.
	 */
#ifdef HAVE_OPENSSL_EVP_SHA256
	EVP_add_digest(EVP_sha256());
#endif

	ctx = SSL_CTX_new(SSLv23_method()); /* which is really "all known SSL / TLS methods".  Idiots. */
	if (!ctx) {
		tls_error_log(NULL, "Failed creating OpenSSL context");
		return NULL;
	}

	/*
	 * Save the config on the context so that callbacks which
	 * only get SSL_CTX* e.g. session persistence, can get it
	 */
	SSL_CTX_set_app_data(ctx, conf);

	/*
	 * Identify the type of certificates that needs to be loaded
	 */
	if (conf->file_type) {
		type = SSL_FILETYPE_PEM;
	} else {
		type = SSL_FILETYPE_ASN1;
	}

	/*
	 * Set the password to load private key
	 */
	if (conf->private_key_password) {
#ifdef __APPLE__
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
				return NULL;
			}

			rad_const_free(conf->private_key_password);
			password = talloc_array(conf, char, max_password_len);
			if (!password) {
				ERROR(LOG_PREFIX ": Can't allocate space for private_key_password");
				ERROR(LOG_PREFIX ": Error reading private_key_file %s", conf->private_key_file);
				pclose(cmd_pipe);
				return NULL;
			}

			fgets(password, max_password_len, cmd_pipe);
			pclose(cmd_pipe);

			/* Get rid of newline at end of password. */
			password[strlen(password) - 1] = '\0';

			DEBUG3(LOG_PREFIX ": Password from command = \"%s\"", password);
			conf->private_key_password = password;
		}
#endif

		{
			char *password;

			memcpy(&password, &conf->private_key_password, sizeof(password));
			SSL_CTX_set_default_passwd_cb_userdata(ctx, password);
			SSL_CTX_set_default_passwd_cb(ctx, cbtls_password);
		}
	}

#ifdef PSK_MAX_IDENTITY_LEN
	/*
	 *	A dynamic query exists.  There MUST NOT be a
	 *	statically configured identity and password.
	 */
	if (conf->psk_query) {
		if (!*conf->psk_query) {
			ERROR(LOG_PREFIX ": Invalid PSK Configuration: psk_query cannot be empty");
			return NULL;
		}

		if (conf->psk_identity && *conf->psk_identity) {
			ERROR(LOG_PREFIX ": Invalid PSK Configuration: psk_identity and psk_query cannot be used at the same time.");
			return NULL;
		}

		if (conf->psk_password && *conf->psk_password) {
			ERROR(LOG_PREFIX ": Invalid PSK Configuration: psk_hexphrase and psk_query cannot be used at the same time.");
			return NULL;
		}

		if (client) {
			ERROR(LOG_PREFIX ": Invalid PSK Configuration: psk_query cannot be used for outgoing connections");
			return NULL;
		}

		/*
		 *	Now check that if PSK is being used, that the config is valid.
		 */
	} else if (conf->psk_identity) {
		if (!*conf->psk_identity) {
			ERROR(LOG_PREFIX ": Invalid PSK Configuration: psk_identity is empty");
			return NULL;
		}


		if (!conf->psk_password || !*conf->psk_password) {
			ERROR(LOG_PREFIX ": Invalid PSK Configuration: psk_identity is set, but there is no psk_hexphrase");
			return NULL;
		}

	} else if (conf->psk_password) {
		ERROR(LOG_PREFIX ": Invalid PSK Configuration: psk_hexphrase is set, but there is no psk_identity");
		return NULL;
	}

	/*
	 *	Set the server PSK callback if necessary.
	 */
	if (!client && (conf->psk_identity || conf->psk_query)) {
		SSL_CTX_set_psk_server_callback(ctx, psk_server_callback);
#if OPENSSL_VERSION_NUMBER >= 0x10101000
		SSL_CTX_set_psk_find_session_callback(ctx, cbtls_psk_find_session);
#endif
	}

	/*
	 *	Do more sanity checking if we have a PSK identity.  We
	 *	check the password, and convert it to it's final form.
	 */
	if (conf->psk_identity) {
		size_t psk_len, hex_len;
		uint8_t buffer[PSK_MAX_PSK_LEN];

		if (client) {
			SSL_CTX_set_psk_client_callback(ctx,
							psk_client_callback);
		}

		if (!conf->psk_password || !*conf->psk_password) {
			ERROR(LOG_PREFIX ": psk_hexphrase cannot be empty");
			return NULL;
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

#ifdef CHECK_FOR_PSK_CERTS
		/*
		 *	RFC 8446 says:
		 *
		 *	When authenticating via a certificate, the server will send the
     		 *	Certificate (Section 4.4.2) and CertificateVerify (Section 4.4.3)
		 *	messages.  In TLS 1.3 as defined by this document, either a PSK or
		 *	a certificate is always used, but not both.  Future documents may
		 *	define how to use them together.
		 */
		if (((conf->psk_identity || conf->psk_password || conf->psk_query)) &&
		    (conf->certificate_file || conf->private_key_password || conf->private_key_file)) {
			psk_and_certs = true;
		}
#endif

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
	if (!chain_file) chain_file = conf->certificate_file;
	if (!chain_file) goto load_ca;

	if (type == SSL_FILETYPE_PEM) {
		if (!(SSL_CTX_use_certificate_chain_file(ctx, chain_file))) {
			tls_error_log(NULL, "Failed reading certificate file \"%s\"",
				      chain_file);
			return NULL;
		}

	} else if (!(SSL_CTX_use_certificate_file(ctx, chain_file, type))) {
		tls_error_log(NULL, "Failed reading certificate file \"%s\"",
			      chain_file);
		return NULL;
	}

load_ca:
	/*
	 *	Load the CAs we trust and configure CRL checks if needed
	 */
	if (conf->ca_file || conf->ca_path) {
		if ((certstore = fr_init_x509_store(conf)) == NULL ) return NULL;
		SSL_CTX_set_cert_store(ctx, certstore);
	} else {
#if defined(X509_V_FLAG_PARTIAL_CHAIN)
		X509_STORE_set_flags(SSL_CTX_get_cert_store(ctx), X509_V_FLAG_PARTIAL_CHAIN);
#endif
	}

	if (conf->ca_file && *conf->ca_file) SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(conf->ca_file));

	conf->ca_path_last_reload = time(NULL);
	conf->old_x509_store = NULL;

	/*
	 * Disable reloading of cert store if we're not using CA path
	 */
	if (!conf->ca_path) conf->ca_path_reload_interval = 0;

	if (conf->ca_path_reload_interval > 0 && conf->ca_path_reload_interval < 300) {
		DEBUG2("ca_path_reload_interval is set too low, reset it to 300");
		conf->ca_path_reload_interval = 300;
	}

	/* Load private key */
	if (!private_key_file) private_key_file = conf->private_key_file;
	if (private_key_file) {
		if (!(SSL_CTX_use_PrivateKey_file(ctx, private_key_file, type))) {
			tls_error_log(NULL, "Failed reading private key file \"%s\"",
				      private_key_file);
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

#ifdef SSL_OP_NO_RENEGOTIATION
	/*
	 *	This is never useful for anything.
	 */
	ctx_options |= SSL_OP_NO_RENEGOTIATION;
#endif

	/*
	 *	We never want SSLv2 or SSLv3.
	 */
	ctx_options |= SSL_OP_NO_SSLv2;
	ctx_options |= SSL_OP_NO_SSLv3;

	/*
	 *	If set then dummy Change Cipher Spec (CCS) messages are sent in
	 *	TLSv1.3. This has the effect of making TLSv1.3 look more like TLSv1.2
	 *	so that middleboxes that do not understand TLSv1.3 will not drop
	 *	the connection. This isn't needed for EAP-TLS, so we disable it.
	 *
	 *	EAP (hopefully) does not have middlebox deployments
	 */
#ifdef SSL_OP_ENABLE_MIDDLEBOX_COMPAT
	ctx_options &= ~SSL_OP_ENABLE_MIDDLEBOX_COMPAT;
#endif

	/*
	 *	SSL_CTX_set_(min|max)_proto_version was included in OpenSSL 1.1.0
	 *
	 *	This version already defines macros for TLS1_2_VERSION and
	 *	below, so we don't need to check for them explicitly.
	 *
	 *	TLS1_3_VERSION is available in OpenSSL 1.1.1.
	 */

	/*
	 *	Get the max version from the configuration files.
	 */
	if (conf->tls_max_version && *conf->tls_max_version) {
		max_version = fr_str2int(version2int, conf->tls_max_version, 0);
		if (!max_version) {
			ERROR("Invalid value for tls_max_version '%s'", conf->tls_max_version);
			return NULL;
		}
	} else {
		/*
		 *	Pick the maximum version available at compile
		 *	time.
		 */
#if defined(TLS1_3_VERSION)
#ifdef WITH_RADIUSV11
		/*
		 *	RADIUS 1.1 requires TLS 1.3 or later.
		 */
		if (conf->radiusv11) {
			max_version = TLS1_3_VERSION;
		} else
#endif


		max_version = TLS1_2_VERSION; /* yes, we only use TLS 1.3 if it's EXPLICITELY ENABLED */
#elif defined(TLS1_2_VERSION)
		max_version = TLS1_2_VERSION;
#elif defined(TLS1_1_VERSION)
		max_version = TLS1_1_VERSION;
#else
		max_version = TLS1_VERSION;
#endif
	}

	/*
	 *	Get the min version from the configuration files.
	 */
	if (conf->tls_min_version && *conf->tls_min_version) {
		min_version = fr_str2int(version2int, conf->tls_min_version, 0);
		if (!min_version) {
			ERROR("Unknown or unsupported value for tls_min_version '%s'", conf->tls_min_version);
			return NULL;
		}

#ifdef WITH_RADIUSV11
		/*
		 *	RADIUS 1.1 requires TLS 1.3 or later.
		 */
		if (conf->radiusv11 && (min_version < TLS1_3_VERSION)) {
			WARN(LOG_PREFIX ": The configuration allows TLS <1.3.  RADIUS/1.1 MUST use TLS 1.3");
			WARN(LOG_PREFIX ": Please set: tls_min_version = '1.3'");
		}
#endif
	} else {
#ifdef WITH_RADIUSV11
		/*
		 *	RADIUS 1.1 requires TLS 1.3 or later.
		 */
		if (conf->radiusv11) {
			min_version = TLS1_3_VERSION;
		} else
#endif
		/*
		 *	Allow TLS 1.0.  It is horribly insecure, but
		 *	some systems still use it.
		 */
		min_version = TLS1_VERSION;
	}

	/*
	 *	Compare the two.
	 */
	if ((min_version > max_version) || (max_version < min_version)) {
		ERROR("tls_min_version '%s' must be <= tls_max_version '%s'",
		      conf->tls_min_version, conf->tls_max_version);
		return NULL;
	}

#ifdef CHECK_FOR_PSK_CERTS
	/*
	 *	Disable TLS 1.3 when using PSKs and certs.
	 *	This doesn't work.
	 *
	 *	It's best to disable the offending
	 *	configuration and warn about it.  The
	 *	alternative is to have the admin wonder why it
	 *	doesn't work.
	 *
	 *	Note that the admin can over-ride this by
	 *	setting "min_version = max_version = 1.3"
	 */
	if (psk_and_certs &&
	    (min_version < TLS1_3_VERSION) && (max_version >= TLS1_3_VERSION)) {
		max_version = TLS1_2_VERSION;
		radlog(L_DBG | L_WARN, "Disabling TLS 1.3 due to PSK and certificates being configured simultaneously.  This is not supported by the standards.");
	}
#endif

	/*
	 *	No one should be using TLS 1.0 or TLS 1.1 any more
	 *
	 *	If TLS1.2 isn't defined by OpenSSL, then we _know_
	 *	it's an insecure version of OpenSSL.
	 */
#ifdef TLS1_2_VERSION
	if (max_version < TLS1_2_VERSION)
#endif
	{
		if (rad_debug_lvl) {
			WARN(LOG_PREFIX ": The configuration allows TLS 1.0 and/or TLS 1.1.  We STRONGLY recommned using only TLS 1.2 for security");
			WARN(LOG_PREFIX ": Please set: tls_min_version = '1.2'");
		}
	}

#ifdef SSL_OP_NO_TLSv1
	/*
	 *	Check min / max against the old-style "disable" flag.
	 */
	if (conf->disable_tlsv1) {
		if (min_version == TLS1_VERSION) {
			ERROR(LOG_PREFIX ": 'disable_tlsv1' is set, but 'min_version = 1.0'.  These cannot both be true.");
			return NULL;
		}
		if (max_version == TLS1_VERSION) {
			ERROR(LOG_PREFIX ": 'disable_tlsv1' is set, but 'max_version = 1.0'.  These cannot both be true.");
			return NULL;
		}
		ctx_options |= SSL_OP_NO_TLSv1;
	}

	if (min_version > TLS1_VERSION) ctx_options |= SSL_OP_NO_TLSv1;

	ctx_available |= SSL_OP_NO_TLSv1;
#endif

#ifdef SSL_OP_NO_TLSv1_1
	/*
	 *	Check min / max against the old-style "disable" flag.
	 */
	if (conf->disable_tlsv1_1) {
		if (min_version <= TLS1_1_VERSION) {
			ERROR(LOG_PREFIX ": 'disable_tlsv1_1' is set, but 'min_version <= 1.1'.  These cannot both be true.");
			return NULL;
		}
		if (max_version == TLS1_1_VERSION) {
			ERROR(LOG_PREFIX ": 'disable_tlsv1_1' is set, but 'max_version = 1.1'.  These cannot both be true.");
			return NULL;
		}
		ctx_options |= SSL_OP_NO_TLSv1_1;
	}

	if (min_version > TLS1_1_VERSION) ctx_options |= SSL_OP_NO_TLSv1_1;
	if (max_version < TLS1_1_VERSION) ctx_options |= SSL_OP_NO_TLSv1_1;

	ctx_available |= SSL_OP_NO_TLSv1_1;
#endif

#ifdef SSL_OP_NO_TLSv1_2
	/*
	 *	Check min / max against the old-style "disable" flag.
	 */
	if (conf->disable_tlsv1_2) {
		if (min_version <= TLS1_2_VERSION) {
			ERROR(LOG_PREFIX ": 'disable_tlsv1_2' is set, but 'min_version <= 1.2'.  These cannot both be true.");
			return NULL;
		}
		if (max_version == TLS1_2_VERSION) {
			ERROR(LOG_PREFIX ": 'disable_tlsv1_1' is set, but 'max_version = 1.2'.  These cannot both be true.");
			return NULL;
		}
		ctx_options |= SSL_OP_NO_TLSv1_2;
	}
	ctx_available |= SSL_OP_NO_TLSv1_2;

	if (min_version > TLS1_2_VERSION) ctx_options |= SSL_OP_NO_TLSv1_2;
	if (max_version < TLS1_2_VERSION) ctx_options |= SSL_OP_NO_TLSv1_2;
#endif

#ifdef SSL_OP_NO_TLSv1_3
	ctx_available |= SSL_OP_NO_TLSv1_3;
	if (min_version > TLS1_3_VERSION) ctx_options |= SSL_OP_NO_TLSv1_3;
	if (max_version < TLS1_3_VERSION) ctx_options |= SSL_OP_NO_TLSv1_3;
#endif


#ifdef WITH_RADIUSV11
	/*
	 *	RADIUS 1.1 requires TLS 1.3 or later.
	 */
	if (conf->radiusv11 && (min_version < TLS1_3_VERSION)) {
		ERROR(LOG_PREFIX ": Please set 'tls_min_version = 1.2' or greater to use 'radiusv1_1 = true'");
		return NULL;
	}
#endif

	/*
	 *	Set the cipher list if we were told to do so.  We do
	 *	this before setting min/max TLS version.  In a sane
	 *	world, OpenSSL would error out if we set the max TLS
	 *	version to something which was unsupported by the
	 *	current security level.  However, this is OpenSSL.  If
	 *	you set conflicting options, it doesn't give an error.
	 *	Instead, it just picks something to do.
	 */
	if (conf->cipher_list) {
		if (!SSL_CTX_set_cipher_list(ctx, conf->cipher_list)) {
			tls_error_log(NULL, "Failed setting cipher list");
			return NULL;
		}
	}

#if OPENSSL_VERSION_NUMBER >= 0x10101000L
	if (conf->sigalgs_list) {
		char *list;

		memcpy(&list, &(conf->sigalgs_list), sizeof(list)); /* const issues */

		if (SSL_CTX_set1_sigalgs_list(ctx, list) == 0) {
			tls_error_log(NULL, "Failed setting signature list '%s'", conf->sigalgs_list);
			return NULL;
		}
	}
#endif

	/*
	 *	Tell OpenSSL PRETTY PLEASE MAY WE USE TLS 1.1.
	 *
	 *	Because saying "use TLS 1.1" isn't enough.  We have to
	 *	send it flowers and cake.
	 */
	if (min_version <= TLS1_1_VERSION) {
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
		int seclevel = SSL_CTX_get_security_level(ctx);
		int required;;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
		required = 0;
#else
		required = 1;
#endif

		if (seclevel != required) {
			WARN(LOG_PREFIX ": In order to use TLS 1.0 and/or TLS 1.1, you likely need to set: cipher_list = \"DEFAULT@SECLEVEL=%d\"", required);
		}

#else
		/*
		 *	No API to get the security level.  Just guess based on the string in the cipher_list.
		 */
		if (conf->cipher_list &&
		    !strstr(conf->cipher_list, "DEFAULT@SECLEVEL=1")) {
			WARN(LOG_PREFIX ": In order to use TLS 1.0 and/or TLS 1.1, you likely need to set: cipher_list = \"DEFAULT@SECLEVEL=1\"");
		}
#endif
	}

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	if (conf->disable_tlsv1) {
		WARN(LOG_PREFIX ": Please use 'tls_min_version' and 'tls_max_version' instead of 'disable_tlsv1'");
	}
	if (conf->disable_tlsv1_1) {
		WARN(LOG_PREFIX ": Please use 'tls_min_version' and 'tls_max_version' instead of 'disable_tlsv1_1'");
	}
	if (conf->disable_tlsv1_2) {
		WARN(LOG_PREFIX ": Please use 'tls_min_version' and 'tls_max_version' instead of 'disable_tlsv1_2'");
	}

	ctx_options &= ~(ctx_available); /* clear these flags, as they're not needed. */

	if (!SSL_CTX_set_max_proto_version(ctx, max_version)) {
		ERROR("Failed setting TLS maximum version");
		return NULL;
	}
	if (!SSL_CTX_set_min_proto_version(ctx, min_version)) {
		ERROR("Failed setting TLS minimum version");
		return NULL;
	}
#endif	/* OpenSSL version < 1.1.0 */

	if ((ctx_options & ctx_available) == ctx_available) {
		ERROR(LOG_PREFIX ": You have disabled all available TLS versions.  EAP will not work");
		return NULL;
	}

	/*
	 *	Cache min / max TLS version so that we can
	 *	programatically disable TLS 1.3 for TTLS, PEAP, and
	 *	FAST.
	 */
	conf->min_version = min_version;
	conf->max_version = max_version;

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

	if (conf->cipher_server_preference) {
		/*
		 *      SSL_OP_CIPHER_SERVER_PREFERENCE to follow best practice
		 *      of nowday's TLS: do not allow poorly-selected ciphers from
		 *      client to take preference
		 */
		ctx_options |= SSL_OP_CIPHER_SERVER_PREFERENCE;
	}

	SSL_CTX_set_options(ctx, ctx_options);

	/*
	 *	TLS 1.3 introduces the concept of early data (also known as zero
	 *	round trip data or 0-RTT data). Early data allows a client to send
	 *	data to a server in the first round trip of a connection, without
	 *	waiting for the TLS handshake to complete if the client has spoken
	 *	to the same server recently. This doesn't work for EAP, so we
	 *	disable early data.
	 *
	 */
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
	SSL_CTX_set_max_early_data(ctx, 0);
#endif

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
		/*
		 *	Cache sessions on disk if requested.
		 */
		if (conf->session_cache_path && *conf->session_cache_path) {
			SSL_CTX_sess_set_new_cb(ctx, cbtls_new_session);
			SSL_CTX_sess_set_get_cb(ctx, cbtls_get_session);
			SSL_CTX_sess_set_remove_cb(ctx, cbtls_remove_session);
		}

		/*
		 *	Or run the cache through a virtual server.
		 */
		if (conf->session_cache_server && *conf->session_cache_server) {
			SSL_CTX_sess_set_new_cb(ctx, cbtls_cache_save);
			SSL_CTX_sess_set_get_cb(ctx, cbtls_cache_load);
			SSL_CTX_sess_set_remove_cb(ctx, cbtls_cache_clear);
		}

		SSL_CTX_set_quiet_shutdown(ctx, 1);
		if (fr_tls_ex_index_vps < 0)
			fr_tls_ex_index_vps = SSL_SESSION_get_ex_new_index(0, NULL, NULL, NULL, NULL);
	}

	/*
	 *	Check the certificates for revocation.
	 */
#ifdef X509_V_FLAG_CRL_CHECK
	if (conf->check_crl) {
		certstore = SSL_CTX_get_cert_store(ctx);
		if (certstore == NULL) {
			tls_error_log(NULL, "Error reading Certificate Store");
	    		return NULL;
		}
		X509_STORE_set_flags(certstore, X509_V_FLAG_CRL_CHECK);

#ifdef X509_V_FLAG_USE_DELTAS
		/*
		 *	If set, delta CRLs (if present) are used to
		 *	determine certificate status. If not set
		 *	deltas are ignored.
		 *
		 *	So it's safe to always set this flag.
		 */
		X509_STORE_set_flags(certstore, X509_V_FLAG_USE_DELTAS);
#endif

#ifdef X509_V_FLAG_CRL_CHECK_ALL
		if (conf->check_all_crl)
			X509_STORE_set_flags(certstore, X509_V_FLAG_CRL_CHECK_ALL);
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

#ifndef LIBRESSL_VERSION_NUMBER
	/* Load randomness */
	if (conf->random_file) {
		if (!(RAND_load_file(conf->random_file, 1024*10))) {
			tls_error_log(NULL, "Failed loading randomness");
			return NULL;
		}
	}
#endif

	/*
	 *	Setup session caching
	 */
	if (conf->session_cache_enable) {
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

		/*
		 *	Cache it, DON'T auto-clear it, and disable the internal OpenSSL session cache.
		 */
		SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER | SSL_SESS_CACHE_NO_AUTO_CLEAR | SSL_SESS_CACHE_NO_INTERNAL);

		SSL_CTX_set_session_id_context(ctx,
					       (unsigned char *) conf->session_context_id,
					       (unsigned int) strlen(conf->session_context_id));

		/*
		 *	Our lifetime is in hours, this is in seconds.
		 */
		SSL_CTX_set_timeout(ctx, conf->session_lifetime * 3600);

		/*
		 *	Set the maximum number of entries in the
		 *	session cache.
		 */
		SSL_CTX_sess_set_cache_size(ctx, conf->session_cache_size);

#if OPENSSL_VERSION_NUMBER >= 0x10101000L && !defined(LIBRESSL_VERSION_NUMBER)
		SSL_CTX_set_num_tickets(ctx, 1);
#endif

	} else {
		SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

#if OPENSSL_VERSION_NUMBER >= 0x10101000L && !defined(LIBRESSL_VERSION_NUMBER)
		/*
		 *	This controls the number of stateful or stateless tickets
		 *	generated with TLS 1.3.  In OpenSSL 1.1.1 it's also
		 *	required to disable sending session tickets,
		 *	SSL_SESS_CACHE_OFF is not good enough.
		 */
		SSL_CTX_set_num_tickets(ctx, 0);
#endif
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
	if (conf->ctx) SSL_CTX_free(conf->ctx);

	if (conf->cache_ht) fr_hash_table_free(conf->cache_ht);

	pthread_mutex_destroy(&conf->mutex);

#ifdef HAVE_OPENSSL_OCSP_H
	if (conf->ocsp_store) X509_STORE_free(conf->ocsp_store);
	conf->ocsp_store = NULL;
#endif

	if (conf->realms) fr_hash_table_free(conf->realms);

#ifndef NDEBUG
	memset(conf, 0, sizeof(*conf));
#endif
	return 0;
}

fr_tls_server_conf_t *tls_server_conf_alloc(TALLOC_CTX *ctx)
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

static uint32_t store_hash(void const *data)
{
	DICT_ATTR const *da = data;
	return fr_hash(&da, sizeof(da));
}

static int store_cmp(void const *a, void const *b)
{
	DICT_ATTR const *one = a;
	DICT_ATTR const *two = b;

	return (one < two) - (one > two);
}

static uint32_t realm_hash(void const *data)
{
	fr_realm_ctx_t const *r = data;

	return fr_hash_string(r->name);
}

static int realm_cmp(void const *a, void const *b)
{
	fr_realm_ctx_t const *one = a;
	fr_realm_ctx_t const *two = b;

	return strcmp(one->name, two->name);
}

static void realm_free(void *data)
{
	fr_realm_ctx_t *r = data;

	SSL_CTX_free(r->ctx);
}

static int tls_realms_load(fr_tls_server_conf_t *conf)
{
	fr_hash_table_t *ht;
	DIR		*dir;
	struct dirent	*dp;
	char		buffer[PATH_MAX];
	char		buffer2[PATH_MAX];

	ht = fr_hash_table_create(realm_hash, realm_cmp, realm_free);
	if (!ht) return -1;

	dir = opendir(conf->realm_dir);
	if (!dir) {
		ERROR("Error reading directory %s: %s", conf->realm_dir, fr_syserror(errno));
	error:
		if (dir) closedir(dir);
		fr_hash_table_free(ht);
		return -1;
	}

	/*
	 *	Read only the PEM files
	 */
	while ((dp = readdir(dir)) != NULL) {
		char *p;
		struct stat stat_buf;
		SSL_CTX *ctx;
		fr_realm_ctx_t *r;
		char const *private_key_file = buffer;

		if (dp->d_name[0] == '.') continue;

		p = strrchr(dp->d_name, '.');
		if (!p) continue;

		if (memcmp(p, ".pem", 5) != 0) continue; /* must END in .pem */

		snprintf(buffer, sizeof(buffer), "%s/%s", conf->realm_dir, dp->d_name); /* ignore directories */
		if ((stat(buffer, &stat_buf) != 0) ||
		    S_ISDIR(stat_buf.st_mode)) continue;

		strcpy(buffer2, buffer);
		p = strrchr(buffer2, '.'); /* which must be there... */
		if (!p) continue;

		/*
		 *	If there's a key file, then use that.
		 *	Otherwise assume that the private key is in
		 *	the chain file.
		 */
		strcpy(p, ".key");
		if (stat(buffer2, &stat_buf) == 0) private_key_file = buffer2;

		ctx = tls_init_ctx(conf, 1, buffer, private_key_file);
		if (!ctx) goto error;

		r = talloc_zero(conf, fr_realm_ctx_t);
		if (!r) {
			SSL_CTX_free(ctx);
			goto error;
		}

		r->name = talloc_strdup(r, buffer);
		r->ctx = ctx;

		if (fr_hash_table_insert(ht, r) < 0) {
			ERROR("Failed inserting certificate file %s into hash table", buffer);
			goto error;
		}

		DEBUG("(TLS) Loaded certificate file %s", buffer);
	}

	conf->realms = ht;
	closedir(dir);

	return 0;
}


fr_tls_server_conf_t *tls_server_conf_parse(CONF_SECTION *cs)
{
	fr_tls_server_conf_t *conf;

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

	/*
	 *	Disallow sessions of more than 7 days, as per RFC
	 *	8446.
	 *
	 *	Note that we also enforce this on TLS 1.2, etc.
	 *	Because there's just no reason to have month-long TLS
	 *	sessions.
	 */
	if (conf->session_lifetime > (7 * 24)) conf->session_lifetime = 7 * 24;

	/*
	 *	Only check for certificate things if we don't have a
	 *	PSK query.
	 */
#ifdef PSK_MAX_IDENTITY_LEN
	if (conf->psk_identity || conf->psk_query) {
		if (conf->private_key_file) {
			WARN(LOG_PREFIX ": Ignoring private key file due to psk_identity being used");
		}

		if (conf->certificate_file) {
			WARN(LOG_PREFIX ": Ignoring certificate file due to psk_identity being used");
		}

	} else
#endif
	{
		if (!conf->private_key_file) {
			ERROR(LOG_PREFIX ": TLS Server requires a private key file");
			goto error;
		}

		if (!conf->certificate_file) {
			ERROR(LOG_PREFIX ": TLS Server requires a certificate file");
			goto error;
		}
	}

	/*
	 *	Initialize configuration mutex
	 */
	pthread_mutex_init(&conf->mutex, NULL);

	/*
	 *	Initialize TLS
	 */
	conf->ctx = tls_init_ctx(conf, 0, NULL, NULL);
	if (conf->ctx == NULL) {
		goto error;
	}

	if (conf->session_cache_enable) {
		CONF_SECTION	*subcs;
		CONF_ITEM	*ci;

		subcs = cf_section_sub_find(cs, "cache");
		if (!subcs) goto skip_list;
		subcs = cf_section_sub_find(subcs, "store");
		if (!subcs) goto skip_list;

		/*
		 *	Largely taken from rlm_detail for laziness.
		 */
		conf->cache_ht = fr_hash_table_create(store_hash, store_cmp, NULL);

		for (ci = cf_item_find_next(subcs, NULL);
		     ci != NULL;
		     ci = cf_item_find_next(subcs, ci)) {
			char const	*attr;
			DICT_ATTR const	*da;

			if (!cf_item_is_pair(ci)) continue;

			attr = cf_pair_attr(cf_item_to_pair(ci));
			if (!attr) continue; /* pair-anoia */

			da = dict_attrbyname(attr);
			if (!da) {
				ERROR(LOG_PREFIX ": TLS Server requires a certificate file");
				goto error;
			}

			/*
			 *	Be kind to minor mistakes.
			 */
			if (fr_hash_table_finddata(conf->cache_ht, da)) {
				WARN(LOG_PREFIX ": Ignoring duplicate entry '%s'", attr);
				continue;
			}


			if (!fr_hash_table_insert(conf->cache_ht, da)) {
				ERROR(LOG_PREFIX ": Failed inserting '%s' into cache list", attr);
				goto error;
			}
		}

		/*
		 *	If we didn't suppress anything, delete the hash table.
		 */
		if (fr_hash_table_num_elements(conf->cache_ht) == 0) {
			fr_hash_table_free(conf->cache_ht);
			conf->cache_ht = NULL;
		}
	}

skip_list:

#ifdef HAVE_OPENSSL_OCSP_H
	/*
	 * 	Initialize OCSP Revocation Store
	 */
	if (conf->ocsp_enable) {
		conf->ocsp_store = fr_init_x509_store(conf);
		if (conf->ocsp_store == NULL) goto error;
	}
#endif /*HAVE_OPENSSL_OCSP_H*/

	{
		char *dh_file;

		memcpy(&dh_file, &conf->dh_file, sizeof(dh_file));
		if (load_dh_params(conf->ctx, dh_file) < 0) {
			goto error;
		}
	}

	if (conf->verify_tmp_dir) {
		if (chmod(conf->verify_tmp_dir, S_IRWXU) < 0) {
			ERROR(LOG_PREFIX ": Failed changing permissions on %s: %s",
			      conf->verify_tmp_dir, fr_syserror(errno));
			goto error;
		}
	}

	if (conf->verify_client_cert_cmd && !conf->verify_tmp_dir) {
		ERROR(LOG_PREFIX ": You MUST set the 'tmpdir' directory in order to use '%s' cmd", conf->verify_client_cert_cmd);
		goto error;
	}

#ifdef SSL_OP_NO_TLSv1_2
	/*
	 *	OpenSSL 1.0.1f and 1.0.1g get the MS-MPPE keys wrong.
	 */
#if (OPENSSL_VERSION_NUMBER >= 0x1010106L) && (OPENSSL_VERSION_NUMBER <= 0x1010107L)
	conf->disable_tlsv1_2 = true;
	WARN(LOG_PREFIX ": Disabling TLSv1.2 due to OpenSSL bugs");
#endif
#endif

	/*
	 *	Load certificates and private keys from the realm directory.
	 */
	if (conf->realm_dir && (tls_realms_load(conf) < 0)) goto error;

	/*
	 *	Cache conf in cs in case we're asked to parse this again.
	 */
	cf_data_add(cs, "tls-conf", conf, NULL);

	return conf;
}

fr_tls_server_conf_t *tls_client_conf_parse(CONF_SECTION *cs)
{
	fr_tls_server_conf_t *conf;

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
	conf->ctx = tls_init_ctx(conf, 1, NULL, NULL);
	if (conf->ctx == NULL) {
		goto error;
	}

	{
		char *dh_file;

		memcpy(&dh_file, &conf->dh_file, sizeof(dh_file));
		if (load_dh_params(conf->ctx, dh_file) < 0) {
			goto error;
		}
	}

	cf_data_add(cs, "tls-conf", conf, NULL);

	return conf;
}


int tls_success(tls_session_t *ssn, REQUEST *request)
{
	VALUE_PAIR *vp, *vps = NULL;
	fr_tls_server_conf_t *conf;
	TALLOC_CTX *talloc_ctx;

	conf = (fr_tls_server_conf_t *)SSL_get_ex_data(ssn->ssl, FR_TLS_EX_INDEX_CONF);
	rad_assert(conf != NULL);

	talloc_ctx = SSL_get_ex_data(ssn->ssl, FR_TLS_EX_INDEX_TALLOC);

	/*
	 *	If there's no session resumption, delete the entry
	 *	from the cache.  This means either it's disabled
	 *	globally for this SSL context, OR we were told to
	 *	disable it for this user.
	 *
	 *	This also means you can't turn it on just for one
	 *	user.
	 */
	if ((!ssn->allow_session_resumption) ||
	    (((vp = fr_pair_find_by_num(request->config, PW_ALLOW_SESSION_RESUMPTION, 0, TAG_ANY)) != NULL) &&
	     (vp->vp_integer == 0))) {
		SSL_CTX_remove_session(ssn->ctx,
				       ssn->ssl_session);
		ssn->allow_session_resumption = false;

		/*
		 *	If we're in a resumed session and it's
		 *	not allowed,
		 */
		if (SSL_session_reused(ssn->ssl)) {
			RDEBUG("(TLS) cache - Forcibly stopping session resumption as it is administratively disabled.");
			return -1;
		}

	/*
	 *	Else resumption IS allowed, so we store the
	 *	user data in the cache.
	 */
	} else if ((!SSL_session_reused(ssn->ssl)) || ssn->session_not_resumed) {
		VALUE_PAIR **certs;
		char buffer[2 * MAX_SESSION_SIZE + 1];

		tls_session_id(ssn->ssl_session, buffer, MAX_SESSION_SIZE);

		RDEBUG("(TLS) cache - Setting up attributes for session resumption");

		vp = fr_pair_list_copy_by_num(talloc_ctx, request->reply->vps, PW_USER_NAME, 0, TAG_ANY);
		if (vp) fr_pair_add(&vps, vp);

		vp = fr_pair_list_copy_by_num(talloc_ctx, request->packet->vps, PW_STRIPPED_USER_NAME, 0, TAG_ANY);
		if (vp) fr_pair_add(&vps, vp);

		vp = fr_pair_list_copy_by_num(talloc_ctx, request->packet->vps, PW_STRIPPED_USER_DOMAIN, 0, TAG_ANY);
		if (vp) fr_pair_add(&vps, vp);

		vp = fr_pair_list_copy_by_num(talloc_ctx, request->packet->vps, PW_EAP_TYPE, 0, TAG_ANY);
		if (vp) fr_pair_add(&vps, vp);

		vp = fr_pair_list_copy_by_num(talloc_ctx, request->reply->vps, PW_CHARGEABLE_USER_IDENTITY, 0, TAG_ANY);
		if (vp) fr_pair_add(&vps, vp);

		vp = fr_pair_list_copy_by_num(talloc_ctx, request->reply->vps, PW_CACHED_SESSION_POLICY, 0, TAG_ANY);
		if (vp) fr_pair_add(&vps, vp);

		if (conf->cache_ht) {
			vp_cursor_t cursor;

			/* Write each attribute/value to the log file */
			for (vp = fr_cursor_init(&cursor, &request->reply->vps);
			     vp;
			     vp = fr_cursor_next(&cursor)) {
				VALUE_PAIR *copy;

				if (!fr_hash_table_finddata(conf->cache_ht, vp->da)) {
					continue;
				}

				copy = fr_pair_copy(talloc_ctx, vp);
				if (copy) fr_pair_add(&vps, copy);
			}
		}

		/*
		 *	Hmm... the certs should probably be session data.
		 */
		certs = (VALUE_PAIR **)SSL_get_ex_data(ssn->ssl, fr_tls_ex_index_certs);
		if (certs) {
			/*
			 *	@todo: some go into reply, others into
			 *	request
			 */
			fr_pair_add(&vps, fr_pair_list_copy(talloc_ctx, *certs));

			vp = fr_pair_find_by_num(vps, PW_TLS_CLIENT_CERT_EXPIRATION, 0, TAG_ANY);
			if (vp) {
				time_t expires;

				if (ocsp_asn1time_to_epoch(&expires, vp->vp_strvalue) < 0) {
					RDEBUG2("Failed getting certificate expiration, removing cache entry for session %s", buffer);
					SSL_CTX_remove_session(ssn->ctx, ssn->ssl_session);
					return -1;
				}

				if (expires <= request->timestamp) {
					RDEBUG2("Certificate has expired, removing cache entry for session %s", buffer);
					SSL_CTX_remove_session(ssn->ctx, ssn->ssl_session);
					return -1;
				}

				/*
				 *	Account for Session-Timeout, if it's available.
				 */
				vp = fr_pair_find_by_num(request->reply->vps, PW_SESSION_TIMEOUT, 0, TAG_ANY);
				if (vp) {
					if ((request->timestamp + vp->vp_integer) > expires) {
						vp->vp_integer = expires - request->timestamp;
						RWDEBUG2("(TLS) Updating Session-Timeout to %u, due to impending certificate expiration",
							 vp->vp_integer);
					}
				}
			}
		}

		if (vps) {
			SSL_SESSION_set_ex_data(ssn->ssl_session, fr_tls_ex_index_vps, vps);
			rdebug_pair_list(L_DBG_LVL_2, request, vps, "  caching ");

			if (conf->session_cache_path) {
				/* write the VPs to the cache file */
				char filename[3 * MAX_SESSION_SIZE + 1], buf[1024];
				FILE *vp_file;

				RDEBUG2("Saving session %s in the disk cache", buffer);

				snprintf(filename, sizeof(filename), "%s%c%s.vps", conf->session_cache_path,
					 FR_DIR_SEP, buffer);
				vp_file = fopen(filename, "w");
				if (vp_file == NULL) {
					RWDEBUG("(TLS) Could not write session VPs to persistent cache: %s",
						fr_syserror(errno));
				} else {
					VALUE_PAIR *prev = NULL;
					vp_cursor_t cursor;
					/* generate a dummy user-style entry which is easy to read back */
					fprintf(vp_file, "# SSL cached session\n");
					fprintf(vp_file, "%s\n\t", buffer);

					for (vp = fr_cursor_init(&cursor, &vps);
					     vp;
					     vp = fr_cursor_next(&cursor)) {
						/*
						 *	Terminate the previous line.
						 */
						if (prev) fprintf(vp_file, ",\n\t");

						/*
						 *	Write this one.
						 */
						vp_prints(buf, sizeof(buf), vp);
						fputs(buf, vp_file);
						prev = vp;
					}

					/*
					 *	Terminate the final line.
					 */
					fprintf(vp_file, "\n");
					fclose(vp_file);
				}

			} else if (conf->session_cache_server) {
				cbtls_cache_save_vps(ssn->ssl, ssn->ssl_session, vps);

			} else {
				RDEBUG("Failed to find 'persist_dir' in TLS configuration.  Session will not be cached on disk.");
			}
		} else {
			RDEBUG2("No information to cache: session caching will be disabled for session %s", buffer);
			SSL_CTX_remove_session(ssn->ctx, ssn->ssl_session);
		}

	/*
	 *	Else the session WAS allowed.  Copy the cached reply.
	 */
	} else {
		RDEBUG("(TLS) cache - Refreshing entry for session resumption");

		/*
		 *	The "restore VPs from OpenSSL cache" code is
		 *	now in eaptls_process()
		 */
		if (conf->session_cache_path) {
			char buffer[2 * MAX_SESSION_SIZE + 1];

#if OPENSSL_VERSION_NUMBER >= 0x10001000L
#ifdef TLS1_3_VERSION
			/*
			 *	OpenSSL frees the underlying session out from
			 *	under us in TLS 1.3.
			 */
			if (SSL_version(ssn->ssl) == TLS1_3_VERSION) ssn->ssl_session = SSL_get_session(ssn->ssl);
#endif
#endif

			tls_session_id(ssn->ssl_session, buffer, MAX_SESSION_SIZE);

			/* "touch" the cached session/vp file */
			char filename[3 * MAX_SESSION_SIZE + 1];

			snprintf(filename, sizeof(filename), "%s%c%s.asn1",
				 conf->session_cache_path, FR_DIR_SEP, buffer);
			utime(filename, NULL);
			snprintf(filename, sizeof(filename), "%s%c%s.vps",
				 conf->session_cache_path, FR_DIR_SEP, buffer);
			utime(filename, NULL);
		}

		if (conf->session_cache_server) {
			cbtls_cache_refresh(ssn->ssl, ssn->ssl_session);
		}

		/*
		 *	Mark the request as resumed.
		 */
		pair_make_request("EAP-Session-Resumed", "1", T_OP_SET);
		RDEBUG("  &request:EAP-Session-Resumed := 1");
	}

	return 0;
}


void tls_fail(tls_session_t *ssn)
{
	/*
	 *	Force the session to NOT be cached.
	 */
	SSL_CTX_remove_session(ssn->ctx, ssn->ssl_session);
}

fr_tls_status_t tls_application_data(tls_session_t *ssn, REQUEST *request)

{
	int err;
	VALUE_PAIR **certs;

	/*
	 *	Decrypt the complete record.
	 */
	if (ssn->dirty_in.used > 0) {
		err = BIO_write(ssn->into_ssl, ssn->dirty_in.data,
				ssn->dirty_in.used);
		if (err != (int) ssn->dirty_in.used) {
			REDEBUG("(TLS) Failed writing %zd bytes to SSL BIO: %d", ssn->dirty_in.used, err);
			record_init(&ssn->dirty_in);
			return FR_TLS_FAIL;
		}

		record_init(&ssn->dirty_in);
	}

	/*
	 *	tls_handshake_recv() may read application data.  So
	 *	don't touch clean_out.  But only if the BIO_write()
	 *	above didn't do anything.
	 */
	else if (ssn->clean_out.used > 0) {
		RDEBUG("(TLS) We already have %zd bytes of application data, processing it.",
		       (ssn->clean_out.used));
		goto add_certs;
	}

	/*
	 *      Read (and decrypt) the tunneled data from the
	 *      SSL session, and put it into the decrypted
	 *      data buffer.
	 */
	err = SSL_read(ssn->ssl, ssn->clean_out.data + ssn->clean_out.used,
		       sizeof(ssn->clean_out.data) - ssn->clean_out.used);
	if (err <= 0) {
		int code;

		RDEBUG3("(TLS) SSL_read Error");

		code = SSL_get_error(ssn->ssl, err);
		switch (code) {
		case SSL_ERROR_WANT_READ:
			if (ssn->clean_out.used > 0) { /* just process what application data we have */
				err = 0;
				break;
			}

			RDEBUG("(TLS) OpenSSL says that it needs to read more data.");
			return FR_TLS_MORE_FRAGMENTS;

		case SSL_ERROR_WANT_WRITE:
			if (ssn->clean_out.used > 0) { /* just process what application data we have */
				err = 0;
				break;
			}

			REDEBUG("(TLS) Error in fragmentation logic: SSL_WANT_WRITE");
			return FR_TLS_FAIL;

		case SSL_ERROR_NONE:
			RDEBUG2("(TLS) No application data received.  Assuming handshake is continuing...");
			err = 0;
			break;

		case SSL_ERROR_ZERO_RETURN:
			RDEBUG2("(TLS) Other end closed the TLS tunnel.");
			return FR_TLS_FAIL;

		default:
			REDEBUG("(TLS) Error in fragmentation logic - code %d", code);
			tls_error_io_log(request, ssn, err, "Failed reading application data from OpenSSL");
			return FR_TLS_FAIL;
		}
	}

	/*
	 *	Passed all checks, successfully decrypted data
	 */
	ssn->clean_out.used += err;

add_certs:
	/*
	 *	Add the certificates to intermediate packets, so that
	 *	the inner tunnel policies can use them.
	 */
	certs = (VALUE_PAIR **)SSL_get_ex_data(ssn->ssl, fr_tls_ex_index_certs);

	if (certs) fr_pair_add(&request->packet->vps, fr_pair_list_copy(request->packet, *certs));

	return FR_TLS_OK;
}


/*
 * Acknowledge received is for one of the following messages sent earlier
 * 1. Handshake completed Message, so now send, EAP-Success
 * 2. Alert Message, now send, EAP-Failure
 * 3. Fragment Message, now send, next Fragment
 */
fr_tls_status_t tls_ack_handler(tls_session_t *ssn, REQUEST *request)
{
	if (ssn == NULL){
		REDEBUG("(TLS) Unexpected ACK received:  No ongoing SSL session");
		return FR_TLS_INVALID;
	}
	if (!ssn->info.initialized) {
		RDEBUG("(TLS) No SSL info available.  Waiting for more SSL data");
		return FR_TLS_REQUEST;
	}

	if ((ssn->info.content_type == handshake) && (ssn->info.origin == 0)) {
		REDEBUG("(TLS) Unexpected ACK received:  We sent no previous messages");
		return FR_TLS_INVALID;
	}

	switch (ssn->info.content_type) {
	case alert:
		RDEBUG2("(TLS) Peer ACKed our alert");
		return FR_TLS_FAIL;

	case handshake:
		if (ssn->dirty_out.used > 0) {
			RDEBUG2("(TLS) Peer ACKed our handshake fragment");
			/* Fragmentation handler, send next fragment */
			return FR_TLS_REQUEST;
		}

		if (ssn->is_init_finished || SSL_is_init_finished(ssn->ssl)) {
			RDEBUG2("(TLS) Peer ACKed our handshake fragment.  handshake is finished");

			/*
			 *	From now on all the content is
			 *	application data set it here as nobody else
			 *	sets it.
			 */
			ssn->info.content_type = application_data;
			return FR_TLS_SUCCESS;
		} /* else more data to send */

		REDEBUG("(TLS) Cannot continue, as the peer is misbehaving.");
		return FR_TLS_FAIL;

	case application_data:
		RDEBUG2("(TLS) Peer ACKed our application data fragment");
		return FR_TLS_REQUEST;

		/*
		 *	For the rest of the conditions, switch over
		 *	to the default section below.
		 */
	default:
		REDEBUG("(TLS) Invalid ACK received: %d", ssn->info.content_type);
		return FR_TLS_INVALID;
	}
}
#endif	/* WITH_TLS */
