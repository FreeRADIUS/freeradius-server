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
	uint64_t	high;
	uint64_t	low;

	char const	*id;
	char const	*name;
	char const	*comment;
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
	{ "ok",				FR_TLS_OK },
	{ "ack",			FR_TLS_ACK },
	{ "first fragment",		FR_TLS_FIRST_FRAGMENT },
	{ "more fragments",		FR_TLS_MORE_FRAGMENTS },
	{ "length included",		FR_TLS_LENGTH_INCLUDED },
	{ "handled",			FR_TLS_HANDLED },
	{  NULL , 			-1},
};

/* index we use to store cached session VPs
 * needs to be dynamic so we can supply a "free" function
 */
int fr_tls_ex_index_vps = -1;

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

#ifdef PSK_MAX_IDENTITY_LEN
static bool identity_is_safe(const char *identity)
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


/*
 *	When a client uses TLS-PSK to talk to a server, this callback
 *	is used by the server to determine the PSK to use.
 */
static unsigned int psk_server_callback(SSL *ssl, const char *identity,
					unsigned char *psk,
					unsigned int max_psk_len)
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
		size_t hex_len;
		VALUE_PAIR *vp;
		char buffer[2 * PSK_MAX_PSK_LEN + 4]; /* allow for too-long keys */

		/*
		 *	The passed identity is weird.  Deny it.
		 */
		if (!identity_is_safe(identity)) {
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
			RWDEBUG("Returned PSK is too long (%u > %u)",
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

tls_session_t *tls_new_client_session(TALLOC_CTX *ctx, fr_tls_server_conf_t *conf, int fd)
{
	int verify_mode;
	tls_session_t *ssn = NULL;
	REQUEST *request;

	ssn = talloc_zero(ctx, tls_session_t);
	if (!ssn) return NULL;

	talloc_set_destructor(ssn, _tls_session_free);

	ssn->ctx = conf->ctx;

	SSL_CTX_set_mode(ssn->ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_AUTO_RETRY);

	ssn->ssl = SSL_new(ssn->ctx);
	if (!ssn->ssl) {
		talloc_free(ssn);
		return NULL;
	}

	request = request_alloc(ssn);
	SSL_set_ex_data(ssn->ssl, FR_TLS_EX_INDEX_REQUEST, (void *)request);

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
	SSL_set_fd(ssn->ssl, fd);
	if (SSL_connect(ssn->ssl) <= 0) {
		int err;
		while ((err = ERR_get_error())) {
			ERROR("tls: %s", ERR_error_string(err, NULL));
		}
		talloc_free(ssn);

		return NULL;
	}

	ssn->mtu = conf->fragment_size;

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
 * @return
 *	- A new session on success.
 *	- NULL on error.
 */
tls_session_t *tls_new_session(TALLOC_CTX *ctx, fr_tls_server_conf_t *conf, REQUEST *request, bool client_cert)
{
	tls_session_t	*state = NULL;
	SSL		*new_tls = NULL;
	int		verify_mode = 0;
	VALUE_PAIR	*vp;

	rad_assert(request != NULL);

	RDEBUG2("Initiating new EAP-TLS session");

	/*
	 *	Manually flush the sessions every so often.  If HALF
	 *	of the session lifetime has passed since we last
	 *	flushed, then flush it again.
	 *
	 *	FIXME: Also do it every N sessions?
	 */
	if (conf->session_cache_enable && !conf->session_cache_server &&
	    ((conf->session_last_flushed + ((int)conf->session_timeout * 1800)) <= request->timestamp)){
		RDEBUG2("Flushing SSL sessions (of #%ld)", SSL_CTX_sess_number(conf->ctx));

		SSL_CTX_flush_sessions(conf->ctx, request->timestamp);
		conf->session_last_flushed = request->timestamp;
	}

	if ((new_tls = SSL_new(conf->ctx)) == NULL) {
		RERROR("Error creating new SSL session: %s", ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}

	/* We use the SSL's "app_data" to indicate a call-back */
	SSL_set_app_data(new_tls, NULL);

	if ((state = talloc_zero(ctx, tls_session_t)) == NULL) {
		RERROR("Error allocating memory for SSL state");
		return NULL;
	}
	session_init(state);
	talloc_set_destructor(state, _tls_session_free);

	state->ctx = conf->ctx;
	state->ssl = new_tls;

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

	/*
	 *	In Server mode we only accept.
	 */
	SSL_set_accept_state(state->ssl);

	/*
	 *	Verify the peer certificate, if asked.
	 */
	if (client_cert) {
		RDEBUG2("Setting verify mode to require certificate from client");
		verify_mode = SSL_VERIFY_PEER;
		verify_mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
		verify_mode |= SSL_VERIFY_CLIENT_ONCE;
	}
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
	vp = fr_pair_find_by_num(request->packet->vps, PW_FRAMED_MTU, 0, TAG_ANY);
	if (vp && (vp->vp_integer > 100) && (vp->vp_integer < state->mtu)) {
		state->mtu = vp->vp_integer;
	}

	if (conf->session_cache_enable) state->allow_session_resumption = true; /* otherwise it's false */

	return state;
}

/*
 *	Print out some text describing the error.
 */
static int int_ssl_check(REQUEST *request, SSL *s, int ret, char const *text)
{
	int e;
	unsigned long l;

	if ((l = ERR_get_error()) != 0) {
		char const *p = ERR_error_string(l, NULL);

		if (p) ROPTIONAL(REDEBUG, ERROR, "SSL says: %s", p);
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
		ROPTIONAL(REDEBUG, ERROR, "FATAL SSL error: %d", e);
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
int tls_handshake_recv(REQUEST *request, tls_session_t *ssn)
{
	int err;

	if (ssn->invalid_hb_used) return 0;

	err = BIO_write(ssn->into_ssl, ssn->dirty_in.data, ssn->dirty_in.used);
	if (err != (int) ssn->dirty_in.used) {
		REDEBUG("Failed writing %zd bytes to SSL BIO: %d", ssn->dirty_in.used, err);
		record_init(&ssn->dirty_in);
		return 0;
	}
	record_init(&ssn->dirty_in);

	err = SSL_read(ssn->ssl, ssn->clean_out.data + ssn->clean_out.used,
		       sizeof(ssn->clean_out.data) - ssn->clean_out.used);
	if (err > 0) {
		ssn->clean_out.used += err;
		return 1;
	}

	if (!int_ssl_check(request, ssn->ssl, err, "SSL_read")) return 0;

	/* Some Extra STATE information for easy debugging */
	if (SSL_is_init_finished(ssn->ssl)) RDEBUG2("SSL connection established");
	if (SSL_in_init(ssn->ssl)) RDEBUG2("In SSL handshake phase");
	if (SSL_in_before(ssn->ssl)) RDEBUG2("Before SSL handshake phase");
	if (SSL_in_accept_init(ssn->ssl)) RDEBUG2("In SSL accept mode");
	if (SSL_in_connect_init(ssn->ssl)) RDEBUG2("In SSL connect mode");

	err = BIO_ctrl_pending(ssn->from_ssl);
	if (err > 0) {
		err = BIO_read(ssn->from_ssl, ssn->dirty_out.data,
			       sizeof(ssn->dirty_out.data));
		if (err > 0) {
			ssn->dirty_out.used = err;

		} else if (BIO_should_retry(ssn->from_ssl)) {
			record_init(&ssn->dirty_in);
			RDEBUG2("Asking for more data in tunnel");
			return 1;

		} else {
			int_ssl_check(request, ssn->ssl, err, "BIO_read");
			record_init(&ssn->dirty_in);
			return 0;
		}
	} else {
		RDEBUG2("SSL Application Data");
		/* Its clean application data, do whatever we want */
		record_init(&ssn->clean_out);
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
		err = BIO_read(ssn->from_ssl, ssn->dirty_out.data,
			       sizeof(ssn->dirty_out.data));
		if (err > 0) {
			ssn->dirty_out.used = err;
		} else {
			int_ssl_check(request, ssn->ssl, err, "handshake_send");
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
	SSL_set_quiet_shutdown(ssn->ssl, 1);
	SSL_shutdown(ssn->ssl);

	if (ssn->ssl) {
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
	if(rec->used > 0)
		memmove(rec->data, rec->data + taken, rec->used);
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
	if (rad_debug_lvl == 0) {
		return;
	}

	str_write_p = tls_session->info.origin ? ">>>" : "<<<";

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

	{ FR_CONF_OFFSET("lifetime", PW_TYPE_INTEGER | PW_TYPE_DEPRECATED, fr_tls_server_conf_t, session_timeout), .dflt = "24" },
	{ FR_CONF_OFFSET("max_entries", PW_TYPE_INTEGER | PW_TYPE_DEPRECATED, fr_tls_server_conf_t, session_cache_size), .dflt = "255" },
	{ FR_CONF_OFFSET("persist_dir", PW_TYPE_STRING | PW_TYPE_DEPRECATED, fr_tls_server_conf_t, session_cache_path) },

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
	{ FR_CONF_OFFSET("rsa_key_exchange", PW_TYPE_BOOLEAN, fr_tls_server_conf_t, rsa_key), .dflt = "no" },
	{ FR_CONF_OFFSET("dh_key_exchange", PW_TYPE_BOOLEAN, fr_tls_server_conf_t, dh_key), .dflt = "yes" },
	{ FR_CONF_OFFSET("rsa_key_length", PW_TYPE_INTEGER, fr_tls_server_conf_t, rsa_key_length), .dflt = "512" },
	{ FR_CONF_OFFSET("dh_key_length", PW_TYPE_INTEGER, fr_tls_server_conf_t, dh_key_length), .dflt = "512" },
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
	{ FR_CONF_OFFSET("rsa_key_exchange", PW_TYPE_BOOLEAN, fr_tls_server_conf_t, rsa_key), .dflt = "no" },
	{ FR_CONF_OFFSET("dh_key_exchange", PW_TYPE_BOOLEAN, fr_tls_server_conf_t, dh_key), .dflt = "yes" },
	{ FR_CONF_OFFSET("rsa_key_length", PW_TYPE_INTEGER, fr_tls_server_conf_t, rsa_key_length), .dflt = "512" },
	{ FR_CONF_OFFSET("dh_key_length", PW_TYPE_INTEGER, fr_tls_server_conf_t, dh_key_length), .dflt = "512" },
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

	request = SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_REQUEST);
	conf = SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_CONF);

	if (cache_key_add(request, sess->session_id, sess->session_id_length, CACHE_ACTION_SESSION_WRITE) < 0) {
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

	conf = SSL_CTX_get_app_data(ctx);

	/*
	 *	We need a fake request for the virtual server, but we
	 *	don't have a parent request to base it on.  So just
	 *	invent one.
	 */
	request = request_alloc(NULL);
	request->packet = rad_alloc(request, false);
	request->reply = rad_alloc(request, false);

	if (cache_key_add(request, sess->session_id, sess->session_id_length, CACHE_ACTION_SESSION_DELETE) < 0) {
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

/*
 *	Old session caching code
 */


/*
 *	Print debugging messages, and free data.
 */
static void cbtls_remove_session(SSL_CTX *ctx, SSL_SESSION *sess)
{
	size_t			size;
	char			buffer[2 * MAX_SESSION_SIZE + 1];
	fr_tls_server_conf_t	*conf;

	size = sess->session_id_length;
	if (size > MAX_SESSION_SIZE) size = MAX_SESSION_SIZE;

	fr_bin2hex(buffer, sess->session_id, size);

	conf = (fr_tls_server_conf_t *)SSL_CTX_get_app_data(ctx);
	if (!conf) {
		DEBUG(LOG_PREFIX ": Failed to find TLS configuration in session");
		return;
	}

	{
		char filename[256];
		size_t len;

		DEBUG2(LOG_PREFIX ": Removing session %s from the cache", buffer);

		/* remove session and any cached VPs */
		len = snprintf(filename, sizeof(filename), "%s%c%s.asn1", conf->session_cache_path, FR_DIR_SEP, buffer);
		if (is_truncated(len, sizeof(filename))) {
		truncated:
			ERROR(LOG_PREFIX ": Filename buffer too small to write out cache file path.  "
			      "Use smaller session cache path, and remove stale cache files manually");
			return;
		}

		if (unlink(filename) != 0) {
		unlink_error:
			ERROR(LOG_PREFIX ": Could not remove persisted session file %s: %s",
			      filename, fr_syserror(errno));
			return;
		}

		/* VPs might be absent; might not have been written to disk yet */
		len = snprintf(filename, sizeof(filename), "%s%c%s.vps", conf->session_cache_path, FR_DIR_SEP, buffer);
		if (is_truncated(len, sizeof(filename))) goto truncated;

		if (unlink(filename) != 0) goto unlink_error;
	}

	return;
}

static int cbtls_new_session(SSL *ssl, SSL_SESSION *sess)
{
	size_t			size;
	char			buffer[2 * MAX_SESSION_SIZE + 1];
	fr_tls_server_conf_t	*conf;
	unsigned char		*sess_blob = NULL;

	REQUEST			*request = SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_REQUEST);

	conf = (fr_tls_server_conf_t *)SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_CONF);
	if (!conf) {
		RWDEBUG("Failed to find TLS configuration in session");
		return 0;
	}

	size = sess->session_id_length;
	if (size > MAX_SESSION_SIZE) size = MAX_SESSION_SIZE;

	fr_bin2hex(buffer, sess->session_id, size);

	{
		int fd, rv, todo, blob_len;
		size_t len;
		char filename[256];
		unsigned char *p;

		RDEBUG2("Serialising session %s, and storing in cache", buffer);

		/* find out what length data we need */
		blob_len = i2d_SSL_SESSION(sess, NULL);
		if (blob_len < 1) {
			/* something went wrong */
			RWDEBUG("Session serialisation failed, couldn't determine required buffer length");
			return 0;
		}


		/* Do not convert to TALLOC - Thread safety */
		/* alloc and convert to ASN.1 */
		sess_blob = malloc(blob_len);
		if (!sess_blob) {
			RWDEBUG("Session serialisation failed, couldn't allocate buffer (%d bytes)", blob_len);
			return 0;
		}
		/* openssl mutates &p */
		p = sess_blob;
		rv = i2d_SSL_SESSION(sess, &p);
		if (rv != blob_len) {
			RWDEBUG("Session serialisation failed");
			goto error;
		}

		/* open output file */
		len = snprintf(filename, sizeof(filename), "%s%c%s.asn1", conf->session_cache_path, FR_DIR_SEP, buffer);
		if (is_truncated(len, sizeof(filename))) {
			ERROR("Filename buffer too small, reduce length of session cache path");
			goto error;
		}

		fd = open(filename, O_RDWR | O_CREAT | O_EXCL, 0600);
		if (fd < 0) {
			RERROR("Session serialisation failed, failed opening session file %s: %s",
			      filename, fr_syserror(errno));
			goto error;
		}

		todo = blob_len;
		p = sess_blob;
		while (todo > 0) {
			rv = write(fd, p, todo);
			if (rv < 1) {
				RWDEBUG("Failed writing session: %s", fr_syserror(errno));
				close(fd);
				goto error;
			}
			p += rv;
			todo -= rv;
		}
		close(fd);
		RWDEBUG("Wrote session %s to %s (%d bytes)", buffer, filename, blob_len);
	}

error:
	free(sess_blob);

	return 0;
}

static SSL_SESSION *cbtls_get_session(SSL *ssl, unsigned char *data, int inlen, int *copy)
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

	size = inlen;
	if (size > MAX_SESSION_SIZE) size = MAX_SESSION_SIZE;

	fr_bin2hex(buffer, data, size);

	RDEBUG2("Peer requested cached session: %s", buffer);

	*copy = 0;

	conf = (fr_tls_server_conf_t *)SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_CONF);
	if (!conf) {
		RWDEBUG("Failed to find TLS configuration in session");
		return NULL;
	}

	talloc_ctx = SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_TALLOC);

	{
		int			rv, fd, todo;
		size_t			len;
		char			filename[256];

		unsigned char const	**o;
		unsigned char		**p;
		uint8_t			*q;

		struct			stat st;
		VALUE_PAIR		*vps = NULL;

		/* read in the cached VPs from the .vps file */
		len = snprintf(filename, sizeof(filename), "%s%c%s.vps", conf->session_cache_path, FR_DIR_SEP, buffer);
		if (is_truncated(len, sizeof(filename))) {
			RWDEBUG("Filename buffer too small, reduce length of session cache path");
			goto error;
		}

		rv = pairlist_read(NULL, filename, &pairlist, 1);
		if (rv < 0) {
			/* not safe to un-persist a session w/o VPs */
			RWDEBUG("Could not load persisted VPs for session %s", buffer);
			goto error;
		}

		/* load the actual SSL session */
		len = snprintf(filename, sizeof(filename), "%s%c%s.asn1", conf->session_cache_path, FR_DIR_SEP, buffer);
		if (is_truncated(len, sizeof(filename))) {
			RWDEBUG("Filename buffer too small, reduce length of session cache path");
			goto error;
		}

		fd = open(filename, O_RDONLY);
		if (fd == -1) {
			RWDEBUG("Could not find persisted session file %s: %s", filename, fr_syserror(errno));
			goto error;
		}

		rv = fstat(fd, &st);
		if (rv == -1) {
			RWDEBUG("Could not stat persisted session file %s: %s", filename, fr_syserror(errno));
			close(fd);
			goto error;
		}

		sess_data = talloc_array(NULL, unsigned char, st.st_size);
		if (!sess_data) {
			RWDEBUG("Could not alloc buffer for persisted session len=%d", (int) st.st_size);
			close(fd);
			goto error;
		}

		q = sess_data;
		todo = st.st_size;
		while (todo > 0) {
			rv = read(fd, q, todo);
			if (rv < 1) {
				RWDEBUG("Could not read from persisted session: %s", fr_syserror(errno));
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
			RWDEBUG("Failed loading persisted session: %s", ERR_error_string(ERR_get_error(), NULL));
			goto error;
		}

		/* move the cached VPs into the session */
		fr_pair_list_move_by_num(talloc_ctx, &vps, &pairlist->reply, 0, 0, TAG_ANY);

		SSL_SESSION_set_ex_data(sess, fr_tls_ex_index_vps, vps);
		RWDEBUG("Successfully restored session %s", buffer);
		rdebug_pair_list(L_DBG_LVL_2, request, vps, "reply:");
	}
error:
	if (sess_data) talloc_free(sess_data);
	if (pairlist) pairlist_free(&pairlist);

	return sess;
}

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
		RERROR("SSL says error %d : %s", err, p);
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
		fr_pair_add(&request->state, cert_vps);
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
static int set_ecdh_curve(SSL_CTX *ctx, char const *ecdh_curve)
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

	SSL_CTX_set_options(ctx, SSL_OP_SINGLE_ECDH_USE);

	EC_KEY_free(ecdh);

	return 0;
}
#endif
#endif

/*
 * DIE OPENSSL DIE DIE DIE
 *
 * What a palaver, just to free some data attached the
 * session. We need to do this because the "remove" callback
 * is called when refcount > 0 sometimes, if another thread
 * is using the session
 */
static void sess_free_vps(UNUSED void *parent, void *data_ptr,
				UNUSED CRYPTO_EX_DATA *ad, UNUSED int idx,
				UNUSED long argl, UNUSED void *argp)
{
	VALUE_PAIR *vp = data_ptr;
	if (!vp) return;

	DEBUG2(LOG_PREFIX ": Freeing cached session VPs");

	fr_pair_list_free(&vp);
}

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

/** Create SSL context
 *
 * - Load the trusted CAs
 * - Load the Private key & the certificate
 * - Set the Context options & Verify options
 */
SSL_CTX *tls_init_ctx(fr_tls_server_conf_t *conf, int client)
{
	SSL_CTX		*ctx;
	X509_STORE	*cert_vpstore;
	int		verify_mode = SSL_VERIFY_NONE;
	int		ctx_options = 0;
	int		ctx_tls_versions = 0;
	int		type;

	ctx = SSL_CTX_new(SSLv23_method()); /* which is really "all known SSL / TLS methods".  Idiots. */
	if (!ctx) {
		int err;
		while ((err = ERR_get_error())) {
			ERROR(LOG_PREFIX ": Failed creating SSL context: %s", ERR_error_string(err, NULL));
			return NULL;
		}
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
			SSL_CTX_set_psk_server_callback(ctx, psk_server_callback);
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
			SSL_CTX_set_psk_client_callback(ctx,
							psk_client_callback);
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
			ERROR(LOG_PREFIX ": SSL error %s", ERR_error_string(ERR_get_error(), NULL));
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

	/*
	 *	SSL_OP_SINGLE_DH_USE must be used in order to prevent
	 *	small subgroup attacks and forward secrecy. Always
	 *	using
	 *
	 *	SSL_OP_SINGLE_DH_USE has an impact on the computer
	 *	time needed during negotiation, but it is not very
	 *	large.
	 */
	ctx_options |= SSL_OP_SINGLE_DH_USE;

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
	if (set_ecdh_curve(ctx, conf->ecdh_curve) < 0) {
		return NULL;
	}
#endif
#endif

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
		} else

		/*
		 *	Cache sessions on disk if requested.
		 */
		if (conf->session_cache_path) {
			SSL_CTX_sess_set_new_cb(ctx, cbtls_new_session);
			SSL_CTX_sess_set_get_cb(ctx, cbtls_get_session);
			SSL_CTX_sess_set_remove_cb(ctx, cbtls_remove_session);
		}

		SSL_CTX_set_quiet_shutdown(ctx, 1);
		if (fr_tls_ex_index_vps < 0)
			fr_tls_ex_index_vps = SSL_SESSION_get_ex_new_index(0, NULL, NULL, NULL, sess_free_vps);
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

		} else {	/* persist_dir, or in-memory cache. */
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
			 *	Cache it, and DON'T auto-clear it.
			 */
			SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER | SSL_SESS_CACHE_NO_AUTO_CLEAR);

			SSL_CTX_set_session_id_context(ctx,
						       (unsigned char *) conf->session_context_id,
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
	 *	Initialize TLS
	 */
	conf->ctx = tls_init_ctx(conf, 0);
	if (conf->ctx == NULL) {
		goto error;
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
	conf->ctx = tls_init_ctx(conf, 1);
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
				       ssn->ssl->session);
		ssn->allow_session_resumption = false;

		/*
		 *	If we're in a resumed session and it's
		 *	not allowed,
		 */
		if (SSL_session_reused(ssn->ssl)) {
			RDEBUG("Forcibly stopping session resumption as it is not allowed");
			return -1;
		}

	/*
	 *	Else resumption IS allowed, so we store the
	 *	user data in the cache.
	 */
	} else if (!SSL_session_reused(ssn->ssl)) {
		size_t size;
		char buffer[2 * MAX_SESSION_SIZE + 1];

		size = ssn->ssl->session->session_id_length;
		if (size > MAX_SESSION_SIZE) size = MAX_SESSION_SIZE;

		fr_bin2hex(buffer, ssn->ssl->session->session_id, size);

		vp = fr_pair_list_copy_by_num(talloc_ctx, request->reply->vps, PW_USER_NAME, 0, TAG_ANY);
		if (vp) fr_pair_add(&vps, vp);

		vp = fr_pair_list_copy_by_num(talloc_ctx, request->packet->vps, PW_STRIPPED_USER_NAME, 0, TAG_ANY);
		if (vp) fr_pair_add(&vps, vp);

		vp = fr_pair_list_copy_by_num(talloc_ctx, request->packet->vps, PW_STRIPPED_USER_DOMAIN, 0, TAG_ANY);
		if (vp) fr_pair_add(&vps, vp);

		vp = fr_pair_list_copy_by_num(talloc_ctx, request->reply->vps, PW_CHARGEABLE_USER_IDENTITY, 0, TAG_ANY);
		if (vp) fr_pair_add(&vps, vp);

		vp = fr_pair_list_copy_by_num(talloc_ctx, request->reply->vps, PW_CACHED_SESSION_POLICY, 0, TAG_ANY);
		if (vp) fr_pair_add(&vps, vp);

		if (vps) {
			SSL_SESSION_set_ex_data(ssn->ssl->session, fr_tls_ex_index_vps, vps);
			rdebug_pair_list(L_DBG_LVL_2, request, vps, "  caching ");

			if (conf->session_cache_path) {
				/* write the VPs to the cache file */
				char filename[256], buf[1024];
				FILE *vp_file;

				RDEBUG2("Saving session %s in the disk cache", buffer);

				snprintf(filename, sizeof(filename), "%s%c%s.vps", conf->session_cache_path,
					 FR_DIR_SEP, buffer);
				vp_file = fopen(filename, "w");
				if (vp_file == NULL) {
					RWDEBUG("Could not write session VPs to persistent cache: %s",
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
						fr_pair_snprint(buf, sizeof(buf), vp);
						fputs(buf, vp_file);
						prev = vp;
					}

					/*
					 *	Terminate the final line.
					 */
					fprintf(vp_file, "\n");
					fclose(vp_file);
				}
			} else {
				RDEBUG("Failed to find 'persist_dir' in TLS configuration.  Session will not be cached on disk.");
			}
		} else {
			RDEBUG2("No information to cache: session caching will be disabled for session %s", buffer);
			SSL_CTX_remove_session(ssn->ctx, ssn->ssl->session);
		}

	/*
	 *	Else the session WAS allowed.  Copy the cached reply.
	 */
	} else {
		size_t size;
		char buffer[2 * MAX_SESSION_SIZE + 1];

		size = ssn->ssl->session->session_id_length;
		if (size > MAX_SESSION_SIZE) size = MAX_SESSION_SIZE;

		fr_bin2hex(buffer, ssn->ssl->session->session_id, size);

		/*
		 *	The "restore VPs from OpenSSL cache" code is
		 *	now in eaptls_process()
		 */

		if (conf->session_cache_path) {
			/* "touch" the cached session/vp file */
			char filename[256];

			snprintf(filename, sizeof(filename), "%s%c%s.asn1",
				 conf->session_cache_path, FR_DIR_SEP, buffer);
			utime(filename, NULL);
			snprintf(filename, sizeof(filename), "%s%c%s.vps",
				 conf->session_cache_path, FR_DIR_SEP, buffer);
			utime(filename, NULL);
		}

		/*
		 *	Mark the request as resumed.
		 */
		pair_make_request("EAP-Session-Resumed", "1", T_OP_SET);
	}

	return 0;
}


void tls_fail(tls_session_t *ssn)
{
	/*
	 *	Force the session to NOT be cached.
	 */
	SSL_CTX_remove_session(ssn->ctx, ssn->ssl->session);
}

fr_tls_status_t tls_application_data(tls_session_t *ssn, REQUEST *request)

{
	int err;

	/*
	 *	Decrypt the complete record.
	 */
	err = BIO_write(ssn->into_ssl, ssn->dirty_in.data,
			ssn->dirty_in.used);
	if (err != (int) ssn->dirty_in.used) {
		record_init(&ssn->dirty_in);
		RDEBUG("Failed writing %zd bytes to SSL BIO: %d", ssn->dirty_in.used, err);
		return FR_TLS_FAIL;
	}

	/*
	 *      Clear the dirty buffer now that we are done with it
	 *      and init the clean_out buffer to store decrypted data
	 */
	record_init(&ssn->dirty_in);
	record_init(&ssn->clean_out);

	/*
	 *      Read (and decrypt) the tunneled data from the
	 *      SSL session, and put it into the decrypted
	 *      data buffer.
	 */
	err = SSL_read(ssn->ssl, ssn->clean_out.data, sizeof(ssn->clean_out.data));
	if (err < 0) {
		int code;

		RDEBUG("SSL_read Error");

		code = SSL_get_error(ssn->ssl, err);
		switch (code) {
		case SSL_ERROR_WANT_READ:
			DEBUG("Error in fragmentation logic: SSL_WANT_READ");
			return FR_TLS_MORE_FRAGMENTS;

		case SSL_ERROR_WANT_WRITE:
			DEBUG("Error in fragmentation logic: SSL_WANT_WRITE");
			break;

		default:
			DEBUG("Error in fragmentation logic: %s", ERR_error_string(code, NULL));

			/*
			 *	FIXME: Call int_ssl_check?
			 */
			break;
		}
		return FR_TLS_FAIL;
	}

	if (err == 0) RWDEBUG("No data inside of the tunnel");

	/*
	 *	Passed all checks, successfully decrypted data
	 */
	ssn->clean_out.used = err;

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
		REDEBUG("Unexpected ACK received:  No ongoing SSL session");
		return FR_TLS_INVALID;
	}
	if (!ssn->info.initialized) {
		RDEBUG("No SSL info available.  Waiting for more SSL data");
		return FR_TLS_REQUEST;
	}

	if ((ssn->info.content_type == handshake) && (ssn->info.origin == 0)) {
		REDEBUG("Unexpected ACK received:  We sent no previous messages");
		return FR_TLS_INVALID;
	}

	switch (ssn->info.content_type) {
	case alert:
		RDEBUG2("Peer ACKed our alert");
		return FR_TLS_FAIL;

	case handshake:
		if ((ssn->info.handshake_type == handshake_finished) && (ssn->dirty_out.used == 0)) {
			RDEBUG2("Peer ACKed our handshake fragment.  handshake is finished");

			/*
			 *	From now on all the content is
			 *	application data set it here as nobody else
			 *	sets it.
			 */
			ssn->info.content_type = application_data;
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
		REDEBUG("Invalid ACK received: %d", ssn->info.content_type);
		return FR_TLS_INVALID;
	}
}
#endif	/* WITH_TLS */
