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

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/autoconf.h>
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/tls.h>
#include <freeradius-devel/rad_assert.h>

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef WITH_TLS
#ifdef HAVE_OPENSSL_RAND_H
#include <openssl/rand.h>
#endif

#ifdef HAVE_OPENSSL_OCSP_H
#include <openssl/ocsp.h>
#endif

#ifdef HAVE_PTHREAD_H
#define PTHREAD_MUTEX_LOCK pthread_mutex_lock
#define PTHREAD_MUTEX_UNLOCK pthread_mutex_unlock
#else
#define PTHREAD_MUTEX_LOCK(_x)
#define PTHREAD_MUTEX_UNLOCK(_x)
#endif


/* record */
static void 		record_init(record_t *buf);
static void 		record_close(record_t *buf);
static unsigned int 	record_plus(record_t *buf, const void *ptr,
				    unsigned int size);
static unsigned int 	record_minus(record_t *buf, void *ptr,
				     unsigned int size);

tls_session_t *tls_new_session(SSL_CTX *ssl_ctx, int client_cert)
{
	tls_session_t *state = NULL;
	SSL *new_tls = NULL;

	client_cert = client_cert; /* -Wunused.  See bug #350 */

	if ((new_tls = SSL_new(ssl_ctx)) == NULL) {
		radlog(L_ERR, "SSL: Error creating new SSL: %s",
		       ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}

	/* We use the SSL's "app_data" to indicate a call-back */
	SSL_set_app_data(new_tls, NULL);

	state = (tls_session_t *)malloc(sizeof(*state));
	memset(state, 0, sizeof(*state));
	session_init(state);

	state->ctx = ssl_ctx;
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

	return state;
}

/*
 *	Print out some text describing the error.
 */
static int int_ssl_check(REQUEST *request, SSL *s, int ret, const char *text)
{
	int e;
	unsigned long l;

	if ((l = ERR_get_error()) != 0) {
		const char *p = ERR_error_string(l, NULL);
		VALUE_PAIR *vp;

		radlog(L_ERR, "SSL error %s", p);

		if (request) {
			vp = pairmake("Module-Failure-Message", p, T_OP_ADD);
			if (vp) pairadd(&request->packet->vps, vp);
		}
	}
	e = SSL_get_error(s, ret);

	switch(e) {
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
		radlog(L_ERR, "SSL: %s failed in a system call (%d), TLS session fails.",
		       text, ret);
		return 0;

	case SSL_ERROR_SSL:
		radlog(L_ERR, "SSL: %s failed inside of TLS (%d), TLS session fails.",
		       text, ret);
		return 0;

	default:
		/*
		 *	For any other errors that (a) exist, and (b)
		 *	crop up - we need to interpret what to do with
		 *	them - so "politely inform" the caller that
		 *	the code needs updating here.
		 */
		radlog(L_ERR, "SSL: FATAL SSL error ..... %d\n", e);
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

	BIO_write(ssn->into_ssl, ssn->dirty_in.data, ssn->dirty_in.used);

	err = SSL_read(ssn->ssl, ssn->clean_out.data + ssn->clean_out.used,
		       sizeof(ssn->clean_out.data) - ssn->clean_out.used);
	if (err > 0) {
		ssn->clean_out.used += err;
		record_init(&ssn->dirty_in);
		return 1;
	}

	if (!int_ssl_check(request, ssn->ssl, err, "SSL_read")) {
		return 0;
	}

	/* Some Extra STATE information for easy debugging */
	if (SSL_is_init_finished(ssn->ssl)) {
		DEBUG2("SSL Connection Established\n");
	}
   	if (SSL_in_init(ssn->ssl)) {
		DEBUG2("In SSL Handshake Phase\n");
	}
   	if (SSL_in_before(ssn->ssl)) {
		DEBUG2("Before SSL Handshake Phase\n");
	}
   	if (SSL_in_accept_init(ssn->ssl)) {
		DEBUG2("In SSL Accept mode \n");
	}
   	if (SSL_in_connect_init(ssn->ssl)) {
		DEBUG2("In SSL Connect mode \n");
	}

	err = BIO_ctrl_pending(ssn->from_ssl);
	if (err > 0) {
		err = BIO_read(ssn->from_ssl, ssn->dirty_out.data,
			       sizeof(ssn->dirty_out.data));
		if (err > 0) {
			ssn->dirty_out.used = err;

		} else if (BIO_should_retry(ssn->from_ssl)) {
			record_init(&ssn->dirty_in);
			DEBUG2("  tls: Asking for more data in tunnel");
			return 1;

		} else {
			int_ssl_check(request, ssn->ssl, err, "BIO_read");
			record_init(&ssn->dirty_in);
			return 0;
		}
	} else {
		DEBUG2("SSL Application Data");
		/* Its clean application data, do whatever we want */
		record_init(&ssn->clean_out);
	}

	/* We are done with dirty_in, reinitialize it */
	record_init(&ssn->dirty_in);
	return 1;
}

/*
 *	Take clear-text user data, and encrypt it into the output buffer,
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

void session_init(tls_session_t *ssn)
{
	ssn->ssl = NULL;
	ssn->into_ssl = ssn->from_ssl = NULL;
	record_init(&ssn->clean_in);
	record_init(&ssn->clean_out);
	record_init(&ssn->dirty_in);
	record_init(&ssn->dirty_out);

	memset(&ssn->info, 0, sizeof(ssn->info));

	ssn->offset = 0;
	ssn->fragment = 0;
	ssn->tls_msg_len = 0;
	ssn->length_flag = 0;
	ssn->opaque = NULL;
	ssn->free_opaque = NULL;
}

void session_close(tls_session_t *ssn)
{	
	if (ssn->ssl->session) {
		VALUE_PAIR *vp;

		vp = SSL_SESSION_get_ex_data(ssn->ssl->session,
					     FR_TLS_EX_INDEX_VPS);
		if (vp) pairfree(&vp);
	}

	SSL_set_quiet_shutdown(ssn->ssl, 1);
	SSL_shutdown(ssn->ssl);

	if(ssn->ssl)
		SSL_free(ssn->ssl);
#if 0
/*
 * WARNING: SSL_free seems to decrement the reference counts already,
 * 	so doing this might crash the application.
 */
	if(ssn->into_ssl)
		BIO_free(ssn->into_ssl);
	if(ssn->from_ssl)
		BIO_free(ssn->from_ssl);
#endif
	record_close(&ssn->clean_in);
	record_close(&ssn->clean_out);
	record_close(&ssn->dirty_in);
	record_close(&ssn->dirty_out);
	session_init(ssn);
}

void session_free(void *ssn)
{
	tls_session_t *sess = (tls_session_t *)ssn;

	if (!ssn) return;

	/*
	 *	Free any opaque TTLS or PEAP data.
	 */
	if ((sess->opaque) && (sess->free_opaque)) {
		sess->free_opaque(sess->opaque);
		sess->opaque = NULL;
	}

	session_close(sess);

	free(sess);
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
static unsigned int record_plus(record_t *rec, const void *ptr,
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
	const char *str_write_p, *str_version, *str_content_type = "";
	const char *str_details1 = "", *str_details2= "";
	REQUEST *request;

	/*
	 *	Don't print this out in the normal course of
	 *	operations.
	 */
	if (debug_flag == 0) {
		return;
	}

	str_write_p = tls_session->info.origin ? ">>>" : "<<<";

	switch (tls_session->info.version)
	{
	case SSL2_VERSION:
		str_version = "SSL 2.0";
		break;
	case SSL3_VERSION:
		str_version = "SSL 3.0 ";
		break;
	case TLS1_VERSION:
		str_version = "TLS 1.0 ";
		break;
	default:
		str_version = "Unknown TLS version";
		break;
	}

	if (tls_session->info.version == SSL3_VERSION ||
	    tls_session->info.version == TLS1_VERSION) {
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
			str_content_type = "UnknownContentType";
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

			if (tls_session->info.record_len > 0)
			switch (tls_session->info.handshake_type)
			{
			case SSL3_MT_HELLO_REQUEST:
				str_details1 = ", HelloRequest";
				break;
			case SSL3_MT_CLIENT_HELLO:
				str_details1 = ", ClientHello";
				break;
			case SSL3_MT_SERVER_HELLO:
				str_details1 = ", ServerHello";
				break;
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
			}
		}
	}

	snprintf(tls_session->info.info_description, 
		 sizeof(tls_session->info.info_description),
		 "%s %s%s [length %04lx]%s%s\n",
		 str_write_p, str_version, str_content_type,
		 (unsigned long)tls_session->info.record_len,
		 str_details1, str_details2);

	request = SSL_get_ex_data(tls_session->ssl, FR_TLS_EX_INDEX_REQUEST);

	RDEBUG2("%s\n", tls_session->info.info_description);
}

static CONF_PARSER cache_config[] = {
	{ "enable", PW_TYPE_BOOLEAN,
	  offsetof(fr_tls_server_conf_t, session_cache_enable), NULL, "no" },
	{ "lifetime", PW_TYPE_INTEGER,
	  offsetof(fr_tls_server_conf_t, session_timeout), NULL, "24" },
	{ "max_entries", PW_TYPE_INTEGER,
	  offsetof(fr_tls_server_conf_t, session_cache_size), NULL, "255" },
	{ "name", PW_TYPE_STRING_PTR,
	  offsetof(fr_tls_server_conf_t, session_id_name), NULL, NULL},
	{ NULL, -1, 0, NULL, NULL }           /* end the list */
};

static CONF_PARSER verify_config[] = {
	{ "tmpdir", PW_TYPE_STRING_PTR,
	  offsetof(fr_tls_server_conf_t, verify_tmp_dir), NULL, NULL},
	{ "client", PW_TYPE_STRING_PTR,
	  offsetof(fr_tls_server_conf_t, verify_client_cert_cmd), NULL, NULL},
	{ NULL, -1, 0, NULL, NULL }           /* end the list */
};

#ifdef HAVE_OPENSSL_OCSP_H
static CONF_PARSER ocsp_config[] = {
	{ "enable", PW_TYPE_BOOLEAN,
	  offsetof(fr_tls_server_conf_t, ocsp_enable), NULL, "no"},
	{ "override_cert_url", PW_TYPE_BOOLEAN,
	  offsetof(fr_tls_server_conf_t, ocsp_override_url), NULL, "no"},
	{ "url", PW_TYPE_STRING_PTR,
	  offsetof(fr_tls_server_conf_t, ocsp_url), NULL, NULL },
	{ NULL, -1, 0, NULL, NULL }           /* end the list */
};
#endif

static CONF_PARSER tls_server_config[] = {
	{ "rsa_key_exchange", PW_TYPE_BOOLEAN,
	  offsetof(fr_tls_server_conf_t, rsa_key), NULL, "no" },
	{ "dh_key_exchange", PW_TYPE_BOOLEAN,
	  offsetof(fr_tls_server_conf_t, dh_key), NULL, "yes" },
	{ "rsa_key_length", PW_TYPE_INTEGER,
	  offsetof(fr_tls_server_conf_t, rsa_key_length), NULL, "512" },
	{ "dh_key_length", PW_TYPE_INTEGER,
	  offsetof(fr_tls_server_conf_t, dh_key_length), NULL, "512" },
	{ "verify_depth", PW_TYPE_INTEGER,
	  offsetof(fr_tls_server_conf_t, verify_depth), NULL, "0" },
	{ "CA_path", PW_TYPE_FILENAME,
	  offsetof(fr_tls_server_conf_t, ca_path), NULL, NULL },
	{ "pem_file_type", PW_TYPE_BOOLEAN,
	  offsetof(fr_tls_server_conf_t, file_type), NULL, "yes" },
	{ "private_key_file", PW_TYPE_FILENAME,
	  offsetof(fr_tls_server_conf_t, private_key_file), NULL, NULL },
	{ "certificate_file", PW_TYPE_FILENAME,
	  offsetof(fr_tls_server_conf_t, certificate_file), NULL, NULL },
	{ "CA_file", PW_TYPE_FILENAME,
	  offsetof(fr_tls_server_conf_t, ca_file), NULL, NULL },
	{ "private_key_password", PW_TYPE_STRING_PTR,
	  offsetof(fr_tls_server_conf_t, private_key_password), NULL, NULL },
	{ "dh_file", PW_TYPE_STRING_PTR,
	  offsetof(fr_tls_server_conf_t, dh_file), NULL, NULL },
	{ "random_file", PW_TYPE_STRING_PTR,
	  offsetof(fr_tls_server_conf_t, random_file), NULL, NULL },
	{ "fragment_size", PW_TYPE_INTEGER,
	  offsetof(fr_tls_server_conf_t, fragment_size), NULL, "1024" },
	{ "include_length", PW_TYPE_BOOLEAN,
	  offsetof(fr_tls_server_conf_t, include_length), NULL, "yes" },
	{ "check_crl", PW_TYPE_BOOLEAN,
	  offsetof(fr_tls_server_conf_t, check_crl), NULL, "no"},
	{ "allow_expired_crl", PW_TYPE_BOOLEAN,
	  offsetof(fr_tls_server_conf_t, allow_expired_crl), NULL, NULL},
	{ "check_cert_cn", PW_TYPE_STRING_PTR,
	  offsetof(fr_tls_server_conf_t, check_cert_cn), NULL, NULL},
	{ "cipher_list", PW_TYPE_STRING_PTR,
	  offsetof(fr_tls_server_conf_t, cipher_list), NULL, NULL},
	{ "check_cert_issuer", PW_TYPE_STRING_PTR,
	  offsetof(fr_tls_server_conf_t, check_cert_issuer), NULL, NULL},
	{ "make_cert_command", PW_TYPE_STRING_PTR,
	  offsetof(fr_tls_server_conf_t, make_cert_command), NULL, NULL},

	{ "cache", PW_TYPE_SUBSECTION, 0, NULL, (const void *) cache_config },

	{ "verify", PW_TYPE_SUBSECTION, 0, NULL, (const void *) verify_config },

#ifdef HAVE_OPENSSL_OCSP_H
	{ "ocsp", PW_TYPE_SUBSECTION, 0, NULL, (const void *) ocsp_config },
#endif

	{ NULL, -1, 0, NULL, NULL }           /* end the list */
};

/*
 *	TODO: Check for the type of key exchange * like conf->dh_key
 */
static int load_dh_params(SSL_CTX *ctx, char *file)
{
	DH *dh = NULL;
	BIO *bio;

	if ((bio = BIO_new_file(file, "r")) == NULL) {
		radlog(L_ERR, "rlm_eap_tls: Unable to open DH file - %s", file);
		return -1;
	}

	dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
	BIO_free(bio);
	if (!dh) {
		DEBUG2("WARNING: rlm_eap_tls: Unable to set DH parameters.  DH cipher suites may not work!");
		DEBUG2("WARNING: Fix this by running the OpenSSL command listed in eap.conf");
		return 0;
	}

	if (SSL_CTX_set_tmp_dh(ctx, dh) < 0) {
		radlog(L_ERR, "rlm_eap_tls: Unable to set DH parameters");
		DH_free(dh);
		return -1;
	}

	DH_free(dh);
	return 0;
}


/*
 *	Generate ephemeral RSA keys.
 */
static int generate_eph_rsa_key(SSL_CTX *ctx)
{
	RSA *rsa;

	rsa = RSA_generate_key(512, RSA_F4, NULL, NULL);

	if (!SSL_CTX_set_tmp_rsa(ctx, rsa)) {
		radlog(L_ERR, "rlm_eap_tls: Couldn't set ephemeral RSA key");
		return -1;
	}

	RSA_free(rsa);
	return 0;
}


/*
 *	These functions don't do anything other than print debugging
 *	messages.
 *
 *	FIXME: Write sessions to some long-term storage, so that
 *	       session resumption can still occur after the server
 *	       restarts.
 */
#define MAX_SESSION_SIZE (256)

static void cbtls_remove_session(UNUSED SSL_CTX *ctx, SSL_SESSION *sess)
{
	size_t size;
	char buffer[2 * MAX_SESSION_SIZE + 1];

	size = sess->session_id_length;
	if (size > MAX_SESSION_SIZE) size = MAX_SESSION_SIZE;

	fr_bin2hex(sess->session_id, buffer, size);

        DEBUG2("  SSL: Removing session %s from the cache", buffer);
        SSL_SESSION_free(sess);

        return;
}

static int cbtls_new_session(UNUSED SSL *s, SSL_SESSION *sess)
{
	size_t size;
	char buffer[2 * MAX_SESSION_SIZE + 1];

	size = sess->session_id_length;
	if (size > MAX_SESSION_SIZE) size = MAX_SESSION_SIZE;

	fr_bin2hex(sess->session_id, buffer, size);

	DEBUG2("  SSL: adding session %s to cache", buffer);

	return 1;
}

static SSL_SESSION *cbtls_get_session(UNUSED SSL *s,
				      unsigned char *data, int len,
				      UNUSED int *copy)
{
	size_t size;
	char buffer[2 * MAX_SESSION_SIZE + 1];

	size = len;
	if (size > MAX_SESSION_SIZE) size = MAX_SESSION_SIZE;

	fr_bin2hex(data, buffer, size);

        DEBUG2("  SSL: Client requested nonexistent cached session %s",
	       buffer);

	return NULL;
}

#ifdef HAVE_OPENSSL_OCSP_H
/*
 * This function extracts the OCSP Responder URL
 * from an existing x509 certificate.
 */
static int ocsp_parse_cert_url(X509 *cert, char **phost, char **pport,
			       char **ppath, int *pssl)
{
	int i;

	AUTHORITY_INFO_ACCESS *aia;
	ACCESS_DESCRIPTION *ad;

	aia = X509_get_ext_d2i(cert, NID_info_access, NULL, NULL);

	for (i = 0; i < sk_ACCESS_DESCRIPTION_num(aia); i++) {
		ad = sk_ACCESS_DESCRIPTION_value(aia, 0);
		if (OBJ_obj2nid(ad->method) == NID_ad_OCSP) {
			if (ad->location->type == GEN_URI) {
				if(OCSP_parse_url(ad->location->d.ia5->data,
					phost, pport, ppath, pssl))
					return 1;
			}
		}
	}
	return 0;
}

/*
 * This function sends a OCSP request to a defined OCSP responder
 * and checks the OCSP response for correctness.
 */
static int ocsp_check(X509_STORE *store, X509 *issuer_cert, X509 *client_cert,
		      fr_tls_server_conf_t *conf)
{
	OCSP_CERTID *certid;
	OCSP_REQUEST *req;
	OCSP_RESPONSE *resp;
	OCSP_BASICRESP *bresp = NULL;
	char *host = NULL;
	char *port = NULL;
	char *path = NULL;
	int use_ssl = -1;
	BIO *cbio;
	int ocsp_ok;
	int status;

	/*
	 * Create OCSP Request
	 */
	certid = OCSP_cert_to_id(NULL, client_cert, issuer_cert);
	req = OCSP_REQUEST_new();
	OCSP_request_add0_id(req, certid);
	OCSP_request_add1_nonce(req, NULL, 8);

	/*
	 * Send OCSP Request and get OCSP Response
	 */

	/* Get OCSP responder URL */
	if(conf->ocsp_override_url) {
		OCSP_parse_url(conf->ocsp_url, &host, &port, &path, &use_ssl);
	}
	else {
		ocsp_parse_cert_url(client_cert, &host, &port, &path, &use_ssl);
	}

	DEBUG2("[ocsp] --> Responder URL = http://%s:%s%s", host, port, path);

	/* Setup BIO socket to OCSP responder */
	cbio = BIO_new_connect(host);
	BIO_set_conn_port(cbio, port);
	BIO_do_connect(cbio);

	/* Send OCSP request and wait for response */
	resp = OCSP_sendreq_bio(cbio, path, req);
	if(resp==0) {
		radlog(L_ERR, "Error: Couldn't get OCSP response");
		ocsp_ok = 0;
		goto ocsp_end;
	}

	/* Verify OCSP response */
	status = OCSP_response_status(resp);
	if(status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
		radlog(L_ERR, "Error: OCSP response status: %s", OCSP_response_status_str(status));
		ocsp_ok = 0;
		goto ocsp_end;
	}
	bresp = OCSP_response_get1_basic(resp);
	if(OCSP_check_nonce(req, bresp)!=1) {
		radlog(L_ERR, "Error: OCSP response has wrong nonce value");
		ocsp_ok = 0;
		goto ocsp_end;
	}
	if(OCSP_basic_verify(bresp, NULL, store, 0)!=1){
		radlog(L_ERR, "Error: Couldn't verify OCSP basic response");
		ocsp_ok = 0;
		goto ocsp_end;
	}

	ocsp_ok = 1;

ocsp_end:
	/* Free OCSP Stuff */
	OCSP_REQUEST_free(req);
	OCSP_RESPONSE_free(resp);
	free(host);
	free(port);
	free(path);
	BIO_free_all(cbio);
	OCSP_BASICRESP_free(bresp);

	if (ocsp_ok) {
		DEBUG2("[ocsp] --> Certificate is valid!");
	} else {
		DEBUG2("[ocsp] --> Certificate has been expired/revoked!");
	}

	return ocsp_ok;
}
#endif	/* HAVE_OPENSSL_OCSP_H */

/*
 *	For creating certificate attributes.
 */
static const char *cert_attr_names[5][2] = {
  { "TLS-Client-Cert-Serial",		"TLS-Cert-Serial" },
  { "TLS-Client-Cert-Expiration",	"TLS-Cert-Expiration" },
  { "TLS-Client-Cert-Subject",		"TLS-Cert-Subject" },
  { "TLS-Client-Cert-Issuer",		"TLS-Cert-Issuer" },
  { "TLS-Client-Cert-Common-Name",	"TLS-Cert-Common-Name" }
};

#define EAPTLS_SERIAL		(0)
#define EAPTLS_EXPIRATION	(1)
#define EAPTLS_SUBJECT		(2)
#define EAPTLS_ISSUER		(3)
#define EAPTLS_CN		(4)

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
	char subject[1024]; /* Used for the subject name */
	char issuer[1024]; /* Used for the issuer name */
	char common_name[1024];
	char cn_str[1024];
	char buf[64];
	X509 *client_cert;
	X509 *issuer_cert;
	SSL *ssl;
	int err, depth, lookup;
	fr_tls_server_conf_t *conf;
	int my_ok = ok;
	REQUEST *request;
	ASN1_INTEGER *sn = NULL;
	ASN1_TIME *asn_time = NULL;
	VALUE_PAIR **certs;
	char **identity;
#ifdef HAVE_OPENSSL_OCSP_H
	X509_STORE *ocsp_store = NULL;
#endif

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
	 * Retrieve the pointer to the SSL of the connection currently treated
	 * and the application specific data stored into the SSL object.
	 */
	ssl = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
	conf = (fr_tls_server_conf_t *)SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_CONF);
	if (!conf) return 1;

	request = (REQUEST *)SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_REQUEST);

	if (!request) return 1;	/* FIXME: outbound TLS */

	rad_assert(request != NULL);
	certs = (VALUE_PAIR **)SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_CERTS);
	rad_assert(certs != NULL);
	identity = (char **)SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_IDENTITY);
#ifdef HAVE_OPENSSL_OCSP_H
	ocsp_store = (X509_STORE *)SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_STORE);
#endif


	/*
	 *	Get the Serial Number
	 */
	buf[0] = '\0';
	sn = X509_get_serialNumber(client_cert);

	/*
	 *	For this next bit, we create the attributes *only* if
	 *	we're at the client or issuing certificate.
	 */
	if ((lookup <= 1) && sn && (sn->length < (sizeof(buf) / 2))) {
		char *p = buf;
		int i;

		for (i = 0; i < sn->length; i++) {
			sprintf(p, "%02x", (unsigned int)sn->data[i]);
			p += 2;
		}
		pairadd(certs,
			pairmake(cert_attr_names[EAPTLS_SERIAL][lookup], buf, T_OP_SET));
	}


	/*
	 *	Get the Expiration Date
	 */
	buf[0] = '\0';
	asn_time = X509_get_notAfter(client_cert);
	if ((lookup <= 1) && asn_time && (asn_time->length < MAX_STRING_LEN)) {
		memcpy(buf, (char*) asn_time->data, asn_time->length);
		buf[asn_time->length] = '\0';
		pairadd(certs,
			pairmake(cert_attr_names[EAPTLS_EXPIRATION][lookup], buf, T_OP_SET));
	}

	/*
	 *	Get the Subject & Issuer
	 */
	subject[0] = issuer[0] = '\0';
	X509_NAME_oneline(X509_get_subject_name(client_cert), subject,
			  sizeof(subject));
	subject[sizeof(subject) - 1] = '\0';
	if ((lookup <= 1) && subject[0] && (strlen(subject) < MAX_STRING_LEN)) {
		pairadd(certs,
			pairmake(cert_attr_names[EAPTLS_SUBJECT][lookup], subject, T_OP_SET));
	}

	X509_NAME_oneline(X509_get_issuer_name(ctx->current_cert), issuer,
			  sizeof(issuer));
	issuer[sizeof(issuer) - 1] = '\0';
	if ((lookup <= 1) && issuer[0] && (strlen(issuer) < MAX_STRING_LEN)) {
		pairadd(certs,
			pairmake(cert_attr_names[EAPTLS_ISSUER][lookup], issuer, T_OP_SET));
	}

	/*
	 *	Get the Common Name
	 */
	X509_NAME_get_text_by_NID(X509_get_subject_name(client_cert),
				  NID_commonName, common_name, sizeof(common_name));
	common_name[sizeof(common_name) - 1] = '\0';
	if ((lookup <= 1) && common_name[0] && (strlen(common_name) < MAX_STRING_LEN)) {
		pairadd(certs,
			pairmake(cert_attr_names[EAPTLS_CN][lookup], common_name, T_OP_SET));
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
		const char *p = X509_verify_cert_error_string(err);
		radlog(L_ERR,"--> verify error:num=%d:%s\n",err, p);
		radius_pairmake(request, &request->packet->vps,
				"Module-Failure-Message", p, T_OP_SET);
		return my_ok;
	}

	switch (ctx->error) {

	case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
		radlog(L_ERR, "issuer= %s\n", issuer);
		break;
	case X509_V_ERR_CERT_NOT_YET_VALID:
	case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
		radlog(L_ERR, "notBefore=");
#if 0
		ASN1_TIME_print(bio_err, X509_get_notBefore(ctx->current_cert));
#endif
		break;
	case X509_V_ERR_CERT_HAS_EXPIRED:
	case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
		radlog(L_ERR, "notAfter=");
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
			radlog(L_AUTH, "rlm_eap_tls: Certificate issuer (%s) does not match specified value (%s)!", issuer, conf->check_cert_issuer);
			my_ok = 0;
		}

		/*
		 *	If the conf tells us to, check the CN in the
		 *	cert against xlat'ed value, but only if the
		 *	previous checks passed.
		 */
		if (my_ok && conf->check_cert_cn) {
			if (!radius_xlat(cn_str, sizeof(cn_str), conf->check_cert_cn, request, NULL)) {
				radlog(L_ERR, "rlm_eap_tls (%s): xlat failed.",
				       conf->check_cert_cn);
				/* if this fails, fail the verification */
				my_ok = 0;
			} else {
				RDEBUG2("checking certificate CN (%s) with xlat'ed value (%s)", common_name, cn_str);
				if (strcmp(cn_str, common_name) != 0) {
					radlog(L_AUTH, "rlm_eap_tls: Certificate CN (%s) does not match specified value (%s)!", common_name, cn_str);
					my_ok = 0;
				}
			}
		} /* check_cert_cn */

#ifdef HAVE_OPENSSL_OCSP_H
		if (my_ok && conf->ocsp_enable){
			RDEBUG2("--> Starting OCSP Request");
			if(X509_STORE_CTX_get1_issuer(&issuer_cert, ctx, client_cert)!=1) {
				radlog(L_ERR, "Error: Couldn't get issuer_cert for %s", common_name);
			}
			my_ok = ocsp_check(ocsp_store, issuer_cert, client_cert, conf);
		}
#endif

		while (conf->verify_client_cert_cmd) {
			char filename[256];
			int fd;
			FILE *fp;

			snprintf(filename, sizeof(filename), "%s/%s.client.XXXXXXXX",
				 conf->verify_tmp_dir, progname);
			fd = mkstemp(filename);
			if (fd < 0) {
				RDEBUG("Failed creating file in %s: %s",
				       conf->verify_tmp_dir, strerror(errno));
				break;
			}

			fp = fdopen(fd, "w");
			if (!fp) {
				RDEBUG("Failed opening file %s: %s",
				       filename, strerror(errno));
				break;
			}

			if (!PEM_write_X509(fp, client_cert)) {
				fclose(fp);
				RDEBUG("Failed writing certificate to file");
				goto do_unlink;
			}
			fclose(fp);

			if (!radius_pairmake(request, &request->packet->vps,
					     "TLS-Client-Cert-Filename",
					     filename, T_OP_SET)) {
				RDEBUG("Failed creating TLS-Client-Cert-Filename");

				goto do_unlink;
			}

			RDEBUG("Verifying client certificate: %s",
			       conf->verify_client_cert_cmd);
			if (radius_exec_program(conf->verify_client_cert_cmd,
						request, 1, NULL, 0,
						request->packet->vps,
						NULL, 1) != 0) {
				radlog(L_AUTH, "rlm_eap_tls: Certificate CN (%s) fails external verification!", common_name);
				my_ok = 0;
			} else {
				RDEBUG("Client certificate CN %s passed external validation", common_name);
			}

		do_unlink:
			unlink(filename);
			break;
		}


	} /* depth == 0 */

	if (debug_flag > 0) {
		RDEBUG2("chain-depth=%d, ", depth);
		RDEBUG2("error=%d", err);

		RDEBUG2("--> User-Name = %s", *identity);
		RDEBUG2("--> BUF-Name = %s", common_name);
		RDEBUG2("--> subject = %s", subject);
		RDEBUG2("--> issuer  = %s", issuer);
		RDEBUG2("--> verify return:%d", my_ok);
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
			radlog(L_ERR, "rlm_eap: X509_STORE error %s", ERR_error_string(ERR_get_error(), NULL));
			radlog(L_ERR, "rlm_eap_tls: Error reading Trusted root CA list %s",conf->ca_file );
			return NULL;
		}

#ifdef X509_V_FLAG_CRL_CHECK
	if (conf->check_crl)
		X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
#endif
	return store;
}
#endif	/* HAVE_OPENSSL_OCSP_H */

/*
 *	Create Global context SSL and use it in every new session
 *
 *	- Load the trusted CAs
 *	- Load the Private key & the certificate
 *	- Set the Context options & Verify options
 */
static SSL_CTX *init_tls_ctx(fr_tls_server_conf_t *conf)
{
	SSL_METHOD *meth;
	SSL_CTX *ctx;
	X509_STORE *certstore;
	int verify_mode = SSL_VERIFY_NONE;
	int ctx_options = 0;
	int type;

	/*
	 *	Add all the default ciphers and message digests
	 *	Create our context.
	 */
	SSL_library_init();
	SSL_load_error_strings();

	/*
	 *	SHA256 is in all versions of OpenSSL, but isn't
	 *	initialized by default.  It's needed for WiMAX
	 *	certificates.
	 */
#ifdef HAVE_OPENSSL_EVP_SHA256
	EVP_add_digest(EVP_sha256());
#endif

	meth = TLSv1_method();
	ctx = SSL_CTX_new(meth);

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
		const char* special_string = "Apple:UseCertAdmin";
		if (strncmp(conf->private_key_password,
					special_string,
					strlen(special_string)) == 0)
		{
			char cmd[256];
			const long max_password_len = 128;
			snprintf(cmd, sizeof(cmd) - 1,
					 "/usr/sbin/certadmin --get-private-key-passphrase \"%s\"",
					 conf->private_key_file);

			DEBUG2("rlm_eap: Getting private key passphrase using command \"%s\"", cmd);

			FILE* cmd_pipe = popen(cmd, "r");
			if (!cmd_pipe) {
				radlog(L_ERR, "rlm_eap: %s command failed.	Unable to get private_key_password", cmd);
				radlog(L_ERR, "rlm_eap: Error reading private_key_file %s", conf->private_key_file);
				return NULL;
			}

			free(conf->private_key_password);
			conf->private_key_password = malloc(max_password_len * sizeof(char));
			if (!conf->private_key_password) {
				radlog(L_ERR, "rlm_eap: Can't malloc space for private_key_password");
				radlog(L_ERR, "rlm_eap: Error reading private_key_file %s", conf->private_key_file);
				pclose(cmd_pipe);
				return NULL;
			}

			fgets(conf->private_key_password, max_password_len, cmd_pipe);
			pclose(cmd_pipe);

			/* Get rid of newline at end of password. */
			conf->private_key_password[strlen(conf->private_key_password) - 1] = '\0';
			DEBUG2("rlm_eap:  Password from command = \"%s\"", conf->private_key_password);
		}
#endif
		SSL_CTX_set_default_passwd_cb_userdata(ctx, conf->private_key_password);
		SSL_CTX_set_default_passwd_cb(ctx, cbtls_password);
	}

	/*
	 *	Load our keys and certificates
	 *
	 *	If certificates are of type PEM then we can make use
	 *	of cert chain authentication using openssl api call
	 *	SSL_CTX_use_certificate_chain_file.  Please see how
	 *	the cert chain needs to be given in PEM from
	 *	openSSL.org
	 */
	if (type == SSL_FILETYPE_PEM) {
		if (!(SSL_CTX_use_certificate_chain_file(ctx, conf->certificate_file))) {
			radlog(L_ERR, "rlm_eap: SSL error %s", ERR_error_string(ERR_get_error(), NULL));
			radlog(L_ERR, "rlm_eap_tls: Error reading certificate file %s", conf->certificate_file);
			return NULL;
		}

	} else if (!(SSL_CTX_use_certificate_file(ctx, conf->certificate_file, type))) {
		radlog(L_ERR, "rlm_eap: SSL error %s", ERR_error_string(ERR_get_error(), NULL));
		radlog(L_ERR, "rlm_eap_tls: Error reading certificate file %s", conf->certificate_file);
		return NULL;
	}

	/* Load the CAs we trust */
	if (conf->ca_file || conf->ca_path) {
		if (!SSL_CTX_load_verify_locations(ctx, conf->ca_file, conf->ca_path)) {
			radlog(L_ERR, "rlm_eap: SSL error %s", ERR_error_string(ERR_get_error(), NULL));
			radlog(L_ERR, "rlm_eap_tls: Error reading Trusted root CA list %s",conf->ca_file );
			return NULL;
		}
	}
	if (conf->ca_file && *conf->ca_file) SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(conf->ca_file));
	if (!(SSL_CTX_use_PrivateKey_file(ctx, conf->private_key_file, type))) {
		radlog(L_ERR, "rlm_eap: SSL error %s", ERR_error_string(ERR_get_error(), NULL));
		radlog(L_ERR, "rlm_eap_tls: Error reading private key file %s", conf->private_key_file);
		return NULL;
	}

	/*
	 * Check if the loaded private key is the right one
	 */
	if (!SSL_CTX_check_private_key(ctx)) {
		radlog(L_ERR, "rlm_eap_tls: Private key does not match the certificate public key");
		return NULL;
	}

	/*
	 *	Set ctx_options
	 */
	ctx_options |= SSL_OP_NO_SSLv2;
	ctx_options |= SSL_OP_NO_SSLv3;
#ifdef SSL_OP_NO_TICKET
	ctx_options |= SSL_OP_NO_TICKET ;
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

	/* Set Info callback */
	SSL_CTX_set_info_callback(ctx, cbtls_info);

	/*
	 *	Callbacks, etc. for session resumption.
	 */
	if (conf->session_cache_enable) {
		SSL_CTX_sess_set_new_cb(ctx, cbtls_new_session);
		SSL_CTX_sess_set_get_cb(ctx, cbtls_get_session);
		SSL_CTX_sess_set_remove_cb(ctx, cbtls_remove_session);

		SSL_CTX_set_quiet_shutdown(ctx, 1);
	}

	/*
	 *	Check the certificates for revocation.
	 */
#ifdef X509_V_FLAG_CRL_CHECK
	if (conf->check_crl) {
	  certstore = SSL_CTX_get_cert_store(ctx);
	  if (certstore == NULL) {
	    radlog(L_ERR, "rlm_eap: SSL error %s", ERR_error_string(ERR_get_error(), NULL));
	    radlog(L_ERR, "rlm_eap_tls: Error reading Certificate Store");
	    return NULL;
	  }
	  X509_STORE_set_flags(certstore, X509_V_FLAG_CRL_CHECK);
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
	if (!(RAND_load_file(conf->random_file, 1024*1024))) {
		radlog(L_ERR, "rlm_eap: SSL error %s", ERR_error_string(ERR_get_error(), NULL));
		radlog(L_ERR, "rlm_eap_tls: Error loading randomness");
		return NULL;
	}

	/*
	 * Set the cipher list if we were told to
	 */
	if (conf->cipher_list) {
		if (!SSL_CTX_set_cipher_list(ctx, conf->cipher_list)) {
			radlog(L_ERR, "rlm_eap_tls: Error setting cipher list");
			return NULL;
		}
	}

	/*
	 *	Setup session caching
	 */
	if (conf->session_cache_enable) {
		/*
		 *	Create a unique context Id per EAP-TLS configuration.
		 */
		if (conf->session_id_name) {
			snprintf(conf->session_context_id,
				 sizeof(conf->session_context_id),
				 "FreeRADIUS EAP-TLS %s",
				 conf->session_id_name);
		} else {
			snprintf(conf->session_context_id,
				 sizeof(conf->session_context_id),
				 "FreeRADIUS EAP-TLS %p", conf);
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

	} else {
		SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
	}

	return ctx;
}


void tls_server_conf_free(fr_tls_server_conf_t *conf)
{
	if (!conf) return;

	if (conf->cs) cf_section_parse_free(conf->cs, conf);

	if (conf->ctx) SSL_CTX_free(conf->ctx);

#ifdef HAVE_OPENSSL_OCSP_H
	if (conf->ocsp_store) X509_STORE_free(conf->ocsp_store);
	conf->ocsp_store = NULL;
#endif

	memset(conf, 0, sizeof(*conf));
	free(conf);
}


fr_tls_server_conf_t *tls_server_conf_parse(CONF_SECTION *cs)
{
	fr_tls_server_conf_t *conf;

	conf = malloc(sizeof(*conf));
	if (!conf) {
		radlog(L_ERR, "Out of memory");
		return NULL;
	}
	memset(conf, 0, sizeof(*conf));

	if (cf_section_parse(cs, conf, tls_server_config) < 0) {
	error:
		tls_server_conf_free(conf);
		return NULL;
	}

	/*
	 *	Save people from their own stupidity.
	 */
	if (conf->fragment_size < 100) conf->fragment_size = 100;

	/*
	 *	This magic makes the administrators life HUGELY easier
	 *	on initial deployments.
	 *
	 *	If the server starts up in debugging mode, AND the
	 *	bootstrap command is configured, AND it exists, AND
	 *	there is no server certificate
	 */
	if (conf->make_cert_command && (debug_flag >= 2)) {
		struct stat buf;

		if ((stat(conf->make_cert_command, &buf) == 0) &&
		    (stat(conf->certificate_file, &buf) < 0) &&
		    (errno == ENOENT) &&
		    (radius_exec_program(conf->make_cert_command, NULL, 1,
					 NULL, 0, NULL, NULL, 0) != 0)) {
			goto error;
		}
	}

	if (!conf->private_key_file) {
		radlog(L_ERR, "TLS Server requires a private key file");
		goto error;
	}

	if (!conf->private_key_password) {
		radlog(L_ERR, "TLS Server requires a private key password");
		goto error;
	}

	if (!conf->certificate_file) {
		radlog(L_ERR, "TLS Server requires a certificate file");
		goto error;
	}

	/*
	 *	Initialize TLS
	 */
	conf->ctx = init_tls_ctx(conf);
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
#endif HAVE_OPENSSL_OCSP_H

	if (load_dh_params(conf->ctx, conf->dh_file) < 0) {
		goto error;
	}

        if (generate_eph_rsa_key(conf->ctx) < 0) {
		goto error;
        }

	if (conf->verify_tmp_dir) {
		if (chmod(conf->verify_tmp_dir, S_IRWXU) < 0) {
			radlog(L_ERR, "Failed changing permissions on %s: %s", conf->verify_tmp_dir, strerror(errno));
			goto error;
		}
	}

	if (conf->verify_client_cert_cmd && !conf->verify_tmp_dir) {
		radlog(L_ERR, "You MUST set the verify directory in order to use verify_client_cmd");
		goto error;
	}

	return conf;
}
