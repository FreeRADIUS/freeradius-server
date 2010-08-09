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

#include "eap_tls.h"

/* record */
static void 		record_init(record_t *buf);
static void 		record_close(record_t *buf);
static unsigned int 	record_plus(record_t *buf, const void *ptr,
				    unsigned int size);
static unsigned int 	record_minus(record_t *buf, void *ptr,
				     unsigned int size);

tls_session_t *eaptls_new_session(SSL_CTX *ssl_ctx, int client_cert)
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
	 *	and we can update those BIOs from the EAP packets we've
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

		radlog(L_ERR, "rlm_eap: SSL error %s", p);

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
 * As of now, if handshake is successful, then it is EAP-Success
 * or else EAP-failure should be sent
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
	EAP_HANDLER *handler;
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

	handler = (EAP_HANDLER *)SSL_get_ex_data(tls_session->ssl, 0);
	if (handler) {
		request = handler->request;
	} else {
		request = NULL;
	}

	RDEBUG2("%s\n", tls_session->info.info_description);
}
