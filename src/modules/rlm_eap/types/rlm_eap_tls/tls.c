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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2001  hereUare Communications, Inc. <raghud@hereuare.com>
 */
#include "eap_tls.h"

/*
 * TODO: Check for the type of key exchange
 *  like conf->dh_key
 */
int load_dh_params(SSL_CTX *ctx, char *file)
{
	DH *dh = NULL;
	BIO *bio;

	if ((bio = BIO_new_file(file, "r")) == NULL) {
		radlog(L_ERR, "rlm_eap_tls: Unable to open DH file - %s", file);
		return -1;
	}

	dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
	BIO_free(bio);
	if (SSL_CTX_set_tmp_dh(ctx, dh) < 0) {
		radlog(L_ERR, "rlm_eap_tls: Unable to set DH parameters");
		DH_free(dh);
		return -1;
	}

	DH_free(dh);
	return 0;
}

int generate_eph_rsa_key(SSL_CTX *ctx)
{
	RSA *rsa;

	rsa = RSA_generate_key(512, RSA_F4, NULL, NULL);

	if (!SSL_CTX_set_tmp_rsa(ctx, rsa)) {
		radlog(L_ERR, "rlm_eap_tls: Couldn't set RSA key");
		return -1;
	}

	RSA_free(rsa);
	return 0;
}

/*
 * Create Global context SSL and use it in every new session
 * # Load the trusted CAs
 * # Load the Private key & the certificate
 * # Set the Context options & Verify options
 */
SSL_CTX *init_tls_ctx(EAP_TLS_CONF *conf)
{
	SSL_METHOD *meth;
	SSL_CTX *ctx;
	int verify_mode = 0;
	int ctx_options = 0;
	int type;

	/*
	 * Add all the default ciphers and message digests
	 * Create our context
	 */
	SSL_library_init();
	SSL_load_error_strings();

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

	/* Load the CAs we trust */
	if (!(SSL_CTX_load_verify_locations(ctx, conf->ca_file, conf->ca_path)) ||
			(!SSL_CTX_set_default_verify_paths(ctx))) {
		ERR_print_errors_fp(stderr);
		radlog(L_ERR, "rlm_eap_tls: Error reading Trusted root CA list");
		return NULL;
	}
	SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(conf->ca_file));

	/* 
	 * Set the password to load private key
	 */
	if (conf->private_key_password) {
		SSL_CTX_set_default_passwd_cb_userdata(ctx, conf->private_key_password);
		SSL_CTX_set_default_passwd_cb(ctx, cbtls_password);
	}

	/* Load our keys and certificates*/
	if (!(SSL_CTX_use_certificate_file(ctx, conf->certificate_file, type))) {
		ERR_print_errors_fp(stderr);
		radlog(L_ERR, "rlm_eap_tls: Error reading certificate file");
		return NULL;
	}

	if (!(SSL_CTX_use_PrivateKey_file(ctx, conf->private_key_file, type))) {
		ERR_print_errors_fp(stderr);
		radlog(L_ERR, "rlm_eap_tls: Error reading private key file");
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
	 * Set ctx_options
	 */
	ctx_options |= SSL_OP_NO_SSLv2;
   	ctx_options |= SSL_OP_NO_SSLv3;
	/* 
       SSL_OP_SINGLE_DH_USE must be used in order to prevent 
	   small subgroup attacks and forward secrecy. Always using
       SSL_OP_SINGLE_DH_USE has an impact on the computer time
       needed during negotiation, but it is not very large.
	 */
   	ctx_options |= SSL_OP_SINGLE_DH_USE;
	SSL_CTX_set_options(ctx, ctx_options);

	/*
	 * TODO: Set the RSA & DH
	SSL_CTX_set_tmp_rsa_callback(ctx, cbtls_rsa);
	SSL_CTX_set_tmp_dh_callback(ctx, cbtls_dh);
	 */

	/*
	 * set the message callback to identify the type of message.
	 * For every new session, there can be a different callback argument
	SSL_CTX_set_msg_callback(ctx, cbtls_msg);
	 */

	/* Set Info callback */
	SSL_CTX_set_info_callback(ctx, cbtls_info);

	/*
	 * Set verify modes
	 * Always verify the peer certificate
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
		ERR_print_errors_fp(stderr);
		radlog(L_ERR, "rlm_eap_tls: Error loading randomness");
		return NULL;
	}

	return ctx;
}

tls_session_t *new_tls_session(eap_tls_t *eaptls)
{
	tls_session_t *state = NULL;
	SSL *new_tls = NULL;
	int verify_mode = 0;

	if ((new_tls = SSL_new(eaptls->ctx)) == NULL) {
		radlog(L_ERR, "rlm_eap_tls: Error creating new SSL");
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	/* We use the SSL's "app_data" to indicate a call-back */
	SSL_set_app_data(new_tls, NULL);

	state = (tls_session_t *)malloc(sizeof(tls_session_t));
	session_init(state);
	state->ssl = new_tls;

	/*
	 * Create & hook the BIOs to handle the dirty side of the SSL
	 * This is *very important* as we want to handle the transmission part.
	 * Now the only IO interface that SSL is aware of, is our defined BIO buffers.
	 */
	state->into_ssl = BIO_new(BIO_s_mem());
	state->from_ssl = BIO_new(BIO_s_mem());
	SSL_set_bio(state->ssl, state->into_ssl, state->from_ssl);

	/*
	 * Add the message callback to identify
	 * what type of message/handshake is passed
	 */
	SSL_set_msg_callback(new_tls, cbtls_msg);
	SSL_set_msg_callback_arg(new_tls, state);
	SSL_set_info_callback(new_tls, cbtls_info);

	/* Always verify the peer certificate */
	verify_mode |= SSL_VERIFY_PEER;
	verify_mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
	verify_mode |= SSL_VERIFY_CLIENT_ONCE;
	SSL_set_verify(state->ssl, verify_mode, cbtls_verify);
	
	/* In Server mode we only accept.  */
	SSL_set_accept_state(state->ssl);

	return state;
}

static void int_ssl_check(SSL *s, int ret)
{
	int e;

	ERR_print_errors_fp(stderr);
	e = SSL_get_error(s, ret);

	radlog(L_ERR, " Error code is ..... %d\n", e);

	switch(e) {
		/* These seem to be harmless and already "dealt with" by our
		 * non-blocking environment. NB: "ZERO_RETURN" is the clean
		 * "error" indicating a successfully closed SSL tunnel. We let
		 * this happen because our IO loop should not appear to have
		 * broken on this condition - and outside the IO loop, the
		 * "shutdown" state is checked. */
	case SSL_ERROR_NONE:
	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
	case SSL_ERROR_WANT_X509_LOOKUP:
	case SSL_ERROR_ZERO_RETURN:
		radlog(L_ERR, " SSL Error ..... %d\n", e);
		return;
		/* These seem to be indications of a genuine error that should
		 * result in the SSL tunnel being regarded as "dead". */
	case SSL_ERROR_SYSCALL:
	case SSL_ERROR_SSL:
		radlog(L_ERR, " Error in SSL ..... %d\n", e);
		SSL_set_app_data(s, (char *)1);
		return;
	default:
		break;
	}
	radlog(L_ERR, "Unknown Error ..... %d\n", e);
	/* For any other errors that (a) exist, and (b) crop up - we need to
	 * interpret what to do with them - so "politely inform" the caller that
	 * the code needs updating here. */
	abort();
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
int tls_handshake_recv(tls_session_t *ssn)
{
	int err;

	BIO_write(ssn->into_ssl, ssn->dirty_in.data, ssn->dirty_in.used);
	err = SSL_read(ssn->ssl, ssn->clean_out.data, MAX_RECORD_SIZE);
	if (err > 0) {
		ssn->clean_out.used = err;
	} else {
		radlog(L_INFO, "rlm_eap_tls: SSL_read Error");
		int_ssl_check(ssn->ssl, err);
	}

	/* Some Extra STATE information for easy debugging */
	/*
	if (SSL_is_init_finished(ssn->ssl)) {
		printf("SSL Connection Established\n");
	}
   	if (SSL_in_init(ssn->ssl)) {
		printf("In SSL Handshake Phase\n");
	}
   	if (SSL_in_before(ssn->ssl)) {
		printf("Before SSL Handshake Phase\n");
	}
   	if (SSL_in_accept_init(ssn->ssl)) {
		printf("In SSL Accept mode \n");
	}
   	if (SSL_in_connect_init(ssn->ssl)) {
		printf("In SSL Connect mode \n");
	}
	*/

	if (ssn->info.content_type != application_data) {
		err = BIO_read(ssn->from_ssl, ssn->dirty_out.data, MAX_RECORD_SIZE);
		if (err > 0) {
			ssn->dirty_out.used = err;
		} else {
			radlog(L_ERR, "rlm_eap_tls: BIO_read Error");
			int_ssl_check(ssn->ssl, err);
			record_init(&ssn->dirty_in);
			return 0;
		}
	} else {
		radlog(L_INFO, "rlm_eap_tls: Application Data");
		/* Its clean application data, do whatever we want */
		record_init(&ssn->clean_out);
	}

	/* We are done with dirty_in, reinitialize it */
	record_init(&ssn->dirty_in);
	return 1;
}

/* We have clean data to send. so dirty it before sending. */
int tls_handshake_send(tls_session_t *ssn)
{
	int err;

	/*
	 * Fill the SSL with the clean data to dirt it
	 * Based on Server's logic this clean_in is expected to
	 * contain/filled with the data.
	 */
	if (ssn->clean_in.used > 0) {
		SSL_write(ssn->ssl, ssn->clean_in.data, ssn->clean_in.used);

		/* Get the dirty data from Bio to send it */
		err = BIO_read(ssn->from_ssl, ssn->dirty_out.data, MAX_RECORD_SIZE);
		if (err > 0) {
			ssn->dirty_out.used = err;
		} else {
			int_ssl_check(ssn->ssl, err);
		}
	}

	if (ssn->dirty_out.used > 0) {
		record_init(&ssn->dirty_out);
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
}

void session_close(tls_session_t *ssn)
{
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

void session_free(void **ssn)
{
	tls_session_t **sess = (tls_session_t **)ssn;
	if ((sess == NULL) || (*sess == NULL))
		return;

	session_close(*sess);
	free(*sess);
	*sess = NULL;
}

void record_init(record_t *rec)
{
	rec->used = 0;
}

void record_close(record_t *rec)
{
	rec->used = 0;
}

unsigned int record_plus(record_t *rec, const unsigned char *ptr,
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

unsigned int record_minus(record_t *rec, unsigned char *ptr,
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

	if(rec->used > 0)
		memmove(rec->data, rec->data + taken, rec->used);
	return taken;
}

void tls_session_information(tls_session_t *tls_session)
{
	const char *str_write_p, *str_version, *str_content_type = "", *str_details1 = "", *str_details2= "";
	
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
		str_version = "???";
	}

	if (tls_session->info.version == SSL3_VERSION ||
		tls_session->info.version == TLS1_VERSION)
	{
		switch (tls_session->info.content_type)
		{
		case 20:
			str_content_type = "ChangeCipherSpec";
			break;
		case 21:
			str_content_type = "Alert";
			break;
		case 22:
			str_content_type = "Handshake";
			break;
		}

		if (tls_session->info.content_type == 21) /* Alert */
		{
			str_details1 = ", ???";
			
			if (tls_session->info.record_len == 2) {

				switch (tls_session->info.alert_level)
				{
				case 1:
					str_details1 = ", warning";
					break;
				case 2:
					str_details1 = ", fatal";
					break;
				}

				str_details2 = " ???";
				switch (tls_session->info.alert_description)
				{
				case 0:
					str_details2 = " close_notify";
					break;
				case 10:
					str_details2 = " unexpected_message";
					break;
				case 20:
					str_details2 = " bad_record_mac";
					break;
				case 21:
					str_details2 = " decryption_failed";
					break;
				case 22:
					str_details2 = " record_overflow";
					break;
				case 30:
					str_details2 = " decompression_failure";
					break;
				case 40:
					str_details2 = " handshake_failure";
					break;
				case 42:
					str_details2 = " bad_certificate";
					break;
				case 43:
					str_details2 = " unsupported_certificate";
					break;
				case 44:
					str_details2 = " certificate_revoked";
					break;
				case 45:
					str_details2 = " certificate_expired";
					break;
				case 46:
					str_details2 = " certificate_unknown";
					break;
				case 47:
					str_details2 = " illegal_parameter";
					break;
				case 48:
					str_details2 = " unknown_ca";
					break;
				case 49:
					str_details2 = " access_denied";
					break;
				case 50:
					str_details2 = " decode_error";
					break;
				case 51:
					str_details2 = " decrypt_error";
					break;
				case 60:
					str_details2 = " export_restriction";
					break;
				case 70:
					str_details2 = " protocol_version";
					break;
				case 71:
					str_details2 = " insufficient_security";
					break;
				case 80:
					str_details2 = " internal_error";
					break;
				case 90:
					str_details2 = " user_canceled";
					break;
				case 100:
					str_details2 = " no_renegotiation";
					break;
				}
			}
		}
		
		if (tls_session->info.content_type == 22) /* Handshake */
		{
			str_details1 = "???";

			if (tls_session->info.record_len > 0)
			switch (tls_session->info.handshake_type)
			{
			case 0:
				str_details1 = ", HelloRequest";
				break;
			case 1:
				str_details1 = ", ClientHello";
				break;
			case 2:
				str_details1 = ", ServerHello";
				break;
			case 11:
				str_details1 = ", Certificate";
				break;
			case 12:
				str_details1 = ", ServerKeyExchange";
				break;
			case 13:
				str_details1 = ", CertificateRequest";
				break;
			case 14:
				str_details1 = ", ServerHelloDone";
				break;
			case 15:
				str_details1 = ", CertificateVerify";
				break;
			case 16:
				str_details1 = ", ClientKeyExchange";
				break;
			case 20:
				str_details1 = ", Finished";
				break;
			}
		}
	}

	sprintf(tls_session->info.info_description, "%s %s%s [length %04lx]%s%s\n", 
		str_write_p, str_version, str_content_type, 
		(unsigned long)tls_session->info.record_len, str_details1, str_details2);
	printf("%s\n", tls_session->info.info_description);
}
