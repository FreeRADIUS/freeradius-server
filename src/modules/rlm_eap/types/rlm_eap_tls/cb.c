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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2001  hereUare Communications, Inc. <raghud@hereuare.com>
 */
#include "eap_tls.h"

#ifndef NO_OPENSSL

void cbtls_info(const SSL *s, int where, int ret)
{
	char *str, *state;
	int w;

	w = where & ~SSL_ST_MASK;
	if (w & SSL_ST_CONNECT) str="TLS_connect";
	else if (w & SSL_ST_ACCEPT) str="TLS_accept";
	else str="undefined";

	state = (char *)SSL_state_string_long(s);
	state = state ? state : "NULL";

	if (where & SSL_CB_LOOP) {
		radlog(L_INFO, "%s: %s\n", str, state);
	} else if (where & SSL_CB_HANDSHAKE_START) {
		radlog(L_INFO, "%s: %s\n", str, state);
	} else if (where & SSL_CB_HANDSHAKE_DONE) {
		radlog(L_INFO, "%s: %s\n", str, state);
	} else if (where & SSL_CB_ALERT) {
		str=(where & SSL_CB_READ)?"read":"write";
		radlog(L_ERR,"TLS Alert %s:%s:%s\n", str,
			SSL_alert_type_string_long(ret),
			SSL_alert_desc_string_long(ret));
	} else if (where & SSL_CB_EXIT) {
		if (ret == 0)
			radlog(L_ERR, "%s:failed in %s\n", str, state);
		else if (ret < 0)
			radlog(L_ERR, "%s:error in %s\n", str, state);
	}
}

/*
 * Before trusting a certificate, you must make sure that the certificate is
   'valid'. There are several steps that your application can take in 
   determining if a certificate is valid. Commonly used steps are: 

  1.Verifying the certificate's signature, and verifying that the certificate
    has been issued by a trusted Certificate Authority. 

  2.Verifying that the certificate is valid for the present date (i.e. it is
    being presented within its validity dates). 

  3.Verifying that the certificate has not been revoked by its issuing
    Certificate Authority, by checking with respect to a Certificate
    Revocation List (CRL). 

  4.Verifying that the credentials presented by the certificate fulfill
    additional requirements specific to the application, such as with respect
    to access control lists or with respect to OCSP (Online Certificate Status
    Processing). 
 */
/*
 * NOTE: This callback will be called multiple times based on the 
 * depth of the root certificate chain
 */
int cbtls_verify(int ok, X509_STORE_CTX *ctx)
{
	char subject[256]; /* Used for the subject name */
	char issuer[256]; /* Used for the issuer name */
	char buf[256]; 
	char *user_name = NULL; /* User-Name */
	X509 *client_cert;
	SSL *ssl;
	int err, depth;
	int index = 0;

	client_cert = X509_STORE_CTX_get_current_cert(ctx);
	err = X509_STORE_CTX_get_error(ctx);
	depth = X509_STORE_CTX_get_error_depth(ctx);

	if(!ok)
		radlog(L_ERR,"--> verify error:num=%d:%s\n",err,
			X509_verify_cert_error_string(err));
	/*
	Catch too long Certificate chains
	*/

	/*
	 * Retrieve the pointer to the SSL of the connection currently treated
	 * and the application specific data stored into the SSL object.
	 */
	ssl = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
	user_name = (char *)SSL_get_ex_data(ssl, index);

	/*
	 * Get the Subject & Issuer
	 */
	subject[0] = issuer[0] = '\0';
	X509_NAME_oneline(X509_get_subject_name(client_cert), subject, 256);
	X509_NAME_oneline(X509_get_issuer_name(ctx->current_cert), issuer, 256);

	/* Get the Common Name */
	X509_NAME_get_text_by_NID(X509_get_subject_name(client_cert),
             NID_commonName, buf, 256);

	switch (ctx->error) {

	case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
		radlog(L_ERR, "issuer= %s\n", issuer);
		break;
	case X509_V_ERR_CERT_NOT_YET_VALID:
	case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
		radlog(L_ERR, "notBefore=");
		//ASN1_TIME_print(bio_err, X509_get_notBefore(ctx->current_cert));
		break;
	case X509_V_ERR_CERT_HAS_EXPIRED:
	case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
		radlog(L_ERR, "notAfter=");
		//ASN1_TIME_print(bio_err, X509_get_notAfter(ctx->current_cert));
		break;
	}

	radlog(L_INFO, "chain-depth=%d, ", depth);
	/*
	if (depth > 0) {
		return ok;
	}
	*/
	radlog(L_INFO, "error=%d", err);

	radlog(L_INFO, "--> User-Name = %s", user_name);
	radlog(L_INFO, "--> BUF-Name = %s", buf);
	radlog(L_INFO, "--> subject = %s", subject);
	radlog(L_INFO, "--> issuer  = %s", issuer);
	radlog(L_INFO, "--> verify return:%d", ok);
	return ok;
}

void cbtls_msg(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg)
{
	tls_session_t *state = (tls_session_t *)arg;

	state->info.origin = (unsigned char)write_p;
	state->info.content_type = (unsigned char)content_type;
	state->info.record_len = len;
	state->info.version = version;

	if (content_type == 21) {
		state->info.alert_level = ((unsigned char*)buf)[0];
		state->info.alert_description = ((unsigned char*)buf)[1];
		state->info.handshake_type = 0x00;
	
	} else if (content_type == 22) {
		state->info.handshake_type = ((unsigned char*)buf)[0];
		state->info.alert_level = 0x00;
		state->info.alert_description = 0x00;
	}
	tls_session_information(state);
}

int cbtls_password(char *buf, int num, int rwflag, void *userdata)
{
	strcpy(buf, (char *)userdata);
	return(strlen((char *)userdata));
}

RSA *cbtls_rsa(SSL *s, int is_export, int keylength)
{
	static RSA *rsa_tmp=NULL;

	if (rsa_tmp == NULL)
	{
		radlog(L_INFO, "Generating temp (%d bit) RSA key...", keylength);
		rsa_tmp=RSA_generate_key(keylength, RSA_F4, NULL, NULL);
	}
	return(rsa_tmp);
}

#endif /* !defined(NO_OPENSSL) */

