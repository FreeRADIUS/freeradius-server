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

/* Output level:
 *     0 = nothing,
 *     1 = minimal, just errors,
 *     2 = minimal, all steps,
 *     3 = detail, all steps */
static unsigned int cb_ssl_verify_level = 3;
/*
static int int_verify_depth = 10;
*/

void cbtls_info(const SSL *s, int where, int ret)
{
	char *str1, *str2;
	int w;

	if (where & SSL_CB_HANDSHAKE_START)
		fprintf(stdout, "Callback has been called because a new handshake is started.\n");
	if (where & SSL_CB_HANDSHAKE_DONE)
		fprintf(stdout, "Callback has been called because handshake is finished.\n");

	w = where & ~SSL_ST_MASK;
	str1 = (w & SSL_ST_CONNECT ? "SSL_connect" : (w & SSL_ST_ACCEPT ?
				"SSL_accept" : "undefined")),
	str2 = SSL_state_string_long(s);
	str2 = str2 ? str2 : "NULL";

	if (where & SSL_CB_LOOP)
		fprintf(stdout, "(%s) %s\n", str1, str2);
	else if (where & SSL_CB_EXIT) {
		if (ret == 0)
			fprintf(stdout, "(%s) failed in %s\n", str1, str2);
		else if (ret < 0)
			fprintf(stdout, "%s:error in %s\n", str1, str2);
	}
}

static const char *int_reason_no_issuer = "X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT";
static const char *int_reason_not_yet = "X509_V_ERR_CERT_NOT_YET_VALID";
static const char *int_reason_before = "X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD";
static const char *int_reason_expired = "X509_V_ERR_CERT_HAS_EXPIRED";
static const char *int_reason_after = "X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD";
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
int cbtls_verify(int ok, X509_STORE_CTX *ctx)
{
	char buf1[256]; /* Used for the subject name */
	char buf2[256]; /* Used for the issuer name */
	const char *reason = NULL; /* Error reason (if any) */
	X509 *err_cert;
	int err, depth;

	if(cb_ssl_verify_level == 0)
		return ok;
	err_cert = X509_STORE_CTX_get_current_cert(ctx);
	err = X509_STORE_CTX_get_error(ctx);
	depth = X509_STORE_CTX_get_error_depth(ctx);

	buf1[0] = buf2[0] = '\0';
	/* Fill buf1 */
	X509_NAME_oneline(X509_get_subject_name(err_cert), buf1, 256);
	/* Fill buf2 */
	X509_NAME_oneline(X509_get_issuer_name(ctx->current_cert), buf2, 256);
	switch (ctx->error) {
	case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
		reason = int_reason_no_issuer;
		break;
	case X509_V_ERR_CERT_NOT_YET_VALID:
		reason = int_reason_not_yet;
		break;
	case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
		reason = int_reason_before;
		break;
	case X509_V_ERR_CERT_HAS_EXPIRED:
		reason = int_reason_expired;
		break;
	case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
		reason = int_reason_after;
		break;
	}

	if((cb_ssl_verify_level == 1) && ok)
		return ok;
	fprintf(stdout, "chain-depth=%d, ", depth);
	if(reason)
		fprintf(stdout, "error=%s\n", reason);
	else
		fprintf(stdout, "error=%d\n", err);
	if(cb_ssl_verify_level < 3)
		return ok;
	fprintf(stdout, "--> subject = %s\n", buf1);
	fprintf(stdout, "--> issuer  = %s\n", buf2);
	if(!ok)
		fprintf(stdout,"--> verify error:num=%d:%s\n",err,
			X509_verify_cert_error_string(err));
	fprintf(stdout, "--> verify return:%d\n",ok);
	return ok;
}

void cbtls_msg(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg)
{
	tls_session_t *state = arg;

	state->info.origin = (unsigned char)write_p;
	state->info.content_type = (unsigned char)content_type;
	state->info.record_len = len;
	state->info.version = version;

	printf("content_type = %d\n", content_type);
	printf("record_len = %d\n", len);
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

/*
 * Got to figure out how to register & call this callback 
 */
long cb_bio_dump(BIO *bio, int cmd, const char *argp, int argi,
	     long argl, long ret)
{
	BIO *out;

	out=(BIO *)BIO_get_callback_arg(bio);
	if (out == NULL) return(ret);

	if (cmd == (BIO_CB_READ|BIO_CB_RETURN))
	{
		BIO_printf(out,"read from %08X [%08lX] (%d bytes => %ld (0x%X))\n",
			bio,argp,argi,ret,ret);
		BIO_dump(out,argp,(int)ret);
		return(ret);
	}
	else if (cmd == (BIO_CB_WRITE|BIO_CB_RETURN))
	{
		BIO_printf(out,"write to %08X [%08lX] (%d bytes => %ld (0x%X))\n",
			bio,argp,argi,ret,ret);
		BIO_dump(out,argp,(int)ret);
	}
	return(ret);
}

#endif /* !defined(NO_OPENSSL) */

