/*
 * rlm_eap_tls.c  contains the interfaces that are called from eap
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
 * Copyright 2003  Alan DeKok <aland@freeradius.org>
 */

#include "autoconf.h"

#ifdef HAVE_OPENSSL_RAND_H
#include <openssl/rand.h>
#endif

#include "rlm_eap_tls.h"

static CONF_PARSER module_config[] = {
	{ "rsa_key_exchange", PW_TYPE_BOOLEAN,
	  offsetof(EAP_TLS_CONF, rsa_key), NULL, "no" },
	{ "dh_key_exchange", PW_TYPE_BOOLEAN,
	  offsetof(EAP_TLS_CONF, dh_key), NULL, "yes" },
	{ "rsa_key_length", PW_TYPE_INTEGER,
	  offsetof(EAP_TLS_CONF, rsa_key_length), NULL, "512" },
	{ "dh_key_length", PW_TYPE_INTEGER,
	  offsetof(EAP_TLS_CONF, dh_key_length), NULL, "512" },
	{ "verify_depth", PW_TYPE_INTEGER,
	  offsetof(EAP_TLS_CONF, verify_depth), NULL, "0" },
	{ "CA_path", PW_TYPE_STRING_PTR,
	  offsetof(EAP_TLS_CONF, ca_path), NULL, NULL },
	{ "pem_file_type", PW_TYPE_BOOLEAN,
	  offsetof(EAP_TLS_CONF, file_type), NULL, "yes" },
	{ "private_key_file", PW_TYPE_STRING_PTR,
	  offsetof(EAP_TLS_CONF, private_key_file), NULL, NULL },
	{ "certificate_file", PW_TYPE_STRING_PTR,
	  offsetof(EAP_TLS_CONF, certificate_file), NULL, NULL },
	{ "CA_file", PW_TYPE_STRING_PTR,
	  offsetof(EAP_TLS_CONF, ca_file), NULL, NULL },
	{ "private_key_password", PW_TYPE_STRING_PTR,
	  offsetof(EAP_TLS_CONF, private_key_password), NULL, NULL },
	{ "dh_file", PW_TYPE_STRING_PTR,
	  offsetof(EAP_TLS_CONF, dh_file), NULL, NULL },
	{ "random_file", PW_TYPE_STRING_PTR,
	  offsetof(EAP_TLS_CONF, random_file), NULL, NULL },
	{ "fragment_size", PW_TYPE_INTEGER,
	  offsetof(EAP_TLS_CONF, fragment_size), NULL, "1024" },
	{ "include_length", PW_TYPE_BOOLEAN,
	  offsetof(EAP_TLS_CONF, include_length), NULL, "yes" },
	{ "check_crl", PW_TYPE_BOOLEAN,
	  offsetof(EAP_TLS_CONF, check_crl), NULL, "no"},
	{ "check_cert_cn", PW_TYPE_STRING_PTR,
	  offsetof(EAP_TLS_CONF, check_cert_cn), NULL, NULL},
	{ "cipher_list", PW_TYPE_STRING_PTR,
	  offsetof(EAP_TLS_CONF, cipher_list), NULL, NULL},
	{ "check_cert_issuer", PW_TYPE_STRING_PTR,
	  offsetof(EAP_TLS_CONF, check_cert_issuer), NULL, NULL},

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
	if (SSL_CTX_set_tmp_dh(ctx, dh) < 0) {
		radlog(L_ERR, "rlm_eap_tls: Unable to set DH parameters");
		DH_free(dh);
		return -1;
	}

	DH_free(dh);
	return 0;
}

/*
 *	Generte ephemeral RSA keys.
 */
static int generate_eph_rsa_key(SSL_CTX *ctx)
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
static int cbtls_verify(int ok, X509_STORE_CTX *ctx)
{
	char subject[1024]; /* Used for the subject name */
	char issuer[1024]; /* Used for the issuer name */
	char common_name[1024];
	char cn_str[1024];
	EAP_HANDLER *handler = NULL;
	X509 *client_cert;
	SSL *ssl;
	int err, depth;
	EAP_TLS_CONF *conf;
	int my_ok = ok;

	client_cert = X509_STORE_CTX_get_current_cert(ctx);
	err = X509_STORE_CTX_get_error(ctx);
	depth = X509_STORE_CTX_get_error_depth(ctx);

	if (!my_ok) {
		radlog(L_ERR,"--> verify error:num=%d:%s\n",err,
			X509_verify_cert_error_string(err));
		return my_ok;
	}

	/*
	 * Retrieve the pointer to the SSL of the connection currently treated
	 * and the application specific data stored into the SSL object.
	 */
	ssl = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
	handler = (EAP_HANDLER *)SSL_get_ex_data(ssl, 0);
	conf = (EAP_TLS_CONF *)SSL_get_ex_data(ssl, 1);

	/*
	 *	Get the Subject & Issuer
	 */
	subject[0] = issuer[0] = '\0';
	X509_NAME_oneline(X509_get_subject_name(client_cert), subject,
			  sizeof(subject));
	X509_NAME_oneline(X509_get_issuer_name(ctx->current_cert), issuer,
			  sizeof(issuer));

	subject[sizeof(subject) - 1] = '\0';
	issuer[sizeof(issuer) - 1] = '\0';

	/*
	 *	Get the Common Name
	 */
	X509_NAME_get_text_by_NID(X509_get_subject_name(client_cert),
				  NID_commonName, common_name, sizeof(common_name));
	common_name[sizeof(common_name) - 1] = '\0';

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
			if (!radius_xlat(cn_str, sizeof(cn_str), conf->check_cert_cn, handler->request, NULL)) {
				radlog(L_ERR, "rlm_eap_tls (%s): xlat failed.",
				       conf->check_cert_cn);
				/* if this fails, fail the verification */
				my_ok = 0;
			} else {
				DEBUG2("    rlm_eap_tls: checking certificate CN (%s) with xlat'ed value (%s)", common_name, cn_str);
				if (strcmp(cn_str, common_name) != 0) {
					radlog(L_AUTH, "rlm_eap_tls: Certificate CN (%s) does not match specified value (%s)!", common_name, cn_str);
					my_ok = 0;
				}
			}
		} /* check_cert_cn */
	} /* depth == 0 */

	if (debug_flag > 0) {
		radlog(L_INFO, "chain-depth=%d, ", depth);
		radlog(L_INFO, "error=%d", err);

		radlog(L_INFO, "--> User-Name = %s", handler->identity);
		radlog(L_INFO, "--> BUF-Name = %s", common_name);
		radlog(L_INFO, "--> subject = %s", subject);
		radlog(L_INFO, "--> issuer  = %s", issuer);
		radlog(L_INFO, "--> verify return:%d", my_ok);
	}
	return my_ok;
}


/*
 *	Create Global context SSL and use it in every new session
 *
 *	- Load the trusted CAs
 *	- Load the Private key & the certificate
 *	- Set the Context options & Verify options
 */
static SSL_CTX *init_tls_ctx(EAP_TLS_CONF *conf)
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
		radlog(L_INFO, "rlm_eap_tls: Loading the certificate file as a chain");
		if (!(SSL_CTX_use_certificate_chain_file(ctx, conf->certificate_file))) {
			radlog(L_ERR, "rlm_eap: SSL error %s", ERR_error_string(ERR_get_error(), NULL));
			radlog(L_ERR, "rlm_eap_tls: Error reading certificate file");
			return NULL;
		}

	} else if (!(SSL_CTX_use_certificate_file(ctx, conf->certificate_file, type))) {
		radlog(L_ERR, "rlm_eap: SSL error %s", ERR_error_string(ERR_get_error(), NULL));
		radlog(L_ERR, "rlm_eap_tls: Error reading certificate file");
		return NULL;
	}


	/* Load the CAs we trust */
	if (!SSL_CTX_load_verify_locations(ctx, conf->ca_file, conf->ca_path)) {
		radlog(L_ERR, "rlm_eap: SSL error %s", ERR_error_string(ERR_get_error(), NULL));
		radlog(L_ERR, "rlm_eap_tls: Error reading Trusted root CA list");
		return NULL;
	}
	SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(conf->ca_file));

	if (!(SSL_CTX_use_PrivateKey_file(ctx, conf->private_key_file, type))) {
		radlog(L_ERR, "rlm_eap: SSL error %s", ERR_error_string(ERR_get_error(), NULL));
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
	 *	Set ctx_options
	 */
	ctx_options |= SSL_OP_NO_SSLv2;
   	ctx_options |= SSL_OP_NO_SSLv3;

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

	return ctx;
}


/*
 *	Detach the EAP-TLS module.
 */
static int eaptls_detach(void *arg)
{
	EAP_TLS_CONF	 *conf;
	eap_tls_t 	 *inst;

	inst = (eap_tls_t *) arg;
	conf = inst->conf;

	if (conf) {
		free(conf->dh_file);
		free(conf->ca_path);
		free(conf->certificate_file);
		free(conf->private_key_file);
		free(conf->private_key_password);
		free(conf->ca_file);
		free(conf->random_file);

		free(conf->check_cert_cn);
		free(conf->check_cert_cn);
		free(conf->cipher_list);
		free(conf->check_cert_issuer);

		memset(conf, 0, sizeof(*conf));
		free(inst->conf);
		inst->conf = NULL;
	}

	if (inst->ctx) SSL_CTX_free(inst->ctx);
	inst->ctx = NULL;

	free(inst);

	return 0;
}


/*
 *	Attach the EAP-TLS module.
 */
static int eaptls_attach(CONF_SECTION *cs, void **instance)
{
	EAP_TLS_CONF	 *conf;
	eap_tls_t 	 *inst;

	/* Store all these values in the data structure for later references */
	inst = (eap_tls_t *)malloc(sizeof(*inst));
	if (!inst) {
		radlog(L_ERR, "rlm_eap_tls: out of memory");
		return -1;
	}
	memset(inst, 0, sizeof(*inst));

	/*
	 *	Parse the config file & get all the configured values
	 */
	conf = (EAP_TLS_CONF *)malloc(sizeof(*conf));
	if (conf == NULL) {
		radlog(L_ERR, "rlm_eap_tls: out of memory");
		return -1;
	}
	memset(conf, 0, sizeof(*conf));

	inst->conf = conf;
	if (cf_section_parse(cs, conf, module_config) < 0) {
		eaptls_detach(inst);
		return -1;
	}


	/*
	 *	Initialize TLS
	 */
	inst->ctx = init_tls_ctx(conf);
	if (inst->ctx == NULL) {
		eaptls_detach(inst);
		return -1;
	}

	if (load_dh_params(inst->ctx, conf->dh_file) < 0) {
		eaptls_detach(inst);
		return -1;
	}
	if (generate_eph_rsa_key(inst->ctx) < 0) {
		eaptls_detach(inst);
		return -1;
	}

	*instance = inst;

	return 0;
}


/*
 *	Send an initial eap-tls request to the peer.
 *
 *	Frame eap reply packet.
 *	len = header + type + tls_typedata
 *	tls_typedata = flags(Start (S) bit set, and no data)
 *
 *	Once having received the peer's Identity, the EAP server MUST
 *	respond with an EAP-TLS/Start packet, which is an
 *	EAP-Request packet with EAP-Type=EAP-TLS, the Start (S) bit
 *	set, and no data.  The EAP-TLS conversation will then begin,
 *	with the peer sending an EAP-Response packet with
 *	EAP-Type = EAP-TLS.  The data field of that packet will
 *	be the TLS data.
 *
 *	Fragment length is Framed-MTU - 4.
 *
 *	http://mail.frascone.com/pipermail/public/eap/2003-July/001426.html
 */
static int eaptls_initiate(void *type_arg, EAP_HANDLER *handler)
{
	int		status;
	tls_session_t	*ssn;
	eap_tls_t	*inst;
	VALUE_PAIR	*vp;
	int		client_cert = TRUE;
	int		verify_mode = SSL_VERIFY_NONE;

	inst = (eap_tls_t *)type_arg;

	/*
	 *	If we're TTLS or PEAP, then do NOT require a client
	 *	certificate.
	 *
	 *	FIXME: This should be more configurable.
	 */
	if (handler->eap_type != PW_EAP_TLS) {
		vp = pairfind(handler->request->config_items,
			      PW_EAP_TLS_REQUIRE_CLIENT_CERT);
		if (!vp) {
			client_cert = FALSE;
		} else {
			client_cert = vp->lvalue;
		}
	}

	/*
	 *	Every new session is started only from EAP-TLS-START.
	 *	Before Sending EAP-TLS-START, open a new SSL session.
	 *	Create all the required data structures & store them
	 *	in Opaque.  So that we can use these data structures
	 *	when we get the response
	 */
	ssn = eaptls_new_session(inst->ctx, client_cert);
	if (!ssn) {
		return 0;
	}

	/*
	 *	Verify the peer certificate, if asked.
	 */
	if (client_cert) {
		DEBUG2(" rlm_eap_tls: Requiring client certificate");
		verify_mode = SSL_VERIFY_PEER;
		verify_mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
		verify_mode |= SSL_VERIFY_CLIENT_ONCE;
	}
	SSL_set_verify(ssn->ssl, verify_mode, cbtls_verify);

	/*
	 *	Create a structure for all the items required to be
	 *	verified for each client and set that as opaque data
	 *	structure.
	 *
	 *	NOTE: If we want to set each item sepearately then
	 *	this index should be global.
	 */
	SSL_set_ex_data(ssn->ssl, 0, (void *)handler);
	SSL_set_ex_data(ssn->ssl, 1, (void *)inst->conf);

	ssn->length_flag = inst->conf->include_length;

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
	ssn->offset = inst->conf->fragment_size;
	vp = pairfind(handler->request->packet->vps, PW_FRAMED_MTU);
	if (vp && ((vp->lvalue - 14) < ssn->offset)) {
		/*
		 *	Discount the Framed-MTU by:
		 *	 4 : EAPOL header
		 *	 4 : EAP header (code + id + length)
		 *	 1 : EAP type == EAP-TLS
		 *	 1 : EAP-TLS Flags
		 *	 4 : EAP-TLS Message length
		 *	    (even if conf->include_length == 0,
		 *	     just to be lazy).
		 *	---
		 *	14
		 */
		ssn->offset = vp->lvalue - 14;
	}

	handler->opaque = ((void *)ssn);
	handler->free_opaque = session_free;

	DEBUG2("  rlm_eap_tls: Initiate");

	/*
	 *	PEAP-specific breakage.
	 */
	if (handler->eap_type == PW_EAP_PEAP) {
		/*
		 *	As it is a poorly designed protocol, PEAP uses
		 *	bits in the TLS header to indicate PEAP
		 *	version numbers.  For now, we only support
		 *	PEAP version 0, so it doesn't matter too much.
		 *	However, if we support later versions of PEAP,
		 *	we will need this flag to indicate which
		 *	version we're currently dealing with.
		 */
		ssn->peap_flag = 0x00;

		/*
		 *	PEAP version 0 requires 'include_length = no',
		 *	so rather than hoping the user figures it out,
		 *	we force it here.
		 */
		ssn->length_flag = 0;
	}

	/*
	 *	TLS session initialization is over.  Now handle TLS
	 *	related handshaking or application data.
	 */
	status = eaptls_start(handler->eap_ds, ssn->peap_flag);
	DEBUG2("  rlm_eap_tls: Start returned %d", status);
	if (status == 0)
		return 0;

	/*
	 *	The next stage to process the packet.
	 */
	handler->stage = AUTHENTICATE;

	return 1;
}

/*
 *	Do authentication, by letting EAP-TLS do most of the work.
 */
static int eaptls_authenticate(void *arg UNUSED, EAP_HANDLER *handler)
{
	eaptls_status_t	status;
	tls_session_t *tls_session = (tls_session_t *) handler->opaque;

	DEBUG2("  rlm_eap_tls: Authenticate");

	status = eaptls_process(handler);
	DEBUG2("  eaptls_process returned %d\n", status);
	switch (status) {
		/*
		 *	EAP-TLS handshake was successful, return an
		 *	EAP-TLS-Success packet here.
		 */
	case EAPTLS_SUCCESS:
		break;

		/*
		 *	The TLS code is still working on the TLS
		 *	exchange, and it's a valid TLS request.
		 *	do nothing.
		 */
	case EAPTLS_HANDLED:
		return 1;

		/*
		 *	Handshake is done, proceed with decoding tunneled
		 *	data.
		 */
	case EAPTLS_OK:
		DEBUG2("  rlm_eap_tls: Received unexpected tunneled data after successful handshake.");
#ifndef NDEBUG
		if (debug_flag > 2) {
			unsigned int i;
			unsigned int data_len;
			unsigned char buffer[1024];

			data_len = (tls_session->record_minus)(&tls_session->dirty_in,
						buffer, sizeof(buffer));
			log_debug("  Tunneled data (%u bytes)\n", data_len);
			for (i = 0; i < data_len; i++) {
				if ((i & 0x0f) == 0x00) printf("  %x: ", i);
				if ((i & 0x0f) == 0x0f) printf("\n");

				printf("%02x ", buffer[i]);
			}
			printf("\n");
		}
#endif

		eaptls_fail(handler->eap_ds, 0);
		return 0;
		break;

		/*
		 *	Anything else: fail.
		 */
	default:
		return 0;
	}

	/*
	 *	Success: Return MPPE keys.
	 */
	eaptls_success(handler->eap_ds, 0);
	eaptls_gen_mppe_keys(&handler->request->reply->vps,
			     tls_session->ssl,
			     "client EAP encryption");
	return 1;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
EAP_TYPE rlm_eap_tls = {
	"eap_tls",
	eaptls_attach,			/* attach */
	eaptls_initiate,		/* Start the initial request */
	NULL,				/* authorization */
	eaptls_authenticate,		/* authentication */
	eaptls_detach			/* detach */
};
