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
#include "eap_tls.h"

#ifdef HAVE_OPENSSL_RAND_H
#include <openssl/rand.h>
#endif

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
	int verify_mode = 0;
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
	    ERR_print_errors_fp(stderr);
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
		ERR_print_errors_fp(stderr);
		radlog(L_ERR, "rlm_eap_tls: Error loading randomness");
		return NULL;
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
		if (conf->dh_file) free(conf->dh_file);
		conf->dh_file = NULL;
		if (conf->certificate_file) free(conf->certificate_file);
		conf->certificate_file = NULL;
		if (conf->private_key_file) free(conf->private_key_file);
		conf->private_key_file = NULL;
		if (conf->private_key_password) free(conf->private_key_password);
		conf->private_key_password = NULL;
		if (conf->random_file) free(conf->random_file);
		conf->random_file = NULL;

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
	 *	Create a structure for all the items required to be
	 *	verified for each client and set that as opaque data
	 *	structure.
	 *
	 *	NOTE: If we want to set each item sepearately then
	 *	this index should be global.
	 */
	SSL_set_ex_data(ssn->ssl, 0, (void *)handler->identity);

	ssn->length_flag = inst->conf->include_length;

	/*
	 *	We set a default fragment size, unless the Framed-MTU
	 *	tells us it's too big.
	 */
	ssn->offset = inst->conf->fragment_size;
	vp = pairfind(handler->request->packet->vps, PW_FRAMED_MTU);
	if (vp && ((vp->lvalue - 4) < ssn->offset)) {
		ssn->offset = vp->lvalue - 4;
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

			data_len = record_minus(&tls_session->dirty_in,
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
