/*
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
 */

/**
 * $Id$
 *
 * @file tls/ctx.c
 * @brief Initialise and configure SSL_CTX structures.
 *
 * @copyright 2001 hereUare Communications, Inc. (raghud@hereuare.com)
 * @copyright 2003 Alan DeKok (aland@freeradius.org)
 * @copyright 2006-2016 The FreeRADIUS server project
 */
RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#ifdef WITH_TLS
#define LOG_PREFIX "tls - "

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/hex.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/syserror.h>

#include <openssl/rand.h>
#include <openssl/dh.h>

#include "base.h"
#include "missing.h"

#ifndef OPENSSL_NO_ECDH
static int ctx_ecdh_curve_set(SSL_CTX *ctx, char const *ecdh_curve, bool disable_single_dh_use)
{
	int      nid;
	EC_KEY  *ecdh;

	if (!ecdh_curve || !*ecdh_curve) return 0;

	nid = OBJ_sn2nid(ecdh_curve);
	if (!nid) {
		ERROR("Unknown ecdh_curve \"%s\"", ecdh_curve);
		return -1;
	}

	ecdh = EC_KEY_new_by_curve_name(nid);
	if (!ecdh) {
		ERROR("Unable to create new curve \"%s\"", ecdh_curve);
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

/*
 *	TODO: Check for the type of key exchange * like conf->dh_key
 */
static int ctx_dh_params_load(SSL_CTX *ctx, char *file)
{
	DH *dh = NULL;
	BIO *bio;

	if (!file) return 0;

	if ((bio = BIO_new_file(file, "r")) == NULL) {
		ERROR("Unable to open DH file - %s", file);
		return -1;
	}

	dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
	BIO_free(bio);
	if (!dh) {
		WARN("Unable to set DH parameters.  DH cipher suites may not work!");
		WARN("Fix this by generating the DH parameter file");
		return 0;
	}

	if (SSL_CTX_set_tmp_dh(ctx, dh) < 0) {
		ERROR("Unable to set DH parameters");
		DH_free(dh);
		return -1;
	}

	DH_free(dh);
	return 0;
}

static int tls_ctx_load_cert_chain(SSL_CTX *ctx, fr_tls_chain_conf_t const *chain)
{
	char		*password;

	/*
	 *	Conf parser should ensure they're both populated
	 */
	fr_assert(chain->certificate_file && chain->private_key_file);

	/*
	 *	Set the password (this should have been retrieved earlier)
	 */
	memcpy(&password, &chain->password, sizeof(password));
	SSL_CTX_set_default_passwd_cb_userdata(ctx, password);

	/*
	 *	Always set the callback as it provides useful debug
	 *	output if the certificate isn't set.
	 */
	SSL_CTX_set_default_passwd_cb(ctx, fr_tls_session_password_cb);

	switch (chain->file_format) {
	case SSL_FILETYPE_PEM:
		if (!(SSL_CTX_use_certificate_chain_file(ctx, chain->certificate_file))) {
			fr_tls_log_error(NULL, "Failed reading certificate file \"%s\"",
				      chain->certificate_file);
			return -1;
		}
		break;

	case SSL_FILETYPE_ASN1:
		if (!(SSL_CTX_use_certificate_file(ctx, chain->certificate_file, chain->file_format))) {
			fr_tls_log_error(NULL, "Failed reading certificate file \"%s\"",
				      chain->certificate_file);
			return -1;
		}
		break;

	default:
		fr_assert(0);
		break;
	}

	if (!(SSL_CTX_use_PrivateKey_file(ctx, chain->private_key_file, chain->file_format))) {
		fr_tls_log_error(NULL, "Failed reading private key file \"%s\"",
			      chain->private_key_file);
		return -1;
	}

	{
		size_t		extra_cnt, i;
		/*
		 *	Load additional chain certificates from other files
		 *	This allows us to specify chains in DER format as
		 *	well as PEM, and means we can keep the intermediaries
		 *	CAs and client/server certs in separate files.
		 */
		extra_cnt = talloc_array_length(chain->ca_files);
		for (i = 0; i < extra_cnt; i++) {
			FILE		*fp;
			X509		*cert;
			char const	*filename = chain->ca_files[i];

			fp = fopen(filename, "r");
			if (!fp) {
				ERROR("Failed opening ca_file \"%s\": %s", filename, fr_syserror(errno));
				return -1;
			}

			/*
			 *	Load the PEM encoded X509 certificate
			 */
			switch (chain->file_format) {
			case SSL_FILETYPE_PEM:
				cert = PEM_read_X509(fp, NULL, NULL, NULL);
				break;

			case SSL_FILETYPE_ASN1:
				cert = d2i_X509_fp(fp, NULL);
				break;

			default:
				fr_assert(0);
				fclose(fp);
				return -1;
			}
			fclose(fp);

			if (!cert) {
				fr_tls_log_error(NULL, "Failed reading certificate file \"%s\"", filename);
				return -1;
			}
			SSL_CTX_add0_chain_cert(ctx, cert);
		}
	}

	/*
	 *	Check if the last loaded private key matches the last
	 *	loaded certificate.
	 *
	 *	Note: The call to SSL_CTX_use_certificate_chain_file
	 *	can load in a private key too.
	 */
	if (!SSL_CTX_check_private_key(ctx)) {
		ERROR("Private key does not match the certificate public key");
		return -1;
	}

	{
		int mode = SSL_BUILD_CHAIN_FLAG_CHECK;

		if (!chain->include_root_ca) mode |= SSL_BUILD_CHAIN_FLAG_NO_ROOT;

		/*
		 *	Explicitly check that the certificate chain
		 *	we just loaded is sane.
		 *
		 *	This operates on the last loaded certificate.
		 */
		switch (chain->verify_mode) {
		case FR_TLS_CHAIN_VERIFY_NONE:
			mode |= SSL_BUILD_CHAIN_FLAG_CLEAR_ERROR | SSL_BUILD_CHAIN_FLAG_IGNORE_ERROR;
			(void)SSL_CTX_build_cert_chain(ctx, mode);
			break;

		/*
		 *	Seems to be a bug where
		 *	SSL_BUILD_CHAIN_FLAG_IGNORE_ERROR trashes the error,
		 *	so have the function fail as normal.
		 */
		case FR_TLS_CHAIN_VERIFY_SOFT:
			if (!SSL_CTX_build_cert_chain(ctx, mode)) {
				tls_strerror_printf(NULL);
				PWARN("Failed verifying chain");
			}
			break;

		case FR_TLS_CHAIN_VERIFY_HARD:
			if (!SSL_CTX_build_cert_chain(ctx, mode)) {
				tls_strerror_printf(NULL);
				PERROR("Failed verifying chain");
				return -1;
			}
			break;

		default:
			break;
		}
	}
	return 0;
}

/** Create SSL context
 *
 * - Load the trusted CAs
 * - Load the Private key & the certificate
 * - Set the Context options & Verify options
 *
 * @param conf to read settings from.
 * @param client If true SSL_CTX will be configured as a client context.
 * @return
 *	- A new SSL_CTX on success.
 *	- NULL on failure.
 */
SSL_CTX *fr_tls_ctx_alloc(fr_tls_conf_t const *conf, bool client)
{
	SSL_CTX		*ctx;
	X509_STORE	*cert_vpstore;
	X509_STORE	*chain_store;
	X509_STORE 	*verify_store;
	int		verify_mode = SSL_VERIFY_NONE;
	int		ctx_options = 0;
	void		*app_data_index;

	/*
	 *	This addresses memory leaks in OpenSSL 1.0.2
	 *	at the cost of the server occasionally
	 *	crashing on exit.
	 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	FR_OPENSSL_BIND_OBJ_MEMORY(ctx = SSL_CTX_new(SSLv23_method())); /* which is really "all known SSL / TLS methods".  Idiots. */
#else
	ctx = SSL_CTX_new(SSLv23_method());
#endif
	if (!ctx) {
		fr_tls_log_error(NULL, "Failed creating TLS context");
		return NULL;
	}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	/*
	 *	Bind any other memory to the ctx to fix
	 *	leaks on exit.
	 */
	FR_OPENSSL_BIND_MEMORY_BEGIN(ctx);
#endif

	/*
	 *	Save the config on the context so that callbacks which
	 *	only get SSL_CTX* e.g. session persistence, can get it
	 */
	memcpy(&app_data_index, &conf, sizeof(app_data_index));
	SSL_CTX_set_app_data(ctx, app_data_index);

	/*
	 *	Identify the type of certificates that needs to be loaded
	 */
#ifdef PSK_MAX_IDENTITY_LEN
	/*
	 *	A dynamic query exists.  There MUST NOT be a
	 *	statically configured identity and password.
	 */
	if (conf->psk_query) {
		if (!*conf->psk_query) {
			ERROR("Invalid PSK Configuration: psk_query cannot be empty");
		error:
#if OPENSSL_VERSION_NUMBER < 0x10100000L
			FR_OPENSSL_BIND_MEMORY_END;
#endif
			SSL_CTX_free(ctx);
			return NULL;
		}

		if (conf->psk_identity && *conf->psk_identity) {
			ERROR("Invalid PSK Configuration: psk_identity and psk_query cannot be used at the same time.");
			goto error;
		}

		if (conf->psk_password && *conf->psk_password) {
			ERROR("Invalid PSK Configuration: psk_password and psk_query cannot be used at the same time.");
			goto error;
		}

		if (client) {
			ERROR("Invalid PSK Configuration: psk_query cannot be used for outgoing connections");
			goto error;
		}

		/*
		 *	Now check that if PSK is being used, that the config is valid.
		 */
	} else if (conf->psk_identity) {
		if (!*conf->psk_identity) {
			ERROR("Invalid PSK Configuration: psk_identity is empty");
			goto error;
		}


		if (!conf->psk_password || !*conf->psk_password) {
			ERROR("Invalid PSK Configuration: psk_identity is set, but there is no psk_password");
			goto error;
		}

	} else if (conf->psk_password) {
		ERROR("Invalid PSK Configuration: psk_password is set, but there is no psk_identity");
		goto error;
	}

	/*
	 *	Set the server PSK callback if necessary.
	 */
	if (!client && (conf->psk_identity || conf->psk_query)) {
		SSL_CTX_set_psk_server_callback(ctx, fr_tls_session_psk_server_cb);
	}

	/*
	 *	Do more sanity checking if we have a PSK identity.  We
	 *	check the password, and convert it to it's final form.
	 */
	if (conf->psk_identity && *conf->psk_identity) {
		size_t psk_len, hex_len;
		uint8_t buffer[PSK_MAX_PSK_LEN];

		if (client) {
			SSL_CTX_set_psk_client_callback(ctx, fr_tls_session_psk_client_cb);
		}

		if (!conf->psk_password) goto error; /* clang is too dumb to catch the above checks */

		psk_len = strlen(conf->psk_password);
		if (strlen(conf->psk_password) > (2 * PSK_MAX_PSK_LEN)) {
			ERROR("psk_hexphrase is too long (max %d)", PSK_MAX_PSK_LEN);
			goto error;
		}

		/*
		 *	Check the password now, so that we don't have
		 *	errors at run-time.
		 */
		hex_len = fr_hex2bin(NULL,
				     &FR_DBUFF_TMP(buffer, sizeof(buffer)),
				     &FR_SBUFF_IN(conf->psk_password, psk_len), false);
		if (psk_len != (2 * hex_len)) {
			ERROR("psk_hexphrase is not all hex");
			goto error;
		}

		goto post_ca;
	}
#else
	(void) client;	/* -Wunused */
#endif

	/*
	 *	Set mode before processing any certifictes
	 */
	{
		int mode = 0;

		/*
		 *	OpenSSL will automatically create certificate chains,
		 *	unless we tell it to not do that.  The problem is that
		 *	it sometimes gets the chains right from a certificate
		 *	signature view, but wrong from the clients view.
		 */
		if (!conf->auto_chain) mode |= SSL_MODE_NO_AUTO_CHAIN;

		if (client) {
			mode |= SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER;
			mode |= SSL_MODE_AUTO_RETRY;
		}

		if (mode) SSL_CTX_set_mode(ctx, mode);
	}

	/*
	 *	If we're using a sufficiently new version of
	 *	OpenSSL, initialise different stores for creating
	 *	the certificate chains we present, and for
	 *	holding certificates to verify the chain presented
	 *	by the peer.
	 *
	 *	If we don't do this, a single store is used for
	 *	both functions, which is confusing and annoying.
	 *
	 *	We use the set0 variant so that the stores are
	 *	freed at the same time as the SSL_CTX.
	 */
	if (!conf->auto_chain) {
		MEM(chain_store = X509_STORE_new());
		SSL_CTX_set0_chain_cert_store(ctx, chain_store);

		MEM(verify_store = X509_STORE_new());
		SSL_CTX_set0_verify_cert_store(ctx, verify_store);
	}

	/*
	 *	Load the CAs we trust
	 */
	if (conf->ca_file || conf->ca_path) {
		if (!SSL_CTX_load_verify_locations(ctx, conf->ca_file, conf->ca_path)) {
			fr_tls_log_error(NULL, "Failed reading Trusted root CA list \"%s\"",
				      conf->ca_file);
			goto error;
		}
	}

	/*
	 *	Load our certificate chains and keys
	 */
	if (conf->chains) {
		size_t chains_conf = talloc_array_length(conf->chains);

		/*
		 *	Load our keys and certificates
		 *
		 *	If certificates are of type PEM then we can make use
		 *	of cert chain authentication using openssl api call
		 *	SSL_CTX_use_certificate_chain_file.  Please see how
		 *	the cert chain needs to be given in PEM from
		 *	openSSL.org
		 */
		{
			size_t i;

			for (i = 0; i < chains_conf; i++) {
				if (tls_ctx_load_cert_chain(ctx, conf->chains[i]) < 0) goto error;
			}
		}

		/*
		 *	Print out our certificate chains.
		 *
		 *	There may be up to three, one for RSA, DH, DSA and EC.
		 *	OpenSSL internally and transparently stores completely
		 *	separate and distinct RSA/DSA/DH/ECC key pairs and chains.
		 */
		if (DEBUG_ENABLED2) {
			size_t chains_set = 0;
			int ret;

			/*
			 *	Iterate over the different chain types we have
			 *	RSA, DSA, DH, EC etc...
			 */
			for (ret = SSL_CTX_set_current_cert(ctx, SSL_CERT_SET_FIRST);
			     ret == 1;
			     ret = SSL_CTX_set_current_cert(ctx, SSL_CERT_SET_NEXT)) chains_set++;

			/*
			 *	Check for discrepancies
			 */

			DEBUG3("Found %zu server certificate chain(s)", chains_set);

			if (chains_set != chains_conf) {
				WARN("Number of chains configured (%zu) does not match chains set (%zu)",
				      chains_conf, chains_set);
				if (chains_conf > chains_set) WARN("Only one chain per key type is allowed, "
								   "check config for duplicates");
			}

			for (ret = SSL_CTX_set_current_cert(ctx, SSL_CERT_SET_FIRST);
			     ret == 1;
			     ret = SSL_CTX_set_current_cert(ctx, SSL_CERT_SET_NEXT)) {
			     	STACK_OF(X509)	*our_chain;
				X509		*our_cert;

				our_cert = SSL_CTX_get0_certificate(ctx);

				/*
				 *	The pkey type of the server certificate
				 *	determines which pkey slot OpenSSL
				 *	uses to store the chain.
				 */
				DEBUG3("%s chain", fr_tls_utils_x509_pkey_type(our_cert));
				if (!SSL_CTX_get0_chain_certs(ctx, &our_chain)) {
					fr_tls_log_error(NULL, "Failed retrieving chain certificates");
					goto error;
				}

				if (DEBUG_ENABLED3) fr_tls_log_certificate_chain(NULL, our_chain, our_cert);
			}
			(void)SSL_CTX_set_current_cert(ctx, SSL_CERT_SET_FIRST);	/* Reset */
		}
	}

	/*
	 *	Sets the list of CAs we send to the peer if we're
	 *	requesting a certificate.
	 *
	 *	This does not change the trusted certificate authorities,
	 *	those are set above with SSL_CTX_load_verify_locations.
	 */
	if (conf->ca_file && *conf->ca_file) SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(conf->ca_file));

#ifdef PSK_MAX_IDENTITY_LEN
post_ca:
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	/*
	 *	SSL_CTX_set_(min|max)_proto_version was included in OpenSSL 1.1.0
	 *
	 *	This version already defines macros for TLS1_2_VERSION and
	 *	below, so we don't need to check for them explicitly.
	 *
	 *	TLS1_3_VERSION is available in OpenSSL 1.1.1.
	 *
	 *	TLS1_4_VERSION in speculative.
	 */
	if (conf->tls_max_version > (float) 0.0) {
		int max_version = 0;

		if (conf->tls_min_version > conf->tls_max_version) {
			/*
			 *	%f is actually %lg now (double).  Compile complains about
			 *      implicit promotion unless we cast args to double.
			 */
			ERROR("tls_min_version (%f) must be <= tls_max_version (%f)",
			      (double)conf->tls_min_version, (double)conf->tls_max_version);
			goto error;
		}

		if (conf->tls_max_version < (float) 1.0) {
			ERROR("tls_max_version must be >= 1.0 as SSLv2 and SSLv3 are permanently disabled");
			goto error;
		}

#  ifdef TLS1_4_VERSION
		else if (conf->tls_max_version >= (float) 1.4) max_version = TLS1_4_VERSION;
#  endif
#  ifdef TLS1_3_VERSION
		else if (conf->tls_max_version >= (float) 1.3) max_version = TLS1_3_VERSION;
#  endif
		else if (conf->tls_max_version >= (float) 1.2) max_version = TLS1_2_VERSION;
		else if (conf->tls_max_version >= (float) 1.1) max_version = TLS1_1_VERSION;
		else max_version = TLS1_VERSION;

		if (!SSL_CTX_set_max_proto_version(ctx, max_version)) {
			fr_tls_log_error(NULL, "Failed setting TLS maximum version");
			goto error;
		}
	}

	{
		int min_version = TLS1_2_VERSION;

		if (conf->tls_min_version < (float) 1.0) {
			ERROR("tls_min_version must be >= 1.0 as SSLv2 and SSLv3 are permanently disabled");
			goto error;
		}
#  ifdef TLS1_4_VERSION
		else if (conf->tls_min_version >= (float) 1.4) min_version = TLS1_4_VERSION;
#  endif
#  ifdef TLS1_3_VERSION
		else if (conf->tls_min_version >= (float) 1.3) min_version = TLS1_3_VERSION;
#  endif
		else if (conf->tls_min_version >= (float) 1.2) min_version = TLS1_2_VERSION;
		else if (conf->tls_min_version >= (float) 1.1) min_version = TLS1_1_VERSION;

		if (!SSL_CTX_set_min_proto_version(ctx, min_version)) {
			fr_tls_log_error(NULL, "Failed setting TLS minimum version");
			goto error;
		}
	}
#else
	/*
	 *	OpenSSL < 1.1.0 - This doesn't need to change when new TLS versions are issued
	 *	as new TLS versions will never be added to older OpenSSL versions.
	 */
	{
		int ctx_tls_versions = 0;

		/*
		 *	We never want SSLv2 or SSLv3.
		 */
		ctx_options |= SSL_OP_NO_SSLv2;
		ctx_options |= SSL_OP_NO_SSLv3;

		if (conf->tls_min_version < (float) 1.0) {
			ERROR("SSLv2 and SSLv3 are permanently disabled due to critical security issues");
			goto error;
		}

		/*
		 *	As of 3.0.5, we always allow TLSv1.1 and TLSv1.2.
		 *	Though they can be *globally* disabled if necessary.
		 */
#  ifdef SSL_OP_NO_TLSv1
		if (conf->tls_min_version > (float) 1.0) ctx_options |= SSL_OP_NO_TLSv1;
		ctx_tls_versions |= SSL_OP_NO_TLSv1;
#  endif
#  ifdef SSL_OP_NO_TLSv1_1
		if (conf->tls_min_version > (float) 1.1) ctx_options |= SSL_OP_NO_TLSv1_1;
		if ((conf->tls_max_version > (float) 0.0) && (conf->tls_max_version < (float) 1.1)) {
			ctx_options |= SSL_OP_NO_TLSv1_1;
		}
		ctx_tls_versions |= SSL_OP_NO_TLSv1_1;
#  endif
#  ifdef SSL_OP_NO_TLSv1_2
		if (conf->tls_min_version > (float) 1.2) ctx_options |= SSL_OP_NO_TLSv1_2;
		if ((conf->tls_max_version > (float) 0.0) && (conf->tls_max_version < (float) 1.2)) {
			ctx_options |= SSL_OP_NO_TLSv1_2;
		}
		ctx_tls_versions |= SSL_OP_NO_TLSv1_2;
#  endif

		if ((ctx_options & ctx_tls_versions) == ctx_tls_versions) {
			ERROR("You have disabled all available TLS versions.  EAP will not work");
			goto error;
		}
	}
#endif

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

#ifdef SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS
	if (conf->allow_renegotiation) {
		/*
		 *	Note: This flag isn't honoured by all OpenSSL forks.
		 */
		ctx_options |= SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS;
	}
#endif

	/*
	 *	SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS to work around issues
	 *	in Windows Vista client.
	 *	http://www.openssl.org/~bodo/tls-cbc.txt
	 *	http://www.nabble.com/(RADIATOR)-Radiator-Version-3.16-released-t2600070.html
	 */
	ctx_options |= SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS;

	if (conf->cipher_server_preference) {
	/*
	 *	SSL_OP_CIPHER_SERVER_PREFERENCE to follow best practice
	 *	of nowday's TLS: do not allow poorly-selected ciphers from
	 *	client to take preference
	 */
		ctx_options |= SSL_OP_CIPHER_SERVER_PREFERENCE;
	}

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
	 *	SSL_CTX_set_msg_callback(ctx, fr_tls_session_msg_cb);
	 */

	/*
	 *	Set eliptical curve crypto configuration.
	 */
#ifndef OPENSSL_NO_ECDH
	if (ctx_ecdh_curve_set(ctx, conf->ecdh_curve, conf->disable_single_dh_use) < 0) {
		goto error;
	}
#endif

	/* Set Info callback */
	SSL_CTX_set_info_callback(ctx, fr_tls_session_info_cb);

	/*
	 *	Check the certificates for revocation.
	 */
#ifdef X509_V_FLAG_CRL_CHECK_ALL
	if (conf->check_crl) {
		cert_vpstore = SSL_CTX_get_cert_store(ctx);
		if (cert_vpstore == NULL) {
			fr_tls_log_error(NULL, "Error reading Certificate Store");
	    		goto error;
		}
		X509_STORE_set_flags(cert_vpstore, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
#ifdef X509_V_FLAG_USE_DELTAS
		/*
		 *	If set, delta CRLs (if present) are used to
		 *	determine certificate status. If not set
		 *	deltas are ignored.
		 *
		 *	So it's safe to always set this flag.
		 */
		X509_STORE_set_flags(cert_vpstore, X509_V_FLAG_USE_DELTAS);
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
	SSL_CTX_set_verify(ctx, verify_mode, fr_tls_validate_cert_cb);

	if (conf->verify_depth) {
		SSL_CTX_set_verify_depth(ctx, conf->verify_depth);
	}

	/*
	 *	Configure OCSP stapling for the server cert
	 */
	if (conf->staple.enable) {
		SSL_CTX_set_tlsext_status_cb(ctx, fr_tls_ocsp_staple_cb);

		{
			fr_tls_ocsp_conf_t const *staple_conf = &(conf->staple);	/* Need to assign offset first */
			fr_tls_ocsp_conf_t *tmp;

			memcpy(&tmp, &staple_conf, sizeof(tmp));

			SSL_CTX_set_tlsext_status_arg(ctx, tmp);
		}
	}

	/*
	 *	Set the cipher list if we were told to
	 */
	if (conf->cipher_list) {
		if (!SSL_CTX_set_cipher_list(ctx, conf->cipher_list)) {
			fr_tls_log_error(NULL, "Failed setting cipher list");
			goto error;
		}
	}

	/*
	 *	Print the actual cipher list
	 */
	if (DEBUG_ENABLED3) {
		SSL		*ssl;
		unsigned int	i = 0;
		char const	*cipher;

		ssl = SSL_new(ctx);
		if (!ssl) {
			fr_tls_log_error(NULL, "Failed creating temporary SSL session");
			goto error;
		}

		DEBUG3("Configured ciphers (by priority)");

		while ((cipher = SSL_get_cipher_list(ssl, i))) {
			DEBUG3("[%i] %s", i, cipher);
			i++;		/* Print index starting at zero */
		}

		SSL_free(ssl);
	}

	/*
	 *	Load dh params
	 */
	if (conf->dh_file) {
		char *dh_file;

		memcpy(&dh_file, &conf->dh_file, sizeof(dh_file));
		if (ctx_dh_params_load(ctx, dh_file) < 0) goto error;
	}

	/*
	 *	We're done configuring the ctx.
	 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	FR_OPENSSL_BIND_MEMORY_END;
#endif

	/*
	 *	Setup session caching
	 */
	fr_tls_cache_init(ctx, conf->session_cache_server ? true : false, conf->session_cache_lifetime);

	return ctx;
}
#endif
