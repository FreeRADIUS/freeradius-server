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
#define LOG_PREFIX "tls"

#include <freeradius-devel/tls/log.h>
#include <freeradius-devel/tls/strerror.h>
#include <freeradius-devel/util/base16.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/syserror.h>

#include "base.h"
#include "utils.h"
#include "log.h"
#include "cert.h"

#include <openssl/rand.h>
#include <openssl/dh.h>
#include <openssl/x509v3.h>
#include <openssl/provider.h>

#ifndef OPENSSL_NO_ECDH
static int ctx_ecdh_curve_set(SSL_CTX *ctx, char const *ecdh_curve, bool disable_single_dh_use)
{
	char *list;

	if (!disable_single_dh_use) {
		SSL_CTX_set_options(ctx, SSL_OP_SINGLE_ECDH_USE);
	}

	if (!ecdh_curve || !*ecdh_curve) return 0;

	list = strdup(ecdh_curve);
	if (SSL_CTX_set1_curves_list(ctx, list) == 0) {
		free(list);
		ERROR("Unknown ecdh_curve \"%s\"", ecdh_curve);
		return -1;
	}
	free(list);
	return 0;
}
#endif

/*
 *	TODO: Check for the type of key exchange * like conf->dh_key
 */
static int ctx_dh_params_load(SSL_CTX *ctx, char *file)
{
	BIO	*bio;
	int	ret;

	EVP_PKEY *dh = NULL;

	if (!file) return 0;

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
	if (EVP_default_properties_is_fips_enabled(NULL)) {
		WARN(LOG_PREFIX ": Ignoring user-selected DH parameters in FIPS mode. Using defaults.");
		return 0;
	}

	if ((bio = BIO_new_file(file, "r")) == NULL) {
		ERROR("Unable to open DH file - %s", file);
		return -1;
	}

	dh = PEM_read_bio_Parameters(bio, &dh);
	BIO_free(bio);
	if (!dh) {
		WARN("Unable to set DH parameters.  DH cipher suites may not work!");
		WARN("Fix this by generating the DH parameter file");
		return 0;
	}

	ret = SSL_CTX_set0_tmp_dh_pkey(ctx, dh);
	if (ret == 0) {
		ERROR("Unable to set DH parameters");
		return -1;
	}

	return 0;
}

static int tls_ctx_verify_chain_member(fr_unix_time_t *expires_first, X509 **self_signed,
				       SSL_CTX *ctx, X509 *to_verify,
				       fr_tls_chain_verify_mode_t verify_mode)
{
	fr_unix_time_t	not_after;

	STACK_OF(X509)	*chain;
	X509		*leaf;

	leaf = SSL_CTX_get0_certificate(ctx);
	if (!leaf) {
		ERROR("Chain does not contain a valid leaf certificate");
		return -1;
	}

	if (!SSL_CTX_get0_chain_certs(ctx, &chain)) {
		fr_tls_log(NULL, "Failed retrieving chain certificates");
		return -1;
	}

	switch (fr_tls_cert_is_valid(NULL, &not_after, to_verify)) {
	case -1:
		fr_tls_chain_marker_log(NULL, L_ERR, chain, leaf, to_verify);
		PERROR("Malformed certificate");
		return -1;

	case -2:
	case -3:
		switch (verify_mode) {
		case FR_TLS_CHAIN_VERIFY_SOFT:
			fr_tls_chain_marker_log(NULL, L_WARN, chain, leaf, to_verify);
			PWARN("Certificate validation failed");
			break;

		case FR_TLS_CHAIN_VERIFY_HARD:
			fr_tls_chain_marker_log(NULL, L_ERR, chain, leaf, to_verify);
			PERROR("Certificate validation failed");
			return -1;

		default:
			break;
		}

	}

	/*
	 *	Check for self-signed certs
	 */
	switch (verify_mode) {
	case FR_TLS_CHAIN_VERIFY_SOFT:
	case FR_TLS_CHAIN_VERIFY_HARD:
		/*
		 *	There can be only one... self signed
		 *	cert in a chain.
		 *
		 *	We have to do this check manually
		 *	because the OpenSSL functions will
		 *	only check to see if it can build
		 *	a chain, not that all certificates
		 *	in the chain are used.
		 *
		 *	Having multiple self-signed certificates
		 *	usually indicates someone has copied
		 *	the wrong certificates into the
		 *	server.pem file.
		 */
		if (X509_name_cmp(X509_get_subject_name(to_verify),
				  X509_get_issuer_name(to_verify)) == 0) {
			if (*self_signed) {
				switch (verify_mode) {
				case FR_TLS_CHAIN_VERIFY_SOFT:
					WARN("Found multiple self-signed certificates in chain");
					WARN("First certificate was:");
					fr_tls_chain_marker_log(NULL, L_WARN,
									    chain, leaf, *self_signed);

					WARN("Second certificate was:");
					fr_tls_chain_marker_log(NULL, L_WARN,
									    chain, leaf, to_verify);
					break;

				case FR_TLS_CHAIN_VERIFY_HARD:
					ERROR("Found multiple self-signed certificates in chain");
					ERROR("First certificate was:");
					fr_tls_chain_marker_log(NULL, L_ERR,
									    chain, leaf, *self_signed);

					ERROR("Second certificate was:");
					fr_tls_chain_marker_log(NULL, L_ERR,
									    chain, leaf, to_verify);
					return -1;

				default:
					break;
				}
			}
			*self_signed = to_verify;
		}
		break;

	default:
		break;
	}

	/*
	 *	Record the time the first certificate in
	 *	the chain expires so we can use it for
	 *	runtime checks.
	 */
	if (!fr_unix_time_ispos(*expires_first) ||
	    (fr_unix_time_gt(*expires_first, not_after))) *expires_first = not_after;

	 return 0;
}

static int tls_ctx_load_cert_chain(SSL_CTX *ctx, fr_tls_chain_conf_t *chain, bool allow_multi_self_signed)
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
			fr_tls_log(NULL, "Failed reading certificate file \"%s\"",
				      chain->certificate_file);
			return -1;
		}
		break;

	case SSL_FILETYPE_ASN1:
		if (!(SSL_CTX_use_certificate_file(ctx, chain->certificate_file, chain->file_format))) {
			fr_tls_log(NULL, "Failed reading certificate file \"%s\"",
				      chain->certificate_file);
			return -1;
		}
		break;

	default:
		fr_assert(0);
		break;
	}

	if (!(SSL_CTX_use_PrivateKey_file(ctx, chain->private_key_file, chain->file_format))) {
		fr_tls_log(NULL, "Failed reading private key file \"%s\"",
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
				fr_tls_log(NULL, "Failed reading certificate file \"%s\"", filename);
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

	/*
	 *	Loop over the certificates checking validity periods.
	 *	SSL_CTX_build_cert_chain does this too, but we can
	 *	produce significantly better errors here.
	 *
	 *	After looping over all the certs we figure out when
	 *      the chain will next need refreshing.
	 */
	{
		fr_unix_time_t  expires_first = fr_unix_time_wrap(0);
		X509		*self_signed = NULL;
		STACK_OF(X509)	*our_chain;
		int		i;

		if (tls_ctx_verify_chain_member(&expires_first, &self_signed,
						ctx, SSL_CTX_get0_certificate(ctx),
						chain->verify_mode) < 0) return -1;

		if (!SSL_CTX_get0_chain_certs(ctx, &our_chain)) {
			fr_tls_log(NULL, "Failed retrieving chain certificates");
			return -1;
		}

		if (allow_multi_self_signed) self_signed = NULL;

DIAG_OFF(DIAG_UNKNOWN_PRAGMAS)
DIAG_OFF(used-but-marked-unused)	/* fix spurious warnings for sk macros */
		for (i = sk_X509_num(our_chain); i > 0 ; i--) {
			/*
			 *	SSL_CTX_use_certificate_chain_file set the
			 *	current cert to be the one loaded from
			 *	that pem file.
			 */
			if (tls_ctx_verify_chain_member(&expires_first, &self_signed,
							ctx, sk_X509_value(our_chain, i - 1),
							chain->verify_mode) < 0) return -1;

			if (allow_multi_self_signed) self_signed = NULL;
		}
DIAG_ON(used-but-marked-unused)	/* fix spurious warnings for sk macros */
DIAG_ON(DIAG_UNKNOWN_PRAGMAS)
		/*
		 *	Record this as a unix timestamp as
		 *	internal time might not progress at
		 *	the same rate as wallclock time.
		 */
		chain->valid_until = expires_first;
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
				fr_tls_strerror_printf(NULL);
				PWARN("Failed verifying chain");
			}
			break;

		case FR_TLS_CHAIN_VERIFY_HARD:
			if (!SSL_CTX_build_cert_chain(ctx, mode)) {
				fr_tls_strerror_printf(NULL);
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

static inline CC_HINT(always_inline)
int tls_ctx_version_set(
			UNUSED
			int *ctx_options, SSL_CTX *ctx, fr_tls_conf_t const *conf)
{
	/*
	 *	SSL_CTX_set_(min|max)_proto_version was included in OpenSSL 1.1.0
	 *
	 *	This version already defines macros for TLS1_2_VERSION and
	 *	below, so we don't need to check for them explicitly.
	 *
	 *	TLS1_3_VERSION is available in OpenSSL 1.1.1.
	 *
	 *	TLS1_4_VERSION does not exist yet.  But we allow it
	 *	only if it is explicitly permitted by the
	 *	administrator.
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
		error:
			return -1;
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

		/*
		 *	Complain about insecure TLS versions.
		 */
		if (max_version < TLS1_2_VERSION) {
			WARN("TLS 1.0 and 1.1 are insecure and SHOULD NOT be used");
			WARN("tls_max_version SHOULD be 1.2 or greater");
		}

		if (!SSL_CTX_set_max_proto_version(ctx, max_version)) {
			fr_tls_log(NULL, "Failed setting TLS maximum version");
			goto error;
		}
	}

	{
		int min_version;

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
		else min_version = TLS1_VERSION;

		/*
		 *	Complain about insecure TLS versions.
		 */
		if (min_version < TLS1_2_VERSION) {
			WARN("TLS 1.0 and 1.1 are insecure and SHOULD NOT be used");
			WARN("tls_min_version SHOULD be 1.2 or greater");
		}

		if (!SSL_CTX_set_min_proto_version(ctx, min_version)) {
			fr_tls_log(NULL, "Failed setting TLS minimum version");
			goto error;
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
	X509_STORE	*verify_store;
	int		ctx_options = 0;

	ctx = SSL_CTX_new(TLS_method());
	if (!ctx) {
		fr_tls_log(NULL, "Failed creating TLS context");
		return NULL;
	}

	/*
	 *	Save the config on the context so that callbacks which
	 *	only get SSL_CTX* e.g. session persistence, can get at it.
	 */
	SSL_CTX_set_ex_data(ctx, FR_TLS_EX_INDEX_CONF, UNCONST(void *, conf));

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
			SSL_CTX_free(ctx);
			return NULL;
		}

		if (conf->psk_identity && *conf->psk_identity) {
			ERROR("Invalid PSK Configuration: psk_identity and psk_query cannot be used at the same time.");
			goto error;
		}

		if (conf->psk_password && *conf->psk_password) {
			ERROR("Invalid PSK Configuration: psk_hexphrase and psk_query cannot be used at the same time.");
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
			ERROR("Invalid PSK Configuration: psk_identity is set, but there is no psk_hexphrase");
			goto error;
		}

	} else if (conf->psk_password) {
		ERROR("Invalid PSK Configuration: psk_hexphrase is set, but there is no psk_identity");
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
		hex_len = fr_base16_decode(NULL,
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
		int mode = SSL_MODE_ASYNC;

		/*
		 *	OpenSSL will automatically create certificate chains,
		 *	unless we tell it to not do that.  The problem is that
		 *	it sometimes gets the chains right from a certificate
		 *	signature view, but wrong from the clients view.
		 *
		 *	It's better just to have users specify the complete
		 *	chains.
		 */
		mode |= SSL_MODE_NO_AUTO_CHAIN;

		if (client) {
			mode |= SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER;
			mode |= SSL_MODE_AUTO_RETRY;
		}

		if (mode) SSL_CTX_set_mode(ctx, mode);
	}

	/*
	 *	Initialise a separate store for verifying user
	 *      certificates.
	 *
	 *      This makes the configuration cleaner as there's
	 *	no mixing of chain certs and user certs.
	 */
	MEM(verify_store = X509_STORE_new());

	/* Sets OpenSSL's (CERT *)->verify_store, overring (SSL_CTX *)->cert_store */
	SSL_CTX_set0_verify_cert_store(ctx, verify_store);

	/* This isn't accessible to use later, i.e. there's no SSL_CTX_get0_verify_cert_store */
	SSL_CTX_set_ex_data(ctx, FR_TLS_EX_CTX_INDEX_VERIFY_STORE, verify_store);

	/*
	 *	Load the CAs we trust
	 */
	if (conf->ca_file || conf->ca_path) {
		/*
		 *	This adds all the certificates to the store for conf->ca_file
		 *      and adds a dynamic lookup for conf->ca_path.
		 *
		 *      It's also possible to add extra virtual server lookups
		 */
		if (!X509_STORE_load_locations(verify_store, conf->ca_file, conf->ca_path)) {
			fr_tls_log(NULL, "Failed reading Trusted root CA list \"%s\"",
				      conf->ca_file ? conf->ca_file : conf->ca_path);
			goto error;
		}

		/*
		 *	These set the default parameters of the store when the
		 *      store is involved in building chains.
		 *
		 *	- X509_PURPOSE_SSL_CLIENT ensure the purpose of the
		 *	  client certificate is for peer authentication as
		 *	  a client.
		 */
		X509_STORE_set_purpose(verify_store, X509_PURPOSE_SSL_CLIENT);

		/*
		 *	Sets the list of CAs we send to the peer if we're
		 *	requesting a certificate.
		 *
		 *	This does not change the trusted certificate authorities,
		 *	those are set above with SSL_CTX_load_verify_locations.
		 */
		if (conf->ca_file) SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(conf->ca_file));
	} else {
		X509_STORE_set_default_paths(verify_store);
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
				if (tls_ctx_load_cert_chain(ctx, conf->chains[i], false) < 0) goto error;
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
					fr_tls_log(NULL, "Failed retrieving chain certificates");
					goto error;
				}

				if (DEBUG_ENABLED3) fr_tls_chain_log(NULL, L_DBG, our_chain, our_cert);
			}
			(void)SSL_CTX_set_current_cert(ctx, SSL_CERT_SET_FIRST);	/* Reset */
		}
	}

#ifdef PSK_MAX_IDENTITY_LEN
post_ca:
#endif
	if (tls_ctx_version_set(&ctx_options, ctx, conf) < 0) goto error;

	/*
	 *	SSL_OP_SINGLE_DH_USE must be used in order to prevent
	 *	small subgroup attacks and forward secrecy. Always
	 *	using SSL_OP_SINGLE_DH_USE has an impact on the
	 *	computer time needed during negotiation, but it is not
	 *	very large.
	 */
	if (!conf->disable_single_dh_use) {
		ctx_options |= SSL_OP_SINGLE_DH_USE;
	}

#ifdef SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS
	/*
	 *	Note: This flag isn't honoured by all OpenSSL forks.
	 */
	if (conf->allow_renegotiation) {
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

	/*
	 *	SSL_OP_CIPHER_SERVER_PREFERENCE to follow best practice
	 *	of nowday's TLS: do not allow poorly-selected ciphers from
	 *	client to take preference
	 */
	if (conf->cipher_server_preference) ctx_options |= SSL_OP_CIPHER_SERVER_PREFERENCE;

	SSL_CTX_set_options(ctx, ctx_options);

	/*
	 *	TODO: Set the RSA & DH
	 *	SSL_CTX_set_tmp_rsa_callback(ctx, cbtls_rsa);
	 *	SSL_CTX_set_tmp_dh_callback(ctx, cbtls_dh);
	 */

	/*
	 *	Set the block size for record padding.  This is only
	 *	used in TLS 1.3.
	 */
	if (conf->padding_block_size) SSL_CTX_set_block_padding(ctx, conf->padding_block_size);

	/*
	 *	Set elliptical curve crypto configuration.
	 */
#ifndef OPENSSL_NO_ECDH
	if (ctx_ecdh_curve_set(ctx, conf->ecdh_curve, conf->disable_single_dh_use) < 0) goto error;
#endif


	/* Set Info callback */
	SSL_CTX_set_info_callback(ctx, fr_tls_session_info_cb);

	/*
	 *	Check the certificates for revocation.
	 */
#ifdef X509_V_FLAG_CRL_CHECK_ALL
	if (conf->verify.check_crl) {
		cert_vpstore = SSL_CTX_get_cert_store(ctx);
		if (cert_vpstore == NULL) {
			fr_tls_log(NULL, "Error reading Certificate Store");
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
	 *	SSL_ctx_set_verify is now called in the session
	 *	alloc functions so they can set custom behaviour
	 *	depending on the code area the SSL * will be used
	 *	and whether we're acting as a client or server.
	 */
	if (conf->verify_depth) {
		SSL_CTX_set_verify_depth(ctx, conf->verify_depth);
	}

#ifdef HAVE_OPENSSL_OCSP_H
	/*
	 *	Configure OCSP stapling for the server cert
	 */
	if (conf->staple.enable) {
		SSL_CTX_set_tlsext_status_cb(ctx, fr_tls_ocsp_staple_cb);
		SSL_CTX_set_tlsext_status_arg(ctx, UNCONST(fr_tls_ocsp_conf_t *, &(conf->staple)));
	}
#endif

	/*
	 *	Set the cipher list if we were told to
	 */
	if (conf->cipher_list) {
		if (!SSL_CTX_set_cipher_list(ctx, conf->cipher_list)) {
			fr_tls_log(NULL, "Failed setting cipher list");
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
			fr_tls_log(NULL, "Failed creating temporary SSL session");
			goto error;
		}

		DEBUG3("Configured ciphers (by priority)");

		while ((cipher = SSL_get_cipher_list(ssl, i))) {
			DEBUG3("[%u] %s", i, cipher);
			i++;		/* Print index starting at zero */
		}

		SSL_free(ssl);
	}

	/*
	 *	Load dh params
	 */
	if (conf->dh_file) {
		if (ctx_dh_params_load(ctx, UNCONST(char *, conf->dh_file)) < 0) goto error;
	} else {
		/*
		 *	Tell OpenSSL to automatically set the DH
		 *	parameters based on the the size of the key
		 *	associated with the certificate, or for PSK,
		 *	with the negotiated symmetric cipher key.
		 */
		SSL_CTX_set_dh_auto(ctx, 1);
	}

	/*
	 *	Setup session caching
	 */
	if (fr_tls_cache_ctx_init(ctx, &conf->cache) < 0) goto error;

	/*
	 *	Set the keylog file if the admin requested it.
	 */
	if ((getenv("SSLKEYLOGFILE") != NULL) || (conf->keylog_file && *conf->keylog_file)) {
		SSL_CTX_set_keylog_callback(ctx, fr_tls_session_keylog_cb);
	}

	return ctx;
}
#endif
