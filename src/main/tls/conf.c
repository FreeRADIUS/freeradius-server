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
 * @file tls/conf.c
 * @brief Configuration parsing for TLS servers and clients.
 *
 * @copyright 2001 hereUare Communications, Inc. <raghud@hereuare.com>
 * @copyright 2003  Alan DeKok <aland@freeradius.org>
 * @copyright 2006-2016 The FreeRADIUS server project
 */
RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#ifdef WITH_TLS
#define LOG_PREFIX "tls - "

#ifdef HAVE_SYS_STAT_H
#  include <sys/stat.h>
#endif
#include <openssl/conf.h>

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>

static CONF_PARSER cache_config[] = {
	{ FR_CONF_OFFSET("virtual_server", PW_TYPE_STRING, fr_tls_conf_t, session_cache_server) },
	{ FR_CONF_OFFSET("name", PW_TYPE_STRING, fr_tls_conf_t, session_id_name) },
	{ FR_CONF_OFFSET("lifetime", PW_TYPE_INTEGER, fr_tls_conf_t, session_cache_lifetime), .dflt = "86400" },
	{ FR_CONF_OFFSET("verify", PW_TYPE_BOOLEAN, fr_tls_conf_t, session_cache_verify), .dflt = "no" },

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	{ FR_CONF_OFFSET("require_extended_master_secret", PW_TYPE_BOOLEAN, fr_tls_conf_t, session_cache_require_extms), .dflt = "yes" },
	{ FR_CONF_OFFSET("require_perfect_forward_secrecy", PW_TYPE_BOOLEAN, fr_tls_conf_t, session_cache_require_pfs), .dflt = "no" },
#endif

	{ FR_CONF_DEPRECATED("enable", PW_TYPE_BOOLEAN, fr_tls_conf_t, NULL) },
	{ FR_CONF_DEPRECATED("max_entries", PW_TYPE_INTEGER, fr_tls_conf_t, NULL) },
	{ FR_CONF_DEPRECATED("persist_dir", PW_TYPE_STRING, fr_tls_conf_t, NULL) },

	CONF_PARSER_TERMINATOR
};

static CONF_PARSER verify_config[] = {
	{ FR_CONF_OFFSET("tmpdir", PW_TYPE_STRING, fr_tls_conf_t, verify_tmp_dir) },
	{ FR_CONF_OFFSET("client", PW_TYPE_STRING, fr_tls_conf_t, verify_client_cert_cmd) },
	CONF_PARSER_TERMINATOR
};

#ifdef HAVE_OPENSSL_OCSP_H
static CONF_PARSER ocsp_config[] = {
	{ FR_CONF_OFFSET("enable", PW_TYPE_BOOLEAN, fr_tls_ocsp_conf_t, enable), .dflt = "no" },

	{ FR_CONF_OFFSET("virtual_server", PW_TYPE_STRING, fr_tls_ocsp_conf_t, cache_server) },

	{ FR_CONF_OFFSET("override_cert_url", PW_TYPE_BOOLEAN, fr_tls_ocsp_conf_t, override_url), .dflt = "no" },
	{ FR_CONF_OFFSET("url", PW_TYPE_STRING, fr_tls_ocsp_conf_t, url) },
	{ FR_CONF_OFFSET("use_nonce", PW_TYPE_BOOLEAN, fr_tls_ocsp_conf_t, use_nonce), .dflt = "yes" },
	{ FR_CONF_OFFSET("timeout", PW_TYPE_INTEGER, fr_tls_ocsp_conf_t, timeout), .dflt = "yes" },
	{ FR_CONF_OFFSET("softfail", PW_TYPE_BOOLEAN, fr_tls_ocsp_conf_t, softfail), .dflt = "no" },

	CONF_PARSER_TERMINATOR
};
#endif

static CONF_PARSER tls_server_config[] = {
	{ FR_CONF_OFFSET("verify_depth", PW_TYPE_INTEGER, fr_tls_conf_t, verify_depth), .dflt = "0" },
	{ FR_CONF_OFFSET("ca_path", PW_TYPE_FILE_INPUT, fr_tls_conf_t, ca_path) },
	{ FR_CONF_OFFSET("pem_file_type", PW_TYPE_BOOLEAN, fr_tls_conf_t, file_type), .dflt = "yes" },
	{ FR_CONF_OFFSET("private_key_file", PW_TYPE_FILE_INPUT, fr_tls_conf_t, private_key_file) },
	{ FR_CONF_OFFSET("certificate_file", PW_TYPE_FILE_INPUT, fr_tls_conf_t, certificate_file) },
	{ FR_CONF_OFFSET("ca_file", PW_TYPE_FILE_INPUT, fr_tls_conf_t, ca_file) },
	{ FR_CONF_OFFSET("private_key_password", PW_TYPE_STRING | PW_TYPE_SECRET, fr_tls_conf_t, private_key_password) },
#ifdef PSK_MAX_IDENTITY_LEN
	{ FR_CONF_OFFSET("psk_identity", PW_TYPE_STRING, fr_tls_conf_t, psk_identity) },
	{ FR_CONF_OFFSET("psk_hexphrase", PW_TYPE_STRING | PW_TYPE_SECRET, fr_tls_conf_t, psk_password) },
	{ FR_CONF_OFFSET("psk_query", PW_TYPE_STRING, fr_tls_conf_t, psk_query) },
#endif
	{ FR_CONF_OFFSET("dh_file", PW_TYPE_FILE_INPUT, fr_tls_conf_t, dh_file) },
	{ FR_CONF_OFFSET("random_file", PW_TYPE_FILE_EXISTS, fr_tls_conf_t, random_file) },
	{ FR_CONF_OFFSET("fragment_size", PW_TYPE_INTEGER, fr_tls_conf_t, fragment_size), .dflt = "1024" },
	{ FR_CONF_OFFSET("auto_chain", PW_TYPE_BOOLEAN, fr_tls_conf_t, auto_chain), .dflt = "yes" },
	{ FR_CONF_OFFSET("disable_single_dh_use", PW_TYPE_BOOLEAN, fr_tls_conf_t, disable_single_dh_use) },
	{ FR_CONF_OFFSET("check_crl", PW_TYPE_BOOLEAN, fr_tls_conf_t, check_crl), .dflt = "no" },
#ifdef X509_V_FLAG_CRL_CHECK_ALL
	{ FR_CONF_DEPRECATED("check_all_crl", PW_TYPE_BOOLEAN, fr_tls_conf_t, NULL) },
#endif
	{ FR_CONF_OFFSET("allow_expired_crl", PW_TYPE_BOOLEAN, fr_tls_conf_t, allow_expired_crl) },
	{ FR_CONF_OFFSET("check_cert_cn", PW_TYPE_STRING, fr_tls_conf_t, check_cert_cn) },
	{ FR_CONF_OFFSET("cipher_list", PW_TYPE_STRING, fr_tls_conf_t, cipher_list) },
	{ FR_CONF_OFFSET("cipher_server_preference", PW_TYPE_BOOLEAN, fr_tls_conf_t, cipher_server_preference), .dflt = "yes" },
#ifdef SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS
	{ FR_CONF_OFFSET("allow_renegotiation", PW_TYPE_BOOLEAN, fr_tls_conf_t, allow_renegotiation), .dflt = "no" },
#endif
	{ FR_CONF_OFFSET("check_cert_issuer", PW_TYPE_STRING, fr_tls_conf_t, check_cert_issuer) },
	{ FR_CONF_OFFSET("require_client_cert", PW_TYPE_BOOLEAN, fr_tls_conf_t, require_client_cert) },
	{ FR_CONF_OFFSET("ca_path_reload_interval", PW_TYPE_INTEGER, fr_tls_conf_t, ca_path_reload_interval), .dflt = "0" },

#if OPENSSL_VERSION_NUMBER >= 0x0090800fL
#ifndef OPENSSL_NO_ECDH
	{ FR_CONF_OFFSET("ecdh_curve", PW_TYPE_STRING, fr_tls_conf_t, ecdh_curve), .dflt = "prime256v1" },
#endif
#endif

#ifdef SSL_OP_NO_TLSv1
	{ FR_CONF_OFFSET("disable_tlsv1", PW_TYPE_BOOLEAN, fr_tls_conf_t, disable_tlsv1) },
#endif

#ifdef SSL_OP_NO_TLSv1_1
	{ FR_CONF_OFFSET("disable_tlsv1_1", PW_TYPE_BOOLEAN, fr_tls_conf_t, disable_tlsv1_1) },
#endif

#ifdef SSL_OP_NO_TLSv1_2
	{ FR_CONF_OFFSET("disable_tlsv1_2", PW_TYPE_BOOLEAN, fr_tls_conf_t, disable_tlsv1_2) },
#endif

	{ FR_CONF_POINTER("cache", PW_TYPE_SUBSECTION, NULL), .subcs = (void const *) cache_config },

	{ FR_CONF_POINTER("verify", PW_TYPE_SUBSECTION, NULL), .subcs = (void const *) verify_config },

#ifdef HAVE_OPENSSL_OCSP_H
	{ FR_CONF_OFFSET("ocsp", PW_TYPE_SUBSECTION, fr_tls_conf_t, ocsp), .subcs = (void const *) ocsp_config },

	{ FR_CONF_OFFSET("staple", PW_TYPE_SUBSECTION, fr_tls_conf_t, staple), .subcs = (void const *) ocsp_config },
#endif
	CONF_PARSER_TERMINATOR
};

static CONF_PARSER tls_client_config[] = {
	{ FR_CONF_OFFSET("verify_depth", PW_TYPE_INTEGER, fr_tls_conf_t, verify_depth), .dflt = "0" },
	{ FR_CONF_OFFSET("ca_path", PW_TYPE_FILE_INPUT, fr_tls_conf_t, ca_path) },
	{ FR_CONF_OFFSET("pem_file_type", PW_TYPE_BOOLEAN, fr_tls_conf_t, file_type), .dflt = "yes" },
	{ FR_CONF_OFFSET("private_key_file", PW_TYPE_FILE_INPUT, fr_tls_conf_t, private_key_file) },
	{ FR_CONF_OFFSET("certificate_file", PW_TYPE_FILE_INPUT, fr_tls_conf_t, certificate_file) },
	{ FR_CONF_OFFSET("ca_file", PW_TYPE_FILE_INPUT, fr_tls_conf_t, ca_file) },
	{ FR_CONF_OFFSET("private_key_password", PW_TYPE_STRING | PW_TYPE_SECRET, fr_tls_conf_t, private_key_password) },
	{ FR_CONF_OFFSET("dh_file", PW_TYPE_STRING, fr_tls_conf_t, dh_file) },
	{ FR_CONF_OFFSET("random_file", PW_TYPE_STRING, fr_tls_conf_t, random_file) },
	{ FR_CONF_OFFSET("fragment_size", PW_TYPE_INTEGER, fr_tls_conf_t, fragment_size), .dflt = "1024" },
	{ FR_CONF_OFFSET("check_crl", PW_TYPE_BOOLEAN, fr_tls_conf_t, check_crl), .dflt = "no" },
	{ FR_CONF_OFFSET("check_cert_cn", PW_TYPE_STRING, fr_tls_conf_t, check_cert_cn) },
	{ FR_CONF_OFFSET("cipher_list", PW_TYPE_STRING, fr_tls_conf_t, cipher_list) },
	{ FR_CONF_OFFSET("check_cert_issuer", PW_TYPE_STRING, fr_tls_conf_t, check_cert_issuer) },

#if OPENSSL_VERSION_NUMBER >= 0x0090800fL
#ifndef OPENSSL_NO_ECDH
	{ FR_CONF_OFFSET("ecdh_curve", PW_TYPE_STRING, fr_tls_conf_t, ecdh_curve), .dflt = "prime256v1" },
#endif
#endif

#ifdef SSL_OP_NO_TLSv1
	{ FR_CONF_OFFSET("disable_tlsv1", PW_TYPE_BOOLEAN, fr_tls_conf_t, disable_tlsv1) },
#endif

#ifdef SSL_OP_NO_TLSv1_1
	{ FR_CONF_OFFSET("disable_tlsv1_1", PW_TYPE_BOOLEAN, fr_tls_conf_t, disable_tlsv1_1) },
#endif

#ifdef SSL_OP_NO_TLSv1_2
	{ FR_CONF_OFFSET("disable_tlsv1_2", PW_TYPE_BOOLEAN, fr_tls_conf_t, disable_tlsv1_2) },
#endif
	CONF_PARSER_TERMINATOR
};

#ifdef __APPLE__
/** Use cert_admin to retrieve the password for the private key
 *
 */
static int conf_cert_admin_password(fr_tls_conf_t *conf)
{
	if (!conf->private_key_password) return 0;

	/*
	 *	We don't want to put the private key password in eap.conf, so check
	 *	for our special string which indicates we should get the password
	 *	programmatically.
	 */
	char const *special_string = "Apple:UsecertAdmin";
	if (strncmp(conf->private_key_password, special_string, strlen(special_string)) == 0) {
		char cmd[256];
		char *password;
		long const max_password_len = 128;
		FILE *cmd_pipe;

		snprintf(cmd, sizeof(cmd) - 1, "/usr/sbin/certadmin --get-private-key-passphrase \"%s\"",
			 conf->private_key_file);

		DEBUG2("Getting private key passphrase using command \"%s\"", cmd);

		cmd_pipe = popen(cmd, "r");
		if (!cmd_pipe) {
			ERROR("%s command failed: Unable to get private_key_password", cmd);
			ERROR("Error reading private_key_file %s", conf->private_key_file);
			return -1;
		}

		rad_const_free(conf->private_key_password);
		password = talloc_array(conf, char, max_password_len);
		if (!password) {
			ERROR("Can't allocate space for private_key_password");
			ERROR("Error reading private_key_file %s", conf->private_key_file);
			pclose(cmd_pipe);
			return -1;
		}

		fgets(password, max_password_len, cmd_pipe);
		pclose(cmd_pipe);

		/* Get rid of newline at end of password. */
		password[strlen(password) - 1] = '\0';

		DEBUG3("Password from command = \"%s\"", password);
		conf->private_key_password = password;
	}

	return 0;
}
#endif

/*
 *	Configure a X509 CA store to verify OCSP or client repsonses
 *
 * 	- Load the trusted CAs
 * 	- Load the trusted issuer certificates
 *	- Configure CRLs check if needed
 */
X509_STORE *tls_conf_init_x509_store(fr_tls_conf_t const *conf)
{
	X509_STORE *store = NULL;

	store = X509_STORE_new();
	if (store == NULL) return NULL;

	/* Load the CAs we trust */
	if (conf->ca_file || conf->ca_path)
		if (!X509_STORE_load_locations(store, conf->ca_file, conf->ca_path)) {
			tls_log_error(NULL, "Error reading Trusted root CA list \"%s\"", conf->ca_file);
			return NULL;
		}

#ifdef X509_V_FLAG_CRL_CHECK_ALL
	if (conf->check_crl) X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
#endif

	return store;
}

/*
 *	Free TLS client/server config
 *	Should not be called outside this code, as a callback is
 *	added to automatically free the data when the CONF_SECTION
 *	is freed.
 */
static int _conf_server_free(fr_tls_conf_t *conf)
{
	uint32_t i;

	for (i = 0; i < conf->ctx_count; i++) {
		SSL_CTX_free(conf->ctx_pool[i].ctx);
		pthread_mutex_destroy(&conf->ctx_pool[i].mtx);
	}

#ifdef HAVE_OPENSSL_OCSP_H
	if (conf->ocsp.store) X509_STORE_free(conf->ocsp.store);
	conf->ocsp.store = NULL;
	if (conf->staple.store) X509_STORE_free(conf->staple.store);
	conf->staple.store = NULL;
#endif

#ifndef NDEBUG
	memset(conf, 0, sizeof(*conf));
#endif
	return 0;
}

static fr_tls_conf_t *conf_alloc(TALLOC_CTX *ctx)
{
	fr_tls_conf_t *conf;

	conf = talloc_zero(ctx, fr_tls_conf_t);
	if (!conf) {
		ERROR("Out of memory");
		return NULL;
	}

	talloc_set_destructor(conf, _conf_server_free);

	return conf;
}

fr_tls_conf_t *tls_conf_parse_server(CONF_SECTION *cs)
{
	fr_tls_conf_t *conf;
	uint32_t i;
	time_t now;

	/*
	 *	If cs has already been parsed there should be a cached copy
	 *	of conf already stored, so just return that.
	 */
	conf = cf_data_find(cs, "tls-conf");
	if (conf) {
		DEBUG("Using cached TLS configuration from previous invocation");
		return conf;
	}

	conf = conf_alloc(cs);

	if (cf_section_parse(cs, conf, tls_server_config) < 0) {
	error:
		talloc_free(conf);
		return NULL;
	}

	/*
	 *	Save people from their own stupidity.
	 */
	if (conf->fragment_size < 100) conf->fragment_size = 100;

	/*
	 *	Setup session caching
	 */
	if (conf->session_cache_server) {
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
	}

#ifdef __APPLE__
	if (conf_cert_admin_password(conf) < 0) goto error;
#endif

	if (!main_config.spawn_workers) {
		conf->ctx_count = 1;
	} else {
		conf->ctx_count = fr_tls_max_threads * 2; /* Reduce contention */
		rad_assert(conf->ctx_count > 0);
	}

	/*
	 *	Initialize TLS
	 */
	now = time(NULL);
	conf->ctx_pool = talloc_array(conf, ssl_ctx_pool_t, conf->ctx_count);
	for (i = 0; i < conf->ctx_count; i++) {
		conf->ctx_pool[i].ctx = tls_ctx_alloc(conf, false);
		if (conf->ctx_pool[i].ctx == NULL) goto error;
		conf->ctx_pool[i].ca_path_last_reload = now;
		conf->ctx_pool[i].old_x509_store = NULL;
	}

	/*
	 * Disable reloading of cert store if we're not using CA path
	 */
	if (!conf->ca_path) conf->ca_path_reload_interval = 0;

	if (conf->ca_path_reload_interval > 0)
		FR_INTEGER_BOUND_CHECK("ca_path_reload_interval", conf->ca_path_reload_interval, >=, 300);

#ifdef HAVE_OPENSSL_OCSP_H
	/*
	 *	@fixme:  This is all pretty terrible.
	 *	The stores initialized here are for validating
	 *	OCSP responses.  They have nothing to do with
	 *	verifying other certificates.
	 */

	/*
	 * 	Initialize OCSP Revocation Store
	 */
	if (conf->ocsp.enable) {
		conf->ocsp.store = tls_conf_init_x509_store(conf);
		if (conf->ocsp.store == NULL) goto error;
	}

	if (conf->staple.enable) {
		conf->staple.store = tls_conf_init_x509_store(conf);
		if (conf->staple.store == NULL) goto error;
	}
#endif /*HAVE_OPENSSL_OCSP_H*/

	if (conf->verify_tmp_dir) {
		if (chmod(conf->verify_tmp_dir, S_IRWXU) < 0) {
			ERROR("Failed changing permissions on %s: %s",
			      conf->verify_tmp_dir, fr_syserror(errno));
			goto error;
		}
	}

	if (conf->verify_client_cert_cmd && !conf->verify_tmp_dir) {
		ERROR("You MUST set the verify directory in order to use verify_client_cmd");
		goto error;
	}

	if (conf->session_cache_server &&
	    !cf_section_sub_find_name2(main_config.config, "server", conf->session_cache_server)) {
		ERROR("No such virtual server '%s'", conf->session_cache_server);
		goto error;
	}

	if (conf->ocsp.cache_server &&
	    !cf_section_sub_find_name2(main_config.config, "server", conf->ocsp.cache_server)) {
		ERROR("No such virtual server '%s'", conf->ocsp.cache_server);
		goto error;
	}

	if (conf->staple.cache_server &&
	    !cf_section_sub_find_name2(main_config.config, "server", conf->staple.cache_server)) {
		ERROR("No such virtual server '%s'", conf->staple.cache_server);
		goto error;
	}

#ifdef SSL_OP_NO_TLSv1_2
	/*
	 *	OpenSSL 1.0.1f and 1.0.1g get the MS-MPPE keys wrong.
	 */
#if (OPENSSL_VERSION_NUMBER >= 0x10010060L) && (OPENSSL_VERSION_NUMBER < 0x10010060L)
	conf->disable_tlsv1_2 = true;
	WARN("OpenSSL version in range 1.0.1f-1.0.1g. "
	     "TLSv1.2 disabled to workaround broken keying material export");
#endif
#endif

	/*
	 *	Cache conf in cs in case we're asked to parse this again.
	 */
	cf_data_add(cs, "tls-conf", conf, NULL);

	return conf;
}

fr_tls_conf_t *tls_conf_parse_client(CONF_SECTION *cs)
{
	fr_tls_conf_t *conf;
	uint32_t i;

	conf = cf_data_find(cs, "tls-conf");
	if (conf) {
		DEBUG2("Using cached TLS configuration from previous invocation");
		return conf;
	}

	conf = conf_alloc(cs);

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
	if (!main_config.spawn_workers) {
		conf->ctx_count = 1;
	} else {
		conf->ctx_count = fr_tls_max_threads * 2; /* Even one context per thread will lead to contention */
		rad_assert(conf->ctx_count > 0);
	}

#ifdef __APPLE__
	if (conf_cert_admin_password(conf) < 0) goto error;
#endif

	conf->ctx_pool = talloc_array(conf, ssl_ctx_pool_t, conf->ctx_count);
	for (i = 0; i < conf->ctx_count; i++) {
		conf->ctx_pool[i].ctx = tls_ctx_alloc(conf, true);
		if (conf->ctx_pool[i].ctx == NULL) goto error;
		pthread_mutex_init(&conf->ctx_pool[i].mtx, NULL);
	}

	cf_data_add(cs, "tls-conf", conf, NULL);

	return conf;
}
#endif	/* WITH_TLS */
