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
 * @copyright 2001 hereUare Communications, Inc. (raghud@hereuare.com)
 * @copyright 2003 Alan DeKok (aland@freeradius.org)
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

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/rad_assert.h>
#include <freeradius-devel/util/syserror.h>

#include "base.h"
#include "missing.h"

/** Certificate formats
 *
 */
static fr_table_num_sorted_t const certificate_format_table[] = {
	{ "ASN1",	SSL_FILETYPE_ASN1	},
	{ "DER",	SSL_FILETYPE_ASN1	},	/* Alternate name for ASN1 */
	{ "PEM",	SSL_FILETYPE_PEM	}
};
static size_t certificate_format_table_len = NUM_ELEMENTS(certificate_format_table);

static fr_table_num_sorted_t const chain_verify_mode_table[] = {
	{ "hard",	FR_TLS_CHAIN_VERIFY_HARD },
	{ "none",	FR_TLS_CHAIN_VERIFY_NONE },
	{ "soft",	FR_TLS_CHAIN_VERIFY_SOFT }
};
static size_t chain_verify_mode_table_len = NUM_ELEMENTS(chain_verify_mode_table);

static int chain_verify_mode_parse(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent,
				   CONF_ITEM *ci, UNUSED CONF_PARSER const *rule);
static int certificate_format_type_parse(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent,
					 CONF_ITEM *ci, UNUSED CONF_PARSER const *rule);

static CONF_PARSER cache_config[] = {
	{ FR_CONF_OFFSET("virtual_server", FR_TYPE_STRING, fr_tls_conf_t, session_cache_server) },
	{ FR_CONF_OFFSET("name", FR_TYPE_TMPL, fr_tls_conf_t, session_id_name),
			 .dflt = "%{EAP-Type}%{Virtual-Server}", .quote = T_DOUBLE_QUOTED_STRING },
	{ FR_CONF_OFFSET("lifetime", FR_TYPE_UINT32, fr_tls_conf_t, session_cache_lifetime), .dflt = "86400" },
	{ FR_CONF_OFFSET("verify", FR_TYPE_BOOL, fr_tls_conf_t, session_cache_verify), .dflt = "no" },

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	{ FR_CONF_OFFSET("require_extended_master_secret", FR_TYPE_BOOL, fr_tls_conf_t, session_cache_require_extms), .dflt = "yes" },
	{ FR_CONF_OFFSET("require_perfect_forward_secrecy", FR_TYPE_BOOL, fr_tls_conf_t, session_cache_require_pfs), .dflt = "no" },
#endif

	{ FR_CONF_DEPRECATED("enable", FR_TYPE_BOOL, fr_tls_conf_t, NULL) },
	{ FR_CONF_DEPRECATED("max_entries", FR_TYPE_UINT32, fr_tls_conf_t, NULL) },
	{ FR_CONF_DEPRECATED("persist_dir", FR_TYPE_STRING, fr_tls_conf_t, NULL) },

	CONF_PARSER_TERMINATOR
};

static CONF_PARSER verify_config[] = {
	{ FR_CONF_OFFSET("tmpdir", FR_TYPE_STRING, fr_tls_conf_t, verify_tmp_dir) },
	{ FR_CONF_OFFSET("client", FR_TYPE_STRING, fr_tls_conf_t, verify_client_cert_cmd) },
	CONF_PARSER_TERMINATOR
};

#ifdef HAVE_OPENSSL_OCSP_H
static CONF_PARSER ocsp_config[] = {
	{ FR_CONF_OFFSET("enable", FR_TYPE_BOOL, fr_tls_ocsp_conf_t, enable), .dflt = "no" },

	{ FR_CONF_OFFSET("virtual_server", FR_TYPE_STRING, fr_tls_ocsp_conf_t, cache_server) },

	{ FR_CONF_OFFSET("override_cert_url", FR_TYPE_BOOL, fr_tls_ocsp_conf_t, override_url), .dflt = "no" },
	{ FR_CONF_OFFSET("url", FR_TYPE_STRING, fr_tls_ocsp_conf_t, url) },
	{ FR_CONF_OFFSET("use_nonce", FR_TYPE_BOOL, fr_tls_ocsp_conf_t, use_nonce), .dflt = "yes" },
	{ FR_CONF_OFFSET("timeout", FR_TYPE_UINT32, fr_tls_ocsp_conf_t, timeout), .dflt = "yes" },
	{ FR_CONF_OFFSET("softfail", FR_TYPE_BOOL, fr_tls_ocsp_conf_t, softfail), .dflt = "no" },

	CONF_PARSER_TERMINATOR
};
#endif

static CONF_PARSER tls_chain_config[] = {
	{ FR_CONF_OFFSET("format", FR_TYPE_VOID, fr_tls_chain_conf_t, file_format), .dflt = "pem", .func = certificate_format_type_parse },
	{ FR_CONF_OFFSET("certificate_file", FR_TYPE_FILE_INPUT | FR_TYPE_REQUIRED , fr_tls_chain_conf_t, certificate_file) },
	{ FR_CONF_OFFSET("private_key_password", FR_TYPE_STRING | FR_TYPE_SECRET, fr_tls_chain_conf_t, password) },
	{ FR_CONF_OFFSET("private_key_file", FR_TYPE_FILE_INPUT | FR_TYPE_REQUIRED, fr_tls_chain_conf_t, private_key_file) },

	{ FR_CONF_OFFSET("ca_file", FR_TYPE_FILE_INPUT | FR_TYPE_MULTI, fr_tls_chain_conf_t, ca_files) },

	{ FR_CONF_OFFSET("verify_mode", FR_TYPE_VOID, fr_tls_chain_conf_t, verify_mode), .dflt = "hard", .func = chain_verify_mode_parse },
	{ FR_CONF_OFFSET("include_root_ca", FR_TYPE_BOOL, fr_tls_chain_conf_t, include_root_ca), .dflt = "no" },
	CONF_PARSER_TERMINATOR
};

CONF_PARSER fr_tls_server_config[] = {
	{ FR_CONF_OFFSET("auto_chain", FR_TYPE_BOOL, fr_tls_conf_t, auto_chain), .dflt = "yes" },

	{ FR_CONF_OFFSET("chain", FR_TYPE_SUBSECTION | FR_TYPE_MULTI, fr_tls_conf_t, chains),
	  .subcs_size = sizeof(fr_tls_chain_conf_t), .subcs_type = "fr_tls_chain_conf_t",
	  .subcs = tls_chain_config, .ident2 = CF_IDENT_ANY },

	{ FR_CONF_DEPRECATED("pem_file_type", FR_TYPE_BOOL, fr_tls_conf_t, NULL) },
	{ FR_CONF_DEPRECATED("certificate_file", FR_TYPE_FILE_INPUT, fr_tls_conf_t, NULL) },
	{ FR_CONF_DEPRECATED("private_key_password", FR_TYPE_STRING | FR_TYPE_SECRET, fr_tls_conf_t, NULL) },
	{ FR_CONF_DEPRECATED("private_key_file", FR_TYPE_FILE_INPUT, fr_tls_conf_t, NULL) },

	{ FR_CONF_OFFSET("verify_depth", FR_TYPE_UINT32, fr_tls_conf_t, verify_depth), .dflt = "0" },
	{ FR_CONF_OFFSET("ca_path", FR_TYPE_FILE_INPUT, fr_tls_conf_t, ca_path) },
	{ FR_CONF_OFFSET("ca_file", FR_TYPE_FILE_INPUT, fr_tls_conf_t, ca_file) },
#ifdef PSK_MAX_IDENTITY_LEN
	{ FR_CONF_OFFSET("psk_identity", FR_TYPE_STRING, fr_tls_conf_t, psk_identity) },
	{ FR_CONF_OFFSET("psk_hexphrase", FR_TYPE_STRING | FR_TYPE_SECRET, fr_tls_conf_t, psk_password) },
	{ FR_CONF_OFFSET("psk_query", FR_TYPE_STRING, fr_tls_conf_t, psk_query) },
#endif
	{ FR_CONF_OFFSET("dh_file", FR_TYPE_FILE_INPUT, fr_tls_conf_t, dh_file) },
	{ FR_CONF_OFFSET("fragment_size", FR_TYPE_UINT32, fr_tls_conf_t, fragment_size), .dflt = "1024" },

	{ FR_CONF_OFFSET("disable_single_dh_use", FR_TYPE_BOOL, fr_tls_conf_t, disable_single_dh_use) },
	{ FR_CONF_OFFSET("check_crl", FR_TYPE_BOOL, fr_tls_conf_t, check_crl), .dflt = "no" },
#ifdef X509_V_FLAG_CRL_CHECK_ALL
	{ FR_CONF_DEPRECATED("check_all_crl", FR_TYPE_BOOL, fr_tls_conf_t, NULL) },
#endif
	{ FR_CONF_OFFSET("allow_expired_crl", FR_TYPE_BOOL, fr_tls_conf_t, allow_expired_crl) },
	{ FR_CONF_OFFSET("check_cert_cn", FR_TYPE_STRING, fr_tls_conf_t, check_cert_cn) },
	{ FR_CONF_OFFSET("cipher_list", FR_TYPE_STRING, fr_tls_conf_t, cipher_list) },
	{ FR_CONF_OFFSET("cipher_server_preference", FR_TYPE_BOOL, fr_tls_conf_t, cipher_server_preference), .dflt = "yes" },
#ifdef SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS
	{ FR_CONF_OFFSET("allow_renegotiation", FR_TYPE_BOOL, fr_tls_conf_t, allow_renegotiation), .dflt = "no" },
#endif
	{ FR_CONF_OFFSET("check_cert_issuer", FR_TYPE_STRING, fr_tls_conf_t, check_cert_issuer) },
	{ FR_CONF_OFFSET("require_client_cert", FR_TYPE_BOOL, fr_tls_conf_t, require_client_cert) },

#ifndef OPENSSL_NO_ECDH
	{ FR_CONF_OFFSET("ecdh_curve", FR_TYPE_STRING, fr_tls_conf_t, ecdh_curve), .dflt = "prime256v1" },
#endif
	{ FR_CONF_OFFSET("tls_max_version", FR_TYPE_FLOAT32, fr_tls_conf_t, tls_max_version) },

	{ FR_CONF_OFFSET("tls_min_version", FR_TYPE_FLOAT32, fr_tls_conf_t, tls_min_version), .dflt = "1.2" },

	{ FR_CONF_POINTER("cache", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) cache_config },

	{ FR_CONF_POINTER("verify", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) verify_config },

#ifdef HAVE_OPENSSL_OCSP_H
	{ FR_CONF_OFFSET("ocsp", FR_TYPE_SUBSECTION, fr_tls_conf_t, ocsp), .subcs = (void const *) ocsp_config },

	{ FR_CONF_OFFSET("staple", FR_TYPE_SUBSECTION, fr_tls_conf_t, staple), .subcs = (void const *) ocsp_config },
#endif
	CONF_PARSER_TERMINATOR
};

CONF_PARSER fr_tls_client_config[] = {
	{ FR_CONF_OFFSET("chain", FR_TYPE_SUBSECTION | FR_TYPE_MULTI, fr_tls_conf_t, chains),
	  .subcs_size = sizeof(fr_tls_chain_conf_t), .subcs_type = "fr_tls_chain_conf_t",
	  .subcs = tls_chain_config },

	{ FR_CONF_DEPRECATED("pem_file_type", FR_TYPE_BOOL, fr_tls_conf_t, NULL) },
	{ FR_CONF_DEPRECATED("certificate_file", FR_TYPE_FILE_INPUT, fr_tls_conf_t, NULL) },
	{ FR_CONF_DEPRECATED("private_key_password", FR_TYPE_STRING | FR_TYPE_SECRET, fr_tls_conf_t, NULL) },
	{ FR_CONF_DEPRECATED("private_key_file", FR_TYPE_FILE_INPUT, fr_tls_conf_t, NULL) },

	{ FR_CONF_OFFSET("verify_depth", FR_TYPE_UINT32, fr_tls_conf_t, verify_depth), .dflt = "0" },
	{ FR_CONF_OFFSET("ca_path", FR_TYPE_FILE_INPUT, fr_tls_conf_t, ca_path) },

	{ FR_CONF_OFFSET("ca_file", FR_TYPE_FILE_INPUT, fr_tls_conf_t, ca_file) },
	{ FR_CONF_OFFSET("dh_file", FR_TYPE_STRING, fr_tls_conf_t, dh_file) },
	{ FR_CONF_OFFSET("random_file", FR_TYPE_STRING, fr_tls_conf_t, random_file) },
	{ FR_CONF_OFFSET("fragment_size", FR_TYPE_UINT32, fr_tls_conf_t, fragment_size), .dflt = "1024" },
	{ FR_CONF_OFFSET("check_crl", FR_TYPE_BOOL, fr_tls_conf_t, check_crl), .dflt = "no" },
	{ FR_CONF_OFFSET("check_cert_cn", FR_TYPE_STRING, fr_tls_conf_t, check_cert_cn) },
	{ FR_CONF_OFFSET("cipher_list", FR_TYPE_STRING, fr_tls_conf_t, cipher_list) },
	{ FR_CONF_OFFSET("check_cert_issuer", FR_TYPE_STRING, fr_tls_conf_t, check_cert_issuer) },

#ifndef OPENSSL_NO_ECDH
	{ FR_CONF_OFFSET("ecdh_curve", FR_TYPE_STRING, fr_tls_conf_t, ecdh_curve), .dflt = "prime256v1" },
#endif

	{ FR_CONF_OFFSET("tls_max_version", FR_TYPE_FLOAT32, fr_tls_conf_t, tls_max_version) },

	{ FR_CONF_OFFSET("tls_min_version", FR_TYPE_FLOAT32, fr_tls_conf_t, tls_min_version), .dflt = "1.2" },

	CONF_PARSER_TERMINATOR
};

/** Calls to convert verify_mode strings into macros
 *
 * @param[in] ctx	to allocate data in.
 * @param[out] out	the verify_mode macro representing the mode.
 * @param[in] ci	#CONF_PAIR specifying the name of the mode.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int chain_verify_mode_parse(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent,
				   CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	fr_tls_chain_verify_mode_t	type;
	char const			*type_str;

	type_str = cf_pair_value(cf_item_to_pair(ci));
	type = fr_table_value_by_str(chain_verify_mode_table, type_str, 0);
	if (type == 0) {
		cf_log_err(ci, "Invalid mode \"%s\", expected 'hard', 'soft' or 'none'", type_str);
		return -1;
	}

	*((int *)out) = type;

	return 0;
}

/** Calls to convert format strings to OpenSSL macros
 *
 * @param[in] ctx	to allocate data in.
 * @param[out] out	the OpenSSL macro representing the format.
 * @param[in] ci	#CONF_PAIR specifying the name of the format.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int certificate_format_type_parse(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent,
					 CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	int		type;
	char const	*type_str;

	type_str = cf_pair_value(cf_item_to_pair(ci));
	type = fr_table_value_by_str(certificate_format_table, type_str, -1);
	if (type == -1) {
		cf_log_err(ci, "Invalid format \"%s\", expected either 'PEM' or 'ASN1'", type_str);
		return -1;
	}

	*((int *)out) = type;

	return 0;
}

#ifdef __APPLE__
/*
 *	We don't want to put the private key password in eap.conf, so check
 *	for our special string which indicates we should get the password
 *	programmatically.
 */
static char const *special_string = "Apple:UsecertAdmin";

/** Use cert_admin to retrieve the password for the private key
 *
 */
static int conf_cert_admin_password(fr_tls_conf_t *conf)
{
	size_t i, cnt;

	if (!conf->chains) return 0;

	cnt = talloc_array_length(conf->chains);
	for (i = 0; i < cnt; i++) {
		char		cmd[256];
		char		*password;
		long const	max_password_len = 128;
		FILE		*cmd_pipe;

		if (!conf->chains[i]->password) continue;

		if (strncmp(conf->chains[i]->password, special_string, strlen(special_string)) != 0) continue;

		snprintf(cmd, sizeof(cmd) - 1, "/usr/sbin/certadmin --get-private-key-passphrase \"%s\"",
			 conf->chains[i]->private_key_file);

		DEBUG2("Getting private key passphrase using command \"%s\"", cmd);

		cmd_pipe = popen(cmd, "r");
		if (!cmd_pipe) {
			ERROR("%s command failed: Unable to get private_key_password", cmd);
			ERROR("Error reading private_key_file %s", conf->chains[i]->private_key_file);
			return -1;
		}

		password = talloc_array(conf, char, max_password_len);
		if (!password) {
			ERROR("Can't allocate space for private_key_password");
			ERROR("Error reading private_key_file %s", conf->chains[i]->private_key_file);
			pclose(cmd_pipe);
			return -1;
		}

		fgets(password, max_password_len, cmd_pipe);
		pclose(cmd_pipe);

		/* Get rid of newline at end of password. */
		password[strlen(password) - 1] = '\0';

		DEBUG3("Password from command = \"%s\"", password);
		talloc_const_free(conf->chains[i]->password);
		conf->chains[i]->password = password;
	}

	return 0;
}
#endif

#ifdef HAVE_OPENSSL_OCSP_H
/*
 * 	Create Global X509 revocation store and use it to verify
 * 	OCSP responses
 *
 * 	- Load the trusted CAs
 * 	- Load the trusted issuer certificates
 */
static X509_STORE *conf_ocsp_revocation_store(fr_tls_conf_t *conf)
{
	X509_STORE *store = NULL;

	store = X509_STORE_new();

	/* Load the CAs we trust */
	if (conf->ca_file || conf->ca_path)
		if (!X509_STORE_load_locations(store, conf->ca_file, conf->ca_path)) {
			fr_tls_log_error(NULL, "Error reading Trusted root CA list \"%s\"", conf->ca_file);
			return NULL;
		}

#ifdef X509_V_FLAG_CRL_CHECK_ALL
	if (conf->check_crl) X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
#endif

	return store;
}
#endif

/*
 *	Free TLS client/server config
 *	Should not be called outside this code, as a callback is
 *	added to automatically free the data when the CONF_SECTION
 *	is freed.
 */
static int _conf_server_free(fr_tls_conf_t *conf)
{
	uint32_t i;

	for (i = 0; i < conf->ctx_count; i++) SSL_CTX_free(conf->ctx[i]);

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

fr_tls_conf_t *fr_tls_conf_alloc(TALLOC_CTX *ctx)
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

fr_tls_conf_t *fr_tls_conf_parse_server(CONF_SECTION *cs)
{
	fr_tls_conf_t *conf;
	uint32_t i;

	/*
	 *	If cs has already been parsed there should be a cached copy
	 *	of conf already stored, so just return that.
	 */
	conf = cf_data_value(cf_data_find(cs, fr_tls_conf_t, NULL));
	if (conf) {
		DEBUG("Using cached TLS configuration from previous invocation");
		return conf;
	}

	if (cf_section_rules_push(cs, fr_tls_server_config) < 0) return NULL;

	conf = fr_tls_conf_alloc(cs);

	if ((cf_section_parse(conf, conf, cs) < 0) ||
	    (cf_section_parse_pass2(conf, cs) < 0)) {
	error:
		talloc_free(conf);
		return NULL;
	}

	/*
	 *	Save people from their own stupidity.
	 */
	if (conf->fragment_size < 100) conf->fragment_size = 100;

#ifdef __APPLE__
	if (conf_cert_admin_password(conf) < 0) goto error;
#endif

	conf->ctx_count = fr_tls_max_threads * 2; /* Reduce contention */
	if (!conf->ctx_count) conf->ctx_count = 1;

	/*
	 *	Initialize TLS
	 */
	conf->ctx = talloc_zero_array(conf, SSL_CTX *, conf->ctx_count);
	for (i = 0; i < conf->ctx_count; i++) {
		conf->ctx[i] = fr_tls_ctx_alloc(conf, false);
		if (conf->ctx[i] == NULL) goto error;
	}

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
		conf->ocsp.store = conf_ocsp_revocation_store(conf);
		if (conf->ocsp.store == NULL) goto error;
	}

	if (conf->staple.enable) {
		conf->staple.store = conf_ocsp_revocation_store(conf);
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

	if (conf->session_cache_server) {
		CONF_SECTION *server_cs;

		server_cs = virtual_server_find(conf->session_cache_server);
		if (!server_cs) {
			ERROR("No such virtual server '%s'", conf->session_cache_server);
			goto error;
		}

		if (fr_tls_cache_compile(&conf->session_cache, server_cs) < 0) goto error;
	}

	if (conf->ocsp.cache_server) {
		CONF_SECTION *server_cs;

		server_cs = virtual_server_find(conf->ocsp.cache_server);
		if (!server_cs) {
			ERROR("No such virtual server '%s'", conf->ocsp.cache_server);
			goto error;
		}

		if (fr_tls_ocsp_state_cache_compile(&conf->ocsp.cache, server_cs) < 0) goto error;
	}

	if (conf->staple.cache_server) {
		CONF_SECTION *server_cs;

		server_cs = virtual_server_find(conf->staple.cache_server);
		if (!server_cs) {
			ERROR("No such virtual server '%s'", conf->staple.cache_server);
			goto error;
		}

		if (fr_tls_ocsp_staple_cache_compile(&conf->staple.cache, server_cs) < 0) goto error;
	}

	/*
	 *	Cache conf in cs in case we're asked to parse this again.
	 */
	cf_data_add(cs, conf, NULL, false);

	return conf;
}

fr_tls_conf_t *fr_tls_conf_parse_client(CONF_SECTION *cs)
{
	fr_tls_conf_t *conf;
	uint32_t i;

	conf = cf_data_value(cf_data_find(cs, fr_tls_conf_t, NULL));
	if (conf) {
		DEBUG2("Using cached TLS configuration from previous invocation");
		return conf;
	}

	if (cf_section_rules_push(cs, fr_tls_client_config) < 0) return NULL;

	conf = fr_tls_conf_alloc(cs);

	if ((cf_section_parse(conf, conf, cs) < 0) ||
	    (cf_section_parse_pass2(conf, cs) < 0)) {
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
	conf->ctx_count = fr_tls_max_threads * 2; /* Even one context per thread will lead to contention */
	if (!conf->ctx_count) conf->ctx_count = 1;

#ifdef __APPLE__
	if (conf_cert_admin_password(conf) < 0) goto error;
#endif

	conf->ctx = talloc_array(conf, SSL_CTX *, conf->ctx_count);
	for (i = 0; i < conf->ctx_count; i++) {
		conf->ctx[i] = fr_tls_ctx_alloc(conf, true);
		if (conf->ctx[i] == NULL) goto error;
	}

	cf_data_add(cs, conf, NULL, false);

	return conf;
}
#endif	/* WITH_TLS */
