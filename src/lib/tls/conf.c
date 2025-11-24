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
#define LOG_PREFIX "tls"

#ifdef HAVE_SYS_STAT_H
#  include <sys/stat.h>
#endif
#include <openssl/conf.h>

#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/virtual_servers.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/util/rand.h>

#include "base.h"
#include "log.h"

static int tls_conf_parse_cache_mode(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, conf_parser_t const *rule);
static int tls_virtual_server_cf_parse(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, conf_parser_t const *rule);

/** Certificate formats
 *
 */
static fr_table_num_sorted_t const certificate_format_table[] = {
	{ L("ASN1"),			SSL_FILETYPE_ASN1			},
	{ L("DER"),			SSL_FILETYPE_ASN1			},	/* Alternate name for ASN1 */
	{ L("PEM"),			SSL_FILETYPE_PEM			}
};
static size_t certificate_format_table_len = NUM_ELEMENTS(certificate_format_table);

static fr_table_num_sorted_t const chain_verify_mode_table[] = {
	{ L("hard"),			FR_TLS_CHAIN_VERIFY_HARD		},
	{ L("none"),			FR_TLS_CHAIN_VERIFY_NONE		},
	{ L("soft"),			FR_TLS_CHAIN_VERIFY_SOFT		}
};
static size_t chain_verify_mode_table_len = NUM_ELEMENTS(chain_verify_mode_table);

static fr_table_num_sorted_t const cache_mode_table[] = {
	{ L("auto"),			FR_TLS_CACHE_AUTO			},
	{ L("disabled"),		FR_TLS_CACHE_DISABLED			},
	{ L("stateful"),		FR_TLS_CACHE_STATEFUL			},
	{ L("stateless"),		FR_TLS_CACHE_STATELESS			}
};
static size_t cache_mode_table_len = NUM_ELEMENTS(cache_mode_table);

static fr_table_num_sorted_t const verify_mode_table[] = {
	{ L("all"),			FR_TLS_VERIFY_MODE_ALL		},
	{ L("client"),			FR_TLS_VERIFY_MODE_LEAF		},
	{ L("client-and-issuer"),	FR_TLS_VERIFY_MODE_LEAF | FR_TLS_VERIFY_MODE_ISSUER },
	{ L("disabled"),		FR_TLS_VERIFY_MODE_DISABLED	},
	{ L("untrusted"),		FR_TLS_VERIFY_MODE_UNTRUSTED	}
};
static size_t verify_mode_table_len = NUM_ELEMENTS(verify_mode_table);

static conf_parser_t tls_cache_config[] = {
	{ FR_CONF_OFFSET("mode", fr_tls_cache_conf_t, mode),
			 .func = tls_conf_parse_cache_mode,
			 .uctx = &(cf_table_parse_ctx_t){
			 	.table = cache_mode_table,
			 	.len = &cache_mode_table_len
			 },
			 .dflt = "auto" },
	{ FR_CONF_OFFSET_HINT_TYPE("name", FR_TYPE_STRING, fr_tls_cache_conf_t, id_name),
			 .dflt = "%{EAP-Type}%interpreter('server')", .quote = T_DOUBLE_QUOTED_STRING },
	{ FR_CONF_OFFSET("lifetime", fr_tls_cache_conf_t, lifetime), .dflt = "1d" },

	{ FR_CONF_OFFSET("require_extended_master_secret", fr_tls_cache_conf_t, require_extms), .dflt = "yes" },
	{ FR_CONF_OFFSET("require_perfect_forward_secrecy", fr_tls_cache_conf_t, require_pfs), .dflt = "no" },

	{ FR_CONF_OFFSET("session_ticket_key", fr_tls_cache_conf_t, session_ticket_key) },

	/*
	 *	Deprecated
	 */
	{ FR_CONF_DEPRECATED("enable", fr_tls_cache_conf_t, NULL) },
	{ FR_CONF_DEPRECATED("max_entries", fr_tls_cache_conf_t, NULL) },
	{ FR_CONF_DEPRECATED("persist_dir", fr_tls_cache_conf_t, NULL) },

	CONF_PARSER_TERMINATOR
};

static conf_parser_t tls_chain_config[] = {
	{ FR_CONF_OFFSET("format", fr_tls_chain_conf_t, file_format),
			 .func = cf_table_parse_int,
			 .uctx = &(cf_table_parse_ctx_t){
			 	.table = certificate_format_table,
			 	.len = &certificate_format_table_len
			 },
			 .dflt = "pem" },
	{ FR_CONF_OFFSET_FLAGS("certificate_file", CONF_FLAG_FILE_READABLE | CONF_FLAG_FILE_EXISTS | CONF_FLAG_REQUIRED, fr_tls_chain_conf_t, certificate_file) },
	{ FR_CONF_OFFSET_FLAGS("private_key_password", CONF_FLAG_SECRET, fr_tls_chain_conf_t, password) },
	{ FR_CONF_OFFSET_FLAGS("private_key_file", CONF_FLAG_FILE_READABLE | CONF_FLAG_FILE_EXISTS | CONF_FLAG_REQUIRED, fr_tls_chain_conf_t, private_key_file) },

	{ FR_CONF_OFFSET_FLAGS("ca_file", CONF_FLAG_FILE_READABLE | CONF_FLAG_MULTI, fr_tls_chain_conf_t, ca_files) },

	{ FR_CONF_OFFSET("verify_mode", fr_tls_chain_conf_t, verify_mode),
			 .func = cf_table_parse_int,
			 .uctx = &(cf_table_parse_ctx_t){
			 	.table = chain_verify_mode_table,
			 	.len = &chain_verify_mode_table_len
			 },
			 .dflt = "hard" },
	{ FR_CONF_OFFSET("include_root_ca", fr_tls_chain_conf_t, include_root_ca), .dflt = "no" },
	CONF_PARSER_TERMINATOR
};

static conf_parser_t tls_verify_config[] = {
	{ FR_CONF_OFFSET("mode", fr_tls_verify_conf_t, mode),
			 .func = cf_table_parse_int,
			 .uctx = &(cf_table_parse_ctx_t){
			 	.table = verify_mode_table,
			 	.len = &verify_mode_table_len
			 },
			 .dflt = "all" },
	{ FR_CONF_OFFSET("attribute_mode", fr_tls_verify_conf_t, attribute_mode),
			 .func = cf_table_parse_int,
			 .uctx = &(cf_table_parse_ctx_t){
			 	.table = verify_mode_table,
			 	.len = &verify_mode_table_len
			 },
			 .dflt = "client-and-issuer" },
	{ FR_CONF_OFFSET("check_crl", fr_tls_verify_conf_t, check_crl), .dflt = "no" },
	{ FR_CONF_OFFSET("allow_expired_crl", fr_tls_verify_conf_t, allow_expired_crl) },
	{ FR_CONF_OFFSET("allow_not_yet_valid_crl", fr_tls_verify_conf_t, allow_not_yet_valid_crl) },
	{ FR_CONF_OFFSET("der_decode", fr_tls_verify_conf_t, der_decode) },
	CONF_PARSER_TERMINATOR
};

conf_parser_t fr_tls_server_config[] = {
	{ FR_CONF_OFFSET_TYPE_FLAGS("virtual_server", FR_TYPE_VOID, 0, fr_tls_conf_t, virtual_server), .func = tls_virtual_server_cf_parse },

	{ FR_CONF_OFFSET_SUBSECTION("chain", CONF_FLAG_MULTI, fr_tls_conf_t, chains, tls_chain_config),
	  .subcs_size = sizeof(fr_tls_chain_conf_t), .subcs_type = "fr_tls_chain_conf_t", .name2 = CF_IDENT_ANY },

	{ FR_CONF_DEPRECATED("pem_file_type", fr_tls_conf_t, NULL) },
	{ FR_CONF_DEPRECATED("certificate_file", fr_tls_conf_t, NULL) },
	{ FR_CONF_DEPRECATED("private_key_password", fr_tls_conf_t, NULL) },
	{ FR_CONF_DEPRECATED("private_key_file", fr_tls_conf_t, NULL) },

	{ FR_CONF_OFFSET("verify_depth", fr_tls_conf_t, verify_depth), .dflt = "0" },
	{ FR_CONF_OFFSET_FLAGS("ca_path", CONF_FLAG_FILE_READABLE, fr_tls_conf_t, ca_path) },
	{ FR_CONF_OFFSET_FLAGS("ca_file", CONF_FLAG_FILE_READABLE, fr_tls_conf_t, ca_file) },

#ifdef PSK_MAX_IDENTITY_LEN
	{ FR_CONF_OFFSET("psk_identity", fr_tls_conf_t, psk_identity) },
	{ FR_CONF_OFFSET_FLAGS("psk_hexphrase", CONF_FLAG_SECRET, fr_tls_conf_t, psk_password) },
	{ FR_CONF_OFFSET("psk_query", fr_tls_conf_t, psk_query) },
#endif
	{ FR_CONF_OFFSET("keylog_file", fr_tls_conf_t, keylog_file) },

	{ FR_CONF_OFFSET_FLAGS("dh_file", CONF_FLAG_FILE_READABLE, fr_tls_conf_t, dh_file) },
	{ FR_CONF_OFFSET("fragment_size", fr_tls_conf_t, fragment_size), .dflt = "1024" },
	{ FR_CONF_OFFSET("padding", fr_tls_conf_t, padding_block_size), },

	{ FR_CONF_OFFSET("disable_single_dh_use", fr_tls_conf_t, disable_single_dh_use) },

	{ FR_CONF_OFFSET("cipher_list", fr_tls_conf_t, cipher_list) },
	{ FR_CONF_OFFSET("cipher_server_preference", fr_tls_conf_t, cipher_server_preference), .dflt = "yes" },
#ifdef SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS
	{ FR_CONF_OFFSET("allow_renegotiation", fr_tls_conf_t, allow_renegotiation), .dflt = "no" },
#endif

#ifndef OPENSSL_NO_ECDH
	{ FR_CONF_OFFSET("ecdh_curve", fr_tls_conf_t, ecdh_curve), .dflt = "prime256v1" },
#endif
	{ FR_CONF_OFFSET("tls_max_version", fr_tls_conf_t, tls_max_version) },

	{ FR_CONF_OFFSET("tls_min_version", fr_tls_conf_t, tls_min_version), .dflt = "1.2" },

	{ FR_CONF_OFFSET("client_hello_parse", fr_tls_conf_t, client_hello_parse )},

	{ FR_CONF_OFFSET_SUBSECTION("session", 0, fr_tls_conf_t, cache, tls_cache_config) },

	{ FR_CONF_OFFSET_SUBSECTION("verify", 0, fr_tls_conf_t, verify, tls_verify_config) },

	{ FR_CONF_DEPRECATED("check_cert_issuer", fr_tls_conf_t, check_cert_issuer) },
	{ FR_CONF_DEPRECATED("check_cert_cn", fr_tls_conf_t, check_cert_cn) },
	CONF_PARSER_TERMINATOR
};

conf_parser_t fr_tls_client_config[] = {
	{ FR_CONF_OFFSET_SUBSECTION("chain", CONF_FLAG_OK_MISSING | CONF_FLAG_MULTI, fr_tls_conf_t, chains, tls_chain_config),
	  .subcs_size = sizeof(fr_tls_chain_conf_t), .subcs_type = "fr_tls_chain_conf_t" },

	{ FR_CONF_DEPRECATED("pem_file_type", fr_tls_conf_t, NULL) },
	{ FR_CONF_DEPRECATED("certificate_file", fr_tls_conf_t, NULL) },
	{ FR_CONF_DEPRECATED("private_key_password", fr_tls_conf_t, NULL) },
	{ FR_CONF_DEPRECATED("private_key_file", fr_tls_conf_t, NULL) },

#ifdef PSK_MAX_IDENTITY_LEN
	{ FR_CONF_OFFSET("psk_identity", fr_tls_conf_t, psk_identity) },
	{ FR_CONF_OFFSET_FLAGS("psk_hexphrase", CONF_FLAG_SECRET, fr_tls_conf_t, psk_password) },
#endif

	{ FR_CONF_OFFSET("keylog_file", fr_tls_conf_t, keylog_file) },

	{ FR_CONF_OFFSET("verify_depth", fr_tls_conf_t, verify_depth), .dflt = "0" },
	{ FR_CONF_OFFSET_FLAGS("ca_path", CONF_FLAG_FILE_READABLE, fr_tls_conf_t, ca_path) },

	{ FR_CONF_OFFSET_FLAGS("ca_file", CONF_FLAG_FILE_READABLE, fr_tls_conf_t, ca_file) },
	{ FR_CONF_OFFSET("dh_file", fr_tls_conf_t, dh_file) },
	{ FR_CONF_OFFSET("random_file", fr_tls_conf_t, random_file) },
	{ FR_CONF_OFFSET("fragment_size",  fr_tls_conf_t, fragment_size), .dflt = "1024" },

	{ FR_CONF_OFFSET("cipher_list", fr_tls_conf_t, cipher_list) },

#ifndef OPENSSL_NO_ECDH
	{ FR_CONF_OFFSET("ecdh_curve", fr_tls_conf_t, ecdh_curve), .dflt = "prime256v1" },
#endif

	{ FR_CONF_OFFSET("tls_max_version", fr_tls_conf_t, tls_max_version) },

	{ FR_CONF_OFFSET("tls_min_version", fr_tls_conf_t, tls_min_version), .dflt = "1.2" },

	{ FR_CONF_DEPRECATED("check_cert_issuer", fr_tls_conf_t, check_cert_issuer) },
	{ FR_CONF_DEPRECATED("check_cert_cn", fr_tls_conf_t, check_cert_cn) },
	CONF_PARSER_TERMINATOR
};

static int tls_virtual_server_cf_parse(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, conf_parser_t const *rule)
{
	fr_tls_conf_t	*conf = talloc_get_type_abort(parent, fr_tls_conf_t);
	virtual_server_t const	*vs = NULL;

	if (virtual_server_cf_parse(ctx, &vs, parent, ci, rule) < 0) return -1;

	if (!vs) return 0;

	/*
	 *	`out` points to conf->virtual_server
	 */
	*((CONF_SECTION const **)out) = virtual_server_cs(vs);
	conf->verify_certificate = cf_section_find(conf->virtual_server, "verify", "certificate") ? true : false;
	conf->new_session = cf_section_find(conf->virtual_server, "new", "session") ? true : false;
	conf->establish_session = cf_section_find(conf->virtual_server, "establish", "session") ? true : false;
	return 0;
}

static int tls_conf_parse_cache_mode(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, conf_parser_t const *rule)
{
	fr_tls_conf_t	*conf = talloc_get_type_abort((uint8_t *)parent - offsetof(fr_tls_conf_t, cache), fr_tls_conf_t);
	int		cache_mode;

	if (cf_table_parse_int(ctx, &cache_mode, parent, ci, rule) < 0) return -1;

	/*
	 *	Ensure our virtual server contains the
	 *      correct sections for the specified
	 *      cache mode.
	 */
	switch (cache_mode) {
	case FR_TLS_CACHE_DISABLED:
	case FR_TLS_CACHE_STATELESS:
		break;

	case FR_TLS_CACHE_STATEFUL:
		if (!conf->virtual_server) {
			cf_log_err(ci, "A virtual_server must be set when cache.mode = \"stateful\"");
		error:
			return -1;
		}

		if (!cf_section_find(conf->virtual_server, "load", "session")) {
			cf_log_err(ci, "Specified virtual_server must contain a \"load session { ... }\" section "
				   "when cache.mode = \"stateful\"");
			goto error;
		}

		if (!cf_section_find(conf->virtual_server, "store", "session")) {
			cf_log_err(ci, "Specified virtual_server must contain a \"store session { ... }\" section "
				   "when cache.mode = \"stateful\"");
			goto error;
		}

		if (!cf_section_find(conf->virtual_server, "clear", "session")) {
			cf_log_err(ci, "Specified virtual_server must contain a \"clear session { ... }\" section "
			           "when cache.mode = \"stateful\"");
			goto error;
		}

		if (conf->tls_min_version >= (float)1.3) {
			cf_log_err(ci, "cache.mode = \"stateful\" is not supported with tls_min_version >= 1.3");
			goto error;
		}
		break;

	case FR_TLS_CACHE_AUTO:
		if (!conf->virtual_server) {
			WARN("A virtual_server must be provided for stateful caching. "
			     "cache.mode = \"auto\" rewritten to cache.mode = \"stateless\"");
		cache_stateless:
			cache_mode = FR_TLS_CACHE_STATELESS;
			break;
		}

		if (!cf_section_find(conf->virtual_server, "load", "session")) {
			cf_log_warn(ci, "Specified virtual_server missing \"load session { ... }\" section. "
			            "cache.mode = \"auto\" rewritten to cache.mode = \"stateless\"");
			goto cache_stateless;
		}

		if (!cf_section_find(conf->virtual_server, "store", "session")) {
			cf_log_warn(ci, "Specified virtual_server missing \"store session { ... }\" section. "
			            "cache.mode = \"auto\" rewritten to cache.mode = \"stateless\"");
			goto cache_stateless;
		}

		if (!cf_section_find(conf->virtual_server, "clear", "session")) {
			cf_log_warn(ci, "Specified virtual_server missing \"clear cache { ... }\" section. "
				    "cache.mode = \"auto\" rewritten to cache.mode = \"stateless\"");
			goto cache_stateless;
		}

		if (conf->tls_min_version >= (float)1.3) {
			cf_log_err(ci, "stateful session-resumption is not supported with tls_min_version >= 1.3. "
			           "cache.mode = \"auto\" rewritten to cache.mode = \"stateless\"");
			goto error;
		}
		break;
	}

	/*
	 *	Generate random, ephemeral, session-ticket keys.
	 */
	if (cache_mode & FR_TLS_CACHE_STATELESS) {
		/*
		 *	Fill the key with randomness if one
		 *	wasn't specified by the user.
		 */
		if (!conf->cache.session_ticket_key) {
			MEM(conf->cache.session_ticket_key = talloc_array(conf, uint8_t, 256));
			fr_rand_buffer(UNCONST(uint8_t *, conf->cache.session_ticket_key),
				       talloc_array_length(conf->cache.session_ticket_key));
		}
	}

	*((int *)out) = cache_mode;

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
			fr_tls_log(NULL, "Error reading Trusted root CA list \"%s\"", conf->ca_file);
			X509_STORE_free(store);
			return NULL;
		}

#ifdef X509_V_FLAG_CRL_CHECK_ALL
	if (conf->verify.check_crl) X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
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
	memset(conf, 0, sizeof(*conf));
	return 0;
}

fr_tls_conf_t *fr_tls_conf_alloc(TALLOC_CTX *ctx)
{
	fr_tls_conf_t *conf;

	MEM(conf = talloc_zero(ctx, fr_tls_conf_t));
	talloc_set_destructor(conf, _conf_server_free);

	return conf;
}

fr_tls_conf_t *fr_tls_conf_parse_server(CONF_SECTION *cs)
{
	fr_tls_conf_t *conf;

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
#ifdef __APPLE__
	error:
#endif
		talloc_free(conf);
		return NULL;
	}

	/*
	 *	Save people from their own stupidity.
	 */
	if (conf->fragment_size < 100) conf->fragment_size = 100;

	FR_INTEGER_BOUND_CHECK("padding", conf->padding_block_size, <=, SSL3_RT_MAX_PLAIN_LENGTH);

#ifdef __APPLE__
	if (conf_cert_admin_password(conf) < 0) goto error;
#endif

	/*
	 *	Cache conf in cs in case we're asked to parse this again.
	 */
	cf_data_add(cs, conf, NULL, false);

	return conf;
}

fr_tls_conf_t *fr_tls_conf_parse_client(CONF_SECTION *cs)
{
	fr_tls_conf_t *conf;

	conf = cf_data_value(cf_data_find(cs, fr_tls_conf_t, NULL));
	if (conf) {
		DEBUG2("Using cached TLS configuration from previous invocation");
		return conf;
	}

	if (cf_section_rules_push(cs, fr_tls_client_config) < 0) return NULL;

	conf = fr_tls_conf_alloc(cs);

	if ((cf_section_parse(conf, conf, cs) < 0) ||
	    (cf_section_parse_pass2(conf, cs) < 0)) {
#ifdef __APPLE__
	error:
#endif
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
#ifdef __APPLE__
	if (conf_cert_admin_password(conf) < 0) goto error;
#endif

	cf_data_add(cs, conf, NULL, false);

	return conf;
}
#endif	/* WITH_TLS */
