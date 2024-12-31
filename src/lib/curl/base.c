/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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
 * @file curl/base.c
 * @brief Curl global initialisation
 *
 * @copyright 2020 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
#include <freeradius-devel/curl/base.h>
#include <freeradius-devel/curl/xlat.h>
#ifdef WITH_TLS
#include <freeradius-devel/tls/base.h>
#endif

#include <freeradius-devel/util/talloc.h>
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/unlang/xlat_func.h>

#include "attrs.h"

fr_dict_attr_t const *attr_tls_certificate;
static fr_dict_t const *dict_freeradius; /*internal dictionary for server*/

extern fr_dict_attr_autoload_t curl_attr[];
fr_dict_attr_autoload_t curl_attr[] = {
	{ .out = &attr_tls_certificate, .name = "TLS-Certificate", .type = FR_TYPE_TLV, .dict = &dict_freeradius },
	{ NULL }
};

static fr_dict_autoload_t curl_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ NULL }
};

static fr_table_num_sorted_t const fr_curl_sslcode_table[] = {
	{L("allow"),     CURLUSESSL_TRY          },
	{L("demand"),    CURLUSESSL_ALL          },
	{L("never"),	 CURLUSESSL_NONE         },
};
static size_t fr_curl_sslcode_table_len = NUM_ELEMENTS(fr_curl_sslcode_table);

static int tls_config_dflt_capath(CONF_PAIR **out, UNUSED void *parent, CONF_SECTION *cs, fr_token_t quote, conf_parser_t const *rule)
{
	char const	*ca_path = NULL;
#if CURL_AT_LEAST_VERSION(7,70,0)
	ca_path = curl_version_info(CURLVERSION_NOW)->capath;
#endif
	if (!ca_path) return 0;
	MEM(*out = cf_pair_alloc(cs, rule->name1, ca_path, T_OP_EQ, T_BARE_WORD, quote));
	return 0;
}

conf_parser_t fr_curl_tls_config[] = {
	{ FR_CONF_OFFSET_FLAGS("ca_file", CONF_FLAG_FILE_INPUT, fr_curl_tls_t, ca_file) },
	{ FR_CONF_OFFSET_FLAGS("ca_issuer_file", CONF_FLAG_FILE_INPUT, fr_curl_tls_t, ca_issuer_file) },
	{ FR_CONF_OFFSET_FLAGS("ca_path", CONF_FLAG_FILE_INPUT, fr_curl_tls_t, ca_path), .dflt_func = tls_config_dflt_capath },
	{ FR_CONF_OFFSET_FLAGS("certificate_file", CONF_FLAG_FILE_INPUT, fr_curl_tls_t, certificate_file) },
	{ FR_CONF_OFFSET_FLAGS("private_key_file", CONF_FLAG_FILE_INPUT, fr_curl_tls_t, private_key_file) },
	{ FR_CONF_OFFSET_FLAGS("private_key_password", CONF_FLAG_SECRET, fr_curl_tls_t, private_key_password) },
	{ FR_CONF_OFFSET("random_file", fr_curl_tls_t, random_file) },
	{ FR_CONF_OFFSET_TYPE_FLAGS("require_cert", FR_TYPE_VOID, 0, fr_curl_tls_t, require_cert),
       		.func = cf_table_parse_int,
       		.uctx = &(cf_table_parse_ctx_t){
       			.table = fr_curl_sslcode_table,
       			.len = &fr_curl_sslcode_table_len
       		},
		.dflt = "allow" },
	{ FR_CONF_OFFSET("check_cert", fr_curl_tls_t, check_cert), .dflt = "yes" },
	{ FR_CONF_OFFSET("check_cert_cn", fr_curl_tls_t, check_cert_cn), .dflt = "yes" },
	{ FR_CONF_OFFSET("extract_cert_attrs", fr_curl_tls_t, extract_cert_attrs), .dflt = "no" },
#ifdef WITH_TLS
	{ FR_CONF_OFFSET_FLAGS("keylog_file", CONF_FLAG_FILE_OUTPUT, fr_curl_tls_t,  keylog_file) },
#endif
	CONF_PARSER_TERMINATOR
};

static conf_parser_t reuse_curl_conn_config[] = {
	FR_SLAB_CONFIG_CONF_PARSER
	CONF_PARSER_TERMINATOR
};

conf_parser_t fr_curl_conn_config[] = {
	{ FR_CONF_OFFSET_SUBSECTION("reuse", 0, fr_curl_conn_config_t, reuse, reuse_curl_conn_config) },
	{ FR_CONF_OFFSET("connect_timeout", fr_curl_conn_config_t, connect_timeout), .dflt = "3.0" },
	CONF_PARSER_TERMINATOR
};

#ifdef WITH_TLS
static void _curl_easy_tls_keylog(const SSL *ssl, const char *line)
{
	fr_curl_tls_t const *conf = SSL_CTX_get_ex_data(SSL_get_SSL_CTX(ssl), FR_TLS_EX_INDEX_CURL_CONF);

	FILE *fp = fopen(conf->keylog_file, "a");
	if (!fp) {
		RATE_LIMIT_GLOBAL(WARN, "Failed opening keylog file \"%s\" - %s", conf->keylog_file, fr_syserror(errno));
		return;
	}

	/*
	 *	POSIX states fprintf calls must not intermingle
	 *	data being written to the same file, and as all
	 *	keying material is written on the same line, this
	 *	should be safe.
	 */
	fprintf(fp, "%s\n", line);
	fclose(fp);
}

static CURLcode _curl_easy_ssl_ctx_conf(UNUSED CURL *curl, void *ssl_ctx, void *clientp)
{
	SSL_CTX *ctx = ssl_ctx;
	fr_curl_tls_t const *conf = clientp; /* May not be talloced */

	SSL_CTX_set_ex_data(ctx, FR_TLS_EX_INDEX_CURL_CONF, UNCONST(void *, conf));

	if (conf->keylog_file) {
		SSL_CTX_set_keylog_callback(ctx, _curl_easy_tls_keylog);
	}

	return CURLE_OK;
}
#endif

int fr_curl_easy_tls_init(fr_curl_io_request_t *randle, fr_curl_tls_t const *conf)
{
	request_t *request = randle->request;

	if (conf->certificate_file) FR_CURL_ROPTIONAL_SET_OPTION(CURLOPT_SSLCERT, conf->certificate_file);
	if (conf->private_key_file) FR_CURL_ROPTIONAL_SET_OPTION(CURLOPT_SSLKEY, conf->private_key_file);
	if (conf->private_key_password) FR_CURL_ROPTIONAL_SET_OPTION(CURLOPT_KEYPASSWD, conf->private_key_password);
	if (conf->ca_file) FR_CURL_ROPTIONAL_SET_OPTION(CURLOPT_CAINFO, conf->ca_file);
	if (conf->ca_issuer_file) FR_CURL_ROPTIONAL_SET_OPTION(CURLOPT_ISSUERCERT, conf->ca_issuer_file);
	if (conf->ca_path) FR_CURL_ROPTIONAL_SET_OPTION(CURLOPT_CAPATH, conf->ca_path);
#if !CURL_AT_LEAST_VERSION(7,84,0)
	if (conf->random_file) FR_CURL_ROPTIONAL_SET_OPTION(CURLOPT_RANDOM_FILE, conf->random_file);
#endif
	FR_CURL_ROPTIONAL_SET_OPTION(CURLOPT_USE_SSL, conf->require_cert);

	FR_CURL_ROPTIONAL_SET_OPTION(CURLOPT_SSL_VERIFYPEER, (conf->check_cert == true) ? 1L : 0L);
	FR_CURL_ROPTIONAL_SET_OPTION(CURLOPT_SSL_VERIFYHOST, (conf->check_cert_cn == true) ? 2L : 0L);
	if (conf->extract_cert_attrs) FR_CURL_ROPTIONAL_SET_OPTION(CURLOPT_CERTINFO, 1L);

#ifdef WITH_TLS
	if (conf->keylog_file) {
		FR_CURL_ROPTIONAL_SET_OPTION(CURLOPT_SSL_CTX_FUNCTION, _curl_easy_ssl_ctx_conf);
		FR_CURL_ROPTIONAL_SET_OPTION(CURLOPT_SSL_CTX_DATA, conf);
	}
#endif

	return 0;
error:
	return -1;
}

int fr_curl_response_certinfo(request_t *request, fr_curl_io_request_t *randle)
{
	CURL			*candle = randle->candle;
	CURLcode		ret;
	int			i;
	char		 	buffer[265];
	char			*p , *q;
	fr_pair_list_t		cert_vps;

	struct curl_certinfo *to_certinfo = NULL;

	fr_pair_list_init(&cert_vps);

	ret = curl_easy_getinfo(candle, CURLINFO_CERTINFO, &to_certinfo);
	if (ret != CURLE_OK) {
		REDEBUG("Getting certificate info failed: %i - %s", ret, curl_easy_strerror(ret));

		return -1;
	}

	/*
	 *	There doesn't seem to be any way to determine if
	 *	the session uses ssl or not, so if no certs are
	 *	returned, we assume it's not an ssl session.
	 */
	if (!to_certinfo || to_certinfo->num_of_certs == 0) return 0;

	RDEBUG2("Chain has %i certificate(s)", to_certinfo->num_of_certs);
	for (i = 0; i < to_certinfo->num_of_certs; i++) {
		struct curl_slist *cert_attrs;
		fr_pair_t *container;

		MEM(container = fr_pair_afrom_da(request->request_ctx, attr_tls_certificate));
		fr_pair_append(&cert_vps, container);

		RDEBUG2("Processing certificate %i",i);

		for (cert_attrs = to_certinfo->certinfo[i];
		     cert_attrs;
		     cert_attrs = cert_attrs->next) {
		     	fr_pair_t		*vp;
		     	fr_dict_attr_t const	*da;

		     	q = strchr(cert_attrs->data, ':');
			if (!q) {
				RWDEBUG("Malformed certinfo from libcurl: %s", cert_attrs->data);
				continue;
			}

			strlcpy(buffer, cert_attrs->data, (q - cert_attrs->data) + 1);
			for (p = buffer; *p != '\0'; p++) if (*p == ' ') *p = '-';

			da = fr_dict_attr_by_name(NULL, attr_tls_certificate, buffer);
			if (!da) {
				RDEBUG3("Skipping %s += '%s'", buffer, q + 1);
				RDEBUG3("If this value is required, define attribute \"%s\"", buffer);
				continue;
			}
			MEM(vp = fr_pair_afrom_da(container, da));
			fr_pair_value_from_str(vp, q + 1, strlen(q + 1), NULL, true);

			fr_pair_append(&container->vp_group, vp);
		}
		/*
		 *	Add a copy of the cert_vps to the request list.
		 */
		if (!fr_pair_list_empty(&cert_vps)) {
			/*
			 *	Print out all the pairs we have so far
			 */
			log_request_pair_list(L_DBG_LVL_2, request, NULL, &cert_vps, NULL);
			fr_pair_list_append(&request->request_pairs, &cert_vps);
		}
	}
	return 0;
}

/** Free the curl easy handle
 *
 * @param[in] arg		curl easy handle to free.
 */
static int _curl_tmpl_handle(void *arg)
{
	curl_easy_cleanup(arg);
	return 0;
}

/** Return a thread local curl easy handle
 *
 * This should only be used for calls into libcurl functions
 * which don't operate on an active request, like the
 * escape/unescape functions.
 *
 * @return
 *	- A thread local curl easy handle.
 *	- NULL on failure.
 */
CURL *fr_curl_tmp_handle(void)
{
	static _Thread_local CURL	*t_candle;

	if (unlikely(t_candle == NULL)) {
		CURL *candle;

		MEM(candle = curl_easy_init());
		fr_atexit_thread_local(t_candle, _curl_tmpl_handle, candle);
	}

	return t_candle;
}

/** Initialise global curl options
 *
 * libcurl is meant to performa reference counting, but still seems to
 * leak lots of memory if we call curl_global_init many times.
 */
static int fr_curl_init(void)
{
	CURLcode ret;
	curl_version_info_data *curlversion;

#ifdef WITH_TLS
	/*
	 *	Use our OpenSSL init with the hope that
	 *	the free function will also free the
	 *	memory allocated during SSL init.
	 */
	if (fr_openssl_init() < 0) return -1;
#endif

	if (fr_dict_autoload(curl_dict) < 0) {
		PERROR("Failed loading dictionaries for curl");
		return -1;
	}

	if (fr_dict_attr_autoload(curl_attr) < 0) {
		PERROR("Failed loading dictionaries for curl");
		return -1;
	}

	ret = curl_global_init(CURL_GLOBAL_ALL);
	if (ret != CURLE_OK) {
		ERROR("CURL init returned error: %i - %s", ret, curl_easy_strerror(ret));
	error:
		fr_dict_autofree(curl_dict);
		return -1;
	}

	curlversion = curl_version_info(CURLVERSION_NOW);
	if (strcmp(LIBCURL_VERSION, curlversion->version) != 0) {
		WARN("libcurl version changed since the server was built");
		WARN("linked: %s built: %s", curlversion->version, LIBCURL_VERSION);
	}

	INFO("libcurl version: %s", curl_version());

	{
		xlat_t *xlat;

		/*
		 *	Generic escape function for all CURL based modules
		 *	Use CURL_URI_SAFE_FOR within the module.
		 */
		xlat = xlat_func_register(NULL, "uri.escape", fr_curl_xlat_uri_escape, FR_TYPE_STRING);
		if (unlikely(!xlat)) {
			ERROR("Failed registering \"uri.escape\" xlat");
			goto error;
		}
		xlat_func_args_set(xlat, fr_curl_xlat_uri_args);
		xlat_func_flags_set(xlat, XLAT_FUNC_FLAG_PURE);
		xlat_func_safe_for_set(xlat, CURL_URI_SAFE_FOR);

		/*
		 *	Generic safe function for all CURL based modules
		 *	Use CURL_URI_SAFE_FOR within the module.
		 */
		xlat = xlat_func_register(NULL, "uri.safe", xlat_transparent, FR_TYPE_STRING);
		if (unlikely(!xlat)) {
			ERROR("Failed registering \"uri.safe\" xlat");
			goto error;
		}
		xlat_func_args_set(xlat, fr_curl_xlat_safe_args);
		xlat_func_flags_set(xlat, XLAT_FUNC_FLAG_PURE);
		xlat_func_safe_for_set(xlat, CURL_URI_SAFE_FOR);

		/*
		 *	Generic unescape function for all CURL based modules
		 */
		xlat = xlat_func_register(NULL, "uri.unescape", fr_curl_xlat_uri_unescape, FR_TYPE_STRING);
		if (unlikely(!xlat)) {
			ERROR("Failed registering \"uri.unescape\" xlat");
			goto error;
		}
		xlat_func_flags_set(xlat, XLAT_FUNC_FLAG_PURE);
		xlat_func_args_set(xlat, fr_curl_xlat_uri_args);
	}

	return 0;
}

static void fr_curl_free(void)
{
	fr_dict_autofree(curl_dict);

#ifdef WITH_TLS
	fr_openssl_free();
#endif
	curl_global_cleanup();

	xlat_func_unregister("uri.escape");
	xlat_func_unregister("uri.safe");
	xlat_func_unregister("uri.unescape");
}

/*
 *	Public symbol modules can reference to auto instantiate libcurl
 */
global_lib_autoinst_t fr_curl_autoinst = {
	.name = "curl",
	.init = fr_curl_init,
	.free = fr_curl_free
};
