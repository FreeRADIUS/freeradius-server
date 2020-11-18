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
#ifdef WITH_TLS
#include <freeradius-devel/tls/base.h>
#endif

#define CURL_NO_OLDIES 1

#include <curl/curl.h>
#include <talloc.h>

/*
 *	We have to use this as curl uses lots of enums
 */
#ifndef CURL_AT_LEAST_VERSION
#  define CURL_VERSION_BITS(x, y, z) ((x) << 16 | (y) << 8 | z)
#  define CURL_AT_LEAST_VERSION(x, y, z) (LIBCURL_VERSION_NUM >= CURL_VERSION_BITS(x, y, z))
#endif

static uint32_t instance_count = 0;
static fr_dict_t const *dict_freeradius; /*internal dictionary for server*/

static fr_dict_autoload_t curl_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ NULL }
};

fr_table_num_sorted_t const fr_curl_sslcode_table[] = {
	{L("allow"),     	CURLUSESSL_TRY          },
	{L("demand"),     	CURLUSESSL_ALL          },
	{L("never"), 	CURLUSESSL_NONE         },
};
static size_t fr_curl_sslcode_table_len = NUM_ELEMENTS(fr_curl_sslcode_table);

CONF_PARSER fr_curl_tls_config[] = {
	{ FR_CONF_OFFSET("ca_file", FR_TYPE_FILE_INPUT, fr_curl_tls_t, ca_file) },
	{ FR_CONF_OFFSET("ca_issuer_file", FR_TYPE_FILE_INPUT, fr_curl_tls_t, ca_issuer_file) },
	{ FR_CONF_OFFSET("ca_path", FR_TYPE_FILE_INPUT, fr_curl_tls_t, ca_path) },
	{ FR_CONF_OFFSET("certificate_file", FR_TYPE_FILE_INPUT, fr_curl_tls_t, certificate_file) },
	{ FR_CONF_OFFSET("private_key_file", FR_TYPE_FILE_INPUT, fr_curl_tls_t, private_key_file) },
	{ FR_CONF_OFFSET("private_key_password", FR_TYPE_STRING | FR_TYPE_SECRET, fr_curl_tls_t, private_key_password) },
	{ FR_CONF_OFFSET("random_file", FR_TYPE_STRING, fr_curl_tls_t, random_file) },
	{ FR_CONF_OFFSET("require_cert", FR_TYPE_VOID, fr_curl_tls_t, require_cert),
       	.func = cf_table_parse_int32, .uctx = &(cf_table_parse_ctx_t){ .table = fr_curl_sslcode_table, .len = &fr_curl_sslcode_table_len },
	.dflt = "allow" },
	{ FR_CONF_OFFSET("check_cert", FR_TYPE_BOOL, fr_curl_tls_t, check_cert), .dflt = "yes" },
	{ FR_CONF_OFFSET("check_cert_cn", FR_TYPE_BOOL, fr_curl_tls_t, check_cert_cn), .dflt = "yes" },
	{ FR_CONF_OFFSET("extract_cert_attrs", FR_TYPE_BOOL, fr_curl_tls_t, extract_cert_attrs), .dflt = "no" },
	CONF_PARSER_TERMINATOR
};

/** Initialise global curl options
 *
 * libcurl is meant to performa reference counting, but still seems to
 * leak lots of memory if we call curl_global_init many times.
 */
int fr_curl_init(void)
{
	CURLcode ret;
	curl_version_info_data *curlversion;

	if (instance_count > 0) {
		instance_count++;
		return 0;
	}

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

	ret = curl_global_init(CURL_GLOBAL_ALL);
	if (ret != CURLE_OK) {
		ERROR("CURL init returned error: %i - %s", ret, curl_easy_strerror(ret));
		fr_dict_autofree(curl_dict);
		return -1;
	}

	curlversion = curl_version_info(CURLVERSION_NOW);
	if (strcmp(LIBCURL_VERSION, curlversion->version) != 0) {
		WARN("libcurl version changed since the server was built");
		WARN("linked: %s built: %s", curlversion->version, LIBCURL_VERSION);
	}

	INFO("libcurl version: %s", curl_version());

	instance_count++;

	return 0;
}

void fr_curl_free(void)
{
	if (--instance_count > 0) return;

	fr_dict_autofree(curl_dict);

#ifdef WITH_TLS
	fr_openssl_free();
#endif
	curl_global_cleanup();
}

int fr_curl_easy_tls_init(fr_curl_io_request_t *randle, fr_curl_tls_t const *conf)
{
	request_t *request = randle->request;

	if (conf->certificate_file) FR_CURL_ROPTIONAL_SET_OPTION(CURLOPT_SSLCERT, conf->certificate_file);
	if (conf->private_key_file) FR_CURL_ROPTIONAL_SET_OPTION(CURLOPT_SSLKEY, conf->private_key_file);
	if (conf->private_key_password) FR_CURL_ROPTIONAL_SET_OPTION(CURLOPT_KEYPASSWD, conf->private_key_password);
	if (conf->ca_file) FR_CURL_ROPTIONAL_SET_OPTION(CURLOPT_CAINFO, conf->ca_file);
	if (conf->ca_issuer_file) FR_CURL_ROPTIONAL_SET_OPTION(CURLOPT_ISSUERCERT, conf->ca_issuer_file);
	if (conf->ca_path) FR_CURL_ROPTIONAL_SET_OPTION(CURLOPT_CAPATH, conf->ca_path);
	if (conf->random_file) FR_CURL_ROPTIONAL_SET_OPTION(CURLOPT_RANDOM_FILE, conf->random_file);
	FR_CURL_ROPTIONAL_SET_OPTION(CURLOPT_USE_SSL, conf->require_cert);

	FR_CURL_ROPTIONAL_SET_OPTION(CURLOPT_SSL_VERIFYPEER, (conf->check_cert == true) ? 1L : 0L);
	FR_CURL_ROPTIONAL_SET_OPTION(CURLOPT_SSL_VERIFYHOST, (conf->check_cert_cn == true) ? 2L : 0L);
	if (conf->extract_cert_attrs) FR_CURL_ROPTIONAL_SET_OPTION(CURLOPT_CERTINFO, 1L);

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
	char			*p , *q, *attr = buffer;
	fr_cursor_t		cursor, list;
	fr_pair_list_t		cert_vps;
	/*
	 *	Examples and documentation show cert_info being
	 *	a struct curl_certinfo *, but CPP checks require
	 *	it to be a struct curl_slist *.
	 *
	 *	https://curl.haxx.se/libcurl/c/certinfo.html
	 */
	union {
		struct curl_slist    *to_info;
		struct curl_certinfo *to_certinfo;
	} ptr;
	ptr.to_info = NULL;

	fr_pair_list_init(&cert_vps);
	fr_cursor_init(&list, &request->request_pairs);

	ret = curl_easy_getinfo(candle, CURLINFO_CERTINFO, &ptr.to_info);
	if (ret != CURLE_OK) {
		REDEBUG("Getting certificate info failed: %i - %s", ret, curl_easy_strerror(ret));

		return -1;
	}

	attr += strlcpy(attr, "TLS-Cert-", sizeof(buffer));

	RDEBUG2("Chain has %i certificate(s)", ptr.to_certinfo->num_of_certs);
	for (i = 0; i < ptr.to_certinfo->num_of_certs; i++) {
		struct curl_slist *cert_attrs;

		RDEBUG2("Processing certificate %i",i);
		fr_cursor_init(&cursor, &cert_vps);

		for (cert_attrs = ptr.to_certinfo->certinfo[i];
		     cert_attrs;
		     cert_attrs = cert_attrs->next) {
		     	fr_pair_t		*vp;
		     	fr_dict_attr_t const	*da;

		     	q = strchr(cert_attrs->data, ':');
			if (!q) {
				RWDEBUG("Malformed certinfo from libcurl: %s", cert_attrs->data);
				continue;
			}

			strlcpy(attr, cert_attrs->data, (q - cert_attrs->data) + 1);
			for (p = attr; *p != '\0'; p++) if (*p == ' ') *p = '-';

			da = fr_dict_attr_by_name(NULL, fr_dict_root(dict_freeradius), buffer);
			if (!da) {
				RDEBUG3("Skipping %s += '%s'", buffer, q + 1);
				RDEBUG3("If this value is required, define attribute \"%s\"", buffer);
				continue;
			}
			MEM(vp = fr_pair_afrom_da(request->packet, da));
			fr_pair_value_from_str(vp, q + 1, -1, '\0', true);

			fr_cursor_append(&cursor, vp);
		}
		/*
		 *	Add a copy of the cert_vps to the request list.
		 *
		 *	Both PVS studio and Coverity detect the condition
		 *	below as logically dead code unless we explicitly
		 *	set cert_vps.  This is because they're too dumb
		 *	to realise that the cursor argument passed to
		 *	tls_session_pairs_from_x509_cert contains a
		 *	reference to cert_vps.
		 */
		cert_vps = fr_cursor_head(&cursor);
		if (cert_vps) {
			/*
			 *	Print out all the pairs we have so far
			 */
			log_request_pair_list(L_DBG_LVL_2, request, cert_vps, NULL);
			fr_cursor_merge(&list, &cursor);
			fr_pair_list_init(&cert_vps);
		}
	}
	return 0;
}
