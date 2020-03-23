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
 * @file libfreeradius-curl/base.c 
 * @brief Curl global initialisation
 *
 * @copyright 2020 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
#include <freeradius-devel/curl/base.h>
#ifdef WITH_TLS
#include <freeradius-devel/tls/base.h>
#endif

#include <curl/curl.h>
#include <talloc.h>



static int instance_count;

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
	if (tls_init() < 0) return -1;
#endif

	ret = curl_global_init(CURL_GLOBAL_ALL);
	if (ret != CURLE_OK) {
		ERROR("rlm_curl - CURL init returned error: %i - %s", ret, curl_easy_strerror(ret));
		return -1;
	}

	curlversion = curl_version_info(CURLVERSION_NOW);
	if (strcmp(LIBCURL_VERSION, curlversion->version) != 0) {
		WARN("rlm_curl - libcurl version changed since the server was built");
		WARN("rlm_curl - linked: %s built: %s", curlversion->version, LIBCURL_VERSION);
	}

	INFO("rlm_curl - libcurl version: %s", curl_version());

	instance_count++;

	return 0;
}

void fr_curl_free(void)
{
	if (--instance_count > 0) return;

#ifdef WITH_TLS
	tls_free();
#endif

	curl_global_cleanup();
}

int  fr_curl_easy_tls_init (UNUSED fr_curl_io_request_t *creq, fr_curl_tls_t *conf);

int fr_curl_easy_tls_init (fr_curl_io_request_t *randle, fr_curl_tls_t *conf)
{
	int 	ret;

	if (false){

	}

	if (conf->tls_certificate_file) SET_OPTION(CURLOPT_SSLCERT, conf->tls_certificate_file);
	if (conf->tls_private_key_file) SET_OPTION(CURLOPT_SSLKEY, conf->tls_private_key_file);
	if (conf->tls_private_key_password) SET_OPTION(CURLOPT_KEYPASSWD, conf->tls_private_key_password);
	if (conf->tls_ca_file) SET_OPTION(CURLOPT_CAINFO, conf->tls_ca_file);
	if (conf->tls_ca_issuer_file) SET_OPTION(CURLOPT_ISSUERCERT, conf->tls_ca_issuer_file);
	if (conf->tls_ca_path) SET_OPTION(CURLOPT_CAPATH, conf->tls_ca_path);
	if (conf->tls_random_file) SET_OPTION(CURLOPT_RANDOM_FILE, conf->tls_random_file);

	SET_OPTION(CURLOPT_SSL_VERIFYPEER, (conf->tls_check_cert == true) ? 1L : 0L);
	SET_OPTION(CURLOPT_SSL_VERIFYHOST, (conf->tls_check_cert_cn == true) ? 2L : 0L);

	return 0;
	error:
	return -1;
}

