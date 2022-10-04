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
 * @file tls/base.c
 * @brief Initialise OpenSSL
 *
 * @copyright 2001 hereUare Communications, Inc. (raghud@hereuare.com)
 * @copyright 2003 Alan DeKok (aland@freeradius.org)
 * @copyright 2006-2016 The FreeRADIUS server project
 */
RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#ifdef WITH_TLS
#define LOG_PREFIX "tls"

#include "log.h"
#include "bio.h"

#include <openssl/conf.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#  include <openssl/provider.h>
#endif

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/tls/attrs.h>
#include <freeradius-devel/tls/base.h>
#include <freeradius-devel/tls/engine.h>
#include <freeradius-devel/util/atexit.h>
#include <freeradius-devel/util/debug.h>

static uint32_t instance_count = 0;

/** The context which holds any memory OpenSSL allocates
 *
 * This should be used to work around memory leaks in the OpenSSL.
 */
_Thread_local TALLOC_CTX 	*ssl_talloc_ctx;

/** Used to control freeing of thread local OpenSSL resources
 *
 */
static _Thread_local bool	*async_pool_init;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static OSSL_PROVIDER *openssl_default_provider = NULL;
static OSSL_PROVIDER *openssl_legacy_provider = NULL;
#endif

fr_dict_t const *dict_freeradius;
fr_dict_t const *dict_radius;
fr_dict_t const *dict_tls;

extern fr_dict_autoload_t tls_dict[];
fr_dict_autoload_t tls_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ .out = &dict_tls, .proto = "tls" },
	{ NULL }
};

fr_dict_attr_t const *attr_allow_session_resumption;
fr_dict_attr_t const *attr_session_resumed;

/*
 *	Certificate decoding attributes
 */
fr_dict_attr_t const *attr_tls_certificate;
fr_dict_attr_t const *attr_tls_certificate_serial;
fr_dict_attr_t const *attr_tls_certificate_signature;
fr_dict_attr_t const *attr_tls_certificate_signature_algorithm;
fr_dict_attr_t const *attr_tls_certificate_issuer;
fr_dict_attr_t const *attr_tls_certificate_not_before;
fr_dict_attr_t const *attr_tls_certificate_not_after;
fr_dict_attr_t const *attr_tls_certificate_subject;
fr_dict_attr_t const *attr_tls_certificate_common_name;
fr_dict_attr_t const *attr_tls_certificate_subject_alt_name_dns;
fr_dict_attr_t const *attr_tls_certificate_subject_alt_name_email;
fr_dict_attr_t const *attr_tls_certificate_subject_alt_name_upn;
fr_dict_attr_t const *attr_tls_certificate_x509v3_extended_key_usage;
fr_dict_attr_t const *attr_tls_certificate_x509v3_subject_key_identifier;
fr_dict_attr_t const *attr_tls_certificate_x509v3_authority_key_identifier;
fr_dict_attr_t const *attr_tls_certificate_x509v3_basic_constraints;

fr_dict_attr_t const *attr_tls_client_error_code;
fr_dict_attr_t const *attr_tls_ocsp_cert_valid;
fr_dict_attr_t const *attr_tls_ocsp_next_update;
fr_dict_attr_t const *attr_tls_ocsp_response;
fr_dict_attr_t const *attr_tls_psk_identity;

fr_dict_attr_t const *attr_tls_session_cert_file;
fr_dict_attr_t const *attr_tls_session_require_client_cert;
fr_dict_attr_t const *attr_tls_session_cipher_suite;
fr_dict_attr_t const *attr_tls_session_version;

fr_dict_attr_t const *attr_framed_mtu;

fr_dict_attr_t const *attr_tls_packet_type;
fr_dict_attr_t const *attr_tls_session_data;
fr_dict_attr_t const *attr_tls_session_id;
fr_dict_attr_t const *attr_tls_session_resumed;
fr_dict_attr_t const *attr_tls_session_ttl;

extern fr_dict_attr_autoload_t tls_dict_attr[];
fr_dict_attr_autoload_t tls_dict_attr[] = {
	{ .out = &attr_allow_session_resumption, .name = "Allow-Session-Resumption", .type = FR_TYPE_BOOL, .dict = &dict_freeradius },
	{ .out = &attr_session_resumed, .name = "EAP-Session-Resumed", .type = FR_TYPE_BOOL, .dict = &dict_freeradius },

	/*
	 *	Certificate decoding attributes
	 */
	{ .out = &attr_tls_certificate, .name = "TLS-Certificate", .type = FR_TYPE_TLV, .dict = &dict_freeradius },
	{ .out = &attr_tls_certificate_serial, .name = "TLS-Certificate.Serial", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_tls_certificate_signature, .name = "TLS-Certificate.Signature", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_tls_certificate_signature_algorithm, .name = "TLS-Certificate.Signature-Algorithm", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_tls_certificate_issuer, .name = "TLS-Certificate.Issuer", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_tls_certificate_not_before, .name = "TLS-Certificate.Not-Before", .type = FR_TYPE_DATE, .dict = &dict_freeradius },
	{ .out = &attr_tls_certificate_not_after, .name = "TLS-Certificate.Not-After", .type = FR_TYPE_DATE, .dict = &dict_freeradius },
	{ .out = &attr_tls_certificate_subject, .name = "TLS-Certificate.Subject", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_tls_certificate_common_name, .name = "TLS-Certificate.Common-Name", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_tls_certificate_subject_alt_name_dns, .name = "TLS-Certificate.Subject-Alt-Name-Dns", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_tls_certificate_subject_alt_name_email, .name = "TLS-Certificate.Subject-Alt-Name-Email", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_tls_certificate_subject_alt_name_upn, .name = "TLS-Certificate.Subject-Alt-Name-Upn", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_tls_certificate_x509v3_extended_key_usage, .name = "TLS-Certificate.X509v3-Extended-Key-Usage", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_tls_certificate_x509v3_subject_key_identifier, .name = "TLS-Certificate.X509v3-Subject-Key-Identifier", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_tls_certificate_x509v3_authority_key_identifier, .name = "TLS-Certificate.X509v3-Authority-Key-Identifier", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_tls_certificate_x509v3_basic_constraints, .name = "TLS-Certificate.X509v3-Basic-Constraints", .type = FR_TYPE_STRING, .dict = &dict_freeradius },

	{ .out = &attr_tls_client_error_code, .name = "TLS-Client-Error-Code", .type = FR_TYPE_UINT8, .dict = &dict_freeradius },
	{ .out = &attr_tls_ocsp_cert_valid, .name = "TLS-OCSP-Cert-Valid", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_tls_ocsp_next_update, .name = "TLS-OCSP-Next-Update", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_tls_ocsp_response, .name = "TLS-OCSP-Response", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_tls_psk_identity, .name = "TLS-PSK-Identity", .type = FR_TYPE_STRING, .dict = &dict_freeradius },

	{ .out = &attr_tls_session_cert_file, .name = "TLS-Session-Certificate-File", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_tls_session_require_client_cert, .name = "TLS-Session-Require-Client-Certificate", .type = FR_TYPE_BOOL, .dict = &dict_freeradius },
	{ .out = &attr_tls_session_cipher_suite, .name = "TLS-Session-Cipher-Suite", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_tls_session_version, .name = "TLS-Session-Version", .type = FR_TYPE_STRING, .dict = &dict_freeradius },

	{ .out = &attr_framed_mtu, .name = "Framed-MTU", .type = FR_TYPE_UINT32, .dict = &dict_radius },

	/*
	 *	Eventually all TLS attributes will be in the TLS dictionary
	 */
	{ .out = &attr_tls_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_tls },
	{ .out = &attr_tls_session_data, .name = "Session-Data", .type = FR_TYPE_OCTETS, .dict = &dict_tls },
	{ .out = &attr_tls_session_id, .name = "Session-Id", .type = FR_TYPE_OCTETS, .dict = &dict_tls },
	{ .out = &attr_tls_session_resumed, .name = "Session-Resumed", .type = FR_TYPE_BOOL, .dict = &dict_tls },
	{ .out = &attr_tls_session_ttl, .name = "Session-TTL", .type = FR_TYPE_TIME_DELTA, .dict = &dict_tls },
	{ NULL }
};

/*
 *	request types
 */
fr_value_box_t const	*enum_tls_packet_type_load_session;
fr_value_box_t const	*enum_tls_packet_type_store_session;
fr_value_box_t const	*enum_tls_packet_type_clear_session;
fr_value_box_t const	*enum_tls_packet_type_verify_certificate;

/*
 *	response types
 */
fr_value_box_t const	*enum_tls_packet_type_success;
fr_value_box_t const	*enum_tls_packet_type_failure;
fr_value_box_t const	*enum_tls_packet_type_notfound;

extern fr_dict_enum_autoload_t tls_dict_enum[];
fr_dict_enum_autoload_t tls_dict_enum[] = {
	{ .out = &enum_tls_packet_type_load_session, .name = "Load-Session", .attr = &attr_tls_packet_type },
	{ .out = &enum_tls_packet_type_store_session, .name = "Store-Session", .attr = &attr_tls_packet_type },
	{ .out = &enum_tls_packet_type_clear_session, .name = "Clear-Session", .attr = &attr_tls_packet_type },
	{ .out = &enum_tls_packet_type_verify_certificate, .name = "Verify-Certificate", .attr = &attr_tls_packet_type },

	{ .out = &enum_tls_packet_type_success, .name = "Success", .attr = &attr_tls_packet_type },
	{ .out = &enum_tls_packet_type_failure, .name = "Failure", .attr = &attr_tls_packet_type },
	{ .out = &enum_tls_packet_type_notfound, .name = "Notfound", .attr = &attr_tls_packet_type },
	{ NULL }
};

/*
 *	Updated by threads.c in the server, and left alone for everyone else.
 */
int fr_tls_max_threads = 1;

/** Allocate memory for OpenSSL in the NULL context
 *
 * @param len to alloc.
 * @return realloc.
 */
static void *fr_openssl_talloc(size_t len, char const *file, NDEBUG_UNUSED int line)
{
	static char const *async_file;
	void *chunk;

	/*
	 *	Cache the filename pointer for the async_posix.c
	 *	source file, so we can figure out when we're
	 *	being asked for stack memory.
	 *
	 *	This is terrible, we're basically guessing at the
	 *	stack size.  OpenSSL 3.1.0 will have proper
	 *	allocation functions so we can something more
	 *	sensible.
	 */
	if (!async_file) {
		char const *sep;

		sep = strrchr(file, '/');
		if (!sep) {
			sep = file;
		} else {
			sep++;
		}
		if (strcmp(sep, "async_posix.c") == 0) {
			async_file = file;
		alloc_stack:
			len *= 4;
		}
	} else if (file == async_file) goto alloc_stack;

	chunk = talloc_array(ssl_talloc_ctx, uint8_t, len);
#ifndef NDEBUG
	talloc_set_name(chunk, "%s:%u", file, line);
#endif
	return chunk;
}

/** Reallocate memory for OpenSSL in the NULL context
 *
 * @param old memory to realloc.
 * @param len to extend to.
 * @return realloced memory.
 */
static void *fr_openssl_talloc_realloc(void *old, size_t len, NDEBUG_UNUSED char const *file, NDEBUG_UNUSED int line)
{
	void *chunk;

	chunk = talloc_realloc_size(ssl_talloc_ctx, old, len);
#ifndef NDEBUG
	talloc_set_name(chunk, "%s:%u", file, line);
#endif
	return chunk;
}

/** Free memory allocated by OpenSSL
 *
 * @param to_free memory to free.
 */
#ifdef NDEBUG
/*
 *	If we're not debugging, use only the filename.  Otherwise the
 *	cost of snprintf() is too large.
 */
static void fr_openssl_talloc_free(void *to_free, char const *file, UNUSED int line)
{
	(void)_talloc_free(to_free, file);
}
#else
static void fr_openssl_talloc_free(void *to_free, char const *file, int line)
{
	char buffer[256];

	snprintf(buffer, sizeof(buffer), "%s:%i", file, line);
	(void)_talloc_free(to_free, buffer);
}
#endif

/** Cleanup async pools if the thread exits
 *
 */
static int _openssl_thread_free(void *init)
{
	ASYNC_cleanup_thread();
	return talloc_free(init);
}

/** Perform thread-specific initialisation for OpenSSL
 *
 * Async contexts are what OpenSSL uses to track
 *
 * @param[in] async_pool_size_init	The initial number of async contexts
 *					we keep in the pool.
 * @param[in] async_pool_size_max	The maximum number of async contexts
 *					we keep in the thread-local pool.
 * @return
 *	- 0 on success.
 *      - -1 on failure.
 */
int fr_openssl_thread_init(size_t async_pool_size_init, size_t async_pool_size_max)
{
	/*
	 *	Hack to use thread local destructor code
	 */
	if (!async_pool_init) {
		bool *init = talloc_zero(NULL, bool);

		if (ASYNC_init_thread(async_pool_size_max, async_pool_size_init) != 1) {
			fr_tls_log(NULL, "Failed initialising OpenSSL async context pool");
			return -1;
		}

		fr_atexit_thread_local(async_pool_init, _openssl_thread_free, init);
	}

	return 0;
}

/** Free any memory alloced by libssl
 *
 * OpenSSL >= 1.1.0 uses an atexit handler to automatically free
 * memory. However, we need to call OPENSSL_cleanup manually because
 * some of the SSL ctx is parented to the main config which will get
 * freed before the atexit handler, causing a segfault on exit.
 */
void fr_openssl_free(void)
{
	if (--instance_count > 0) return;

	fr_dict_autofree(tls_dict);

	fr_tls_log_free();

	fr_tls_bio_free();
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static void _openssl_provider_free(void)
{
	if (openssl_default_provider && !OSSL_PROVIDER_unload(openssl_default_provider)) {
		fr_tls_log(NULL, "Failed unloading default provider");
	}
	openssl_default_provider = NULL;

	if (openssl_legacy_provider && !OSSL_PROVIDER_unload(openssl_legacy_provider)) {
		fr_tls_log(NULL, "Failed unloading legacy provider");
	}
	openssl_legacy_provider = NULL;
}
#endif

#if OPENSSL_VERSION_NUMBER < 0x30000000L
static void _openssl_engine_free(void)
{
	fr_tls_engine_free_all();
}
#endif

static int fr_openssl_cleanup(UNUSED void *uctx)
{
	OPENSSL_cleanup();
	return 0;
}

/** Add all the default ciphers and message digests to our context.
 *
 * This should be called exactly once from main, before reading the main config
 * or initialising any modules.
 */
int fr_openssl_init(void)
{
	if (instance_count > 0) {
		instance_count++;
		return 0;
	}

	/*
	 *	This will only fail if memory has already been allocated
	 *	by OpenSSL.
	 */
	if (CRYPTO_set_mem_functions(fr_openssl_talloc, fr_openssl_talloc_realloc, fr_openssl_talloc_free) != 1) {
		fr_tls_log(NULL, "Failed to set OpenSSL memory allocation functions.  fr_openssl_init() called too late");
		return -1;
	}

	/*
	 *	NO_ATEXIT has no effect if init is done after
	 *	loading providers, and we need to control the
	 *	exit handler as it needs to be executed last
	 *	after all the EVP_MD ctx have been called, as
	 *      they may unload elements of providers once all
	 *	the contexts have been cleaned up.
	 */
	if (OPENSSL_init_ssl(OPENSSL_INIT_NO_ATEXIT | OPENSSL_INIT_LOAD_CONFIG, NULL) != 1) {
		fr_tls_log(NULL, "Failed calling OPENSSL_init_crypto()");
		return -1;
	}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	/*
	 *	Load the default provider for most algorithms
	 */
	openssl_default_provider = OSSL_PROVIDER_load(NULL, "default");
	if (!openssl_default_provider) {
		fr_tls_log(NULL, "Failed loading default provider");
		return -1;
	}

	/*
	 *	Needed for MD4
	 *
	 *	https://www.openssl.org/docs/man3.0/man7/migration_guide.html#Legacy-Algorithms
	 */
	openssl_legacy_provider = OSSL_PROVIDER_load(NULL, "legacy");
	if (!openssl_legacy_provider) {
		fr_tls_log(NULL, "Failed loading legacy provider");
		return -1;
	}
#endif

	/*
	 *	It's best to use OpenSSL's cleanup stack
	 *	as then everything is cleaned up relative
	 *	to the OPENSSL_cleanup() call.
	 */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	OPENSSL_atexit(_openssl_provider_free);
#endif

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	OPENSSL_atexit(_openssl_engine_free);
#endif

	/*
	 *	SHA256 is in all versions of OpenSSL, but isn't
	 *	initialized by default.  It's needed for WiMAX
	 *	certificates.
	 */
	EVP_add_digest(EVP_sha256());

	/*
	 *	FIXME - This should be done _after_
	 *	running any engine controls.
	 */
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	fr_tls_engine_load_builtin();
#endif

	fr_tls_log_init();

	fr_tls_bio_init();

	/*
	 *	Use an atexit handler to try and ensure
	 *	that OpenSSL gets freed last.
	 *
	 *	All EVP_*ctxs need to be freed before we
	 *	de-initialise the libraries else we get
	 *	crashes (at least with OpenSSL 3.0.1).
	 */
	fr_atexit_global(fr_openssl_cleanup, NULL);

	instance_count++;

	return 0;
}

/** Enable or disable fips mode
 *
 * @param[in] enabled		If true enable fips mode if false disable fips mode.
 * @return
 *	- 0 on success.
 *      - -1 on failure
 */
int fr_openssl_fips_mode(bool enabled)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	if (!EVP_set_default_properties(NULL, enabled ? "fips=yes" : "fips=no")) {
		fr_tls_log(NULL, "Failed %s OpenSSL FIPS mode", enabled ? "enabling" : "disabling");
		return -1;
	}
#else
	if (!FIPS_mode_set(enabled ? 1 : 0)) {
		fr_tls_log(NULL, "Failed %s OpenSSL FIPS mode", enabled ? "enabling" : "disabling");
		return -1;
	}
#endif

	return 0;
}

/** Load dictionary attributes
 *
 * This is a separate function because of ordering issues.
 * OpenSSL may need to be initialised before anything else
 * including the dictionary loader.
 *
 * fr_openssl_free will unload both the dictionary and the
 * OpenSSL library.
 */
int fr_tls_dict_init(void)
{
	if (fr_dict_autoload(tls_dict) < 0) {
		PERROR("Failed initialising protocol library");
		fr_openssl_free();
		return -1;
	}

	if (fr_dict_attr_autoload(tls_dict_attr) < 0) {
		PERROR("Failed resolving attributes");
		fr_openssl_free();
		return -1;
	}

	if (fr_dict_enum_autoload(tls_dict_enum) < 0) {
		PERROR("Failed resolving enums");
		fr_openssl_free();
		return -1;
	}
	return 0;
}
#endif /* WITH_TLS */
