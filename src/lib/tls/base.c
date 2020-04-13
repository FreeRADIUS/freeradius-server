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
#define LOG_PREFIX "tls - "

#include <openssl/conf.h>

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/util/debug.h>
#include "base.h"
#include "attrs.h"

static uint32_t instance_count = 0;

/** The context which holds any memory OpenSSL allocates
 *
 * This should be used to work around memory leaks in the OpenSSL.
 */
_Thread_local TALLOC_CTX 	*ssl_talloc_ctx;

fr_dict_t const *dict_freeradius;
fr_dict_t const *dict_radius;

extern fr_dict_autoload_t tls_dict[];
fr_dict_autoload_t tls_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

fr_dict_attr_t const *attr_allow_session_resumption;
fr_dict_attr_t const *attr_eap_session_resumed;

fr_dict_attr_t const *attr_tls_cert_common_name;
fr_dict_attr_t const *attr_tls_cert_expiration;
fr_dict_attr_t const *attr_tls_cert_issuer;
fr_dict_attr_t const *attr_tls_cert_serial;
fr_dict_attr_t const *attr_tls_cert_subject;
fr_dict_attr_t const *attr_tls_cert_subject_alt_name_dns;
fr_dict_attr_t const *attr_tls_cert_subject_alt_name_email;
fr_dict_attr_t const *attr_tls_cert_subject_alt_name_upn;

fr_dict_attr_t const *attr_tls_client_cert_common_name;
fr_dict_attr_t const *attr_tls_client_cert_expiration;
fr_dict_attr_t const *attr_tls_client_cert_issuer;
fr_dict_attr_t const *attr_tls_client_cert_serial;
fr_dict_attr_t const *attr_tls_client_cert_subject;
fr_dict_attr_t const *attr_tls_client_cert_subject_alt_name_dns;
fr_dict_attr_t const *attr_tls_client_cert_subject_alt_name_email;
fr_dict_attr_t const *attr_tls_client_cert_subject_alt_name_upn;

fr_dict_attr_t const *attr_tls_client_cert_filename;
fr_dict_attr_t const *attr_tls_client_error_code;
fr_dict_attr_t const *attr_tls_ocsp_cert_valid;
fr_dict_attr_t const *attr_tls_ocsp_next_update;
fr_dict_attr_t const *attr_tls_ocsp_response;
fr_dict_attr_t const *attr_tls_psk_identity;
fr_dict_attr_t const *attr_tls_session_cert_file;
fr_dict_attr_t const *attr_tls_session_data;
fr_dict_attr_t const *attr_tls_session_id;

fr_dict_attr_t const *attr_framed_mtu;

extern fr_dict_attr_autoload_t tls_dict_attr[];
fr_dict_attr_autoload_t tls_dict_attr[] = {
	{ .out = &attr_allow_session_resumption, .name = "Allow-Session-Resumption", .type = FR_TYPE_BOOL, .dict = &dict_freeradius },
	{ .out = &attr_eap_session_resumed, .name = "EAP-Session-Resumed", .type = FR_TYPE_BOOL, .dict = &dict_freeradius },

	{ .out = &attr_tls_cert_common_name, .name = "TLS-Cert-Common-Name", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_tls_cert_expiration, .name = "TLS-Cert-Expiration", .type = FR_TYPE_DATE, .dict = &dict_freeradius },
	{ .out = &attr_tls_cert_issuer, .name = "TLS-Cert-Issuer", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_tls_cert_serial, .name = "TLS-Cert-Serial", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_tls_cert_subject, .name = "TLS-Cert-Subject", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_tls_cert_subject_alt_name_dns, .name = "TLS-Cert-Subject-Alt-Name-Dns", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_tls_cert_subject_alt_name_email, .name = "TLS-Cert-Subject-Alt-Name-Email", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_tls_cert_subject_alt_name_upn, .name = "TLS-Cert-Subject-Alt-Name-Upn", .type = FR_TYPE_STRING, .dict = &dict_freeradius },

	{ .out = &attr_tls_client_cert_common_name, .name = "TLS-Client-Cert-Common-Name", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_tls_client_cert_expiration, .name = "TLS-Client-Cert-Expiration", .type = FR_TYPE_DATE, .dict = &dict_freeradius },
	{ .out = &attr_tls_client_cert_issuer, .name = "TLS-Client-Cert-Issuer", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_tls_client_cert_serial, .name = "TLS-Client-Cert-Serial", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_tls_client_cert_subject, .name = "TLS-Client-Cert-Subject", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_tls_client_cert_subject_alt_name_dns, .name = "TLS-Client-Cert-Subject-Alt-Name-Dns", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_tls_client_cert_subject_alt_name_email, .name = "TLS-Client-Cert-Subject-Alt-Name-Email", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_tls_client_cert_subject_alt_name_upn, .name = "TLS-Client-Cert-Subject-Alt-Name-Upn", .type = FR_TYPE_STRING, .dict = &dict_freeradius },

	{ .out = &attr_tls_client_cert_filename, .name = "TLS-Client-Cert-Filename", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_tls_client_error_code, .name = "TLS-Client-Error-Code", .type = FR_TYPE_UINT8, .dict = &dict_freeradius },
	{ .out = &attr_tls_ocsp_cert_valid, .name = "TLS-OCSP-Cert-Valid", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_tls_ocsp_next_update, .name = "TLS-OCSP-Next-Update", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_tls_ocsp_response, .name = "TLS-OCSP-Response", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_tls_psk_identity, .name = "TLS-PSK-Identity", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_tls_session_cert_file, .name = "TLS-Session-Cert-File", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_tls_session_data, .name = "Session-Data", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_tls_session_id, .name = "Session-Id", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },

	{ .out = &attr_framed_mtu, .name = "Framed-MTU", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ NULL }
};

/*
 *	Updated by threads.c in the server, and left alone for everyone else.
 */
int fr_tls_max_threads = 1;

#ifdef ENABLE_OPENSSL_VERSION_CHECK
typedef struct {
	uint64_t	high;		//!< The last version number this defect affected.
	uint64_t	low;		//!< The first version this defect affected.

	char const	*id;		//!< CVE (or other ID)
	char const	*name;		//!< As known in the media...
	char const	*comment;	//!< Where to get more information.
} fr_openssl_defect_t;

#undef VM
#undef Vm
#define VM(_a,_b,_c) (((((_a) << 24) | ((_b) << 16) | ((_c) << 8)) << 4) | 0x0f)
#define Vm(_a,_b,_c,_d) (((((_a) << 24) | ((_b) << 16) | ((_c) << 8) | ((_d) - 'a' + 1)) << 4) | 0x0f)

/* Record critical defects in libssl here, new versions of OpenSSL to older versions of OpenSSL.  */
static fr_openssl_defect_t fr_openssl_defects[] =
{
	{
		.low		= Vm(1,1,0,'a'),		/* 1.1.0a */
		.high		= Vm(1,1,0,'a'),		/* 1.1.0a */
		.id		= "CVE-2016-6309",
		.name		= "OCSP status request extension",
		.comment	= "For more information see https://www.openssl.org/news/secadv/20160926.txt"
	},
	{
		.low		= VM(1,1,0),			/* 1.1.0  */
		.high		= VM(1,1,0),			/* 1.1.0  */
		.id		= "CVE-2016-6304",
		.name		= "OCSP status request extension",
		.comment	= "For more information see https://www.openssl.org/news/secadv/20160922.txt"
	},
	{
		.low		= Vm(1,0,2,'i'),		/* 1.0.2i */
		.high		= Vm(1,0,2,'i'),		/* 1.0.2i */
		.id		= "CVE-2016-7052",
		.name		= "OCSP status request extension",
		.comment	= "For more information see https://www.openssl.org/news/secadv/20160926.txt"
	},
	{
		.low		= VM(1,0,2),			/* 1.0.2  */
		.high		= Vm(1,0,2,'h'),		/* 1.0.2h */
		.id		= "CVE-2016-6304",
		.name		= "OCSP status request extension",
		.comment	= "For more information see https://www.openssl.org/news/secadv/20160922.txt"
	},
};
#endif /* ENABLE_OPENSSL_VERSION_CHECK */

#if OPENSSL_VERSION_NUMBER < 0x10100000L
/*
 *	If we're linking against OpenSSL, then it is the
 *	duty of the application, if it is multithreaded,
 *	to provide OpenSSL with appropriate thread id
 *	and mutex locking functions
 *
 *	Note: this only implements static callbacks.
 *	OpenSSL does not use dynamic locking callbacks
 *	right now, but may in the future, so we will have
 *	to add them at some point.
 */
static pthread_mutex_t *global_mutexes = NULL;

static unsigned long _thread_id(void)
{
	unsigned long ret;
	pthread_t thread = pthread_self();

	if (sizeof(ret) >= sizeof(thread)) {
		memcpy(&ret, &thread, sizeof(thread));
	} else {
		memcpy(&ret, &thread, sizeof(ret));
	}

	return ret;
}

/*
 *	Use preprocessor magic to get the right function and argument
 *	to use.  This avoids ifdef's through the rest of the code.
 */
static void ssl_id_function(CRYPTO_THREADID *id)
{
	CRYPTO_THREADID_set_numeric(id, _thread_id());
}
#define set_id_callback CRYPTO_THREADID_set_callback


static void _global_mutex(int mode, int n, UNUSED char const *file, UNUSED int line)
{
	if (mode & CRYPTO_LOCK) {
		pthread_mutex_lock(&(global_mutexes[n]));
	} else {
		pthread_mutex_unlock(&(global_mutexes[n]));
	}
}

/** Free the static mutexes we allocated for OpenSSL
 *
 */
static int _global_mutexes_free(pthread_mutex_t *mutexes)
{
	size_t i;

	/*
	 *	Ensure OpenSSL doesn't use the locks
	 */
	CRYPTO_set_id_callback(NULL);
	CRYPTO_set_locking_callback(NULL);

	/*
	 *	Destroy all the mutexes
	 */
	for (i = 0; i < talloc_array_length(mutexes); i++) pthread_mutex_destroy(&(mutexes[i]));

	return 0;
}

/** OpenSSL uses static mutexes which we need to initialise
 *
 * @note Yes, these really are global.
 *
 * @param ctx to alloc mutexes/array in.
 * @return array of mutexes.
 */
static pthread_mutex_t *global_mutexes_init(TALLOC_CTX *ctx)
{
	int i = 0;
	pthread_mutex_t *mutexes;

#define SETUP_CRYPTO_LOCK if (i < CRYPTO_num_locks()) pthread_mutex_init(&(mutexes[i++]), NULL)

	mutexes = talloc_array(ctx, pthread_mutex_t, CRYPTO_num_locks());
	if (!mutexes) {
		ERROR("Error allocating memory for OpenSSL mutexes!");
		return NULL;
	}

	talloc_set_destructor(mutexes, _global_mutexes_free);

	/*
	 *	Some profiling tools only give us the line the mutex
	 *	was initialised on.  In that case this allows us to
	 *	see which of the mutexes in the profiling tool relates
	 *	to which OpenSSL mutex.
	 *
	 *	OpenSSL locks are usually indexed from 1, but just to
	 *	be sure we initialise index 0 too.
	 */
	SETUP_CRYPTO_LOCK; /* UNUSED */
	SETUP_CRYPTO_LOCK; /* 1  - CRYPTO_LOCK_ERR */
	SETUP_CRYPTO_LOCK; /* 2  - CRYPTO_LOCK_EX_DATA */
	SETUP_CRYPTO_LOCK; /* 3  - CRYPTO_LOCK_X509 */
	SETUP_CRYPTO_LOCK; /* 4  - CRYPTO_LOCK_X509_INFO */
	SETUP_CRYPTO_LOCK; /* 5  - CRYPTO_LOCK_X509_PKEY */
	SETUP_CRYPTO_LOCK; /* 6  - CRYPTO_LOCK_X509_CRL */
	SETUP_CRYPTO_LOCK; /* 7  - CRYPTO_LOCK_X509_REQ */
	SETUP_CRYPTO_LOCK; /* 8  - CRYPTO_LOCK_DSA */
	SETUP_CRYPTO_LOCK; /* 9  - CRYPTO_LOCK_RSA */
	SETUP_CRYPTO_LOCK; /* 10 - CRYPTO_LOCK_EVP_PKEY */
	SETUP_CRYPTO_LOCK; /* 11 - CRYPTO_LOCK_X509_STORE */
	SETUP_CRYPTO_LOCK; /* 12 - CRYPTO_LOCK_SSL_CTX */
	SETUP_CRYPTO_LOCK; /* 13 - CRYPTO_LOCK_SSL_CERT */
	SETUP_CRYPTO_LOCK; /* 14 - CRYPTO_LOCK_SSL_SESSION */
	SETUP_CRYPTO_LOCK; /* 15 - CRYPTO_LOCK_SSL_SESS_CERT */
	SETUP_CRYPTO_LOCK; /* 16 - CRYPTO_LOCK_SSL */
	SETUP_CRYPTO_LOCK; /* 17 - CRYPTO_LOCK_SSL_METHOD */
	SETUP_CRYPTO_LOCK; /* 18 - CRYPTO_LOCK_RAND */
	SETUP_CRYPTO_LOCK; /* 19 - CRYPTO_LOCK_RAND2 */
	SETUP_CRYPTO_LOCK; /* 20 - CRYPTO_LOCK_MALLOC */
	SETUP_CRYPTO_LOCK; /* 21 - CRYPTO_LOCK_BIO  */
	SETUP_CRYPTO_LOCK; /* 22 - CRYPTO_LOCK_GETHOSTBYNAME */
	SETUP_CRYPTO_LOCK; /* 23 - CRYPTO_LOCK_GETSERVBYNAME */
	SETUP_CRYPTO_LOCK; /* 24 - CRYPTO_LOCK_READDIR */
	SETUP_CRYPTO_LOCK; /* 25 - CRYPTO_LOCRYPTO_LOCK_RSA_BLINDING */
	SETUP_CRYPTO_LOCK; /* 26 - CRYPTO_LOCK_DH */
	SETUP_CRYPTO_LOCK; /* 27 - CRYPTO_LOCK_MALLOC2  */
	SETUP_CRYPTO_LOCK; /* 28 - CRYPTO_LOCK_DSO */
	SETUP_CRYPTO_LOCK; /* 29 - CRYPTO_LOCK_DYNLOCK */
	SETUP_CRYPTO_LOCK; /* 30 - CRYPTO_LOCK_ENGINE */
	SETUP_CRYPTO_LOCK; /* 31 - CRYPTO_LOCK_UI */
	SETUP_CRYPTO_LOCK; /* 32 - CRYPTO_LOCK_ECDSA */
	SETUP_CRYPTO_LOCK; /* 33 - CRYPTO_LOCK_EC */
	SETUP_CRYPTO_LOCK; /* 34 - CRYPTO_LOCK_ECDH */
	SETUP_CRYPTO_LOCK; /* 35 - CRYPTO_LOCK_BN */
	SETUP_CRYPTO_LOCK; /* 36 - CRYPTO_LOCK_EC_PRE_COMP */
	SETUP_CRYPTO_LOCK; /* 37 - CRYPTO_LOCK_STORE */
	SETUP_CRYPTO_LOCK; /* 38 - CRYPTO_LOCK_COMP */
	SETUP_CRYPTO_LOCK; /* 39 - CRYPTO_LOCK_FIPS  */
	SETUP_CRYPTO_LOCK; /* 40 - CRYPTO_LOCK_FIPS2 */

	/*
	 *	Incase more are added *sigh*
	 */
	while (i < CRYPTO_num_locks()) SETUP_CRYPTO_LOCK;

	set_id_callback(ssl_id_function);
	CRYPTO_set_locking_callback(_global_mutex);

	return mutexes;
}
#endif

#ifdef ENABLE_OPENSSL_VERSION_CHECK
/** Check for vulnerable versions of libssl
 *
 * @param acknowledged The highest CVE number a user has confirmed is not present in the system's
 *	libssl.
 * @return 0 if the CVE specified by the user matches the most recent CVE we have, else -1.
 */
int fr_openssl_version_check(char const *acknowledged)
{
	uint64_t v;
	bool bad = false;
	size_t i;

	/*
	 *	Didn't get passed anything, that's an error.
	 */
	if (!acknowledged || !*acknowledged) {
		ERROR("Refusing to start until 'allow_vulnerable_openssl' is given a value");
		return -1;
	}

	if (strcmp(acknowledged, "yes") == 0) return 0;

	/* Check for bad versions */
	v = (uint64_t) SSLeay();

	for (i = 0; i < (NUM_ELEMENTS(fr_openssl_defects)); i++) {
		fr_openssl_defect_t *defect = &fr_openssl_defects[i];

		if ((v >= defect->low) && (v <= defect->high)) {
			/*
			 *	If the CVE is acknowledged, allow it.
			 */
			if (!bad && (strcmp(acknowledged, defect->id) == 0)) return 0;

			ERROR("Refusing to start with libssl version %s (in range %s)",
			      ssl_version(), ssl_version_range(defect->low, defect->high));
			ERROR("Security advisory %s (%s)", defect->id, defect->name);
			ERROR("%s", defect->comment);

			/*
			 *	Only warn about the first one...
			 */
			if (!bad) {
				INFO("Once you have verified libssl has been correctly patched, "
				     "set security.allow_vulnerable_openssl = '%s'", defect->id);
				bad = true;
			}
		}
	}

	if (bad) return -1;

	return 0;
}
#endif

/** Allocate memory for OpenSSL in the NULL context
 *
 * @param len to alloc.
 * @return realloc.
 */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
static void *fr_openssl_talloc(size_t len, UNUSED char const *file, UNUSED int line)
#else
static void *fr_openssl_talloc(size_t len)
#endif
{
	return talloc_array(ssl_talloc_ctx, uint8_t, len);
}

/** Reallocate memory for OpenSSL in the NULL context
 *
 * @param old memory to realloc.
 * @param len to extend to.
 * @return realloced memory.
 */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
static void *fr_openssl_talloc_realloc(void *old, size_t len, UNUSED char const *file, UNUSED int line)
#else
static void *fr_openssl_talloc_realloc(void *old, size_t len)
#endif
{
	return talloc_realloc_size(ssl_talloc_ctx, old, len);
}

/** Free memory allocated by OpenSSL
 *
 * @param to_free memory to free.
 */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
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
#else
static void fr_openssl_talloc_free(void *to_free)
{
	(void)talloc_free(to_free);
}
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
void fr_openssl_free(void)
{
	if (--instance_count > 0) return;

	/*
	 *	If we linked with OpenSSL, the application
	 *	must remove the thread's error queue before
	 *	exiting to prevent memory leaks.
	 */
	ERR_remove_thread_state(NULL);
	ENGINE_cleanup();
	CONF_modules_unload(1);
	ERR_free_strings();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();

	TALLOC_FREE(global_mutexes);

	fr_dict_autofree(tls_dict);
}
#else
/** Free any memory alloced by libssl
 *
 * OpenSSL >= 1.1.0 uses an atexit handler to automatically free
 * memory. However, we need to call OPENSSL_cleanup manually because
 * some of the SSL ctx is parented to the main config which will get
 * freed before the atexit handler, causing a segfault on exit.
 */
void fr_openssl_free(void)
{
	OPENSSL_cleanup();
	fr_dict_autofree(tls_dict);
}
#endif



/** Add all the default ciphers and message digests to our context.
 *
 * This should be called exactly once from main, before reading the main config
 * or initialising any modules.
 */
int fr_openssl_init(void)
{
	ENGINE *rand_engine;

	if (instance_count > 0) {
		instance_count++;
		return 0;
	}

	/*
	 *	This will only fail if memory has already been allocated
	 *	by OpenSSL.
	 */
	if (CRYPTO_set_mem_functions(fr_openssl_talloc, fr_openssl_talloc_realloc, fr_openssl_talloc_free) != 1) {
		fr_tls_log_error(NULL, "Failed to set OpenSSL memory allocation functions.  fr_openssl_init() called too late");
		return -1;
	}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	SSL_load_error_strings();	/* Readable error messages (examples show call before library_init) */
	SSL_library_init();		/* Initialize library */
	OpenSSL_add_all_algorithms();	/* Required for SHA2 in OpenSSL < 0.9.8o and 1.0.0.a */
	ENGINE_load_builtin_engines();	/* Needed to load AES-NI engine (also loads rdrand, boo) */

#  ifdef HAVE_OPENSSL_EVP_SHA256
	/*
	 *	SHA256 is in all versions of OpenSSL, but isn't
	 *	initialized by default.  It's needed for WiMAX
	 *	certificates.
	 */
	EVP_add_digest(EVP_sha256());
#  endif
	/*
	 *	If we're linking with OpenSSL too, then we need
	 *	to set up the mutexes and enable the thread callbacks.
	 */
	global_mutexes = global_mutexes_init(NULL);
	if (!global_mutexes) {
		ERROR("Failed to set up SSL mutexes");
		fr_openssl_free();
		return -1;
	}

	OPENSSL_config(NULL);
#else
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG | OPENSSL_INIT_ENGINE_ALL_BUILTIN, NULL);
#endif

	/*
	 *	Mirror the paranoia found elsewhere on the net,
	 *	and disable rdrand as the default random number
	 *	generator.
	 */
	rand_engine = ENGINE_get_default_RAND();
	if (rand_engine && (strcmp(ENGINE_get_id(rand_engine), "rdrand") == 0)) ENGINE_unregister_RAND(rand_engine);
	ENGINE_register_all_complete();

	instance_count++;

	return 0;
}

/** Load dictionary attributes
 *
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

	return 0;
}

#endif /* WITH_TLS */
