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
 * @file tls/version.c
 * @brief Check OpenSSL library/header consistency, and process version information.
 *
 * @copyright 2022 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
#define LOG_PREFIX "tls"

#include "version.h"

#ifdef WITH_TLS
#include <freeradius-devel/server/log.h>

static long ssl_built = OPENSSL_VERSION_NUMBER;

/** Check built and linked versions of OpenSSL match
 *
 * OpenSSL version number consists of:
 * MNNFFPPS: major minor fix patch status
 *
 * Where status >= 0 && < 10 means beta, and status 10 means release.
 *
 *	https://wiki.openssl.org/index.php/Versioning
 *
 * Startup check for whether the linked version of OpenSSL matches the
 * version the server was built against.
 *
 * @return
 *	- 0 if ok.
 *	- -1 if not ok.
 */
int fr_openssl_version_consistent(void)
{
	unsigned long ssl_linked;

	ssl_linked = OpenSSL_version_num();


	/*
	 *	Major mismatch, that's bad.
	 *
	 *	For OpenSSL 3, the minor versions are API/ABI compatible.
	 *
	 *	https://openssl-library.org/policies/releasestrat/index.html
	 */
	if ((ssl_linked & 0xff000000) != (ssl_built & 0xff000000)) {
		ERROR("libssl version mismatch.  built: %lx linked: %lx",
		      (unsigned long) ssl_built,
		      (unsigned long) ssl_linked);
		return -1;
	}

	return 0;
}

/** Convert a version number to a text string
 *
 * @note Not thread safe.
 *
 * @param v version to convert.
 * @return pointer to a static buffer containing the version string.
 */
static char const *fr_openssl_version_str_from_num(uint32_t v)
{
	/* 2 (%s) + 1 (.) + 2 (%i) + 1 (.) + 2 (%i) + 1 (c) + 8 (%s) + \0 */
	static _Thread_local char buffer[18];

	/*
	 *	OpenSSL major versions >= 3 (which FreeRADIUS requires) use the
	 *	new version number layout
	 *
	 * 	OPENSSL_VERSION_NUMBER is a combination of the major, minor
	 *	and patch version into a single integer 0xMNN00PP0L, where:
	 *
	 *	M is the number from OPENSSL_VERSION_MAJOR, in hexadecimal notation.
	 *	NN is the number from OPENSSL_VERSION_MINOR, in hexadecimal notation.
	 *	PP is the number from OPENSSL_VERSION_PATCH, in hexadecimal notation.
	 */
	snprintf(buffer, sizeof(buffer), "%u.%u.%u",
		 (0xf0000000 & v) >> 28,
		 (0x0ff00000 & v) >> 20,
		 (0x00000ff0 & v) >> 4);

	return buffer;
}

/** Convert two openssl version numbers into a range string
 *
 * @param[in] low version to convert.
 * @param[in] high version to convert.
 * @return pointer to a static buffer containing the version range string.
 */
char const *fr_openssl_version_range(uint32_t low, uint32_t high)
{
	/* 18 (version) + 3 ( - ) + 18 (version) */
	static _Thread_local char buffer[40];
	char *p = buffer;

	p += strlcpy(p, fr_openssl_version_str_from_num(low), sizeof(buffer));
	p += strlcpy(p, " - ", sizeof(buffer) - (p - buffer));
	strlcpy(p, fr_openssl_version_str_from_num(high), sizeof(buffer) - (p - buffer));

	return buffer;
}

/** Return the linked SSL version number as a string
 *
 * @return pointer to a static buffer containing the version string.
 */
char const *fr_openssl_version_basic(void)
{
	unsigned long ssl_linked;

	ssl_linked = OpenSSL_version_num();
	return fr_openssl_version_str_from_num((uint32_t)ssl_linked);
}

/** Print the current linked version of Openssl
 *
 * Print the currently linked version of the OpenSSL library.
 *
 * @return pointer to a static buffer containing libssl version information.
 */
char const *fr_openssl_version_expanded(void)
{
	static _Thread_local char buffer[256];

	unsigned long v = OpenSSL_version_num();

	snprintf(buffer, sizeof(buffer), "%s 0x%.8lx (%s)",
		 OpenSSL_version(OPENSSL_VERSION),		/* Not all builds include a useful version number */
		 v,
		 fr_openssl_version_str_from_num(v));

	return buffer;
}

#  ifdef ENABLE_OPENSSL_VERSION_CHECK
typedef struct {
	uint64_t	high;		//!< The last version number this defect affected.
	uint64_t	low;		//!< The first version this defect affected.

	char const	*id;		//!< CVE (or other ID)
	char const	*name;		//!< As known in the media...
	char const	*comment;	//!< Where to get more information.
} fr_openssl_defect_t;

#  undef VM
#  undef Vm
#  define VM(_a,_b,_c) (((((_a) << 24) | ((_b) << 16) | ((_c) << 8)) << 4) | 0x0f)
#  define Vm(_a,_b,_c,_d) (((((_a) << 24) | ((_b) << 16) | ((_c) << 8) | ((_d) - 'a' + 1)) << 4) | 0x0f)

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
	}
};

/** Check for vulnerable versions of libssl
 *
 * @param acknowledged The highest CVE number a user has confirmed is not present in the system's
 *	libssl.
 * @return 0 if the CVE specified by the user matches the most recent CVE we have, else -1.
 */
int fr_openssl_version_check(char const *acknowledged)
{
	bool bad = false;
	size_t i;
	unsigned long ssl_linked;


	/*
	 *	Didn't get passed anything, that's an error.
	 */
	if (!acknowledged || !*acknowledged) {
		ERROR("Refusing to start until 'allow_vulnerable_openssl' is given a value");
		return -1;
	}

	if (strcmp(acknowledged, "yes") == 0) return 0;

	/* Check for bad versions */
	ssl_linked = OpenSSL_version_num();
	for (i = 0; i < (NUM_ELEMENTS(fr_openssl_defects)); i++) {
		fr_openssl_defect_t *defect = &fr_openssl_defects[i];

		if ((ssl_linked >= defect->low) && (ssl_linked <= defect->high)) {
			/*
			 *	If the CVE is acknowledged, allow it.
			 */
			if (!bad && (strcmp(acknowledged, defect->id) == 0)) return 0;

			ERROR("Refusing to start with libssl version %s (in range %s)",
			      fr_openssl_version_expanded(), fr_openssl_version_range(defect->low, defect->high));
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
#  endif
#else
int fr_openssl_version_consistent(void) {
	return 0;
}

char const *fr_openssl_version_basic(void)
{
	return "not linked";
}

char const *fr_openssl_version_expanded(void)
{
	return "not linked";
}
#endif /* ifdef WITH_TLS */
