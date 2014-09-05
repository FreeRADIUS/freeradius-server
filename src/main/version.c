/*
 * version.c	Print version number and exit.
 *
 * Version:	$Id$
 *
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
 *
 * Copyright 1999-2014  The FreeRADIUS server project
 * Copyright 2012  Alan DeKok <aland@ox.org>
 * Copyright 2000  Chris Parker <cparker@starnetusa.com>
 */

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

static uint64_t libmagic = RADIUSD_MAGIC_NUMBER;

#ifdef HAVE_OPENSSL_CRYPTO_H
#  include <openssl/crypto.h>
#  include <openssl/opensslv.h>

static long ssl_built = OPENSSL_VERSION_NUMBER;

/** Check built and linked versions of OpenSSL match
 *
 * OpenSSL version number consists of:
 * MMNNFFPPS: major minor fix patch status
 *
 * Where status >= 0 && < 10 means beta, and status 10 means release.
 *
 * Startup check for whether the linked version of OpenSSL matches the
 * version the server was built against.
 *
 * @return 0 if ok, else -1
 */
int ssl_check_consistency(void)
{
	long ssl_linked;

	ssl_linked = SSLeay();

	/*
	 *	Status mismatch always triggers error.
	 */
	if ((ssl_linked & 0x00000000f) != (ssl_built & 0x00000000f)) {
	mismatch:
		ERROR("libssl version mismatch.  built: %lx linked: %lx",
		       (unsigned long) ssl_built,
		       (unsigned long) ssl_linked);

		return -1;
	}

	/*
	 *	Use the OpenSSH approach and relax fix checks after version
	 *	1.0.0 and only allow moving backwards within a patch
	 *	series.
	 */
	if (ssl_built & 0xff) {
		if ((ssl_built & 0xffff) != (ssl_linked & 0xffff) ||
		    (ssl_built & 0x0000ff) > (ssl_linked & 0x0000ff)) goto mismatch;
	/*
	 *	Before 1.0.0 we require the same major minor and fix version
	 *	and ignore the patch number.
	 */
	} else if ((ssl_built & 0xffffff) != (ssl_linked & 0xffffff)) goto mismatch;

	return 0;
}

/** Convert a version number to a text string
 *
 * @note Not thread safe.
 *
 * @param v version to convert.
 * @return pointer to a static buffer containing the version string.
 */
char const *ssl_version_by_num(uint64_t v)
{
	/* 2 (%s) + 1 (.) + 2 (%i) + 1 (.) + 2 (%i) + 1 (c) + 1 (-) + 2 (%i) + \0 */
	static char buffer[13];
	char *p = buffer;

	p += sprintf(p, "%i.%i.%i",
		     (int) ((0xff0000000 & v) >> 28),
		     (int) ((0x00ff00000 & v) >> 20),
		     (int) ((0x0000ff000 & v) >> 12));

	if ((0x000000ff0 & v) >> 4) {
		*p++ =  (char) (0x60 + ((0x000000ff0 & v) >> 4));
	}

	sprintf(p, "-%i", (int) (0x00000000f & v));

	return buffer;
}

/** Convert two openssl version numbers into a range string
 *
 * @note Not thread safe.
 *
 * @param low version to convert.
 * @param high version to convert.
 * @return pointer to a static buffer containing the version range string.
 */
char const *ssl_version_range(uint64_t low, uint64_t high)
{
	/* 12 (version) + 3 ( - ) + 12 (version) */
	static char buffer[28];
	char *p = buffer;

	p += strlcpy(p, ssl_version_by_num(low), sizeof(buffer));
	p += strlcpy(p, " - ", sizeof(buffer) - (p - buffer));
	strlcpy(p, ssl_version_by_num(high), sizeof(buffer) - (p - buffer));

	return buffer;
}

/** Print the current linked version of Openssl
 *
 * Print the currently linked version of the OpenSSL library.
 *
 * @note Not thread safe.
 * @return pointer to a static buffer containing libssl version information.
 */
char const *ssl_version(void)
{
	static char buffer[256];

	uint64_t v = (uint64_t) SSLeay();

	snprintf(buffer, sizeof(buffer), "%s 0x%.9" PRIx64 " (%s)",
		 SSLeay_version(SSLEAY_VERSION),		/* Not all builds include a useful version number */
		 v,
		 ssl_version_by_num((uint64_t) v));

	return buffer;
}
#  else
int ssl_check_consistency(void) {
	return 0;
}

char const *ssl_version()
{
	return "not linked";
}
#endif /* ifdef HAVE_OPENSSL_CRYPTO_H */


/** Check if the application linking to the library has the correct magic number
 *
 * @param magic number as defined by RADIUSD_MAGIC_NUMBER
 * @returns 0 on success, -1 on prefix mismatch, -2 on version mismatch -3 on commit mismatch.
 */
int rad_check_lib_magic(uint64_t magic)
{
	if (MAGIC_PREFIX(magic) != MAGIC_PREFIX(libmagic)) {
		ERROR("Application and libfreeradius-server magic number (prefix) mismatch."
		      "  application: %x library: %x",
		      MAGIC_PREFIX(magic), MAGIC_PREFIX(libmagic));
		return -1;
	}

	if (MAGIC_VERSION(magic) != MAGIC_VERSION(libmagic)) {
		ERROR("Application and libfreeradius-server magic number (version) mismatch."
		      "  application: %lx library: %lx",
		      (unsigned long) MAGIC_VERSION(magic), (unsigned long) MAGIC_VERSION(libmagic));
		return -2;
	}

	if (MAGIC_COMMIT(magic) != MAGIC_COMMIT(libmagic)) {
		ERROR("Application and libfreeradius-server magic number (commit) mismatch."
		      "  application: %lx library: %lx",
		      (unsigned long) MAGIC_COMMIT(magic), (unsigned long) MAGIC_COMMIT(libmagic));
		return -3;
	}

	return 0;
}

/*
 *	Display the revision number for this program
 */
void version(void)
{
	INFO("%s: %s", progname, radiusd_version);

	DEBUG3("Server was built with: ");

#ifdef WITH_ACCOUNTING
	DEBUG3("  accounting");
#endif
	DEBUG3("  authentication"); /* always enabled */

#ifdef WITH_ASCEND_BINARY
	DEBUG3("  ascend binary attributes");
#endif
#ifdef WITH_COA
	DEBUG3("  coa");
#endif
#ifdef WITH_COMMAND_SOCKET
	DEBUG3("  control-socket");
#endif
#ifdef WITH_DETAIL
	DEBUG3("  detail");
#endif
#ifdef WITH_DHCP
	DEBUG3("  dhcp");
#endif
#ifdef WITH_DYNAMIC_CLIENTS
	DEBUG3("  dynamic clients");
#endif
#ifdef OSFC2
	DEBUG3("  OSFC2");
#endif
#ifdef WITH_PROXY
	DEBUG3("  proxy");
#endif
#ifdef HAVE_PCRE
	DEBUG3("  regex-pcre");
#else
#  ifdef HAVE_REGEX
#    ifdef HAVE_REG_EXTENDED
	DEBUG3("  regex-posix-extended");
#    else
	DEBUG3("  regex-posix");
#    endif
#  endif
#endif

#ifdef WITH_SESSION_MGMT
	DEBUG3("  session-management");
#endif
#ifdef WITH_STATS
	DEBUG3("  stats");
#endif
#ifdef WITH_TCP
	DEBUG3("  tcp");
#endif
#ifdef WITH_THREADS
	DEBUG3("  threads");
#endif
#ifdef WITH_TLS
	DEBUG3("  tls");
#endif
#ifdef WITH_UNLANG
	DEBUG3("  unlang");
#endif
#ifdef WITH_VMPS
	DEBUG3("  vmps");
#endif
#ifndef NDEBUG
	DEBUG3("  developer");
#endif

	DEBUG3("Server core libs:");
	DEBUG3("  talloc : %i.%i.*", talloc_version_major(), talloc_version_minor());
	DEBUG3("  ssl    : %s", ssl_version());

	DEBUG3("Library magic number:");
	DEBUG3("  0x%llx", (unsigned long long) libmagic);

	DEBUG3("Endianess:");
#if defined(LITTLE_ENDIAN)
	DEBUG3("  little");
#elif defined(BIG_ENDIAN)
	DEBUG3("  big");
#else
	DEBUG3("  unknown");
#endif

	INFO("Copyright (C) 1999-2014 The FreeRADIUS server project and contributors");
	INFO("There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A");
	INFO("PARTICULAR PURPOSE");
	INFO("You may redistribute copies of FreeRADIUS under the terms of the");
	INFO("GNU General Public License");
	INFO("For more information about these matters, see the file named COPYRIGHT");

	fflush(NULL);
}

