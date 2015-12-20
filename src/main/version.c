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
 * Copyright 1999-2008  The FreeRADIUS server project
 * Copyright 2000  Alan DeKok <aland@ox.org>
 * Copyright 2000  Chris Parker <cparker@starnetusa.com>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>


#ifdef HAVE_OPENSSL_CRYPTO_H
#include <openssl/crypto.h>
#include <openssl/opensslv.h>

static long ssl_built = OPENSSL_VERSION_NUMBER;

/** Print the current linked version of Openssl
 *
 * Print the currently linked version of the OpenSSL library.
 */
const char *ssl_version(void)
{
	return SSLeay_version(SSLEAY_VERSION);
}
#else
const char *ssl_version()
{
	return "not linked";
}
#endif


/** Check built and linked versions of OpenSSL match
 *
 * OpenSSL version number consists of:
 * MNNFFPPS: major minor fix patch status
 *
 * Where status >= 0 && < 10 means beta, and status 10 means release.
 *
 * Startup check for whether the linked version of OpenSSL matches the
 * version the server was built against.
 *
 * @return 0 if ok, else -1
 */
#ifdef HAVE_OPENSSL_CRYPTO_H
int ssl_check_version()
{
	long ssl_linked;

	ssl_linked = SSLeay();

	/*
	 *	Status mismatch always triggers error.
	 */
	if ((ssl_linked & 0x0000000f) != (ssl_built & 0x0000000f)) {
	mismatch:
		radlog(L_ERR, "libssl version mismatch.  built: %lx linked: %lx",
		       (unsigned long) ssl_built, (unsigned long) ssl_linked);

		return -1;
	}

	/*
	 *	Use the OpenSSH approach and relax fix checks after version
	 *	1.0.0 and only allow moving backwards within a patch
	 *	series.
	 */
	if (ssl_built & 0xf0000000) {
		if ((ssl_built & 0xfffff000) != (ssl_linked & 0xfffff000) ||
		    (ssl_built & 0x00000ff0) > (ssl_linked & 0x00000ff0)) goto mismatch;
	/*
	 *	Before 1.0.0 we require the same major minor and fix version
	 *	and ignore the patch number.
	 */
	} else if ((ssl_built & 0xfffff000) != (ssl_linked & 0xfffff000)) goto mismatch;

	return 0;
}

/** Check OpenSSL version for known vulnerabilities.
 *
 * OpenSSL version number consists of:
 * MNNFFPPS: major minor fix patch status
 *
 * Where status >= 0 && < 10 means beta, and status 10 means release.
 *
 * Startup check for whether the linked version of OpenSSL is a version known to
 * have serious vulnerabilities impacting FreeRADIUS.
 *
 * @return 0 if ok, else -1
 */
#  ifdef ENABLE_OPENSSL_VERSION_CHECK
int ssl_check_vulnerable()
{
	long ssl_linked;

	ssl_linked = SSLeay();

	/* Check for bad versions */
	/* 1.0.1 - 1.0.1f CVE-2014-0160 http://heartbleed.com */
	if ((ssl_linked >= 0x010001000) && (ssl_linked < 0x010001070)) {
		radlog(L_ERR, "Refusing to start with libssl version %s (in range 1.0.1 - 1.0.1f).  "
		      "Security advisory CVE-2014-0160 (Heartbleed)", ssl_version());
		radlog(L_ERR, "For more information see http://heartbleed.com");

		return -1;
	}

	return 0;
}
#  endif

#endif

/*
 *	Display the revision number for this program
 */
void version(void)
{

	radlog(L_INFO, "%s: %s", progname, radiusd_version);
	DEBUG3("Server was built with: ");

#ifdef WITH_ACCOUNTING
	DEBUG3("  accounting");
#endif
	DEBUG3("  authentication"); /* always enabled */
	/* here are all the conditional feature flags */
#if defined(WITH_DHCP)
	DEBUG3(" WITH_DHCP");
#endif
#if defined(WITH_VMPS)
	DEBUG3(" WITH_VMPS");
#endif
#if defined(OSFC2)
	DEBUG3(" OSFC2");
#endif
#if defined(WITHOUT_PROXY)
	DEBUG3(" WITHOUT_PROXY");
#endif
#if defined(WITHOUT_DETAIL)
	DEBUG3(" WITHOUT_DETAIL");
#endif
#if defined(WITHOUT_SESSION_MGMT)
	DEBUG3(" WITHOUT_SESSION_MGMT");
#endif
#if defined(WITHOUT_UNLANG)
	DEBUG3(" WITHOUT_UNLANG");
#endif
#if defined(WITHOUT_ACCOUNTING)
	DEBUG3(" WITHOUT_ACCOUNTING");
#endif
#if defined(WITHOUT_DYNAMIC_CLIENTS)
	DEBUG3(" WITHOUT_DYNAMIC_CLIENTS");
#endif
#if defined(WITHOUT_STATS)
	DEBUG3(" WITHOUT_STATS");
#endif
#if defined(WITHOUT_COMMAND_SOCKET)
	DEBUG3(" WITHOUT_COMMAND_SOCKET");
#endif
#if defined(WITHOUT_COA)
	DEBUG3(" WITHOUT_COA");
#endif
	DEBUG3("Server core libs:");
	DEBUG3("  ssl: %s", ssl_version());

	radlog(L_INFO, "Copyright (C) 1999-2015 The FreeRADIUS server project and contributors.");
	radlog(L_INFO, "There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A");
	radlog(L_INFO, "PARTICULAR PURPOSE.");
	radlog(L_INFO, "You may redistribute copies of FreeRADIUS under the terms of the");
	radlog(L_INFO, "GNU General Public License.");
	radlog(L_INFO, "For more information about these matters, see the file named COPYRIGHT.");

	fflush(NULL);
}

