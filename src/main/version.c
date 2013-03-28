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

/** Check build and linked versions of OpenSSL match
 *
 * Startup check for whether the linked version of OpenSSL matches the
 * version the server was built against.
 *
 * @return 0 if ok, else -1
 */
int ssl_check_version(void)
{
	long ssl_linked;
	
	ssl_linked = SSLeay();
	
	if (ssl_linked != ssl_built) {
		radlog(L_ERR, "libssl version mismatch."
		       "  Built with: %lx\n  Linked: %lx",
		       (unsigned long) ssl_built,
		       (unsigned long) ssl_linked);
	
		return -1;
	};
	
	return 0;
}

/** Print the current linked version of Openssl
 *
 * Print the currently linked version of the OpenSSL library.
 */
const char *ssl_version(void)
{
	return SSLeay_version(SSLEAY_VERSION); 
}
#else
int ssl_version_check(void) {
	return 0;
}

const char *ssl_version()
{
	return "not linked";
}
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

	radlog(L_INFO, "Copyright (C) 1999-2013 The FreeRADIUS server project and contributors.");
	radlog(L_INFO, "There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A");
	radlog(L_INFO, "PARTICULAR PURPOSE.");
	radlog(L_INFO, "You may redistribute copies of FreeRADIUS under the terms of the");
	radlog(L_INFO, "GNU General Public License.");
	radlog(L_INFO, "For more information about these matters, see the file named COPYRIGHT.");
	
	fflush(NULL);
}

