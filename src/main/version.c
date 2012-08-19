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
 * Copyright 1999-2012  The FreeRADIUS server project
 * Copyright 2012  Alan DeKok <aland@ox.org>
 * Copyright 2000  Chris Parker <cparker@starnetusa.com>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>

/*
 *	Display the revision number for this program
 */
void NEVER_RETURNS version(void)
{

	printf("%s: %s\n", progname, radiusd_version);

	printf("Copyright (C) 1999-2012 The FreeRADIUS server project and contributors.\n");
	printf("There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A\n");
	printf("PARTICULAR PURPOSE.\n");
	printf("You may redistribute copies of FreeRADIUS under the terms of the\n");
	printf("GNU General Public License.\n");
	printf("For more information about these matters, see the file named COPYRIGHT.\n");

	if (debug_flag) {
		printf("\n");

		printf("Functionality: ");
		
#ifdef WITH_ACCOUNTING
		printf("accounting, ");
#endif
		printf("authentication, "); /* always enabled */

#ifdef WITH_COA
		printf("coa, ");
#endif
#ifdef WITH_COMMAND_SOCKET
		printf("control-socket, ");
#endif
#ifdef WITH_DETAIL
		printf("detail, ");
#endif
#ifdef WITH_DHCP
		printf("dhcp, ");
#endif
#ifdef WITH_DYNAMIC_CLIENTS
		printf("dynamic clients, ");
#endif
#ifdef OSFC2
		printf("OSFC2, ");
#endif
#ifdef WITH_PROXY
		printf("proxy, ");
#endif
#ifdef HAVE_PCREPOSIX_H
		printf("regex-PCRE, ");
#else
#ifdef HAVE_REGEX_H
		printf("regex-posix, ");
#endif
#endif

#ifdef WITH_SESSION_MGMT
		printf("session-management, ");
#endif
#ifdef WITH_STATS
		printf("stats, ");
#endif
#ifdef WITH_TCP
		printf("tcp, ");
#endif
#ifdef WITH_TLS
		printf("TLS, ");
#endif
#ifdef WITH_UNLANG
		printf("unlang, ");
#endif
#ifdef WITH_VMPS
		printf("vmps, ");
#endif
		printf("\n");
	}

	exit (0);
}

