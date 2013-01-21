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
void version(void)
{
	radlog(L_INFO, "%s: %s", progname, radiusd_version);
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
#ifdef HAVE_PCREPOSIX_H
	DEBUG3("  regex-pcre");
#else
#ifdef HAVE_REGEX_H
	DEBUG3("  regex-posix");
#endif
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
	radlog(L_INFO, "Copyright (C) 1999-2013 The FreeRADIUS server project and contributors.");
	radlog(L_INFO, "There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A");
	radlog(L_INFO, "PARTICULAR PURPOSE.");
	radlog(L_INFO, "You may redistribute copies of FreeRADIUS under the terms of the");
	radlog(L_INFO, "GNU General Public License.");
	radlog(L_INFO, "For more information about these matters, see the file named COPYRIGHT.");
	
	fflush(NULL);
}

