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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2000  The FreeRADIUS server project
 * Copyright 2000  Alan DeKok <aland@ox.org>
 * Copyright 2000  Chris Parker <cparker@starnetusa.com>
 */

static const char rcsid[] = "$Id$";

#include "autoconf.h"
#include "libradius.h"

#include <stdio.h>
#include <stdlib.h>
#include "radiusd.h"

/*
 *	Display the revision number for this program
 */
void version(void)
{

	fprintf(stderr, "%s: %s\n", progname, radiusd_version);
#if 0
	fprintf(stderr, "Compilation flags: ");

	/* here are all the conditional feature flags */
#if defined(OSFC2)
	fprintf(stderr," OSFC2");
#endif
#if defined(WITH_SNMP)
	fprintf(stderr," WITH_SNMP");
#endif
	fprintf(stderr,"\n");
#endif
	exit (0);
}

