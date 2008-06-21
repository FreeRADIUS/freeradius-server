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

/*
 *	Display the revision number for this program
 */
void NEVER_RETURNS version(void)
{

	printf("%s: %s\n", progname, radiusd_version);
#if 0
	printf("Compilation flags: ");

	/* here are all the conditional feature flags */
#if defined(OSFC2)
	printf(" OSFC2");
#endif
	printf("\n");
#endif
	printf("Copyright (C) 1999-2008 The FreeRADIUS server project and contributors.\n");
	printf("There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A\n");
	printf("PARTICULAR PURPOSE.\n");
	printf("You may redistribute copies of FreeRADIUS under the terms of the\n");
	printf("GNU General Public License.\n");
	printf("For more information about these matters, see the file named COPYRIGHT.\n");
	exit (0);
}

