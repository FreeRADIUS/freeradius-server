/*
 * rlm_dictionary.c	
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
 * Copyright 2000  Alan Curry <pacman-radius@cqc.com>
 */

#include "autoconf.h"
#include <stdio.h>
#include <stdlib.h>

#include "radiusd.h"
#include "modules.h"
#include "conffile.h"

static const char rcsid[] = "$Id$";

/*
 *	Do any per-module initialization.  e.g. set up connections
 *	to external databases, read configuration files, set up
 *	dictionary entries, etc.
 *
 */
static int radius_init(void)
{
        /* Initialize the dictionary */
	if (dict_init(radius_dir, RADIUS_DICTIONARY) != 0) {
		radlog(L_ERR|L_CONS, "Errors reading dictionary %s/%s: %s",
		    radius_dir, RADIUS_DICTIONARY, librad_errstr);
		return -1;
	}

	/*
	 *	Everything's OK, return without an error.
	 */
	return 0;
}

/* globally exported name */
module_t rlm_dictionary = {
	"dictionary",
	0,				/* type: reserved */
	radius_init,			/* initialization */
	NULL,            		/* instantiation */
	{
		NULL,               	/* authentication */
		NULL,            	/* authorization */
		NULL,            	/* preaccounting */
		NULL,              	/* accounting */
		NULL              	/* checksimul */
	},
	NULL,				/* detach */
	NULL 				/* destroy */
};
