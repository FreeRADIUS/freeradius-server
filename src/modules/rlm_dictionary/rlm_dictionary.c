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
	NULL,            		/* authorization */
	NULL,               		/* authentication */
	NULL,            		/* preaccounting */
	NULL,              		/* accounting */
	NULL,				/* detach */
	NULL 				/* destroy */
};
