/*
 * version.c	Print version number and exit.
 *
 * Version:	$Id$
 *
 */
static const char rcsid[] = "$Id$";

#include	"autoconf.h"
#include	"libradius.h"

#include	<stdio.h>
#include	<stdlib.h>
#include	"radiusd.h"

/*
 *	Version number. This should ideally be created by autoconf
 *	or similar, so that this would always be up to date.
 */
#define		VERSION		"FreeRADIUS ALPHA, built on " __DATE__ 

/*
 *	Display the revision number for this program
 */
void version(void)
{

	fprintf(stderr, "%s: RADIUS version " VERSION ".\n", progname);
	fprintf(stderr, "Compilation flags: ");

	/* here are all the conditional feature flags */
#if defined(OSFC2)
	fprintf(stderr," OSFC2");
#endif
#if defined(WITH_DICT_NOCASE)
	fprintf(stderr," WITH_DICT_NOCASE");
#endif
#if defined(WITH_SNMP)
	fprintf(stderr," WITH_SNMP");
#endif
	fprintf(stderr,"\n");
	exit (0);
}

