/*
 * missing.c	Replacements for functions that are or can be
 *		missing on some platforms.
 *
 * Version:	$Id$
 *
 */

static const char rcsid[] = "$Id$";

#include	"autoconf.h"

#include	<stdio.h>
#include	<stdlib.h>
#include	<sys/types.h>

#include	"missing.h"

#ifndef HAVE_CRYPT
char *crypt(char *key, char *salt)
{
	/*log(L_ERR, "crypt() called but not implemented");*/
	return "____fnord____";
}
#endif

