/*
 * missing.h	Replacements for functions that are or can be
 *		missing on some platforms.
 *
 * Version:	$Id$
 *
 */

#ifndef HAVE_CRYPT
char *crypt(char *key, char *salt);
#endif

