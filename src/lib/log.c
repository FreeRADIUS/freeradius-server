/*
 * log.c	Functions in the library call radlib_log() which
 *		sets a global error string "char *librad_errstr".
 *
 * Version:	@(#)log.c  1.00  25-Oct-1998  miquels@cistron.nl
 *
 */

#include "autoconf.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

char librad_errstr[1024];

void librad_log(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
#ifdef HAVE_VSNPRINTF
	vsnprintf(librad_errstr, sizeof(librad_errstr), fmt, ap);
#else
	vsprintf(librad_errstr, fmt, ap);
#endif
	va_end(ap);
}

void librad_perror(char *fmt, ...)
{
	va_list *ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	if (strchr(fmt, ':') == NULL)
		fprintf(stderr, ": ");
	fprintf(stderr, "%s\n", librad_errstr);
}

