/*
 * sysutmp.h	Compatibility stuff for the different UTMP systems.
 *
 * Version:	@(#)sysutmp.h  1.0  01-Jul-1999
 */

#ifndef SYSUTMP_H_INCLUDED
#define SYSUTMP_H_INCLUDED

/* UTMP stuff. Uses utmpx on svr4 */
#ifdef __svr4__
#  include <utmpx.h>
#  include <sys/fcntl.h>
#  define utmp utmpx
#  define UT_NAMESIZE	32
#  define UT_LINESIZE	32
#  define UT_HOSTSIZE	257
#else
#  include <utmp.h>
#endif
#ifdef __osf__
#  define UT_NAMESIZE	32
#  define UT_LINESIZE	32
#  define UT_HOSTSIZE	64
#endif
#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(bsdi)
#  ifndef UTMP_FILE
#    define UTMP_FILE "/var/run/utmp"
#  endif
#  define ut_user ut_name
#endif

#endif /* SYSUTMP_H_INCLUDED */
