/*
 * sysutmp.h	Compatibility stuff for the different UTMP systems.
 *
 * Version:	$Id$
 */

#ifndef SYSUTMP_H_INCLUDED
#define SYSUTMP_H_INCLUDED

#ifdef HAVE_UTMP_H

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

#else /* HAVE_UTMP_H */

/*
 *	No <utmp.h> file - define stuff ourselves (minimally).
 */
#define UT_LINESIZE	16
#define UT_NAMESIZE	16
#define UT_HOSTSIZE	16

#define USER_PROCESS	7
#define DEAD_PROCESS	8

#define UTMP_FILE	"/var/run/utmp"
#define ut_name		ut_user

struct utmp {
	short	ut_type;
	int	ut_pid;
	char	ut_line[UT_LINESIZE];
	char	ut_id[4];
	long	ut_time;
	char	ut_user[UT_NAMESIZE];
	char	ut_host[UT_HOSTSIZE];
	long	ut_addr;
};

#endif /* HAVE_UTMP_H */

#endif /* SYSUTMP_H_INCLUDED */
