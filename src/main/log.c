/*
 * log.c	Logging module.
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
 * Copyright 2001  The FreeRADIUS server project
 * Copyright 2000  Miquel van Smoorenburg <miquels@cistron.nl>
 * Copyright 2000  Alan DeKok <aland@ox.org>
 * Copyright 2001  Chad Miller <cmiller@surfsouth.com>
 */

static const char rcsid[] = "$Id$";

#include "autoconf.h"
#include "libradius.h"

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#include "radiusd.h"

#if HAVE_SYSLOG_H
#	include <syslog.h>
#endif

static int r_mkdir(const char *);


static int r_mkdir(const char *part) {
	char *ptr, parentdir[500];
	struct stat st;

	if (stat(part, &st) == 0)
		return(0);

	ptr = strrchr(part, '/');

	if (ptr == part)
		return(0);

	snprintf(parentdir, (ptr - part)+1, "%s", part);

	if (r_mkdir(parentdir) != 0)
		return(1);

	if (mkdir(part, 0770) != 0) {
		fprintf(stderr, "mkdir(%s) error: %s\n", part, strerror(errno));
		return(1);
	}

	fprintf(stderr, "Created directory %s\n", part);

	return(0);
}
		

int radlogdir_iswritable(const char *effectiveuser) {
	struct passwd *pwent;

	if (radlog_dir[0] != '/')
		return(0);

	if (r_mkdir(radlog_dir) != 0)
		return(1);

	/* FIXME: do we have this function? */
	if (strstr(radlog_dir, "radius") == NULL)
		return(0);

	/* we have a logdir that mentions 'radius', so it's probably 
	 * safe to chown the immediate directory to be owned by the normal 
	 * process owner. we gotta do it before we give up root.  -chad
	 */
	
	pwent = getpwnam(effectiveuser);

	if (pwent == NULL) /* uh oh! */
		return(1);

	if (chown(radlog_dir, pwent->pw_uid, -1) != 0)
		return(1);

	return(0);
}


/*
 *	Log the message to the logfile. Include the severity and
 *	a time stamp.
 */
static int do_log(int lvl, const char *fmt, va_list ap)
{
	FILE *msgfd = NULL;
	const char *s = ": ";
	unsigned char *p;
	char buffer[8192];
	time_t timeval;
	int len;

	/*
	 *	NOT debugging, and trying to log debug messages.
	 *
	 *	Throw the message away.
	 */
	if (!debug_flag && (lvl == L_DBG)) {
		return 0;
	}

	if (radlog_dir != NULL) {
		if (debug_flag || (radlog_dest == RADLOG_STDOUT)) {
			msgfd = stdout;

		} else if (radlog_dest == RADLOG_STDERR) {
			msgfd = stderr;

		} else if (radlog_dest != RADLOG_SYSLOG) {

			sprintf(buffer, "%.1000s/%.1000s", radlog_dir, RADIUS_LOG);
			if ((msgfd = fopen(buffer, "a")) == NULL) {
				fprintf(stderr, "%s: Couldn't open %s for logging: %s\n",
						progname, buffer, strerror(errno));

				fprintf(stderr, "  (");
				vfprintf(stderr, fmt, ap);  /* the message that caused the log */
				fprintf(stderr, ")\n");
				return -1;
			}
		}
	}

	timeval = time(NULL);
#if HAVE_SYSLOG_H
	if (radlog_dest == RADLOG_SYSLOG)
		*buffer = '\0';
	else {
		ctime_r(&timeval, buffer);

		switch(lvl & ~L_CONS) {
			case L_DBG:
				s = ": Debug: ";
				break;
			case L_AUTH:
				s = ": Auth: ";
				break;
			case L_PROXY:
				s = ": Proxy: ";
				break;
			case L_INFO:
				s = ": Info: ";
				break;
			case L_ERR:
				s = ": Error: ";
				break;
		}
		strcat(buffer, s);
	}
#endif
	len = strlen(buffer);

#ifdef HAVE_VSNPRINTF
	vsnprintf(buffer + len, sizeof(buffer) - len -1, fmt, ap);
#else
	vsprintf(buffer + len, fmt, ap);
	if (strlen(buffer) >= sizeof(buffer) - 1)
		/* What can we do? */
		_exit(42);
#endif

	/*
	 *	Filter out characters not in Latin-1.
	 */
	for (p = (unsigned char *)buffer; *p != '\0'; p++) {
		if (*p == '\r' || *p == '\n')
			*p = ' ';
		else if (*p < 32 || (*p >= 128 && *p <= 160))
			*p = '?';
	}
	strcat(buffer, "\n");

	if ((lvl & L_CONS) || radlog_dir == NULL || debug_flag) {
		if (!debug_flag) 
			fprintf(stdout, "%s: ", progname);
		fprintf(stdout, "%s", buffer+len);
	}

	if (radlog_dir == NULL || debug_flag) 
		return 0;


#if HAVE_SYSLOG_H
	if (radlog_dest != RADLOG_SYSLOG) {
		fputs(buffer, msgfd);
#endif
		if (msgfd == stdout) {
			fflush(stdout);
		} else if (msgfd == stderr) {
			fflush(stderr);
		} else {
			fclose(msgfd);
		}

#if HAVE_SYSLOG_H
	} else {
		switch(lvl & ~L_CONS) {
			case L_DBG:
				lvl = LOG_DEBUG;
				break;
			case L_AUTH:
				lvl = LOG_NOTICE;
				break;
			case L_PROXY:
				lvl = LOG_NOTICE;
				break;
			case L_INFO:
				lvl = LOG_INFO;
				break;
			case L_ERR:
				lvl = LOG_ERR;
				break;
		}
		syslog(lvl, "%s", buffer);
	}
#endif

	return 0;
}

int log_debug(const char *msg, ...)
{
	va_list ap;
	int r;

	va_start(ap, msg);
	r = do_log(L_DBG, msg, ap);
	va_end(ap);

	return r;
}

int radlog(int lvl, const char *msg, ...)
{
	va_list ap;
	int r;

	va_start(ap, msg);
	r = do_log(lvl, msg, ap);
	va_end(ap);

	return r;
}

