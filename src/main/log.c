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
#include <sys/types.h>
#include <errno.h>

#include "radiusd.h"

#ifdef HAVE_SYSLOG_H
#	include <syslog.h>
/* keep track of whether we've run openlog() */
static int openlog_run = 0;
#endif

 /*
 * Logging facility names
 */
static LRAD_NAME_NUMBER levels[] = {
	{ ": Debug: ",          L_DBG   },
	{ ": Auth: ",           L_AUTH  },
	{ ": Proxy: ",          L_PROXY },
	{ ": Info: ",           L_INFO  },
	{ ": Error: ",          L_ERR   },
	{ NULL, 0 }
};

/*
 *	Log the message to the logfile. Include the severity and
 *	a time stamp.
 */
int vradlog(int lvl, const char *fmt, va_list ap)
{
	FILE *fp = NULL;
	unsigned char *p;
	char buffer[8192];
	int len;

	/*
	 *	NOT debugging, and trying to log debug messages.
	 *
	 *	Throw the message away.
	 */
	if (!debug_flag && (lvl == L_DBG)) {
		return 0;
	}

	/*
	 *	If we don't want any messages, then
	 *	throw them away.
	 */
	if (mainconfig.radlog_dest == RADLOG_NULL) {
		return 0;
	}
	
	*buffer = '\0';
	len = 0;
	if (mainconfig.radlog_fd != -1) {
		/*
		 *	Do nothing, but allow it.
		 */

#ifdef HAVE_SYSLOG_H
	} else if (mainconfig.radlog_dest == RADLOG_SYSLOG) {
		/*
		 *	Open run openlog() on the first log message
		 */
		if(!openlog_run) {
			openlog(progname, LOG_PID, mainconfig.syslog_facility);
			openlog_run = 1;
		}
#endif

	} else if (!mainconfig.log_file) {
		/*
		 *	No log file set.  Discard it.
		 */
		return 0;

	} else if ((fp = fopen(mainconfig.log_file, "a")) == NULL) {
		fprintf(stderr, "%s: Couldn't open %s for logging: %s\n",
			progname, mainconfig.log_file, strerror(errno));
		
		fprintf(stderr, "  (");
		vfprintf(stderr, fmt, ap);  /* the message that caused the log */
		fprintf(stderr, ")\n");
		return -1;
	}

	/*
	 *	Don't print timestamps to syslog, it does that for us.
	 *	Don't print timestamps for low levels of debugging.
	 *
	 *	Print timestamps for non-debugging, and for high levels
	 *	of debugging.
	 */
	if ((mainconfig.radlog_dest != RADLOG_SYSLOG) &&
	    (debug_flag != 1) && (debug_flag != 2)) {
		const char *s;
		time_t timeval;

		timeval = time(NULL);
		CTIME_R(&timeval, buffer, 8192);

		s = lrad_int2str(levels, (lvl & ~L_CONS), ": ");

		strcat(buffer, s);
		len = strlen(buffer);
	}

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

#ifdef HAVE_SYSLOG_H
	if (mainconfig.radlog_dest == RADLOG_SYSLOG) {
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
	} else
#endif
	if (fp != NULL) {
		fputs(buffer, fp);
		fflush(fp);
		fclose(fp);
	} else {
		write(mainconfig.radlog_fd, buffer, strlen(buffer));
	}

	return 0;
}

int log_debug(const char *msg, ...)
{
	va_list ap;
	int r;

	va_start(ap, msg);
	r = vradlog(L_DBG, msg, ap);
	va_end(ap);

	return r;
}

int radlog(int lvl, const char *msg, ...)
{
	va_list ap;
	int r;

	va_start(ap, msg);
	r = vradlog(lvl, msg, ap);
	va_end(ap);

	return r;
}


/*
 *      Dump a whole list of attributes to DEBUG2
 */
void vp_listdebug(VALUE_PAIR *vp)
{
        char tmpPair[70];
        for (; vp; vp = vp->next) {
                vp_prints(tmpPair, sizeof(tmpPair), vp);
                DEBUG2("     %s", tmpPair);
        }
}




