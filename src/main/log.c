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
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2001,2006  The FreeRADIUS server project
 * Copyright 2000  Miquel van Smoorenburg <miquels@cistron.nl>
 * Copyright 2000  Alan DeKok <aland@ox.org>
 * Copyright 2001  Chad Miller <cmiller@surfsouth.com>
 */

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_SYSLOG_H
#	include <syslog.h>
#endif

/*
 * Logging facility names
 */
static const FR_NAME_NUMBER levels[] = {
	{ ": Debug: ",		L_DBG   },
	{ ": Auth: ",		L_AUTH  },
	{ ": Proxy: ",		L_PROXY },
	{ ": Info: ",		L_INFO  },
	{ ": Acct: ",		L_ACCT  },
	{ ": Error: ",		L_ERR   },
	{ ": WARNING: ",	L_DBG_WARN   },
	{ ": ERROR: ",		L_DBG_ERR   },
	{ ": WARNING: ",	L_DBG_WARN2   },
	{ ": ERROR: ",		L_DBG_ERR2   },
	{ NULL, 0 }
};

#define VTC_RED		"\x1b[31m"
#define VTC_YELLOW      "\x1b[33m"
#define VTC_BOLD	"\x1b[1m"
#define VTC_RESET	"\x1b[0m"

static const FR_NAME_NUMBER colours[] = {
	{ "",			L_DBG   },
	{ VTC_BOLD,		L_AUTH  },
	{ VTC_BOLD,		L_PROXY },
	{ VTC_BOLD,		L_INFO  },
	{ VTC_BOLD,		L_ACCT  },
	{ VTC_RED,		L_ERR   },
	{ VTC_BOLD VTC_RED,	L_DBG_ERR   },
	{ VTC_BOLD VTC_YELLOW,	L_DBG_WARN  },
	{ VTC_BOLD VTC_RED,	L_DBG_ERR2  },
	{ VTC_BOLD VTC_YELLOW,	L_DBG_WARN2 },
	{ NULL, 0 }
};

int log_dates_utc = 0;


/*
 *	Log the message to the logfile. Include the severity and
 *	a time stamp.
 */
DIAG_OFF(format-nonliteral)
int vradlog(int lvl, char const *fmt, va_list ap)
{
	struct main_config_t *myconfig = &mainconfig;
	unsigned char *p;
	char buffer[8192];
	char *unsan;
	size_t len;
	int colourise = myconfig->colourise;

	/*
	 *	NOT debugging, and trying to log debug messages.
	 *
	 *	Throw the message away.
	 */
	if (!debug_flag && ((lvl & L_DBG) != 0)) {
		return 0;
	}

	/*
	 *	If we don't want any messages, then
	 *	throw them away.
	 */
	if (myconfig->radlog_dest == RADLOG_NULL) {
		return 0;
	}

	buffer[0] = '\0';
	len = 0;

	if (colourise) {
		len += strlcpy(buffer + len, fr_int2str(colours, lvl, ""),
			       sizeof(buffer) - len) ;
		if (len == 0) colourise = FALSE;
	}
	
	/*
	 *	Mark the point where we treat the buffer as unsanitized.
	 */
	unsan = buffer + len;

	/*
	 *	Don't print timestamps to syslog, it does that for us.
	 *	Don't print timestamps for low levels of debugging.
	 *
	 *	Print timestamps for non-debugging, and for high levels
	 *	of debugging.
	 */
	if ((myconfig->radlog_dest != RADLOG_SYSLOG) &&
	    (debug_flag != 1) && (debug_flag != 2)) {
		time_t timeval;

		timeval = time(NULL);
		CTIME_R(&timeval, buffer + len, sizeof(buffer) - len - 1);
		
		len = strlen(buffer);

		len += strlcpy(buffer + len,
			       fr_int2str(levels, lvl, ": "),
			       sizeof(buffer) - len);
	}

	switch (lvl) {
	case L_DBG_WARN:
		len += strlcpy(buffer + len, "WARNING: ", sizeof(buffer) - len);
		break;

	case L_DBG_ERR:
		len += strlcpy(buffer + len, "ERROR: ", sizeof(buffer) - len);
		break;

	default:
		break;
	}

	if (len < sizeof(buffer)) {
		len += vsnprintf(buffer + len, sizeof(buffer) - len - 1, fmt, ap);
	}
	
	/*
	 *	Filter out characters not in Latin-1.
	 */
	for (p = (unsigned char *)unsan; *p != '\0'; p++) {
		if (*p == '\r' || *p == '\n')
			*p = ' ';
		else if (*p == '\t') continue;
		else if (*p < 32 || (*p >= 128 && *p <= 160))
			*p = '?';
	}

	if (colourise && (len < sizeof(buffer))) {
		len += strlcpy(buffer + len, VTC_RESET, sizeof(buffer) - len);
	}
	
	if (len < (sizeof(buffer) - 2)) {
		buffer[len]	= '\n';
		buffer[len + 1] = '\0';
	} else {
		buffer[sizeof(buffer) - 2] = '\n';
		buffer[sizeof(buffer) - 1] = '\0';
	}
	
	switch (myconfig->radlog_dest) {

#ifdef HAVE_SYSLOG_H
	case RADLOG_SYSLOG:
		switch(lvl) {
			case L_DBG:
			case L_DBG_WARN:
			case L_DBG_ERR:
				lvl = LOG_DEBUG;
				break;
			case L_AUTH:
				lvl = LOG_NOTICE;
				break;
			case L_PROXY:
				lvl = LOG_NOTICE;
				break;
			case L_ACCT:
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
		break;
#endif

	case RADLOG_FILES:
	case RADLOG_STDOUT:
	case RADLOG_STDERR:
		return write(myconfig->radlog_fd, buffer, strlen(buffer));

	default:
	case RADLOG_NULL:	/* should have been caught above */
		break;
	}

	return 0;
}
DIAG_ON(format-nonliteral)

int log_debug(char const *msg, ...)
{
	va_list ap;
	int r;

	va_start(ap, msg);
	r = vradlog(L_DBG, msg, ap);
	va_end(ap);

	return r;
}

int radlog(int lvl, char const *msg, ...)
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

extern char *request_log_file;
#ifdef WITH_COMMAND_SOCKET
extern char *debug_log_file;
#endif

void radlog_request(int lvl, int priority, REQUEST *request, char const *msg, ...)
{
	size_t len = 0;
	char const *filename = request_log_file;
	FILE *fp = NULL;
	va_list ap;
	char buffer[8192];
	char *p;
	char const *extra = "";

	va_start(ap, msg);

	/*
	 *	Debug messages get treated specially.
	 */
	if ((lvl & L_DBG) != 0) {
		/*
		 *	There is log function, but the debug level
		 *	isn't high enough.  OR, we're in debug mode,
		 *	and the debug level isn't high enough.  Return.
		 */
		if ((request && request->radlog &&
		     (priority > request->options)) ||
		    ((debug_flag != 0) && (priority > debug_flag))) {
			va_end(ap);
			return;
		}

		/*
		 *	Use the debug output file, if specified,
		 *	otherwise leave it as "request_log_file".
		 */
#ifdef WITH_COMMAND_SOCKET
		filename = debug_log_file;
		if (!filename)
#endif
		  filename = request_log_file;

		filename = request_log_file;
	}

	if (request && filename) {
		radlog_func_t rl = request->radlog;

		request->radlog = NULL;

		/*
		 *	This is SLOW!  Doing it for every log message
		 *	in every request is NOT recommended!
		 */
		
		 /* FIXME: escape chars! */
		if (radius_xlat(buffer, sizeof(buffer), request, filename, NULL, NULL) < 0) {
			return;
		}
		request->radlog = rl;
		
		p = strrchr(buffer, FR_DIR_SEP);
		if (p) {
			*p = '\0';
			if (rad_mkdir(buffer, S_IRWXU) < 0) {
				ERROR("Failed creating %s: %s",
				       buffer,strerror(errno));
				va_end(ap);
				return;
			}
			*p = FR_DIR_SEP;
		}

		fp = fopen(buffer, "a");
	}

	/*
	 *	Print timestamps to the file.
	 */
	if (fp) {
		time_t timeval;
		timeval = time(NULL);

#ifdef HAVE_GMTIME_R
		if (log_dates_utc) {
			struct tm utc;
			gmtime_r(&timeval, &utc);
			asctime_r(&utc, buffer);
		} else
#endif
			CTIME_R(&timeval, buffer, sizeof(buffer) - 1);
		
		len = strlen(buffer);
		p = strrchr(buffer, '\n');
		if (p) {
			p[0] = ' ';
			p[1] = '\0';
		}
		
		len += strlcpy(buffer + len,
			       fr_int2str(levels, lvl, ": "),
		 	       sizeof(buffer) - len);
		 	
		if (len >= sizeof(buffer)) goto finish;
	}
	
	if (request && request->module[0]) {
		len = snprintf(buffer + len, sizeof(buffer) - len, "%s : ",
			       request->module);
			
		if (len >= sizeof(buffer)) goto finish;
	}
	
	vsnprintf(buffer + len, sizeof(buffer) - len, msg, ap);
	
	finish:
	switch (lvl) {
	case L_DBG_WARN:
		extra = "WARNING: ";
		lvl = L_DBG_WARN2;
		break;

	case L_DBG_ERR:
		extra = "ERROR: ";
		lvl = L_DBG_ERR2;
		break;

		break;
	}

	if (!fp) {
		if (request) {
			radlog(lvl, "(%u) %s%s", request->number, extra, buffer);
		} else {
			radlog(lvl, "%s%s", extra, buffer);
		}
	} else {
		if (request) fprintf(fp, "(%u) ", request->number);
		fputs(buffer, fp);
		fputc('\n', fp);
		fclose(fp);
	}

	va_end(ap);
}

void log_talloc(char const *msg)
{
	radlog(L_INFO, "%s", msg);
}

void log_talloc_report(TALLOC_CTX *ctx)
{

	struct main_config_t *myconfig = &mainconfig;
	FILE *fd;
	char const *null_ctx;
	int i = 0;

	if (ctx) {
		null_ctx = talloc_get_name(NULL);
	}

	fd = fdopen(myconfig->radlog_fd, "w");
	if (!fd) {
		ERROR("Couldn't write memory report, fdopen failed: %s", strerror(errno));

		return;
	}
	
	if (!ctx) {
		talloc_report_full(NULL, fd);
	} else {
		do {
			radlog(L_INFO, "Context level %i", i++);
		
			talloc_report_full(ctx, fd);
		} while ((ctx = talloc_parent(ctx)) && (talloc_get_name(ctx) != null_ctx));  /* Stop before we hit NULL ctx */
	}
	
	fclose(fd);
}
