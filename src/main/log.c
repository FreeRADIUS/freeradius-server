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

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_SYSLOG_H
#	include <syslog.h>
/* keep track of whether we've run openlog() */
static int openlog_run = 0;
#endif

static int can_update_log_fp = TRUE;
static FILE *log_fp = NULL;

/*
 * Logging facility names
 */
static const FR_NAME_NUMBER levels[] = {
	{ ": Debug: ",          L_DBG   },
	{ ": Auth: ",           L_AUTH  },
	{ ": Proxy: ",          L_PROXY },
	{ ": Info: ",           L_INFO  },
	{ ": Acct: ",           L_ACCT  },
	{ ": Error: ",          L_ERR   },
	{ NULL, 0 }
};

/*
 *	Log the message to the logfile. Include the severity and
 *	a time stamp.
 */
int vradlog(int lvl, const char *fmt, va_list ap)
{
	struct main_config_t *myconfig = &mainconfig;
	int fd = myconfig->radlog_fd;
	FILE *fp = NULL;
	unsigned char *p;
	char buffer[8192];
	int len, print_timestamp = 0;

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
	if (myconfig->radlog_dest == RADLOG_NULL) {
		return 0;
	}

	/*
	 *	Don't print timestamps to syslog, it does that for us.
	 *	Don't print timestamps for low levels of debugging.
	 *
	 *	Print timestamps for non-debugging, and for high levels
	 *	of debugging.
	 */
	if ((myconfig->radlog_dest != RADLOG_SYSLOG) &&
	    (debug_flag != 1) && (debug_flag != 2)) {
		print_timestamp = 1;
	}

	if ((fd != -1) &&
	    (myconfig->radlog_dest != RADLOG_STDOUT) &&
	    (myconfig->radlog_dest != RADLOG_STDERR)) {
		myconfig->radlog_fd = -1;
		fd = -1;
	}

	*buffer = '\0';
	len = 0;
	if (fd != -1) {
		/*
		 *	Use it, rather than anything else.
		 */

#ifdef HAVE_SYSLOG_H
	} else if (myconfig->radlog_dest == RADLOG_SYSLOG) {
		/*
		 *	Open run openlog() on the first log message
		 */
		if(!openlog_run) {
			openlog(progname, LOG_PID, myconfig->syslog_facility);
			openlog_run = 1;
		}
#endif

	} else if (myconfig->radlog_dest == RADLOG_FILES) {
		if (!myconfig->log_file) {
			/*
			 *	Errors go to stderr, in the hope that
			 *	they will be printed somewhere.
			 */
			if (lvl & L_ERR) {
				fd = STDERR_FILENO;
				print_timestamp = 0;
				snprintf(buffer, sizeof(buffer), "%s: ", progname);
				len = strlen(buffer);
			} else {
				/*
				 *	No log file set.  Discard it.
				 */
				return 0;
			}
			
		} else if (log_fp) {
			struct stat buf;

			if (stat(myconfig->log_file, &buf) < 0) {
				fclose(log_fp);
				log_fp = fr_log_fp = NULL;
			}
		}

		if (!log_fp && myconfig->log_file) {
			fp = fopen(myconfig->log_file, "a");
			if (!fp) {
				fprintf(stderr, "%s: Couldn't open %s for logging: %s\n",
					progname, myconfig->log_file, strerror(errno));
				
				fprintf(stderr, "  (");
				vfprintf(stderr, fmt, ap);  /* the message that caused the log */
				fprintf(stderr, ")\n");
				return -1;
			}
			setlinebuf(fp);
		}

		/*
		 *	We can only set the global variable log_fp IF
		 *	we have no child threads.  If we do have child
		 *	threads, each thread has to open it's own FP.
		 */
		if (can_update_log_fp && fp) fr_log_fp = log_fp = fp;
	}

	if (print_timestamp) {
		const char *s;
		time_t timeval;

		timeval = time(NULL);
		CTIME_R(&timeval, buffer + len, sizeof(buffer) - len - 1);

		s = fr_int2str(levels, (lvl & ~L_CONS), ": ");

		strcat(buffer, s);
		len = strlen(buffer);
	}

	vsnprintf(buffer + len, sizeof(buffer) - len - 1, fmt, ap);

	/*
	 *	Filter out characters not in Latin-1.
	 */
	for (p = (unsigned char *)buffer; *p != '\0'; p++) {
		if (*p == '\r' || *p == '\n')
			*p = ' ';
		else if (*p == '\t') continue;
		else if (*p < 32 || (*p >= 128 && *p <= 160))
			*p = '?';
	}
	strcat(buffer, "\n");

#ifdef HAVE_SYSLOG_H
	if (myconfig->radlog_dest == RADLOG_SYSLOG) {
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
	} else
#endif
	if (log_fp != NULL) {
		fputs(buffer, log_fp);
	} else if (fp != NULL) {
		fputs(buffer, fp);
		fclose(fp);
	} else if (fd >= 0) {
		write(fd, buffer, strlen(buffer));
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

/*
 *	If the server is running with multiple threads, signal the log
 *	subsystem that we're about to START multiple threads.  Once
 *	that happens, we can no longer open/close the log_fp in a
 *	child thread, as writing to global variables causes a race
 *	condition.
 *
 *	We also close the fr_log_fp, as it can no longer write to the
 *	log file (if any).
 *
 *	All of this work is because we want to catch the case of the
 *	administrator deleting the log file.  If that happens, we want
 *	the logs to go to the *new* file, and not the *old* one.
 */
void force_log_reopen(void)
{
	can_update_log_fp = 0;

	if (mainconfig.radlog_dest != RADLOG_FILES) return;

	if (log_fp) fclose(log_fp);
	fr_log_fp = log_fp = NULL;
}

extern char *request_log_file;
extern char *debug_log_file;

void radlog_request(int lvl, int priority, REQUEST *request, const char *msg, ...)
{
	size_t len = 0;
	const char *filename = request_log_file;
	FILE *fp = NULL;
	va_list ap;
	char buffer[1024];

	va_start(ap, msg);

	/*
	 *	Debug messages get treated specially.
	 */
	if (lvl == L_DBG) {
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
		filename = debug_log_file;
		if (!filename) filename = request_log_file;

		/*
		 *	Debug messages get mashed to L_INFO for
		 *	radius.log.
		 */
		if (!filename) lvl = L_INFO;
	}

	if (request && filename) {
		char *p;
		radlog_func_t rl = request->radlog;

		request->radlog = NULL;

		/*
		 *	This is SLOW!  Doing it for every log message
		 *	in every request is NOT recommended!
		 */
		
		radius_xlat(buffer, sizeof(buffer), filename,
			    request, NULL); /* FIXME: escape chars! */
		request->radlog = rl;
		
		p = strrchr(buffer, FR_DIR_SEP);
		if (p) {
			*p = '\0';
			if (rad_mkdir(buffer, S_IRWXU) < 0) {
				radlog(L_ERR, "Failed creating %s: %s",
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
		char *s;
		time_t timeval;
		timeval = time(NULL);

		CTIME_R(&timeval, buffer + len, sizeof(buffer) - len - 1);
		
		s = strrchr(buffer, '\n');
		if (s) {
			s[0] = ' ';
			s[1] = '\0';
		}
		
		s = fr_int2str(levels, (lvl & ~L_CONS), ": ");
		
		strcat(buffer, s);
		len = strlen(buffer);
	}
	
	if (request && request->module[0]) {
		snprintf(buffer + len, sizeof(buffer) + len, "[%s] ", request->module);
		len = strlen(buffer);
	}
	vsnprintf(buffer + len, sizeof(buffer) - len, msg, ap);
	
	if (!fp) {
		if (request) {
			radlog(lvl, "(%u) %s", request->number, buffer);
		} else {
			radlog(lvl, "%s", buffer);
		}
	} else {
		if (request) fprintf(fp, "(%u) ", request->number);
		fputs(buffer, fp);
		fputc('\n', fp);
		fclose(fp);
	}

	va_end(ap);
}
