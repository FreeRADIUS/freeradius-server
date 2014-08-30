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
#include <freeradius-devel/rad_assert.h>

#ifdef HAVE_SYS_STAT_H
#  include <sys/stat.h>
#endif

#include <fcntl.h>

#ifdef HAVE_SYSLOG_H
#  include <syslog.h>
#endif

#include <sys/file.h>

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif

bool rate_limit = true;

/*
 * Logging facility names
 */
static const FR_NAME_NUMBER levels[] = {
	{ ": Debug: ",		L_DBG		},
	{ ": Auth: ",		L_AUTH		},
	{ ": Proxy: ",		L_PROXY		},
	{ ": Info: ",		L_INFO		},
	{ ": Warning: ",	L_WARN		},
	{ ": Acct: ",		L_ACCT		},
	{ ": Error: ",		L_ERR		},
	{ ": WARNING: ",	L_DBG_WARN	},
	{ ": ERROR: ",		L_DBG_ERR	},
	{ ": WARNING: ",	L_DBG_WARN_REQ	},
	{ ": ERROR: ",		L_DBG_ERR_REQ	},
	{ NULL, 0 }
};

#define VTC_RED		"\x1b[31m"
#define VTC_YELLOW      "\x1b[33m"
#define VTC_BOLD	"\x1b[1m"
#define VTC_RESET	"\x1b[0m"

static const FR_NAME_NUMBER colours[] = {
	{ "",			L_DBG		},
	{ VTC_BOLD,		L_AUTH		},
	{ VTC_BOLD,		L_PROXY		},
	{ VTC_BOLD,		L_INFO		},
	{ VTC_BOLD,		L_ACCT		},
	{ VTC_RED,		L_ERR		},
	{ VTC_BOLD VTC_YELLOW,	L_WARN		},
	{ VTC_BOLD VTC_RED,	L_DBG_ERR	},
	{ VTC_BOLD VTC_YELLOW,	L_DBG_WARN	},
	{ VTC_BOLD VTC_RED,	L_DBG_ERR_REQ	},
	{ VTC_BOLD VTC_YELLOW,	L_DBG_WARN_REQ	},
	{ NULL, 0 }
};

/*
 *	Syslog facility table.
 */
const FR_NAME_NUMBER syslog_str2fac[] = {
#ifdef LOG_KERN
	{ "kern",		LOG_KERN	},
#endif
#ifdef LOG_USER
	{ "user",		LOG_USER	},
#endif
#ifdef LOG_MAIL
	{ "mail",		LOG_MAIL	},
#endif
#ifdef LOG_DAEMON
	{ "daemon",		LOG_DAEMON	},
#endif
#ifdef LOG_AUTH
	{ "auth",		LOG_AUTH	},
#endif
#ifdef LOG_LPR
	{ "lpr",		LOG_LPR		},
#endif
#ifdef LOG_NEWS
	{ "news",		LOG_NEWS	},
#endif
#ifdef LOG_UUCP
	{ "uucp",		LOG_UUCP	},
#endif
#ifdef LOG_CRON
	{ "cron",		LOG_CRON	},
#endif
#ifdef LOG_AUTHPRIV
	{ "authpriv",		LOG_AUTHPRIV	},
#endif
#ifdef LOG_FTP
	{ "ftp",		LOG_FTP		},
#endif
#ifdef LOG_LOCAL0
	{ "local0",		LOG_LOCAL0	},
#endif
#ifdef LOG_LOCAL1
	{ "local1",		LOG_LOCAL1	},
#endif
#ifdef LOG_LOCAL2
	{ "local2",		LOG_LOCAL2	},
#endif
#ifdef LOG_LOCAL3
	{ "local3",		LOG_LOCAL3	},
#endif
#ifdef LOG_LOCAL4
	{ "local4",		LOG_LOCAL4	},
#endif
#ifdef LOG_LOCAL5
	{ "local5",		LOG_LOCAL5	},
#endif
#ifdef LOG_LOCAL6
	{ "local6",		LOG_LOCAL6	},
#endif
#ifdef LOG_LOCAL7
	{ "local7",		LOG_LOCAL7	},
#endif
	{ NULL,			-1		}
};

const FR_NAME_NUMBER log_str2dst[] = {
	{ "null",		L_DST_NULL	},
	{ "files",		L_DST_FILES	},
	{ "syslog",		L_DST_SYSLOG	},
	{ "stdout",		L_DST_STDOUT	},
	{ "stderr",		L_DST_STDERR	},
	{ NULL,			L_DST_NUM_DEST	}
};

bool log_dates_utc = false;

fr_log_t default_log = {
	.colourise = false,	//!< Will be set later. Should be off before we do terminal detection.
	.fd = STDOUT_FILENO,
	.dst = L_DST_STDOUT,
	.file = NULL,
	.debug_file = NULL,
};

static int stderr_fd = -1;	//!< The original unmolested stderr file descriptor
static int stdout_fd = -1;	//!< The original unmolested stdout file descriptor

static char const spaces[] = "                                                                                                                        ";

/** On fault, reset STDOUT and STDERR to something useful.
 *
 * @return 0
 */
static int _restore_std(UNUSED int sig)
{
	if ((stderr_fd > 0) && (stdout_fd > 0)) {
		dup2(stderr_fd, STDOUT_FILENO);
		dup2(stdout_fd, STDERR_FILENO);
		return 0;
	}

	if (default_log.fd > 0) {
		dup2(default_log.fd, STDOUT_FILENO);
		dup2(default_log.fd, STDERR_FILENO);
		return 0;
	}

	return 0;
}

/** Pass debug logging through to vradlog
 *
 */
static void CC_HINT(format (printf, 1, 2)) _radlog_info(char const *msg, ...)
{
	va_list ap;

	va_start(ap, msg);
	vradlog(L_INFO, msg, ap);
	va_end(ap);
}

/** Initialise file descriptors based on logging destination
 *
 * @param log Logger to manipulate.
 * @param daemonize Whether the server is starting as a daemon.
 * @return 0 on success -1 on failure.
 */
int radlog_init(fr_log_t *log, bool daemonize)
{
	int devnull;

	rate_limit = daemonize;

	/*
	 *	If we're running in foreground mode, save STDIN /
	 *	STDERR as higher FDs, which won't get used by anyone
	 *	else.  When we fork/exec a program, it's STD FDs will
	 *	get set to pipes.  We later set STDOUT / STDERR to
	 *	/dev/null, so that any library trying to write to them
	 *	doesn't screw anything up.
	 *
	 *	Then, when something goes wrong, restore them so that
	 *	any debugger called from the panic action has access
	 *	to STDOUT / STDERR.
	 */
	if (!daemonize) {
		fr_fault_set_cb(_restore_std);

		stdout_fd = dup(STDOUT_FILENO);
		stderr_fd = dup(STDERR_FILENO);
	}

	devnull = open("/dev/null", O_RDWR);
	if (devnull < 0) {
		fr_strerror_printf("Error opening /dev/null: %s", fr_syserror(errno));
		return -1;
	}

	/*
	 *	STDOUT & STDERR go to /dev/null, unless we have "-x",
	 *	then STDOUT & STDERR go to the "-l log" destination.
	 *
	 *	The complexity here is because "-l log" can go to
	 *	STDOUT or STDERR, too.
	 */
	if (log->dst == L_DST_STDOUT) {
		setlinebuf(stdout);
		log->fd = STDOUT_FILENO;

		/*
		 *	If we're debugging, allow STDERR to go to
		 *	STDOUT too, for executed programs,
		 */
		if (debug_flag) {
			dup2(STDOUT_FILENO, STDERR_FILENO);
		} else {
			dup2(devnull, STDERR_FILENO);
		}

	} else if (log->dst == L_DST_STDERR) {
		setlinebuf(stderr);
		log->fd = STDERR_FILENO;

		/*
		 *	If we're debugging, allow STDOUT to go to
		 *	STDERR too, for executed programs,
		 */
		if (debug_flag) {
			dup2(STDERR_FILENO, STDOUT_FILENO);
		} else {
			dup2(devnull, STDOUT_FILENO);
		}

	} else if (log->dst == L_DST_SYSLOG) {
		/*
		 *	Discard STDOUT and STDERR no matter what the
		 *	status of debugging.  Syslog isn't a file
		 *	descriptor, so we can't use it.
		 */
		dup2(devnull, STDOUT_FILENO);
		dup2(devnull, STDERR_FILENO);

	} else if (debug_flag) {
		/*
		 *	If we're debugging, allow STDOUT and STDERR to
		 *	go to the log file.
		 */
		dup2(log->fd, STDOUT_FILENO);
		dup2(log->fd, STDERR_FILENO);

	} else {
		/*
		 *	Not debugging, and the log isn't STDOUT or
		 *	STDERR.  Ensure that we move both of them to
		 *	/dev/null, so that the calling terminal can
		 *	exit, and the output from executed programs
		 *	doesn't pollute STDOUT / STDERR.
		 */
		dup2(devnull, STDOUT_FILENO);
		dup2(devnull, STDERR_FILENO);
	}

	close(devnull);

	/*
	 *	This handles setting up all the talloc logging
	 *	and callbacks too.
	 */
	fr_fault_set_log_fn(_radlog_info);
	fr_fault_set_log_fd(log->fd);

	return 0;
}

/*
 *	Log the message to the logfile. Include the severity and
 *	a time stamp.
 */
int vradlog(log_type_t type, char const *fmt, va_list ap)
{
	unsigned char *p;
	char buffer[10240];	/* The largest config item size, then extra for prefixes and suffixes */
	char *unsan;
	size_t len;
	int colourise = default_log.colourise;

	/*
	 *	If we don't want any messages, then
	 *	throw them away.
	 */
	if (default_log.dst == L_DST_NULL) {
		return 0;
	}

	buffer[0] = '\0';
	len = 0;

	if (colourise) {
		len += strlcpy(buffer + len, fr_int2str(colours, type, ""), sizeof(buffer) - len) ;
		if (len == 0) {
			colourise = false;
		}
	}

	/*
	 *	Mark the point where we treat the buffer as unsanitized.
	 */
	unsan = buffer + len;

	/*
	 *	Don't print timestamps to syslog, it does that for us.
	 *	Don't print timestamps and error types for low levels
	 *	of debugging.
	 *
	 *	Print timestamps for non-debugging, and for high levels
	 *	of debugging.
	 */
	if (default_log.dst != L_DST_SYSLOG) {
		if ((debug_flag != 1) && (debug_flag != 2)) {
			time_t timeval;

			timeval = time(NULL);
			CTIME_R(&timeval, buffer + len, sizeof(buffer) - len - 1);

			len = strlen(buffer);
			len += strlcpy(buffer + len, fr_int2str(levels, type, ": "), sizeof(buffer) - len);
		} else goto add_prefix;
	} else {
	add_prefix:
		if (len < sizeof(buffer)) switch (type) {
		case L_DBG_WARN:
			len += strlcpy(buffer + len, "WARNING: ", sizeof(buffer) - len);
			break;

		case L_DBG_ERR:
			len += strlcpy(buffer + len, "ERROR: ", sizeof(buffer) - len);
			break;

		default:
			break;
		}
	}

	if (len < sizeof(buffer)) {
		len += vsnprintf(buffer + len, sizeof(buffer) - len - 1, fmt, ap);
	}

	/*
	 *	Filter out control chars and non UTF8 chars
	 */
	for (p = (unsigned char *)unsan; *p != '\0'; p++) {
		int clen;

		switch (*p) {
		case '\r':
		case '\n':
			*p = ' ';
			break;

		case '\t':
			continue;

		default:
			clen = fr_utf8_char(p);
			if (!clen) {
				*p = '?';
				continue;
			}
			p += (clen - 1);
			break;
		}
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

	switch (default_log.dst) {

#ifdef HAVE_SYSLOG_H
	case L_DST_SYSLOG:
		switch(type) {
		case L_DBG:
		case L_WARN:
		case L_DBG_WARN:
		case L_DBG_ERR:
		case L_DBG_ERR_REQ:
		case L_DBG_WARN_REQ:
			type = LOG_DEBUG;
			break;
		case L_AUTH:
		case L_PROXY:
		case L_ACCT:
			type = LOG_NOTICE;
			break;
		case L_INFO:
			type = LOG_INFO;
			break;
		case L_ERR:
			type = LOG_ERR;
			break;
		}
		syslog(type, "%s", buffer);
		break;
#endif

	case L_DST_FILES:
	case L_DST_STDOUT:
	case L_DST_STDERR:
		return write(default_log.fd, buffer, strlen(buffer));

	default:
	case L_DST_NULL:	/* should have been caught above */
		break;
	}

	return 0;
}

int radlog(log_type_t type, char const *msg, ...)
{
	va_list ap;
	int r = 0;

	va_start(ap, msg);

	/*
	 *	Non-debug message, or debugging is enabled.  Log it.
	 */
	if (((type & L_DBG) == 0) || (debug_flag > 0)) {
		r = vradlog(type, msg, ap);
	}
	va_end(ap);

	return r;
}

/*
 *	Always log.
 */
static int CC_HINT(format (printf, 2, 3)) radlog_always(log_type_t type, char const *msg, ...)
{
	va_list ap;
	int r;

	va_start(ap, msg);
	r = vradlog(type, msg, ap);
	va_end(ap);

	return r;
}

/*
 *      Dump a whole list of attributes to DEBUG2
 */
void vp_listdebug(VALUE_PAIR *vp)
{
	vp_cursor_t cursor;
	char tmpPair[70];
	for (vp = fr_cursor_init(&cursor, &vp);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		vp_prints(tmpPair, sizeof(tmpPair), vp);
		DEBUG2("     %s", tmpPair);
	}
}

inline bool debug_enabled(log_type_t type, log_debug_t lvl)
{
	if ((type & L_DBG) && (debug_flag != 0) && (lvl > debug_flag)) return true;

	return false;
}

inline bool rate_limit_enabled(void)
{
	if (rate_limit || (debug_flag < 1)) return true;

	return false;
}

inline bool radlog_debug_enabled(log_type_t type, log_debug_t lvl, REQUEST *request)
{
	/*
	 *	It's a debug class message, not this doesn't mean it's a debug type message.
	 *
	 *	For example it could be a RIDEBUG message, which would be an informational message,
	 *	instead of an RDEBUG message which would be a debug debug message.
	 *
	 *	There is log function, but the request debug level isn't high enough.
	 *	OR, we're in debug mode, and the global debug level isn't high enough,
	 *	then don't log the message.
	 */
	if ((type & L_DBG) &&
	    ((request && request->log.func && (lvl > request->log.lvl)) ||
	     ((debug_flag != 0) && (lvl > debug_flag)))) {
		return false;
	}

	return true;
}

void vradlog_request(log_type_t type, log_debug_t lvl, REQUEST *request, char const *msg, va_list ap)
{
	size_t len = 0;
	char const *filename = default_log.file;
	FILE *fp = NULL;
	char buffer[10240];	/* The largest config item size, then extra for prefixes and suffixes */
	char *p;
	char const *extra = "";
	va_list aq;

	rad_assert(request);

	/*
	 *	Debug messages get treated specially.
	 */
	if ((type & L_DBG) != 0) {

		if (!radlog_debug_enabled(type, lvl, request)) {
			return;
		}

		/*
		 *	Use the debug output file, if specified,
		 *	otherwise leave it as the default log file.
		 */
#ifdef WITH_COMMAND_SOCKET
		filename = default_log.debug_file;
		if (!filename)
#endif

		filename = default_log.file;
	}

	if (request && filename) {
		radlog_func_t rl = request->log.func;

		request->log.func = NULL;

		/*
		 *	This is SLOW!  Doing it for every log message
		 *	in every request is NOT recommended!
		 */

		 /* FIXME: escape chars! */
		if (radius_xlat(buffer, sizeof(buffer), request, filename, NULL, NULL) < 0) {
			return;
		}
		request->log.func = rl;

		p = strrchr(buffer, FR_DIR_SEP);
		if (p) {
			*p = '\0';
			if (rad_mkdir(buffer, S_IRWXU) < 0) {
				ERROR("Failed creating %s: %s", buffer, fr_syserror(errno));
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
			ASCTIME_R(&utc, buffer, sizeof(buffer) - 1);
		} else
#endif
		{
			CTIME_R(&timeval, buffer, sizeof(buffer) - 1);
		}

		len = strlen(buffer);
		p = strrchr(buffer, '\n');
		if (p) {
			p[0] = ' ';
			p[1] = '\0';
		}

		len += strlcpy(buffer + len, fr_int2str(levels, type, ": "), sizeof(buffer) - len);
		if (len >= sizeof(buffer)) goto finish;
	}

	if (request && request->module[0]) {
		len = snprintf(buffer + len, sizeof(buffer) - len, "%s : ", request->module);
		if (len >= sizeof(buffer)) goto finish;
	}

	/*
	 *  If we don't copy the original ap we get a segfault from vasprintf. This is apparently
	 *  due to ap sometimes being implemented with a stack offset which is invalidated if
	 *  ap is passed into another function. See here:
	 *  http://julipedia.meroh.net/2011/09/using-vacopy-to-safely-pass-ap.html
	 *
	 *  I don't buy that explanation, but doing a va_copy here does prevent SEGVs seen when
	 *  running unit tests which generate errors under CI.
	 */
	va_copy(aq, ap);
	vsnprintf(buffer + len, sizeof(buffer) - len, msg, aq);
	va_end(aq);

	finish:
	switch (type) {
	case L_DBG_WARN:
		extra = "WARNING: ";
		type = L_DBG_WARN_REQ;
		break;

	case L_DBG_ERR:
		extra = "ERROR: ";
		type = L_DBG_ERR_REQ;
		break;
	default:
		break;
	}

	if (!fp) {

		if (debug_flag > 2) extra = "";

		if (request) {
			uint8_t indent;

			indent = request->log.indent > sizeof(spaces) ?
				 sizeof(spaces) :
				 request->log.indent;
			radlog_always(type, "(%u) %.*s%s%s", request->number, indent, spaces, extra, buffer);
		} else {
			radlog_always(type, "%s%s", extra, buffer);
		}
	} else {
		if (request) {
			fprintf(fp, "(%u) %s", request->number, extra);
		}
		fputs(buffer, fp);
		fputc('\n', fp);
		fclose(fp);
	}
}

/** Martial variadic log arguments into a va_list and pass to normal logging functions
 *
 * @see radlog_request_error for more details.
 *
 * @param type the log category.
 * @param lvl of debugging this message should be displayed at.
 * @param request The current request.
 * @param msg format string.
 */
void radlog_request(log_type_t type, log_debug_t lvl, REQUEST *request, char const *msg, ...)
{
	va_list ap;

	rad_assert(request);

	if (request->log.func == NULL) return;

	va_start(ap, msg);
	request->log.func(type, lvl, request, msg, ap);
	va_end(ap);
}

/** Martial variadic log arguments into a va_list and pass to error logging functions
 *
 * This could all be done in a macro, but it turns out some implementations of the
 * variadic macros do not work at all well if the va_list being written to is further
 * up the stack (which is required as you still need a function to convert the elipses
 * into a va_list).
 *
 * So, we use this small wrapper function instead, which will hopefully guarantee
 * consistent behaviour.
 *
 * @param type the log category.
 * @param lvl of debugging this message should be displayed at.
 * @param request The current request.
 * @param msg format string.
 */
void radlog_request_error(log_type_t type, log_debug_t lvl, REQUEST *request, char const *msg, ...)
{
	va_list ap;

	rad_assert(request);

	va_start(ap, msg);
	if (request->log.func) {
		request->log.func(type, lvl, request, msg, ap);
	}
	vmodule_failure_msg(request, msg, ap);
	va_end(ap);
}

/** Parse error, write out string we were parsing, and a message indicating the error
 *
 * @param type the log category.
 * @param lvl of debugging this message should be displayed at.
 * @param request The current request.
 * @param fmt string we were parsing.
 * @param idx The position of the marker relative to the string.
 * @param error What the parse error was.
 */
void radlog_request_marker(log_type_t type, log_debug_t lvl, REQUEST *request,
			   char const *fmt, size_t idx, char const *error)
{
	char const *prefix = "";
	uint8_t indent;

	rad_assert(request);

	if (idx >= sizeof(spaces)) {
		size_t offset = (idx - (sizeof(spaces) - 1)) + (sizeof(spaces) * 0.75);
		idx -= offset;
		fmt += offset;

		prefix = "... ";
	}

	/*
	 *  Don't want format markers being indented
	 */
	indent = request->log.indent;
	request->log.indent = 0;

	radlog_request(type, lvl, request, "%s%s", prefix, fmt);
	radlog_request(type, lvl, request, "%s%.*s^ %s", prefix, (int) idx, spaces, error);

	request->log.indent = indent;
}

typedef struct fr_logfile_entry_t {
	int		fd;
	int		dup;
	uint32_t	hash;
	time_t		last_used;
	char		*filename;
} fr_logfile_entry_t;


struct fr_logfile_t {
	uint32_t max_entries;
#ifdef HAVE_PTHREAD_H
	pthread_mutex_t mutex;
#endif
	fr_logfile_entry_t *entries;
};


#ifdef HAVE_PTHREAD_H
#define PTHREAD_MUTEX_LOCK pthread_mutex_lock
#define PTHREAD_MUTEX_UNLOCK pthread_mutex_unlock

#else
/*
 *	This is easier than ifdef's throughout the code.
 */
#define PTHREAD_MUTEX_LOCK(_x)
#define PTHREAD_MUTEX_UNLOCK(_x)
#endif

static int _logfile_free(fr_logfile_t *lf)
{
	uint32_t i;

	PTHREAD_MUTEX_LOCK(&lf->mutex);

	for (i = 0; i < lf->max_entries; i++) {
		if (!lf->entries[i].filename) continue;

		close(lf->entries[i].fd);
	}

	PTHREAD_MUTEX_UNLOCK(&lf->mutex);

#ifdef HAVE_PTHREAD_H
	pthread_mutex_destroy(&lf->mutex);
#endif

	return 0;
}


/** Initialize a way for multiple threads to log to one or more files.
 *
 * @param ctx The talloc context
 * @return the new context, or NULL on error.
 */
fr_logfile_t *fr_logfile_init(TALLOC_CTX *ctx)
{
	fr_logfile_t *lf;

	lf = talloc_zero(ctx, fr_logfile_t);
	if (!lf) return NULL;

	lf->entries = talloc_zero_array(lf, fr_logfile_entry_t, 64);
	if (!lf->entries) {
		talloc_free(lf);
		return NULL;
	}

#ifdef HAVE_PTHREAD_H
	if (pthread_mutex_init(&lf->mutex, NULL) != 0) {
		talloc_free(lf);
		return NULL;
	}
#endif

	lf->max_entries = 64;

	talloc_set_destructor(lf, _logfile_free);

	return lf;
}


/** Open a new log file, or maybe an existing one.
 *
 * When multithreaded, the FD is locked via a mutex.  This way we're
 * sure that no other thread is writing to the file.
 *
 * @param lf The logfile context returned from fr_logfile_init().
 * @param filename the file to open.
 * @param permissions to use.
 * @return an FD used to write to the file, or -1 on error.
 */
int fr_logfile_open(fr_logfile_t *lf, char const *filename, mode_t permissions)
{
	uint32_t i;
	uint32_t hash;
	time_t now = time(NULL);
	struct stat st;

	if (!lf || !filename) return -1;

	hash = fr_hash_string(filename);

	PTHREAD_MUTEX_LOCK(&lf->mutex);

	/*
	 *	Clean up old entries.
	 */
	for (i = 0; i < lf->max_entries; i++) {
		if (!lf->entries[i].filename) continue;

		/*
		 *	FIXME: make this configurable?
		 */
		if ((lf->entries[i].last_used + 30) < now) {
			/*
			 *	This will block forever if a thread is
			 *	doing something stupid.
			 */
			TALLOC_FREE(lf->entries[i].filename);
			close(lf->entries[i].fd);
		}
	}

	/*
	 *	Find the matching entry.
	 */
	for (i = 0; i < lf->max_entries; i++) {
		if (!lf->entries[i].filename) continue;

		if (lf->entries[i].hash == hash) {
			/*
			 *	Same hash but different filename.  Give up.
			 */
			if (strcmp(lf->entries[i].filename, filename) != 0) {
				PTHREAD_MUTEX_UNLOCK(&lf->mutex);
				return -1;
			}
			/*
			 *	Someone else failed to create the entry.
			 */
			if (!lf->entries[i].filename) {
				PTHREAD_MUTEX_UNLOCK(&lf->mutex);
				return -1;
			}
			goto do_return;
		}
	}

	/*
	 *	Find an unused entry
	 */
	for (i = 0; i < lf->max_entries; i++) {
		if (!lf->entries[i].filename) break;
	}

	if (i >= lf->max_entries) {
		fr_strerror_printf("Too many different filenames");
		PTHREAD_MUTEX_UNLOCK(&(lf->mutex));
		return -1;
	}

	/*
	 *	Create a new entry.
	 */

	lf->entries[i].hash = hash;
	lf->entries[i].filename = talloc_strdup(lf->entries, filename);
	lf->entries[i].fd = -1;

	lf->entries[i].fd = open(filename, O_WRONLY | O_APPEND | O_CREAT, permissions);
	if (lf->entries[i].fd < 0) {
		mode_t dirperm;
		char *p, *dir;

		/*
		 *	Maybe the directory doesn't exist.  Try to
		 *	create it.
		 */
		dir = talloc_strdup(lf, filename);
		if (!dir) goto error;
		p = strrchr(dir, FR_DIR_SEP);
		if (!p) {
			fr_strerror_printf("No '/' in '%s'", filename);
			goto error;
		}
		*p = '\0';

		/*
		 *	Ensure that the 'x' bit is set, so that we can
		 *	read the directory.
		 */
		dirperm = permissions;
		if ((dirperm & 0600) != 0) dirperm |= 0100;
		if ((dirperm & 0060) != 0) dirperm |= 0010;
		if ((dirperm & 0006) != 0) dirperm |= 0001;

		if (rad_mkdir(dir, dirperm) < 0) {
			fr_strerror_printf("Failed to create directory %s: %s",
					   dir, strerror(errno));
			talloc_free(dir);
			goto error;
		}
		talloc_free(dir);

		lf->entries[i].fd = open(filename, O_WRONLY | O_CREAT, permissions);
		if (lf->entries[i].fd < 0) {
			fr_strerror_printf("Failed to open file %s: %s",
					   filename, strerror(errno));
			goto error;
		} /* else fall through to creating the rest of the entry */
	} /* else the file was already opened */

do_return:
	/*
	 *	Lock from the start of the file.
	 */
	if (lseek(lf->entries[i].fd, 0, SEEK_SET) < 0) {
		fr_strerror_printf("Failed to seek in file %s: %s",
				   filename, strerror(errno));

	error:
		lf->entries[i].hash = 0;
		TALLOC_FREE(lf->entries[i].filename);
		close(lf->entries[i].fd);
		lf->entries[i].fd = -1;

		PTHREAD_MUTEX_UNLOCK(&(lf->mutex));
		return -1;
	}

	if (rad_lockfd(lf->entries[i].fd, 0) < 0) {
		fr_strerror_printf("Failed to lock file %s: %s",
				   filename, strerror(errno));
		goto error;
	}

	/*
	 *	Maybe someone deleted the file while we were waiting
	 *	for the lock.  If so, re-open it.
	 */
	if (fstat(lf->entries[i].fd, &st) < 0) {
		fr_strerror_printf("Failed to stat file %s: %s",
				   filename, strerror(errno));
		goto error;
	}

	if (st.st_nlink == 0) {
		close(lf->entries[i].fd);
		lf->entries[i].fd = open(filename, O_WRONLY | O_CREAT, permissions);
		if (lf->entries[i].fd < 0) {
			fr_strerror_printf("Failed to open file %s: %s",
					   filename, strerror(errno));
			goto error;
		}
	}

	/*
	 *	Seek to the end of the file before returning the FD to
	 *	the caller.
	 */
	lseek(lf->entries[i].fd, 0, SEEK_END);

	/*
	 *	Return holding the mutex for the entry.
	 */
	lf->entries[i].last_used = now;
	lf->entries[i].dup = dup(lf->entries[i].fd);
	if (lf->entries[i].dup < 0) {
		fr_strerror_printf("Failed calling dup(): %s",
				   strerror(errno));
		goto error;
	}

	return lf->entries[i].dup;
}

/** Close the log file.  Really just return it to the pool.
 *
 * When multithreaded, the FD is locked via a mutex.  This way we're
 * sure that no other thread is writing to the file.  This function
 * will unlock the mutex, so that other threads can write to the file.
 *
 * @param lf The logfile context returned from fr_logfile_init()
 * @param fd the FD to close (i.e. return to the pool)
 * @return 0 on success, or -1 on error
 */
int fr_logfile_close(fr_logfile_t *lf, int fd)
{
	uint32_t i;

	for (i = 0; i < lf->max_entries; i++) {
		if (!lf->entries[i].filename) continue;

		/*
		 *	Unlock the bytes that we had previously locked.
		 */
		if (lf->entries[i].dup == fd) {
			(void) rad_unlockfd(lf->entries[i].dup, 0);
			close(lf->entries[i].dup); /* releases the fcntl lock */
			lf->entries[i].dup = -1;

			PTHREAD_MUTEX_UNLOCK(&(lf->mutex));
			return 0;
		}
	}

	PTHREAD_MUTEX_UNLOCK(&(lf->mutex));

	fr_strerror_printf("Attempt to unlock file which does not exist");
	return -1;
}

int fr_logfile_unlock(fr_logfile_t *lf, int fd)
{
	uint32_t i;

	for (i = 0; i < lf->max_entries; i++) {
		if (!lf->entries[i].filename) continue;

		if (lf->entries[i].dup == fd) {
			lf->entries[i].dup = -1;
			PTHREAD_MUTEX_UNLOCK(&(lf->mutex));
			return 0;
		}
	}

	PTHREAD_MUTEX_UNLOCK(&(lf->mutex));

	fr_strerror_printf("Attempt to unlock file which does not exist");
	return -1;
}
