/*
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
 */

/**
 * $Id$
 *
 * @brief Logging functions used by the server core.
 * @file main/log.c
 *
 * @copyright 2000,2006  The FreeRADIUS server project
 * @copyright 2000  Miquel van Smoorenburg <miquels@cistron.nl>
 * @copyright 2000  Alan DeKok <aland@ox.org>
 * @copyright 2001  Chad Miller <cmiller@surfsouth.com>
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
#include <pthread.h>

log_lvl_t	rad_debug_lvl = 0;		//!< Global debugging level
log_lvl_t	req_debug_lvl = 0;		//!< Request debugging level
static bool	rate_limit = true;		//!< Whether repeated log entries should be rate limited

/** Maps log categories to message prefixes
 */
static const FR_NAME_NUMBER levels[] = {
	{ ": Debug : ",		L_DBG		},
	{ ": Auth  : ",		L_AUTH		},
	{ ": Proxy : ",		L_PROXY		},
	{ ": Info  : ",		L_INFO		},
	{ ": Warn  : ",		L_WARN		},
	{ ": Acct  : ",		L_ACCT		},
	{ ": Error : ",		L_ERR		},
	{ ": WARN  : ",		L_DBG_WARN	},
	{ ": ERROR : ",		L_DBG_ERR	},
	{ ": WARN  : ",		L_DBG_WARN_REQ	},
	{ ": ERROR : ",		L_DBG_ERR_REQ	},
	{ NULL, 0 }
};

/** @name VT100 escape sequences
 *
 * These sequences may be written to VT100 terminals to change the
 * colour and style of the text.
 *
 @code{.c}
   fprintf(stdout, VTC_RED "This text will be coloured red" VTC_RESET);
 @endcode
 * @{
 */
#define VTC_RED		"\x1b[31m"	//!< Colour following text red.
#define VTC_YELLOW      "\x1b[33m"	//!< Colour following text yellow.
#define VTC_BOLD	"\x1b[1m"	//!< Embolden following text.
#define VTC_RESET	"\x1b[0m"	//!< Reset terminal text to default style/colour.
/** @} */

/** Maps log categories to VT100 style/colour escape sequences
 */
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

/** Syslog facility table
 *
 * Maps syslog facility keywords, to the syslog facility macros defined
 * in the system's syslog.h.
 *
 * @note Not all facilities are supported by every operating system.
 *       If a facility is unavailable it will not appear in the table.
 */
const FR_NAME_NUMBER syslog_facility_table[] = {
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

/** Syslog severity table
 *
 * Maps syslog severity keywords, to the syslog severity macros defined
 * in the system's syslog.h file.
 *
 */
const FR_NAME_NUMBER syslog_severity_table[] = {
#ifdef LOG_EMERG
	{ "emergency",		LOG_EMERG	},
#endif
#ifdef LOG_ALERT
	{ "alert",		LOG_ALERT	},
#endif
#ifdef LOG_CRIT
	{ "critical",		LOG_CRIT	},
#endif
#ifdef LOG_ERR
	{ "error",		LOG_ERR		},
#endif
#ifdef LOG_WARNING
	{ "warning",		LOG_WARNING	},
#endif
#ifdef LOG_NOTICE
	{ "notice",		LOG_NOTICE	},
#endif
#ifdef LOG_INFO
	{ "info",		LOG_INFO	},
#endif
#ifdef LOG_DEBUG
	{ "debug",		LOG_DEBUG	},
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
	.colourise = false,		//!< Will be set later. Should be off before we do terminal detection.
	.fd = STDOUT_FILENO,
	.dst = L_DST_STDOUT,
	.file = NULL,
};

static int stderr_fd = -1;		//!< The original unmolested stderr file descriptor
static int stdout_fd = -1;		//!< The original unmolested stdout file descriptor

static char const spaces[] = "                                                                                                                        ";

/** On fault, reset STDOUT and STDERR to something useful
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

/** Initialise file descriptors based on logging destination
 *
 * @param log Logger to manipulate.
 * @param daemonize Whether the server is starting as a daemon.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
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
		 *	STDOUT too, for executed programs.
		 *
		 *	Allow stdout when running in foreground mode
		 *	as it's useful for some profiling tools,
		 *	like mutrace.
		 */
		if (rad_debug_lvl || !daemonize) {
			dup2(STDOUT_FILENO, STDERR_FILENO);
		} else {
			dup2(devnull, STDERR_FILENO);
		}

	} else if (log->dst == L_DST_STDERR) {
		setlinebuf(stderr);
		log->fd = STDERR_FILENO;

		/*
		 *	If we're debugging, allow STDOUT to go to
		 *	STDERR too, for executed programs.
		 *
		 *	Allow stdout when running in foreground mode
		 *	as it's useful for some profiling tools,
		 *	like mutrace.
		 */
		if (rad_debug_lvl || !daemonize) {
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

	} else if (rad_debug_lvl) {
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

	fr_fault_set_log_fd(log->fd);

	return 0;
}

/** Send a server log message to its destination
 *
 * @param type of log message.
 * @param msg with printf style substitution tokens.
 * @param ap Substitution arguments.
 */
int vradlog(log_type_t type, char const *msg, va_list ap)
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
		if ((rad_debug_lvl != 1) && (rad_debug_lvl != 2)) {
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
		len += vsnprintf(buffer + len, sizeof(buffer) - len - 1, msg, ap);
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
			clen = fr_utf8_char(p, -1);
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
		switch (type) {
		case L_DBG:
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

		case L_WARN:
			type = LOG_WARNING;
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

/** Send a server log message to its destination
 *
 * @param type of log message.
 * @param msg with printf style substitution tokens.
 * @param ... Substitution arguments.
 */
int radlog(log_type_t type, char const *msg, ...)
{
	va_list ap;
	int r = 0;

	va_start(ap, msg);

	/*
	 *	Non-debug message, or debugging is enabled.  Log it.
	 */
	if (((type & L_DBG) == 0) || (rad_debug_lvl > 0)) {
		r = vradlog(type, msg, ap);
	}
	va_end(ap);

	return r;
}

/** Send a server log message to its destination without evaluating its debug level
 *
 * @param type of log message.
 * @param msg with printf style substitution tokens.
 * @param ... Substitution arguments.
 */
static int radlog_always(log_type_t type, char const *msg, ...) CC_HINT(format (printf, 2, 3));
static int radlog_always(log_type_t type, char const *msg, ...)
{
	va_list ap;
	int r;

	va_start(ap, msg);
	r = vradlog(type, msg, ap);
	va_end(ap);

	return r;
}

/** Whether a server debug message should be logged
 *
 * @param type of message.
 * @param lvl of debugging this message should be logged at.
 * @return
 *	- true if message should be logged.
 *	- false if message shouldn't be logged.
 */
inline bool debug_enabled(log_type_t type, log_lvl_t lvl)
{
	if ((type & L_DBG) && (lvl <= rad_debug_lvl)) return true;

	return false;
}

/** Whether rate limiting is enabled
 */
bool rate_limit_enabled(void)
{
	if (rate_limit || (rad_debug_lvl < 1)) return true;

	return false;
}

/** Whether a request specific debug message should be logged
 *
 * @param type of message.
 * @param lvl of debugging this message should be logged at.
 * @param request The current request.
 * @return
 *	- true if message should be logged.
 *	- false if message shouldn't be logged.
 */
inline bool radlog_debug_enabled(log_type_t type, log_lvl_t lvl, REQUEST *request)
{
	/*
	 *	It's a debug class message, note this doesn't mean it's a debug type message.
	 *
	 *	For example it could be a RIDEBUG message, which would be an informational message,
	 *	instead of an RDEBUG message which would be a debug debug message.
	 *
	 *	There is log function, but the request debug level isn't high enough.
	 *	OR, we're in debug mode, and the global debug level isn't high enough,
	 *	then don't log the message.
	 */
	if ((type & L_DBG) &&
	    ((request->log.func && (lvl <= request->log.lvl)) ||
	     ((rad_debug_lvl != 0) && (lvl <= rad_debug_lvl)))) {
		return true;
	}

	return false;
}

/** Send a log message to its destination, possibly including fields from the request
 *
 * @param type of log message, #L_ERR, #L_WARN, #L_INFO, #L_DBG.
 * @param lvl Minimum required server or request level to output this message.
 * @param request The current request.
 * @param msg with printf style substitution tokens.
 * @param ap Substitution arguments.
 */
void vradlog_request(log_type_t type, log_lvl_t lvl, REQUEST *request, char const *msg, va_list ap)
{
	char const	*filename = request->log.output->file;
	FILE		*fp = NULL;

	char		*p;
	char const	*extra = "";
	uint8_t		unlang_indent, module_indent;
	va_list		aq;

	char		*msg_prefix = NULL;
	char		*msg_module = NULL;
	char		*msg_exp = NULL;

	rad_assert(request);

	/*
	 *	Debug messages get treated specially.
	 */
	if ((type & L_DBG) != 0) {
		if (!radlog_debug_enabled(type, lvl, request)) return;

		/*
		 *	If we're debugging to a file, then use that.
		 *
		 *	@todo: have vradlog() take a fr_log_t*, so
		 *	that we can cache the opened descriptor, and
		 *	we don't need to re-open it on every log
		 *	message.
		 */
		if (request->log.output) {
			switch (request->log.output->dst) {
			case L_DST_FILES:
				fp = fopen(request->log.output->file, "a");
				if (!fp) goto finish;
				break;

#if defined(HAVE_FOPENCOOKIE) || defined (HAVE_FUNOPEN)
			case L_DST_EXTRA:
			{
#  ifdef HAVE_FOPENCOOKIE
				cookie_io_functions_t io;

				/*
				 *	These must be set separately as they have different prototypes.
				 */
				io.read = NULL;
				io.seek = NULL;
				io.close = NULL;
				io.write = request->log.output->cookie_write;

				fp = fopencookie(request->log.output->cookie, "w", io);
#  else
				fp = funopen(request->log.output->cookie,
					     NULL, request->log.output->cookie_write, NULL, NULL);

#  endif
				if (!fp) goto finish;
			}
				break;
#endif
			default:
				break;
			}
			goto print_msg;
		}
	}

	if (filename) {
		char *exp;

		radlog_func_t log_func = request->log.func;

		/*
		 *	Prevent infinitely recursive calls if
		 *	radius_axlat attempts to write to the request log.
		 */
		request->log.func = NULL;

		/*
		 *	This is SLOW!  Doing it for every log message
		 *	in every request is NOT recommended!
		 */
		if (radius_axlat(&exp, request, filename, rad_filename_escape, NULL) < 0) return;

		/*
		 *	Restore the original logging function
		 */
		request->log.func = log_func;

		/*
		 *	Ensure the directory structure exists, for
		 *	where we're going to write the log file.
		 */
		p = strrchr(exp, FR_DIR_SEP);
		if (p) {
			*p = '\0';
			if (rad_mkdir(exp, S_IRWXU, -1, -1) < 0) {
				ERROR("Failed creating %s: %s", exp, fr_syserror(errno));
				talloc_free(exp);
				return;
			}
			*p = FR_DIR_SEP;
		}

		fp = fopen(exp, "a");
		talloc_free(exp);
	}

print_msg:
	/*
	 *	Request prefix i.e.
	 *
	 *	(0) <msg>
	 */
	if ((request->seq_start == 0) || (request->number == request->seq_start)) {
		msg_prefix = talloc_asprintf(request, "(%" PRIu64 ")  ", request->number);
	} else {
		msg_prefix = talloc_asprintf(request, "(%" PRIu64 ",%" PRIu64 ")  ",
					     request->number, request->seq_start);
	}

	/*
	 *	Make sure the indent isn't set to something crazy
	 */
	unlang_indent = request->log.unlang_indent > sizeof(spaces) - 1 ?
			sizeof(spaces) - 1 :
			request->log.unlang_indent;

	module_indent = request->log.module_indent > sizeof(spaces) - 1 ?
			sizeof(spaces) - 1 :
			request->log.module_indent;

	/*
	 *	Module name and indentation i.e.
	 *
	 *	test -     <msg>
	 */
	if (request->module) {
		msg_module = talloc_asprintf(request, "%s - %.*s", request->module, module_indent, spaces);
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
	msg_exp = talloc_vasprintf(request, msg, aq);
	va_end(aq);

	/*
	 *	Logging to a file descriptor
	 */
	if (fp) {
		char time_buff[64];	/* The current timestamp */

		time_t timeval;
		timeval = time(NULL);

#ifdef HAVE_GMTIME_R
		if (log_dates_utc) {
			struct tm utc;
			gmtime_r(&timeval, &utc);
			ASCTIME_R(&utc, time_buff, sizeof(time_buff));
		} else
#endif
		{
			CTIME_R(&timeval, time_buff, sizeof(time_buff));
		}

		/*
		 *	Strip trailing new lines
		 */
		p = strrchr(time_buff, '\n');
		if (p) p[0] = '\0';

		fprintf(fp, "%s" "%s" "%s" "%.*s" "%s" "%s" "\n",
			msg_prefix,
			time_buff,
			fr_int2str(levels, type, ""),
			unlang_indent, spaces,
			msg_module ? msg_module : "",
			msg_exp);
		fclose(fp);
		goto finish;
	}

	/*
	 *	Logging everywhere else
	 */
	if (!DEBUG_ENABLED3) switch (type) {
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
	};

	radlog_always(type, "%s" "%.*s" "%s" "%s" "%s",
		      msg_prefix,
		      unlang_indent, spaces,
		      msg_module ? msg_module : "",
		      extra,
		      msg_exp);

finish:
	talloc_free(msg_exp);
	talloc_free(msg_module);
	talloc_free(msg_prefix);
}

/** Martial variadic log arguments into a va_list and pass to normal logging functions
 *
 * @see radlog_request_error for more details.
 *
 * @param type the log category.
 * @param lvl of debugging this message should be logged at.
 * @param request The current request.
 * @param msg with printf style substitution tokens.
 * @param ... Substitution arguments.
 */
void radlog_request(log_type_t type, log_lvl_t lvl, REQUEST *request, char const *msg, ...)
{
	va_list ap;

	rad_assert(request);

	if (!request->log.func && !(type & L_DBG)) return;

	va_start(ap, msg);
	if (request->log.func) request->log.func(type, lvl, request, msg, ap);
	else if (!(type & L_DBG)) vradlog_request(type, lvl, request, msg, ap);
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
 * @param lvl of debugging this message should be logged at.
 * @param request The current request.
 * @param msg with printf style substitution tokens.
 * @param ... Substitution arguments.
 */
void radlog_request_error(log_type_t type, log_lvl_t lvl, REQUEST *request, char const *msg, ...)
{
	va_list ap;

	rad_assert(request);

	va_start(ap, msg);
	if (request->log.func) request->log.func(type, lvl, request, msg, ap);
	else if (!(type & L_DBG)) vradlog_request(type, lvl, request, msg, ap);
	vmodule_failure_msg(request, msg, ap);
	va_end(ap);
}

/** Write the string being parsed, and a marker showing where the parse error occurred
 *
 * @param type the log category.
 * @param lvl of debugging this message should be logged at.
 * @param request The current request.
 * @param msg string we were parsing.
 * @param idx The position of the marker relative to the string.
 * @param error What the parse error was.
 */
void radlog_request_marker(log_type_t type, log_lvl_t lvl, REQUEST *request,
			   char const *msg, size_t idx, char const *error)
{
	char const *prefix = "";
	uint8_t unlang_indent;
	uint8_t module_indent;

	rad_assert(request);

	if (idx >= sizeof(spaces)) {
		size_t offset = (idx - (sizeof(spaces) - 1)) + (sizeof(spaces) * 0.75);
		idx -= offset;
		msg += offset;

		prefix = "... ";
	}

	/*
	 *  Don't want format markers being indented
	 */
	unlang_indent = request->log.unlang_indent;
	module_indent = request->log.module_indent;
	request->log.unlang_indent = 0;
	request->log.module_indent = 0;

	radlog_request(type, lvl, request, "%s%s", prefix, msg);
	radlog_request(type, lvl, request, "%s%.*s^ %s", prefix, (int) idx, spaces, error);

	request->log.unlang_indent = unlang_indent;
	request->log.module_indent = module_indent;
}

void radlog_request_hex(log_type_t type, log_lvl_t lvl, REQUEST *request,
			uint8_t const *data, size_t data_len)
{
	size_t i, j, len;
	char *p;
	char buffer[(0x10 * 3) + 1];

	for (i = 0; i < data_len; i += 0x10) {
		len = 0x10;
		if ((i + len) > data_len) len = data_len - i;

		for (p = buffer, j = 0; j < len; j++, p += 3) sprintf(p, "%02x ", data[i + j]);
		radlog_request(type, lvl, request, "%04x: %s", (int)i, buffer);
	}
}

void radlog_hex(log_type_t type, log_lvl_t lvl, uint8_t const *data, size_t data_len)
{
	size_t i, j, len;
	char *p;
	char buffer[(0x10 * 3) + 1];

	if (!debug_enabled(L_DBG, lvl)) return;

	for (i = 0; i < data_len; i += 0x10) {
		len = 0x10;
		if ((i + len) > data_len) len = data_len - i;

		for (p = buffer, j = 0; j < len; j++, p += 3) sprintf(p, "%02x ", data[i + j]);
		radlog(type, "%04x: %s", (int)i, buffer);
	}
}
