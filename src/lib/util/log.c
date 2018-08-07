/*
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** Support functions for logging in FreeRADIUS libraries
 *
 * @file src/lib/util/log.c
 *
 * @copyright 2003,2006  The FreeRADIUS server project
 */
RCSID("$Id$")

#include "log.h"

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/print.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/syserror.h>

#include <fcntl.h>
#ifdef HAVE_FEATURES_H
#  include <features.h>
#endif
#include <stdio.h>
#ifdef HAVE_SYSLOG_H
#  include <syslog.h>
#endif
#include <time.h>
#include <unistd.h>

FILE	*fr_log_fp = NULL;
int	fr_debug_lvl = 0;

/** Canonicalize error strings, removing tabs, and generate spaces for error marker
 *
 * @note talloc_free must be called on the buffer returned in spaces and text
 *
 * Used to produce error messages such as this:
 @verbatim
  I'm a string with a parser # error
                             ^ Unexpected character in string
 @endverbatim
 *
 * With code resembling this:
 @code{.c}
   ERROR("%s", parsed_str);
   ERROR("%s^ %s", space, text);
 @endcode
 *
 * @todo merge with above function (log_request_marker)
 *
 * @param sp Where to write a dynamically allocated buffer of spaces used to indent the error text.
 * @param text Where to write the canonicalized version of msg (the error text).
 * @param ctx to allocate the spaces and text buffers in.
 * @param slen of error marker. Expects negative integer value, as returned by parse functions.
 * @param msg to canonicalize.
 */
void fr_canonicalize_error(TALLOC_CTX *ctx, char **sp, char **text, ssize_t slen, char const *msg)
{
	size_t offset, skip = 0;
	char *spbuf, *p;
	char *value;

	offset = -slen;

	/*
	 *	Ensure that the error isn't indented
	 *	too far.
	 */
	if (offset > 45) {
		skip = offset - 40;
		offset -= skip;
		value = talloc_strdup(ctx, msg + skip);
		memcpy(value, "...", 3);

	} else {
		value = talloc_strdup(ctx, msg);
	}

	spbuf = talloc_array(ctx, char, offset + 1);
	memset(spbuf, ' ', offset);
	spbuf[offset] = '\0';

	/*
	 *	Smash tabs to spaces for the input string.
	 */
	for (p = value; *p != '\0'; p++) {
		if (*p == '\t') *p = ' ';
	}


	/*
	 *	Ensure that there isn't too much text after the error.
	 */
	if (strlen(value) > 100) {
		memcpy(value + 95, "... ", 5);
	}

	*sp = spbuf;
	*text = value;
}

/** Maps log categories to message prefixes
 */
const FR_NAME_NUMBER fr_log_levels[] = {
	{ "Debug : ",		L_DBG		},
	{ "Auth  : ",		L_AUTH		},
	{ "Proxy : ",		L_PROXY		},
	{ "Info  : ",		L_INFO		},
	{ "Warn  : ",		L_WARN		},
	{ "Acct  : ",		L_ACCT		},
	{ "Error : ",		L_ERR		},
	{ "WARN  : ",		L_DBG_WARN	},
	{ "ERROR : ",		L_DBG_ERR	},
	{ "WARN  : ",		L_DBG_WARN_REQ	},
	{ "ERROR : ",		L_DBG_ERR_REQ	},
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


bool log_dates_utc = false;

fr_log_t default_log = {
	.colourise = false,		//!< Will be set later. Should be off before we do terminal detection.
	.fd = STDOUT_FILENO,
	.dst = L_DST_STDOUT,
	.file = NULL,
	.timestamp = L_TIMESTAMP_AUTO
};

/** Send a server log message to its destination
 *
 * @param log	destination.
 * @param type	of log message.
 * @param msg	with printf style substitution tokens.
 * @param ap	Substitution arguments.
 */
int fr_vlog(fr_log_t const *log, fr_log_type_t type, char const *msg, va_list ap)
{
	uint8_t		*p;
	char		buffer[10240];	/* The largest config item size, then extra for prefixes and suffixes */
	char		*unsan;
	size_t		len;
	int		colourise = log->colourise;

	/*
	 *	If we don't want any messages, then
	 *	throw them away.
	 */
	if (log->dst == L_DST_NULL) return 0;

	buffer[0] = '\0';
	len = 0;

	/*
	 *	Set colourisation
	 */
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
	 *	Determine if we need to add a timestamp to the start of the message
	 */
	switch (log->timestamp) {
	case L_TIMESTAMP_OFF:
		break;

	/*
	 *	If we're not logging to syslog, and the debug level is -xxx
	 *	then log timestamps by default.
	 */
	case L_TIMESTAMP_AUTO:
		if (log->dst == L_DST_SYSLOG) break;
		if ((log->dst != L_DST_FILES) && (fr_debug_lvl <= L_DBG_LVL_2)) break;
		/* FALL-THROUGH */

	case L_TIMESTAMP_ON:
	{
		time_t timeval;

		timeval = time(NULL);
#ifdef HAVE_GMTIME_R
		if (log->dates_utc) {
			struct tm utc;
			gmtime_r(&timeval, &utc);
			ASCTIME_R(&utc, buffer + len, sizeof(buffer) - len - 1);
		} else
#endif
		{
			CTIME_R(&timeval, buffer + len, sizeof(buffer) - len - 1);
		}
		len = strlen(buffer);
		len += strlcpy(buffer + len, ": ", sizeof(buffer) - len - 1);
	}
		break;
	}

	/*
	 *	Add ERROR or WARNING prefixes to messages not going to
	 *	syslog.  It's redundant for syslog because of syslog
	 *	facilities.
	 */
	if (log->dst != L_DST_SYSLOG) {
		/*
		 *	Only print the 'facility' if we're not colourising the log messages
		 *	and this isn't syslog.
		 */
		if (!log->colourise) {
			len += strlcpy(buffer + len, fr_int2str(fr_log_levels, type, ": "), sizeof(buffer) - len);
		}

		/*
		 *	Add an additional prefix to highlight that this is a bad message
		 *	the user should pay attention to.
		 */
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
		char *tmp;

		/*
		 *	Fixme - All this code should be reworked to use a dynamic buffer
		 */
		tmp = fr_vasprintf(NULL, msg, ap);
		len += strlcpy(buffer + len, tmp, sizeof(buffer) - len);
		talloc_free(tmp);
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

	/*
	 *	Reset colourisation if we applied it
	 */
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

	switch (log->dst) {

#ifdef HAVE_SYSLOG_H
	case L_DST_SYSLOG:
		switch (type) {
		case L_DBG:
		case L_DBG_INFO:
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
		return write(log->fd, buffer, strlen(buffer));

	default:
	case L_DST_NULL:	/* should have been caught above */
		break;
	}

	return 0;
}

/** Send a server log message to its destination
 *
 * @param log	destination.
 * @param type	of log message.
 * @param msg	with printf style substitution tokens.
 * @param ...	Substitution arguments.
 */
int fr_log(fr_log_t const *log, fr_log_type_t type, char const *msg, ...)
{
	va_list ap;
	int ret = 0;

	/*
	 *	Non-debug message, or debugging is enabled.  Log it.
	 */
	if (!(((type & L_DBG) == 0) || (fr_debug_lvl > 0))) return 0;

	va_start(ap, msg);
	ret = fr_vlog(log, type, msg, ap);
	va_end(ap);

	return ret;
}

/** Drain any outstanding messages from the fr_strerror buffers
 *
 * This function drains any messages from fr_strerror buffer adding a prefix (msg)
 * to the first message.
 *
 * @param log	destination.
 * @param type	of log message.
 * @param msg	with printf style substitution tokens.
 * @param ...	Substitution arguments.
 */
int fr_log_perror(fr_log_t const *log, fr_log_type_t type, char const *msg, ...)
{
	char const *strerror;
	int ret;

	/*
	 *	Non-debug message, or debugging is enabled.  Log it.
	 */
	if (!(((type & L_DBG) == 0) || (fr_debug_lvl > 0))) return 0;

	strerror = fr_strerror_pop();
	if (!strerror) {
		va_list ap;
		if (!msg) return 0;	/* NOOP */

		va_start(ap, msg);
		ret = fr_vlog(log, type, msg, ap);
		va_end(ap);

		return ret;		/* DONE */
	}

	/*
	 *	Concatenate msg with fr_strerror()
	 */
	if (msg) {
		va_list ap;
		char *tmp;

		va_start(ap, msg);
		tmp = talloc_vasprintf(NULL, msg, ap);
		va_end(ap);

		if (!tmp) return -1;

		fr_log(log, type, "%s: %s", tmp, strerror);
		talloc_free(tmp);
	} else {
		fr_log(log, type, "%s", strerror);
	}

	/*
	 *	Only the first message gets the prefix
	 */
	while ((strerror = fr_strerror_pop())) {
		ret = fr_log(log, type, "%s", strerror);
		if (ret < 0) return ret;
	}

	return 0;
}

static int stderr_fd = -1;		//!< The original unmolested stderr file descriptor
static int stdout_fd = -1;		//!< The original unmolested stdout file descriptor
static bool rate_limit = true;		//!< Whether repeated log entries should be rate limited

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
int fr_log_init(fr_log_t *log, bool daemonize)
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
		if (fr_debug_lvl || !daemonize) {
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
		if (fr_debug_lvl || !daemonize) {
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

	} else if (fr_debug_lvl) {
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

/** Whether rate limiting is enabled
 */
bool fr_rate_limit_enabled(void)
{
	if (rate_limit || (fr_debug_lvl < 1)) return true;

	return false;
}

void fr_printf_log(char const *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if ((fr_debug_lvl == 0) || !fr_log_fp) {
		va_end(ap);
		return;
	}

	vfprintf(fr_log_fp, fmt, ap);
	va_end(ap);

	return;
}
