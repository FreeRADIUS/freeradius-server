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
 * @file src/lib/server/log.c
 *
 * @copyright 2000,2006  The FreeRADIUS server project
 * @copyright 2000  Miquel van Smoorenburg <miquels@cistron.nl>
 * @copyright 2000  Alan DeKok <aland@ox.org>
 * @copyright 2001  Chad Miller <cmiller@surfsouth.com>
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/rad_assert.h>

#ifdef HAVE_SYS_STAT_H
#  include <sys/stat.h>
#endif

#include <fcntl.h>

#ifdef HAVE_SYSLOG_H
#  include <syslog.h>
#endif

#include <sys/file.h>
#include <pthread.h>

fr_log_lvl_t	rad_debug_lvl = 0;		//!< Global debugging level
fr_log_lvl_t	req_debug_lvl = 0;		//!< Request debugging level

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

static char const spaces[] = "                                                                                                                        ";

static fr_dict_t *dict_freeradius;

extern fr_dict_autoload_t log_dict[];
fr_dict_autoload_t log_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_module_failure_message;

extern fr_dict_attr_autoload_t log_dict_attr[];
fr_dict_attr_autoload_t log_dict_attr[] = {
	{ .out = &attr_module_failure_message, .name = "Module-Failure-Message", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ NULL }
};

/** Send a server log message to its destination without evaluating its debug level
 *
 * @param log	destination.
 * @param type	of log message.
 * @param msg	with printf style substitution tokens.
 * @param ...	Substitution arguments.
 */
static int log_always(fr_log_t const *log, fr_log_type_t type, char const *msg, ...) CC_HINT(format (printf, 3, 4));
static int log_always(fr_log_t const *log, fr_log_type_t type, char const *msg, ...)
{
	va_list ap;
	int r;

	va_start(ap, msg);
	r = fr_vlog(log, type, msg, ap);
	va_end(ap);

	return r;
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
inline bool log_debug_enabled(fr_log_type_t type, fr_log_lvl_t lvl, REQUEST *request)
{
	if (!request->log.dst) return false;

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
	    ((lvl <= request->log.lvl) ||
	     ((rad_debug_lvl != 0) && (lvl <= rad_debug_lvl)))) {
		return true;
	}

	return false;
}

/** Send a log message to its destination, possibly including fields from the request
 *
 * @param[in] type	of log message, #L_ERR, #L_WARN, #L_INFO, #L_DBG.
 * @param[in] lvl	Minimum required server or request level to output this message.
 * @param[in] request	The current request.
 * @param[in] msg	with printf style substitution tokens.
 * @param[in] ap	Substitution arguments.
 * @param[in] uctx	The #fr_log_t specifying the destination for log messages.
 */
void vlog_request(fr_log_type_t type, fr_log_lvl_t lvl, REQUEST *request, char const *msg, va_list ap, void *uctx)
{
	char const	*filename;
	FILE		*fp = NULL;

	char		*p;
	char const	*extra = "";
	uint8_t		unlang_indent, module_indent;
	va_list		aq;

	char		*msg_prefix = NULL;
	char		*msg_module = NULL;
	char		*msg_exp = NULL;

	fr_log_t	*log_dst = uctx;

	/*
	 *	No output means no output.
	 */
	if (!log_dst) return;

	filename = log_dst->file;

	/*
	 *	Debug messages get treated specially.
	 */
	if ((type & L_DBG) != 0) {
		if (!log_debug_enabled(type, lvl, request)) return;

		/*
		 *	If we're debugging to a file, then use that.
		 *
		 *	@todo: have fr_vlog() take a fr_log_t*, so
		 *	that we can cache the opened descriptor, and
		 *	we don't need to re-open it on every log
		 *	message.
		 */
		switch (log_dst->dst) {
		case L_DST_FILES:
			fp = fopen(log_dst->file, "a");
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
			io.write = log_dst->cookie_write;

			fp = fopencookie(log_dst->cookie, "w", io);
#  else
			fp = funopen(log_dst->cookie, NULL, log_dst->cookie_write, NULL, NULL);

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

	if (filename) {
		char		*exp;
		log_dst_t	*dst;

		dst = request->log.dst;

		/*
		 *	Prevent infinitely recursive calls if
		 *	xlat_aeval attempts to write to the request log.
		 */
		request->log.dst = NULL;

		/*
		 *	This is SLOW!  Doing it for every log message
		 *	in every request is NOT recommended!
		 */
		if (xlat_aeval(request, &exp, request, filename, rad_filename_escape, NULL) < 0) return;

		/*
		 *	Restore the original logging function
		 */
		request->log.dst = dst;

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
		msg_prefix = talloc_typed_asprintf(request, "(%s)  ", request->name);
	} else {
		msg_prefix = talloc_typed_asprintf(request, "(%s,%" PRIu64 ")  ",
					     request->name, request->seq_start);
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
		msg_module = talloc_typed_asprintf(request, "%s - %.*s", request->module, module_indent, spaces);
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
	msg_exp = fr_vasprintf(request, msg, aq);
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

		fprintf(fp, "%s" "%s : " "%s" "%.*s" "%s" "%s" "\n",
			msg_prefix,
			time_buff,
			fr_int2str(fr_log_levels, type, ""),
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

	log_always(log_dst,
		      type, "%s" "%.*s" "%s" "%s" "%s",
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

/** Add a module failure message VALUE_PAIR to the request
 *
 * @param[in] request	The current request.
 * @param[in] msg	with printf style substitution tokens.
 * @param[in] ap	Substitution arguments.
 */
void vlog_module_failure_msg(REQUEST *request, char const *msg, va_list ap)
{
	char		*p;
	VALUE_PAIR	*vp;
	va_list		aq;

	if (!msg || !request || !request->packet) return;

	rad_assert(attr_module_failure_message);

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
	p = fr_vasprintf(request, msg, aq);
	va_end(aq);

	MEM(pair_add_request(&vp, attr_module_failure_message) >= 0);
	if (request->module && (request->module[0] != '\0')) {
		fr_pair_value_snprintf(vp, "%s: %s", request->module, p);
	} else {
		fr_pair_value_snprintf(vp, "%s", p);
	}
	talloc_free(p);
}

/** Add a module failure message VALUE_PAIRE to the request
 *
 * @param[in] request	The current request.
 * @param[in] msg	with printf style substitution tokens.
 * @param[in] ...	Substitution arguments.
 */
void log_module_failure_msg(REQUEST *request, char const *msg, ...)
{
	va_list ap;

	va_start(ap, msg);
	vlog_module_failure_msg(request, msg, ap);
	va_end(ap);
}

/** Martial variadic log arguments into a va_list and pass to normal logging functions
 *
 * @see log_request_error for more details.
 *
 * @param[in] type	the log category.
 * @param[in] lvl	of debugging this message should be logged at.
 * @param[in] request	The current request.
 * @param[in] msg	with printf style substitution tokens.
 * @param[in] ...	Substitution arguments.
 */
void log_request(fr_log_type_t type, fr_log_lvl_t lvl, REQUEST *request, char const *msg, ...)
{
	va_list		ap;
	log_dst_t	*dst_p;

	if (!request->log.dst) return;

	va_start(ap, msg);
	for (dst_p = request->log.dst; dst_p; dst_p = dst_p->next) {
		dst_p->func(type, lvl, request, msg, ap, dst_p->uctx);
	}
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
 * @param[in] type	the log category.
 * @param[in] lvl	of debugging this message should be logged at.
 * @param[in] request	The current request.
 * @param[in] msg	with printf style substitution tokens.
 * @param[in] ...	Substitution arguments.
 */
void log_request_error(fr_log_type_t type, fr_log_lvl_t lvl, REQUEST *request, char const *msg, ...)
{
	va_list		ap;
	log_dst_t	*dst_p;

	if (!request->log.dst) return;

	va_start(ap, msg);
	for (dst_p = request->log.dst; dst_p; dst_p = dst_p->next) {
		dst_p->func(type, lvl, request, msg, ap, dst_p->uctx);
	}
	vlog_module_failure_msg(request, msg, ap);
	va_end(ap);
}

/** Drain any outstanding messages from the fr_strerror buffers
 *
 * This function drains any messages from fr_strerror buffer adding a prefix (msg)
 * to the first message.
 *
 * @param[in] type	the log category.
 * @param[in] lvl	of debugging this message should be logged at.
 * @param[in] request	The current request.
 * @param[in] msg	with printf style substitution tokens.
 * @param[in] ...	Substitution arguments.
 */
void log_request_perror(fr_log_type_t type, fr_log_lvl_t lvl, REQUEST *request, char const *msg, ...)
{
	char const *strerror;

	if (!request->log.dst) return;

	/*
	 *	No strerror gets us identical behaviour to log_request_error
	 */
	strerror = fr_strerror_pop();
	if (!strerror) {
		va_list		ap;
		log_dst_t	*dst_p;

		if (!msg) return;	/* NOOP */

		va_start(ap, msg);
		for (dst_p = request->log.dst; dst_p; dst_p = dst_p->next) {
			dst_p->func(type, lvl, request, msg, ap, dst_p->uctx);
		}
		va_end(ap);

		return;			/* DONE */
	}

	/*
	 *	Concatenate msg with fr_strerror()
	 */
	if (msg) {
		va_list ap;
		char *tmp;

		va_start(ap, msg);
		tmp = fr_vasprintf(request, msg, ap);
		va_end(ap);

		if (!tmp) return;

		log_request_error(type, lvl, request, "%s: %s", tmp, strerror);
		talloc_free(tmp);
	} else {
		log_request_error(type, lvl, request, "%s", strerror);
	}

	/*
	 *	Only the first message gets the prefix
	 */
	while ((strerror = fr_strerror_pop())) {
		log_request_error(type, lvl, request, "%s", strerror);
	}
}

/** Print a list of VALUE_PAIRs.
 *
 * @param[in] lvl	Debug lvl (1-4).
 * @param[in] request	to read logging params from.
 * @param[in] vp	to print.
 * @param[in] prefix	(optional).
 */
void log_request_pair_list(fr_log_lvl_t lvl, REQUEST *request, VALUE_PAIR *vp, char const *prefix)
{
	fr_cursor_t cursor;

	if (!vp || !request || !request->log.dst) return;

	if (!log_debug_enabled(L_DBG, lvl, request)) return;

	RINDENT();
	for (vp = fr_cursor_init(&cursor, &vp);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		VP_VERIFY(vp);

		RDEBUGX(lvl, "%s%pP", prefix ? prefix : "&", vp);
	}
	REXDENT();
}

/** Print a list of protocol VALUE_PAIRs.
 *
 * @param[in] lvl	Debug lvl (1-4).
 * @param[in] request	to read logging params from.
 * @param[in] vp	to print.
 * @param[in] prefix	(optional).
 */
void log_request_proto_pair_list(fr_log_lvl_t lvl, REQUEST *request, VALUE_PAIR *vp, char const *prefix)
{
	fr_cursor_t cursor;

	if (!vp || !request || !request->log.dst) return;

	if (!log_debug_enabled(L_DBG, lvl, request)) return;

	RINDENT();
	for (vp = fr_cursor_init(&cursor, &vp);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		VP_VERIFY(vp);
		if (vp->da->flags.internal) continue;

		RDEBUGX(lvl, "%s%pP", prefix ? prefix : "&", vp);
	}
	REXDENT();
}

/** Write the string being parsed, and a marker showing where the parse error occurred
 *
 * @param[in] type	the log category.
 * @param[in] lvl	of debugging this message should be logged at.
 * @param[in] request	The current request.
 * @param[in] msg	string we were parsing.
 * @param[in] idx	The position of the marker relative to the string.
 * @param[in] error	What the parse error was.
 */
void log_request_marker(fr_log_type_t type, fr_log_lvl_t lvl, REQUEST *request,
			char const *msg, size_t idx, char const *error)
{
	char const *prefix = "";
	uint8_t unlang_indent;
	uint8_t module_indent;

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

	log_request(type, lvl, request, "%s%s", prefix, msg);
	log_request(type, lvl, request, "%s%.*s^ %s", prefix, (int) idx, spaces, error);

	request->log.unlang_indent = unlang_indent;
	request->log.module_indent = module_indent;
}

void log_request_hex(fr_log_type_t type, fr_log_lvl_t lvl, REQUEST *request,
			uint8_t const *data, size_t data_len)
{
	size_t i, j, len;
	char *p;
	char buffer[(0x10 * 3) + 1];

	for (i = 0; i < data_len; i += 0x10) {
		len = 0x10;
		if ((i + len) > data_len) len = data_len - i;

		for (p = buffer, j = 0; j < len; j++, p += 3) sprintf(p, "%02x ", data[i + j]);
		log_request(type, lvl, request, "%04x: %s", (int)i, buffer);
	}
}

void log_hex(fr_log_t const *log, fr_log_type_t type, fr_log_lvl_t lvl, uint8_t const *data, size_t data_len)
{
	size_t i, j, len;
	char *p;
	char buffer[(0x10 * 3) + 1];

	if (!debug_enabled(L_DBG, lvl)) return;

	for (i = 0; i < data_len; i += 0x10) {
		len = 0x10;
		if ((i + len) > data_len) len = data_len - i;

		for (p = buffer, j = 0; j < len; j++, p += 3) sprintf(p, "%02x ", data[i + j]);
		fr_log(log, type, "%04x: %s", (int)i, buffer);
	}
}

/** Log a fatal error, then exit
 *
 */
void log_fatal(char const *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fr_vlog(&default_log, L_ERR, fmt, ap);
	va_end(ap);

	fr_exit_now(1);
}

/** Initialises the server logging functionality, and the underlying libfreeradius log
 *
 * @note Call log free when the server is done to fix any spurious memory leaks.
 *
 * @param[in] log	Logging parameters.
 * @param[in] daemonize	Changes what we do with stdout/stderr.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int log_global_init(fr_log_t *log, bool daemonize)
{
	int ret;

	ret = fr_log_init(log, daemonize);
	if (ret < 0) return ret;

	if (fr_dict_autoload(log_dict) < 0) {
		fr_perror("log_init");
		return -1;
	}

	if (fr_dict_attr_autoload(log_dict_attr) < 0) {
		fr_perror("log_init");
		return -1;
	}

	return ret;
}

void log_global_free(void)
{
	fr_dict_autofree(log_dict);
}
