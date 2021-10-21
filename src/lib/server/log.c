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
 * @copyright 2000,2006 The FreeRADIUS server project
 * @copyright 2000 Miquel van Smoorenburg (miquels@cistron.nl)
 * @copyright 2000 Alan DeKok (aland@freeradius.org)
 * @copyright 2001 Chad Miller (cmiller@surfsouth.com)
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/util/debug.h>

#ifdef HAVE_SYS_STAT_H
#  include <sys/stat.h>
#endif

#include <fcntl.h>

#ifdef HAVE_SYSLOG_H
#  include <syslog.h>
#endif

#include <sys/file.h>
#include <pthread.h>

static _Thread_local TALLOC_CTX *fr_vlog_request_pool;
static _Thread_local fr_sbuff_t *fr_log_request_oid_buff;

/** Syslog facility table
 *
 * Maps syslog facility keywords, to the syslog facility macros defined
 * in the system's syslog.h.
 *
 * @note Not all facilities are supported by every operating system.
 *       If a facility is unavailable it will not appear in the table.
 */
fr_table_num_sorted_t const syslog_facility_table[] = {
#ifdef LOG_AUTH
	{ L("auth"),		LOG_AUTH	},
#endif

#ifdef LOG_AUTHPRIV
	{ L("authpriv"),	LOG_AUTHPRIV	},
#endif

#ifdef LOG_CRON
	{ L("cron"),		LOG_CRON	},
#endif

#ifdef LOG_DAEMON
	{ L("daemon"),		LOG_DAEMON	},
#endif

#ifdef LOG_FTP
	{ L("ftp"),		LOG_FTP		},
#endif

#ifdef LOG_KERN
	{ L("kern"),		LOG_KERN	},
#endif

#ifdef LOG_LOCAL0
	{ L("local0"),		LOG_LOCAL0	},
#endif

#ifdef LOG_LOCAL1
	{ L("local1"),		LOG_LOCAL1	},
#endif

#ifdef LOG_LOCAL2
	{ L("local2"),		LOG_LOCAL2	},
#endif

#ifdef LOG_LOCAL3
	{ L("local3"),		LOG_LOCAL3	},
#endif

#ifdef LOG_LOCAL4
	{ L("local4"),		LOG_LOCAL4	},
#endif

#ifdef LOG_LOCAL5
	{ L("local5"),		LOG_LOCAL5	},
#endif

#ifdef LOG_LOCAL6
	{ L("local6"),		LOG_LOCAL6	},
#endif

#ifdef LOG_LOCAL7
	{ L("local7"),		LOG_LOCAL7	},
#endif

#ifdef LOG_LPR
	{ L("lpr"),		LOG_LPR		},
#endif

#ifdef LOG_MAIL
	{ L("mail"),		LOG_MAIL	},
#endif

#ifdef LOG_NEWS
	{ L("news"),		LOG_NEWS	},
#endif

#ifdef LOG_USER
	{ L("user"),		LOG_USER	},
#endif

#ifdef LOG_UUCP
	{ L("uucp"),		LOG_UUCP	}
#endif
};
size_t syslog_facility_table_len = NUM_ELEMENTS(syslog_facility_table);

/** Syslog severity table
 *
 * Maps syslog severity keywords, to the syslog severity macros defined
 * in the system's syslog.h file.
 *
 */
fr_table_num_sorted_t const syslog_severity_table[] = {
#ifdef LOG_ALERT
	{ L("alert"),		LOG_ALERT	},
#endif

#ifdef LOG_CRIT
	{ L("critical"),	LOG_CRIT	},
#endif

#ifdef LOG_DEBUG
	{ L("debug"),		LOG_DEBUG	},
#endif

#ifdef LOG_EMERG
	{ L("emergency"),	LOG_EMERG	},
#endif

#ifdef LOG_ERR
	{ L("error"),		LOG_ERR		},
#endif

#ifdef LOG_INFO
	{ L("info"),		LOG_INFO	},
#endif

#ifdef LOG_NOTICE
	{ L("notice"),		LOG_NOTICE	},
#endif

#ifdef LOG_WARNING
	{ L("warning"),		LOG_WARNING	},
#endif
};
size_t syslog_severity_table_len = NUM_ELEMENTS(syslog_severity_table);

fr_table_num_sorted_t const log_destination_table[] = {
	{ L("files"),		L_DST_FILES	},
	{ L("null"),		L_DST_NULL	},
	{ L("stderr"),		L_DST_STDERR	},
	{ L("stdout"),		L_DST_STDOUT	},
	{ L("syslog"),		L_DST_SYSLOG	},
};
size_t log_destination_table_len = NUM_ELEMENTS(log_destination_table);

static char const spaces[] = "                                                                                                                        ";

static fr_dict_t const *dict_freeradius;

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
 * @param[in] log	destination.
 * @param[in] type	of log message.
 * @param[in] file	src file the log message was generated in.
 * @param[in] line	number the log message was generated on.
 * @param[in] fmt	with printf style substitution tokens.
 * @param[in] ...	Substitution arguments.
 */

static CC_HINT(format (printf, 5, 6))
void log_always(fr_log_t const *log, fr_log_type_t type,
		char const *file, int line,
		char const *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fr_vlog(log, type, file, line, fmt, ap);
	va_end(ap);
}

/** Whether a request specific debug message should be logged
 *
 * @param lvl of debugging this message should be logged at.
 * @param request The current request.
 * @return
 *	- true if message should be logged.
 *	- false if message shouldn't be logged.
 */
inline bool log_rdebug_enabled(fr_log_lvl_t lvl, request_t const *request)
{
	if (!request->log.dst) return false;

	if (lvl <= request->log.lvl) return true;

	return false;
}

/** Cleanup the memory pool used by vlog_request
 *
 */
static void _fr_vlog_request_pool_free(void *arg)
{
	talloc_free(arg);
}

/** Send a log message to its destination, possibly including fields from the request
 *
 * @param[in] type	of log message, #L_ERR, #L_WARN, #L_INFO, #L_DBG.
 * @param[in] lvl	Minimum required server or request level to output this message.
 * @param[in] request	The current request.
 * @param[in] file	src file the log message was generated in.
 * @param[in] line	number the log message was generated on.
 * @param[in] fmt	with printf style substitution tokens.
 * @param[in] ap	Substitution arguments.
 * @param[in] uctx	The #fr_log_t specifying the destination for log messages.
 */
void vlog_request(fr_log_type_t type, fr_log_lvl_t lvl, request_t *request,
		  char const *file, int line,
		  char const *fmt, va_list ap, void *uctx)
{
	char const	*filename;
	FILE		*fp = NULL;

	char		*p;
	char const	*extra = "";
	uint8_t		unlang_indent, module_indent;
	va_list		aq;

	char const	*fmt_location = "";
	char const	*fmt_prefix = "";
	char const	*fmt_module = "";
	char const	*fmt_exp = "";

	fr_log_t	*log_dst = uctx;
	TALLOC_CTX	*pool;

	/*
	 *	No output means no output.
	 */
	if (!log_dst) return;
	if (!log_rdebug_enabled(lvl, request)) return;

	/*
	 *	Allocate a thread local, 4k pool so we don't
	 *      need to keep allocating memory on the heap.
	 */
	pool = fr_vlog_request_pool;
	if (!pool) {
		pool = talloc_pool(NULL, 4096);
		if (!pool) {
			fr_perror("Failed allocating memory for vlog_request_pool");
			return;
		}
		fr_atexit_thread_local(fr_vlog_request_pool, _fr_vlog_request_pool_free, pool);
	}

	filename = log_dst->file;

	/*
	 *	Debug messages get treated specially.
	 */
	if ((type & L_DBG) != 0) {
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
		case L_DST_FUNC:
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
		goto print_fmt;
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
			if (fr_mkdir(NULL, exp, -1, S_IRWXU, NULL, NULL) < 0) {
				ERROR("Failed creating %s: %s", exp, fr_syserror(errno));
				talloc_free(exp);
				return;
			}
			*p = FR_DIR_SEP;
		}

		fp = fopen(exp, "a");
		talloc_free(exp);
	}

print_fmt:
	/*
	 *	Request prefix i.e.
	 *
	 *	(0) <fmt>
	 */
	if (request->name) {
		if ((request->seq_start == 0) || (request->number == request->seq_start)) {
			fmt_prefix = talloc_typed_asprintf(pool, "(%s)  ", request->name);
		} else {
			fmt_prefix = talloc_typed_asprintf(pool, "(%s,%" PRIu64 ")  ",
							   request->name, request->seq_start);
		}
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
	 *	test -     <fmt>
	 */
	if (request->module) {
		fmt_module = talloc_typed_asprintf(pool, "%s - %.*s", request->module, module_indent, spaces);
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
	fmt_exp = fr_vasprintf(pool, fmt, aq);
	va_end(aq);

	/*
	 *	Logging to a file descriptor
	 */
	if (fp) {
		char time_buff[64];	/* The current timestamp */

		time_t timeval;
		timeval = time(NULL);

#if 0
		fmt_location = talloc_typed_asprintf(pool, "%s[%i]: ", file, line);
#endif

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

		fprintf(fp,
			"%s"		/* location */
			"%s"		/* prefix */
			"%s : "		/* time */
			"%s"		/* facility */
			"%.*s"		/* indent */
			"%s"		/* module */
			"%s"		/* message */
			"\n",
			fmt_location,
			fmt_prefix,
			time_buff,
			fr_table_str_by_value(fr_log_levels, type, ""),
			unlang_indent, spaces,
			fmt_module,
			fmt_exp);
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

	log_always(log_dst, type, file, line,
		   "%s"			/* prefix */
		   "%.*s"		/* indent */
		   "%s"			/* module */
		   "%s"			/* extra */
		   "%s",		/* message */
		   fmt_prefix,
		   unlang_indent, spaces,
		   fmt_module,
		   extra,
		   fmt_exp);

finish:
	talloc_free_children(pool);
}

/** Add a module failure message fr_pair_t to the request
 *
 * @param[in] request	The current request.
 * @param[in] fmt	with printf style substitution tokens.
 * @param[in] ap	Substitution arguments.
 */
void vlog_module_failure_msg(request_t *request, char const *fmt, va_list ap)
{
	char		*p;
	fr_pair_t	*vp;
	va_list		aq;

	if (!fmt || !request || !request->packet) return;

	fr_assert(attr_module_failure_message);

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
	p = fr_vasprintf(request, fmt, aq);
	va_end(aq);

	MEM(pair_prepend_request(&vp, attr_module_failure_message) >= 0);
	if (request->module && (request->module[0] != '\0')) {
		fr_pair_value_aprintf(vp, "%s: %s", request->module, p);
	} else {
		fr_pair_value_strdup(vp, p, false);
	}

	talloc_free(p);
}

/** Add a module failure message fr_pair_tE to the request
 *
 * @param[in] request	The current request.
 * @param[in] fmt	with printf style substitution tokens.
 * @param[in] ...	Substitution arguments.
 */
void log_module_failure_msg(request_t *request, char const *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vlog_module_failure_msg(request, fmt, ap);
	va_end(ap);
}

/** Martial variadic log arguments into a va_list and pass to normal logging functions
 *
 * @see log_request_error for more details.
 *
 * @param[in] type	the log category.
 * @param[in] lvl	of debugging this message should be logged at.
 * @param[in] request	The current request.
 * @param[in] file	src file the log message was generated in.
 * @param[in] line	number the log message was generated on.
 * @param[in] fmt	with printf style substitution tokens.
 * @param[in] ...	Substitution arguments.
 */
void log_request(fr_log_type_t type, fr_log_lvl_t lvl, request_t *request,
		 char const *file, int line, char const *fmt, ...)
{
	va_list		ap;
	log_dst_t	*dst_p;

	if (!request->log.dst) return;

	va_start(ap, fmt);
	for (dst_p = request->log.dst; dst_p; dst_p = dst_p->next) {
		dst_p->func(type, lvl, request, file, line, fmt, ap, dst_p->uctx);
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
 * @param[in] file	src file the log message was generated in.
 * @param[in] line	number the log message was generated on.
 * @param[in] fmt	with printf style substitution tokens.
 * @param[in] ...	Substitution arguments.
 */
void log_request_error(fr_log_type_t type, fr_log_lvl_t lvl, request_t *request,
		       char const *file, int line, char const *fmt, ...)
{
	va_list		ap;
	log_dst_t	*dst_p;

	if (!request->log.dst) return;

	va_start(ap, fmt);
	for (dst_p = request->log.dst; dst_p; dst_p = dst_p->next) {
		dst_p->func(type, lvl, request, file, line, fmt, ap, dst_p->uctx);
	}
	if ((type == L_ERR) || (type == L_DBG_ERR) || (type == L_DBG_ERR_REQ)) {
		vlog_module_failure_msg(request, fmt, ap);
	}

	va_end(ap);
}

/** Drain any outstanding messages from the fr_strerror buffers
 *
 * This function drains any messages from fr_strerror buffer adding a prefix (fmt)
 * to the first message.
 *
 * @param[in] type	the log category.
 * @param[in] lvl	of debugging this message should be logged at.
 * @param[in] request	The current request.
 * @param[in] file	src file the log message was generated in.
 * @param[in] line	number the log message was generated on.
 * @param[in] fmt	with printf style substitution tokens.
 * @param[in] ...	Substitution arguments.
 */
void log_request_perror(fr_log_type_t type, fr_log_lvl_t lvl, request_t *request,
			char const *file, int line, char const *fmt, ...)
{
	char const *error;

	if (!request->log.dst) return;

	/*
	 *	No strerror gets us identical behaviour to log_request_error
	 */
	error = fr_strerror_pop();
	if (!error) {
		va_list		ap;
		log_dst_t	*dst_p;

		if (!fmt) return;	/* NOOP */

		va_start(ap, fmt);
		for (dst_p = request->log.dst; dst_p; dst_p = dst_p->next) {
			dst_p->func(type, lvl, request, file, line, fmt, ap, dst_p->uctx);
		}
		if ((type == L_ERR) || (type == L_DBG_ERR) || (type == L_DBG_ERR_REQ)) {
			vlog_module_failure_msg(request, fmt, ap);
		}
		va_end(ap);

		return;			/* DONE */
	}

	/*
	 *	Concatenate fmt with fr_strerror()
	 */
	if (fmt) {
		va_list ap;
		char *tmp;

		va_start(ap, fmt);
		tmp = fr_vasprintf(request, fmt, ap);
		va_end(ap);

		if (!tmp) return;

		log_request_error(type, lvl, request, file, line, "%s: %s", tmp, error);
		talloc_free(tmp);
	} else {
		log_request_error(type, lvl, request, file, line, "%s", error);
	}

	/*
	 *	Only the first message gets the prefix
	 */
	while ((error = fr_strerror_pop())) log_request_error(type, lvl, request, file, line, "%s", error);
}

/** Cleanup the memory pool used by the OID sbuff
 *
 */
static void _fr_log_request_oid_buff_free(void *arg)
{
	talloc_free(arg);
}

/** Allocate an extensible sbuff for printing OID strings
 *
 */
static inline CC_HINT(always_inline) fr_sbuff_t *log_request_oid_buff(void)
{
	fr_sbuff_t		*sbuff;
	fr_sbuff_uctx_talloc_t	*tctx;

	sbuff = fr_log_request_oid_buff;
	if (unlikely(!sbuff)) {
		sbuff = talloc(NULL, fr_sbuff_t);
		if (!sbuff) {
			fr_perror("Failed allocating memory for fr_log_request_oid_buff");
			return NULL;
		}
		tctx = talloc(sbuff, fr_sbuff_uctx_talloc_t);
		if (!tctx) {
			fr_perror("Failed allocating memory for fr_sbuff_uctx_talloc_t");
			talloc_free(sbuff);
			return NULL;
		}

		fr_sbuff_init_talloc(sbuff, sbuff, tctx, 1024, (FR_DICT_ATTR_MAX_NAME_LEN + 1) * FR_DICT_MAX_TLV_STACK);

		fr_atexit_thread_local(fr_log_request_oid_buff, _fr_log_request_oid_buff_free, sbuff);
	} else {
		fr_sbuff_set(sbuff, fr_sbuff_start(sbuff));	/* Reset position */
	}

	return sbuff;
}

/** Print a #fr_pair_t.
 *
 * @param[in] lvl	Debug lvl (1-4).
 * @param[in] request	to read logging params from.
 * @param[in] parent	of pair to print, may be NULL.
 * @param[in] vp	to print.
 * @param[in] prefix	(optional).
 */
void log_request_pair(fr_log_lvl_t lvl, request_t *request,
		      fr_pair_t const *parent, fr_pair_t const *vp, char const *prefix)
{
	fr_dict_attr_t const	*parent_da = NULL;
	fr_sbuff_t		*oid_buff;

	if (!request->log.dst) return;

	if (!log_rdebug_enabled(lvl, request)) return;

	PAIR_VERIFY(vp);

	oid_buff = log_request_oid_buff();

	if (parent && (parent->da->type != FR_TYPE_GROUP)) parent_da = parent->da;
	if (fr_dict_attr_oid_print(oid_buff, parent_da, vp->da, false) <= 0) return;

	/*
	 *	Recursively print grouped attributes.
	 */
	switch (vp->da->type) {
	case FR_TYPE_STRUCTURAL:
		RDEBUGX(lvl, "%s%pV {", prefix ? prefix : "",
			fr_box_strvalue_len(fr_sbuff_start(oid_buff), fr_sbuff_used(oid_buff)));
		log_request_pair_list(lvl, request, vp, &vp->vp_group, NULL);
		RDEBUGX(lvl, "}");
		break;

	case FR_TYPE_QUOTED:
		RDEBUGX(lvl, "%s%pV = \"%pV\"", prefix ? prefix : "",
			fr_box_strvalue_len(fr_sbuff_start(oid_buff), fr_sbuff_used(oid_buff)),
			&vp->data);
		break;
	default:
		RDEBUGX(lvl, "%s%pV = %pV", prefix ? prefix : "",
			fr_box_strvalue_len(fr_sbuff_start(oid_buff), fr_sbuff_used(oid_buff)),
			&vp->data);
		break;
	}
}

/** Print a #fr_pair_list_t
 *
 * @param[in] lvl	Debug lvl (1-4).
 * @param[in] request	to read logging params from.
 * @param[in] parent	of vps to print, may be NULL.
 * @param[in] vps	to print.
 * @param[in] prefix	(optional).
 */
void log_request_pair_list(fr_log_lvl_t lvl, request_t *request,
			   fr_pair_t const *parent, fr_pair_list_t const *vps, char const *prefix)
{
	fr_pair_list_t		*m_vp = UNCONST(fr_pair_list_t *, vps);
	fr_pair_t		*vp;

	if (fr_pair_list_empty(vps) || !request->log.dst) return;

	if (!log_rdebug_enabled(lvl, request)) return;

	RINDENT();
	for (vp = fr_pair_list_head(m_vp);
	     vp;
	     vp = fr_pair_list_next(m_vp, vp)) {
		PAIR_VERIFY(vp);

		log_request_pair(lvl, request, parent, vp, prefix);
	}
	REXDENT();
}

/** Print a list of protocol fr_pair_ts.
 *
 * @param[in] lvl	Debug lvl (1-4).
 * @param[in] request	to read logging params from.
 * @param[in] parent	of vps to print, may be NULL.
 * @param[in] vps	to print.
 * @param[in] prefix	(optional).
 */
void log_request_proto_pair_list(fr_log_lvl_t lvl, request_t *request,
				 fr_pair_t const *parent, fr_pair_list_t const *vps, char const *prefix)
{
	fr_pair_t		*vp;

	if (fr_pair_list_empty(vps) || !request->log.dst) return;

	if (!log_rdebug_enabled(lvl, request)) return;

	RINDENT();
	for (vp = fr_pair_list_head(vps);
	     vp;
	     vp = fr_pair_list_next(vps, vp)) {
		PAIR_VERIFY(vp);

		if (!fr_dict_attr_common_parent(fr_dict_root(request->dict), vp->da, true)) continue;

		log_request_pair(lvl, request, parent, vp, prefix);
	}
	REXDENT();
}

/** Write the string being parsed, and a marker showing where the parse error occurred
 *
 * @param[in] type		the log category.
 * @param[in] lvl		of debugging this message should be logged at.
 * @param[in] request		The current request.
 * @param[in] file		src file the log message was generated in.
 * @param[in] line		number the log message was generated on.
 * @param[in] str		Subject string we're printing a marker for.
 * @param[in] str_len		Subject string length.  Use SIZE_MAX for the
 *				length of the string.
 * @param[in] marker_idx	The position of the marker relative to the string.
 * @param[in] marker_fmt	What the parse error was.
 * @param[in] ...		Arguments for fmt string.
 */
void log_request_marker(fr_log_type_t type, fr_log_lvl_t lvl, request_t *request,
			char const *file, int line,
			char const *str, size_t str_len,
			ssize_t marker_idx, char const *marker_fmt, ...)
{
	char const		*ellipses = "";
	uint8_t			unlang_indent;
	uint8_t			module_indent;
	va_list			ap;
	char			*error;
	static char const	marker_spaces[] = "                                                            "; /* 60 */

	if (str_len == SIZE_MAX) str_len = strlen(str);

	if (marker_idx < 0) marker_idx = marker_idx * -1;

	if ((size_t)marker_idx >= sizeof(marker_spaces)) {
		size_t offset = (marker_idx - (sizeof(marker_spaces) - 1)) + (sizeof(marker_spaces) * 0.75);
		marker_idx -= offset;
		str += offset;
		str_len -= offset;

		ellipses = "... ";
	}

	/*
	 *  Don't want format markers being indented
	 */
	unlang_indent = request->log.unlang_indent;
	module_indent = request->log.module_indent;
	request->log.unlang_indent = 0;
	request->log.module_indent = 0;

	va_start(ap, marker_fmt);
	error = fr_vasprintf(request, marker_fmt, ap);
	va_end(ap);

	log_request(type, lvl, request, file, line, "%s%.*s", ellipses, (int)str_len, str);
	log_request(type, lvl, request, file, line, "%s%.*s^ %s", ellipses, (int) marker_idx, marker_spaces, error);
	talloc_free(error);

	request->log.unlang_indent = unlang_indent;
	request->log.module_indent = module_indent;
}

void log_request_hex(fr_log_type_t type, fr_log_lvl_t lvl, request_t *request,
		     char const *file, int line,
		     uint8_t const *data, size_t data_len)
{
	size_t i, j, len;
	char *p;
	char buffer[(0x10 * 3) + 1];

	for (i = 0; i < data_len; i += 0x10) {
		len = 0x10;
		if ((i + len) > data_len) len = data_len - i;

		for (p = buffer, j = 0; j < len; j++, p += 3) sprintf(p, "%02x ", data[i + j]);
		log_request(type, lvl, request, file, line, "%04x: %s", (int)i, buffer);
	}
}

/** Function to provide as the readable callback to the event loop
 *
 * Writes any data read from a file descriptor to the request log,
 * tries very hard not to chop lines in the middle, but will split
 * at 1024 byte boundaries if forced to.
 *
 * @param[in] el	UNUSED
 * @param[in] fd	UNUSED
 * @param[in] flags	UNUSED
 * @param[in] uctx	Pointer to a log_fd_event_ctx_t
 */
void log_request_fd_event(UNUSED fr_event_list_t *el, int fd, UNUSED int flags, void *uctx)
{
	char			buffer[1024];
	log_fd_event_ctx_t	*log_info = uctx;
	request_t		*request = log_info->request;
	fr_sbuff_t		sbuff;
	fr_sbuff_marker_t	m_start, m_end;

	fr_sbuff_term_t const 	line_endings = FR_SBUFF_TERMS(L("\n"), L("\r"));

	if (!RDEBUG_ENABLEDX(log_info->lvl)) {
		while (read(fd, buffer, sizeof(buffer) > 0));
		return;
	}

	fr_sbuff_init(&sbuff, buffer, sizeof(buffer));
	fr_sbuff_marker(&m_start, &sbuff);
	fr_sbuff_marker(&m_end, &sbuff);

#ifndef NDEBUG
	memset(buffer, 0x42, sizeof(buffer));
#endif

	for (;;) {
		ssize_t		slen;

		slen = read(fd, fr_sbuff_current(&m_end), fr_sbuff_remaining(&m_end));
		if (slen < 0) {
			if (errno == EINTR) continue;

			/*
			 *	This can happen if the I/O handler is
			 *	manually called to clear out any pending
			 *	data, and we're using a nonblocking FD.
			 *
			 *	This can happen with the exec code if
			 *	the EVFILT_PROC event gets passed before
			 *	the EVFILT_READ event.
			 */
			if (errno == EWOULDBLOCK) slen = 0;
		}
		if ((slen < 0) && (errno == EINTR)) continue;

		if (slen > 0) fr_sbuff_advance(&m_end, slen);

		while (fr_sbuff_ahead(&m_end) > 0) {
			fr_sbuff_adv_until(&sbuff, fr_sbuff_ahead(&m_end), &line_endings, '\0');

			/*
			 *	Incomplete line, try and read the rest.
			 */
			if ((slen > 0) && (fr_sbuff_used(&m_start) > 0) &&
			    !fr_sbuff_is_terminal(&sbuff, &line_endings)) {
				break;
			}

			log_request(log_info->type, log_info->lvl, log_info->request,
				    __FILE__, __LINE__,
				    "%s%s%pV",
				    log_info->prefix ? log_info->prefix : "",
				    log_info->prefix ? " - " : "",
				    fr_box_strvalue_len(fr_sbuff_current(&m_start),
							fr_sbuff_behind(&m_start)));

			fr_sbuff_advance(&sbuff, 1);	/* Skip the whitespace */
			fr_sbuff_set(&m_start, &sbuff);
		}

		/*
		 *	Error or done
		 */
		if (slen <= 0) break;

		/*
		 *	Clear out the existing data
		 */
		fr_sbuff_shift(&sbuff, fr_sbuff_used(&m_start));
	};
}

/** Log a fatal error, then exit
 *
 */
void log_fatal(fr_log_t const *log, char const *file, int line, char const *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fr_vlog(log, L_ERR, file, line, fmt, ap);
	va_end(ap);

	fr_exit_now(EXIT_FAILURE);
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

	ret = fr_log_init_legacy(log, daemonize);
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
