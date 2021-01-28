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
 * @copyright 2003,2006 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/log.h>
#include <freeradius-devel/util/print.h>
#include <freeradius-devel/util/sbuff.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/util/thread_local.h>
#include <freeradius-devel/util/value.h>

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

static _Thread_local TALLOC_CTX *fr_log_pool;

static uint32_t location_indent = 30;

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
 * @param text Where to write the canonicalized version of fmt (the error text).
 * @param ctx to allocate the spaces and text buffers in.
 * @param slen of error marker. Expects negative integer value, as returned by parse functions.
 * @param fmt to canonicalize.
 */
void fr_canonicalize_error(TALLOC_CTX *ctx, char **sp, char **text, ssize_t slen, char const *fmt)
{
	size_t offset, prefix, suffix;
	char *spaces, *p;
	char const *start;
	char *value;
	size_t inlen;

	offset = -slen;

	inlen = strlen(fmt);
	start = fmt;
	prefix = suffix = 0;

	/*
	 *	Catch bad callers.
	 */
	if (offset > inlen) {
		*sp = NULL;
		*text = NULL;
		return;
	}

	/*
	 *	Too many characters before the inflection point.  Skip
	 *	leading text until we have only 45 characters before it.
	 */
	if (offset > 30) {
		size_t skip = offset - 30;

		start += skip;
		inlen -= skip;
		offset -= skip;
		prefix = 4;
	}

	/*
	 *	Too many characters after the inflection point,
	 *	truncate it to 30 characters after the inflection
	 *	point.
	 */
	if (inlen > (offset + 30)) {
		inlen = offset + 30;
		suffix = 4;
	}

	/*
	 *	Allocate an array to hold just the text we need.
	 */
	value = talloc_array(ctx, char, prefix + inlen + 1 + suffix);
	if (prefix) {
		memcpy(value, "... ", 4);
	}
	memcpy(value + prefix, start, inlen);
	if (suffix) {
		memcpy(value + prefix + inlen, "...", 3);
		value[prefix + inlen + 3] = '\0';
	}
	value[prefix + inlen + suffix] = '\0';

	/*
	 *	Smash tabs to spaces for the input string.
	 */
	for (p = value; *p != '\0'; p++) {
		if (*p == '\t') *p = ' ';
	}

	/*
	 *	Allocate the spaces array
	 */
	spaces = talloc_array(ctx, char, prefix + offset + 1);
	memset(spaces, ' ', prefix + offset);
	spaces[prefix + offset] = '\0';

	*sp = spaces;
	*text = value;
}

/** Maps log categories to message prefixes
 */
fr_table_num_ordered_t const fr_log_levels[] = {
	{ L("Debug : "),		L_DBG		},
	{ L("Info  : "),		L_INFO		},
	{ L("Warn  : "),		L_WARN		},
	{ L("Error : "),		L_ERR		},
	{ L("Auth  : "),		L_AUTH		},
	{ L("WARN  : "),		L_DBG_WARN	},
	{ L("ERROR : "),		L_DBG_ERR	},
	{ L("WARN  : "),		L_DBG_WARN_REQ	},
	{ L("ERROR : "),		L_DBG_ERR_REQ	}
};
size_t fr_log_levels_len = NUM_ELEMENTS(fr_log_levels);

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
static fr_table_num_ordered_t const colours[] = {
	{ L(VTC_BOLD),			L_INFO		},
	{ L(VTC_RED),			L_ERR		},
	{ L(VTC_BOLD VTC_YELLOW),	L_WARN		},
	{ L(VTC_BOLD VTC_RED),		L_DBG_ERR	},
	{ L(VTC_BOLD VTC_YELLOW),	L_DBG_WARN	},
	{ L(VTC_BOLD VTC_RED),		L_DBG_ERR_REQ	},
	{ L(VTC_BOLD VTC_YELLOW),	L_DBG_WARN_REQ	},
};
static size_t colours_len = NUM_ELEMENTS(colours);


bool log_dates_utc = false;

fr_log_t default_log = {
	.colourise = false,		//!< Will be set later. Should be off before we do terminal detection.
	.fd = STDOUT_FILENO,
	.dst = L_DST_STDOUT,
	.file = NULL,
	.timestamp = L_TIMESTAMP_AUTO
};

/** Cleanup the memory pool used by vlog_request
 *
 */
static void _fr_log_pool_free(void *arg)
{
	talloc_free(arg);
	fr_log_pool = NULL;
}

/** talloc ctx to use when composing log messages
 *
 * Functions must ensure that they allocate a new ctx from the one returned
 * here, and that this ctx is freed before the function returns.
 *
 * @return talloc pool to use for scratch space.
 */
TALLOC_CTX *fr_log_pool_init(void)
{
	TALLOC_CTX	*pool;

	pool = fr_log_pool;
	if (unlikely(!pool)) {
		pool = talloc_pool(NULL, 16384);
		if (!pool) {
			fr_perror("Failed allocating memory for vlog_request_pool");
			return NULL;
		}
		fr_thread_local_set_destructor(fr_log_pool, _fr_log_pool_free, pool);
	}

	return pool;
}

/** Send a server log message to its destination
 *
 * @param[in] log	destination.
 * @param[in] type	of log message.
 * @param[in] file	src file the log message was generated in.
 * @param[in] line	number the log message was generated on.
 * @param[in] fmt	with printf style substitution tokens.
 * @param[in] ap	Substitution arguments.
 */
int fr_vlog(fr_log_t const *log, fr_log_type_t type, char const *file, int line, char const *fmt, va_list ap)
{
	int		colourise = log->colourise;
	char		*buffer;
	TALLOC_CTX	*pool, *thread_log_pool;
	int		ret = 0;
	char const	*fmt_colour = "";
	char const	*fmt_location = "";
	char		fmt_time[50];
	char const	*fmt_facility = "";
	char const	*fmt_type = "";
	char		*fmt_msg;

	static char const *spaces = "                                    ";	/* 40 */

	fmt_time[0] = '\0';

	/*
	 *	If we don't want any messages, then
	 *	throw them away.
	 */
	if (log->dst == L_DST_NULL) return 0;

	thread_log_pool = fr_log_pool_init();
	pool = talloc_new(thread_log_pool);	/* Track our local allocations */

	/*
	 *	Set colourisation
	 */
	if (colourise) {
		fmt_colour = fr_table_str_by_value(colours, type, NULL);
		if (!fmt_colour) colourise = false;
	}

	/*
	 *	Print src file/line
	 */
	if (log->line_number) {
		size_t	len;
		int	pad = 0;
		char	*str;

		str = talloc_asprintf(pool, "%s:%i", file, line);
		len = talloc_array_length(str) - 1;

		/*
		 *	Only increase the indent
		 */
		if (len > location_indent) {
			location_indent = len;
		} else {
			pad = location_indent - len;
		}

		fmt_location = talloc_asprintf_append_buffer(str, "%.*s : ", pad, spaces);
	}
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
		FALL_THROUGH;

	case L_TIMESTAMP_ON:
	{
		time_t timeval;
		size_t len;

		timeval = time(NULL);
#ifdef HAVE_GMTIME_R
		if (log->dates_utc) {
			struct tm utc;
			gmtime_r(&timeval, &utc);
			ASCTIME_R(&utc, fmt_time, sizeof(fmt_time));
		} else
#endif
		{
			CTIME_R(&timeval, fmt_time, sizeof(fmt_time));
		}

		/*
		 *	ctime adds '\n'
		 */
		len = strlen(fmt_time);
		if ((len > 0) && (fmt_time[len - 1] == '\n')) fmt_time[len - 1] = '\0';
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
		if (!log->colourise && log->print_level) fmt_facility = fr_table_str_by_value(fr_log_levels, type, ": ");

		/*
		 *	Add an additional prefix to highlight that this is a bad message
		 *	the user should pay attention to.
		 */
		switch (type) {
		case L_DBG_WARN:
		case L_DBG_ERR:
			fmt_type = fr_table_str_by_value(fr_log_levels, type, NULL);
			break;

		default:
			break;
		}
	}

	/*
	 *	Sanitize output.
	 *
	 *	Most strings should be escaped before they get here.
	 */
	{
		char	*p, *end;

		p = fmt_msg = fr_vasprintf(pool, fmt, ap);
		end = p + talloc_array_length(fmt_msg) - 1;

		/*
		 *	Filter out control chars and non UTF8 chars
		 */
		for (p = fmt_msg; p < end; p++) {
			int clen;

			switch (*p) {
			case '\r':
			case '\n':
				*p = ' ';
				break;

			case '\t':
				continue;

			default:
				clen = fr_utf8_char((uint8_t *)p, -1);
				if (!clen) {
					*p = '?';
					continue;
				}
				p += (clen - 1);
				break;
			}
		}
	}

	switch (log->dst) {

#ifdef HAVE_SYSLOG_H
	case L_DST_SYSLOG:
	{
		int syslog_priority;

		switch (type) {
		case L_DBG:
		case L_DBG_INFO:
		case L_DBG_WARN:
		case L_DBG_ERR:
		case L_DBG_ERR_REQ:
		case L_DBG_WARN_REQ:
			syslog_priority= LOG_DEBUG;
			break;

		case L_INFO:
			syslog_priority = LOG_INFO;
			break;

		case L_WARN:
			syslog_priority = LOG_WARNING;
			break;

		case L_ERR:
			syslog_priority = LOG_ERR;
			break;

		case L_AUTH:
			syslog_priority = LOG_AUTH | LOG_INFO;
			break;
		}
		syslog(syslog_priority,
		       "%s"	/* time */
		       "%s"	/* time sep */
		       "%s",	/* message */
		       fmt_time,
		       fmt_time[0] ? ": " : "",
		       fmt_msg);
	}
		break;
#endif

	case L_DST_FILES:
	case L_DST_STDOUT:
	case L_DST_STDERR:
	{
		size_t len, wrote;

		buffer = talloc_asprintf(pool,
					 "%s"	/* colourise */
					 "%s"	/* location */
					 "%s"	/* time */
					 "%s"	/* time sep */
					 "%s"	/* facility */
					 "%s"	/* message type */
					 "%s"	/* message */
					 "%s"	/* colourise reset */
					 "\n",
					 colourise ? fmt_colour : "",
					 fmt_location,
				 	 fmt_time,
				 	 fmt_time[0] ? ": " : "",
				 	 fmt_facility,
				 	 fmt_type,
				 	 fmt_msg,
				 	 colourise ? VTC_RESET : "");

		len = talloc_array_length(buffer) - 1;
		wrote = write(log->fd, buffer, len);
		if (wrote < len) ret = -1;
	}
		break;

	default:
	case L_DST_NULL:	/* should have been caught above */
		break;
	}

	talloc_free(pool);	/* clears all temporary allocations */

	return ret;
}

/** Send a server log message to its destination
 *
 * @param log	destination.
 * @param type	of log message.
 * @param file	where the log message originated
 * @param line	where the log message originated
 * @param fmt	with printf style substitution tokens.
 * @param ...	Substitution arguments.
 */
int fr_log(fr_log_t const *log, fr_log_type_t type, char const *file, int line, char const *fmt, ...)
{
	va_list ap;
	int ret = 0;

	/*
	 *	Non-debug message, or debugging is enabled.  Log it.
	 */
	if (!(((type & L_DBG) == 0) || (fr_debug_lvl > 0))) return 0;

	va_start(ap, fmt);
	ret = fr_vlog(log, type, file, line, fmt, ap);
	va_end(ap);

	return ret;
}

/** Drain any outstanding messages from the fr_strerror buffers
 *
 * This function drains any messages from fr_strerror buffer prefixing
 * the first message with fmt + args.
 *
 * If a prefix is specified in rules, this is prepended to all lines
 * logged.  The prefix is useful for adding context, i.e. configuration
 * file and line number information.
 *
 * @param[in] log	destination.
 * @param[in] type	of log message.
 * @param[in] file	src file the log message was generated in.
 * @param[in] line	number the log message was generated on.
 * @param[in] f_rules	for printing multiline errors.
 * @param[in] fmt	with printf style substitution tokens.
 * @param[in] ap	Substitution arguments.
 */
int fr_vlog_perror(fr_log_t const *log, fr_log_type_t type, char const *file, int line,
		   fr_log_perror_format_t const *f_rules, char const *fmt, va_list ap)
{
	char const				*error;
	int					ret;
	static fr_log_perror_format_t		default_f_rules;

	TALLOC_CTX			        *thread_log_pool;
	fr_sbuff_marker_t			prefix_m;

	fr_sbuff_t				sbuff;
	fr_sbuff_uctx_talloc_t			tctx;

	/*
	 *	Non-debug message, or debugging is enabled.  Log it.
	 */
	if (!(((type & L_DBG) == 0) || (fr_debug_lvl > 0))) return 0;

	if (!f_rules) f_rules = &default_f_rules;

	thread_log_pool = fr_log_pool_init();

	/*
	 *	Setup the aggregation buffer
	 */
	fr_sbuff_init_talloc(thread_log_pool, &sbuff, &tctx, 1024, 16384);

	/*
	 *	Add the prefix for the first line
	 */
	if (f_rules->first_prefix) fr_sbuff_in_strcpy(&sbuff, f_rules->first_prefix);

	/*
	 *	Add the (optional) message, and/or (optional) error
	 *	with the error_sep.
	 *	i.e. <msg>: <error>
	 */
	error = fr_strerror_pop();
	if (error) {
		if (fmt) {
			va_list aq;

			va_copy(aq, ap);
			fr_sbuff_in_vsprintf(&sbuff, fmt, aq);
			va_end(aq);

			fr_sbuff_in_strcpy(&sbuff, ": ");
			fr_sbuff_in_strcpy(&sbuff, error);	/* may not be talloced with const */
			error = fr_sbuff_start(&sbuff);
		}
	/*
	 *	No error, just print the fmt string
	 */
	} else {
		va_list aq;

		if (!fmt) return 0;	/* NOOP */

		va_copy(aq, ap);
		fr_sbuff_in_vsprintf(&sbuff, fmt, ap);
		va_end(aq);

		error = fr_sbuff_start(&sbuff);
	}

	/*
	 *	Log the first line
	 */
	ret = fr_log(log, type, file, line, "%s", error);
	if (ret < 0) {
	error:
		talloc_free(sbuff.buff);
		return ret;
	}

	fr_sbuff_set_to_start(&sbuff);
	if (f_rules->subsq_prefix) {
		fr_sbuff_in_strcpy(&sbuff, f_rules->subsq_prefix);
		fr_sbuff_marker(&prefix_m, &sbuff);
	}

	/*
	 *	Print out additional error lines
	 */
	while ((error = fr_strerror_pop())) {
		if (f_rules->subsq_prefix) {
			fr_sbuff_set(&sbuff, &prefix_m);
			fr_sbuff_in_strcpy(&sbuff, error);	/* may not be talloced with const */
			error = fr_sbuff_start(&sbuff);
		}

		ret = fr_log(log, type, file, line, "%s", error);
		if (ret < 0) goto error;
	}

	talloc_free(sbuff.buff);

	return 0;
}

/** Drain any outstanding messages from the fr_strerror buffers
 *
 * This function drains any messages from fr_strerror buffer adding a prefix (fmt)
 * to the first message.
 *
 * @param[in] log	destination.
 * @param[in] type	of log message.
 * @param[in] file	src file the log message was generated in.
 * @param[in] line	number the log message was generated on.
 * @param[in] rules	for printing multiline errors.
 * @param[in] fmt	with printf style substitution tokens.
 * @param[in] ...	Substitution arguments.
 */
int fr_log_perror(fr_log_t const *log, fr_log_type_t type, char const *file, int line,
		  fr_log_perror_format_t const *rules, char const *fmt, ...)
{
	int	ret;
	va_list ap;

	va_start(ap, fmt);
	ret = fr_vlog_perror(log, type, file, line, rules, fmt, ap);
	va_end(ap);

	return ret;
}

DIAG_OFF(format-nonliteral)
/** Print out an error marker
 *
 * @param[in] log		destination.
 * @param[in] type		of log message.
 * @param[in] file		src file the log message was generated in.
 * @param[in] line		number the log message was generated on.
 * @param[in] str		Subject string we're printing a marker for.
 * @param[in] str_len		Subject string length.  Use SIZE_MAX for the
 *				length of the string.
 * @param[in] marker_idx	Where to place the marker.  May be negative.
 * @param[in] marker		text to print at marker_idx.
 * @param[in] line_prefix_fmt	Prefix to add to the marker messages.
 * @param[in] ...		Arguments for line_prefix_fmt.
 */
void fr_log_marker(fr_log_t const *log, fr_log_type_t type, char const *file, int line,
		   char const *str, size_t str_len,
		   ssize_t marker_idx, char const *marker, char const *line_prefix_fmt, ...)
{
	char const		*ellipses = "";
	va_list			ap;
	TALLOC_CTX		*thread_log_pool = fr_log_pool_init();
	char			*line_prefix = NULL;
	static char const	marker_spaces[] = "                                                            "; /* 60 */

	if (str_len == SIZE_MAX) str_len = strlen(str);

	if (marker_idx < 0) marker_idx = marker_idx * -1;

	if ((size_t)marker_idx >= sizeof(marker_spaces)) {
		size_t offset = (marker_idx - (sizeof(marker_spaces) - 1)) + (sizeof(marker_spaces) * 0.75);
		marker_idx -= offset;

		if (offset > str_len) offset = str_len;
		str += offset;
		str_len -= offset;

		ellipses = "... ";
	}

	if (line_prefix_fmt) {
		va_start(ap, line_prefix_fmt);
		line_prefix = fr_vasprintf(thread_log_pool, line_prefix_fmt, ap);
		va_end(ap);
	}

	fr_log(log, type, file, line, "%s%s%.*s",
	       line_prefix ? line_prefix : "", ellipses, (int)str_len, str);
	fr_log(log, type, file, line, "%s%s%.*s^ %s",
	       line_prefix ? line_prefix : "", ellipses, (int)marker_idx, marker_spaces, marker);

	if (line_prefix_fmt) talloc_free(line_prefix);
}

/** Print out hex block
 *
 * @param[in] log		destination.
 * @param[in] type		of log message.
 * @param[in] file		src file the log message was generated in.
 * @param[in] line		number the log message was generated on.
 * @param[in] data		to print.
 * @param[in] data_len		length of data.
 * @param[in] line_prefix_fmt	Prefix to add to the marker messages.
 * @param[in] ...		Arguments for line_prefix_fmt.
 */
void fr_log_hex(fr_log_t const *log, fr_log_type_t type, char const *file, int line,
		uint8_t const *data, size_t data_len, char const *line_prefix_fmt, ...)
{
	size_t		i, j, len;
	char		*p;
	char		buffer[(0x10 * 3) + 1];
	TALLOC_CTX	*thread_log_pool = fr_log_pool_init();
	char		*line_prefix = NULL;

	if (line_prefix_fmt) {
		va_list ap;

		va_start(ap, line_prefix_fmt);
		line_prefix = fr_vasprintf(thread_log_pool, line_prefix_fmt, ap);
		va_end(ap);
	}

	for (i = 0; i < data_len; i += 0x10) {
		len = 0x10;
		if ((i + len) > data_len) len = data_len - i;

		for (p = buffer, j = 0; j < len; j++, p += 3) sprintf(p, "%02x ", data[i + j]);

		if (line_prefix_fmt) {
			fr_log(log, type, file, line, "%s%04x: %s",
			       line_prefix, (int)i, buffer);
		} else {
			fr_log(log, type, file, line, "%04x: %s", (int)i, buffer);
		}
	}

	if (line_prefix_fmt) talloc_free(line_prefix);
}

/** Print out hex block
 *
 * @param[in] log		destination.
 * @param[in] type		of log message.
 * @param[in] file		src file the log message was generated in.
 * @param[in] line		number the log message was generated on.
 * @param[in] data		to print.
 * @param[in] data_len		length of data.
 * @param[in] marker_idx	Where to place the marker.  May be negative.
 * @param[in] marker		text to print at marker_idx.
 * @param[in] line_prefix_fmt	Prefix to add to the marker messages.
 * @param[in] ...		Arguments for line_prefix_fmt.
 */
void fr_log_hex_marker(fr_log_t const *log, fr_log_type_t type, char const *file, int line,
		       uint8_t const *data, size_t data_len,
		       ssize_t marker_idx, char const *marker, char const *line_prefix_fmt, ...)
{
	size_t		i, j, len;
	char		*p;
	char		buffer[(0x10 * 3) + 1];
	TALLOC_CTX	*thread_log_pool = fr_log_pool_init();

	char		*line_prefix = NULL;
	static char	spaces[3 * 0x10];	/* Bytes per line */

	if (!*spaces) memset(spaces, ' ', sizeof(spaces) - 1);	/* Leave a \0 */

	if (marker_idx < 0) marker_idx = marker_idx * -1;
	if (line_prefix_fmt) {
		va_list ap;

		va_start(ap, line_prefix_fmt);
		line_prefix = fr_vasprintf(thread_log_pool, line_prefix_fmt, ap);
		va_end(ap);
	}

	for (i = 0; i < data_len; i += 0x10) {
		len = 0x10;
		if ((i + len) > data_len) len = data_len - i;

		for (p = buffer, j = 0; j < len; j++, p += 3) sprintf(p, "%02x ", data[i + j]);

		if (line_prefix_fmt) {
			fr_log(log, type, file, line, "%s%04x: %s",
			       line_prefix, (int)i, buffer);
		} else {
			fr_log(log, type, file, line, "%04x: %s", (int)i, buffer);
		}

		/*
		 *	Marker is on this line
		 */
		if (((size_t)marker_idx >= i) && ((size_t)marker_idx < (i + 0x10))) {
			if (line_prefix_fmt) {
				fr_log(log, type, file, line, "%s      %.*s^ %s", line_prefix,
				       (int)((marker_idx - i) * 3), spaces, marker);
			} else {
				fr_log(log, type, file, line, "      %.*s^ %s",
				       (int)((marker_idx - i) * 3), spaces, marker);
			}
		}
	}

	if (line_prefix_fmt) talloc_free(line_prefix);
}
DIAG_ON(format-nonliteral)

static int stderr_fd = -1;		//!< The original unmolested stderr file descriptor
static int stdout_fd = -1;		//!< The original unmolested stdout file descriptor
bool fr_log_rate_limit = true;		//!< Whether repeated log entries should be rate limited

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

	fr_log_rate_limit = daemonize;

	/*
	 *	If we're running in foreground mode, save STDIN /
	 *	STDERR as higher FDs, which won't get used by anyone
	 *	else.  When we fork/exec a program, its STD FDs will
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
		log->print_level = false;

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
