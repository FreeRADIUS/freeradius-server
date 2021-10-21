#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */
/** libfreeradius logging functions
 *
 * @file src/lib/util/log.h
 *
 * @copyright 2016 The FreeRADIUS server project
 */
RCSIDH(util_log_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/build.h>
#include <freeradius-devel/missing.h>
#include <freeradius-devel/util/event.h>
#include <freeradius-devel/util/fopencookie.h>
#include <freeradius-devel/util/table.h>
#include <freeradius-devel/util/talloc.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern FILE	*fr_log_fp;

/*
 *	Error functions.
 */
void		fr_canonicalize_error(TALLOC_CTX *ctx, char **spaces, char **text, ssize_t slen, char const *fmt);

extern int	fr_debug_lvl;	/* 0 = no debugging information */
extern bool	log_dates_utc;

extern fr_table_num_ordered_t const fr_log_levels[];
extern size_t fr_log_levels_len;

typedef enum {
	L_INFO = 3,				//!< Informational message.
	L_ERR = 4,				//!< Error message.
	L_WARN = 5,				//!< Warning.
	L_AUTH = 6,				//!< Authentication logs
	L_DBG = 16,				//!< Only displayed when debugging is enabled.
	L_DBG_INFO = 17,			//!< Info only displayed when debugging is enabled.
	L_DBG_WARN = 18,			//!< Warning only displayed when debugging is enabled.
	L_DBG_ERR = 19,				//!< Error only displayed when debugging is enabled.
	L_DBG_WARN_REQ = 20,			//!< Less severe warning only displayed when debugging is enabled.
	L_DBG_ERR_REQ = 21			//!< Less severe error only displayed when debugging is enabled.
} fr_log_type_t;

typedef enum {
	L_DBG_LVL_DISABLE = -1,			//!< Don't print messages.
	L_DBG_LVL_OFF = 0,			//!< No debug messages.
	L_DBG_LVL_1,				//!< Highest priority debug messages (-x).
	L_DBG_LVL_2,				//!< 2nd highest priority debug messages (-xx | -X).
	L_DBG_LVL_3,				//!< 3rd highest priority debug messages (-xxx | -Xx).
	L_DBG_LVL_4,				//!< 4th highest priority debug messages (-xxxx | -Xxx).
	L_DBG_LVL_MAX				//!< Lowest priority debug messages (-xxxxx | -Xxxx).
} fr_log_lvl_t;

typedef enum {
	L_DST_STDOUT = 0,			//!< Log to stdout.
	L_DST_FILES,				//!< Log to a file on disk.
	L_DST_SYSLOG,				//!< Log to syslog.
	L_DST_STDERR,				//!< Log to stderr.
	L_DST_FUNC,				//!< Send log messages to a FILE*, via fopencookie()
	L_DST_NULL,				//!< Discard log messages.
	L_DST_NUM_DEST
} fr_log_dst_t;

typedef enum {
	L_TIMESTAMP_AUTO = 0,			//!< Timestamp logging preference not specified. Do it based on
						//!< debug level and destination.
	L_TIMESTAMP_ON,				//!< Always log timestamps.
	L_TIMESTAMP_OFF				//!< Never log timestamps.
} fr_log_timestamp_t;

typedef struct {
	fr_log_dst_t		dst;		//!< Log destination.

	bool			line_number;	//!< Log src file and line number.

	bool			colourise;	//!< Prefix log messages with VT100 escape codes to change text
						//!< colour.

	bool			dates_utc;	//!< Whether timestamps should be UTC or local timezone.

	bool			print_level;	//!< sometimes we don't want log levels printed

	fr_log_timestamp_t	timestamp;	//!< Prefix log messages with timestamps.

	int			fd;		//!< File descriptor to write messages to.
	char const		*file;		//!< Path to log file.

	void			*cookie;	//!< for fopencookie()
	FILE			*handle;	//!< Path to log file.

	ssize_t			(*cookie_write)(void *, char const *, size_t);	//!< write function
	void			*uctx;		//!< User data associated with the fr_log_t.
} fr_log_t;

typedef struct {
	char const		*first_prefix;	//!< Prefix for the first line printed.
	char const		*subsq_prefix;	//!< Prefix for subsequent lines.
} fr_log_perror_format_t;

/** Context structure for the log fd event function
 *
 * This enables a file descriptor to be inserted into an event loop
 * and produce log output.  It's useful for execd child processes
 * and for capturing stdout/stderr from libraries.
 */
typedef struct {
	fr_log_t const	*dst;		//!< Where to log to.
	fr_log_type_t	type;		//!< What type of log message it is.
	fr_log_lvl_t	lvl;		//!< Priority of the message.
	char const	*prefix;	//!< To add to log messages.
} fr_log_fd_event_ctx_t;

extern fr_log_t default_log;
extern bool fr_log_rate_limit;

/** Whether rate limiting is enabled
 *
 */
static inline bool fr_rate_limit_enabled(void)
{
	if (fr_log_rate_limit || (fr_debug_lvl < 1)) return true;

	return false;
}

int	fr_log_init_legacy(fr_log_t *log, bool daemonize);

void	fr_log_fd_event(UNUSED fr_event_list_t *el, int fd, UNUSED int flags, void *uctx);

void	fr_vlog(fr_log_t const *log, fr_log_type_t lvl, char const *file, int line, char const *fmt, va_list ap)
	CC_HINT(format (printf, 5, 0)) CC_HINT(nonnull (1,3));

void	fr_log(fr_log_t const *log, fr_log_type_t lvl, char const *file, int line, char const *fmt, ...)
	CC_HINT(format (printf, 5, 6)) CC_HINT(nonnull (1,3));

void	fr_vlog_perror(fr_log_t const *log, fr_log_type_t type,
		       char const *file, int line, fr_log_perror_format_t const *rules, char const *fmt, va_list ap)
	CC_HINT(format (printf, 6, 0)) CC_HINT(nonnull (1));

void	fr_log_perror(fr_log_t const *log, fr_log_type_t type,
		      char const *file, int line, fr_log_perror_format_t const *rules, char const *fmt, ...)
	CC_HINT(format (printf, 6, 7)) CC_HINT(nonnull (1));

void	fr_log_marker(fr_log_t const *log, fr_log_type_t type, char const *file, int line,
		      char const *str, size_t str_len,
		      ssize_t marker_idx, char const *marker, char const *line_prefix_fmt, ...)
		      CC_HINT(format (printf, 9, 10)) CC_HINT(nonnull (1,3,5,8));

void	fr_log_hex(fr_log_t const *log, fr_log_type_t type, char const *file, int line,
		   uint8_t const *data, size_t data_len, char const *line_prefix_fmt, ...)
		   CC_HINT(format (printf, 7, 8)) CC_HINT(nonnull (1,3,5));

void	fr_log_hex_marker(fr_log_t const *log, fr_log_type_t type, char const *file, int line,
			  uint8_t const *data, size_t data_len,
			  ssize_t marker_idx, char const *marker, char const *line_prefix_fmt, ...)
			  CC_HINT(format (printf, 9, 10)) CC_HINT(nonnull (1, 3, 5, 8));

int	fr_log_init_std(fr_log_t *log, fr_log_dst_t dst_type) CC_HINT(nonnull);

int	fr_log_init_file(fr_log_t *log, char const *file) CC_HINT(nonnull);

int	fr_log_init_syslog(fr_log_t *log) CC_HINT(nonnull);

int	fr_log_init_func(fr_log_t *log, cookie_write_function_t write, cookie_close_function_t close, void *uctx)
	CC_HINT(nonnull(1,3));

int	fr_log_close(fr_log_t *log) CC_HINT(nonnull);

TALLOC_CTX *fr_log_pool_init(void);

int	fr_log_global_init(fr_event_list_t *el, bool daemonize)	CC_HINT(nonnull);

void	fr_log_global_free(void);

#ifdef __cplusplus
}
#endif
