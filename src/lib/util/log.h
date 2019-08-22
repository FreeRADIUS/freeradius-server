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
#include <freeradius-devel/util/table.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <talloc.h>

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
	L_DST_EXTRA,				//!< Send log messages to a FILE*, via fopencookie()
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

	fr_log_timestamp_t	timestamp;	//!< Prefix log messages with timestamps.

	int			fd;		//!< File descriptor to write messages to.
	char const		*file;		//!< Path to log file.

	void			*cookie;	//!< for fopencookie()
#ifdef HAVE_FOPENCOOKIE
	ssize_t			(*cookie_write)(void *, char const *, size_t);	//!< write function
#else
	int			(*cookie_write)(void *, char const *, int);	//!< write function
#endif
} fr_log_t;

extern fr_log_t default_log;

int	fr_log_init(fr_log_t *log, bool daemonize);

int	fr_vlog(fr_log_t const *log, fr_log_type_t lvl, char const *file, int line, char const *fmt, va_list ap)
	CC_HINT(format (printf, 5, 0)) CC_HINT(nonnull (1,3));

int	fr_log(fr_log_t const *log, fr_log_type_t lvl, char const *file, int line, char const *fmt, ...)
	CC_HINT(format (printf, 5, 6)) CC_HINT(nonnull (1,3));

int	fr_vlog_perror(fr_log_t const *log, fr_log_type_t type, char const *file, int line, char const *fmt, va_list ap)
	CC_HINT(format (printf, 5, 0)) CC_HINT(nonnull (1));

int	fr_log_perror(fr_log_t const *log, fr_log_type_t type, char const *file, int line, char const *fmt, ...)
	CC_HINT(format (printf, 5, 6)) CC_HINT(nonnull (1));

void	fr_log_hex(fr_log_t const *log, fr_log_type_t type,
		   char const *file, int line,
		   uint8_t const *data, size_t data_len, char const *fmt, ...)
		   CC_HINT(format (printf, 7, 8)) CC_HINT(nonnull (1,3,5));

bool	fr_rate_limit_enabled(void);

#ifdef __cplusplus
}
#endif
