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
#ifndef _FR_LOG_H
#define _FR_LOG_H

#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include <freeradius-devel/token.h>

/**
 * $Id$
 *
 * @file include/fr_log.h
 * @brief libfreeradius logging functions
 *
 * @copyright 2016  The FreeRADIUS server project
 */

extern FILE	*fr_log_fp;

/*
 *	Error functions.
 */
void		fr_printf_log(char const *, ...) CC_HINT(format (printf, 1, 2));

void		fr_strerror_printf(char const *, ...) CC_HINT(format (printf, 1, 2));
void		fr_strerror_printf_push(char const *fmt, ...)  CC_HINT(format (printf, 1, 2));

char const	*fr_strerror(void);
char const	*fr_strerror_pop(void);

void		fr_perror(char const *, ...) CC_HINT(format (printf, 1, 2));
void		fr_canonicalize_error(TALLOC_CTX *ctx, char **spaces, char **text, ssize_t slen, char const *msg);

char const	*fr_syserror(int num);
extern bool	fr_dns_lookups;	/* do IP -> hostname lookups? */
extern bool	fr_hostname_lookups; /* do hostname -> IP lookups? */
extern int	fr_debug_lvl;	/* 0 = no debugging information */
extern bool	log_dates_utc;

extern const FR_NAME_NUMBER fr_log_levels[];

typedef enum log_type {
	L_AUTH = 2,			//!< Authentication message.
	L_INFO = 3,			//!< Informational message.
	L_ERR = 4,			//!< Error message.
	L_WARN = 5,			//!< Warning.
	L_PROXY	= 6,			//!< Proxy messages
	L_ACCT = 7,			//!< Accounting messages

	L_DBG = 16,			//!< Only displayed when debugging is enabled.
	L_DBG_INFO = 17,		//!< Info only displayed when debugging is enabled.
	L_DBG_WARN = 18,		//!< Warning only displayed when debugging is enabled.
	L_DBG_ERR = 19,			//!< Error only displayed when debugging is enabled.
	L_DBG_WARN_REQ = 20,		//!< Less severe warning only displayed when debugging is enabled.
	L_DBG_ERR_REQ = 21		//!< Less severe error only displayed when debugging is enabled.
} log_type_t;

typedef enum log_lvl {
	L_DBG_LVL_DISABLE = -1,		//!< Don't print messages.
	L_DBG_LVL_OFF = 0,		//!< No debug messages.
	L_DBG_LVL_1,			//!< Highest priority debug messages (-x).
	L_DBG_LVL_2,			//!< 2nd highest priority debug messages (-xx | -X).
	L_DBG_LVL_3,			//!< 3rd highest priority debug messages (-xxx | -Xx).
	L_DBG_LVL_MAX			//!< Lowest priority debug messages (-xxxx | -Xxx).
} log_lvl_t;

typedef enum log_dst {
	L_DST_STDOUT = 0,		//!< Log to stdout.
	L_DST_FILES,			//!< Log to a file on disk.
	L_DST_SYSLOG,			//!< Log to syslog.
	L_DST_STDERR,			//!< Log to stderr.
	L_DST_EXTRA,			//!< Send log messages to a FILE*, via fopencookie()
	L_DST_NULL,			//!< Discard log messages.
	L_DST_NUM_DEST
} log_dst_t;

typedef enum {
	L_TIMESTAMP_AUTO = 0,		//!< Timestamp logging preference not specified. Do it based on
					//!< debug level and destination.
	L_TIMESTAMP_ON,			//!< Always log timestamps.
	L_TIMESTAMP_OFF			//!< Never log timestamps.
} log_timestamp_t;

typedef struct fr_log_t {
	log_dst_t	dst;		//!< Log destination.

	bool		colourise;	//!< Prefix log messages with VT100 escape codes to change text
					//!< colour.
	log_timestamp_t	timestamp;	//!< Prefix log messages with timestamps.

	int		fd;		//!< File descriptor to write messages to.
	char const	*file;		//!< Path to log file.

	void		*cookie;	//!< for fopencookie()
#ifdef HAVE_FOPENCOOKIE
	ssize_t		(*cookie_write)(void *, char const *, size_t); //!< write function
#else
	int		(*cookie_write)(void *, char const *, int); //!< write function
#endif
} fr_log_t;

extern fr_log_t default_log;

int	fr_log_init(fr_log_t *log, bool daemonize);

int	fr_vlog(fr_log_t const *log, log_type_t lvl, char const *fmt, va_list ap)
	CC_HINT(format (printf, 3, 0)) CC_HINT(nonnull (1,3));

int	fr_log(fr_log_t const *log, log_type_t lvl, char const *fmt, ...)
	CC_HINT(format (printf, 3, 4)) CC_HINT(nonnull (1,3));

int	fr_log_perror(fr_log_t const *log, log_type_t type, char const *msg, ...)
	CC_HINT(format (printf, 3, 4)) CC_HINT(nonnull (1));

bool	fr_rate_limit_enabled(void);


#endif /* _FR_LOG_H */
