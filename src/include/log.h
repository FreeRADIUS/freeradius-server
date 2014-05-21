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
#ifndef FR_LOG_H
#define FR_LOG_H
/*
 * $Id$
 *
 * @file log.h
 * @brief Structures and prototypes for logging.
 *
 * @copyright 2013 Alan DeKok <aland@freeradius.org>
 */
RCSIDH(log_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

typedef enum log_type {
	L_AUTH = 2,		//!< Authentication message.
	L_INFO = 3,		//!< Informational message.
	L_ERR = 4,		//!< Error message.
	L_WARN = 5,		//!< Warning.
	L_PROXY	= 6,		//!< Proxy messages
	L_ACCT = 7,		//!< Accounting messages

	L_DBG = 16,		//!< Only displayed when debugging is enabled.
	L_DBG_WARN = 17,	//!< Warning only displayed when debugging is enabled.
	L_DBG_ERR = 18,		//!< Error only displayed when debugging is enabled.
	L_DBG_WARN_REQ = 19,	//!< Less severe warning only displayed when debugging is enabled.
	L_DBG_ERR_REQ = 20	//!< Less severe error only displayed when debugging is enabled.
} log_type_t;

typedef enum log_debug {
	L_DBG_LVL_MIN = -1,	//!< Hack for stupid GCC warnings (comparison with 0 always true)
	L_DBG_LVL_OFF = 0,	//!< No debug messages.
	L_DBG_LVL_1,		//!< Highest priority debug messages (-x).
	L_DBG_LVL_2,		//!< 2nd highest priority debug messages (-xx | -X).
	L_DBG_LVL_3,		//!< 3rd highest priority debug messages (-xxx | -Xx).
	L_DBG_LVL_MAX		//!< Lowest priority debug messages (-xxxx | -Xxx).
} log_debug_t;

typedef enum log_dst {
	L_DST_STDOUT = 0,	//!< Log to stdout.
	L_DST_FILES,		//!< Log to a file on disk.
	L_DST_SYSLOG,		//!< Log to syslog.
	L_DST_STDERR,		//!< Log to stderr.
	L_DST_NULL,		//!< Discard log messages.
	L_DST_NUM_DEST
} log_dst_t;

typedef struct fr_log_t {
	int		colourise;	//!< Prefix log messages with VT100 escape codes to change text
					//!< colour.
	int		fd;		//!< File descriptor to write messages to.
	log_dst_t	dst;		//!< Log destination.
	char const	*file;		//!< Path to log file.
	char const	*debug_file;	//!< Path to debug log file.
} fr_log_t;

typedef		void (*radlog_func_t)(log_type_t lvl, log_debug_t priority, REQUEST *, char const *, va_list ap);

extern FR_NAME_NUMBER const syslog_str2fac[];
extern FR_NAME_NUMBER const log_str2dst[];
extern fr_log_t default_log;

int	radlog_init(fr_log_t *log, bool daemonize);

void 	vp_listdebug(VALUE_PAIR *vp);

int	vradlog(log_type_t lvl, char const *fmt, va_list ap)
	CC_HINT(format (printf, 2, 0)) CC_HINT(nonnull);
int	radlog(log_type_t lvl, char const *fmt, ...)
	CC_HINT(format (printf, 2, 3)) CC_HINT(nonnull (2));

bool	debug_enabled(log_type_t type, log_debug_t lvl);

bool	rate_limit_enabled(void);

bool	radlog_debug_enabled(log_type_t type, log_debug_t lvl, REQUEST *request)
	CC_HINT(nonnull);

void	vradlog_request(log_type_t type, log_debug_t lvl, REQUEST *request, char const *msg, va_list ap)
	CC_HINT(format (printf, 4, 0)) CC_HINT(nonnull (3, 4));

void	radlog_request(log_type_t type, log_debug_t lvl, REQUEST *request, char const *msg, ...)
	CC_HINT(format (printf, 4, 5)) CC_HINT(nonnull (3, 4));

void	radlog_request_error(log_type_t type, log_debug_t lvl, REQUEST *request, char const *msg, ...)
	CC_HINT(format (printf, 4, 5)) CC_HINT(nonnull (3, 4));

void	radlog_request_marker(log_type_t type, log_debug_t lvl, REQUEST *request,
			      char const *fmt, size_t indent, char const *error)
	CC_HINT(nonnull);

/*
 *	Multiple threads logging to one or more files.
 */
typedef struct fr_logfile_t fr_logfile_t;

fr_logfile_t *fr_logfile_init(TALLOC_CTX *ctx);
int fr_logfile_open(fr_logfile_t *lf, char const *filename, mode_t permissions);
int fr_logfile_close(fr_logfile_t *lf, int fd);
int fr_logfile_unlock(fr_logfile_t *lf, int fd);

/*
 *	Logging macros.
 *
 *	For server code, do not call radlog, vradlog et al directly, use one of the logging macros instead.
 *
 *	R*			- Macros prefixed with an R will automatically prepend request information to the
 *				  log messages.
 *	INFO | WARN | ERROR	- Macros containing these words will be displayed at all log levels.
 *	*DEBUG* 		- Macros with the word DEBUG, will only be displayed if the server or request debug
 *				  level is above 0.
 *	*[IWE]DEBUG[0-9]?	- Macros with I, W, E as (or just after) the prefix, will log with the priority
 *				  specified by the integer if the server or request log level at or above that integer.
 *				  If there is no integer the level is 1. The I|W|E prefix determines the type
 *				  (INFO, WARN, ERROR), if there is no I|W|E prefix the DEBUG type will be used.
 */

/*
 *	Log server driven messages like threadpool exhaustion and connection failures
 */
#define _SL(_l, _p, _f, ...)	if (debug_flag >= _p) radlog(_l, _f, ## __VA_ARGS__)

#define DEBUG_ENABLED		debug_enabled(L_DBG, L_DBG_LVL_1)
#define DEBUG_ENABLED2		debug_enabled(L_DBG, L_DBG_LVL_2)
#define DEBUG_ENABLED3		debug_enabled(L_DBG, L_DBG_LVL_3)
#define DEBUG_ENABLED4		debug_enabled(L_DBG, L_DBG_LVL_MAX)

#define AUTH(fmt, ...)		_SL(L_AUTH, L_DBG_LVL_OFF, fmt, ## __VA_ARGS__)
#define ACCT(fmt, ...)		_SL(L_ACCT, L_DBG_LVL_OFF, fmt, ## __VA_ARGS__)
#define PROXY(fmt, ...)		_SL(L_PROXY, L_DBG_LVL_OFF, fmt, ## __VA_ARGS__)

#define DEBUG(fmt, ...)		_SL(L_DBG, L_DBG_LVL_1, fmt, ## __VA_ARGS__)
#define DEBUG2(fmt, ...)	_SL(L_DBG, L_DBG_LVL_2, fmt, ## __VA_ARGS__)
#define DEBUG3(fmt, ...)	_SL(L_DBG, L_DBG_LVL_3, fmt, ## __VA_ARGS__)
#define DEBUG4(fmt, ...)	_SL(L_DBG, L_DBG_LVL_MAX, fmt, ## __VA_ARGS__)

#define INFO(fmt, ...)		_SL(L_INFO, L_DBG_LVL_OFF, fmt, ## __VA_ARGS__)
#define WARN(fmt, ...)		_SL(L_WARN, L_DBG_LVL_OFF, fmt, ## __VA_ARGS__)
#define ERROR(fmt, ...)		_SL(L_ERR, L_DBG_LVL_OFF, fmt, ## __VA_ARGS__)

/*
 *	Log request driven messages which including elements from the current request, like section and module
 *
 *	If a REQUEST * is available, these functions should be used.
 */
#define _RLOG(_l, _p, _f, ...)		radlog_request(_l, _p, request, _f, ## __VA_ARGS__)
#define _RMOD(_l, _p, _f, ...)		radlog_request_error(_l, _p, request, _f, ## __VA_ARGS__)
#define _RMKR(_l, _p, _m, _i, _e)	radlog_request_marker(_l, _p, request, _m, _i, _e)

#define RDEBUG_ENABLED		radlog_debug_enabled(L_DBG, L_DBG_LVL_1, request)
#define RDEBUG_ENABLED2		radlog_debug_enabled(L_DBG, L_DBG_LVL_2, request)
#define RDEBUG_ENABLED3		radlog_debug_enabled(L_DBG, L_DBG_LVL_3, request)
#define RDEBUG_ENABLED4		radlog_debug_enabled(L_DBG, L_DBG_LVL_MAX, request)

#define RAUTH(fmt, ...)		_RLOG(L_AUTH, L_DBG_LVL_OFF, fmt, ## __VA_ARGS__)
#define RACCT(fmt, ...)		_RLOG(L_ACCT, L_DBG_LVL_OFF, fmt, ## __VA_ARGS__)
#define RPROXY(fmt, ...)	_RLOG(L_PROXY, L_DBG_LVL_OFF, fmt, ## __VA_ARGS__)

#define RDEBUGX(_l, fmt, ...)	_RLOG(L_DBG, _l, fmt, ## __VA_ARGS__)
#define RDEBUG(fmt, ...)	_RLOG(L_DBG, L_DBG_LVL_1, fmt, ## __VA_ARGS__)
#define RDEBUG2(fmt, ...)	_RLOG(L_DBG, L_DBG_LVL_2, fmt, ## __VA_ARGS__)
#define RDEBUG3(fmt, ...)	_RLOG(L_DBG, L_DBG_LVL_3, fmt, ## __VA_ARGS__)
#define RDEBUG4(fmt, ...)	_RLOG(L_DBG, L_DBG_LVL_MAX, fmt, ## __VA_ARGS__)

#define RINFO(fmt, ...)		_RLOG(L_INFO, L_DBG_LVL_OFF, fmt, ## __VA_ARGS__)
#define RIDEBUG(fmt, ...)	_RLOG(L_INFO, L_DBG_LVL_1, fmt, ## __VA_ARGS__)
#define RIDEBUG2(fmt, ...)	_RLOG(L_INFO, L_DBG_LVL_2, fmt, ## __VA_ARGS__)

#define RWARN(fmt, ...)		_RLOG(L_DBG_WARN, L_DBG_LVL_OFF, fmt, ## __VA_ARGS__)
#define RWDEBUG(fmt, ...)	_RLOG(L_DBG_WARN, L_DBG_LVL_1, fmt, ## __VA_ARGS__)
#define RWDEBUG2(fmt, ...)	_RLOG(L_DBG_WARN, L_DBG_LVL_2, fmt, ## __VA_ARGS__)

#define RERROR(fmt, ...)	_RMOD(L_DBG_ERR, L_DBG_LVL_OFF, fmt, ## __VA_ARGS__)
#define REDEBUG(fmt, ...)	_RMOD(L_DBG_ERR, L_DBG_LVL_1, fmt, ## __VA_ARGS__)
#define REDEBUG2(fmt, ...)	_RMOD(L_DBG_ERR, L_DBG_LVL_2, fmt, ## __VA_ARGS__)
#define REDEBUG3(fmt, ...)	_RMOD(L_DBG_ERR, L_DBG_LVL_3, fmt, ## __VA_ARGS__)
#define REDEBUG4(fmt, ...)	_RMOD(L_DBG_ERR, L_DBG_LVL_MAX, fmt, ## __VA_ARGS__)

#define RINDENT()		(request->log.indent++)
#define REXDENT()		(request->log.indent--)

/*
 * Output string with error marker, showing where format error occurred.
 *
 @verbatim
   my pet kitty
      ^ kitties are not pets, are nature devouring hell beasts
 @endverbatim
 *
 * @param _m string to mark e.g. "my pet kitty".
 * @param _i index e.g. 3 (starts from 0).
 * @param _e error e.g. "kitties are not pets, are nature devouring hell beasts".
 */
#define REMARKER(_m, _i, _e)	_RMKR(L_DBG_ERR, L_DBG_LVL_1, _m, _i, _e)
#define RDMARKER(_m, _i, _e)	_RMKR(L_DBG, L_DBG_LVL_1, _m, _i, _e)

/*
 *	Rate limit messages.
 */
#define RATE_LIMIT_ENABLED rate_limit_enabled()
#define RATE_LIMIT(_x) \
do {\
	if (RATE_LIMIT_ENABLED) {\
		static time_t _last_complained = 0;\
		time_t _now = time(NULL);\
		if (_now != _last_complained) {\
			_last_complained = _now;\
			_x;\
		}\
	} else _x;\
} while (0)

#ifdef __cplusplus
}
#endif

#endif /* FR_LOG_H */
