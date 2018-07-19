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

/**
 * $Id$
 *
 * @file lib/server/log.h
 * @brief Macros and function definitions to write log messages, and control the logging system.
 *
 * @copyright 2015 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2013 Alan DeKok <aland@freeradius.org>
 */
RCSIDH(server_log_h, "$Id$")

#include <freeradius-devel/util/log.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Logging callback to write log messages to a destination
 *
 * This allows the logging destination to be customised on a per request basis.
 *
 * @note Logging functions must not block waiting on I/O.
 *
 * @param[in] type	What type of message this is (error, warn, info, debug).
 * @param[in] lvl	At what logging level this message should be output.
 * @param[in] request	The current request.
 * @param[in] fmt	sprintf style fmt string.
 * @param[in] ap	Arguments for the fmt string.
 * @param[in] uctx	Context data for the log function.  Usually an #fr_log_t for vlog_request.
 */
typedef	void (*log_func_t)(fr_log_type_t type, fr_log_lvl_t lvl, REQUEST *request, char const *fmt, va_list ap, void *uctx);

/** A logging destination, consisting of a function and its context
 *
 */
typedef struct log_dst log_dst_t;
struct log_dst {
	log_func_t	func;	//!< Function to call to log to this destination.
	void		*uctx;	//!< Context to pass to the logging function.
	log_dst_t	*next;	//!< Next logging destination.
};

extern FR_NAME_NUMBER const syslog_facility_table[];
extern FR_NAME_NUMBER const syslog_severity_table[];
extern FR_NAME_NUMBER const log_str2dst[];

#define debug_enabled(_type, _lvl) ((_type & L_DBG) && (_lvl <= rad_debug_lvl))

bool	log_debug_enabled(fr_log_type_t type, fr_log_lvl_t lvl, REQUEST *request)
	CC_HINT(nonnull);

void	vlog_request(fr_log_type_t type, fr_log_lvl_t lvl, REQUEST *request, char const *msg, va_list ap, void *uctx)
	CC_HINT(format (printf, 4, 0)) CC_HINT(nonnull (3, 4));

void	log_request(fr_log_type_t type, fr_log_lvl_t lvl, REQUEST *request, char const *msg, ...)
	CC_HINT(format (printf, 4, 5)) CC_HINT(nonnull (3, 4));

void	log_module_failure_msg(REQUEST *request, char const *fmt, ...)
	CC_HINT(format (printf, 2, 3));

void	vlog_module_failure_msg(REQUEST *request, char const *fmt, va_list ap)
	CC_HINT(format (printf, 2, 0));

void	log_request_error(fr_log_type_t type, fr_log_lvl_t lvl, REQUEST *request, char const *msg, ...)
	CC_HINT(format (printf, 4, 5)) CC_HINT(nonnull (3, 4));

void	log_request_perror(fr_log_type_t type, fr_log_lvl_t lvl, REQUEST *request, char const *msg, ...)
	CC_HINT(format (printf, 4, 5)) CC_HINT(nonnull (3));

void	log_request_pair_list(fr_log_lvl_t lvl, REQUEST *request, VALUE_PAIR *vp, char const *prefix);

void	log_request_proto_pair_list(fr_log_lvl_t lvl, REQUEST *request, VALUE_PAIR *vp, char const *prefix);

void	log_request_marker(fr_log_type_t type, fr_log_lvl_t lvl, REQUEST *request,
			      char const *fmt, size_t indent, char const *error)
	CC_HINT(nonnull);

void	log_request_hex(fr_log_type_t type, fr_log_lvl_t lvl, REQUEST *request,
			   uint8_t const *data, size_t data_len)
	CC_HINT(nonnull);

void	log_hex(fr_log_t const *log, fr_log_type_t type, fr_log_lvl_t lvl, uint8_t const *data, size_t data_len)
	CC_HINT(nonnull);

void	log_fatal(char const *fmt, ...) CC_HINT(format (printf, 1, 2)) CC_HINT(nonnull) NEVER_RETURNS;

int	log_global_init(fr_log_t *log, bool daemonize);

void	log_global_free(void);

/** Prefix for global log messages
 *
 * Should be defined in source file (before including radius.h) to add prefix to
 * global log messages.
 */
#ifndef LOG_PREFIX
#  define LOG_PREFIX ""
#endif

#ifdef LOG_PREFIX_ARGS
#  define _FR_LOG(_l, _f, ...) fr_log(&default_log, _l, LOG_PREFIX _f, LOG_PREFIX_ARGS, ## __VA_ARGS__)
#  define _FR_LOG_PERROR(_l, _f, ...) fr_log_perror(&default_log, _l, LOG_PREFIX _f, LOG_PREFIX_ARGS, ## __VA_ARGS__)
#else
#  define _FR_LOG(_l, _f, ...) fr_log(&default_log, _l, LOG_PREFIX _f, ## __VA_ARGS__)
#  define _FR_LOG_PERROR(_l, _f, ...) fr_log_perror(&default_log, _l, LOG_PREFIX _f, ## __VA_ARGS__)
#endif

/** @name Log global messages
 *
 * Write to the global log.
 *
 * Messages will always be written irrespective of the debugging level set with ``-x`` or ``-X``.
 *
 * @warning If a REQUEST * is **NOT** available, these macros **MUST** be used.
 *
 * @note These macros should only be used for important global events.
 *
 * **Debug categories**
 * Name     | Syslog severity         | Colour/style | When to use
 * -------- | ----------------------- | ------------ | -----------
 * AUTH     | LOG_NOTICE              | Bold         | Never - Deprecated
 * ACCT     | LOG_NOTICE              | Bold         | Never - Deprecated
 * PROXY    | LOG_NOTICE              | Bold         | Never - Deprecated
 * INFO     | LOG_INFO                | Bold         | TBD
 * WARN     | LOG_WARNING             | Yellow       | Warnings. Impending resource exhaustion, resource exhaustion
 * ERROR    | LOG_ERR                 | Red          | Critical server errors. Malformed queries, failed operations, connection errors, packet processing errors
 *
 * @{
 */
#define AUTH(fmt, ...)		_FR_LOG(L_AUTH, fmt, ## __VA_ARGS__)
#define ACCT(fmt, ...)		_FR_LOG(L_ACCT, fmt, ## __VA_ARGS__)
#define PROXY(fmt, ...)		_FR_LOG(L_PROXY, fmt, ## __VA_ARGS__)

#define INFO(fmt, ...)		_FR_LOG(L_INFO, fmt, ## __VA_ARGS__)
#define WARN(fmt, ...)		_FR_LOG(L_WARN, fmt, ## __VA_ARGS__)
#define ERROR(fmt, ...)		_FR_LOG(L_ERR, fmt, ## __VA_ARGS__)
#define PERROR(fmt, ...)	_FR_LOG_PERROR(L_ERR, fmt, ## __VA_ARGS__)
#define PWARN(fmt, ...)		_FR_LOG_PERROR(L_WARN, fmt, ## __VA_ARGS__)
/** @} */

/** @name Log global debug messages (DEBUG*)
 *
 * Write debugging messages to the global log.
 *
 * Messages will be written if the debug level is high enough.
 *
 * **Debug categories**
 * Name     | Syslog severity         | Colour/style | When to use
 * -------- | ----------------------- | -------------| -----------
 * DEBUG    | LOG_DEBUG               | Regular      | Normal debug output
 *
 * **Debug levels**
 * Level    | Debug arguments         | Macro(s) enabled   | When to use
 * -------- | ----------------------- | ------------------ | -----------
 * 1        | ``-x``                  | DEBUG              | Never - Deprecated
 * 2        | ``-xx`` or ``-X``       | DEBUG, DEBUG2      | Interactions with external entities. Connection management, control socket, triggers, etc...
 * 3        | ``-xxx`` or ``-Xx``     | DEBUG, DEBUG[2-3]  | Lower priority events. Polling for detail files, cleanups, etc...
 * 4        | ``-xxxx`` or ``-Xxx``   | DEBUG, DEBUG[2-4]  | Internal server state debugging.
 * 5        | ``-xxxxx`` or ``-Xxxx`` | DEBUG, DEBUG[2-5]  | Low level internal server state debugging.
 *
 * @{
 */
#define DEBUG_ENABLED		debug_enabled(L_DBG, L_DBG_LVL_1)			//!< True if global debug level 1 messages are enabled
#define DEBUG_ENABLED2		debug_enabled(L_DBG, L_DBG_LVL_2)			//!< True if global debug level 1-2 messages are enabled
#define DEBUG_ENABLED3		debug_enabled(L_DBG, L_DBG_LVL_3)			//!< True if global debug level 1-3 messages are enabled
#define DEBUG_ENABLED4		debug_enabled(L_DBG, L_DBG_LVL_4)			//!< True if global debug level 1-3 messages are enabled
#define DEBUG_ENABLED5		debug_enabled(L_DBG, L_DBG_LVL_MAX)			//!< True if global debug level 1-5 messages are enabled

#define _DEBUG_LOG(_l, _p, _f, ...)	if (rad_debug_lvl >= _p) _FR_LOG(_l, _f, ## __VA_ARGS__)
#define DEBUG(fmt, ...)		_DEBUG_LOG(L_DBG, L_DBG_LVL_1, fmt, ## __VA_ARGS__)
#define DEBUG2(fmt, ...)	_DEBUG_LOG(L_DBG, L_DBG_LVL_2, fmt, ## __VA_ARGS__)
#define DEBUG3(fmt, ...)	_DEBUG_LOG(L_DBG, L_DBG_LVL_3, fmt, ## __VA_ARGS__)
#define DEBUG4(fmt, ...)	_DEBUG_LOG(L_DBG, L_DBG_LVL_MAX, fmt, ## __VA_ARGS__)
#define DEBUGX(_lvl, fmt, ...)	_DEBUG_LOG(L_DBG, _lvl, fmt, ## __VA_ARGS__)
/** @} */

/** @name Log request-specific messages (R*)
 *
 * Write to the request log, or the global log if a request logging function is not set.
 *
 * Messages will always be written irrespective of the debugging level set with ``-x`` or ``-X``.
 *
 * @note Automatically prepends date (at lvl >= 3), request number, and module, to the log message.
 * @note If a REQUEST * is available, these macros should be used.
 * @note These macros should only be used for important global events.
 *
 * **Debug categories**
 * Name     | Syslog severity         | Colour/style | When to use
 * -------- | ----------------------- | -------------| -----------
 * RAUTH    | LOG_NOTICE              | Bold         | Never - Deprecated
 * RACCT    | LOG_NOTICE              | Bold         | Never - Deprecated
 * RPROXY   | LOG_NOTICE              | Bold         | Never - Deprecated
 * RINFO    | LOG_INFO                | Bold         | TBD
 * RWARN    | LOG_WARNING             | Yellow/Bold  | Warnings. Impending resource exhaustion, or resource exhaustion.
 * RERROR   | LOG_ERR                 | Red/Bold     | Critical server errors. Malformed queries, failed operations, connection errors, packet processing errors.
 * @{
 */
#define RAUTH(fmt, ...)		log_request(L_AUTH, L_DBG_LVL_OFF, request, fmt, ## __VA_ARGS__)
#define RACCT(fmt, ...)		log_request(L_ACCT, L_DBG_LVL_OFF, request, fmt, ## __VA_ARGS__)
#define RPROXY(fmt, ...)	log_request(L_PROXY, L_DBG_LVL_OFF, request, fmt, ## __VA_ARGS__)
#define RINFO(fmt, ...)		log_request(L_INFO, L_DBG_LVL_OFF, request, fmt, ## __VA_ARGS__)
#define RWARN(fmt, ...)		log_request(L_DBG_WARN, L_DBG_LVL_OFF, request, fmt, ## __VA_ARGS__)
#define RERROR(fmt, ...)	log_request_error(L_DBG_ERR, L_DBG_LVL_OFF, request, fmt, ## __VA_ARGS__)
#define RPERROR(fmt, ...)	log_request_perror(L_DBG_ERR, L_DBG_LVL_OFF, request, fmt, ## __VA_ARGS__)
/** @} */

/** @name Log request-specific debug (R*DEBUG*)
 *
 * Write debug messages to the request log.
 *
 * Messages will only be written if a request log function is set and the request or global
 * debug level is high enough.
 *
 * @note Automatically prepends date (at lvl >= 3), request number, and module, to the log message.
 *
 * **Debug categories**
 * Name     | Syslog severity         | Colour and style | When to use
 * -------- | ----------------------- | -----------------| -----------
 * RDEBUG*  | LOG_DEBUG               | Regular          | Normal debugging messages
 * RIDEBUG* | LOG_DEBUG               | Bold             | Informational messages.
 * RWDEBUG* | LOG_DEBUG               | Yellow/Bold      | Warnings. Invalid configuration, missing or invalid attributes etc...
 * REDEBUG* | LOG_DEBUG               | Red/Bold         | Errors. Reject messages, bad values etc...
 *
 * **Debug levels**
 * Level    | Debug arguments         | Macro(s) enabled      | When to use
 * -------- | ----------------------- | --------------------- | -----------
 * 1        | ``-x``                  | R*DEBUG               | Never - Deprecated
 * 2        | ``-xx`` or ``-X``       | R*DEBUG, R*DEBUG2     | Normal request flow. Operations, Results of queries, or execs, etc...
 * 3        | ``-xxx`` or ``-Xx``     | R*DEBUG, R*DEBUG[2-3] | Internal server state or packet input. State machine changes, extra attribute info, etc...
 * 4        | ``-xxxx`` or ``-Xxx``   | R*DEBUG, R*DEBUG[2-4] | Verbose internal server state messages or packet input. Hex dumps, structure dumps, pointer values.
 * 5        | ``-xxxxx`` or ``-Xxxx`` | R*DEBUG, R*DEBUG[2-5] | Low level internal server state messages.
 *
 * @{
 */
#define RDEBUG_ENABLED		log_debug_enabled(L_DBG, L_DBG_LVL_1, request)	//!< True if request debug level 1 messages are enabled
#define RDEBUG_ENABLED2		log_debug_enabled(L_DBG, L_DBG_LVL_2, request)	//!< True if request debug level 1-2 messages are enabled
#define RDEBUG_ENABLED3		log_debug_enabled(L_DBG, L_DBG_LVL_3, request)	//!< True if request debug level 1-3 messages are enabled
#define RDEBUG_ENABLED4		log_debug_enabled(L_DBG, L_DBG_LVL_4, request)	//!< True if request debug level 1-4 messages are enabled
#define RDEBUG_ENABLED5		log_debug_enabled(L_DBG, L_DBG_LVL_MAX, request)	//!< True if request debug level 1-5 messages are enabled

#define RDEBUGX(_l, fmt, ...)	do { if (rad_debug_lvl || request->log.lvl) log_request(L_DBG, _l, request, fmt, ## __VA_ARGS__); } while(0)
#define RDEBUG(fmt, ...)	do { if (rad_debug_lvl || request->log.lvl) log_request(L_DBG, L_DBG_LVL_1, request, fmt, ## __VA_ARGS__); } while(0)
#define RDEBUG2(fmt, ...)	do { if (rad_debug_lvl || request->log.lvl) log_request(L_DBG, L_DBG_LVL_2, request, fmt, ## __VA_ARGS__); } while(0)
#define RDEBUG3(fmt, ...)	do { if (rad_debug_lvl || request->log.lvl) log_request(L_DBG, L_DBG_LVL_3, request, fmt, ## __VA_ARGS__); } while(0)
#define RDEBUG4(fmt, ...)	do { if (rad_debug_lvl || request->log.lvl) log_request(L_DBG, L_DBG_LVL_4, request, fmt, ## __VA_ARGS__); } while(0)

#define RIDEBUG(fmt, ...)	do { if (rad_debug_lvl || request->log.lvl) log_request(L_DBG_INFO, L_DBG_LVL_1, request, fmt, ## __VA_ARGS__); } while(0)
#define RIDEBUG2(fmt, ...)	do { if (rad_debug_lvl || request->log.lvl) log_request(L_DBG_INFO, L_DBG_LVL_2, request, fmt, ## __VA_ARGS__); } while(0)
#define RIDEBUG3(fmt, ...)	do { if (rad_debug_lvl || request->log.lvl) log_request(L_DBG_INFO, L_DBG_LVL_3, request, fmt, ## __VA_ARGS__); } while(0)
#define RIDEBUG4(fmt, ...)	do { if (rad_debug_lvl || request->log.lvl) log_request(L_DBG_INFO, L_DBG_LVL_4, request, fmt, ## __VA_ARGS__); } while(0)

#define RWDEBUG(fmt, ...)	do { if (rad_debug_lvl || request->log.lvl) log_request(L_DBG_WARN, L_DBG_LVL_1, request, fmt, ## __VA_ARGS__); } while(0)
#define RWDEBUG2(fmt, ...)	do { if (rad_debug_lvl || request->log.lvl) log_request(L_DBG_WARN, L_DBG_LVL_2, request, fmt, ## __VA_ARGS__); } while(0)
#define RWDEBUG3(fmt, ...)	do { if (rad_debug_lvl || request->log.lvl) log_request(L_DBG_WARN, L_DBG_LVL_3, request, fmt, ## __VA_ARGS__); } while(0)
#define RWDEBUG4(fmt, ...)	do { if (rad_debug_lvl || request->log.lvl) log_request(L_DBG_WARN, L_DBG_LVL_4, request, fmt, ## __VA_ARGS__); } while(0)

#define RPWDEBUG(fmt, ...)	do { if (rad_debug_lvl || request->log.lvl) log_request_perror(L_DBG_WARN, L_DBG_LVL_1, request, fmt, ## __VA_ARGS__); } while(0)
#define RPWDEBUG2(fmt, ...)	do { if (rad_debug_lvl || request->log.lvl) log_request_perror(L_DBG_WARN, L_DBG_LVL_2, request, fmt, ## __VA_ARGS__); } while(0)
#define RPWDEBUG3(fmt, ...)	do { if (rad_debug_lvl || request->log.lvl) log_request_perror(L_DBG_WARN, L_DBG_LVL_3, request, fmt, ## __VA_ARGS__); } while(0)
#define RPWDEBUG4(fmt, ...)	do { if (rad_debug_lvl || request->log.lvl) log_request_perror(L_DBG_WARN, L_DBG_LVL_4, request, fmt, ## __VA_ARGS__); } while(0)

#define REDEBUG(fmt, ...)	log_request_error(L_DBG_ERR, L_DBG_LVL_1, request, fmt, ## __VA_ARGS__)
#define REDEBUG2(fmt, ...)	log_request_error(L_DBG_ERR, L_DBG_LVL_2, request, fmt, ## __VA_ARGS__)
#define REDEBUG3(fmt, ...)	log_request_error(L_DBG_ERR, L_DBG_LVL_3, request, fmt, ## __VA_ARGS__)
#define REDEBUG4(fmt, ...)	log_request_error(L_DBG_ERR, L_DBG_LVL_MAX, request, fmt, ## __VA_ARGS__)

#define RPEDEBUG(fmt, ...)	log_request_perror(L_DBG_ERR, L_DBG_LVL_1, request, fmt, ## __VA_ARGS__)
#define RPEDEBUG2(fmt, ...)	log_request_perror(L_DBG_ERR, L_DBG_LVL_2, request, fmt, ## __VA_ARGS__)
#define RPEDEBUG3(fmt, ...)	log_request_perror(L_DBG_ERR, L_DBG_LVL_3, request, fmt, ## __VA_ARGS__)
#define RPEDEBUG4(fmt, ...)	log_request_perror(L_DBG_ERR, L_DBG_LVL_MAX, request, fmt, ## __VA_ARGS__)
/** @} */

#ifdef DEBUG_INDENT
/** Indent R* messages by one level
 *
 * @note Has no effect on the indentation of INFO, WARN, ERROR, DEBUG messages,
 *	 only RINFO, RWARN, RERROR etc...
 */
#  define RINDENT() do {\
	RDEBUG4(">> (%i) at %s[%u]", request->log.unlang_indent, __FILE__, __LINE__); \
	if (request->module) {\
		request->log.module_indent += 2;\
	} else {\
		request->log.unlang_indent += 2;\
	}\
} while(0)

/** Exdent (unindent) R* messages by one level
 *
 * @note Has no effect on the indentation of INFO, WARN, ERROR, DEBUG messages,
 *	 only RINFO, RWARN, RERROR etc...
 */
#  define REXDENT() do {\
	if (request->module) {\
		request->log.module_indent -= 2;\
	} else {\
		request->log.unlang_indent -= 2;\
	}\
	RDEBUG4("<< (%i) at %s[%u]", request->log.unlang_indent, __FILE__, __LINE__); \
} while(0)
#else
/** Indent R* messages by one level
 *
 * @note Has no effect on the indentation of INFO, WARN, ERROR, DEBUG messages,
 *	 only RINFO, RWARN, RERROR etc...
 */
#  define RINDENT() do {\
	if (request->module) {\
		request->log.module_indent += 2;\
	} else {\
		request->log.unlang_indent += 2;\
	}\
} while(0)

/** Exdent (unindent) R* messages by one level
 *
 * @note Has no effect on the indentation of INFO, WARN, ERROR, DEBUG messages,
 *	 only RINFO, RWARN, RERROR etc...
 */
#  define REXDENT() do {\
	if (request->module) {\
		request->log.module_indent -= 2;\
	} else {\
		request->log.unlang_indent -= 2;\
	}\
} while(0)
#endif

/** Output string with error marker, showing where format error occurred
 *
 @verbatim
   my pet kitty
      ^ kitties are not pets, are nature devouring hell beasts
 @endverbatim
 *
 * @warning If a REQUEST * is **NOT** available, or is NULL, this macro must **NOT** be used.
 *
 * @param _l log category, a fr_log_type_t value.
 * @param _p log priority, a fr_log_lvl_t value.
 * @param _m string to mark e.g. "my pet kitty".
 * @param _i index e.g. 3 (starts from 0).
 * @param _e error e.g. "kitties are not pets, are nature devouring hell beasts".
 */
#ifndef DEBUG_INDENT
#define RMARKER(_l, _p, _m, _i, _e)	log_request_marker(_l, _p, request, _m, _i, _e)
#else
#define RMARKER(_l, _p, _m, _i, _e) do { \
		RDEBUG4("== (0) at %s[%u]", __FILE__, __LINE__); \
		log_request_marker(_l, _p, request, _m, _i, _e); \
	} while (0)
#endif

/** Output string with error marker, showing where format error occurred
 *
 * These are logged as RERROR messages.
 *
 @verbatim
   my pet kitty
      ^ kitties are not pets, are nature devouring hell beasts
 @endverbatim
 *
 * @warning If a REQUEST * is **NOT** available, or is NULL, this macro must **NOT** be used.
 *
 * @param _m string to mark e.g. "my pet kitty".
 * @param _i index e.g. 3 (starts from 0).
 * @param _e error e.g. "kitties are not pets, are nature devouring hell beasts".
 */
#define REMARKER(_m, _i, _e)		RMARKER(L_DBG_ERR, L_DBG_LVL_1, _m, _i, _e)

/** Output string with error marker, showing where format error occurred
 *
 * These are logged as RDEBUG messages.
 *
 @verbatim
   my pet kitty
      ^ kitties are not pets, are nature devouring hell beasts
 @endverbatim
 *
 * @warning If a REQUEST * is **NOT** available, or is NULL, this macro must **NOT** be used.
 *
 * @param _m string to mark e.g. "my pet kitty".
 * @param _i index e.g. 3 (starts from 0).
 * @param _e error e.g. "kitties are not pets, are nature devouring hell beasts".
 */
#define RDMARKER(_m, _i, _e)		RMARKER(L_DBG, L_DBG_LVL_1, _m, _i, _e)

/** Use different logging functions depending on whether request is NULL or not.
 *
 * This is useful for areas of code which are run on server startup, and when
 * processing requests.
 *
 * @param _l_request The name of a R* logging macro e.g. RDEBUG3.
 * @param _l_global The name of a global logging macro e.g. DEBUG3.
 * @param fmt printf style format string.
 * @param ... printf arguments.
 */
#define ROPTIONAL(_l_request, _l_global, fmt, ...) \
do {\
	if (request) {\
		_l_request(fmt, ## __VA_ARGS__);\
	} else {\
		_l_global(fmt, ## __VA_ARGS__);\
 	}\
} while (0)

#define RATE_LIMIT_ENABLED fr_rate_limit_enabled()		//!< True if rate limiting is enabled.

/** Rate limit messages
 *
 * Rate limit log messages so they're written a maximum of once per second.
 *
 @code{.c}
   RATE_LIMIT(RERROR("Home servers alive in pool %s", pool->name));
 @endcode
 * @note Rate limits the macro, not the message. If five different messages are
 *	 produced using the same macro in the same second, only the first will
 *	 be written to the log.
 *
 * @param _x Logging macro to limit.
 */
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

#define RHEXDUMP(_lvl, _data, _len, _fmt, ...) \
	if (rad_debug_lvl >= _lvl) do { \
		log_request(L_DBG, _lvl, request, _fmt, ## __VA_ARGS__); \
		log_request_hex(L_DBG, _lvl, request, _data, _len); \
	} while (0)

#define RHEXDUMP_INLINE(_lvl, _data, _len, _fmt, ...) \
	if (rad_debug_lvl >= _lvl) do { \
		char *_tmp; \
		_tmp = talloc_array(NULL, char, ((_len) * 2) + 1); \
		fr_bin2hex(_tmp, _data, _len); \
		log_request(L_DBG, _lvl, request, _fmt " 0x%s", ## __VA_ARGS__, _tmp); \
		talloc_free(_tmp); \
	} while(0)


#ifdef __cplusplus
}
#endif
