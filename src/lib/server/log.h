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
 * @copyright 2015 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2013 Alan DeKok (aland@freeradius.org)
 */
RCSIDH(server_log_h, "$Id$")

/*
 *	Forward declarations
 */
#ifdef __cplusplus
extern "C" {
#endif

/** A logging destination, consisting of a function and its context
 *
 */
typedef struct log_dst log_dst_t;

#include <freeradius-devel/server/request.h>
#include <freeradius-devel/util/log.h>
#include <freeradius-devel/util/pair.h>

/** Logging callback to write log messages to a destination
 *
 * This allows the logging destination to be customised on a per request basis.
 *
 * @note Logging functions must not block waiting on I/O.
 *
 * @param[in] type	What type of message this is (error, warn, info, debug).
 * @param[in] lvl	At what logging level this message should be output.
 * @param[in] file	src file the log message was generated in.
 * @param[in] line	number the log message was generated on.
 * @param[in] request	The current request.
 * @param[in] fmt	sprintf style fmt string.
 * @param[in] ap	Arguments for the fmt string.
 * @param[in] uctx	Context data for the log function.  Usually an #fr_log_t for vlog_request.
 */
typedef	void (*log_func_t)(fr_log_type_t type, fr_log_lvl_t lvl, REQUEST *request,
			   char const *file, int line,
			   char const *fmt, va_list ap, void *uctx);

struct log_dst {
	log_func_t	func;	//!< Function to call to log to this destination.
	void		*uctx;	//!< Context to pass to the logging function.
	log_dst_t	*next;	//!< Next logging destination.
};

extern fr_table_num_sorted_t const syslog_facility_table[];
extern size_t syslog_facility_table_len;
extern fr_table_num_sorted_t const syslog_severity_table[];
extern size_t syslog_severity_table_len;
extern fr_table_num_sorted_t const log_str2dst[];
extern size_t log_str2dst_len;

#define debug_enabled(_type, _lvl) (((_type & L_DBG) != 0) && (_lvl <= fr_debug_lvl))

bool	log_rdebug_enabled(fr_log_lvl_t lvl, REQUEST *request) CC_HINT(nonnull);

void	vlog_request(fr_log_type_t type, fr_log_lvl_t lvl, REQUEST *request,
		     char const *file, int line,
		     char const *fmt, va_list ap, void *uctx)
	CC_HINT(format (printf, 6, 0)) CC_HINT(nonnull (3, 4));

void	log_request(fr_log_type_t type, fr_log_lvl_t lvl, REQUEST *request,
		    char const *file, int line,
		    char const *fmt, ...)
		    CC_HINT(format (printf, 6, 7)) CC_HINT(nonnull (3, 6));

void	log_module_failure_msg(REQUEST *request, char const *fmt, ...)
	CC_HINT(format (printf, 2, 3));

void	vlog_module_failure_msg(REQUEST *request, char const *fmt, va_list ap)
	CC_HINT(format (printf, 2, 0));

void	log_request_error(fr_log_type_t type, fr_log_lvl_t lvl, REQUEST *request,
			  char const *file, int line,
			  char const *fmt, ...)
	CC_HINT(format (printf, 6, 7)) CC_HINT(nonnull (3, 6));

void	log_request_perror(fr_log_type_t type, fr_log_lvl_t lvl, REQUEST *request,
			   char const *file, int line, char const *fmt, ...)
	CC_HINT(format (printf, 6, 7)) CC_HINT(nonnull (3));

void	log_request_pair_list(fr_log_lvl_t lvl, REQUEST *request, VALUE_PAIR *vp, char const *prefix);

void	log_request_proto_pair_list(fr_log_lvl_t lvl, REQUEST *request, VALUE_PAIR *vp, char const *prefix);

void 	log_request_marker(fr_log_type_t type, fr_log_lvl_t lvl, REQUEST *request,
			   char const *file, int line,
			   char const *str, size_t idx,
			   char const *fmt, ...) CC_HINT(format (printf, 8, 9)) CC_HINT(nonnull);

void	log_request_hex(fr_log_type_t type, fr_log_lvl_t lvl, REQUEST *request,
			char const *file, int line,
			uint8_t const *data, size_t data_len) CC_HINT(nonnull);

void	log_fatal(fr_log_t const *log, char const *file, int line, char const *fmt, ...)
	CC_HINT(format (printf, 4, 5)) CC_HINT(noreturn);

int	log_global_init(fr_log_t *log, bool daemonize);

void	log_global_free(void);

/*
 *  Sets the default log destination for global messages
 */
#ifndef LOG_DST
#  define LOG_DST &default_log
#endif
#define _FR_LOG_DST(_lvl, _fmt, ...) fr_log(LOG_DST, _lvl, __FILE__, __LINE__, _fmt, ## __VA_ARGS__)
#define _FR_LOG_DST_PERROR(_lvl, _fmt, ...) fr_log_perror(LOG_DST, _lvl, __FILE__, __LINE__, _fmt, ## __VA_ARGS__)
#define _FR_LOG_DST_FATAL(_fmt, ...) log_fatal(LOG_DST, __FILE__, __LINE__, _fmt, ## __VA_ARGS__)

/*
 *  Adds a default prefix to all messages in a source file
 *
 *  The prefix is set with LOG_PREFIX, and arguments may
 *  be passed with LOG_PREFIX_ARGS
 */
#ifndef LOG_PREFIX
#  define LOG_PREFIX ""
#endif
#ifdef LOG_PREFIX_ARGS
#  define _FR_LOG_PREFIX(_lvl, _fmt, ...) _FR_LOG_DST(_lvl, LOG_PREFIX _fmt, LOG_PREFIX_ARGS, ## __VA_ARGS__)
#  define _FR_LOG_PREFIX_PERROR(_lvl, _fmt, ...) _FR_LOG_DST_PERROR(_lvl, LOG_PREFIX _fmt, LOG_PREFIX_ARGS, ## __VA_ARGS__)
#  define _FR_LOG_PREFIX_FATAL(_fmt, ...) _FR_LOG_DST_FATAL(LOG_PREFIX _fmt, LOG_PREFIX_ARGS, ## __VA_ARGS__)
#else
#  define _FR_LOG_PREFIX(_lvl, _fmt, ...) _FR_LOG_DST(_lvl, LOG_PREFIX _fmt, ## __VA_ARGS__)
#  define _FR_LOG_PREFIX_PERROR(_lvl, _fmt, ...) _FR_LOG_DST_PERROR(_lvl, LOG_PREFIX _fmt, ## __VA_ARGS__)
#  define _FR_LOG_PREFIX_FATAL(_fmt, ...) _FR_LOG_DST_FATAL(LOG_PREFIX _fmt, ## __VA_ARGS__)
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
 * INFO     | LOG_INFO                | Bold         | TBD
 * WARN     | LOG_WARNING             | Yellow       | Warnings. Impending resource exhaustion, resource exhaustion
 * ERROR    | LOG_ERR                 | Red          | Critical server errors. Malformed queries, failed operations, connection errors, packet processing errors
 *
 * @{
 */
#define INFO(_fmt, ...)		_FR_LOG_PREFIX(L_INFO, _fmt, ## __VA_ARGS__)
#define WARN(_fmt, ...)		_FR_LOG_PREFIX(L_WARN, _fmt, ## __VA_ARGS__)
#define ERROR(_fmt, ...)	_FR_LOG_PREFIX(L_ERR, _fmt, ## __VA_ARGS__)
#define FATAL(_fmt, ...)	_FR_LOG_PREFIX_FATAL(_fmt, ## __VA_ARGS__)

#define PINFO(_fmt, ...)	_FR_LOG_PREFIX_PERROR(L_INFO, _fmt, ## __VA_ARGS__)
#define PWARN(_fmt, ...)	_FR_LOG_PREFIX_PERROR(L_WARN, _fmt, ## __VA_ARGS__)
#define PERROR(_fmt, ...)	_FR_LOG_PREFIX_PERROR(L_ERR, _fmt, ## __VA_ARGS__)


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

#define _DEBUG_LOG(_type, _lvl, _fmt, ...)	if (fr_debug_lvl >= _lvl) _FR_LOG_PREFIX(_type, _fmt, ## __VA_ARGS__)
#define DEBUG(_fmt, ...)		_DEBUG_LOG(L_DBG, L_DBG_LVL_1, _fmt, ## __VA_ARGS__)
#define DEBUG2(_fmt, ...)		_DEBUG_LOG(L_DBG, L_DBG_LVL_2, _fmt, ## __VA_ARGS__)
#define DEBUG3(_fmt, ...)		_DEBUG_LOG(L_DBG, L_DBG_LVL_3, _fmt, ## __VA_ARGS__)
#define DEBUG4(_fmt, ...)		_DEBUG_LOG(L_DBG, L_DBG_LVL_MAX, _fmt, ## __VA_ARGS__)
#define DEBUGX(_lvl, _fmt, ...)		_DEBUG_LOG(L_DBG, _lvl, _fmt, ## __VA_ARGS__)

#define _PDEBUG_LOG(_type, _lvl, _fmt, ...)	if (fr_debug_lvl >= _lvl) _FR_LOG_PREFIX_PERROR(_type, _fmt, ## __VA_ARGS__)
#define PDEBUG(_fmt, ...)		_PDEBUG_LOG(L_DBG, L_DBG_LVL_1, _fmt, ## __VA_ARGS__)
#define PDEBUG2(_fmt, ...)		_PDEBUG_LOG(L_DBG, L_DBG_LVL_2, _fmt, ## __VA_ARGS__)
#define PDEBUG3(_fmt, ...)		_PDEBUG_LOG(L_DBG, L_DBG_LVL_3, _fmt, ## __VA_ARGS__)
#define PDEBUG4(_fmt, ...)		_PDEBUG_LOG(L_DBG, L_DBG_LVL_MAX, _fmt, ## __VA_ARGS__)
#define PDEBUGX(_lvl, _fmt, ...)		_PDEBUG_LOG(L_DBG, _lvl, _fmt, ## __VA_ARGS__)
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
 * RINFO    | LOG_INFO                | Bold         | TBD
 * RWARN    | LOG_WARNING             | Yellow/Bold  | Warnings. Impending resource exhaustion, or resource exhaustion.
 * RERROR   | LOG_ERR                 | Red/Bold     | Critical server errors. Malformed queries, failed operations, connection errors, packet processing errors.
 * @{
 */
#define RINFO(fmt, ...)		log_request(L_INFO, L_DBG_LVL_OFF, request, __FILE__, __LINE__, fmt, ## __VA_ARGS__)
#define RWARN(fmt, ...)		log_request(L_DBG_WARN, L_DBG_LVL_OFF, request, __FILE__, __LINE__, fmt, ## __VA_ARGS__)
#define RERROR(fmt, ...)	log_request_error(L_DBG_ERR, L_DBG_LVL_OFF, request, __FILE__, __LINE__, fmt, ## __VA_ARGS__)

#define RPINFO(fmt, ...)	log_request_perror(L_DBG_INFO, L_DBG_LVL_OFF, request, __FILE__, __LINE__, fmt, ## __VA_ARGS__)
#define RPWARN(fmt, ...)	log_request_perror(L_DBG_WARN, L_DBG_LVL_OFF, request, __FILE__, __LINE__, fmt, ## __VA_ARGS__)
#define RPERROR(fmt, ...)	log_request_perror(L_DBG_ERR, L_DBG_LVL_OFF, request, __FILE__, __LINE__, fmt, ## __VA_ARGS__)
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
 * 1        | ``-x``                  | R*DEBUG               | Packet processing, entering/exiting virtual servers, results of module calls
 * 2        | ``-xx`` or ``-X``       | R*DEBUG, R*DEBUG2     | Unlang keyword evaluation. Module debug output, results of queries, or execs, etc...
 * 3        | ``-xxx`` or ``-Xx``     | R*DEBUG, R*DEBUG[2-3] | Internal server state or packet input. State machine changes, extra attribute info, etc...
 * 4        | ``-xxxx`` or ``-Xxx``   | R*DEBUG, R*DEBUG[2-4] | Verbose internal server state messages or packet input. Hex dumps, structure dumps, pointer values.
 * 5        | ``-xxxxx`` or ``-Xxxx`` | R*DEBUG, R*DEBUG[2-5] | Low level internal server state messages.
 *
 * @{
 */
#define RDEBUG_ENABLED		log_rdebug_enabled(L_DBG_LVL_1, request)		//!< True if request debug level 1 messages are enabled
#define RDEBUG_ENABLED2		log_rdebug_enabled(L_DBG_LVL_2, request)		//!< True if request debug level 1-2 messages are enabled
#define RDEBUG_ENABLED3		log_rdebug_enabled(L_DBG_LVL_3, request)		//!< True if request debug level 1-3 messages are enabled
#define RDEBUG_ENABLED4		log_rdebug_enabled(L_DBG_LVL_4, request)		//!< True if request debug level 1-4 messages are enabled
#define RDEBUG_ENABLED5		log_rdebug_enabled(L_DBG_LVL_MAX, request)	//!< True if request debug level 1-5 messages are enabled

#define RDEBUGX(_l, fmt, ...)	do { if (request->log.lvl) log_request(L_DBG, _l, request, __FILE__, __LINE__, fmt, ## __VA_ARGS__); } while(0)
#define RDEBUG(fmt, ...)	do { if (request->log.lvl) log_request(L_DBG, L_DBG_LVL_1, request, __FILE__, __LINE__, fmt, ## __VA_ARGS__); } while(0)
#define RDEBUG2(fmt, ...)	do { if (request->log.lvl) log_request(L_DBG, L_DBG_LVL_2, request, __FILE__, __LINE__, fmt, ## __VA_ARGS__); } while(0)
#define RDEBUG3(fmt, ...)	do { if (request->log.lvl) log_request(L_DBG, L_DBG_LVL_3, request, __FILE__, __LINE__, fmt, ## __VA_ARGS__); } while(0)
#define RDEBUG4(fmt, ...)	do { if (request->log.lvl) log_request(L_DBG, L_DBG_LVL_4, request, __FILE__, __LINE__, fmt, ## __VA_ARGS__); } while(0)

#define RPDEBUG(fmt, ...)	do { if (request->log.lvl) log_request_perror(L_DBG, L_DBG_LVL_1, request, __FILE__, __LINE__, fmt, ## __VA_ARGS__); } while(0)
#define RPDEBUG2(fmt, ...)	do { if (request->log.lvl) log_request_perror(L_DBG, L_DBG_LVL_2, request, __FILE__, __LINE__, fmt, ## __VA_ARGS__); } while(0)
#define RPDEBUG3(fmt, ...)	do { if (request->log.lvl) log_request_perror(L_DBG, L_DBG_LVL_3, request, __FILE__, __LINE__, fmt, ## __VA_ARGS__); } while(0)
#define RPDEBUG4(fmt, ...)	do { if (request->log.lvl) log_request_perror(L_DBG, L_DBG_LVL_4, request, __FILE__, __LINE__, fmt, ## __VA_ARGS__); } while(0)

#define RIDEBUG(fmt, ...)	do { if (request->log.lvl) log_request(L_DBG_INFO, L_DBG_LVL_1, request, __FILE__, __LINE__, fmt, ## __VA_ARGS__); } while(0)
#define RIDEBUG2(fmt, ...)	do { if (request->log.lvl) log_request(L_DBG_INFO, L_DBG_LVL_2, request, __FILE__, __LINE__, fmt, ## __VA_ARGS__); } while(0)
#define RIDEBUG3(fmt, ...)	do { if (request->log.lvl) log_request(L_DBG_INFO, L_DBG_LVL_3, request, __FILE__, __LINE__, fmt, ## __VA_ARGS__); } while(0)
#define RIDEBUG4(fmt, ...)	do { if (request->log.lvl) log_request(L_DBG_INFO, L_DBG_LVL_4, request, __FILE__, __LINE__, fmt, ## __VA_ARGS__); } while(0)

#define RPIDEBUG(fmt, ...)	do { if (request->log.lvl) log_request_perror(L_DBG_INFO, L_DBG_LVL_1, request, __FILE__, __LINE__, fmt, ## __VA_ARGS__); } while(0)
#define RPIDEBUG2(fmt, ...)	do { if (request->log.lvl) log_request_perror(L_DBG_INFO, L_DBG_LVL_2, request, __FILE__, __LINE__, fmt, ## __VA_ARGS__); } while(0)
#define RPIDEBUG3(fmt, ...)	do { if (request->log.lvl) log_request_perror(L_DBG_INFO, L_DBG_LVL_3, request, __FILE__, __LINE__, fmt, ## __VA_ARGS__); } while(0)
#define RPIDEBUG4(fmt, ...)	do { if (request->log.lvl) log_request_perror(L_DBG_INFO, L_DBG_LVL_4, request, __FILE__, __LINE__, fmt, ## __VA_ARGS__); } while(0)

#define RWDEBUG(fmt, ...)	do { if (request->log.lvl) log_request(L_DBG_WARN, L_DBG_LVL_1, request, __FILE__, __LINE__, fmt, ## __VA_ARGS__); } while(0)
#define RWDEBUG2(fmt, ...)	do { if (request->log.lvl) log_request(L_DBG_WARN, L_DBG_LVL_2, request, __FILE__, __LINE__, fmt, ## __VA_ARGS__); } while(0)
#define RWDEBUG3(fmt, ...)	do { if (request->log.lvl) log_request(L_DBG_WARN, L_DBG_LVL_3, request, __FILE__, __LINE__, fmt, ## __VA_ARGS__); } while(0)
#define RWDEBUG4(fmt, ...)	do { if (request->log.lvl) log_request(L_DBG_WARN, L_DBG_LVL_4, request, __FILE__, __LINE__, fmt, ## __VA_ARGS__); } while(0)

#define RPWDEBUG(fmt, ...)	do { if (request->log.lvl) log_request_perror(L_DBG_WARN, L_DBG_LVL_1, request, __FILE__, __LINE__, fmt, ## __VA_ARGS__); } while(0)
#define RPWDEBUG2(fmt, ...)	do { if (request->log.lvl) log_request_perror(L_DBG_WARN, L_DBG_LVL_2, request, __FILE__, __LINE__, fmt, ## __VA_ARGS__); } while(0)
#define RPWDEBUG3(fmt, ...)	do { if (request->log.lvl) log_request_perror(L_DBG_WARN, L_DBG_LVL_3, request, __FILE__, __LINE__, fmt, ## __VA_ARGS__); } while(0)
#define RPWDEBUG4(fmt, ...)	do { if (request->log.lvl) log_request_perror(L_DBG_WARN, L_DBG_LVL_4, request, __FILE__, __LINE__, fmt, ## __VA_ARGS__); } while(0)

#define REDEBUG(fmt, ...)	log_request_error(L_DBG_ERR, L_DBG_LVL_1, request, __FILE__, __LINE__, fmt, ## __VA_ARGS__)
#define REDEBUG2(fmt, ...)	log_request_error(L_DBG_ERR, L_DBG_LVL_2, request, __FILE__, __LINE__, fmt, ## __VA_ARGS__)
#define REDEBUG3(fmt, ...)	log_request_error(L_DBG_ERR, L_DBG_LVL_3,request,  __FILE__, __LINE__, fmt, ## __VA_ARGS__)
#define REDEBUG4(fmt, ...)	log_request_error(L_DBG_ERR, L_DBG_LVL_MAX, request, __FILE__, __LINE__, fmt, ## __VA_ARGS__)

#define RPEDEBUG(fmt, ...)	log_request_perror(L_DBG_ERR, L_DBG_LVL_1, request, __FILE__, __LINE__, fmt, ## __VA_ARGS__)
#define RPEDEBUG2(fmt, ...)	log_request_perror(L_DBG_ERR, L_DBG_LVL_2, request, __FILE__, __LINE__, fmt, ## __VA_ARGS__)
#define RPEDEBUG3(fmt, ...)	log_request_perror(L_DBG_ERR, L_DBG_LVL_3, request, __FILE__, __LINE__, fmt, ## __VA_ARGS__)
#define RPEDEBUG4(fmt, ...)	log_request_perror(L_DBG_ERR, L_DBG_LVL_MAX, request, __FILE__, __LINE__, fmt, ## __VA_ARGS__)
/** @} */

#ifdef DEBUG_INDENT
/** Indent R* messages by one level
 *
 * @note Has no effect on the indentation of INFO, WARN, ERROR, DEBUG messages,
 *	 only RINFO, RWARN, RERROR etc...
 */
#  define RINDENT() do {\
	RDEBUG4(">> (%i)", request->log.unlang_indent); \
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
	RDEBUG4("<< (%i)", request->log.unlang_indent); \
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
 * @param[in] _type	log category, a #fr_log_type_t value.
 * @param[in] _lvl	log priority, a #fr_log_lvl_t value.
 * @param[in] _str	to mark e.g. "my pet kitty".
 * @param[in] _idx	index e.g. 3 (starts from 0).
 * @param[in] _fmt	error message e.g. "kitties are not pets, are nature devouring hell beasts".
 * @param[in] ...	arguments for error string.
 */
#ifndef DEBUG_INDENT
#define RMARKER(_type, _lvl, _str, _idx, _fmt, ...) \
	log_request_marker(_type, _lvl, request, \
			   __FILE__, __LINE__, \
			   _str, _idx, _fmt, ## __VA_ARGS__)
#else
#define RMARKER(_type, _lvl, _str, _idx, _fmt, ...) do { \
		RDEBUG4("== (0) at %s[%u]", __FILE__, __LINE__); \
		log_request_marker(_type, _lvl, request, __FILE__, __LINE__, _str, _idx, _fmt, ## __VA_ARGS__); \
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
 * @param[in] _str	to mark e.g. "my pet kitty".
 * @param[in] _idx	index e.g. 3 (starts from 0).
 * @param[in] _fmt	error message e.g. "kitties are not pets, are nature devouring hell beasts".
 * @param[in] ...	arguments for error string.
 */
#define REMARKER(_str, _idx, _fmt, ...)	RMARKER(L_DBG_ERR, L_DBG_LVL_1, _str, _idx, _fmt, ## __VA_ARGS__)

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
 * @param[in] _str	to mark e.g. "my pet kitty".
 * @param[in] _idx	index e.g. 3 (starts from 0).
 * @param[in] _fmt	error message e.g. "kitties are not pets, are nature devouring hell beasts".
 * @param[in] ...	arguments for error string.
 */
#define RDMARKER(_str, _idx, _fmt, ...)	RMARKER(L_DBG, L_DBG_LVL_1, _str, _idx, _fmt, ## __VA_ARGS__)

/** Use different logging functions depending on whether request is NULL or not.
 *
 * This is useful for areas of code which are run on server startup, and when
 * processing requests.
 *
 * @param[in] _l_request	The name of a R* logging macro e.g. RDEBUG3.
 * @param[in] _l_global		The name of a global logging macro e.g. DEBUG3.
 * @param[in] _fmt		printf style format string.
 * @param[in] ...		printf arguments.
 */
#define ROPTIONAL(_l_request, _l_global, _fmt, ...) \
do {\
	if (request) {\
		_l_request(_fmt, ## __VA_ARGS__);\
	} else {\
		_l_global(_fmt, ## __VA_ARGS__);\
 	}\
} while (0)

/** Track when a log message was last repeated
 *
 */
typedef struct {
	time_t		now;			//!< Current time - Here because it avoids repeated stack allocation.
	time_t		last_complained;	//!< Last time we emitted a log message.
	unsigned int	repeated;		//!< Number of "skipped" messages.
} fr_rate_limit_t;

/** Rate limit messages using a local limiting entry
 *
 * Rate limit log messages so they're written a maximum of once per second.
 *
 @code{.c}
   RATE_LIMIT(&inst->home_server_alive_rate_limit, RERROR, "Home servers alive in pool %s", pool->name));
 @endcode
 * @note Rate limits the macro, not the message. If five different messages are
 *	 produced using the same macro in the same second, only the first will
 *	 be written to the log.
 *
 * @param[in] _entry		Used to track rate limiting.
 * @param[in] _log		Logging macro.
 * @param[in] _fmt		printf style format string.
 * @param[in] ...		printf arguments.
 */
#define RATE_LIMIT_LOCAL(_entry, _log, _fmt, ...) \
do {\
	if (fr_rate_limit_enabled()) {\
		(_entry)->now = time(NULL);\
		if ((_entry)->now != (_entry)->last_complained) {\
			(_entry)->last_complained = (_entry)->now;\
			if (((_entry)->repeated > 0) && (((_entry)->now - (_entry)->last_complained) == 1)) { \
				_log(_fmt " - repeated %u time(s)", ##__VA_ARGS__, (_entry)->repeated); \
			} else { \
				_log(_fmt, ##__VA_ARGS__); \
			}\
			(_entry)->repeated = 0; \
		} else { \
			(_entry)->repeated++; \
		} \
	} else (_log(_fmt, ##__VA_ARGS__));\
} while (0)

/** Rate limit messages using a local limiting entry
 *
 * Rate limit log messages so they're written a maximum of once per second.
 * The ROPTIOANL variant allows different logging macros to be used based on whether a request is
 * available.
 *
 @code{.c}
   RATE_LIMIT(&inst->home_server_alive_rate_limit, RERROR, "Home servers alive in pool %s", pool->name));
 @endcode
 * @note Rate limits the macro, not the message. If five different messages are
 *	 produced using the same macro in the same second, only the first will
 *	 be written to the log.
 *
 * @param[in] _entry		Used to track rate limiting.
 * @param[in] _l_request	The name of a R* logging macro e.g. RDEBUG3.
 * @param[in] _l_global		The name of a global logging macro e.g. DEBUG3.
 * @param[in] _fmt		printf style format string.
 * @param[in] ...		printf arguments.
 */
#define RATE_LIMIT_LOCAL_ROPTIONAL(_entry, _l_request, _l_global, _fmt, ...) \
do {\
	if (fr_rate_limit_enabled()) {\
		(_entry)->now = time(NULL);\
		if ((_entry)->now != (_entry)->last_complained) {\
			(_entry)->last_complained = (_entry)->now;\
			if (((_entry)->repeated > 0) && (((_entry)->now - (_entry)->last_complained) == 1)) { \
				ROPTIONAL(_l_request, _l_global, _fmt " - repeated %u time(s)", ##__VA_ARGS__, (_entry)->repeated); \
			} else { \
				ROPTIONAL(_l_request, _l_global, _fmt, ##__VA_ARGS__); \
			}\
			(_entry)->repeated = 0; \
		} else { \
			(_entry)->repeated++; \
		} \
	} else { \
		ROPTIONAL(_l_request, _l_global, _fmt, ##__VA_ARGS__);\
	} \
} while (0)

/** Rate limit messages using a global limiting entry
 *
 * Rate limit log messages so they're written a maximum of once per second.
 *
 @code{.c}
   RATE_LIMIT(RERROR, "Home servers alive in pool %s", pool->name));
 @endcode
 * @note Rate limits the macro, not the message. If five different messages are
 *	 produced using the same macro in the same second, only the first will
 *	 be written to the log.
 *
 * @param[in] _log		Logging macro.
 * @param[in] _fmt		printf style format string.
 * @param[in] ...		printf arguments.
 */
#define RATE_LIMIT_GLOBAL(_log, _fmt, ...) \
do {\
	static fr_rate_limit_t	_rate_limit; \
	RATE_LIMIT_LOCAL(&_rate_limit, _log, _fmt, ##__VA_ARGS__); \
} while (0)

/** Rate limit messages using a global limiting entry
 *
 * Rate limit log messages so they're written a maximum of once per second.
 *
 @code{.c}
   RATE_LIMIT(RERROR, "Home servers alive in pool %s", pool->name));
 @endcode
 * @note Rate limits the macro, not the message. If five different messages are
 *	 produced using the same macro in the same second, only the first will
 *	 be written to the log.
 *
 * @param[in] _l_request	The name of a R* logging macro e.g. RDEBUG3.
 * @param[in] _l_global		The name of a global logging macro e.g. DEBUG3.
 * @param[in] _fmt		printf style format string.
 * @param[in] ...		printf arguments.
 */
#define RATE_LIMIT_GLOBAL_ROPTIONAL(_l_request, _l_global, _fmt, ...) \
do {\
	static fr_rate_limit_t _rate_limit; \
	RATE_LIMIT_LOCAL_ROPTIONAL(&_rate_limit, _l_request, _l_global, _fmt, ##__VA_ARGS__); \
} while (0)

/** Pretty print binary data, with hex output inline with message
 *
 * Output format is @verbatim <msg>0x<hex string> @endverbatim.
 *
 * @param[in] _lvl	Debug level at which we start emitting the log message.
 * @param[in] _data	Binary data to print.
 * @param[in] _len	Length of binary data.
 * @param[in] _fmt	Message to prefix hex output with.
 * @param[in] ...	Additional arguments to print.
 */
#define _RHEXDUMP_INLINE(_lvl, _data, _len, _fmt, ...) \
	if (log_rdebug_enabled(_lvl, request)) { \
		log_request(L_DBG, _lvl, request, __FILE__, __LINE__, _fmt " 0x%pH", ## __VA_ARGS__, fr_box_octets(_data, _len)); \
	}

#define RHEXDUMP_INLINE1(_data, _len, _fmt, ...) _RHEXDUMP_INLINE(L_DBG_LVL_1, _data, _len, _fmt, ## __VA_ARGS__)
#define RHEXDUMP_INLINE2(_data, _len, _fmt, ...) _RHEXDUMP_INLINE(L_DBG_LVL_2, _data, _len, _fmt, ## __VA_ARGS__)
#define RHEXDUMP_INLINE3(_data, _len, _fmt, ...) _RHEXDUMP_INLINE(L_DBG_LVL_3, _data, _len, _fmt, ## __VA_ARGS__)
#define RHEXDUMP_INLINE4(_data, _len, _fmt, ...) _RHEXDUMP_INLINE(L_DBG_LVL_4, _data, _len, _fmt, ## __VA_ARGS__)

/** Pretty print binary data as hex, with output as a wrapped block with addresses
 *
 * @param[in] _lvl	Debug level at which we start emitting the log message.
 * @param[in] _data	Binary data to print.
 * @param[in] _len	Length of binary data.
 * @param[in] _fmt	Message to print as a header to the hex output.
 * @param[in] ...	Additional arguments to print.
 */
#define _RHEXDUMP(_lvl, _data, _len, _fmt, ...) \
	if (log_rdebug_enabled(_lvl, request)) do { \
		log_request(L_DBG, _lvl, request, __FILE__, __LINE__, _fmt, ## __VA_ARGS__); \
		log_request_hex(L_DBG, _lvl, request, __FILE__, __LINE__, _data, _len); \
	} while (0)

#define RHEXDUMP1(_data, _len, _fmt, ...) _RHEXDUMP(L_DBG_LVL_1, _data, _len, _fmt, ## __VA_ARGS__)
#define RHEXDUMP2(_data, _len, _fmt, ...) _RHEXDUMP(L_DBG_LVL_2, _data, _len, _fmt, ## __VA_ARGS__)
#define RHEXDUMP3(_data, _len, _fmt, ...) _RHEXDUMP(L_DBG_LVL_3, _data, _len, _fmt, ## __VA_ARGS__)
#define RHEXDUMP4(_data, _len, _fmt, ...) _RHEXDUMP(L_DBG_LVL_4, _data, _len, _fmt, ## __VA_ARGS__)

/** Pretty print binary data as hex, with output as a wrapped block with addresses
 *
 * @param[in] _lvl	Debug level at which we start emitting the log message.
 * @param[in] _data	Binary data to print.
 * @param[in] _len	Length of binary data.
 * @param[in] _fmt	Message to prefix hex output with.
 * @param[in] ...	Additional arguments to print.
 */
#define _HEXDUMP(_lvl, _data, _len, _fmt, ...) \
	if (debug_enabled(L_DBG, _lvl)) do { \
		fr_log_hex(LOG_DST, L_DBG, __FILE__, __LINE__, _data, _len, _fmt, ## __VA_ARGS__); \
	} while (0)

#define HEXDUMP1(_data, _len, _fmt, ...) _HEXDUMP(L_DBG_LVL_1, _data, _len, _fmt, ## __VA_ARGS__)
#define HEXDUMP2(_data, _len, _fmt, ...) _HEXDUMP(L_DBG_LVL_2, _data, _len, _fmt, ## __VA_ARGS__)
#define HEXDUMP3(_data, _len, _fmt, ...) _HEXDUMP(L_DBG_LVL_3, _data, _len, _fmt, ## __VA_ARGS__)
#define HEXDUMP4(_data, _len, _fmt, ...) _HEXDUMP(L_DBG_LVL_4, _data, _len, _fmt, ## __VA_ARGS__)

/** Pretty print binary data as hex, with output as a wrapped block with addresses and a marker
 *
 * @param[in] _lvl	Debug level at which we start emitting the log message.
 * @param[in] _data	Binary data to print.
 * @param[in] _len	Length of binary data.
 * @param[in] _slen	Where the marker should be placed.
 * @param[in] _error	to print after the marker.
 * @param[in] _fmt	Message to prefix hex output with.
 * @param[in] ...	Additional arguments to print.
 */
#define _HEX_MARKER(_lvl, _data, _len, _slen, _error, _fmt, ...) \
	if (debug_enabled(L_DBG, _lvl)) do { \
		fr_log_hex_marker(LOG_DST, L_DBG, __FILE__, __LINE__, _data, _len, _slen, _error, _fmt, ## __VA_ARGS__); \
	} while (0)

#define HEX_MARKER1(_data, _len, _slen, _error, _fmt, ...) _HEX_MARKER(L_DBG_LVL_1, _data, _len, _slen, _error, _fmt, ## __VA_ARGS__)
#define HEX_MARKER2(_data, _len, _slen, _error, _fmt, ...) _HEX_MARKER(L_DBG_LVL_2, _data, _len, _slen, _error, _fmt, ## __VA_ARGS__)
#define HEX_MARKER3(_data, _len, _slen, _error, _fmt, ...) _HEX_MARKER(L_DBG_LVL_3, _data, _len, _slen, _error, _fmt, ## __VA_ARGS__)
#define HEX_MARKER4(_data, _len, _slen, _error, _fmt, ...) _HEX_MARKER(L_DBG_LVL_4, _data, _len, _slen, _error, _fmt, ## __VA_ARGS__)
