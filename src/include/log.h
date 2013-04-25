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

typedef enum log_lvl {
	L_AUTH = 2,		//!< Authentication message.
	L_INFO = 3,		//!< Informational message.
	L_ERR = 4,		//!< Error message.
	L_WARN = 5,		//!< Warning.
	L_PROXY	= 6,		//!< Proxy messages
	L_ACCT = 7,		//!< Accounting messages

	L_DBG = 16,		//!< Only displayed when debugging is enabled.
	L_DBG_WARN = 17,	//!< Warning only displayed when debugging is enabled.
	L_DBG_ERR = 18,		//!< Error only displayed when debugging is enabled.
	L_DBG_WARN2 = 19,	//!< Less severe warning only displayed when debugging is enabled.
	L_DBG_ERR2 = 20		//!< Less severe warning only displayed when debugging is enabled.
} log_lvl_t;

typedef enum log_dst {
	RADLOG_STDOUT = 0,	//!< Log to stdout.
	RADLOG_FILES,		//!< Log to a file on disk.
	RADLOG_SYSLOG,		//!< Log to syslog.
	RADLOG_STDERR,		//!< Log to stderr.
	RADLOG_NULL,		//!< Discard log messages.
	RADLOG_NUM_DEST
} log_dst_t;

typedef struct fr_log_t {
	int		colourise;
	int		fd;
	log_dst_t	dest;
	char		*file;
	char		*debug_file;
} fr_log_t;

extern FR_NAME_NUMBER const syslog_str2fac[];
extern FR_NAME_NUMBER const log_str2dst[];
extern fr_log_t default_log;

int		vradlog(int, char const *, va_list ap);
int		radlog(int, char const *, ...)
#ifdef __GNUC__
		__attribute__ ((format (printf, 2, 3)))
#endif
;
int		log_debug(char const *, ...)
;
void 		vp_listdebug(VALUE_PAIR *vp);
void radlog_request(int lvl, int priority, REQUEST *request, char const *msg, ...)
#ifdef __GNUC__
		__attribute__ ((format (printf, 4, 5)))
#endif
;

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
 *	*[IWE]DEBUG[0-9]?	- Macros with I, W, E after the prefix, will log with the priority specified by the
 *				  integer if the server or request log level at or above that integer. If there
 *				  is no integer the level is 1.
 */
 
/*
 *	Log server driven messages like threadpool exhaustion and connection failures
 */
#define _SL(_l, _p, _f, ...)	if (debug_flag >= _p) radlog(_l, _f, ## __VA_ARGS__)
 
#define AUTH(fmt, ...)		_SL(L_AUTH, 0, fmt, ## __VA_ARGS__)
#define ACCT(fmt, ...)		_SL(L_ACCT, 0, fmt, ## __VA_ARGS__)
#define PROXY(fmt, ...)		_SL(L_PROXY, 0, fmt, ## __VA_ARGS__)
 
#define DEBUG(fmt, ...)		_SL(L_DBG, 1, fmt, ## __VA_ARGS__)
#define DEBUG2(fmt, ...)	_SL(L_DBG, 2, fmt, ## __VA_ARGS__)
#define DEBUG3(fmt, ...)	_SL(L_DBG, 3, fmt, ## __VA_ARGS__)
#define DEBUG4(fmt, ...)	_SL(L_DBG, 4, fmt, ## __VA_ARGS__)
 
#define INFO(fmt, ...)		_SL(L_INFO, 0, fmt, ## __VA_ARGS__)
#define DEBUGI(fmt, ...)	_SL(L_INFO, 1, fmt, ## __VA_ARGS__)
 
#define WARN(fmt, ...)		_SL(L_WARN, 0, fmt, ## __VA_ARGS__)
#define WDEBUG(fmt, ...)	_SL(L_WARN, 1, fmt, ## __VA_ARGS__)
#define WDEBUG2(fmt, ...)	_SL(L_WARN, 2, fmt, ## __VA_ARGS__)
 
#define ERROR(fmt, ...)		_SL(L_ERR, 0, fmt, ## __VA_ARGS__)
#define EDEBUG(fmt, ...)	_SL(L_ERR, 1, fmt, ## __VA_ARGS__)
#define EDEBUG2(fmt, ...)	_SL(L_ERR, 1, fmt, ## __VA_ARGS__)
 
/*
 *	Log request driven messages which including elements from the current request, like section and module
 *
 *	If a REQUEST * is available, these functions should be used.
 */
#define _RL(_l, _p, _f, ...)	if (request && request->radlog) request->radlog(_l, _p, request, _f, ## __VA_ARGS__)
#define _RM(_l, _p, _f, ...)	do { \
					if(request) { \
						module_failure_msg(request, _f, ## __VA_ARGS__); \
						_RL(_l, _p, _f, ## __VA_ARGS__); \
					} \
				} while(0)
				
#define RAUTH(fmt, ...)		_RL(L_AUTH, 0, fmt, ## __VA_ARGS__)
#define RACCT(fmt, ...)		_RL(L_PROXY, 0, fmt, ## __VA_ARGS__)
#define RPROXY(fmt, ...)	_RL(L_PROXY, 0, fmt, ## __VA_ARGS__)
 
#define RDEBUG(fmt, ...)	_RL(L_DBG, 1, fmt, ## __VA_ARGS__)
#define RDEBUG2(fmt, ...)	_RL(L_DBG, 2, fmt, ## __VA_ARGS__)
#define RDEBUG3(fmt, ...)	_RL(L_DBG, 3, fmt, ## __VA_ARGS__)
#define RDEBUG4(fmt, ...)	_RL(L_DBG, 4, fmt, ## __VA_ARGS__)
 
#define RINFO(fmt, ...)		_RL(L_INFO, 0, fmt, ## __VA_ARGS__)
#define RIDEBUG(fmt, ...)	_RL(L_INFO, 1, fmt, ## __VA_ARGS__)
 
#define RWARN(fmt, ...)		_RL(L_DBG_WARN, 0, fmt, ## __VA_ARGS__)
#define RWDEBUG(fmt, ...)	_RL(L_DBG_WARN, 1, fmt, ## __VA_ARGS__)
#define RWDEBUG2(fmt, ...)	_RL(L_DBG_WARN, 2, fmt, ## __VA_ARGS__)
 
#define RERROR(fmt, ...)	_RM(L_DBG_ERR, 0, fmt, ## __VA_ARGS__)
#define REDEBUG(fmt, ...)	_RM(L_DBG_ERR, 1, fmt, ## __VA_ARGS__)
#define REDEBUG2(fmt, ...)	_RM(L_DBG_ERR, 2, fmt, ## __VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif /* FR_LOG_H */
