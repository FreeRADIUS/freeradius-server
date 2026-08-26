/*
 * rlm_linelog.h
 *
 * Version:	$Id$
 *
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
 *
 * @copyright 2004,2006 The FreeRADIUS server project
 * @copyright 2004 Alan DeKok (aland@freeradius.org)
 */

#include <freeradius-devel/server/base.h>

 typedef enum {
	LINELOG_DST_INVALID = 0,
	LINELOG_DST_FILE,				//!< Log to a file.
	LINELOG_DST_REQUEST,				//!< Log to the request->log
	LINELOG_DST_SYSLOG,				//!< Log to syslog.
	LINELOG_DST_UNIX,				//!< Log via Unix socket.
	LINELOG_DST_UDP,				//!< Log via UDP.
	LINELOG_DST_TCP,				//!< Log via TCP.
	LINELOG_DST_STDOUT,				//!< Log to stdout.
	LINELOG_DST_STDERR,				//!< Log to stderr.
} linefr_log_dst_t;

typedef struct {
	fr_ipaddr_t		dst_ipaddr;		//!< Network server.
	fr_ipaddr_t		src_ipaddr;		//!< Send requests from a given src_ipaddr.
	uint16_t		port;			//!< Network port.
	fr_time_delta_t		timeout;		//!< How long to wait for read/write operations.
} linelog_net_t;

/** linelog module instance
 */
typedef struct {
	fr_pool_t		*pool;			//!< Connection pool instance.

	char const		*delimiter;		//!< Line termination string (usually \n).
	size_t			delimiter_len;		//!< Length of line termination string.

	linefr_log_dst_t	log_dst;		//!< Logging destination.
	char const		*log_dst_str;		//!< Logging destination string.

	struct {
		char const		*facility;		//!< Syslog facility string.
		char const		*severity;		//!< Syslog severity string.
		int			priority;		//!< Bitwise | of severity and facility.
	} syslog;

	struct {
		mode_t			permissions;		//!< Permissions to use when creating new files.
		char const		*group_str;		//!< Group to set on new files.
		gid_t			group;			//!< Resolved gid.
		exfile_t		*ef;			//!< Exclusive file access handle.
		bool			escape;			//!< Do filename escaping, yes / no.
		bool			fsync;			//!< fsync after each write.
		fr_time_delta_t		max_idle;		//!< How long to keep file metadata around without activity.
		bool			buffer_write;		//!< Whether buffering is enabled.
		uint32_t		buffer_count;		//!< Max number of entries to buffer before writing.
		fr_time_delta_t		buffer_delay;		//!< Max time to wait before flushing buffer.
		bool			buffer_delay_is_set;	//!< Whether buffer_delay was explicitly set.
		fr_time_delta_t		buffer_expiry;		//!< How long to keep file metadata around without activity.
		bool 			buffer_expiry_is_set;	//!< Whether buffer_expiry was explicitly set.
	} file;

	struct {
		char const		*path;			//!< Where the UNIX socket lives.
		fr_time_delta_t		timeout;		//!< How long to wait for read/write operations.
	} unix_sock;	// Lowercase unix is a macro on some systems?!

	linelog_net_t		tcp;			//!< TCP server.
	linelog_net_t		udp;			//!< UDP server.

	CONF_SECTION		*cs;			//!< #CONF_SECTION to use as the root for #log_ref lookups.

	bool			triggers;		//!< Do we do triggers.
} rlm_linelog_t;

typedef struct {
	tmpl_t			*log_src;		//!< Source of log messages.

	fr_value_box_t		*log_ref;		//!< Path to a #CONF_PAIR (to use as the source of
							///< log messages).

	fr_value_box_t		*log_head;		//!< Header to add to each new log file.

	fr_value_box_t		*filename;		//!< File name, if output is to a file.
} linelog_call_env_t;
