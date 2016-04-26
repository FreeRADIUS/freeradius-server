/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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
 * @file rlm_linelog.h
 * @brief Prototypes and functions for the linelog module
 *
 * @copyright 2000,2006  The FreeRADIUS server project
 */
#ifndef _RLM_LINELOG_H
#define _RLM_LINELOG_H

RCSIDH(rlm_linelog_h, "$Id$")

#include <freeradius-devel/modpriv.h>

typedef enum {
	LINELOG_DST_INVALID = 0,
	LINELOG_DST_FILE,				//!< Log to a file.
	LINELOG_DST_SYSLOG,				//!< Log to syslog.
	LINELOG_DST_UNIX,				//!< Log via Unix socket.
	LINELOG_DST_UDP,				//!< Log via UDP.
	LINELOG_DST_TCP,				//!< Log via TCP.
} linelog_dst_t;

typedef struct linelog_net {
	fr_ipaddr_t		dst_ipaddr;		//!< Network server.
	fr_ipaddr_t		src_ipaddr;		//!< Send requests from a given src_ipaddr.
	uint16_t		port;			//!< Network port.
	struct timeval		timeout;		//!< How long to wait for read/write operations.
} linelog_net_t;

/** linelog module instance
 */
typedef struct linelog_instance_t {
	char const		*name;			//!< Module instance name.
	fr_connection_pool_t	*pool;			//!< Connection pool instance.

	char const		*delimiter;		//!< Line termination string (usually \n).
	size_t			delimiter_len;		//!< Length of line termination string.

	vp_tmpl_t		*log_src;		//!< Source of log messages.

	vp_tmpl_t		*log_ref;		//!< Path to a #CONF_PAIR (to use as the source of
							///< log messages).

	linelog_dst_t		log_dst;		//!< Logging destination.
	char const		*log_dst_str;		//!< Logging destination string.

	struct {
		char const		*facility;		//!< Syslog facility string.
		char const		*severity;		//!< Syslog severity string.
		int			priority;		//!< Bitwise | of severity and facility.
	} syslog;

	struct {
		char const		*name;			//!< File to write to.
		uint32_t		permissions;		//!< Permissions to use when creating new files.
		char const		*group_str;		//!< Group to set on new files.
		gid_t			group;			//!< Resolved gid.
		exfile_t		*ef;			//!< Exclusive file access handle.
		bool			escape;			//!< Do filename escaping, yes / no.
		xlat_escape_t		escape_func;		//!< Escape function.
	} file;

	struct {
		char const		*path;			//!< Where the UNIX socket lives.
		struct timeval		timeout;		//!< How long to wait for read/write operations.
	} unix_sock;	// Lowercase unix is a macro on some systems?!

	linelog_net_t		tcp;			//!< TCP server.
	linelog_net_t		udp;			//!< UDP server.

	CONF_SECTION		*cs;			//!< #CONF_SECTION to use as the root for #log_ref lookups.
} linelog_instance_t;

#endif
