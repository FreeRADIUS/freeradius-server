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
 * @file lib/server/realms.h
 * @brief Request forwarding API.
 *
 * @copyright 2015 The FreeRADIUS server project
 */
RCSIDH(realms_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	HOME_TYPE_INVALID = 0,
	HOME_TYPE_AUTH,		//!< Authentication server
	HOME_TYPE_ACCT,		//!< Accounting server
	HOME_TYPE_AUTH_ACCT	//!< Authentication and accounting server

#ifdef WITH_COA
	,HOME_TYPE_COA		//!< CoA destination (NAS or Proxy)
#endif
} home_type_t;

typedef enum {
	HOME_PING_CHECK_INVALID = 0,
	HOME_PING_CHECK_NONE,
	HOME_PING_CHECK_STATUS_SERVER,
	HOME_PING_CHECK_REQUEST
} home_ping_check_t;

typedef enum {
	HOME_STATE_ALIVE = 0,
	HOME_STATE_ZOMBIE,
	HOME_STATE_IS_DEAD,
	HOME_STATE_UNKNOWN
} home_state_t;

typedef struct fr_socket_limit_t {
	uint32_t	max_connections;
	uint32_t	num_connections;
	uint32_t	max_requests;
	uint32_t	num_requests;
	uint32_t	lifetime;
	uint32_t	idle_timeout;
} fr_socket_limit_t;

typedef struct home_server {
	char const		*log_name;		//!< The name used for log messages.

	char const		*name;			//!< Name the server may be referenced by for querying
							//!< stats or when specifying home servers for a pool.

	bool			dual;			//!< One of a pair of homeservers on consecutive ports.

	bool			is_ourself;		//!< if we're proxying to one of our own ports.

	char const		*server;		//!< For internal proxying
	char const		*parent_server;

	fr_ipaddr_t		ipaddr;			//!< IP address of home server.
	uint16_t		port;

	char const		*type_str;		//!< String representation of type.
	home_type_t		type;			//!< Auth, Acct, CoA etc.

	char const		*src_ipaddr_str;	//!< Need to parse the string specially as it may
							//!< require a DNS lookup and the address family for that
							//!< is the same as ipaddr.
	fr_ipaddr_t		src_ipaddr;		//!< Resolved version of src_ipaddr_str.  Preferred source
							//!< IP address (useful for multihomed systems).

	char const		*proto_str;		//!< String representation of protocol.
	int			proto;			//!< TCP or UDP.

	fr_socket_limit_t 	limit;

	char const		*secret;

	fr_event_timer_t const	*ev;
	struct timeval		when;

	struct timeval		response_window;
	uint32_t		response_timeouts;
	uint32_t		max_response_timeouts;
	uint32_t		max_outstanding;	//!< Maximum outstanding requests.
	uint32_t		currently_outstanding;

	time_t			last_packet_sent;
	time_t			last_packet_recv;
	time_t			last_failed_open;
	struct timeval		revive_time;
	struct timeval		zombie_period_start;
	uint32_t		zombie_period;		//!< Unresponsive for T, mark it dead.

	int			state;

	char const		*ping_check_str;
	home_ping_check_t	ping_check;		//!< What method we use to perform the 'ping'
							//!< none, status-server or fake request.

	char const		*ping_user_name;
	char const		*ping_user_password;

	uint32_t		ping_interval;
	uint32_t		num_pings_to_alive;
	uint32_t		num_sent_pings;
	uint32_t		num_received_pings;
	uint32_t		ping_timeout;

	uint32_t		revive_interval;	//!< How often we revive it (if it doesn't support pings).
	CONF_SECTION		*cs;
#ifdef WITH_COA
	uint32_t		coa_irt;
	uint32_t		coa_mrc;
	uint32_t		coa_mrt;
	uint32_t		coa_mrd;
#endif
#if 0
	fr_tls_conf_t	*tls;
#endif

#ifdef WITH_STATS
	int			number;

	fr_stats_t		stats;

	fr_stats_ema_t  	ema;
#endif
} home_server_t;


typedef enum home_pool_type_t {
	HOME_POOL_INVALID = 0,
	HOME_POOL_LOAD_BALANCE,
	HOME_POOL_FAIL_OVER,
	HOME_POOL_CLIENT_BALANCE,
	HOME_POOL_CLIENT_PORT_BALANCE,
	HOME_POOL_KEYED_BALANCE
} home_pool_type_t;


typedef struct home_pool_t {
	char const		*name;
	home_pool_type_t	type;

	home_type_t    		server_type;
	CONF_SECTION		*cs;

	char const		*virtual_server; /* for pre/post-proxy */

	home_server_t		*fallback;
	int			in_fallback;
	time_t			time_all_dead;

	int			num_home_servers;
	home_server_t		*servers[1];
} home_pool_t;


typedef struct _realm {
	char const		*name;

	bool			strip_realm;

	home_pool_t		*auth_pool;
	home_pool_t		*acct_pool;
#ifdef WITH_COA
	home_pool_t		*coa_pool;
#endif
} REALM;

#ifdef __cplusplus
}
#endif
