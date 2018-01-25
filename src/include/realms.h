#ifndef REALMS_H
#define REALMS_H

/*
 * realms.h	Structures, prototypes and global variables
 *		for realms
 *
 * Version:	$Id$
 *
 */

RCSIDH(realms_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

extern bool home_servers_udp;	//!< Whether there are any UDP home servers

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

	fr_event_t		*ev;
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
#ifdef WITH_TLS
	fr_tls_server_conf_t	*tls;
#endif

#ifdef WITH_STATS
	int			number;

	fr_stats_t		stats;

	fr_stats_ema_t  	ema;
#endif
#ifdef HAVE_TRUST_ROUTER_TR_DH_H
	time_t			expiration;
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

typedef struct realm_config realm_config_t;

int		realms_init(CONF_SECTION *config);
void		realms_free(void);
REALM		*realm_find(char const *name); /* name is from a packet */
REALM		*realm_find2(char const *name); /* ... with name taken from realm_find */

void		realm_home_server_sanitize(home_server_t *home, CONF_SECTION *cs);
int		realm_pool_add(home_pool_t *pool, CONF_SECTION *cs);
void		realm_pool_free(home_pool_t *pool);
bool		realm_home_server_add(home_server_t *home);
int		realm_realm_add( REALM *r, CONF_SECTION *cs);

void		home_server_update_request(home_server_t *home, REQUEST *request);
home_server_t	*home_server_ldb(char const *realmname, home_pool_t *pool, REQUEST *request);
home_server_t	*home_server_find(fr_ipaddr_t *ipaddr, uint16_t port, int proto);
home_server_t	*home_server_afrom_cs(TALLOC_CTX *ctx, realm_config_t *rc, CONF_SECTION *cs);
CONF_SECTION	*home_server_cs_afrom_client(CONF_SECTION *client);
#ifdef WITH_COA
home_server_t	*home_server_byname(char const *name, int type);
#endif
#ifdef WITH_STATS
home_server_t	*home_server_bynumber(int number);
#endif
home_pool_t	*home_pool_byname(char const *name, int type);

#ifdef __cplusplus
}
#endif

#endif /* REALMS_H */
