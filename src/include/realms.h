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

typedef enum {
	HOME_TYPE_INVALID = 0,
	HOME_TYPE_AUTH,
	HOME_TYPE_ACCT
#ifdef WITH_COA
	,HOME_TYPE_COA
#endif
} home_type_t;

typedef enum {
	HOME_PING_CHECK_NONE = 0,
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
	char const	*name;

	char const	*hostname;
	char const	*server; /* for internal proxying */
	char const	*parent_server;

	fr_ipaddr_t	ipaddr;

	int		port;
	int		type;		/* auth/acct */

	int		proto;
	fr_socket_limit_t limit;

	fr_ipaddr_t	src_ipaddr; /* preferred source IP address */

	char const	*secret;

	fr_event_t	*ev;
	struct timeval	when;

	struct timeval	response_window;
	int		max_outstanding; /* don't overload it */
	int		currently_outstanding;

	time_t		last_packet_sent;
	time_t		last_packet_recv;
	time_t		last_failed_open;
	struct timeval	revive_time;
	struct timeval	zombie_period_start;
	int		zombie_period; /* unresponsive for T, mark it dead */

	int		state;

	int		ping_check;
	char const	*ping_user_name;
	char const	*ping_user_password;

	int		ping_interval;
	int		num_pings_to_alive;
	int		num_sent_pings;
	int		num_received_pings;
	int		ping_timeout;

	int		revive_interval; /* if it doesn't support pings */
	CONF_SECTION	*cs;
#ifdef WITH_COA
	int		coa_irt;
	int		coa_mrc;
	int		coa_mrt;
	int		coa_mrd;
#endif
#ifdef WITH_TLS
	fr_tls_server_conf_t	*tls;
#endif

#ifdef WITH_STATS
	int		number;

	fr_stats_t	stats;

	fr_stats_ema_t  ema;
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

	int			server_type;
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

	int			striprealm;

	home_pool_t		*auth_pool;
	home_pool_t		*acct_pool;
#ifdef WITH_COA
	home_pool_t		*coa_pool;
#endif
} REALM;

int realms_init(CONF_SECTION *config);
void realms_free(void);
REALM *realm_find(char const *name); /* name is from a packet */
REALM *realm_find2(char const *name); /* ... with name taken from realm_find */

void home_server_update_request(home_server_t *home, REQUEST *request);
home_server_t *home_server_ldb(char const *realmname, home_pool_t *pool, REQUEST *request);
home_server_t *home_server_find(fr_ipaddr_t *ipaddr, int port, int proto);
#ifdef WITH_COA
home_server_t *home_server_byname(char const *name, int type);
#endif
#ifdef WITH_STATS
home_server_t *home_server_bynumber(int number);
#endif
home_pool_t *home_pool_byname(char const *name, int type);

#ifdef __cplusplus
}
#endif

#endif /* REALMS_H */
