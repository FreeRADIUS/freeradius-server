#ifndef REALMS_H
#define REALMS_H

/*
 * realms.h	Structures, prototypes and global variables
 *		for realms
 *
 * Version:	$Id$
 *
 */

#include <freeradius-devel/ident.h>
RCSIDH(realms_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#define HOME_TYPE_INVALID (0)
#define HOME_TYPE_AUTH    (1)
#define HOME_TYPE_ACCT    (2)
#ifdef WITH_COA
#define HOME_TYPE_COA     (3)
#endif

#define HOME_PING_CHECK_NONE		(0)
#define HOME_PING_CHECK_STATUS_SERVER	(1)
#define HOME_PING_CHECK_REQUEST		(2)

#define HOME_STATE_ALIVE		(0)
#define HOME_STATE_ZOMBIE		(1)
#define HOME_STATE_IS_DEAD		(2)

typedef struct home_server {
	const char	*name;

	const char	*hostname;
	const char	*server; /* for internal proxying */

	fr_ipaddr_t	ipaddr;

	int		port;
	int		type;		/* auth/acct */

	int		proto;
	int		max_connections;
	int		num_connections; /* protected by proxy mutex */
	int		max_requests;	 /* for one connection */
	int		lifetime;
	int		idle_timeout;

	/*
	 *	Maybe also have list of source IP/ports, && socket?
	 */

	const char	*secret;

	fr_event_t	*ev;
	struct timeval	when;

	int		response_window;
	int		no_response_fail;
	int		max_outstanding; /* don't overload it */
	int		currently_outstanding;
	int		message_authenticator;

	time_t		last_packet;
	struct timeval	revive_time;
	struct timeval	zombie_period_start;
	int		zombie_period; /* unresponsive for T, mark it dead */

	int		state;

	int		ping_check;
	const char	*ping_user_name;
	const char	*ping_user_password;

	int		ping_interval;
	int		num_pings_to_alive;
	int		num_sent_pings;
	int		num_received_pings;
	int		ping_timeout;

	int		revive_interval; /* if it doesn't support pings */
	CONF_SECTION	*cs;
#ifdef WITH_COA
	int			coa_irt;
	int			coa_mrc;
	int			coa_mrt;
	int			coa_mrd;
#endif
#ifdef WITH_TLS
	fr_tls_server_conf_t	*tls;
#endif
#ifdef WITH_STATS
	int		number;

	fr_ipaddr_t	src_ipaddr; /* preferred source IP address */

	fr_stats_t	stats;

	fr_stats_ema_t  ema;
#endif
} home_server;


typedef enum home_pool_type_t {
	HOME_POOL_INVALID = 0,
	HOME_POOL_LOAD_BALANCE,
	HOME_POOL_FAIL_OVER,
	HOME_POOL_CLIENT_BALANCE,
	HOME_POOL_CLIENT_PORT_BALANCE,
	HOME_POOL_KEYED_BALANCE
} home_pool_type_t;


typedef struct home_pool_t {
	const char		*name;
	home_pool_type_t	type;

	int			server_type;
	CONF_SECTION		*cs;

	const char		*virtual_server; /* for pre/post-proxy */
	
	home_server		*fallback;
	int			in_fallback;
	time_t			time_all_dead;

	int			num_home_servers;
	home_server		*servers[1];
} home_pool_t;


typedef struct _realm {
	const char		*name;

	int			striprealm;

	home_pool_t		*auth_pool;
	home_pool_t		*acct_pool;
} REALM;

int realms_init(CONF_SECTION *config);
void realms_free(void);
REALM *realm_find(const char *name); /* name is from a packet */
REALM *realm_find2(const char *name); /* ... with name taken from realm_find */

home_server *home_server_ldb(const char *realmname, home_pool_t *pool, REQUEST *request);
home_server *home_server_find(fr_ipaddr_t *ipaddr, int port, int proto);
#ifdef WITH_COA
home_server *home_server_byname(const char *name, int type);
#endif
#ifdef WITH_STATS
home_server *home_server_bynumber(int number);
#endif
home_pool_t *home_pool_byname(const char *name, int type);

#ifdef __cplusplus
}
#endif

#endif /* REALMS_H */
