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

#define HOME_TYPE_INVALID (0)
#define HOME_TYPE_AUTH    (1)
#define HOME_TYPE_ACCT    (2)

#define HOME_PING_CHECK_NONE		(0)
#define HOME_PING_CHECK_STATUS_SERVER	(1)
#define HOME_PING_CHECK_REQUEST		(2)

#define HOME_STATE_ALIVE		(0)
#define HOME_STATE_ZOMBIE		(1)
#define HOME_STATE_IS_DEAD		(2)

typedef struct home_server {
	const char	*name;

	const char	*hostname;

	lrad_ipaddr_t	ipaddr;


	int		port;
	int		type;		/* auth/acct */

	/*
	 *	Maybe also have list of source IP/ports, && socket?
	 */

	const char	*secret;

	lrad_event_t	*ev;
	struct timeval	when;

	int		response_window;
	int		max_outstanding; /* don't overload it */
	int		currently_outstanding;
	uint32_t       	total_requests_sent;

	struct timeval	zombie_period_start;
	int		zombie_period; /* unresponsive for T, mark it dead */

	int		state;

	int		ping_check;
	const char	*ping_user_name;
	const char	*ping_user_password;

	int		ping_interval;
	int		num_pings_to_alive;
	int		num_received_pings;
	int		ping_timeout;

	int		revive_interval; /* if it doesn't support pings */
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
int realm_add(CONF_SECTION *cs);
REALM *realm_find(const char *name);

home_server *home_server_ldb(const char *realmname, home_pool_t *pool, REQUEST *request);
home_server *home_server_find(lrad_ipaddr_t *ipaddr, int port);

#endif /* REALMS_H */
