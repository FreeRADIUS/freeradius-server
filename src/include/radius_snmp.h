#ifndef _RADIUS_SNMP_H
#define _RADIUS_SNMP_H

#include <freeradius-devel/stats.h>

/*
 * Version:	$Id$
 */

#include <freeradius-devel/ident.h>
RCSIDH(radius_snmp_h, "$Id$")

#ifdef WITH_SNMP

#ifndef WITH_STATS
#error WITH_SNMP needs WITH_STATS
#endif

typedef enum smux_event_t {
  SMUX_NONE, SMUX_CONNECT, SMUX_READ
} smux_event_t;

extern int radius_snmp_init(CONF_SECTION *);
extern int smux_connect(void);
extern int smux_read(void);

/*
 *	The RADIUS server snmp data structures.
 */
typedef struct rad_snmp_server_t {
	const char 	*ident;
	time_t		start_time;
	int32_t		uptime;	/* in hundredths of a second */

	time_t		last_reset_time;
	int32_t		reset_time;
	int32_t		config_reset;
} rad_snmp_server_t;

typedef struct rad_snmp_t {
	rad_snmp_server_t auth;
#ifdef WITH_ACCOUNTING
	rad_snmp_server_t acct;
#endif
  	smux_event_t      smux_event;
	const char	  *smux_password;
	int		  snmp_write_access;
	int		  smux_fd;
	int		  smux_failures;
	int		  smux_max_failures;
} rad_snmp_t;

extern rad_snmp_t	rad_snmp;
#endif /* WITH_SNMP */

#endif /* _RADIUS_SNMP_H */
