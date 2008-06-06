#ifndef _RADIUS_SNMP_H
#define _RADIUS_SNMP_H
/*
 * Version:	$Id$
 */

#include <freeradius-devel/ident.h>
RCSIDH(radius_snmp_h, "$Id$")

#ifdef WITH_SNMP

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
	int32_t		total_requests;
	int32_t		total_invalid_requests;
	int32_t		total_dup_requests;
	int32_t		total_responses;
	int32_t		total_access_accepts;
	int32_t		total_access_rejects;
	int32_t		total_access_challenges;
	int32_t		total_malformed_requests;
	int32_t		total_bad_authenticators;
	int32_t		total_packets_dropped;
	int32_t		total_no_records;
	int32_t		total_unknown_types;
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

/*
 *  Taken from RFC 2619 and RFC 2621
 */
struct rad_snmp_client_entry_t {
	int		index;
	/* IP address */
	/* Client ID (string ) */
	uint32_t       	requests;
	uint32_t	dup_requests;
	uint32_t	responses;
	uint32_t	accepts;
	uint32_t	rejects;
	uint32_t	challenges;
	uint32_t	malformed_requests;
	uint32_t	bad_authenticators;
	uint32_t	packets_dropped;
	uint32_t	unknown_types;
};

extern rad_snmp_t	rad_snmp;

#define RAD_SNMP_INC(_x) if (mainconfig.do_snmp) _x++
#ifdef WITH_ACCOUNTING
#define RAD_SNMP_TYPE_INC(_listener, _x) if (mainconfig.do_snmp) { \
                                     if (_listener->type == RAD_LISTEN_AUTH) { \
                                       rad_snmp.auth._x++; \
				     } else { if (_listener->type == RAD_LISTEN_ACCT) \
                                       rad_snmp.acct._x++; } }

#define RAD_SNMP_CLIENT_INC(_listener, _client, _x) if (mainconfig.do_snmp) { \
                                     if (_listener->type == RAD_LISTEN_AUTH) { \
                                       _client->auth->_x++; \
				     } else { if (_listener->type == RAD_LISTEN_ACCT) \
                                       _client->acct->_x++; } }

#else  /* WITH_ACCOUNTING */

#define RAD_SNMP_TYPE_INC(_listener, _x) if (mainconfig.do_snmp) { \
                                     rad_snmp.auth._x++; }

#define RAD_SNMP_CLIENT_INC(_listener, _client, _x) if (mainconfig.do_snmp) { \
                                     _client->auth->_x++; }

#endif


#else
#define  RAD_SNMP_INC(_x)
#define RAD_SNMP_TYPE_INC(_listener, _x)
#define RAD_SNMP_CLIENT_INC(_listener, _client, _x)

#endif /* WITH_SNMP */

#endif /* _RADIUS_SNMP_H */
