#ifndef _RADIUS_SNMP_H
#define _RADIUS_SNMP_H

/*
 * Version:	$Id$
 */

#include	<asn1.h>
#include	<snmp.h>
#include	<snmp_impl.h>
#include        "smux.h"

extern void radius_snmp_init(void);
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
	rad_snmp_server_t acct;
	smux_event        smux_event;
	const char	  *smux_password;
	int		  snmp_write_access;
	int		  smux_fd;
} rad_snmp_t;

extern rad_snmp_t	rad_snmp;

#endif /* _RADIUS_SNMP_H */
