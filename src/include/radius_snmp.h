#ifndef _RADIUS_SNMP_H
#define _RADIUS_SNMP_H

/*
 * Version:	$Id$
 */

#if HAVE_ASN1_H
#include	<asn1.h>
#elif HAVE_UCD_SNMP_ASN1_H
#include	<ucd-snmp/asn1.h>
#endif

#if HAVE_SNMP_H
#include	<snmp.h>
#elif HAVE_UCD_SNMP_SNMP_H
#include	<ucd-snmp/snmp.h>
#endif

#if HAVE_SNMP_IMPL_H
#include	<snmp_impl.h>
#elif HAVE_UCD_SNMP_SNMP_IMPL_H
#include	<ucd-snmp/snmp_impl.h>
#endif

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
	smux_event_t      smux_event;
	const char	  *smux_password;
	int		  snmp_write_access;
	int		  smux_fd;
	int		  smux_failures;
	int		  smux_max_failures;
} rad_snmp_t;

extern rad_snmp_t	rad_snmp;

#endif /* _RADIUS_SNMP_H */
