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

#endif /* _RADIUS_SNMP_H */
