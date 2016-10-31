/*
 * (C) 2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by On-Waves
 * All Rights Reserved
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#ifndef snmp_mtp_h
#define snmp_mtp_h

#include <stdlib.h>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/utilities.h>
#include <net-snmp/net-snmp-includes.h>

struct snmp_mtp_session {
	netsnmp_session session, *ss;
	void *data;

	/*
	 * The callbacks will be called multiple times. Even if
	 * we only toggle one object. Remember which request we
	 * are handling here and then we will claim success on the
	 * first of a series of PDUs. This is the easies to manage
	 * and if a link fails to come up the SLTM will catch it.
	 */
	int last_up_req;
	int last_do_req;
};

enum {
	SNMP_LINK_UP,
	SNMP_LINK_DOWN,
};

enum {
	SNMP_STATUS_OK,
	SNMP_STATUS_TIMEOUT,
};

struct snmp_mtp_session *snmp_mtp_session_create(void);
int snmp_mtp_peer_name(struct snmp_mtp_session *, char *name);
void snmp_mtp_deactivate(struct snmp_mtp_session *, int link_id);
void snmp_mtp_activate(struct snmp_mtp_session *, int link_id);
void snmp_mtp_poll();

/* to be implemented by the handler */
void snmp_mtp_callback(struct snmp_mtp_session *, int area, int res, int link_id);

#endif
