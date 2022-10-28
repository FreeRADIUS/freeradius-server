# pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/*
 * $Id$
 *
 * @file rfc4533.h
 * @brief Callback routines for direcories implementing RFC 4533
 *
 * @copyright 2022 Network RADIUS SARL (legal@networkradius.com)
 */
#include <freeradius-devel/ldap/base.h>
#include "proto_ldap_sync_ldap.h"

int rfc4533_sync_init(fr_ldap_connection_t *conn, size_t sync_no,
		      proto_ldap_sync_t const *inst, uint8_t const *cookie);

int rfc4533_sync_search_entry(sync_state_t *sync, LDAPMessage *msg, LDAPControl **ctrls);

int rfc4533_sync_intermediate(sync_state_t *sync, LDAPMessage *msg, LDAPControl **ctrls);

int rfc4533_sync_search_result(sync_state_t *sync, LDAPMessage *msg, LDAPControl **ctrls);

int rfc4533_sync_refresh_required(sync_state_t *sync, LDAPMessage *msg, LDAPControl **ctrls);
