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
 * @file persistent_search.h
 * @brief Callback routines for direcories implementing persistent search
 *
 * @copyright 2022 Network RADIUS SARL (legal@networkradius.com)
 */
#include <freeradius-devel/ldap/base.h>
#include "proto_ldap_sync_ldap.h"

int persistent_sync_state_init(fr_ldap_connection_t *conn, size_t sync_no, proto_ldap_sync_t const *inst,
			       UNUSED uint8_t const *cookie);

int persistent_sync_search_entry(sync_state_t *sync, LDAPMessage *msg, LDAPControl **ctrls);
