/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 * @file trustrouter.h
 * @brief Headers for trust router code
 *
 * @copyright 2014 Network RADIUS SARL
 */
#ifndef TRUSTROUTER_INTEG_H
#define TRUSTROUTER_INTEG_H

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

REALM *tr_query_realm(REQUEST *request, char const *realm,
		      char const *community,
		      char const *rprealm,
		      char const *trustrouter,
		      unsigned int port);

bool tr_init(bool cnf_rekey_enabled, uint32_t cnf_realm_lifetime);

#endif
