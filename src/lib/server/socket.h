#pragma once
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

/**
 * $Id$
 *
 * @file lib/server/socket.h
 * @brief Socket structures.
 *
 * @copyright 2018 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(server_socket_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	uint32_t	max_connections;
	uint32_t	num_connections;
	uint32_t	max_requests;
	uint32_t	num_requests;
	fr_time_delta_t	lifetime;
	fr_time_delta_t	idle_timeout;
} fr_socket_limit_t;

#ifdef __cplusplus
}
#endif
