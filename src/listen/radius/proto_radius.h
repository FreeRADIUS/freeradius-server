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

/*
 * $Id$
 *
 * @file proto_radius.h
 * @brief Structures for the RADIUS protocol
 *
 * @copyright 2018 Alan DeKok (aland@freeradius.org)
 */
#include <freeradius-devel/io/master.h>
#include <freeradius-devel/radius/radius.h>

/** An instance of a proto_radius listen section
 *
 */
typedef struct {
	fr_io_instance_t		io;				//!< wrapper for IO abstraction

	uint32_t			max_packet_size;		//!< for message ring buffer.
	uint32_t			num_messages;			//!< for message ring buffer.

	bool				tunnel_password_zeros;		//!< check for trailing zeroes in Tunnel-Password.
	uint32_t			priorities[FR_RADIUS_CODE_MAX];	//!< priorities for individual packets

	char const			**allowed_types;		//!< names for for 'type = ...'
	bool				allowed[FR_RADIUS_CODE_MAX];

	fr_radius_require_ma_t		require_message_authenticator;			//!< Require Message-Authenticator in all requests.
	fr_radius_limit_proxy_state_t	limit_proxy_state;		//!< Limit Proxy-State to packets containing
									///< Message-Authenticator.
} proto_radius_t;

void proto_radius_log(fr_listen_t *li, char const *name, fr_radius_decode_fail_t reason, fr_socket_t const *sock, char const *fmt, ...);
