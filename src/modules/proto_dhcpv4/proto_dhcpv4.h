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
 * @file proto_dhcpv4.h
 * @brief Structures for the DHCPV4 protocol
 *
 * @copyright 2018 Alan DeKok <aland@freedhcpv4.org>
 */
#include <freeradius-devel/io/master.h>
#include <freeradius-devel/dhcpv4/dhcpv4.h>

/** An instance of a proto_dhcpv4 listen section
 *
 */
typedef struct proto_dhcpv4_t {
	fr_io_instance_t		io;				//!< wrapper for IO abstraction

	dl_instance_t			**type_submodule;		//!< Instance of the various types
	dl_instance_t			*dynamic_submodule;		//!< proto_dhcpv4_dynamic_client
									//!< only one instance per type allowed.
	dl_instance_t			*type_submodule_by_code[FR_DHCP_MAX];  	//!< Lookup process entry point by code.

	uint32_t			max_packet_size;		//!< for message ring buffer.
	uint32_t			num_messages;			//!< for message ring buffer.

	bool				tunnel_password_zeros;		//!< check for trailing zeroes in Tunnel-Password.

	bool				code_allowed[FR_DHCP_MAX];     	//!< Allowed packet codes.

	uint32_t			priorities[FR_DHCP_MAX];       	//!< priorities for individual packets
} proto_dhcpv4_t;

