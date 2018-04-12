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
 * @file proto_vmps.h
 * @brief Structures for the VMPS protocol
 *
 * @copyright 2017 Alan DeKok <aland@freeradius.org>
 */
#include "vqp.h"

/** Return the VMPS client associated with the request
 *
 * @param[in] instance		#fr_app_io_t instance.
 * @param[in] packet_ctx	as allocated/returned by the #fr_app_io_t.
 */
typedef RADCLIENT *(*proto_vmps_client_get_t)(void const *instance, void const *packet_ctx);

/** Get src/dst address from the #fr_app_io_t module
 *
 * @param[out] sockaddr		structure to populate.  If UNIX socket, path will be a shallow copy.
 * @param[in] instance		#fr_app_io_t instance.
 * @param[in] packet_ctx	as allocated/returned by the #fr_app_io_t.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
typedef int (*proto_vmps_addr_get_t)(fr_socket_addr_t *sockaddr,
				       void const *instance, void const *packet_ctx);

/** Semi-private functions exported by proto_vmps #fr_app_io_t modules
 *
 * Should only be used by the proto_vmps module, and submodules.
 */
typedef struct {
	proto_vmps_addr_get_t		src;				//!< Retrieve the src address of the packet.
	proto_vmps_addr_get_t		dst;				//!< Retrieve the dst address of the packet.
} proto_vmps_app_io_t;

/** An instance of a proto_vmps listen section
 *
 */
typedef struct {
	CONF_SECTION			*server_cs;			//!< server CS for this listener

	dl_instance_t			*io_submodule;			//!< As provided by the transport_parse
									///< callback.  Broken out into the
									///< app_io_* fields below for convenience.

	fr_app_io_t const		*app_io;			//!< Easy access to the app_io handle.
	void				*app_io_instance;		//!< Easy access to the app_io instance.
	CONF_SECTION			*app_io_conf;			//!< Easy access to the app_io's config section.
	proto_vmps_app_io_t		*app_io_private;		//!< Internal interface for proto_vmps.

	dl_instance_t			**process_submodule;		//!< Instance of the various types

	fr_io_process_t			process;			//!< process entry point

	uint32_t			default_message_size;		//!< for message ring buffer
	uint32_t			num_messages;			//!< for message ring buffer

	fr_listen_t const		*listen;			//!< The listener structure which describes
									///< the I/O path.
} proto_vmps_t;
