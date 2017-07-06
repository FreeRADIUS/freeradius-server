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
#ifndef _RLM_RADIUS_H
#define _RLM_RADIUS_H
#include <freeradius-devel/connection.h>

/*
 * $Id$
 *
 * @file rlm_radius.h
 * @brief Structures for the RADIUS client packets
 *
 * @copyright 2017 Alan DeKok <aland@freeradius.org>
 */

/** Process a request through a client socket.
 *
 *  This function typically encodes the packet, writes it to a socket,
 *  inserts itself into event list with a read / timeout, and returns
 *  RLM_MODULE_YIELD.
 */
typedef rlm_rcode_t (*fr_radius_client_process)(void *instance, REQUEST *request);

/** Public structure describing an I/O path for an outgoing socket.
 *
 * This structure is exported by client I/O modules e.g. rlm_radius_udp.
 */
typedef struct fr_radius_client_io_t {
	RAD_MODULE_COMMON;				//!< Common fields to all loadable modules.

	fr_app_bootstrap_t		bootstrap;
	fr_app_instantiate_t		instantiate;
	module_thread_t			thread_instantiate;	//!< Callback to configure a module's instance for
								//!< a new worker thread.
	fr_connection_init_t		init;			//!< initialize a socket using thread instance data
	fr_connection_open_t		open;			//!< open a socket using thread instance data
	fr_connection_close_t		close;			//!< close a socket using thread instance data
	fr_radius_client_process	process;	       	//!< process a packet through a socket using thread instance data
} fr_radius_client_io_t;

#endif	/* _RLM_RADIUS_H */
