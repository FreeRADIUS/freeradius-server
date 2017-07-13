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

/** Initialize a RADIUS client socket
 *
 */
typedef fr_connection_state_t (*fr_radius_client_init_t)(int *fd_out, void *io_ctx, void const *uctx);

/** Get a printable name for a socket.
 *
 */
typedef char const *(*fr_radius_client_name_t)(TALLOC_CTX *ctx, void *io_ctx);

/** Update the FD state to active or idle
 *
 */
typedef bool (*fr_radius_client_active_t)(void *io_ctx);

/** Get a REQUEST from a socket
 *
 */
typedef int (*fr_radius_client_read_t)(REQUEST **p_request, rlm_rcode_t *p_rcode, fr_event_list_t *el, int sock, void *io_ctx);

/** Write a REQUEST to a socket.
 *
 */
typedef int (*fr_radius_client_write_t)(REQUEST *request, void *request_ctx, void *io_ctx);

/** Flush a socket for writing
 *
 */
typedef int (*fr_radius_client_flush_t)(void *uctx);


/** Public structure describing an I/O path for an outgoing socket.
 *
 * This structure is exported by client I/O modules e.g. rlm_radius_udp.
 */
typedef struct fr_radius_client_io_t {
	RAD_MODULE_COMMON;				//!< Common fields to all loadable modules.

	fr_app_bootstrap_t		bootstrap;
	fr_app_instantiate_t		instantiate;
	size_t				io_inst_size;		//!< Size of data to allocate to the IO handler
	size_t				request_inst_size;	//!< size of the data to allocate per-request.


	fr_radius_client_init_t		init;			//!< initialize a socket using thread instance data
	fr_connection_open_t		open;			//!< open a socket using thread instance data
	fr_connection_close_t       	close;			//!< close a socket using thread instance data
	fr_radius_client_name_t		get_name;	       	//!< get the name of this socket.

	fr_radius_client_active_t	fd_active;		//!< mark the FD as active
	fr_radius_client_active_t	fd_idle;		//!< mark the FD as idle

	fr_radius_client_write_t	write;			//!< write a REQUEST to a socket
	fr_radius_client_write_t	remove;			//!< remove a written request from a socket
	fr_radius_client_read_t		read;			//!< read a REQUEST from a socket.
	fr_radius_client_flush_t	flush;			//!< flush data for an outgoing socket
} fr_radius_client_io_t;

/*
 *	So transports can calculate retransmission timers.
 */
bool rlm_radius_update_delay(struct timeval *start, uint32_t *rt, uint32_t *count, int code, void *client_io_ctx, struct timeval *now);

#endif	/* _RLM_RADIUS_H */
