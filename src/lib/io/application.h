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
 * @file io/application.h
 * @brief Application interfaces.
 *
 * @copyright 2017 The FreeRADIUS project
 */
#include <freeradius-devel/cf_util.h>
#include <freeradius-devel/dl.h>
#include <freeradius-devel/io/io.h>

/*
 *	src/lib/io/schedule.h
 */
typedef struct fr_schedule_t fr_schedule_t;

typedef int (*fr_app_open_t)(void *instance, fr_schedule_t *sc, CONF_SECTION *cs);
typedef int (*fr_app_instantiate_t)(void *instance, CONF_SECTION *cs);
typedef int (*fr_app_bootstrap_t)( void *instance, CONF_SECTION *cs);

/** Set the next state executed by the request to be one of the application subtype's entry points
 *
 * @param[in] instance	of the #fr_app_t.
 * @param[in] request	To set the next state function for.
 */
typedef void (*fr_app_process_set_t)(void const *instance, REQUEST *request);

/** Called by the network thread to pass an event list for the module to use for timer events
 */
typedef void (*fr_app_event_list_set_t)(void *instance, fr_event_list_t *el, void *nr);

/** Describes a new application (protocol)
 *
 */
typedef struct {
	RAD_MODULE_COMMON;				//!< Common fields to all loadable modules.

	fr_app_bootstrap_t		bootstrap;
	fr_app_instantiate_t		instantiate;
	fr_app_open_t			open;		//!< Open listen sockets.

	fr_io_decode_t			decode;		//!< Translate raw bytes into VALUE_PAIRs and metadata.
							///< May be NULL.
							///< Here for convenience, so that decode operations common
							///< to all #fr_app_io_t can be performed by the #fr_app_t.

	fr_io_encode_t			encode;		//!< Pack VALUE_PAIRs back into a byte array.
							///< May be NULL.
							///< Here for convenience, so that encode operations common
							///< to all #fr_app_io_t can be performed by the #fr_app_t.
	fr_app_process_set_t		process_set;
} fr_app_t;

/** Public structure describing an application (protocol) specialisation
 *
 * Some protocols perform multiple distinct functions, and use
 * different state machines to perform those functions.
 */
typedef struct fr_app_process_t {
	RAD_MODULE_COMMON;				//!< Common fields to all loadable modules.

	fr_app_bootstrap_t		bootstrap;
	fr_app_instantiate_t		instantiate;
	fr_io_process_t			process;	//!< Entry point into the protocol subtype's state machine.
} fr_app_process_t;

/** Public structure describing an I/O path for a protocol
 *
 * This structure is exported by I/O modules e.g. proto_radius_udp.
 */
typedef struct fr_app_io_t {
	RAD_MODULE_COMMON;				//!< Common fields to all loadable modules.

	fr_app_bootstrap_t		bootstrap;
	fr_app_instantiate_t		instantiate;
	fr_app_event_list_set_t		event_list_set;	//!< Called by the network thread to pass an event list
							//!< for use by the app_io_t.

	size_t				default_message_size;	//!< Usually maximum message size
	size_t				default_reply_size;	//!< same for replies
	bool				track_duplicates;	//!< track duplicate packets

	fr_io_open_t			open;		//!< Open a new socket for listening, or accept/connect a new
							//!< connection.
	fr_io_get_fd_t			fd;		//!< Return the file descriptor from the instance.
	fr_io_data_read_t		read;		//!< Read from a socket to a data buffer
	fr_io_data_write_t		write;		//!< Write from a data buffer to a socket
	fr_io_data_inject_t		inject;		//!< Inject a packet into a socket.
	fr_io_data_vnode_t		vnode;		//!< Handle notifications that the VNODE has changed
	fr_io_decode_t			decode;		//!< Translate raw bytes into VALUE_PAIRs and metadata.
	fr_io_encode_t			encode;		//!< Pack VALUE_PAIRs back into a byte array.
	fr_io_signal_t			flush;		//!< Flush the data when the socket is ready for writing.
	fr_io_signal_t			error;		//!< There was an error on the socket.
	fr_io_open_t			close;		//!< Close the transport.
	fr_io_nak_t			nak;		//!< Function to send a NAK.
} fr_app_io_t;
