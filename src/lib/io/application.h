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
#include <freeradius-devel/server/cf_util.h>
#include <freeradius-devel/server/dl.h>
#include <freeradius-devel/io/base.h>

/*
 *	src/lib/io/schedule.h
 */
typedef struct fr_schedule_t fr_schedule_t;

/** Bootstrap the #fr_app_t
 *
 * Primarily used to allow the #fr_app_t to load its submodules.
 *
 * @param[in] instance	of the #fr_app_t.
 * @param[in] cs	of the listen section that created this #fr_app_t.
 * @return
 *	- 0 on success.
 *	- <0 on failure.
 */
typedef int (*fr_app_bootstrap_t)( void *instance, CONF_SECTION *cs);

/** Instantiate the #fr_app_t
 *
 * Primarily used to allow the #fr_app_t to validate its config
 * and to allow its submodules to validate their configurations.
 *
 * @param[in] instance	of the #fr_app_t.
 * @param[in] cs	of the listen section that created this #fr_app_t.
 * @return
 *	- 0 on success.
 *	- <0 on failure.
 */
typedef int (*fr_app_instantiate_t)(void *instance, CONF_SECTION *cs);

/** Open a new socket or other packet source
 *
 * @param[in] instance  of the #fr_app_t.
 * @param[in] sc	we should register sockets with.
 * @param[in] cs	of the listen section that created this #fr_app_t.
 * @return
 *	- 0 on success.
 *	- <0 on failure.
 */
typedef int (*fr_app_open_t)(void *instance, fr_schedule_t *sc, CONF_SECTION *cs);

/** Set the next state executed by the request to be one of the application subtype's entry points
 *
 * @param[in] instance	of the #fr_app_t.
 * @param[in] request	To set the next state function for.
 */
typedef void (*fr_app_entry_point_set_t)(void const *instance, REQUEST *request);

/** Set the priority of a packet
 *
 * @param[in] instance	of the #fr_app_t.
 * @param[in] buffer	raw packet
 * @param[in] buflen	length of the packet
 * @return
 *	-1 - error, drop the packet
 *	0  - no error, but we still drop the packet
 *	*  - the priority of this packet
 */
typedef int (*fr_app_priority_get_t)(void const *instance, uint8_t const *buffer, size_t buflen);

/** Called by the network thread to pass an event list for the module to use for timer events
 */
typedef void (*fr_app_event_list_set_t)(void *instance, fr_event_list_t *el, void *nr);

/** Describes a new application (protocol)
 *
 * This is the main application structure.  It contains different callbacks that
 * are run at different points during the server lifecycle and are called by the IO
 * framework.
 *
 * How the fr_app_t operates is specific to each protocol.
 */
typedef struct {
	RAD_MODULE_COMMON;				//!< Common fields to all loadable modules.

	fr_app_bootstrap_t		bootstrap;	//!< Bootstrap function to allow the fr_app_t to load the
							///< various submodules it requires.

	fr_app_instantiate_t		instantiate;	//!< Instantiate function to perform config validation and
							///< massaging.

	fr_app_open_t			open;		//!< Callback to allow the #fr_app_t to build an #fr_listen_t
							///< and register it with the scheduler so we can receive
							///< data.

	fr_io_decode_t			decode;		//!< Translate raw bytes into VALUE_PAIRs and metadata.
							///< May be NULL.
							///< Here for convenience, so that decode operations common
							///< to all #fr_app_io_t can be performed by the #fr_app_t.

	fr_io_encode_t			encode;		//!< Pack VALUE_PAIRs back into a byte array.
							///< May be NULL.
							///< Here for convenience, so that encode operations common
							///< to all #fr_app_io_t can be performed by the #fr_app_t.

	fr_app_entry_point_set_t	entry_point_set;//!< Callback to Set the entry point into the state machine
							///< provided by the fr_app_worker_t.
							///< We need a function this as the #fr_app_worker_t might
							///< change based on the packet we received.

	fr_app_priority_get_t		priority;	//!< Assign a priority to the packet.
} fr_app_t;

/** Public structure describing an application (protocol) specialisation
 *
 * The fr_app_worker_t provides the state machine that's used to process
 * the packet after its been decoded.
 */
typedef struct {
	RAD_MODULE_COMMON;				//!< Common fields to all loadable modules.

	fr_app_bootstrap_t		bootstrap;
	fr_app_instantiate_t		instantiate;
	fr_io_process_t			entry_point;	//!< Entry point into the protocol subtype's state machine.
} fr_app_worker_t;

/** Public structure describing an I/O path for a protocol
 *
 * This structure is exported by I/O modules e.g. proto_radius_udp.
 */
typedef struct {
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
	fr_io_set_fd_t			fd_set;		//!< Set the file descriptor to the instance.

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

	fr_io_data_cmp_t		compare;	//!< compare two packets

	fr_io_connection_set_t		connection_set;	//!< set src/dst IP/port of a connection
	fr_io_network_get_t		network_get;	//!< get dynamic network information
	fr_io_client_find_t		client_find;	//!< find radclient

	void				*private;	//!< any private APIs it needs to export.
} fr_app_io_t;
