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
 * @file io/app_io.h
 * @brief Application IO interfaces.
 *
 * @copyright 2018 The FreeRADIUS project
 */


/** Public structure describing an I/O path for a protocol
 *
 * This structure is exported by I/O modules e.g. proto_radius_udp.
 */
typedef struct {
	DL_MODULE_COMMON;				//!< Common fields to all loadable modules.

	fr_app_bootstrap_t		bootstrap;
	fr_app_instantiate_t		instantiate;
	fr_app_event_list_set_t		event_list_set;	//!< Called by the network thread to pass an event list
							//!< for use by the app_io_t.

	size_t				default_message_size;	//!< Usually maximum message size
	size_t				default_reply_size;	//!< same for replies
	size_t				thread_inst_size;	//!< thread-specific socket information size
	bool				track_duplicates;	//!< track duplicate packets

	fr_io_open_t			open;		//!< Open a new socket for listening, or accept/connect a new
							//!< connection.
	fr_io_set_fd_t			fd_set;		//!< Set the file descriptor to the instance.

	fr_io_data_read_t		read;		//!< Read from a socket to a data buffer
	fr_io_data_write_t		write;		//!< Write from a data buffer to a socket

	fr_io_data_inject_t		inject;		//!< Inject a packet into a socket.

	fr_io_data_vnode_t		vnode;		//!< Handle notifications that the VNODE has changed

	fr_io_decode_t			decode;		//!< Translate raw bytes into VALUE_PAIRs and metadata.
	fr_io_encode_t			encode;		//!< Pack VALUE_PAIRs back into a byte array.

	fr_io_signal_t			flush;		//!< Flush the data when the socket is ready for writing.

	fr_io_signal_t			error;		//!< There was an error on the socket.
	fr_io_close_t			close;		//!< Close the transport.

	fr_io_nak_t			nak;		//!< Function to send a NAK.

	fr_io_track_create_t		track;		//!< create a tracking structure
	fr_io_track_cmp_t		compare;	//!< compare two tracking structures

	fr_io_connection_set_t		connection_set;	//!< set src/dst IP/port of a connection
	fr_io_network_get_t		network_get;	//!< get dynamic network information
	fr_io_client_find_t		client_find;	//!< find radclient
	fr_io_name_t			get_name;	//!< get the socket name

	void				*private;	//!< any private APIs it needs to export.
} fr_app_io_t;

/*
 *	A common function to get a humanly readable socket name.
 */
char const *fr_app_io_socket_name(TALLOC_CTX *ctx, fr_app_io_t const *app_io,
				  fr_ipaddr_t const *src_ipaddr, int src_port,
				  fr_ipaddr_t const *dst_ipaddr, int dst_port,
				  char const *interface);
/*
 *	A common function to get a machine readable socket name
 */
fr_socket_addr_t *fr_app_io_socket_addr(TALLOC_CTX *ctx, int proto, fr_ipaddr_t const *ipaddr, int port);
