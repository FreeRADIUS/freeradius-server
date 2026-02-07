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
#include <freeradius-devel/io/base.h>
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/server/time_tracking.h>

/** Describes a path data takes to/from the wire to/from fr_pair_ts
 *
 */
typedef struct fr_listen fr_listen_t;
struct fr_listen {
	fr_rb_node_t		virtual_server_node;	//!< Entry into the virtual server's tree of listeners.

	int			fd;			//!< file descriptor for this socket - set by open
	char const		*name;			//!< printable name for this socket - set by open
	fr_dict_t const		*dict;			//!< dictionary for this listener

	fr_app_io_t const	*app_io;		//!< I/O path functions.
	void const    		*app_io_instance;	//!< I/O path configuration context.
	void			*thread_instance;	//!< thread / socket context

	fr_socket_t		*app_io_addr;		//!< for tracking duplicate sockets

	fr_app_t const		*app;
	void const		*app_instance;

	CONF_SECTION		*cs;			//!< of this listener
	CONF_SECTION		*server_cs;		//!< CONF_SECTION of the server

	bool			connected;		//!< is this for a connected socket?
	bool			track_duplicates;	//!< do we track duplicate packets?
	bool			no_write_callback;     	//!< sometimes we don't need to do writes
	bool			non_socket_listener;	//!< special internal listener that does not use sockets.
	bool			needs_full_setup;	//!< Set to true to avoid the short cut when adding the listener.
							///< Added for rlm_detail which requires inst->parent->sc to be
							///< populated when event_list_set callback is run which doesn't
							///< happen if the short cut is taken.

	bool			read_hexdump;		//!< Do we debug hexdump packets as they're read.
	bool			write_hexdump;		//!< Do we debug hexdump packets as they're written.

	size_t			default_message_size;	//!< copied from app_io, but may be changed
	size_t			num_messages;		//!< for the message ring buffer
};

/**
 *	Minimal data structure to use the new code.
 */
struct fr_async_s {
	fr_time_t		recv_time;
	fr_event_list_t		*el;

	fr_time_tracking_t	tracking;
	fr_channel_t		*channel;

	fr_dlist_t		entry;		//!< in the list of requests associated with this channel

	void			*packet_ctx;
	fr_listen_t		*listen;	//!< How we received this request,
						//!< and how we'll send the reply.
};

int fr_io_listen_free(fr_listen_t *li);
