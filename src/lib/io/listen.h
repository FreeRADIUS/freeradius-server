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
#include <freeradius-devel/io/time_tracking.h>

/** Describes a path data takes to/from the wire to/from VALUE_PAIRs
 *
 */
typedef struct fr_listen fr_listen_t;
struct fr_listen {
	int			fd;			//!< file descriptor for this socket - set by open
	char const		*name;			//!< printable name for this socket - set by open

	fr_app_io_t const	*app_io;		//!< I/O path functions.
	void const    		*app_io_instance;	//!< I/O path configuration context.
	void			*thread_instance;	//!< thread / socket context

	fr_socket_addr_t	*app_io_addr;		//!< for tracking duplicate sockets

	fr_app_t const		*app;
	void const		*app_instance;

	CONF_SECTION		*server_cs;		//!< CONF_SECTION of the server

	bool			connected;		//!< is this for a connected socket?
	size_t			default_message_size;	//!< copied from app_io, but may be changed
	size_t			num_messages;		//!< for the message ring buffer
};

/**
 *	Minimal data structure to use the new code.
 */
struct fr_async_s {
	fr_io_process_t		process;		//!< The current state function.
	void			*process_inst;		//!< Instance data for the current state machine.

	fr_time_t		recv_time;
	fr_time_t		*original_recv_time;
	fr_event_list_t		*el;

	fr_time_tracking_t	tracking;
	fr_channel_t		*channel;

	void			*packet_ctx;
	fr_listen_t		*listen;	//!< How we received this request,
						//!< and how we'll send the reply.
	uint32_t		priority;
	bool			fake;		//!< is it a fake request
};

int fr_io_listen_free(fr_listen_t *li);
