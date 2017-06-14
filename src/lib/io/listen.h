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
#ifndef _FR_IO_LISTEN_H
#define _FR_IO_LISTEN_H
#include <freeradius-devel/io/io.h>
#include <freeradius-devel/io/application.h>


/** Describes a path data takes to/from the wire to/from VALUE_PAIRs
 *
 */
typedef struct fr_io fr_io_t;
struct fr_io {
	fr_io_op_t const	*op;		//!< I/O path functions.
	void			*ctx;		//!< I/O path specific context.

	fr_io_decode_t		decode;		//!< Function to decode packet to request (worker)
	fr_io_encode_t		encode;		//!< Function to encode request to packet (worker)

	fr_app_set_process_t	set_process;	//!< Set the state machine entry point for a request.
	void const		*app_ctx;
};

#ifndef _FR_RADIUSD_H
/**
 *	Minimal data structure to use the new code.
 */
struct rad_request {
	uint64_t		number;
	int			heap_id;

	fr_dlist_t		time_order;	//!< tracking requests by time order
	fr_heap_t		*runnable;	//!< heap of runnable requests

	fr_time_t		recv_time;
	fr_time_t		*original_recv_time;
	fr_event_list_t		*el;
	fr_io_process_t		process_async;
	fr_time_tracking_t	tracking;
	fr_channel_t		*channel;

	uint32_t		priority;
	fr_io_t	const		*io;		//!< How we received this request,
						//!< and how we'll send the reply.
};
#endif
#endif
