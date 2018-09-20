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
 * @file proto_detail.h
 * @brief Detail master protocol handler.
 *
 * @copyright 2017  Alan DeKok <alan@freeradius.org>
 */
RCSIDH(detail_h, "$Id$")

#include <freeradius-devel/server/modules.h>
#include <freeradius-devel/util/dlist.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct proto_detail_t {
	CONF_SECTION			*server_cs;			//!< server CS for this listener
	CONF_SECTION			*cs;				//!< my configuration
	fr_app_t			*self;				//!< child / parent linking issues

	dl_instance_t			*io_submodule;			//!< As provided by the transport_parse
									///< callback.  Broken out into the
									///< app_io_* fields below for convenience.

	fr_app_io_t const		*app_io;			//!< Easy access to the app_io handle.
	void				*app_io_instance;		//!< Easy access to the app_io instance.
	CONF_SECTION			*app_io_conf;			//!< Easy access to the app_io's config section.
//	proto_detail_app_io_t		*app_io_private;		//!< Internal interface for proto_radius.

	dl_instance_t			*work_submodule;		//!< the worker

	fr_app_io_t const		*work_io;			//!< Easy access to the app_io handle.
	void				*work_io_instance;		//!< Easy access to the app_io instance.
	CONF_SECTION			*work_io_conf;			//!< Easy access to the app_io's config secti


	dl_instance_t			*type_submodule;		//!< Instance of the type

	uint32_t			code;				//!< RADIUS code to use for incoming packets
	uint32_t			max_packet_size;		//!< for message ring buffer
	uint32_t			num_messages;			//!< for message ring buffer
	uint32_t			priority;			//!< for packet processing, larger == higher

	fr_schedule_t			*sc;				//!< the scheduler, where we insert new readers

	fr_listen_t			*listen;			//!< The listener structure which describes
									//!< the I/O path.
#ifdef HAVE_PTHREAD_H
	pthread_mutex_t			worker_mutex;			//!< for the workers
#endif
	int				num_workers;			//!< number of workers

} proto_detail_t;

/*
 *	The detail "work" data structure, shared by all of the detail readers.
 */
typedef struct proto_detail_work_t {
	CONF_SECTION			*cs;			//!< our configuration section
	proto_detail_t			*parent;		//!< The module that spawned us!
	char const			*name;			//!< debug name for printing

	int				fd;			//!< file descriptor
	int				vnode_fd;      		//!< file descriptor for vnode_delete

	fr_event_list_t			*el;			//!< for various timers

	char const			*directory;     	//!< containing the file below
	char const			*filename;     		//!< file name, usually with wildcards
	char const			*filename_work;		//!< work file name

	uint32_t			poll_interval;		//!< interval between polling

	uint32_t			lock_interval;		//!< interval between trying the locks.

	uint32_t			irt;
	uint32_t			mrt;
	uint32_t			mrc;
	uint32_t			mrd;
	uint32_t			max_outstanding;	//!< number of packets to run in parallel
	uint32_t       			outstanding;		//!< number of currently outstanding records;

	fr_dlist_head_t			list;			//!< for retransmissions

	bool				vnode;			//!< are we the vnode instance,
								//!< or the filename_work instance?
	bool				eof;			//!< are we at EOF on reading?
	bool				closing;		//!< we should be closing the file

	bool				track_progress;		//!< do we track progress by writing?
	bool				retransmit;		//!< are we retransmitting on error?
	bool				paused;			//!< Is reading paused?
	bool				free_on_close;		//!< free the worker on close

	int				mode;			//!< O_RDWR or O_RDONLY

	int				count;			//!< number of packets we read from this file.

	size_t				leftover;
	uint8_t				*leftover_buffer;

	size_t				last_search;		//!< where we last searched in the buffer
								//!< MUST be offset, as the buffers can change.

	off_t				file_size;		//!< size of the file
	off_t				header_offset;		//!< offset of the current header we're reading
	off_t				read_offset;		//!< where we're reading from in filename_work

	fr_event_timer_t const		*ev;			//!< for detail file timers.
	RADCLIENT			*client;		//!< so the rest of the server doesn't complain

	fr_network_t			*nr;			//!< for Linux-specific callbacks
} proto_detail_work_t;

typedef struct proto_detail_process_t {
	rlm_components_t	recv_type;
	rlm_components_t	send_type;
} proto_detail_process_t;

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#define PTHREAD_MUTEX_LOCK   pthread_mutex_lock
#define PTHREAD_MUTEX_UNLOCK pthread_mutex_unlock

#else
#define PTHREAD_MUTEX_LOCK
#define PTHREAD_MUTEX_UNLOCK
#endif

#ifdef __cplusplus
}
#endif
