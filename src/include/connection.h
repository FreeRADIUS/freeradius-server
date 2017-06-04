/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 * @file conn.h
 * @brief Simple state machine for managing connection states.
 *
 * @copyright 2017 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
#include <talloc.h>
#include <freeradius-devel/event.h>

typedef struct fr_conn fr_conn_t;

typedef enum {
	FR_CONNECTION_STATE_INIT = 0,		//!< Init state, sets up connection.
	FR_CONNECTION_STATE_CONNECTING,		//!< Waiting for file descriptor to open.
	FR_CONNECTION_STATE_TIMEOUT,		//!< Timeout during #FR_CONNECTION_STATE_CONNECTING.
	FR_CONNECTION_STATE_CONNECTED,		//!< File descriptor is open (ready for writing).
	FR_CONNECTION_STATE_FAILED		//!< File descriptor errored, and is waiting to reconnect.
} fr_conn_state_t;

/** Callback for the initialise state
 *
 * Should attempt to open a non-blocking connection and return it in fd_out.
 *
 * @param[out] fd_out	Where to write the new file descriptor.
 * @param[in] uctx	User context.
 * @return
 *	- FR_CONNECTION_STATE_CONNECTING	if a file descriptor was successfully created.
 *	- FR_CONNECTION_STATE_FAILED	if we could not open a file descriptor.
 */
typedef fr_conn_state_t (*fr_conn_init_t)(int *fd_out, void *uctx);

/** Notification that the connection is now open
 *
 * This should be used to add any additional I/O events for the file descriptor
 * to call other code if it becomes readable or writable.
 *
 * @param[in] fd	That was successfully opened.
 * @param[in] el	to use for inserting I/O events.
 * @param[in] uctx	User context.
 * @return
 *	- FR_CONNECTION_STATE_CONNECTED		if the file descriptor is useable.
 *	- FR_CONNECTION_STATE_FAILED	if the file descriptor is unusable.
 */
typedef fr_conn_state_t (*fr_conn_open_t)(int fd, fr_event_list_t *el, void *uctx);

/** Notification that the connection has errored and must be closed
 *
 * This should be used to close the file descriptor.  It is assumed
 * that the file descriptor is invalid after this callback has been executed.
 *
 * If this callback does not close the file descriptor, the server will leak
 * file descriptors.
 *
 * @param[in] fd	to close.
 * @param[in] uctx	User context.
 */
typedef void (*fr_conn_close_t)(int fd, void *uctx);


fr_conn_t const		*fr_conn_alloc(TALLOC_CTX *ctx, fr_event_list_t *el,
			       	       struct timeval *open_time, struct timeval *wait_time,
				       fr_conn_init_t init, fr_conn_open_t open, fr_conn_close_t close,
				       char const *log_prefix,
				       void *uctx);
int			fr_conn_get_fd(fr_conn_t const *conn);
void			fr_conn_reconnect(fr_conn_t *conn);
