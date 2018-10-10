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
 * @file lib/server/process.h
 * @brief State machine for a server to process packets.
 *
 * @copyright  2012 The FreeRADIUS server project
 * @copyright  2012 Alan DeKok <aland@deployingradius.com
 */
RCSIDH(process_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	RADIUS_SIGNAL_SELF_NONE		= (0),
	RADIUS_SIGNAL_SELF_HUP		= (1 << 0),
	RADIUS_SIGNAL_SELF_TERM		= (1 << 1),
	RADIUS_SIGNAL_SELF_EXIT		= (1 << 2),
	RADIUS_SIGNAL_SELF_DETAIL	= (1 << 3),
	RADIUS_SIGNAL_SELF_NEW_FD	= (1 << 4),
	RADIUS_SIGNAL_SELF_MAX		= (1 << 5)
} radius_signal_t;

extern time_t fr_start_time;

extern struct timeval sd_watchdog_interval;

#include <freeradius-devel/server/client.h>
#include <freeradius-devel/server/listen.h>
#include <freeradius-devel/server/signal.h>

typedef	void (*fr_request_process_t)(REQUEST *, fr_state_signal_t);	//!< Function handler for requests.

fr_event_list_t		*fr_global_event_list(void);

void			radius_signal_self(int flag);

int			radius_event_init(void);

int			radius_event_start(bool spawn_flag);

void			radius_event_free(void);

int			radius_event_process(void);

void			radius_update_listener(rad_listen_t *listener);

#ifdef __cplusplus
}
#endif
