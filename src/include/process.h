#ifndef FR_PROCESS_H
#define FR_PROCESS_H

/*
 * process.h	State machine for a server to process packets.
 *
 * Version:	$Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2012 The FreeRADIUS server project
 * Copyright 2012 Alan DeKok <aland@deployingradius.com>
 */

RCSIDH(process_h, "$Id$")

#include <freeradius-devel/clients.h>
#include <freeradius-devel/listen.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum fr_state_action_t {	/* server action */
	FR_ACTION_INVALID = 0,
	FR_ACTION_RUN,
	FR_ACTION_DONE,
	FR_ACTION_DUP,
	FR_ACTION_TIMER,
#ifdef WITH_PROXY
	FR_ACTION_PROXY_REPLY,
#endif
} fr_state_action_t;

/*
 *  Function handler for requests.
 */
typedef	int (*RAD_REQUEST_FUNP)(REQUEST *);
typedef	void (*fr_request_process_t)(REQUEST *, int);

extern time_t fr_start_time;

#ifdef HAVE_PTHREAD_H
/*
 *	In threads.c
 */
int request_enqueue(REQUEST *request);
#endif

int request_receive(TALLOC_CTX *ctx, rad_listen_t *listener, RADIUS_PACKET *packet,
		    RADCLIENT *client, RAD_REQUEST_FUNP fun);

#ifdef WITH_PROXY
int request_proxy_reply(RADIUS_PACKET *packet);
#endif

#ifdef __cplusplus
}
#endif

#endif /* FR_PROCESS_H */
