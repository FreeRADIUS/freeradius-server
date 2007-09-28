#ifndef LRAD_EVENT_H
#define LRAD_EVENT_H

/*
 * event.h	Simple event queue
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
 * Copyright 2007 The FreeRADIUS server project
 * Copyright 2007 Alan DeKok <aland@deployingradius.com>
 */

#include <freeradius-devel/ident.h>
RCSIDH(event_h, "$Id$")

typedef struct lrad_event_list_t lrad_event_list_t;
typedef struct lrad_event_t lrad_event_t;

typedef	void (*lrad_event_callback_t)(void *);
typedef	void (*lrad_event_status_t)(struct timeval *);
typedef void (*lrad_event_fd_handler_t)(lrad_event_list_t *el, int sock, void *ctx);

lrad_event_list_t *lrad_event_list_create(lrad_event_status_t status);
void lrad_event_list_free(lrad_event_list_t *el);

int lrad_event_list_num_elements(lrad_event_list_t *el);

int lrad_event_insert(lrad_event_list_t *el,
		      lrad_event_callback_t callback,
		      void *ctx, struct timeval *when, lrad_event_t **ev_p);
int lrad_event_delete(lrad_event_list_t *el, lrad_event_t **ev_p);

int lrad_event_run(lrad_event_list_t *el, struct timeval *when);

int lrad_event_now(lrad_event_list_t *el, struct timeval *when);

int lrad_event_fd_insert(lrad_event_list_t *el, int type, int fd,
			 lrad_event_fd_handler_t handler, void *ctx);
int lrad_event_fd_delete(lrad_event_list_t *el, int type, int fd);
int lrad_event_loop(lrad_event_list_t *el);
void lrad_event_loop_exit(lrad_event_list_t *el);

#endif /* LRAD_HASH_H */
