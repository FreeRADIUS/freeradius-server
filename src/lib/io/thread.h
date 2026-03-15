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
 * @file io/thread.h
 * @brief Common thread instantiation and detach for worker and coordinator threads
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(thread_h, "$Id$")

#include <freeradius-devel/util/event.h>
#include <freeradius-devel/util/semaphore.h>
#include <freeradius-devel/util/talloc.h>
#include <freeradius-devel/util/dlist.h>

#include <pthread.h>

typedef void *(*fr_thread_entry_t)(void *);

int	fr_thread_create(pthread_t *thread, fr_thread_entry_t func, void *arg);

void	fr_thread_wait(fr_sem_t *sem, unsigned int count);

int	fr_thread_setup(TALLOC_CTX **ctx, fr_event_list_t **el, char const *name);

int	fr_thread_instantiate(TALLOC_CTX *ctx, fr_event_list_t *el);

void	fr_thread_detach(void);
