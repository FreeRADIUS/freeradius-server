#pragma once
/*
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
 */

/**
 * $Id$
 *
 * @brief Function prototypes and datatypes for the REST (HTTP) transport.
 * @file rlm_unbound/unbound.h
 *
 * @copyright 2019 The FreeRADIUS server project
 * @copyright 2019 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(rlm_unbound_io_h, "$Id$")


#ifdef HAVE_WDOCUMENTATION
DIAG_OFF(documentation)
#endif
#include <unbound.h>
#ifdef HAVE_WDOCUMENTATION
DIAG_ON(documentation)
#endif

typedef struct unbound_io_event_base_s unbound_io_event_base_t;

typedef struct {
	struct ub_ctx		*ub;		//!< There's one unbound context per thread, as they
						///< contain the event list configuration, so we need
						///< one per worker event loop.
	unbound_io_event_base_t *ev_b;		//!< Contains callbacks and configuration libunbound
						///< needs when creating new rlm_unbound_event_t.
						///< Must be freed after the ub_ctx.
} rlm_unbound_thread_t;

/*
 *	io.c
 */
int	unbound_io_init(rlm_unbound_thread_t *t, fr_event_list_t *el);
void	unbound_io_free(rlm_unbound_thread_t *t);
