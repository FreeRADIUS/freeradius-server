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

#ifdef __cplusplus
extern "C" {
#endif

#ifdef HAVE_WDOCUMENTATION
DIAG_OFF(documentation)
#endif
#include <unbound.h>
#include <unbound-event.h>
#ifdef HAVE_WDOCUMENTATION
DIAG_ON(documentation)
#endif

/** Wrapper around our event loop specifying callbacks for creating new event handles
 *
 * This stores libunbound specific information in addition to the el for the current
 * worker thread.  It's passed into the 'new_event' callback when a new event handle
 * is created.  So we use it to pass in the el, and any other useful information.
 *
 * Lifetime should be bound to the thread instance.
 */
typedef struct {
	struct ub_event_base	base;		//!< Interface structure for libunbound.
						///< MUST BE LISTED FIRST.
	struct ub_ctx		*ub;		//!< Unbound ctx instantiated from this event base.

	fr_event_list_t		*el;		//!< Event loop events should be inserted into.
} unbound_io_event_base_t;

int unbound_io_init(TALLOC_CTX *ctx, unbound_io_event_base_t **ev_b_out, fr_event_list_t *el);

#ifdef __cplusplus
}
#endif
