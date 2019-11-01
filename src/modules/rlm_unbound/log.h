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
RCSIDH(rlm_unbound_log_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/server/request.h>

#ifdef HAVE_WDOCUMENTATION
DIAG_OFF(documentation)
#endif
#include <unbound.h>
#ifdef HAVE_WDOCUMENTATION
DIAG_ON(documentation)
#endif

/** Logging state
 *
 */
typedef struct {
	REQUEST		*request;		//!< Request we're logging to.
	FILE		*stream;		//!< Stream we use to interface with the
						///< FreeRADIUS logging functions.
} unbound_log_t;

int	unbound_log_to_request(unbound_log_t *u_log, struct ub_ctx *ub, REQUEST *request);

int	unbound_log_to_global(unbound_log_t *u_log, struct ub_ctx *ub);

int	unbound_log_init(TALLOC_CTX *ctx, unbound_log_t **u_log_out, struct ub_ctx *ub);

#ifdef __cplusplus
}
#endif
