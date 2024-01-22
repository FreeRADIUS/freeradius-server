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
 * @file lib/bio/haproxy.h
 * @brief Binary IO abstractions for HA proxy protocol interceptors
 *
 *  The haproxy bio should be inserted before an FD bio.  The caller
 *  can then read from it until the "activation" function is called.
 *  The activate callback should unchain the haproxy bio, and add the
 *  real top-level bio.  Or, just use the FD bio as-is.
 *
 *  This process means that the caller should manually cache pointers
 *  to the individual bios, so that they can be tracked and queried as
 *  necessary.
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(lib_bio_fd_h, "$Id$")

#include <freeradius-devel/util/socket.h>

/** Data structure which describes the "real" client connection.
 *
 */
typedef struct {
	fr_socket_t	socket;
} fr_bio_haproxy_info_t;

fr_bio_t	*fr_bio_haproxy_alloc(TALLOC_CTX *ctx, fr_bio_cb_funcs_t *cb, fr_bio_t *next) CC_HINT(nonnull);

fr_bio_haproxy_info_t const *fr_bio_haproxy_info(fr_bio_t *bio) CC_HINT(nonnull);
