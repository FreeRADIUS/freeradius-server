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
 * @file protocols/radius/server_priv.h
 * @brief RADIUS bio handlers for outgoing RADIUS private server sockets
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(radius_server_priv_h, "$Id$")

#include <freeradius-devel/radius/server.h>
#include <freeradius-devel/radius/id.h>

/*
 *	Server connected data structure
 */
typedef struct {
	fr_bio_packet_t		common;

	fr_radius_server_config_t cfg;

	fr_bio_t		*dedup;
	fr_bio_t		*mem;
	fr_bio_t		*fd;

	fr_radius_server_bio_info_t info;

	fr_rb_tree_t		rb;

	/*
	 *	@todo - perhaps we want to have the read() routine allocate memory for the packet?  Or the
	 *	verify routine can do that?
	 */
	uint8_t			buffer[4096];	//!< temporary read buffer
} fr_radius_server_fd_bio_t;

fr_radius_server_fd_bio_t *fr_radius_server_fd_bio_alloc(TALLOC_CTX *ctx, size_t read_size, fr_radius_server_config_t *cfg, fr_bio_fd_config_t const *fd_cfg) CC_HINT(nonnull);

int	fr_radius_server_fd_bio_write(fr_bio_packet_t *bio, void *pctx, fr_packet_t *packet, fr_pair_list_t *list);

int	fr_radius_server_fd_bio_read(fr_bio_packet_t *bio, void **packet_ctx_p, fr_packet_t **packet_p, TALLOC_CTX *out_ctx, fr_pair_list_t *out);
