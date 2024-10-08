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
 * @file protocols/radius/server.h
 * @brief RADIUS bio handlers for outgoing RADIUS server sockets
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(radius_server_h, "$Id$")

#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/radius/bio.h>
#include <freeradius-devel/bio/packet.h>
#include <freeradius-devel/bio/fd.h>
#include <freeradius-devel/bio/dedup.h>

typedef struct {
	fr_log_t		*log;

	fr_radius_bio_verify_t	verify;

	fr_bio_dedup_config_t	dedup_cfg;

	fr_bio_packet_cb_funcs_t packet_cb_cfg;
} fr_radius_server_config_t;

typedef struct {
	bool			connected;
	bool			write_blocked;
	bool			read_blocked;

	fr_bio_fd_info_t const	*fd_info;
} fr_radius_server_bio_info_t;

typedef struct {
	fr_bio_fd_packet_ctx_t	fd;
	fr_bio_dedup_entry_t	*dedup;
} fr_radius_server_bio_pctx_t;

fr_bio_packet_t *fr_radius_server_bio_alloc(TALLOC_CTX *ctx, fr_radius_server_config_t *cfg, fr_bio_fd_config_t const *fd_cfg) CC_HINT(nonnull);

fr_bio_t	*fr_radius_server_bio_get_fd(fr_bio_packet_t *bio) CC_HINT(nonnull);

fr_radius_server_bio_info_t const *fr_radius_server_bio_info(fr_bio_packet_t *bio) CC_HINT(nonnull);
