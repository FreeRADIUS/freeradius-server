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
 * @file protocols/radius/client.h
 * @brief RADIUS bio handlers for outgoing RADIUS client sockets
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(radius_client_h, "$Id$")

#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/radius/bio.h>
#include <freeradius-devel/bio/packet.h>
#include <freeradius-devel/bio/fd.h>
#include <freeradius-devel/bio/retry.h>

typedef struct {
	fr_event_list_t		*el;
	fr_log_t		*log;

	fr_radius_bio_verify_t	verify;

	fr_bio_retry_config_t	retry_cfg;

	fr_bio_packet_cb_funcs_t packet_cb_cfg;

	fr_time_delta_t		connection_timeout;

	bool			add_proxy_state;
	uint64_t		proxy_state;

	bool			outgoing[FR_RADIUS_CODE_MAX];	//!< allowed outgoing packet types

	fr_retry_config_t 	retry[FR_RADIUS_CODE_MAX];	//!< default retry configuration for each packet type
} fr_radius_client_config_t;

typedef struct {
	bool			connected;

	fr_bio_fd_info_t const	*fd_info;

	size_t			outstanding;		//!< total number of outstanding packets.

	fr_time_t		mrs_time;		//!< Most recent sent time which had a reply.
	fr_time_t		last_reply;		//!< When we last received a reply.
	fr_time_t		first_sent;		//!< first time we sent a packet since going idle
	fr_time_t		last_sent;		//!< last time we sent a packet.
	fr_time_t		last_idle;		//!< last time we had nothing to do

	fr_bio_retry_info_t const	*retry_info;
} fr_radius_client_bio_info_t;

fr_bio_packet_t *fr_radius_client_bio_alloc(TALLOC_CTX *ctx, fr_radius_client_config_t *cfg, fr_bio_fd_config_t const *fd_cfg) CC_HINT(nonnull);

int		fr_radius_client_fd_bio_cancel(fr_bio_packet_t *bio, fr_packet_t *packet) CC_HINT(nonnull);

fr_radius_client_bio_info_t const *fr_radius_client_bio_info(fr_bio_packet_t *bio) CC_HINT(nonnull);

size_t		fr_radius_client_bio_outstanding(fr_bio_packet_t *bio) CC_HINT(nonnull);

int		fr_radius_client_bio_force_id(fr_bio_packet_t *bio, int code, int id);

void		fr_radius_client_bio_connect(fr_event_list_t *el, int fd, int flags, void *uctx);
