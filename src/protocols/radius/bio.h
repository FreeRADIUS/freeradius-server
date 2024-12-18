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
 * @file protocols/radius/bio.h
 * @brief RADIUS bio handlers
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(radius_bio_h, "$Id$")

#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/bio/fd.h>
#include <freeradius-devel/bio/mem.h>
#include <freeradius-devel/util/retry.h>

typedef struct {
	uint8_t const	*secret;
	size_t		secret_len;

	uint32_t	max_attributes;
	uint32_t	max_packet_size;

	bool		allowed[FR_RADIUS_CODE_MAX];	//!< allowed outgoing packet types

	bool		require_message_authenticator;
	bool		limit_proxy_state;
} fr_radius_bio_verify_t;

fr_bio_verify_action_t fr_radius_bio_verify(fr_bio_t *bio, void *verify_ctx, void *packet_ctx, const void *data, size_t *size) CC_HINT(nonnull(1,2,4));

fr_bio_verify_action_t fr_radius_bio_verify_datagram(fr_bio_t *bio, void *verify_ctx , void *packet_ctx, const void *data, size_t *size) CC_HINT(nonnull(1,2,4));
