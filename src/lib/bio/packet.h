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
 * @file lib/bio/packet.h
 * @brief Binary IO abstractions for packets in buffers
 *
 * Write packets of data to bios.  If a packet is partially
 * read/written, it is cached for later processing.
 *
 * @todo - Not quite done yet.  It still needs to be integrated into the bio framework,
 * and be managed through a bio of its own.
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(lib_bio_packet_h, "$Id$")

typedef void	(*fr_bio_packet_callback_t)(fr_bio_t *bio, void *packet_ctx, const void *buffer, size_t size);
typedef void	(*fr_bio_packet_saved_t)(fr_bio_t *bio, void *packet_ctx, const void *buffer, size_t size, void *ctx);

fr_bio_t	*fr_bio_packet_alloc(TALLOC_CTX *ctx, size_t max_saved,
				     fr_bio_packet_saved_t saved,
				     fr_bio_packet_callback_t sent,
				     fr_bio_packet_callback_t cancel,
				     fr_bio_t *next) CC_HINT(nonnull(1,6));

int		fr_bio_packet_cancel(fr_bio_t *bio, void *ctx) CC_HINT(nonnull);
