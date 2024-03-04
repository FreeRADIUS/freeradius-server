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
 * @file lib/bio/queue.h
 * @brief Binary IO abstractions for queues of raw packets
 *
 * Write packets of data to bios.  If a packet is partially
 * read/written, it is cached for later processing.
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(lib_bio_queue_h, "$Id$")

typedef struct fr_bio_queue_entry_s fr_bio_queue_entry_t;

typedef void	(*fr_bio_queue_callback_t)(fr_bio_t *bio, void *packet_ctx, const void *buffer, size_t size);
typedef void	(*fr_bio_queue_saved_t)(fr_bio_t *bio, void *packet_ctx, const void *buffer, size_t size, fr_bio_queue_entry_t *queue_ctx);

fr_bio_t	*fr_bio_queue_alloc(TALLOC_CTX *ctx, size_t max_saved,
				    fr_bio_queue_saved_t saved,
				    fr_bio_queue_callback_t sent,
				    fr_bio_queue_callback_t cancel,
				    fr_bio_t *next) CC_HINT(nonnull(1,6));

int		fr_bio_queue_cancel(fr_bio_t *bio, fr_bio_queue_entry_t *queue_ctx) CC_HINT(nonnull);
