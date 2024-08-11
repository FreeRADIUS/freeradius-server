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
 * @file lib/bio/dedup.h
 * @brief Binary IO abstractions for deduping of raw packets
 *
 * Read packets from a dedup bio.  Once a packet is read, it is checked
 * against a dedup tree.  Duplicate packets are suppressed.
 *
 * The caller has to manage the actual dedup tree and comparisons.
 * Each protocol has its own requirements for dedup, and it is too
 * awkward to make a generic method which works everywhere.
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(lib_bio_dedup_h, "$Id$")

#include <freeradius-devel/util/event.h>

typedef struct {
	fr_event_list_t		*el;		//!< event list

	fr_time_delta_t		lifetime;	//!< default lifetime of dedup entry
} fr_bio_dedup_config_t;

typedef struct fr_bio_dedup_entry_s fr_bio_dedup_entry_t;

#ifndef _BIO_DEDUP_PRIVATE
struct  fr_bio_dedup_entry_s {
	void		*uctx;			//!< user-writable context
	void		*packet_ctx;		//!< packet_ctx for dedup purposes
	uint8_t		*packet;	       	//!< cached packet data.
	size_t		packet_size;		//!< size of the cached packet data
	void		*reply_ctx;		//!< reply ctx
	uint8_t		*reply;			//!< reply cached by the application
	size_t		reply_size;		//!< size of the cached reply

	fr_rb_node_t	dedup;			//!< user managed dedup node
};
#endif

typedef enum {
	FR_BIO_DEDUP_EXPIRED = 0,
	FR_BIO_DEDUP_CANCELLED,
	FR_BIO_DEDUP_WRITE_ERROR,
	FR_BIO_DEDUP_INTERNAL_ERROR,
} fr_bio_dedup_release_reason_t;

/** Callback on read to see if we should receive the packet.
 *
 *  The caller should cache dedup_ctx, unless it's a duplicate request.
 *
 *  If it's a duplicate request, the caller should call fr_bio_dedup_respond() to write out the reply.
 *
 *  @param bio		the binary IO handler
 *  @param dedup_ctx	new dedup_ctx assigned to this potential packet
 *  @param packet_ctx	per-packet context for the response
 *  @return
 *	- false - discard the packet
 *	- true - create a new entry for the packet
 */
typedef bool (*fr_bio_dedup_receive_t)(fr_bio_t *bio, fr_bio_dedup_entry_t *dedup_ctx, void *packet_ctx);

/** Callback on release the packet (timeout, or cancelled by the application)
 *
 *  The callback function should clean up any resources associated with the packet.  The resources MUST NOT be
 *  released until the data is either "released" or "cancelled".
 *
 *  The packet will be cancelled after this call returns.  The cancellation callback will NOT be run.
 *
 *  @param bio		the binary IO handler
 *  @param dedup_ctx	the dedup ctx to release
 *  @param reason	why this packet is being released
 */
typedef void	(*fr_bio_dedup_release_t)(fr_bio_t *bio, fr_bio_dedup_entry_t *dedup_ctx, fr_bio_dedup_release_reason_t reason);

typedef fr_bio_dedup_entry_t *(*fr_bio_dedup_get_item_t)(fr_bio_t *bio, void *packet_ctx);

fr_bio_t	*fr_bio_dedup_alloc(TALLOC_CTX *ctx, size_t max_saved,
				    fr_bio_dedup_receive_t receive,
				    fr_bio_dedup_release_t release,
				    fr_bio_dedup_get_item_t get_item,
				    fr_bio_dedup_config_t const *cfg,
				    fr_bio_t *next) CC_HINT(nonnull(1,3,4,6,7));

void		fr_bio_dedup_entry_cancel(fr_bio_t *bio, fr_bio_dedup_entry_t *dedup_ctx) CC_HINT(nonnull);

ssize_t		fr_bio_dedup_respond(fr_bio_t *bio, fr_bio_dedup_entry_t *item) CC_HINT(nonnull);

int		fr_bio_dedup_entry_extend(fr_bio_t *bio, fr_bio_dedup_entry_t *dedup_ctx, fr_time_t expires) CC_HINT(nonnull);
