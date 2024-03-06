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
 * @file lib/bio/retry.h
 * @brief Binary IO abstractions for retrying of raw packets
 *
 * Write packets of data to bios.  Once a packet is written, it is
 * retried until a response is returned.  Note that this ONLY works
 * for datagram bios, where the packets can be retransmitted
 * identically without any changes.
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(lib_bio_retry_h, "$Id$")

#include <freeradius-devel/util/retry.h>
#include <freeradius-devel/util/event.h>

typedef struct {
	fr_event_list_t		*el;		//!< event list

	fr_retry_config_t	retry_config;	//!< base retry config
} fr_bio_retry_config_t;

typedef struct fr_bio_retry_entry_s fr_bio_retry_entry_t;

typedef enum {
	FR_BIO_RETRY_DONE = 0,
	FR_BIO_RETRY_NO_REPLY,
	FR_BIO_RETRY_CANCELLED,
	FR_BIO_RETRY_WRITE_ERROR,
} fr_bio_retry_release_reason_t;

/** Callback for when a packet is sent
 *
 *  The purpose of the callback is for the application to save the retry_ctx, in case the packet needs to be
 *  cancelled at a later point in time.
 *
 *  @param bio		the binary IO handler
 *  @param packet_ctx	per-packet context
 *  @param buffer	raw data for the packet
 *  @param size		size of the raw data
 *  @param retry_ctx	pointer to save for use with later cancellation
 */
typedef void	(*fr_bio_retry_sent_t)(fr_bio_t *bio, void *packet_ctx, const void *buffer, size_t size,
				       fr_bio_retry_entry_t *retry_ctx);

typedef ssize_t	(*fr_bio_retry_rewrite_t)(fr_bio_t *bio, fr_bio_retry_entry_t *retry_ctx, const void *buffer, size_t size);

/** Callback on read to see if a packet is a response
 *
 *  The callback should manually associate the response with a request, but allow the packet to be returned
 *  to the application.
 *
 *  The callback should also set item_p, _even if the response is duplicate_.  That way the retry bio can
 *  properly track multiple requests and responses.
 *
 *  If there is a fatal error reading the response, the callback should set a flag (in the bio)? and return.
 *  It should NOT call any bio shutdown routine.
 *
 *  @param bio		the binary IO handler
 *  @param[out] item_p	item pointer for request, from #fr_bio_retry_saved_t
 *  @param packet_ctx	per-packet context for the response
 *  @param buffer	raw data for the response
 *  @param size		size of the raw response data
 *  @return
 *	- false - do not pass the packet to the reader
 *	- true - pass the packet through to the reader
 */
typedef bool (*fr_bio_retry_response_t)(fr_bio_t *bio, fr_bio_retry_entry_t **item_p, void *packet_ctx, const void *buffer, size_t size);

/** Callback on release the packet (timeout or have all replies)
 *
 *  The callback function should clean up any resources associated with the packet.  The resources MUST NOT be
 *  released until the data is either "released" or "cancelled".
 *
 *  The packet will be cancelled after this call returns.  The cancellation callback will NOT be run.
 *
 *  @param bio		the binary IO handler
 *  @param packet_ctx	per-packet context
 *  @param buffer	raw data for the packet
 *  @param size		size of the raw data
 *  @param reason	why this packet is being released
 */
typedef void	(*fr_bio_retry_release_t)(fr_bio_t *bio, void *packet_ctx, const void *buffer, size_t size, fr_bio_retry_release_reason_t reason);

fr_bio_t	*fr_bio_retry_alloc(TALLOC_CTX *ctx, size_t max_saved,
				    fr_bio_retry_sent_t sent,
				    fr_bio_retry_response_t response,
				    fr_bio_retry_rewrite_t rewrite,
				    fr_bio_retry_release_t release,
				    fr_bio_retry_config_t const *cfg,
				    fr_bio_t *next) CC_HINT(nonnull(1,3,4,6,7,8));

int		fr_bio_retry_entry_cancel(fr_bio_t *bio, fr_bio_retry_entry_t *retry_ctx) CC_HINT(nonnull);

int		fr_bio_retry_entry_start(fr_bio_t *bio, fr_bio_retry_entry_t *retry_ctx, fr_retry_config_t const *cfg) CC_HINT(nonnull);

const fr_retry_t *fr_bio_retry_entry_info(fr_bio_t *bio, fr_bio_retry_entry_t *retry_ctx) CC_HINT(nonnull);

ssize_t		fr_bio_retry_rewrite(fr_bio_t *bio, fr_bio_retry_entry_t *retry_ctx, const void *buffer, size_t size) CC_HINT(nonnull(1,2));
