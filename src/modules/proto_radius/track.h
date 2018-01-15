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
#ifndef _FR_TRACK_H
#define _FR_TRACK_H
/**
 * $Id$
 *
 * @file proto_radius/track.h
 * @brief RADIUS packet tracking.
 *
 * @copyright 2016 Alan DeKok <aland@freeradius.org>
 */
RCSIDH(track_h, "$Id$")

#include <freeradius-devel/io/channel.h>
#include <freeradius-devel/libradius.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct fr_tracking_t fr_tracking_t;

/**
 *  An entry for the tracking table.  It contains the minimum
 *  information required to track RADIUS packets.
 *
 *  @todo include event information, so that this tracking entry can
 *  be cleaned up at an appropriate time.
 */
typedef struct fr_tracking_entry_t {
	fr_tracking_t		*ft;		//!< for cleanup_delay
	fr_event_timer_t const	*ev;		//!< for cleanup_delay

	size_t			src_dst_size;   //!< size of the data in src_dst
	fr_time_t		timestamp;	//!< when the request was received
	uint8_t const		*reply;		//!< the response (if any);
	size_t			reply_len;	//!< the length of the response
	uint8_t			data[20];	//!< the full RADIUS packet header
	uint64_t       		src_dst[0];	//!< information about src/dst IP/port
} fr_tracking_entry_t;

/**
 *  The status of an insert.
 */
typedef enum fr_tracking_status_t {
	FR_TRACKING_ERROR = -1,
	FR_TRACKING_UNUSED = 0,
	FR_TRACKING_NEW,
	FR_TRACKING_SAME,
	FR_TRACKING_UPDATED,
	FR_TRACKING_CONFLICTING,
} fr_tracking_status_t;

fr_tracking_t			*fr_radius_tracking_create(TALLOC_CTX *ctx, size_t src_dst_size,
							   bool const allowed_packets[FR_MAX_PACKET_CODE]);

int				fr_radius_tracking_entry_delete(fr_tracking_t *ft,
								fr_tracking_entry_t *entry) CC_HINT(nonnull);

fr_tracking_status_t		fr_radius_tracking_entry_insert(fr_tracking_entry_t **p_entry,
								fr_tracking_t *ft, uint8_t *packet, fr_time_t timestamp,
								void *src_dst);

int				fr_radius_tracking_entry_reply(fr_tracking_t *ft, fr_tracking_entry_t *entry,
							       fr_time_t reply_time,
							       uint8_t const *reply, size_t reply_len);
#ifdef __cplusplus
}
#endif

#endif /* _FR_TRACK_H */
