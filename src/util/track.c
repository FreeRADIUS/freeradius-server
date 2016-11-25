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
 *
 * @brief RADIUS packet tracking
 * @file util/track.c
 *
 * @copyright 2016 Alan DeKok <aland@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/util/track.h>
#include <freeradius-devel/rad_assert.h>

/**
 *  RADIUS-specific tracking table.
 *
 *  It's a fixed-size array of 256 entries, indexed by ID.  Which
 *  means we don't need to store ID in the table.  We also don't
 *  need to store the packet type, as we assume that we have a
 *  unique tracking table per packet type.
 *
 *  @todo add a "reply" heap / list, ordered by when we need to
 *  clean up the replies.  The heap should contain nothing more than
 *  the time and the ID of the packet which needs cleaning up.
 *
 *  @todo add an "allocation" heap, ordered by when the entry was
 *  freed.  This is so that new allocations are O(1), and use the
 *  oldest unused ID.
 */
struct fr_tracking_t {
	int		num_entries;	//!< number of used entries.

	fr_tracking_entry_t packet[256];
};

/** Create a tracking table for one type of RADIUS packets.
 *
 * @param[in] ctx the talloc ctx
 * @return
 *	- NULL on error
 *	- fr_tracking_t * on success
 */
fr_tracking_t *fr_radius_tracking_create(TALLOC_CTX *ctx)
{
	fr_tracking_t *ft;

	if (!ctx) return NULL;

	ft = talloc_zero(ctx, fr_tracking_t);
	if (!ft) return NULL;

	ft->num_entries = 0;
	return ft;
}

/** Delete an entry from the tracking table.
 *
 * @param[in] ft the tracking table
 * @param[in] id the ID of the entry to delete
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_radius_tracking_entry_delete(fr_tracking_t *ft, uint8_t id)
{
	fr_tracking_entry_t *entry;

#ifndef NDEBUG
	(void) talloc_get_type_abort(ft, fr_tracking_t);
#endif

	entry = &ft->packet[id];
	if (entry->timestamp == 0) return -1;

	entry->timestamp = 0;
	ft->num_entries--;

	/*
	 *	Mark the reply (if any) as done.
	 */
	if (entry->reply) {
		fr_message_done(&entry->reply->m);
		entry->reply = NULL;
	}

	return 0;
}

/** Insert a (possibly new) packet and a timestamp
 *
 * @param[in] ft the tracking table
 * @param[in] packet the packet to insert
 * @param[in] timestamp when this packet was received
 * @param[out] p_entry pointer to newly inserted entry.
 * @return
 *	- FR_TRACKING_UNUSED, there was an error inserting the element
 *	- FR_TRACKING_NEW, a new entry was created
 *	- FR_TRACKING_SAME, the packet is the same as one already in the tracking table
 *	- FR_TRACKING_DIFFERENT, the old packet was deleted, and the newer packet inserted
 */
fr_tracking_status_t fr_radius_tracking_entry_insert(fr_tracking_t *ft, uint8_t *packet, fr_time_t timestamp,
						     fr_tracking_entry_t **p_entry)
{
	fr_tracking_entry_t *entry;

#ifndef NDEBUG
	(void) talloc_get_type_abort(ft, fr_tracking_t);
#endif

	entry = &ft->packet[packet[1]];

	/*
	 *	The entry is unused, insert it.
	 */
	if (entry->timestamp == 0) {
		entry->timestamp = timestamp;
		memcpy(&entry->data[0], packet + 2, 18);
		*p_entry = entry;

		ft->num_entries++;
		return FR_TRACKING_NEW;
	}

	/*
	 *	Is it the same packet?  If so, return that.
	 */
	if (memcmp(packet + 2, &entry->data[0], 18) == 0) {
		*p_entry = entry;
		return FR_TRACKING_SAME;
	}

	/*
	 *	It's in use, but the new packet is different.  update
	 *	the timestamp, so that anyone checking it knows it's
	 *	no longer relevant.
	 */
	entry->timestamp = timestamp;

	/*
	 *	Copy the new packet over top of the old one.
	 */
	memcpy(&entry->data[0], packet + 2, 18);
	*p_entry = entry;

	return FR_TRACKING_DIFFERENT;
}

/** Insert a (possibly new) packet and a timestamp
 *
 * @param[in] ft the tracking table
 * @param[in] id the ID of the entry which this reply is for
 * @param[in] cd the reply message
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_radius_tracking_entry_reply(fr_tracking_t *ft, uint8_t id,
				   fr_channel_data_t *cd)
{
	fr_tracking_entry_t *entry;

#ifndef NDEBUG
	(void) talloc_get_type_abort(ft, fr_tracking_t);
#endif

	entry = &ft->packet[id];

	if (entry->timestamp != cd->reply.request_time) {
		fr_message_done(&cd->m);
		return 0;
	}

	rad_assert(entry->reply == NULL);

	entry->reply = cd;

	return 0;
}
