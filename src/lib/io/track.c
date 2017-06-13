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
 * @file io/track.c
 *
 * @copyright 2016 Alan DeKok <aland@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/io/track.h>
#include <freeradius-devel/rad_assert.h>


/*
 *	Copied here for simplicity...
 */
static void talloc_const_free(void const *ptr)
{
	void *tmp;
	if (!ptr) return;

	memcpy(&tmp, &ptr, sizeof(tmp));
	talloc_free(tmp);
}


/**
 *  RADIUS-specific tracking table.
 *
 *  It's a fixed-size array of 256 entries, indexed by ID.
 *
 *  @todo add a "reply" heap / list, ordered by when we need to
 *  clean up the replies.  The heap should contain nothing more than
 *  the time and the ID of the packet which needs cleaning up.
 *
 *  @todo allow for Request Authenticator to be used as part of the
 *  identifier.  With provisions for which attribute is used, and a
 *  slab allocator, as we can now have more than 256 packets
 *  outstanding.
 */
struct fr_tracking_t {
	int		num_entries;	//!< number of used entries.

	fr_tracking_entry_t *codes[FR_MAX_PACKET_CODE];
};

/** Create a tracking table for one type of RADIUS packets.
 *
 * @param[in] ctx the talloc ctx
 * @param[in] allowed_packets the array of packet codes which are tracked in this table.
 * @return
 *	- NULL on error
 *	- fr_tracking_t * on success
 */
fr_tracking_t *fr_radius_tracking_create(TALLOC_CTX *ctx, void *allowed_packets[FR_MAX_PACKET_CODE])
{
	int i;
	fr_tracking_t *ft;

	if (!ctx) return NULL;

	ft = talloc_zero(ctx, fr_tracking_t);
	if (!ft) return NULL;

	ft->num_entries = 0;

	for (i = 0; i < FR_MAX_PACKET_CODE; i++) {
		if (!allowed_packets[i]) continue;

		ft->codes[i] = talloc_zero_array(ft, fr_tracking_entry_t, 256);
		if (!ft->codes[i]) {
			talloc_free(ft);
			return NULL;
		}
	}

	return ft;
}

/** Delete an entry from the tracking table.
 *
 * @param[in] ft the tracking table
 * @param[in] entry the entry to delete.
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_radius_tracking_entry_delete(fr_tracking_t *ft, fr_tracking_entry_t *entry)
{
	(void) talloc_get_type_abort(ft, fr_tracking_t);

	if (entry->timestamp == 0) return -1;

	entry->timestamp = 0;
	ft->num_entries--;

	/*
	 *	Mark the reply (if any) as done.
	 */
	if (entry->reply) {
		talloc_const_free(entry->reply);
		entry->reply = NULL;
		entry->reply_len = 0;
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
 *	- FR_TRACKING_ERROR, gthere was an error in the function parameters
 *	- FR_TRACKING_NEW, a new entry was created
 *	- FR_TRACKING_SAME, the packet is the same as one already in the tracking table
 *	- FR_TRACKING_DIFFERENT, the old packet was deleted, and the newer packet inserted
 */
fr_tracking_status_t fr_radius_tracking_entry_insert(fr_tracking_t *ft, uint8_t *packet, fr_time_t timestamp,
						     fr_tracking_entry_t **p_entry)
{
	fr_tracking_entry_t *entry;

	(void) talloc_get_type_abort(ft, fr_tracking_t);

	if (!packet[0] || (packet[0] > FR_MAX_PACKET_CODE)) return FR_TRACKING_ERROR;

	if (!ft->codes[packet[0]]) return FR_TRACKING_ERROR;

	entry = &ft->codes[packet[0]][packet[1]];

	/*
	 *	The entry is unused, insert it.
	 */
	if (entry->timestamp == 0) {
		entry->timestamp = timestamp;
		memcpy(&entry->data[0], packet, sizeof(entry->data));
		*p_entry = entry;

		ft->num_entries++;
		return FR_TRACKING_NEW;
	}

	/*
	 *	Is it the same packet?  If so, return that.
	 */
	if (memcmp(&entry->data[0], packet, sizeof(entry->data)) == 0) {
		*p_entry = entry;
		return FR_TRACKING_SAME;
	}

	/*
	 *	It's in use, but the new packet is different.  update
	 *	the timestamp, so that anyone checking it knows it's
	 *	no longer relevant.
	 */
	entry->timestamp = timestamp;

	if (entry->reply) {
		talloc_const_free(entry->reply);
		entry->reply_len = 0;
	}

	/*
	 *	Copy the new packet over top of the old one.
	 */
	memcpy(&entry->data[0], packet, sizeof(entry->data));
	*p_entry = entry;

	return FR_TRACKING_DIFFERENT;
}

/** Insert a (possibly new) packet and a timestamp
 *
 * @param[in] ft the tracking table
 * @param[in] entry the original entry for the request packet
 * @param[in] timestamp when the caller thinks the original entry was created
 * @param[in] reply the reply packet
 * @param[in] reply_len the length of the reply message
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_radius_tracking_entry_reply(fr_tracking_t *ft, fr_tracking_entry_t *entry,
				   fr_time_t timestamp,
				   uint8_t const *reply, size_t reply_len)
{
	(void) talloc_get_type_abort(ft, fr_tracking_t);

	if (entry->timestamp != timestamp) {
		return 0;
	}

	entry->reply = talloc_memdup(ft, reply, reply_len);
	entry->reply_len = reply_len;

	return 0;
}
