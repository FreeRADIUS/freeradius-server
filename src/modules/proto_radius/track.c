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
 * @file proto_radius/track.c
 *
 * @copyright 2016 Alan DeKok <aland@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/rbtree.h>
#include <freeradius-devel/rad_assert.h>
#include "track.h"

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
	int			num_entries;	//!< number of used entries.

	size_t			src_dst_size;	//!< size of per-packet src/dst information

	rbtree_t		*tree;		//!< for unconnected sockets

	fr_tracking_entry_t	*codes[];
};


static int entry_cmp(void const *one, void const *two)
{
	fr_tracking_entry_t const *a = one, *b = two;

	return memcmp(a->src_dst, b->src_dst, a->src_dst_size);
}

/** Free one entry.
 *
 *  @todo - use a slab allocator.
 */
static void entry_free(void *data)
{
	fr_tracking_entry_t *entry = data;

	if (entry->ev) talloc_const_free(entry->ev);
	talloc_free(entry);
}


/** Create a tracking table for one type of RADIUS packets
 *
 * For connected sockets, it just tracks packets by ID.
 * For unconnected sockets, the caller has to provide a context for each packet...
 *
 * @param[in] ctx			the talloc ctx.
 * @param[in] src_dst_size		size of src/dst information for a packet on this socket.
 * @param[in] allowed_packets		the array of packet codes which are tracked in this table.
 *					We use this so we don't have to allocate arrays of tracking
 *					entries for unused codes.
 * @return
 *	- NULL on error
 *	- fr_tracking_t * on success
 */
fr_tracking_t *fr_radius_tracking_create(TALLOC_CTX *ctx, size_t src_dst_size,
					 UNUSED bool const allowed_packets[FR_MAX_PACKET_CODE])
{
	fr_tracking_t *ft;

	if (!ctx) return NULL;

	/*
	 *	Connected sockets need an array of codes.
	 *	Unconnected ones do not.
	 */
	ft = talloc_zero(ctx, fr_tracking_t);
	if (!ft) return NULL;

	ft->num_entries = 0;
	ft->src_dst_size = src_dst_size;

	/*
	 *	The socket is unconnected.  We need to track entries by src/dst ip/port.
	 */
	ft->tree = rbtree_create(ft, entry_cmp, entry_free, RBTREE_FLAG_NONE);
	return ft;
}

/** Delete an entry from the tracking table
 *
 * @param[in] ft	The tracking table.
 * @param[in] entry	to delete.
 * @param[in] recv_time	when the caller thinks the entry was allocated.
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_radius_tracking_entry_delete(fr_tracking_t *ft, fr_tracking_entry_t *entry, fr_time_t recv_time)
{
	(void) talloc_get_type_abort(ft, fr_tracking_t);

	rad_assert(entry->uses > 0);
	entry->uses--;

	/*
	 *	Someone else is using it, so we don't delete it.
	 */
	if (recv_time != entry->timestamp) {
		if (entry->uses == 0) goto delete;
		return 0;
	}

	/*
	 *	Mark the reply (if any) as done.
	 */
	if (entry->reply) {
		talloc_const_free(entry->reply);
		entry->reply = NULL;
		entry->reply_len = 0;
	}

	rad_assert(entry->ev == NULL);
	entry->timestamp = 0;

	/*
	 *	Don't delete it.  Someone else is still using it.
	 */
	if (entry->uses > 0) return 0;

delete:
	/*
	 *	We are tracking src/dst ip/port, we have to remove
	 *	this entry from the tracking tree, and then free it.
	 */
	rbtree_deletebydata(ft->tree, entry);

	ft->num_entries--;
	return 0;
}

/** Insert a (possibly new) packet and a timestamp
 *
 * @param[out] p_entry		pointer to newly inserted entry.
 * @param[in] ft		The tracking table.
 * @param[in] packet		to insert.
 * @param[in] timestamp		When this packet was received.
 * @param[in] src_dst		the data structure holding src/dst ip/port information for this packet.
 * @return
 *	- FR_TRACKING_ERROR, there was an error in the function parameters.
 *	- FR_TRACKING_NEW, a new entry was created.
 *	- FR_TRACKING_SAME, the packet is the same as one already in the tracking table.
 *	- FR_TRACKING_UPDATED, the old packet was deleted, and the newer packet inserted.
 *	- FR_TRACKING_CONFLICTING, the old packet was marked as "bad", and the newer packet inserted.
 */
fr_tracking_status_t fr_radius_tracking_entry_insert(fr_tracking_entry_t **p_entry,
						     fr_tracking_t *ft, uint8_t *packet, fr_time_t timestamp,
						     void *src_dst)
{
	fr_tracking_entry_t	*entry;
	uint64_t		buffer[256];

	(void) talloc_get_type_abort(ft, fr_tracking_t);

	if (!packet[0] || (packet[0] >= FR_MAX_PACKET_CODE)) return FR_TRACKING_ERROR;

	/*
	 *	See if we're adding a duplicate, or
	 *	over-writing an existing one.
	 */
	entry = (fr_tracking_entry_t *) buffer;
	memcpy(entry->src_dst, src_dst, ft->src_dst_size);
	entry->src_dst_size = ft->src_dst_size;
	memcpy(entry->data, packet, sizeof(entry->data));

	entry = rbtree_finddata(ft->tree, entry);
	if (!entry) {
		/*
		 *	No existing entry, create a new one.
		 */
		entry = talloc_zero_size(ft->tree, sizeof(*entry) + ft->src_dst_size);
		if (!entry) return FR_TRACKING_ERROR;

		talloc_set_name_const(entry, "fr_tracking_entry_t");

		entry->ft = ft;
		entry->timestamp = timestamp;
		entry->uses = 1;

		/*
		 *	Copy the src_dst information over to the entry.
		 */
		entry->src_dst_size = ft->src_dst_size;
		memcpy(entry->src_dst, src_dst, entry->src_dst_size);

		/*
		 *	Copy the new packet over.
		 */
		memcpy(&entry->data[0], packet, sizeof(entry->data));

		if (!rbtree_insert(ft->tree, entry)) {
			talloc_free(entry);
			return FR_TRACKING_ERROR;
		}

		*p_entry = entry;
		return FR_TRACKING_NEW;
	}

	/*
	 *	Duplicate, tell the caller so.
	 *
	 *	Same Code, ID, size, and authentication vector.
	 */
	if (memcmp(&entry->data[0], packet, sizeof(entry->data)) == 0) {
		*p_entry = entry;
		return FR_TRACKING_SAME;
	}

	/*
	 *	Over-write an existing entry.
	 */
	entry->timestamp = timestamp;
	entry->uses++;

	/*
	 *	The new packet conflicts with the old one.  Allow BOTH
	 *	to operate, and let the caller figure out what to do.
	 */
	if (entry->reply_len == 0) {
		rad_assert(entry->reply == NULL);
		*p_entry = entry;
		return FR_TRACKING_CONFLICTING;
	}

	if (entry->reply) {
		talloc_const_free(entry->reply);
		entry->reply = NULL;
		entry->reply_len = 0;
	}

	/*
	 *	Don't change src_dst.  It MUST have
	 *	the same data as the previous entry.
	 */

	/*
	 *	Copy the new packet over top of the old one.
	 */
	memcpy(&entry->data[0], packet, sizeof(entry->data));
	*p_entry = entry;

	return FR_TRACKING_UPDATED;
}

/** Insert a (possibly new) packet and a timestamp
 *
 * @param[in] ft		the tracking table.
 * @param[in] entry the		original entry for the request packet
 * @param[in] reply_time	when the reply was sent.
 * @param[in] reply		the reply packet.
 * @param[in] reply_len		the length of the reply message.
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_radius_tracking_entry_reply(fr_tracking_t *ft, fr_tracking_entry_t *entry,
				   UNUSED fr_time_t reply_time,
				   uint8_t const *reply, size_t reply_len)
{
	(void) talloc_get_type_abort(ft, fr_tracking_t);

	/*
	 *	Bad packets are "don't reply"
	 */
	if (reply_len < 20) {
		entry->reply = NULL;
		entry->reply_len = 1;
		return 0;
	}

	rad_assert(entry->reply == NULL);
	entry->reply = talloc_memdup(ft, reply, reply_len);
	entry->reply_len = reply_len;

	return 0;
}
