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
#include <freeradius-devel/rbtree.h>
#include <freeradius-devel/rad_assert.h>

#if 0
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
#endif

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

	size_t		src_dst_size;	//!< size of per-packet src/dst information

	rbtree_t	*tree;		//!< for unconnected sockets

	fr_tracking_entry_t *codes[];
};


static int entry_cmp(void const *one, void const *two)
{
	fr_tracking_entry_t const *a = one;
	fr_tracking_entry_t const *b = two;

	/*
	 *	Check Code and Identifier.
	 *
	 *	But NOT the Request Authenticator.
	 */
	if (a->data[0] < b->data[0]) return -1;
	if (a->data[0] > b->data[0]) return +1;

	if (a->data[1] < b->data[1]) return -1;
	if (a->data[1] > b->data[1]) return +1;

	return memcmp(a->src_dst, b->src_dst, a->src_dst_size);
}


/** Free one entry.
 *
 *  @todo - use a slab allocator.
 */
static void entry_free(void *data)
{
	fr_tracking_entry_t *entry = data;

	talloc_free(entry);
}


/** Create a tracking table for one type of RADIUS packets.
 *
 *  For connected sockets, it just tracks packets by ID.
 *  For unconnected sockets, the caller has to provide a context for each packet...
 *
 * @param[in] ctx the talloc ctx
 * @param[in] src_dst_size size of src/dst information for a packet on this socket.  Use 0 for connected sockets.
 * @param[in] allowed_packets the array of packet codes which are tracked in this table.
 * @return
 *	- NULL on error
 *	- fr_tracking_t * on success
 */
fr_tracking_t *fr_radius_tracking_create(TALLOC_CTX *ctx, size_t src_dst_size, void *allowed_packets[FR_MAX_PACKET_CODE])
{
	int i;
	size_t ft_size;
	fr_tracking_t *ft;

	if (!ctx) return NULL;

	/*
	 *	Connected sockets need an array of codes.
	 *	Unconnected ones do not.
	 */
	ft_size = sizeof(fr_tracking_t);
	if (!src_dst_size) ft_size += sizeof(ft->codes[0]) * FR_MAX_PACKET_CODE;

	ft = talloc_size(ctx, ft_size);
	if (!ft) return NULL;

	memset(ft, 0, ft_size);
	talloc_set_type(ft, fr_tracking_t);

	ft->num_entries = 0;
	ft->src_dst_size = src_dst_size;

	/*
	 *	The socket is unconnected.  We need to track entries by src/dst ip/port.
	 */
	if (src_dst_size > 0) {
		ft->tree = rbtree_create(ft, entry_cmp, entry_free, RBTREE_FLAG_NONE);
		return ft;
	}

	/*
	 *	The socket is connected.  We don't need per-packet
	 *	src/dst information.
	 */
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

	/*
	 *	If we're not tracking src/dst ip/port, just return.
	 */
	if (!ft->src_dst_size) return 0;

	/*
	 *	We are tracking src/dst ip/port, we have to remove
	 *	this entry from the tracking tree, and then free it.
	 */
	rbtree_deletebydata(ft->tree, entry);

	return 0;
}

/** Insert a (possibly new) packet and a timestamp
 *
 * @param[in] ft the tracking table
 * @param[in] packet the packet to insert
 * @param[in] timestamp when this packet was received
 * @param[in] src_dst the data structure holding src/dst ip/port information for this packet.
 * @param[out] p_entry pointer to newly inserted entry.
 * @return
 *	- FR_TRACKING_ERROR, gthere was an error in the function parameters
 *	- FR_TRACKING_NEW, a new entry was created
 *	- FR_TRACKING_SAME, the packet is the same as one already in the tracking table
 *	- FR_TRACKING_DIFFERENT, the old packet was deleted, and the newer packet inserted
 */
fr_tracking_status_t fr_radius_tracking_entry_insert(fr_tracking_t *ft, uint8_t *packet, fr_time_t timestamp,
						     uint8_t const *src_dst, fr_tracking_entry_t **p_entry)
{
	bool insert = false;
	fr_tracking_entry_t *entry;

	(void) talloc_get_type_abort(ft, fr_tracking_t);

	if (!packet[0] || (packet[0] >= FR_MAX_PACKET_CODE)) return FR_TRACKING_ERROR;

	/*
	 *	Connected socket: just look in the array.
	 */
	if (!ft->src_dst_size) {
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

	} else {
		fr_tracking_entry_t my_entry;

		/*
		 *	Unconnected socket: we have to allocate the
		 *	entry ourselves.
		 *
		 *	@todo - use a slab allocator
		 */
		my_entry.src_dst = src_dst;
		my_entry.src_dst_size = ft->src_dst_size;
		memcpy(my_entry.data, packet, sizeof(my_entry.data));

		/*
		 *	See if we're adding a duplicate, or
		 *	over-writing an existing one.
		 */
		entry = rbtree_finddata(ft->tree, &my_entry);
		if (entry) {
			/*
			 *	Duplicate, tell the caller so.
			 */
			if (memcmp(&entry->data[0], packet, sizeof(entry->data)) == 0) {
				*p_entry = entry;
				return FR_TRACKING_SAME;
			}			

			/*
			 *	Over-write an existing entry.
			 */
			entry->timestamp = timestamp;

			if (entry->reply) {
				talloc_const_free(entry->reply);
				entry->reply_len = 0;
			}

			/*
			 *	Don't change src_dst.  It MUST have
			 *	the same data as the previous entry.
			 */

		} else {
			size_t align;
			uint8_t *p;

			/*
			 *	Ensure that structures are aligned.
			 */
			align = sizeof(fr_tracking_entry_t);
			align += 15;
			align &= ~(15);

			/*
			 *	No existing entry, create a new one.
			 */
			entry = talloc_size(ft->tree, align + ft->src_dst_size);
			if (!entry) return FR_TRACKING_ERROR;

			entry->timestamp = timestamp;
			insert = true;

			/*
			 *	Copy the src_dst information over to the entry.
			 */
			entry->src_dst = p = ((uint8_t *) entry) + align;
			entry->src_dst_size = ft->src_dst_size;
			memcpy(p, src_dst, entry->src_dst_size);
		}
	}

	/*
	 *	Copy the new packet over top of the old one.
	 */
	memcpy(&entry->data[0], packet, sizeof(entry->data));
	*p_entry = entry;

	if (insert) rbtree_insert(ft->tree, entry);

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
