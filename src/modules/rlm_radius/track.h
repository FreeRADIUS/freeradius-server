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
#ifndef _RLM_RADIUS_TRACK_H
#define _RLM_RADIUS_TRACK_H

/*
 * $Id$
 *
 * @file track.h
 * @brief RADIUS client packet tracking
 *
 * @copyright 2017 Alan DeKok <aland@freeradius.org>
 */

/** Track one request to a response
 *
 */
typedef struct rlm_radius_request_t {
	REQUEST			*request;	//!< the original request

	fr_event_timer_t const	*ev;		//!< timer event associated with this request

	int			id;		//!< our ID
	struct timeval		start;		//!< when we started sending the packet
	uint32_t		count;		//!< how many times we sent this packet
	uint32_t		rt;		//!< retransmit timer (microseconds)

	union {
		fr_dlist_t		entry;		//!< for free chain
		uint8_t			vector[16];	//!< copy of the authentication vector
	};
} rlm_radius_request_t;

typedef struct rlm_radius_id_t {
	int			num_requests;  	//!< number of requests in the allocation
	int			num_free;	//!< number of entries in the free list

	fr_dlist_t		free_list;     	//!< so we allocate by least recently used

	bool			use_authenticator; //!< whether to use the request authenticator as an ID
	int			next_id;	//!< next ID to allocate

	rlm_radius_request_t	id[256];	//!< which ID was used

	rbtree_t		*subtree[256];	//!< for Original-Request-Authenticator
} rlm_radius_id_t;

rlm_radius_id_t *rr_track_create(TALLOC_CTX *ctx);
rlm_radius_request_t *rr_track_alloc(rlm_radius_id_t *id, REQUEST *request) CC_HINT(nonnull);
int rr_track_update(rlm_radius_id_t *id, rlm_radius_request_t *rr, uint8_t *vector) CC_HINT(nonnull);
rlm_radius_request_t *rr_track_find(rlm_radius_id_t *id, int packet_id, uint8_t *vector) CC_HINT(nonnull(1));
int rr_track_delete(rlm_radius_id_t *id, rlm_radius_request_t *rr);
void rr_track_use_authenticator(rlm_radius_id_t *id, bool flag);

#endif	/* _RLM_RADIUS_TRACK_H */
