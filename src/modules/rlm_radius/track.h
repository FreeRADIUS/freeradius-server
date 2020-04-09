#pragma once
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

/*
 * $Id$
 *
 * @file track.h
 * @brief RADIUS client packet tracking
 *
 * @copyright 2017 Alan DeKok (aland@freeradius.org)
 */

#include "rlm_radius.h"
#include <freeradius-devel/util/dlist.h>

typedef struct radius_track_entry_s radius_track_entry_t;
typedef struct radius_track_s radius_track_t;

/** Track one request to a response
 *
 */
struct radius_track_entry_s {
	radius_track_t	*tt;

	radius_track_entry_t ***binding;	//!< Binding chunk we use to release the entry
						///< when its parent is freed.  We also zero
						///< out the tracking entry field in the parent.

	REQUEST		*request;		//!< as always...

	void		*uctx;			//!< Result/resumption context.

	uint8_t		code;			//!< packet code (sigh)
	uint8_t		id;			//!< our ID

	union {
		fr_dlist_t	entry;					//!< For free list.
		uint8_t		vector[RADIUS_AUTH_VECTOR_LENGTH];	//!< copy of the request authenticator.
	};

#ifndef NDEBUG
	uint64_t	operation;		//!< Used to give an idea of the alloc/free timeline.
	char const	*file;			//!< Where the entry was allocated.
	int		line;			//!< Where the entry was freed.
#endif
};

struct radius_track_s {
	unsigned int	num_requests;  		//!< number of requests in the allocation

	fr_dlist_head_t	free_list;     		//!< so we allocate by least recently used

	bool		use_authenticator;	//!< whether to use the request authenticator as an ID
	int		next_id;		//!< next ID to allocate

	radius_track_entry_t	id[UINT8_MAX + 1];	//!< which ID was used

	rbtree_t	*subtree[UINT8_MAX + 1];	//!< for Original-Request-Authenticator

#ifndef NDEBUG
	uint64_t	operation;		//!< Incremented each alloc and de-alloc
#endif
};

radius_track_t		*radius_track_alloc(TALLOC_CTX *ctx);

/*
 *	Debug functions which track allocations and frees
 */
#ifndef NDEBUG
#  define		radius_track_entry_reserve(_te_out, _ctx, _tt, _request, _code, _uctx) \
				_radius_track_entry_reserve( __FILE__, __LINE__, _te_out, _ctx, _tt, _request, _code, _uctx)
int			_radius_track_entry_reserve(char const *file, int line,
						    radius_track_entry_t **te_out,
						    TALLOC_CTX *ctx, radius_track_t *tt, REQUEST *request,
						    uint8_t code, void *uctx)
						    CC_HINT(nonnull(3,5,6));

#  define		radius_track_entry_release(_te) \
				_radius_track_entry_release( __FILE__, __LINE__, _te)
int			_radius_track_entry_release(char const *file, int line, radius_track_entry_t **te)
						    CC_HINT(nonnull);

typedef void (*radius_track_log_extra_t)(fr_log_t const *log, fr_log_type_t log_type, char const *file, int line,
					 radius_track_entry_t *te);

void			radius_track_state_log(fr_log_t const *log, fr_log_type_t log_type, char const *file, int line,
					       radius_track_t *tt, radius_track_log_extra_t extra);
/*
 *	Non-debug functions
 */
#else
int			radius_track_entry_reserve(radius_track_entry_t **te_out,
						   TALLOC_CTX *ctx, radius_track_t *tt, REQUEST *request,
						   uint8_t code, void *uctx)
						   CC_HINT(nonnull(1,3,4));

int			radius_track_entry_release(radius_track_entry_t **te) CC_HINT(nonnull);
#endif

int			radius_track_entry_update(radius_track_entry_t *te,
						  uint8_t const *vector) CC_HINT(nonnull);

radius_track_entry_t	*radius_track_entry_find(radius_track_t *tt, uint8_t packet_id,
						 uint8_t const *vector) CC_HINT(nonnull(1));

void			radius_track_use_authenticator(radius_track_t *te, bool flag) CC_HINT(nonnull);
