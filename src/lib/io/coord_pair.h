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

/**
 * $Id$
 *
 * @file io/coord_pair.h
 * @brief Sending pair lists to and from coordination threads
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(coord_pair_h, "$Id$")

#include <freeradius-devel/io/coord.h>
#include <freeradius-devel/server/request.h>
#include <freeradius-devel/util/pair.h>

typedef struct fr_coord_pair_reg_s fr_coord_pair_reg_t;

typedef void (*fr_coord_worker_pair_cb_t)(fr_coord_worker_t *cw, fr_coord_pair_reg_t *coord_pair_reg, fr_pair_list_t const *list, fr_time_t now, void *uctx);

typedef struct {
	uint32_t			packet_type;		//!< Packet type value for this callback
	fr_coord_worker_pair_cb_t	callback;		//!< Function to call
	void				*uctx;			//!< Ctx to pass to callback
} fr_coord_worker_pair_cb_reg_t;

typedef struct {
	fr_coord_worker_pair_cb_reg_t	*outbound_cb;		//!< Callbacks for coordinator -> worker pair messages.
	fr_dict_attr_t const		*packet_type;		//!< Packet type attribute.
	fr_dict_attr_t const		*root;			//!< Root attribute for decoding pair list messages.
	uint32_t			cb_id;			//!< Coordinator callback id used for pair list messages.
} fr_coord_pair_reg_ctx_t;

fr_coord_pair_reg_t	*fr_coord_pair_register(TALLOC_CTX *ctx, fr_coord_pair_reg_ctx_t *reg_ctx);

int		fr_coord_to_worker_reply_send(request_t *request, uint32_t worker_id);

int		fr_worker_to_coord_pair_send(fr_coord_worker_t *cw, fr_coord_pair_reg_t *coord_pair_reg, fr_pair_list_t *list);

void		coord_recv_pair_data(fr_coord_t *coord, uint32_t worker_id, fr_dbuff_t *dbuff, fr_time_t now, void *uctx);
void		coord_worker_recv_pair_data(fr_coord_worker_t *cw, fr_dbuff_t *dbuff, fr_time_t now, void *uctx);

/** Set callback for handling worker -> coordinator pair list data
 * @param _id	Callback ID to use
 */
#define FR_COORD_PAIR_CALLBACK(_id)	[_id] = { .callback = coord_recv_pair_data }

/** Set callback for handling coordinator -> worker pair list data
 * @param _id	Callback ID to use
 */
#define FR_COORD_WORKER_PAIR_CALLBACK(_id) 	[_id] = { .callback = coord_worker_recv_pair_data }

/** Set up ctx on pair list callbacks
 * @param _in_cb	Array of worker -> coordinator callbacks.
 * @param _out_cb	Array of coordinator -> worker callbacks.
 * @param _id		Callback ID fir pair list callbacks.
 * @param _reg		Registered coordinator pair list callback data.
 */
#define FR_COORD_PAIR_CB_CTX_SET(_in_cb, _out_cb, _id, _reg)	_in_cb[_id].uctx = _reg; \
	_out_cb[_id].uctx = _reg;
