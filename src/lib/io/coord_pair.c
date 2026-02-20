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
 * @brief Sending pair lists to and from coordination threads
 * @file io/coord_pair.c
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/internal/internal.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/io/coord_pair.h>
#include <freeradius-devel/io/coord_priv.h>
#include <freeradius-devel/util/dlist.h>

static fr_dlist_head_t	*coord_pair_regs = NULL;

/** Registration of pair list callbacks
 *
 */
struct fr_coord_pair_reg_s {
	fr_dlist_t			entry;			//!< Entry in list of pair list registrations
	fr_dict_attr_t const 		*attr_packet_type;	//!< Attribute containing packet type
	fr_dict_attr_t const		*root;			//!< Pair list decoding root attribute
	fr_coord_worker_pair_cb_reg_t	**callbacks;		//!< Array of pointers to callbacks
	uint32_t			max_packet_type;	//!< Largest valid value for packet type
	uint32_t			cb_id;			//!< The coordinator callback ID used for pair list handling
};

/** Remove a coord pair registration from the list when it is freed
 */
static int _coord_pair_reg_free(fr_coord_pair_reg_t *to_free)
{
	fr_assert(coord_pair_regs);

	fr_dlist_remove(coord_pair_regs, to_free);

	/* If all the registrations are gone, free the list */
	if (fr_dlist_num_elements(coord_pair_regs) == 0) {
		TALLOC_FREE(coord_pair_regs);
	}
	return 0;
}

/** Register a set of callbacks for pair list based coordinator messages
 */
fr_coord_pair_reg_t *fr_coord_pair_register(TALLOC_CTX *ctx, fr_coord_pair_reg_ctx_t *reg_ctx)
{
	fr_coord_pair_reg_t		*coord_pair_reg;
	fr_coord_worker_pair_cb_reg_t	*cb_reg = reg_ctx->outbound_cb;

	fr_assert(reg_ctx->packet_type->type == FR_TYPE_UINT32);
	fr_assert(reg_ctx->root);

	if (!coord_pair_regs) {
		MEM(coord_pair_regs = talloc_zero(NULL, fr_dlist_head_t));
		fr_dlist_init(coord_pair_regs, fr_coord_pair_reg_t, entry);
	}

	MEM(coord_pair_reg = talloc(ctx, fr_coord_pair_reg_t));
	*coord_pair_reg = (fr_coord_pair_reg_t) {
		.attr_packet_type = reg_ctx->packet_type,
		.root = reg_ctx->root
	};

	while (cb_reg->callback) {
		if (cb_reg->packet_type > coord_pair_reg->max_packet_type) {
			coord_pair_reg->max_packet_type = cb_reg->packet_type;
		}
		cb_reg++;
	}

	/*
	 *	A sane limit on packet type values to avoid a huge array.
	 *	If larger values are needed in the future we can a folded array.
	 */
	fr_assert(coord_pair_reg->max_packet_type <= 256);

	MEM(coord_pair_reg->callbacks = talloc_zero_array(coord_pair_reg, fr_coord_worker_pair_cb_reg_t *,
							  coord_pair_reg->max_packet_type + 1));

	cb_reg = reg_ctx->outbound_cb;
	while (cb_reg->callback) {
		coord_pair_reg->callbacks[cb_reg->packet_type] = cb_reg;
		cb_reg++;
	}

	fr_dlist_insert_tail(coord_pair_regs, coord_pair_reg);
	talloc_set_destructor(coord_pair_reg, _coord_pair_reg_free);

	return coord_pair_reg;
}

/** Callback run when a coordinator receives a pair list message
 */
void coord_recv_pair_data(fr_coord_t *coord, uint32_t worker_id, fr_dbuff_t *dbuff, UNUSED fr_time_t now, void *uctx)
{
	fr_coord_pair_reg_t	*coord_pair_reg = talloc_get_type_abort(uctx, fr_coord_pair_reg_t);
	coord_request_bootstrap(coord, worker_id, dbuff, now, coord_pair_reg);

	return;
}

/** Callback run when a worker receives a pair list message
 */
void coord_worker_recv_pair_data(fr_coord_worker_t *cw, fr_dbuff_t *dbuff, fr_time_t now, void *uctx)
{
	fr_coord_pair_reg_t		*coord_pair_reg = talloc_get_type_abort(uctx, fr_coord_pair_reg_t);
	fr_pair_list_t			list;
	fr_pair_t			*vp;

	fr_pair_list_init(&list);
	fr_internal_decode_list_dbuff(NULL, &list, coord_pair_reg->root, dbuff, NULL);

	vp = fr_pair_find_by_da_nested(&list, NULL, coord_pair_reg->attr_packet_type);

	if (!vp) {
		ERROR("Message received without %s", coord_pair_reg->attr_packet_type->name);
		return;
	}

	if (vp->vp_uint32 > coord_pair_reg->max_packet_type || !coord_pair_reg->callbacks[vp->vp_uint32]) {
		ERROR("Message received with invalid value %pP", vp);
		return;
	}

	coord_pair_reg->callbacks[vp->vp_uint32]->callback(cw, coord_pair_reg, &list, now,
							   coord_pair_reg->callbacks[vp->vp_uint32]->uctx);

	fr_pair_list_free(&list);
}

/** Send a reply list from a coordinator to a worker
 *
 * @param request	containing the reply to send.
 * @param worker_id	to send the reply to.
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int fr_coord_to_worker_reply_send(request_t *request, uint32_t worker_id)
{
	fr_dbuff_t		dbuff;
	fr_dbuff_uctx_talloc_t	tctx;
	fr_coord_packet_ctx_t	*packet_ctx = talloc_get_type_abort(request->async->packet_ctx, fr_coord_packet_ctx_t);
	fr_coord_pair_reg_t	*coord_pair_reg = talloc_get_type_abort(packet_ctx->uctx, fr_coord_pair_reg_t);
	int			ret;

	if (fr_dbuff_init_talloc(NULL, &dbuff, &tctx, 1024, SIZE_MAX) == NULL) return -1;
	if (fr_internal_encode_list(&dbuff, &request->reply_pairs, NULL) < 0) return -1;

	ret = fr_coord_to_worker_send(packet_ctx->coord, worker_id, coord_pair_reg->cb_id, &dbuff);

	fr_dbuff_free_talloc(&dbuff);

	return ret;
}

/** Send a pair list from a worker to a coordinator
 *
 * The pair list must include an attribute indicating the packet type
 *
 * @param cw	The coord worker sending the data.
 * @param list	of pairs to send.
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int fr_worker_to_coord_pair_send(fr_coord_worker_t *cw, fr_coord_pair_reg_t *coord_pair_reg, fr_pair_list_t *list)
{
	fr_dbuff_t		dbuff;
	fr_dbuff_uctx_talloc_t	tctx;
	int			ret;

	if (fr_dbuff_init_talloc(NULL, &dbuff, &tctx, 1024, SIZE_MAX) == NULL) return -1;
	if (fr_internal_encode_list(&dbuff, list, NULL) < 0) return -1;

	ret = fr_worker_to_coord_send(cw, coord_pair_reg->cb_id, &dbuff);

	fr_dbuff_free_talloc(&dbuff);
	return ret;
}
