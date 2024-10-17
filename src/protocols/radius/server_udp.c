/*
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @file protocols/radius/server_udp.c
 * @brief Functions to support RADIUS bio handlers for server udp sockets
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/bio/packet.h>
#include <freeradius-devel/radius/server_udp.h>
#include <freeradius-devel/radius/server_priv.h>

static bool radius_server_dedup_receive(fr_bio_t *bio, fr_bio_dedup_entry_t *dedup_ctx, void *packet_ctx)
{
	fr_radius_server_fd_bio_t *my = talloc_get_type_abort(bio->uctx, fr_radius_server_fd_bio_t);
	fr_bio_dedup_entry_t *prev;
	fr_radius_server_bio_pctx_t *ctx = packet_ctx;

	/*
	 *	Find any previous entry.
	 */
	prev = fr_rb_find(&my->rb, dedup_ctx);
	if (prev) {
		// @todo - signal duplicate packet
		return false;
	}
	
	if (!fr_rb_insert(&my->rb, dedup_ctx)) {
		// @todo - signal an error
		return false;
	}

	/*
	 *	Glue it all together
	 */
	dedup_ctx->uctx = ctx;
	ctx->dedup = dedup_ctx;

	return true;
}

static fr_bio_dedup_entry_t *radius_server_dedup_get_item(UNUSED fr_bio_t *bio, void *packet_ctx)
{
	fr_radius_server_bio_pctx_t *ctx = packet_ctx;

	return ctx->dedup;
}

static void radius_server_dedup_release(fr_bio_t *bio, fr_bio_dedup_entry_t *dedup_ctx, UNUSED fr_bio_dedup_release_reason_t reason)
{
	fr_radius_server_fd_bio_t *my = talloc_get_type_abort(bio->uctx, fr_radius_server_fd_bio_t);
	fr_radius_server_bio_pctx_t *ctx = dedup_ctx->uctx;

	(void) fr_rb_delete(&my->rb, dedup_ctx);
	ctx->dedup = NULL;
}

static int fr_radius_server_udp_bio_read(fr_bio_packet_t *bio, void **packet_ctx_p, fr_packet_t **packet_p,
					 TALLOC_CTX *out_ctx, fr_pair_list_t *out)
{
	int rcode;
	fr_radius_server_bio_pctx_t *ctx;

	/*
	 *	Read the packet.
	 */
	rcode = fr_radius_server_fd_bio_read(bio, packet_ctx_p, packet_p, out_ctx, out);
	if (rcode < 0) return rcode;

	ctx = *packet_ctx_p;

	/*
	 *	The dedup_ctx starts off with the raw data in a buffer somewhere.  That buffer will get
	 *	over-written with a later packet.  So be sure to update the dedup_ctx with the long-term
	 *	version of the packet contents.
	 */
	fr_assert(ctx->dedup->packet_size == (*packet_p)->data_len);

	ctx->dedup->packet = (*packet_p)->data;
	ctx->dedup->packet_size = (*packet_p)->data_len;

	return 0;
}

/** Allocate a RADIUS bio for receiving packets from clients.
 *
 *  It also verifies that the packets we receive are valid for RADIUS.
 */
fr_bio_packet_t *fr_radius_server_udp_bio_alloc(TALLOC_CTX *ctx, fr_radius_server_config_t *cfg, fr_bio_fd_config_t const *fd_cfg)
{
	fr_radius_server_fd_bio_t *my;

	my = fr_radius_server_fd_bio_alloc(ctx, 2 * 4096, cfg, fd_cfg);
	if (!my) return NULL;

	if (fr_bio_mem_set_verify(my->mem, fr_radius_bio_verify_datagram, &my->cfg.verify, true) < 0) {
	fail:
		talloc_free(my);
		return NULL;
	}

	/*
	 *	Once we've allocated a FD and memory BIO, UDP needs de-duping.
	 */
	my->dedup = fr_bio_dedup_alloc(my, 256, radius_server_dedup_receive, radius_server_dedup_release,
				       radius_server_dedup_get_item, &cfg->dedup_cfg, my->mem);
	if (!my->dedup) goto fail;
	my->dedup->uctx = my;

	my->common.bio = my->dedup;

	my->common.read = fr_radius_server_udp_bio_read;
	my->common.write = fr_radius_server_fd_bio_write;

	// @todo - insert comparison function
	// @todo - comparison function is different for connected and unconnected sockets

	return (fr_bio_packet_t *) my;
}
