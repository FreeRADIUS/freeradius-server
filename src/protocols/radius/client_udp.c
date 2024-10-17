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
 * @file protocols/radius/client_udp.c
 * @brief Functions to support RADIUS bio handlers for client udp sockets
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/bio/packet.h>
#include <freeradius-devel/radius/client_udp.h>
#include <freeradius-devel/radius/client_priv.h>

/**  Allocate an ID, and write one packet.
 *
 */
static int fr_radius_client_udp_bio_write(fr_bio_packet_t *bio, void *pctx, fr_packet_t *packet, fr_pair_list_t *list)
{
	ssize_t slen;
	fr_radius_client_fd_bio_t *my = talloc_get_type_abort(bio, fr_radius_client_fd_bio_t);

	if (!packet->data) return fr_radius_client_fd_bio_write(my, pctx, packet, list);

	slen = fr_bio_write(my->common.bio, &packet->socket, packet->data, packet->data_len);
	if (slen <= 0) return -1;

	return 0;
}

/** Allocate a RADIUS bio for writing client packets
 *
 *  It also verifies that the packets we receive are valid for RADIUS.
 */
fr_bio_packet_t *fr_radius_client_udp_bio_alloc(TALLOC_CTX *ctx, fr_radius_client_config_t *cfg, fr_bio_fd_config_t const *fd_cfg)
{
	fr_radius_client_fd_bio_t *my;

	my = fr_radius_client_fd_bio_alloc(ctx, 2 * 4096, cfg, fd_cfg);
	if (!my) return NULL;

	if (fr_bio_mem_set_verify(my->mem, fr_radius_bio_verify_datagram, &my->cfg.verify, true) < 0) {
		talloc_free(my);
		return NULL;
	}

	my->common.read = fr_radius_client_fd_bio_read;
	my->common.write = fr_radius_client_udp_bio_write;

	return (fr_bio_packet_t *) my;
}
