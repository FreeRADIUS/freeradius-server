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
 * @file protocols/radius/server.c
 * @brief Functions to support RADIUS bio handlers for server sockets
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/radius/server.h>
#include <freeradius-devel/radius/server_udp.h>
#include <freeradius-devel/radius/server_priv.h>

fr_bio_packet_t *fr_radius_server_bio_alloc(TALLOC_CTX *ctx, fr_radius_server_config_t *cfg, fr_bio_fd_config_t const *fd_cfg)
{
	fr_assert(fd_cfg->type == FR_BIO_FD_UNCONNECTED); /* UDP sockets only for now */

	if (fd_cfg->path || fd_cfg->filename) {
		fr_strerror_const("Domain sockets and files are not supported");
		return NULL;
	}

	if (fd_cfg->socket_type == SOCK_DGRAM) return fr_radius_server_udp_bio_alloc(ctx, cfg, fd_cfg);

	fr_strerror_const("No TCP for you.");
	return NULL;

//	return fr_radius_server_tcp_bio_alloc(ctx, cfg, fd_cfg);
}

static int _radius_server_fd_bio_free(fr_radius_server_fd_bio_t *my)
{
	if (fr_bio_shutdown(my->common.bio) < 0) return -1;

	if (fr_bio_free(my->common.bio) < 0) return -1;

	return 0;
}


fr_radius_server_fd_bio_t *fr_radius_server_fd_bio_alloc(TALLOC_CTX *ctx, size_t read_size, fr_radius_server_config_t *cfg, fr_bio_fd_config_t const *fd_cfg)
{
	fr_radius_server_fd_bio_t *my;

	/*
	 *	For now we only support unconnected UDP server sockets.
	 *
	 *	Connected TCP server sockets require the ability to create new BIOs and add new sockets on the fly.
	 */
	fr_assert(fd_cfg->type == FR_BIO_FD_UNCONNECTED);

	my = talloc_zero(ctx, fr_radius_server_fd_bio_t);
	if (!my) return NULL;

	my->fd = fr_bio_fd_alloc(my, fd_cfg, 0);
	if (!my->fd) {
	fail:
		talloc_free(my);
		return NULL;
	}

	/*
	 *	So that read / write pause / resume callbacks can find us
	 */
	my->fd->uctx = my;

	my->info.fd_info = fr_bio_fd_info(my->fd);
	fr_assert(my->info.fd_info != NULL);

	my->mem = fr_bio_mem_alloc(my, read_size, 2 * 4096, my->fd);
	if (!my->mem) goto fail;
	my->mem->uctx = &my->cfg.verify;

	my->cfg = *cfg;

	my->common.bio = my->mem;

	talloc_set_destructor(my, _radius_server_fd_bio_free);

	return my;
}

int fr_radius_server_fd_bio_write(fr_bio_packet_t *bio, UNUSED void *pctx, fr_packet_t *reply, fr_pair_list_t *list)
{
	fr_radius_server_fd_bio_t *my = talloc_get_type_abort(bio, fr_radius_server_fd_bio_t);
	fr_packet_t *request = reply->uctx;
	ssize_t slen;

	fr_assert(!reply->data);

	fr_assert(reply->code > 0);
	fr_assert(reply->code < FR_RADIUS_CODE_MAX);

	/*
	 *	Encode the packet.
	 */
	if (fr_packet_encode(reply, list, request, (char const *) my->cfg.verify.secret) < 0) {
	fail:
		return fr_bio_error(GENERIC);
	}

	if (fr_packet_sign(reply, request, (char const *) my->cfg.verify.secret) < 0) goto fail;

	slen = fr_bio_write(my->common.bio, &reply->socket, reply->data, reply->data_len);
	if (slen < 0) {
		fr_assert((slen != fr_bio_error(IO_WOULD_BLOCK)) || my->common.write_blocked);

		return slen;
	}

	my->info.write_blocked = false;

	return 0;
}


int fr_radius_server_fd_bio_read(fr_bio_packet_t *bio, UNUSED void **packet_ctx_p, fr_packet_t **packet_p,
				 TALLOC_CTX *out_ctx, fr_pair_list_t *out)
{
	ssize_t slen;
	fr_radius_server_fd_bio_t *my = talloc_get_type_abort(bio, fr_radius_server_fd_bio_t);
	fr_packet_t *packet;

	/*
	 *	We don't need to set up response.socket for connected bios.
	 */
	fr_packet_t base = {};

	/*
	 *	We read the response packet ctx into our local structure.  If we have a real response, we will
	 *	swap to using the request context, and not the response context.
	 */
	slen = fr_bio_read(my->common.bio, &base, &my->buffer, sizeof(my->buffer));
	if (!slen) return 0;

	if (slen < 0) {
		fr_assert(slen != fr_bio_error(IO_WOULD_BLOCK));
		return slen;
	}


	/*
	 *	Allocate the packet data structure
	 */
	packet = fr_packet_alloc(out_ctx, false);
	if (!packet) return -1;

	packet->data = talloc_memdup(packet, my->buffer, slen);
	if (!packet->data) {
		talloc_free(packet);
		return -1;
	}
	packet->data_len = slen;

	packet->code = packet->data[0];
	packet->id = packet->data[1];
	memcpy(packet->vector, packet->data + 4, sizeof(packet->vector));

	/*
	 *	If this fails, we're out of memory.
	 */
	if (fr_radius_decode_simple(packet, out, packet->data, packet->data_len,
				    NULL, (char const *) my->cfg.verify.secret) < 0) {
		talloc_free(packet);
		return -1;
	}

	*packet_p = packet;

	return 1;
}

fr_bio_t *fr_radius_server_bio_get_fd(fr_bio_packet_t *bio)
{
	fr_radius_server_fd_bio_t *my = talloc_get_type_abort(bio, fr_radius_server_fd_bio_t);

	return my->fd;
}

fr_radius_server_bio_info_t const *fr_radius_server_bio_info(fr_bio_packet_t *bio)
{
	fr_radius_server_fd_bio_t *my = talloc_get_type_abort(bio, fr_radius_server_fd_bio_t);

	return &my->info;
}
