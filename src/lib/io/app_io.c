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
 * @file io/app_io.c
 * @brief APP IO utility functions
 *
 * @copyright 2018 Alan DeKok (aland@freeradius.org)
 */
#include <freeradius-devel/io/base.h>
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/util/debug.h>


char const *fr_app_io_socket_name(TALLOC_CTX *ctx, fr_app_io_t const *app_io,
				  fr_ipaddr_t const *src_ipaddr, int src_port,
				  fr_ipaddr_t const *dst_ipaddr, int dst_port,
				  char const *interface)
{
	char		    dst_buf[128], src_buf[128];

	/*
	 *	Get our name.
	 */
	if (fr_ipaddr_is_inaddr_any(dst_ipaddr)) {
		if (dst_ipaddr->af == AF_INET) {
			strlcpy(dst_buf, "*", sizeof(dst_buf));
		} else {
			fr_assert(dst_ipaddr->af == AF_INET6);
			strlcpy(dst_buf, "::", sizeof(dst_buf));
		}
	} else {
		fr_value_box_snprint(dst_buf, sizeof(dst_buf), fr_box_ipaddr(*dst_ipaddr), 0);
	}

	if (src_ipaddr) fr_value_box_snprint(src_buf, sizeof(src_buf), fr_box_ipaddr(*src_ipaddr), 0);

	if (!interface) {
		if (!src_ipaddr) {
			return talloc_typed_asprintf(ctx, "proto_%s server %s port %u",
						     app_io->name, dst_buf, dst_port);
		}


		return talloc_typed_asprintf(ctx, "proto_%s from client %s port %u to server %s port %u",
					     app_io->name, src_buf, src_port, dst_buf, dst_port);
	}

	if (!src_ipaddr) {
		return talloc_typed_asprintf(ctx, "proto_%s server %s port %u on interface %s",
					     app_io->name, dst_buf, dst_port, interface);
		}


		return talloc_typed_asprintf(ctx, "proto_%s from client %s port %u to server %s port %u on interface %s",
					     app_io->name, src_buf, src_port, dst_buf, dst_port, interface);
}

fr_socket_addr_t *fr_app_io_socket_addr(TALLOC_CTX *ctx, int proto, fr_ipaddr_t const *ipaddr, int port)
{
	fr_socket_addr_t *addr;

	addr = talloc_zero(ctx, fr_socket_addr_t);

	addr->proto = proto;
	addr->ipaddr = *ipaddr;
	addr->port = port;

	return addr;
}
