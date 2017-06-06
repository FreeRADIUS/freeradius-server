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
#ifndef _PROTO_RADIUS_H
#define _PROTO_RADIUS_H
/*
 * $Id$
 *
 * @file proto_radius.h
 * @brief Structures for the RADIUS protocol
 *
 * @copyright 2017 Alan DeKok <aland@freeradius.org>
 */

typedef struct proto_radius_ctx_t {
	int			sockfd;				//!< sanity checks
	void			*ctx;			//!< for the underlying IO layer

	char const		*secret;			//!< shared secret
	size_t			secret_len;			//!< length of the shared secret

	fr_io_op_t		transport;
	fr_io_process_t		process[FR_MAX_PACKET_CODE];
} proto_radius_ctx_t;

#endif	/* _PROTO_RADIUS_H */
