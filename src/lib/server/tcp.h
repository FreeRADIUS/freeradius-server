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
 * @file lib/server/tcp.h
 * @brief RADIUS over TCP
 *
 * @copyright 2009 Dante http://dante.net
 */
RCSIDH(tcp_h, "$Id$")

int fr_tcp_read_packet(RADIUS_PACKET *packet, uint32_t max_attributes, bool require_ma);
RADIUS_PACKET *fr_tcp_recv(int sockfd, int flags);
