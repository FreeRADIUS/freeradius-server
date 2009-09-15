#ifndef FR_TCP_H
#define FR_TCP_H

/*
 * tcp.h	RADIUS over TCP
 *
 * Version:	$Id$
 *
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
 *
 * Copyright (C) 2009 Dante http://dante.net
 */

#include <freeradius-devel/ident.h>
RCSIDH(tcp_h, "$Id$")

/*
 *	Application-layer watchdog from RFC 3539, Appendix A.
 */
typedef enum fr_watchdog_t {
	ALW_INITIAL = 0,
	ALW_OK,
	ALW_SUSPECT,
	ALW_DOWN,
	ALW_REOPEN
} fr_watchdog_t;

#define ALW_TWINIT (6)

typedef struct fr_tcp_radius_t {
	int		fd;
	fr_ipaddr_t	src_ipaddr;
	fr_ipaddr_t	dst_ipaddr;
	int		src_port;
	int		dst_port;

	int		num_packets;
	int		lifetime;

	time_t		opened;
	time_t		last_packet;
#ifdef WITH_TCP_PING
	struct timeval	when;
	void		*ev;
#endif

	int		state;
	int		ping_interval;
	int		num_pings_to_alive;
	int		num_received_pings;
	int		num_pings_sent;
	int		ping_timeout;

	int		used;
	void		*ev;
	RADIUS_PACKET	**ids[256];
} fr_tcp_radius_t;

int fr_tcp_socket(fr_ipaddr_t *ipaddr, int port);
int fr_tcp_client_socket(fr_ipaddr_t *ipaddr, int port);
int fr_tcp_read_packet(RADIUS_PACKET *packet, int flags);
RADIUS_PACKET *fr_tcp_recv(int sockfd, int flags);
RADIUS_PACKET *fr_tcp_accept(int sockfd);
ssize_t fr_tcp_write_packet(RADIUS_PACKET *packet);

int fr_tcp_list_init(fr_tcp_radius_t *list);
int fr_tcp_list_insert(RADIUS_PACKET **packet, int num,
		       fr_tcp_radius_t *array[]);

int fr_tcp_id_free(int ids[256], int id);

#endif /* FR_TCP_H */
