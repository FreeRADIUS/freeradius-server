#ifndef LRAD_PACKET_H
#define LRAD_PACKET_H

/*
 * packet.h	Structures and prototypes
 *		for packet manipulation
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
 * Copyright 2001,2002,2003,2004,2005,2006  The FreeRADIUS server project
 */

#include <freeradius-devel/ident.h>
RCSIDH(packet_h, "$Id$")

uint32_t lrad_request_packet_hash(const RADIUS_PACKET *packet);
uint32_t lrad_reply_packet_hash(const RADIUS_PACKET *packet);
int lrad_packet_cmp(const RADIUS_PACKET *a, const RADIUS_PACKET *b);
void lrad_request_from_reply(RADIUS_PACKET *request,
			     const RADIUS_PACKET *reply);
int lrad_socket(lrad_ipaddr_t *ipaddr, int port);

typedef struct lrad_packet_list_t lrad_packet_list_t;

lrad_packet_list_t *lrad_packet_list_create(int alloc_id);
void lrad_packet_list_free(lrad_packet_list_t *pl);
int lrad_packet_list_insert(lrad_packet_list_t *pl,
			    RADIUS_PACKET **request_p);

RADIUS_PACKET **lrad_packet_list_find(lrad_packet_list_t *pl,
				      RADIUS_PACKET *request);
RADIUS_PACKET **lrad_packet_list_find_byreply(lrad_packet_list_t *pl,
					      RADIUS_PACKET *reply);
RADIUS_PACKET **lrad_packet_list_yank(lrad_packet_list_t *pl,
				      RADIUS_PACKET *request);
int lrad_packet_list_num_elements(lrad_packet_list_t *pl);
int lrad_packet_list_id_alloc(lrad_packet_list_t *pl,
			      RADIUS_PACKET *request);
int lrad_packet_list_id_free(lrad_packet_list_t *pl,
			     RADIUS_PACKET *request);
int lrad_packet_list_socket_add(lrad_packet_list_t *pl, int sockfd);
int lrad_packet_list_socket_remove(lrad_packet_list_t *pl, int sockfd);
int lrad_packet_list_walk(lrad_packet_list_t *pl, void *ctx,
			  lrad_hash_table_walk_t callback);
int lrad_packet_list_fd_set(lrad_packet_list_t *pl, fd_set *set);
RADIUS_PACKET *lrad_packet_list_recv(lrad_packet_list_t *pl, fd_set *set);

int lrad_packet_list_num_incoming(lrad_packet_list_t *pl);
int lrad_packet_list_num_outgoing(lrad_packet_list_t *pl);


#ifndef offsetof
# define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

/*
 *	"find" returns a pointer to the RADIUS_PACKET* member in the
 *	caller's structure.  In order to get the pointer to the *top*
 *	of the caller's structure, you have to subtract the offset to
 *	the member from the returned pointer, and cast it to the
 *	required type.
 */
# define lrad_packet2myptr(TYPE, MEMBER, PTR) (TYPE *) (((char *)PTR) - offsetof(TYPE, MEMBER))
#endif /* LRAD_PACKET_H */
