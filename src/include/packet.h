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
#ifndef _FR_PACKET_H
#define _FR_PACKET_H
/**
 * $Id$
 *
 * @file include/packet.h
 * @brief Structures and functions for packet manipulation
 *
 * @copyright 2001, 2002, 2003, 2004, 2005, 2006 The FreeRADIUS server project
 */
RCSIDH(packet_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/inet.h>
#include <freeradius-devel/pair.h>
#include <freeradius-devel/rbtree.h>

#define AUTH_VECTOR_LEN		16

/*
 *	vector:		Request authenticator from access-request packet
 *			Put in there by rad_decode, and must be put in the
 *			response RADIUS_PACKET as well before calling fr_radius_packet_send
 *
 *	verified:	Filled in by rad_decode for accounting-request packets
 *
 *	data,data_len:	Used between fr_radius_recv and fr_radius_decode.
 */
typedef struct radius_packet {
	int			sockfd;			//!< Socket this packet was read from.
	int			if_index;		//!< Index of receiving interface.
	fr_ipaddr_t		src_ipaddr;		//!< Src IP address of packet.
	fr_ipaddr_t		dst_ipaddr;		//!< Dst IP address of packet.
	uint16_t		src_port;		//!< Src port of packet.
	uint16_t		dst_port;		//!< DST Port of packet.

	int			id;			//!< Packet ID (used to link requests/responses).
	unsigned int		code;			//!< Packet code (type).

	uint8_t			vector[AUTH_VECTOR_LEN];//!< RADIUS authentication vector.

	uint32_t       		count;			//!< Number of times we've seen this packet
	struct timeval		timestamp;		//!< When we received the packet.
	uint8_t			*data;			//!< Packet data (body).
	size_t			data_len;		//!< Length of packet data.
	VALUE_PAIR		*vps;			//!< Result of decoding the packet into VALUE_PAIRs.

	uint32_t       		rounds;			//!< for State[0]

#ifdef WITH_TCP
	size_t			partial;
	int			proto;
#endif
} RADIUS_PACKET;

int fr_packet_cmp(RADIUS_PACKET const *a, RADIUS_PACKET const *b);
void fr_request_from_reply(RADIUS_PACKET *request,
			     RADIUS_PACKET const *reply);

typedef struct fr_packet_list_t fr_packet_list_t;

fr_packet_list_t *fr_packet_list_create(int alloc_id);
void fr_packet_list_free(fr_packet_list_t *pl);
bool fr_packet_list_insert(fr_packet_list_t *pl,
			    RADIUS_PACKET **request_p);

RADIUS_PACKET **fr_packet_list_find(fr_packet_list_t *pl,
				      RADIUS_PACKET *request);
RADIUS_PACKET **fr_packet_list_find_byreply(fr_packet_list_t *pl,
					      RADIUS_PACKET *reply);
bool fr_packet_list_yank(fr_packet_list_t *pl,
			 RADIUS_PACKET *request);
uint32_t fr_packet_list_num_elements(fr_packet_list_t *pl);
bool fr_packet_list_id_alloc(fr_packet_list_t *pl, int proto,
			    RADIUS_PACKET **request_p, void **pctx);
bool fr_packet_list_id_free(fr_packet_list_t *pl,
			    RADIUS_PACKET *request, bool yank);
bool fr_packet_list_socket_add(fr_packet_list_t *pl, int sockfd, int proto,
			      fr_ipaddr_t *dst_ipaddr, uint16_t dst_port,
			      void *ctx);
bool fr_packet_list_socket_del(fr_packet_list_t *pl, int sockfd);
bool fr_packet_list_socket_freeze(fr_packet_list_t *pl, int sockfd);
bool fr_packet_list_socket_thaw(fr_packet_list_t *pl, int sockfd);
int fr_packet_list_walk(fr_packet_list_t *pl, void *ctx, rb_walker_t callback);
int fr_packet_list_fd_set(fr_packet_list_t *pl, fd_set *set);
RADIUS_PACKET *fr_packet_list_recv(fr_packet_list_t *pl, fd_set *set);

uint32_t fr_packet_list_num_incoming(fr_packet_list_t *pl);
uint32_t fr_packet_list_num_outgoing(fr_packet_list_t *pl);
void fr_packet_header_print(FILE *fp, RADIUS_PACKET *packet, bool received);

/*
 *	"find" returns a pointer to the RADIUS_PACKET* member in the
 *	caller's structure.  In order to get the pointer to the *top*
 *	of the caller's structure, you have to subtract the offset to
 *	the member from the returned pointer, and cast it to the
 *	required type.
 */
# define fr_packet2myptr(TYPE, MEMBER, PTR) (TYPE *) (((char *)PTR) - offsetof(TYPE, MEMBER))

#ifdef __cplusplus
}
#endif
#endif /* _FR_PACKET_H */
