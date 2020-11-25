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
 * @file protocols/radius/list.c
 * @brief Functions to deal with outgoing lists / sets of packets.
 *
 * @copyright 2000-2017 The FreeRADIUS server project
 */

RCSID("$Id$")

#include "radius.h"
#include "list.h"

#include <freeradius-devel/util/base.h>
#include <freeradius-devel/util/udp.h>
#include <freeradius-devel/server/tcp.h>
#include <fcntl.h>

/*
 *	See if two packets are identical.
 *
 *	Note that we do NOT compare the authentication vectors.
 *	That's because if the authentication vector is different,
 *	it means that the NAS has given up on the earlier request.
 */
int fr_packet_cmp(fr_radius_packet_t const *a, fr_radius_packet_t const *b)
{
	int ret;

	/*
	 *	256-way fanout.
	 */
	if (a->id < b->id) return -1;
	if (a->id > b->id) return +1;

	if (a->socket.fd < b->socket.fd) return -1;
	if (a->socket.fd > b->socket.fd) return +1;

	/*
	 *	Source ports are pretty much random.
	 */
	ret = (int) a->socket.inet.src_port - (int) b->socket.inet.src_port;
	if (ret != 0) return ret;

	/*
	 *	Usually many client IPs, and few server IPs
	 */
	ret = fr_ipaddr_cmp(&a->socket.inet.src_ipaddr, &b->socket.inet.src_ipaddr);
	if (ret != 0) return ret;

	/*
	 *	One socket can receive packets for multiple
	 *	destination IPs, so we check that before checking the
	 *	file descriptor.
	 */
	ret = fr_ipaddr_cmp(&a->socket.inet.dst_ipaddr, &b->socket.inet.dst_ipaddr);
	if (ret != 0) return ret;

	/*
	 *	At this point, the order of comparing socket FDs
	 *	and/or destination ports doesn't matter.  One of those
	 *	fields will make the socket unique, and the other is
	 *	pretty much redundant.
	 */
	ret = (int) a->socket.inet.dst_port - (int) b->socket.inet.dst_port;
	return ret;
}

/*
 *	Create a fake "request" from a reply, for later lookup.
 */
void fr_request_from_reply(fr_radius_packet_t *request,
			   fr_radius_packet_t const *reply)
{
	fr_socket_addr_swap(&request->socket, &reply->socket);
	request->id = reply->id;
}

/*
 *	We need to keep track of the socket & it's IP/port.
 */
typedef struct {
	fr_socket_t	socket;

	int		src_any;
	int		dst_any;
	void			*ctx;

	uint32_t		num_outgoing;

	bool			dont_use;

	uint8_t			id[32];
} fr_packet_socket_t;


#define FNV_MAGIC_PRIME (0x01000193)
#define MAX_SOCKETS (256)
#define SOCKOFFSET_MASK (MAX_SOCKETS - 1)
#define SOCK2OFFSET(_sockfd) ((_sockfd * FNV_MAGIC_PRIME) & SOCKOFFSET_MASK)

/*
 *	Structure defining a list of packets (incoming or outgoing)
 *	that should be managed.
 */
struct fr_packet_list_s {
	rbtree_t	*tree;

	int		alloc_id;
	uint32_t	num_outgoing;
	int		last_recv;
	int		num_sockets;

	fr_packet_socket_t sockets[MAX_SOCKETS];
};


/*
 *	Ugh.  Doing this on every sent/received packet is not nice.
 */
static fr_packet_socket_t *fr_socket_find(fr_packet_list_t *pl, int sockfd)
{
	int i, start;

	i = start = SOCK2OFFSET(sockfd);

	do {			/* make this hack slightly more efficient */
		if (pl->sockets[i].socket.fd == sockfd) return &pl->sockets[i];

		i = (i + 1) & SOCKOFFSET_MASK;
	} while (i != start);

	return NULL;
}

bool fr_packet_list_socket_freeze(fr_packet_list_t *pl, int sockfd)
{
	fr_packet_socket_t *ps;

	if (!pl) {
		fr_strerror_printf("Invalid argument");
		return false;
	}

	ps = fr_socket_find(pl, sockfd);
	if (!ps) {
		fr_strerror_printf("No such socket");
		return false;
	}

	ps->dont_use = true;
	return true;
}

bool fr_packet_list_socket_thaw(fr_packet_list_t *pl, int sockfd)
{
	fr_packet_socket_t *ps;

	if (!pl) return false;

	ps = fr_socket_find(pl, sockfd);
	if (!ps) return false;

	ps->dont_use = false;
	return true;
}


bool fr_packet_list_socket_del(fr_packet_list_t *pl, int sockfd)
{
	fr_packet_socket_t *ps;

	if (!pl) return false;

	ps = fr_socket_find(pl, sockfd);
	if (!ps) return false;

	if (ps->num_outgoing != 0) return false;

	ps->socket.fd = -1;
	pl->num_sockets--;

	return true;
}


bool fr_packet_list_socket_add(fr_packet_list_t *pl, int sockfd, int proto,
			      fr_ipaddr_t *dst_ipaddr, uint16_t dst_port,
			      void *ctx)
{
	int i, start;
	struct sockaddr_storage	src;
	socklen_t		sizeof_src;
	fr_packet_socket_t	*ps;

	if (!pl || !dst_ipaddr || (dst_ipaddr->af == AF_UNSPEC)) {
		fr_strerror_printf("Invalid argument");
		return false;
	}

	if (pl->num_sockets >= MAX_SOCKETS) {
		fr_strerror_printf("Too many open sockets");
		return false;
	}

	ps = NULL;
	i = start = SOCK2OFFSET(sockfd);

	do {
		if (pl->sockets[i].socket.fd == -1) {
			ps =  &pl->sockets[i];
			break;
		}

		i = (i + 1) & SOCKOFFSET_MASK;
	} while (i != start);

	if (!ps) {
		fr_strerror_printf("All socket entries are full");
		return false;
	}

	memset(ps, 0, sizeof(*ps));
	ps->ctx = ctx;
	ps->socket.proto = proto;

	/*
	 *	Get address family, etc. first, so we know if we
	 *	need to do udpfromto.
	 *
	 *	FIXME: udpfromto also does this, but it's not
	 *	a critical problem.
	 */
	sizeof_src = sizeof(src);
	memset(&src, 0, sizeof_src);
	if (getsockname(sockfd, (struct sockaddr *) &src, &sizeof_src) < 0) {
		fr_strerror_printf("%s", fr_syserror(errno));
		return false;
	}

	if (fr_ipaddr_from_sockaddr(&ps->socket.inet.src_ipaddr, &ps->socket.inet.src_port, &src, sizeof_src) < 0) {
		fr_strerror_printf("Failed to get IP");
		return false;
	}

	ps->socket.inet.dst_ipaddr = *dst_ipaddr;
	ps->socket.inet.dst_port = dst_port;

	ps->src_any = fr_ipaddr_is_inaddr_any(&ps->socket.inet.src_ipaddr);
	if (ps->src_any < 0) return false;

	ps->dst_any = fr_ipaddr_is_inaddr_any(&ps->socket.inet.dst_ipaddr);
	if (ps->dst_any < 0) return false;

	/*
	 *	As the last step before returning.
	 */
	ps->socket.fd = sockfd;
	pl->num_sockets++;

	return true;
}

static int packet_entry_cmp(void const *one, void const *two)
{
	fr_radius_packet_t const * const *a = one;
	fr_radius_packet_t const * const *b = two;

	return fr_packet_cmp(*a, *b);
}

void fr_packet_list_free(fr_packet_list_t *pl)
{
	if (!pl) return;

	talloc_free(pl->tree);
	talloc_free(pl);
}


/*
 *	Caller is responsible for managing the packet entries.
 */
fr_packet_list_t *fr_packet_list_create(int alloc_id)
{
	int i;
	fr_packet_list_t	*pl;

	pl = talloc_zero(NULL, fr_packet_list_t);
	if (!pl) return NULL;
	pl->tree = rbtree_alloc(pl, packet_entry_cmp, NULL, 0);	/* elements not talloc safe */
	if (!pl->tree) {
		fr_packet_list_free(pl);
		return NULL;
	}

	for (i = 0; i < MAX_SOCKETS; i++) {
		pl->sockets[i].socket.fd = -1;
	}

	pl->alloc_id = alloc_id;

	return pl;
}


/*
 *	If pl->alloc_id is set, then fr_packet_list_id_alloc() MUST
 *	be called before inserting the packet into the list!
 */
bool fr_packet_list_insert(fr_packet_list_t *pl,
			    fr_radius_packet_t **request_p)
{
	if (!pl || !request_p || !*request_p) return 0;

	return rbtree_insert(pl->tree, request_p);
}

fr_radius_packet_t **fr_packet_list_find(fr_packet_list_t *pl, fr_radius_packet_t *request)
{
	if (!pl || !request) return 0;

	return rbtree_finddata(pl->tree, &request);
}


/*
 *	This presumes that the reply has dst_ipaddr && dst_port set up
 *	correctly (i.e. real IP, or "*").
 */
fr_radius_packet_t **fr_packet_list_find_byreply(fr_packet_list_t *pl, fr_radius_packet_t *reply)
{
	fr_radius_packet_t my_request, *request;
	fr_packet_socket_t *ps;

	if (!pl || !reply) return NULL;

	ps = fr_socket_find(pl, reply->socket.fd);
	if (!ps) return NULL;

	/*
	 *	TCP sockets are always bound to the correct src/dst IP/port
	 */
	if (ps->socket.proto == IPPROTO_TCP) {
		fr_socket_addr_swap(&reply->socket, &ps->socket);
		my_request.socket = ps->socket;
	} else {
		my_request.socket = ps->socket;

		if (!ps->src_any) my_request.socket.inet.src_ipaddr = reply->socket.inet.dst_ipaddr;
		my_request.socket.inet.dst_ipaddr = reply->socket.inet.src_ipaddr;
		my_request.socket.inet.dst_port = reply->socket.inet.src_port;
	}

	/*
	 *	Initialize request from reply, AND from the source
	 *	IP & port of this socket.  The client may have bound
	 *	the socket to 0, in which case it's some random port,
	 *	that is NOT in the original request->socket.inet.src_port.
	 */
	my_request.socket.fd = reply->socket.fd;
	my_request.id = reply->id;
	request = &my_request;

	return rbtree_finddata(pl->tree, &request);
}


bool fr_packet_list_yank(fr_packet_list_t *pl, fr_radius_packet_t *request)
{
	rbnode_t *node;

	if (!pl || !request) return false;

	node = rbtree_find(pl->tree, &request);
	if (!node) return false;

	rbtree_delete(pl->tree, node);
	return true;
}

uint32_t fr_packet_list_num_elements(fr_packet_list_t *pl)
{
	if (!pl) return 0;

	return rbtree_num_elements(pl->tree);
}


/*
 *	1 == ID was allocated & assigned
 *	0 == couldn't allocate ID.
 *
 *	Note that this ALSO assigns a socket to use, and updates
 *	packet->request->socket.inet.src_ipaddr && packet->request->socket.inet.src_port
 *
 *	In multi-threaded systems, the calls to id_alloc && id_free
 *	should be protected by a mutex.  This does NOT have to be
 *	the same mutex as the one protecting the insert/find/yank
 *	calls!
 *
 *	We assume that the packet has dst_ipaddr && dst_port
 *	already initialized.  We will use those to find an
 *	outgoing socket.  The request MAY also have src_ipaddr set.
 *
 *	We also assume that the sender doesn't care which protocol
 *	should be used.
 */
bool fr_packet_list_id_alloc(fr_packet_list_t *pl, int proto,
			    fr_radius_packet_t **request_p, void **pctx)
{
	int i, j, k, fd, id, start_i, start_j, start_k;
	int src_any = 0;
	fr_packet_socket_t *ps= NULL;
	fr_radius_packet_t *request = *request_p;

	if ((request->socket.inet.dst_ipaddr.af == AF_UNSPEC) ||
	    (request->socket.inet.dst_port == 0)) {
		fr_strerror_printf("No destination address/port specified");
		return false;
	}

	/*
	 *	Special case: unspec == "don't care"
	 */
	if (request->socket.inet.src_ipaddr.af == AF_UNSPEC) {
		memset(&request->socket.inet.src_ipaddr, 0, sizeof(request->socket.inet.src_ipaddr));
		request->socket.inet.src_ipaddr.af = request->socket.inet.dst_ipaddr.af;
	}

	src_any = fr_ipaddr_is_inaddr_any(&request->socket.inet.src_ipaddr);
	if (src_any < 0) {
		fr_strerror_printf("Can't check src_ipaddr");
		return false;
	}

	/*
	 *	MUST specify a destination address.
	 */
	if (fr_ipaddr_is_inaddr_any(&request->socket.inet.dst_ipaddr) != 0) {
		fr_strerror_printf("Must specify a dst_ipaddr");
		return false;
	}

	/*
	 *	FIXME: Go to an LRU system.  This prevents ID re-use
	 *	for as long as possible.  The main problem with that
	 *	approach is that it requires us to populate the
	 *	LRU/FIFO when we add a new socket, or a new destination,
	 *	which can be expensive.
	 *
	 *	The LRU can be avoided if the caller takes care to free
	 *	Id's only when all responses have been received, OR after
	 *	a timeout.
	 *
	 *	Right now, the random approach is almost OK... it's
	 *	brute-force over all of the available ID's, BUT using
	 *	random numbers for everything spreads the load a bit.
	 *
	 *	The old method had a hash lookup on allocation AND
	 *	on free.  The new method has brute-force on allocation,
	 *	and near-zero cost on free.
	 */

	id = fd = -1;
	if (request->id >= 0 && request->id < 256)
		id = request->id;
	start_i = fr_rand() & SOCKOFFSET_MASK;

#define ID_i ((i + start_i) & SOCKOFFSET_MASK)
	for (i = 0; i < MAX_SOCKETS; i++) {
		if (pl->sockets[ID_i].socket.fd == -1) continue; /* paranoia */

		ps = &(pl->sockets[ID_i]);

		/*
		 *	This socket is marked as "don't use for new
		 *	packets".  But we can still receive packets
		 *	that are outstanding.
		 */
		if (ps->dont_use) continue;

		/*
		 *	All IDs are allocated: ignore it.
		 */
		if (ps->num_outgoing == 256) continue;

		if (ps->socket.proto != proto) continue;

		/*
		 *	Address families don't match, skip it.
		 */
		if (ps->socket.inet.src_ipaddr.af != request->socket.inet.dst_ipaddr.af) continue;

		/*
		 *	MUST match dst port, if we have one.
		 */
		if ((ps->socket.inet.dst_port != 0) &&
		    (ps->socket.inet.dst_port != request->socket.inet.dst_port)) continue;

		/*
		 *	MUST match requested src port, if one has been given.
		 */
		if ((request->socket.inet.src_port != 0) &&
		    (ps->socket.inet.src_port != request->socket.inet.src_port)) continue;

		/*
		 *	We don't care about the source IP, but this
		 *	socket is link local, and the requested
		 *	destination is not link local.  Ignore it.
		 */
		if (src_any && (ps->socket.inet.src_ipaddr.af == AF_INET) &&
		    (((ps->socket.inet.src_ipaddr.addr.v4.s_addr >> 24) & 0xff) == 127) &&
		    (((request->socket.inet.dst_ipaddr.addr.v4.s_addr >> 24) & 0xff) != 127)) continue;

		/*
		 *	We're sourcing from *, and they asked for a
		 *	specific source address: ignore it.
		 */
		if (ps->src_any && !src_any) continue;

		/*
		 *	We're sourcing from a specific IP, and they
		 *	asked for a source IP that isn't us: ignore
		 *	it.
		 */
		if (!ps->src_any && !src_any &&
		    (fr_ipaddr_cmp(&request->socket.inet.src_ipaddr,
				   &ps->socket.inet.src_ipaddr) != 0)) continue;

		/*
		 *	UDP sockets are allowed to match
		 *	destination IPs exactly, OR a socket
		 *	with destination * is allowed to match
		 *	any requested destination.
		 *
		 *	TCP sockets must match the destination
		 *	exactly.  They *always* have dst_any=0,
		 *	so the first check always matches.
		 */
		if (!ps->dst_any &&
		    (fr_ipaddr_cmp(&request->socket.inet.dst_ipaddr,
				   &ps->socket.inet.dst_ipaddr) != 0)) continue;

		/*
		 *	Otherwise, this socket is OK to use.
		 */

		/*
		 *	An explicit ID was requested
		 */

		if (id != -1) {
			if  ((ps->id[(id >> 3) & 0x1f] & (1 << (id & 0x07))) != 0) continue;

			ps->id[(id >> 3) & 0x1f] |= (1 << (id & 0x07));
			fd = i;
			break;
		}

		/*
		 *	Look for a free Id, starting from a random number.
		 */
		start_j = fr_rand() & 0x1f;
#define ID_j ((j + start_j) & 0x1f)
		for (j = 0; j < 32; j++) {
			if (ps->id[ID_j] == 0xff) continue;


			start_k = fr_rand() & 0x07;
#define ID_k ((k + start_k) & 0x07)
			for (k = 0; k < 8; k++) {
				if ((ps->id[ID_j] & (1 << ID_k)) != 0) continue;

				ps->id[ID_j] |= (1 << ID_k);
				id = (ID_j * 8) + ID_k;
				fd = i;
				break;
			}
			if (fd >= 0) break;
		}
#undef ID_i
#undef ID_j
#undef ID_k
		break;
	}

	/*
	 *	Ask the caller to allocate a new ID.
	 */
	if (fd < 0) {
		fr_strerror_printf("Failed finding socket, caller must allocate a new one");
		return false;
	}

	/*
	 *	Set the ID, source IP, and source port.
	 */
	request->id = id;

	request->socket.fd = ps->socket.fd;
	request->socket.inet.src_ipaddr = ps->socket.inet.src_ipaddr;
	request->socket.inet.src_port = ps->socket.inet.src_port;

	/*
	 *	If we managed to insert it, we're done.
	 */
	if (fr_packet_list_insert(pl, request_p)) {
		if (pctx) *pctx = ps->ctx;
		ps->num_outgoing++;
		pl->num_outgoing++;
		return true;
	}

	/*
	 *	Mark the ID as free.  This is the one line from
	 *	id_free() that we care about here.
	 */
	ps->id[(request->id >> 3) & 0x1f] &= ~(1 << (request->id & 0x07));

	request->id = -1;
	request->socket.fd = -1;
	request->socket.inet.src_ipaddr.af = AF_UNSPEC;
	request->socket.inet.src_port = 0;

	return false;
}

/*
 *	Should be called AFTER yanking it from the list, so that
 *	any newly inserted entries don't collide with this one.
 */
bool fr_packet_list_id_free(fr_packet_list_t *pl,
			    fr_radius_packet_t *request, bool yank)
{
	fr_packet_socket_t *ps;

	if (!pl || !request) return false;

	if (yank && !fr_packet_list_yank(pl, request)) return false;

	ps = fr_socket_find(pl, request->socket.fd);
	if (!ps) return false;

	ps->id[(request->id >> 3) & 0x1f] &= ~(1 << (request->id & 0x07));

	ps->num_outgoing--;
	pl->num_outgoing--;

	request->id = -1;
	request->socket.inet.src_ipaddr.af = AF_UNSPEC; /* id_alloc checks this */
	request->socket.inet.src_port = 0;

	return true;
}

/*
 *	We always walk RBTREE_DELETE_ORDER, which is like RBTREE_IN_ORDER, except that
 *	<0 means error, stop
 *	0  means OK, continue
 *	1  means delete current node and stop
 *	2  means delete current node and continue
 */
int fr_packet_list_walk(fr_packet_list_t *pl, rb_walker_t callback, void *uctx)
{
	if (!pl || !callback) return 0;

	return rbtree_walk(pl->tree, RBTREE_DELETE_ORDER, callback, uctx);
}

int fr_packet_list_fd_set(fr_packet_list_t *pl, fd_set *set)
{
	int i, maxfd;

	if (!pl || !set) return 0;

	maxfd = -1;

	for (i = 0; i < MAX_SOCKETS; i++) {
		if (pl->sockets[i].socket.fd == -1) continue;
		FD_SET(pl->sockets[i].socket.fd, set);
		if (pl->sockets[i].socket.fd > maxfd) {
			maxfd = pl->sockets[i].socket.fd;
		}
	}

	if (maxfd < 0) return -1;

	return maxfd + 1;
}

/*
 *	Round-robins the receivers, without priority.
 *
 *	FIXME: Add socket.fd, if -1, do round-robin, else do socket.fd
 *		IF in fdset.
 */
fr_radius_packet_t *fr_packet_list_recv(fr_packet_list_t *pl, fd_set *set, uint32_t max_attributes, bool require_ma)
{
	int start;
	fr_radius_packet_t *packet;

	if (!pl || !set) return NULL;

	start = pl->last_recv;
	do {
		start++;
		start &= SOCKOFFSET_MASK;

		if (pl->sockets[start].socket.fd == -1) continue;

		if (!FD_ISSET(pl->sockets[start].socket.fd, set)) continue;

		if (pl->sockets[start].socket.proto == IPPROTO_TCP) {
			packet = fr_tcp_recv(pl->sockets[start].socket.fd, false);
		} else
			packet = fr_radius_packet_recv(NULL, pl->sockets[start].socket.fd, UDP_FLAGS_NONE,
						       max_attributes, require_ma);
		if (!packet) continue;

		/*
		 *	Call fr_packet_list_find_byreply().  If it
		 *	doesn't find anything, discard the reply.
		 */

		pl->last_recv = start;
		packet->socket.proto = pl->sockets[start].socket.proto;
		return packet;
	} while (start != pl->last_recv);

	return NULL;
}

uint32_t fr_packet_list_num_incoming(fr_packet_list_t *pl)
{
	uint32_t num_elements;

	if (!pl) return 0;

	num_elements = rbtree_num_elements(pl->tree);
	if (num_elements < pl->num_outgoing) return 0; /* panic! */

	return num_elements - pl->num_outgoing;
}

uint32_t fr_packet_list_num_outgoing(fr_packet_list_t *pl)
{
	if (!pl) return 0;

	return pl->num_outgoing;
}

/*
 *	Debug the packet if requested.
 */
void fr_packet_header_log(fr_log_t const *log, fr_radius_packet_t *packet, bool received)
{
	char src_ipaddr[FR_IPADDR_STRLEN];
	char dst_ipaddr[FR_IPADDR_STRLEN];
#ifdef WITH_IFINDEX_NAME_RESOLUTION
	char if_name[IFNAMSIZ];
#endif

	if (!log) return;
	if (!packet) return;

	/*
	 *	Client-specific debugging re-prints the input
	 *	packet into the client log.
	 *
	 *	This really belongs in a utility library
	 */
	if (is_radius_code(packet->code)) {
		fr_log(log, L_DBG, __FILE__, __LINE__,
		       "%s %s Id %i from %s%s%s:%i to %s%s%s:%i "
#ifdef WITH_IFINDEX_NAME_RESOLUTION
		       "%s%s%s"
#endif
		       "length %zu\n",
		        received ? "Received" : "Sent",
		        fr_packet_codes[packet->code],
		        packet->id,
		        packet->socket.inet.src_ipaddr.af == AF_INET6 ? "[" : "",
			fr_inet_ntop(src_ipaddr, sizeof(src_ipaddr), &packet->socket.inet.src_ipaddr),
			packet->socket.inet.src_ipaddr.af == AF_INET6 ? "]" : "",
		        packet->socket.inet.src_port,
		        packet->socket.inet.dst_ipaddr.af == AF_INET6 ? "[" : "",
			fr_inet_ntop(dst_ipaddr, sizeof(dst_ipaddr), &packet->socket.inet.dst_ipaddr),
		        packet->socket.inet.dst_ipaddr.af == AF_INET6 ? "]" : "",
		        packet->socket.inet.dst_port,
#ifdef WITH_IFINDEX_NAME_RESOLUTION
			received ? "via " : "",
			received ? fr_ifname_from_ifindex(if_name, packet->socket.inet.ifindex) : "",
			received ? " " : "",
#endif
			packet->data_len);
	} else {
		fr_log(log, L_DBG, __FILE__, __LINE__,
		       "%s code %u Id %i from %s%s%s:%i to %s%s%s:%i "
#ifdef WITH_IFINDEX_NAME_RESOLUTION
		       "%s%s%s"
#endif
		       "length %zu\n",
		        received ? "Received" : "Sent",
		        packet->code,
		        packet->id,
		        packet->socket.inet.src_ipaddr.af == AF_INET6 ? "[" : "",
			fr_inet_ntop(src_ipaddr, sizeof(src_ipaddr), &packet->socket.inet.src_ipaddr),
		        packet->socket.inet.src_ipaddr.af == AF_INET6 ? "]" : "",
		        packet->socket.inet.src_port,
		        packet->socket.inet.dst_ipaddr.af == AF_INET6 ? "[" : "",
			fr_inet_ntop(dst_ipaddr, sizeof(dst_ipaddr), &packet->socket.inet.dst_ipaddr),
		        packet->socket.inet.dst_ipaddr.af == AF_INET6 ? "]" : "",
		        packet->socket.inet.dst_port,
#ifdef WITH_IFINDEX_NAME_RESOLUTION
			received ? "via " : "",
			received ? fr_ifname_from_ifindex(if_name, packet->socket.inet.ifindex) : "",
			received ? " " : "",
#endif
		        packet->data_len);
	}
}

/*
 *	Debug the packet header and all attributes
 */
void fr_packet_log(fr_log_t const *log, fr_radius_packet_t *packet, bool received)
{
	fr_packet_header_log(log, packet, received);
	if (fr_debug_lvl >= L_DBG_LVL_1) fr_pair_list_log(log, packet->vps);
#ifndef NDEBUG
	if (fr_debug_lvl >= L_DBG_LVL_4) fr_radius_packet_log_hex(log, packet);
#endif
}
