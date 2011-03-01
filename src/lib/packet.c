/*
 * packet.c	Generic packet manipulation functions.
 *
 * Version:	$Id$
 *
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
 *
 * Copyright 2000-2006  The FreeRADIUS server project
 */

#include	<freeradius-devel/ident.h>
RCSID("$Id$")

#include	<freeradius-devel/libradius.h>

#ifdef WITH_UDPFROMTO
#include	<freeradius-devel/udpfromto.h>
#endif

/*
 *	Take the key fields of a request packet, and convert it to a
 *	hash.
 */
uint32_t fr_request_packet_hash(const RADIUS_PACKET *packet)
{
	uint32_t hash;

	if (packet->hash) return packet->hash;

	hash = fr_hash(&packet->sockfd, sizeof(packet->sockfd));
	hash = fr_hash_update(&packet->src_port, sizeof(packet->src_port),
				hash);
	hash = fr_hash_update(&packet->dst_port,
				sizeof(packet->dst_port), hash);
	hash = fr_hash_update(&packet->src_ipaddr.af,
				sizeof(packet->src_ipaddr.af), hash);

	/*
	 *	The caller ensures that src & dst AF are the same.
	 */
	switch (packet->src_ipaddr.af) {
	case AF_INET:
		hash = fr_hash_update(&packet->src_ipaddr.ipaddr.ip4addr,
					sizeof(packet->src_ipaddr.ipaddr.ip4addr),
					hash);
		hash = fr_hash_update(&packet->dst_ipaddr.ipaddr.ip4addr,
					sizeof(packet->dst_ipaddr.ipaddr.ip4addr),
					hash);
		break;
	case AF_INET6:
		hash = fr_hash_update(&packet->src_ipaddr.ipaddr.ip6addr,
					sizeof(packet->src_ipaddr.ipaddr.ip6addr),
					hash);
		hash = fr_hash_update(&packet->dst_ipaddr.ipaddr.ip6addr,
					sizeof(packet->dst_ipaddr.ipaddr.ip6addr),
					hash);
		break;
	default:
		break;
	}

	return fr_hash_update(&packet->id, sizeof(packet->id), hash);
}


/*
 *	Take the key fields of a reply packet, and convert it to a
 *	hash.
 *
 *	i.e. take a reply packet, and find the hash of the request packet
 *	that asked for the reply.  To do this, we hash the reverse fields
 *	of the request.  e.g. where the request does (src, dst), we do
 *	(dst, src)
 */
uint32_t fr_reply_packet_hash(const RADIUS_PACKET *packet)
{
	uint32_t hash;

	hash = fr_hash(&packet->sockfd, sizeof(packet->sockfd));
	hash = fr_hash_update(&packet->id, sizeof(packet->id), hash);
	hash = fr_hash_update(&packet->src_port, sizeof(packet->src_port),
				hash);
	hash = fr_hash_update(&packet->dst_port,
				sizeof(packet->dst_port), hash);
	hash = fr_hash_update(&packet->src_ipaddr.af,
				sizeof(packet->src_ipaddr.af), hash);

	/*
	 *	The caller ensures that src & dst AF are the same.
	 */
	switch (packet->src_ipaddr.af) {
	case AF_INET:
		hash = fr_hash_update(&packet->dst_ipaddr.ipaddr.ip4addr,
					sizeof(packet->dst_ipaddr.ipaddr.ip4addr),
					hash);
		hash = fr_hash_update(&packet->src_ipaddr.ipaddr.ip4addr,
					sizeof(packet->src_ipaddr.ipaddr.ip4addr),
					hash);
		break;
	case AF_INET6:
		hash = fr_hash_update(&packet->dst_ipaddr.ipaddr.ip6addr,
					sizeof(packet->dst_ipaddr.ipaddr.ip6addr),
					hash);
		hash = fr_hash_update(&packet->src_ipaddr.ipaddr.ip6addr,
					sizeof(packet->src_ipaddr.ipaddr.ip6addr),
					hash);
		break;
	default:
		break;
	}

	return fr_hash_update(&packet->id, sizeof(packet->id), hash);
}


/*
 *	See if two packets are identical.
 *
 *	Note that we do NOT compare the authentication vectors.
 *	That's because if the authentication vector is different,
 *	it means that the NAS has given up on the earlier request.
 */
int fr_packet_cmp(const RADIUS_PACKET *a, const RADIUS_PACKET *b)
{
	int rcode;

	if (a->sockfd < b->sockfd) return -1;
	if (a->sockfd > b->sockfd) return +1;

	if (a->id < b->id) return -1;
	if (a->id > b->id) return +1;

	if (a->src_port < b->src_port) return -1;
	if (a->src_port > b->src_port) return +1;

	if (a->dst_port < b->dst_port) return -1;
	if (a->dst_port > b->dst_port) return +1;

	rcode = fr_ipaddr_cmp(&a->dst_ipaddr, &b->dst_ipaddr);
	if (rcode != 0) return rcode;
	return fr_ipaddr_cmp(&a->src_ipaddr, &b->src_ipaddr);
}


static int fr_inaddr_any(fr_ipaddr_t *ipaddr)
{

	if (ipaddr->af == AF_INET) {
		if (ipaddr->ipaddr.ip4addr.s_addr == INADDR_ANY) {
			return 1;
		}

#ifdef HAVE_STRUCT_SOCKADDR_IN6
	} else if (ipaddr->af == AF_INET6) {
		if (IN6_IS_ADDR_UNSPECIFIED(&(ipaddr->ipaddr.ip6addr))) {
			return 1;
		}
#endif

	} else {
		fr_strerror_printf("Unknown address family");
		return -1;
	}

	return 0;
}


/*
 *	Create a fake "request" from a reply, for later lookup.
 */
void fr_request_from_reply(RADIUS_PACKET *request,
			     const RADIUS_PACKET *reply)
{
	request->sockfd = reply->sockfd;
	request->id = reply->id;
	request->src_port = reply->dst_port;
	request->dst_port = reply->src_port;
	request->src_ipaddr = reply->dst_ipaddr;
	request->dst_ipaddr = reply->src_ipaddr;
}


/*
 *	Open a socket on the given IP and port.
 */
int fr_socket(fr_ipaddr_t *ipaddr, int port)
{
	int sockfd;
	struct sockaddr_storage salocal;
	socklen_t	salen;

	if ((port < 0) || (port > 65535)) {
		fr_strerror_printf("Port %d is out of allowed bounds", port);
		return -1;
	}

	sockfd = socket(ipaddr->af, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		fr_strerror_printf("cannot open socket: %s", strerror(errno));
		return sockfd;
	}

#ifdef WITH_UDPFROMTO
	/*
	 *	Initialize udpfromto for all sockets.
	 */
	if (udpfromto_init(sockfd) != 0) {
		close(sockfd);
		fr_strerror_printf("cannot initialize udpfromto: %s", strerror(errno));
		return -1;
	}
#endif


	if (!fr_ipaddr2sockaddr(ipaddr, port, &salocal, &salen)) {
		return sockfd;
	}

#ifdef HAVE_STRUCT_SOCKADDR_IN6
	if (ipaddr->af == AF_INET6) {
		/*
		 *	Listening on '::' does NOT get you IPv4 to
		 *	IPv6 mapping.  You've got to listen on an IPv4
		 *	address, too.  This makes the rest of the server
		 *	design a little simpler.
		 */
#ifdef IPV6_V6ONLY

		if (IN6_IS_ADDR_UNSPECIFIED(&ipaddr->ipaddr.ip6addr)) {
			int on = 1;

			setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY,
				   (char *)&on, sizeof(on));
		}
#endif /* IPV6_V6ONLY */
	}
#endif /* HAVE_STRUCT_SOCKADDR_IN6 */

	if (ipaddr->af == AF_INET) {
		UNUSED int flag;
		
#if defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DONT)
		/*
		 *	Disable PMTU discovery.  On Linux, this
		 *	also makes sure that the "don't fragment"
		 *	flag is zero.
		 */
		flag = IP_PMTUDISC_DONT;
		setsockopt(sockfd, IPPROTO_IP, IP_MTU_DISCOVER,
			   &flag, sizeof(flag));
#endif

#if defined(IP_DONTFRAG)
		/*
		 *	Ensure that the "don't fragment" flag is zero.
		 */
		flag = 0;
		setsockopt(sockfd, IPPROTO_IP, IP_DONTFRAG,
			   &flag, sizeof(flag));
#endif
	}

	if (bind(sockfd, (struct sockaddr *) &salocal, salen) < 0) {
		close(sockfd);
		fr_strerror_printf("cannot bind socket: %s", strerror(errno));
		return -1;
	}

	return sockfd;
}


/*
 *	We need to keep track of the socket & it's IP/port.
 */
typedef struct fr_packet_socket_t {
	int		sockfd;

	int		num_outgoing;

	int		offset;	/* 0..31 */
	int		inaddr_any;
	fr_ipaddr_t	ipaddr;
	int		port;
} fr_packet_socket_t;


#define FNV_MAGIC_PRIME (0x01000193)
#define MAX_SOCKETS (32)
#define SOCKOFFSET_MASK (MAX_SOCKETS - 1)
#define SOCK2OFFSET(sockfd) ((sockfd * FNV_MAGIC_PRIME) & SOCKOFFSET_MASK)

#define MAX_QUEUES (8)

/*
 *	Structure defining a list of packets (incoming or outgoing)
 *	that should be managed.
 */
struct fr_packet_list_t {
	fr_hash_table_t *ht;

	fr_hash_table_t *dst2id_ht;

	int		alloc_id;
	int		num_outgoing;

	uint32_t mask;
	int last_recv;
	fr_packet_socket_t sockets[MAX_SOCKETS];
};


/*
 *	Ugh.  Doing this on every sent/received packet is not nice.
 */
static fr_packet_socket_t *fr_socket_find(fr_packet_list_t *pl,
					     int sockfd)
{
	int i, start;

	i = start = SOCK2OFFSET(sockfd);

	do {			/* make this hack slightly more efficient */
		if (pl->sockets[i].sockfd == sockfd) return &pl->sockets[i];

		i = (i + 1) & SOCKOFFSET_MASK;
	} while (i != start);

	return NULL;
}

int fr_packet_list_socket_remove(fr_packet_list_t *pl, int sockfd)
{
	fr_packet_socket_t *ps;

	if (!pl) return 0;

	ps = fr_socket_find(pl, sockfd);
	if (!ps) return 0;

	/*
	 *	FIXME: Allow the caller forcibly discard these?
	 */
	if (ps->num_outgoing != 0) return 0;

	ps->sockfd = -1;
	pl->mask &= ~(1 << ps->offset);


	return 1;
}

int fr_packet_list_socket_add(fr_packet_list_t *pl, int sockfd)
{
	int i, start;
	struct sockaddr_storage	src;
	socklen_t	        sizeof_src = sizeof(src);
	fr_packet_socket_t	*ps;

	if (!pl) return 0;

	ps = NULL;
	i = start = SOCK2OFFSET(sockfd);

	do {
		if (pl->sockets[i].sockfd == -1) {
			ps =  &pl->sockets[i];
			start = i;
			break;
		}

		i = (i + 1) & SOCKOFFSET_MASK;
	} while (i != start);

	if (!ps) {
		return 0;
	}

	memset(ps, 0, sizeof(*ps));
	ps->sockfd = sockfd;
	ps->offset = start;

	/*
	 *	Get address family, etc. first, so we know if we
	 *	need to do udpfromto.
	 *
	 *	FIXME: udpfromto also does this, but it's not
	 *	a critical problem.
	 */
	memset(&src, 0, sizeof_src);
	if (getsockname(sockfd, (struct sockaddr *) &src,
			&sizeof_src) < 0) {
		return 0;
	}

	if (!fr_sockaddr2ipaddr(&src, sizeof_src, &ps->ipaddr, &ps->port)) {
		return 0;
	}

	/*
	 *	Grab IP addresses & ports from the sockaddr.
	 */
	if (src.ss_family == AF_INET) {
		if (ps->ipaddr.ipaddr.ip4addr.s_addr == INADDR_ANY) {
			ps->inaddr_any = 1;
		}

#ifdef HAVE_STRUCT_SOCKADDR_IN6
	} else if (src.ss_family == AF_INET6) {
		if (IN6_IS_ADDR_UNSPECIFIED(&ps->ipaddr.ipaddr.ip6addr)) {
			ps->inaddr_any = 1;
		}
#endif
	} else {
		return 0;
	}

	pl->mask |= (1 << ps->offset);
	return 1;
}

static uint32_t packet_entry_hash(const void *data)
{
	return fr_request_packet_hash(*(const RADIUS_PACKET * const *) data);
}

static int packet_entry_cmp(const void *one, const void *two)
{
	const RADIUS_PACKET * const *a = one;
	const RADIUS_PACKET * const *b = two;

	if (!a || !*a || !b || !*b) return -1; /* work-around for bug #35 */

	return fr_packet_cmp(*a, *b);
}

/*
 *	A particular socket can have 256 RADIUS ID's outstanding to
 *	any one destination IP/port.  So we have a structure that
 *	manages destination IP & port, and has an array of 256 ID's.
 *
 *	The only magic here is that we map the socket number (0..256)
 *	into an "internal" socket number 0..31, that we use to set
 *	bits in the ID array.  If a bit is 1, then that ID is in use
 *	for that socket, and the request MUST be in the packet hash!
 *
 *	Note that as a minor memory leak, we don't have an API to free
 *	this structure, except when we discard the whole packet list.
 *	This means that if destinations are added and removed, they
 *	won't be removed from this tree.
 */
typedef struct fr_packet_dst2id_t {
	fr_ipaddr_t	dst_ipaddr;
	int		dst_port;
	uint32_t	id[1];	/* really id[256] */
} fr_packet_dst2id_t;


static uint32_t packet_dst2id_hash(const void *data)
{
	uint32_t hash;
	const fr_packet_dst2id_t *pd = data;

	hash = fr_hash(&pd->dst_port, sizeof(pd->dst_port));

	switch (pd->dst_ipaddr.af) {
	case AF_INET:
		hash = fr_hash_update(&pd->dst_ipaddr.ipaddr.ip4addr,
					sizeof(pd->dst_ipaddr.ipaddr.ip4addr),
					hash);
		break;
	case AF_INET6:
		hash = fr_hash_update(&pd->dst_ipaddr.ipaddr.ip6addr,
					sizeof(pd->dst_ipaddr.ipaddr.ip6addr),
					hash);
		break;
	default:
		break;
	}

	return hash;
}

static int packet_dst2id_cmp(const void *one, const void *two)
{
	const fr_packet_dst2id_t *a = one;
	const fr_packet_dst2id_t *b = two;

	if (a->dst_port < b->dst_port) return -1;
	if (a->dst_port > b->dst_port) return +1;

	return fr_ipaddr_cmp(&a->dst_ipaddr, &b->dst_ipaddr);
}

static void packet_dst2id_free(void *data)
{
	free(data);
}


void fr_packet_list_free(fr_packet_list_t *pl)
{
	if (!pl) return;

	fr_hash_table_free(pl->ht);
	fr_hash_table_free(pl->dst2id_ht);
	free(pl);
}


/*
 *	Caller is responsible for managing the packet entries.
 */
fr_packet_list_t *fr_packet_list_create(int alloc_id)
{
	int i;
	fr_packet_list_t	*pl;

	pl = malloc(sizeof(*pl));
	if (!pl) return NULL;
	memset(pl, 0, sizeof(*pl));

	pl->ht = fr_hash_table_create(packet_entry_hash,
					packet_entry_cmp,
					NULL);
	if (!pl->ht) {
		fr_packet_list_free(pl);
		return NULL;
	}

	for (i = 0; i < MAX_SOCKETS; i++) {
		pl->sockets[i].sockfd = -1;
	}

	if (alloc_id) {
		pl->alloc_id = 1;

		pl->dst2id_ht = fr_hash_table_create(packet_dst2id_hash,
						       packet_dst2id_cmp,
						       packet_dst2id_free);
		if (!pl->dst2id_ht) {
			fr_packet_list_free(pl);
			return NULL;
		}
	}

	return pl;
}


/*
 *	If pl->alloc_id is set, then fr_packet_list_id_alloc() MUST
 *	be called before inserting the packet into the list!
 */
int fr_packet_list_insert(fr_packet_list_t *pl,
			    RADIUS_PACKET **request_p)
{
	if (!pl || !request_p || !*request_p) return 0;

	(*request_p)->hash = fr_request_packet_hash(*request_p);

	return fr_hash_table_insert(pl->ht, request_p);
}

RADIUS_PACKET **fr_packet_list_find(fr_packet_list_t *pl,
				      RADIUS_PACKET *request)
{
	if (!pl || !request) return 0;

	return fr_hash_table_finddata(pl->ht, &request);
}


/*
 *	This presumes that the reply has dst_ipaddr && dst_port set up
 *	correctly (i.e. real IP, or "*").
 */
RADIUS_PACKET **fr_packet_list_find_byreply(fr_packet_list_t *pl,
					      RADIUS_PACKET *reply)
{
	RADIUS_PACKET my_request, *request;
	fr_packet_socket_t *ps;

	if (!pl || !reply) return NULL;

	ps = fr_socket_find(pl, reply->sockfd);
	if (!ps) return NULL;

	/*
	 *	Initialize request from reply, AND from the source
	 *	IP & port of this socket.  The client may have bound
	 *	the socket to 0, in which case it's some random port,
	 *	that is NOT in the original request->src_port.
	 */
	my_request.sockfd = reply->sockfd;
	my_request.id = reply->id;

	if (ps->inaddr_any) {
		my_request.src_ipaddr = ps->ipaddr;
	} else {
		my_request.src_ipaddr = reply->dst_ipaddr;
	}
	my_request.src_port = ps->port;;

	my_request.dst_ipaddr = reply->src_ipaddr;
	my_request.dst_port = reply->src_port;
	my_request.hash = 0;

	request = &my_request;

	return fr_hash_table_finddata(pl->ht, &request);
}


RADIUS_PACKET **fr_packet_list_yank(fr_packet_list_t *pl,
				      RADIUS_PACKET *request)
{
	if (!pl || !request) return NULL;

	return fr_hash_table_yank(pl->ht, &request);
}

int fr_packet_list_num_elements(fr_packet_list_t *pl)
{
	if (!pl) return 0;

	return fr_hash_table_num_elements(pl->ht);
}


/*
 *	1 == ID was allocated & assigned
 *	0 == error allocating memory
 *	-1 == all ID's are used, caller should open a new socket.
 *
 *	Note that this ALSO assigns a socket to use, and updates
 *	packet->request->src_ipaddr && packet->request->src_port
 *
 *	In multi-threaded systems, the calls to id_alloc && id_free
 *	should be protected by a mutex.  This does NOT have to be
 *	the same mutex as the one protecting the insert/find/yank
 *	calls!
 */
int fr_packet_list_id_alloc(fr_packet_list_t *pl,
			      RADIUS_PACKET *request)
{
	int i, id, start;
	int src_any = 0;
	uint32_t free_mask;
	fr_packet_dst2id_t my_pd, *pd;
	fr_packet_socket_t *ps;

	if (!pl || !pl->alloc_id || !request) {
		fr_strerror_printf("Invalid arguments");
		return 0;
	}

	/*
	 *	Error out if no destination is specified.
	 */
	if ((request->dst_ipaddr.af == AF_UNSPEC) ||
	    (request->dst_port == 0)) {
		fr_strerror_printf("No destination address/port specified");
		return 0;
	}

	/*
	 *	Special case: unspec == "don't care"
	 */
	if (request->src_ipaddr.af == AF_UNSPEC) {
		memset(&request->src_ipaddr, 0, sizeof(request->src_ipaddr));
		request->src_ipaddr.af = request->dst_ipaddr.af;
	}

	src_any = fr_inaddr_any(&request->src_ipaddr);
	if (src_any < 0) {
		fr_strerror_printf("Error checking src IP address");
		return 0;
	}

	/*
	 *	MUST specify a destination address.
	 */
	if (fr_inaddr_any(&request->dst_ipaddr) != 0) {
		fr_strerror_printf("Error checking dst IP address");
		return 0;
	}

	my_pd.dst_ipaddr = request->dst_ipaddr;
	my_pd.dst_port = request->dst_port;

	pd = fr_hash_table_finddata(pl->dst2id_ht, &my_pd);
	if (!pd) {
		pd = malloc(sizeof(*pd) + 255 * sizeof(pd->id[0]));
		if (!pd) return 0;

		memset(pd, 0, sizeof(*pd) + 255 * sizeof(pd->id[0]));

		pd->dst_ipaddr = request->dst_ipaddr;
		pd->dst_port = request->dst_port;

		if (!fr_hash_table_insert(pl->dst2id_ht, pd)) {
			free(pd);
			fr_strerror_printf("Failed inserting into hash");
			return 0;
		}
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
	 */
	id = start = (int) fr_rand() & 0xff;

	while (pd->id[id] == pl->mask) { /* all sockets are using this ID */
		id++;
		id &= 0xff;
		if (id == start) {
			fr_strerror_printf("All IDs are being used");
			return 0;
		}
	}

	free_mask = ~((~pd->id[id]) & pl->mask);

	start = -1;
	for (i = 0; i < MAX_SOCKETS; i++) {
		if (pl->sockets[i].sockfd == -1) continue; /* paranoia */

		ps = &(pl->sockets[i]);

		/*
		 *	Address families don't match, skip it.
		 */
		if (ps->ipaddr.af != request->dst_ipaddr.af) continue;

		/*
		 *	We're sourcing from *, and they asked for a
		 *	specific source address: ignore it.
		 */
		if (ps->inaddr_any && !src_any) continue;

		/*
		 *	We're sourcing from a specific IP, and they
		 *	asked for a source IP that isn't us: ignore
		 *	it.
		 */
		if (!ps->inaddr_any && !src_any &&
		    (fr_ipaddr_cmp(&request->src_ipaddr,
				   &ps->ipaddr) != 0)) continue;

		if ((free_mask & (1 << i)) == 0) {
			start = i;
			break;
		}
	}

	if (start < 0) {
		fr_strerror_printf("Internal sanity check failed");
		return 0; /* bad error */
	}

	pd->id[id] |= (1 << start);
	ps = &pl->sockets[start];

	ps->num_outgoing++;
	pl->num_outgoing++;

	/*
	 *	Set the ID, source IP, and source port.
	 */
	request->id = id;

	request->sockfd = ps->sockfd;
	request->src_ipaddr = ps->ipaddr;
	request->src_port = ps->port;

	return 1;
}

/*
 *	Should be called AFTER yanking it from the list, so that
 *	any newly inserted entries don't collide with this one.
 */
int fr_packet_list_id_free(fr_packet_list_t *pl,
			     RADIUS_PACKET *request)
{
	fr_packet_socket_t *ps;
	fr_packet_dst2id_t my_pd, *pd;

	if (!pl || !request) return 0;

	ps = fr_socket_find(pl, request->sockfd);
	if (!ps) return 0;

	my_pd.dst_ipaddr = request->dst_ipaddr;
	my_pd.dst_port = request->dst_port;

	pd = fr_hash_table_finddata(pl->dst2id_ht, &my_pd);
	if (!pd) return 0;

	pd->id[request->id] &= ~(1 << ps->offset);
	request->hash = 0;	/* invalidate the cached hash */

	ps->num_outgoing--;
	pl->num_outgoing--;

	return 1;
}

int fr_packet_list_walk(fr_packet_list_t *pl, void *ctx,
			  fr_hash_table_walk_t callback)
{
	if (!pl || !callback) return 0;

	return fr_hash_table_walk(pl->ht, callback, ctx);
}

int fr_packet_list_fd_set(fr_packet_list_t *pl, fd_set *set)
{
	int i, maxfd;

	if (!pl || !set) return 0;

	maxfd = -1;

	for (i = 0; i < MAX_SOCKETS; i++) {
		if (pl->sockets[i].sockfd == -1) continue;
		FD_SET(pl->sockets[i].sockfd, set);
		if (pl->sockets[i].sockfd > maxfd) {
			maxfd = pl->sockets[i].sockfd;
		}
	}

	if (maxfd < 0) return -1;

	return maxfd + 1;
}

/*
 *	Round-robins the receivers, without priority.
 *
 *	FIXME: Add sockfd, if -1, do round-robin, else do sockfd
 *		IF in fdset.
 */
RADIUS_PACKET *fr_packet_list_recv(fr_packet_list_t *pl, fd_set *set)
{
	int start;
	RADIUS_PACKET *packet;

	if (!pl || !set) return NULL;

	start = pl->last_recv;
	do {
		start++;
		start &= SOCKOFFSET_MASK;

		if (pl->sockets[start].sockfd == -1) continue;

		if (!FD_ISSET(pl->sockets[start].sockfd, set)) continue;

		packet = rad_recv(pl->sockets[start].sockfd, 0);
		if (!packet) continue;

		/*
		 *	Call fr_packet_list_find_byreply().  If it
		 *	doesn't find anything, discard the reply.
		 */

		pl->last_recv = start;
		return packet;
	} while (start != pl->last_recv);

	return NULL;
}

int fr_packet_list_num_incoming(fr_packet_list_t *pl)
{
	int num_elements;

	if (!pl) return 0;

	num_elements = fr_hash_table_num_elements(pl->ht);
	if (num_elements < pl->num_outgoing) return 0; /* panic! */

	return num_elements - pl->num_outgoing;
}

int fr_packet_list_num_outgoing(fr_packet_list_t *pl)
{
	if (!pl) return 0;

	return pl->num_outgoing;
}
