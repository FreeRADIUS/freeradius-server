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

static const char rcsid[] = "$Id$";

#include	<freeradius-devel/autoconf.h>
#include	<freeradius-devel/libradius.h>

#include <unistd.h>

/*
 *	Take the key fields of a request packet, and convert it to a
 *	hash.
 */
uint32_t lrad_request_packet_hash(const RADIUS_PACKET *packet)
{
	uint32_t hash;
	
	hash = lrad_hash(&packet->src_port, sizeof(packet->src_port));
	hash = lrad_hash_update(&packet->dst_port,
				sizeof(packet->dst_port), hash);

	/*
	 *	The caller ensures that src & dst AF are the same.
	 */
	switch (packet->src_ipaddr.af) {
	case AF_INET:
		hash = lrad_hash_update(&packet->src_ipaddr.ipaddr.ip4addr,
					sizeof(packet->src_ipaddr.ipaddr.ip4addr),
					hash);
		hash = lrad_hash_update(&packet->dst_ipaddr.ipaddr.ip4addr,
					sizeof(packet->dst_ipaddr.ipaddr.ip4addr),
					hash);
		break;
	case AF_INET6:
		hash = lrad_hash_update(&packet->src_ipaddr.ipaddr.ip6addr,
					sizeof(packet->src_ipaddr.ipaddr.ip6addr),
					hash);
		hash = lrad_hash_update(&packet->dst_ipaddr.ipaddr.ip6addr,
					sizeof(packet->dst_ipaddr.ipaddr.ip6addr),
					hash);
		break;
	default:
		/* FIXME: die! */
		break;
	}

	return lrad_hash_update(&packet->id, sizeof(packet->id), hash);
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
uint32_t lrad_reply_packet_hash(const RADIUS_PACKET *packet)
{
	uint32_t hash;
	
	hash = lrad_hash(&packet->src_port, sizeof(packet->src_port));
	hash = lrad_hash_update(&packet->dst_port,
				sizeof(packet->dst_port), hash);

	/*
	 *	The caller ensures that src & dst AF are the same.
	 */
	switch (packet->src_ipaddr.af) {
	case AF_INET:
		hash = lrad_hash_update(&packet->dst_ipaddr.ipaddr.ip4addr,
					sizeof(packet->dst_ipaddr.ipaddr.ip4addr),
					hash);
		hash = lrad_hash_update(&packet->src_ipaddr.ipaddr.ip4addr,
					sizeof(packet->src_ipaddr.ipaddr.ip4addr),
					hash);
		break;
	case AF_INET6:
		hash = lrad_hash_update(&packet->dst_ipaddr.ipaddr.ip6addr,
					sizeof(packet->dst_ipaddr.ipaddr.ip6addr),
					hash);
		hash = lrad_hash_update(&packet->src_ipaddr.ipaddr.ip6addr,
					sizeof(packet->src_ipaddr.ipaddr.ip6addr),
					hash);
		break;
	default:
		/* FIXME: die! */
		break;
	}

	return lrad_hash_update(&packet->id, sizeof(packet->id), hash);
}


/*
 *	See if two packets are identical.
 *
 *	Note that we do NOT compare the authentication vectors.
 *	That's because if the authentication vector is different,
 *	it means that the NAS has given up on the earlier request.
 */
int lrad_packet_cmp(const RADIUS_PACKET *a, const RADIUS_PACKET *b)
{
	int rcode;

	if (a->sockfd < b->sockfd) return -1;
	if (a->sockfd > b->sockfd) return +1;

	if (a->src_ipaddr.af < b->dst_ipaddr.af) return -1;
	if (a->src_ipaddr.af > b->dst_ipaddr.af) return +1;

	if (a->id < b->id) return -1;
	if (a->id > b->id) return +1;

	if (a->src_port < b->src_port) return -1;
	if (a->src_port > b->src_port) return +1;

	if (a->dst_port < b->dst_port) return -1;
	if (a->dst_port > b->dst_port) return +1;

	switch (a->dst_ipaddr.af) {
	case AF_INET:
		rcode = memcmp(&a->dst_ipaddr.ipaddr.ip4addr,
			       &b->dst_ipaddr.ipaddr.ip4addr,
			       sizeof(a->dst_ipaddr.ipaddr.ip4addr));
		if (rcode != 0) return rcode;
		rcode = memcmp(&a->src_ipaddr.ipaddr.ip4addr,
			       &b->src_ipaddr.ipaddr.ip4addr,
			       sizeof(a->src_ipaddr.ipaddr.ip4addr));
		if (rcode != 0) return rcode;
		break;
	case AF_INET6:
		rcode = memcmp(&a->dst_ipaddr.ipaddr.ip6addr,
			       &b->dst_ipaddr.ipaddr.ip6addr,
			       sizeof(a->dst_ipaddr.ipaddr.ip6addr));
		if (rcode != 0) return rcode;
		rcode = memcmp(&a->src_ipaddr.ipaddr.ip6addr,
			       &b->src_ipaddr.ipaddr.ip6addr,
			       sizeof(a->src_ipaddr.ipaddr.ip6addr));
		if (rcode != 0) return rcode;
		break;
	default:
		return -1;
		break;
	}

	/*
	 *	Everything's equal.  Say so.
	 */
	return 0;
}


/*
 *	Create a fake "request" from a reply, for later lookup.
 */
void lrad_request_from_reply(RADIUS_PACKET *request,
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
int lrad_socket(lrad_ipaddr_t *ipaddr, int port)
{
	int sockfd;
	struct sockaddr salocal;
	socklen_t	salen;

	if ((port < 0) || (port > 65535)) {
		librad_log("Port %d is out of allowed bounds", port);
		return -1;
	}

	sockfd = socket(ipaddr->af, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		librad_log("Failed opening socket: %s", strerror(errno));
		return sockfd;
	}

#ifdef WITH_UDPFROMTO
	/*
	 *	Initialize udpfromto for all sockets.
	 */
	if (udpfromto_init(sockfd) != 0) {
		close(sockfd);
		return -1;
	}
#endif
	
	if (ipaddr->af == AF_INET) {
		struct sockaddr_in *sa;
		
		sa = (struct sockaddr_in *) &salocal;
		memset(sa, 0, sizeof(salocal));
		sa->sin_family = AF_INET;
		sa->sin_addr = ipaddr->ipaddr.ip4addr;
		sa->sin_port = htons((uint16_t) port);
		salen = sizeof(*sa);
		
#ifdef HAVE_STRUCT_SOCKADDR_IN6
	} else if (ipaddr->af == AF_INET6) {
		struct sockaddr_in6 *sa;
		
		sa = (struct sockaddr_in6 *) &salocal;
		memset(sa, 0, sizeof(salocal));
		sa->sin6_family = AF_INET6;
		sa->sin6_addr = ipaddr->ipaddr.ip6addr;
		sa->sin6_port = htons((uint16_t) port);
		salen = sizeof(*sa);
		
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
#endif /* HAVE_STRUCT_SOCKADDR_IN6 */
	} else {
		return sockfd;	/* don't bind it */
	}

	if (bind(sockfd, &salocal, salen) < 0) {
		librad_log("Bind to address failed: %s", strerror(errno));
		close(sockfd);
		return -1;
	}

	return sockfd;
}
