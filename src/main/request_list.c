/*
 * request_list.c	Hide the handling of the REQUEST list from
 *			the main server.
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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2003-2004  The FreeRADIUS server project
 */
static const char rcsid[] = "$Id$";

#include "autoconf.h"
#include "libradius.h"

#include <stdlib.h>
#include <string.h>

#include "radiusd.h"
#include "rad_assert.h"
#include "request_list.h"
#include "radius_snmp.h"


/*
 *	We keep the incoming requests in an array, indexed by ID.
 *
 *	Each array element contains a linked list of containers of
 *	active requests, a count of the number of requests, and a time
 *	at which the first request in the list must be serviced.
 *
 *	Note that we ALSO keep a tree view of the same data, below.
 *	Both views are needed for the server to work optimally.
 */
typedef struct REQNODE {
	struct REQNODE *prev, *next;
	REQUEST *req;
} REQNODE;

typedef struct REQUESTINFO {
	REQNODE *first_request;
	REQNODE *last_request;
	int request_count;
	time_t last_cleaned_list;
} REQUESTINFO;

static REQUESTINFO	request_list[256];

/*
 *	Remember the next request at which we start walking
 *	the list.
 */
static REQUEST *last_request = NULL;

/*
 *	It MAY make more sense here to key off of the packet ID, just
 *	like the request_list.  Then again, saving another 8 lookups
 *	(on average) isn't much of a problem.
 *
 *	The "request_cmp" function keys off of the packet ID first,
 *	so the first 8 layers of the tree will be the fanned-out
 *	tree for packet ID's.
 */
static rbtree_t		*request_tree;

#ifdef HAVE_PTHREAD_H
static pthread_mutex_t	proxy_mutex;
#else
/*
 *	This is easier than ifdef's throughout the code.
 */
#define pthread_mutex_lock(_x)
#define pthread_mutex_unlock(_x)
#endif

/*
 *	We keep track of packets we're proxying, keyed by
 *	source socket, and destination ip/port, and Id.
 */
static rbtree_t		*proxy_tree;

/*
 *	We keep track of free/used Id's, by destination ip/port.
 *
 *	We need a different tree than above, because this one is NOT
 *	keyed by Id.  Instead, we use this one to allocate Id's.
 */
static rbtree_t		*proxy_id_tree;

/*
 *	We keep the proxy FD's here.  The RADIUS Id's are marked
 *	"allocated" per Id, via a bit per proxy FD.
 */
static int		proxy_fds[32];

/*
 *	We can use 256 RADIUS Id's per dst ipaddr/port, per server
 *	socket.  So, to allocate them, we key off of dst ipaddr/port,
 *	and then search the RADIUS Id's, looking for an unused socket.
 *
 *	We do NOT key off of socket fd's, here, either.  Instead,
 *	we look for a free Id from a sockfd, any sockfd.
 */
typedef struct proxy_id_t {
	uint32_t	dst_ipaddr;
	int		dst_port;

	/*
	 *	FIXME: Allocate more proxy sockets when this gets full.
	 */
	int		index;
	uint32_t	mask;	/* of FD's we know about. */
	uint32_t	id[1];	/* really id[256] */
} proxy_id_t;


/*
 *	Find a matching entry in the proxy ID tree.
 */
static int proxy_id_cmp(const void *one, const void *two)
{
	const proxy_id_t *a = one;
	const proxy_id_t *b = two;

	/*
	 *	The following comparisons look weird, but it's
	 *	the only way to make the comparisons work.
	 */
	if (a->dst_ipaddr < b->dst_ipaddr) return -1;
	if (a->dst_ipaddr > b->dst_ipaddr) return +1;

	if (a->dst_port < b->dst_port) return -1;
	if (a->dst_port > b->dst_port) return +1;
	
	/*
	 *	Everything's equal.  Say so.
	 */
	return 0;
}


/*
 *	Compare two REQUEST data structures, based on a number
 *	of criteria.
 */
static int request_cmp(const void *one, const void *two)
{
	const REQUEST *a = one;
	const REQUEST *b = two;

	/*
	 *	The following comparisons look weird, but it's
	 *	the only way to make the comparisons work.
	 */

	/*
	 *	If the packets didn't arrive on the same socket,
	 *	they're not identical, no matter what their src/dst
	 *	ip/ports say.
	 */
	if (a->packet->sockfd < b->packet->sockfd) return -1;
	if (a->packet->sockfd > b->packet->sockfd) return +1;

	if (a->packet->id < b->packet->id) return -1;
	if (a->packet->id > b->packet->id) return +1;

	if (a->packet->code < b->packet->code) return -1;
	if (a->packet->code > b->packet->code) return +1;

	if (a->packet->src_ipaddr < b->packet->src_ipaddr) return -1;
	if (a->packet->src_ipaddr > b->packet->src_ipaddr) return +1;

	if (a->packet->src_port < b->packet->src_port) return -1;
	if (a->packet->src_port > b->packet->src_port) return +1;

	/*
	 *	Hmm... we may be listening on IPADDR_ANY, in which case
	 *	the destination IP is important, too.
	 */
	if (a->packet->dst_ipaddr < b->packet->dst_ipaddr) return -1;
	if (a->packet->dst_ipaddr > b->packet->dst_ipaddr) return +1;

	if (a->packet->dst_port < b->packet->dst_port) return -1;
	if (a->packet->dst_port > b->packet->dst_port) return +1;

	/*
	 *	Everything's equal.  Say so.
	 */
	return 0;
}

/*
 *	Compare two REQUEST data structures, based on a number
 *	of criteria, for proxied packets.
 */
static int proxy_cmp(const void *one, const void *two)
{
	const REQUEST *a = one;
	const REQUEST *b = two;

	rad_assert(a->magic == REQUEST_MAGIC);
	rad_assert(b->magic == REQUEST_MAGIC);

	rad_assert(a->proxy != NULL);
	rad_assert(b->proxy != NULL);

	/*
	 *	The following code looks unreasonable, but it's
	 *	the only way to make the comparisons work.
	 */
	if (a->proxy->sockfd < b->proxy->sockfd) return -1;
	if (a->proxy->sockfd > b->proxy->sockfd) return +1;

	if (a->proxy->id < b->proxy->id) return -1;
	if (a->proxy->id > b->proxy->id) return +1;

	/*
	 *	We've got to check packet codes, too.  But
	 *	this should be done later, by someone else...
	 */

	if (a->proxy->dst_ipaddr < b->proxy->dst_ipaddr) return -1;
	if (a->proxy->dst_ipaddr > b->proxy->dst_ipaddr) return +1;

	if (a->proxy->dst_port < b->proxy->dst_port) return -1;
	if (a->proxy->dst_port > b->proxy->dst_port) return +1;

	/*
	 *	FIXME: Check the Proxy-State attribute, too.
	 *	This will help cut down on duplicates.
	 */

	/*
	 *	Everything's equal.  Say so.
	 */
	return 0;
}


/*
 *	Initialize the request list.
 */
int rl_init(void)
{
	/*
	 *	Initialize the request_list[] array.
	 */
	memset(request_list, 0, sizeof(request_list));

	request_tree = rbtree_create(request_cmp, NULL, 0);
	if (!request_tree) {
		rad_assert("FAIL" == NULL);
	}

	/*
	 *	Create the tree for managing proxied requests and
	 *	responses.
	 */
	proxy_tree = rbtree_create(proxy_cmp, NULL, 1);
	if (!proxy_tree) {
		rad_assert("FAIL" == NULL);
	}

	/*
	 *	Create the tree for allocating proxy ID's.
	 */
	proxy_id_tree = rbtree_create(proxy_id_cmp, NULL, 0);
	if (!proxy_id_tree) {
		rad_assert("FAIL" == NULL);
	}

#ifdef HAVE_PTHREAD_H
	/*
	 *	For now, always create the mutex.
	 *
	 *	Later, we can only create it if there are multiple threads.
	 */
	if (pthread_mutex_init(&proxy_mutex, NULL) != 0) {
		radlog(L_ERR, "FATAL: Failed to initialize proxy mutex: %s",
		       strerror(errno));
		exit(1);
	}
#endif

	/*
	 *	The Id allocation table is done by bits, so we have
	 *	32 bits per Id.  These bits indicate which entry
	 *	in the proxy_fds array is used for that Id.
	 *
	 *	This design allows 256*32 = 8k requests to be
	 *	outstanding to a home server, before something goes
	 *	wrong.
	 */
	{
		int i;
		rad_listen_t *listener;

		/*
		 *	Mark the Fd's as unused.
		 */
		for (i = 0; i < 32; i++) proxy_fds[i] = -1;

		for (listener = mainconfig.listen;
		     listener != NULL;
		     listener = listener->next) {
			if (listener->type == RAD_LISTEN_PROXY) {
				proxy_fds[listener->fd & 0x1f] = listener->fd;
				break;
			}
		}
	}

	return 1;
}


/*
 *	Delete everything in the request list.
 *
 *	This should be called only when debugging the server...
 */
void rl_deinit(void)
{
	int i;

	rbtree_free(proxy_tree);
	proxy_tree = NULL;

	rbtree_free(proxy_id_tree);
	proxy_id_tree = NULL;

	/*
	 *	Loop over the request list, deleting the requests.
	 */
	for (i = 0; i < 256; i++) {
		REQNODE *this, *next;

		for (this = request_list[i].first_request;
		     this != NULL;
		     this = next) {
			next = this->next;

			request_free(&this->req);
			free(this);
		}
	}
	
	/*
	 *	Just to ensure no one is using the memory.
	 */
	memset(request_list, 0, sizeof(request_list));
}


/*
 *	Delete a request from the proxy trees.
 */
static void rl_delete_proxy(REQUEST *request, rbnode_t *node)
{
	proxy_id_t	myid, *entry;

	rad_assert(node != NULL);

	rbtree_delete(proxy_tree, node);
	
	myid.dst_ipaddr = request->proxy->dst_ipaddr;
	myid.dst_port = request->proxy->dst_port;

	/*
	 *	Find the Id in the array of allocated Id's,
	 *	and delete it.
	 */
	entry = rbtree_finddata(proxy_id_tree, &myid);
	if (entry) {
		int i;

		DEBUG3(" proxy: de-allocating %08x:%d %d",
		       entry->dst_ipaddr,
		       entry->dst_port,
		       request->proxy->id);

		/*
		 *	Find the proxy socket associated with this
		 *	Id.  We loop over all 32 proxy fd's, but we
		 *	partially index by proxy fd's, which means
		 *	that we almost always break out of the loop
		 *	quickly.
		 */
		for (i = 0; i < 32; i++) {
			int offset;

			offset = (request->proxy->sockfd + i) & 0x1f;
		  
			if (proxy_fds[offset] == request->proxy->sockfd) {
				
				entry->id[request->proxy->id] &= ~(1 << offset);
				break;
			}
		} /* else die horribly? */
	} else {
		/*
		 *	Hmm... not sure what to do here.
		 */
		DEBUG3(" proxy: FAILED TO FIND %08x:%d %d",
		       myid.dst_ipaddr,
		       myid.dst_port,
		       request->proxy->id);
	}
}


/*
 *	Delete a particular request.
 */
void rl_delete(REQUEST *request)
{
	int id;
	REQNODE *prev, *next;

	prev = ((REQNODE *) request->container)->prev;
	next = ((REQNODE *) request->container)->next;

	id = request->packet->id;

	/*
	 *	Update the last request we touched.
	 *
	 *	This is so the periodic "walk & clean list"
	 *	function, below, doesn't walk over all requests
	 *	all of the time.  Rather, it tries to amortize
	 *	the cost...
	 */
	if (last_request == request) {
		last_request = rl_next(last_request);
	}


	if (prev == NULL) {
		request_list[id].first_request = next;
	} else {
		prev->next = next;
	}

	if (next == NULL) {
		request_list[id].last_request = prev;
	} else {
		next->prev = prev;
	}

	free(request->container);

#ifdef WITH_SNMP
	/*
	 *	Update the SNMP statistics.
	 *
	 *	Note that we do NOT do this in rad_respond(),
	 *	as that function is called from child threads.
	 *	Instead, we update the stats when a request is
	 *	deleted, because only the main server thread calls
	 *	this function...
	 */
	if (mainconfig.do_snmp) {
		switch (request->reply->code) {
		case PW_AUTHENTICATION_ACK:
		  rad_snmp.auth.total_responses++;
		  rad_snmp.auth.total_access_accepts++;
		  break;

		case PW_AUTHENTICATION_REJECT:
		  rad_snmp.auth.total_responses++;
		  rad_snmp.auth.total_access_rejects++;
		  break;

		case PW_ACCESS_CHALLENGE:
		  rad_snmp.auth.total_responses++;
		  rad_snmp.auth.total_access_challenges++;
		  break;

		case PW_ACCOUNTING_RESPONSE:
		  rad_snmp.acct.total_responses++;
		  break;

		default:
			break;
		}
	}
#endif

	/*
	 *	Delete the request from the tree.
	 */
	{
		rbnode_t *node;

		node = rbtree_find(request_tree, request);
		rad_assert(node != NULL);
		rbtree_delete(request_tree, node);


		/*
		 *	If there's a proxied packet, and we're still
		 *	waiting for a reply, then delete the packet
		 *	from the list of outstanding proxied requests.
		 */
		if (request->proxy &&
		    (request->proxy_outstanding > 0)) {
			pthread_mutex_lock(&proxy_mutex);
			node = rbtree_find(proxy_tree, request);
			rl_delete_proxy(request, node);
			pthread_mutex_unlock(&proxy_mutex);
		}
	}

	request_free(&request);
	request_list[id].request_count--;

}

/*
 *	Add a request to the request list.
 */
void rl_add(REQUEST *request)
{
	int id = request->packet->id;
	REQNODE *node;

	rad_assert(request->container == NULL);

	request->container = rad_malloc(sizeof(REQNODE));
	node = (REQNODE *) request->container;
	node->req = request;

	node->prev = NULL;
	node->next = NULL;

	if (!request_list[id].first_request) {
		rad_assert(request_list[id].request_count == 0);

		request_list[id].first_request = node;
		request_list[id].last_request = node;
	} else {
		rad_assert(request_list[id].request_count != 0);

		node->prev = request_list[id].last_request;
		request_list[id].last_request->next = node;
		request_list[id].last_request = node;
	}

	/*
	 *	Insert the request into the tree.
	 */
	if (rbtree_insert(request_tree, request) == 0) {
		rad_assert("FAIL" == NULL);
	}

	request_list[id].request_count++;
}

/*
 *	Look up a particular request, using:
 *
 *	Request ID, request code, source IP, source port,
 *
 *	Note that we do NOT use the request vector to look up requests.
 *
 *	We MUST NOT have two requests with identical (id/code/IP/port), and
 *	different vectors.  This is a serious error!
 */
REQUEST *rl_find(RADIUS_PACKET *packet)
{
	REQUEST myrequest;

	myrequest.packet = packet;

	return rbtree_finddata(request_tree, &myrequest);
}

/*
 *	See mainconfig.c
 */
extern int proxy_new_listener(void);

/*
 *	Add an entry to the proxy tree.
 *
 *	This is the ONLY function in this source file which may be called
 *	from a child thread.  It therefore needs mutexes...
 */
int rl_add_proxy(REQUEST *request)
{
	int		i, found, proxy;
	uint32_t	mask;
	proxy_id_t	myid, *entry;

	myid.dst_ipaddr = request->proxy->dst_ipaddr;
	myid.dst_port = request->proxy->dst_port;

	/*
	 *	Proxied requests get sent out the proxy FD ONLY.
	 *
	 *	FIXME: Once we allocate multiple proxy FD's, move this
	 *	code to below, so we can have more than 256 requests
	 *	outstanding.
	 */
	request->proxy_outstanding = 1;

	pthread_mutex_lock(&proxy_mutex);

	/*
	 *	Assign a proxy ID.
	 */
	entry = rbtree_finddata(proxy_id_tree, &myid);
	if (!entry) {	/* allocate it */
		entry = rad_malloc(sizeof(*entry) + sizeof(entry->id) * 255);
		
		entry->dst_ipaddr = request->proxy->dst_ipaddr;
		entry->dst_port = request->proxy->dst_port;
		entry->index = 0;

		DEBUG3(" proxy: creating %08x:%d",
		       entry->dst_ipaddr,
		       entry->dst_port);
		
		/*
		 *	Insert the new home server entry into
		 *	the tree.
		 *
		 *	FIXME: We don't (currently) delete the
		 *	entries, so this is technically a
		 *	memory leak.
		 */
		if (rbtree_insert(proxy_id_tree, entry) == 0) {
			DEBUG2("ERROR: Failed to insert entry into proxy Id tree");
			free(entry);
			return 0;
		}

		/*
		 *	Clear out bits in the array which DO have
		 *	proxy Fd's associated with them.  We do this
		 *	by getting the mask of bits which have proxy
		 *	fd's...  */
		mask = 0;
		for (i = 0; i < 32; i++) {
			if (proxy_fds[i] != -1) {
				mask |= (1 << i);
			}
		}
		rad_assert(mask != 0);

		/*
		 *	Set bits here indicate that the Fd is in use.
		 */
		entry->mask = mask;

		mask = ~mask;

		/*
		 *	Set the bits which are unused (and therefore
		 *	allocated).  The clear bits indicate that the Id
		 *	for that FD is unused.
		 */
		for (i = 0; i < 256; i++) {
			entry->id[i] = mask;
		}
	} /* else the entry already existed in the proxy Id tree */
	
 retry:
	/*
	 *	Try to find a free Id.
	 */
	found = -1;
	for (i = 0; i < 256; i++) {
		/*
		 *	Some bits are still zero..
		 */
		if (entry->id[(i + entry->index) & 0xff] != (uint32_t) ~0) {
			found = (i + entry->index) & 0xff;
			break;
		}

		/*
		 *	Hmm... do we want to re-use Id's, when we
		 *	haven't seen all of the responses?
		 */
	}
	
	/*
	 *	No free Id, try to get a new FD.
	 */
	if (found < 0) {
		/*
		 *	First, see if there were FD's recently allocated,
		 *	which we don't know about.
		 */
		mask = 0;
		for (i = 0; i < 32; i++) {
			if (proxy_fds[i] < 0) continue;

			mask |= (1 << i);
		}

		/*
		 *	There ARE more FD's than we know about.
		 *	Update the masks for Id's, and re-try.
		 */
		if (entry->mask != mask) {
			/*
			 *	New mask always has more bits than
			 *	the old one, but never fewer bits.
			 */
			rad_assert((entry->mask & mask) == entry->mask);

			/*
			 *	Clear the bits we already know about,
			 *	and then or in those bits into the
			 *	global mask.
			 */
			mask ^= entry->mask;
			entry->mask |= mask;
			mask = ~mask;
			
			/*
			 *	Clear the bits in the Id's for the new
			 *	FD's.
			 */
			for (i = 0; i < 256; i++) {
				entry->id[i] &= mask;
			}
			
			/*
			 *	And try again to allocate an Id.
			 */
			goto retry;
		} /* else no new Fd's were allocated. */

		/*
		 *	If all Fd's are allocated, die.
		 */
		if (~mask == 0) {
			radlog(L_ERR|L_CONS, "ERROR: More than 8000 proxied requests outstanding for home server %08x:%d",
			       ntohs(entry->dst_ipaddr), entry->dst_port);
			return 0;
		}
		
		/*
		 *	Allocate a new proxy Fd.  This function adds it
		 *	into the list of listeners.
		 */
		proxy = proxy_new_listener();
		if (proxy < 0) {
			DEBUG2("ERROR: Failed to create a new socket for proxying requests.");
			return 0;
		}

		/*
		 *
		 */
		found = -1;
		for (i = 0; i < 32; i++) {
			/*
			 *	Found a free entry.  Save the socket,
			 *	and remember where we saved it.
			 */
			if (proxy_fds[(proxy + i) & 0x1f] == -1) {
				proxy_fds[(proxy + i) & 0x1f] = proxy;
				found = (proxy + i) & 0x1f;
				break;
			}
		}
		rad_assert(found >= 0);	/* i.e. the mask had free bits. */

		mask = 1 << found;
		entry->mask |= mask;
		mask = ~mask;

		/*
		 *	Clear the relevant bits in the mask.
		 */
		for (i = 0; i < 256; i++) {
			entry->id[i] &= mask;
		}

		/*
		 *	Pick a random Id to start from, as we've
		 *	just guaranteed that it's free.
		 */
		found = lrad_rand() & 0xff;
	}
	
	/*
	 *	Mark next (hopefully unused) entry.
	 */
	entry->index = (found + 1) & 0xff;
	
	/*
	 *	We now have to find WHICH proxy fd to use.
	 */
	proxy = -1;
	for (i = 0; i < 32; i++) {
		/*
		 *	FIXME: pick a random socket to use?
		 */
		if ((entry->id[found] & (1 << i)) == 0) {
			proxy = i;
			break;
		}
	}

	/*
	 *	There was no bit clear, which we had just checked above...
	 */
	rad_assert(proxy != -1);

	/*
	 *	Mark the Id as allocated, for thei Fd.
	 */
	entry->id[found] |= (1 << proxy);
	request->proxy->id = found;

	rad_assert(proxy_fds[proxy] != -1);
	request->proxy->sockfd = proxy_fds[proxy];

	DEBUG3(" proxy: allocating %08x:%d %d",
	       entry->dst_ipaddr,
	       entry->dst_port,
	       request->proxy->id);
	
	if (!rbtree_insert(proxy_tree, request)) {
		DEBUG2("ERROR: Failed to insert entry into proxy tree");
		return 0;
	}
	
	pthread_mutex_unlock(&proxy_mutex);

	return 1;
}


/*
 *	Look up a particular request, using:
 *
 *	Request Id, request code, source IP, source port,
 *
 *	Note that we do NOT use the request vector to look up requests.
 *
 *	We MUST NOT have two requests with identical (id/code/IP/port), and
 *	different vectors.  This is a serious error!
 */
REQUEST *rl_find_proxy(RADIUS_PACKET *packet)
{
	rbnode_t	*node;
	REQUEST		myrequest, *maybe = NULL;
	RADIUS_PACKET	myproxy;

	/*
	 *	If we use the socket FD as an indicator,
	 *	then that implicitely contains information
	 *	as to our src ipaddr/port, so we don't need
	 *	to use that in the comparisons.
	 */
	myproxy.sockfd = packet->sockfd;
	myproxy.id = packet->id;
	myproxy.dst_ipaddr = packet->src_ipaddr;
	myproxy.dst_port = packet->src_port;

#ifndef NDEBUG
	myrequest.magic = REQUEST_MAGIC;
#endif
	myrequest.proxy = &myproxy;

	pthread_mutex_lock(&proxy_mutex);
        node = rbtree_find(proxy_tree, &myrequest);

	if (node) {
		maybe = rbtree_node2data(proxy_tree, node);
		rad_assert(maybe->proxy_outstanding > 0);
		maybe->proxy_outstanding--;
		
		/*
		 *	Received all of the replies we expect.
		 *	delete it from both trees.
		 */
		if (maybe->proxy_outstanding == 0) {
			rl_delete_proxy(&myrequest, node);
		}
	}
	pthread_mutex_unlock(&proxy_mutex);

	return maybe;
}


/*
 *	Walk over all requests, performing a callback for each request.
 */
int rl_walk(RL_WALK_FUNC walker, void *data)
{
	int id, rcode;
	REQNODE *curreq, *next;

	/*
	 *	Walk over all 256 ID's.
	 */
	for (id = 0; id < 256; id++) {

		/*
		 *	Walk over the request list for each ID.
		 */
		for (curreq = request_list[id].first_request;
				curreq != NULL ;
				curreq = next) {
			/*
			 *	The callback MIGHT delete the current
			 *	request, so we CANNOT depend on curreq->next
			 *	to be there, when going to the next element
			 *	in the 'for' loop.
			 */
			next = curreq->next;

			rcode = walker(curreq->req, data);
			if (rcode != RL_WALK_CONTINUE) {
				return rcode;
			}
		}
	}

	return 0;
}


/*
 *	Walk from one request to the next.
 */
REQUEST *rl_next(REQUEST *request)
{
	int id, start_id;
	int count;

	/*
	 *	If we were passed a request, then go to the "next" one.
	 */
	if (request != NULL) {
		rad_assert(request->magic == REQUEST_MAGIC);

		/*
		 *	It has a "next", return it.
		 */
		if (((REQNODE *)request->container)->next != NULL) {
			return ((REQNODE *)request->container)->next->req;
		} else {
			/*
			 *	No "next", increment the ID, and look
			 *	at that one.
			 */
			start_id = request->packet->id + 1;
			start_id &= 0xff;
			count = 255;
		}
	} else {
		/*
		 *	No input request, start looking at ID 0.
		 */
		start_id = 0;
		count = 256;
	}

	/*
	 *	Check all ID's, wrapping around at 255.
	 */
	for (id = start_id; id < (start_id + count); id++) {

		/*
		 *	This ID has a request, return it.
		 */
		if (request_list[id & 0xff].first_request != NULL) {
			rad_assert(request_list[id&0xff].first_request->req != request);

			return request_list[id & 0xff].first_request->req;
		}
	}

	/*
	 *	No requests at all in the list. Nothing to do.
	 */
	DEBUG3("rl_next:  returning NULL");
	return NULL;
}


/*
 *	Return the number of requests in the request list.
 */
int rl_num_requests(void)
{
	int id;
	int request_count = 0;

	for (id = 0; id < 256; id++) {
		request_count += request_list[id].request_count;
	}

	return request_count;
}


typedef struct rl_walk_t {
	time_t	now;
	time_t	smallest;
} rl_walk_t;


/*
 *  Refresh a request, by using proxy_retry_delay, cleanup_delay,
 *  max_request_time, etc.
 *
 *  When walking over the request list, all of the per-request
 *  magic is done here.
 */
static int refresh_request(REQUEST *request, void *data)
{
	rl_walk_t *info = (rl_walk_t *) data;
	time_t difference;
	child_pid_t child_pid;

	rad_assert(request->magic == REQUEST_MAGIC);

	/*
	 *  If the request is marked as a delayed reject, AND it's
	 *  time to send the reject, then do so now.
	 */
	if (request->finished &&
	    ((request->options & RAD_REQUEST_OPTION_DELAYED_REJECT) != 0)) {
		rad_assert(request->child_pid == NO_SUCH_CHILD_PID);

		difference = info->now - request->timestamp;
		if (difference >= (time_t) mainconfig.reject_delay) {

			/*
			 *  Clear the 'delayed reject' bit, so that we
			 *  don't do this again.
			 */
			request->options &= ~RAD_REQUEST_OPTION_DELAYED_REJECT;
			rad_send(request->reply, request->packet,
				 request->secret);
		}
	}

	/*
	 *  If the request has finished processing, AND it's child has
	 *  been cleaned up, AND it's time to clean up the request,
	 *  OR, it's an accounting request.  THEN, go delete it.
	 *
	 *  If this is a request which had the "don't cache" option
	 *  set, then delete it immediately, as it CANNOT have a
	 *  duplicate.
	 */
	if (request->finished &&
	    ((request->timestamp + mainconfig.cleanup_delay <= info->now) ||
	     ((request->options & RAD_REQUEST_OPTION_DONT_CACHE) != 0))) {
		rad_assert(request->child_pid == NO_SUCH_CHILD_PID);

		/*
		 *  Request completed, delete it, and unlink it
		 *  from the currently 'alive' list of requests.
		 */
		DEBUG2("Cleaning up request %d ID %d with timestamp %08lx",
				request->number, request->packet->id,
				(unsigned long) request->timestamp);

		/*
		 *  Delete the request.
		 */
		rl_delete(request);
		return RL_WALK_CONTINUE;
	}

	/*
	 *  Maybe the child process handling the request has hung:
	 *  kill it, and continue.
	 */
	if ((request->timestamp + mainconfig.max_request_time) <= info->now) {
		int number;

		child_pid = request->child_pid;
		number = request->number;

		/*
		 *	There MUST be a RAD_PACKET reply.
		 */
		rad_assert(request->reply != NULL);

		/*
		 *	If we've tried to proxy the request, and
		 *	the proxy server hasn't responded, then
		 *	we send a REJECT back to the caller.
		 *
		 *	For safety, we assert that there is no child
		 *	handling the request.  If the assertion fails,
		 *	it means that we've sent a proxied request to
		 *	the home server, and the child thread is still
		 *	sitting on the request!
		 */
		if (request->proxy && !request->proxy_reply) {
			rad_assert(request->child_pid == NO_SUCH_CHILD_PID);

			radlog(L_ERR, "Rejecting request %d due to lack of any response from home server %s:%d",
			       request->number,
			       client_name(request->packet->src_ipaddr),
			       request->packet->src_port);
			request_reject(request, REQUEST_FAIL_HOME_SERVER);
			request->finished = TRUE;
			return RL_WALK_CONTINUE;
		}

		if (mainconfig.kill_unresponsive_children) {
			if (child_pid != NO_SUCH_CHILD_PID) {
				/*
				 *  This request seems to have hung
				 *   - kill it
				 */
#ifdef HAVE_PTHREAD_H
				radlog(L_ERR, "Killing unresponsive thread for request %d",
				       request->number);
				pthread_cancel(child_pid);
#endif
			} /* else no proxy reply, quietly fail */

			/*
			 *	Maybe we haven't killed it.  In that
			 *	case, print a warning.
			 */
		} else if ((child_pid != NO_SUCH_CHILD_PID) &&
			   ((request->options & RAD_REQUEST_OPTION_LOGGED_CHILD) == 0)) {
			radlog(L_ERR, "WARNING: Unresponsive child (id %lu) for request %d",
			       (unsigned long)child_pid, number);

			/*
			 *  Set the option that we've sent a log message,
			 *  so that we don't send more than one message
			 *  per request.
			 */
			request->options |= RAD_REQUEST_OPTION_LOGGED_CHILD;
		}

		/*
		 *  Send a reject message for the request, mark it
		 *  finished, and forget about the child.
		 */
		request_reject(request,
			       REQUEST_FAIL_SERVER_TIMEOUT);
		
		request->child_pid = NO_SUCH_CHILD_PID;

		if (mainconfig.kill_unresponsive_children)
			request->finished = TRUE;
		return RL_WALK_CONTINUE;
	} /* the request has been in the queue for too long */

	/*
	 *  If the request is still being processed, then due to the
	 *  above check, it's still within it's time limit.  In that
	 *  case, don't do anything.
	 */
	if (request->child_pid != NO_SUCH_CHILD_PID) {
		return RL_WALK_CONTINUE;
	}

	/*
	 *  The request is finished.
	 */
	if (request->finished) goto setup_timeout;

	/*
	 *  We're not proxying requests at all.
	 */
	if (!mainconfig.proxy_requests) goto setup_timeout;

	/*
	 *  We're proxying synchronously, so we don't retry it here.
	 *  Some other code takes care of retrying the proxy requests.
	 */
	if (mainconfig.proxy_synchronous) goto setup_timeout;

	/*
	 *  The proxy retry delay is zero, meaning don't retry.
	 */
	if (mainconfig.proxy_retry_delay == 0) goto setup_timeout;

	/*
	 *  There is no proxied request for this packet, so there's
	 *  no proxy retries.
	 */
	if (!request->proxy) goto setup_timeout;

	/*
	 *  We've already seen the proxy reply, so we don't need
	 *  to send another proxy request.
	 */
	if (request->proxy_reply) goto setup_timeout;

	/*
	 *  It's not yet time to re-send this proxied request.
	 */
	if (request->proxy_next_try > info->now) goto setup_timeout;

	/*
	 *  If the proxy retry count is zero, then
	 *  we've sent the last try, and have NOT received
	 *  a reply from the end server.  In that case,
	 *  we don't bother trying again, but just mark
	 *  the request as finished, and go to the next one.
	 */
	if (request->proxy_try_count == 0) {
		rad_assert(request->child_pid == NO_SUCH_CHILD_PID);
		request_reject(request, REQUEST_FAIL_HOME_SERVER2);
		realm_disable(request->proxy->dst_ipaddr,request->proxy->dst_port);
		request->finished = TRUE;
		goto setup_timeout;
	}

	/*
	 *  We're trying one more time, so count down
	 *  the tries, and set the next try time.
	 */
	request->proxy_try_count--;
	request->proxy_next_try = info->now + mainconfig.proxy_retry_delay;

	/* Fix up Acct-Delay-Time */
	if (request->proxy->code == PW_ACCOUNTING_REQUEST) {
		VALUE_PAIR *delaypair;
		delaypair = pairfind(request->proxy->vps, PW_ACCT_DELAY_TIME);

		if (!delaypair) {
			delaypair = paircreate(PW_ACCT_DELAY_TIME, PW_TYPE_INTEGER);
			if (!delaypair) {
				radlog(L_ERR|L_CONS, "no memory");
				exit(1);
			}
			pairadd(&request->proxy->vps, delaypair);
		}
		delaypair->lvalue = info->now - request->proxy->timestamp;

		/* Must recompile the valuepairs to wire format */
		free(request->proxy->data);
		request->proxy->data = NULL;
	} /* proxy accounting request */

	/*
	 *  Assert that we have NOT seen the proxy reply yet.
	 *
	 *  If we HAVE seen it, then we SHOULD NOT be bugging the
	 *  home server!
	 */
	rad_assert(request->proxy_reply == NULL);

	/*
	 *  Send the proxy packet.
	 */
	request->proxy_outstanding++;
	rad_send(request->proxy, NULL, request->proxysecret);

setup_timeout:
	/*
	 *  Don't do more long-term checks, if we've got to wake
	 *  up now.
	 */
	if (info->smallest == 0) {
		return RL_WALK_CONTINUE;
	}

	/*
	 *  The request is finished.  Wake up when it's time to
	 *  clean it up.
	 */
	if (request->finished) {
		difference = (request->timestamp + mainconfig.cleanup_delay) - info->now;

		/*
		 *  If the request is marked up to be rejected later,
		 *  then wake up later.
		 */
		if ((request->options & RAD_REQUEST_OPTION_DELAYED_REJECT) != 0) {
			if (difference >= (time_t) mainconfig.reject_delay) {
				difference = (time_t) mainconfig.reject_delay;
			}
		}

	} else if (request->proxy && !request->proxy_reply) {
		/*
		 *  The request is NOT finished, but there is an
		 *  outstanding proxy request, with no matching
		 *  proxy reply.
		 *
		 *  Wake up when it's time to re-send
		 *  the proxy request.
		 *
		 *  But in synchronous proxy, we don't retry but we update
		 *  the next retry time as NAS has not resent the request
		 *  in the given retry window.
		 */
		if (mainconfig.proxy_synchronous) {
			/*
			 *	If the retry_delay * count has passed,
			 *	then mark the realm dead.
			 */
			if (info->now > (request->timestamp + (mainconfig.proxy_retry_delay * mainconfig.proxy_retry_count))) {
				rad_assert(request->child_pid == NO_SUCH_CHILD_PID);
				request_reject(request, REQUEST_FAIL_HOME_SERVER3);
				
				realm_disable(request->proxy->dst_ipaddr,
					      request->proxy->dst_port);
				request->finished = TRUE;
				goto setup_timeout;
			}
			request->proxy_next_try = info->now + mainconfig.proxy_retry_delay;
		}
		difference = request->proxy_next_try - info->now;
	} else {
		/*
		 *  The request is NOT finished.
		 *
		 *  Wake up when it's time to kill the errant
		 *  thread/process.
		 */
		difference = (request->timestamp + mainconfig.max_request_time) - info->now;
	}

	/*
	 *  If the server is CPU starved, then we CAN miss a time
	 *  for servicing requests.  In which case the 'difference'
	 *  value will be negative.  select() doesn't like that,
	 *  so we fix it.
	 */
	if (difference < 0) {
		difference = 0;
	}

	/*
	 *  Update the 'smallest' time.
	 */
	if ((info->smallest < 0) ||
		(difference < info->smallest)) {
		info->smallest = difference;
	}

	return RL_WALK_CONTINUE;
}


/*
 *  Clean up the request list, every so often.
 *
 *  This is done by walking through ALL of the list, and
 *  - marking any requests which are finished, and expired
 *  - killing any processes which are NOT finished after a delay
 *  - deleting any marked requests.
 */
struct timeval *rl_clean_list(time_t now)
{
	/*
	 *  Static variables, so that we don't do all of this work
	 *  more than once per second.
	 *
	 *  Note that we have 'tv' and 'last_tv'.  'last_tv' is
	 *  pointed to by 'last_tv_ptr', and depending on the
	 *  system implementation of select(), it MAY be modified.
	 *
	 *  In that was, we want to use the ORIGINAL value, from
	 *  'tv', and wipe out the (possibly modified) last_tv.
	 */
	static time_t last_cleaned_list = 0;
	static struct timeval tv, *last_tv_ptr = NULL;
	static struct timeval last_tv;

	rl_walk_t info;

	info.now = now;
	info.smallest = -1;

	/*
	 *  If we've already set up the timeout or cleaned the
	 *  request list this second, then don't do it again.  We
	 *  simply return the sleep delay from last time.
	 *
	 *  Note that if we returned NULL last time, there was nothing
	 *  to do.  BUT we've been woken up since then, which can only
	 *  happen if we received a packet.  And if we've received a
	 *  packet, then there's some work to do in the future.
	 *
	 *  FIXME: We can probably use gettimeofday() for finer clock
	 *  resolution, as the current method will cause it to sleep
	 *  too long...
	 */
	if ((last_tv_ptr != NULL) &&
	    (last_cleaned_list == now) &&
	    (tv.tv_sec != 0)) {
		int i;

		/*
		 *  If we're NOT walking the entire request list,
		 *  then we want to iteratively check the request
		 *  list.
		 *
		 *  If there is NO previous request, go look for one.
		 */
		if (!last_request)
			last_request = rl_next(last_request);

		/*
		 *  On average, there will be one request per
		 *  'cleanup_delay' requests, which needs to be
		 *  serviced.
		 *
		 *  And only do this servicing, if we have a request
		 *  to service.
		 */
		if (last_request)
			for (i = 0; i < mainconfig.cleanup_delay; i++) {
				REQUEST *next;

				/*
				 *  This function call MAY delete the
				 *  request pointed to by 'last_request'.
				 */
				next = rl_next(last_request);
				refresh_request(last_request, &info);
				last_request = next;

				/*
				 *  Nothing to do any more, exit.
				 */
				if (!last_request)
					break;
			}

		last_tv = tv;
		DEBUG2("Waking up in %d seconds...",
				(int) last_tv_ptr->tv_sec);
		return last_tv_ptr;
	}
	last_cleaned_list = now;
	last_request = NULL;
	DEBUG2("--- Walking the entire request list ---");

	/*
	 *  Hmmm... this is Big Magic.  We make it seem like
	 *  there's an additional second to wait, for a whole
	 *  host of reasons which I can't explain adequately,
	 *  but which cause the code to Just Work Right.
	 */
	info.now--;

	rl_walk(refresh_request, &info);

	/*
	 *  We haven't found a time at which we need to wake up.
	 *  Return NULL, so that the select() call will sleep forever.
	 */
	if (info.smallest < 0) {
		/*
		 *  If we're not proxying, then there really isn't anything
		 *  to do.
		 *
		 *  If we ARE proxying, then we can safely sleep
		 *  forever if we're told to NEVER send proxy retries
		 *  ourselves, until the NAS kicks us again.
		 *
		 *  Otherwise, there are no outstanding requests, then
		 *  we can sleep forever.  This happens when we get
		 *  woken up with a bad packet.  It's discarded, so if
		 *  there are no live requests, we can safely sleep
		 *  forever.
		 */
		if ((!mainconfig.proxy_requests) ||
		    mainconfig.proxy_synchronous ||
		    (rl_num_requests() == 0)) {
			DEBUG2("Nothing to do.  Sleeping until we see a request.");
			last_tv_ptr = NULL;
			return NULL;
		}

		/*
		 *  We ARE proxying.  In that case, we avoid a race condition
		 *  where a child thread handling a request proxies the
		 *  packet, and sets the retry delay.  In that case, we're
		 *  supposed to wake up in N seconds, but we can't, as
		 *  we're sleeping forever.
		 *
		 *  Instead, we prevent the problem by waking up anyhow
		 *  at the 'proxy_retry_delay' time, even if there's
		 *  nothing to do.  In the worst case, this will cause
		 *  the server to wake up every N seconds, to do a small
		 *  amount of unnecessary work.
		 */
		info.smallest = mainconfig.proxy_retry_delay;
	}
	/*
	 *  Set the time (in seconds) for how long we're
	 *  supposed to sleep.
	 */
	tv.tv_sec = info.smallest;
	tv.tv_usec = 0;
	DEBUG2("Waking up in %d seconds...", (int) info.smallest);

	/*
	 *  Remember how long we should sleep for.
	 */
	last_tv = tv;
	last_tv_ptr = &last_tv;
	return last_tv_ptr;
}
