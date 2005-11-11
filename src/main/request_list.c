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

#include <freeradius-devel/autoconf.h>

#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>
#include <freeradius-devel/request_list.h>
#include <freeradius-devel/radius_snmp.h>

struct request_list_t {
	lrad_hash_table_t *ht;
	int collisions;
};

typedef struct request_entry_t {
	struct request_entry_t *next;
	REQUEST		       *request;
} request_entry_t;


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
static rad_listen_t	*proxy_listeners[32];

/*
 *	We can use 256 RADIUS Id's per dst ipaddr/port, per server
 *	socket.  So, to allocate them, we key off of dst ipaddr/port,
 *	and then search the RADIUS Id's, looking for an unused socket.
 *
 *	We do NOT key off of socket fd's, here, either.  Instead,
 *	we look for a free Id from a sockfd, any sockfd.
 */
typedef struct proxy_id_t {
	lrad_ipaddr_t	dst_ipaddr;
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
	int rcode;
	const proxy_id_t *a = one;
	const proxy_id_t *b = two;

	/*
	 *	The following comparisons look weird, but it's
	 *	the only way to make the comparisons work.
	 */
	if (a->dst_port < b->dst_port) return -1;
	if (a->dst_port > b->dst_port) return +1;
	
	if (a->dst_ipaddr.af < b->dst_ipaddr.af) return -1;
	if (a->dst_ipaddr.af > b->dst_ipaddr.af) return +1;

	switch (a->dst_ipaddr.af) {
	case AF_INET:
		rcode = memcmp(&a->dst_ipaddr.ipaddr.ip4addr,
			       &b->dst_ipaddr.ipaddr.ip4addr,
			       sizeof(a->dst_ipaddr.ipaddr.ip4addr));
		break;
	case AF_INET6:
		rcode = memcmp(&a->dst_ipaddr.ipaddr.ip6addr,
			       &b->dst_ipaddr.ipaddr.ip6addr,
			       sizeof(a->dst_ipaddr.ipaddr.ip6addr));
		break;
	default:
		return -1;	/* FIXME: die! */
		break;
	}
	/*
	 *	We could optimize this away, but the compiler should
	 *	do that work for us, and this coding style helps us
	 *	remember what to do if we add more checks later.
	 */
	if (rcode != 0) return rcode;

	/*
	 *	Everything's equal.  Say so.
	 */
	return 0;
}


static void packet_hash(RADIUS_PACKET *packet)
{
	uint32_t hash;

	hash = lrad_hash(&packet->src_port, sizeof(packet->src_port));

	/*
	 *	We shouldn't have to hash af, sockfd, code, or dst_port,
	 *	as they're the same for one request_list_t
	 */
#if 0
	hash = lrad_hash_update(&packet->src_ipaddr.af,
				sizeof(packet->src_ipaddr.af), hash);
	
	hash = lrad_hash_update(&packet->code, sizeof(packet->code), hash);
	hash = lrad_hash_update(&packet->sockfd, sizeof(packet->sockfd), hash);
	hash = lrad_hash_update(&packet->dst_port,
				sizeof(packet->dst_port), hash);
#endif

	/*
	 *	The caller ensures that src & dst AF are the same.
	 *
	 *	We use dst IP in the hash, as the sockfd may be listening
	 *	on "*", with udpfromto, to get multiple dst IP's.
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

	/*
	 *	Put the packet Id into the high byte of the hash,
	 *	to minimize the number of possible collisions.
	 *
	 *	The hash table indexing is done via the low bits,
	 *	so we shouldn't use those.
	 */
	rad_assert((packet->id >= 0) && (packet->id < 256));
	packet->hash = packet->id << 24;
	packet->hash |= hash >> 8;
}


static int packet_cmp(const RADIUS_PACKET *a, const RADIUS_PACKET *b)
{

	if (a->id != b->id) return 0;

	if (a->src_port != b->src_port) return 0;

	switch (a->dst_ipaddr.af) {
	case AF_INET:
		if (memcmp(&a->dst_ipaddr.ipaddr.ip4addr,
			   &b->dst_ipaddr.ipaddr.ip4addr,
			   sizeof(a->dst_ipaddr.ipaddr.ip4addr)) != 0)
			return 0;
		if (memcmp(&a->src_ipaddr.ipaddr.ip4addr,
			   &b->src_ipaddr.ipaddr.ip4addr,
			   sizeof(a->src_ipaddr.ipaddr.ip4addr)) != 0)
			return 0;
		break;
	case AF_INET6:
		if (memcmp(&a->dst_ipaddr.ipaddr.ip6addr,
			   &b->dst_ipaddr.ipaddr.ip6addr,
			   sizeof(a->dst_ipaddr.ipaddr.ip6addr)) != 0)
			return 0;
		if (memcmp(&a->src_ipaddr.ipaddr.ip6addr,
			   &b->src_ipaddr.ipaddr.ip6addr,
			   sizeof(a->src_ipaddr.ipaddr.ip6addr)) != 0)
			return 0;
		break;
	default:
		return 0;
		break;
	}

	/*
	 *	These next comparisons should reall be assertions.
	 */
	if (a->src_ipaddr.af != b->src_ipaddr.af) return 0;

	if (a->dst_ipaddr.af != b->dst_ipaddr.af) return 0;

	if (a->sockfd != b->sockfd) return 0;

	if (a->code != b->code) return 0;

	if (a->dst_port != b->dst_port) return 0;

	/*
	 *	Everything's equal.  Say so.
	 */
	return 1;
}

/*
 *	Compare two REQUEST data structures, based on a number
 *	of criteria, for proxied packets.
 */
static int proxy_cmp(const void *one, const void *two)
{
	int rcode;
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
	if (a->proxy->dst_ipaddr.af < b->proxy->dst_ipaddr.af) return -1;
	if (a->proxy->dst_ipaddr.af > b->proxy->dst_ipaddr.af) return +1;

	if (a->proxy->dst_port < b->proxy->dst_port) return -1;
	if (a->proxy->dst_port > b->proxy->dst_port) return +1;

	switch (a->proxy->dst_ipaddr.af) {
	case AF_INET:
		rcode = memcmp(&a->proxy->dst_ipaddr.ipaddr.ip4addr,
			       &b->proxy->dst_ipaddr.ipaddr.ip4addr,
			       sizeof(a->proxy->dst_ipaddr.ipaddr.ip4addr));
		break;
	case AF_INET6:
		rcode = memcmp(&a->proxy->dst_ipaddr.ipaddr.ip6addr,
			       &b->proxy->dst_ipaddr.ipaddr.ip6addr,
			       sizeof(a->proxy->dst_ipaddr.ipaddr.ip6addr));
		break;
	default:
		return -1;	/* FIXME: die! */
		break;
	}
	if (rcode != 0) return rcode;

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
request_list_t *rl_init(void)
{
	request_list_t *rl = rad_malloc(sizeof(*rl));

	/*
	 *	Initialize the request_list[] array.
	 */
	memset(rl, 0, sizeof(*rl));

	rl->ht = lrad_hash_table_create(10, NULL, 0);
	if (!rl->ht) {
		rad_assert("FAIL" == NULL);
	}
	lrad_hash_table_set_data_size(rl->ht, sizeof(request_entry_t));

	return rl;
}

int rl_init_proxy(void)
{
	/*
	 *	Hacks, so that multiple users can call rl_init,
	 *	and it won't get excited.
	 *
	 *	FIXME: Move proxy stuff to another struct entirely.
	 */
	if (proxy_tree) return 0;

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
				proxy_listeners[listener->fd & 0x1f] = listener;
				break;
			}
		}
	}

	return 1;
}

static int rl_free_entry(void *ctx, void *data)
{
	request_entry_t *next, *entry = data;
	REQUEST *request;

	ctx = ctx;		/* -Wunused */

	for (entry = data; entry != NULL; entry = next) {
		next = entry->next;

#ifdef HAVE_PTHREAD_H 
		/*
		 *	If someone is processing this request, kill
		 *	them, and mark the request as not being used.
		 */
		if (request->child_pid != NO_SUCH_CHILD_PID) {
			pthread_kill(request->child_pid, SIGKILL);
			request->child_pid = NO_SUCH_CHILD_PID;
		}
#endif
		request_free(&request);
		if (entry != data) free(entry);
	}

	return 0;
}


/*
 *	Delete everything in the request list.
 *
 *	This should be called only when debugging the server...
 */
void rl_deinit(request_list_t *rl)
{
	if (!rl) return;

	if (proxy_tree) {
		rbtree_free(proxy_tree);
		proxy_tree = NULL;
		
		rbtree_free(proxy_id_tree);
		proxy_id_tree = NULL;
	}

	/*
	 *	Delete everything in the table, too.
	 */
	lrad_hash_table_walk(rl->ht, rl_free_entry, NULL);

	lrad_hash_table_free(rl->ht);


	/*
	 *	Just to ensure no one is using the memory.
	 */
	memset(rl, 0, sizeof(*rl));
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
		char buf[128];
		
		DEBUG3(" proxy: de-allocating destination %s port %d - Id %d",
		       inet_ntop(entry->dst_ipaddr.af,
				 &entry->dst_ipaddr.ipaddr, buf, sizeof(buf)),
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
		char buf[128];

		/*
		 *	Hmm... not sure what to do here.
		 */
		DEBUG3(" proxy: FAILED TO FIND destination %s port %d - Id %d",
		       inet_ntop(myid.dst_ipaddr.af,
				 &myid.dst_ipaddr.ipaddr, buf, sizeof(buf)),
		       myid.dst_port,
		       request->proxy->id);
	}
}


/*
 *	Yank a request from the tree, without free'ing it.
 */
void rl_yank(request_list_t *rl, REQUEST *request)
{
	request_entry_t *entry;

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
	 *	Delete the request from the list.
	 */
	entry = lrad_hash_table_finddata(rl->ht, request->packet->hash);

	/*
	 *	The entry managed by the hash table is being deleted.
	 */
	if (entry->request == request) {
		if (entry->next) {
			request_entry_t *next = entry->next;
			entry->next = next->next;
			entry->request = next->request;
			free(next);
			
			rad_assert(rl->collisions > 0);
			rl->collisions--;
		} else {
			lrad_hash_table_delete(rl->ht, request->packet->hash);
		}

	} else {		/* a secondary entry is being deleted */
		request_entry_t *this, *next, **last;

		last = &entry->next;
		for (this = entry->next; this != NULL; this = next) {
			next = this->next;
			
			if (this->request != request) {
				last = &this->next;
				continue;
			}

			*last = this->next;
			free(this);

			rad_assert(rl->collisions > 0);
			rl->collisions--;
			break;
		}
	}

	
	/*
	 *	If there's a proxied packet, and we're still
	 *	waiting for a reply, then delete the packet
	 *	from the list of outstanding proxied requests.
	 */
	if (request->proxy &&
	    (request->proxy_outstanding > 0)) {
		rbnode_t *node;
		pthread_mutex_lock(&proxy_mutex);
		node = rbtree_find(proxy_tree, request);
		rl_delete_proxy(request, node);
		pthread_mutex_unlock(&proxy_mutex);
	}
}


/*
 *	Delete a request from the tree.
 */
void rl_delete(request_list_t *rl, REQUEST *request)
{
	rl_yank(rl, request);
	request_free(&request);
}


/*
 *	Add a request to the request list.
 */
int rl_add(request_list_t *rl, REQUEST *request)
{
	request_entry_t *entry, myentry;

	entry = lrad_hash_table_finddata(rl->ht, request->packet->hash);
	if (!entry) {
		myentry.next = NULL;
		myentry.request = request;
		return lrad_hash_table_insert(rl->ht, request->packet->hash,
					      &myentry);
	}

	/*
	 *	Collision: insert it into a linked list (yuck)
	 */
	entry->next = rad_malloc(sizeof(*entry));
	entry->next->next = NULL;
	entry->next->request = request;

	DEBUG3(" FYI: hash collision...");

	rl->collisions++;

	return 1;
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
REQUEST *rl_find(request_list_t *rl, RADIUS_PACKET *packet)
{
	request_entry_t *entry;

	packet_hash(packet);

	entry = lrad_hash_table_finddata(rl->ht, packet->hash);
	if (!entry) return NULL;

	/*
	 *	Call a packet comparison function?
	 */
	while (entry && !packet_cmp(packet, entry->request->packet)) {
		entry = entry->next;
	}

	if (!entry) return NULL;

	return entry->request;
}

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
	char   		buf[128];

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

		DEBUG3(" proxy: creating destination %s port %d",
		       inet_ntop(entry->dst_ipaddr.af,
				 &entry->dst_ipaddr.ipaddr, buf, sizeof(buf)),
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
			pthread_mutex_unlock(&proxy_mutex);
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
		rad_listen_t *proxy_listener;

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
			pthread_mutex_unlock(&proxy_mutex);
			radlog(L_ERR|L_CONS, "ERROR: More than 8000 proxied requests outstanding for destination %s port %d",
			       inet_ntop(entry->dst_ipaddr.af,
					 &entry->dst_ipaddr.ipaddr,
					 buf, sizeof(buf)),
			       entry->dst_port);
			return 0;
		}
		
		/*
		 *	Allocate a new proxy Fd.  This function adds it
		 *	into the list of listeners.
		 */
		proxy_listener = proxy_new_listener();
		if (!proxy_listener) {
			pthread_mutex_unlock(&proxy_mutex);
			DEBUG2("ERROR: Failed to create a new socket for proxying requests.");
			return 0;
		}

		/*
		 *
		 */
		found = -1;
		proxy = proxy_listener->fd;
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
	request->proxy_listener = proxy_listeners[proxy];

	DEBUG3(" proxy: allocating destination %s port %d - Id %d",
	       inet_ntop(entry->dst_ipaddr.af,
			 &entry->dst_ipaddr.ipaddr, buf, sizeof(buf)),
	       entry->dst_port,
	       request->proxy->id);
	
	if (!rbtree_insert(proxy_tree, request)) {
		pthread_mutex_unlock(&proxy_mutex);
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
 *	Return the number of requests in the request list.
 */
int rl_num_requests(request_list_t *rl)
{
	return lrad_hash_table_num_elements(rl->ht) + rl->collisions;
}


/*
 *	See also radiusd.c
 */
#define SLEEP_FOREVER (65536)
typedef struct rl_walk_t {
	time_t	now;
	int	sleep_time;
	request_list_t *rl;
} rl_walk_t;


/*
 *  Refresh a request, by using cleanup_delay, max_request_time, etc.
 *
 *  When walking over the request list, all of the per-request
 *  magic is done here.
 */
static int refresh_request(void *ctx, void *data)
{
	int time_passed;
	rl_walk_t *info = (rl_walk_t *) ctx;
	child_pid_t child_pid;
	request_list_t *rl = info->rl;
	request_entry_t *entry = data;
	request_entry_t *next = entry->next;
	REQUEST *request = entry->request;

	if (next) refresh_request(ctx, next);

	rad_assert(request->magic == REQUEST_MAGIC);

	time_passed = (int) (info->now - request->timestamp);
	
	/*
	 *	If the request is marked as a delayed reject, AND it's
	 *	time to send the reject, then do so now.
	 */
	if (request->finished &&
	    ((request->options & RAD_REQUEST_OPTION_DELAYED_REJECT) != 0)) {
		rad_assert(request->child_pid == NO_SUCH_CHILD_PID);
		if (time_passed < mainconfig.reject_delay) {
			goto reject_delay;
		}

	reject_packet:
		/*
		 *	Clear the 'delayed reject' bit, so that we
		 *	don't do this again, and fall through to
		 *	setting cleanup delay.
		 */
		request->listener->send(request->listener, request);
		request->options &= ~RAD_REQUEST_OPTION_DELAYED_REJECT;

		/*
		 *	FIXME: Beware interaction with cleanup_delay,
		 *	where we might send a reject, and immediately
		 *	there-after clean it up!
		 */
	}

	/*
	 *	If the request is finished, AND more than cleanup_delay
	 *	seconds have passed since it was received, clean it up.
	 *
	 *	OR, if this is a request which had the "don't cache"
	 *	option set, then delete it immediately, as it CANNOT
	 *	have a duplicate.
	 */
	if ((request->finished &&
	     (time_passed >= mainconfig.cleanup_delay)) ||
	    ((request->options & RAD_REQUEST_OPTION_DONT_CACHE) != 0)) {
		rad_assert(request->child_pid == NO_SUCH_CHILD_PID);
	
		/*
		 *  Request completed, delete it, and unlink it
		 *  from the currently 'alive' list of requests.
		 */
	cleanup:
		DEBUG2("Cleaning up request %d ID %d with timestamp %08lx",
				request->number, request->packet->id,
				(unsigned long) request->timestamp);

		/*
		 *  Delete the request.
		 */
		rl_delete(rl, request);
		return 0;
	}

	/*
	 *	If more than max_request_time has passed since
	 *	we received the request, kill it.
	 */
	if (time_passed >= mainconfig.max_request_time) {
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

			radlog(L_ERR, "Rejecting request %d due to lack of any response from home server %s port %d",
			       request->number,
			       client_name_old(&request->packet->src_ipaddr),
			       request->packet->src_port);
			request_reject(request, REQUEST_FAIL_HOME_SERVER);
			request->finished = TRUE;
			return 0;
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
		 *	Send a reject message for the request, mark it
		 *	finished, and forget about the child.
		 */
		request_reject(request, REQUEST_FAIL_SERVER_TIMEOUT);
		
		request->child_pid = NO_SUCH_CHILD_PID;

		if (mainconfig.kill_unresponsive_children)
			request->finished = TRUE;
		return 0;
	} /* else the request is still allowed to be in the queue */

	/*
	 *	If the request is finished, set the cleanup delay.
	 */
	if (request->finished) {
		time_passed = mainconfig.cleanup_delay - time_passed;
		goto setup_timeout;
	}

	/*
	 *	Set reject delay, if appropriate.
	 */
	if ((request->packet->code == PW_AUTHENTICATION_REQUEST) &&
	    (mainconfig.reject_delay > 0)) {
	reject_delay:
		time_passed = mainconfig.reject_delay - time_passed;
		
		/*
		 *	This catches a corner case, apparently.
		 */
		if ((request->reply->code == PW_AUTHENTICATION_REJECT) &&
		    (time_passed == 0)) goto reject_packet;
		if (time_passed == 0) time_passed = 1;
		goto setup_timeout;
	}

	/*
	 *	Accounting requests are always proxied
	 *	asynchronously, authentication requests are
	 *	always proxied synchronously.
	 */
	if ((request->packet->code == PW_ACCOUNTING_REQUEST) &&
	    (request->proxy && !request->proxy_reply) &&
	    (info->now != request->proxy_start_time)) {
		/*
		 *	We've tried to send it, but the home server
		 *	hasn't responded.
		 */
		if (request->proxy_try_count == 0) {
			request_reject(request, REQUEST_FAIL_HOME_SERVER2);
			rad_assert(request->proxy->dst_ipaddr.af == AF_INET);
			request->finished = TRUE;
			goto cleanup; /* delete the request & continue */
		}
		
		/*
		 *	Figure out how long we have to wait before
		 *	sending a re-transmit.
		 */
		time_passed = (info->now - request->proxy_start_time) % mainconfig.proxy_retry_delay;
		if (time_passed == 0) {
			VALUE_PAIR *vp;
			vp = pairfind(request->proxy->vps, PW_ACCT_DELAY_TIME);
			if (!vp) {
				vp = paircreate(PW_ACCT_DELAY_TIME,
						PW_TYPE_INTEGER);
				if (!vp) {
					radlog(L_ERR|L_CONS, "no memory");
					exit(1);
				}
				pairadd(&request->proxy->vps, vp);
				vp->lvalue = info->now - request->proxy_start_time;
			} else {
				vp->lvalue += mainconfig.proxy_retry_delay;
			}
			
			/*
			 *	This function takes care of re-transmits.
			 */
			request->proxy_listener->send(request->proxy_listener, request);
			request->proxy_try_count--;
		}
		time_passed = mainconfig.proxy_retry_delay - time_passed;
		goto setup_timeout;
	}

	/*
	 *	The request is still alive, wake up when it's
	 *	taken too long.
	 */
	time_passed = mainconfig.max_request_time - time_passed;

setup_timeout:		
	if (time_passed < info->sleep_time) {
		info->sleep_time = time_passed;
	}

	return 0;
}


/*
 *  Clean up the request list, every so often.
 *
 *  This is done by walking through ALL of the list, and
 *  - marking any requests which are finished, and expired
 *  - killing any processes which are NOT finished after a delay
 *  - deleting any marked requests.
 *
 *	Returns the number of millisends to sleep, before processing
 *	something.
 */
int rl_clean_list(request_list_t *rl, time_t now)
{
	rl_walk_t info;

	info.now = now;
	info.sleep_time = SLEEP_FOREVER;
	info.rl = rl;

	lrad_hash_table_walk(rl->ht, refresh_request, &info);

	if (info.sleep_time < 0) info.sleep_time = 0;

	return info.sleep_time;
}
