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
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
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
};

#ifdef HAVE_PTHREAD_H
static pthread_mutex_t	proxy_mutex;
#else
/*
 *	This is easier than ifdef's throughout the code.
 */
#define pthread_mutex_lock(_x)
#define pthread_mutex_unlock(_x)
#endif

static lrad_packet_list_t *proxy_list = NULL;

/*
 *	We keep the proxy FD's here.  The RADIUS Id's are marked
 *	"allocated" per Id, via a bit per proxy FD.
 */
static int		proxy_fds[32];
static rad_listen_t	*proxy_listeners[32];

static uint32_t request_hash(const void *data)
{
	return lrad_request_packet_hash(((const REQUEST *) data)->packet);
}

static int request_cmp(const void *a, const void *b)
{
	return lrad_packet_cmp(((const REQUEST *) a)->packet,
				       ((const REQUEST *) b)->packet);
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

	rl->ht = lrad_hash_table_create(request_hash, request_cmp, NULL);
	if (!rl->ht) {
		rad_assert("FAIL" == NULL);
	}

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
	if (proxy_list) return 0;

	/*
	 *	Create the tree for managing proxied requests and
	 *	responses.
	 */
	proxy_list = lrad_packet_list_create(1);
	if (!proxy_list) {
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
				/*
				 *	FIXME: This works only because we
				 *	start off with one proxy socket.
				 */
				proxy_fds[listener->fd & 0x1f] = listener->fd;
				proxy_listeners[listener->fd & 0x1f] = listener;
				lrad_packet_list_socket_add(proxy_list, listener->fd);
				break;
			}
		}
	}

	return 1;
}

static int rl_free_entry(void *ctx, void *data)
{
	REQUEST *request = data;
	
	ctx = ctx;		/* -Wunused */

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

	if (proxy_list) {
		lrad_packet_list_free(proxy_list);
		proxy_list = NULL;
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
 *	Yank a request from the tree, without free'ing it.
 */
void rl_yank(request_list_t *rl, REQUEST *request)
{
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
	lrad_hash_table_delete(rl->ht, request);
	
	/*
	 *	If there's a proxied packet, and we're still
	 *	waiting for a reply, then delete the packet
	 *	from the list of outstanding proxied requests.
	 */
	if (request->proxy &&
	    (request->proxy_outstanding > 0)) {
		pthread_mutex_lock(&proxy_mutex);
		lrad_packet_list_id_free(proxy_list, request->proxy);
		lrad_packet_list_yank(proxy_list, request->proxy);
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
	return lrad_hash_table_insert(rl->ht, request);
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
	REQUEST request;

	request.packet = packet;

	return lrad_hash_table_finddata(rl->ht, &request);
}

/*
 *	Add an entry to the proxy tree.
 *
 *	This is the ONLY function in this source file which may be called
 *	from a child thread.  It therefore needs mutexes...
 */
int rl_add_proxy(REQUEST *request)
{
	int i, proxy;
	char buf[128];

	request->proxy_outstanding = 1;
	request->proxy->sockfd = -1;

	pthread_mutex_lock(&proxy_mutex);

	if (!lrad_packet_list_id_alloc(proxy_list, request->proxy)) {
		int found;
		rad_listen_t *proxy_listener;

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
		 *	Cache it locally.
		 */
		found = -1;
		proxy = proxy_listener->fd;
		for (i = 0; i < 32; i++) {
			/*
			 *	Found a free entry.  Save the socket,
			 *	and remember where we saved it.
			 */
			if (proxy_fds[(proxy + i) & 0x1f] == -1) {
				found = (proxy + i) & 0x1f;
				proxy_fds[found] = proxy;
				proxy_listeners[found] = proxy_listener;
				break;
			}
		}
		rad_assert(found >= 0);

		if (!lrad_packet_list_socket_add(proxy_list, proxy_listener->fd)) {
			pthread_mutex_unlock(&proxy_mutex);
			DEBUG2("ERROR: Failed to create a new socket for proxying requests.");
			return 0; /* leak proxy_listener */
			
		}
		    
		if (!lrad_packet_list_id_alloc(proxy_list, request->proxy)) {
			pthread_mutex_unlock(&proxy_mutex);
			DEBUG2("ERROR: Failed to create a new socket for proxying requests.");
			return 0;
		}
	}

	DEBUG("SOCKFD %d\n", request->proxy->sockfd);

	/*
	 *	FIXME: Hack until we get rid of rad_listen_t, and put
	 *	the information into the packet_list.
	 */
	proxy = -1;
	for (i = 0; i < 32; i++) {
		if (proxy_fds[i] == request->proxy->sockfd) {
			proxy = i;
			break;
		}
	}
	rad_assert(proxy >= 0);

	rad_assert(proxy_fds[proxy] != -1);
	request->proxy_listener = proxy_listeners[proxy];

	if (!lrad_packet_list_insert(proxy_list, &request->proxy)) {
		pthread_mutex_unlock(&proxy_mutex);
		DEBUG2("ERROR: Failed to insert entry into proxy list");
		return 0;
	}
	
	pthread_mutex_unlock(&proxy_mutex);

	DEBUG3(" proxy: allocating destination %s port %d - Id %d",
	       inet_ntop(request->proxy->dst_ipaddr.af,
			 &request->proxy->dst_ipaddr.ipaddr, buf, sizeof(buf)),
	       request->proxy->dst_port,
	       request->proxy->id);
	
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
REQUEST *rl_find_proxy(RADIUS_PACKET *reply)
{
	RADIUS_PACKET **proxy_p;
	REQUEST *request;

	pthread_mutex_lock(&proxy_mutex);
	proxy_p = lrad_packet_list_find_byreply(proxy_list, reply);

	if (!proxy_p) {
		pthread_mutex_unlock(&proxy_mutex);
		return NULL;
	}

	request = lrad_packet2myptr(REQUEST, proxy, proxy_p);
	rad_assert(request->proxy_outstanding > 0);
	request->proxy_outstanding--;
		
	/*
	 *	Received all of the replies we expect.
	 *	delete it from the managed list.
	 */
	if (request->proxy_outstanding == 0) {
		lrad_packet_list_id_free(proxy_list, request->proxy);
		lrad_packet_list_yank(proxy_list, request->proxy);
	}
	pthread_mutex_unlock(&proxy_mutex);

	return request;
}


/*
 *	Return the number of requests in the request list.
 */
int rl_num_requests(request_list_t *rl)
{
	return lrad_hash_table_num_elements(rl->ht);
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
	REQUEST *request = data;

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
		if (time_passed <= 0) time_passed = 1;
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
	if (time_passed < 0) time_passed = 1;

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
