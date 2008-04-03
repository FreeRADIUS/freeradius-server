/*
 * event.c	Server event handling
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
 * Copyright 2007  The FreeRADIUS server project
 * Copyright 2007  Alan DeKok <aland@deployingradius.com>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/event.h>
#include <freeradius-devel/detail.h>
#include <freeradius-devel/radius_snmp.h>

#include <freeradius-devel/rad_assert.h>

#include <signal.h>
#include <fcntl.h>

#ifdef HAVE_SYS_WAIT_H
#	include <sys/wait.h>
#endif

#define USEC (1000000)

extern pid_t radius_pid;
extern int dont_fork;
extern int check_config;
extern void force_log_reopen(void);

/*
 *	Ridiculous amounts of local state.
 */
static fr_event_list_t	*el = NULL;
static fr_packet_list_t	*pl = NULL;
static int			request_num_counter = 0;
static struct timeval		now;
static time_t			start_time;
static int			have_children;
static int			has_detail_listener = FALSE;
static int			just_started = FALSE;

#ifndef __MINGW32__
static int self_pipe[2];
#endif

#ifdef HAVE_PTHREAD_H
static pthread_mutex_t	proxy_mutex;

#define PTHREAD_MUTEX_LOCK if (have_children) pthread_mutex_lock
#define PTHREAD_MUTEX_UNLOCK if (have_children) pthread_mutex_unlock
#else
/*
 *	This is easier than ifdef's throughout the code.
 */
#define PTHREAD_MUTEX_LOCK(_x)
#define PTHREAD_MUTEX_UNLOCK(_x)
#endif

#define INSERT_EVENT(_function, _ctx) if (!fr_event_insert(el, _function, _ctx, &((_ctx)->when), &((_ctx)->ev))) { _rad_panic(__FILE__, __LINE__, "Failed to insert event"); }

static fr_packet_list_t *proxy_list = NULL;

/*
 *	We keep the proxy FD's here.  The RADIUS Id's are marked
 *	"allocated" per Id, via a bit per proxy FD.
 */
static int		proxy_fds[32];
static rad_listen_t	*proxy_listeners[32];

static void request_post_handler(REQUEST *request);
static void wait_a_bit(void *ctx);
static void event_socket_handler(fr_event_list_t *xel, UNUSED int fd, void *ctx);

static void NEVER_RETURNS _rad_panic(const char *file, unsigned int line,
				    const char *msg)
{
	radlog(L_ERR, "[%s:%d] %s", file, line, msg);
	_exit(1);
}

#define rad_panic(x) _rad_panic(__FILE__, __LINE__, x)


static void tv_add(struct timeval *tv, int usec_delay)
{
	if (usec_delay > USEC) {
		tv->tv_sec += usec_delay / USEC;
		usec_delay %= USEC;
	}
	tv->tv_usec += usec_delay;

	if (tv->tv_usec > USEC) {
		tv->tv_usec -= USEC;
		tv->tv_sec++;
	}
}

#ifdef WITH_SNMP
static void snmp_inc_counters(REQUEST *request)
{
	if (!request->root->do_snmp) return;

	if (request->master_state == REQUEST_COUNTED) return;

	if ((request->listener->type != RAD_LISTEN_AUTH) &&
	    (request->listener->type != RAD_LISTEN_ACCT)) return;

	/*
	 *	Update the SNMP statistics.
	 *
	 *	Note that we do NOT do this in a child thread.
	 *	Instead, we update the stats when a request is
	 *	deleted, because only the main server thread calls
	 *	this function, which makes it thread-safe.
	 */
	switch (request->reply->code) {
	case PW_AUTHENTICATION_ACK:
		rad_snmp.auth.total_responses++;
		rad_snmp.auth.total_access_accepts++;
		if (request->client && request->client->auth) {
			request->client->auth->accepts++;
		}
		break;

	case PW_AUTHENTICATION_REJECT:
		rad_snmp.auth.total_responses++;
		rad_snmp.auth.total_access_rejects++;
		if (request->client && request->client->auth) {
			request->client->auth->rejects++;
		}
		break;

	case PW_ACCESS_CHALLENGE:
		rad_snmp.auth.total_responses++;
		rad_snmp.auth.total_access_challenges++;
		if (request->client && request->client->auth) {
			request->client->auth->challenges++;
		}
		break;

	case PW_ACCOUNTING_RESPONSE:
		rad_snmp.acct.total_responses++;
		if (request->client && request->client->acct) {
			request->client->acct->responses++;
		}
		break;

		/*
		 *	No response, it must have been a bad
		 *	authenticator.
		 */
	case 0:
		if (request->packet->code == PW_AUTHENTICATION_REQUEST) {
			rad_snmp.auth.total_bad_authenticators++;
			if (request->client && request->client->auth) {
				request->client->auth->bad_authenticators++;
			}
		}
		break;

	default:
		break;
	}

	request->master_state = REQUEST_COUNTED;
}
#else
#define snmp_inc_counters(_x)
#endif


static void remove_from_request_hash(REQUEST *request)
{
	if (!request->in_request_hash) return;

	fr_packet_list_yank(pl, request->packet);
	request->in_request_hash = FALSE;

	snmp_inc_counters(request);
}


static REQUEST *lookup_in_proxy_hash(RADIUS_PACKET *reply)
{
	RADIUS_PACKET **proxy_p;
	REQUEST *request;

	PTHREAD_MUTEX_LOCK(&proxy_mutex);
	proxy_p = fr_packet_list_find_byreply(proxy_list, reply);

	if (!proxy_p) {
		PTHREAD_MUTEX_UNLOCK(&proxy_mutex);
		return NULL;
	}

	request = fr_packet2myptr(REQUEST, proxy, proxy_p);

	if (!request) {
		PTHREAD_MUTEX_UNLOCK(&proxy_mutex);
		return NULL;
	}

	request->num_proxied_responses++;

	/*
	 *	Catch the most common case of everything working
	 *	correctly.
	 */
	if (request->num_proxied_requests == request->num_proxied_responses) {
		fr_packet_list_yank(proxy_list, request->proxy);
		fr_packet_list_id_free(proxy_list, request->proxy);
		request->in_proxy_hash = FALSE;
	}

	/*
	 *	On the FIRST reply, decrement the count of outstanding
	 *	requests.  Note that this is NOT the count of sent
	 *	packets, but whether or not the home server has
	 *	responded at all.
	 */
	if (!request->proxy_reply &&
	    request->home_server->currently_outstanding) {
		request->home_server->currently_outstanding--;
	}

	PTHREAD_MUTEX_UNLOCK(&proxy_mutex);

	return request;
}


static void remove_from_proxy_hash(REQUEST *request)
{
	if (!request->in_proxy_hash) return;

	PTHREAD_MUTEX_LOCK(&proxy_mutex);
	fr_packet_list_yank(proxy_list, request->proxy);
	fr_packet_list_id_free(proxy_list, request->proxy);

	/*
	 *	The home server hasn't replied, but we've given up on
	 *	this request.  Don't count this request against the
	 *	home server.
	 */
	if (!request->proxy_reply &&
	    request->home_server->currently_outstanding) {
		request->home_server->currently_outstanding--;
	}

  	PTHREAD_MUTEX_UNLOCK(&proxy_mutex);

	request->in_proxy_hash = FALSE;
}


static int insert_into_proxy_hash(REQUEST *request)
{
	int i, proxy;
	char buf[128];

	rad_assert(request->proxy != NULL);
	rad_assert(proxy_list != NULL);

	request->proxy->sockfd = -1;

	PTHREAD_MUTEX_LOCK(&proxy_mutex);

	request->home_server->currently_outstanding++;
	request->home_server->total_requests_sent++;

	/*
	 *	On overflow, back up to ~0.
	 */
	if (!request->home_server->total_requests_sent) {
		request->home_server->total_requests_sent--;
	}

	if (!fr_packet_list_id_alloc(proxy_list, request->proxy)) {
		int found;
		rad_listen_t *proxy_listener;

		/*
		 *	Allocate a new proxy fd.  This function adds
		 *	it to the tail of the list of listeners.  With
		 *	some care, this can be thread-safe.
		 */
		proxy_listener = proxy_new_listener();
		if (!proxy_listener) {
			PTHREAD_MUTEX_UNLOCK(&proxy_mutex);
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

		if (!fr_packet_list_socket_add(proxy_list, proxy_listener->fd)) {
			PTHREAD_MUTEX_UNLOCK(&proxy_mutex);
			DEBUG2("ERROR: Failed to create a new socket for proxying requests.");
			return 0;

		}

		if (!fr_packet_list_id_alloc(proxy_list, request->proxy)) {
			PTHREAD_MUTEX_UNLOCK(&proxy_mutex);
			DEBUG2("ERROR: Failed to create a new socket for proxying requests.");
			return 0;
		}

		/*
		 *	Signal the main thread to add the new FD to the list
		 *	of listening FD's.
		 */
		radius_signal_self(RADIUS_SIGNAL_SELF_NEW_FD);
	}
	rad_assert(request->proxy->sockfd >= 0);

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

	if (proxy < 0) {
		PTHREAD_MUTEX_UNLOCK(&proxy_mutex);
		DEBUG2("ERROR: All sockets are full.");
		return 0;
	}

	rad_assert(proxy_fds[proxy] != -1);
	rad_assert(proxy_listeners[proxy] != NULL);
	request->proxy_listener = proxy_listeners[proxy];

	if (!fr_packet_list_insert(proxy_list, &request->proxy)) {
		fr_packet_list_id_free(proxy_list, request->proxy);
		PTHREAD_MUTEX_UNLOCK(&proxy_mutex);
		DEBUG2("ERROR: Failed to insert entry into proxy list");
		return 0;
	}

	PTHREAD_MUTEX_UNLOCK(&proxy_mutex);

	DEBUG3(" proxy: allocating destination %s port %d - Id %d",
	       inet_ntop(request->proxy->dst_ipaddr.af,
			 &request->proxy->dst_ipaddr.ipaddr, buf, sizeof(buf)),
	       request->proxy->dst_port,
	       request->proxy->id);

	request->in_proxy_hash = TRUE;

	return 1;
}


/*
 *	Called as BOTH an event, and in-line from other functions.
 */
static void wait_for_proxy_id_to_expire(void *ctx)
{
	REQUEST *request = ctx;
	home_server *home = request->home_server;

	rad_assert(request->magic == REQUEST_MAGIC);
	rad_assert(request->proxy != NULL);

	if (!fr_event_now(el, &now)) gettimeofday(&now, NULL);
	request->when = request->proxy_when;
	request->when.tv_sec += home->response_window;

	if ((request->num_proxied_requests == request->num_proxied_responses) ||
	    timercmp(&now, &request->when, >)) {
		if (request->packet) {
			DEBUG2("Cleaning up request %d ID %d with timestamp +%d",
			       request->number, request->packet->id,
			       (unsigned int) (request->timestamp - start_time));
		} else {
			DEBUG2("Cleaning up request %d with timestamp +%d",
			       request->number,
			       (unsigned int) (request->timestamp - start_time));
		}
		fr_event_delete(el, &request->ev);
		remove_from_proxy_hash(request);
		remove_from_request_hash(request);
		request_free(&request);
		return;
	}

	INSERT_EVENT(wait_for_proxy_id_to_expire, request);
}


static void wait_for_child_to_die(void *ctx)
{
	REQUEST *request = ctx;

	rad_assert(request->magic == REQUEST_MAGIC);

	if ((request->child_state == REQUEST_QUEUED) |
	    (request->child_state == REQUEST_RUNNING)) {
		request->delay += (request->delay >> 1);
		tv_add(&request->when, request->delay);

		DEBUG2("Child is still stuck for request %d", request->number);

		INSERT_EVENT(wait_for_child_to_die, request);
		return;
	}

	DEBUG2("Child is finally responsive for request %d", request->number);
	remove_from_request_hash(request);

	if (request->proxy) {
		wait_for_proxy_id_to_expire(request);
		return;
	}

	request_free(&request);
}


static void cleanup_delay(void *ctx)
{
	REQUEST *request = ctx;

	rad_assert(request->magic == REQUEST_MAGIC);
	rad_assert((request->child_state == REQUEST_CLEANUP_DELAY) ||
		   (request->child_state == REQUEST_DONE));

	remove_from_request_hash(request);

	if (request->proxy && request->in_proxy_hash) {
		wait_for_proxy_id_to_expire(request);
		return;
	}

	DEBUG2("Cleaning up request %d ID %d with timestamp +%d",
	       request->number, request->packet->id,
	       (unsigned int) (request->timestamp - start_time));

	fr_event_delete(el, &request->ev);
	request_free(&request);
}


static void reject_delay(void *ctx)
{
	REQUEST *request = ctx;

	rad_assert(request->magic == REQUEST_MAGIC);
	rad_assert(request->child_state == REQUEST_REJECT_DELAY);

	DEBUG2("Sending delayed reject for request %d", request->number);

	request->listener->send(request->listener, request);

	request->when.tv_sec += request->root->cleanup_delay;
	request->child_state = REQUEST_CLEANUP_DELAY;

	INSERT_EVENT(cleanup_delay, request);
}


static void revive_home_server(void *ctx)
{
	home_server *home = ctx;

	home->state = HOME_STATE_ALIVE;
	DEBUG2("Marking home server alive again... we have no idea if it really is alive or not.");
	home->currently_outstanding = 0;
}


static void no_response_to_ping(void *ctx)
{
	REQUEST *request = ctx;
	home_server *home = request->home_server;
	char buffer[128];

	home->num_received_pings = 0;

	DEBUG2("No response to status check %d from home server %s port %d",
	       request->number,
	       inet_ntop(request->proxy->dst_ipaddr.af,
			 &request->proxy->dst_ipaddr.ipaddr,
			 buffer, sizeof(buffer)),
	       request->proxy->dst_port);

	wait_for_proxy_id_to_expire(request);
}


static void received_response_to_ping(REQUEST *request)
{
	home_server *home = request->home_server;
	char buffer[128];

	home->num_received_pings++;

	DEBUG2("Received response to status check %d (%d in current sequence)",
	       request->number, home->num_received_pings);

	if (home->num_received_pings < home->num_pings_to_alive) {
		wait_for_proxy_id_to_expire(request);
		return;
	}

	DEBUG2("Marking home server %s port %d alive",
	       inet_ntop(request->proxy->dst_ipaddr.af,
			 &request->proxy->dst_ipaddr.ipaddr,
			 buffer, sizeof(buffer)),
	       request->proxy->dst_port);

	if (!fr_event_delete(el, &home->ev)) {
		DEBUG2("Hmm... no event for home server, WTF?");
	}

	if (!fr_event_delete(el, &request->ev)) {
		DEBUG2("Hmm... no event for request, WTF?");
	}

	wait_for_proxy_id_to_expire(request);

	home->state = HOME_STATE_ALIVE;
	home->currently_outstanding = 0;
}


static void ping_home_server(void *ctx)
{
	uint32_t jitter;
	home_server *home = ctx;
	REQUEST *request;
	VALUE_PAIR *vp;

	if (home->state == HOME_STATE_ALIVE) {
		radlog(L_INFO, "Suspicious proxy state... continuing");
		return;
	}

	request = request_alloc();
	request->number = request_num_counter++;

	request->proxy = rad_alloc(1);
	rad_assert(request->proxy != NULL);

	fr_event_now(el, &request->when);
	home->when = request->when;

	if (home->ping_check == HOME_PING_CHECK_STATUS_SERVER) {
		request->proxy->code = PW_STATUS_SERVER;

		radius_pairmake(request, &request->proxy->vps,
				"Message-Authenticator", "0x00", T_OP_SET);

	} else if (home->type == HOME_TYPE_AUTH) {
		request->proxy->code = PW_AUTHENTICATION_REQUEST;

		radius_pairmake(request, &request->proxy->vps,
				"User-Name", home->ping_user_name, T_OP_SET);
		radius_pairmake(request, &request->proxy->vps,
				"User-Password", home->ping_user_password, T_OP_SET);
		radius_pairmake(request, &request->proxy->vps,
				"Service-Type", "Authenticate-Only", T_OP_SET);
		radius_pairmake(request, &request->proxy->vps,
				"Message-Authenticator", "0x00", T_OP_SET);

	} else {
		request->proxy->code = PW_ACCOUNTING_REQUEST;
		
		radius_pairmake(request, &request->proxy->vps,
				"User-Name", home->ping_user_name, T_OP_SET);
		radius_pairmake(request, &request->proxy->vps,
				"Acct-Status-Type", "Stop", T_OP_SET);
		radius_pairmake(request, &request->proxy->vps,
				"Acct-Session-Id", "00000000", T_OP_SET);
		vp = radius_pairmake(request, &request->proxy->vps,
				     "Event-Timestamp", "0", T_OP_SET);
		vp->vp_date = now.tv_sec;
	}

	radius_pairmake(request, &request->proxy->vps,
			"NAS-Identifier", "Status Check. Are you alive?",
			T_OP_SET);

	request->proxy->dst_ipaddr = home->ipaddr;
	request->proxy->dst_port = home->port;
	request->home_server = home;

	rad_assert(request->proxy_listener == NULL);

	if (!insert_into_proxy_hash(request)) {
		DEBUG2("ERROR: Failed inserting status check %d into proxy hash.  Discarding it.",
		       request->number);
		request_free(&request);
		return;
	}
	rad_assert(request->proxy_listener != NULL);
	request->proxy_listener->send(request->proxy_listener,
				      request);

	request->next_callback = NULL;
	request->child_state = REQUEST_PROXIED;
	request->when.tv_sec += home->ping_timeout;;

	INSERT_EVENT(no_response_to_ping, request);

	/*
	 *	Add +/- 2s of jitter, as suggested in RFC 3539
	 *	and in the Issues and Fixes draft.
	 */
	home->when.tv_sec += home->ping_interval - 2;

	jitter = fr_rand();
	jitter ^= (jitter >> 10);
	jitter &= ((1 << 23) - 1); /* 22 bits of 1 */

	tv_add(&home->when, jitter);


	INSERT_EVENT(ping_home_server, home);
}


static void check_for_zombie_home_server(REQUEST *request)
{
	home_server *home;
	struct timeval when;
	char buffer[128];

	home = request->home_server;

	if (home->state != HOME_STATE_ZOMBIE) return;

	when = home->zombie_period_start;
	when.tv_sec += home->zombie_period;

	fr_event_now(el, &now);
	if (timercmp(&now, &when, <)) {
		return;
	}

	/*
	 *	It's been a zombie for too long, mark it as
	 *	dead.
	 */
	DEBUG2("FAILURE: Marking home server %s port %d as dead.",
	       inet_ntop(request->proxy->dst_ipaddr.af,
			 &request->proxy->dst_ipaddr.ipaddr,
			 buffer, sizeof(buffer)),
	       request->proxy->dst_port);
	home->state = HOME_STATE_IS_DEAD;
	home->num_received_pings = 0;
	home->when = request->when;

	if (home->ping_check != HOME_PING_CHECK_NONE) {
		rad_assert((home->ping_check == HOME_PING_CHECK_STATUS_SERVER) ||
			   (home->ping_user_name != NULL));
		home->when.tv_sec += home->ping_interval;

		INSERT_EVENT(ping_home_server, home);
	} else {
		home->when.tv_sec += home->revive_interval;

		INSERT_EVENT(revive_home_server, home);
	}
}


static int setup_post_proxy_fail(REQUEST *request)
{
	DICT_VALUE *dval = NULL;
	VALUE_PAIR *vp;

	if (request->packet->code == PW_AUTHENTICATION_REQUEST) {
		dval = dict_valbyname(PW_POST_PROXY_TYPE, "Fail-Authentication");

	} else if (request->packet->code == PW_ACCOUNTING_REQUEST) {
		dval = dict_valbyname(PW_POST_PROXY_TYPE, "Fail-Accounting");

	} else {
		return 0;
	}

	if (!dval) dval = dict_valbyname(PW_POST_PROXY_TYPE, "Fail");

	if (!dval) {
		pairdelete(&request->config_items, PW_POST_PROXY_TYPE);
		return 0;
	}

	vp = pairfind(request->config_items, PW_POST_PROXY_TYPE);
	if (!vp) vp = radius_paircreate(request, &request->config_items,
					PW_POST_PROXY_TYPE, PW_TYPE_INTEGER);
	vp->vp_integer = dval->value;

	rad_assert(request->proxy_reply == NULL);

	return 1;
}


static int null_handler(UNUSED REQUEST *request)
{
	return 0;
}

static void post_proxy_fail_handler(REQUEST *request)
{
	/*
	 *	A proper time is required for wait_a_bit.
	 */
	request->delay = USEC / 10;
	gettimeofday(&now, NULL);

	/*
	 *	Not set up to run Post-Proxy-Type = Fail.
	 *
	 *	Mark the request as still running, and figure out what
	 *	to do next.
	 */
	if (!setup_post_proxy_fail(request)) {
		request->child_state = REQUEST_RUNNING;
		request_post_handler(request);

	} else {
		/*
		 *	Re-queue the request.
		 */
		request->child_state = REQUEST_QUEUED;

		/*
		 *	There is a post-proxy-type of fail.  We run
		 *	the request through the pre/post proxy
		 *	handlers, just like it was a real proxied
		 *	request.  However, we set the per-request
		 *	handler to NULL, as we don't want to do
		 *	anything else.
		 *
		 *	Note that when we're not threaded, this will
		 *	process the request even if it's greater than
		 *	max_request_time.  That's not fatal.
		 */
		request->priority = 0;
		rad_assert(request->proxy != NULL);
		thread_pool_addrequest(request, null_handler);

	}

	/*
	 *	MAY free the request if we're over max_request_time,
	 *	AND we're not in threaded mode!
	 */
	wait_a_bit(request);
}


/* maybe check this against wait_for_proxy_id_to_expire? */
static void no_response_to_proxied_request(void *ctx)
{
	REQUEST *request = ctx;
	home_server *home;
	char buffer[128];

	rad_assert(request->magic == REQUEST_MAGIC);
	rad_assert(request->child_state == REQUEST_PROXIED);

	radlog(L_ERR, "Rejecting request %d due to lack of any response from home server %s port %d",
	       request->number,
	       inet_ntop(request->proxy->dst_ipaddr.af,
			 &request->proxy->dst_ipaddr.ipaddr,
			 buffer, sizeof(buffer)),
	       request->proxy->dst_port);

	check_for_zombie_home_server(request);

	home = request->home_server;

	post_proxy_fail_handler(request);

	/*
	 *	Don't touch request due to race conditions
	 */
	if (home->state == HOME_STATE_IS_DEAD) {
		rad_assert(home->ev != NULL); /* or it will never wake up */
		return;
	}

	/*
	 *	Enable the zombie period when we notice that the home
	 *	server hasn't responded.  We also back-date the start
	 *	of the zombie period to when the proxied request was
	 *	sent.
	 */
	if (home->state == HOME_STATE_ALIVE) {
		DEBUG2("WARNING: Marking home server %s port %d as zombie (it looks like it is dead).",
		       inet_ntop(home->ipaddr.af, &home->ipaddr.ipaddr,
				 buffer, sizeof(buffer)),
		       home->port);
		home->state = HOME_STATE_ZOMBIE;
		home->zombie_period_start = now;
		home->zombie_period_start.tv_sec -= home->response_window;
		return;
	}
}


static void wait_a_bit(void *ctx)
{
	struct timeval when;
	REQUEST *request = ctx;
	fr_event_callback_t callback = NULL;

	rad_assert(request->magic == REQUEST_MAGIC);

	switch (request->child_state) {
	case REQUEST_QUEUED:
	case REQUEST_RUNNING:
		when = request->received;
		when.tv_sec += request->root->max_request_time;

		/*
		 *	Normally called from the event loop with the
		 *	proper event loop time.  Otherwise, called from
		 *	post proxy fail handler, which sets "now", and
		 *	this call won't re-set it, because we're not
		 *	in the event loop.
		 */
		fr_event_now(el, &now);

		/*
		 *	Request still has more time.  Continue
		 *	waiting.
		 */
		if (timercmp(&now, &when, <) ||
		    ((request->listener->type == RAD_LISTEN_DETAIL) &&
		     (request->child_state == REQUEST_QUEUED))) {
			if (request->delay < (USEC / 10)) {
				request->delay = USEC / 10;
			}
			request->delay += request->delay >> 1;

			/*
			 *	Cap wait at some sane value for detail
			 *	files.
			 */
			if ((request->listener->type == RAD_LISTEN_DETAIL) &&
			    (request->delay > (request->root->max_request_time * USEC))) {
				request->delay = request->root->max_request_time * USEC;
			}

			request->when = now;
			tv_add(&request->when, request->delay);
			callback = wait_a_bit;
			break;
		}

		/*
		 *	A child thread MAY still be running on the
		 *	request.  Ask the thread to stop working on
		 *	the request.
		 */
		if (have_children) {
			/* FIXME: kill unresponsive children? */

			/*
			 *	Print this error message ONLY if
			 *	there's a child currently processing
			 *	the request.  As we don't have thread
			 *	locks here, there may be race
			 *	conditions on this check.  But it's
			 *	just an error message, so that's OK.
			 */
			if (request->child_pid != NO_SUCH_CHILD_PID) {
				radlog(L_ERR, "WARNING: Unresponsive child (id %lu) for request %d, in module %s component %s",
			       (unsigned long)request->child_pid, request->number,
				       request->module ? request->module : "<server core>",
				       request->component ? request->component : "<server core>");
			}

			request->master_state = REQUEST_STOP_PROCESSING;
			
			request->delay = USEC / 4;
			tv_add(&request->when, request->delay);
			callback = wait_for_child_to_die;
			break;
		}

		/*
		 *	Else there are no child threads.  We probably
		 *	should have just marked the request as 'done'
		 *	elsewhere, like in the post-proxy-fail
		 *	handler.  But doing that would involve
		 *	checking for max_request_time in multiple
		 *	places, so this may be simplest.
		 */
		request->child_state = REQUEST_DONE;
		/* FALL-THROUGH */

		/*
		 *	Mark the request as no longer running,
		 *	and clean it up.
		 */
	case REQUEST_DONE:
		request->child_pid = NO_SUCH_CHILD_PID;
		snmp_inc_counters(request);
		cleanup_delay(request);
		return;

	case REQUEST_REJECT_DELAY:
	case REQUEST_CLEANUP_DELAY:
		request->child_pid = NO_SUCH_CHILD_PID;
		snmp_inc_counters(request);

	case REQUEST_PROXIED:
		rad_assert(request->next_callback != NULL);
		rad_assert(request->next_callback != wait_a_bit);

		request->when = request->next_when;
		callback = request->next_callback;
		request->next_callback = NULL;
		break;

	default:
		rad_panic("Internal sanity check failure");
		return;
	}

	/*
	 *	Something major went wrong.  Discard the request, and
	 *	keep running.
	 *
	 *	FIXME: No idea why this happens or how to fix it...
	 *	It seems to happen *only* when requests are proxied,
	 *	and where the home server doesn't respond.  So it looks
	 *	like a race condition above, but it happens in debug
	 *	mode, with no threads...
	 */
	if (!callback) {
		DEBUG("WARNING: Internal sanity check failed in event handler for request %d: Discarding the request!", request->number);
		fr_event_delete(el, &request->ev);
		remove_from_proxy_hash(request);
		remove_from_request_hash(request);
		request_free(&request);
		return;
	}

	INSERT_EVENT(callback, request);
}


static int request_pre_handler(REQUEST *request)
{
	int rcode;

	rad_assert(request->magic == REQUEST_MAGIC);
	rad_assert(request->packet != NULL);

	request->child_state = REQUEST_RUNNING;

	/*
	 *	Don't decode the packet if it's an internal "fake"
	 *	request.  Instead, just return so that the caller can
	 *	process it.
	 */
	if (request->packet->dst_port == 0) {
		request->username = pairfind(request->packet->vps,
					     PW_USER_NAME);
		request->password = pairfind(request->packet->vps,
					     PW_USER_PASSWORD);
		return 1;
	}

	/*
	 *	Put the decoded packet into it's proper place.
	 */
	if (request->proxy_reply != NULL) {
		rcode = request->proxy_listener->decode(request->proxy_listener,
							request);
	} else if (request->packet->vps == NULL) {
		rcode = request->listener->decode(request->listener, request);

	} else {
		rcode = 0;
	}

	if (rcode < 0) {
		radlog(L_ERR, "%s Dropping packet without response.", librad_errstr);
		request->child_state = REQUEST_DONE;
		return 0;
	}

	if (!request->proxy) {
		request->username = pairfind(request->packet->vps,
					     PW_USER_NAME);

	} else {
		int post_proxy_type = 0;
		VALUE_PAIR *vp;

		/*
		 *	Delete any reply we had accumulated until now.
		 */
		pairfree(&request->reply->vps);

		/*
		 *	Run the packet through the post-proxy stage,
		 *	BEFORE playing games with the attributes.
		 */
		vp = pairfind(request->config_items, PW_POST_PROXY_TYPE);
		if (vp) {
			DEBUG2("  Found Post-Proxy-Type %s", vp->vp_strvalue);
			post_proxy_type = vp->vp_integer;
		}

		rad_assert(request->home_pool != NULL);

		if (request->home_pool->virtual_server) {
			const char *old_server = request->server;

			request->server = request->home_pool->virtual_server;
			DEBUG2(" server %s {", request->server);
			rcode = module_post_proxy(post_proxy_type, request);
			DEBUG2(" }");
			request->server = old_server;
		} else {
			rcode = module_post_proxy(post_proxy_type, request);
		}

		/*
		 *	There may NOT be a proxy reply, as we may be
		 *	running Post-Proxy-Type = Fail.
		 */
		if (request->proxy_reply) {
			/*
			 *	Delete the Proxy-State Attributes from
			 *	the reply.  These include Proxy-State
			 *	attributes from us and remote server.
			 */
			pairdelete(&request->proxy_reply->vps, PW_PROXY_STATE);

			/*
			 *	Add the attributes left in the proxy
			 *	reply to the reply list.
			 */
			pairadd(&request->reply->vps, request->proxy_reply->vps);
			request->proxy_reply->vps = NULL;

			/*
			 *	Free proxy request pairs.
			 */
			pairfree(&request->proxy->vps);
		}

		switch (rcode) {
                default:  /* Don't do anything */
			break;
                case RLM_MODULE_FAIL:
			/* FIXME: debug print stuff */
			request->child_state = REQUEST_DONE;
			return 0;

                case RLM_MODULE_HANDLED:
			/* FIXME: debug print stuff */
			request->child_state = REQUEST_DONE;
			return 0;
		}
	}

	return 1;
}


/*
 *	Do state handling when we proxy a request.
 */
static int proxy_request(REQUEST *request)
{
	struct timeval when;
	char buffer[128];

	if (!insert_into_proxy_hash(request)) {
		DEBUG("ERROR: Failed inserting request into proxy hash.");
		return 0;
	}

	request->proxy_listener->encode(request->proxy_listener, request);

	when = request->received;
	when.tv_sec += request->root->max_request_time;

	gettimeofday(&request->proxy_when, NULL);

	request->next_when = request->proxy_when;
	request->next_when.tv_sec += request->home_server->response_window;

	rad_assert(request->home_server->response_window > 0);

	if (timercmp(&when, &request->next_when, <)) {
		request->next_when = when;
	}
	request->next_callback = no_response_to_proxied_request;

	DEBUG2("Proxying request %d to home server %s port %d",
	       request->number,
	       inet_ntop(request->proxy->dst_ipaddr.af,
			 &request->proxy->dst_ipaddr.ipaddr,
			 buffer, sizeof(buffer)),
	       request->proxy->dst_port);

	/*
	 *	Note that we set proxied BEFORE sending the packet.
	 *
	 *	Once we send it, the request is tainted, as
	 *	another thread may have picked it up.  Don't
	 *	touch it!
	 */
	request->num_proxied_requests = 1;
	request->num_proxied_responses = 0;
	request->child_pid = NO_SUCH_CHILD_PID;
	request->child_state = REQUEST_PROXIED;
	request->proxy_listener->send(request->proxy_listener,
				      request);
	return 1;
}


/*
 *	"Proxy" the request by sending it to a new virtual server.
 */
static int proxy_to_virtual_server(REQUEST *request)
{
	REQUEST *fake;

	if (!request->home_server || !request->home_server->server) return 0;

	if (request->parent) {
		DEBUG2("WARNING: Cancelling proxy request to virtual server %s as this request was itself proxied.", request->home_server->server);
		return 0;
	}

	fake = request_alloc_fake(request);
	if (!fake) {
		DEBUG2("WARNING: Out of memory");
		return 0;
	}

	fake->packet->vps = paircopy(request->proxy->vps);
	fake->server = request->home_server->server;

	DEBUG2(">>> Sending proxied request internally to virtual server.");
	radius_handle_request(fake, rad_authenticate);
	DEBUG2("<<< Received proxied response from internal virtual server.");

	request->proxy_reply = fake->reply;
	fake->reply = NULL;

	/*
	 *	And run it through the post-proxy section...
	 */
	rad_authenticate(request);

	return 2;		/* success, but NOT '1' !*/
}


/*
 *	Return 1 if we did proxy it, or the proxy attempt failed
 *	completely.  Either way, the caller doesn't touch the request
 *	any more if we return 1.
 */
static int successfully_proxied_request(REQUEST *request)
{
	int rcode;
	int pre_proxy_type = 0;
	VALUE_PAIR *realmpair;
	VALUE_PAIR *strippedname;
	VALUE_PAIR *vp;
	char *realmname;
	home_server *home;
	REALM *realm = NULL;
	home_pool_t *pool;

	/*
	 *	If it was already proxied, do nothing.
	 *
	 *	FIXME: This should really be a serious error.
	 */
	if (request->in_proxy_hash) {
		return 0;
	}

	realmpair = pairfind(request->config_items, PW_PROXY_TO_REALM);
	if (!realmpair || (realmpair->length == 0)) {
		return 0;
	}

	realmname = (char *) realmpair->vp_strvalue;

	realm = realm_find(realmname);
	if (!realm) {
		DEBUG2("ERROR: Cannot proxy to unknown realm %s", realmname);
		return 0;
	}

	/*
	 *	Figure out which pool to use.
	 */
	if (request->packet->code == PW_AUTHENTICATION_REQUEST) {
		pool = realm->auth_pool;

	} else if (request->packet->code == PW_ACCOUNTING_REQUEST) {
		pool = realm->acct_pool;

	} else {
		rad_panic("Internal sanity check failed");
	}

	if (!pool) {
		DEBUG2(" WARNING: Cancelling proxy to Realm %s, as the realm is local.",
		       realmname);
		return 0;
	}

	home = home_server_ldb(realmname, pool, request);
	if (!home) {
		DEBUG2("ERROR: Failed to find live home server for realm %s",
		       realmname);
		return -1;
	}
	request->home_pool = pool;

	/*
	 *	Remember that we sent the request to a Realm.
	 */
	pairadd(&request->packet->vps,
		pairmake("Realm", realmname, T_OP_EQ));

	/*
	 *	We read the packet from a detail file, AND it came from
	 *	the server we're about to send it to.  Don't do that.
	 */
	if ((request->packet->code == PW_ACCOUNTING_REQUEST) &&
	    (request->listener->type == RAD_LISTEN_DETAIL) &&
	    (home->ipaddr.af == AF_INET) &&
	    (request->packet->src_ipaddr.af == AF_INET) &&
	    (home->ipaddr.ipaddr.ip4addr.s_addr == request->packet->src_ipaddr.ipaddr.ip4addr.s_addr)) {
		DEBUG2("    rlm_realm: Packet came from realm %s, proxy cancelled", realmname);
		return 0;
	}

	/*
	 *	Allocate the proxy packet, only if it wasn't already
	 *	allocated by a module.  This check is mainly to support
	 *	the proxying of EAP-TTLS and EAP-PEAP tunneled requests.
	 *
	 *	In those cases, the EAP module creates a "fake"
	 *	request, and recursively passes it through the
	 *	authentication stage of the server.  The module then
	 *	checks if the request was supposed to be proxied, and
	 *	if so, creates a proxy packet from the TUNNELED request,
	 *	and not from the EAP request outside of the tunnel.
	 *
	 *	The proxy then works like normal, except that the response
	 *	packet is "eaten" by the EAP module, and encapsulated into
	 *	an EAP packet.
	 */
	if (!request->proxy) {
		if ((request->proxy = rad_alloc(TRUE)) == NULL) {
			radlog(L_ERR|L_CONS, "no memory");
			exit(1);
		}

		/*
		 *	Copy the request, then look up name and
		 *	plain-text password in the copy.
		 *
		 *	Note that the User-Name attribute is the
		 *	*original* as sent over by the client.  The
		 *	Stripped-User-Name attribute is the one hacked
		 *	through the 'hints' file.
		 */
		request->proxy->vps =  paircopy(request->packet->vps);
	}

	/*
	 *	Strip the name, if told to.
	 *
	 *	Doing it here catches the case of proxied tunneled
	 *	requests.
	 */
	if (realm->striprealm == TRUE &&
	   (strippedname = pairfind(request->proxy->vps, PW_STRIPPED_USER_NAME)) != NULL) {
		/*
		 *	If there's a Stripped-User-Name attribute in
		 *	the request, then use THAT as the User-Name
		 *	for the proxied request, instead of the
		 *	original name.
		 *
		 *	This is done by making a copy of the
		 *	Stripped-User-Name attribute, turning it into
		 *	a User-Name attribute, deleting the
		 *	Stripped-User-Name and User-Name attributes
		 *	from the vps list, and making the new
		 *	User-Name the head of the vps list.
		 */
		vp = pairfind(request->proxy->vps, PW_USER_NAME);
		if (!vp) {
			vp = radius_paircreate(request, NULL,
					       PW_USER_NAME, PW_TYPE_STRING);
			rad_assert(vp != NULL);	/* handled by above function */
			/* Insert at the START of the list */
			vp->next = request->proxy->vps;
			request->proxy->vps = vp;
		}
		memcpy(vp->vp_strvalue, strippedname->vp_strvalue,
		       sizeof(vp->vp_strvalue));
		vp->length = strippedname->length;

		/*
		 *	Do NOT delete Stripped-User-Name.
		 */
	}

	/*
	 *	If there is no PW_CHAP_CHALLENGE attribute but
	 *	there is a PW_CHAP_PASSWORD we need to add it
	 *	since we can't use the request authenticator
	 *	anymore - we changed it.
	 */
	if (pairfind(request->proxy->vps, PW_CHAP_PASSWORD) &&
	    pairfind(request->proxy->vps, PW_CHAP_CHALLENGE) == NULL) {
		vp = radius_paircreate(request, &request->proxy->vps,
				       PW_CHAP_CHALLENGE, PW_TYPE_OCTETS);
		vp->length = AUTH_VECTOR_LEN;
		memcpy(vp->vp_strvalue, request->packet->vector, AUTH_VECTOR_LEN);
	}

	/*
	 *	The RFC's say we have to do this, but FreeRADIUS
	 *	doesn't need it.
	 */
	vp = radius_paircreate(request, &request->proxy->vps,
			       PW_PROXY_STATE, PW_TYPE_OCTETS);
	snprintf(vp->vp_strvalue, sizeof(vp->vp_strvalue), "%d",
		 request->packet->id);
	vp->length = strlen(vp->vp_strvalue);

	/*
	 *	Should be done BEFORE inserting into proxy hash, as
	 *	pre-proxy may use this information, or change it.
	 */
	request->proxy->code = request->packet->code;
	request->proxy->dst_ipaddr = home->ipaddr;
	request->proxy->dst_port = home->port;
	request->home_server = home;

	/*
	 *	Call the pre-proxy routines.
	 */
	vp = pairfind(request->config_items, PW_PRE_PROXY_TYPE);
	if (vp) {
		DEBUG2("  Found Pre-Proxy-Type %s", vp->vp_strvalue);
		pre_proxy_type = vp->vp_integer;
	}

	rad_assert(request->home_pool != NULL);

	if (request->home_pool->virtual_server) {
		const char *old_server = request->server;
		
		request->server = request->home_pool->virtual_server;
		DEBUG2(" server %s {", request->server);
		rcode = module_pre_proxy(pre_proxy_type, request);
		DEBUG2(" }");
			request->server = old_server;
	} else {
		rcode = module_pre_proxy(pre_proxy_type, request);
	}
	switch (rcode) {
	case RLM_MODULE_FAIL:
	case RLM_MODULE_INVALID:
	case RLM_MODULE_NOTFOUND:
	case RLM_MODULE_USERLOCK:
	default:
		/* FIXME: debug print failed stuff */
		return -1;

	case RLM_MODULE_REJECT:
	case RLM_MODULE_HANDLED:
		return 0;

	/*
	 *	Only proxy the packet if the pre-proxy code succeeded.
	 */
	case RLM_MODULE_NOOP:
	case RLM_MODULE_OK:
	case RLM_MODULE_UPDATED:
		break;
	}

	/*
	 *	If it's a fake request, don't send the proxy
	 *	packet.  The outer tunnel session will take
	 *	care of doing that.
	 */
	if (request->packet->dst_port == 0) {
		request->home_server = NULL;
		return 1;
	}

	if (request->home_server->server) {
		return proxy_to_virtual_server(request);
	}

	if (!proxy_request(request)) {
		DEBUG("ERROR: Failed to proxy request %d", request->number);
		return -1;
	}
	
	return 1;
}


static void request_post_handler(REQUEST *request)
{
	int child_state = -1;
	struct timeval when;
	VALUE_PAIR *vp;

	if ((request->master_state == REQUEST_STOP_PROCESSING) ||
	    (request->parent &&
	     (request->parent->master_state == REQUEST_STOP_PROCESSING))) {
		DEBUG2("Request %d was cancelled.", request->number);
		request->child_pid = NO_SUCH_CHILD_PID;
		request->child_state = REQUEST_DONE;
		return;
	}

	if (request->child_state != REQUEST_RUNNING) {
		rad_panic("Internal sanity check failed");
	}

	if ((request->reply->code == 0) &&
	    ((vp = pairfind(request->config_items, PW_AUTH_TYPE)) != NULL) &&
	    (vp->vp_integer == PW_AUTHTYPE_REJECT)) {
		request->reply->code = PW_AUTHENTICATION_REJECT;
	}

	if (request->root->proxy_requests &&
	    !request->in_proxy_hash &&
	    (request->reply->code == 0) &&
	    (request->packet->dst_port != 0) &&
	    (request->packet->code != PW_STATUS_SERVER)) {
		int rcode = successfully_proxied_request(request);

		if (rcode == 1) return;

		/*
		 *	Failed proxying it (dead home servers, etc.)
		 *	Run it through Post-Proxy-Type = Fail, and
		 *	respond to the request.
		 *
		 *	Note that we're in a child thread here, so we
		 *	do NOT re-schedule the request.  Instead, we
		 *	do what we would have done, which is run the
		 *	pre-handler, a NULL request handler, and then
		 *	the post handler.
		 */
		if ((rcode < 0) && setup_post_proxy_fail(request)) {
			request_pre_handler(request);
		}

		/*
		 *	Else we weren't supposed to proxy it,
		 *	OR we proxied it internally to a virutal server.
		 */
	}

	/*
	 *	Fake requests don't get encoded or signed.  The caller
	 *	also requires the reply VP's, so we don't free them
	 *	here!
	 */
	if (request->packet->dst_port == 0) {
		/* FIXME: DEBUG going to the next request */
		request->child_pid = NO_SUCH_CHILD_PID;
		request->child_state = REQUEST_DONE;
		return;
	}

	/*
	 *	Copy Proxy-State from the request to the reply.
	 */
	vp = paircopy2(request->packet->vps, PW_PROXY_STATE);
	if (vp) pairadd(&request->reply->vps, vp);

	/*
	 *	Access-Requests get delayed or cached.
	 */
	switch (request->packet->code) {
	case PW_AUTHENTICATION_REQUEST:
		gettimeofday(&request->next_when, NULL);

		if (request->reply->code == 0) {
			/*
			 *	Check if the lack of response is intentional.
			 */
			vp = pairfind(request->config_items,
				      PW_RESPONSE_PACKET_TYPE);
			if (!vp || (vp->vp_integer != 256)) {
				DEBUG2("There was no response configured: rejecting request %d",
				       request->number);
				request->reply->code = PW_AUTHENTICATION_REJECT;
			} else {
				DEBUG2("Not responding to request %d",
				       request->number);
			}
		}

		/*
		 *	Run rejected packets through
		 *
		 *	Post-Auth-Type = Reject
		 */
		if (request->reply->code == PW_AUTHENTICATION_REJECT) {
			pairdelete(&request->config_items, PW_POST_AUTH_TYPE);
			vp = radius_pairmake(request, &request->config_items,
					     "Post-Auth-Type", "Reject",
					     T_OP_SET);
			if (vp) rad_postauth(request);

			/*
			 *	If configured, delay Access-Reject packets.
			 *
			 *	If request->root->reject_delay = 0, we discover
			 *	that we have to send the packet now.
			 */
			when = request->received;
			when.tv_sec += request->root->reject_delay;

			if (timercmp(&when, &request->next_when, >)) {
				DEBUG2("Delaying reject of request %d for %d seconds",
				       request->number,
				       request->root->reject_delay);
				request->next_when = when;
				request->next_callback = reject_delay;
				request->child_pid = NO_SUCH_CHILD_PID;
				request->child_state = REQUEST_REJECT_DELAY;
				return;
			}
		}

		request->next_when.tv_sec += request->root->cleanup_delay;
		request->next_callback = cleanup_delay;
		child_state = REQUEST_CLEANUP_DELAY;
		break;

	case PW_ACCOUNTING_REQUEST:
		request->next_callback = NULL; /* just to be safe */
		child_state = REQUEST_DONE;
		break;

		/*
		 *	FIXME: Status-Server should probably not be
		 *	handled here...
		 */
	case PW_STATUS_SERVER:
		request->next_callback = NULL;
		child_state = REQUEST_DONE;
		break;

	default:
		rad_panic("Unknown packet type");
		break;
	}

	/*
	 *      Suppress "no reply" packets here, unless we're reading
	 *      from the "detail" file.  In that case, we've got to
	 *      tell the detail file handler that the request is dead,
	 *      and it should re-send it.
	 *	If configured, encode, sign, and send.
	 */
	if ((request->reply->code != 0) ||
	    (request->listener->type == RAD_LISTEN_DETAIL)) {
		request->listener->send(request->listener, request);
	}

	/*
	 *	Clean up.  These are no longer needed.
	 */
	pairfree(&request->config_items);

	pairfree(&request->packet->vps);
	request->username = NULL;
	request->password = NULL;

	pairfree(&request->reply->vps);

	if (request->proxy) {
		pairfree(&request->proxy->vps);

		if (request->proxy_reply) {
			pairfree(&request->proxy_reply->vps);
		}

		/*
		 *	We're not tracking responses from the home
		 *	server, we can therefore free this memory in
		 *	the child thread.
		 */
		if (!request->in_proxy_hash) {
			rad_free(&request->proxy);
			rad_free(&request->proxy_reply);
			request->home_server = NULL;
		}
	}

	DEBUG2("Finished request %d.", request->number);

	request->child_state = child_state;

	/*
	 *	Single threaded mode: update timers now.
	 */
	if (!have_children) wait_a_bit(request);
}


static void received_retransmit(REQUEST *request, const RADCLIENT *client)
{
	char buffer[128];

	RAD_SNMP_TYPE_INC(request->listener, total_dup_requests);
	RAD_SNMP_CLIENT_INC(request->listener, client, dup_requests);

	switch (request->child_state) {
	case REQUEST_QUEUED:
	case REQUEST_RUNNING:
	discard:
		radlog(L_ERR, "Discarding duplicate request from "
		       "client %s port %d - ID: %d due to unfinished request %d",
		       client->shortname,
		       request->packet->src_port,request->packet->id,
		       request->number);
		break;

	case REQUEST_PROXIED:
		/*
		 *	We're not supposed to have duplicate
		 *	accounting packets.  The other states handle
		 *	duplicates fine (discard, or send duplicate
		 *	reply).  But we do NOT want to retransmit an
		 *	accounting request here, because that would
		 *	involve updating the Acct-Delay-Time, and
		 *	therefore changing the packet Id, etc.
		 *
		 *	Instead, we just discard the packet.  We may
		 *	eventually respond, or the client will send a
		 *	new accounting packet.
		 */
		if (request->packet->code == PW_ACCOUNTING_REQUEST) {
			goto discard;
		}

		check_for_zombie_home_server(request);

		/*
		 *	If we've just discovered that the home server is
		 *	dead, send the packet to another one.
		 */
		if ((request->packet->dst_port != 0) &&
		    (request->home_server->state == HOME_STATE_IS_DEAD)) {
			home_server *home;

			remove_from_proxy_hash(request);

			home = home_server_ldb(NULL, request->home_pool, request);
			if (!home) {
				DEBUG2("Failed to find live home server for request %d", request->number);
			no_home_servers:
				/*
				 *	Do post-request processing,
				 *	and any insertion of necessary
				 *	events.
				 */
				post_proxy_fail_handler(request);
				return;
			}

			request->proxy->code = request->packet->code;
			request->proxy->dst_ipaddr = home->ipaddr;
			request->proxy->dst_port = home->port;
			request->home_server = home;

			/*
			 *	Free the old packet, to force re-encoding
			 */
			free(request->proxy->data);
			request->proxy->data = NULL;
			request->proxy->data_len = 0;

			/*
			 *	Try to proxy the request.
			 */
			if (!proxy_request(request)) {
				DEBUG("ERROR: Failed to re-proxy request %d", request->number);
				goto no_home_servers;
			}

			/*
			 *	This code executes in the main server
			 *	thread, so there's no need for locking.
			 */
			rad_assert(request->next_callback != NULL);
			INSERT_EVENT(request->next_callback, request);
			request->next_callback = NULL;
			return;
		} /* else the home server is still alive */

		DEBUG2("Sending duplicate proxied request to home server %s port %d - ID: %d",
		       inet_ntop(request->proxy->dst_ipaddr.af,
				 &request->proxy->dst_ipaddr.ipaddr,
				 buffer, sizeof(buffer)),
		       request->proxy->dst_port,
		       request->proxy->id);
		request->num_proxied_requests++;
		request->proxy_listener->send(request->proxy_listener,
					      request);
		break;

	case REQUEST_REJECT_DELAY:
		DEBUG2("Waiting to send Access-Reject "
		       "to client %s port %d - ID: %d",
		       client->shortname,
		       request->packet->src_port, request->packet->id);
		break;

	case REQUEST_CLEANUP_DELAY:
	case REQUEST_DONE:
		DEBUG2("Sending duplicate reply "
		       "to client %s port %d - ID: %d",
		       client->shortname,
		       request->packet->src_port, request->packet->id);
		request->listener->send(request->listener, request);
		break;
	}
}


static void received_conflicting_request(REQUEST *request,
					 const RADCLIENT *client)
{
	radlog(L_ERR, "Received conflicting packet from "
	       "client %s port %d - ID: %d due to unfinished request %d.  Giving up on old request.",
	       client->shortname,
	       request->packet->src_port, request->packet->id,
	       request->number);

	/*
	 *	Nuke it from the request hash, so we can receive new
	 *	packets.
	 */
	remove_from_request_hash(request);

	switch (request->child_state) {
		/*
		 *	It's queued or running.  Tell it to stop, and
		 *	wait for it to do so.
		 */
	case REQUEST_QUEUED:
	case REQUEST_RUNNING:
		request->master_state = REQUEST_STOP_PROCESSING;
		request->delay += request->delay >> 1;

		tv_add(&request->when, request->delay);

		INSERT_EVENT(wait_for_child_to_die, request);
		return;

		/*
		 *	It's in some other state, and therefore also
		 *	in the event queue.  At some point, the
		 *	child will notice, and we can then delete it.
		 */
	default:
		rad_assert(request->ev != NULL);
		break;
	}
}


static int can_handle_new_request(RADIUS_PACKET *packet,
				  RADCLIENT *client,
				  struct main_config_t *root)
{
	/*
	 *	Count the total number of requests, to see if
	 *	there are too many.  If so, return with an
	 *	error.
	 */
	if (root->max_requests) {
		int request_count = fr_packet_list_num_elements(pl);

		/*
		 *	This is a new request.  Let's see if
		 *	it makes us go over our configured
		 *	bounds.
		 */
		if (request_count > root->max_requests) {
			radlog(L_ERR, "Dropping request (%d is too many): "
			       "from client %s port %d - ID: %d", request_count,
			       client->shortname,
			       packet->src_port, packet->id);
			radlog(L_INFO, "WARNING: Please check the configuration file.\n"
			       "\tThe value for 'max_requests' is probably set too low.\n");
			return 0;
		} /* else there were a small number of requests */
	} /* else there was no configured limit for requests */

	/*
	 *	FIXME: Add per-client checks.  If one client is sending
	 *	too many packets, start discarding them.
	 *
	 *	We increment the counters here, and decrement them
	 *	when the response is sent... somewhere in this file.
	 */

	/*
	 *	FUTURE: Add checks for system load.  If the system is
	 *	busy, start dropping requests...
	 *
	 *	We can probably keep some statistics ourselves...  if
	 *	there are more requests coming in than we can handle,
	 *	start dropping some.
	 */

	return 1;
}


int received_request(rad_listen_t *listener,
		     RADIUS_PACKET *packet, REQUEST **prequest,
		     RADCLIENT *client)
{
	RADIUS_PACKET **packet_p;
	REQUEST *request = NULL;
	struct main_config_t *root = &mainconfig;

	packet_p = fr_packet_list_find(pl, packet);
	if (packet_p) {
		request = fr_packet2myptr(REQUEST, packet, packet_p);
		rad_assert(request->in_request_hash);

		if ((request->packet->data_len == packet->data_len) &&
		    (memcmp(request->packet->vector, packet->vector,
			    sizeof(packet->vector)) == 0)) {
			received_retransmit(request, client);
			return 0;
		}

		/*
		 *	The new request is different from the old one,
		 *	but maybe the old is finished.  If so, delete
		 *	the old one.
		 */
		switch (request->child_state) {
			struct timeval when;

		default:
			gettimeofday(&when, NULL);
			when.tv_sec -= 1;

			/*
			 *	If the cached request was received
			 *	within the last second, then we
			 *	discard the NEW request instead of the
			 *	old one.  This will happen ONLY when
			 *	the client is severely broken, and is
			 *	sending conflicting packets very
			 *	quickly.
			 */
			if (timercmp(&when, &request->received, <)) {
				radlog(L_ERR, "Discarding conflicting packet from "
				       "client %s port %d - ID: %d due to recent request %d.",
				       client->shortname,
				       packet->src_port, packet->id,
				       request->number);
				return 0;
			}

			received_conflicting_request(request, client);
			request = NULL;
			break;

		case REQUEST_REJECT_DELAY:
		case REQUEST_CLEANUP_DELAY:
			request->child_state = REQUEST_DONE;
		case REQUEST_DONE:
			cleanup_delay(request);
			request = NULL;
			break;
		}
	}

	/*
	 *	We may want to quench the new request.
	 */
	if ((listener->type != RAD_LISTEN_DETAIL) &&
	    !can_handle_new_request(packet, client, root)) {
		return 0;
	}

	/*
	 *	Create and initialize the new request.
	 */
	request = request_alloc(); /* never fails */

	if ((request->reply = rad_alloc(0)) == NULL) {
		radlog(L_ERR, "No memory");
		exit(1);
	}

	request->listener = listener;
	request->client = client;
	request->packet = packet;
	request->packet->timestamp = request->timestamp;
	request->number = request_num_counter++;
	request->priority = listener->type;

	/*
	 *	Set virtual server identity
	 */
	if (client->server) {
		request->server = client->server;
	} else if (listener->server) {
		request->server = listener->server;
	} else {
		request->server = NULL;
	}

	/*
	 *	Remember the request in the list.
	 */
	if (!fr_packet_list_insert(pl, &request->packet)) {
		radlog(L_ERR, "Failed to insert request %d in the list of live requests: discarding", request->number);
		request_free(&request);
		return 0;
	}

	request->in_request_hash = TRUE;
	request->root = root;
	root->refcount++;

	/*
	 *	The request passes many of our sanity checks.
	 *	From here on in, if anything goes wrong, we
	 *	send a reject message, instead of dropping the
	 *	packet.
	 */

	/*
	 *	Build the reply template from the request.
	 */

	request->reply->sockfd = request->packet->sockfd;
	request->reply->dst_ipaddr = request->packet->src_ipaddr;
	request->reply->src_ipaddr = request->packet->dst_ipaddr;
	request->reply->dst_port = request->packet->src_port;
	request->reply->src_port = request->packet->dst_port;
	request->reply->id = request->packet->id;
	request->reply->code = 0; /* UNKNOWN code */
	memcpy(request->reply->vector, request->packet->vector,
	       sizeof(request->reply->vector));
	request->reply->vps = NULL;
	request->reply->data = NULL;
	request->reply->data_len = 0;

	request->master_state = REQUEST_ACTIVE;
	request->child_state = REQUEST_QUEUED;
	request->next_callback = NULL;

	gettimeofday(&request->received, NULL);
	request->timestamp = request->received.tv_sec;
	request->when = request->received;

	request->delay = USEC;

	tv_add(&request->when, request->delay);

	INSERT_EVENT(wait_a_bit, request);

	*prequest = request;
	return 1;
}


REQUEST *received_proxy_response(RADIUS_PACKET *packet)
{
	char		buffer[128];
	home_server	*home;
	REQUEST		*request;

	if (!home_server_find(&packet->src_ipaddr, packet->src_port)) {
		radlog(L_ERR, "Ignoring request from unknown home server %s port %d",
		       inet_ntop(packet->src_ipaddr.af,
				 &packet->src_ipaddr.ipaddr,
				 buffer, sizeof(buffer)),
			       packet->src_port);
		rad_free(&packet);
		return NULL;
	}

	/*
	 *	Also removes from the proxy hash if responses == requests
	 */
	request = lookup_in_proxy_hash(packet);

	if (!request) {
		radlog(L_PROXY, "No outstanding request was found for proxy reply from home server %s port %d - ID %d",
		       inet_ntop(packet->src_ipaddr.af,
				 &packet->src_ipaddr.ipaddr,
				 buffer, sizeof(buffer)),
		       packet->src_port, packet->id);
		rad_free(&packet);
		return NULL;
	}

	home = request->home_server;

	gettimeofday(&now, NULL);
	home->state = HOME_STATE_ALIVE;

	if (request->reply && request->reply->code != 0) {
		DEBUG2("We already replied to this request.  Discarding response from home server.");
		rad_free(&packet);
		return NULL;
	}

	/*
	 *	We had previously received a reply, so we don't need
	 *	to do anything here.
	 */
	if (request->proxy_reply) {
		if (memcmp(request->proxy_reply->vector,
			   packet->vector,
			   sizeof(request->proxy_reply->vector)) == 0) {
			DEBUG2("Discarding duplicate reply from home server %s port %d  - ID: %d for request %d",
			       inet_ntop(packet->src_ipaddr.af,
					 &packet->src_ipaddr.ipaddr,
					 buffer, sizeof(buffer)),
			       packet->src_port, packet->id,
			       request->number);
		} else {
			/*
			 *	? The home server gave us a new proxy
			 *	reply, which doesn't match the old
			 *	one.  Delete it.
			 */
			DEBUG2("Ignoring conflicting proxy reply");
		}

		/* assert that there's an event queued for request? */
		rad_free(&packet);
		return NULL;
	}

	switch (request->child_state) {
	case REQUEST_QUEUED:
	case REQUEST_RUNNING:
		rad_panic("Internal sanity check failed for child state");
		break;

	case REQUEST_REJECT_DELAY:
	case REQUEST_CLEANUP_DELAY:
	case REQUEST_DONE:
		radlog(L_ERR, "Reply from home server %s port %d  - ID: %d arrived too late for request %d. Try increasing 'retry_delay' or 'max_request_time'",
		       inet_ntop(packet->src_ipaddr.af,
				 &packet->src_ipaddr.ipaddr,
				 buffer, sizeof(buffer)),
		       packet->src_port, packet->id,
		       request->number);
		/* assert that there's an event queued for request? */
		rad_free(&packet);
		return NULL;

	case REQUEST_PROXIED:
		break;
	}

	request->proxy_reply = packet;

#if 0
	/*
	 *	Perform RTT calculations, as per RFC 2988 (for TCP).
	 *	Note that we do so only if we sent one request, and
	 *	received one response.  If we sent two requests, we
	 *	have no idea if the response is for the first, or for
	 *	the second request/
	 */
	if (request->num_proxied_requests == 1) {
		int rtt;
		home_server *home = request->home_server;

		rtt = now.tv_sec - request->proxy_when.tv_sec;
		rtt *= USEC;
		rtt += now.tv_usec;
		rtt -= request->proxy_when.tv_usec;

		if (!home->has_rtt) {
			home->has_rtt = TRUE;

			home->srtt = rtt;
			home->rttvar = rtt / 2;

		} else {
			home->rttvar -= home->rttvar >> 2;
			home->rttvar += (home->srtt - rtt);
			home->srtt -= home->srtt >> 3;
			home->srtt += rtt >> 3;
		}

		home->rto = home->srtt;
		if (home->rttvar > (USEC / 4)) {
			home->rto += home->rttvar * 4;
		} else {
			home->rto += USEC;
		}
	}
#endif

	/*
	 *	There's no incoming request, so it's a proxied packet
	 *	we originated.
	 */
	if (!request->packet) {
		received_response_to_ping(request);
		return NULL;
	}

	request->child_state = REQUEST_QUEUED;
	request->when = now;
	request->delay = USEC;
	request->priority = RAD_LISTEN_PROXY;
	tv_add(&request->when, request->delay);

	/*
	 *	Wait a bit will take care of max_request_time
	 */
	INSERT_EVENT(wait_a_bit, request);

	return request;
}


static void event_detail_timer(void *ctx)
{
	rad_listen_t *listener = ctx;
	RAD_REQUEST_FUNP fun;
	REQUEST *request;

	if (listener->recv(listener, &fun, &request)) {
		if (!thread_pool_addrequest(request, fun)) {
			request->child_state = REQUEST_DONE;
		}
	}
}

static void handle_signal_self(int flag)
{
	if ((flag & (RADIUS_SIGNAL_SELF_EXIT | RADIUS_SIGNAL_SELF_TERM)) != 0) {
		if ((flag & RADIUS_SIGNAL_SELF_EXIT) != 0) {
			fr_event_loop_exit(el, 1);
		} else {
			fr_event_loop_exit(el, 2);
		}

		return;
	} /* else exit/term flags weren't set */

	/*
	 *	Tell the even loop to stop processing.
	 */
	if ((flag & RADIUS_SIGNAL_SELF_HUP) != 0) {
		time_t when;
		static time_t last_hup = 0;

		DEBUG("Received HUP signal.");

		when = time(NULL);
		if ((int) (when - last_hup) < 5) {
			radlog(L_INFO, "Ignoring HUP (less than 5s since last one)");
			return;
		}
		last_hup = when;

		fr_event_loop_exit(el, 0x80);
	}

	if ((flag & RADIUS_SIGNAL_SELF_DETAIL) != 0) {
		rad_listen_t *this;
		
		for (this = mainconfig.listen;
		     this != NULL;
		     this = this->next) {
			int delay;
			struct timeval when;

			if (this->type != RAD_LISTEN_DETAIL) continue;
			
			delay = detail_delay(this);
			if (!delay) continue;

			fr_event_now(el, &now);
			when = now;
			tv_add(&when, delay);

			if (delay > 100000) {
				DEBUG2("Delaying next detail event for %d.%01u seconds.",
				       delay / USEC, (delay % USEC) / 100000);
			}

			if (!fr_event_insert(el, event_detail_timer, this,
					     &when, NULL)) {
				radlog(L_ERR, "Failed remembering timer");
				exit(1);
			}
		}
	}

	if ((flag & RADIUS_SIGNAL_SELF_NEW_FD) != 0) {
		rad_listen_t *this;
		
		for (this = mainconfig.listen;
		     this != NULL;
		     this = this->next) {
			if (this->type != RAD_LISTEN_PROXY) continue;
			
			if (!fr_event_fd_insert(el, 0, this->fd,
						event_socket_handler, this)) {
				radlog(L_ERR, "Failed remembering handle for proxy socket!");
				exit(1);
			}
		}
	}
}

#ifdef __MINGW32__
void radius_signal_self(int flag)
{
	handle_signal_self(flag);
}
#else
/*
 *	Inform ourselves that we received a signal.
 */
void radius_signal_self(int flag)
{
	ssize_t rcode;
	uint8_t buffer[16];

	/*
	 *	The read MUST be non-blocking for this to work.
	 */
	rcode = read(self_pipe[0], buffer, sizeof(buffer));
	if (rcode > 0) {
		ssize_t i;

		for (i = 0; i < rcode; i++) {
			buffer[0] |= buffer[i];
		}
	} else {
		buffer[0] = 0;
	}

	buffer[0] |= flag;

	write(self_pipe[1], buffer, 1);
}


static void event_signal_handler(UNUSED fr_event_list_t *xel,
				 UNUSED int fd, UNUSED void *ctx)
{
	ssize_t i, rcode;
	uint8_t buffer[32];

	rcode = read(self_pipe[0], buffer, sizeof(buffer));
	if (rcode <= 0) return;

	/*
	 *	Merge pending signals.
	 */
	for (i = 0; i < rcode; i++) {
		buffer[0] |= buffer[i];
	}

	handle_signal_self(buffer[0]);
}
#endif


static void event_socket_handler(fr_event_list_t *xel, UNUSED int fd,
				 void *ctx)
{
	rad_listen_t *listener = ctx;
	RAD_REQUEST_FUNP fun;
	REQUEST *request;

	rad_assert(xel == el);

	xel = xel;

	if (listener->fd < 0) rad_panic("Socket was closed on us!");
	
	if (!listener->recv(listener, &fun, &request)) return;

	if (!thread_pool_addrequest(request, fun)) {
		request->child_state = REQUEST_DONE;
	}
}


/*
 *	This function is called periodically to see if any FD's are
 *	available for reading.
 */
static void event_poll_fds(UNUSED void *ctx)
{
	int rcode;
	RAD_REQUEST_FUNP fun;
	REQUEST *request;
	rad_listen_t *this;
	struct timeval when;

	fr_event_now(el, &now);
	when = now;
	when.tv_sec += 1;

	for (this = mainconfig.listen; this != NULL; this = this->next) {
		if (this->fd >= 0) continue;

		/*
		 *	Try to read something.
		 *
		 *	FIXME: This does poll AND receive.
		 */
		rcode = this->recv(this, &fun, &request);
		if (!rcode) continue;
		
		rad_assert(fun != NULL);
		rad_assert(request != NULL);
			
		if (!thread_pool_addrequest(request, fun)) {
			request->child_state = REQUEST_DONE;
		}

		/*
		 *	We have an FD.  Start watching it.
		 */
		if (this->fd >= 0) {
			/*
			 *	... unless it's a detail file.  In
			 *	that case, we rely on the signal to
			 *	self to know when to continue
			 *	processing the detail file.
			 */
			if (this->type == RAD_LISTEN_DETAIL) continue;

			/*
			 *	FIXME: this should be SNMP handler,
			 *	and we should do SOMETHING when the
			 *	fd is closed!
			 */
			if (!fr_event_fd_insert(el, 0, this->fd,
						event_socket_handler, this)) {
				char buffer[256];
				
				this->print(this, buffer, sizeof(buffer));
				rad_panic("Failed creating handler for snmp");
			}
		}
	}

	/*
	 *	Reset the poll.
	 */
	if (!fr_event_insert(el, event_poll_fds, NULL,
			     &when, NULL)) {
		radlog(L_ERR, "Failed creating handler");
		exit(1);
	}
}


static void event_status(struct timeval *wake)
{
#if !defined(HAVE_PTHREAD_H) && defined(WNOHANG)
	int argval;
#endif

	if (debug_flag == 0) {
		if (just_started) {
			radlog(L_INFO, "Ready to process requests.");
			just_started = FALSE;
		}
		return;
	}

	if (!wake) {
		DEBUG("Ready to process requests.");

	} else if ((wake->tv_sec != 0) ||
		   (wake->tv_usec >= 100000)) {
		DEBUG("Waking up in %d.%01u seconds.",
		      (int) wake->tv_sec, (unsigned int) wake->tv_usec / 100000);
	}


	/*
	 *	FIXME: Put this somewhere else, where it isn't called
	 *	all of the time...
	 */

#if !defined(HAVE_PTHREAD_H) && defined(WNOHANG)
	/*
	 *	If there are no child threads, then there may
	 *	be child processes.  In that case, wait for
	 *	their exit status, and throw that exit status
	 *	away.  This helps get rid of zxombie children.
	 */
	while (waitpid(-1, &argval, WNOHANG) > 0) {
		/* do nothing */
	}
#endif

}


/*
 *	Externally-visibly functions.
 */
int radius_event_init(CONF_SECTION *cs, int spawn_flag)
{
	int i;
	int has_snmp_listener = FALSE;
	rad_listen_t *this, *head = NULL;

	if (el) return 0;

	time(&start_time);

	el = fr_event_list_create(event_status);
	if (!el) return 0;

	pl = fr_packet_list_create(0);
	if (!el) return 0;

	request_num_counter = 0;

	/*
	 *	Move all of the thread calls to this file?
	 *
	 *	It may be best for the mutexes to be in this file...
	 */
	have_children = spawn_flag;

	if (mainconfig.proxy_requests) {
		/*
		 *	Create the tree for managing proxied requests and
		 *	responses.
		 */
		proxy_list = fr_packet_list_create(1);
		if (!proxy_list) return 0;

#ifdef HAVE_PTHREAD_H
		if (pthread_mutex_init(&proxy_mutex, NULL) != 0) {
			radlog(L_ERR, "FATAL: Failed to initialize proxy mutex: %s",
			       strerror(errno));
			exit(1);
		}
#endif
	}

	/*
	 *	Just before we spawn the child threads, force the log
	 *	subsystem to re-open the log file for every write.
	 */
	if (spawn_flag) force_log_reopen();

#ifdef HAVE_PTHREAD_H
	if (thread_pool_init(cs, spawn_flag) < 0) {
		exit(1);
	}
#endif

	if (check_config) {
		DEBUG2("%s: #### Skipping IP addresses and Ports ####",
		       mainconfig.name);
		return 1;
	}

#ifndef __MINGW32__
	/*
	 *	Child threads need a pipe to signal us, as do the
	 *	signal handlers.
	 */
	if (pipe(self_pipe) < 0) {
		radlog(L_ERR, "radiusd: Error opening internal pipe: %s",
		       strerror(errno));
		exit(1);
	}
	if (fcntl(self_pipe[0], F_SETFL, O_NONBLOCK | FD_CLOEXEC) < 0) {
		radlog(L_ERR, "radiusd: Error setting internal flags: %s",
		       strerror(errno));
		exit(1);
	}
	if (fcntl(self_pipe[1], F_SETFL, O_NONBLOCK | FD_CLOEXEC) < 0) {
		radlog(L_ERR, "radiusd: Error setting internal flags: %s",
		       strerror(errno));
		exit(1);
	}

	if (!fr_event_fd_insert(el, 0, self_pipe[0],
				  event_signal_handler, el)) {
		radlog(L_ERR, "Failed creating handler for signals");
		exit(1);
	}
#endif

	/*
	 *	Mark the proxy Fd's as unused.
	 */
	for (i = 0; i < 32; i++) proxy_fds[i] = -1;

	DEBUG2("%s: #### Opening IP addresses and Ports ####",
	       mainconfig.name);

	if (listen_init(cs, &head) < 0) {
		_exit(1);
	}
	
	/*
	 *	Add all of the sockets to the event loop.
	 */
	for (this = head;
	     this != NULL;
	     this = this->next) {
		char buffer[256];

		this->print(this, buffer, sizeof(buffer));

		switch (this->type) {
		case RAD_LISTEN_DETAIL:
			DEBUG("Listening on %s", buffer);
			has_detail_listener = TRUE;
			break;

		case RAD_LISTEN_SNMP:
			DEBUG("Listening on SNMP %s", buffer);
			has_snmp_listener = TRUE;
			break;

		case RAD_LISTEN_PROXY:
			rad_assert(proxy_fds[this->fd & 0x1f] == -1);
			rad_assert(proxy_listeners[this->fd & 0x1f] == NULL);
			
			proxy_fds[this->fd & 0x1f] = this->fd;
			proxy_listeners[this->fd & 0x1f] = this;
			if (!fr_packet_list_socket_add(proxy_list,
							 this->fd)) {
				rad_assert(0 == 1);
			}
			/* FALL-THROUGH */

		default:
			DEBUG("Listening on %s", buffer);
			break;
		}

		/*
		 *	The file descriptor isn't ready.  Poll for
		 *	when it will become ready.  This is for SNMP
		 *	and detail file fd's.
		 */
		if (this->fd < 0) {
			continue;
		}

		/*
		 *	The socket is open.  It MUST be a socket,
		 *	as we don't pre-open the detail files (yet).
		 *
		 *	FIXME: if we DO open the detail files automatically,
		 *	then much of this code becomes simpler.
		 */
		if (!fr_event_fd_insert(el, 0, this->fd,
					  event_socket_handler, this)) {
			this->print(this, buffer, sizeof(buffer));
			radlog(L_ERR, "Failed creating handler for socket %s",
			       buffer);
			exit(1);
		}
	}

	if (has_detail_listener || has_snmp_listener) {
		struct timeval when;
		
		gettimeofday(&when, NULL);
		when.tv_sec += 1;
		
		if (!fr_event_insert(el, event_poll_fds, NULL,
				     &when, NULL)) {
			radlog(L_ERR, "Failed creating handler");
			exit(1);
		}
	}

	mainconfig.listen = head;

	return 1;
}


static int request_hash_cb(UNUSED void *ctx, void *data)
{
	REQUEST *request = fr_packet2myptr(REQUEST, packet, data);

	rad_assert(request->in_proxy_hash == FALSE);

	fr_event_delete(el, &request->ev);
	remove_from_request_hash(request);
	request_free(&request);

	return 0;
}


static int proxy_hash_cb(UNUSED void *ctx, void *data)
{
	REQUEST *request = fr_packet2myptr(REQUEST, proxy, data);

	fr_packet_list_yank(proxy_list, request->proxy);
	request->in_proxy_hash = FALSE;

	if (!request->in_request_hash) {
		fr_event_delete(el, &request->ev);
		request_free(&request);
	}

	return 0;
}


void radius_event_free(void)
{
	/*
	 *	FIXME: Stop all threads, or at least check that
	 *	they're all waiting on the semaphore, and the queues
	 *	are empty.
	 */

	/*
	 *	There are requests in the proxy hash that aren't
	 *	referenced from anywhere else.  Remove them first.
	 */
	if (proxy_list) {
		PTHREAD_MUTEX_LOCK(&proxy_mutex);
		fr_packet_list_walk(proxy_list, NULL, proxy_hash_cb);
		PTHREAD_MUTEX_UNLOCK(&proxy_mutex);
		fr_packet_list_free(proxy_list);
		proxy_list = NULL;
	}

	fr_packet_list_walk(pl, NULL, request_hash_cb);

	fr_packet_list_free(pl);
	pl = NULL;

	fr_event_list_free(el);
}

int radius_event_process(void)
{
	if (!el) return 0;

	just_started = TRUE;

	return fr_event_loop(el);
}

void radius_handle_request(REQUEST *request, RAD_REQUEST_FUNP fun)
{
	if (request_pre_handler(request)) {
		rad_assert(fun != NULL);
		rad_assert(request != NULL);
		
		if (request->server) DEBUG("server %s {",
					     request->server); 
		fun(request);

		if (request->server) DEBUG("} # server %s",
					     request->server);

		request_post_handler(request);
	}

	DEBUG2("Going to the next request");
	return;
}
