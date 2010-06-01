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
extern char *debug_condition;

/*
 *	Ridiculous amounts of local state.
 */
static fr_event_list_t	*el = NULL;
static fr_packet_list_t	*pl = NULL;
static int			request_num_counter = 0;
static struct timeval		now;
time_t				fr_start_time;
static int			have_children;
static int			just_started = TRUE;

#ifndef __MINGW32__
#ifdef HAVE_PTHREAD_H
#define WITH_SELF_PIPE (1)
#endif
#endif

#ifdef WITH_SELF_PIPE
static int self_pipe[2];
#endif

#ifdef HAVE_PTHREAD_H
#ifdef WITH_PROXY
static pthread_mutex_t	proxy_mutex;
static rad_listen_t *proxy_listener_list = NULL;
static int proxy_no_new_sockets = FALSE;
#endif

#define PTHREAD_MUTEX_LOCK if (have_children) pthread_mutex_lock
#define PTHREAD_MUTEX_UNLOCK if (have_children) pthread_mutex_unlock

static pthread_t NO_SUCH_CHILD_PID;
#else
/*
 *	This is easier than ifdef's throughout the code.
 */
#define PTHREAD_MUTEX_LOCK(_x)
#define PTHREAD_MUTEX_UNLOCK(_x)
#endif

/*
 *	We need mutexes around the event FD list *only* in certain
 *	cases.
 */
#if defined (HAVE_PTHREAD_H) && (defined(WITH_PROXY) || defined(WITH_TCP))
static pthread_mutex_t	fd_mutex;
#define FD_MUTEX_LOCK if (have_children) pthread_mutex_lock
#define FD_MUTEX_UNLOCK if (have_children) pthread_mutex_unlock
#else
/*
 *	This is easier than ifdef's throughout the code.
 */
#define FD_MUTEX_LOCK(_x)
#define FD_MUTEX_UNLOCK(_x)
#endif


#define INSERT_EVENT(_function, _ctx) if (!fr_event_insert(el, _function, _ctx, &((_ctx)->when), &((_ctx)->ev))) { _rad_panic(__FILE__, __LINE__, "Failed to insert event"); }

#ifdef WITH_PROXY
static fr_packet_list_t *proxy_list = NULL;
static void remove_from_proxy_hash(REQUEST *request);

static void check_for_zombie_home_server(REQUEST *request);
#else
#define remove_from_proxy_hash(foo)
#endif

static void request_post_handler(REQUEST *request);
static void wait_a_bit(void *ctx);
static void event_socket_handler(fr_event_list_t *xel, UNUSED int fd, void *ctx);
#ifdef WITH_DETAIL
static void event_poll_detail(void *ctx);
#endif

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
		tv->tv_sec += tv->tv_usec / USEC;
		tv->tv_usec %= USEC;
	}
}

static void remove_from_request_hash(REQUEST *request)
{
	if (!request->in_request_hash) return;

	fr_packet_list_yank(pl, request->packet);
	request->in_request_hash = FALSE;

	request_stats_final(request);

#ifdef WITH_TCP
	request->listener->count--;
#endif
}

static void ev_request_free(REQUEST **prequest)
{
	REQUEST *request;
	
	if (!prequest || !*prequest) return;

	request = *prequest;

#ifdef WITH_COA
	if (request->coa) {
		/*
		 *	Divorce the child from the parent first,
		 *	then clean up the child.
		 */
		request->coa->parent = NULL;
		ev_request_free(&request->coa);
	}

	/*
	 *	Divorce the parent from the child, and leave the
	 *	parent still alive.
	 */
	if (request->parent && (request->parent->coa == request)) {
		request->parent->coa = NULL;
	}
#endif

	if (request->ev) fr_event_delete(el, &request->ev);
#ifdef WITH_PROXY
	if (request->in_proxy_hash) remove_from_proxy_hash(request);
#endif
	if (request->in_request_hash) remove_from_request_hash(request);

	request_free(prequest);
}

#ifdef WITH_PROXY
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
	request->num_proxied_responses++; /* needs to be protected by lock */

	PTHREAD_MUTEX_UNLOCK(&proxy_mutex);

	return request;
}


static void remove_from_proxy_hash(REQUEST *request)
{
	/*
	 *	Check this without grabbing the mutex because it's a
	 *	lot faster that way.
	 */
	if (!request->in_proxy_hash) return;

	/*
	 *	The "not in hash" flag is definitive.  However, if the
	 *	flag says that it IS in the hash, there might still be
	 *	a race condition where it isn't.
	 */
	PTHREAD_MUTEX_LOCK(&proxy_mutex);

	if (!request->in_proxy_hash) {
		PTHREAD_MUTEX_UNLOCK(&proxy_mutex);
		return;
	}

	fr_packet_list_yank(proxy_list, request->proxy);
	fr_packet_list_id_free(proxy_list, request->proxy);

	/*
	 *	On the FIRST reply, decrement the count of outstanding
	 *	requests.  Note that this is NOT the count of sent
	 *	packets, but whether or not the home server has
	 *	responded at all.
	 */
	if (!request->proxy_reply &&
	    request->home_server &&
	    request->home_server->currently_outstanding) {
		request->home_server->currently_outstanding--;
	}

#ifdef WITH_TCP
	request->proxy_listener->count--;
	request->proxy_listener = NULL;
#endif

	/*
	 *	Got from YES in hash, to NO, not in hash while we hold
	 *	the mutex.  This guarantees that when another thread
	 *	grabs the mutex, the "not in hash" flag is correct.
	 */
	request->in_proxy_hash = FALSE;

  	PTHREAD_MUTEX_UNLOCK(&proxy_mutex);
}
#endif	/* WITH_PROXY */

#ifdef WITH_TCP
static int remove_all_requests(void *ctx, void *data)
{
	rad_listen_t *this = ctx;
	RADIUS_PACKET **packet_p = data;
	REQUEST *request;
	
	request = fr_packet2myptr(REQUEST, packet, packet_p);
	if (request->packet->sockfd != this->fd) return 0;

	switch (request->child_state) {
	case REQUEST_RUNNING:
		rad_assert(request->ev != NULL); /* or it's lost forever */
	case REQUEST_QUEUED:
		request->master_state = REQUEST_STOP_PROCESSING;
		return 0;

		/*
		 *	Waiting for a reply.  There's no point in
		 *	doing anything else.  We remove it from the
		 *	request hash so that we can close the upstream
		 *	socket.
		 */
	case REQUEST_PROXIED:
		remove_from_request_hash(request);
		request->child_state = REQUEST_DONE;
		return 0;

	case REQUEST_REJECT_DELAY:
	case REQUEST_CLEANUP_DELAY:
	case REQUEST_DONE:
		ev_request_free(&request);
		break;
	}

	return 0;
}

#ifdef WITH_PROXY
static int remove_all_proxied_requests(void *ctx, void *data)
{
	rad_listen_t *this = ctx;
	RADIUS_PACKET **proxy_p = data;
	REQUEST *request;
	
	request = fr_packet2myptr(REQUEST, proxy, proxy_p);
	if (request->proxy->sockfd != this->fd) return 0;

	switch (request->child_state) {
	case REQUEST_RUNNING:
		rad_assert(request->ev != NULL); /* or it's lost forever */
	case REQUEST_QUEUED:
		request->master_state = REQUEST_STOP_PROCESSING;
		return 0;

		/*
		 *	Eventually we will discover that there is no
		 *	response to the proxied request.
		 */
	case REQUEST_PROXIED:
		break;

		/*
		 *	Keep it in the cache for duplicate detection.
		 */
	case REQUEST_REJECT_DELAY:
	case REQUEST_CLEANUP_DELAY:
	case REQUEST_DONE:
		break;
	}

	remove_from_proxy_hash(request);
	return 0;
}
#endif	/* WITH_PROXY */
#endif	/* WITH_TCP */


#ifdef WITH_PROXY
static int insert_into_proxy_hash(REQUEST *request)
{
	char buf[128];
	int rcode, tries;
	void *proxy_listener;

	rad_assert(request->proxy != NULL);
	rad_assert(proxy_list != NULL);

	tries = 1;
retry:
	PTHREAD_MUTEX_LOCK(&proxy_mutex);
	rcode = fr_packet_list_id_alloc(proxy_list,
					request->home_server->proto,
					request->proxy, &proxy_listener);
	request->num_proxied_requests = 1;
	request->num_proxied_responses = 0;
	PTHREAD_MUTEX_UNLOCK(&proxy_mutex);
	
	if (!rcode) {
		if (proxy_no_new_sockets) return 0;

		/*
		 *	Also locks the proxy mutex, so we have to call
		 *	it with the mutex unlocked.  Some systems
		 *	don't support recursive mutexes.
		 */
		if (!proxy_new_listener(request->home_server, 0)) {
			radlog(L_ERR, "Failed to create a new socket for proxying requests.");
			return 0;
		}
		request->proxy->src_port = 0; /* Use any new socket */

		tries++;
		if (tries > 2) {
			RDEBUG2("ERROR: Failed allocating Id for new socket when proxying requests.");
			return 0;
		}
		
		goto retry;
	}

	request->proxy_listener = proxy_listener;

	PTHREAD_MUTEX_LOCK(&proxy_mutex);
	if (!fr_packet_list_insert(proxy_list, &request->proxy)) {
		fr_packet_list_id_free(proxy_list, request->proxy);
		PTHREAD_MUTEX_UNLOCK(&proxy_mutex);
		radlog(L_PROXY, "Failed to insert entry into proxy list");
		return 0;
	}

	request->in_proxy_hash = TRUE;

	/*
	 *	Keep track of maximum outstanding requests to a
	 *	particular home server.  'max_outstanding' is
	 *	enforced in home_server_ldb(), in realms.c.
	 */
	if (request->home_server) {
		request->home_server->currently_outstanding++;
	}

#ifdef WITH_TCP
	request->proxy_listener->count++;
#endif

	PTHREAD_MUTEX_UNLOCK(&proxy_mutex);

	RDEBUG3(" proxy: allocating destination %s port %d - Id %d",
	       inet_ntop(request->proxy->dst_ipaddr.af,
			 &request->proxy->dst_ipaddr.ipaddr, buf, sizeof(buf)),
	       request->proxy->dst_port,
	       request->proxy->id);

	return 1;
}


/*
 *	Called as BOTH an event, and in-line from other functions.
 */
static void wait_for_proxy_id_to_expire(void *ctx)
{
	REQUEST *request = ctx;

	rad_assert(request->magic == REQUEST_MAGIC);
	rad_assert(request->proxy != NULL);

	fr_event_now(el, &now);
	request->when = request->proxy_when;

#ifdef WITH_COA
	if (((request->proxy->code == PW_COA_REQUEST) ||
	     (request->proxy->code == PW_DISCONNECT_REQUEST)) &&
	    (request->packet->code != request->proxy->code)) {
		request->when.tv_sec += request->home_server->coa_mrd;
	} else
#endif
	request->when.tv_sec += request->home_server->response_window;

	if ((request->num_proxied_requests == request->num_proxied_responses) ||
#ifdef WITH_TCP
	    (request->home_server->proto == IPPROTO_TCP) ||
#endif
	    timercmp(&now, &request->when, >)) {
		if (request->packet) {
			RDEBUG2("Cleaning up request packet ID %d with timestamp +%d",
			       request->packet->id,
			       (unsigned int) (request->timestamp - fr_start_time));
		} else {
			RDEBUG2("Cleaning up request with timestamp +%d",
			       (unsigned int) (request->timestamp - fr_start_time));
		}

		ev_request_free(&request);
		return;
	}

	INSERT_EVENT(wait_for_proxy_id_to_expire, request);
}
#endif

#ifdef HAVE_PTHREAD_H
static void wait_for_child_to_die(void *ctx)
{
	REQUEST *request = ctx;

	rad_assert(request->magic == REQUEST_MAGIC);

	/*
	 *	If it's still queued (waiting for a thread to pick it
	 *	up) OR, it's running AND there's still a child thread
	 *	handling it, THEN delay some more.
	 */
	if ((request->child_state == REQUEST_QUEUED) ||
	    ((request->child_state == REQUEST_RUNNING) &&
	     (pthread_equal(request->child_pid, NO_SUCH_CHILD_PID) == 0))) {

		/*
		 *	Cap delay at five minutes.
		 */
		if (request->delay < (USEC * 60 * 5)) {
			request->delay += (request->delay >> 1);
			radlog_request(L_INFO, 0, request, "WARNING: Child is hung in component %s module %s.",
			       request->component, request->module);
		} else {
			RDEBUG2("Child is still stuck");
		}
		tv_add(&request->when, request->delay);

		INSERT_EVENT(wait_for_child_to_die, request);
		return;
	}

	RDEBUG2("Child is finally responsive");
	remove_from_request_hash(request);

#ifdef WITH_PROXY
	if (request->proxy) {
		wait_for_proxy_id_to_expire(request);
		return;
	}
#endif

	ev_request_free(&request);
}
#endif

static void cleanup_delay(void *ctx)
{
	REQUEST *request = ctx;

	rad_assert(request->magic == REQUEST_MAGIC);
	rad_assert((request->child_state == REQUEST_CLEANUP_DELAY) ||
		   (request->child_state == REQUEST_DONE));

	remove_from_request_hash(request);

#ifdef WITH_PROXY
	if (request->proxy && request->in_proxy_hash) {
		wait_for_proxy_id_to_expire(request);
		return;
	}
#endif

	RDEBUG2("Cleaning up request packet ID %d with timestamp +%d",
	        request->packet->id,
	       (unsigned int) (request->timestamp - fr_start_time));

	ev_request_free(&request);
}


/*
 *	In daemon mode, AND this request has debug flags set.
 */
#define DEBUG_PACKET if (!debug_flag && request->options && request->radlog) debug_packet

static void debug_packet(REQUEST *request, RADIUS_PACKET *packet, int direction)
{
	VALUE_PAIR *vp;
	char buffer[1024];
	const char *received, *from;
	const fr_ipaddr_t *ip;
	int port;

	if (!packet) return;

	rad_assert(request->radlog != NULL);

	if (direction == 0) {
		received = "Received";
		from = "from";	/* what else? */
		ip = &packet->src_ipaddr;
		port = packet->src_port;

	} else {
		received = "Sending";
		from = "to";	/* hah! */
		ip = &packet->dst_ipaddr;
		port = packet->dst_port;
	}
	
	/*
	 *	Client-specific debugging re-prints the input
	 *	packet into the client log.
	 *
	 *	This really belongs in a utility library
	 */
	if ((packet->code > 0) && (packet->code < FR_MAX_PACKET_CODE)) {
		RDEBUG("%s %s packet %s host %s port %d, id=%d, length=%d",
		       received, fr_packet_codes[packet->code], from,
		       inet_ntop(ip->af, &ip->ipaddr, buffer, sizeof(buffer)),
		       port, packet->id, packet->data_len);
	} else {
		RDEBUG("%s packet %s host %s port %d code=%d, id=%d, length=%d",
		       received, from,
		       inet_ntop(ip->af, &ip->ipaddr, buffer, sizeof(buffer)),
		       port,
		       packet->code, packet->id, packet->data_len);
	}

	for (vp = packet->vps; vp != NULL; vp = vp->next) {
		vp_prints(buffer, sizeof(buffer), vp);
		request->radlog(L_DBG, 0, request, "\t%s", buffer);
	}
}

static void reject_delay(void *ctx)
{
	REQUEST *request = ctx;

	rad_assert(request->magic == REQUEST_MAGIC);
	rad_assert(request->child_state == REQUEST_REJECT_DELAY);

	RDEBUG2("Sending delayed reject");

	DEBUG_PACKET(request, request->reply, 1);

	request->listener->send(request->listener, request);

	request->when.tv_sec += request->root->cleanup_delay;
	request->child_state = REQUEST_CLEANUP_DELAY;

	INSERT_EVENT(cleanup_delay, request);
}


#ifdef WITH_PROXY
void revive_home_server(void *ctx)
{
	home_server *home = ctx;
	char buffer[128];

#ifdef WITH_TCP
	rad_assert(home->proto != IPPROTO_TCP);
#endif

	home->state = HOME_STATE_ALIVE;
	home->currently_outstanding = 0;
	home->revive_time = now;

	/*
	 *	Delete any outstanding events.
	 */
	if (home->ev) fr_event_delete(el, &home->ev);

	radlog(L_PROXY, "Marking home server %s port %d alive again... we have no idea if it really is alive or not.",
	       inet_ntop(home->ipaddr.af, &home->ipaddr.ipaddr,
			 buffer, sizeof(buffer)),
	       home->port);

}


static void no_response_to_ping(void *ctx)
{
	REQUEST *request = ctx;
	home_server *home;
	char buffer[128];

	rad_assert(request->home_server != NULL);

	home = request->home_server;
#ifdef WITH_TCP
	rad_assert(home->proto != IPPROTO_TCP);
#endif

	home->num_received_pings = 0;

	radlog(L_ERR, "No response to status check %d for home server %s port %d",
	       request->number,
	       inet_ntop(request->proxy->dst_ipaddr.af,
			 &request->proxy->dst_ipaddr.ipaddr,
			 buffer, sizeof(buffer)),
	       request->proxy->dst_port);

	check_for_zombie_home_server(request);

	wait_for_proxy_id_to_expire(request);
}


/*
 *	Note that we don't care what the value of the code field is.
 *	If the response has a valid (src ip/port, dst ip/port), id,
 *	and correctly signed Message-Authenticator, that's good
 *	enough.
 */
static void received_response_to_ping(REQUEST *request)
{
	home_server *home;
	char buffer[128];

	rad_assert(request->home_server != NULL);

	home = request->home_server;
#ifdef WITH_TCP
	rad_assert(home->proto != IPPROTO_TCP);
#endif

	home->num_received_pings++;

	radlog(L_PROXY, "Received response to status check %d (%d in current sequence)",
	       request->number, home->num_received_pings);

	/*
	 *	Remove the request from any hashes
	 */
	fr_event_delete(el, &request->ev);
	remove_from_proxy_hash(request);
	rad_assert(request->in_request_hash == FALSE);

	/*
	 *	The control socket may have marked the home server as
	 *	alive.  OR, it may have suddenly started responding to
	 *	requests again.  If so, don't re-do the "make alive"
	 *	work.
	 */
	if (home->state == HOME_STATE_ALIVE) return;

	/*
	 *	We haven't received enough ping responses to mark it
	 *	"alive".  Wait a bit.
	 */
	if (home->num_received_pings < home->num_pings_to_alive) {
		return;
	}

	home->state = HOME_STATE_ALIVE;
	home->currently_outstanding = 0;
	home->revive_time = now;

	if (!fr_event_delete(el, &home->ev)) {
		RDEBUG2("Hmm... no event for home server.  Oh well.");
	}

	radlog(L_PROXY, "Marking home server %s port %d alive",
	       inet_ntop(request->proxy->dst_ipaddr.af,
			 &request->proxy->dst_ipaddr.ipaddr,
			 buffer, sizeof(buffer)),
	       request->proxy->dst_port);
}


/*
 *	Called from start of zombie period, OR after control socket
 *	marks the home server dead.
 */
static void ping_home_server(void *ctx)
{
	uint32_t jitter;
	home_server *home = ctx;
	REQUEST *request;
	VALUE_PAIR *vp;

#ifdef WITH_TCP
	rad_assert(home->proto != IPPROTO_TCP);
#endif

	if ((home->state == HOME_STATE_ALIVE) ||
	    (home->ping_check == HOME_PING_CHECK_NONE) ||
	    (home->ev != NULL)) {
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
#ifdef WITH_ACCOUNTING
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
#else
		rad_assert("Internal sanity check failed");
#endif
	}

	radius_pairmake(request, &request->proxy->vps,
			"NAS-Identifier", "Status Check. Are you alive?",
			T_OP_SET);

	request->proxy->dst_ipaddr = home->ipaddr;
	request->proxy->dst_port = home->port;
	request->home_server = home;

	rad_assert(request->proxy_listener == NULL);

	if (!insert_into_proxy_hash(request)) {
		radlog(L_PROXY, "Failed inserting status check %d into proxy hash.  Discarding it.",
		       request->number);
		ev_request_free(&request);
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


void mark_home_server_dead(home_server *home, struct timeval *when)
{
	int previous_state = home->state;
	char buffer[128];

	radlog(L_PROXY, "Marking home server %s port %d as dead.",
	       inet_ntop(home->ipaddr.af, &home->ipaddr.ipaddr,
			 buffer, sizeof(buffer)),
	       home->port);

	home->state = HOME_STATE_IS_DEAD;
	home->num_received_pings = 0;

	if (home->ping_check != HOME_PING_CHECK_NONE) {
		/*
		 *	If the control socket marks us dead, start
		 *	pinging.  Otherwise, we already started
		 *	pinging when it was marked "zombie".
		 */
		if (previous_state == HOME_STATE_ALIVE) {
			ping_home_server(home);
		}

	} else {
		/*
		 *	Revive it after a fixed period of time.  This
		 *	is very, very, bad.
		 */
		home->when = *when;
		home->when.tv_sec += home->revive_interval;

		INSERT_EVENT(revive_home_server, home);
	}
}

static void check_for_zombie_home_server(REQUEST *request)
{
	home_server *home;
	struct timeval when;

	home = request->home_server;

	if (home->state != HOME_STATE_ZOMBIE) return;

	when = home->zombie_period_start;
	when.tv_sec += home->zombie_period;

	fr_event_now(el, &now);
	if (timercmp(&now, &when, <)) {
		return;
	}

	mark_home_server_dead(home, &request->when);
}

static int proxy_to_virtual_server(REQUEST *request);

static int virtual_server_handler(UNUSED REQUEST *request)
{
	proxy_to_virtual_server(request);
	return 0;
}

static void proxy_fallback_handler(REQUEST *request)
{
	/*
	 *	A proper time is required for wait_a_bit.
	 */
	request->delay = USEC / 10;
	gettimeofday(&now, NULL);
	request->next_when = now;
	tv_add(&request->next_when, request->delay);
	request->next_callback = wait_a_bit;

	/*
	 *	Re-queue the request.
	 */
	request->child_state = REQUEST_QUEUED;
	
	rad_assert(request->proxy != NULL);
	thread_pool_addrequest(request, virtual_server_handler);

#ifdef HAVE_PTHREAD_H
	/*
	 *	MAY free the request if we're over max_request_time,
	 *	AND we're not in threaded mode!
	 *
	 *	Note that we call this ONLY if we're threaded, as
	 *	if we're NOT threaded, request_post_handler() calls
	 *	wait_a_bit(), which means that "request" may not
	 *	exist any more...
	 */
	if (have_children) wait_a_bit(request);
#endif
}


static int setup_post_proxy_fail(REQUEST *request)
{
	DICT_VALUE *dval = NULL;
	VALUE_PAIR *vp;

	request->child_state = REQUEST_RUNNING;

	if (request->packet->code == PW_AUTHENTICATION_REQUEST) {
	  dval = dict_valbyname(PW_POST_PROXY_TYPE, 0, "Fail-Authentication");

	} else if (request->packet->code == PW_ACCOUNTING_REQUEST) {
		dval = dict_valbyname(PW_POST_PROXY_TYPE, 0, "Fail-Accounting");

#ifdef WITH_COA
		/*
		 *	See no_response_to_coa_request
		 */
	} else if (((request->packet->code >> 8) & 0xff) == PW_COA_REQUEST) {
		request->packet->code &= 0xff; /* restore it */

		if (request->proxy->code == PW_COA_REQUEST) {
			dval = dict_valbyname(PW_POST_PROXY_TYPE, 0, "Fail-CoA");

		} else if (request->proxy->code == PW_DISCONNECT_REQUEST) {
			dval = dict_valbyname(PW_POST_PROXY_TYPE, 0, "Fail-Disconnect");
		} else {
			return 0;
		}

#endif
	} else {
		return 0;
	}

	if (!dval) dval = dict_valbyname(PW_POST_PROXY_TYPE, 0, "Fail");

	if (!dval) {
		pairdelete(&request->config_items, PW_POST_PROXY_TYPE, 0);
		return 0;
	}

	vp = pairfind(request->config_items, PW_POST_PROXY_TYPE, 0);
	if (!vp) vp = radius_paircreate(request, &request->config_items,
					PW_POST_PROXY_TYPE, 0, PW_TYPE_INTEGER);
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
	 *
	 *	Note that we call this ONLY if we're threaded, as
	 *	if we're NOT threaded, request_post_handler() calls
	 *	wait_a_bit(), which means that "request" may not
	 *	exist any more...
	 */
	if (have_children) wait_a_bit(request);
}

/* maybe check this against wait_for_proxy_id_to_expire? */
static void no_response_to_proxied_request(void *ctx)
{
	REQUEST *request = ctx;
	home_server *home;
	char buffer[128];

	rad_assert(request->magic == REQUEST_MAGIC);

	if (request->master_state == REQUEST_STOP_PROCESSING) {
		ev_request_free(&request);
		return;
	}

	rad_assert(request->child_state == REQUEST_PROXIED);

	/*
	 *	If we've failed over to an internal home server,
	 *	replace the callback with the correct one.  This
	 *	is due to locking issues with child threads...
	 */
	if (request->home_server->server) {
		wait_a_bit(request);
		return;
	}

#ifdef WITH_TCP
	if (request->home_server->proto != IPPROTO_TCP)
#endif
		check_for_zombie_home_server(request);

	home = request->home_server;

	/*
	 *	The default as of 2.1.7 is to allow requests to
	 *	fail-over to a backup home server when this one does
	 *	not respond.  The old behavior can be configured as
	 *	well.
	 */
	if (home->no_response_fail) {
		radlog_request(L_ERR, 0, request, "Rejecting request (proxy Id %d) due to lack of any response from home server %s port %d",
		       request->proxy->id,
		       inet_ntop(request->proxy->dst_ipaddr.af,
				 &request->proxy->dst_ipaddr.ipaddr,
				 buffer, sizeof(buffer)),
		       request->proxy->dst_port);

		post_proxy_fail_handler(request);
	} else {
		/*
		 *	Enforce max_request_time.
		 *
		 *	We fail over to another backup home server
		 *	when the client re-transmits the request.  If
		 *	the client doesn't re-transmit, no fail-over
		 *	occurs.
		 */
		rad_assert(request->ev == NULL);
		request->child_state = REQUEST_RUNNING;
		wait_a_bit(request);
	}

	/*
	 *	Don't touch request due to race conditions
	 */

#ifdef WITH_TCP
	/*
	 *	Do nothing more.  The home server didn't respond,
	 *	but that isn't a catastrophic failure.  Some home
	 *	servers don't respond to packets...
	 */
	if (home->proto == IPPROTO_TCP) {
		/*
		 *	FIXME: Set up TCP pinging on this connection.
		 *
		 *	Maybe the CONNECTION is dead, but the home
		 *	server is alive.  In that case, we need to start
		 *	pinging on the connection.
		 *
		 *	This means doing the pinging BEFORE the
		 *	post_proxy_fail_handler above, as it may do
		 *	something with the request, and cause the
		 *	proxy listener to go away!
		 */
		return;
	}
#endif

	if (home->state == HOME_STATE_IS_DEAD) {
		rad_assert(home->ev != NULL); /* or it will never wake up */
		return;
	}

	/*
	 *	Enable the zombie period when we notice that the home
	 *	server hasn't responded.  We do NOT back-date the start
	 *	of the zombie period.
	 */
	if (home->state == HOME_STATE_ALIVE) {
		home->state = HOME_STATE_ZOMBIE;
		home->zombie_period_start = now;	
		fr_event_delete(el, &home->ev);
		home->currently_outstanding = 0;
		home->num_received_pings = 0;

		radlog(L_PROXY, "Marking home server %s port %d as zombie (it looks like it is dead).",
		       inet_ntop(home->ipaddr.af, &home->ipaddr.ipaddr,
				 buffer, sizeof(buffer)),
		       home->port);

		/*
		 *	Start pinging the home server.
		 */
		ping_home_server(home);
	}
}
#endif

static void wait_a_bit(void *ctx)
{
	struct timeval when;
	REQUEST *request = ctx;
	fr_event_callback_t callback = NULL;

	rad_assert(request->magic == REQUEST_MAGIC);

	/*
	 *	The socket was closed.  Tell the request that
	 *	there is no point in continuing.
	 */
	if (request->listener->status != RAD_LISTEN_STATUS_KNOWN) {
		goto stop_processing;
	}

#ifdef WITH_COA
	/*
	 *	The CoA request is a new (internally generated)
	 *	request, created in a child thread.  We therefore need
	 *	some way to tie its events back into the main event
	 *	handler.
	 */
	if (request->coa && !request->coa->proxy_reply &&
	    request->coa->next_callback) {
		request->coa->when = request->coa->next_when;
		INSERT_EVENT(request->coa->next_callback, request->coa);
		request->coa->next_callback = NULL;
		request->coa->parent = NULL;
		request->coa = NULL;
	}
#endif

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

#ifdef WITH_DETAIL
			/*
			 *	Cap wait at some sane value for detail
			 *	files.
			 */
			if ((request->listener->type == RAD_LISTEN_DETAIL) &&
			    (request->delay > (request->root->max_request_time * USEC))) {
				request->delay = request->root->max_request_time * USEC;
			}
#endif

			request->when = now;
			tv_add(&request->when, request->delay);
			callback = wait_a_bit;
			break;
		}

	stop_processing:
#if defined(HAVE_PTHREAD_H)
		/*
		 *	A child thread MAY still be running on the
		 *	request.  Ask the thread to stop working on
		 *	the request.
		 */
		if (have_children &&
		    (pthread_equal(request->child_pid, NO_SUCH_CHILD_PID) == 0)) {
			request->master_state = REQUEST_STOP_PROCESSING;

			radlog_request(L_ERR, 0, request, "WARNING: Unresponsive child in module %s component %s",
			       request->module ? request->module : "<server core>",
			       request->component ? request->component : "<server core>");
			
			request->delay = USEC / 4;
			tv_add(&request->when, request->delay);
			callback = wait_for_child_to_die;
			break;
		}
#endif

		/*
		 *	Else no child thread is processing the
		 *	request.  We probably should have just marked
		 *	the request as 'done' elsewhere, like in the
		 *	post-proxy-fail handler.  But doing that would
		 *	involve checking for max_request_time in
		 *	multiple places, so this may be simplest.
		 */
		request->child_state = REQUEST_DONE;
		/* FALL-THROUGH */

		/*
		 *	Mark the request as no longer running,
		 *	and clean it up.
		 */
	case REQUEST_DONE:
#ifdef HAVE_PTHREAD_H
		request->child_pid = NO_SUCH_CHILD_PID;
#endif

#ifdef WITH_COA
		/*
		 *	This is a CoA request.  It's been divorced
		 *	from everything else, so we clean it up now.
		 */
		if (!request->in_request_hash &&
		    request->proxy &&
		    (request->packet->code != request->proxy->code) &&
		    ((request->proxy->code == PW_COA_REQUEST) ||
		     (request->proxy->code == PW_DISCONNECT_REQUEST))) {
			/*
			 *	FIXME: Do CoA MIBs
			 */
			ev_request_free(&request);
			return;
		}
#endif
		request_stats_final(request);
		cleanup_delay(request);
		return;

	case REQUEST_REJECT_DELAY:
	case REQUEST_CLEANUP_DELAY:
#ifdef HAVE_PTHREAD_H
		request->child_pid = NO_SUCH_CHILD_PID;
#endif
		request_stats_final(request);

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
		RDEBUG("WARNING: Internal sanity check failed in event handler: Discarding the request!");
		ev_request_free(&request);
		return;
	}

	INSERT_EVENT(callback, request);
}

#ifdef WITH_COA
static void no_response_to_coa_request(void *ctx)
{
	REQUEST *request = ctx;
	char buffer[128];

	rad_assert(request->magic == REQUEST_MAGIC);
	rad_assert(request->child_state == REQUEST_PROXIED);
	rad_assert(request->home_server != NULL);
	rad_assert(!request->in_request_hash);

	radlog(L_ERR, "No response to CoA request sent to %s",
	       inet_ntop(request->proxy->dst_ipaddr.af,
			 &request->proxy->dst_ipaddr.ipaddr,
			 buffer, sizeof(buffer)));

	/*
	 *	Hack.
	 */
	request->packet->code |= (PW_COA_REQUEST << 8);
	post_proxy_fail_handler(request);
}


static int update_event_timestamp(RADIUS_PACKET *packet, time_t when)
{
	VALUE_PAIR *vp;

	vp = pairfind(packet->vps, PW_EVENT_TIMESTAMP, 0);
	if (!vp) return 0;

	vp->vp_date = when;

	if (packet->data) {
		free(packet->data);
		packet->data = NULL;
		packet->data_len = 0;
	}

	return 1;		/* time stamp updated */
}


/*
 *	Called when we haven't received a response to a CoA request.
 */
static void retransmit_coa_request(void *ctx)
{
	int delay, frac;
	struct timeval mrd;
	REQUEST *request = ctx;

	rad_assert(request->magic == REQUEST_MAGIC);
	rad_assert(request->child_state == REQUEST_PROXIED);
	rad_assert(request->home_server != NULL);
	rad_assert(!request->in_request_hash);
	rad_assert(request->parent == NULL);
	
	fr_event_now(el, &now);

	/*
	 *	Cap count at MRC, if it is non-zero.
	 */
	if (request->home_server->coa_mrc &&
	    (request->num_coa_requests >= request->home_server->coa_mrc)) {
		no_response_to_coa_request(request);
		return;
	}

	/*
	 *	RFC 5080 Section 2.2.1
	 *
	 *	RT = 2*RTprev + RAND*RTprev
	 *	   = 1.9 * RTprev + rand(0,.2) * RTprev
	 *	   = 1.9 * RTprev + rand(0,1) * (RTprev / 5)
	 */
	delay = fr_rand();
	delay ^= (delay >> 16);
	delay &= 0xffff;
	frac = request->delay / 5;
	delay = ((frac >> 16) * delay) + (((frac & 0xffff) * delay) >> 16);

	delay += (2 * request->delay) - (request->delay / 10);

	/*
	 *	Cap delay at MRT, if MRT is non-zero.
	 */
	if (request->home_server->coa_mrt &&
	    (delay > (request->home_server->coa_mrt * USEC))) {
		int mrt_usec = request->home_server->coa_mrt * USEC;

		/*
		 *	delay = MRT + RAND * MRT
		 *	      = 0.9 MRT + rand(0,.2)  * MRT
		 */
		delay = fr_rand();
		delay ^= (delay >> 15);
		delay &= 0x1ffff;
		delay = ((mrt_usec >> 16) * delay) + (((mrt_usec & 0xffff) * delay) >> 16);
		delay += mrt_usec - (mrt_usec / 10);
	}

	request->delay = delay;
	request->when = now;
	tv_add(&request->when, request->delay);
	mrd = request->proxy_when;
	mrd.tv_sec += request->home_server->coa_mrd;

	/*
	 *	Cap duration at MRD.
	 */
	if (timercmp(&mrd, &request->when, <)) {
		request->when = mrd;
		INSERT_EVENT(no_response_to_coa_request, request);

	} else {
		INSERT_EVENT(retransmit_coa_request, request);
	}
	
	if (update_event_timestamp(request->proxy, now.tv_sec)) {
		/*
		 *	Keep a copy of the old Id so that the
		 *	re-transmitted request doesn't re-use the old
		 *	Id.
		 */
		RADIUS_PACKET old = *request->proxy;
		home_server *home = request->home_server;
		rad_listen_t *listener = request->proxy_listener;

		/*
		 *	Don't free the old Id on error.
		 */
		if (!insert_into_proxy_hash(request)) {
			radlog(L_PROXY,"Failed re-inserting CoA request into proxy hash.");
			return;
		}

		/*
		 *	Now that we have a new Id, free the old one
		 *	and update the various statistics.
		 */
		PTHREAD_MUTEX_LOCK(&proxy_mutex);
		fr_packet_list_yank(proxy_list, &old);
		fr_packet_list_id_free(proxy_list, &old);
		if (home) home->currently_outstanding--;
#ifdef WITH_TCP
		if (listener) listener->count--;
#endif
		PTHREAD_MUTEX_UNLOCK(&proxy_mutex);

	} else {		/* FIXME: protect by a mutex? */
		request->num_proxied_requests++;
	}

	request->num_coa_requests++; /* is NOT reset by code 3 lines above! */

	request->proxy_listener->send(request->proxy_listener,
				      request);
}


/*
 *	The original request is either DONE, or in CLEANUP_DELAY.
 */
static int originated_coa_request(REQUEST *request)
{
	int delay, rcode, pre_proxy_type = 0;
	VALUE_PAIR *vp;
	REQUEST *coa;
	fr_ipaddr_t ipaddr;
	char buffer[256];

	rad_assert(request->proxy == NULL);
	rad_assert(!request->in_proxy_hash);
	rad_assert(request->proxy_reply == NULL);

	/*
	 *	Check whether we want to originate one, or cancel one.
	 */
	vp = pairfind(request->config_items, PW_SEND_COA_REQUEST, 0);
	if (!vp && request->coa) {
		vp = pairfind(request->coa->proxy->vps, PW_SEND_COA_REQUEST, 0);
	}

	if (vp) {
		if (vp->vp_integer == 0) {
			ev_request_free(&request->coa);
			return 1;	/* success */
		}
	}

	if (!request->coa) request_alloc_coa(request);
	if (!request->coa) return 0;

	coa = request->coa;

	/*
	 *	src_ipaddr will be set up in proxy_encode.
	 */
	memset(&ipaddr, 0, sizeof(ipaddr));
	vp = pairfind(coa->proxy->vps, PW_PACKET_DST_IP_ADDRESS, 0);
	if (vp) {
		ipaddr.af = AF_INET;
		ipaddr.ipaddr.ip4addr.s_addr = vp->vp_ipaddr;

	} else if ((vp = pairfind(coa->proxy->vps,
				  PW_PACKET_DST_IPV6_ADDRESS, 0)) != NULL) {
		ipaddr.af = AF_INET6;
		ipaddr.ipaddr.ip6addr = vp->vp_ipv6addr;
		
	} else if ((vp = pairfind(coa->proxy->vps,
				  PW_HOME_SERVER_POOL, 0)) != NULL) {
		coa->home_pool = home_pool_byname(vp->vp_strvalue,
						  HOME_TYPE_COA);
		if (!coa->home_pool) {
			RDEBUG2("WARNING: No such home_server_pool %s",
			       vp->vp_strvalue);
	fail:
			ev_request_free(&request->coa);
			return 0;
		}

		/*
		 *	Prefer
		 */
	} else if (request->client->coa_pool) {
		coa->home_pool = request->client->coa_pool;

	} else if (request->client->coa_server) {
		coa->home_server = request->client->coa_server;

	} else {
		/*
		 *	If all else fails, send it to the client that
		 *	originated this request.
		 */
		memcpy(&ipaddr, &request->packet->src_ipaddr, sizeof(ipaddr));
	}

	/*
	 *	Use the pool, if it exists.
	 */
	if (coa->home_pool) {
		coa->home_server = home_server_ldb(NULL, coa->home_pool, coa);
		if (!coa->home_server) {
			RDEBUG("WARNING: No live home server for home_server_pool %s", vp->vp_strvalue);
			goto fail;
		}

	} else if (!coa->home_server) {
		int port = PW_COA_UDP_PORT;

		vp = pairfind(coa->proxy->vps, PW_PACKET_DST_PORT, 0);
		if (vp) port = vp->vp_integer;

		coa->home_server = home_server_find(&ipaddr, port, IPPROTO_UDP);
		if (!coa->home_server) {
			RDEBUG2("WARNING: Unknown destination %s:%d for CoA request.",
			       inet_ntop(ipaddr.af, &ipaddr.ipaddr,
					 buffer, sizeof(buffer)), port);
			goto fail;
		}
	}

	vp = pairfind(coa->proxy->vps, PW_PACKET_TYPE, 0);
	if (vp) {
		switch (vp->vp_integer) {
		case PW_COA_REQUEST:
		case PW_DISCONNECT_REQUEST:
			coa->proxy->code = vp->vp_integer;
			break;
			
		default:
			DEBUG("Cannot set CoA Packet-Type to code %d",
			      vp->vp_integer);
			goto fail;
		}
	}

	if (!coa->proxy->code) coa->proxy->code = PW_COA_REQUEST;

	/*
	 *	The rest of the server code assumes that
	 *	request->packet && request->reply exist.  Copy them
	 *	from the original request.
	 */
	rad_assert(coa->packet != NULL);
	rad_assert(coa->packet->vps == NULL);
	memcpy(coa->packet, request->packet, sizeof(*request->packet));
	coa->packet->vps = paircopy(request->packet->vps);
	coa->packet->data = NULL;
	rad_assert(coa->reply != NULL);
	rad_assert(coa->reply->vps == NULL);
	memcpy(coa->reply, request->reply, sizeof(*request->reply));
	coa->reply->vps = paircopy(request->reply->vps);
	coa->reply->data = NULL;
	coa->config_items = paircopy(request->config_items);

	/*
	 *	Call the pre-proxy routines.
	 */
	vp = pairfind(request->config_items, PW_PRE_PROXY_TYPE, 0);
	if (vp) {
		RDEBUG2("  Found Pre-Proxy-Type %s", vp->vp_strvalue);
		pre_proxy_type = vp->vp_integer;
	}

	if (coa->home_pool && coa->home_pool->virtual_server) {
		const char *old_server = coa->server;
		
		coa->server = coa->home_pool->virtual_server;
		RDEBUG2(" server %s {", coa->server);
		rcode = module_pre_proxy(pre_proxy_type, coa);
		RDEBUG2(" }");
		coa->server = old_server;
	} else {
		rcode = module_pre_proxy(pre_proxy_type, coa);
	}
	switch (rcode) {
	default:
		goto fail;

	/*
	 *	Only send the CoA packet if the pre-proxy code succeeded.
	 */
	case RLM_MODULE_NOOP:
	case RLM_MODULE_OK:
	case RLM_MODULE_UPDATED:
		break;
	}

	/*
	 *	Source IP / port is set when the proxy socket
	 *	is chosen.
	 */
	coa->proxy->dst_ipaddr = coa->home_server->ipaddr;
	coa->proxy->dst_port = coa->home_server->port;

	if (!insert_into_proxy_hash(coa)) {
		radlog(L_PROXY, "Failed inserting CoA request into proxy hash.");
		goto fail;
	}

	/*
	 *	We CANNOT divorce the CoA request from the parent
	 *	request.  This function is running in a child thread,
	 *	and we need access to the main event loop in order to
	 *	to add the timers for the CoA packet.  See
	 *	wait_a_bit().
	 */

	/*
	 *	Forget about the original request completely at this
	 *	point.
	 */
	request = coa;

	gettimeofday(&request->proxy_when, NULL);	
	request->received = request->next_when = request->proxy_when;
	rad_assert(request->proxy_reply == NULL);

	/*
	 *	Implement re-transmit algorithm as per RFC 5080
	 *	Section 2.2.1.
	 *
	 *	We want IRT + RAND*IRT
	 *	or 0.9 IRT + rand(0,.2) IRT
	 *
	 *	2^20 ~ USEC, and we want 2.
	 *	rand(0,0.2) USEC ~ (rand(0,2^21) / 10)
	 */
	delay = (fr_rand() & ((1 << 22) - 1)) / 10;
	request->delay = delay * request->home_server->coa_irt;
	delay = request->home_server->coa_irt * USEC;
	delay -= delay / 10;
	delay += request->delay;
     
	request->delay = delay;
	tv_add(&request->next_when, delay);
	request->next_callback = retransmit_coa_request;
	
	/*
	 *	Note that we set proxied BEFORE sending the packet.
	 *
	 *	Once we send it, the request is tainted, as
	 *	another thread may have picked it up.  Don't
	 *	touch it!
	 */
	request->child_pid = NO_SUCH_CHILD_PID;

	update_event_timestamp(request->proxy, request->proxy_when.tv_sec);

	request->child_state = REQUEST_PROXIED;

	DEBUG_PACKET(request, request->proxy, 1);

	request->proxy_listener->send(request->proxy_listener,
				      request);
	return 1;
}
#endif	/* WITH_COA */

#ifdef WITH_PROXY
static int process_proxy_reply(REQUEST *request)
{
	int rcode;
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
	vp = pairfind(request->config_items, PW_POST_PROXY_TYPE, 0);
	if (vp) {
		RDEBUG2("  Found Post-Proxy-Type %s", vp->vp_strvalue);
		post_proxy_type = vp->vp_integer;
	}
	
	if (request->home_pool && request->home_pool->virtual_server) {
		const char *old_server = request->server;
		
		request->server = request->home_pool->virtual_server;
		RDEBUG2(" server %s {", request->server);
		rcode = module_post_proxy(post_proxy_type, request);
		RDEBUG2(" }");
		request->server = old_server;
	} else {
		rcode = module_post_proxy(post_proxy_type, request);
	}

#ifdef WITH_COA
	if (request->packet->code == request->proxy->code)
	  /*
	   *	Don't run the next bit if we originated a CoA
	   *	packet, after receiving an Access-Request or
	   *	Accounting-Request.
	   */
#endif
	
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
		pairdelete(&request->proxy_reply->vps, PW_PROXY_STATE, 0);
		
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

	return 1;
}
#endif

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
					     PW_USER_NAME, 0);
		request->password = pairfind(request->packet->vps,
					     PW_USER_PASSWORD, 0);
		return 1;
	}

#ifdef WITH_PROXY
	/*
	 *	Put the decoded packet into it's proper place.
	 */
	if (request->proxy_reply != NULL) {
		rcode = request->proxy_listener->decode(request->proxy_listener, request);
		DEBUG_PACKET(request, request->proxy_reply, 0);

		/*
		 *	Pro-actively remove it from the proxy hash.
		 *	This is later than in 2.1.x, but it means that
		 *	the replies are authenticated before being
		 *	removed from the hash.
		 */
		if ((rcode == 0) &&
		    (request->num_proxied_requests <= request->num_proxied_responses)) {
			remove_from_proxy_hash(request);
		}

	} else
#endif
	if (request->packet->vps == NULL) {
		rcode = request->listener->decode(request->listener, request);
		
		if (debug_condition) {
			int result = FALSE;
			const char *my_debug = debug_condition;

			/*
			 *	Ignore parse errors.
			 */
			radius_evaluate_condition(request, RLM_MODULE_OK, 0,
						  &my_debug, 1,
						  &result);
			if (result) {
				request->options = 2;
				request->radlog = radlog_request;
			}
		}
		
		DEBUG_PACKET(request, request->packet, 0);
	} else {
		rcode = 0;
	}

	if (rcode < 0) {
		RDEBUG("%s Dropping packet without response.", fr_strerror());
		request->reply->offset = -2; /* bad authenticator */
		request->child_state = REQUEST_DONE;
		return 0;
	}

	if (!request->username) {
		request->username = pairfind(request->packet->vps,
					     PW_USER_NAME, 0);
	}

#ifdef WITH_PROXY
	if (request->proxy) {
		return process_proxy_reply(request);
#endif
	}

	return 1;
}


#ifdef WITH_PROXY
/*
 *	Do state handling when we proxy a request.
 */
static int proxy_request(REQUEST *request)
{
	struct timeval when;
	char buffer[128];

#ifdef WITH_COA
	if (request->coa) {
		RDEBUG("WARNING: Cannot proxy and originate CoA packets at the same time.  Cancelling CoA request");
		ev_request_free(&request->coa);
	}
#endif

	if (request->home_server->server) {
		RDEBUG("ERROR: Cannot perform real proxying to a virtual server.");
		return 0;
	}

	if (!insert_into_proxy_hash(request)) {
		radlog(L_PROXY, "Failed inserting request into proxy hash.");
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

	RDEBUG2("Proxying request to home server %s port %d",
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
#ifdef HAVE_PTHREAD_H
	request->child_pid = NO_SUCH_CHILD_PID;
#endif
	request->child_state = REQUEST_PROXIED;

	DEBUG_PACKET(request, request->proxy, 1);

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
	RAD_REQUEST_FUNP fun;

	if (!request->home_server || !request->home_server->server) return 0;

	if (request->parent) {
		RDEBUG2("WARNING: Cancelling proxy request to virtual server %s as this request was itself proxied.", request->home_server->server);
		return 0;
	}

	fake = request_alloc_fake(request);
	if (!fake) {
		RDEBUG2("WARNING: Out of memory");
		return 0;
	}

	fake->packet->vps = paircopy(request->proxy->vps);
	fake->server = request->home_server->server;

	if (request->proxy->code == PW_AUTHENTICATION_REQUEST) {
		fun = rad_authenticate;

#ifdef WITH_ACCOUNTING
	} else if (request->proxy->code == PW_ACCOUNTING_REQUEST) {
		fun = rad_accounting;
#endif

	} else {
		RDEBUG2("Unknown packet type %d", request->proxy->code);
		ev_request_free(&fake);
		return 0;
	}

	RDEBUG2(">>> Sending proxied request internally to virtual server.");
	radius_handle_request(fake, fun);
	RDEBUG2("<<< Received proxied response code %d from internal virtual server.", fake->reply->code);

	if (fake->reply->code != 0) {
		request->proxy_reply = fake->reply;
		fake->reply = NULL;
	} else {
		/*
		 *	There was no response
		 */
		setup_post_proxy_fail(request);
	}

	ev_request_free(&fake);

	process_proxy_reply(request);

	/*
	 *	Process it through the normal section again, but ONLY
	 *	if we received a proxy reply..
	 */
	if (request->proxy_reply) {
		if (request->server) RDEBUG("server %s {",
					    request->server != NULL ?
					    request->server : ""); 
		fun(request);
		
		if (request->server) RDEBUG("} # server %s",
					    request->server != NULL ?
					    request->server : "");
	}

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
	char *realmname = NULL;
	home_server *home;
	REALM *realm = NULL;
	home_pool_t *pool;

	/*
	 *	If it was already proxied, do nothing.
	 *
	 *	FIXME: This should really be a serious error.
	 */
	if (request->in_proxy_hash ||
	    (request->proxy_reply && (request->proxy_reply->code != 0))) {
		return 0;
	}

	realmpair = pairfind(request->config_items, PW_PROXY_TO_REALM, 0);
	if (!realmpair || (realmpair->length == 0)) {
		int pool_type;

		vp = pairfind(request->config_items, PW_HOME_SERVER_POOL, 0);
		if (!vp) return 0;

		switch (request->packet->code) {
		case PW_AUTHENTICATION_REQUEST:
			pool_type = HOME_TYPE_AUTH;
			break;

#ifdef WITH_ACCOUNTING
		case PW_ACCOUNTING_REQUEST:
			pool_type = HOME_TYPE_ACCT;
			break;
#endif

#ifdef WITH_COA
		case PW_COA_REQUEST:
		case PW_DISCONNECT_REQUEST:
			pool_type = HOME_TYPE_COA;
			break;
#endif

		default:
			return 0;
		}

		pool = home_pool_byname(vp->vp_strvalue, pool_type);
		if (!pool) {
			RDEBUG2("ERROR: Cannot proxy to unknown pool %s",
				vp->vp_strvalue);
			return 0;
		}

		realmname = NULL; /* no realms */
		realm = NULL;
		goto found_pool;
	}

	realmname = (char *) realmpair->vp_strvalue;

	realm = realm_find2(realmname);
	if (!realm) {
		RDEBUG2("ERROR: Cannot proxy to unknown realm %s", realmname);
		return 0;
	}

	/*
	 *	Figure out which pool to use.
	 */
	if (request->packet->code == PW_AUTHENTICATION_REQUEST) {
		pool = realm->auth_pool;

#ifdef WITH_ACCOUNTING
	} else if (request->packet->code == PW_ACCOUNTING_REQUEST) {
		pool = realm->acct_pool;
#endif

#ifdef WITH_COA
	} else if ((request->packet->code == PW_COA_REQUEST) ||
		   (request->packet->code == PW_DISCONNECT_REQUEST)) {
		pool = realm->acct_pool;
#endif

	} else {
		rad_panic("Internal sanity check failed");
	}

	if (!pool) {
		RDEBUG2(" WARNING: Cancelling proxy to Realm %s, as the realm is local.",
		       realmname);
		return 0;
	}

found_pool:
	home = home_server_ldb(realmname, pool, request);
	if (!home) {
		RDEBUG2("ERROR: Failed to find live home server for realm %s",
		       realmname);
		return -1;
	}
	request->home_pool = pool;

#ifdef WITH_COA
	/*
	 *	Once we've decided to proxy a request, we cannot send
	 *	a CoA packet.  So we free up any CoA packet here.
	 */
	ev_request_free(&request->coa);
#endif
	/*
	 *	Remember that we sent the request to a Realm.
	 */
	if (realmname) pairadd(&request->packet->vps,
			       pairmake("Realm", realmname, T_OP_EQ));

	/*
	 *	Strip the name, if told to.
	 *
	 *	Doing it here catches the case of proxied tunneled
	 *	requests.
	 */
	if (realm && (realm->striprealm == TRUE) &&
	   (strippedname = pairfind(request->proxy->vps, PW_STRIPPED_USER_NAME, 0)) != NULL) {
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
		vp = pairfind(request->proxy->vps, PW_USER_NAME, 0);
		if (!vp) {
			vp = radius_paircreate(request, NULL,
					       PW_USER_NAME, 0, PW_TYPE_STRING);
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
	if ((request->packet->code == PW_AUTHENTICATION_REQUEST) &&
	    pairfind(request->proxy->vps, PW_CHAP_PASSWORD, 0) &&
	    pairfind(request->proxy->vps, PW_CHAP_CHALLENGE, 0) == NULL) {
		vp = radius_paircreate(request, &request->proxy->vps,
				       PW_CHAP_CHALLENGE, 0, PW_TYPE_OCTETS);
		vp->length = AUTH_VECTOR_LEN;
		memcpy(vp->vp_strvalue, request->packet->vector, AUTH_VECTOR_LEN);
	}

	/*
	 *	The RFC's say we have to do this, but FreeRADIUS
	 *	doesn't need it.
	 */
	vp = radius_paircreate(request, &request->proxy->vps,
			       PW_PROXY_STATE, 0, PW_TYPE_OCTETS);
	snprintf(vp->vp_strvalue, sizeof(vp->vp_strvalue), "%d",
		 request->packet->id);
	vp->length = strlen(vp->vp_strvalue);

	/*
	 *	Should be done BEFORE inserting into proxy hash, as
	 *	pre-proxy may use this information, or change it.
	 */
	request->proxy->code = request->packet->code;

	/*
	 *	Call the pre-proxy routines.
	 */
	vp = pairfind(request->config_items, PW_PRE_PROXY_TYPE, 0);
	if (vp) {
		RDEBUG2("  Found Pre-Proxy-Type %s", vp->vp_strvalue);
		pre_proxy_type = vp->vp_integer;
	}

	rad_assert(request->home_pool != NULL);

	if (request->home_pool->virtual_server) {
		const char *old_server = request->server;
		
		request->server = request->home_pool->virtual_server;
		RDEBUG2(" server %s {", request->server);
		rcode = module_pre_proxy(pre_proxy_type, request);
		RDEBUG2(" }");
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
		RDEBUG("ERROR: Failed to proxy request");
		return -1;
	}
	
	return 1;
}
#endif

static void request_post_handler(REQUEST *request)
{
	int child_state = -1;
	struct timeval when;
	VALUE_PAIR *vp;

	if ((request->master_state == REQUEST_STOP_PROCESSING) ||
	    (request->parent &&
	     (request->parent->master_state == REQUEST_STOP_PROCESSING))) {
		RDEBUG2("request was cancelled.");
#ifdef HAVE_PTHREAD_H
		request->child_pid = NO_SUCH_CHILD_PID;
#endif
		child_state = REQUEST_DONE;
		goto cleanup;
	}

	if (request->child_state != REQUEST_RUNNING) {
		rad_panic("Internal sanity check failed");
	}

#ifdef WITH_COA
	/*
	 *	If it's not in the request hash, it's a CoA request.
	 *	We hope.
	 */
	if (!request->in_request_hash &&
	    request->proxy &&
	    ((request->proxy->code == PW_COA_REQUEST) ||
	     (request->proxy->code == PW_DISCONNECT_REQUEST))) {
		request->next_callback = NULL;
		child_state = REQUEST_DONE;
		goto cleanup;
	}
#endif

	/*
	 *	Catch Auth-Type := Reject BEFORE proxying the packet.
	 */
	if ((request->packet->code == PW_AUTHENTICATION_REQUEST) &&
	    (request->reply->code == 0) &&
	    ((vp = pairfind(request->config_items, PW_AUTH_TYPE, 0)) != NULL) &&
	    (vp->vp_integer == PW_AUTHTYPE_REJECT)) {
		request->reply->code = PW_AUTHENTICATION_REJECT;
	}

#ifdef WITH_PROXY
	if (request->root->proxy_requests &&
	    !request->in_proxy_hash &&
	    (request->reply->code == 0) &&
	    (request->packet->dst_port != 0) &&
	    (request->packet->code != PW_STATUS_SERVER)) {
		int rcode = successfully_proxied_request(request);

		if (rcode == 1) return; /* request is invalid */

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

#ifdef WITH_COA
	else if (request->proxy && request->coa) {
		RDEBUG("WARNING: Cannot proxy and originate CoA packets at the same time.  Cancelling CoA request");
		ev_request_free(&request->coa);
	}
#endif
#endif

	/*
	 *	Fake requests don't get encoded or signed.  The caller
	 *	also requires the reply VP's, so we don't free them
	 *	here!
	 */
	if (request->packet->dst_port == 0) {
		/* FIXME: RDEBUG going to the next request */
#ifdef HAVE_PTHREAD_H
		request->child_pid = NO_SUCH_CHILD_PID;
#endif
		request->child_state = REQUEST_DONE;
		return;
	}

#ifdef WITH_PROXY
	/*
	 *	Copy Proxy-State from the request to the reply.
	 */
	vp = paircopy2(request->packet->vps, PW_PROXY_STATE, 0);
	if (vp) pairadd(&request->reply->vps, vp);
#endif

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
				      PW_RESPONSE_PACKET_TYPE, 0);
			if (!vp) {
				RDEBUG2("There was no response configured: rejecting request");
				request->reply->code = PW_AUTHENTICATION_REJECT;

			} else if (vp->vp_integer == 256) {
				RDEBUG2("Not responding to request");

				/*
				 *	Force cleanup after a long
				 *	time, so that we don't
				 *	re-process the packet.
				 */
				request->next_when.tv_sec += request->root->max_request_time;
				request->next_callback = cleanup_delay;
				child_state = REQUEST_CLEANUP_DELAY;
				break;
			} else {
				request->reply->code = vp->vp_integer;

			}
		}

		/*
		 *	Run rejected packets through
		 *
		 *	Post-Auth-Type = Reject
		 */
		if (request->reply->code == PW_AUTHENTICATION_REJECT) {
			pairdelete(&request->config_items, PW_POST_AUTH_TYPE, 0);
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
				RDEBUG2("Delaying reject  for %d seconds",
				       request->root->reject_delay);
				request->next_when = when;
				request->next_callback = reject_delay;
#ifdef HAVE_PTHREAD_H
				request->child_pid = NO_SUCH_CHILD_PID;
#endif
				request->child_state = REQUEST_REJECT_DELAY;
				return;
			}
		}

#ifdef WITH_COA
	case PW_COA_REQUEST:
	case PW_DISCONNECT_REQUEST:
#endif
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
		/*
		 *	DHCP, VMPS, etc.
		 */
		request->next_callback = NULL;
		child_state = REQUEST_DONE;
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
		DEBUG_PACKET(request, request->reply, 1);
		request->listener->send(request->listener, request);
	}

#ifdef WITH_COA
	/*
	 *	Now that we've completely processed the request,
	 *	see if we need to originate a CoA request.  But ONLY
	 *	if it wasn't proxied.
	 */
	if (!request->proxy &&
	    (request->coa ||
	     (pairfind(request->config_items, PW_SEND_COA_REQUEST, 0) != NULL))) {
		if (!originated_coa_request(request)) {
			RDEBUG2("Do CoA Fail handler here");
		}
		/* request->coa is stil set, so we can update events */
	}
#endif

 cleanup:
	/*
	 *	Clean up.  These are no longer needed.
	 */
	pairfree(&request->config_items);

	pairfree(&request->packet->vps);
	request->username = NULL;
	request->password = NULL;

	pairfree(&request->reply->vps);

#ifdef WITH_PROXY
	if (request->proxy) {
		pairfree(&request->proxy->vps);

		if (request->proxy_reply) {
			pairfree(&request->proxy_reply->vps);
		}

#if 0
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
#endif
	}
#endif

	RDEBUG2("Finished request.");
	rad_assert(child_state >= 0);
	request->child_state = child_state;

	/*
	 *	Single threaded mode: update timers now.
	 */
	if (!have_children) wait_a_bit(request);
}


static void rad_retransmit_packet(REQUEST *request)
{
	char buffer[256];

#ifdef WITH_TCP
	if (request->home_server->proto == IPPROTO_TCP) {
		DEBUG2("Suppressing duplicate proxied request to home server %s port %d proto TCP - ID: %d",
		       inet_ntop(request->proxy->dst_ipaddr.af,
				 &request->proxy->dst_ipaddr.ipaddr,
				 buffer, sizeof(buffer)),
		       request->proxy->dst_port,
		       request->proxy->id);
		return;		/* don't do anything else */
	}
#endif

	RDEBUG2("Sending duplicate proxied request to home server %s port %d - ID: %d",
		inet_ntop(request->proxy->dst_ipaddr.af,
			  &request->proxy->dst_ipaddr.ipaddr,
			  buffer, sizeof(buffer)),
		request->proxy->dst_port,
		request->proxy->id);
	request->num_proxied_requests++;

	DEBUG_PACKET(request, request->proxy, 1);
	request->proxy_listener->send(request->proxy_listener,
				      request);
}


static int rad_retransmit(REQUEST *request)
{
	/*
	 *	If we've just discovered that the home server
	 *	is dead, OR the socket has been closed, look for
	 *	another connection to a home server.
	 */
	if ((request->home_server->state == HOME_STATE_IS_DEAD) ||
	    (request->proxy_listener->status != RAD_LISTEN_STATUS_KNOWN)) {
		home_server *home;
		
		remove_from_proxy_hash(request);
		
		home = home_server_ldb(NULL, request->home_pool, request);
		if (!home) {
			RDEBUG2("Failed to find live home server for request");
		no_home_servers:
			/*
			 *	Do post-request processing,
			 *	and any insertion of necessary
			 *	events.
			 */
			post_proxy_fail_handler(request);
			return 1;
		}

		request->proxy->code = request->packet->code;

		/*
		 *	Free the old packet, to force re-encoding
		 */
		free(request->proxy->data);
		request->proxy->data = NULL;
		request->proxy->data_len = 0;

		/*
		 *	This request failed over to a virtual
		 *	server.  Push it back onto the queue
		 *	to be processed.
		 */
		if (request->home_server->server) {
			proxy_fallback_handler(request);
			return 1;
		}

		/*
		 *	Try to proxy the request.
		 */
		if (!proxy_request(request)) {
			RDEBUG("ERROR: Failed to re-proxy request");
			goto no_home_servers;
		}
		return 1;
	} /* else the home server is still alive */

	rad_retransmit_packet(request);

	return 1;
}


static void received_retransmit(REQUEST *request, const RADCLIENT *client)
{

	RAD_STATS_TYPE_INC(request->listener, total_dup_requests);
	RAD_STATS_CLIENT_INC(request->listener, client, total_dup_requests);
	
	switch (request->child_state) {
	case REQUEST_QUEUED:
	case REQUEST_RUNNING:
#ifdef WITH_PROXY
	discard:
#endif
		radlog(L_ERR, "Discarding duplicate request from "
		       "client %s port %d - ID: %d due to unfinished request %u",
		       client->shortname,
		       request->packet->src_port,request->packet->id,
		       request->number);
		break;

#ifdef WITH_PROXY
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
		 *
		 *	The same comments go for Status-Server, and
		 *	other packet types.
		 *
		 *	FIXME: coa: when we proxy CoA && Disconnect
		 *	packets, this logic has to be fixed.
		 */
		if (request->packet->code != PW_AUTHENTICATION_REQUEST) {
			goto discard;
		}

		check_for_zombie_home_server(request);

		/*
		 *	Home server is still alive, and the proxy
		 *	socket is OK.  Just re-send the packet.
		 */
		if ((request->home_server->state != HOME_STATE_IS_DEAD) &&
		    (request->proxy_listener->status == RAD_LISTEN_STATUS_KNOWN)) {
			rad_retransmit_packet(request);
			break;
		}

		/*
		 *	Otherwise, we need to fail over to another
		 *	home server, and possibly run "post-proxy-type
		 *	fail".  Add an event waiting for the child to
		 *	have a result.
		 */
		INSERT_EVENT(wait_a_bit, request);

		request->priority = RAD_LISTEN_PROXY;
		thread_pool_addrequest(request, rad_retransmit);
		break;
#endif

	case REQUEST_REJECT_DELAY:
		RDEBUG2("Waiting to send Access-Reject "
		       "to client %s port %d - ID: %d",
		       client->shortname,
		       request->packet->src_port, request->packet->id);
		break;

	case REQUEST_CLEANUP_DELAY:
	case REQUEST_DONE:
		if (request->reply->code == 0) {
			RDEBUG2("Ignoring retransmit from client %s port %d "
				"- ID: %d, no reply was configured",
				client->shortname,
				request->packet->src_port, request->packet->id);
			return;
		}

		/*
		 *	FIXME: This sends duplicate replies to
		 *	accounting requests, even if Acct-Delay-Time
		 *	or Event-Timestamp is in the packet.  In those
		 *	cases, the Id should be changed, and the packet
		 *	re-calculated.
		 */
		RDEBUG2("Sending duplicate reply "
		       "to client %s port %d - ID: %d",
		       client->shortname,
		       request->packet->src_port, request->packet->id);
		DEBUG_PACKET(request, request->reply, 1);
		request->listener->send(request->listener, request);
		break;
	}
}


static void received_conflicting_request(REQUEST *request,
					 const RADCLIENT *client)
{
	radlog(L_ERR, "Received conflicting packet from "
	       "client %s port %d - ID: %d due to unfinished request %u.  Giving up on old request.",
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
		 *	Tell it to stop, and wait for it to do so.
		 */
	default:
		request->master_state = REQUEST_STOP_PROCESSING;
		request->delay += request->delay >> 1;

		tv_add(&request->when, request->delay);

		INSERT_EVENT(wait_for_child_to_die, request);
		return;

		/*
		 *	Catch race conditions.  It may have switched
		 *	from running to done while this code is being
		 *	executed.
		 */
	case REQUEST_REJECT_DELAY:
	case REQUEST_CLEANUP_DELAY:
	case REQUEST_DONE:
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
			/*
			 *	Special hacks for race conditions.
			 *	The reply is encoded, and therefore
			 *	likely sent.  We received a *new*
			 *	packet from the client, likely before
			 *	the next line or two of code which
			 *	updated the child state.  In this
			 *	case, just accept the new request.
			 */
			if ((request->reply->code != 0) &&
			    request->reply->data) {
				radlog(L_INFO, "WARNING: Allowing fast client %s port %d - ID: %d for recent request %u.",
				       client->shortname,
				       packet->src_port, packet->id,
				       request->number);
				remove_from_request_hash(request);
				request = NULL;
				break;
			}

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
				       "client %s port %d - ID: %d due to recent request %u.",
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
		return 0;
	}

	request->listener = listener;
	request->client = client;
	request->packet = packet;
	request->packet->timestamp = request->timestamp;
	request->number = request_num_counter++;
	request->priority = listener->type;
#ifdef HAVE_PTHREAD_H
	request->child_pid = NO_SUCH_CHILD_PID;
#endif

	/*
	 *	Status-Server packets go to the head of the queue.
	 */
	if (request->packet->code == PW_STATUS_SERVER) request->priority = 0;

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
		radlog(L_ERR, "Failed to insert request %u in the list of live requests: discarding", request->number);
		ev_request_free(&request);
		return 0;
	}

	request->in_request_hash = TRUE;
	request->root = root;
	root->refcount++;
#ifdef WITH_TCP
	request->listener->count++;
#endif

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


#ifdef WITH_PROXY
REQUEST *received_proxy_response(RADIUS_PACKET *packet)
{
	char		buffer[128];
	REQUEST		*request;

	/*
	 *	Lookup *without* removal.  In versions prior to 2.2.0,
	 *	this did lookup *and* removal.  That method allowed
	 *	attackers to spoof replies that caused entries to be
	 *	removed from the proxy hash prior to validation.
	 */
	request = lookup_in_proxy_hash(packet);

	if (!request) {
		radlog(L_PROXY, "No outstanding request was found for reply from host %s port %d - ID %d",
		       inet_ntop(packet->src_ipaddr.af,
				 &packet->src_ipaddr.ipaddr,
				 buffer, sizeof(buffer)),
		       packet->src_port, packet->id);
		return NULL;
	}

	/*
	 *	There's a reply: discard it if it's a conflicting one.
	 */
	if (request->proxy_reply) {
		/*
		 *	? The home server gave us a new proxy
		 *	reply which doesn't match the old
		 *	one.  Delete it.
		 */
		if (memcmp(request->proxy_reply->vector,
			   packet->vector,
			   sizeof(request->proxy_reply->vector)) != 0) {
			RDEBUG2("Ignoring conflicting proxy reply");
			
		
			/* assert that there's an event queued for request? */
			return NULL;
		} /* else it had previously passed verification */

		/*
		 *	Verify the packet before doing ANYTHING with
		 *	it.  This means we're doing more MD5 checks in
		 *	the server core.  However, we can fix that by
		 *	moving to multiple threads listening on
		 *	sockets.
		 *
		 *	We do this AFTER looking the request up in the
		 *	hash, and AFTER checking if we saw a previous
		 *	request.  This helps minimize the DoS effect
		 *	of people attacking us with spoofed packets.
		 *
		 *	FIXME: move the "read from proxy socket" code
		 *	into one (or more) threads.  Have it read from
		 *	the socket, do the validation, and write a
		 *	pointer to the packet into a pipe? Or queue it
		 *	to the main server?
		 */
	} else if (rad_verify(packet, request->proxy,
			      request->home_server->secret) != 0) {
		DEBUG("Ignoring spoofed proxy reply.  Signature is invalid");
		return NULL;
	}

	/*
	 *	Check (again) if it's a duplicate reply.  We do this
	 *	after deleting the packet from the proxy hash.
	 */
	if (request->proxy_reply) {
		RDEBUG2("Discarding duplicate reply from host %s port %d  - ID: %d",
			inet_ntop(packet->src_ipaddr.af,
				  &packet->src_ipaddr.ipaddr,
				  buffer, sizeof(buffer)),
			packet->src_port, packet->id);
	}

	gettimeofday(&now, NULL);

	/*
	 *	Maybe move this earlier in the decision process?
	 *	Having it here means that late or duplicate proxy
	 *	replies no longer get the home server marked as
	 *	"alive".  This might be good for stability, though.
	 *
	 *	FIXME: Do we really want to do this whenever we
	 *	receive a packet?  Setting this here means that we
	 *	mark it alive on *any* packet, even if it's lost all
	 *	of the *other* packets in the last 10s.
	 */
	if (request->proxy->code != PW_STATUS_SERVER) {
		request->home_server->state = HOME_STATE_ALIVE;
	}
	
#ifdef WITH_COA
	/*
	 *	When originating CoA, the "proxy" reply is the reply
	 *	to the CoA request that we originated.  At this point,
	 *	the original request is finished, and it has a reply.
	 *
	 *	However, if we haven't separated the two requests, do
	 *	so now.  This is done so that cleaning up the original
	 *	request won't cause the CoA request to be free'd.  See
	 *	util.c, request_free()
	 */
	if (request->parent && (request->parent->coa == request)) {
		request->parent->coa = NULL;
		request->parent = NULL;

		/*
		 *	The proxied packet was different from the
		 *	original packet, AND the proxied packet was
		 *	a CoA: allow it.
		 */
	} else if ((request->packet->code != request->proxy->code) &&
		   ((request->proxy->code == PW_COA_REQUEST) ||
		    (request->proxy->code == PW_DISCONNECT_REQUEST))) {
	  /*
	   *	It's already divorced: do nothing.
	   */
	  
	} else
		/*
		 *	Skip the next set of checks, as the original
		 *	reply is cached.  We want to be able to still
		 *	process the CoA reply, AND to reference the
		 *	original request/reply.
		 *
		 *	This is getting to be really quite a bit of a
		 *	hack.
		 */
#endif

	/*
	 *	If there's a reply to the NAS, ignore everything
	 *	related to proxy responses
	 */
	if (request->reply && request->reply->code != 0) {
		RDEBUG2("Ignoring proxy reply that arrived after we sent a reply to the NAS");
		return NULL;
	}
	
#ifdef WITH_STATS
	/*
	 *	The average includes our time to receive packets and
	 *	look them up in the hashes, which should be the same
	 *	for all packets.
	 *
	 *	We update the response time only for the FIRST packet
	 *	we receive.
	 */
	if (request->home_server->ema.window > 0) {
		radius_stats_ema(&request->home_server->ema,
				 &now, &request->proxy_when);
	}
#endif

	switch (request->child_state) {
	case REQUEST_QUEUED:
	case REQUEST_RUNNING:
		radlog(L_ERR, "Internal sanity check failed for child state");
		/* FALL-THROUGH */

	case REQUEST_REJECT_DELAY:
	case REQUEST_CLEANUP_DELAY:
	case REQUEST_DONE:
		radlog(L_ERR, "Reply from home server %s port %d  - ID: %d arrived too late for request %u. Try increasing 'retry_delay' or 'max_request_time'",
		       inet_ntop(packet->src_ipaddr.af,
				 &packet->src_ipaddr.ipaddr,
				 buffer, sizeof(buffer)),
		       packet->src_port, packet->id,
		       request->number);
		/* assert that there's an event queued for request? */
		return NULL;

	case REQUEST_PROXIED:
		break;
	}

	request->proxy_reply = packet;

#if 0
	/*
	 *	Perform RTT calculations, as per RFC 2988 (for TCP).
	 *	Note that we only do so on the first response.
	 */
	if ((request->num_proxied_responses == 1)
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
		request->proxy_reply = NULL; /* caller will free it */
		ev_request_free(&request);
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

#endif /* WITH_PROXY */

#ifdef WITH_TCP
static void tcp_socket_lifetime(void *ctx)
{
	rad_listen_t *listener = ctx;
	char buffer[256];

	listener->print(listener, buffer, sizeof(buffer));

	DEBUG("Reached maximum lifetime on socket %s", buffer);

	listener->status = RAD_LISTEN_STATUS_CLOSED;
	event_new_fd(listener);
}

static void tcp_socket_idle_timeout(void *ctx)
{
	rad_listen_t *listener = ctx;
	listen_socket_t *sock = listener->data;
	char buffer[256];

	fr_event_now(el, &now);	/* should always succeed... */

	rad_assert(sock->home != NULL);

	/*
	 *	We implement idle timeout by polling, because it's
	 *	cheaper than resetting the idle timeout every time
	 *	we send / receive a packet.
	 */
	if ((sock->last_packet + sock->home->idle_timeout) > now.tv_sec) {
		struct timeval when;
		void *fun = tcp_socket_idle_timeout;
		
		when.tv_sec = sock->last_packet;
		when.tv_sec += sock->home->idle_timeout;
		when.tv_usec = 0;

		if (sock->home->lifetime &&
		    (sock->opened + sock->home->lifetime < when.tv_sec)) {
			when.tv_sec = sock->opened + sock->home->lifetime;
			fun = tcp_socket_lifetime;
		}
		
		if (!fr_event_insert(el, fun, listener, &when, &sock->ev)) {
			rad_panic("Failed to insert event");
		}

		return;
	}

	listener->print(listener, buffer, sizeof(buffer));
	
	DEBUG("Reached idle timeout on socket %s", buffer);

	listener->status = RAD_LISTEN_STATUS_CLOSED;
	event_new_fd(listener);
}
#endif

int event_new_fd(rad_listen_t *this)
{
	char buffer[1024];

	if (this->status == RAD_LISTEN_STATUS_KNOWN) return 1;

	this->print(this, buffer, sizeof(buffer));

	if (this->status == RAD_LISTEN_STATUS_INIT) {
		if (just_started) {
			DEBUG("Listening on %s", buffer);
		} else {
			radlog(L_INFO, " ... adding new socket %s", buffer);
		}

#ifdef WITH_PROXY
		/*
		 *	Add it to the list of sockets we can use.
		 *	Server sockets (i.e. auth/acct) are never
		 *	added to the packet list.
		 */
		if (this->type == RAD_LISTEN_PROXY) {
			listen_socket_t *sock = this->data;

			PTHREAD_MUTEX_LOCK(&proxy_mutex);
			if (!fr_packet_list_socket_add(proxy_list, this->fd,
						       sock->proto,
						       &sock->other_ipaddr, sock->other_port,
						       this)) {

				proxy_no_new_sockets = TRUE;
				PTHREAD_MUTEX_UNLOCK(&proxy_mutex);

				/*
				 *	This is bad.  However, the
				 *	packet list now supports 256
				 *	open sockets, which should
				 *	minimize this problem.
				 */
				radlog(L_ERR, "Failed adding proxy socket: %s",
				       fr_strerror());
				return 0;
			}

			if (sock->home) {
				sock->home->num_connections++;
				
				/*
				 *	If necessary, add it to the list of
				 *	new proxy listeners.
				 */
				if (sock->home->lifetime || sock->home->idle_timeout) {
					this->next = proxy_listener_list;
					proxy_listener_list = this;
				}
			}
			PTHREAD_MUTEX_UNLOCK(&proxy_mutex);

			/*
			 *	Tell the main thread that we've added
			 *	a proxy listener, but only if we need
			 *	to update the event list.  Do this
			 *	with the mutex unlocked, to reduce
			 *	contention.
			 */
			if (sock->home) {
				if (sock->home->lifetime || sock->home->idle_timeout) {
					radius_signal_self(RADIUS_SIGNAL_SELF_NEW_FD);
				}
			}
		}
#endif		

#ifdef WITH_DETAIL
		/*
		 *	Detail files are always known, and aren't
		 *	put into the socket event loop.
		 */
		if (this->type == RAD_LISTEN_DETAIL) {
			this->status = RAD_LISTEN_STATUS_KNOWN;
			
			/*
			 *	Set up the first poll interval.
			 */
			event_poll_detail(this);
			return 1;
		}
#endif

		FD_MUTEX_LOCK(&fd_mutex);
		if (!fr_event_fd_insert(el, 0, this->fd,
					event_socket_handler, this)) {
			radlog(L_ERR, "Failed adding event handler for proxy socket!");
			exit(1);
		}
		FD_MUTEX_UNLOCK(&fd_mutex);
		
		this->status = RAD_LISTEN_STATUS_KNOWN;
		return 1;
	}

	/*
	 *	Something went wrong with the socket: make it harmless.
	 */
	if (this->status == RAD_LISTEN_STATUS_REMOVE_FD) {
		int devnull;

		/*
		 *	Remove it from the list of live FD's.
		 */
		FD_MUTEX_LOCK(&fd_mutex);
		fr_event_fd_delete(el, 0, this->fd);
		FD_MUTEX_UNLOCK(&fd_mutex);

#ifdef WITH_TCP
		/*
		 *	We track requests using this socket only for
		 *	TCP.  For UDP, we don't currently close
		 *	sockets.
		 */
#ifdef WITH_PROXY
		if (this->type != RAD_LISTEN_PROXY)
#endif
		{
			if (this->count != 0) {
				fr_packet_list_walk(pl, this,
						    remove_all_requests);
			}

			if (this->count == 0) {
				this->status = RAD_LISTEN_STATUS_FINISH;
				goto finish;
			}
		}		
#ifdef WITH_PROXY
		else {
			int count = this->count;

			/*
			 *	Duplicate code
			 */
			PTHREAD_MUTEX_LOCK(&proxy_mutex);
			if (!fr_packet_list_socket_freeze(proxy_list,
							  this->fd)) {
				radlog(L_ERR, "Fatal error freezing socket: %s",
				       fr_strerror());
				exit(1);
			}

			/*
			 *	Doing this with the proxy mutex held
			 *	is a Bad Thing.  We should move to
			 *	finer-grained mutexes.
			 */
			count = this->count;
			if (count > 0) {
				fr_packet_list_walk(proxy_list, this,
						    remove_all_proxied_requests);
			}
			count = this->count; /* protected by mutex */
			PTHREAD_MUTEX_UNLOCK(&proxy_mutex);

			if (count == 0) {
				this->status = RAD_LISTEN_STATUS_FINISH;
				goto finish;
			}
		}
#endif	/* WITH_PROXY */
#endif	/* WITH_TCP */

		/*
		 *      Re-open the socket, pointing it to /dev/null.
		 *      This means that all writes proceed without
		 *      blocking, and all reads return "no data".
		 *
		 *      This leaves the socket active, so any child
		 *      threads won't go insane.  But it means that
		 *      they cannot send or receive any packets.
		 *
		 *	This is EXTRA work in the normal case, when
		 *	sockets are closed without error.  But it lets
		 *	us have one simple processing method for all
		 *	sockets.
		 */
		devnull = open("/dev/null", O_RDWR);
		if (devnull < 0) {
			radlog(L_ERR, "FATAL failure opening /dev/null: %s",
			       strerror(errno));
			exit(1);
		}
		if (dup2(devnull, this->fd) < 0) {
			radlog(L_ERR, "FATAL failure closing socket: %s",
			       strerror(errno));
			exit(1);
		}
		close(devnull);

		this->status = RAD_LISTEN_STATUS_CLOSED;

		/*
		 *	Fall through to the next section.
		 */
	}

#ifdef WITH_TCP
	/*
	 *	Called ONLY from the main thread.  On the following
	 *	conditions:
	 *
	 *	idle timeout
	 *	max lifetime
	 *
	 *	(and falling through from "forcibly close FD" above)
	 *	client closed connection on us
	 *	client sent us a bad packet.
	 */
	if (this->status == RAD_LISTEN_STATUS_CLOSED) {
		int count = this->count;
		rad_assert(this->type != RAD_LISTEN_DETAIL);

#ifdef WITH_PROXY
		/*
		 *	Remove it from the list of active sockets, so
		 *	that it isn't used when proxying new packets.
		 */
		if (this->type == RAD_LISTEN_PROXY) {
			PTHREAD_MUTEX_LOCK(&proxy_mutex);
			if (!fr_packet_list_socket_freeze(proxy_list,
							  this->fd)) {
				radlog(L_ERR, "Fatal error freezing socket: %s",
				       fr_strerror());
				exit(1);
			}
			count = this->count; /* protected by mutex */
			PTHREAD_MUTEX_UNLOCK(&proxy_mutex);
		}
#endif

		/*
		 *	Requests are still using the socket.  Wait for
		 *	them to finish.
		 */
		if (count != 0) {
			struct timeval when;
			listen_socket_t *sock = this->data;

			/*
			 *	Try again to clean up the socket in 30
			 *	seconds.
			 */
			gettimeofday(&when, NULL);
			when.tv_sec += 30;
			
			if (!fr_event_insert(el,
					     (fr_event_callback_t) event_new_fd,
					     this, &when, &sock->ev)) {
				rad_panic("Failed to insert event");
			}
		       
			return 1;
		}

		/*
		 *	No one is using this socket: we can delete it
		 *	immediately.
		 */
		this->status = RAD_LISTEN_STATUS_FINISH;
	}
	
finish:
	if (this->status == RAD_LISTEN_STATUS_FINISH) {
		listen_socket_t *sock = this->data;

		rad_assert(this->count == 0);
		radlog(L_INFO, " ... closing socket %s", buffer);

		/*
		 *	Remove it from the list of live FD's.  Note
		 *	that it MAY also have been removed above.  We
		 *	do it again here, to catch the case of sockets
		 *	closing on idle timeout, or max
		 *	lifetime... AFTER all requests have finished
		 *	using it.
		 */
		FD_MUTEX_LOCK(&fd_mutex);
		fr_event_fd_delete(el, 0, this->fd);
		FD_MUTEX_UNLOCK(&fd_mutex);
		
#ifdef WITH_PROXY
		/*
		 *	Remove it from the list of sockets to be used
		 *	when proxying.
		 */
		if (this->type == RAD_LISTEN_PROXY) {
			PTHREAD_MUTEX_LOCK(&proxy_mutex);
			if (!fr_packet_list_socket_remove(proxy_list,
							  this->fd, NULL)) {
				radlog(L_ERR, "Fatal error removing socket: %s",
				       fr_strerror());
				exit(1);
			}
			if (sock->home) sock->home->num_connections--;
			PTHREAD_MUTEX_UNLOCK(&proxy_mutex);
		}
#endif

		/*
		 *	Remove any pending cleanups.
		 */
		if (sock->ev) fr_event_delete(el, &sock->ev);

		/*
		 *	And finally, close the socket.
		 */
		listen_free(&this);
	}
#endif	/* WITH_TCP */

	return 1;
}

static void handle_signal_self(int flag)
{
	if ((flag & (RADIUS_SIGNAL_SELF_EXIT | RADIUS_SIGNAL_SELF_TERM)) != 0) {
		if ((flag & RADIUS_SIGNAL_SELF_EXIT) != 0) {
			radlog(L_INFO, "Received TERM signal");
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

		when = time(NULL);
		if ((int) (when - last_hup) < 5) {
			radlog(L_INFO, "Ignoring HUP (less than 5s since last one)");
			return;
		}

		radlog(L_INFO, "Received HUP signal.");

		last_hup = when;

		fr_event_loop_exit(el, 0x80);
	}

#ifdef WITH_DETAIL
	if ((flag & RADIUS_SIGNAL_SELF_DETAIL) != 0) {
		rad_listen_t *this;
		
		/*
		 *	FIXME: O(N) loops suck.
		 */
		for (this = mainconfig.listen;
		     this != NULL;
		     this = this->next) {
			if (this->type != RAD_LISTEN_DETAIL) continue;

			/*
			 *	This one didn't send the signal, skip
			 *	it.
			 */
			if (!this->decode(this, NULL)) continue;

			/*
			 *	Go service the interrupt.
			 */
			event_poll_detail(this);
		}
	}
#endif

#ifdef WITH_TCP
#ifdef WITH_PROXY
	/*
	 *	Add event handlers for idle timeouts && maximum lifetime.
	 */
	if ((flag & RADIUS_SIGNAL_SELF_NEW_FD) != 0) {
		struct timeval when;
		void *fun = NULL;

		fr_event_now(el, &now);

		PTHREAD_MUTEX_LOCK(&proxy_mutex);

		while (proxy_listener_list) {
			rad_listen_t *this = proxy_listener_list;
			listen_socket_t *sock = this->data;

			proxy_listener_list = this->next;
			this->next = NULL;

			if (!sock->home) continue; /* skip UDP sockets */

			when = now;

			if (!sock->home->idle_timeout) {
				rad_assert(sock->home->lifetime != 0);

				when.tv_sec += sock->home->lifetime;
				fun = tcp_socket_lifetime;
			} else {
				rad_assert(sock->home->idle_timeout != 0);

				when.tv_sec += sock->home->idle_timeout;
				fun = tcp_socket_idle_timeout;
			}

			if (!fr_event_insert(el, fun, this, &when,
					     &(sock->ev))) {
				rad_panic("Failed to insert event");
			}
		}

		PTHREAD_MUTEX_UNLOCK(&proxy_mutex);
	}
#endif	/* WITH_PROXY */
#endif	/* WITH_TCP */
}

#ifndef WITH_SELF_PIPE
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

	rad_assert(fun != NULL);
	rad_assert(request != NULL);

	thread_pool_addrequest(request, fun);
}


/*
 *	This function is called periodically to see if this detail
 *	file is available for reading.
 */
static void event_poll_detail(void *ctx)
{
	int delay;
	rad_listen_t *this = ctx;
	struct timeval when;
	listen_detail_t *detail = this->data;

	rad_assert(this->type == RAD_LISTEN_DETAIL);

	event_socket_handler(el, this->fd, this);

	fr_event_now(el, &now);
	when = now;

	/*
	 *	Backdoor API to get the delay until the next poll
	 *	time.
	 */
	delay = this->encode(this, NULL);
	tv_add(&when, delay);

	if (!fr_event_insert(el, event_poll_detail, this,
			     &when, &detail->ev)) {
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
		radlog(L_INFO, "Ready to process requests.");

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
	rad_listen_t *head = NULL;

	if (el) return 0;

	time(&fr_start_time);

	el = fr_event_list_create(event_status);
	if (!el) return 0;

	pl = fr_packet_list_create(0);
	if (!pl) return 0;	/* leak el */

	request_num_counter = 0;

#ifdef WITH_PROXY
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
#endif

#ifdef HAVE_PTHREAD_H
#ifndef __MINGW32__
	NO_SUCH_CHILD_PID = (pthread_t ) (0);
#else
	NO_SUCH_CHILD_PID = pthread_self(); /* not a child thread */
#endif
	/*
	 *	Initialize the threads ONLY if we're spawning, AND
	 *	we're running normally.
	 */
	if (spawn_flag && !check_config &&
	    (thread_pool_init(cs, &spawn_flag) < 0)) {
		exit(1);
	}
#endif

	/*
	 *	Move all of the thread calls to this file?
	 *
	 *	It may be best for the mutexes to be in this file...
	 */
	have_children = spawn_flag;

	if (check_config) {
		DEBUG("%s: #### Skipping IP addresses and Ports ####",
		       mainconfig.name);
		return 1;
	}

#ifdef WITH_SELF_PIPE
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
#endif	/* WITH_SELF_PIPE */

       DEBUG("%s: #### Opening IP addresses and Ports ####",
	       mainconfig.name);

       /*
	*	The server temporarily switches to an unprivileged
	*	user very early in the bootstrapping process.
	*	However, some sockets MAY require privileged access
	*	(bind to device, or to port < 1024, or to raw
	*	sockets).  Those sockets need to call suid up/down
	*	themselves around the functions that need a privileged
	*	uid.
	*/
	if (listen_init(cs, &head) < 0) {
		_exit(1);
	}
	
	mainconfig.listen = head;

	/*
	 *	At this point, no one has any business *ever* going
	 *	back to root uid.
	 */
	fr_suid_down_permanent();

	return 1;
}


static int request_hash_cb(UNUSED void *ctx, void *data)
{
	REQUEST *request = fr_packet2myptr(REQUEST, packet, data);

#ifdef WITH_PROXY
	rad_assert(request->in_proxy_hash == FALSE);
#endif

	ev_request_free(&request);

	return 0;
}


#ifdef WITH_PROXY
static int proxy_hash_cb(UNUSED void *ctx, void *data)
{
	REQUEST *request = fr_packet2myptr(REQUEST, proxy, data);

	ev_request_free(&request);

	return 0;
}
#endif

void radius_event_free(void)
{
	/*
	 *	FIXME: Stop all threads, or at least check that
	 *	they're all waiting on the semaphore, and the queues
	 *	are empty.
	 */

#ifdef WITH_PROXY
	/*
	 *	There are requests in the proxy hash that aren't
	 *	referenced from anywhere else.  Remove them first.
	 */
	if (proxy_list) {
		fr_packet_list_walk(proxy_list, NULL, proxy_hash_cb);
		fr_packet_list_free(proxy_list);
		proxy_list = NULL;
	}
#endif

	fr_packet_list_walk(pl, NULL, request_hash_cb);

	fr_packet_list_free(pl);
	pl = NULL;

	fr_event_list_free(el);
}

int radius_event_process(void)
{
	if (!el) return 0;

	return fr_event_loop(el);
}

void radius_handle_request(REQUEST *request, RAD_REQUEST_FUNP fun)
{
	request->options = RAD_REQUEST_OPTION_DEBUG2;

	if (request_pre_handler(request)) {
		rad_assert(fun != NULL);
		rad_assert(request != NULL);
		
		if (request->server) RDEBUG("server %s {",
					    request->server != NULL ?
					    request->server : ""); 
		fun(request);

		if (request->server) RDEBUG("} # server %s",
					     request->server != NULL ?
					    request->server : "");

		request_post_handler(request);
	}

	DEBUG2("Going to the next request");
	return;
}
