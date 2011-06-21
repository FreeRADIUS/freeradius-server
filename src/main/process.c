/*
 * process.c	Handle requests
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
 * Copyright 2011  The FreeRADIUS server project
 * Copyright 2011  Alan DeKok <aland@deployingradius.com>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/process.h>
#include <freeradius-devel/event.h>
#include <freeradius-devel/packet.h>
#include <freeradius-devel/modules.h>

#include <freeradius-devel/rad_assert.h>

#ifdef WITH_DETAIL
#include <freeradius-devel/detail.h>
#endif

#include <signal.h>
#include <fcntl.h>

#ifdef HAVE_SYS_WAIT_H
#	include <sys/wait.h>
#endif

#define NDEBUG

extern pid_t radius_pid;
extern int check_config;
extern char *debug_condition;

static int spawn_flag = 0;
static int just_started = TRUE;
time_t				fr_start_time;
static fr_packet_list_t *pl = NULL;
static fr_event_list_t *el = NULL;

static const char *action_codes[] = {
	"INVALID",
	"run",
	"done",
	"dup",
	"conflicting",
	"timer",
#ifdef WITH_PROXY
	"proxy-reply"
#endif
};

#ifdef DEBUG_STATE_MACHINE
#define TRACE_STATE_MACHINE if (debug_flag) printf("(%u) ********\tSTATE %s action %s live M%u C%u\t********\n", request->number, __FUNCTION__, action_codes[action], request->master_state, request->child_state)
#else
#define TRACE_STATE_MACHINE {}
#endif

/*
 *	Time sequence of a request
 *
 *	RQ-----------------P=============================Y-J-C
 *	 ::::::::::::::::::::::::::::::::::::::::::::::::::::::::M
 *
 * 	R: received.  Duplicate detection is done, and request is
 * 	   cached.
 *
 *	Q: Request is placed onto a queue for child threads to pick up.
 *	   If there are no child threads, the request goes immediately
 *	   to P.
 *
 *	P: Processing the request through the modules.
 *
 *	Y: Reply is ready.  Rejects MAY be delayed here.  All other
 *	   replies are sent immediately.
 *
 *	J: Reject is sent "reject_delay" after the reply is ready.
 *
 *	C: For Access-Requests, After "cleanup_delay", the request is
 *	   deleted.  Accounting-Request packets go directly from Y to C.
 *
 *	M: Max request time.  If the request hits this timer, it is
 *	   forcibly stopped.
 *
 *	Other considerations include duplicate and conflicting
 *	packets.  When a dupicate packet is received, it is ignored
 *	until we've reached Y, as no response is ready.  If the reply
 *	is a reject, duplicates are ignored until J, when we're ready
 *	to send the reply.  In between the reply being sent (Y or J),
 *	and C, the server responds to duplicates by sending the cached
 *	reply.
 *
 *	Conflicting packets are sent in 2 situations.
 *
 *	The first is in between R and Y.  In that case, we consider
 *	it as a hint that we're taking too long, and the NAS has given
 *	up on the request.  We then behave just as if the M timer was
 *	reached, and we discard the current request.  This allows us
 *	to process the new one.
 *
 *	The second case is when we're at Y, but we haven't yet
 *	finished processing the request.  This is a race condition in
 *	the threading code (avoiding locks is faster).  It means that
 *	a thread has actually encoded and sent the reply, and that the
 *	NAS has responded with a new packet.  The server can then
 *	safely mark the current request as "OK to delete", and behaves
 *	just as if the M timer was reached.  This usually happens only
 *	in high-load situations.
 *
 *	Duplicate packets are sent when the NAS thinks we're taking
 *	too long, and wants a reply.  From R-Y, duplicates are
 *	ignored.  From Y-J (for Access-Rejects), duplicates are also
 *	ignored.  From Y-C, duplicates get a duplicate reply.  *And*,
 *	they cause the "cleanup_delay" time to be extended.  This
 *	extension means that we're more likely to send a duplicate
 *	reply (if we have one), or to suppress processing the packet
 *	twice if we didn't reply to it.
 *
 *	All functions in this file should be thread-safe, and should
 *	assume thet the REQUEST structure is being accessed
 *	simultaneously by the main thread, and by the child worker
 *	threads.  This means that timers, etc. cannot be updated in
 *	the child thread.
 *
 *	Instead, the master thread periodically calls request->process
 *	with action TIMER.  It's up to the individual functions to
 *	determine how to handle that.  They need to check if they're
 *	being called from a child thread or the master, and then do
 *	different things based on that.
 */


#ifdef WITH_PROXY
static fr_packet_list_t *proxy_list = NULL;
#endif

#ifdef HAVE_PTHREAD_H
#ifdef WITH_PROXY
static pthread_mutex_t	proxy_mutex;
static rad_listen_t *proxy_listener_list = NULL;
static int proxy_no_new_sockets = FALSE;
#endif

#define PTHREAD_MUTEX_LOCK if (spawn_flag) pthread_mutex_lock
#define PTHREAD_MUTEX_UNLOCK if (spawn_flag) pthread_mutex_unlock

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
#define FD_MUTEX_LOCK if (spawn_flag) pthread_mutex_lock
#define FD_MUTEX_UNLOCK if (spawn_flag) pthread_mutex_unlock
#else
/*
 *	This is easier than ifdef's throughout the code.
 */
#define FD_MUTEX_LOCK(_x)
#define FD_MUTEX_UNLOCK(_x)
#endif

static int request_num_counter = 0;
#ifdef WITH_PROXY
static int request_will_proxy(REQUEST *request);
static int request_proxy(REQUEST *request, int retransmit);
static void request_proxied(UNUSED REQUEST *request, int action);
static void request_post_proxy(REQUEST *request, int action);
static int process_proxy_reply(REQUEST *request);
static void remove_from_proxy_hash(REQUEST *request);
static int insert_into_proxy_hash(REQUEST *request);
#endif
static void request_common(UNUSED REQUEST *request, int action);

#if  defined(HAVE_PTHREAD_H) && !defined (NDEBUG)
static int we_are_master(void)
{
	if (spawn_flag &&
	    (pthread_equal(pthread_self(), NO_SUCH_CHILD_PID) == 0)) {
		return 0;
	}

	return 1;
}
#define ASSERT_MASTER 	if (!we_are_master()) rad_panic("We are not master")

#else
#define we_are_master(_x) (1)
#define ASSERT_MASTER
#endif

static void request_reject_delay(REQUEST *request, int action);
static void request_cleanup_delay(REQUEST *request, int action);
static void request_running(REQUEST *request, int action);
#ifdef WITH_COA
static void request_coa_timer(REQUEST *request);
static void request_coa_originate(REQUEST *request);
static void request_coa_process(REQUEST *request, int action);
static void request_coa_separate(REQUEST *coa);
#endif

#undef USEC
#define USEC (1000000)

#define INSERT_EVENT(_function, _ctx) if (!fr_event_insert(el, _function, _ctx, &((_ctx)->when), &((_ctx)->ev))) { _rad_panic(__FILE__, __LINE__, "Failed to insert event"); }

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


/***********************************************************************
 *
 *	Start of RADIUS server state machine.
 *
 ***********************************************************************/

/*
 *	Callback for ALL timer events related to the request.
 */
static void request_timer(void *ctx)
{
	REQUEST *request = ctx;
#ifdef DEBUG_STATE_MACHINE
	int action = FR_ACTION_TIMER;
#endif

	TRACE_STATE_MACHINE;

	request->process(request, FR_ACTION_TIMER);
}

#define USEC (1000000)

/*
 *	Only ever called from the master thread.
 */
static void request_done(REQUEST *request, int action)
{
	struct timeval now;

	TRACE_STATE_MACHINE;

#ifdef WITH_COA
	/*
	 *	CoA requests can be cleaned up in the child thread,
	 *	but ONLY if they aren't tied into anything.
	 */
	if (request->parent && (request->parent->coa == request)) {
		rad_assert(request->child_state == REQUEST_DONE);
		rad_assert(!request->in_request_hash);
		rad_assert(!request->in_proxy_hash);
		rad_assert(action == FR_ACTION_DONE);
		rad_assert(request->packet == NULL);
		rad_assert(request->ev == NULL);
	} else
#endif
	  {
		  ASSERT_MASTER;
	  }

	/*
	 *	Mark ourselves as handling the request.
	 */
	request->process = request_done;
	request->master_state = REQUEST_STOP_PROCESSING;

#ifdef WITH_COA
	/*
	 *	Move the CoA request to its own handler.
	 */
	if (request->coa) request_coa_separate(request->coa);

	/*
	 *	If we're the CoA request, make the parent forget about
	 *	us.
	 */
	if (request->parent && (request->parent->coa == request)) {
		request->parent->coa = NULL;
	}

#endif

	/*
	 *	It doesn't hurt to send duplicate replies.  All other
	 *	signals are ignored, as the request will be cleaned up
	 *	soon anyways.
	 */
	switch (action) {
	case FR_ACTION_DUP:
		if (request->reply->code != 0) {
			request->listener->send(request->listener, request);
			return;
		}
		break;

		/*
		 *	This is only called from the master thread
		 *	when there is a child thread processing the
		 *	request.
		 */
	case FR_ACTION_CONFLICTING:
		if (request->child_state == REQUEST_DONE) break;

		/*
		 *	If there's a reply packet, then we presume
		 *	that the child has sent the reply, and we get
		 *	pinged here before the child has a chance to
		 *	say "I'm done!"
		 */
		if (request->reply->data) break;

		radlog(L_ERR, "Received conflicting packet from "
		       "client %s port %d - ID: %d due to unfinished request %u.  Giving up on old request.",
		       request->client->shortname,
		       request->packet->src_port, request->packet->id,
		       request->number);
		break;

		/*
		 *	Called only when there's an error remembering
		 *	the packet, or when the socket gets closed from
		 *	under us.
		 */
	case FR_ACTION_DONE:
#ifdef DEBUG_STATE_MACHINE
		if (debug_flag) printf("(%u) ********\tSTATE %s C%u -> C%u\t********\n", request->number, __FUNCTION__, request->child_state, REQUEST_DONE);
#endif
#ifdef HAVE_PTHREAD_H
		rad_assert(request->child_pid == NO_SUCH_CHILD_PID);
#endif
		request->child_state = REQUEST_DONE;
		break;

		/*
		 *	Called when the child is taking too long to
		 *	finish.  We've already marked it "please
		 *	stop", so we don't complain any more.
		 */
	case FR_ACTION_TIMER:
		break;
		
#ifdef WITH_PROXY
		/*
		 *	Child is still alive, and we're receiving more
		 *	packets from the home server.
		 */
	case FR_ACTION_PROXY_REPLY:
		request_common(request, action);
		break;
#endif
		
	default:
		RDEBUG3("%s: Ignoring action %s", __FUNCTION__, action_codes[action]);
		break;
	}

	/*
	 *	Remove it from the request hash.
	 */
	if (request->in_request_hash) {
		fr_packet_list_yank(pl, request->packet);
		request->in_request_hash = FALSE;
		
		request_stats_final(request);
		
#ifdef WITH_TCP
		request->listener->count--;
#endif
	}
	
#ifdef WITH_PROXY
	/*
	 *	Wait for the proxy ID to expire.  This allows us to
	 *	avoid re-use of proxy IDs for a while.
	 */
	if (request->in_proxy_hash) {
		struct timeval when;
		
		fr_event_now(el, &now);
		when = request->proxy->timestamp;

#ifdef WITH_COA
		if ((request->packet->code != request->proxy->code) &&
		    ((request->proxy->code == PW_COA_REQUEST) ||
		     (request->proxy->code == PW_DISCONNECT_REQUEST))) {
			when.tv_sec += request->home_server->coa_mrd;
		} else
#endif
		when.tv_sec += request->home_server->response_window;

		/*
		 *	We haven't received all responses, AND there's still
		 *	time to wait.  Do so.
		 */
		if ((request->num_proxied_requests > request->num_proxied_responses) &&
#ifdef WITH_TCP
		    (request->home_server->proto != IPPROTO_TCP) &&
#endif
		    timercmp(&now, &when, <)) {
			RDEBUG("Waiting for more responses from the home server");
			goto wait_some_more;
		}

		/*
		 *	Time to remove it.
		 */
		remove_from_proxy_hash(request);
	}
#endif

	if (request->child_state != REQUEST_DONE) {

#ifdef HAVE_PTHREAD_H
		if (!spawn_flag)
#endif
		{
			rad_assert("Internal sanity check failed");
			exit(2);
		}
		
		gettimeofday(&now, NULL);
#ifdef WITH_PROXY
	wait_some_more:
#endif

#ifdef HAVE_PTHREAD_H
		if (spawn_flag &&
		    (pthread_equal(request->child_pid, NO_SUCH_CHILD_PID) == 0)) {
			RDEBUG("Waiting for child thread to stop");
		}
#endif
		tv_add(&now, request->delay);
		request->delay += request->delay >> 1;
		if (request->delay > (10 * USEC)) request->delay = 10 * USEC;
		fr_event_insert(el, request_timer, request, &now,
				&request->ev);
		return;
	}

#ifdef HAVE_PTHREAD_H
	rad_assert(request->child_pid == NO_SUCH_CHILD_PID);
#endif

	if (request->packet) {
		RDEBUG2("Cleaning up request packet ID %d with timestamp +%d",
			request->packet->id,
			(unsigned int) (request->timestamp - fr_start_time));
	} /* else don't print anything */

	if (request->ev) fr_event_delete(el, &request->ev);

	request_free(&request);
}

/*
 *	Function to do all time-related events.
 */
static void request_process_timer(REQUEST *request)
{
	struct timeval now, when;
	rad_assert(request->magic == REQUEST_MAGIC);
#ifdef DEBUG_STATE_MACHINE
	int action = FR_ACTION_TIMER;
#endif

	TRACE_STATE_MACHINE;
	ASSERT_MASTER;

#ifdef WITH_COA
	/*
	 *	If we originated a CoA request, divorce it from the
	 *	parent.  Then, set up the timers so that we can clean
	 *	it up as appropriate.
	 */
	if (request->coa) request_coa_separate(request->coa);

	/*
	 *	Check request stuff ONLY if we're running the request.
	 */
	if (!request->proxy || (request->packet->code == request->proxy->code))
#endif
	{
		rad_assert(request->listener != NULL);
		
		/*
		 *	The socket was closed.  Tell the request that
		 *	there is no point in continuing.
		 */
		if (request->listener->status != RAD_LISTEN_STATUS_KNOWN) {
			DEBUG("WARNING: Socket was closed while processing request %u: Stopping it.", request->number);
			goto done;
		}
	}

	gettimeofday(&now, NULL);

	/*
	 *	A child thread is still working on the request,
	 *	OR it was proxied, and there was no response.
	 */
	if ((request->child_state != REQUEST_DONE) &&
	    (request->master_state != REQUEST_STOP_PROCESSING)) {
		when = request->packet->timestamp;
		when.tv_sec += request->root->max_request_time;
		
		/*
		 *	Taking too long: tell it to die.
		 */
		if (timercmp(&now, &when, >=)) {
#ifdef HAVE_PTHREAD_H
			/*
			 *	If there's a child thread processing it,
			 *	complain.
			 */
			if (spawn_flag &&
			    (pthread_equal(request->child_pid, NO_SUCH_CHILD_PID) == 0)) {
				radlog(L_ERR, "WARNING: Unresponsive child for request %u, in component %s module %s",
				       request->number,
				       request->component ? request->component : "<server core>",
			       request->module ? request->module : "<server core>");
				exec_trigger(request, NULL, "server.thread.unresponsive");
			}
#endif

			/*
			 *	Tell the request to stop it.
			 */
			goto done;
		} /* else we're not at max_request_time */

#ifdef WITH_PROXY
		if ((request->master_state != REQUEST_STOP_PROCESSING) &&
		    request->proxy &&
		    (request->process == request_running)) {
#ifdef DEBUG_STATE_MACHINE
			if (debug_flag) printf("(%u) ********\tNEXT-STATE %s -> %s\n", request->number, __FUNCTION__, "request_proxied");
#endif
			request->process = request_proxied;
		}
#endif

		/*
		 *	Wake up again in the future, to check for
		 *	more things to do.
		 */
		when = now;
		tv_add(&when, request->delay);
		request->delay += request->delay >> 1;
		fr_event_insert(el, request_timer, request,
				&when, &request->ev);
		return;
	}

#ifdef WITH_ACCOUNTING
	if (request->reply->code == PW_ACCOUNTING_RESPONSE) {
		goto done;
	}
#endif

#ifdef WITH_COA
	if (!request->proxy || (request->packet->code == request->proxy->code))
#endif

	if ((request->reply->code == PW_AUTHENTICATION_REJECT) &&
	    (request->root->reject_delay)) {
		when = request->reply->timestamp; 
		when.tv_sec += request->root->reject_delay;

		/*
		 *	Set timer for when we need to send it.
		 */
		if (timercmp(&when, &now, >)) {
#ifdef DEBUG_STATE_MACHINE
			if (debug_flag) printf("(%u) ********\tNEXT-STATE %s -> %s\n", request->number, __FUNCTION__, "request_reject_delay");
#endif
			request->process = request_reject_delay;

			fr_event_insert(el, request_timer, request,
					&when, &request->ev);
			return;
		}

		if (request->process == request_reject_delay) {
			/*
			 *	Assume we're at (or near) the reject
			 *	delay time.
			 */
			request->reply->timestamp = now;
			
			RDEBUG2("Sending delayed reject");
			DEBUG_PACKET(request, request->reply, 1);
			request->process = request_cleanup_delay;
			request->listener->send(request->listener, request);
		}
	}

	/*
	 *	The cleanup_delay is zero for accounting packets, and
	 *	enforced for all other packets.  We do the
	 *	cleanup_delay even if we don't respond to the NAS, so
	 *	that any retransmit is *not* processed as a new packet.
	 */
	if ((request->packet->code != PW_ACCOUNTING_REQUEST) &&
	    (request->root->cleanup_delay)) {
		when = request->reply->timestamp;
		request->delay = request->root->cleanup_delay;
		when.tv_sec += request->delay;

		/*
		 *	Set timer for when we need to clean it up.
		 */
		if (timercmp(&when, &now, >)) {
#ifdef DEBUG_STATE_MACHINE
			if (debug_flag) printf("(%u) ********\tNEXT-STATE %s -> %s\n", request->number, __FUNCTION__, "request_cleanup_delay");
#endif
			request->process = request_cleanup_delay;

			fr_event_insert(el, request_timer, request,
					&when, &request->ev);
			return;
		}
	}

done:
	request_done(request, FR_ACTION_DONE);
}

static void request_queue_or_run(UNUSED REQUEST *request,
				 fr_request_process_t process)
{
#ifdef DEBUG_STATE_MACHINE
	int action = FR_ACTION_TIMER;
#endif

	TRACE_STATE_MACHINE;
	ASSERT_MASTER;

#ifdef HAVE_PTHREAD_H
	rad_assert(request->child_pid == NO_SUCH_CHILD_PID);
#endif

	/*
	 *	Set the initial delay.
	 */
	if (!request->ev) {
		struct timeval now;

		request->delay = USEC / 10;
		gettimeofday(&now, NULL);
		tv_add(&now, request->delay);
		request->delay += request->delay >> 1;
		fr_event_insert(el, request_timer, request, &now,
				&request->ev);
	}

	/*
	 *	Do this here so that fewer other functions need to do
	 *	it.
	 */
	if (request->master_state == REQUEST_STOP_PROCESSING) {
#ifdef DEBUG_STATE_MACHINE
		if (debug_flag) printf("(%u) ********\tSTATE %s C%u -> C%u\t********\n", request->number, __FUNCTION__, request->child_state, REQUEST_DONE);
#endif
		request_done(request, FR_ACTION_DONE);
		return;
	}

	request->process = process;

#ifdef HAVE_PTHREAD_H
	if (spawn_flag) {
		if (!request_enqueue(request)) {
			request_done(request, FR_ACTION_DONE);
			return;
		}

	} else
#endif
	{
		request->process(request, FR_ACTION_RUN);

#ifdef WNOHANG
		/*
		 *	Requests that care about child process exit
		 *	codes have already either called
		 *	rad_waitpid(), or they've given up.
		 */
		wait(NULL);
#endif
	}
}

static void request_common(UNUSED REQUEST *request, int action)
{
#ifdef WITH_PROXY
	char buffer[128];
#endif

	TRACE_STATE_MACHINE;

	switch (action) {
	case FR_ACTION_DUP:
#ifdef WITH_PROXY
		if ((request->master_state != REQUEST_STOP_PROCESSING) &&
		     request->proxy && !request->proxy_reply) {
			/*
			 *	TODO: deal with this in a better way?
			 */
			request_proxied(request, action);
			return;
		}
#endif
		radlog(L_ERR, "Discarding duplicate request from "
		       "client %s port %d - ID: %u due to unfinished request %u",
		       request->client->shortname,
		       request->packet->src_port,request->packet->id,
		       request->number);
		break;

	case FR_ACTION_CONFLICTING:
		/*
		 *	We're in the master thread, ask the child to
		 *	stop processing the request.
		 */
		request_done(request, action);
		return;

	case FR_ACTION_TIMER:
		request_process_timer(request);
		return;

#ifdef WITH_PROXY
	case FR_ACTION_PROXY_REPLY:
		DEBUG2("Reply from home server %s port %d  - ID: %d arrived too late for request %u. Try increasing 'retry_delay' or 'max_request_time'",
		       inet_ntop(request->proxy->src_ipaddr.af,
				 &request->proxy->src_ipaddr.ipaddr,
				 buffer, sizeof(buffer)),
		       request->proxy->dst_port, request->proxy->id,
		       request->number);
		return;
#endif

	default:
		RDEBUG3("%s: Ignoring action %s", __FUNCTION__, action_codes[action]);
		break;
	}
}

static void request_cleanup_delay(REQUEST *request, int action)
{
	struct timeval when;

	TRACE_STATE_MACHINE;
	ASSERT_MASTER;

	switch (action) {
	case FR_ACTION_DUP:
		if (request->reply->code != 0) {
			request->listener->send(request->listener, request);
		}

		/*
		 *	Double the cleanup_delay to catch retransmits.
		 */
		when = request->reply->timestamp;
		request->delay += request->delay ;
		when.tv_sec += request->delay;
		fr_event_insert(el, request_timer, request,
				&when, &request->ev);
		return;

#ifdef WITH_PROXY
	case FR_ACTION_PROXY_REPLY:
#endif
	case FR_ACTION_CONFLICTING:
	case FR_ACTION_TIMER:
		request_common(request, action);
		return;

	default:
		RDEBUG3("%s: Ignoring action %s", __FUNCTION__, action_codes[action]);
		break;
	}
}

static void request_reject_delay(REQUEST *request, int action)
{
	TRACE_STATE_MACHINE;
	ASSERT_MASTER;

	switch (action) {
	case FR_ACTION_DUP:
		radlog(L_ERR, "Discarding duplicate request from "
		       "client %s port %d - ID: %u due to delayed reject %u",
		       request->client->shortname,
		       request->packet->src_port,request->packet->id,
		       request->number);
		return;

#ifdef WITH_PROXY
	case FR_ACTION_PROXY_REPLY:
#endif
	case FR_ACTION_CONFLICTING:
	case FR_ACTION_TIMER:
		request_common(request, action);
		break;

	default:
		RDEBUG3("%s: Ignoring action %s", __FUNCTION__, action_codes[action]);
		break;
	}
}


static int request_pre_handler(REQUEST *request, UNUSED int action)
{
	TRACE_STATE_MACHINE;

	int rcode;

	if (request->master_state == REQUEST_STOP_PROCESSING) return 0;

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
		RDEBUG("Dropping packet without response because of error %s", fr_strerror());
		request->reply->offset = -2; /* bad authenticator */
		return 0;
	}

	if (!request->username) {
		request->username = pairfind(request->packet->vps,
					     PW_USER_NAME, 0);
	}

#ifdef WITH_PROXY
	if (action == FR_ACTION_PROXY_REPLY) {
		return process_proxy_reply(request);
	}
#endif

	return 1;
}

static void request_finish(REQUEST *request, UNUSED int action)
{
	TRACE_STATE_MACHINE;

	VALUE_PAIR *vp;

	if (request->master_state == REQUEST_STOP_PROCESSING) return;

	/*
	 *	Don't send replies if there are none to send.
	 */
	if (!request->in_request_hash) return;

	/*
	 *	Catch Auth-Type := Reject BEFORE proxying the packet.
	 */
	if ((request->packet->code == PW_AUTHENTICATION_REQUEST) &&
	    (request->reply->code == 0)) {
		if (((vp = pairfind(request->config_items, PW_AUTH_TYPE, 0)) != NULL) &&
		    (vp->vp_integer == PW_AUTHTYPE_REJECT)) {
			request->reply->code = PW_AUTHENTICATION_REJECT;

		} else {
			/*
			 *	Check if the lack of response is
			 *	intentional.
			 */
			vp = pairfind(request->config_items,
				      PW_RESPONSE_PACKET_TYPE, 0);
			if (!vp) {
				RDEBUG2("There was no response configured: rejecting request");
				request->reply->code = PW_AUTHENTICATION_REJECT;

			} else if (vp->vp_integer == 256) {
				RDEBUG2("Not responding to request");

			} else {
				request->reply->code = vp->vp_integer;
			}
		}
	}

	/*
	 *	Copy Proxy-State from the request to the reply.
	 */
	vp = paircopy2(request->packet->vps, PW_PROXY_STATE, 0);
	if (vp) pairadd(&request->reply->vps, vp);

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
	}

	/*
	 *	Send the reply here.
	 */
	if ((request->reply->code != PW_AUTHENTICATION_REJECT) ||
	    (request->root->reject_delay == 0)) {
		DEBUG_PACKET(request, request->reply, 1);
		request->listener->send(request->listener,
					request);
	}

	gettimeofday(&request->reply->timestamp, NULL);

	/*
	 *	Clean up.  These are no longer needed.
	 */
	pairfree(&request->config_items);

	pairfree(&request->packet->vps);
	request->username = NULL;
	request->password = NULL;
	
	if (request->reply->code != PW_AUTHENTICATION_REJECT) {
		pairfree(&request->reply->vps);
	}

#ifdef WITH_PROXY
	if (request->proxy) {
		pairfree(&request->proxy->vps);

		if (request->proxy_reply) {
			pairfree(&request->proxy_reply->vps);
		}
	}
#endif
	
	RDEBUG2("Finished request %u.", request->number);
}

static void request_running(REQUEST *request, int action)
{
	TRACE_STATE_MACHINE;

	switch (action) {
	case FR_ACTION_CONFLICTING:
	case FR_ACTION_DUP:
	case FR_ACTION_TIMER:
		request_common(request, action);
		return;

#ifdef WITH_PROXY
	case FR_ACTION_PROXY_REPLY:
#ifdef HAVE_PTHREAD_H
		/*
		 *	Catch the case of a proxy reply when called
		 *	from the main worker thread.
		 */
		if (we_are_master() &&
		    (request->process != request_post_proxy)) {
			request_queue_or_run(request, request_post_proxy);
			return;
		}
		/* FALL-THROUGH */
#endif
#endif

	case FR_ACTION_RUN:
		if (!request_pre_handler(request, action)) goto done;

		rad_assert(request->handle != NULL);
		request->handle(request);

#ifdef WITH_PROXY
		/*
		 *	We may need to send a proxied request.
		 */
		if ((action == FR_ACTION_RUN) &&
		    request_will_proxy(request)) {
#ifdef DEBUG_STATE_MACHINE
			if (debug_flag) printf("(%u) ********\tWill Proxy\t********\n", request->number);
#endif
			/*
			 *	If this fails, it
			 *	takes care of setting
			 *	up the post proxy fail
			 *	handler.
			 */
			if (request_proxy(request, 0) < 0) goto done;
		} else
#endif
		{
#ifdef DEBUG_STATE_MACHINE
			if (debug_flag) printf("(%u) ********\tFinished\t********\n", request->number);
#endif

#ifdef WITH_COA
			/*
			 *	Maybe originate a CoA request.
			 */
			if ((action == FR_ACTION_RUN) && request->coa) {
				request_coa_originate(request);
			}
#endif

		done:
			request_finish(request, action);

#ifdef DEBUG_STATE_MACHINE
			if (debug_flag) printf("(%u) ********\tSTATE %s C%u -> C%u\t********\n", request->number, __FUNCTION__, request->child_state, REQUEST_DONE);
#endif

#ifdef HAVE_PTHREAD_H
			request->child_pid = NO_SUCH_CHILD_PID;
#endif	
			request->child_state = REQUEST_DONE;
		}
		break;

	default:
		RDEBUG3("%s: Ignoring action %s", __FUNCTION__, action_codes[action]);
		break;
	}
}

int request_receive(rad_listen_t *listener, RADIUS_PACKET *packet,
		    RADCLIENT *client, RAD_REQUEST_FUNP fun)
{
	int count;
	RADIUS_PACKET **packet_p;
	REQUEST *request = NULL;
	struct timeval now;
	listen_socket_t *sock = listener->data;

	/*
	 *	Set the last packet received.
	 */
	gettimeofday(&now, NULL);
	sock->last_packet = now.tv_sec;

	packet_p = fr_packet_list_find(pl, packet);
	if (packet_p) {
		request = fr_packet2myptr(REQUEST, packet, packet_p);
		rad_assert(request->in_request_hash);

		/*
		 *	Same src/dst ip/port, length, and
		 *	authentication vector: must be a duplicate.
		 */
		if ((request->packet->data_len == packet->data_len) &&
		    (memcmp(request->packet->vector, packet->vector,
			    sizeof(packet->vector)) == 0)) {

#ifdef WITH_STATS
			switch (packet->code) {
			case PW_AUTHENTICATION_REQUEST:
				FR_STATS_INC(auth, total_dup_requests);
				break;

#ifdef WITH_ACCOUNTING
			case PW_ACCOUNTING_REQUEST:
				FR_STATS_INC(acct, total_dup_requests);
				break;
#endif					     
#ifdef WITH_COA
			case PW_COA_REQUEST:
				FR_STATS_INC(coa, total_dup_requests);
				break;

			case PW_DISCONNECT_REQUEST:
				FR_STATS_INC(dsc, total_dup_requests);
				break;
#endif

			default:
			  break;
			}
#endif	/* WITH_STATS */

			request->process(request, FR_ACTION_DUP);
			return 0;
		}

		/*
		 *	Say we're ignoring the old one, and continue
		 *	to process the new one.
		 */
		request->process(request, FR_ACTION_CONFLICTING);
		request = NULL;
	}

	/*
	 *	Quench maximum number of outstanding requests.
	 */
	if (mainconfig.max_requests &&
	    ((count = fr_packet_list_num_elements(pl)) > mainconfig.max_requests)) {
		static time_t last_complained = 0;

		radlog(L_ERR, "Dropping request (%d is too many): from client %s port %d - ID: %d", count,
		       client->shortname,
		       packet->src_port, packet->id);
		radlog(L_INFO, "WARNING: Please check the configuration file.\n"
		       "\tThe value for 'max_requests' is probably set too low.\n");

		/*
		 *	Complain once every 10 seconds.
		 */
		if ((last_complained + 10) < now.tv_sec) {
			last_complained = now.tv_sec;
			exec_trigger(NULL, NULL, "server.max_requests");
		}

		return 0;
	}

	return request_insert(listener, packet, client, fun, &now);
}

int request_insert(rad_listen_t *listener, RADIUS_PACKET *packet,
		   RADCLIENT *client, RAD_REQUEST_FUNP fun,
		   struct timeval *pnow)
{
	REQUEST *request;

	/*
	 *	Create and initialize the new request.
	 */
	request = request_alloc(); /* never fails */
	
	if ((request->reply = rad_alloc(0)) == NULL) {
		radlog(L_ERR, "No memory");
		request_free(&request);
		return 1;
	}

	request->listener = listener;
	request->client = client;
	request->packet = packet;
	request->packet->timestamp = *pnow;
	request->number = request_num_counter++;
	request->priority = listener->type;
	request->master_state = REQUEST_ACTIVE;
#ifdef DEBUG_STATE_MACHINE
	if (debug_flag) printf("(%u) ********\tSTATE %s C%u -> C%u\t********\n", request->number, __FUNCTION__, request->child_state, REQUEST_ACTIVE);
#endif
	request->child_state = REQUEST_ACTIVE;
	request->handle = fun;
	request->options = RAD_REQUEST_OPTION_DEBUG2;
#ifdef HAVE_PTHREAD_H
	request->child_pid = NO_SUCH_CHILD_PID;
#endif

#ifdef WITH_STATS
	request->listener->stats.last_packet = request->packet->timestamp.tv_sec;
	if (packet->code == PW_AUTHENTICATION_REQUEST) {
		request->client->auth.last_packet = request->packet->timestamp.tv_sec;
		radius_auth_stats.last_packet = request->packet->timestamp.tv_sec;
#ifdef WITH_ACCOUNTING
	} else if (packet->code == PW_ACCOUNTING_REQUEST) {
		request->client->acct.last_packet = request->packet->timestamp.tv_sec;
		radius_acct_stats.last_packet = request->packet->timestamp.tv_sec;
#endif
	}
#endif	/* WITH_STATS */

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
		request_done(request, FR_ACTION_DONE);
		return 1;
	}

	request->in_request_hash = TRUE;
	request->root = &mainconfig;
	mainconfig.refcount++;
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

	request_queue_or_run(request, request_running);

	return 1;
}

#ifdef WITH_TCP
#ifdef WITH_PROXY
/***********************************************************************
 *
 *	TCP Handlers.
 *
 ***********************************************************************/

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
	struct timeval now;
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

static int remove_all_proxied_requests(void *ctx, void *data)
{
	rad_listen_t *this = ctx;
	RADIUS_PACKET **proxy_p = data;
	REQUEST *request;
	
	request = fr_packet2myptr(REQUEST, proxy, proxy_p);
	if (request->proxy->sockfd != this->fd) return 0;

	request_done(request, FR_ACTION_DONE);
	return 0;
}
#endif	/* WITH_PROXY */

static int remove_all_requests(void *ctx, void *data)
{
	rad_listen_t *this = ctx;
	RADIUS_PACKET **packet_p = data;
	REQUEST *request;
	
	request = fr_packet2myptr(REQUEST, packet, packet_p);
	if (request->packet->sockfd != this->fd) return 0;

	request_done(request, FR_ACTION_DONE);
	return 0;
}
#endif	/* WITH_TCP */

#ifdef WITH_PROXY
/***********************************************************************
 *
 *	Proxy handlers for the state machine.
 *
 ***********************************************************************/

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
#endif
	request->proxy_listener = NULL;

	/*
	 *	Got from YES in hash, to NO, not in hash while we hold
	 *	the mutex.  This guarantees that when another thread
	 *	grabs the mutex, the "not in hash" flag is correct.
	 */
	request->in_proxy_hash = FALSE;

  	PTHREAD_MUTEX_UNLOCK(&proxy_mutex);
}

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
		radlog(L_PROXY, "Failed to insert entry into proxy list.");
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
		return 0;
		
	case RLM_MODULE_HANDLED:
		return 0;
	}

	return 1;
}

int request_proxy_reply(RADIUS_PACKET *packet)
{
	RADIUS_PACKET **proxy_p;
	REQUEST *request;
	struct timeval now;
	char buffer[128];

	PTHREAD_MUTEX_LOCK(&proxy_mutex);
	proxy_p = fr_packet_list_find_byreply(proxy_list, packet);

	if (!proxy_p) {
		PTHREAD_MUTEX_UNLOCK(&proxy_mutex);
		radlog(L_PROXY, "No outstanding request was found for reply from host %s port %d - ID %d",
		       inet_ntop(packet->src_ipaddr.af,
				 &packet->src_ipaddr.ipaddr,
				 buffer, sizeof(buffer)),
		       packet->src_port, packet->id);
		return 0;
	}

	request = fr_packet2myptr(REQUEST, proxy, proxy_p);
	request->num_proxied_responses++; /* needs to be protected by lock */

	PTHREAD_MUTEX_UNLOCK(&proxy_mutex);

	/*
	 *	No reply, BUT the current packet fails verification:
	 *	ignore it.  This does the MD5 calculations in the
	 *	server core, but I guess we can fix that later.
	 */
	if (!request->proxy_reply &&
	    (rad_verify(packet, request->proxy,
			request->home_server->secret) != 0)) {
		DEBUG("Ignoring spoofed proxy reply.  Signature is invalid");
		return 0;
	}

	/*
	 *	The home server sent us a packet which doesn't match
	 *	something we have: ignore it.  This is done only to
	 *	catch the case of broken systems.
	 */
	if (request->proxy_reply &&
	    (memcmp(request->proxy_reply->vector,
		    packet->vector,
		    sizeof(request->proxy_reply->vector)) != 0)) {
		RDEBUG2("Ignoring conflicting proxy reply");
		return 0;
	}

	gettimeofday(&now, NULL);

	/*
	 *	Status-Server packets don't count as real packets.
	 */
	if (request->proxy->code != PW_STATUS_SERVER) {
		listen_socket_t *sock = request->proxy_listener->data;

		request->home_server->last_packet = now.tv_sec;
		sock->last_packet = now.tv_sec;
	}

	/*
	 *	If we have previously seen a reply, ignore the
	 *	duplicate.
	 */
	if (request->proxy_reply) {
		RDEBUG2("Discarding duplicate reply from host %s port %d  - ID: %d",
			inet_ntop(packet->src_ipaddr.af,
				  &packet->src_ipaddr.ipaddr,
				  buffer, sizeof(buffer)),
			packet->src_port, packet->id);
		return 0;
	}

	/*
	 *	Call the state machine to do something useful with the
	 *	request.
	 */
	request->proxy_reply = packet;
	packet->timestamp = now;
	request->priority = RAD_LISTEN_PROXY;

#ifdef WITH_STATS
	request->home_server->stats.last_packet = packet->timestamp.tv_sec;
	request->proxy_listener->stats.last_packet = packet->timestamp.tv_sec;

	if (request->proxy->code == PW_AUTHENTICATION_REQUEST) {
		proxy_auth_stats.last_packet = packet->timestamp.tv_sec;
#ifdef WITH_ACCOUNTING
	} else if (request->proxy->code == PW_ACCOUNTING_REQUEST) {
		proxy_acct_stats.last_packet = packet->timestamp.tv_sec;
#endif
	}
#endif	/* WITH_STATS */

#ifdef WITH_COA
	/*
	 *	When we originate CoA requests, we patch them in here
	 *	so that they don't affect the rest of the state
	 *	machine.
	 */
	if (request->parent) {
		rad_assert(request->parent->coa == request);
		rad_assert((request->proxy->code == PW_COA_REQUEST) ||
			   (request->proxy->code == PW_DISCONNECT_REQUEST));
		rad_assert(request->process != NULL);
		request_coa_separate(request);
	}
#endif

	request->process(request, FR_ACTION_PROXY_REPLY);
	
	return 1;
}


static int setup_post_proxy_fail(REQUEST *request)
{
	const DICT_VALUE *dval = NULL;
	VALUE_PAIR *vp;

	if (request->proxy->code == PW_AUTHENTICATION_REQUEST) {
		dval = dict_valbyname(PW_POST_PROXY_TYPE, 0,
				      "Fail-Authentication");
		
	} else if (request->proxy->code == PW_ACCOUNTING_REQUEST) {
		dval = dict_valbyname(PW_POST_PROXY_TYPE, 0,
				      "Fail-Accounting");
#ifdef WITH_COA
	} else if (request->proxy->code == PW_COA_REQUEST) {
		dval = dict_valbyname(PW_POST_PROXY_TYPE, 0, "Fail-CoA");

	} else if (request->proxy->code == PW_DISCONNECT_REQUEST) {
		dval = dict_valbyname(PW_POST_PROXY_TYPE, 0, "Fail-Disconnect");
#endif
	} else {
		DEBUG("WARNING: Unknown packet type in Post-Proxy-Type Fail: ignoring");
		return 0;
	}
	
	if (!dval) dval = dict_valbyname(PW_POST_PROXY_TYPE, 0, "Fail");
	
	if (!dval) {
		DEBUG("No Post-Proxy-Type Fail: ignoring");
		pairdelete(&request->config_items, PW_POST_PROXY_TYPE, 0);
		return 0;
	}
	
	vp = pairfind(request->config_items, PW_POST_PROXY_TYPE, 0);
	if (!vp) vp = radius_paircreate(request, &request->config_items,
					PW_POST_PROXY_TYPE, 0, PW_TYPE_INTEGER);
	vp->vp_integer = dval->value;

	return 1;
}

static void request_post_proxy(REQUEST *request, int action)
{
	TRACE_STATE_MACHINE;

	switch (action) {
	case FR_ACTION_CONFLICTING:
	case FR_ACTION_DUP:
	case FR_ACTION_TIMER:
	case FR_ACTION_PROXY_REPLY:
		request_common(request, action);
		break;

	case FR_ACTION_RUN:
		request_running(request, FR_ACTION_PROXY_REPLY);
		break;

	default:
		RDEBUG3("%s: Ignoring action %s", __FUNCTION__, action_codes[action]);
		break;
	}
}

static void request_virtual_server(REQUEST *request, int action)
{
	TRACE_STATE_MACHINE;

	switch (action) {
	case FR_ACTION_CONFLICTING:
	case FR_ACTION_DUP:
	case FR_ACTION_TIMER:
	case FR_ACTION_PROXY_REPLY:
		request_common(request, action);
		break;

	case FR_ACTION_RUN:
		request_running(request, action);
		break;

	default:
		RDEBUG3("%s: Ignoring action %s", __FUNCTION__, action_codes[action]);
		break;
	}
}


static int request_will_proxy(REQUEST *request)
{
	int rcode, pre_proxy_type = 0;
	const char *realmname = NULL;
	VALUE_PAIR *vp, *strippedname;
	home_server *home;
	REALM *realm = NULL;
	home_pool_t *pool = NULL;

	if (!request->root->proxy_requests) return 0;
	if (request->packet->dst_port == 0) return 0;
	if (request->packet->code == PW_STATUS_SERVER) return 0;
	if (request->in_proxy_hash) return 0;

	/*
	 *	FIXME: for 3.0, allow this only for rejects?
	 */
	if (request->reply->code != 0) return 0;

	vp = pairfind(request->config_items, PW_PROXY_TO_REALM, 0);
	if (vp) {
		realm = realm_find2(vp->vp_strvalue);
		if (!realm) {
			RDEBUG2("ERROR: Cannot proxy to unknown realm %s",
				vp->vp_strvalue);
			return 0;
		}

		realmname = vp->vp_strvalue;

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
			/*
			 *	FIXME: This is likely wrong.  We don't
			 *	want to set Proxy-To-Realm for CoA
			 *	packets.  OR, we have a CoA pool
			 *	specifically for them.
			 */
			pool = realm->acct_pool;
#endif

		} else {
			return 0;
		}

	} else {
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
	}
	
	if (!pool) {
		RDEBUG2(" WARNING: Cancelling proxy as no home pool exists");
		return 0;
	}

	request->home_pool = pool;

	home = home_server_ldb(realmname, pool, request);
	if (!home) {
		RDEBUG2("ERROR: Failed to find live home server: Cancelling proxy");
		return 0;
	}

#ifdef WITH_COA
	/*
	 *	Once we've decided to proxy a request, we cannot send
	 *	a CoA packet.  So we free up any CoA packet here.
	 */
	if (request->coa) request_done(request->coa, FR_ACTION_DONE);
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
		memcpy(vp->vp_strvalue, request->packet->vector,
		       sizeof(request->packet->vector));
		vp->length = sizeof(request->packet->vector);
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

	return 1;
}

static int request_proxy(REQUEST *request, int retransmit)
{
	char buffer[128];

	rad_assert(request->parent == NULL);
	rad_assert(request->home_server != NULL);

#ifdef WITH_COA
	if (request->coa) {
		RDEBUG("WARNING: Cannot proxy and originate CoA packets at the same time.  Cancelling CoA request");
		request_done(request->coa, FR_ACTION_DONE);
	}
#endif

	/*
	 *	The request may be sent to a virtual server.  If we're
	 *	in a child thread, just process it here. If we're the
	 *	master, push it back onto the queue for later
	 *	processing.
	 */
	if (request->home_server->server) {
		if (!we_are_master()) {
			request_virtual_server(request, FR_ACTION_RUN);
#ifdef HAVE_PTHREAD_H
			request->child_pid = NO_SUCH_CHILD_PID;
#endif
			return 1;
		}

		request_queue_or_run(request, request_virtual_server);
		return 1;
	}

	/*
	 *	We're actually sending a proxied packet.  Do that now.
	 */
	if (!insert_into_proxy_hash(request)) {
		radlog(L_PROXY, "Failed to insert request %u into proxy list.",
			request->number);
		return -1;
	}

	request->proxy_listener->encode(request->proxy_listener, request);

	RDEBUG2("Proxying request to home server %s port %d",
	       inet_ntop(request->proxy->dst_ipaddr.af,
			 &request->proxy->dst_ipaddr.ipaddr,
			 buffer, sizeof(buffer)),
		request->proxy->dst_port);

	DEBUG_PACKET(request, request->proxy, 1);

	gettimeofday(&request->proxy_retransmit, NULL);
	if (!retransmit) request->proxy->timestamp = request->proxy_retransmit;

#ifdef HAVE_PTHREAD_H
	request->child_pid = NO_SUCH_CHILD_PID;
#endif
	request->proxy_listener->send(request->proxy_listener,
				      request);
	return 1;
}

/*
 *	Proxy the packet as if it was new.
 */
static int request_proxy_anew(REQUEST *request)
{
	/*
	 *	Keep a copy of the old Id so that the
	 *	re-transmitted request doesn't re-use the old
	 *	Id.
	 */
	RADIUS_PACKET old = *request->proxy;
	home_server *home;
	home_server *old_home = request->home_server;
#ifdef WITH_TCP
	rad_listen_t *listener = request->proxy_listener;
#endif

	rad_assert(old_home != NULL);
	
	/*
	 *	Find a live home server for the request.
	 */
	home = home_server_ldb(NULL, request->home_pool, request);
	if (!home) {
		RDEBUG2("ERROR: Failed to find live home server for request");
	post_proxy_fail:
		remove_from_proxy_hash(request);

		if (!setup_post_proxy_fail(request)) {
			return 0;
		}
		
		request_queue_or_run(request, request_post_proxy);
		return 0;
	}

	/*
	 *	Don't free the old Id on error.
	 */
	if (!insert_into_proxy_hash(request)) {
		radlog(L_PROXY,"Failed to insert retransmission of request %u into the proxy list.", request->number);
		goto post_proxy_fail;
	}

	/*
	 *	Now that we have a new Id, free the old one
	 *	and update the various statistics.
	 */
	PTHREAD_MUTEX_LOCK(&proxy_mutex);
	fr_packet_list_yank(proxy_list, &old);
	fr_packet_list_id_free(proxy_list, &old);
	old_home->currently_outstanding--;
#ifdef WITH_TCP
	if (listener) listener->count--;
#endif
	PTHREAD_MUTEX_UNLOCK(&proxy_mutex);

	/*
	 *	Free the old packet, to force re-encoding
	 */
	free(request->proxy->data);
	request->proxy->data = NULL;
	request->proxy->data_len = 0;

#ifdef WITH_ACCOUNTING
	/*
	 *	Update the Acct-Delay-Time attribute.
	 */
	if (request->packet->code == PW_ACCOUNTING_REQUEST) {
		VALUE_PAIR *vp;

		vp = pairfind(request->proxy->vps, PW_ACCT_DELAY_TIME, 0);
		if (!vp) vp = radius_paircreate(request,
						&request->proxy->vps,
						PW_ACCT_DELAY_TIME, 0,
						PW_TYPE_INTEGER);
		if (vp) {
			struct timeval now;
			
			gettimeofday(&now, NULL);
			vp->vp_integer += now.tv_sec - request->proxy_retransmit.tv_sec;
		}
	}
#endif

	if (request_proxy(request, 1) != 1) goto post_proxy_fail;

	return 1;
}

static void request_ping(REQUEST *request, int action)
{
	home_server *home = request->home_server;
	char buffer[128];

	TRACE_STATE_MACHINE;
	ASSERT_MASTER;

	switch (action) {
	case FR_ACTION_TIMER:
		radlog(L_ERR, "No response to status check %d for home server %s port %d",
		       request->number,
		       inet_ntop(request->proxy->dst_ipaddr.af,
				 &request->proxy->dst_ipaddr.ipaddr,
				 buffer, sizeof(buffer)),
		       request->proxy->dst_port);
		break;

	case FR_ACTION_PROXY_REPLY:
		rad_assert(request->in_proxy_hash);

		request->home_server->num_received_pings++;
		radlog(L_PROXY, "Received response to status check %d (%d in current sequence)",
		       request->number, home->num_received_pings);

		/*
		 *	Remove the request from any hashes
		 */
		fr_event_delete(el, &request->ev);
		remove_from_proxy_hash(request);

		/*
		 *	The control socket may have marked the home server as
		 *	alive.  OR, it may have suddenly started responding to
		 *	requests again.  If so, don't re-do the "make alive"
		 *	work.
		 */
		if (home->state == HOME_STATE_ALIVE) break;
		
		/*
		 *	We haven't received enough ping responses to mark it
		 *	"alive".  Wait a bit.
		 */
		if (home->num_received_pings < home->num_pings_to_alive) {
			break;
		}

		/*
		 *	Mark it alive and delete any outstanding
		 *	pings.
		 */
		home->state = HOME_STATE_ALIVE;
		exec_trigger(request, request->home_server->cs, "home_server.alive");
		home->currently_outstanding = 0;
		home->num_sent_pings = 0;
		home->num_received_pings = 0;
		gettimeofday(&home->revive_time, NULL);
		
		fr_event_delete(el, &home->ev);

		radlog(L_PROXY, "Marking home server %s port %d alive",
		       inet_ntop(request->proxy->dst_ipaddr.af,
				 &request->proxy->dst_ipaddr.ipaddr,
				 buffer, sizeof(buffer)),
		       request->proxy->dst_port);
		break;

	default:
		RDEBUG3("%s: Ignoring action %s", __FUNCTION__, action_codes[action]);
		break;
	}

	rad_assert(!request->in_request_hash);
	rad_assert(request->ev == NULL);
	request_done(request, FR_ACTION_DONE);
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
	struct timeval when, now;

	if ((home->state == HOME_STATE_ALIVE) ||
	    (home->ping_check == HOME_PING_CHECK_NONE) ||
#ifdef WITH_TCP
	    (home->proto == IPPROTO_TCP) ||
#endif
	    (home->ev != NULL)) {
		return;
	}

	gettimeofday(&now, NULL);

	if (home->state == HOME_STATE_ZOMBIE) {
		when = home->zombie_period_start;
		when.tv_sec += home->zombie_period;

		if (timercmp(&when, &now, <)) {
			DEBUG("PING: Zombie period is over");
			mark_home_server_dead(home, &now);
		}
	}

	request = request_alloc();
	request->number = request_num_counter++;
#ifdef HAVE_PTHREAD_H
	request->child_pid = NO_SUCH_CHILD_PID;
#endif

	request->proxy = rad_alloc(1);
	rad_assert(request->proxy != NULL);

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

	vp = radius_pairmake(request, &request->proxy->vps,
			     "NAS-Identifier", "", T_OP_SET);
	if (vp) {
		snprintf(vp->vp_strvalue, sizeof(vp->vp_strvalue),
			 "Status Check %u. Are you alive?",
			 home->num_sent_pings);
		vp->length = strlen(vp->vp_strvalue);
	}

	request->proxy->dst_ipaddr = home->ipaddr;
	request->proxy->dst_port = home->port;
	request->home_server = home;
#ifdef DEBUG_STATE_MACHINE
	if (debug_flag) printf("(%u) ********\tSTATE %s C%u -> C%u\t********\n", request->number, __FUNCTION__, request->child_state, REQUEST_DONE);
	if (debug_flag) printf("(%u) ********\tNEXT-STATE %s -> %s\n", request->number, __FUNCTION__, "request_ping");
#endif
#ifdef HAVE_PTHREAD_H
	rad_assert(request->child_pid == NO_SUCH_CHILD_PID);
#endif
	request->child_state = REQUEST_DONE;
	request->process = request_ping;

	rad_assert(request->proxy_listener == NULL);

	if (!insert_into_proxy_hash(request)) {
		radlog(L_PROXY, "Failed to insert status check %d into proxy list.  Discarding it.",
		       request->number);

		rad_assert(!request->in_request_hash);
		rad_assert(!request->in_proxy_hash);
		rad_assert(request->ev == NULL);
		request_free(&request);
		return;
	}

	/*
	 *	Set up the timer callback.
	 */
	when = now;
	when.tv_sec += home->ping_timeout;

	DEBUG("PING: Waiting %u seconds for response to ping",
	      home->ping_timeout);
	fr_event_insert(el, request_timer, request, &when,
			&request->ev);
	home->num_sent_pings++;

	rad_assert(request->proxy_listener != NULL);
	request->proxy_listener->send(request->proxy_listener,
				      request);

	/*
	 *	Add +/- 2s of jitter, as suggested in RFC 3539
	 *	and in the Issues and Fixes draft.
	 */
	home->when = now;
	home->when.tv_sec += home->ping_interval - 2;

	jitter = fr_rand();
	jitter ^= (jitter >> 10);
	jitter &= ((1 << 23) - 1); /* 22 bits of 1 */

	tv_add(&home->when, jitter);

	DEBUG("PING: Next status packet in %u seconds", home->ping_interval);
	INSERT_EVENT(ping_home_server, home);
}

static void home_trigger(home_server *home, const char *trigger)
{
	REQUEST my_request;
	RADIUS_PACKET my_packet;

	memset(&my_request, 0, sizeof(my_request));
	memset(&my_packet, 0, sizeof(my_packet));
	my_request.proxy = &my_packet;
	my_packet.dst_ipaddr = home->ipaddr;
	my_packet.src_ipaddr = home->src_ipaddr;

	exec_trigger(&my_request, home->cs, trigger);
}

static void mark_home_server_zombie(home_server *home)
{
	char buffer[128];

	ASSERT_MASTER;

	rad_assert(home->state == HOME_STATE_ALIVE);

#ifdef WITH_TCP
	if (home->proto == IPPROTO_TCP) {
		DEBUG("WARNING: Not marking TCP server zombie");
		return;
	}
#endif

	home->state = HOME_STATE_ZOMBIE;
	home_trigger(home, "home_server.zombie");

	home->zombie_period_start.tv_sec = home->last_packet;
	home->zombie_period_start.tv_usec = USEC / 2;
	
	fr_event_delete(el, &home->ev);
	home->num_sent_pings = 0;
	home->num_received_pings = 0;
	
	radlog(L_PROXY, "Marking home server %s port %d as zombie (it looks like it is dead).",
	       inet_ntop(home->ipaddr.af, &home->ipaddr.ipaddr,
			 buffer, sizeof(buffer)),
	       home->port);

	ping_home_server(home);
}


void revive_home_server(void *ctx)
{
	home_server *home = ctx;
	char buffer[128];

#ifdef WITH_TCP
	rad_assert(home->proto != IPPROTO_TCP);
#endif

	home->state = HOME_STATE_ALIVE;
	home_trigger(home, "home_server.alive");
	home->currently_outstanding = 0;
	gettimeofday(&home->revive_time, NULL);

	/*
	 *	Delete any outstanding events.
	 */
	if (home->ev) fr_event_delete(el, &home->ev);

	radlog(L_PROXY, "Marking home server %s port %d alive again... we have no idea if it really is alive or not.",
	       inet_ntop(home->ipaddr.af, &home->ipaddr.ipaddr,
			 buffer, sizeof(buffer)),
	       home->port);
}

void mark_home_server_dead(home_server *home, struct timeval *when)
{
	int previous_state = home->state;
	char buffer[128];

#ifdef WITH_TCP
	if (home->proto == IPPROTO_TCP) {
		DEBUG("WARNING: Not marking TCP server dead");
		return;
	}
#endif

	radlog(L_PROXY, "Marking home server %s port %d as dead.",
	       inet_ntop(home->ipaddr.af, &home->ipaddr.ipaddr,
			 buffer, sizeof(buffer)),
	       home->port);

	home->state = HOME_STATE_IS_DEAD;
	home_trigger(home, "home_server.dead");

	if (home->ping_check != HOME_PING_CHECK_NONE) {
		/*
		 *	If the control socket marks us dead, start
		 *	pinging.  Otherwise, we already started
		 *	pinging when it was marked "zombie".
		 */
		if (previous_state == HOME_STATE_ALIVE) {
			ping_home_server(home);
		} else {
			DEBUG("PING: Already pinging home server");
		}

	} else {
		/*
		 *	Revive it after a fixed period of time.  This
		 *	is very, very, bad.
		 */
		home->when = *when;
		home->when.tv_sec += home->revive_interval;

		DEBUG("PING: Reviving home server in %u seconds",
			home->revive_interval);
		INSERT_EVENT(revive_home_server, home);
	}
}

static void request_proxied(REQUEST *request, int action)
{
	struct timeval now, when;
	home_server *home = request->home_server;
	char buffer[128];

	TRACE_STATE_MACHINE;

	rad_assert(request->packet->code != PW_STATUS_SERVER);
	rad_assert(request->home_server != NULL);

	gettimeofday(&now, NULL);

	rad_assert(request->child_state != REQUEST_DONE);

	if (request->master_state == REQUEST_STOP_PROCESSING) {
		request_done(request, FR_ACTION_DONE);
		return;
	}

	switch (action) {
	case FR_ACTION_DUP:
		if ((home->state == HOME_STATE_IS_DEAD) ||
		    (request->proxy_listener->status != RAD_LISTEN_STATUS_KNOWN)) {
			request_proxy_anew(request);
			return;
		}

#ifdef WITH_TCP
		if (home->proto == IPPROTO_TCP) {
			DEBUG2("Suppressing duplicate proxied request to home server %s port %d proto TCP - ID: %d",
			       inet_ntop(request->proxy->dst_ipaddr.af,
					 &request->proxy->dst_ipaddr.ipaddr,
					 buffer, sizeof(buffer)),
			       request->proxy->dst_port,
			       request->proxy->id);
			return;
		}
#endif

#ifdef WITH_ACCOUNTING
		/*
		 *	If we update the Acct-Delay-Time, we need to
		 *	get a new ID.
		 */
		if ((request->packet->code == PW_ACCOUNTING_REQUEST) &&
		    pairfind(request->proxy->vps, PW_ACCT_DELAY_TIME, 0)) {
			request_proxy_anew(request);
			return;
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
		/* FALL-THROUGH */

	case FR_ACTION_TIMER:
		/*
		 *	If we haven't received a packet for a while,
		 *	mark it as zombie.  If the connection is TCP,
		 *	then another "watchdog timer" function takes
		 *	care of pings, etc.
		 */
		if ((home->state == HOME_STATE_ALIVE) &&
#ifdef WITH_TCP
		    (home->proto != IPPROTO_TCP) &&
#endif
		    ((home->last_packet + ((home->zombie_period + 3) / 4)) < now.tv_sec)) {
			mark_home_server_zombie(home);
		}

		when = request->proxy->timestamp;
		when.tv_sec += home->response_window;

		/*
		 *	Not at the response window.  Set the timer for
		 *	that.
		 */
		if (timercmp(&when, &now, >)) {
			fr_event_insert(el, request_timer, request,
					&when, &request->ev);
			return;
		}

		/*
		 *	FIXME: debug log no response to proxied request
		 */

		/*
		 *	No response, but we're supposed to do nothing
		 *	when there's no response.  The request is finished.
		 */
		if (!home->no_response_fail) {
#ifdef HAVE_PTHREAD_H
			request->child_pid = NO_SUCH_CHILD_PID;
#endif
			gettimeofday(&request->reply->timestamp, NULL);
#ifdef DEBUG_STATE_MACHINE
			if (debug_flag) printf("(%u) ********\tSTATE %s C%u -> C%u\t********\n", request->number, __FUNCTION__, request->child_state, REQUEST_DONE);
#endif
#ifdef HAVE_PTHREAD_H
			rad_assert(request->child_pid == NO_SUCH_CHILD_PID);
#endif
			request->child_state = REQUEST_DONE;
			request_process_timer(request);
			return;
		}

		/*
		 *	Do "fail on no response".
		 */
		radlog_request(L_ERR, 0, request, "Rejecting request (proxy Id %d) due to lack of any response from home server %s port %d",
			       request->proxy->id,
			       inet_ntop(request->proxy->dst_ipaddr.af,
					 &request->proxy->dst_ipaddr.ipaddr,
					 buffer, sizeof(buffer)),
			       request->proxy->dst_port);

		if (!setup_post_proxy_fail(request)) {
			return;
		}
		/* FALL-THROUGH */

		/*
		 *	Duplicate proxy replies have been quenched by
		 *	now.  This state is only called ONCE, when we
		 *	receive a new reply from the home server.
		 */
	case FR_ACTION_PROXY_REPLY:
		request_queue_or_run(request, request_post_proxy);
		break;

	case FR_ACTION_CONFLICTING:
		request_done(request, action);
		return;

	default:
		RDEBUG3("%s: Ignoring action %s", __FUNCTION__, action_codes[action]);
		break;
	}
}
#endif	/* WITH_PROXY */

/***********************************************************************
 *
 *  CoA code
 *
 ***********************************************************************/
#ifdef WITH_COA
static int null_handler(UNUSED REQUEST *request)
{
	return 0;
}

/*
 *	See if we need to originate a CoA request.
 */
static void request_coa_originate(REQUEST *request)
{
	int rcode, pre_proxy_type = 0;
	VALUE_PAIR *vp;
	REQUEST *coa;
	fr_ipaddr_t ipaddr;
	char buffer[256];

	rad_assert(request != NULL);
	rad_assert(request->coa != NULL);
	rad_assert(request->proxy == NULL);
	rad_assert(!request->in_proxy_hash);
	rad_assert(request->proxy_reply == NULL);

	/*
	 *	Check whether we want to originate one, or cancel one.
	 */
	vp = pairfind(request->config_items, PW_SEND_COA_REQUEST, 0);
	if (!vp) {
		vp = pairfind(request->coa->proxy->vps, PW_SEND_COA_REQUEST, 0);
	}

	if (vp) {
		if (vp->vp_integer == 0) {
		fail:
			request_done(request->coa, FR_ACTION_DONE);
			return;
		}
	}

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
			goto fail;
		}

		/*
		 *	Prefer the pool to one server
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
	coa->num_coa_requests = 0;
	coa->handle = null_handler;
	coa->number = request->number ^ (1 << 24);

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
		radlog(L_PROXY, "Failed to insert CoA request into proxy list.");
		goto fail;
	}

	/*
	 *	We CANNOT divorce the CoA request from the parent
	 *	request.  This function is running in a child thread,
	 *	and we need access to the main event loop in order to
	 *	to add the timers for the CoA packet.
	 *
	 *	Instead, we wait for the timer on the parent request
	 *	to fire.
	 */
	gettimeofday(&coa->proxy->timestamp, NULL);
	coa->packet->timestamp = coa->proxy->timestamp; /* for max_request_time */
	coa->delay = 0;		/* need to calculate a new delay */

	DEBUG_PACKET(coa, coa->proxy, 1);

	coa->process = request_coa_process;
#ifdef DEBUG_STATE_MACHINE
	if (debug_flag) printf("(%u) ********\tSTATE %s C%u -> C%u\t********\n", request->number, __FUNCTION__, request->child_state, REQUEST_ACTIVE);
#endif
	coa->child_state = REQUEST_ACTIVE;
	rad_assert(coa->proxy_reply == NULL);
	coa->proxy_listener->send(coa->proxy_listener, coa);
}


static void request_coa_separate(REQUEST *request)
{
#ifdef DEBUG_STATE_MACHINE
	int action = FR_ACTION_TIMER;
#endif
	TRACE_STATE_MACHINE;

	rad_assert(request->parent != NULL);
	rad_assert(request->parent->coa == request);
	rad_assert(request->ev == NULL);
	rad_assert(!request->in_request_hash);

	request->parent->coa = NULL;
	request->parent = NULL;

	/*
	 *	Set up timers for the CoA request.  These do all kinds
	 *	of different things....
	 */
	request_coa_timer(request);
}

static void request_coa_timer(REQUEST *request)
{
	int delay, frac;
	struct timeval now, when, mrd;

	rad_assert(request->parent == NULL);

	if (request->proxy_reply) return request_process_timer(request);

	gettimeofday(&now, NULL);

	if (request->delay == 0) {
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
		
		when = request->proxy->timestamp;
		tv_add(&when, delay);

		if (timercmp(&when, &now, >)) {
			fr_event_insert(el, request_timer, request, &when,
					&request->ev);
			return;
		}
	}

	/*
	 *	Retransmit CoA request.
	 */

	/*
	 *	Cap count at MRC, if it is non-zero.
	 */
	if (request->home_server->coa_mrc &&
	    (request->num_coa_requests >= request->home_server->coa_mrc)) {
		if (!setup_post_proxy_fail(request)) {
			return;
		}
		
		request_queue_or_run(request, request_post_proxy);
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
	when = now;
	tv_add(&when, request->delay);
	mrd = request->proxy->timestamp;
	mrd.tv_sec += request->home_server->coa_mrd;

	/*
	 *	Cap duration at MRD.
	 */
	if (timercmp(&mrd, &when, <)) {
		when = mrd;
	}
	fr_event_insert(el, request_timer, request, &when, &request->ev);

	request->num_coa_requests++; /* is NOT reset by code 3 lines above! */

	request->proxy_listener->send(request->proxy_listener,
				      request);
}


static void request_coa_post_proxy(REQUEST *request, int action)
{
	TRACE_STATE_MACHINE;

	switch (action) {
	case FR_ACTION_TIMER:
		request_coa_timer(request);
		break;
	       
	case FR_ACTION_PROXY_REPLY:
		request_common(request, action);
		break;

	case FR_ACTION_RUN:
		request_running(request, FR_ACTION_PROXY_REPLY);
		break;

	default:
		RDEBUG3("%s: Ignoring action %s", __FUNCTION__, action_codes[action]);
		break;
	}
}


/*
 *	Process CoA requests that we originated.
 */
static void request_coa_process(REQUEST *request, int action)
{
	TRACE_STATE_MACHINE;

	switch (action) {
	case FR_ACTION_TIMER:
		request_coa_timer(request);
		break;
		
	case FR_ACTION_PROXY_REPLY:
		rad_assert(request->parent == NULL);
#ifdef HAVE_PTHREAD_H
		/*
		 *	Catch the case of a proxy reply when called
		 *	from the main worker thread.
		 */
		if (we_are_master() &&
		    (request->process != request_coa_post_proxy)) {
			request_queue_or_run(request, request_coa_post_proxy);
			return;
		}
		/* FALL-THROUGH */
#endif
	case FR_ACTION_RUN:
		request_running(request, action);
		break;
		
	default:
		RDEBUG3("%s: Ignoring action %s", __FUNCTION__, action_codes[action]);
		break;
	}
}

#endif	/* WITH_COA */

/***********************************************************************
 *
 *  End of the State machine.  Start of additional helper code.
 *
 ***********************************************************************/

/***********************************************************************
 *
 *	Event handlers.
 *
 ***********************************************************************/
static void event_socket_handler(fr_event_list_t *xel, UNUSED int fd,
				 void *ctx)
{
	rad_listen_t *listener = ctx;

	rad_assert(xel == el);

	xel = xel;

	if (
#ifdef WITH_DETAIL
	    (listener->type != RAD_LISTEN_DETAIL) &&
#endif
	    (listener->fd < 0)) {
		char buffer[256];

		listener->print(listener, buffer, sizeof(buffer));
		radlog(L_ERR, "FATAL: Asked to read from closed socket: %s",
		       buffer);
	
		rad_panic("Socket was closed on us!");
		_exit(1);
	}
	
	listener->recv(listener);
}

#ifdef WITH_DETAIL
/*
 *	This function is called periodically to see if this detail
 *	file is available for reading.
 */
static void event_poll_detail(void *ctx)
{
	int delay;
	rad_listen_t *this = ctx;
	struct timeval when, now;
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
#endif

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
			int count;

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

#ifdef WITH_DETAIL
		rad_assert(this->type != RAD_LISTEN_DETAIL);
#endif

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

/***********************************************************************
 *
 *	Signal handlers.
 *
 ***********************************************************************/

static void handle_signal_self(int flag)
{
	if ((flag & (RADIUS_SIGNAL_SELF_EXIT | RADIUS_SIGNAL_SELF_TERM)) != 0) {
		if ((flag & RADIUS_SIGNAL_SELF_EXIT) != 0) {
			radlog(L_INFO, "Signalled to exit");
			fr_event_loop_exit(el, 1);
		} else {
			radlog(L_INFO, "Signalled to terminate");
			exec_trigger(NULL, NULL, "server.signal.term");
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

		exec_trigger(NULL, NULL, "server.signal.hup");
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
		struct timeval when, now;
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

/***********************************************************************
 *
 *	Bootstrapping code.
 *
 ***********************************************************************/

/*
 *	Externally-visibly functions.
 */
int radius_event_init(CONF_SECTION *cs, int have_children)
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
	NO_SUCH_CHILD_PID = pthread_self(); /* not a child thread */

	/*
	 *	Initialize the threads ONLY if we're spawning, AND
	 *	we're running normally.
	 */
	if (have_children && !check_config &&
	    (thread_pool_init(cs, &have_children) < 0)) {
		exit(1);
	}
#endif

	/*
	 *	Move all of the thread calls to this file?
	 *
	 *	It may be best for the mutexes to be in this file...
	 */
	spawn_flag = have_children;

	if (check_config) {
		DEBUG("%s: #### Skipping IP addresses and Ports ####",
		       mainconfig.name);
		if (listen_init(cs, &head, spawn_flag) < 0) {
			fflush(NULL);
			exit(1);
		}
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
       if (listen_init(cs, &head, spawn_flag) < 0) {
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

	request_done(request, FR_ACTION_DONE);

	return 0;
}


#ifdef WITH_PROXY
static int proxy_hash_cb(UNUSED void *ctx, void *data)
{
	REQUEST *request = fr_packet2myptr(REQUEST, proxy, data);

	request_done(request, FR_ACTION_DONE);

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
