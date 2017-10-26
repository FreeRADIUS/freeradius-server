/*
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
 */

/**
 * $Id$
 *
 * @file process.c
 * @brief Defines the state machines that control how requests are processed.
 *
 * @copyright 2012  The FreeRADIUS server project
 * @copyright 2012  Alan DeKok <aland@deployingradius.com>
 */

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/process.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/state.h>

#include <freeradius-devel/rad_assert.h>

#ifdef WITH_DETAIL
#include <freeradius-devel/detail.h>
#endif

#include <signal.h>
#include <fcntl.h>

#ifdef HAVE_SYS_WAIT_H
#	include <sys/wait.h>
#endif

extern pid_t radius_pid;
extern fr_cond_t *debug_condition;

static bool spawn_flag = false;
static bool just_started = true;
time_t fr_start_time = (time_t)-1;
static rbtree_t *pl = NULL;
static fr_event_list_t *el = NULL;

fr_event_list_t *radius_event_list_corral(UNUSED event_corral_t hint) {
	/* Currently we do not run a second event loop for modules. */
	return el;
}

static char const *action_codes[] = {
	"INVALID",
	"run",
	"done",
	"dup",
	"timer",
#ifdef WITH_PROXY
	"proxy-reply"
#endif
};

#ifdef DEBUG_STATE_MACHINE
#  define TRACE_STATE_MACHINE \
if (rad_debug_lvl) do { \
	struct timeval debug_tv; \
	gettimeofday(&debug_tv, NULL); \
	debug_tv.tv_sec -= fr_start_time; \
	printf("(%u) %d.%06d ********\tSTATE %s action %s live M-%s C-%s\t********\n",\
	       request->number, (int) debug_tv.tv_sec, (int) debug_tv.tv_usec, \
	       __FUNCTION__, action_codes[action], master_state_names[request->master_state], \
	       child_state_names[request->child_state]); \
} while (0)

static char const *master_state_names[REQUEST_MASTER_NUM_STATES] = {
	"?",
	"active",
	"stop-processing",
	"counted"
};

static char const *child_state_names[REQUEST_CHILD_NUM_STATES] = {
	"?",
	"queued",
	"running",
	"proxied",
	"reject-delay",
	"cleanup-delay",
	"done"
};

#else
#  define TRACE_STATE_MACHINE {}
#endif

static NEVER_RETURNS void _rad_panic(char const *file, unsigned int line, char const *msg)
{
	ERROR("%s[%u]: %s", file, line, msg);
	fr_exit_now(1);
}

#define rad_panic(x) _rad_panic(__FILE__, __LINE__, x)

/** Declare a state in the state machine
 *
 * Expands to the start of a function definition for a given state.
 *
 * @param _x the name of the state.
 */
#define STATE_MACHINE_DECL(_x) static void _x(REQUEST *request, int action)

static void request_timer(void *ctx);

/** Insert #REQUEST back into the event heap, to continue executing at a future time
 *
 * @param file the state machine timer call occurred in.
 * @param line the state machine timer call occurred on.
 * @param request to set add the timer event for.
 * @param when the event should fine.
 * @param action to perform when we resume processing the request.
 */
static inline void state_machine_timer(char const *file, int line, REQUEST *request,
				       struct timeval *when, fr_state_action_t action)
{
	request->timer_action = action;
	if (!fr_event_insert(el, request_timer, request, when, &request->ev)) {
		_rad_panic(file, line, "Failed to insert event");
	}
}

/** @copybrief state_machine_timer
 *
 * @param _x the action to perform when we resume processing the request.
 */
#define STATE_MACHINE_TIMER(_x) state_machine_timer(__FILE__, __LINE__, request, &when, _x)

/*
 *	We need a different VERIFY_REQUEST macro in process.c
 *	To avoid the race conditions with the master thread
 *	checking the REQUEST whilst it's being worked on by
 *	the child.
 */
#if defined(WITH_VERIFY_PTR) && defined(HAVE_PTHREAD_H)
#  undef VERIFY_REQUEST
#  define VERIFY_REQUEST(_x) if (pthread_equal(pthread_self(), _x->child_pid) != 0) verify_request(__FILE__, __LINE__, _x)
#endif

/**
 * @section request_timeline
 *
 *	Time sequence of a request
 * @code
 *
 *	RQ-----------------P=============================Y-J-C
 *	 ::::::::::::::::::::::::::::::::::::::::::::::::::::::::M
 * @endcode
 *
 * -	R: received.  Duplicate detection is done, and request is
 * 	   cached.
 *
 * -	Q: Request is placed onto a queue for child threads to pick up.
 *	   If there are no child threads, the request goes immediately
 *	   to P.
 *
 * -	P: Processing the request through the modules.
 *
 * -	Y: Reply is ready.  Rejects MAY be delayed here.  All other
 *	   replies are sent immediately.
 *
 * -	J: Reject is sent "response_delay" after the reply is ready.
 *
 * -	C: For Access-Requests, After "cleanup_delay", the request is
 *	   deleted.  Accounting-Request packets go directly from Y to C.
 *
 * -	M: Max request time.  If the request hits this timer, it is
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
static TALLOC_CTX *proxy_ctx = NULL;
#endif

#ifdef HAVE_PTHREAD_H
#  ifdef WITH_PROXY
static pthread_mutex_t proxy_mutex;
static bool proxy_no_new_sockets = false;
#  endif

#  define PTHREAD_MUTEX_LOCK if (spawn_flag) pthread_mutex_lock
#  define PTHREAD_MUTEX_UNLOCK if (spawn_flag) pthread_mutex_unlock

static pthread_t NO_SUCH_CHILD_PID;
#  define NO_CHILD_THREAD request->child_pid = NO_SUCH_CHILD_PID

#else
/*
 *	This is easier than ifdef's throughout the code.
 */
#  define PTHREAD_MUTEX_LOCK(_x)
#  define PTHREAD_MUTEX_UNLOCK(_x)
#  define NO_CHILD_THREAD
#endif

#ifdef HAVE_PTHREAD_H
static bool we_are_master(void)
{
	if (spawn_flag &&
	    (pthread_equal(pthread_self(), NO_SUCH_CHILD_PID) == 0)) {
		return false;
	}

	return true;
}

/*
 *	Assertions are debug checks.
 */
#  ifndef NDEBUG
#    define ASSERT_MASTER 	if (!we_are_master()) rad_panic("We are not master")
#    endif
#else

/*
 *	No threads: we're always master.
 */
#  define we_are_master(_x) (1)
#endif	/* HAVE_PTHREAD_H */

#ifndef ASSERT_MASTER
#  define ASSERT_MASTER
#endif

/*
 *	Make state transitions simpler.
 */
#define FINAL_STATE(_x) NO_CHILD_THREAD; request->component = "<" #_x ">"; request->module = ""; request->child_state = _x


static int event_new_fd(rad_listen_t *this);

/*
 *	We need mutexes around the event FD list *only* in certain
 *	cases.
 */
#if defined (HAVE_PTHREAD_H) && (defined(WITH_PROXY) || defined(WITH_TCP))
static rad_listen_t *new_listeners = NULL;

static pthread_mutex_t	fd_mutex;
#  define FD_MUTEX_LOCK if (spawn_flag) pthread_mutex_lock
#  define FD_MUTEX_UNLOCK if (spawn_flag) pthread_mutex_unlock

void radius_update_listener(rad_listen_t *this)
{
	/*
	 *	Just do it ourselves.
	 */
	if (we_are_master()) {
		event_new_fd(this);
		return;
	}

	FD_MUTEX_LOCK(&fd_mutex);

	/*
	 *	If it's already in the list, don't add it again.
	 */
	if (this->next) {
		FD_MUTEX_UNLOCK(&fd_mutex);
		return;
	}

	/*
	 *	Otherwise, add it to the list
	 */
	this->next = new_listeners;
	new_listeners = this;
	FD_MUTEX_UNLOCK(&fd_mutex);
	radius_signal_self(RADIUS_SIGNAL_SELF_NEW_FD);
}
#else
void radius_update_listener(rad_listen_t *this)
{
	/*
	 *	No threads.  Just insert it.
	 */
	event_new_fd(this);
}
/*
 *	This is easier than ifdef's throughout the code.
 */
#  define FD_MUTEX_LOCK(_x)
#  define FD_MUTEX_UNLOCK(_x)
#endif

static int request_num_counter = 1;
#ifdef WITH_PROXY
static int request_will_proxy(REQUEST *request) CC_HINT(nonnull);
static int request_proxy(REQUEST *request) CC_HINT(nonnull);
STATE_MACHINE_DECL(request_ping) CC_HINT(nonnull);

STATE_MACHINE_DECL(request_response_delay) CC_HINT(nonnull);
STATE_MACHINE_DECL(request_cleanup_delay) CC_HINT(nonnull);
STATE_MACHINE_DECL(request_running) CC_HINT(nonnull);
STATE_MACHINE_DECL(request_done) CC_HINT(nonnull);

STATE_MACHINE_DECL(proxy_no_reply) CC_HINT(nonnull);
STATE_MACHINE_DECL(proxy_running) CC_HINT(nonnull);
STATE_MACHINE_DECL(proxy_wait_for_reply) CC_HINT(nonnull);

static int process_proxy_reply(REQUEST *request, RADIUS_PACKET *reply) CC_HINT(nonnull (1));
static void remove_from_proxy_hash(REQUEST *request) CC_HINT(nonnull);
static void remove_from_proxy_hash_nl(REQUEST *request, bool yank) CC_HINT(nonnull);
static int insert_into_proxy_hash(REQUEST *request) CC_HINT(nonnull);
static int setup_post_proxy_fail(REQUEST *request);
#endif

static REQUEST *request_setup(TALLOC_CTX *ctx, rad_listen_t *listener, RADIUS_PACKET *packet,
			      RADCLIENT *client, RAD_REQUEST_FUNP fun);
static int request_pre_handler(REQUEST *request, UNUSED int action) CC_HINT(nonnull);

#ifdef WITH_COA
static void request_coa_originate(REQUEST *request) CC_HINT(nonnull);
STATE_MACHINE_DECL(coa_wait_for_reply) CC_HINT(nonnull);
STATE_MACHINE_DECL(coa_no_reply) CC_HINT(nonnull);
STATE_MACHINE_DECL(coa_running) CC_HINT(nonnull);
static void coa_separate(REQUEST *request) CC_HINT(nonnull);
#  define COA_SEPARATE if (request->coa) coa_separate(request->coa);
#else
#  define COA_SEPARATE
#endif

#define CHECK_FOR_STOP do { if (request->master_state == REQUEST_STOP_PROCESSING) {request_done(request, FR_ACTION_DONE);return;}} while (0)

#undef USEC
#define USEC (1000000)

#define INSERT_EVENT(_function, _ctx) if (!fr_event_insert(el, _function, _ctx, &((_ctx)->when), &((_ctx)->ev))) { _rad_panic(__FILE__, __LINE__, "Failed to insert event"); }

static void tv_add(struct timeval *tv, int usec_delay)
{
	if (usec_delay >= USEC) {
		tv->tv_sec += usec_delay / USEC;
		usec_delay %= USEC;
	}
	tv->tv_usec += usec_delay;

	if (tv->tv_usec >= USEC) {
		tv->tv_sec += tv->tv_usec / USEC;
		tv->tv_usec %= USEC;
	}
}

/*
 *	Debug the packet if requested.
 */
static void debug_packet(REQUEST *request, RADIUS_PACKET *packet, bool received)
{
	char src_ipaddr[128];
	char dst_ipaddr[128];

	if (!packet) return;
	if (!RDEBUG_ENABLED) return;

#ifdef WITH_DETAIL
	/*
	 *	Don't print IP addresses for detail files.
	 */
	if (request->listener &&
	    (request->listener->type == RAD_LISTEN_DETAIL)) return;

#endif
	/*
	 *	Client-specific debugging re-prints the input
	 *	packet into the client log.
	 *
	 *	This really belongs in a utility library
	 */
	if (is_radius_code(packet->code)) {
		RDEBUG("%s %s Id %i from %s%s%s:%i to %s%s%s:%i length %zu",
		       received ? "Received" : "Sent",
		       fr_packet_codes[packet->code],
		       packet->id,
		       packet->src_ipaddr.af == AF_INET6 ? "[" : "",
		       inet_ntop(packet->src_ipaddr.af,
				 &packet->src_ipaddr.ipaddr,
				 src_ipaddr, sizeof(src_ipaddr)),
		       packet->src_ipaddr.af == AF_INET6 ? "]" : "",
		       packet->src_port,
		       packet->dst_ipaddr.af == AF_INET6 ? "[" : "",
		       inet_ntop(packet->dst_ipaddr.af,
				 &packet->dst_ipaddr.ipaddr,
				 dst_ipaddr, sizeof(dst_ipaddr)),
		       packet->dst_ipaddr.af == AF_INET6 ? "]" : "",
		       packet->dst_port,
		       packet->data_len);
	} else {
		RDEBUG("%s code %u Id %i from %s%s%s:%i to %s%s%s:%i length %zu\n",
		       received ? "Received" : "Sent",
		       packet->code,
		       packet->id,
		       packet->src_ipaddr.af == AF_INET6 ? "[" : "",
		       inet_ntop(packet->src_ipaddr.af,
				 &packet->src_ipaddr.ipaddr,
				 src_ipaddr, sizeof(src_ipaddr)),
		       packet->src_ipaddr.af == AF_INET6 ? "]" : "",
		       packet->src_port,
		       packet->dst_ipaddr.af == AF_INET6 ? "[" : "",
		       inet_ntop(packet->dst_ipaddr.af,
				 &packet->dst_ipaddr.ipaddr,
				 dst_ipaddr, sizeof(dst_ipaddr)),
		       packet->dst_ipaddr.af == AF_INET6 ? "]" : "",
		       packet->dst_port,
		       packet->data_len);
	}

	if (received) {
		rdebug_pair_list(L_DBG_LVL_1, request, packet->vps, NULL);
	} else {
		rdebug_proto_pair_list(L_DBG_LVL_1, request, packet->vps);
	}
}


/***********************************************************************
 *
 *	Start of RADIUS server state machine.
 *
 ***********************************************************************/

static struct timeval *request_response_window(REQUEST *request)
{
	VERIFY_REQUEST(request);

	rad_assert(request->home_server != NULL);

	if (request->client) {
		/*
		 *	The client hasn't set the response window.  Return
		 *	either the home server one, if set, or the global one.
		 */
		if (!timerisset(&request->client->response_window)) {
			return &request->home_server->response_window;
		}

		if (timercmp(&request->client->response_window,
			     &request->home_server->response_window, <)) {
			return &request->client->response_window;
		}
	}

	return &request->home_server->response_window;
}

/*
 * Determine initial request processing delay.
 */
static int request_init_delay(REQUEST *request)
{
	struct timeval half_response_window;

	VERIFY_REQUEST(request);

	/* Allow client response window to lower initial delay */
	if (timerisset(&request->client->response_window)) {
		half_response_window.tv_sec = request->client->response_window.tv_sec >> 1;
		half_response_window.tv_usec =
			((request->client->response_window.tv_sec & 1) * USEC +
				request->client->response_window.tv_usec) >> 1;
		if (timercmp(&half_response_window, &request->root->init_delay, <))
			return (int)half_response_window.tv_sec * USEC +
				(int)half_response_window.tv_usec;
	}

	return (int)request->root->init_delay.tv_sec * USEC +
		(int)request->root->init_delay.tv_usec;
}

/*
 *	Callback for ALL timer events related to the request.
 */
static void request_timer(void *ctx)
{
	REQUEST *request = talloc_get_type_abort(ctx, REQUEST);
	int action;

	action = request->timer_action;

	TRACE_STATE_MACHINE;

	request->process(request, action);
}

/*
 *	Wrapper for talloc pools.  If there's no parent, just free the
 *	request.  If there is a parent, free the parent INSTEAD of the
 *	request.
 */
static void request_free(REQUEST *request)
{
	void *ptr;

	rad_assert(request->ev == NULL);
	rad_assert(!request->in_request_hash);
	rad_assert(!request->in_proxy_hash);

	if ((request->options & RAD_REQUEST_OPTION_CTX) == 0) {
		talloc_free(request);
		return;
	}

	ptr = talloc_parent(request);
	rad_assert(ptr != NULL);
	talloc_free(ptr);
}


#ifdef WITH_PROXY
static void proxy_reply_too_late(REQUEST *request)
{
	char buffer[128];

	RDEBUG2("Reply from home server %s port %d  - ID: %d arrived too late.  Try increasing 'retry_delay' or 'max_request_time'",
		inet_ntop(request->proxy->dst_ipaddr.af,
			  &request->proxy->dst_ipaddr.ipaddr,
			  buffer, sizeof(buffer)),
		request->proxy->dst_port, request->proxy->id);
}
#endif


/** Mark a request DONE and clean it up.
 *
 *  When a request is DONE, it can have ties to a number of other
 *  portions of the server.  The request hash, proxy hash, events,
 *  child threads, etc.  This function takes care of either cleaning
 *  up the request, or managing the timers to wait for the ties to be
 *  removed.
 *
 *  \dot
 *	digraph done {
 *		done -> done [ label = "still running" ];
 *	}
 *  \enddot
 */
static void request_done(REQUEST *request, int action)
{
	struct timeval now, when;

	VERIFY_REQUEST(request);

	TRACE_STATE_MACHINE;

	/*
	 *	Force this no matter what.
	 */
	request->process = request_done;

#ifdef WITH_DETAIL
	/*
	 *	Tell the detail listener that we're done.
	 */
	if (request->listener &&
	    (request->listener->type == RAD_LISTEN_DETAIL) &&
	    (request->simul_max != 1)) {
		request->simul_max = 1;
		request->listener->send(request->listener,
					request);
	}
#endif

#ifdef HAVE_PTHREAD_H
	/*
	 *	If called from a child thread, mark ourselves as done,
	 *	and wait for the master thread timer to clean us up.
	 */
	if (!we_are_master()) {
		FINAL_STATE(REQUEST_DONE);
		return;
	}
#endif

	/*
	 *	Mark the request as STOP.
	 */
	request->master_state = REQUEST_STOP_PROCESSING;

#ifdef WITH_COA
	/*
	 *	Move the CoA request to its own handler.
	 */
	if (request->coa) {
		coa_separate(request->coa);
	} else if (request->parent && (request->parent->coa == request)) {
		coa_separate(request);
	}
#endif

	/*
	 *	It doesn't hurt to send duplicate replies.  All other
	 *	signals are ignored, as the request will be cleaned up
	 *	soon anyways.
	 */
	switch (action) {
	case FR_ACTION_DUP:
#ifdef WITH_DETAIL
		rad_assert(request->listener != NULL);
#endif
		if (request->reply->code != 0) {
			request->listener->send(request->listener, request);
			return;
		} else {
			RDEBUG("No reply.  Ignoring retransmit");
		}
		break;

		/*
		 *	Mark the request as done.
		 */
	case FR_ACTION_DONE:
#ifdef HAVE_PTHREAD_H
		/*
		 *	If the child is still running, leave it alone.
		 */
		if (spawn_flag && (request->child_state <= REQUEST_RUNNING)) {
			break;
		}
#endif

#ifdef DEBUG_STATE_MACHINE
		if (rad_debug_lvl) printf("(%u) ********\tSTATE %s C-%s -> C-%s\t********\n",
				       request->number, __FUNCTION__,
				       child_state_names[request->child_state],
				       child_state_names[REQUEST_DONE]);
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
	case FR_ACTION_PROXY_REPLY:
		proxy_reply_too_late(request);
		break;
#endif

	default:
		break;
	}

	/*
	 *	Remove it from the request hash.
	 */
	if (request->in_request_hash) {
		if (!rbtree_deletebydata(pl, &request->packet)) {
			rad_assert(0 == 1);
		}
		request->in_request_hash = false;
	}

#ifdef WITH_PROXY
	/*
	 *	Wait for the proxy ID to expire.  This allows us to
	 *	avoid re-use of proxy IDs for a while.
	 */
	if (request->in_proxy_hash) {
		rad_assert(request->proxy != NULL);

		fr_event_now(el, &now);
		when = request->proxy->timestamp;

#ifdef WITH_COA
		if (((request->proxy->code == PW_CODE_COA_REQUEST) ||
		     (request->proxy->code == PW_CODE_DISCONNECT_REQUEST)) &&
		    (request->packet->code != request->proxy->code)) {
			when.tv_sec += request->home_server->coa_mrd;
		} else
#endif
			timeradd(&when, request_response_window(request), &when);

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

#ifdef HAVE_PTHREAD_H
	/*
	 *	If there's no children, we can mark the request as done.
	 */
	if (!spawn_flag) request->child_state = REQUEST_DONE;
#endif

	/*
	 *	If the child is still running, wait for it to be finished.
	 */
	if (request->child_state <= REQUEST_RUNNING) {
		gettimeofday(&now, NULL);
#ifdef WITH_PROXY
	wait_some_more:
#endif
		when = now;
		if (request->delay < (USEC / 3)) request->delay = USEC / 3;
		tv_add(&when, request->delay);
		request->delay += request->delay >> 1;
		if (request->delay > (10 * USEC)) request->delay = 10 * USEC;

		STATE_MACHINE_TIMER(FR_ACTION_TIMER);
		return;
	}

#ifdef HAVE_PTHREAD_H
	rad_assert(request->child_pid == NO_SUCH_CHILD_PID);
#endif

	/*
	 *	@todo: do final states for TCP sockets, too?
	 */
	request_stats_final(request);
#ifdef WITH_TCP
	if (request->listener) {
		request->listener->count--;

		/*
		 *	If we're the last one, remove the listener now.
		 */
		if ((request->listener->count == 0) &&
		    (request->listener->status >= RAD_LISTEN_STATUS_FROZEN)) {
			event_new_fd(request->listener);
		}
	}
#endif

	if (request->packet) {
		RDEBUG2("Cleaning up request packet ID %u with timestamp +%d",
			request->packet->id,
			(unsigned int) (request->timestamp - fr_start_time));
	} /* else don't print anything */

	ASSERT_MASTER;
	fr_event_delete(el, &request->ev);
	request_free(request);
}


static void request_cleanup_delay_init(REQUEST *request)
{
	struct timeval now, when;

	VERIFY_REQUEST(request);

	/*
	 *	Do cleanup delay ONLY for RADIUS packets from a real
	 *	client.  Everything else just gets cleaned up
	 *	immediately.
	 */
	if (request->packet->dst_port == 0) goto done;

	/*
	 *	Accounting packets shouldn't be retransmitted.  They
	 *	should always be updated with Acct-Delay-Time.
	 */
#ifdef WITH_ACCOUNTING
	if (request->packet->code == PW_CODE_ACCOUNTING_REQUEST) goto done;
#endif

#ifdef WITH_DHCP
	if (request->listener->type == RAD_LISTEN_DHCP) goto done;
#endif

#ifdef WITH_VMPS
	if (request->listener->type == RAD_LISTEN_VQP) goto done;
#endif

	if (!request->root->cleanup_delay) goto done;

	gettimeofday(&now, NULL);

	rad_assert(request->reply->timestamp.tv_sec != 0);
	when = request->reply->timestamp;

	request->delay = request->root->cleanup_delay;
	when.tv_sec += request->delay;

	/*
	 *	Set timer for when we need to clean it up.
	 */
	if (timercmp(&when, &now, >)) {
#ifdef DEBUG_STATE_MACHINE
		if (rad_debug_lvl) printf("(%u) ********\tNEXT-STATE %s -> %s\n", request->number, __FUNCTION__, "request_cleanup_delay");
#endif
		request->process = request_cleanup_delay;

		if (!we_are_master()) {
			FINAL_STATE(REQUEST_CLEANUP_DELAY);
			return;
		}

		/*
		 *	Update this if we can, otherwise let the timers pick it up.
		 */
		request->child_state = REQUEST_CLEANUP_DELAY;
#ifdef HAVE_PTHREAD_H
		rad_assert(request->child_pid == NO_SUCH_CHILD_PID);
#endif
		STATE_MACHINE_TIMER(FR_ACTION_TIMER);
		return;
	}

	/*
	 *	Otherwise just clean it up.
	 */
done:
	request_done(request, FR_ACTION_DONE);
}


/*
 *	Enforce max_request_time.
 */
static bool request_max_time(REQUEST *request)
{
	struct timeval now, when;
	rad_assert(request->magic == REQUEST_MAGIC);
#ifdef DEBUG_STATE_MACHINE
	int action = FR_ACTION_TIMER;
#endif

	VERIFY_REQUEST(request);

	TRACE_STATE_MACHINE;
	ASSERT_MASTER;

	/*
	 *	The child thread has acknowledged it's done.
	 *	Transition to the DONE state.
	 *
	 *	If the request was marked STOP, then the "check for
	 *	stop" macro already took care of it.
	 */
	if (request->child_state == REQUEST_DONE) {
	done:
		request_done(request, FR_ACTION_DONE);
		return true;
	}

	/*
	 *	The request is still running.  Enforce max_request_time.
	 */
	fr_event_now(el, &now);
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
			ERROR("Unresponsive child for request %u, in component %s module %s",
			      request->number,
			      request->component ? request->component : "<core>",
			      request->module ? request->module : "<core>");
			exec_trigger(request, NULL, "server.thread.unresponsive", true);
		}
#endif
		/*
		 *	Tell the request that it's done.
		 */
		goto done;
	}

	/*
	 *	Sleep for some more.  We HOPE that the child will
	 *	become responsive at some point in the future.  We do
	 *	this by adding 50% to the current timer.
	 */
	when = now;
	tv_add(&when, request->delay);
	request->delay += request->delay >> 1;
	STATE_MACHINE_TIMER(FR_ACTION_TIMER);
	return false;
}

static void request_queue_or_run(REQUEST *request,
				 fr_request_process_t process)
{
#ifdef DEBUG_STATE_MACHINE
	int action = FR_ACTION_TIMER;
#endif

	VERIFY_REQUEST(request);

	TRACE_STATE_MACHINE;

	/*
	 *	Do this here so that fewer other functions need to do
	 *	it.
	 */
	if (request->master_state == REQUEST_STOP_PROCESSING) {
#ifdef DEBUG_STATE_MACHINE
		if (rad_debug_lvl) printf("(%u) ********\tSTATE %s M-%s causes C-%s-> C-%s\t********\n",
				       request->number, __FUNCTION__,
				       master_state_names[request->master_state],
				       child_state_names[request->child_state],
				       child_state_names[REQUEST_DONE]);
#endif
		request_done(request, FR_ACTION_DONE);
		return;
	}

	request->process = process;

	if (we_are_master()) {
		struct timeval when;

		/*
		 *	(re) set the initial delay.
		 */
		request->delay = request_init_delay(request);
		if (request->delay > USEC) request->delay = USEC;
		gettimeofday(&when, NULL);
		tv_add(&when, request->delay);
		request->delay += request->delay >> 1;

		STATE_MACHINE_TIMER(FR_ACTION_TIMER);

#ifdef HAVE_PTHREAD_H
		if (spawn_flag) {
			/*
			 *	A child thread will eventually pick it up.
			 */
			if (request_enqueue(request)) return;

			/*
			 *	Otherwise we're not going to do anything with
			 *	it...
			 */
			request_done(request, FR_ACTION_DONE);
			return;
		}
#endif
	}

	request->child_state = REQUEST_RUNNING;
	request->process(request, FR_ACTION_RUN);

#ifdef WNOHANG
	/*
	 *	Requests that care about child process exit
	 *	codes have already either called
	 *	rad_waitpid(), or they've given up.
	 */
	while (waitpid(-1, NULL, WNOHANG) > 0);
#endif
}


static void request_dup(REQUEST *request)
{
	ERROR("(%u) Ignoring duplicate packet from "
	      "client %s port %d - ID: %u due to unfinished request "
	      "in component %s module %s",
	      request->number, request->client->shortname,
	      request->packet->src_port,request->packet->id,
	      request->component, request->module);
}


/** Sit on a request until it's time to clean it up.
 *
 *  A NAS may not see a response from the server.  When the NAS
 *  retransmits, we want to be able to send a cached reply back.  The
 *  alternative is to re-process the packet, which does bad things for
 *  EAP, among others.
 *
 *  IF we do see a NAS retransmit, we extend the cleanup delay,
 *  because the NAS might miss our cached reply.
 *
 *  Otherwise, once we reach cleanup_delay, we transition to DONE.
 *
 *  \dot
 *	digraph cleanup_delay {
 *		cleanup_delay;
 *		send_reply [ label = "send_reply\nincrease cleanup delay" ];
 *
 *		cleanup_delay -> send_reply [ label = "DUP" ];
 *		send_reply -> cleanup_delay;
 *		cleanup_delay -> proxy_reply_too_late [ label = "PROXY_REPLY", arrowhead = "none" ];
 *		cleanup_delay -> cleanup_delay [ label = "TIMER < timeout" ];
 *		cleanup_delay -> done [ label = "TIMER >= timeout" ];
 *	}
 *  \enddot
 */
static void request_cleanup_delay(REQUEST *request, int action)
{
	struct timeval when, now;

	VERIFY_REQUEST(request);

	TRACE_STATE_MACHINE;
	ASSERT_MASTER;
	COA_SEPARATE;
	CHECK_FOR_STOP;

	switch (action) {
	case FR_ACTION_DUP:
		if (request->reply->code != 0) {
			request->listener->send(request->listener, request);
		} else {
			RDEBUG("No reply.  Ignoring retransmit");
		}

		/*
		 *	Double the cleanup_delay to catch retransmits.
		 */
		when = request->reply->timestamp;
		request->delay += request->delay;
		when.tv_sec += request->delay;

		STATE_MACHINE_TIMER(FR_ACTION_TIMER);
		break;

#ifdef WITH_PROXY
	case FR_ACTION_PROXY_REPLY:
		proxy_reply_too_late(request);
		break;
#endif

	case FR_ACTION_TIMER:
		fr_event_now(el, &now);

		rad_assert(request->root->cleanup_delay > 0);

		when = request->reply->timestamp;
		when.tv_sec += request->root->cleanup_delay;

		if (timercmp(&when, &now, >)) {
#ifdef DEBUG_STATE_MACHINE
			if (rad_debug_lvl) printf("(%u) ********\tNEXT-STATE %s -> %s\n", request->number, __FUNCTION__, "request_cleanup_delay");
#endif
			STATE_MACHINE_TIMER(FR_ACTION_TIMER);
			return;
		} /* else it's time to clean up */

		request_done(request, FR_ACTION_DONE);
		break;

	default:
		RDEBUG3("%s: Ignoring action %s", __FUNCTION__, action_codes[action]);
		break;
	}
}


/** Sit on a request until it's time to respond to it.
 *
 *  For security reasons, rejects (and maybe some other) packets are
 *  delayed for a while before we respond.  This delay means that
 *  badly behaved NASes don't hammer the server with authentication
 *  attempts.
 *
 *  Otherwise, once we reach response_delay, we send the reply, and
 *  transition to cleanup_delay.
 *
 *  \dot
 *	digraph response_delay {
 *		response_delay -> proxy_reply_too_late [ label = "PROXY_REPLY", arrowhead = "none" ];
 *		response_delay -> response_delay [ label = "DUP, TIMER < timeout" ];
 *		response_delay -> send_reply [ label = "TIMER >= timeout" ];
 *		send_reply -> cleanup_delay;
 *	}
 *  \enddot
 */
static void request_response_delay(REQUEST *request, int action)
{
	struct timeval when, now;

	VERIFY_REQUEST(request);

	TRACE_STATE_MACHINE;
	ASSERT_MASTER;
	COA_SEPARATE;
	CHECK_FOR_STOP;

	switch (action) {
	case FR_ACTION_DUP:
		RDEBUG("(%u) Discarding duplicate request from "
		      "client %s port %d - ID: %u due to delayed response",
		      request->number, request->client->shortname,
		      request->packet->src_port,request->packet->id);
		break;

#ifdef WITH_PROXY
	case FR_ACTION_PROXY_REPLY:
		proxy_reply_too_late(request);
		break;
#endif

	case FR_ACTION_TIMER:
		fr_event_now(el, &now);

		/*
		 *	See if it's time to send the reply.  If not,
		 *	we wait some more.
		 */
		when = request->reply->timestamp;

		tv_add(&when, request->response_delay.tv_sec * USEC);
		tv_add(&when, request->response_delay.tv_usec);

		if (timercmp(&when, &now, >)) {
#ifdef DEBUG_STATE_MACHINE
			if (rad_debug_lvl) printf("(%u) ********\tNEXT-STATE %s -> %s\n", request->number, __FUNCTION__, "request_response_delay");
#endif
			STATE_MACHINE_TIMER(FR_ACTION_TIMER);
			return;
		} /* else it's time to send the reject */

		RDEBUG2("Sending delayed response");
		debug_packet(request, request->reply, false);
		request->listener->send(request->listener, request);

		/*
		 *	Clean up the request.
		 */
		request_cleanup_delay_init(request);
		break;

	default:
		RDEBUG3("%s: Ignoring action %s", __FUNCTION__, action_codes[action]);
		break;
	}
}


static int request_pre_handler(REQUEST *request, UNUSED int action)
{
	int rcode;

	VERIFY_REQUEST(request);

	TRACE_STATE_MACHINE;

	if (request->master_state == REQUEST_STOP_PROCESSING) return 0;

	/*
	 *	Don't decode the packet if it's an internal "fake"
	 *	request.  Instead, just return so that the caller can
	 *	process it.
	 */
	if (request->packet->dst_port == 0) {
		request->username = fr_pair_find_by_num(request->packet->vps, PW_USER_NAME, 0, TAG_ANY);
		request->password = fr_pair_find_by_num(request->packet->vps, PW_USER_PASSWORD, 0, TAG_ANY);
		return 1;
	}

	if (!request->packet->vps) { /* FIXME: check for correct state */
		rcode = request->listener->decode(request->listener, request);

#ifdef WITH_UNLANG
		if (debug_condition) {
			/*
			 *	Ignore parse errors.
			 */
			if (radius_evaluate_cond(request, RLM_MODULE_OK, 0, debug_condition)) {
				request->log.lvl = L_DBG_LVL_2;
				request->log.func = vradlog_request;
			}
		}
#endif

		debug_packet(request, request->packet, true);
	} else {
		rcode = 0;
	}

	if (rcode < 0) {
		RATE_LIMIT(INFO("Dropping packet without response because of error: %s", fr_strerror()));
		request->reply->offset = -2; /* bad authenticator */
		return 0;
	}

	if (!request->username) {
		request->username = fr_pair_find_by_num(request->packet->vps, PW_USER_NAME, 0, TAG_ANY);
	}

	return 1;
}


/**  Do the final processing of a request before we reply to the NAS.
 *
 *  Various cleanups, suppress responses, copy Proxy-State, and set
 *  response_delay or cleanup_delay;
 */
static void request_finish(REQUEST *request, int action)
{
	VALUE_PAIR *vp;

	VERIFY_REQUEST(request);

	TRACE_STATE_MACHINE;
	CHECK_FOR_STOP;

	(void) action;	/* -Wunused */

#ifdef WITH_COA
	/*
	 *	Don't do post-auth if we're a CoA request originated
	 *	from an Access-Request.  See request_alloc_coa() for
	 *	details.
	 */
	if ((request->options & RAD_REQUEST_OPTION_COA) != 0) goto done;
#endif

	/*
	 *	Override the response code if a control:Response-Packet-Type attribute is present.
	 */
	vp = fr_pair_find_by_num(request->config, PW_RESPONSE_PACKET_TYPE, 0, TAG_ANY);
	if (vp) {
		if (vp->vp_integer == 256) {
			RDEBUG2("Not responding to request");
			request->reply->code = 0;
		} else {
			request->reply->code = vp->vp_integer;
		}
	}
	/*
	 *	Catch Auth-Type := Reject BEFORE proxying the packet.
	 */
	else if (request->packet->code == PW_CODE_ACCESS_REQUEST) {
		if (request->reply->code == 0) {
			vp = fr_pair_find_by_num(request->config, PW_AUTH_TYPE, 0, TAG_ANY);
			if (!vp || (vp->vp_integer != 5)) {
				RDEBUG2("There was no response configured: "
					"rejecting request");
			}

			request->reply->code = PW_CODE_ACCESS_REJECT;
		}
	}

	/*
	 *	Copy Proxy-State from the request to the reply.
	 */
	vp = fr_pair_list_copy_by_num(request->reply, request->packet->vps,
		       PW_PROXY_STATE, 0, TAG_ANY);
	if (vp) fr_pair_add(&request->reply->vps, vp);

	/*
	 *	Call Post-Auth for Access-Request packets.
	 */
	if (request->packet->code == PW_CODE_ACCESS_REQUEST) {
		rad_postauth(request);
	}

#ifdef WITH_COA
	/*
	 *	Maybe originate a CoA request.
	 */
	if ((action == FR_ACTION_RUN) && !request->proxy && request->coa) {
		request_coa_originate(request);
	}
#endif

	/*
	 *	Clean up.  These are no longer needed.
	 */
	gettimeofday(&request->reply->timestamp, NULL);

	/*
	 *	Fake packets get marked as "done", and have the
	 *	proxy-reply section deal with the reply attributes.
	 *	We therefore don't free the reply attributes.
	 */
	if (request->packet->dst_port == 0) {
		RDEBUG("Finished internally proxied request.");
		FINAL_STATE(REQUEST_DONE);
		return;
	}

#ifdef WITH_DETAIL
	/*
	 *	Always send the reply to the detail listener.
	 */
	if (request->listener->type == RAD_LISTEN_DETAIL) {
		request->simul_max = 1;

		/*
		 *	But only print the reply if there is one.
		 */
		if (request->reply->code != 0) {
			debug_packet(request, request->reply, false);
		}

		request->listener->send(request->listener, request);
		goto done;
	}
#endif

	/*
	 *	Ignore all "do not respond" packets.
	 *	Except for the detail ones, which need to ping
	 *	the detail file reader so that it will retransmit.
	 */
	if (!request->reply->code) {
		RDEBUG("Not sending reply to client.");
		goto done;
	}

	/*
	 *	If it's not in the request hash, we MIGHT not want to
	 *	send a reply.
	 *
	 *	If duplicate packets are allowed, then then only
	 *	reason to NOT be in the request hash is because we
	 *	don't want to send a reply.
	 *
	 *	FIXME: this is crap.  The rest of the state handling
	 *	should use a different field so that we don't have two
	 *	meanings for it.
	 *
	 *	Otherwise duplicates are forbidden, and the request is
	 *	SUPPOSED to avoid the request hash.
	 *
	 *	In that case, we need to send a reply.
	 */
	if (!request->in_request_hash &&
	    !request->listener->nodup) {
		RDEBUG("Suppressing reply to client.");
		goto done;
	}

	/*
	 *	See if we need to delay an Access-Reject packet.
	 */
	if ((request->reply->code == PW_CODE_ACCESS_REJECT) &&
	    (request->root->reject_delay.tv_sec > 0)) {
		request->response_delay = request->root->reject_delay;

		vp = fr_pair_find_by_num(request->reply->vps, PW_FREERADIUS_RESPONSE_DELAY, 0, TAG_ANY);
		if (vp) {
			if (vp->vp_integer <= 10) {
				request->response_delay.tv_sec = vp->vp_integer;
			} else {
				request->response_delay.tv_sec = 10;
			}
			request->response_delay.tv_usec = 0;
		} else {
			vp = fr_pair_find_by_num(request->reply->vps, PW_FREERADIUS_RESPONSE_DELAY_USEC, 0, TAG_ANY);
			if (vp) {
				if (vp->vp_integer <= 10 * USEC) {
					request->response_delay.tv_sec = vp->vp_integer / USEC;
					request->response_delay.tv_usec = vp->vp_integer % USEC;
				} else {
					request->response_delay.tv_sec = 10;
					request->response_delay.tv_usec = 0;
				}
			}
		}

#ifdef WITH_PROXY
		/*
		 *	If we timed out a proxy packet, don't delay
		 *	the reject any more.
		 */
		if (request->proxy && !request->proxy_reply) {
			request->response_delay.tv_sec = 0;
			request->response_delay.tv_usec = 0;
		}
#endif
	}

	/*
	 *	Send the reply.
	 */
	if ((request->response_delay.tv_sec == 0) &&
	    (request->response_delay.tv_usec == 0)) {

		/*
		 *	Don't print a reply if there's none to send.
		 */
		if (request->reply->code != 0) {
			if (rad_debug_lvl && request->state &&
			    (request->reply->code == PW_CODE_ACCESS_ACCEPT)) {
				if (!fr_pair_find_by_num(request->packet->vps, PW_STATE, 0, TAG_ANY)) {
					RWDEBUG2("Unused attributes found in &session-state:");
				}
			}

			debug_packet(request, request->reply, false);
			request->listener->send(request->listener, request);
		}

	done:
		RDEBUG2("Finished request");
		request_cleanup_delay_init(request);

	} else {
		/*
		 *	Encode and sign it here, so that the master
		 *	thread can just send the encoded data, which
		 *	means it does less work.
		 */
		RDEBUG2("Delaying response for %d.%06d seconds",
			(int) request->response_delay.tv_sec, (int) request->response_delay.tv_usec);
		request->listener->encode(request->listener, request);
		request->process = request_response_delay;

		FINAL_STATE(REQUEST_RESPONSE_DELAY);
	}
}

/** Process a request from a client.
 *
 *  The outcome might be that the request is proxied.
 *
 *  \dot
 *	digraph running {
 *		running -> running [ label = "TIMER < max_request_time" ];
 *		running -> done [ label = "TIMER >= max_request_time" ];
 *		running -> proxy [ label = "proxied" ];
 *		running -> dup [ label = "DUP", arrowhead = "none" ];
 *	}
 *  \enddot
 */
static void request_running(REQUEST *request, int action)
{
	VERIFY_REQUEST(request);

	TRACE_STATE_MACHINE;
	CHECK_FOR_STOP;

	switch (action) {
	case FR_ACTION_TIMER:
		COA_SEPARATE;
		(void) request_max_time(request);
		break;

	case FR_ACTION_DUP:
		request_dup(request);
		break;

	case FR_ACTION_RUN:
		if (!request_pre_handler(request, action)) {
#ifdef DEBUG_STATE_MACHINE
			if (rad_debug_lvl) printf("(%u) ********\tSTATE %s failed in pre-handler C-%s -> C-%s\t********\n",
					       request->number, __FUNCTION__,
					       child_state_names[request->child_state],
					       child_state_names[REQUEST_DONE]);
#endif
			FINAL_STATE(REQUEST_DONE);
			break;
		}

		rad_assert(request->handle != NULL);
		request->handle(request);

#ifdef WITH_PROXY
		/*
		 *	We may need to send a proxied request.
		 */
		if (request_will_proxy(request)) {
#ifdef DEBUG_STATE_MACHINE
			if (rad_debug_lvl) printf("(%u) ********\tWill Proxy\t********\n", request->number);
#endif
			/*
			 *	If this fails, it
			 *	takes care of setting
			 *	up the post proxy fail
			 *	handler.
			 */
			if (request_proxy(request) < 0) {
				(void) setup_post_proxy_fail(request);
				process_proxy_reply(request, NULL);
				goto req_finished;
			}
		} else
#endif
		{
#ifdef DEBUG_STATE_MACHINE
			if (rad_debug_lvl) printf("(%u) ********\tFinished\t********\n", request->number);
#endif

#ifdef WITH_PROXY
		req_finished:
#endif
			request_finish(request, action);
		}
		break;

	default:
		RDEBUG3("%s: Ignoring action %s", __FUNCTION__, action_codes[action]);
		break;
	}
}

int request_receive(TALLOC_CTX *ctx, rad_listen_t *listener, RADIUS_PACKET *packet,
		    RADCLIENT *client, RAD_REQUEST_FUNP fun)
{
	uint32_t count;
	RADIUS_PACKET **packet_p;
	REQUEST *request = NULL;
	struct timeval now;
	listen_socket_t *sock = NULL;

	VERIFY_PACKET(packet);

	/*
	 *	Set the last packet received.
	 */
	gettimeofday(&now, NULL);

	packet->timestamp = now;

#ifdef WITH_ACCOUNTING
	if (listener->type != RAD_LISTEN_DETAIL)
#endif

#ifdef WITH_TCP
	{
		sock = listener->data;
		sock->last_packet = now.tv_sec;

		packet->proto = sock->proto;
	}
#endif

	/*
	 *	Skip everything if required.
	 */
	if (listener->nodup) goto skip_dup;

	packet_p = rbtree_finddata(pl, &packet);
	if (packet_p) {
		rad_child_state_t child_state;

		request = fr_packet2myptr(REQUEST, packet, packet_p);
		rad_assert(request->in_request_hash);
		child_state = request->child_state;

		/*
		 *	Same src/dst ip/port, length, and
		 *	authentication vector: must be a duplicate.
		 */
		if ((request->packet->data_len == packet->data_len) &&
		    (memcmp(request->packet->vector, packet->vector,
			    sizeof(packet->vector)) == 0)) {

#ifdef WITH_STATS
			switch (packet->code) {
			case PW_CODE_ACCESS_REQUEST:
				FR_STATS_INC(auth, total_dup_requests);
				break;

#ifdef WITH_ACCOUNTING
			case PW_CODE_ACCOUNTING_REQUEST:
				FR_STATS_INC(acct, total_dup_requests);
				break;
#endif
#ifdef WITH_COA
			case PW_CODE_COA_REQUEST:
				FR_STATS_INC(coa, total_dup_requests);
				break;

			case PW_CODE_DISCONNECT_REQUEST:
				FR_STATS_INC(dsc, total_dup_requests);
				break;
#endif

			default:
				break;
			}
#endif	/* WITH_STATS */

			/*
			 *	Tell the state machine that there's a
			 *	duplicate request.
			 */
			request->process(request, FR_ACTION_DUP);
			return 0; /* duplicate of live request */
		}

		/*
		 *	Mark the request as done ASAP, and before we
		 *	log anything.  The child may stop processing
		 *	the request just as we're logging the
		 *	complaint.
		 */
		request_done(request, FR_ACTION_DONE);
		request = NULL;

		/*
		 *	It's a new request, not a duplicate.  If the
		 *	old one is done, then we can clean it up.
		 */
		if (child_state <= REQUEST_RUNNING) {
			/*
			 *	The request is still QUEUED or RUNNING.  That's a problem.
			 */
			ERROR("Received conflicting packet from "
			      "client %s port %d - ID: %u due to "
			      "unfinished request.  Giving up on old request.",
			      client->shortname,
			      packet->src_port, packet->id);
		}

		/*
		 *	Mark the old request as done.  If there's no
		 *	child, the request will be cleaned up
		 *	immediately.  If there is a child, we'll set a
		 *	timer to go clean up the request.
		 */
	} /* else the new packet is unique */

	/*
	 *	Quench maximum number of outstanding requests.
	 */
	if (main_config.max_requests &&
	    ((count = rbtree_num_elements(pl)) > main_config.max_requests)) {
		RATE_LIMIT(ERROR("Dropping request (%d is too many): from client %s port %d - ID: %d", count,
				 client->shortname,
				 packet->src_port, packet->id);
			   WARN("Please check the configuration file.\n"
				"\tThe value for 'max_requests' is probably set too low.\n"));

		exec_trigger(NULL, NULL, "server.max_requests", true);
		return 0;
	}

skip_dup:
	/*
	 *	Rate-limit the incoming packets
	 */
	if (sock && sock->max_rate) {
		uint32_t pps;

		pps = rad_pps(&sock->rate_pps_old, &sock->rate_pps_now, &sock->rate_time, &now);
		if (pps > sock->max_rate) {
			DEBUG("Dropping request due to rate limiting");
			return 0;
		}
		sock->rate_pps_now++;
	}

	/*
	 *	Allocate a pool for the request.
	 */
	if (!ctx) {
		ctx = talloc_pool(NULL, main_config.talloc_pool_size);
		if (!ctx) return 0;
		talloc_set_name_const(ctx, "request_receive_pool");

		/*
		 *	The packet is still allocated from a different
		 *	context, but oh well.
		 */
		(void) talloc_steal(ctx, packet);
	}

	request = request_setup(ctx, listener, packet, client, fun);
	if (!request) {
		talloc_free(ctx);
		return 1;
	}

	/*
	 *	Mark it as a "real" request with a context.
	 */
	request->options |= RAD_REQUEST_OPTION_CTX;

	/*
	 *	Remember the request in the list.
	 */
	if (!listener->nodup) {
		if (!rbtree_insert(pl, &request->packet)) {
			RERROR("Failed to insert request in the list of live requests: discarding it");
			request_done(request, FR_ACTION_DONE);
			return 1;
		}

		request->in_request_hash = true;
	}

	/*
	 *	Process it.  Send a response, and free it.
	 */
	if (listener->synchronous) {
#ifdef WITH_DETAIL
		rad_assert(listener->type != RAD_LISTEN_DETAIL);
#endif

		request->listener->decode(request->listener, request);
		request->username = fr_pair_find_by_num(request->packet->vps, PW_USER_NAME, 0, TAG_ANY);
		request->password = fr_pair_find_by_num(request->packet->vps, PW_USER_PASSWORD, 0, TAG_ANY);

		fun(request);

		if (request->reply->code != 0) {
			request->listener->send(request->listener, request);
		} else {
			RDEBUG("Not sending reply");
		}

		/*
		 *	Don't do delayed reject.  Oh well.
		 */
		request_free(request);
		return 1;
	}

	/*
	 *	Otherwise, insert it into the state machine.
	 *	The child threads will take care of processing it.
	 */
	request_queue_or_run(request, request_running);

	return 1;
}


static REQUEST *request_setup(TALLOC_CTX *ctx, rad_listen_t *listener, RADIUS_PACKET *packet,
			      RADCLIENT *client, RAD_REQUEST_FUNP fun)
{
	REQUEST *request;

	/*
	 *	Create and initialize the new request.
	 */
	request = request_alloc(ctx);
	if (!request) {
		ERROR("No memory");
		return NULL;
	}
	request->reply = rad_alloc_reply(request, packet);
	if (!request->reply) {
		ERROR("No memory");
		talloc_free(request);
		return NULL;
	}

	request->listener = listener;
	request->client = client;
	request->packet = talloc_steal(request, packet);
	request->number = request_num_counter++;
	request->priority = listener->type;
	request->master_state = REQUEST_ACTIVE;
	request->child_state = REQUEST_RUNNING;
#ifdef DEBUG_STATE_MACHINE
	if (rad_debug_lvl) printf("(%u) ********\tSTATE %s C-%s -> C-%s\t********\n",
			       request->number, __FUNCTION__,
			       child_state_names[request->child_state],
			       child_state_names[REQUEST_RUNNING]);
#endif
	request->handle = fun;
	NO_CHILD_THREAD;

#ifdef WITH_STATS
	request->listener->stats.last_packet = request->packet->timestamp.tv_sec;
	if (packet->code == PW_CODE_ACCESS_REQUEST) {
		request->client->auth.last_packet = request->packet->timestamp.tv_sec;
		radius_auth_stats.last_packet = request->packet->timestamp.tv_sec;
#ifdef WITH_ACCOUNTING
	} else if (packet->code == PW_CODE_ACCOUNTING_REQUEST) {
		request->client->acct.last_packet = request->packet->timestamp.tv_sec;
		radius_acct_stats.last_packet = request->packet->timestamp.tv_sec;
#endif
	}
#endif	/* WITH_STATS */

	/*
	 *	Status-Server packets go to the head of the queue.
	 */
	if (request->packet->code == PW_CODE_STATUS_SERVER) request->priority = 0;

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

	request->root = &main_config;
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

	return request;
}

#ifdef WITH_TCP
/***********************************************************************
 *
 *	TCP Handlers.
 *
 ***********************************************************************/

/*
 *	Timer function for all TCP sockets.
 */
static void tcp_socket_timer(void *ctx)
{
	rad_listen_t *listener = talloc_get_type_abort(ctx, rad_listen_t);
	listen_socket_t *sock = listener->data;
	struct timeval end, now;
	char buffer[256];
	fr_socket_limit_t *limit;

	ASSERT_MASTER;

	if (listener->status != RAD_LISTEN_STATUS_KNOWN) return;

	fr_event_now(el, &now);

	switch (listener->type) {
#ifdef WITH_PROXY
	case RAD_LISTEN_PROXY:
		limit = &sock->home->limit;
		break;
#endif

	case RAD_LISTEN_AUTH:
#ifdef WITH_ACCOUNTING
	case RAD_LISTEN_ACCT:
#endif
		limit = &sock->limit;
		break;

	default:
		return;
	}

	/*
	 *	If we enforce a lifetime, do it now.
	 */
	if (limit->lifetime > 0) {
		end.tv_sec = sock->opened + limit->lifetime;
		end.tv_usec = 0;

		if (timercmp(&end, &now, <=)) {
			listener->print(listener, buffer, sizeof(buffer));
			DEBUG("Reached maximum lifetime on socket %s", buffer);

		do_close:

#ifdef WITH_PROXY
			/*
			 *	Proxy sockets get frozen, so that we don't use
			 *	them for new requests.  But we do keep them
			 *	open to listen for replies to requests we had
			 *	previously sent.
			 */
			if (listener->type == RAD_LISTEN_PROXY) {
				PTHREAD_MUTEX_LOCK(&proxy_mutex);
				if (!fr_packet_list_socket_freeze(proxy_list,
								  listener->fd)) {
					ERROR("Fatal error freezing socket: %s", fr_strerror());
					fr_exit(1);
				}
				PTHREAD_MUTEX_UNLOCK(&proxy_mutex);
			}
#endif

			/*
			 *	Mark the socket as "don't use if at all possible".
			 */
			listener->status = RAD_LISTEN_STATUS_FROZEN;
			event_new_fd(listener);
			return;
		}
	} else {
		end = now;
		end.tv_sec += 3600;
	}

	/*
	 *	Enforce an idle timeout.
	 */
	if (limit->idle_timeout > 0) {
		struct timeval idle;

		rad_assert(sock->last_packet != 0);
		idle.tv_sec = sock->last_packet + limit->idle_timeout;
		idle.tv_usec = 0;

		if (timercmp(&idle, &now, <=)) {
			listener->print(listener, buffer, sizeof(buffer));
			DEBUG("Reached idle timeout on socket %s", buffer);
			goto do_close;
		}

		/*
		 *	Enforce the minimum of idle timeout or lifetime.
		 */
		if (timercmp(&idle, &end, <)) {
			end = idle;
		}
	}

	/*
	 *	Wake up at t + 0.5s.  The code above checks if the timers
	 *	are <= t.  This addition gives us a bit of leeway.
	 */
	end.tv_usec = USEC / 2;

	ASSERT_MASTER;
	if (!fr_event_insert(el, tcp_socket_timer, listener, &end, &sock->ev)) {
		rad_panic("Failed to insert event");
	}
}


#ifdef WITH_PROXY
/*
 *	Called by socket_del to remove requests with this socket
 */
static int eol_proxy_listener(void *ctx, void *data)
{
	rad_listen_t *this = talloc_get_type_abort(ctx, rad_listen_t);
	RADIUS_PACKET **proxy_p = data;
	REQUEST *request;

	request = fr_packet2myptr(REQUEST, proxy, proxy_p);
	if (request->proxy_listener != this) return 0;

	/*
	 *	The normal "remove_from_proxy_hash" tries to grab the
	 *	proxy mutex.  We already have it held, so grabbing it
	 *	again will cause a deadlock.  Instead, call the "no
	 *	lock" version of the function.
	 */
	rad_assert(request->in_proxy_hash == true);
	remove_from_proxy_hash_nl(request, false);

	/*
	 *	Don't mark it as DONE.  The client can retransmit, and
	 *	the packet SHOULD be re-proxied somewhere else.
	 *
	 *	Return "2" means that the rbtree code will remove it
	 *	from the tree, and we don't need to do it ourselves.
	 */
	return 2;
}
#endif	/* WITH_PROXY */

static int eol_listener(void *ctx, void *data)
{
	rad_listen_t *this = talloc_get_type_abort(ctx, rad_listen_t);
	RADIUS_PACKET **packet_p = data;
	REQUEST *request;

	request = fr_packet2myptr(REQUEST, packet, packet_p);
	if (request->listener != this) return 0;

	request->master_state = REQUEST_STOP_PROCESSING;
	request->process = request_done;

	return 0;
}
#endif	/* WITH_TCP */

#ifdef WITH_PROXY
/***********************************************************************
 *
 *	Proxy handlers for the state machine.
 *
 ***********************************************************************/

/*
 *	Called with the proxy mutex held
 */
static void remove_from_proxy_hash_nl(REQUEST *request, bool yank)
{
	VERIFY_REQUEST(request);

	if (!request->in_proxy_hash) return;

	fr_packet_list_id_free(proxy_list, request->proxy, yank);
	request->in_proxy_hash = false;

	/*
	 *	On the FIRST reply, decrement the count of outstanding
	 *	requests.  Note that this is NOT the count of sent
	 *	packets, but whether or not the home server has
	 *	responded at all.
	 */
	if (request->home_server &&
	    request->home_server->currently_outstanding) {
		request->home_server->currently_outstanding--;

		/*
		 *	If we're NOT sending it packets, AND it's been
		 *	a while since we got a response, then we don't
		 *	know if it's alive or dead.
		 */
		if ((request->home_server->currently_outstanding == 0) &&
		    (request->home_server->state == HOME_STATE_ALIVE)) {
			struct timeval when, now;

			when.tv_sec = request->home_server->last_packet_recv ;
			when.tv_usec = 0;

			timeradd(&when, request_response_window(request), &when);
			gettimeofday(&now, NULL);

			/*
			 *	last_packet + response_window
			 *
			 *	We *administratively* mark the home
			 *	server as "unknown" state, because we
			 *	haven't seen a packet for a while.
			 */
			if (timercmp(&now, &when, >)) {
				request->home_server->state = HOME_STATE_UNKNOWN;
				request->home_server->last_packet_sent = 0;
				request->home_server->last_packet_recv = 0;
			}
		}
	}

#ifdef WITH_TCP
	if (request->proxy_listener) {
		request->proxy_listener->count--;
	}
#endif
	request->proxy_listener = NULL;

	/*
	 *	Got from YES in hash, to NO, not in hash while we hold
	 *	the mutex.  This guarantees that when another thread
	 *	grabs the mutex, the "not in hash" flag is correct.
	 */
}

static void remove_from_proxy_hash(REQUEST *request)
{
	VERIFY_REQUEST(request);

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

	remove_from_proxy_hash_nl(request, true);

	PTHREAD_MUTEX_UNLOCK(&proxy_mutex);
}

static int insert_into_proxy_hash(REQUEST *request)
{
	char buf[128];
	int tries;
	bool success = false;
	void *proxy_listener;

	VERIFY_REQUEST(request);

	rad_assert(request->proxy != NULL);
	rad_assert(request->home_server != NULL);
	rad_assert(proxy_list != NULL);


	PTHREAD_MUTEX_LOCK(&proxy_mutex);
	proxy_listener = NULL;
	request->num_proxied_requests = 1;
	request->num_proxied_responses = 0;

	for (tries = 0; tries < 2; tries++) {
		rad_listen_t *this;
		listen_socket_t *sock;

		RDEBUG3("proxy: Trying to allocate ID (%d/2)", tries);
		success = fr_packet_list_id_alloc(proxy_list,
						request->home_server->proto,
						&request->proxy, &proxy_listener);
		if (success) break;

		if (tries > 0) continue; /* try opening new socket only once */

#ifdef HAVE_PTHREAD_H
		if (proxy_no_new_sockets) break;
#endif

		RDEBUG3("proxy: Trying to open a new listener to the home server");
		this = proxy_new_listener(proxy_ctx, request->home_server, 0);
		if (!this) {
			PTHREAD_MUTEX_UNLOCK(&proxy_mutex);
			goto fail;
		}

		request->proxy->src_port = 0; /* Use any new socket */
		proxy_listener = this;

		sock = this->data;
		if (!fr_packet_list_socket_add(proxy_list, this->fd,
					       sock->proto,
					       &sock->other_ipaddr, sock->other_port,
					       this)) {

#ifdef HAVE_PTHREAD_H
			proxy_no_new_sockets = true;
#endif
			PTHREAD_MUTEX_UNLOCK(&proxy_mutex);

			/*
			 *	This is bad.  However, the
			 *	packet list now supports 256
			 *	open sockets, which should
			 *	minimize this problem.
			 */
			ERROR("Failed adding proxy socket: %s",
			      fr_strerror());
			goto fail;
		}

		/*
		 *	Add it to the event loop.  Ensure that we have
		 *	only one mutex locked at a time.
		 */
		PTHREAD_MUTEX_UNLOCK(&proxy_mutex);
		radius_update_listener(this);
		PTHREAD_MUTEX_LOCK(&proxy_mutex);
	}

	if (!proxy_listener || !success) {
		PTHREAD_MUTEX_UNLOCK(&proxy_mutex);
		REDEBUG2("proxy: Failed allocating Id for proxied request");
	fail:
		request->proxy_listener = NULL;
		request->in_proxy_hash = false;
		return 0;
	}

	rad_assert(request->proxy->id >= 0);

	request->proxy_listener = proxy_listener;
	request->in_proxy_hash = true;
	RDEBUG3("proxy: request is now in proxy hash");

	/*
	 *	Keep track of maximum outstanding requests to a
	 *	particular home server.  'max_outstanding' is
	 *	enforced in home_server_ldb(), in realms.c.
	 */
	request->home_server->currently_outstanding++;

#ifdef WITH_TCP
	request->proxy_listener->count++;
#endif

	PTHREAD_MUTEX_UNLOCK(&proxy_mutex);

	RDEBUG3("proxy: allocating destination %s port %d - Id %d",
	       inet_ntop(request->proxy->dst_ipaddr.af,
			 &request->proxy->dst_ipaddr.ipaddr, buf, sizeof(buf)),
	       request->proxy->dst_port,
	       request->proxy->id);

	return 1;
}

static int process_proxy_reply(REQUEST *request, RADIUS_PACKET *reply)
{
	int rcode;
	int post_proxy_type = 0;
	VALUE_PAIR *vp;

	VERIFY_REQUEST(request);

	/*
	 *	There may be a proxy reply, but it may be too late.
	 */
	if ((request->home_server && !request->home_server->server) && !request->proxy_listener) return 0;

	/*
	 *	Delete any reply we had accumulated until now.
	 */
	RDEBUG2("Clearing existing &reply: attributes");
	fr_pair_list_free(&request->reply->vps);

	/*
	 *	Run the packet through the post-proxy stage,
	 *	BEFORE playing games with the attributes.
	 */
	vp = fr_pair_find_by_num(request->config, PW_POST_PROXY_TYPE, 0, TAG_ANY);
	if (vp) {
		post_proxy_type = vp->vp_integer;
	/*
	 *	If we have a proxy_reply, and it was a reject, or a NAK
	 *	setup Post-Proxy <type>.
	 *
	 *	If the <type> doesn't have a section, then the Post-Proxy
	 *	section is ignored.
	 */
	} else if (reply) {
		DICT_VALUE *dval = NULL;

		switch (reply->code) {
		case PW_CODE_ACCESS_REJECT:
			dval = dict_valbyname(PW_POST_PROXY_TYPE, 0, "Reject");
			if (dval) post_proxy_type = dval->value;
			break;

		case PW_CODE_DISCONNECT_NAK:
			dval = dict_valbyname(PW_POST_PROXY_TYPE, 0, fr_packet_codes[reply->code]);
			if (dval) post_proxy_type = dval->value;
			break;

		case PW_CODE_COA_NAK:
			dval = dict_valbyname(PW_POST_PROXY_TYPE, 0, fr_packet_codes[reply->code]);
			if (dval) post_proxy_type = dval->value;
			break;

		default:
			break;
		}

		/*
		 *	Create config:Post-Proxy-Type
		 */
		if (dval) {
			vp = radius_pair_create(request, &request->config, PW_POST_PROXY_TYPE, 0);
			vp->vp_integer = dval->value;
		}
	}

	if (post_proxy_type > 0) RDEBUG2("Found Post-Proxy-Type %s",
					 dict_valnamebyattr(PW_POST_PROXY_TYPE, 0, post_proxy_type));

	if (reply) {
		VERIFY_PACKET(reply);

		/*
		 *	Decode the packet if required.
		 */
		if (request->proxy_listener) {
			rcode = request->proxy_listener->decode(request->proxy_listener, request);
			debug_packet(request, reply, true);

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
		} else {
			rad_assert(!request->in_proxy_hash);
		}
	} else if (request->in_proxy_hash) {
		remove_from_proxy_hash(request);
	}

	if (request->home_pool && request->home_pool->virtual_server) {
		char const *old_server = request->server;

		request->server = request->home_pool->virtual_server;
		RDEBUG2("server %s {", request->server);
		RINDENT();
		rcode = process_post_proxy(post_proxy_type, request);
		REXDENT();
		RDEBUG2("}");
		request->server = old_server;
	} else {
		rcode = process_post_proxy(post_proxy_type, request);
	}

#ifdef WITH_COA
	if (request->proxy && request->packet->code == request->proxy->code) {
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
		if (reply) {
			fr_pair_add(&request->reply->vps, fr_pair_list_copy(request->reply, reply->vps));

			/*
			 *	Delete the Proxy-State Attributes from
			 *	the reply.  These include Proxy-State
			 *	attributes from us and remote server.
			 */
			fr_pair_delete_by_num(&request->reply->vps, PW_PROXY_STATE, 0, TAG_ANY);

		} else {
			vp = fr_pair_find_by_num(request->config, PW_RESPONSE_PACKET_TYPE, 0, TAG_ANY);
			if (vp && (vp->vp_integer != 256)) {
				request->proxy_reply = rad_alloc_reply(request, request->proxy);
				request->proxy_reply->code = vp->vp_integer;
			}
		}
#ifdef WITH_COA
	}
#endif
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

static void mark_home_server_alive(REQUEST *request, home_server_t *home)
{
	char buffer[128];

	home->state = HOME_STATE_ALIVE;
	home->response_timeouts = 0;
	exec_trigger(request, home->cs, "home_server.alive", false);
	home->currently_outstanding = 0;
	home->num_sent_pings = 0;
	home->num_received_pings = 0;
	gettimeofday(&home->revive_time, NULL);

	fr_event_delete(el, &home->ev);

	RPROXY("Marking home server %s port %d alive",
	       inet_ntop(request->proxy->dst_ipaddr.af,
			 &request->proxy->dst_ipaddr.ipaddr,
			 buffer, sizeof(buffer)),
	       request->proxy->dst_port);
}


int request_proxy_reply(RADIUS_PACKET *packet)
{
	RADIUS_PACKET **proxy_p;
	REQUEST *request;
	struct timeval now;
	char buffer[128];

	VERIFY_PACKET(packet);

	PTHREAD_MUTEX_LOCK(&proxy_mutex);
	proxy_p = fr_packet_list_find_byreply(proxy_list, packet);

	if (!proxy_p) {
		PTHREAD_MUTEX_UNLOCK(&proxy_mutex);
		PROXY("No outstanding request was found for %s packet from host %s port %d - ID %u",
		       fr_packet_codes[packet->code],
		       inet_ntop(packet->src_ipaddr.af,
				 &packet->src_ipaddr.ipaddr,
				 buffer, sizeof(buffer)),
		       packet->src_port, packet->id);
		return 0;
	}

	request = fr_packet2myptr(REQUEST, proxy, proxy_p);

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
	if (request->proxy->code != PW_CODE_STATUS_SERVER) {
#ifdef WITH_TCP
		listen_socket_t *sock = request->proxy_listener->data;

		sock->last_packet = now.tv_sec;
#endif
		request->home_server->last_packet_recv = now.tv_sec;
	}

	request->num_proxied_responses++;

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
	request->proxy_reply = talloc_steal(request, packet);
	packet->timestamp = now;
	request->priority = RAD_LISTEN_PROXY;

#ifdef WITH_STATS
	/*
	 *	Update the proxy listener stats here, because only one
	 *	thread accesses that at a time.  The home_server and
	 *	main proxy_*_stats structures are updated once the
	 *	request is cleaned up.
	 */
	request->proxy_listener->stats.total_responses++;

	request->home_server->stats.last_packet = packet->timestamp.tv_sec;
	request->proxy_listener->stats.last_packet = packet->timestamp.tv_sec;

	switch (request->proxy->code) {
	case PW_CODE_ACCESS_REQUEST:
		proxy_auth_stats.last_packet = packet->timestamp.tv_sec;

		if (request->proxy_reply->code == PW_CODE_ACCESS_ACCEPT) {
			request->proxy_listener->stats.total_access_accepts++;

		} else if (request->proxy_reply->code == PW_CODE_ACCESS_REJECT) {
			request->proxy_listener->stats.total_access_rejects++;

		} else if (request->proxy_reply->code == PW_CODE_ACCESS_CHALLENGE) {
			request->proxy_listener->stats.total_access_challenges++;
		}
		break;

#ifdef WITH_ACCOUNTING
	case PW_CODE_ACCOUNTING_REQUEST:
		request->proxy_listener->stats.total_responses++;
		proxy_acct_stats.last_packet = packet->timestamp.tv_sec;
		break;

#endif

#ifdef WITH_COA
	case PW_CODE_COA_REQUEST:
		request->proxy_listener->stats.total_responses++;
		proxy_coa_stats.last_packet = packet->timestamp.tv_sec;
		break;

	case PW_CODE_DISCONNECT_REQUEST:
		request->proxy_listener->stats.total_responses++;
		proxy_dsc_stats.last_packet = packet->timestamp.tv_sec;
		break;

#endif
	default:
		break;
	}
#endif

	/*
	 *	If we hadn't been sending the home server packets for
	 *	a while, just mark it alive.  Or, if it was zombie,
	 *	it's now responded, and is therefore alive.
	 */
	if ((request->home_server->state == HOME_STATE_UNKNOWN) ||
	    (request->home_server->state == HOME_STATE_ZOMBIE)) {
		mark_home_server_alive(request, request->home_server);
	}

	/*
	 *	Tell the request state machine that we have a proxy
	 *	reply.  Depending on the function, this should either
	 *	ignore it, or process it.
	 */
	request->process(request, FR_ACTION_PROXY_REPLY);

	return 1;
}


static int setup_post_proxy_fail(REQUEST *request)
{
	DICT_VALUE const *dval = NULL;
	VALUE_PAIR *vp;
	RADIUS_PACKET *packet;

	VERIFY_REQUEST(request);

	packet = request->proxy ? request->proxy : request->packet;

	if (packet->code == PW_CODE_ACCESS_REQUEST) {
		dval = dict_valbyname(PW_POST_PROXY_TYPE, 0,
				      "Fail-Authentication");
#ifdef WITH_ACCOUNTING
	} else if (packet->code == PW_CODE_ACCOUNTING_REQUEST) {
		dval = dict_valbyname(PW_POST_PROXY_TYPE, 0,
				      "Fail-Accounting");
#endif

#ifdef WITH_COA
	} else if (packet->code == PW_CODE_COA_REQUEST) {
		dval = dict_valbyname(PW_POST_PROXY_TYPE, 0, "Fail-CoA");

	} else if (packet->code == PW_CODE_DISCONNECT_REQUEST) {
		dval = dict_valbyname(PW_POST_PROXY_TYPE, 0, "Fail-Disconnect");
#endif
	} else {
		WARN("Unknown packet type in Post-Proxy-Type Fail: ignoring");
		return 0;
	}

	if (!dval) dval = dict_valbyname(PW_POST_PROXY_TYPE, 0, "Fail");

	if (!dval) {
		fr_pair_delete_by_num(&request->config, PW_POST_PROXY_TYPE, 0, TAG_ANY);
		return 0;
	}

	vp = fr_pair_find_by_num(request->config, PW_POST_PROXY_TYPE, 0, TAG_ANY);
	if (!vp) vp = radius_pair_create(request, &request->config,
					PW_POST_PROXY_TYPE, 0);
	vp->vp_integer = dval->value;

	return 1;
}


/** Process a request after the proxy has timed out.
 *
 *  Run the packet through Post-Proxy-Type Fail
 *
 *  \dot
 *	digraph proxy_no_reply {
 *		proxy_no_reply;
 *
 *		proxy_no_reply -> dup [ label = "DUP", arrowhead = "none" ];
 *		proxy_no_reply -> timer [ label = "TIMER < max_request_time" ];
 *		proxy_no_reply -> proxy_reply_too_late [ label = "PROXY_REPLY" arrowhead = "none"];
 *		proxy_no_reply -> process_proxy_reply [ label = "RUN" ];
 *		proxy_no_reply -> done [ label = "TIMER >= timeout" ];
 *	}
 *  \enddot
 */
static void proxy_no_reply(REQUEST *request, int action)
{
	VERIFY_REQUEST(request);

	TRACE_STATE_MACHINE;
	CHECK_FOR_STOP;

	switch (action) {
	case FR_ACTION_DUP:
		request_dup(request);
		break;

	case FR_ACTION_TIMER:
		(void) request_max_time(request);
		break;

	case FR_ACTION_PROXY_REPLY:
		proxy_reply_too_late(request);
		break;

	case FR_ACTION_RUN:
		if (process_proxy_reply(request, NULL)) {
			request->handle(request);
		}
		request_finish(request, action);
		break;

	default:
		RDEBUG3("%s: Ignoring action %s", __FUNCTION__, action_codes[action]);
		break;
	}
}

/** Process the request after receiving a proxy reply.
 *
 *  Throught the post-proxy section, and the through the handler
 *  function.
 *
 *  \dot
 *	digraph proxy_running {
 *		proxy_running;
 *
 *		proxy_running -> dup [ label = "DUP", arrowhead = "none" ];
 *		proxy_running -> timer [ label = "TIMER < max_request_time" ];
 *		proxy_running -> process_proxy_reply [ label = "RUN" ];
 *		proxy_running -> done [ label = "TIMER >= timeout" ];
 *	}
 *  \enddot
 */
static void proxy_running(REQUEST *request, int action)
{
	VERIFY_REQUEST(request);

	TRACE_STATE_MACHINE;
	CHECK_FOR_STOP;

	switch (action) {
	case FR_ACTION_DUP:
		request_dup(request);
		break;

	case FR_ACTION_TIMER:
		(void) request_max_time(request);
		break;

	case FR_ACTION_RUN:
		if (process_proxy_reply(request, request->proxy_reply)) {
			request->handle(request);
		}
		request_finish(request, action);
		break;

	default:		/* duplicate proxy replies are suppressed */
		RDEBUG3("%s: Ignoring action %s", __FUNCTION__, action_codes[action]);
		break;
	}
}

/** Determine if a #REQUEST needs to be proxied, and perform pre-proxy operations
 *
 * Whether a request will be proxied is determined by the attributes present
 * in request->config. If any of the following attributes are found, the
 * request may be proxied.
 *
 * The key attributes are:
 *   - PW_PROXY_TO_REALM          - Specifies a realm the request should be proxied to.
 *   - PW_HOME_SERVER_POOL        - Specifies a specific home server pool to proxy to.
 *   - PW_PACKET_DST_IP_ADDRESS   - Specifies a specific IPv4 home server to proxy to.
 *   - PW_PACKET_DST_IPV6_ADDRESS - Specifies a specific IPv6 home server to proxy to.
 *
 * Certain packet types such as #PW_CODE_STATUS_SERVER will never be proxied.
 *
 * If request should be proxied, will:
 *   - Add request:Proxy-State
 *   - Strip the current username value of its realm (depending on config)
 *   - Create a CHAP-Challenge from the original request vector, if one doesn't already
 *     exist.
 *   - Call the pre-process section in the current server, or in the virtual server
 *     associated with the home server pool we're proxying to.
 *
 * @todo A lot of this logic is RADIUS specific, and should be moved out into a protocol
 *	specific function.
 *
 * @param request The #REQUEST to evaluate for proxying.
 * @return 0 if not proxying, 1 if request should be proxied, -1 on error.
 */
static int request_will_proxy(REQUEST *request)
{
	int rcode, pre_proxy_type = 0;
	char const *realmname = NULL;
	VALUE_PAIR *vp, *strippedname;
	home_server_t *home;
	REALM *realm = NULL;
	home_pool_t *pool = NULL;

	VERIFY_REQUEST(request);

	if (!request->root->proxy_requests) return 0;
	if (request->packet->dst_port == 0) return 0;
	if (request->packet->code == PW_CODE_STATUS_SERVER) return 0;
	if (request->in_proxy_hash) return 0;

	/*
	 *	FIXME: for 3.0, allow this only for rejects?
	 */
	if (request->reply->code != 0) return 0;

	vp = fr_pair_find_by_num(request->config, PW_PROXY_TO_REALM, 0, TAG_ANY);
	if (vp) {
		realm = realm_find2(vp->vp_strvalue);
		if (!realm) {
			REDEBUG2("Cannot proxy to unknown realm %s",
				vp->vp_strvalue);
			return 0;
		}

		realmname = vp->vp_strvalue;

		/*
		 *	Figure out which pool to use.
		 */
		if (request->packet->code == PW_CODE_ACCESS_REQUEST) {
			DEBUG3("Using home pool auth for realm %s", realm->name);
			pool = realm->auth_pool;

#ifdef WITH_ACCOUNTING
		} else if (request->packet->code == PW_CODE_ACCOUNTING_REQUEST) {
			DEBUG3("Using home pool acct for realm %s", realm->name);
			pool = realm->acct_pool;
#endif

#ifdef WITH_COA
		} else if ((request->packet->code == PW_CODE_COA_REQUEST) ||
			   (request->packet->code == PW_CODE_DISCONNECT_REQUEST)) {
			DEBUG3("Using home pool coa for realm %s", realm->name);
			pool = realm->coa_pool;
#endif

		} else {
			return 0;
		}

	} else if ((vp = fr_pair_find_by_num(request->config, PW_HOME_SERVER_POOL, 0, TAG_ANY)) != NULL) {
		int pool_type;

		DEBUG3("Using Home-Server-Pool %s", vp->vp_strvalue);

		switch (request->packet->code) {
		case PW_CODE_ACCESS_REQUEST:
			pool_type = HOME_TYPE_AUTH;
			break;

#ifdef WITH_ACCOUNTING
		case PW_CODE_ACCOUNTING_REQUEST:
			pool_type = HOME_TYPE_ACCT;
			break;
#endif

#ifdef WITH_COA
		case PW_CODE_COA_REQUEST:
		case PW_CODE_DISCONNECT_REQUEST:
			pool_type = HOME_TYPE_COA;
			break;
#endif

		default:
			return 0;
		}

		pool = home_pool_byname(vp->vp_strvalue, pool_type);

		/*
		 *	Send it directly to a home server (i.e. NAS)
		 */
	} else if (((vp = fr_pair_find_by_num(request->config, PW_PACKET_DST_IP_ADDRESS, 0, TAG_ANY)) != NULL) ||
		   ((vp = fr_pair_find_by_num(request->config, PW_PACKET_DST_IPV6_ADDRESS, 0, TAG_ANY)) != NULL)) {
		uint16_t dst_port;
		fr_ipaddr_t dst_ipaddr;

		memset(&dst_ipaddr, 0, sizeof(dst_ipaddr));

		if (vp->da->attr == PW_PACKET_DST_IP_ADDRESS) {
			dst_ipaddr.af = AF_INET;
			dst_ipaddr.ipaddr.ip4addr.s_addr = vp->vp_ipaddr;
			dst_ipaddr.prefix = 32;
		} else {
			dst_ipaddr.af = AF_INET6;
			memcpy(&dst_ipaddr.ipaddr.ip6addr, &vp->vp_ipv6addr, sizeof(vp->vp_ipv6addr));
			dst_ipaddr.prefix = 128;
		}

		vp = fr_pair_find_by_num(request->config, PW_PACKET_DST_PORT, 0, TAG_ANY);
		if (!vp) {
			if (request->packet->code == PW_CODE_ACCESS_REQUEST) {
				dst_port = PW_AUTH_UDP_PORT;

#ifdef WITH_ACCOUNTING
			} else if (request->packet->code == PW_CODE_ACCOUNTING_REQUEST) {
				dst_port = PW_ACCT_UDP_PORT;
#endif

#ifdef WITH_COA
			} else if ((request->packet->code == PW_CODE_COA_REQUEST) ||
				   (request->packet->code == PW_CODE_DISCONNECT_REQUEST)) {
				dst_port = PW_COA_UDP_PORT;
#endif
			} else { /* shouldn't happen for RADIUS... */
				return 0;
			}

		} else {
			dst_port = vp->vp_integer;
		}

		/*
		 *	Nothing does CoA over TCP.
		 */
		home = home_server_find(&dst_ipaddr, dst_port, IPPROTO_UDP);
		if (!home) {
			char buffer[256];

			RWDEBUG("No such home server %s port %u",
				inet_ntop(dst_ipaddr.af, &dst_ipaddr.ipaddr, buffer, sizeof(buffer)),
				(unsigned int) dst_port);
			return 0;
		}

		/*
		 *	The home server is alive (or may be alive).
		 *	Send the packet to the IP.
		 */
		if (home->state != HOME_STATE_IS_DEAD) goto do_home;

		/*
		 *	The home server is dead.  If you wanted
		 *	fail-over, you should have proxied to a pool.
		 *	Sucks to be you.
		 */

		return 0;

	} else {
		return 0;
	}

	if (!pool) {
		RWDEBUG2("Cancelling proxy as no home pool exists");
		return 0;
	}

	if (request->listener->synchronous) {
		WARN("Cannot proxy a request which is from a 'synchronous' socket");
		return 0;
	}

	request->home_pool = pool;

	home = home_server_ldb(realmname, pool, request);

	if (!home) {
		REDEBUG2("Failed to find live home server: Cancelling proxy");
		return 1;
	}

do_home:
	home_server_update_request(home, request);

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
	if (realmname) pair_make_request("Realm", realmname, T_OP_EQ);

	/*
	 *	Strip the name, if told to.
	 *
	 *	Doing it here catches the case of proxied tunneled
	 *	requests.
	 */
	if (realm && (realm->strip_realm == true) &&
	   (strippedname = fr_pair_find_by_num(request->proxy->vps, PW_STRIPPED_USER_NAME, 0, TAG_ANY)) != NULL) {
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
		vp = fr_pair_find_by_num(request->proxy->vps, PW_USER_NAME, 0, TAG_ANY);
		if (!vp) {
			vp_cursor_t cursor;
			vp = radius_pair_create(NULL, NULL,
					       PW_USER_NAME, 0);
			rad_assert(vp != NULL);	/* handled by above function */
			/* Insert at the START of the list */
			/* FIXME: Can't make assumptions about ordering */
			fr_cursor_init(&cursor, &vp);
			fr_cursor_merge(&cursor, request->proxy->vps);
			request->proxy->vps = vp;
		}
		fr_pair_value_strcpy(vp, strippedname->vp_strvalue);

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
	if ((request->packet->code == PW_CODE_ACCESS_REQUEST) &&
	    fr_pair_find_by_num(request->proxy->vps, PW_CHAP_PASSWORD, 0, TAG_ANY) &&
	    fr_pair_find_by_num(request->proxy->vps, PW_CHAP_CHALLENGE, 0, TAG_ANY) == NULL) {
		vp = radius_pair_create(request->proxy, &request->proxy->vps, PW_CHAP_CHALLENGE, 0);
		fr_pair_value_memcpy(vp, request->packet->vector, sizeof(request->packet->vector));
	}

	/*
	 *	The RFC's say we have to do this, but FreeRADIUS
	 *	doesn't need it.
	 */
	vp = radius_pair_create(request->proxy, &request->proxy->vps, PW_PROXY_STATE, 0);
	fr_pair_value_sprintf(vp, "%u", request->packet->id);

	/*
	 *	Should be done BEFORE inserting into proxy hash, as
	 *	pre-proxy may use this information, or change it.
	 */
	request->proxy->code = request->packet->code;

	/*
	 *	Call the pre-proxy routines.
	 */
	vp = fr_pair_find_by_num(request->config, PW_PRE_PROXY_TYPE, 0, TAG_ANY);
	if (vp) {
		DICT_VALUE const *dval = dict_valbyattr(vp->da->attr, vp->da->vendor, vp->vp_integer);
		/* Must be a validation issue */
		rad_assert(dval);
		RDEBUG2("Found Pre-Proxy-Type %s", dval->name);
		pre_proxy_type = vp->vp_integer;
	}

	/*
	 *	home_pool may be NULL when originating CoA packets,
	 *	because they go directly to an IP address.
	 */
	if (request->home_pool && request->home_pool->virtual_server) {
		char const *old_server = request->server;

		request->server = request->home_pool->virtual_server;

		RDEBUG2("server %s {", request->server);
		RINDENT();
		rcode = process_pre_proxy(pre_proxy_type, request);
		REXDENT();
		RDEBUG2("}");

		request->server = old_server;
	} else {
		char buffer[128];

		RDEBUG2("Starting proxy to home server %s port %d",
			inet_ntop(request->proxy->dst_ipaddr.af,
				  &request->proxy->dst_ipaddr.ipaddr,
				  buffer, sizeof(buffer)),
			request->proxy->dst_port);

		rcode = process_pre_proxy(pre_proxy_type, request);
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
		return 1;
	}
}

static int proxy_to_virtual_server(REQUEST *request)
{
	REQUEST *fake;

	if (request->packet->dst_port == 0) {
		WARN("Cannot proxy an internal request");
		return 0;
	}

	DEBUG("Proxying to virtual server %s",
	      request->home_server->server);

	/*
	 *	Packets to virtual servers don't get
	 *	retransmissions sent to them.  And the virtual
	 *	server is run ONLY if we have no child
	 *	threads, or we're running in a child thread.
	 */
	rad_assert(!spawn_flag || !we_are_master());

	fake = request_alloc_fake(request);

	fake->packet->vps = fr_pair_list_copy(fake->packet, request->packet->vps);
	talloc_free(request->proxy);

	fake->server = request->home_server->server;
	fake->handle = request->handle;
	fake->process = NULL; /* should never be run for anything */

	/*
	 *	Run the virtual server.
	 */
	request_running(fake, FR_ACTION_RUN);

	request->proxy = talloc_steal(request, fake->packet);
	fake->packet = NULL;
	request->proxy_reply = talloc_steal(request, fake->reply);
	fake->reply = NULL;

	talloc_free(fake);

	/*
	 *	No reply code, toss the reply we have,
	 *	and do post-proxy-type Fail.
	 */
	if (!request->proxy_reply->code) {
		TALLOC_FREE(request->proxy_reply);
		setup_post_proxy_fail(request);
	}

	/*
	 *	Do the proxy reply (if any)
	 */
	if (process_proxy_reply(request, request->proxy_reply)) {
		request->handle(request);
	}

	return -1;	/* so we call request_finish */
}


static int request_proxy(REQUEST *request)
{
	char buffer[128];

	VERIFY_REQUEST(request);

	rad_assert(request->parent == NULL);

	if (request->master_state == REQUEST_STOP_PROCESSING) return 0;

#ifdef WITH_COA
	if (request->coa) {
		RWDEBUG("Cannot proxy and originate CoA packets at the same time.  Cancelling CoA request");
		request_done(request->coa, FR_ACTION_DONE);
	}
#endif

	if (!request->home_server) {
		RWDEBUG("No home server selected");
		return -1;
	}

	/*
	 *	The request may need sending to a virtual server.
	 *	This code is more than a little screwed up.  The rest
	 *	of the state machine doesn't handle parent / child
	 *	relationships well.  i.e. if the child request takes
	 *	too long, the core will mark the *parent* as "stop
	 *	processing".  And the child will continue without
	 *	knowing anything...
	 *
	 *	So, we have some horrible hacks to get around that.
	 */
	if (request->home_server->server) return proxy_to_virtual_server(request);

	/*
	 *	We're actually sending a proxied packet.  Do that now.
	 */
	if (!request->in_proxy_hash && !insert_into_proxy_hash(request)) {
		RPROXY("Failed to insert request into the proxy list");
		return -1;
	}

	rad_assert(request->proxy->id >= 0);

	if (rad_debug_lvl) {
		struct timeval *response_window;

		response_window = request_response_window(request);

#ifdef WITH_TLS
		if (request->home_server->tls) {
			RDEBUG2("Proxying request to home server %s port %d (TLS) timeout %d.%06d",
				inet_ntop(request->proxy->dst_ipaddr.af,
					  &request->proxy->dst_ipaddr.ipaddr,
					  buffer, sizeof(buffer)),
				request->proxy->dst_port,
				(int) response_window->tv_sec, (int) response_window->tv_usec);
		} else
#endif
			RDEBUG2("Proxying request to home server %s port %d timeout %d.%06d",
				inet_ntop(request->proxy->dst_ipaddr.af,
					  &request->proxy->dst_ipaddr.ipaddr,
					  buffer, sizeof(buffer)),
				request->proxy->dst_port,
				(int) response_window->tv_sec, (int) response_window->tv_usec);


	}

	gettimeofday(&request->proxy->timestamp, NULL);
	request->home_server->last_packet_sent = request->proxy->timestamp.tv_sec;

	/*
	 *	Encode the packet before we do anything else.
	 */
	request->proxy_listener->encode(request->proxy_listener, request);
	debug_packet(request, request->proxy, false);

	/*
	 *	Set the state function, then the state, no child, and
	 *	send the packet.
	 *
	 *	The order here is different from other state changes
	 *	due to race conditions with replies from the home
	 *	server.
	 */
	request->process = proxy_wait_for_reply;
	request->child_state = REQUEST_PROXIED;
	request->component = "<REQUEST_PROXIED>";
	request->module = "";
	NO_CHILD_THREAD;

	/*
	 *	And send the packet.
	 */
	request->proxy_listener->send(request->proxy_listener, request);
	return 1;
}

/*
 *	Proxy the packet as if it was new.
 */
static int request_proxy_anew(REQUEST *request)
{
	home_server_t *home;

	VERIFY_REQUEST(request);

	/*
	 *	Delete the request from the proxy list.
	 *
	 *	The packet list code takes care of ensuring that IDs
	 *	aren't reused until all 256 IDs have been used.  So
	 *	there's a 1/256 chance of re-using the same ID when
	 *	we're sending to the same home server.  Which is
	 *	acceptable.
	 */
	remove_from_proxy_hash(request);

	/*
	 *	Find a live home server for the request.
	 */
	home = home_server_ldb(NULL, request->home_pool, request);
	if (!home) {
		REDEBUG2("Failed to find live home server for request");
	post_proxy_fail:
		if (setup_post_proxy_fail(request)) {
			request_queue_or_run(request, proxy_running);
		} else {
			gettimeofday(&request->reply->timestamp, NULL);
			request_cleanup_delay_init(request);
		}
		return 0;
	}

#ifdef WITH_ACCOUNTING
	/*
	 *	Update the Acct-Delay-Time attribute, since the LAST
	 *	time we tried to retransmit this packet.
	 */
	if (request->packet->code == PW_CODE_ACCOUNTING_REQUEST) {
		VALUE_PAIR *vp;

		vp = fr_pair_find_by_num(request->proxy->vps, PW_ACCT_DELAY_TIME, 0, TAG_ANY);
		if (!vp) vp = radius_pair_create(request->proxy,
						&request->proxy->vps,
						PW_ACCT_DELAY_TIME, 0);
		if (vp) {
			struct timeval now;

			gettimeofday(&now, NULL);
			vp->vp_integer += now.tv_sec - request->proxy->timestamp.tv_sec;
		}
	}
#endif

	/*
	 *	May have failed over to a "fallback" virtual server.
	 *	If so, run that instead of doing proxying to a real
	 *	server.
	 */
	if (home->server) {
		request->home_server = home;
		TALLOC_FREE(request->proxy);

		(void) proxy_to_virtual_server(request);
		return 0;
	}

	home_server_update_request(home, request);

	if (!insert_into_proxy_hash(request)) {
		RPROXY("Failed to insert retransmission into the proxy list");
		goto post_proxy_fail;
	}

	/*
	 *	Free the old packet, to force re-encoding
	 */
	talloc_free(request->proxy->data);
	request->proxy->data = NULL;
	request->proxy->data_len = 0;

	if (request_proxy(request) != 1) goto post_proxy_fail;

	return 1;
}


/** Ping a home server.
 *
 */
static void request_ping(REQUEST *request, int action)
{
	home_server_t *home = request->home_server;
	char buffer[128];

	VERIFY_REQUEST(request);

	TRACE_STATE_MACHINE;
	ASSERT_MASTER;

	switch (action) {
	case FR_ACTION_TIMER:
		ERROR("No response to status check %d ID %u for home server %s port %d",
		       request->number,
		       request->proxy->id,
		       inet_ntop(request->proxy->dst_ipaddr.af,
				 &request->proxy->dst_ipaddr.ipaddr,
				 buffer, sizeof(buffer)),
		       request->proxy->dst_port);
		remove_from_proxy_hash(request);
		break;

	case FR_ACTION_PROXY_REPLY:
		rad_assert(request->in_proxy_hash);

		request->home_server->num_received_pings++;
		RPROXY("Received response to status check %d ID %u (%d in current sequence)",
		       request->number, request->proxy->id, home->num_received_pings);

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
		 *	It's dead, and we haven't received enough ping
		 *	responses to mark it "alive".  Wait a bit.
		 *
		 *	If it's zombie, we mark it alive immediately.
		 */
		if ((home->state == HOME_STATE_IS_DEAD) &&
		    (home->num_received_pings < home->num_pings_to_alive)) {
			return;
		}

		/*
		 *	Mark it alive and delete any outstanding
		 *	pings.
		 */
		mark_home_server_alive(request, home);
		break;

	default:
		RDEBUG3("%s: Ignoring action %s", __FUNCTION__, action_codes[action]);
		break;
	}

	rad_assert(!request->in_request_hash);
	rad_assert(!request->in_proxy_hash);
	rad_assert(request->ev == NULL);
	NO_CHILD_THREAD;
	request_done(request, FR_ACTION_DONE);
}

/*
 *	Add +/- 2s of jitter, as suggested in RFC 3539
 *	and in RFC 5080.
 */
static void add_jitter(struct timeval *when)
{
	uint32_t jitter;

	when->tv_sec -= 2;

	jitter = fr_rand();
	jitter ^= (jitter >> 10);
	jitter &= ((1 << 22) - 1); /* 22 bits of 1 */

	/*
	 *	Add in ~ (4 * USEC) of jitter.
	 */
	tv_add(when, jitter);
}

/*
 *	Called from start of zombie period, OR after control socket
 *	marks the home server dead.
 */
static void ping_home_server(void *ctx)
{
	home_server_t *home = talloc_get_type_abort(ctx, home_server_t);
	REQUEST *request;
	VALUE_PAIR *vp;
	struct timeval when, now;

	if ((home->state == HOME_STATE_ALIVE) ||
	    (home->ev != NULL)) {
		return;
	}

	gettimeofday(&now, NULL);
	ASSERT_MASTER;

	/*
	 *	We've run out of zombie time.  Mark it dead.
	 */
	if (home->state == HOME_STATE_ZOMBIE) {
		when = home->zombie_period_start;
		when.tv_sec += home->zombie_period;

		if (timercmp(&when, &now, <)) {
			DEBUG("PING: Zombie period is over for home server %s", home->log_name);
			mark_home_server_dead(home, &now);
		}
	}

	/*
	 *	We're not supposed to be pinging it.  Just wake up
	 *	when we're supposed to mark it dead.
	 */
	if (home->ping_check == HOME_PING_CHECK_NONE) {
		if (home->state == HOME_STATE_ZOMBIE) {
			home->when = home->zombie_period_start;
			home->when.tv_sec += home->zombie_period;
			INSERT_EVENT(ping_home_server, home);
		}

		/*
		 *	Else mark_home_server_dead will set a timer
		 *	for revive_interval.
		 */
		return;
	}


	request = request_alloc(NULL);
	if (!request) return;
	request->number = request_num_counter++;
	NO_CHILD_THREAD;

	request->proxy = rad_alloc(request, true);
	rad_assert(request->proxy != NULL);

	if (home->ping_check == HOME_PING_CHECK_STATUS_SERVER) {
		request->proxy->code = PW_CODE_STATUS_SERVER;

		fr_pair_make(request->proxy, &request->proxy->vps,
			 "Message-Authenticator", "0x00", T_OP_SET);

	} else if ((home->type == HOME_TYPE_AUTH) ||
		   (home->type == HOME_TYPE_AUTH_ACCT)) {
		request->proxy->code = PW_CODE_ACCESS_REQUEST;

		fr_pair_make(request->proxy, &request->proxy->vps,
			 "User-Name", home->ping_user_name, T_OP_SET);
		fr_pair_make(request->proxy, &request->proxy->vps,
			 "User-Password", home->ping_user_password, T_OP_SET);
		fr_pair_make(request->proxy, &request->proxy->vps,
			 "Service-Type", "Authenticate-Only", T_OP_SET);
		fr_pair_make(request->proxy, &request->proxy->vps,
			 "Message-Authenticator", "0x00", T_OP_SET);

#ifdef WITH_ACCOUNTING
	} else if (home->type == HOME_TYPE_ACCT) {
		request->proxy->code = PW_CODE_ACCOUNTING_REQUEST;

		fr_pair_make(request->proxy, &request->proxy->vps,
			 "User-Name", home->ping_user_name, T_OP_SET);
		fr_pair_make(request->proxy, &request->proxy->vps,
			 "Acct-Status-Type", "Stop", T_OP_SET);
		fr_pair_make(request->proxy, &request->proxy->vps,
			 "Acct-Session-Id", "00000000", T_OP_SET);
		vp = fr_pair_make(request->proxy, &request->proxy->vps,
			      "Event-Timestamp", "0", T_OP_SET);
		vp->vp_date = now.tv_sec;
#endif

	} else {
		/*
		 *	Unkown home server type.
		 */
		talloc_free(request);
		return;
	}

	vp = fr_pair_make(request->proxy, &request->proxy->vps,
		      "NAS-Identifier", "", T_OP_SET);
	if (vp) {
		fr_pair_value_sprintf(vp, "Status Check %u. Are you alive?",
			    home->num_sent_pings);
	}

#ifdef WITH_TCP
	request->proxy->proto = home->proto;
#endif
	request->proxy->src_ipaddr = home->src_ipaddr;
	request->proxy->dst_ipaddr = home->ipaddr;
	request->proxy->dst_port = home->port;
	request->home_server = home;
#ifdef DEBUG_STATE_MACHINE
	if (rad_debug_lvl) printf("(%u) ********\tSTATE %s C-%s -> C-%s\t********\n", request->number, __FUNCTION__,
			       child_state_names[request->child_state],
			       child_state_names[REQUEST_DONE]);
	if (rad_debug_lvl) printf("(%u) ********\tNEXT-STATE %s -> %s\n", request->number, __FUNCTION__, "request_ping");
#endif
#ifdef HAVE_PTHREAD_H
	rad_assert(request->child_pid == NO_SUCH_CHILD_PID);
#endif
	request->child_state = REQUEST_PROXIED;
	request->process = request_ping;

	rad_assert(request->proxy_listener == NULL);

	if (!insert_into_proxy_hash(request)) {
		RPROXY("Failed to insert status check %d into proxy list.  Discarding it.",
		       request->number);

		rad_assert(!request->in_request_hash);
		rad_assert(!request->in_proxy_hash);
		rad_assert(request->ev == NULL);
		talloc_free(request);
		return;
	}

	/*
	 *	Set up the timer callback.
	 */
	when = now;
	when.tv_sec += home->ping_timeout;

	DEBUG("PING: Waiting %u seconds for response to ping",
	      home->ping_timeout);

	STATE_MACHINE_TIMER(FR_ACTION_TIMER);
	home->num_sent_pings++;

	rad_assert(request->proxy_listener != NULL);
	debug_packet(request, request->proxy, false);
	request->proxy_listener->send(request->proxy_listener,
				      request);

	/*
	 *	Add +/- 2s of jitter, as suggested in RFC 3539
	 *	and in the Issues and Fixes draft.
	 */
	home->when = now;
	home->when.tv_sec += home->ping_interval;

	add_jitter(&home->when);

	DEBUG("PING: Next status packet in %u seconds", home->ping_interval);
	INSERT_EVENT(ping_home_server, home);
}

static void home_trigger(home_server_t *home, char const *trigger)
{
	REQUEST *my_request;
	RADIUS_PACKET *my_packet;

	my_request = talloc_zero(NULL, REQUEST);
	my_packet = talloc_zero(my_request, RADIUS_PACKET);
	my_request->proxy = my_packet;
	my_packet->dst_ipaddr = home->ipaddr;
	my_packet->src_ipaddr = home->src_ipaddr;

	exec_trigger(my_request, home->cs, trigger, false);
	talloc_free(my_request);
}

static void mark_home_server_zombie(home_server_t *home, struct timeval *now, struct timeval *response_window)
{
	time_t start;
	char buffer[128];

	ASSERT_MASTER;

	rad_assert((home->state == HOME_STATE_ALIVE) ||
		   (home->state == HOME_STATE_UNKNOWN));

	/*
	 *	We've received a real packet recently.  Don't mark the
	 *	server as zombie until we've received NO packets for a
	 *	while.  The "1/4" of zombie period was chosen rather
	 *	arbitrarily.  It's a balance between too short, which
	 *	gives quick fail-over and fail-back, or too long,
	 *	where the proxy still sends packets to an unresponsive
	 *	home server.
	 */
	start = now->tv_sec - ((home->zombie_period + 3) / 4);
	if (home->last_packet_recv >= start) {
		DEBUG("Received reply from home server %d seconds ago.  Might not be zombie.",
		      (int) (now->tv_sec - home->last_packet_recv));
		return;
	}

	home->state = HOME_STATE_ZOMBIE;
	home_trigger(home, "home_server.zombie");

	/*
	 *	Set the home server to "zombie", as of the time
	 *	calculated above.
	 */
	home->zombie_period_start.tv_sec = start;
	home->zombie_period_start.tv_usec = USEC / 2;

	fr_event_delete(el, &home->ev);

	home->num_sent_pings = 0;
	home->num_received_pings = 0;

	PROXY( "Marking home server %s port %d as zombie (it has not responded in %d.%06d seconds).",
	       inet_ntop(home->ipaddr.af, &home->ipaddr.ipaddr,
			 buffer, sizeof(buffer)),
	       home->port, (int) response_window->tv_sec, (int) response_window->tv_usec);

	ping_home_server(home);
}


void revive_home_server(void *ctx)
{
	home_server_t *home = talloc_get_type_abort(ctx, home_server_t);
	char buffer[128];

	home->state = HOME_STATE_ALIVE;
	home->response_timeouts = 0;
	home_trigger(home, "home_server.alive");
	home->currently_outstanding = 0;
	gettimeofday(&home->revive_time, NULL);

	/*
	 *	Delete any outstanding events.
	 */
	ASSERT_MASTER;
	if (home->ev) fr_event_delete(el, &home->ev);

	PROXY( "Marking home server %s port %d alive again... we have no idea if it really is alive or not.",
	       inet_ntop(home->ipaddr.af, &home->ipaddr.ipaddr,
			 buffer, sizeof(buffer)),
	       home->port);
}

void mark_home_server_dead(home_server_t *home, struct timeval *when)
{
	int previous_state = home->state;
	char buffer[128];

	PROXY( "Marking home server %s port %d as dead.",
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
			DEBUG("PING: Already pinging home server %s", home->log_name);
		}

	} else {
		/*
		 *	Revive it after a fixed period of time.  This
		 *	is very, very, bad.
		 */
		home->when = *when;
		home->when.tv_sec += home->revive_interval;

		DEBUG("PING: Reviving home server %s in %u seconds", home->log_name, home->revive_interval);
		ASSERT_MASTER;
		INSERT_EVENT(revive_home_server, home);
	}
}

/** Wait for a reply after proxying a request.
 *
 *  Retransmit the proxied packet, or time out and go to
 *  proxy_no_reply.  Mark the home server unresponsive, etc.
 *
 *  If we do receive a reply, we transition to proxy_running.
 *
 *  \dot
 *	digraph proxy_wait_for_reply {
 *		proxy_wait_for_reply;
 *
 *		proxy_wait_for_reply -> retransmit_proxied_request [ label = "DUP", arrowhead = "none" ];
 *		proxy_wait_for_reply -> proxy_no_reply [ label = "TIMER >= response_window" ];
 *		proxy_wait_for_reply -> timer [ label = "TIMER < max_request_time" ];
 *		proxy_wait_for_reply -> proxy_running [ label = "PROXY_REPLY" arrowhead = "none"];
 *		proxy_wait_for_reply -> done [ label = "TIMER >= max_request_time" ];
 *	}
 *  \enddot
 */
static void proxy_wait_for_reply(REQUEST *request, int action)
{
	struct timeval now, when;
	struct timeval *response_window = NULL;
	home_server_t *home = request->home_server;
	char buffer[128];

	VERIFY_REQUEST(request);

	TRACE_STATE_MACHINE;
	CHECK_FOR_STOP;

	rad_assert(request->packet->code != PW_CODE_STATUS_SERVER);
	rad_assert(request->home_server != NULL);

	gettimeofday(&now, NULL);

	switch (action) {
	case FR_ACTION_DUP:
		/*
		 *	We have a reply, ignore the retransmit.
		 */
		if (request->proxy_reply) return;

		/*
		 *	The request was proxied to a virtual server.
		 *	Ignore the retransmit.
		 */
		if (request->home_server->server) return;

		/*
		 *	Use a new connection when the home server is
		 *	dead, or when there's no proxy listener, or
		 *	when the listener is failed or dead.
		 *
		 *	If the listener is known or frozen, use it for
		 *	retransmits.
		 */
		if ((home->state == HOME_STATE_IS_DEAD) ||
		    !request->proxy_listener ||
		    (request->proxy_listener->status >= RAD_LISTEN_STATUS_EOL)) {
			request_proxy_anew(request);
			return;
		}

#ifdef WITH_TCP
		/*
		 *	The home server is still alive, but TCP.  We
		 *	rely on TCP to get the request and reply back.
		 *	So there's no need to retransmit.
		 */
		if (home->proto == IPPROTO_TCP) {
			DEBUG2("Suppressing duplicate proxied request (tcp) to home server %s port %d proto TCP - ID: %d",
			       inet_ntop(request->proxy->dst_ipaddr.af,
					 &request->proxy->dst_ipaddr.ipaddr,
					 buffer, sizeof(buffer)),
			       request->proxy->dst_port,
			       request->proxy->id);
			return;
		}
#endif

		/*
		 *	More than one retransmit a second is stupid,
		 *	and should be suppressed by the proxy.
		 */
		when = request->proxy->timestamp;
		when.tv_sec++;

		if (timercmp(&now, &when, <)) {
			DEBUG2("Suppressing duplicate proxied request (too fast) to home server %s port %d proto TCP - ID: %d",
			       inet_ntop(request->proxy->dst_ipaddr.af,
					 &request->proxy->dst_ipaddr.ipaddr,
					 buffer, sizeof(buffer)),
			       request->proxy->dst_port,
			       request->proxy->id);
			return;
		}

#ifdef WITH_ACCOUNTING
		/*
		 *	If we update the Acct-Delay-Time, we need to
		 *	get a new ID.
		 */
		if ((request->packet->code == PW_CODE_ACCOUNTING_REQUEST) &&
		    fr_pair_find_by_num(request->proxy->vps, PW_ACCT_DELAY_TIME, 0, TAG_ANY)) {
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

		rad_assert(request->proxy_listener != NULL);
		FR_STATS_TYPE_INC(home->stats.total_requests);
		home->last_packet_sent = now.tv_sec;
		request->proxy->timestamp = now;
		debug_packet(request, request->proxy, false);
		request->proxy_listener->send(request->proxy_listener, request);
		break;

	case FR_ACTION_TIMER:
		response_window = request_response_window(request);

#ifdef WITH_TCP
		if (!request->proxy_listener ||
		    (request->proxy_listener->status >= RAD_LISTEN_STATUS_EOL)) {
			remove_from_proxy_hash(request);

			when = request->packet->timestamp;
			when.tv_sec += request->root->max_request_time;

			if (timercmp(&when, &now, >)) {
				RDEBUG("Waiting for client retransmission in order to do a proxy retransmit");
				STATE_MACHINE_TIMER(FR_ACTION_TIMER);
				return;
			}
		} else
#endif
		{
			/*
			 *	Wake up "response_window" time in the future.
			 *	i.e. when MY packet hasn't received a response.
			 *
			 *	Note that we DO NOT mark the home server as
			 *	zombie if it doesn't respond to us.  It may be
			 *	responding to other (better looking) packets.
			 */
			when = request->proxy->timestamp;
			timeradd(&when, response_window, &when);

			/*
			 *	Not at the response window.  Set the timer for
			 *	that.
			 */
			if (timercmp(&when, &now, >)) {
				struct timeval diff;
				timersub(&when, &now, &diff);

				RDEBUG("Expecting proxy response no later than %d.%06d seconds from now",
				       (int) diff.tv_sec, (int) diff.tv_usec);
				STATE_MACHINE_TIMER(FR_ACTION_TIMER);
				return;
			}
		}

		RDEBUG("No proxy response, giving up on request and marking it done");

		/*
		 *	If we haven't received any packets for
		 *	"response_window", then mark the home server
		 *	as zombie.
		 *
		 *	This check should really be part of a home
		 *	server state machine.
		 */
		if (((home->state == HOME_STATE_ALIVE) ||
		     (home->state == HOME_STATE_UNKNOWN))
			) {
			home->response_timeouts++;
			if (home->response_timeouts >= home->max_response_timeouts)
				mark_home_server_zombie(home, &now, response_window);
		}

		FR_STATS_TYPE_INC(home->stats.total_timeouts);
		if (home->type == HOME_TYPE_AUTH) {
			if (request->proxy_listener) FR_STATS_TYPE_INC(request->proxy_listener->stats.total_timeouts);
			FR_STATS_TYPE_INC(proxy_auth_stats.total_timeouts);
		}
#ifdef WITH_ACCT
		else if (home->type == HOME_TYPE_ACCT) {
			if (request->proxy_listener) FR_STATS_TYPE_INC(request->proxy_listener->stats.total_timeouts);
			FR_STATS_TYPE_INC(proxy_acct_stats.total_timeouts);
		}
#endif
#ifdef WITH_COA
		else if (home->type == HOME_TYPE_COA) {
			if (request->proxy_listener) FR_STATS_TYPE_INC(request->proxy_listener->stats.total_timeouts);

			if (request->packet->code == PW_CODE_COA_REQUEST) {
				FR_STATS_TYPE_INC(proxy_coa_stats.total_timeouts);
			} else {
				FR_STATS_TYPE_INC(proxy_dsc_stats.total_timeouts);
			}
		}
#endif

		/*
		 *	There was no response within the window.  Stop
		 *	the request.  If the client retransmitted, it
		 *	may have failed over to another home server.
		 *	But that one may be dead, too.
		 *
		 * 	The extra verbose message if we have a username,
		 *	is extremely useful if the proxy is part of a chain
		 *	and the final home server, is not the one we're
		 *	proxying to.
		 */
		if (request->username) {
			RERROR("Failing proxied request for user \"%s\", due to lack of any response from home "
			       "server %s port %d",
			       request->username->vp_strvalue,
			       inet_ntop(request->proxy->dst_ipaddr.af,
					 &request->proxy->dst_ipaddr.ipaddr,
					 buffer, sizeof(buffer)),
			       request->proxy->dst_port);
		} else {
			RERROR("Failing proxied request, due to lack of any response from home server %s port %d",
			       inet_ntop(request->proxy->dst_ipaddr.af,
					 &request->proxy->dst_ipaddr.ipaddr,
					 buffer, sizeof(buffer)),
			       request->proxy->dst_port);
		}

		if (setup_post_proxy_fail(request)) {
			request_queue_or_run(request, proxy_no_reply);
		} else {
			gettimeofday(&request->reply->timestamp, NULL);
			request_cleanup_delay_init(request);
		}
		break;

		/*
		 *	We received a new reply.  Go process it.
		 */
	case FR_ACTION_PROXY_REPLY:
		request_queue_or_run(request, proxy_running);
		break;

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

	VERIFY_REQUEST(request);

	rad_assert(request->coa != NULL);
	rad_assert(request->proxy == NULL);
	rad_assert(!request->in_proxy_hash);
	rad_assert(request->proxy_reply == NULL);

	/*
	 *	Check whether we want to originate one, or cancel one.
	 */
	vp = fr_pair_find_by_num(request->config, PW_SEND_COA_REQUEST, 0, TAG_ANY);
	if (!vp) {
		vp = fr_pair_find_by_num(request->coa->proxy->vps, PW_SEND_COA_REQUEST, 0, TAG_ANY);
	}

	if (vp) {
		if (vp->vp_integer == 0) {
		fail:
			TALLOC_FREE(request->coa);
			return;
		}
	}

	if (!main_config.proxy_requests) {
		RWDEBUG("Cannot originate CoA packets unless 'proxy_requests = yes'");
			TALLOC_FREE(request->coa);
		return;
	}

	coa = request->coa;

	/*
	 *	src_ipaddr will be set up in proxy_encode.
	 */
	memset(&ipaddr, 0, sizeof(ipaddr));
	vp = fr_pair_find_by_num(coa->proxy->vps, PW_PACKET_DST_IP_ADDRESS, 0, TAG_ANY);
	if (vp) {
		ipaddr.af = AF_INET;
		ipaddr.ipaddr.ip4addr.s_addr = vp->vp_ipaddr;
		ipaddr.prefix = 32;
	} else if ((vp = fr_pair_find_by_num(coa->proxy->vps, PW_PACKET_DST_IPV6_ADDRESS, 0, TAG_ANY)) != NULL) {
		ipaddr.af = AF_INET6;
		ipaddr.ipaddr.ip6addr = vp->vp_ipv6addr;
		ipaddr.prefix = 128;
	} else if ((vp = fr_pair_find_by_num(coa->proxy->vps, PW_HOME_SERVER_POOL, 0, TAG_ANY)) != NULL) {
		coa->home_pool = home_pool_byname(vp->vp_strvalue,
						  HOME_TYPE_COA);
		if (!coa->home_pool) {
			RWDEBUG2("No such home_server_pool %s",
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
			RWDEBUG("No live home server for home_server_pool %s", coa->home_pool->name);
			goto fail;
		}
		home_server_update_request(coa->home_server, coa);

	} else if (!coa->home_server) {
		uint16_t port = PW_COA_UDP_PORT;

		vp = fr_pair_find_by_num(coa->proxy->vps, PW_PACKET_DST_PORT, 0, TAG_ANY);
		if (vp) port = vp->vp_integer;

		coa->home_server = home_server_find(&ipaddr, port, IPPROTO_UDP);
		if (!coa->home_server) {
			RWDEBUG2("Unknown destination %s:%d for CoA request.",
			       inet_ntop(ipaddr.af, &ipaddr.ipaddr,
					 buffer, sizeof(buffer)), port);
			goto fail;
		}
	}

	vp = fr_pair_find_by_num(coa->proxy->vps, PW_PACKET_TYPE, 0, TAG_ANY);
	if (vp) {
		switch (vp->vp_integer) {
		case PW_CODE_COA_REQUEST:
		case PW_CODE_DISCONNECT_REQUEST:
			coa->proxy->code = vp->vp_integer;
			break;

		default:
			DEBUG("Cannot set CoA Packet-Type to code %d",
			      vp->vp_integer);
			goto fail;
		}
	}

	if (!coa->proxy->code) coa->proxy->code = PW_CODE_COA_REQUEST;

	/*
	 *	The rest of the server code assumes that
	 *	request->packet && request->reply exist.  Copy them
	 *	from the original request.
	 */
	rad_assert(coa->packet != NULL);
	rad_assert(coa->packet->vps == NULL);

	coa->packet = rad_copy_packet(coa, request->packet);
	coa->reply = rad_copy_packet(coa, request->reply);

	coa->config = fr_pair_list_copy(coa, request->config);
	coa->num_coa_requests = 0;
	coa->handle = null_handler;
	coa->number = request->number; /* it's associated with the same request */

	/*
	 *	Call the pre-proxy routines.
	 */
	vp = fr_pair_find_by_num(request->config, PW_PRE_PROXY_TYPE, 0, TAG_ANY);
	if (vp) {
		DICT_VALUE const *dval = dict_valbyattr(vp->da->attr, vp->da->vendor, vp->vp_integer);
		/* Must be a validation issue */
		rad_assert(dval);
		RDEBUG2("Found Pre-Proxy-Type %s", dval->name);
		pre_proxy_type = vp->vp_integer;
	}

	if (coa->home_pool && coa->home_pool->virtual_server) {
		char const *old_server = coa->server;

		coa->server = coa->home_pool->virtual_server;
		RDEBUG2("server %s {", coa->server);
		RINDENT();
		rcode = process_pre_proxy(pre_proxy_type, coa);
		REXDENT();
		RDEBUG2("}");
		coa->server = old_server;
	} else {
		rcode = process_pre_proxy(pre_proxy_type, coa);
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
		radlog_request(L_PROXY, 0, coa, "Failed to insert CoA request into proxy list");
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
	coa->home_server->last_packet_sent = coa->proxy->timestamp.tv_sec;
	coa->delay = 0;		/* need to calculate a new delay */

	/*
	 *	If requested, put a State attribute into the packet,
	 *	and cache the VPS.
	 */
	fr_state_put_vps(coa, NULL, coa->packet);

	/*
	 *	Encode the packet before we do anything else.
	 */
	coa->proxy_listener->encode(coa->proxy_listener, coa);
	debug_packet(coa, coa->proxy, false);

#ifdef DEBUG_STATE_MACHINE
	if (rad_debug_lvl) printf("(%u) ********\tSTATE %s C-%s -> C-%s\t********\n", request->number, __FUNCTION__,
			       child_state_names[request->child_state],
			       child_state_names[REQUEST_PROXIED]);
#endif

	/*
	 *	Set the state function, then the state, no child, and
	 *	send the packet.
	 */
	coa->process = coa_wait_for_reply;
	coa->child_state = REQUEST_PROXIED;

#ifdef HAVE_PTHREAD_H
	coa->child_pid = NO_SUCH_CHILD_PID;
#endif

	if (we_are_master()) coa_separate(request->coa);

	/*
	 *	And send the packet.
	 */
	coa->proxy_listener->send(coa->proxy_listener, coa);
}


static void coa_retransmit(REQUEST *request)
{
	uint32_t delay, frac;
	struct timeval now, when, mrd;
	char buffer[128];

	VERIFY_REQUEST(request);

	fr_event_now(el, &now);

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
			STATE_MACHINE_TIMER(FR_ACTION_TIMER);
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
		RERROR("Failing request - originate-coa ID %u, due to lack of any response from coa server %s port %d",
		       request->proxy->id,
			       inet_ntop(request->proxy->dst_ipaddr.af,
					 &request->proxy->dst_ipaddr.ipaddr,
					 buffer, sizeof(buffer)),
			       request->proxy->dst_port);

		if (setup_post_proxy_fail(request)) {
			request_queue_or_run(request, coa_no_reply);
		} else {
			request_done(request, FR_ACTION_DONE);
		}
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
	STATE_MACHINE_TIMER(FR_ACTION_TIMER);

	request->num_coa_requests++; /* is NOT reset by code 3 lines above! */

	FR_STATS_TYPE_INC(request->home_server->stats.total_requests);

	RDEBUG2("Sending duplicate CoA request to home server %s port %d - ID: %d",
		inet_ntop(request->proxy->dst_ipaddr.af,
			  &request->proxy->dst_ipaddr.ipaddr,
			  buffer, sizeof(buffer)),
		request->proxy->dst_port,
		request->proxy->id);

	request->proxy_listener->send(request->proxy_listener,
				      request);
}


/** Wait for a reply after originating a CoA a request.
 *
 *  Retransmit the proxied packet, or time out and go to
 *  coa_no_reply.  Mark the home server unresponsive, etc.
 *
 *  If we do receive a reply, we transition to coa_running.
 *
 *  \dot
 *	digraph coa_wait_for_reply {
 *		coa_wait_for_reply;
 *
 *		coa_wait_for_reply -> coa_no_reply [ label = "TIMER >= response_window" ];
 *		coa_wait_for_reply -> timer [ label = "TIMER < max_request_time" ];
 *		coa_wait_for_reply -> coa_running [ label = "PROXY_REPLY" arrowhead = "none"];
 *		coa_wait_for_reply -> done [ label = "TIMER >= max_request_time" ];
 *	}
 *  \enddot
 */
static void coa_wait_for_reply(REQUEST *request, int action)
{
	VERIFY_REQUEST(request);

	TRACE_STATE_MACHINE;
	ASSERT_MASTER;
	CHECK_FOR_STOP;

	if (request->parent) coa_separate(request);

	switch (action) {
	case FR_ACTION_TIMER:
		if (request_max_time(request)) break;

		/*
		 *	Don't do fail-over.  This is a 3.1 feature.
		 */
		if (!request->home_server ||
		    (request->home_server->state == HOME_STATE_IS_DEAD) ||
		    !request->proxy_listener ||
		    (request->proxy_listener->status >= RAD_LISTEN_STATUS_EOL)) {
			request_done(request, FR_ACTION_DONE);
			break;
		}

		coa_retransmit(request);
		break;

	case FR_ACTION_PROXY_REPLY:
		request_queue_or_run(request, coa_running);
		break;

	default:
		RDEBUG3("%s: Ignoring action %s", __FUNCTION__, action_codes[action]);
		break;
	}
}

static void coa_separate(REQUEST *request)
{
	VERIFY_REQUEST(request);
#ifdef DEBUG_STATE_MACHINE
	int action = FR_ACTION_TIMER;
#endif

	TRACE_STATE_MACHINE;
	ASSERT_MASTER;

	rad_assert(request->parent != NULL);
	rad_assert(request->parent->coa == request);
	rad_assert(request->ev == NULL);
	rad_assert(!request->in_request_hash);
	rad_assert(request->coa == NULL);

	rad_assert(request->proxy_reply || request->proxy_listener);

	(void) talloc_steal(NULL, request);
	request->parent->coa = NULL;
	request->parent = NULL;

	if (we_are_master()) {
		request->delay = 0;
		coa_retransmit(request);
	}
}


/** Process a request after the CoA has timed out.
 *
 *  Run the packet through Post-Proxy-Type Fail
 *
 *  \dot
 *	digraph coa_no_reply {
 *		coa_no_reply;
 *
 *		coa_no_reply -> dup [ label = "DUP", arrowhead = "none" ];
 *		coa_no_reply -> timer [ label = "TIMER < max_request_time" ];
 *		coa_no_reply -> coa_reply_too_late [ label = "PROXY_REPLY" arrowhead = "none"];
 *		coa_no_reply -> process_proxy_reply [ label = "RUN" ];
 *		coa_no_reply -> done [ label = "TIMER >= timeout" ];
 *	}
 *  \enddot
 */
static void coa_no_reply(REQUEST *request, int action)
{
	char buffer[128];

	VERIFY_REQUEST(request);

	TRACE_STATE_MACHINE;
	CHECK_FOR_STOP;

	switch (action) {
	case FR_ACTION_TIMER:
		(void) request_max_time(request);
		break;

	case FR_ACTION_PROXY_REPLY: /* too late! */
		RDEBUG2("Reply from CoA server %s port %d  - ID: %d arrived too late.",
			inet_ntop(request->proxy->src_ipaddr.af,
				  &request->proxy->src_ipaddr.ipaddr,
				  buffer, sizeof(buffer)),
			request->proxy->dst_port, request->proxy->id);
		break;

	case FR_ACTION_RUN:
		if (process_proxy_reply(request, NULL)) {
			request->handle(request);
		}
		request_done(request, FR_ACTION_DONE);
		break;

	default:
		RDEBUG3("%s: Ignoring action %s", __FUNCTION__, action_codes[action]);
		break;
	}
}


/** Process the request after receiving a coa reply.
 *
 *  Throught the post-proxy section, and the through the handler
 *  function.
 *
 *  \dot
 *	digraph coa_running {
 *		coa_running;
 *
 *		coa_running -> timer [ label = "TIMER < max_request_time" ];
 *		coa_running -> process_proxy_reply [ label = "RUN" ];
 *		coa_running -> done [ label = "TIMER >= timeout" ];
 *	}
 *  \enddot
 */
static void coa_running(REQUEST *request, int action)
{
	VERIFY_REQUEST(request);

	TRACE_STATE_MACHINE;
	CHECK_FOR_STOP;

	switch (action) {
	case FR_ACTION_TIMER:
		(void) request_max_time(request);
		break;

	case FR_ACTION_RUN:
		if (process_proxy_reply(request, request->proxy_reply)) {
			request->handle(request);
		}
		request_done(request, FR_ACTION_DONE);
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
static void event_socket_handler(fr_event_list_t *xel, UNUSED int fd, void *ctx)
{
	rad_listen_t *listener = talloc_get_type_abort(ctx, rad_listen_t);

	rad_assert(xel == el);

	if ((listener->fd < 0)
#ifdef WITH_DETAIL
#ifndef WITH_DETAIL_THREAD
	    && (listener->type != RAD_LISTEN_DETAIL)
#endif
#endif
		) {
		char buffer[256];

		listener->print(listener, buffer, sizeof(buffer));
		ERROR("FATAL: Asked to read from closed socket: %s",
		       buffer);

		rad_panic("Socket was closed on us!");
		fr_exit_now(1);
	}

	listener->recv(listener);
}

#ifdef WITH_DETAIL
#ifdef WITH_DETAIL_THREAD
#else
/*
 *	This function is called periodically to see if this detail
 *	file is available for reading.
 */
static void event_poll_detail(void *ctx)
{
	int delay;
	rad_listen_t *this = talloc_get_type_abort(ctx, rad_listen_t);
	struct timeval when, now;
	listen_detail_t *detail = this->data;

	rad_assert(this->type == RAD_LISTEN_DETAIL);

 redo:
	event_socket_handler(el, this->fd, this);

	fr_event_now(el, &now);
	when = now;

	/*
	 *	Backdoor API to get the delay until the next poll
	 *	time.
	 */
	delay = this->encode(this, NULL);
	if (delay == 0) goto redo;

	tv_add(&when, delay);

	ASSERT_MASTER;
	if (!fr_event_insert(el, event_poll_detail, this,
			     &when, &detail->ev)) {
		ERROR("Failed creating handler");
		fr_exit(1);
	}
}
#endif	/* WITH_DETAIL_THREAD */
#endif	/* WITH_DETAIL */

static void event_status(struct timeval *wake)
{
#if !defined(HAVE_PTHREAD_H) && defined(WNOHANG)
	int argval;
#endif

	if (rad_debug_lvl == 0) {
		if (just_started) {
			INFO("Ready to process requests");
			just_started = false;
		}
		return;
	}

	if (!wake) {
		INFO("Ready to process requests");

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

#ifdef WITH_TCP
static void listener_free_cb(void *ctx)
{
	rad_listen_t *this = talloc_get_type_abort(ctx, rad_listen_t);
	char buffer[1024];

	if (this->count > 0) {
		struct timeval when;
		listen_socket_t *sock = this->data;

		fr_event_now(el, &when);
		when.tv_sec += 3;

		ASSERT_MASTER;
		if (!fr_event_insert(el, listener_free_cb, this, &when,
				     &(sock->ev))) {
			rad_panic("Failed to insert event");
		}

		return;
	}

	/*
	 *	It's all free, close the socket.
	 */

	this->print(this, buffer, sizeof(buffer));
	DEBUG("... cleaning up socket %s", buffer);
	rad_assert(this->next == NULL);
	talloc_free(this);
}

#ifdef WITH_PROXY
static int proxy_eol_cb(void *ctx, void *data)
{
	struct timeval when;
	REQUEST *request = fr_packet2myptr(REQUEST, proxy, data);

	if (request->proxy_listener != ctx) return 0;

	/*
	 *	We don't care if it's being processed in a child thread.
	 */

#ifdef WITH_ACCOUNTING
	/*
	 *	Accounting packets should be deleted immediately.
	 *	They will never be retransmitted by the client.
	 */
	if (request->proxy->code == PW_CODE_ACCOUNTING_REQUEST) {
		RDEBUG("Stopping request due to failed connection to home server");
		request->master_state = REQUEST_STOP_PROCESSING;
	}
#endif

	/*
	 *	Reset the timer to be now, so that the request is
	 *	quickly updated.  But spread the requests randomly
	 *	over the next second, so that we don't overload the
	 *	server.
	 */
	fr_event_now(el, &when);
	tv_add(&when, fr_rand() % USEC);
	STATE_MACHINE_TIMER(FR_ACTION_TIMER);

	/*
	 *	Don't delete it from the list.
	 */
	return 0;
}
#endif	/* WITH_PROXY */
#endif	/* WITH_TCP */

static int event_new_fd(rad_listen_t *this)
{
	char buffer[1024];

	ASSERT_MASTER;

	if (this->status == RAD_LISTEN_STATUS_KNOWN) return 1;

	this->print(this, buffer, sizeof(buffer));

	if (this->status == RAD_LISTEN_STATUS_INIT) {
		listen_socket_t *sock = this->data;

		rad_assert(sock != NULL);
		if (just_started) {
			DEBUG("Listening on %s", buffer);
		} else {
			INFO(" ... adding new socket %s", buffer);
		}

#ifdef WITH_PROXY
		if (!just_started && (this->type == RAD_LISTEN_PROXY)) {
			home_server_t *home;
			
			home = sock->home;
			if (!home || !home->limit.max_connections) {
				INFO(" ... adding new socket %s", buffer);
			} else {
				INFO(" ... adding new socket %s (%u of %u)", buffer,
				     home->limit.num_connections, home->limit.max_connections);
			}

#endif
		}

		switch (this->type) {
#ifdef WITH_DETAIL
		/*
		 *	Detail files are always known, and aren't
		 *	put into the socket event loop.
		 */
		case RAD_LISTEN_DETAIL:
			this->status = RAD_LISTEN_STATUS_KNOWN;

#ifndef WITH_DETAIL_THREAD
			/*
			 *	Set up the first poll interval.
			 */
			event_poll_detail(this);
			return 1;
#else
			break;	/* add the FD to the list */
#endif
#endif	/* WITH_DETAIL */

#ifdef WITH_PROXY
		/*
		 *	Add it to the list of sockets we can use.
		 *	Server sockets (i.e. auth/acct) are never
		 *	added to the packet list.
		 */
		case RAD_LISTEN_PROXY:
#ifdef WITH_TCP
			rad_assert((sock->proto == IPPROTO_UDP) || (sock->home != NULL));

			/*
			 *	Add timers to outgoing child sockets, if necessary.
			 */
			if (sock->proto == IPPROTO_TCP && sock->opened &&
			    (sock->home->limit.lifetime || sock->home->limit.idle_timeout)) {
				struct timeval when;

				when.tv_sec = sock->opened + 1;
				when.tv_usec = 0;

				ASSERT_MASTER;
				if (!fr_event_insert(el, tcp_socket_timer, this, &when,
						     &(sock->ev))) {
					rad_panic("Failed to insert event");
				}
			}
#endif	/* WITH_TCP */
			break;
#endif	/* WITH_PROXY */

			/*
			 *	FIXME: put idle timers on command sockets.
			 */

		default:
#ifdef WITH_TCP
			/*
			 *	Add timers to incoming child sockets, if necessary.
			 */
			if (sock->proto == IPPROTO_TCP && sock->opened &&
			    (sock->limit.lifetime || sock->limit.idle_timeout)) {
				struct timeval when;

				when.tv_sec = sock->opened + 1;
				when.tv_usec = 0;

				ASSERT_MASTER;
				if (!fr_event_insert(el, tcp_socket_timer, this, &when,
						     &(sock->ev))) {
					ERROR("Failed adding timer for socket: %s", fr_strerror());
					fr_exit(1);
				}
			}
#endif	/* WITH_TCP */
			break;
		} /* switch over listener types */

		/*
		 *	All sockets: add the FD to the event handler.
		 */
		if (!fr_event_fd_insert(el, 0, this->fd,
					event_socket_handler, this)) {
			ERROR("Failed adding event handler for socket: %s", fr_strerror());
			fr_exit(1);
		}

		this->status = RAD_LISTEN_STATUS_KNOWN;
		return 1;
	} /* end of INIT */

#ifdef WITH_TCP
	/*
	 *	The socket has reached a timeout.  Try to close it.
	 */
	if (this->status == RAD_LISTEN_STATUS_FROZEN) {
		/*
		 *	Requests are still using the socket.  Wait for
		 *	them to finish.
		 */
		if (this->count > 0) {
			struct timeval when;
			listen_socket_t *sock = this->data;

			/*
			 *	Try again to clean up the socket in 30
			 *	seconds.
			 */
			gettimeofday(&when, NULL);
			when.tv_sec += 30;

			ASSERT_MASTER;
			if (!fr_event_insert(el,
					     (fr_event_callback_t) event_new_fd,
					     this, &when, &sock->ev)) {
				rad_panic("Failed to insert event");
			}

			return 1;
		}

		fr_event_fd_delete(el, 0, this->fd);
		this->status = RAD_LISTEN_STATUS_REMOVE_NOW;
	}

	/*
	 *	The socket has had a catastrophic error.  Close it.
	 */
	if (this->status == RAD_LISTEN_STATUS_EOL) {
		/*
		 *	Remove it from the list of live FD's.
		 */
		fr_event_fd_delete(el, 0, this->fd);

#ifdef WITH_PROXY
		/*
		 *	Tell all requests using this socket that the socket is dead.
		 */
		if (this->type == RAD_LISTEN_PROXY) {
			PTHREAD_MUTEX_LOCK(&proxy_mutex);
			if (!fr_packet_list_socket_freeze(proxy_list,
							  this->fd)) {
				ERROR("Fatal error freezing socket: %s", fr_strerror());
				fr_exit(1);
			}

			if (this->count > 0) {
				fr_packet_list_walk(proxy_list, this, proxy_eol_cb);
			}
			PTHREAD_MUTEX_UNLOCK(&proxy_mutex);
		}
#endif	/* WITH_PROXY */

		/*
		 *	Requests are still using the socket.  Wait for
		 *	them to finish.
		 */
		if (this->count > 0) {
			struct timeval when;
			listen_socket_t *sock = this->data;

			/*
			 *	Try again to clean up the socket in 30
			 *	seconds.
			 */
			gettimeofday(&when, NULL);
			when.tv_sec += 30;

			ASSERT_MASTER;
			if (!fr_event_insert(el,
					     (fr_event_callback_t) event_new_fd,
					     this, &when, &sock->ev)) {
				rad_panic("Failed to insert event");
			}

			return 1;
		}

		/*
		 *	No one is using the socket.  We can remove it now.
		 */
		this->status = RAD_LISTEN_STATUS_REMOVE_NOW;
	} /* socket is at EOL */
#endif	  /* WITH_TCP */

	/*
	 *	Nuke the socket.
	 */
	if (this->status == RAD_LISTEN_STATUS_REMOVE_NOW) {
		int devnull;
#ifdef WITH_TCP
		listen_socket_t *sock = this->data;
		struct timeval when;
#endif

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
			ERROR("FATAL failure opening /dev/null: %s",
			       fr_syserror(errno));
			fr_exit(1);
		}
		if (dup2(devnull, this->fd) < 0) {
			ERROR("FATAL failure closing socket: %s",
			       fr_syserror(errno));
			fr_exit(1);
		}
		close(devnull);

#ifdef WITH_DETAIL
		rad_assert(this->type != RAD_LISTEN_DETAIL);
#endif

#ifdef WITH_TCP
#ifdef WITH_PROXY
		/*
		 *	The socket is dead.  Force all proxied packets
		 *	to stop using it.  And then remove it from the
		 *	list of outgoing sockets.
		 */
		if (this->type == RAD_LISTEN_PROXY) {
			home_server_t *home;

			home = sock->home;
			if (!home || !home->limit.max_connections) {
				INFO(" ... shutting down socket %s", buffer);
			} else {
				INFO(" ... shutting down socket %s (%u of %u)", buffer,
				     home->limit.num_connections, home->limit.max_connections);
			}

			PTHREAD_MUTEX_LOCK(&proxy_mutex);
			fr_packet_list_walk(proxy_list, this, eol_proxy_listener);

			if (!fr_packet_list_socket_del(proxy_list, this->fd)) {
				ERROR("Fatal error removing socket %s: %s",
				      buffer, fr_strerror());
				fr_exit(1);
			}
			PTHREAD_MUTEX_UNLOCK(&proxy_mutex);
		} else
#endif	/* WITH_PROXY */
		{
			INFO(" ... shutting down socket %s", buffer);

			/*
			 *	EOL all requests using this socket.
			 */
			rbtree_walk(pl, RBTREE_DELETE_ORDER, eol_listener, this);
		}

		/*
		 *	No child threads, clean it up now.
		 */
		if (!spawn_flag) {
			ASSERT_MASTER;
			if (sock->ev) fr_event_delete(el, &sock->ev);
			listen_free(&this);
			return 1;
		}

		/*
		 *	Wait until all requests using this socket are done.
		 */
		gettimeofday(&when, NULL);
		when.tv_sec += 3;

		ASSERT_MASTER;
		if (!fr_event_insert(el, listener_free_cb, this, &when,
				     &(sock->ev))) {
			rad_panic("Failed to insert event");
		}
#endif	/* WITH_TCP */
	}

	return 1;
}

/***********************************************************************
 *
 *	Signal handlers.
 *
 ***********************************************************************/

static void handle_signal_self(int flag)
{
	ASSERT_MASTER;

	if ((flag & (RADIUS_SIGNAL_SELF_EXIT | RADIUS_SIGNAL_SELF_TERM)) != 0) {
		if ((flag & RADIUS_SIGNAL_SELF_EXIT) != 0) {
			INFO("Signalled to exit");
			fr_event_loop_exit(el, 1);
		} else {
			INFO("Signalled to terminate");
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
			INFO("Ignoring HUP (less than 5s since last one)");
			return;
		}

		INFO("Received HUP signal");

		last_hup = when;

		exec_trigger(NULL, NULL, "server.signal.hup", true);
		fr_event_loop_exit(el, 0x80);
	}

#if defined(WITH_DETAIL) && !defined(WITH_DETAIL_THREAD)
	if ((flag & RADIUS_SIGNAL_SELF_DETAIL) != 0) {
		rad_listen_t *this;

		/*
		 *	FIXME: O(N) loops suck.
		 */
		for (this = main_config.listen;
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

#if defined(WITH_TCP) && defined(WITH_PROXY) && defined(HAVE_PTHREAD_H)
	/*
	 *	There are new listeners in the list.  Run
	 *	event_new_fd() on them.
	 */
	if ((flag & RADIUS_SIGNAL_SELF_NEW_FD) != 0) {
		rad_listen_t *this, *next;

		FD_MUTEX_LOCK(&fd_mutex);

		/*
		 *	FIXME: unlock the mutex before calling
		 *	event_new_fd()?
		 */
		for (this = new_listeners; this != NULL; this = next) {
			next = this->next;
			this->next = NULL;

			event_new_fd(this);
		}

		new_listeners = NULL;
		FD_MUTEX_UNLOCK(&fd_mutex);
	}
#endif
}

#ifndef HAVE_PTHREAD_H
void radius_signal_self(int flag)
{
	if (flag == RADIUS_SIGNAL_SELF_TERM) {
		main_config.exiting = true;
	}

	return handle_signal_self(flag);
}

#else
static int self_pipe[2] = { -1, -1 };

/*
 *	Inform ourselves that we received a signal.
 */
void radius_signal_self(int flag)
{
	ssize_t rcode;
	uint8_t buffer[16];

	if (flag == RADIUS_SIGNAL_SELF_TERM) {
		main_config.exiting = true;
	}

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

	if (write(self_pipe[1], buffer, 1) < 0) fr_exit(0);
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
#endif	/* HAVE_PTHREAD_H */

/***********************************************************************
 *
 *	Bootstrapping code.
 *
 ***********************************************************************/

/*
 *	Externally-visibly functions.
 */
int radius_event_init(TALLOC_CTX *ctx) {
	el = fr_event_list_create(ctx, event_status);
	if (!el) return 0;

	return 1;
}

static int packet_entry_cmp(void const *one, void const *two)
{
	RADIUS_PACKET const * const *a = one;
	RADIUS_PACKET const * const *b = two;

	return fr_packet_cmp(*a, *b);
}

#ifdef WITH_PROXY
/*
 *	They haven't defined a proxy listener.  Automatically
 *	add one for them, with the correct address family.
 */
static void create_default_proxy_listener(int af)
{
	uint16_t	port = 0;
	home_server_t	home;
	listen_socket_t *sock;
	rad_listen_t	*this;

	memset(&home, 0, sizeof(home));

	/*
	 *	Open a default UDP port
	 */
	home.proto = IPPROTO_UDP;
	port = 0;

	/*
	 *	Set the address family.
	 */
	home.src_ipaddr.af = af;
	home.ipaddr.af = af;

	/*
	 *	Get the correct listener.
	 */
	this = proxy_new_listener(proxy_ctx, &home, port);
	if (!this) {
		fr_exit_now(1);
	}

	sock = this->data;
	if (!fr_packet_list_socket_add(proxy_list, this->fd,
				       sock->proto,
				       &sock->other_ipaddr, sock->other_port,
				       this)) {
		ERROR("Failed adding proxy socket");
		fr_exit_now(1);
	}

	/*
	 *	Insert the FD into list of FDs to listen on.
	 */
	radius_update_listener(this);
}

/*
 *	See if we automatically need to open a proxy socket.
 */
static void check_proxy(rad_listen_t *head)
{
	bool		defined_proxy;
	bool		has_v4, has_v6;
	rad_listen_t	*this;

	if (check_config) return;
	if (!main_config.proxy_requests) return;
	if (!head) return;
#ifdef WITH_TCP
	if (!home_servers_udp) return;
#endif

	/*
	 *	We passed "-i" on the command line.  Use that address
	 *	family for the proxy socket.
	 */
	if (main_config.myip.af != AF_UNSPEC) {
		create_default_proxy_listener(main_config.myip.af);
		return;
	}

	defined_proxy = has_v4 = has_v6 = false;

	/*
	 *	Figure out if we need to open a proxy socket, and if
	 *	so, which one.
	 */
	for (this = head; this != NULL; this = this->next) {
		listen_socket_t *sock;

		switch (this->type) {
		case RAD_LISTEN_PROXY:
			defined_proxy = true;
			break;

		case RAD_LISTEN_AUTH:
#ifdef WITH_ACCT
		case RAD_LISTEN_ACCT:
#endif
#ifdef WITH_COA
		case RAD_LISTEN_COA:
#endif
			sock = this->data;
			if (sock->my_ipaddr.af == AF_INET) has_v4 = true;
			if (sock->my_ipaddr.af == AF_INET6) has_v6 = true;
			break;
			
		default:
			break;
		}
	}

	/*
	 *	Assume they know what they're doing.
	 */
	if (defined_proxy) return;

	if (has_v4) create_default_proxy_listener(AF_INET);

	if (has_v6) create_default_proxy_listener(AF_INET6);
}
#endif

int radius_event_start(CONF_SECTION *cs, bool have_children)
{
	rad_listen_t *head = NULL;

	if (fr_start_time != (time_t)-1) return 0;

	time(&fr_start_time);

	if (!check_config) {
		/*
		 *  radius_event_init() must be called first
		 */
		rad_assert(el);

		pl = rbtree_create(NULL, packet_entry_cmp, NULL, 0);
		if (!pl) return 0;	/* leak el */
	}

	request_num_counter = 0;

#ifdef WITH_PROXY
	if (main_config.proxy_requests && !check_config) {
		/*
		 *	Create the tree for managing proxied requests and
		 *	responses.
		 */
		proxy_list = fr_packet_list_create(1);
		if (!proxy_list) return 0;

#ifdef HAVE_PTHREAD_H
		if (pthread_mutex_init(&proxy_mutex, NULL) != 0) {
			ERROR("FATAL: Failed to initialize proxy mutex: %s",
			       fr_syserror(errno));
			fr_exit(1);
		}
#endif

		/*
		 *	The "init_delay" is set to "response_window".
		 *	Reset it to half of "response_window" in order
		 *	to give the event loop enough time to service
		 *	the event before hitting "response_window".
		 */
		main_config.init_delay.tv_usec += (main_config.init_delay.tv_sec & 0x01) * USEC;
		main_config.init_delay.tv_usec >>= 1;
		main_config.init_delay.tv_sec >>= 1;

		proxy_ctx = talloc_init("proxy");
	}
#endif

	/*
	 *	Move all of the thread calls to this file?
	 *
	 *	It may be best for the mutexes to be in this file...
	 */
	spawn_flag = have_children;

#ifdef HAVE_PTHREAD_H
	NO_SUCH_CHILD_PID = pthread_self(); /* not a child thread */

	/*
	 *	Initialize the threads ONLY if we're spawning, AND
	 *	we're running normally.
	 */
	if (have_children && !check_config &&
	    (thread_pool_init(cs, &spawn_flag) < 0)) {
		fr_exit(1);
	}
#endif

	if (check_config) {
		DEBUG("%s: #### Skipping IP addresses and Ports ####",
		       main_config.name);
		if (listen_init(cs, &head, spawn_flag) < 0) {
			fflush(NULL);
			fr_exit(1);
		}
		return 1;
	}

#ifdef HAVE_PTHREAD_H
	/*
	 *	Child threads need a pipe to signal us, as do the
	 *	signal handlers.
	 */
	if (pipe(self_pipe) < 0) {
		ERROR("Error opening internal pipe: %s", fr_syserror(errno));
		fr_exit(1);
	}
	if ((fcntl(self_pipe[0], F_SETFL, O_NONBLOCK) < 0) ||
	    (fcntl(self_pipe[0], F_SETFD, FD_CLOEXEC) < 0)) {
		ERROR("Error setting internal flags: %s", fr_syserror(errno));
		fr_exit(1);
	}
	if ((fcntl(self_pipe[1], F_SETFL, O_NONBLOCK) < 0) ||
	    (fcntl(self_pipe[1], F_SETFD, FD_CLOEXEC) < 0)) {
		ERROR("Error setting internal flags: %s", fr_syserror(errno));
		fr_exit(1);
	}
	DEBUG4("Created signal pipe.  Read end FD %i, write end FD %i", self_pipe[0], self_pipe[1]);

	if (!fr_event_fd_insert(el, 0, self_pipe[0], event_signal_handler, el)) {
		ERROR("Failed creating signal pipe handler: %s", fr_strerror());
		fr_exit(1);
	}
#endif

	DEBUG("%s: #### Opening IP addresses and Ports ####", main_config.name);

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
		fr_exit_now(1);
	}

	main_config.listen = head;

#ifdef WITH_PROXY
	check_proxy(head);
#endif

	/*
	 *	At this point, no one has any business *ever* going
	 *	back to root uid.
	 */
	rad_suid_down_permanent();

	return 1;
}


#ifdef WITH_PROXY
static int proxy_delete_cb(UNUSED void *ctx, void *data)
{
	REQUEST *request = fr_packet2myptr(REQUEST, proxy, data);

	VERIFY_REQUEST(request);

	request->master_state = REQUEST_STOP_PROCESSING;

#ifdef HAVE_PTHREAD_H
	if (pthread_equal(request->child_pid, NO_SUCH_CHILD_PID) == 0) return 0;
#endif

	/*
	 *	If it's queued we can't delete it from the queue.
	 *
	 *	Otherwise, it's OK to delete it.  Even RUNNING, because
	 *	that will get caught by the check above.
	 */
	if (request->child_state == REQUEST_QUEUED) return 0;

	request->in_proxy_hash = false;

	if (!request->in_request_hash) {
		request_done(request, FR_ACTION_DONE);
	}

	/*
	 *	Delete it from the list.
	 */
	return 2;
}
#endif


static int request_delete_cb(UNUSED void *ctx, void *data)
{
	REQUEST *request = fr_packet2myptr(REQUEST, packet, data);

	VERIFY_REQUEST(request);

	request->master_state = REQUEST_STOP_PROCESSING;

	/*
	 *	Not done, or the child thread is still processing it.
	 */
	if (request->child_state < REQUEST_RESPONSE_DELAY) return 0; /* continue */

#ifdef HAVE_PTHREAD_H
	if (pthread_equal(request->child_pid, NO_SUCH_CHILD_PID) == 0) return 0;
#endif

#ifdef WITH_PROXY
	rad_assert(request->in_proxy_hash == false);
#endif

	request->in_request_hash = false;
	ASSERT_MASTER;
	if (request->ev) fr_event_delete(el, &request->ev);

	if (main_config.memory_report) {
		RDEBUG2("Cleaning up request packet ID %u with timestamp +%d",
			request->packet->id,
			(unsigned int) (request->timestamp - fr_start_time));
	}

#ifdef WITH_COA
	if (request->coa) {
		rad_assert(!request->coa->in_proxy_hash);
	}
#endif

	request_free(request);

	/*
	 *	Delete it from the list, and continue;
	 */
	return 2;
}


void radius_event_free(void)
{
	ASSERT_MASTER;

#ifdef WITH_PROXY
	/*
	 *	There are requests in the proxy hash that aren't
	 *	referenced from anywhere else.  Remove them first.
	 */
	if (proxy_list) {
		fr_packet_list_walk(proxy_list, NULL, proxy_delete_cb);
	}
#endif

	rbtree_walk(pl, RBTREE_DELETE_ORDER,  request_delete_cb, NULL);

	if (spawn_flag) {
		/*
		 *	Now that all requests have been marked "please stop",
		 *	ensure that all of the threads have exited.
		 */
#ifdef HAVE_PTHREAD_H
		thread_pool_stop();
#endif

		/*
		 *	Walk the lists again, ensuring that all
		 *	requests are done.
		 */
		if (main_config.memory_report) {
			int num;

#ifdef WITH_PROXY
			if (proxy_list) {
				fr_packet_list_walk(proxy_list, NULL, proxy_delete_cb);
				num = fr_packet_list_num_elements(proxy_list);
				if (num > 0) {
					ERROR("Proxy list has %d requests still in it.", num);
				}
			}
#endif

			rbtree_walk(pl, RBTREE_DELETE_ORDER, request_delete_cb, NULL);
			num = rbtree_num_elements(pl);
			if (num > 0) {
				ERROR("Request list has %d requests still in it.", num);
			}
		}
	}

	rbtree_free(pl);
	pl = NULL;

#ifdef WITH_PROXY
	fr_packet_list_free(proxy_list);
	proxy_list = NULL;

	if (proxy_ctx) talloc_free(proxy_ctx);
#endif

	TALLOC_FREE(el);

	if (debug_condition) talloc_free(debug_condition);
}

int radius_event_process(void)
{
	if (!el) return 0;

	return fr_event_loop(el);
}
