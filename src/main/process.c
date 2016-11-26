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

#ifdef HAVE_STDATOMIC_H
#  include <stdatomic.h>
#else
#  include <freeradius-devel/stdatomic.h>
#endif

#include <signal.h>
#include <fcntl.h>

#ifdef HAVE_SYS_WAIT_H
#	include <sys/wait.h>
#endif

#ifdef HAVE_SYSTEMD_WATCHDOG
#  include <systemd/sd-daemon.h>
#endif

extern pid_t radius_pid;
extern fr_cond_t *debug_condition;

#ifdef HAVE_SYSTEMD_WATCHDOG
extern uint64_t sd_watchdog_interval;
#endif

static bool spawn_workers = false;
static bool just_started = true;
time_t fr_start_time = (time_t)-1;
static rbtree_t *pl = NULL;
static fr_event_list_t *el = NULL;

static void mark_home_server_alive(REQUEST *request, home_server_t *home);

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

void request_trace_state_machine(REQUEST *request)
{
	struct timeval debug_tv;
	gettimeofday(&debug_tv, NULL);
	debug_tv.tv_sec -= fr_start_time;
	printf("(%" PRIu64 ") %d.%06d ********\tSTATE %s action %s live M-%s C-%s\t********\n",
	       request->number, (int) debug_tv.tv_sec, (int) debug_tv.tv_usec,
	       __FUNCTION__, action_codes[action], master_state_names[request->master_state],
	       child_state_names[request->child_state]);
}
#endif


#define rad_panic(_x, ...) radlog_fatal("%s[%u]: " _x, __FILE__, __LINE__, ## __VA_ARGS__)

/** Declare a state in the state machine
 *
 * Expands to the start of a function definition for a given state.
 *
 * @param _x the name of the state.
 */
#define STATE_MACHINE_DECL(_x) static void _x(REQUEST *request, fr_state_action_t action)

static void request_timer(struct timeval *now, void *ctx);

/** Insert #REQUEST back into the event heap, to continue executing at a future time
 *
 * @param file the state machine timer call occurred in.
 * @param line the state machine timer call occurred on.
 * @param request to set add the timer event for.
 * @param when the event should fine.
 */
static inline void state_machine_timer(char const *file, int line, REQUEST *request,
				       struct timeval *when)
{
	if (fr_event_timer_insert(el, request_timer, request, when, &request->ev) < 0) {
		radlog_fatal("%s[%u]: Failed to insert event: %s", file, line, fr_strerror());
	}
}

/** @copybrief state_machine_timer
 *
 * @param _x the action to perform when we resume processing the request.
 */
#define STATE_MACHINE_TIMER state_machine_timer(__FILE__, __LINE__, request, &when)

/*
 *	We need a different VERIFY_REQUEST macro in process.c
 *	To avoid the race conditions with the master thread
 *	checking the REQUEST whilst it's being worked on by
 *	the child.
 */
#if defined(WITH_VERIFY_PTR)
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

#ifdef WITH_PROXY
static pthread_mutex_t proxy_mutex;
static bool proxy_no_new_sockets = false;
#endif

#define pthread_mutex_lock if (spawn_workers) pthread_mutex_lock
#define pthread_mutex_unlock if (spawn_workers) pthread_mutex_unlock

static pthread_t NO_SUCH_CHILD_PID;
#define NO_CHILD_THREAD request->child_pid = NO_SUCH_CHILD_PID

static bool we_are_master(void)
{
	if (spawn_workers &&
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
#if (defined(WITH_PROXY) || defined(WITH_TCP))
static rad_listen_t *new_listeners = NULL;

static pthread_mutex_t	fd_mutex;
#  define FD_MUTEX_LOCK if (spawn_workers) pthread_mutex_lock
#  define FD_MUTEX_UNLOCK if (spawn_workers) pthread_mutex_unlock

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

/** Session sequence number
 *
 * Unique for the lifetime of the process (or at least until it wraps).
 */
static atomic_uint_fast64_t request_number_counter = ATOMIC_VAR_INIT(1);

#ifdef WITH_PROXY
static int request_will_proxy(REQUEST *request) CC_HINT(nonnull);
static int request_proxy_send(REQUEST *request) CC_HINT(nonnull);
STATE_MACHINE_DECL(request_ping) CC_HINT(nonnull);

STATE_MACHINE_DECL(request_response_delay) CC_HINT(nonnull);
STATE_MACHINE_DECL(request_cleanup_delay) CC_HINT(nonnull);
STATE_MACHINE_DECL(request_queued) CC_HINT(nonnull);
STATE_MACHINE_DECL(request_running) CC_HINT(nonnull);
STATE_MACHINE_DECL(request_done) CC_HINT(nonnull);

STATE_MACHINE_DECL(proxy_queued) CC_HINT(nonnull);
STATE_MACHINE_DECL(proxy_no_reply) CC_HINT(nonnull);
STATE_MACHINE_DECL(proxy_running) CC_HINT(nonnull);
STATE_MACHINE_DECL(proxy_wait_for_reply) CC_HINT(nonnull);
STATE_MACHINE_DECL(proxy_wait_for_id) CC_HINT(nonnull);

static int process_proxy_reply(REQUEST *request, RADIUS_PACKET *reply) CC_HINT(nonnull (1));
static void remove_from_proxy_hash(REQUEST *request) CC_HINT(nonnull);
static void remove_from_proxy_hash_nl(REQUEST *request, bool yank) CC_HINT(nonnull);
static int insert_into_proxy_hash(REQUEST *request) CC_HINT(nonnull);
#endif

static int request_pre_handler(REQUEST *request, UNUSED fr_state_action_t action) CC_HINT(nonnull);

#ifdef WITH_COA
static void request_coa_originate(REQUEST *request) CC_HINT(nonnull);
STATE_MACHINE_DECL(coa_wait_for_reply) CC_HINT(nonnull);
STATE_MACHINE_DECL(coa_queued) CC_HINT(nonnull);
STATE_MACHINE_DECL(coa_no_reply) CC_HINT(nonnull);
STATE_MACHINE_DECL(coa_running) CC_HINT(nonnull);
static void coa_separate(REQUEST *request) CC_HINT(nonnull);
#  define COA_SEPARATE if (request->coa) coa_separate(request->coa);
#else
#  define COA_SEPARATE
#endif

#define CHECK_FOR_STOP do { if (request->master_state == REQUEST_STOP_PROCESSING) {action = FR_ACTION_DONE;}} while (0)
#define CHECK_FOR_PROXY_CANCELLED do { if (!request->proxy->listener) {action = FR_ACTION_DONE;}} while (0)


#undef USEC
#define USEC (1000000)

#define INSERT_EVENT(_function, _ctx) \
	if (fr_event_timer_insert(el, _function, _ctx, &((_ctx)->when), &((_ctx)->ev)) < 0) { \
		radlog_fatal("%s[%u]: %s", __FILE__, __LINE__, fr_strerror()); \
	}

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

/***********************************************************************
 *
 *	Start of RADIUS server state machine.
 *
 ***********************************************************************/

static struct timeval *request_response_window(REQUEST *request)
{
	VERIFY_REQUEST(request);
	rad_assert(request->proxy != NULL);
	rad_assert(request->proxy->home_server != NULL);

	if (request->client) {
		/*
		 *	The client hasn't set the response window.  Return
		 *	either the home server one, if set, or the global one.
		 */
		if (!fr_timeval_isset(&request->client->response_window)) {
			return &request->proxy->home_server->response_window;
		}

		if (fr_timeval_cmp(&request->client->response_window,
			     	   &request->proxy->home_server->response_window) < 0) {
			return &request->client->response_window;
		}
	}

	return &request->proxy->home_server->response_window;
}

/*
 * Determine initial request processing delay.
 */
static int request_init_delay(REQUEST *request)
{
	int delay;

	VERIFY_REQUEST(request);

	/* Allow client response window to lower initial delay */
	if (fr_timeval_isset(&request->client->response_window) &&
	    fr_timeval_cmp(&main_config.init_delay, &request->client->response_window) > 0) {
		delay = request->client->response_window.tv_sec * USEC;
		delay += request->client->response_window.tv_usec;

		delay >>= 1;

		return delay;
	}

	return (int)request->root->init_delay.tv_sec * USEC +
		(int)request->root->init_delay.tv_usec;
}

/*
 *	Callback for ALL timer events related to the request.
 */
static void request_timer(UNUSED struct timeval *now, void *ctx)
{
	REQUEST *request = talloc_get_type_abort(ctx, REQUEST);
#ifdef DEBUG_STATE_MACHINE
	fr_state_action_t action = FR_ACTION_TIMER;
#endif

	TRACE_STATE_MACHINE;

	request->process(request, FR_ACTION_TIMER);
}

/*
 *	Wrapper for talloc pools.  If there's no parent, just free the
 *	request.  If there is a parent, free the parent INSTEAD of the
 *	request.
 */
void request_free(REQUEST *request)
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
	char buffer[INET6_ADDRSTRLEN];

	RDEBUG2("Reply from home server %s port %d  - ID: %d arrived too late.  "
		"Try increasing 'retry_delay' or 'max_request_time'",
		inet_ntop(request->proxy->packet->dst_ipaddr.af,
			  &request->proxy->packet->dst_ipaddr.ipaddr,
			  buffer, sizeof(buffer)),
		request->proxy->packet->dst_port, request->proxy->packet->id);
}
#endif


static void request_dup_extract(REQUEST *request)
{
	if (!request->in_request_hash) return;

	if (!rbtree_deletebydata(pl, &request->packet)) {
		rad_assert(0 == 1);
	}
	request->in_request_hash = false;
}


/*
 *	If the child is still running, wait for it to be finished.
 */
bool request_thread_active(REQUEST *request)
{
	struct timeval when, now;

	if (!spawn_workers) return false;

	if (!we_are_master()) return true;

	if (request->child_state > REQUEST_RUNNING) return false;

	gettimeofday(&now, NULL);
	when = now;
	if (request->delay < (USEC / 3)) request->delay = USEC / 3;
	tv_add(&when, request->delay);
	request->delay += request->delay >> 1;
	if (request->delay > (10 * USEC)) request->delay = 10 * USEC;

	STATE_MACHINE_TIMER;
	return true;
}


void request_thread_done(REQUEST *request)
{
	request->child_state = REQUEST_DONE;
	NO_CHILD_THREAD;
}

/*
 *	Delete a request.
 */
void request_delete(REQUEST *request)
{
	rad_assert(request->child_pid == NO_SUCH_CHILD_PID);
	rad_assert(!request->in_request_hash);
	rad_assert(request->heap_id == -1);
#ifdef WITH_PROXY
	rad_assert(!request->in_proxy_hash);
#endif

	if (request->el) {
		fr_event_timer_delete(request->el, &request->ev);
	} else {
		fr_event_timer_delete(el, &request->ev);
	}

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
			(unsigned int) (request->packet->timestamp.tv_sec - fr_start_time));
	} /* else don't print anything */

	request_free(request);
}


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
static void request_done(REQUEST *request, fr_state_action_t action)
{
	VERIFY_REQUEST(request);

	TRACE_STATE_MACHINE;

	/*
	 *	Force this no matter what.
	 */
	request->master_state = REQUEST_STOP_PROCESSING;
	request->process = request_done;
	request->component = NULL;
	request->module = NULL;


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

	/*
	 *	If called from a child thread, mark ourselves as done,
	 *	and wait for the master thread timer to clean us up.
	 */
	if (!we_are_master()) {
		FINAL_STATE(REQUEST_DONE);
		return;
	}

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

	switch (action) {
	case FR_ACTION_DUP:
#ifdef WITH_DETAIL
		if (!rad_cond_assert(request->listener != NULL)) return;
#endif
		if (request->reply->code != 0) {
			request->listener->send(request->listener, request);
		} else {
			RDEBUG("No reply.  Ignoring retransmit");
		}
		/* @fixme: increment cleanup_delay */
		break;

		/*
		 *	Mark the request as done.
		 */
	case FR_ACTION_DONE:
		/*
		 *	If the child is still running, leave it alone.
		 */
		if (spawn_workers && (request->child_state <= REQUEST_RUNNING)) {
			break;
		}

#ifdef DEBUG_STATE_MACHINE
		if (rad_debug_lvl) printf("(%" PRIu64 ") ********\tSTATE %s C-%s -> C-%s\t********\n",
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
	request_dup_extract(request);

	/*
	 *	If there's no children, we can mark the request as done.
	 */
	if (!spawn_workers) request->child_state = REQUEST_DONE;

	if (request_thread_active(request)) return;

	request_delete(request);
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
	 *	Only Access-Requests get cleanup_delay.  Everything
	 *	else gets cleaned up immediately.
	 */
	if (request->packet->code != PW_CODE_ACCESS_REQUEST) goto done;

	if (!request->root->cleanup_delay) goto done;

	gettimeofday(&now, NULL);

	rad_assert(request->reply->timestamp.tv_sec != 0);
	when = request->reply->timestamp;

	request->delay = request->root->cleanup_delay;
	when.tv_sec += request->delay;

	/*
	 *	Set timer for when we need to clean it up.
	 */
	if (fr_timeval_cmp(&when, &now) > 0) {
#ifdef DEBUG_STATE_MACHINE
		if (rad_debug_lvl) printf("(%" PRIu64 ") ********\tNEXT-STATE %s -> %s\n", request->number, __FUNCTION__, "request_cleanup_delay");
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
		rad_assert(request->child_pid == NO_SUCH_CHILD_PID);
		STATE_MACHINE_TIMER;
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
bool request_max_time(REQUEST *request)
{
	struct timeval now, when;
	rad_assert(request->magic == REQUEST_MAGIC);
#ifdef DEBUG_STATE_MACHINE
	fr_state_action_t action = FR_ACTION_TIMER;
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
		request->master_state = REQUEST_STOP_PROCESSING;
		request->process(request, FR_ACTION_DONE);
		return true;
	}

	/*
	 *	The request is still running.  Enforce max_request_time.
	 */
	fr_event_list_time(&now, el);
	when = request->packet->timestamp;
	when.tv_sec += request->root->max_request_time;

	/*
	 *	Taking too long: tell it to die.
	 */
	if (fr_timeval_cmp(&now, &when) >= 0) {
		/*
		 *	If there's a child thread processing it,
		 *	complain.
		 */
		if (spawn_workers &&
		    (pthread_equal(request->child_pid, NO_SUCH_CHILD_PID) == 0)) {
			ERROR("Unresponsive child for request %" PRIu64 ", in component %s module %s",
			      request->number,
			      request->component ? request->component : "<core>",
			      request->module ? request->module : "<core>");
			trigger_exec(request, NULL, "server.thread.unresponsive", true, NULL);
		}

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
	STATE_MACHINE_TIMER;
	return false;
}

void request_thread(REQUEST *request, fr_request_process_t process)
{
#ifdef DEBUG_STATE_MACHINE
	fr_state_action_t action = FR_ACTION_TIMER;
#endif
	struct timeval when;

	VERIFY_REQUEST(request);

	TRACE_STATE_MACHINE;
	ASSERT_MASTER;

	request->process = process;

	/*
	 *	(re) set the initial delay.
	 */
	request->delay = request_init_delay(request);
	gettimeofday(&when, NULL);
	tv_add(&when, request->delay);
	request->delay += request->delay >> 1;

	STATE_MACHINE_TIMER;

	request_enqueue(request);
}


static void request_dup_msg(REQUEST *request)
{
	ERROR("(%" PRIu64 ") Ignoring duplicate packet from "
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
static void request_cleanup_delay(REQUEST *request, fr_state_action_t action)
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

		STATE_MACHINE_TIMER;
		break;

#ifdef WITH_PROXY
	case FR_ACTION_PROXY_REPLY:
		proxy_reply_too_late(request);
		break;
#endif

	case FR_ACTION_TIMER:
		fr_event_list_time(&now, el);

		rad_assert(request->root->cleanup_delay > 0);

		when = request->reply->timestamp;
		when.tv_sec += request->root->cleanup_delay;

		if (fr_timeval_cmp(&when, &now) > 0) {
#ifdef DEBUG_STATE_MACHINE
			if (rad_debug_lvl) printf("(%" PRIu64 ") ********\tNEXT-STATE %s -> %s\n", request->number, __FUNCTION__, "request_cleanup_delay");
#endif
			STATE_MACHINE_TIMER;
			return;
		} /* else it's time to clean up */
		/* FALL-THROUGH */

	case FR_ACTION_DONE:
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
static void request_response_delay(REQUEST *request, fr_state_action_t action)
{
	struct timeval when, now;

	VERIFY_REQUEST(request);

	TRACE_STATE_MACHINE;
	ASSERT_MASTER;
	COA_SEPARATE;
	CHECK_FOR_STOP;

	switch (action) {
	case FR_ACTION_DUP:
		ERROR("(%" PRIu64 ") Discarding duplicate request from "
		      "client %s port %d - ID: %u due to delayed response",
		      request->number, request->client->shortname,
		      request->packet->src_port, request->packet->id);
		break;

#ifdef WITH_PROXY
	case FR_ACTION_PROXY_REPLY:
		proxy_reply_too_late(request);
		break;
#endif

	case FR_ACTION_TIMER:
		fr_event_list_time(&now, el);

		/*
		 *	See if it's time to send the reply.  If not,
		 *	we wait some more.
		 */
		when = request->reply->timestamp;

		tv_add(&when, request->response_delay.tv_sec * USEC);
		tv_add(&when, request->response_delay.tv_usec);

		if (fr_timeval_cmp(&when, &now) > 0) {
#ifdef DEBUG_STATE_MACHINE
			if (rad_debug_lvl) printf("(%" PRIu64 ") ********\tNEXT-STATE %s -> %s\n",
						  request->number, __FUNCTION__, "request_response_delay");
#endif
			STATE_MACHINE_TIMER;
			return;
		} /* else it's time to send the reject */

		RDEBUG2("Sending delayed response");
		request->listener->debug(request, request->reply, false);
		request->listener->send(request->listener, request);

		/*
		 *	Clean up the request.
		 */
		request_cleanup_delay_init(request);
		break;

	case FR_ACTION_DONE:
		request_done(request, FR_ACTION_DONE);
		break;

	default:
		RDEBUG3("%s: Ignoring action %s", __FUNCTION__, action_codes[action]);
		break;
	}
}


extern fr_log_t debug_log;

static int request_pre_handler(REQUEST *request, UNUSED fr_state_action_t action)
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
		request->username = fr_pair_find_by_num(request->packet->vps, 0, PW_USER_NAME, TAG_ANY);
		request->password = fr_pair_find_by_num(request->packet->vps, 0, PW_USER_PASSWORD, TAG_ANY);
		return 1;
	}

	if (!request->packet->vps) { /* FIXME: check for correct state */
		rcode = request->listener->decode(request->listener, request);

#ifdef WITH_UNLANG
		/*
		 *	If a specific destination has been set for
		 *	requests, overwrite the pointer to the default
		 *	log so output goes there instead.
		 *
		 *	...but only if there is no debug condition
		 *	or there is a condition and it matches.
		 *
		 *	All other requests will go to the default log
		 *	destination with the default verbosity level.
		 */
		if ((debug_log.dst != L_DST_NULL) &&
		    (!debug_condition || (cond_eval(request, RLM_MODULE_OK, 0, debug_condition) == 1))) {
			request->log.lvl = req_debug_lvl;
			request->log.func = vradlog_request;
			request->log.output = &debug_log;
		}
#endif

		request->listener->debug(request, request->packet, true);
	} else {
		rcode = 0;
	}

	if (rcode < 0) {
		RATE_LIMIT(INFO("Dropping packet without response because of error: %s", fr_strerror()));
		request->reply->offset = -2; /* bad authenticator */
		return 0;
	}

	if (!request->username) {
		request->username = fr_pair_find_by_num(request->packet->vps, 0, PW_USER_NAME, TAG_ANY);
	}

	return 1;
}


/**  Do the final processing of a request before we reply to the NAS.
 *
 *  Various cleanups, suppress responses, copy Proxy-State, and set
 *  response_delay or cleanup_delay;
 */
static void request_finish(REQUEST *request, fr_state_action_t action)
{
	VALUE_PAIR *vp;

	VERIFY_REQUEST(request);

	TRACE_STATE_MACHINE;

	if (request->master_state == REQUEST_STOP_PROCESSING) {
		request->process(request, FR_ACTION_DONE);
		return;
	}

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
	vp = fr_pair_find_by_num(request->control, 0, PW_RESPONSE_PACKET_TYPE, TAG_ANY);
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
			vp = fr_pair_find_by_num(request->control, 0, PW_AUTH_TYPE, TAG_ANY);
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
	vp = fr_pair_list_copy_by_num(request->reply, request->packet->vps, 0, PW_PROXY_STATE, TAG_ANY);
	if (vp) fr_pair_add(&request->reply->vps, vp);

	switch (request->reply->code) {
	case PW_CODE_ACCESS_ACCEPT:
		rad_postauth(request);
		break;
	case PW_CODE_ACCESS_CHALLENGE:
		fr_pair_delete_by_num(&request->control, 0, PW_POST_AUTH_TYPE, TAG_ANY);
		vp = pair_make_config("Post-Auth-Type", "Challenge", T_OP_SET);
		if (vp) rad_postauth(request);
		break;
	default:
		break;
	}

	/*
	 *	Run rejected packets through
	 *
	 *	Post-Auth-Type = Reject
	 *
	 *	We do this separately so ACK and challenge can change the code
	 *	to reject if a module returns reject.
	 */
	if (request->reply->code == PW_CODE_ACCESS_REJECT) {
		fr_pair_delete_by_num(&request->control, 0, PW_POST_AUTH_TYPE, TAG_ANY);
		vp = pair_make_config("Post-Auth-Type", "Reject", T_OP_SET);
		if (vp) rad_postauth(request);
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
			request->listener->debug(request, request->reply, false);
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

		vp = fr_pair_find_by_num(request->reply->vps, 0, PW_FREERADIUS_RESPONSE_DELAY, TAG_ANY);
		if (vp) {
			if (vp->vp_integer <= 10) {
				request->response_delay.tv_sec = vp->vp_integer;
			} else {
				request->response_delay.tv_sec = 10;
			}
			request->response_delay.tv_usec = 0;
		} else {
			vp = fr_pair_find_by_num(request->reply->vps, 0, PW_FREERADIUS_RESPONSE_DELAY_USEC, TAG_ANY);
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
		if (request->proxy && !request->proxy->reply) {
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
			request->listener->debug(request, request->reply, false);
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
static void request_running(REQUEST *request, fr_state_action_t action)
{
	int ret;

	VERIFY_REQUEST(request);

	TRACE_STATE_MACHINE;
	CHECK_FOR_STOP;

	switch (action) {
	case FR_ACTION_TIMER:
		COA_SEPARATE;
		(void) request_max_time(request);
		break;

	case FR_ACTION_DUP:
		request_dup_msg(request);
		break;

	case FR_ACTION_RUN:
		if (!request_pre_handler(request, action)) {
#ifdef DEBUG_STATE_MACHINE
			if (rad_debug_lvl) printf("(%" PRIu64 ") ********\tSTATE %s failed in pre-handler C-%s -> "
						  "C-%s\t********\n",
						  request->number, __FUNCTION__,
						  child_state_names[request->child_state],
						  child_state_names[REQUEST_DONE]);
#endif
			FINAL_STATE(REQUEST_DONE);
			break;
		}

		rad_assert(request->handle != NULL);
		ret = request->handle(request);
		if (ret < 0) REDEBUG2("State callback returned error (%i): %s", ret, fr_strerror());

#ifdef WITH_PROXY
		/*
		 *	We may need to send a proxied request.
		 */
		if ((action == FR_ACTION_RUN) &&
		    request_will_proxy(request)) {
#ifdef DEBUG_STATE_MACHINE
			if (rad_debug_lvl) printf("(%" PRIu64 ") ********\tWill Proxy\t********\n", request->number);
#endif
			/*
			 *	If this fails, it
			 *	takes care of setting
			 *	up the post proxy fail
			 *	handler.
			 */
			if (request_proxy_send(request) < 0) goto req_finished;
		} else
#endif
		{
#ifdef DEBUG_STATE_MACHINE
			if (rad_debug_lvl) printf("(%" PRIu64 ") ********\tFinished\t********\n", request->number);
#endif

#ifdef WITH_PROXY
		req_finished:
#endif
			request_finish(request, action);
		}
		break;

	case FR_ACTION_DONE:
		request_done(request, FR_ACTION_DONE);
		break;

	default:
		RDEBUG3("%s: Ignoring action %s", __FUNCTION__, action_codes[action]);
		break;
	}
}

/** Process events while the request is queued.
 *
 *  We give different messages on DUP, and on DONE,
 *  remove the request from the queue
 *
 *  \dot
 *	digraph queued {
 *		queued -> queued [ label = "TIMER < max_request_time" ];
 *		queued -> done [ label = "TIMER >= max_request_time" ];
 *		queued -> running [ label = "RUNNING" ];
 *		queued -> dup [ label = "DUP", arrowhead = "none" ];
 *	}
 *  \enddot
 */
static void request_queued(REQUEST *request, fr_state_action_t action)
{
	VERIFY_REQUEST(request);

	TRACE_STATE_MACHINE;
	CHECK_FOR_STOP;

	switch (action) {
	case FR_ACTION_TIMER:
		(void) request_max_time(request);
		break;

	case FR_ACTION_DUP:
		ERROR("(%" PRIu64 ") Ignoring duplicate packet from "
		      "client %s port %d - ID: %u as request is still queued.",
		      request->number, request->client->shortname,
		      request->packet->src_port,request->packet->id);
		break;

	case FR_ACTION_RUN:
		request->process = request_running;
		request->process(request, action);
		break;

	case FR_ACTION_DONE:
		request_queue_extract(request);
		request_dup_extract(request);
		request_delete(request);
		break;

	default:
		RDEBUG3("%s: Ignoring action %s", __FUNCTION__, action_codes[action]);
		break;
	}
}

/*
 *	See if a new packet is a duplicate of an old one.
 */
bool request_dup_received(rad_listen_t *listener, rbtree_t *dup_tree, RADCLIENT *client, RADIUS_PACKET *packet)
{
	RADIUS_PACKET **packet_p;
	rad_child_state_t child_state;
	REQUEST *request;

	packet_p = rbtree_finddata(dup_tree, &packet);
	if (!packet_p) return false;

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
		request->packet->count++;
		request->process(request, FR_ACTION_DUP);
		return true;
	}

	/*
	 *	Mark the old request as done ASAP, and before we log
	 *	anything.  The child may stop processing the request
	 *	just as we're logging the complaint.
	 *
	 *	If there's no child thread, the request will be marked
	 *	done immediately.  If there is a child thread, it will
	 *	be notified, and a timer will be set to clean up the
	 *	request.
	 */
	request->process(request, FR_ACTION_DONE);
	request = NULL;

	/*
	 *	It's a new request, not a duplicate.  If the old one
	 *	is done, then we can clean it up.
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

	return false;
}


bool request_limit(rad_listen_t *listener, RADCLIENT *client, RADIUS_PACKET *packet)
{
	uint32_t	count;
	listen_socket_t	*sock = NULL;

	if (main_config.drop_requests) return true;

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

		trigger_exec(NULL, NULL, "server.max_requests", true, NULL);
		return true;
	}

#ifdef WITH_ACCOUNTING
	if (listener->type != RAD_LISTEN_DETAIL)
#endif
	{
		sock = listener->data;
	}

	/*
	 *	Rate-limit the incoming packets
	 */
	if (sock && sock->max_rate) {
		uint32_t pps;

		pps = rad_pps(&sock->rate_pps_old, &sock->rate_pps_now, &sock->rate_time, &packet->timestamp);
		if (pps > sock->max_rate) {
			DEBUG("Dropping request due to rate limiting");
			return true;
		}
		sock->rate_pps_now++;
	}

	return false;
}


int request_receive(TALLOC_CTX *ctx, rad_listen_t *listener, RADIUS_PACKET *packet,
		    RADCLIENT *client, RAD_REQUEST_FUNP fun)
{
	REQUEST *request = NULL;
	struct timeval now;
	listen_socket_t *sock = NULL;

	VERIFY_PACKET(packet);

	/*
	 *	Set the last packet received.
	 */
	now = packet->timestamp;
	rad_assert(packet->timestamp.tv_sec != 0);

	listener->old_style = true; /* hack for now */

#ifdef WITH_ACCOUNTING
	if (listener->type != RAD_LISTEN_DETAIL)
#endif
	{
		sock = listener->data;
		sock->last_packet = now.tv_sec;

#ifdef WITH_TCP
		packet->proto = sock->proto;
#endif
	}

	/*
	 *	Check for duplicates.
	 */
	if (!listener->nodup && request_dup_received(listener, pl, client, packet)) return 0;

	if (request_limit(listener, client, packet)) return 0;

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
	 *	Remember the request in the list.
	 */
	if (!listener->nodup) {
		if (!rbtree_insert(pl, &request->packet)) {
			RERROR("Failed to insert request in the list of live requests: discarding it");
			request_queued(request, FR_ACTION_DONE);
			return 1;
		}

		request->in_request_hash = true;
	}

	/*
	 *	Otherwise, insert it into the state machine.
	 *	The child threads will take care of processing it.
	 */
	request_thread(request, request_queued);

	return 1;
}


REQUEST *request_setup(TALLOC_CTX *ctx, rad_listen_t *listener, RADIUS_PACKET *packet,
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
	request->reply = fr_radius_alloc_reply(request, packet);
	if (!request->reply) {
		ERROR("No memory");
		talloc_free(request);
		return NULL;
	}

	/*
	 *	Mark it as a "real" request with a context.
	 */
	request->options |= RAD_REQUEST_OPTION_CTX;

	request->listener = listener;
	request->client = client;
	request->packet = talloc_steal(request, packet);
	request->number = atomic_fetch_add_explicit(&request_number_counter, 1, memory_order_relaxed);
	request->priority = listener->type;
	if (request->priority >= RAD_LISTEN_MAX) {
		request->priority = RAD_LISTEN_AUTH;
	}

	request->master_state = REQUEST_ACTIVE;
	request->child_state = REQUEST_RUNNING;
#ifdef DEBUG_STATE_MACHINE
	if (rad_debug_lvl) printf("(%" PRIu64 ") ********\tSTATE %s C-%s -> C-%s\t********\n",
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
		request->server_cs = client->server_cs;

	} else {
		request->server = listener->server;
		request->server_cs = listener->server_cs;
	}
	rad_assert(request->server_cs != NULL);

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
	request->reply->if_index = request->packet->if_index;
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
static void tcp_socket_timer(struct timeval *now, void *ctx)
{
	rad_listen_t *listener = talloc_get_type_abort(ctx, rad_listen_t);
	listen_socket_t *sock = listener->data;
	struct timeval end;
	char buffer[256];
	fr_socket_limit_t *limit;

	ASSERT_MASTER;

	if (listener->status != RAD_LISTEN_STATUS_KNOWN) return;

	fr_event_list_time(now, el);

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

		if (fr_timeval_cmp(&end, now) <= 0) {
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
				pthread_mutex_lock(&proxy_mutex);
				if (!fr_packet_list_socket_freeze(proxy_list,
								  listener->fd)) {
					ERROR("Fatal error freezing socket: %s", fr_strerror());
					fr_exit(1);
				}
				pthread_mutex_unlock(&proxy_mutex);
			}
#endif

			/*
			 *	Mark the socket as don't use, and
			 *	remove it from the incoming list of
			 *	FDs.
			 */
			listener->status = RAD_LISTEN_STATUS_FROZEN;
			fr_event_fd_delete(el, listener->fd);
			event_new_fd(listener); /* mainly set a new timer */
			return;
		}
	} else {
		end = *now;
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

		if (fr_timeval_cmp(&idle, now) <= 0) {
			listener->print(listener, buffer, sizeof(buffer));
			DEBUG("Reached idle timeout on socket %s", buffer);
			goto do_close;
		}

		/*
		 *	Enforce the minimum of idle timeout or lifetime.
		 */
		if (fr_timeval_cmp(&idle, &end) < 0) {
			end = idle;
		}
	}

	/*
	 *	Wake up at t + 0.5s.  The code above checks if the timers
	 *	are <= t.  This addition gives us a bit of leeway.
	 */
	end.tv_usec = USEC / 2;

	listener->when = end;

	INSERT_EVENT(tcp_socket_timer, listener);
}


#ifdef WITH_PROXY
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
 *	Called by socket_del to remove requests with this socket
 */
static int eol_proxy_listener(void *ctx, void *data)
{
	rad_listen_t *this = talloc_get_type_abort(ctx, rad_listen_t);
	RADIUS_PACKET **proxy_p = data;
	REQUEST *request;

	request = fr_packet2myptr(REQUEST, packet, proxy_p);

	VERIFY_REQUEST(request);
	rad_assert(request->parent != NULL);
	rad_assert(request->parent->proxy == request);
	request = request->parent;
	VERIFY_REQUEST(request);

	if (request->proxy->listener != this) return 0;

#ifdef WITH_ACCOUNTING
	/*
	 *	Accounting packets should be deleted immediately.
	 *	They will never be retransmitted by the client.
	 */
	if (request->proxy->packet->code == PW_CODE_ACCOUNTING_REQUEST) {
		RDEBUG("Stopping request due to failed connection to home server");
		request->master_state = REQUEST_STOP_PROCESSING;
	}
#endif

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

	fr_packet_list_id_free(proxy_list, request->proxy->packet, yank);
	request->in_proxy_hash = false;

	/*
	 *	On the FIRST reply, decrement the count of outstanding
	 *	requests.  Note that this is NOT the count of sent
	 *	packets, but whether or not the home server has
	 *	responded at all.
	 */
	if (request->proxy->home_server &&
	    request->proxy->home_server->currently_outstanding) {
		request->proxy->home_server->currently_outstanding--;

		/*
		 *	If we're NOT sending it packets, AND it's been
		 *	a while since we got a response, then we don't
		 *	know if it's alive or dead.
		 */
		if ((request->proxy->home_server->currently_outstanding == 0) &&
		    (request->proxy->home_server->state == HOME_STATE_ALIVE)) {
			struct timeval when, now;

			when.tv_sec = request->proxy->home_server->last_packet_recv ;
			when.tv_usec = 0;

			fr_timeval_add(&when, request_response_window(request), &when);
			gettimeofday(&now, NULL);

			/*
			 *	last_packet + response_window
			 *
			 *	We *administratively* mark the home
			 *	server as "unknown" state, because we
			 *	haven't seen a packet for a while.
			 */
			if (fr_timeval_cmp(&now, &when) > 0) {
				request->proxy->home_server->state = HOME_STATE_UNKNOWN;
				request->proxy->home_server->last_packet_sent = 0;
				request->proxy->home_server->last_packet_recv = 0;
			}
		}
	}

#ifdef WITH_TCP
	rad_assert(request->proxy->listener != NULL);
	request->proxy->listener->count--;
#endif
	request->proxy->listener = NULL;

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
	pthread_mutex_lock(&proxy_mutex);

	if (!request->in_proxy_hash) {
		pthread_mutex_unlock(&proxy_mutex);
		return;
	}

	remove_from_proxy_hash_nl(request, true);

	pthread_mutex_unlock(&proxy_mutex);
}

static int insert_into_proxy_hash(REQUEST *request)
{
	char buffer[INET6_ADDRSTRLEN];
	int tries;
	bool success = false;
	void *proxy_listener;

	VERIFY_REQUEST(request);

	rad_assert(request->proxy != NULL);
	rad_assert(request->proxy->home_server != NULL);
	rad_assert(proxy_list != NULL);


	pthread_mutex_lock(&proxy_mutex);
	proxy_listener = NULL;
	request->proxy->packet->count = 1;

	for (tries = 0; tries < 2; tries++) {
		rad_listen_t *this;
		listen_socket_t *sock;

		RDEBUG3("proxy: Trying to allocate ID (%d/2)", tries);
		success = fr_packet_list_id_alloc(proxy_list,
						request->proxy->home_server->proto,
						&request->proxy->packet, &proxy_listener);
		if (success) break;

		if (tries > 0) continue; /* try opening new socket only once */

		if (proxy_no_new_sockets) break;

		RDEBUG3("proxy: Trying to open a new listener to the home server");
		this = proxy_new_listener(proxy_ctx, request->proxy->home_server, 0);
		if (!this) {
			pthread_mutex_unlock(&proxy_mutex);
			goto fail;
		}

		request->proxy->packet->src_port = 0; /* Use any new socket */
		proxy_listener = this;

		sock = this->data;
		if (!fr_packet_list_socket_add(proxy_list, this->fd,
					       sock->proto,
					       &sock->other_ipaddr, sock->other_port,
					       this)) {

			proxy_no_new_sockets = true;

			pthread_mutex_unlock(&proxy_mutex);

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
		pthread_mutex_unlock(&proxy_mutex);
		radius_update_listener(this);
		pthread_mutex_lock(&proxy_mutex);
	}

	if (!proxy_listener || !success) {
		pthread_mutex_unlock(&proxy_mutex);
		REDEBUG2("proxy: Failed allocating Id for proxied request");
	fail:
		request->proxy->listener = NULL;
		request->in_proxy_hash = false;
		return 0;
	}

	rad_assert(request->proxy->packet->id >= 0);

	request->proxy->listener = proxy_listener;
	request->in_proxy_hash = true;
	RDEBUG3("proxy: request is now in proxy hash");

	/*
	 *	Keep track of maximum outstanding requests to a
	 *	particular home server.  'max_outstanding' is
	 *	enforced in home_server_ldb(), in realms.c.
	 */
	request->proxy->home_server->currently_outstanding++;

#ifdef WITH_TCP
	request->proxy->listener->count++;
#endif

	pthread_mutex_unlock(&proxy_mutex);

	RDEBUG3("proxy: allocating destination %s port %d - Id %d",
	       inet_ntop(request->proxy->packet->dst_ipaddr.af, &request->proxy->packet->dst_ipaddr.ipaddr, buffer, sizeof(buffer)),
	       request->proxy->packet->dst_port,
	       request->proxy->packet->id);

	return 1;
}

static int process_proxy_reply(REQUEST *request, RADIUS_PACKET *reply)
{
	int rcode;
	VALUE_PAIR *vp;

	VERIFY_REQUEST(request);

	/*
	 *	Delete any reply we had accumulated until now.
	 */
	RDEBUG2("Clearing existing &reply: attributes");
	fr_pair_list_free(&request->reply->vps);

	/*
	 *	Run the packet through the post-proxy stage,
	 *	BEFORE playing games with the attributes.
	 */
	vp = fr_pair_find_by_num(request->control, 0, PW_POST_PROXY_TYPE, TAG_ANY);

	/*
	 *	If we have a proxy_reply, and it was a reject, or a NAK
	 *	setup Post-Proxy <type>.
	 *
	 *	If the <type> doesn't have a section, then the Post-Proxy
	 *	section is ignored.
	 */
	if (!vp && reply) {
		fr_dict_enum_t *dval = NULL;
		fr_dict_attr_t const *da = fr_dict_attr_by_num(NULL, 0, PW_POST_PROXY_TYPE);

		switch (reply->code) {
		case PW_CODE_ACCESS_REJECT:
		case PW_CODE_DISCONNECT_NAK:
		case PW_CODE_COA_NAK:
			dval = fr_dict_enum_by_name(NULL, da, fr_packet_codes[reply->code]);

			if (dval) {
				vp = radius_pair_create(request, &request->control, PW_POST_PROXY_TYPE, 0);
				vp->vp_integer = dval->value;
			}
			break;

		default:
			break;
		}
	}

	if (vp) RDEBUG2("Found Post-Proxy-Type %s", fr_dict_enum_name_by_da(NULL, vp->da, vp->vp_integer));

	/*
	 *	Remove it from the proxy hash, if there's no reply, or
	 *	if we recieved all of the replies.
	 */
	if (request->in_proxy_hash &&
	    (!reply || (request->proxy->packet->count <= reply->count))) {
		remove_from_proxy_hash(request);
	}

	if (request->home_pool && request->home_pool->virtual_server) {
		char const *old_server = request->server;

		request->server = request->home_pool->virtual_server; /* @fixme 4.0 this shouldn't be necessary! */
		rad_assert(strcmp(request->proxy->server, request->server) == 0);

		RDEBUG2("server %s {", request->server);
		RINDENT();
		rcode = process_post_proxy(vp ? vp->vp_integer : 0, request);
		REXDENT();
		RDEBUG2("}");
		request->server = old_server;
	} else {
		rcode = process_post_proxy(vp ? vp->vp_integer : 0, request);
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

int request_proxy_reply(RADIUS_PACKET *reply)
{
	RADIUS_PACKET **packet_p;
	REQUEST *request, *proxy;
	struct timeval now;
	char buffer[INET6_ADDRSTRLEN];

	VERIFY_PACKET(reply);

	pthread_mutex_lock(&proxy_mutex);
	packet_p = fr_packet_list_find_byreply(proxy_list, reply);

	if (!packet_p) {
		pthread_mutex_unlock(&proxy_mutex);
		PROXY("No outstanding request was found for %s packet from host %s port %d - ID %u",
		       fr_packet_codes[reply->code],
		       inet_ntop(reply->src_ipaddr.af,
				 &reply->src_ipaddr.ipaddr,
				 buffer, sizeof(buffer)),
		       reply->src_port, reply->id);
		return 0;
	}

	/*
	 *	The proxied packet is in request->proxy->packet.
	 *	First, dereference "reply" to find "request->proxy".
	 *	Then, check request->proxy->parent, which is the one we want.
	 */
	proxy = fr_packet2myptr(REQUEST, packet, packet_p);
	VERIFY_REQUEST(proxy);

	/*
	 *	The sent packet is in a proxy REQUEST.
	 *	We want to get the parent request.
	 */
	rad_assert(proxy->parent != NULL);
	rad_assert(proxy->parent->proxy == proxy);

	request = proxy->parent;

	pthread_mutex_unlock(&proxy_mutex);

	VERIFY_REQUEST(request);

	/*
	 *	No reply, BUT the current packet fails verification:
	 *	ignore it.  This does the MD5 calculations in the
	 *	server core, but I guess we can fix that later.
	 */
	if (!proxy->reply && (fr_radius_verify(reply, proxy->packet, proxy->home_server->secret) != 0)) {
		RWDEBUG("Discarding invalid reply from host %s port %d - ID: %d: %s",
			inet_ntop(reply->src_ipaddr.af, &reply->src_ipaddr.ipaddr, buffer, sizeof(buffer)),
			reply->src_port, reply->id, fr_strerror());
		return 0;
	}

	/*
	 *	The home server sent us a packet which doesn't match
	 *	something we have: ignore it.  This is done only to
	 *	catch the case of broken systems.
	 */
	if (proxy->reply && (memcmp(proxy->reply->vector, reply->vector, sizeof(proxy->reply->vector)) != 0)) {
		RWDEBUG("Discarding conflicting reply from host %s port %d - ID: %d",
			inet_ntop(reply->src_ipaddr.af, &reply->src_ipaddr.ipaddr, buffer, sizeof(buffer)),
			reply->src_port, reply->id);
		return 0;
	}

	/*
	 *	If we have previously seen a reply, ignore the
	 *	duplicate.
	 */
	if (proxy->reply) {
		proxy->reply->count++;

		RWDEBUG("Discarding duplicate reply from host %s port %d - ID: %d",
			inet_ntop(reply->src_ipaddr.af, &reply->src_ipaddr.ipaddr, buffer, sizeof(buffer)),
			reply->src_port, reply->id);
		return 0;
	}

	gettimeofday(&now, NULL);

	/*
	 *	Status-Server packets don't count as real packets.
	 */
	if (proxy->packet->code != PW_CODE_STATUS_SERVER) {
		listen_socket_t *sock = proxy->listener->data;

		proxy->home_server->last_packet_recv = now.tv_sec;
		sock->last_packet = now.tv_sec;
	}

	/*
	 *	Call the state machine to do something useful with the
	 *	request.
	 */
	proxy->reply = talloc_steal(proxy, reply);
	proxy->reply->count++;
	request->priority = RAD_LISTEN_PROXY;

#ifdef WITH_STATS
	if (!proxy->listener) goto global_stats;

	/*
	 *	Update the proxy listener stats here, because only one
	 *	thread accesses that at a time.  The home_server and
	 *	main proxy_*_stats structures are updated once the
	 *	request is cleaned up.
	 */
	proxy->listener->stats.total_responses++;

	proxy->listener->stats.last_packet = reply->timestamp.tv_sec;

	switch (proxy->packet->code) {
	case PW_CODE_ACCESS_REQUEST:
		if (proxy->reply->code == PW_CODE_ACCESS_ACCEPT) {
			proxy->listener->stats.total_access_accepts++;

		} else if (proxy->reply->code == PW_CODE_ACCESS_REJECT) {
			proxy->listener->stats.total_access_rejects++;

		} else if (proxy->reply->code == PW_CODE_ACCESS_CHALLENGE) {
			proxy->listener->stats.total_access_challenges++;
		}
		break;

#ifdef WITH_ACCOUNTING
	case PW_CODE_ACCOUNTING_REQUEST:
		proxy->listener->stats.total_responses++;
		break;

#endif

#ifdef WITH_COA
	case PW_CODE_COA_REQUEST:
		proxy->listener->stats.total_responses++;
		break;

	case PW_CODE_DISCONNECT_REQUEST:
		proxy->listener->stats.total_responses++;
		break;

#endif
	default:
		break;
	}

global_stats:
	proxy->home_server->stats.last_packet = reply->timestamp.tv_sec;

	switch (proxy->packet->code) {
	case PW_CODE_ACCESS_REQUEST:
		proxy_auth_stats.last_packet = reply->timestamp.tv_sec;
		break;

#ifdef WITH_ACCOUNTING
	case PW_CODE_ACCOUNTING_REQUEST:
		proxy_acct_stats.last_packet = reply->timestamp.tv_sec;
		break;

#endif

#ifdef WITH_COA
	case PW_CODE_COA_REQUEST:
		proxy_coa_stats.last_packet = reply->timestamp.tv_sec;
		break;

	case PW_CODE_DISCONNECT_REQUEST:
		proxy_dsc_stats.last_packet = reply->timestamp.tv_sec;
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
	if ((proxy->home_server->state == HOME_STATE_UNKNOWN) ||
	    (proxy->home_server->state == HOME_STATE_ZOMBIE)) {
		mark_home_server_alive(request, proxy->home_server);
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
	fr_dict_enum_t const *dval = NULL;
	fr_dict_attr_t const *da = fr_dict_attr_by_num(NULL, 0, PW_POST_PROXY_TYPE);
	VALUE_PAIR *vp;
	char buffer[256];

	VERIFY_REQUEST(request);

	snprintf(buffer, sizeof(buffer), "Fail-%s", fr_packet_codes[request->proxy->packet->code]);
	dval = fr_dict_enum_by_name(NULL, da, buffer);

	if (!dval) dval = fr_dict_enum_by_name(NULL, da, "Fail");

	if (!dval) {
		fr_pair_delete_by_num(&request->control, 0, PW_POST_PROXY_TYPE, TAG_ANY);
		return 0;
	}

	vp = fr_pair_find_by_num(request->control, 0, PW_POST_PROXY_TYPE, TAG_ANY);
	if (!vp) vp = radius_pair_create(request, &request->control,
					PW_POST_PROXY_TYPE, 0);
	vp->vp_integer = dval->value;

	return 1;
}


/** Wait for the proxy ID to expire.
 *
 *  \dot
 *	digraph proxy_wait_for_id {
 *		proxy_wait_for_id;
 *
 *		proxy_wait_for_id -> dup [ label = "DUP", arrowhead = "none" ];
 *		proxy_wait_for_id -> timer [ label = "TIMER < max_request_time" ];
 *		proxy_wait_for_id -> proxy_reply_too_late [ label = "PROXY_REPLY" arrowhead = "none"];
 *		proxy_wait_for_id -> process_proxy_reply [ label = "RUN" ];
 *		proxy_wait_for_id -> done [ label = "TIMER >= timeout" ];
 *	}
 *  \enddot
 */
static void proxy_wait_for_id(REQUEST *request, fr_state_action_t action)
{
	struct timeval now, when;

	VERIFY_REQUEST(request);

	TRACE_STATE_MACHINE;
	CHECK_FOR_STOP;

	/*
	 *	We don't have an ID allocated, so we can just mark
	 *	this request as done.
	 */
	if (!request->in_proxy_hash) goto done2;

	/*
	 *	We've been called from a child thread.  Rely on the timers to call us back...
	 */
	if (!we_are_master()) return;

	switch (action) {
	case FR_ACTION_DUP:
		request_dup_msg(request);
		break;

	case FR_ACTION_TIMER:
		if (request_max_time(request)) goto done;

#ifdef WITH_TCP
		/*
		 *	TCP home servers don't retransmit.  If we have a reply,
		 *	then we can clean up the ID now.
		 */
		if ((request->proxy->home_server->proto == IPPROTO_TCP) &&
		    request->proxy->reply && request->proxy->reply->count) {
			goto done;
		}
#endif

		fr_event_list_time(&now, el);
		when = request->proxy->packet->timestamp;

#ifdef WITH_COA
		if (((request->proxy->packet->code == PW_CODE_COA_REQUEST) ||
		     (request->proxy->packet->code == PW_CODE_DISCONNECT_REQUEST)) &&
		    (request->packet->code != request->proxy->packet->code)) {
			when.tv_sec += request->proxy->home_server->coa_mrd;
		} else
#endif
			fr_timeval_add(&when, request_response_window(request), &when);

		/*
		 *	We may need to keep waiting, if there's no reply, OR
		 *	there are fewer replies than packets sent.
		 */
		if (fr_timeval_cmp(&now, &when) < 0 &&
		    (!request->proxy->reply ||
		     (request->proxy->packet->count > request->proxy->reply->count))) {
			RDEBUG("Waiting for more responses from the home server");
			STATE_MACHINE_TIMER;
			return;
		}
		goto done;

	case FR_ACTION_PROXY_REPLY:
		if (!request->proxy->reply) proxy_reply_too_late(request);
		break;

	done:
	case FR_ACTION_DONE:
		remove_from_proxy_hash(request);
	done2:
		request_done(request, FR_ACTION_DONE);
		break;

	default:
		RDEBUG3("%s: Ignoring action %s", __FUNCTION__, action_codes[action]);
		break;
	}
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
 *		proxy_no_reply -> proxy_wait_for_id [ label = "TIMER >= timeout" ];
 *	}
 *  \enddot
 */
static void proxy_no_reply(REQUEST *request, fr_state_action_t action)
{
	VERIFY_REQUEST(request);

	TRACE_STATE_MACHINE;
	CHECK_FOR_STOP;
	CHECK_FOR_PROXY_CANCELLED;

	switch (action) {
	case FR_ACTION_DUP:
		request_dup_msg(request);
		break;

	case FR_ACTION_TIMER:
		(void) request_max_time(request);
		break;

	case FR_ACTION_PROXY_REPLY:
		proxy_reply_too_late(request);
		break;

	case FR_ACTION_RUN:
		if (process_proxy_reply(request, NULL)) {
			VALUE_PAIR *vp;

			/*
			 *	We didn't receive a reply, but maybe
			 *	post-proxy-type FAIL told us to create
			 *	one.
			 */
			vp = fr_pair_find_by_num(request->control, 0, PW_RESPONSE_PACKET_TYPE, TAG_ANY);
			if (vp && (vp->vp_integer != 256)) {
				request->proxy->reply = fr_radius_alloc_reply(request, request->proxy->packet);
				request->proxy->reply->code = vp->vp_integer;
				fr_pair_delete_by_num(&request->control, 0, PW_RESPONSE_PACKET_TYPE, TAG_ANY);
			}

			request->handle(request);
		}
		request_finish(request, action);
		break;

	case FR_ACTION_DONE:
		request->process = proxy_wait_for_id;
		request->process(request, action);
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
static void proxy_running(REQUEST *request, fr_state_action_t action)
{
	VERIFY_REQUEST(request);

	TRACE_STATE_MACHINE;
	CHECK_FOR_STOP;
	CHECK_FOR_PROXY_CANCELLED;

	switch (action) {
	case FR_ACTION_DUP:
		request_dup_msg(request);
		break;

	case FR_ACTION_TIMER:
		(void) request_max_time(request);
		break;

	case FR_ACTION_RUN:
		if (request->proxy->listener->decode(request->proxy->listener, request) < 0) goto done;
		request->proxy->listener->debug(request, request->proxy->reply, true);

		if (process_proxy_reply(request, request->proxy->reply)) {
			VALUE_PAIR *vp;

			/*
			 *	Base the reply to the NAS on the reply from the home server.
			 *	Except that we don't copy over Proxy-State.
			 */
			vp = fr_pair_list_copy(request->reply, request->proxy->reply->vps);
			fr_pair_delete_by_num(&vp, 0, PW_PROXY_STATE, TAG_ANY);
			fr_pair_add(&request->reply->vps, vp);

			request->handle(request);
		}

		request_finish(request, action);
		break;

	done:
	case FR_ACTION_DONE:
		request->process = proxy_wait_for_id;
		request->process(request, action);
		break;

	default:		/* duplicate proxy replies are suppressed */
		RDEBUG3("%s: Ignoring action %s", __FUNCTION__, action_codes[action]);
		break;
	}
}


/** Handle events while a proxy packet is in the queue.
 *
 *  \dot
 *	digraph proxy_queued {
 *		proxy_queued;
 *
 *		proxy_queued -> timer [ label = "TIMER < max_request_time" ];
 *		proxy_queued -> proxy_queued [ label = "PROXY_REPLY" ];
 *		proxy_queued -> proxy_queued [ label = "DUP" ];
 *		proxy_queued -> proxy_running [ label = "RUN with reply" ];
 *		proxy_queued -> proxy_no_reply [ label = "RUN without reply" ];
 *		proxy_queued -> done [ label = "TIMER >= timeout" ];
 *	}
 *  \enddot
 */
static void proxy_queued(REQUEST *request, fr_state_action_t action)
{
	VERIFY_REQUEST(request);

	TRACE_STATE_MACHINE;
	CHECK_FOR_STOP;
	CHECK_FOR_PROXY_CANCELLED;

	switch (action) {
	case FR_ACTION_DUP:
		request_dup_msg(request);
		break;

	case FR_ACTION_TIMER:
		(void) request_max_time(request);
		break;

		/*
		 *	We have a proxy reply, but wait for it to be
		 *	de-queued before doing anything.
		 */
	case FR_ACTION_PROXY_REPLY:
		break;

	case FR_ACTION_RUN:
		if (request->proxy->reply) {
			request->process = proxy_running;
			request->process(request, FR_ACTION_RUN);
			break;

		} else if (setup_post_proxy_fail(request)) {
			request->process = proxy_no_reply;
			request->process(request, FR_ACTION_RUN);
			break;

		} else {	/* no Post-Proxy-Type fail */
			gettimeofday(&request->reply->timestamp, NULL);
			goto done;
		}

	case FR_ACTION_DONE:
		request_queue_extract(request);
	done:
		request->process = proxy_wait_for_id;
                request->process(request, action);
		break;

	default:
		RDEBUG3("%s: Ignoring action %s", __FUNCTION__, action_codes[action]);
		break;
	}
}

/** Determine if a #REQUEST needs to be proxied, and perform pre-proxy operations
 *
 * Whether a request will be proxied is determined by the attributes present
 * in request->control. If any of the following attributes are found, the
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
 * @return
 *	- 0 if not proxying.
 *	- 1 if #REQUEST should be proxied.
 *	- -1 on failure.
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
	if (request->reply->code != 0) return 0;

	vp = fr_pair_find_by_num(request->control, 0, PW_PROXY_TO_REALM, TAG_ANY);
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
			pool = realm->auth_pool;

#ifdef WITH_ACCOUNTING
		} else if (request->packet->code == PW_CODE_ACCOUNTING_REQUEST) {
			pool = realm->acct_pool;
#endif

#ifdef WITH_COA
		} else if ((request->packet->code == PW_CODE_COA_REQUEST) ||
			   (request->packet->code == PW_CODE_DISCONNECT_REQUEST)) {
			pool = realm->coa_pool;
#endif

		} else {
			return 0;
		}

	} else if ((vp = fr_pair_find_by_num(request->control, 0, PW_HOME_SERVER_POOL, TAG_ANY)) != NULL) {
		int pool_type;

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
	} else if (((vp = fr_pair_find_by_num(request->control, 0, PW_PACKET_DST_IP_ADDRESS, TAG_ANY)) != NULL) ||
		   ((vp = fr_pair_find_by_num(request->control, 0, PW_PACKET_DST_IPV6_ADDRESS, TAG_ANY)) != NULL)) {
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

		vp = fr_pair_find_by_num(request->control, 0, PW_PACKET_DST_PORT, TAG_ANY);
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
			char buffer[INET6_ADDRSTRLEN];

			WARN("No such home server %s port %u",
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

	request->home_pool = pool;

	home = home_server_ldb(realmname, pool, request);

	if (!home) {
		REDEBUG2("Failed to find live home server: Cancelling proxy");
		return 0;
	}

do_home:
	home_server_update_request(home, request);

#ifdef WITH_COA
	if (request->coa) {
		REQUEST *coa = request->coa;

		request->coa = NULL;
		coa->parent = NULL;
		request_free(coa);
	}
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
	    (strippedname = fr_pair_find_by_num(request->proxy->packet->vps, 0, PW_STRIPPED_USER_NAME, TAG_ANY)) != NULL) {
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
		vp = fr_pair_find_by_num(request->proxy->packet->vps, 0, PW_USER_NAME, TAG_ANY);
		if (!vp) {
			vp_cursor_t cursor;
			vp = radius_pair_create(NULL, NULL,
					       PW_USER_NAME, 0);
			rad_assert(vp != NULL);	/* handled by above function */
			/* Insert at the START of the list */
			/* FIXME: Can't make assumptions about ordering */
			fr_cursor_init(&cursor, &vp);
			fr_cursor_merge(&cursor, request->proxy->packet->vps);
			request->proxy->packet->vps = vp;
		}
		fr_pair_value_strcpy(vp, strippedname->vp_strvalue);

		/*
		 *	Do NOT delete Stripped-User-Name.
		 */
	}

	/*
	 *	Call the pre-proxy routines.
	 */
	vp = fr_pair_find_by_num(request->control, 0, PW_PRE_PROXY_TYPE, TAG_ANY);
	if (vp) {
		fr_dict_enum_t const *dval = fr_dict_enum_by_da(NULL, vp->da, vp->vp_integer);
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

		request->proxy->server = request->home_pool->virtual_server;
		request->server = request->proxy->server; /* @fixme 4.0 this shouldn't be necessary! */

		RDEBUG2("server %s {", request->server);
		RINDENT();
		rcode = process_pre_proxy(pre_proxy_type, request);
		REXDENT();
		RDEBUG2("}");

		request->server = old_server;
	} else {
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
	      request->proxy->home_server->server);

	/*
	 *	Packets to virtual servers don't get
	 *	retransmissions sent to them.  And the virtual
	 *	server is run ONLY if we have no child
	 *	threads, or we're running in a child thread.
	 */
	rad_assert(!spawn_workers || !we_are_master());

	fake = request_alloc_fake(request);

	fake->packet->vps = fr_pair_list_copy(fake->packet, request->packet->vps);
	TALLOC_FREE(request->proxy->packet);

	fake->server = request->proxy->home_server->server;
	fake->handle = request->handle;
	fake->process = NULL; /* should never be run for anything */

	/*
	 *	Run the virtual server.
	 */
	request_running(fake, FR_ACTION_RUN);

	request->proxy = request_alloc_proxy(request);

	request->proxy->packet = talloc_steal(request->proxy, fake->packet);
	fake->packet = NULL;
	request->proxy->reply = talloc_steal(request->proxy, fake->reply);
	fake->reply = NULL;

	talloc_free(fake);

	/*
	 *	No reply code, toss the reply we have,
	 *	and do post-proxy-type Fail.
	 */
	if (!request->proxy->reply->code) {
		TALLOC_FREE(request->proxy->reply);
		setup_post_proxy_fail(request);
	}

	/*
	 *	Do the proxy reply (if any)
	 */
	if (process_proxy_reply(request, request->proxy->reply)) {
		request->handle(request);
	}

	return -1;	/* so we call request_finish */
}


static int request_proxy_send(REQUEST *request)
{
	char buffer[INET6_ADDRSTRLEN];

	VERIFY_REQUEST(request);

	rad_assert(request->parent == NULL);
	rad_assert(request->proxy != NULL);
	rad_assert(request->proxy->home_server != NULL);

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
	if (request->proxy->home_server->server) return proxy_to_virtual_server(request);

	/*
	 *	We're actually sending a proxied packet.  Do that now.
	 */
	if (!request->in_proxy_hash && !insert_into_proxy_hash(request)) {
		RPROXY("Failed to insert request into the proxy list");
		return -1;
	}

	rad_assert(request->proxy->packet->id >= 0);

	if (rad_debug_lvl) {
		struct timeval *response_window;

		response_window = request_response_window(request);

#ifdef WITH_TLS
		if (request->proxy->home_server->tls) {
			RDEBUG2("Proxying request to home server %s port %d (TLS) timeout %d.%06d",
				inet_ntop(request->proxy->packet->dst_ipaddr.af,
					  &request->proxy->packet->dst_ipaddr.ipaddr,
					  buffer, sizeof(buffer)),
				request->proxy->packet->dst_port,
				(int) response_window->tv_sec, (int) response_window->tv_usec);
		} else
#endif
			RDEBUG2("Proxying request to home server %s port %d timeout %d.%06d",
				inet_ntop(request->proxy->packet->dst_ipaddr.af,
					  &request->proxy->packet->dst_ipaddr.ipaddr,
					  buffer, sizeof(buffer)),
				request->proxy->packet->dst_port,
				(int) response_window->tv_sec, (int) response_window->tv_usec);

		request->proxy->response_delay = *response_window;
	}

	gettimeofday(&request->proxy->packet->timestamp, NULL);
	request->proxy->home_server->last_packet_sent = request->proxy->packet->timestamp.tv_sec;

	/*
	 *	Encode the packet before we do anything else.
	 */
	request->proxy->listener->encode(request->proxy->listener, request);
	request->proxy->listener->debug(request, request->proxy->packet, false);

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
	request->module = NULL;
	NO_CHILD_THREAD;

	/*
	 *	And send the packet.
	 */
	request->proxy->listener->send(request->proxy->listener, request);
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
			request_thread(request, proxy_no_reply);
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

		vp = fr_pair_find_by_num(request->proxy->packet->vps, 0, PW_ACCT_DELAY_TIME, TAG_ANY);
		if (!vp) vp = radius_pair_create(request->proxy->packet,
						&request->proxy->packet->vps,
						PW_ACCT_DELAY_TIME, 0);
		if (vp) {
			struct timeval now;

			gettimeofday(&now, NULL);
			vp->vp_integer += now.tv_sec - request->proxy->packet->timestamp.tv_sec;
		}
	}
#endif

	/*
	 *	May have failed over to a "fallback" virtual server.
	 *	If so, run that instead of doing proxying to a real
	 *	server.
	 */
	if (home->server) {
		request->proxy->home_server = home;
		TALLOC_FREE(request->proxy->packet);

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
	talloc_free(request->proxy->packet->data);
	request->proxy->packet->data = NULL;
	request->proxy->packet->data_len = 0;

	if (request_proxy_send(request) != 1) goto post_proxy_fail;

	return 1;
}


/** Ping a home server.
 *
 */
static void request_ping(REQUEST *request, fr_state_action_t action)
{
	home_server_t *home;
	char buffer[INET6_ADDRSTRLEN];

	VERIFY_REQUEST(request);

	TRACE_STATE_MACHINE;
	ASSERT_MASTER;

	rad_assert(request->proxy != NULL);
	home = request->proxy->home_server;

	switch (action) {
	case FR_ACTION_TIMER:
		ERROR("No response to status check %" PRIu64 " ID %u for home server %s port %d",
		       request->number,
		       request->proxy->packet->id,
		       inet_ntop(request->proxy->packet->dst_ipaddr.af,
				 &request->proxy->packet->dst_ipaddr.ipaddr,
				 buffer, sizeof(buffer)),
		       request->proxy->packet->dst_port);
		remove_from_proxy_hash(request);
		break;

	case FR_ACTION_PROXY_REPLY:
		rad_assert(request->in_proxy_hash);

		request->proxy->home_server->num_received_pings++;
		RPROXY("Received response to status check %" PRIu64 " ID %u (%d in current sequence)",
		       request->number, request->proxy->packet->id, home->num_received_pings);

		/*
		 *	Remove the request from any hashes
		 */
		fr_event_timer_delete(el, &request->ev);
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

	case FR_ACTION_DONE:
		break;

	default:
		RDEBUG3("%s: Ignoring action %s", __FUNCTION__, action_codes[action]);
		break;
	}

	rad_assert(!request->in_request_hash);
	rad_assert(!request->in_proxy_hash);
	rad_assert(request->ev == NULL);
	NO_CHILD_THREAD;
	request_delete(request);
}

/*
 *	Called from start of zombie period, OR after control socket
 *	marks the home server dead.
 */
static void ping_home_server(struct timeval *now, void *ctx)
{
	home_server_t *home = talloc_get_type_abort(ctx, home_server_t);
	REQUEST *request;
	VALUE_PAIR *vp;
	struct timeval when;

	if ((home->state == HOME_STATE_ALIVE) ||
	    (home->ev != NULL)) {
		return;
	}

	ASSERT_MASTER;

	/*
	 *	We've run out of zombie time.  Mark it dead.
	 */
	if (home->state == HOME_STATE_ZOMBIE) {
		when = home->zombie_period_start;
		when.tv_sec += home->zombie_period;

		if (fr_timeval_cmp(&when, now) < 0) {
			DEBUG("PING: Zombie period is over for home server %s", home->log_name);
			mark_home_server_dead(home, now);
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

	/*
	 *	Skip Status-Server checks if the NAS is retransmitting
	 *	packets.  If it responds to one of the normal packets,
	 *	it will be marked "alive".
	 */
	if ((home->last_packet_sent + home->ping_timeout) >= now->tv_sec) goto reset_timer;

	request = request_alloc(NULL);
	if (!request) return;
	request->number = atomic_fetch_add_explicit(&request_number_counter, 1, memory_order_relaxed);
	NO_CHILD_THREAD;

	request->proxy = request_alloc_proxy(request);

	request->proxy->packet = fr_radius_alloc(request->proxy, true);
	rad_assert(request->proxy != NULL);

	if (home->ping_check == HOME_PING_CHECK_STATUS_SERVER) {
		request->proxy->packet->code = PW_CODE_STATUS_SERVER;

		fr_pair_make(request->proxy->packet, &request->proxy->packet->vps,
			 "Message-Authenticator", "0x00", T_OP_SET);

	} else if ((home->type == HOME_TYPE_AUTH) ||
		   (home->type == HOME_TYPE_AUTH_ACCT)) {
		request->proxy->packet->code = PW_CODE_ACCESS_REQUEST;

		fr_pair_make(request->proxy->packet, &request->proxy->packet->vps,
			 "User-Name", home->ping_user_name, T_OP_SET);
		fr_pair_make(request->proxy->packet, &request->proxy->packet->vps,
			 "User-Password", home->ping_user_password, T_OP_SET);
		fr_pair_make(request->proxy->packet, &request->proxy->packet->vps,
			 "Service-Type", "Authenticate-Only", T_OP_SET);
		fr_pair_make(request->proxy->packet, &request->proxy->packet->vps,
			 "Message-Authenticator", "0x00", T_OP_SET);

#ifdef WITH_ACCOUNTING
	} else if (home->type == HOME_TYPE_ACCT) {
		request->proxy->packet->code = PW_CODE_ACCOUNTING_REQUEST;

		fr_pair_make(request->proxy->packet, &request->proxy->packet->vps,
			 "User-Name", home->ping_user_name, T_OP_SET);
		fr_pair_make(request->proxy->packet, &request->proxy->packet->vps,
			 "Acct-Status-Type", "Stop", T_OP_SET);
		fr_pair_make(request->proxy->packet, &request->proxy->packet->vps,
			 "Acct-Session-Id", "00000000", T_OP_SET);
		vp = fr_pair_make(request->proxy->packet, &request->proxy->packet->vps,
			      "Event-Timestamp", "0", T_OP_SET);
		vp->vp_date = now->tv_sec;
#endif

	} else {
		/*
		 *	Unkown home server type.
		 */
		talloc_free(request);
		return;
	}

	vp = fr_pair_make(request->proxy->packet, &request->proxy->packet->vps,
		      "NAS-Identifier", "", T_OP_SET);
	if (vp) {
		fr_pair_value_snprintf(vp, "Status Check %u. Are you alive?",
			    home->num_sent_pings);
	}

#ifdef WITH_TCP
	request->proxy->packet->proto = home->proto;
#endif
	request->proxy->packet->src_ipaddr = home->src_ipaddr;
	request->proxy->packet->dst_ipaddr = home->ipaddr;
	request->proxy->packet->dst_port = home->port;
	request->proxy->home_server = home;
#ifdef DEBUG_STATE_MACHINE
	if (rad_debug_lvl) printf("(%" PRIu64 ") ********\tSTATE %s C-%s -> C-%s\t********\n",
				  request->number, __FUNCTION__,
				  child_state_names[request->child_state],
				  child_state_names[REQUEST_DONE]);
	if (rad_debug_lvl) printf("(%" PRIu64 ") ********\tNEXT-STATE %s -> %s\n",
				  request->number, __FUNCTION__, "request_ping");
#endif
	rad_assert(request->child_pid == NO_SUCH_CHILD_PID);

	request->child_state = REQUEST_PROXIED;
	request->process = request_ping;

	rad_assert(request->proxy->listener == NULL);

	if (!insert_into_proxy_hash(request)) {
		RPROXY("Failed to insert status check %" PRIu64 " into proxy list.  Discarding it.",
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
	when = *now;
	when.tv_sec += home->ping_timeout;

	DEBUG("PING: Waiting %u seconds for response to ping",
	      home->ping_timeout);

	STATE_MACHINE_TIMER;
	home->num_sent_pings++;

	rad_assert(request->proxy->listener != NULL);
	request->proxy->listener->debug(request, request->proxy->packet, false);
	request->proxy->listener->send(request->proxy->listener, request);

reset_timer:
	/*
	 *	Add +/- 2s of jitter, as suggested in RFC 3539
	 *	and in the Issues and Fixes draft.
	 */
	home->when = *now;
	home->when.tv_sec += home->ping_interval;

	add_jitter(&home->when);

	DEBUG("PING: Next status packet in %u seconds", home->ping_interval);
	INSERT_EVENT(ping_home_server, home);
}

static void home_trigger(home_server_t *home, char const *trigger)
{
	REQUEST *request;

	request = talloc_zero(NULL, REQUEST);
	request->proxy = request_alloc_proxy(request);

	request->proxy->packet = talloc_zero(request->proxy, RADIUS_PACKET);
	request->proxy->packet->dst_ipaddr = home->ipaddr;
	request->proxy->packet->src_ipaddr = home->src_ipaddr;

	trigger_exec(request, home->cs, trigger, false, NULL);
	talloc_free(request);
}

static void mark_home_server_alive(REQUEST *request, home_server_t *home)
{
	char buffer[INET6_ADDRSTRLEN];

	home->state = HOME_STATE_ALIVE;
	home->response_timeouts = 0;
	trigger_exec(request, home->cs, "home_server.alive", false, NULL);
	home->currently_outstanding = 0;
	home->num_sent_pings = 0;
	home->num_received_pings = 0;
	gettimeofday(&home->revive_time, NULL);

	fr_event_timer_delete(el, &home->ev);

	RPROXY("Marking home server %s port %d alive",
	       inet_ntop(request->proxy->packet->dst_ipaddr.af,
			 &request->proxy->packet->dst_ipaddr.ipaddr,
			 buffer, sizeof(buffer)),
	       request->proxy->packet->dst_port);
}


static void mark_home_server_zombie(home_server_t *home, struct timeval *now, struct timeval *response_window)
{
	time_t start;
	char buffer[INET6_ADDRSTRLEN];

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

	fr_event_timer_delete(el, &home->ev);

	home->num_sent_pings = 0;
	home->num_received_pings = 0;

	PROXY("Marking home server %s port %d as zombie (it has not responded in %d.%06d seconds).",
	      inet_ntop(home->ipaddr.af, &home->ipaddr.ipaddr,
			buffer, sizeof(buffer)),
	      home->port, (int) response_window->tv_sec, (int) response_window->tv_usec);

	ping_home_server(now, home);
}


void mark_home_server_dead(home_server_t *home, struct timeval *when)
{
	int previous_state = home->state;
	char buffer[INET6_ADDRSTRLEN];

	PROXY("Marking home server %s port %d as dead",
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
			struct timeval now;

			gettimeofday(&now, NULL);
			ping_home_server(&now, home);
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


void revive_home_server(UNUSED struct timeval *now, void *ctx)
{
	home_server_t *home = talloc_get_type_abort(ctx, home_server_t);
	char buffer[INET6_ADDRSTRLEN];

	home->state = HOME_STATE_ALIVE;
	home->response_timeouts = 0;
	home_trigger(home, "home_server.alive");
	home->currently_outstanding = 0;
	gettimeofday(&home->revive_time, NULL);

	/*
	 *	Delete any outstanding events.
	 */
	ASSERT_MASTER;
	fr_event_timer_delete(el, &home->ev);

	PROXY("Marking home server %s port %d alive again... we have no idea if it really is alive or not.",
	      inet_ntop(home->ipaddr.af, &home->ipaddr.ipaddr, buffer, sizeof(buffer)),
	      home->port);
}


static bool proxy_keep_waiting(REQUEST *request, struct timeval *now)
{
	struct timeval when;
	home_server_t *home = request->proxy->home_server;
	char buffer[INET6_ADDRSTRLEN];

#ifdef WITH_TCP
	if (!request->proxy->listener ||
	    (request->proxy->listener->status >= RAD_LISTEN_STATUS_EOL)) {
		remove_from_proxy_hash(request);

		when = request->packet->timestamp;
		when.tv_sec += request->root->max_request_time;

		if (fr_timeval_cmp(&when, now) > 0) {
			RDEBUG("Waiting for client retransmission in order to do a proxy retransmit");
			STATE_MACHINE_TIMER;
			return true;
		}
	} else
#endif
	{
		/*
		 *	Wake up "response_delay" time in the future.
		 *	i.e. when MY packet hasn't received a response.
		 *
		 *	Note that we DO NOT mark the home server as
		 *	zombie if it doesn't respond to us.  It may be
		 *	responding to other (better looking) packets.
		 */
		when = request->proxy->packet->timestamp;
		fr_timeval_add(&when, &request->proxy->response_delay, &when);

		/*
		 *	Not at the response window.  Set the timer for
		 *	that.
		 */
		if (fr_timeval_cmp(&when, now) > 0) {
			struct timeval diff;
			fr_timeval_subtract(&diff, &when, now);

			RDEBUG("Expecting proxy response no later than %d.%06d seconds from now",
			       (int) diff.tv_sec, (int) diff.tv_usec);
			STATE_MACHINE_TIMER;
			return true;
		}
	}

	RDEBUG("No proxy response, giving up on request and marking it done");

	/*
	 *	If we haven't received any packets for
	 *	"response_delay", then mark the home server
	 *	as zombie.
	 *
	 *	This check should really be part of a home
	 *	server state machine.
	 */
	if (!home->is_ourself &&
	    ((home->state == HOME_STATE_ALIVE) ||
	     (home->state == HOME_STATE_UNKNOWN))) {
		home->response_timeouts++;
		if (home->response_timeouts >= home->max_response_timeouts)
			mark_home_server_zombie(home, now, &request->proxy->response_delay);
	}

	FR_STATS_TYPE_INC(home->stats.total_timeouts);
	if (home->type == HOME_TYPE_AUTH) {
		if (request->proxy->listener) FR_STATS_TYPE_INC(request->proxy->listener->stats.total_timeouts);
		FR_STATS_TYPE_INC(proxy_auth_stats.total_timeouts);
	}
#ifdef WITH_ACCT
	else if (home->type == HOME_TYPE_ACCT) {
		if (request->proxy->listener) FR_STATS_TYPE_INC(request->proxy->listener->stats.total_timeouts);
		FR_STATS_TYPE_INC(proxy_acct_stats.total_timeouts);
	}
#endif
#ifdef WITH_COA
	else if (home->type == HOME_TYPE_COA) {
		if (request->proxy->listener) FR_STATS_TYPE_INC(request->proxy->listener->stats.total_timeouts);

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
		       inet_ntop(request->proxy->packet->dst_ipaddr.af,
				 &request->proxy->packet->dst_ipaddr.ipaddr,
				 buffer, sizeof(buffer)),
		       request->proxy->packet->dst_port);
	} else {
		RERROR("Failing proxied request, due to lack of any response from home server %s port %d",
		       inet_ntop(request->proxy->packet->dst_ipaddr.af,
				 &request->proxy->packet->dst_ipaddr.ipaddr,
				 buffer, sizeof(buffer)),
		       request->proxy->packet->dst_port);
	}

	return false;
}

static void proxy_retransmit(REQUEST *request, struct timeval *now)
{
	struct timeval when;
	home_server_t *home = request->proxy->home_server;
	char buffer[INET6_ADDRSTRLEN];

	/*
	 *	Use a new connection when the home server is
	 *	dead, or when there's no proxy listener, or
	 *	when the listener is failed or dead.
	 *
	 *	If the listener is known or frozen, use it for
	 *	retransmits.
	 */
	if ((home->state == HOME_STATE_IS_DEAD) ||
	    !request->proxy->listener ||
	    (request->proxy->listener->status >= RAD_LISTEN_STATUS_EOL)) {
		request_proxy_anew(request);
		return;
	}

	/*
	 *	More than one retransmit a second is stupid,
	 *	and should be suppressed by the proxy.
	 */
	when = request->proxy->packet->timestamp;
	when.tv_sec++;

	if (fr_timeval_cmp(now, &when) < 0) {
		DEBUG2("Suppressing duplicate proxied request (too fast) to home server %s port %d proto TCP - ID: %d",
		       inet_ntop(request->proxy->packet->dst_ipaddr.af,
				 &request->proxy->packet->dst_ipaddr.ipaddr,
				 buffer, sizeof(buffer)),
		       request->proxy->packet->dst_port,
		       request->proxy->packet->id);
		return;
	}

#ifdef WITH_ACCOUNTING
	/*
	 *	If we update the Acct-Delay-Time, we need to
	 *	get a new ID.
	 */
	if ((request->packet->code == PW_CODE_ACCOUNTING_REQUEST) &&
	    fr_pair_find_by_num(request->proxy->packet->vps, 0, PW_ACCT_DELAY_TIME, TAG_ANY)) {
		request_proxy_anew(request);
		return;
	}
#endif

	RDEBUG2("Sending duplicate proxied request to home server %s port %d - ID: %d",
		inet_ntop(request->proxy->packet->dst_ipaddr.af,
			  &request->proxy->packet->dst_ipaddr.ipaddr,
			  buffer, sizeof(buffer)),
		request->proxy->packet->dst_port,
		request->proxy->packet->id);
	request->proxy->packet->count++;

	rad_assert(request->proxy->listener != NULL);
	FR_STATS_TYPE_INC(home->stats.total_requests);
	home->last_packet_sent = now->tv_sec;
	request->proxy->listener->debug(request, request->proxy->packet, false);
	request->proxy->listener->send(request->proxy->listener, request);
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
 *		proxy_wait_for_reply -> proxy_no_reply [ label = "TIMER >= response_delay" ];
 *		proxy_wait_for_reply -> timer [ label = "TIMER < max_request_time" ];
 *		proxy_wait_for_reply -> proxy_queued [ label = "PROXY_REPLY" arrowhead = "none"];
 *		proxy_wait_for_reply -> done [ label = "TIMER >= max_request_time" ];
 *	}
 *  \enddot
 */
static void proxy_wait_for_reply(REQUEST *request, fr_state_action_t action)
{
	struct timeval now;
	home_server_t *home = request->proxy->home_server;
	char buffer[INET6_ADDRSTRLEN];

	VERIFY_REQUEST(request);

	TRACE_STATE_MACHINE;
	CHECK_FOR_STOP;

	rad_assert(request->packet->code != PW_CODE_STATUS_SERVER);
	rad_assert(request->proxy->home_server != NULL);

	fr_event_list_time(&now, el);

	switch (action) {
	case FR_ACTION_DUP:
		/*
		 *	We have a reply, ignore the retransmit.
		 */
		if (request->proxy->reply) return;

		/*
		 *	The request was proxied to a virtual server.
		 *	Ignore the retransmit.
		 */
		if (request->proxy->home_server->server) return;

#ifdef WITH_TCP
		/*
		 *	The home server is still alive, but TCP.  We
		 *	rely on TCP to get the request and reply back.
		 *	So there's no need to retransmit.
		 */
		if (home->proto == IPPROTO_TCP) {
			DEBUG2("Suppressing duplicate proxied request (tcp) to home server %s port %d proto TCP - ID: %d",
			       inet_ntop(request->proxy->packet->dst_ipaddr.af,
					 &request->proxy->packet->dst_ipaddr.ipaddr,
					 buffer, sizeof(buffer)),
			       request->proxy->packet->dst_port,
			       request->proxy->packet->id);
			return;
		}
#endif

		proxy_retransmit(request, &now);
		break;

	case FR_ACTION_TIMER:
		if (proxy_keep_waiting(request, &now)) break;

		/* FALL-THROUGH */

	case FR_ACTION_PROXY_REPLY:
		request_thread(request, proxy_queued);
		break;

	case FR_ACTION_DONE:
		request->process = proxy_wait_for_id;
		request->process(request, action);
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
static rlm_rcode_t null_handler(UNUSED REQUEST *request)
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

	VERIFY_REQUEST(request);

	rad_assert(request->coa != NULL);
	rad_assert(request->proxy == NULL);
	rad_assert(!request->in_proxy_hash);

	/*
	 *	Check whether we want to originate one, or cancel one.
	 */
	vp = fr_pair_find_by_num(request->control, 0, PW_SEND_COA_REQUEST, TAG_ANY);
	if (!vp) {
		vp = fr_pair_find_by_num(request->coa->proxy->packet->vps, 0, PW_SEND_COA_REQUEST, TAG_ANY);
	}

	if (vp) {
		if (vp->vp_integer == 0) {
		fail:
			TALLOC_FREE(request->coa);
			return;
		}
	}

	coa = request->coa;

	/*
	 *	src_ipaddr will be set up in proxy_encode.
	 */
	memset(&ipaddr, 0, sizeof(ipaddr));
	vp = fr_pair_find_by_num(coa->proxy->packet->vps, 0, PW_PACKET_DST_IP_ADDRESS, TAG_ANY);
	if (vp) {
		ipaddr.af = AF_INET;
		ipaddr.ipaddr.ip4addr.s_addr = vp->vp_ipaddr;
		ipaddr.prefix = 32;
	} else if ((vp = fr_pair_find_by_num(coa->proxy->packet->vps, 0, PW_PACKET_DST_IPV6_ADDRESS, TAG_ANY)) != NULL) {
		ipaddr.af = AF_INET6;
		ipaddr.ipaddr.ip6addr = vp->vp_ipv6addr;
		ipaddr.prefix = 128;
	} else if ((vp = fr_pair_find_by_num(coa->proxy->packet->vps, 0, PW_HOME_SERVER_POOL, TAG_ANY)) != NULL) {
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
		char buffer[INET6_ADDRSTRLEN];

		vp = fr_pair_find_by_num(coa->proxy->packet->vps, 0, PW_PACKET_DST_PORT, TAG_ANY);
		if (vp) port = vp->vp_integer;

		coa->home_server = home_server_find(&ipaddr, port, IPPROTO_UDP);
		if (!coa->home_server) {
			RWDEBUG2("Unknown destination %s:%d for CoA request",
				 inet_ntop(ipaddr.af, &ipaddr.ipaddr,
					   buffer, sizeof(buffer)), port);
			goto fail;
		}
	}

	vp = fr_pair_find_by_num(coa->proxy->packet->vps, 0, PW_PACKET_TYPE, TAG_ANY);
	if (vp) {
		switch (vp->vp_integer) {
		case PW_CODE_COA_REQUEST:
		case PW_CODE_DISCONNECT_REQUEST:
			coa->proxy->packet->code = vp->vp_integer;
			break;

		default:
			DEBUG("Cannot set CoA Packet-Type to code %d",
			      vp->vp_integer);
			goto fail;
		}
	}

	if (!coa->proxy->packet->code) coa->proxy->packet->code = PW_CODE_COA_REQUEST;

	/*
	 *	The rest of the server code assumes that
	 *	request->packet && request->reply exist.  Copy them
	 *	from the original request.
	 */
	rad_assert(coa->packet != NULL);
	rad_assert(coa->packet->vps == NULL);

	coa->packet = fr_radius_copy(coa, request->packet);
	coa->reply = fr_radius_copy(coa, request->reply);

	coa->control = fr_pair_list_copy(coa, request->control);
	coa->proxy->packet->count = 0;
	coa->handle = null_handler;
	coa->number = request->number; /* it's associated with the same request */
	coa->seq_start = request->seq_start;

	/*
	 *	Call the pre-proxy routines.
	 */
	vp = fr_pair_find_by_num(request->control, 0, PW_PRE_PROXY_TYPE, TAG_ANY);
	if (vp) {
		fr_dict_enum_t const *dval = fr_dict_enum_by_da(NULL, vp->da, vp->vp_integer);
		/* Must be a validation issue */
		rad_assert(dval);
		RDEBUG2("Found Pre-Proxy-Type %s", dval->name);
		pre_proxy_type = vp->vp_integer;
	}

	if (coa->home_pool && coa->home_pool->virtual_server) {
		char const *old_server = coa->server;

		coa->proxy->server = coa->home_pool->virtual_server;
		coa->server = coa->proxy->server; /* @fixme 4.0 this shouldn't be necessary! */

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
	coa->proxy->packet->dst_ipaddr = coa->home_server->ipaddr;
	coa->proxy->packet->dst_port = coa->home_server->port;

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
	gettimeofday(&coa->proxy->packet->timestamp, NULL);
	coa->packet->timestamp = coa->proxy->packet->timestamp; /* for max_request_time */
	coa->home_server->last_packet_sent = coa->proxy->packet->timestamp.tv_sec;
	coa->delay = 0;		/* need to calculate a new delay */

	/*
	 *	If requested, put a State attribute into the packet,
	 *	and cache the VPS.
	 */
	fr_request_to_state(global_state, coa, NULL, coa->packet);

	/*
	 *	Encode the packet before we do anything else.
	 */
	coa->proxy->listener->encode(coa->proxy->listener, coa);
	coa->proxy->listener->debug(coa, coa->proxy->packet, false);

#ifdef DEBUG_STATE_MACHINE
	if (rad_debug_lvl) printf("(%" PRIu64 ") ********\tSTATE %s C-%s -> C-%s\t********\n",
				  request->number, __FUNCTION__,
				  child_state_names[request->child_state],
				  child_state_names[REQUEST_PROXIED]);
#endif

	/*
	 *	Set the state function, then the state, no child, and
	 *	send the packet.
	 */
	coa->process = coa_wait_for_reply;
	coa->child_state = REQUEST_PROXIED;

	coa->child_pid = NO_SUCH_CHILD_PID;

	if (we_are_master()) coa_separate(request->coa);

	/*
	 *	And send the packet.
	 */
	coa->proxy->listener->send(coa->proxy->listener, coa);
}


static bool coa_keep_waiting(REQUEST *request)
{
	uint32_t delay, frac;
	struct timeval now, when, mrd;
	home_server_t *home = request->proxy->home_server;
	char buffer[INET6_ADDRSTRLEN];

	VERIFY_REQUEST(request);

	/*
	 *	Use a new connection when the home server is
	 *	dead, or when there's no proxy listener, or
	 *	when the listener is failed or dead.
	 *
	 *	If the listener is known or frozen, use it for
	 *	retransmits.
	 */
	if ((home->state == HOME_STATE_IS_DEAD) ||
	    !request->proxy->listener ||
	    (request->proxy->listener->status >= RAD_LISTEN_STATUS_EOL)) {
		return false;
	}

	fr_event_list_time(&now, el);

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
		request->delay = delay * home->coa_irt;
		delay = home->coa_irt * USEC;
		delay -= delay / 10;
		delay += request->delay;
		request->delay = delay;

		when = request->proxy->packet->timestamp;
		tv_add(&when, delay);

		if (fr_timeval_cmp(&when, &now) > 0) {
			STATE_MACHINE_TIMER;
			return true;
		}
	}

	/*
	 *	Retransmit CoA request.
	 */

	/*
	 *	Cap count at MRC, if it is non-zero.
	 */
	if (home->coa_mrc &&
	    (request->proxy->packet->count >= home->coa_mrc)) {
		RERROR("Failing request - originate-coa ID %u, due to lack of any response from coa server %s port %d",
		       request->proxy->packet->id,
		       inet_ntop(request->proxy->packet->dst_ipaddr.af,
				 &request->proxy->packet->dst_ipaddr.ipaddr,
				 buffer, sizeof(buffer)),
		       request->proxy->packet->dst_port);
		return false;
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
	if (home->coa_mrt &&
	    (delay > (home->coa_mrt * USEC))) {
		int mrt_usec = home->coa_mrt * USEC;

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
	mrd = request->proxy->packet->timestamp;
	mrd.tv_sec += home->coa_mrd;

	/*
	 *	Cap duration at MRD.
	 */
	if (fr_timeval_cmp(&mrd, &when) < 0) {
		when = mrd;
	}
	STATE_MACHINE_TIMER;

	request->proxy->packet->count++;

	FR_STATS_TYPE_INC(home->stats.total_requests);

	RDEBUG2("Sending duplicate CoA request to home server %s port %d - ID: %d",
		inet_ntop(request->proxy->packet->dst_ipaddr.af,
			  &request->proxy->packet->dst_ipaddr.ipaddr,
			  buffer, sizeof(buffer)),
		request->proxy->packet->dst_port,
		request->proxy->packet->id);

	request->proxy->listener->send(request->proxy->listener,
				      request);
	return true;
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
 *		coa_wait_for_reply -> coa_no_reply [ label = "TIMER >= response_delay" ];
 *		coa_wait_for_reply -> timer [ label = "TIMER < max_request_time" ];
 *		coa_wait_for_reply -> coa_queued [ label = "PROXY_REPLY" arrowhead = "none"];
 *		coa_wait_for_reply -> done [ label = "TIMER >= max_request_time" ];
 *	}
 *  \enddot
 */
static void coa_wait_for_reply(REQUEST *request, fr_state_action_t action)
{
	VERIFY_REQUEST(request);

	TRACE_STATE_MACHINE;
	ASSERT_MASTER;
	CHECK_FOR_STOP;

	if (request->parent) coa_separate(request);

	switch (action) {
	case FR_ACTION_TIMER:
		if (request_max_time(request)) goto done;

		/*
		 *	@fixme: for TCP, the socket may go away.
		 *	we probably want to do the checks for proxy_keep_waiting() ??
		 *
		 *	And maybe do fail-over, which would be nice!
		 */
		if (coa_keep_waiting(request)) break;

		/* FALL-THROUGH */

	case FR_ACTION_PROXY_REPLY:
		request_thread(request, coa_queued);
		break;

	case FR_ACTION_DONE:
	done:
		request->process = proxy_wait_for_id;
		request->process(request, action);
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
	fr_state_action_t action = FR_ACTION_TIMER;
#endif

	TRACE_STATE_MACHINE;
	ASSERT_MASTER;

	rad_assert(request->parent != NULL);
	rad_assert(request->parent->coa == request);
	rad_assert(request->ev == NULL);
	rad_assert(!request->in_request_hash);
	rad_assert(request->coa == NULL);

	rad_assert(request->proxy->reply || request->proxy->listener);

	(void) talloc_steal(NULL, request);
	request->parent->coa = NULL;
	request->parent = NULL;

	if (we_are_master()) {
		request->delay = 0;
		(void) coa_keep_waiting(request);
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
static void coa_no_reply(REQUEST *request, fr_state_action_t action)
{
	char buffer[INET6_ADDRSTRLEN];

	VERIFY_REQUEST(request);

	TRACE_STATE_MACHINE;
	CHECK_FOR_STOP;
	CHECK_FOR_PROXY_CANCELLED;

	switch (action) {
	case FR_ACTION_TIMER:
		(void) request_max_time(request);
		break;

	case FR_ACTION_PROXY_REPLY: /* too late! */
		RDEBUG2("Reply from CoA server %s port %d  - ID: %d arrived too late.",
			inet_ntop(request->proxy->packet->src_ipaddr.af,
				  &request->proxy->packet->src_ipaddr.ipaddr,
				  buffer, sizeof(buffer)),
			request->proxy->packet->dst_port, request->proxy->packet->id);
		break;

	case FR_ACTION_RUN:
		if (process_proxy_reply(request, NULL)) {
			request->handle(request);
		}
		/* FALL-THROUGH */

	case FR_ACTION_DONE:
		request->process = proxy_wait_for_id;
		request->process(request, action);
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
static void coa_running(REQUEST *request, fr_state_action_t action)
{
	VERIFY_REQUEST(request);

	TRACE_STATE_MACHINE;
	CHECK_FOR_STOP;
	CHECK_FOR_PROXY_CANCELLED;

	switch (action) {
	case FR_ACTION_TIMER:
		(void) request_max_time(request);
		break;

	case FR_ACTION_RUN:
		if (request->proxy->listener->decode(request->proxy->listener, request) < 0) goto done;
		request->proxy->listener->debug(request, request->proxy->reply, true);

		if (process_proxy_reply(request, request->proxy->reply)) {
			request->handle(request);
		}
		/* FALL-THROUGH */

	done:
	case FR_ACTION_DONE:
		request->process = proxy_wait_for_id;
		request->process(request, action);
		break;

	default:
		RDEBUG3("%s: Ignoring action %s", __FUNCTION__, action_codes[action]);
		break;
	}
}

/** Handle events while a CoA packet is in the queue.
 *
 *  \dot
 *	digraph coa_queued {
 *		coa_queued;
 *
 *		coa_queued -> timer [ label = "TIMER < max_request_time" ];
 *		coa_queued -> coa_queued [ label = "PROXY_REPLY" ];
 *		coa_queued -> coa_running [ label = "RUN with reply" ];
 *		coa_queued -> coa_no_reply [ label = "RUN without reply" ];
 *		coa_queued -> done [ label = "TIMER >= timeout" ];
 *	}
 *  \enddot
 */
static void coa_queued(REQUEST *request, fr_state_action_t action)
{
	VERIFY_REQUEST(request);

	TRACE_STATE_MACHINE;
	CHECK_FOR_STOP;
	CHECK_FOR_PROXY_CANCELLED;

	switch (action) {
	case FR_ACTION_TIMER:
		(void) request_max_time(request);
		break;

		/*
		 *	We have a proxy reply, but wait for it to be
		 *	de-queued before doing anything.
		 */
	case FR_ACTION_PROXY_REPLY:
		break;

	case FR_ACTION_RUN:
		if (request->proxy->reply) {
			request->process = coa_running;
			request->process(request, FR_ACTION_RUN);
			break;

		} else if (setup_post_proxy_fail(request)) {
			request->process = coa_no_reply;
			request->process(request, FR_ACTION_RUN);
			break;

		} else {	/* no Post-Proxy-Type fail */
			goto done;
		}

	case FR_ACTION_DONE:
		request_queue_extract(request);
	done:
		request->process = proxy_wait_for_id;
                request->process(request, action);
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
static void event_socket_handler(NDEBUG_UNUSED fr_event_list_t *xel, UNUSED int fd, void *ctx)
{
	rad_listen_t *listener = talloc_get_type_abort(ctx, rad_listen_t);

	rad_assert(xel == el);

	if (listener->fd < 0) {
		char buffer[256];

		listener->print(listener, buffer, sizeof(buffer));

		rad_panic("FATAL: Asked to read from closed socket (fd %i): %s", listener->fd, buffer);
	}

	listener->recv(listener);
}


static int event_status(struct timeval *wake, UNUSED void *ctx)
{
	if (rad_debug_lvl == 0) {
		if (just_started) {
			INFO("Ready to process requests");
			just_started = false;
		}
		return 0;
	}

	if (!wake) {
		if (main_config.drop_requests) return 0;
		INFO("Ready to process requests");
	} else if ((wake->tv_sec != 0) ||
		   (wake->tv_usec >= 100000)) {
		DEBUG("Waking up in %d.%01u seconds.",
		      (int) wake->tv_sec, (unsigned int) wake->tv_usec / 100000);
	}

	return 0;
}

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
			break;	/* add the FD to the list */
#endif	/* WITH_DETAIL */

#ifdef WITH_PROXY
		/*
		 *	Add it to the list of sockets we can use.
		 *	Server sockets (i.e. auth/acct) are never
		 *	added to the packet list.
		 */
		case RAD_LISTEN_PROXY:
#ifdef WITH_TCP
			if (!rad_cond_assert((sock->proto == IPPROTO_UDP) || (sock->home != NULL))) fr_exit(1);

			/*
			 *	Add timers to outgoing child sockets, if necessary.
			 */
			if (sock->proto == IPPROTO_TCP && sock->opened &&
			    (sock->home->limit.lifetime || sock->home->limit.idle_timeout)) {
				this->when.tv_sec = sock->opened + 1;
				this->when.tv_usec = 0;

				INSERT_EVENT(tcp_socket_timer, this);
			}
#endif
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
				this->when.tv_sec = sock->opened + 1;
				this->when.tv_usec = 0;

				INSERT_EVENT(tcp_socket_timer, this);
			}
#endif
			break;
		} /* switch over listener types */

		/*
		 *	All sockets: add the FD to the event handler.
		 */
		if (!fr_event_fd_insert(el, this->fd, event_socket_handler, NULL, NULL, this)) {
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
		keep_waiting:
			/*
			 *	Try again to clean up the socket in a
			 *	few seconds.  seconds.
			 */
			gettimeofday(&this->when, NULL);
			this->when.tv_sec += 3;

			INSERT_EVENT((fr_event_callback_t) event_new_fd, this);
			return 1;
		}

		this->status = RAD_LISTEN_STATUS_REMOVE_NOW;
	}

	/*
	 *	The socket has had a catastrophic error.  Close it.
	 */
	if (this->status == RAD_LISTEN_STATUS_EOL) {
		int devnull;

		/*
		 *	Remove it from the list of live FD's.
		 */
		fr_event_fd_delete(el, this->fd);

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
			ERROR("FATAL failure opening /dev/null: %s", fr_syserror(errno));
			fr_exit(1);
		}
		if (dup2(devnull, this->fd) < 0) {
			ERROR("FATAL failure closing socket: %s", fr_syserror(errno));
			fr_exit(1);
		}
		close(devnull);

#ifdef WITH_PROXY
		/*
		 *	Tell all requests using this socket that the socket is dead.
		 */
		if (this->type == RAD_LISTEN_PROXY) {
			home_server_t *home;
			listen_socket_t *sock = this->data;

			home = sock->home;
			if (!home || !home->limit.max_connections) {
				INFO(" ... shutting down socket %s", buffer);
			} else {
				INFO(" ... shutting down socket %s (%u of %u)", buffer,
				     home->limit.num_connections, home->limit.max_connections);
			}

			pthread_mutex_lock(&proxy_mutex);
			if (!fr_packet_list_socket_freeze(proxy_list,
							  this->fd)) {
				ERROR("Fatal error freezing socket: %s", fr_strerror());
				fr_exit(1);
			}

			fr_packet_list_walk(proxy_list, this, eol_proxy_listener);
			pthread_mutex_unlock(&proxy_mutex);
		} else
#endif
		{
			INFO(" ... shutting down socket %s", buffer);

			/*
			 *	EOL all requests using this socket.
			 *
			 *	Except for control sockets, which
			 *	don't have any requests associated
			 *	with them.
			 */
#ifdef WITH_COMMAND_SOCKET
			if (this->type != RAD_LISTEN_COMMAND)
#endif

			rbtree_walk(pl, RBTREE_DELETE_ORDER, eol_listener, this);
		}


		/*
		 *	Requests are still using the socket.  Wait for
		 *	them to finish.
		 */
		if (this->count > 0) {
			this->status = RAD_LISTEN_STATUS_FROZEN;
			goto keep_waiting;
		}

		/*
		 *	No one is using the socket.  We can remove it now.
		 */
		this->status = RAD_LISTEN_STATUS_REMOVE_NOW;
	} /* socket is at EOL */

	/*
	 *	Nuke the socket.
	 */
	if (this->status == RAD_LISTEN_STATUS_REMOVE_NOW) {
		if (this->count > 0) goto keep_waiting;

		fr_event_timer_delete(el, &this->ev);

		this->print(this, buffer, sizeof(buffer));
		DEBUG("... cleaning up socket %s", buffer);

		listen_free(&this);
		return 1;
	}
#endif	/* WITH_TCP */

	return 1;
}

/*
 *	Emit a systemd watchdog notification and reschedule the event.
 */
#ifdef HAVE_SYSTEMD_WATCHDOG
static void sd_watchdog_event(struct timeval *now, void *ctx)
{
	struct timeval when;

	DEBUG("Emitting systemd watchdog notification");
	sd_notify(0, "WATCHDOG=1");

	fr_event_list_time(&when, el);
	tv_add(&when, sd_watchdog_interval / 2);
	if (!fr_event_timer_insert(el, sd_watchdog_event, ctx, &when, ctx)) {
		rad_panic("Failed to insert watchdog event");
	}
}
#endif

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

		trigger_exec(NULL, NULL, "server.signal.hup", true, NULL);
		fr_event_loop_exit(el, 0x80);
	}

#if defined(WITH_TCP) && defined(WITH_PROXY)
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

static int self_pipe[2] = { -1, -1 };

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

/***********************************************************************
 *
 *	Bootstrapping code.
 *
 ***********************************************************************/

/*
 *	Externally-visibly functions.
 */
int radius_event_init(TALLOC_CTX *ctx) {
	el = fr_event_list_create(ctx, event_status, NULL);
	if (!el) return 0;

#ifdef HAVE_SYSTEMD_WATCHDOG
	if ( (int) sd_watchdog_interval > 0 ) sd_watchdog_event(ctx);
#endif

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
	if (!home_servers_udp) return;

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

/** Start the main event loop and initialise the listeners
 *
 * @param have_children Whether the server is threaded.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int radius_event_start(bool have_children)
{
	rad_listen_t *head = NULL;

	if (fr_start_time != (time_t)-1) return 0;

	time(&fr_start_time);

	if (!check_config) {
		/*
		 *  radius_event_init() must be called first
		 */
		rad_assert(el);

		MEM(pl = rbtree_create(NULL, packet_entry_cmp, NULL, RBTREE_FLAG_LOCK));
	}

#ifdef WITH_PROXY
	if (main_config.proxy_requests && !check_config) {
		/*
		 *	Create the tree for managing proxied requests and
		 *	responses.
		 */
		MEM(proxy_list = fr_packet_list_create(1));

		if (pthread_mutex_init(&proxy_mutex, NULL) != 0) {
			ERROR("Failed to initialize proxy mutex: %s", fr_syserror(errno));
			return -1;
		}

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
	spawn_workers = have_children;

	NO_SUCH_CHILD_PID = pthread_self(); /* not a child thread */

	if (check_config) {
		DEBUG("%s: #### Skipping IP addresses and Ports ####",
		       main_config.name);
		return 0;
	}

	/*
	 *	Child threads need a pipe to signal us, as do the
	 *	signal handlers.
	 */
	if (pipe(self_pipe) < 0) {
		ERROR("Error opening internal pipe: %s", fr_syserror(errno));
		return -1;
	}
	if ((fcntl(self_pipe[0], F_SETFL, O_NONBLOCK) < 0) ||
	    (fcntl(self_pipe[0], F_SETFD, FD_CLOEXEC) < 0)) {
		ERROR("Error setting internal flags: %s", fr_syserror(errno));
		return -1;
	}
	if ((fcntl(self_pipe[1], F_SETFL, O_NONBLOCK) < 0) ||
	    (fcntl(self_pipe[1], F_SETFD, FD_CLOEXEC) < 0)) {
		ERROR("Error setting internal flags: %s", fr_syserror(errno));
		return -1;
	}
	DEBUG4("Created signal pipe.  Read end FD %i, write end FD %i", self_pipe[0], self_pipe[1]);

	if (!fr_event_fd_insert(el, self_pipe[0], event_signal_handler, NULL, NULL, el)) {
		ERROR("Failed creating signal pipe handler: %s", fr_strerror());
		return -1;
	}

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
	if (listen_init(&head, spawn_workers) < 0) return -1;

	main_config.listen = head;

#ifdef WITH_PROXY
	check_proxy(head);
#endif

	/*
	 *	At this point, no one has any business *ever* going
	 *	back to root uid.
	 */
	rad_suid_down_permanent();

	/*
	 *	Dropping down may change the RLIMIT_CORE value, so
	 *	reset it back to what to should be here.
	 */
	fr_reset_dumpable();

	return 0;
}


#ifdef WITH_PROXY
static int proxy_delete_cb(UNUSED void *ctx, void *data)
{
	REQUEST *request = fr_packet2myptr(REQUEST, packet, data);

	VERIFY_REQUEST(request);
	rad_assert(request->parent != NULL);
	rad_assert(request->parent->proxy == request);
	request = request->parent;
	VERIFY_REQUEST(request);

	request->master_state = REQUEST_STOP_PROCESSING;

	if (request->child_state == REQUEST_QUEUED) {
		request_queue_extract(request);
		request->child_state = REQUEST_DONE;
	}

	if (request->child_state == REQUEST_RUNNING) return 0;

	request->in_proxy_hash = false;

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

	if (request->child_state == REQUEST_QUEUED) {
		request_queue_extract(request);
		request->child_state = REQUEST_DONE;
	}

	if (request->child_state == REQUEST_RUNNING) return 0;

#ifdef WITH_PROXY
	rad_assert(request->in_proxy_hash == false);
#endif

	request->in_request_hash = false;
	fr_event_timer_delete(el, &request->ev);

	if (main_config.talloc_memory_report) {
		RDEBUG2("Cleaning up request packet ID %u with timestamp +%d",
			request->packet->id,
			(unsigned int) (request->packet->timestamp.tv_sec - fr_start_time));
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

	if (spawn_workers) {
		/*
		 *	Walk the lists again, ensuring that all
		 *	requests are done.
		 */
		if (main_config.talloc_memory_report) {
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
