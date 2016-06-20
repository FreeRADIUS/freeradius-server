/*
 * threads.c	request threading support
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
 * Copyright 2000,2006  The FreeRADIUS server project
 * Copyright 2000  Alan DeKok <aland@ox.org>
 */

RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/process.h>
#include <freeradius-devel/heap.h>
#include <freeradius-devel/rad_assert.h>

#ifdef HAVE_SYS_WAIT_H
#  include <sys/wait.h>
#endif

#ifdef HAVE_OPENSSL_CRYPTO_H
#  include <openssl/crypto.h>
#endif
#  ifdef HAVE_OPENSSL_ERR_H
#    include <openssl/err.h>
#  endif
#ifdef HAVE_OPENSSL_EVP_H
#  include <openssl/evp.h>
#endif

#ifdef HAVE_GPERFTOOLS_PROFILER_H
#  include <gperftools/profiler.h>
#endif

#ifndef WITH_GCD
/*
 *	Threads start off in the idle list.
 *
 *	When a packet comes in, the first thread in the idle list is
 *	assigned the request, and is moved to the head of the active
 *	list.  When the thread is done processing the request, it
 *	removes itself from the active list, and adds itself to the
 *	HEAD of the idle list.  This ensures that "hot" threads
 *	continue to get scheduled, and "cold" threads age out of the
 *	CPU cache.
 *
 *	When the server is reaching overload, there are no threads in
 *	the idle queue.  In that case, the request is added to the
 *	backlog.  Any active threads will check the heap FIRST,
 *	before moving themselves to the idle list as described above.
 *	If there are requests in the heap, the thread stays in the
 *	active list, and processes the packet.
 *
 *	Once a second, a random one of the worker threads will manage
 *	the thread pool.  This work involves spawning more threads if
 *	needed, marking old "idle" threads as cancelled, etc.  That
 *	work is done with the mutex released (if at all possible).
 *	This practice minimizes contention on the mutex.
 */
#  define THREAD_IDLE		(1)
#  define THREAD_ACTIVE		(2)
#  define THREAD_CANCELLED	(3)
#  define THREAD_EXITED		(4)

/*
 *  A data structure which contains the information about
 *  the current thread.
 */
typedef struct THREAD_HANDLE {
	struct THREAD_HANDLE	*prev;		//!< Previous thread handle (in the linked list).
	struct THREAD_HANDLE	*next;		//!< Next thread handle (int the linked list).

	pthread_t		pthread_id;	//!< pthread_id.
	int			thread_num;	//!< Server thread number, 1...number of threads.
	int			status;		//!< Is the thread running or exited?
	unsigned int		request_count;	//!< The number of requests that this thread has handled.
	time_t			timestamp;	//!< When the thread started executing.
	time_t			max_time;	//!< for current request
	REQUEST			*request;
} THREAD_HANDLE;

#endif	/* WITH_GCD */

typedef struct thread_fork_t {
	pid_t		pid;
	int		status;
	int		exited;
} thread_fork_t;


#ifdef WITH_STATS
typedef struct fr_pps_t {
	uint32_t	pps_old;
	uint32_t	pps_now;
	uint32_t	pps;
	time_t		time_old;
} fr_pps_t;
#endif


/*
 *	A data structure to manage the thread pool.  There's no real
 *	need for a data structure, but it makes things conceptually
 *	easier.
 */
typedef struct THREAD_POOL {
	bool		spawn_workers;

#ifdef WNOHANG
	pthread_mutex_t	wait_mutex;
	fr_hash_table_t *waiters;
#endif

#ifdef WITH_GCD
	dispatch_queue_t	queue;
#else
	uint32_t	max_thread_num;
	uint32_t	start_threads;
	uint32_t	max_threads;
	uint32_t	min_spare_threads;
	uint32_t	max_spare_threads;
	uint32_t	max_requests_per_thread;
	uint32_t	request_count;
	time_t		time_last_spawned;
	uint32_t	cleanup_delay;
	bool		stop_flag;

#ifdef WITH_STATS
	fr_pps_t	pps_in, pps_out;
#ifdef WITH_ACCOUNTING
	bool		auto_limit_acct;
#endif
#endif

	char const	*queue_priority;

	/*
	 *	To ensure only one thread at a time touches the scheduler.
	 *
	 *	Threads start off on the idle list.  As packets come
	 *	in, the threads go to the active list.  If the idle
	 *	list is empty, packets go to the backlog.
	 */
	bool		spawning;

	uint32_t	max_queue_size;
	uint32_t	num_queued;

	fr_heap_cmp_t	heap_cmp;

	uint32_t	total_threads;
	uint32_t	active_threads;
	uint32_t	idle_threads;
	uint32_t	exited_threads;

	pthread_mutex_t	backlog_mutex;
	fr_heap_t	*backlog;

	pthread_mutex_t	idle_mutex;
	THREAD_HANDLE	*idle_head;
	THREAD_HANDLE	*idle_tail;

	pthread_mutex_t	active_mutex;
	THREAD_HANDLE	*active_head;
	THREAD_HANDLE	*active_tail;

	pthread_mutex_t	exited_mutex;
	THREAD_HANDLE	*exited_head;
	THREAD_HANDLE	*exited_tail;
#endif	/* WITH_GCD */
} THREAD_POOL;

static THREAD_POOL thread_pool;
static bool pool_initialized = false;

#ifndef WITH_GCD
static pid_t thread_fork(void);
static pid_t thread_waitpid(pid_t pid, int *status);
static THREAD_HANDLE *spawn_thread(time_t now, int do_trigger);
#endif

#ifndef WITH_GCD
/*
 *	A mapping of configuration file names to internal integers
 */
static const CONF_PARSER thread_config[] = {
	{ FR_CONF_POINTER("start_servers", PW_TYPE_INTEGER, &thread_pool.start_threads), .dflt = "5" },
	{ FR_CONF_POINTER("max_servers", PW_TYPE_INTEGER, &thread_pool.max_threads), .dflt = "32" },
	{ FR_CONF_POINTER("min_spare_servers", PW_TYPE_INTEGER, &thread_pool.min_spare_threads), .dflt = "3" },
	{ FR_CONF_POINTER("max_spare_servers", PW_TYPE_INTEGER, &thread_pool.max_spare_threads), .dflt = "10" },
	{ FR_CONF_POINTER("max_requests_per_server", PW_TYPE_INTEGER, &thread_pool.max_requests_per_thread), .dflt = "0" },
	{ FR_CONF_POINTER("cleanup_delay", PW_TYPE_INTEGER, &thread_pool.cleanup_delay), .dflt = "5" },
	{ FR_CONF_POINTER("max_queue_size", PW_TYPE_INTEGER, &thread_pool.max_queue_size), .dflt = "65536" },
	{ FR_CONF_POINTER("queue_priority", PW_TYPE_STRING, &thread_pool.queue_priority), .dflt = NULL },
#ifdef WITH_STATS
#ifdef WITH_ACCOUNTING
	{ FR_CONF_POINTER("auto_limit_acct", PW_TYPE_BOOLEAN, &thread_pool.auto_limit_acct) },
#endif
#endif
	CONF_PARSER_TERMINATOR
};
#endif

#ifdef WNOHANG
/*
 *	We don't want to catch SIGCHLD for a host of reasons.
 *
 *	- exec_wait means that someone, somewhere, somewhen, will
 *	call waitpid(), and catch the child.
 *
 *	- SIGCHLD is delivered to a random thread, not the one that
 *	forked.
 *
 *	- if another thread catches the child, we have to coordinate
 *	with the thread doing the waiting.
 *
 *	- if we don't waitpid() for non-wait children, they'll be zombies,
 *	and will hang around forever.
 *
 */
static void reap_children(void)
{
	pid_t pid;
	int status;
	thread_fork_t mytf, *tf;


	pthread_mutex_lock(&thread_pool.wait_mutex);

	do {
	retry:
		pid = waitpid(0, &status, WNOHANG);
		if (pid <= 0) break;

		mytf.pid = pid;
		tf = fr_hash_table_finddata(thread_pool.waiters, &mytf);
		if (!tf) goto retry;

		tf->status = status;
		tf->exited = 1;
	} while (fr_hash_table_num_elements(thread_pool.waiters) > 0);

	pthread_mutex_unlock(&thread_pool.wait_mutex);
}
#else
#  define reap_children()
#endif /* WNOHANG */

#ifndef WITH_GCD
/*
 *	Remove the thread from the active list.
 */
static void unlink_active(THREAD_HANDLE *thread)
{
	pthread_mutex_lock(&thread_pool.active_mutex);
	thread->request = NULL;
	if (thread->prev) {
		rad_assert(thread_pool.active_head != thread);
		thread->prev->next = thread->next;
	} else {
		rad_assert(thread_pool.active_head == thread);
		thread_pool.active_head = thread->next;
	}

	if (thread->next) {
		rad_assert(thread_pool.active_tail != thread);
		thread->next->prev = thread->prev;
	} else {
		rad_assert(thread_pool.active_tail == thread);
		thread_pool.active_tail = thread->prev;
	}
	thread_pool.active_threads--;
	pthread_mutex_unlock(&thread_pool.active_mutex);
}


/*
 *	Add the thread to the tail of the exited list.
 */
static void link_exited_tail(THREAD_HANDLE *thread)
{
	pthread_mutex_lock(&thread_pool.exited_mutex);
	if (thread_pool.exited_tail) {
		thread->prev = thread_pool.exited_tail;
		thread->prev->next = thread;
		thread_pool.exited_tail = thread;
	} else {
		rad_assert(thread_pool.exited_head == NULL);
		thread_pool.exited_head = thread;
		thread_pool.exited_tail = thread;
		thread->prev = NULL;
	}
	thread_pool.total_threads--;

	thread->status = THREAD_CANCELLED;
	pthread_mutex_unlock(&thread_pool.exited_mutex);
}


static void link_idle_head(THREAD_HANDLE *thread)
{
	/*
	 *	Insert it into the head of the idle list.
	 */
	thread->prev = NULL;
	thread->next = thread_pool.idle_head;
	if (thread->next) {
		thread->next->prev = thread;
	} else {
		rad_assert(thread_pool.idle_tail == NULL);
		thread_pool.idle_tail = thread;
	}
	thread_pool.idle_head = thread;
	thread_pool.idle_threads++;
}
			 

/*
 *	Remove ourselves from the idle list
 */
static void unlink_idle(THREAD_HANDLE *thread, bool do_locking)
{
	if (do_locking) pthread_mutex_lock(&thread_pool.idle_mutex);

	if (thread->prev) {
		rad_assert(thread_pool.idle_head != thread);
		thread->prev->next = thread->next;
		
	} else {
		rad_assert(thread_pool.idle_head == thread);
		thread_pool.idle_head = thread->next;
	}

	if (thread->next) {
		rad_assert(thread_pool.idle_tail != thread);
		thread->next->prev = NULL;
	} else {
		rad_assert(thread_pool.idle_tail == thread);
		thread_pool.idle_tail = thread->prev;
		rad_assert(thread_pool.idle_threads == 1);
	}
	thread_pool.idle_threads--;

	if (do_locking) pthread_mutex_unlock(&thread_pool.idle_mutex);
}


/*
 *	Add a request to the list of waiting requests.
 *	This function gets called ONLY from the main handler thread...
 *
 *	This function should never fail.
 */
void request_enqueue(REQUEST *request)
{
	struct timeval now;
	REQUEST *old;
	THREAD_HANDLE *thread;

	request->component = "<core>";

	/*
	 *	No child threads, just process it here.
	 */
	if (!thread_pool.spawn_workers) {
		request->module = NULL;

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
		return;
	}

	request->child_state = REQUEST_QUEUED;
	request->module = "<queue>";

	/*
	 *	Give the request to a thread, doing as little work as
	 *	possible in the contended regions.
	 */
	pthread_mutex_lock(&thread_pool.idle_mutex);
	if (thread_pool.idle_head) {
		int num_blocked;
		uint64_t number;
		char const *module, *component;
		THREAD_HANDLE *blocked;

		static time_t last_checked_active = 0;

		/*
		 *	Remove the thread from the idle list.
		 */
		thread = thread_pool.idle_head;
		thread_pool.idle_head = thread->next;
		if (thread->next) {
			thread->next->prev = NULL;
		} else {
			rad_assert(thread_pool.idle_tail == thread);
			thread_pool.idle_tail = thread->prev;
			rad_assert(thread_pool.idle_threads == 1);
		}
		thread_pool.idle_threads--;
		pthread_mutex_unlock(&thread_pool.idle_mutex);

		/*
		 *	Tell the thread about the request
		 */
		thread->request = request;
		thread->max_time = request->packet->timestamp.tv_sec + request->root->max_request_time;

		/*
		 *	Add the thread to the head of the active list.
		 */
		pthread_mutex_lock(&thread_pool.active_mutex);
		thread->prev = NULL;
		thread->next = thread_pool.active_head;
		if (thread->next) {
			rad_assert(thread_pool.active_tail != NULL);
			thread->next->prev = thread;
		} else {
			rad_assert(thread_pool.active_tail == NULL);
			thread_pool.active_tail = thread;
		}
		thread_pool.active_head = thread;
		thread_pool.active_threads++;
		thread->status = THREAD_ACTIVE;

		/*
		 *	Ssee if any active threads have been taking
		 *	too long.  If so, tell them to stop.
		 */
		blocked = NULL;
		num_blocked = 0;
		gettimeofday(&now, NULL);

		if (last_checked_active < now.tv_sec) {
			last_checked_active = now.tv_sec;

			for (blocked = thread_pool.active_tail;
			     blocked != NULL;
			     blocked = blocked->prev) {
				if (blocked->max_time >= now.tv_sec) continue;

				request = thread->request;

				if (request->master_state == REQUEST_STOP_PROCESSING) continue;

				number = request->number;
				component = request->component;
				module = request->module;
				num_blocked++;

				request->master_state = REQUEST_STOP_PROCESSING;
				request->process(request, FR_ACTION_DONE);
			}
		}
		pthread_mutex_unlock(&thread_pool.active_mutex);

		/*
		 *	Tell the thread that there's a request available for
		 *	it, once we're done all of the above work.
		 */
		pthread_kill(thread->pthread_id, SIGALRM);

		/*
		 *	If a thread is blocked, the request may have
		 *	already been free'd, so don't access it's
		 *	fields outside of the mutex.  Instead, use the
		 *	cached versions.
		 */
		if (num_blocked) {
			ERROR("Unresponsive thread for request %" PRIu64 ", in component %s module %s",
			      number,
			      component ? component : "<core>",
			      module ? module : "<core>");
			ERROR("There are %d new threads blocked in the last second", num_blocked);
			trigger_exec(NULL, NULL, "server.thread.unresponsive", true, NULL);
		}

		return;
	}

	/*
	 *	No idle threads, add the request to the backlog.
	 */
	pthread_mutex_unlock(&thread_pool.idle_mutex);

	gettimeofday(&now, NULL);

	/*
	 *	Manage the backlog.
	 *
	 *	First, by deleting at least one old request from the backlog.
	 *	Second, by seeing if the backlog is full.
	 *	Third, by auto-limiting accounting packets, which are low priority.
	 *	Fourth, by inserting the request into the backlog.
	 */
	pthread_mutex_lock(&thread_pool.backlog_mutex);

	/*
	 *	Only delete one request from the backlog.  Even this
	 *	code is necessary only when the active threads are
	 *	blocked.  And if that happens, all bets are off...
	 *
	 *	@fixme - Complain when this happens, too.
	 */
	old = fr_heap_peek_tail(thread_pool.backlog);
	if ((old->packet->timestamp.tv_sec + old->root->max_request_time) < now.tv_sec) {
		(void) fr_heap_extract(thread_pool.backlog, old);

		old->master_state = REQUEST_STOP_PROCESSING;
		old->process(request, FR_ACTION_DONE);
	}

	/*
	 *	If there are too many requests in the backlog, discard
	 *	this one.  Note that we do these checks without a
	 *	mutex, as if the backlog is completely full, it's OK
	 *	to err on the side of tossing packets.
	 */
	if ((thread_pool.num_queued + 1) >= thread_pool.max_queue_size) {
		pthread_mutex_unlock(&thread_pool.backlog_mutex);

		RATE_LIMIT(ERROR("Something is blocking the server.  There are %d packets in the queue, "
				 "waiting to be processed.  Ignoring the new request.", thread_pool.max_queue_size));
	done:
		request->master_state = REQUEST_STOP_PROCESSING;
		request->process(request, FR_ACTION_DONE);
		return;
	}


#ifdef WITH_STATS
#ifdef WITH_ACCOUNTING
	/*
	 *	We MAY automatically limit accounting packets.  Do
	 *	this before we try inserting the request into the
	 *	backlog.
	 */
	if (thread_pool.auto_limit_acct) {
		/*
		 *	Throw away accounting requests if we're too
		 *	busy.  The NAS should retransmit these, and no
		 *	one should notice.
		 *
		 *	In contrast, we always try to process
		 *	authentication requests.  Those are more time
		 *	critical, and it's harder to determine which
		 *	we can throw away, and which we can keep.
		 *
		 *	We allow the queue to get half full before we
		 *	start worrying.  Even then, we still require
		 *	that the rate of input packets is higher than
		 *	the rate of outgoing packets.  i.e. the queue
		 *	is growing.
		 *
		 *	Once that happens, we roll a dice to see where
		 *	the barrier is for "keep" versus "toss".  If
		 *	the queue is smaller than the barrier, we
		 *	allow it.  If the queue is larger than the
		 *	barrier, we throw the packet away.  Otherwise,
		 *	we keep it.
		 *
		 *	i.e. the probability of throwing the packet
		 *	away increases from 0 (queue is half full), to
		 *	100 percent (queue is completely full).
		 *
		 *	A probabilistic approach allows us to process
		 *	SOME of the new accounting packets.
		 */
		if ((request->packet->code == PW_CODE_ACCOUNTING_REQUEST) &&
		    (thread_pool.num_queued > (thread_pool.max_queue_size / 2)) &&
		    (thread_pool.pps_in.pps_now > thread_pool.pps_out.pps_now)) {
			uint32_t prob;
			uint32_t keep;

			/*
			 *	Take a random value of how full we
			 *	want the queue to be.  It's OK to be
			 *	half full, but we get excited over
			 *	anything more than that.
			 */
			keep = (thread_pool.max_queue_size / 2);
			prob = fr_rand() & ((1 << 10) - 1);
			keep *= prob;
			keep >>= 10;
			keep += (thread_pool.max_queue_size / 2);

			/*
			 *	If the queue is larger than our dice
			 *	roll, we throw the packet away.
			 */
			if (thread_pool.num_queued > keep) {
				pthread_mutex_unlock(&thread_pool.backlog_mutex);
				goto done;
			}
		}

		thread_pool.pps_in.pps = rad_pps(&thread_pool.pps_in.pps_old,
						 &thread_pool.pps_in.pps_now,
						 &thread_pool.pps_in.time_old,
						 &now);

		thread_pool.pps_in.pps_now++;
	}
#endif	/* WITH_ACCOUNTING */
#endif

	/*
	 *	Add the request to the backlog.
	 */
	if (fr_heap_insert(thread_pool.backlog, request) < 0) {
		pthread_mutex_unlock(&thread_pool.backlog_mutex);
		goto done;
	}

	thread_pool.num_queued++;
	pthread_mutex_unlock(&thread_pool.backlog_mutex);
}


void request_queue_extract(REQUEST *request)
{
	if (request->heap_id < 0) return;
	
	pthread_mutex_lock(&thread_pool.backlog_mutex);
	(void) fr_heap_extract(thread_pool.backlog, request);
	thread_pool.num_queued--;
	pthread_mutex_unlock(&thread_pool.backlog_mutex);
}


/*
 *	Remove a request from the queue.
 */
static REQUEST *request_dequeue(void)
{
	time_t now;
	REQUEST *request = NULL;

	/*
	 *	Grab the first entry.
	 */
	pthread_mutex_lock(&thread_pool.backlog_mutex);
	request = fr_heap_peek(thread_pool.backlog);
	if (!request) {
		pthread_mutex_unlock(&thread_pool.backlog_mutex);
		rad_assert(thread_pool.num_queued == 0);
		return NULL;
	}

	now = time(NULL);

	(void) fr_heap_extract(thread_pool.backlog, request);
	thread_pool.num_queued--;
	pthread_mutex_unlock(&thread_pool.backlog_mutex);

	VERIFY_REQUEST(request);

	return request;
}

static void sig_alarm(UNUSED int signal)
{
	reset_signal(SIGALRM, sig_alarm);
}

/*
 *	The main thread handler for requests.
 *
 *	Wait for a request, process it, and continue.
 */
static void *thread_handler(void *arg)
{
	int rcode;
	THREAD_HANDLE *idle;
	THREAD_HANDLE *thread = (THREAD_HANDLE *) arg;
	TALLOC_CTX *ctx;
	fr_event_list_t *el;

	ctx = talloc_init("thread_pool");
	
	el = fr_event_list_create(ctx, NULL);

	/*
	 *	Loop forever, until told to exit.
	 */
	while (true) {
		time_t now;
		REQUEST *request;

#  ifdef HAVE_GPERFTOOLS_PROFILER_H
		ProfilerRegisterThread();
#  endif

		/*
		 *	Wait to be signalled.
		 */
		DEBUG2("Thread %d waiting to be assigned a request",
		       thread->thread_num);
		
		/*
		 *	Run until we get a signal.  Any registered
		 *	timer events or FD events will also be
		 *	serviced here.
		 */
		rcode = fr_event_wait(el);
		if (rcode < 0) {
			ERROR("Thread %d failed waiting for request: %s: Exiting\n",
			      thread->thread_num, fr_syserror(errno));

			rad_assert(thread->status == THREAD_IDLE);

			unlink_idle(thread, true);
			link_exited_tail(thread);
			goto done;
		}

		rad_assert(rcode == 0);

	process:
		/*
		 *	Maybe we've been idle for too long.
		 */
		if (thread->status == THREAD_CANCELLED) break;

		/*
		 *	The server is exiting.  Don't dequeue any
		 *	requests.
		 */
		if (thread_pool.stop_flag) break;

		rad_assert(thread->status == THREAD_ACTIVE);
		rad_assert(thread->request != NULL);
		request = thread->request;

#ifdef WITH_ACCOUNTING
		if ((thread->request->packet->code == PW_CODE_ACCOUNTING_REQUEST) &&
		    thread_pool.auto_limit_acct) {
			VALUE_PAIR *vp;

			vp = radius_pair_create(request, &request->control,
					       181, VENDORPEC_FREERADIUS);
			if (vp) vp->vp_integer = thread_pool.pps_in.pps;

			vp = radius_pair_create(request, &request->control,
					       182, VENDORPEC_FREERADIUS);
			if (vp) vp->vp_integer = thread_pool.pps_in.pps;

			vp = radius_pair_create(request, &request->control,
					       183, VENDORPEC_FREERADIUS);
			if (vp) {
				vp->vp_integer = thread_pool.max_queue_size - thread_pool.num_queued;
				vp->vp_integer *= 100;
				vp->vp_integer /= thread_pool.max_queue_size;
			}
		}
#endif

		thread->request_count++;

		DEBUG2("Thread %d handling request %" PRIu64 ", (%d handled so far)",
		       thread->thread_num, request->number,
		       thread->request_count);

		request->child_pid = thread->pthread_id;
		request->component = "<core>";
		request->module = NULL;
		request->child_state = REQUEST_RUNNING;
		request->log.unlang_indent = 0;

		request->process(thread->request, FR_ACTION_RUN);

		/*
		 *	Clean up any children we exec'd.
		 */
		reap_children();

#  ifdef HAVE_OPENSSL_ERR_H
		/*
		 *	Clear the error queue for the current thread.
		 */
		ERR_clear_error();
#  endif
		
		/*
		 *	Try to get a packet from the backlog.  If we
		 *	have one, update the max time for the request,
		 *	and continue processing.
		 *
		 *	Note that we have to lock the active mutex, so
		 *	that the request_enqueue() function doesn't
		 *	get a stale pointer to thread->request.
		 */
		request = request_dequeue();
		if (request) {
			pthread_mutex_lock(&thread_pool.active_mutex);
			thread->max_time = request->packet->timestamp.tv_sec + request->root->max_request_time;
			thread->request = request;
			pthread_mutex_unlock(&thread_pool.active_mutex);
			goto process;
		}

		unlink_active(thread);

		now = time(NULL);

		/*
		 *      Add it the head of the idle list.
		 */
		pthread_mutex_lock(&thread_pool.idle_mutex);

		/*
		 *	There are too few spare threads.  Create an extra one now.
		 *	We create new threads aggressively, and clean them up slowly.
		 */
		if (!thread_pool.spawning &&
		    (thread_pool.total_threads < thread_pool.max_threads) &&
		    ((thread_pool.idle_threads + 1) < thread_pool.min_spare_threads)) {
			thread_pool.spawning = true;

			pthread_mutex_unlock(&thread_pool.idle_mutex);
			idle = spawn_thread(now, 1);
			pthread_mutex_lock(&thread_pool.idle_mutex);

			thread_pool.total_threads++; /* FIXME atomic */
			link_idle_head(idle);
		} else		/* don't check for deleted threads if we just created one */

		/*
		 *	If we haven't spawned a new thread for
		 *	a while, and we have too many idle
		 *	threads, then delete the thread from
		 *	the tail of the idle list, or ourselves.
		 */
		if ((now < (thread_pool.time_last_spawned + thread_pool.cleanup_delay)) &&
		    ((thread_pool.idle_threads + 1) >= thread_pool.max_spare_threads)) {
			idle = thread_pool.idle_tail;
			if (!idle) {
				pthread_mutex_unlock(&thread_pool.idle_mutex);
				link_exited_tail(thread);
				goto done;
			}

			unlink_idle(idle, false);
			link_exited_tail(idle);

			/*
			 *	Post an extra signal so that the idle thread wakes
			 *	up and knows to exit.
			 */
			pthread_kill(idle->pthread_id, SIGALRM);			
		}

		link_idle_head(thread);
		pthread_mutex_unlock(&thread_pool.idle_mutex);

		/*
		 *	Clean up exited threads.
		 */
		if (thread_pool.exited_head) {
			pthread_mutex_lock(&thread_pool.exited_mutex);
			if (thread_pool.exited_head &&
			    (thread_pool.exited_head->status == THREAD_EXITED)) {
				idle = thread_pool.exited_head;
				
				/*
				 *	Unlink it from the exited list.
				 *
				 *	It's already been removed from
				 *	"total_threads", as we don't count threads
				 *	which are doing nothing.
				 */
				thread_pool.exited_head = idle->next;
				if (idle->next) {
					idle->next->prev = NULL;
				} else {
					thread_pool.exited_tail = NULL;
				}

				/*
				 *	Deleting old threads can take time, so we join
				 *	it with the mutex unlocked.
				 */
				pthread_mutex_unlock(&thread_pool.exited_mutex);
				pthread_join(idle->pthread_id, NULL);
				talloc_free(idle);
			} else {
				pthread_mutex_unlock(&thread_pool.exited_mutex);
			}
		}

	}

done:
	DEBUG2("Thread %d exiting...", thread->thread_num);

	talloc_free(ctx);

#ifdef HAVE_OPENSSL_ERR_H
	/*
	 *	If we linked with OpenSSL, the application
	 *	must remove the thread's error queue before
	 *	exiting to prevent memory leaks.
	 */
	FR_TLS_REMOVE_THREAD_STATE();
#endif

	trigger_exec(NULL, NULL, "server.thread.stop", true, NULL);
	thread->status = THREAD_EXITED;

	return NULL;
}

/*
 *	Spawn a new thread, and place it in the thread pool.
 *	Called with the thread mutex locked...
 */
static THREAD_HANDLE *spawn_thread(time_t now, int do_trigger)
{
	int rcode;
	THREAD_HANDLE *thread;

	/*
	 *	Allocate a new thread handle.
	 */
	MEM(thread = talloc_zero(NULL, THREAD_HANDLE));

	thread->thread_num = thread_pool.max_thread_num++; /* @fixme atomic? */
	thread->request_count = 0;
	thread->status = THREAD_IDLE;
	thread->timestamp = now;

	/*
	 *	Create the thread joinable, so that it can be cleaned up
	 *	using pthread_join().
	 *
	 *	Note that the function returns non-zero on error, NOT
	 *	-1.  The return code is the error, and errno isn't set.
	 */
	rcode = pthread_create(&thread->pthread_id, 0, thread_handler, thread);
	if (rcode != 0) {
		talloc_free(thread);
		ERROR("Thread create failed: %s",
		       fr_syserror(rcode));
		return NULL;
	}

	DEBUG2("Thread spawned new child %d. Total threads in pool: %d",
	       thread->thread_num, thread_pool.total_threads + 1);
	if (do_trigger) trigger_exec(NULL, NULL, "server.thread.start", true, NULL);

	return thread;
}
#endif	/* WITH_GCD */


#ifdef WNOHANG
static uint32_t pid_hash(void const *data)
{
	thread_fork_t const *tf = data;

	return fr_hash(&tf->pid, sizeof(tf->pid));
}

static int pid_cmp(void const *one, void const *two)
{
	thread_fork_t const *a = one;
	thread_fork_t const *b = two;

	return (a->pid - b->pid);
}
#endif

static int timestamp_cmp(void const *one, void const *two)
{
	REQUEST const *a = one;
	REQUEST const *b = two;

	if (timercmp(&a->packet->timestamp, &b->packet->timestamp, < )) return -1;
	if (timercmp(&a->packet->timestamp, &b->packet->timestamp, > )) return +1;

	return 0;
}

/*
 *	Smaller entries go to the top of the heap.
 *	Larger ones to the bottom of the heap.
 */
static int default_cmp(void const *one, void const *two)
{
	REQUEST const *a = one;
	REQUEST const *b = two;

	if (a->priority < b->priority) return -1;
	if (a->priority > b->priority) return +1;

	return timestamp_cmp(one, two);
}


/*
 *	Prioritize by how far along the EAP session is.
 */
static int state_cmp(void const *one, void const *two)
{
	REQUEST const *a = one;
	REQUEST const *b = two;

	/*
	 *	Rounds which are further along go higher in the heap.
	 */
	if (a->packet->rounds > b->packet->rounds) return -1;
	if (a->packet->rounds < b->packet->rounds) return +1;

	return default_cmp(one, two);
}


/** Parse the configuration for the thread pool
 *
 */
int thread_pool_bootstrap(CONF_SECTION *cs, bool *spawn_workers)
{
	CONF_SECTION	*pool_cf;

	rad_assert(spawn_workers != NULL);
	rad_assert(pool_initialized == false); /* not called on HUP */

	/*
	 *	Initialize the thread pool to some reasonable values.
	 */
	memset(&thread_pool, 0, sizeof(THREAD_POOL));
	thread_pool.spawn_workers = *spawn_workers;

	pool_cf = cf_subsection_find_next(cs, NULL, "thread");
#ifdef WITH_GCD
	if (pool_cf) {
		WARN("Built with Grand Central Dispatch.  Ignoring 'thread' subsection");
		return 0;
	}
#else

	/*
	 *	Initialize our counters.
	 */
	thread_pool.total_threads = 0;
	thread_pool.max_thread_num = 1;
	thread_pool.cleanup_delay = 5;
	thread_pool.stop_flag = false;

	/*
	 *	No configuration, don't spawn anything.
	 */
	if (!pool_cf) {
		thread_pool.spawn_workers = *spawn_workers = false;
		WARN("No 'thread pool {..}' found.  Server will be single threaded");
		return 0;
	}

	if (cf_section_parse(pool_cf, NULL, thread_config) < 0) return -1;

	/*
	 *	Catch corner cases.
	 */
	FR_INTEGER_BOUND_CHECK("min_spare_servers", thread_pool.min_spare_threads, >=, 1);
	FR_INTEGER_BOUND_CHECK("max_spare_servers", thread_pool.max_spare_threads, >=, 1);
	FR_INTEGER_BOUND_CHECK("max_spare_servers", thread_pool.max_spare_threads, >=, thread_pool.min_spare_threads);

	FR_INTEGER_BOUND_CHECK("max_queue_size", thread_pool.max_queue_size, >=, 2);
	FR_INTEGER_BOUND_CHECK("max_queue_size", thread_pool.max_queue_size, <, 1024*1024);

	FR_INTEGER_BOUND_CHECK("max_servers", thread_pool.max_threads, >=, 1);
	FR_INTEGER_BOUND_CHECK("start_servers", thread_pool.start_threads, <=, thread_pool.max_threads);

#ifdef WITH_TLS
	/*
	 *	So TLS knows what to do.
	 */
	fr_tls_max_threads = thread_pool.max_threads;
#endif

	if (!thread_pool.queue_priority ||
	    (strcmp(thread_pool.queue_priority, "default") == 0)) {
		thread_pool.heap_cmp = default_cmp;

	} else if (strcmp(thread_pool.queue_priority, "eap") == 0) {
		thread_pool.heap_cmp = state_cmp;

	} else if (strcmp(thread_pool.queue_priority, "time") == 0) {
		thread_pool.heap_cmp = timestamp_cmp;

	} else {
		ERROR("FATAL: Invalid queue_priority '%s'", thread_pool.queue_priority);
		return -1;
	}

	/*
	 *	Patch these in because we're threaded.
	 */
	rad_fork = thread_fork;
	rad_waitpid = thread_waitpid;

#endif	/* WITH_GCD */
	return 0;
}

static void thread_handle_free(void *th)
{
	talloc_free(th);
}


/*
 *	Allocate the thread pool, and seed it with an initial number
 *	of threads.
 */
int thread_pool_init(void)
{
#ifndef WITH_GCD
	uint32_t	i;
	int		rcode;
#endif
	time_t		now;

	now = time(NULL);

	/*
	 *	Don't bother initializing the mutexes or
	 *	creating the hash tables.  They won't be used.
	 */
	if (!thread_pool.spawn_workers) return 0;

	/*
	 *	The pool has already been initialized.  Don't spawn
	 *	new threads, and don't forget about forked children.
	 */
	if (pool_initialized) return 0;

	if (fr_set_signal(SIGALRM, sig_alarm) < 0) {
		ERROR("Failed setting signal catcher in thread handler: %s", fr_strerror());
		return -1;
	}

#ifdef WNOHANG
	if ((pthread_mutex_init(&thread_pool.wait_mutex,NULL) != 0)) {
		ERROR("FATAL: Failed to initialize wait mutex: %s",
		       fr_syserror(errno));
		return -1;
	}

	/*
	 *	Create the hash table of child PID's
	 */
	thread_pool.waiters = fr_hash_table_create(NULL, pid_hash, pid_cmp, thread_handle_free);
	if (!thread_pool.waiters) {
		ERROR("FATAL: Failed to set up wait hash");
		return -1;
	}
#endif


#ifndef WITH_GCD
	rcode = pthread_mutex_init(&thread_pool.idle_mutex, NULL);
	if (rcode != 0) {
		ERROR("FATAL: Failed to initialize thread pool idle mutex: %s",
		       fr_syserror(errno));
		return -1;
	}

	rcode = pthread_mutex_init(&thread_pool.active_mutex, NULL);
	if (rcode != 0) {
		ERROR("FATAL: Failed to initialize thread pool active mutex: %s",
		       fr_syserror(errno));
		return -1;
	}

	rcode = pthread_mutex_init(&thread_pool.exited_mutex, NULL);
	if (rcode != 0) {
		ERROR("FATAL: Failed to initialize thread pool exited mutex: %s",
		       fr_syserror(errno));
		return -1;
	}

	rcode = pthread_mutex_init(&thread_pool.backlog_mutex, NULL);
	if (rcode != 0) {
		ERROR("FATAL: Failed to initialize thread pool backlog mutex: %s",
		       fr_syserror(errno));
		return -1;
	}

	thread_pool.backlog = fr_heap_create(thread_pool.heap_cmp, offsetof(REQUEST, heap_id));
	if (!thread_pool.backlog) {
		ERROR("FATAL: Failed to initialize the incoming queue.");
		return -1;
	}

	/*
	 *	Create a number of waiting threads.  Note we don't
	 *	need to lock the mutex, as nothing is sending
	 *	requests.
	 *
	 *	FIXE: If we fail while creating them, do something intelligent.
	 */
	for (i = 0; i < thread_pool.start_threads; i++) {
		THREAD_HANDLE *thread;

		thread = spawn_thread(now, 0);
		if (!thread) return -1;

		thread->prev = NULL;
		thread->next = thread_pool.idle_head;
		if (thread->next) {
			rad_assert(thread_pool.idle_tail != NULL);
			thread->next->prev = thread;
		} else {
			rad_assert(thread_pool.idle_tail == NULL);
			thread_pool.idle_tail = thread;
		}
		thread_pool.idle_head = thread;
		thread_pool.idle_threads++;

		thread_pool.total_threads++;
	}
#else
	thread_pool.queue = dispatch_queue_create("org.freeradius.threads", NULL);
	if (!thread_pool.queue) {
		ERROR("Failed creating dispatch queue: %s", fr_syserror(errno));
		fr_exit(1);
	}
#endif

	DEBUG2("Thread pool initialized");
	pool_initialized = true;
	return 0;
}


/*
 *	Stop all threads in the pool.
 */
void thread_pool_stop(void)
{
#ifndef WITH_GCD
	THREAD_HANDLE *thread;
	THREAD_HANDLE *next;

	if (!pool_initialized) return;

	/*
	 *	Set pool stop flag.
	 */
	thread_pool.stop_flag = true;


	/*
	 *	Join and free all threads.
	 */
	for (thread = thread_pool.exited_head; thread; thread = next) {
		next = thread->next;

		pthread_join(thread->pthread_id, NULL);
		talloc_free(thread);
	}

	for (thread = thread_pool.idle_head; thread; thread = next) {
		next = thread->next;

		thread->status = THREAD_CANCELLED;
		pthread_kill(thread->pthread_id, SIGALRM);

		pthread_join(thread->pthread_id, NULL);
		talloc_free(thread);
	}

	for (thread = thread_pool.active_head; thread; thread = next) {
		next = thread->next;

		thread->status = THREAD_CANCELLED;
		pthread_kill(thread->pthread_id, SIGALRM);

		pthread_join(thread->pthread_id, NULL);
		talloc_free(thread);
	}

	fr_heap_delete(thread_pool.backlog);

#  ifdef WNOHANG
	fr_hash_table_free(thread_pool.waiters);
#  endif
#endif
}


#ifdef WITH_GCD
void request_enqueue(REQUEST *request)
{
	dispatch_block_t block;

	block = ^{
		request->process(request, FR_ACTION_RUN);
	};

	dispatch_async(thread_pool.queue, block);
}
#endif

#ifdef WNOHANG
/*
 *	Thread wrapper for fork().
 */
static pid_t thread_fork(void)
{
	pid_t child_pid;

	if (!pool_initialized) return fork();

	reap_children();	/* be nice to non-wait thingies */

	if (fr_hash_table_num_elements(thread_pool.waiters) >= 1024) {
		return -1;
	}

	/*
	 *	Fork & save the PID for later reaping.
	 */
	child_pid = fork();
	if (child_pid > 0) {
		int rcode;
		thread_fork_t *tf;

		MEM(tf = talloc_zero(NULL, thread_fork_t));
		tf->pid = child_pid;

		pthread_mutex_lock(&thread_pool.wait_mutex);
		rcode = fr_hash_table_insert(thread_pool.waiters, tf);
		pthread_mutex_unlock(&thread_pool.wait_mutex);

		if (!rcode) {
			ERROR("Failed to store PID, creating what will be a zombie process %d",
			       (int) child_pid);
			talloc_free(tf);
		}
	}

	/*
	 *	Return whatever we were told.
	 */
	return child_pid;
}


/*
 *	Wait 10 seconds at most for a child to exit, then give up.
 */
static pid_t thread_waitpid(pid_t pid, int *status)
{
	int i;
	thread_fork_t mytf, *tf;

	if (!pool_initialized) return waitpid(pid, status, 0);

	if (pid <= 0) return -1;

	mytf.pid = pid;

	pthread_mutex_lock(&thread_pool.wait_mutex);
	tf = fr_hash_table_finddata(thread_pool.waiters, &mytf);
	pthread_mutex_unlock(&thread_pool.wait_mutex);

	if (!tf) return -1;

	for (i = 0; i < 100; i++) {
		reap_children();

		if (tf->exited) {
			*status = tf->status;

			pthread_mutex_lock(&thread_pool.wait_mutex);
			fr_hash_table_delete(thread_pool.waiters, &mytf);
			pthread_mutex_unlock(&thread_pool.wait_mutex);
			return pid;
		}
		usleep(100000);	/* sleep for 1/10 of a second */
	}

	/*
	 *	10 seconds have passed, give up on the child.
	 */
	pthread_mutex_lock(&thread_pool.wait_mutex);
	fr_hash_table_delete(thread_pool.waiters, &mytf);
	pthread_mutex_unlock(&thread_pool.wait_mutex);

	return 0;
}
#else
/*
 *	No rad_fork or rad_waitpid
 */
#endif

void thread_pool_queue_stats(int array[RAD_LISTEN_MAX], int pps[2])
{
	int i;

#ifndef WITH_GCD
	if (pool_initialized) {
		struct timeval now;

		/*
		 *	@fixme: the list of listeners is no longer
		 *	fixed in size.
		 */
		memset(array, 0, sizeof(array[0]) * RAD_LISTEN_MAX);
		array[0] = fr_heap_num_elements(thread_pool.backlog);

		gettimeofday(&now, NULL);

		pps[0] = rad_pps(&thread_pool.pps_in.pps_old,
				 &thread_pool.pps_in.pps_now,
				 &thread_pool.pps_in.time_old,
				 &now);
		pps[1] = rad_pps(&thread_pool.pps_out.pps_old,
				 &thread_pool.pps_out.pps_now,
				 &thread_pool.pps_out.time_old,
				 &now);

	} else
#endif	/* WITH_GCD */
	{
		for (i = 0; i < RAD_LISTEN_MAX; i++) {
			array[i] = 0;
		}

		pps[0] = pps[1] = 0;
	}
}
