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
#include <freeradius-devel/modules.h>

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
 *	Incoming packets are spread across all worker threads.
 */
typedef enum fr_thread_status_t {
	THREAD_NONE = 0,
	THREAD_ACTIVE,
	THREAD_CANCELLED,
	THREAD_EXITED,
} fr_thread_status_t;

/*
 *  A data structure which contains the information about
 *  the current thread.
 */
typedef struct THREAD_HANDLE {
	struct THREAD_HANDLE	*prev;		//!< Previous thread handle (in the linked list).
	struct THREAD_HANDLE	*next;		//!< Next thread handle (int the linked list).

	pthread_t		pthread_id;	//!< pthread_id.
	int			thread_num;	//!< Server thread number, 1...number of threads.
	fr_thread_status_t     	status;		//!< Is the thread running or exited?
	unsigned int		request_count;	//!< The number of requests that this thread has handled.
	time_t			timestamp;	//!< When the thread started executing.
	time_t			max_time;	//!< for current request
	int			pipe_fd[2];	//!< for self signal

	pthread_mutex_t		backlog_mutex;
	fr_heap_t		*backlog;
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

/** Holds this thread's event_list
 *
 * Some modules need direct access to the event_list, so they can
 * insert events that fire independently of processing requests.
 *
 * Libcurl is a good example of this, where it manages its own timers
 * for IO events, and needs to be awoken, when a timeout expires.
 */
static _Thread_local fr_event_list_t *thread_el;

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

	pthread_mutex_t	thread_mutex;
	THREAD_HANDLE	*thread_head;
	THREAD_HANDLE	*thread_tail;

	pthread_key_t	thread_handle_key;
#endif	/* WITH_GCD */
} THREAD_POOL;

static THREAD_POOL thread_pool;
static bool pool_initialized = false;

#ifndef WITH_GCD
static pid_t thread_fork(void);
static pid_t thread_waitpid(pid_t pid, int *status);
static THREAD_HANDLE *thread_spawn(time_t now, int do_trigger);
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
static void link_list_tail(THREAD_HANDLE **head_p, THREAD_HANDLE **tail_p, THREAD_HANDLE *this)
{
	rad_assert(*head_p != this);
	rad_assert(*tail_p != this);

	if (*tail_p) {
		(*tail_p)->next = this;
	}

	this->next = NULL;
	this->prev = *tail_p;

	*tail_p = this;
	if (!*head_p) {
		rad_assert(this->prev == NULL);
		*head_p = this;
	} else {
		rad_assert(this->prev != NULL);
	}
}

/*
 *	Add a request to the list of waiting requests.
 *	This function gets called ONLY from the main handler thread...
 *
 *	This function should never fail.
 */
void request_enqueue(REQUEST *request)
{
	THREAD_HANDLE *thread;
	THREAD_HANDLE *found = NULL;
	char data = 0;

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

	found = thread_pool.thread_head;

	for (thread = thread_pool.thread_head;
	     thread != NULL;
	     thread = thread->next) {
		if (fr_heap_num_elements(found->backlog) > fr_heap_num_elements(thread->backlog)) {
			found = thread;
		}
	}

	if (!found) return;	/* should never happen */

	thread = found;
	DEBUG3("Thread %d being signalled", thread->thread_num);

	pthread_mutex_lock(&thread->backlog_mutex);
	fr_heap_insert(thread->backlog, request);
	request->backlog = thread->backlog;
	request->thread_ctx = thread;
	pthread_mutex_unlock(&thread->backlog_mutex);

	/*
	 *	Tell the thread that there's a request available for
	 *	it, once we're done all of the above work.
	 */
	(void) write(thread->pipe_fd[1], &data, 1);
}

/*
 *	Remove the request from a worker threads queue.
 *
 *	This function is only called from the request_queue() and
 *	friends functions, by the listener thread.
 */
void request_queue_extract(REQUEST *request)
{
	THREAD_HANDLE *thread;

	if (!request->backlog || !request->thread_ctx) return;

	thread = request->thread_ctx;

	pthread_mutex_lock(&thread->backlog_mutex);
	(void) fr_heap_extract(request->backlog, request);
	rad_assert(request->heap_id == -1);
	pthread_mutex_unlock(&thread->backlog_mutex);
}

/*
 *	Drain the socket, but don't do anything else.
 */
static void thread_fd_handler(UNUSED fr_event_list_t *el, int fd, void *ctx)
{
	char buffer[16];
	THREAD_HANDLE *thread = (THREAD_HANDLE *) ctx;

	(void) read(fd, buffer, sizeof(buffer));

	DEBUG3("Thread %d was sent a new request", thread->thread_num);
}

static int timestamp_cmp(void const *one, void const *two)
{
	REQUEST const *a = one;
	REQUEST const *b = two;
	RADIUS_PACKET *pa, *pb;

#ifdef WITH_VERIFY_PTR
	REQUEST *x, *y;

	memcpy(&x, &a, sizeof(a));
	memcpy(&y, &b, sizeof(b));

	VERIFY_REQUEST(x);
	VERIFY_REQUEST(y);
#endif

	if (!a->packet) {
		rad_assert(a->proxy != NULL);
		rad_assert(a->proxy->packet != NULL);

		pa = a->proxy->packet;
	} else {
		pa = a->packet;
	}

	if (!b->packet) {
		rad_assert(b->proxy != NULL);
		rad_assert(b->proxy->packet != NULL);

		pb = b->proxy->packet;
	} else {
		pb = b->packet;
	}

	return fr_timeval_cmp(&pa->timestamp, &pb->timestamp);
}


/*
 *	Enforce max_request_time.
 */
static void max_request_time_hook(void *ctx, UNUSED struct timeval *now)
{
	REQUEST *request = talloc_get_type_abort(ctx, REQUEST);
#ifdef DEBUG_STATE_MACHINE
	fr_state_action_t action = FR_ACTION_DONE;
#endif

	TRACE_STATE_MACHINE;

	request->process(request, FR_ACTION_DONE);
}


static void thread_process_request(THREAD_HANDLE *thread, REQUEST *request)
{
	thread->request_count++;

	RDEBUG2("Thread %d handling request %" PRIu64 ", (%d handled so far)",
		thread->thread_num, request->number,
		thread->request_count);

	request->child_pid = thread->pthread_id;
	request->component = "<core>";
	request->module = NULL;
	request->child_state = REQUEST_RUNNING;
	request->log.unlang_indent = 0;

	request->process(request, FR_ACTION_RUN);

	/*
	 *	Clean up any children we exec'd.
	 */
	reap_children();

#ifdef HAVE_OPENSSL_ERR_H
	/*
	 *	Clear the error queue for the current thread.
	 */
	ERR_clear_error();
#endif
}

/** Return this thread's event list
 *
 * Can be used by modules to get the event_list for the current thread,
 * so that they can add their own timers outside of request processing.
 *
 * @return This thread's fr_event_list_t.
 */
fr_event_list_t *thread_event_list(void)
{
	return thread_el;
}

/*
 *	The main thread handler for requests.
 *
 *	Wait for a request, process it, and continue.
 */
static void *thread_handler(void *arg)
{
	int			rcode;
	THREAD_HANDLE		*thread = talloc_get_type_abort(arg, THREAD_HANDLE);
	TALLOC_CTX		*ctx;
	fr_heap_t		*local_backlog;
	fr_event_list_t		*el;

#ifdef HAVE_GPERFTOOLS_PROFILER_H
	ProfilerRegisterThread();
#endif

	ctx = talloc_init("thread");

	el = thread_el = fr_event_list_create(ctx, NULL, NULL);
	rad_assert(el != NULL);

	local_backlog = fr_heap_create(timestamp_cmp, offsetof(REQUEST, heap_id));
	rad_assert(local_backlog != NULL);

	if (!fr_event_fd_insert(el, thread->pipe_fd[0], thread_fd_handler, NULL, NULL, thread)) {
		ERROR("Failed inserting event for self");
		goto done;
	}

	if (pthread_setspecific(thread_pool.thread_handle_key, thread) != 0) {
		ERROR("Failed setting key for self");
		goto done;
	}

	/*
	 *	Perform thread specific module instantiation
	 */
	if (modules_thread_instantiate(main_config.config) < 0) {
		ERROR("Thread instantiation failed");
		goto done;
	}

	thread->status = THREAD_ACTIVE;

	/*
	 *	Loop forever, until told to exit.
	 */
	while (true) {
		bool		wait_for_event;
		REQUEST		*request;

		/*
		 *	Drain the backlog from the reader thread on
		 *	every round through the loop.  We also add our
		 *	local event loop, backlog, and
		 *	max_request_time handler to the request.
		 */
		if (fr_heap_num_elements(thread->backlog) > 0) {
			struct timeval when;

			gettimeofday(&when, NULL);
			when.tv_sec += main_config.max_request_time;

			pthread_mutex_lock(&thread->backlog_mutex);
			do {
				request = fr_heap_peek(thread->backlog);
				if (!request) break;

				(void) fr_heap_extract(thread->backlog, request);
				rad_assert(request->heap_id == -1);
				VERIFY_REQUEST(request);

				/*
				 *	Old-style requests get
				 *	processed in-place, and starve
				 *	the async requests. This is a
				 *	hack until we get rid of the
				 *	old-style requests.
				 */
				if (request->listener->old_style) {
					pthread_mutex_unlock(&thread->backlog_mutex);
					thread_process_request(thread, request);
					pthread_mutex_lock(&thread->backlog_mutex);
					continue;
				}

				request->backlog = local_backlog;
				fr_heap_insert(local_backlog, request);
				request->thread_ctx = NULL;

				request->el = el;
				if (fr_event_timer_insert(request->el, max_request_time_hook,
						    request, &when, &request->ev) < 0) {
					REDEBUG("Failed inserting max_request_time");
				}
			} while (request != NULL);

			pthread_mutex_unlock(&thread->backlog_mutex);
		}

		/*
		 *	If there's nothing for us to do, wait to be
		 *	signalled.
		 */
		if (fr_heap_num_elements(local_backlog) == 0) {
			wait_for_event = true;

			DEBUG2("Thread %d waiting to be assigned a request", thread->thread_num);
		} else {
			/*
			 *	Otherwise service the timer and FD
			 *	queues, but return immediately and
			 *	process the backlog.
			 */
			wait_for_event = false;
		}

		/*
		 *	Run until we get a signal.  Any registered
		 *	timer events or FD events will also be
		 *	serviced here.
		 */
		rcode = fr_event_corral(el, wait_for_event);
		if (rcode < 0) {
			ERROR("Thread %d failed waiting for request: %s: Exiting",
			      thread->thread_num, fr_syserror(errno));
			fr_exit(EXIT_FAILURE);
		}

		/*
		 *	It only returns 0 on EINTR.
		 */
		if (rcode == 0) continue;

		DEBUG3("Thread %d processing timers and sockets", thread->thread_num);

		/*
		 *	Timer and/or FD events.  Go service them.
		 */
		fr_event_service(el);

		/*
		 *	The server is exiting.  Don't dequeue any
		 *	requests.
		 */
		if (thread_pool.stop_flag) break;

		/*
		 *	Nothing is runnable.  Go back to draining the
		 *	reader queue, and servicing the timers / FDs.
		 */
		if (fr_heap_num_elements(local_backlog) == 0) continue;

		request = fr_heap_peek(local_backlog);
		rad_assert(request != NULL);
		(void) fr_heap_extract(local_backlog, request);
		rad_assert(request->heap_id == -1);
		VERIFY_REQUEST(request);

		thread_process_request(thread, request);
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

	fr_heap_delete(local_backlog);

	trigger_exec(NULL, NULL, "server.thread.stop", true, NULL);
	thread->status = THREAD_EXITED;

	return NULL;
}

/*
 *	Spawn a new thread, and place it in the thread pool.
 *	Called with the thread mutex locked...
 */
static THREAD_HANDLE *thread_spawn(time_t now, int do_trigger)
{
	int rcode;
	THREAD_HANDLE *thread;

	/*
	 *	Allocate a new thread handle.
	 */
	MEM(thread = talloc_zero(NULL, THREAD_HANDLE));

	thread->thread_num = thread_pool.max_thread_num++; /* @fixme atomic? */
	thread->request_count = 0;
	thread->status = THREAD_NONE;
	thread->timestamp = now;

	if (pipe(thread->pipe_fd) < 0) {
		talloc_free(thread);
		ERROR("Thread create pipe failed: %s",
		      fr_strerror());
		return NULL;
	}

#ifdef F_SETNOSIGPIPE
	rcode = 1;
	(void) fcntl(thread->pipe_fd[0], F_SETNOSIGPIPE, &rcode);
	(void) fcntl(thread->pipe_fd[1], F_SETNOSIGPIPE, &rcode);
	fr_nonblock(thread->pipe_fd[0]);
	fr_nonblock(thread->pipe_fd[1]);
#endif

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

	if ((pthread_mutex_init(&thread->backlog_mutex,NULL) != 0)) {
		talloc_free(thread);
		ERROR("FATAL: Failed to initialize thread backlog mutex: %s",
		       fr_syserror(errno));
		return NULL;
	}

	thread->backlog = fr_heap_create(thread_pool.heap_cmp, offsetof(REQUEST, heap_id));
	if (!thread->backlog) {
		ERROR("FATAL: Failed to initialize thread backlog");
		talloc_free(thread);
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
	rcode = pthread_mutex_init(&thread_pool.thread_mutex, NULL);
	if (rcode != 0) {
		ERROR("FATAL: Failed to initialize thread pool handle mutex: %s",
		       fr_syserror(errno));
		return -1;
	}

	if (pthread_key_create(&thread_pool.thread_handle_key, NULL) != 0) {
		ERROR("Failed creating key for thread");
		return -1;
	}

	/*
	 *	Create a number of waiting threads.  Note we don't
	 *	need to lock the mutex, as nothing is sending
	 *	requests.
	 *
	 *	FIXME: If we fail while creating them, do something intelligent.
	 */
	for (i = 0; i < thread_pool.start_threads; i++) {
		THREAD_HANDLE *thread;

		thread = thread_spawn(now, 0);
		if (!thread) return -1;

		link_list_tail(&thread_pool.thread_head, &thread_pool.thread_tail, thread);

		thread_pool.total_threads++;
	}

	rad_assert(thread_pool.thread_head != NULL);

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

	if (!pool_initialized) return;

	/*
	 *	Set pool stop flag.
	 */
	thread_pool.stop_flag = true;

	for (thread = thread_pool.thread_head; thread; thread = thread->next) {
		thread->status = THREAD_CANCELLED;
		close(thread->pipe_fd[1]);
	}

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
