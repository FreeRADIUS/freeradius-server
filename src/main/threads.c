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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2000  The FreeRADIUS server project
 * Copyright 2000  Alan DeKok <aland@ox.org>
 */

#include "libradius.h"

#ifdef HAVE_PTHREAD_H

#include <stdlib.h>
#include <string.h>
#include <semaphore.h>
#include <signal.h>

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#include "radiusd.h"
#include "rad_assert.h"
#include "conffile.h"

static const char rcsid[] =
"$Id$";

#define SEMAPHORE_LOCKED	(0)
#define SEMAPHORE_UNLOCKED	(1)

#define THREAD_RUNNING		(1)
#define THREAD_CANCELLED	(2)
#define THREAD_EXITED		(3)

/*
 *  A data structure which contains the information about
 *  the current thread.
 *
 *  pthread_id     pthread id
 *  thread_num     server thread number, 1...number of threads
 *  semaphore     used to block the thread until a request comes in
 *  status        is the thread running or exited?
 *  request_count the number of requests that this thread has handled
 *  timestamp     when the thread started executing.
 */
typedef struct THREAD_HANDLE {
	struct THREAD_HANDLE *prev;
	struct THREAD_HANDLE *next;
	pthread_t            pthread_id;
	int                  thread_num;
	int                  status;
	unsigned int         request_count;
	time_t               timestamp;
	REQUEST		     *request;
} THREAD_HANDLE;

/*
 *	For the request queue.
 */
typedef struct request_queue_t {
	REQUEST	    	  *request;
	RAD_REQUEST_FUNP  fun;
} request_queue_t;


/*
 *	A data structure to manage the thread pool.  There's no real
 *	need for a data structure, but it makes things conceptually
 *	easier.
 */
typedef struct THREAD_POOL {
	THREAD_HANDLE *head;
	THREAD_HANDLE *tail;

	int total_threads;
	int max_thread_num;
	int start_threads;
	int max_threads;
	int min_spare_threads;
	int max_spare_threads;
	unsigned int max_requests_per_thread;
	unsigned long request_count;
	time_t time_last_spawned;
	int cleanup_delay;

	/*
	 *	All threads wait on this semaphore, for requests
	 *	to enter the queue.
	 */
	sem_t		semaphore;

	/*
	 *	To ensure only one thread at a time touches the queue.
	 */
	pthread_mutex_t	mutex;

	int		active_threads;
	int		queue_head; /* first filled entry */
	int		queue_tail; /* first empty entry */
	int		queue_size;
	request_queue_t *queue;
} THREAD_POOL;

static THREAD_POOL thread_pool;
static int pool_initialized = FALSE;

/*
 *	Data structure to keep track of which child forked which
 *	request.  If we cared, we'd keep a list of "free" and "active"
 *	entries.
 *
 *	FIXME: Have a time out, so we clean up entries which haven't
 *	been picked up!
 */
typedef struct rad_fork_t {
	pthread_t	thread_id;
	pid_t		child_pid;
	sem_t	 	child_done;
	int		status;	/* exit status of the child */
	time_t		time_forked;
} rad_fork_t;

/*
 *  This MUST be a power of 2 for it to work properly!
 */
#define NUM_FORKERS (8192)
static rad_fork_t forkers[NUM_FORKERS];

/*
 *	This mutex ensures that only one thread is doing certain
 *	kinds of magic to the previous array.
 */
static pthread_mutex_t fork_mutex;


/*
 *	A mapping of configuration file names to internal integers
 */
static const CONF_PARSER thread_config[] = {
	{ "start_servers",           PW_TYPE_INTEGER, 0, &thread_pool.start_threads,           "5" },
	{ "max_servers",             PW_TYPE_INTEGER, 0, &thread_pool.max_threads,             "32" },
	{ "min_spare_servers",       PW_TYPE_INTEGER, 0, &thread_pool.min_spare_threads,       "3" },
	{ "max_spare_servers",       PW_TYPE_INTEGER, 0, &thread_pool.max_spare_threads,       "10" },
	{ "max_requests_per_server", PW_TYPE_INTEGER, 0, &thread_pool.max_requests_per_thread, "0" },
	{ "cleanup_delay",           PW_TYPE_INTEGER, 0, &thread_pool.cleanup_delay,           "5" },
	{ NULL, -1, 0, NULL, NULL }
};


/*
 *	Add a request to the list of waiting requests.
 *	This function gets called ONLY from the main handler thread...
 *
 *	This function should never fail.
 *
 *	FIXME: implement some kind of "maximum #" for the waiting
 *	requests...
 */
static void request_enqueue(REQUEST *request, RAD_REQUEST_FUNP fun)
{
	int num_entries;

	pthread_mutex_lock(&thread_pool.mutex);

	thread_pool.request_count++;

	/*
	 *	If the queue is empty, re-set the indices to zero,
	 *	for no particular reason...
	 */
	if ((thread_pool.queue_head == thread_pool.queue_tail) &&
	    (thread_pool.queue_head != 0)) {
		thread_pool.queue_head = thread_pool.queue_tail = 0;
	}

	/*
	 *	If the queue is full, die.
	 *
	 *	The math is to take into account the fact that it's a
	 *	circular queue.
	 */
	num_entries = ((thread_pool.queue_tail + thread_pool.queue_size) -
		       thread_pool.queue_head) % thread_pool.queue_size;
	if (num_entries == (thread_pool.queue_size - 1)) {
		request_queue_t *new_queue;

		/*
		 *	If the queue becomes larger than 65536,
		 *	there's a serious problem.
		 */
		if (thread_pool.queue_size >= 65536) {
			pthread_mutex_unlock(&thread_pool.mutex);

			/*
			 *	Mark the request as done.
			 */
			DEBUG("  ERROR! SERVER IS BLOCKED: Discarding new request %d", request->number);
			
			request->finished = TRUE;
			return;
		}

		/*
		 *	Malloc a new queue, doubled in size, copy the
		 *	data from the current queue over to it, zero
		 *	out the second half of the queue, free the old
		 *	one, and replace thread_pool.queue with the
		 *	new one.
		 */
		new_queue = rad_malloc(sizeof(*new_queue) * thread_pool.queue_size * 2);
		memcpy(new_queue, thread_pool.queue,
		       sizeof(*new_queue) * thread_pool.queue_size);
		memset(new_queue + sizeof(*new_queue) * thread_pool.queue_size,
		       0, sizeof(*new_queue) * thread_pool.queue_size);

		free(thread_pool.queue);
		thread_pool.queue = new_queue;
		thread_pool.queue_size *= 2;
	}

	/*
	 *	Add the data to the queue tail, increment the tail,
	 *	and signal the semaphore that there's another request
	 *	in the queue.
	 */
	thread_pool.queue[thread_pool.queue_tail].request = request;
	thread_pool.queue[thread_pool.queue_tail].fun = fun;
	thread_pool.queue_tail++;
	thread_pool.queue_tail &= (thread_pool.queue_size - 1);

	pthread_mutex_unlock(&thread_pool.mutex);

	/*
	 *	There's one more request in the queue.
	 *
	 *	Note that we're not touching the queue any more, so
	 *	the semaphore post is outside of the mutex.  This also
	 *	means that when the thread wakes up and tries to lock
	 *	the mutex, it will be unlocked, and there won't be
	 *	contention.
	 */

	sem_post(&thread_pool.semaphore);

	return;
}

/*
 *	Remove a request from the queue.
 */
static void request_dequeue(REQUEST **request, RAD_REQUEST_FUNP *fun)
{
	pthread_mutex_lock(&thread_pool.mutex);

	/*
	 *	Head & tail are the same.  There's nothing in
	 *	the queue.
	 */
	if (thread_pool.queue_head == thread_pool.queue_tail) {
		pthread_mutex_unlock(&thread_pool.mutex);
		*request = NULL;
		*fun = NULL;
		return;
	}

	*request = thread_pool.queue[thread_pool.queue_head].request;
	*fun = thread_pool.queue[thread_pool.queue_head].fun;

	rad_assert(*request != NULL);
	rad_assert((*request)->magic == REQUEST_MAGIC);
	rad_assert(*fun != NULL);

	thread_pool.queue_head++;
	thread_pool.queue_head &= (thread_pool.queue_size - 1);

	/*
	 *	FIXME: Check the request timestamp.  If it's more than
	 *	"clean_delay" seconds old, then discard the request,
	 *	log an error, and try to de-queue another request.
	 *
	 *	The main clean-up code won't delete the request from
	 *	the request list, because it's not marked "finished"
	 */

	/*
	 *	The thread is currently processing a request.
	 */
	thread_pool.active_threads++;

	/*
	 *	Just to be paranoid...
	 */
	rad_assert(thread_pool.active_threads <= thread_pool.total_threads);

	pthread_mutex_unlock(&thread_pool.mutex);

	/*
	 *	If the request is currently being processed, then that
	 *	MAY be OK, if it's a proxy reply.  In that case, the
	 *	rad_send() of the packet may result in a reply being
	 *	received before that thread clears the child_pid.
	 *
	 *	In that case, we busy-wait for the request to be free.
	 *
	 *	We COULD push it onto the queue and try to grab
	 *	another request, but what if this is the only request?
	 *	What if there are multiple such packets with race
	 *	conditions?  We don't want to thrash the queue...
	 *
	 *	This busy-wait is less than optimal, but it's simple,
	 *	fail-safe, and it works.
	 */
	if ((*request)->child_pid != NO_SUCH_CHILD_PID) {
		int count, ok;
		struct timeval tv;
#ifdef HAVE_PTHREAD_SIGMASK
		sigset_t set, old_set;

		/*
		 *	Block a large number of signals which could
		 *	cause the select to return EINTR
		 */
		sigemptyset(&set);
		sigaddset(&set, SIGPIPE);
		sigaddset(&set, SIGCONT);
		sigaddset(&set, SIGSTOP);
		sigaddset(&set, SIGCHLD);
		pthread_sigmask(SIG_BLOCK, &set, &old_set);
#endif

		rad_assert((*request)->proxy_reply != NULL);

		ok = FALSE;

		/*
		 *	Sleep for 100 milliseconds.  If the other thread
		 *	doesn't get serviced in this time, to clear
		 *	the "child_pid" entry, then the server is too
		 *	busy, so we die.
		 */
		for (count = 0; count < 10; count++) {
			tv.tv_sec = 0;
			tv.tv_usec = 10000; /* sleep for 10 milliseconds */

			/*
			 *	Portable sleep that's thread-safe.
			 *
			 *	Don't worry about interrupts, as they're
			 *	blocked above.
			 */
			select(0, NULL, NULL, NULL, &tv);
			if ((*request)->child_pid == NO_SUCH_CHILD_PID) {
				ok = TRUE;
				break;
			}
		}

#ifdef HAVE_PTHREAD_SIGMASK
		/*
		 *	Restore the original thread signal mask.
		 */
		pthread_sigmask(SIG_SETMASK, &old_set, NULL);
#endif

		if (!ok) {
			radlog(L_ERR, "FATAL!  Server is too busy to process requests");
			exit(1);
		}
	}

	return;
}


/*
 *	The main thread handler for requests.
 *
 *	Wait on the semaphore until we have it, and process the request.
 */
static void *request_handler_thread(void *arg)
{
	RAD_REQUEST_FUNP  fun;
	THREAD_HANDLE	  *self = (THREAD_HANDLE *) arg;
#ifdef HAVE_PTHREAD_SIGMASK
	sigset_t set;

	/*
	 *	Block SIGHUP handling for the child threads.
	 *
	 *	This ensures that only the main server thread will
	 *	process HUP signals.
	 *
	 *	If we don't have sigprocmask, then it shouldn't be
	 *	a problem, either, as the sig_hup handler should check
	 *	for this condition.
	 */
	sigemptyset(&set);
	sigaddset(&set, SIGHUP);
	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGQUIT);
	sigaddset(&set, SIGTERM);
	pthread_sigmask(SIG_BLOCK, &set, NULL);
#endif

	/*
	 *	Loop forever, until told to exit.
	 */
	do {
		/*
		 *	Wait to be signalled.
		 */
		DEBUG2("Thread %d waiting to be assigned a request",
		       self->thread_num);
	re_wait:
		if (sem_wait(&thread_pool.semaphore) != 0) {
			/*
			 *	Interrupted system call.  Go back to
			 *	waiting, but DON'T print out any more
			 *	text.
			 */
			if (errno == EINTR) {
				DEBUG2("Re-wait %d", self->thread_num);
				goto re_wait;
			}
			radlog(L_ERR, "Thread %d failed waiting for semaphore: %s: Exiting\n",
			       self->thread_num, strerror(errno));
			break;
		}

		DEBUG2("Thread %d got semaphore", self->thread_num);

		/*
		 *	Try to grab a request from the queue.
		 *
		 *	It may be empty, in which case we fail
		 *	gracefully.
		 */
		request_dequeue(&self->request, &fun);
		if (!self->request) continue;

		self->request->child_pid = self->pthread_id;
		self->request_count++;

		DEBUG2("Thread %d handling request %d, (%d handled so far)",
		       self->thread_num, self->request->number,
		       self->request_count);

		/*
		 *	Respond, and reset request->child_pid
		 */
		rad_respond(self->request, fun);
		self->request = NULL;

		/*
		 *	Update the active threads.
		 */
		pthread_mutex_lock(&thread_pool.mutex);
		rad_assert(thread_pool.active_threads > 0);
		thread_pool.active_threads--;
		pthread_mutex_unlock(&thread_pool.mutex);
	} while (self->status != THREAD_CANCELLED);

	DEBUG2("Thread %d exiting...", self->thread_num);

	/*
	 *  Do this as the LAST thing before exiting.
	 */
	self->status = THREAD_EXITED;

	return NULL;
}

/*
 *	Take a THREAD_HANDLE, and delete it from the thread pool.
 *
 *	This function is called ONLY from the main server thread.
 */
static void delete_thread(THREAD_HANDLE *handle)
{
	THREAD_HANDLE *prev;
	THREAD_HANDLE *next;

	rad_assert(handle->request == NULL);

	prev = handle->prev;
	next = handle->next;
	rad_assert(thread_pool.total_threads > 0);
	thread_pool.total_threads--;

	/*
	 *	Remove the handle from the list.
	 */
	if (prev == NULL) {
		rad_assert(thread_pool.head == handle);
		thread_pool.head = next;
	} else {
		prev->next = next;
	}

	if (next == NULL) {
		rad_assert(thread_pool.tail == handle);
		thread_pool.tail = prev;
	} else {
		next->prev = prev;
	}

	DEBUG2("Deleting thread %d", handle->thread_num);

	/*
	 *	This thread has exited.  Delete any additional
	 *	resources associated with it.
	 */

	/*
	 *	Free the memory, now that we're sure the thread
	 *	exited.
	 */
	free(handle);
}


/*
 *	Spawn a new thread, and place it in the thread pool.
 *
 *	The thread is started initially in the blocked state, waiting
 *	for the semaphore.
 */
static THREAD_HANDLE *spawn_thread(time_t now)
{
	int rcode;
	THREAD_HANDLE *handle;
	pthread_attr_t attr;

	/*
	 *	Ensure that we don't spawn too many threads.
	 */
	if (thread_pool.total_threads >= thread_pool.max_threads) {
		DEBUG2("Thread spawn failed.  Maximum number of threads (%d) already running.", thread_pool.max_threads);
		return NULL;
	}

	/*
	 *	Allocate a new thread handle.
	 */
	handle = (THREAD_HANDLE *) rad_malloc(sizeof(THREAD_HANDLE));
	memset(handle, 0, sizeof(THREAD_HANDLE));
	handle->prev = NULL;
	handle->next = NULL;
	handle->pthread_id = NO_SUCH_CHILD_PID;
	handle->thread_num = thread_pool.max_thread_num++;
	handle->request_count = 0;
	handle->status = THREAD_RUNNING;
	handle->timestamp = time(NULL);

	/*
	 *	Initialize the thread's attributes to detached.
	 *
	 *	We could call pthread_detach() later, but if the thread
	 *	exits between the create & detach calls, it will need to
	 *	be joined, which will never happen.
	 */
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	/*
	 *	Create the thread detached, so that it cleans up it's
	 *	own memory when it exits.
	 *
	 *	Note that the function returns non-zero on error, NOT
	 *	-1.  The return code is the error, and errno isn't set.
	 */
	rcode = pthread_create(&handle->pthread_id, &attr,
			request_handler_thread, handle);
	if (rcode != 0) {
		radlog(L_ERR|L_CONS, "FATAL: Thread create failed: %s",
		       strerror(rcode));
		exit(1);
	}
	pthread_attr_destroy(&attr);

	/*
	 *	One more thread to go into the list.
	 */
	thread_pool.total_threads++;
	DEBUG2("Thread spawned new child %d. Total threads in pool: %d",
			handle->thread_num, thread_pool.total_threads);

	/*
	 *	Add the thread handle to the tail of the thread pool list.
	 */
	if (thread_pool.tail) {
		thread_pool.tail->next = handle;
		handle->prev = thread_pool.tail;
		thread_pool.tail = handle;
	} else {
		rad_assert(thread_pool.head == NULL);
		thread_pool.head = thread_pool.tail = handle;
	}

	/*
	 *	Update the time we last spawned a thread.
	 */
	thread_pool.time_last_spawned = now;

	/*
	 *	And return the new handle to the caller.
	 */
	return handle;
}

/*
 *      Temporary function to prevent server from executing a SIGHUP
 *      until all threads are finished handling requests.  This returns
 *      the number of active threads to 'radiusd.c'.
 */
int total_active_threads(void)
{
        int rcode = 0;
	THREAD_HANDLE *handle;

	for (handle = thread_pool.head; handle != NULL; handle = handle->next){
		if (handle->request != NULL) {
			rcode ++;
		}
	}
	return (rcode);
}

/*
 *	Allocate the thread pool, and seed it with an initial number
 *	of threads.
 *
 *	FIXME: What to do on a SIGHUP???
 */
int thread_pool_init(void)
{
	int		i, rcode;
	CONF_SECTION	*pool_cf;
	time_t		now;

	DEBUG("Initializing the thread pool...");
	now = time(NULL);

	/*
	 *	After a SIGHUP, we don't over-write the previous values.
	 */
	if (!pool_initialized) {
		/*
		 *	Initialize the thread pool to some reasonable values.
		 */
		memset(&thread_pool, 0, sizeof(THREAD_POOL));
		thread_pool.head = NULL;
		thread_pool.tail = NULL;
		thread_pool.total_threads = 0;
		thread_pool.max_thread_num = 1;
		thread_pool.cleanup_delay = 5;
	}

	pool_cf = cf_section_find("thread");
	if (pool_cf != NULL) {
		cf_section_parse(pool_cf, NULL, thread_config);
	}

	/*
	 *	Limit the maximum number of threads to the maximum
	 *	number of forks we can do.
	 *
	 *	FIXME: Make this code better...
	 */
	if (thread_pool.max_threads >= NUM_FORKERS) {
		thread_pool.max_threads = NUM_FORKERS;
	}


	/*
	 *	The pool has already been initialized.  Don't spawn
	 *	new threads, and don't forget about forked children,
	 */
	if (pool_initialized) {
		return 0;
	}

	/*
	 *	Initialize the queue of requests.
	 */
	rcode = sem_init(&thread_pool.semaphore, 0, SEMAPHORE_LOCKED);
	if (rcode != 0) {
		radlog(L_ERR|L_CONS, "FATAL: Failed to initialize semaphore: %s",
		       strerror(errno));
		exit(1);
	}

	rcode = pthread_mutex_init(&thread_pool.mutex,NULL);
	if (rcode != 0) {
		radlog(L_ERR, "FATAL: Failed to initialize mutex: %s",
		       strerror(errno));
		exit(1);
	}

	/*
	 *	Queue head & tail are set to zero by the memset,
	 *	above.
	 *
	 *	Allocate an initial queue, always as a power of 2.
	 */
	thread_pool.queue_size = 256;
	thread_pool.queue = rad_malloc(sizeof(*thread_pool.queue) *
				       thread_pool.queue_size);
	memset(thread_pool.queue, 0, (sizeof(*thread_pool.queue) *
				      thread_pool.queue_size));

	/*
	 *	Create a number of waiting threads.
	 *
	 *	If we fail while creating them, do something intelligent.
	 */
	for (i = 0; i < thread_pool.start_threads; i++) {
		if (spawn_thread(now) == NULL) {
			return -1;
		}
	}

	DEBUG2("Thread pool initialized");
	pool_initialized = TRUE;
	return 0;
}


/*
 *	Assign a new request to a free thread.
 *
 *	If there isn't a free thread, then try to create a new one,
 *	up to the configured limits.
 */
int thread_pool_addrequest(REQUEST *request, RAD_REQUEST_FUNP fun)
{
	/*
	 *	If the thread pool is busy handling requests, then
	 *	try to spawn another one.
	 */
	if (thread_pool.active_threads == thread_pool.total_threads) {
		if (spawn_thread(request->timestamp) == NULL) {
			radlog(L_INFO,
			       "The maximum number of threads (%d) are active, cannot spawn new thread to handle request",
			       thread_pool.max_threads);
			return 0;
		}
	}

	/*
	 *	Add the new request to the queue.
	 */
	request_enqueue(request, fun);

	return 1;
}

/*
 *	Check the min_spare_threads and max_spare_threads.
 *
 *	If there are too many or too few threads waiting, then we
 *	either create some more, or delete some.
 */
int thread_pool_clean(time_t now)
{
	int spare;
	int i, total;
	THREAD_HANDLE *handle, *next;
	int active_threads;

	/*
	 *	Loop over the thread pool deleting exited threads.
	 */
	for (handle = thread_pool.head; handle; handle = next) {
		next = handle->next;

		/*
		 *	Maybe we've asked the thread to exit, and it
		 *	has agreed.
		 */
		if (handle->status == THREAD_EXITED) {
			delete_thread(handle);
		}
	}

	/*
	 *	We don't need a mutex lock here, as we're reading
	 *	the location, and not modifying it.  We want a close
	 *	approximation of the number of active threads, and this
	 *	is good enough.
	 */
	active_threads = thread_pool.active_threads;
	spare = thread_pool.total_threads - active_threads;
	if (debug_flag) {
		static int old_total = -1;
		static int old_active = -1;

		if ((old_total != thread_pool.total_threads) ||
				(old_active != active_threads)) {
			DEBUG2("Threads: total/active/spare threads = %d/%d/%d",
					thread_pool.total_threads, active_threads, spare);
			old_total = thread_pool.total_threads;
			old_active = active_threads;
		}
	}

	/*
	 *	If there are too few spare threads, create some more.
	 */
	if (spare < thread_pool.min_spare_threads) {
		total = thread_pool.min_spare_threads - spare;

		DEBUG2("Threads: Spawning %d spares", total);
		/*
		 *	Create a number of spare threads.
		 */
		for (i = 0; i < total; i++) {
			handle = spawn_thread(now);
			if (handle == NULL) {
				return -1;
			}
		}

		/*
		 *	And exit, as there can't be too many spare threads.
		 */
		return 0;
	}

	/*
	 *	Only delete the spare threads if sufficient time has
	 *	passed since we last created one.  This helps to minimize
	 *	the amount of create/delete cycles.
	 */
	if ((now - thread_pool.time_last_spawned) < thread_pool.cleanup_delay) {
		return 0;
	}

	/*
	 *	If there are too many spare threads, delete one.
	 *
	 *	Note that we only delete ONE at a time, instead of
	 *	wiping out many.  This allows the excess servers to
	 *	be slowly reaped, just in case the load spike comes again.
	 */
	if (spare > thread_pool.max_spare_threads) {

		spare -= thread_pool.max_spare_threads;

		DEBUG2("Threads: deleting 1 spare out of %d spares", spare);

		/*
		 *	Walk through the thread pool, deleting the
		 *	first N idle threads we come across.
		 */
		for (handle = thread_pool.head; (handle != NULL) && (spare > 0) ; handle = next) {
			next = handle->next;

			/*
			 *	If the thread is not handling a
			 *	request, but still live, then tell
			 *	it to exit.
			 *
			 *	It will eventually wake up, and realize
			 *	it's been told to commit suicide.
			 */
			if ((handle->request == NULL) &&
			    (handle->status == THREAD_RUNNING)) {
				handle->status = THREAD_CANCELLED;
				/*
				 *	Post an extra semaphore, as a
				 *	signal to wake up, and exit.
				 */
				sem_post(&thread_pool.semaphore);
				spare--;
				break;
			}
		}
	}

	/*
	 *	If the thread has handled too many requests, then make it
	 *	exit.
	 */
	if (thread_pool.max_requests_per_thread > 0) {
		for (handle = thread_pool.head; handle; handle = next) {
			next = handle->next;

			/*
			 *	Not handling a request, but otherwise
			 *	live, we can kill it.
			 */
			if ((handle->request == NULL) &&
			    (handle->status == THREAD_RUNNING) &&
			    (handle->request_count > thread_pool.max_requests_per_thread)) {
				handle->status = THREAD_CANCELLED;
				sem_post(&thread_pool.semaphore);
			}
		}
	}

	/*
	 *	Otherwise everything's kosher.  There are not too few,
	 *	or too many spare threads.  Exit happily.
	 */
	return 0;
}

static int exec_initialized = FALSE;

/*
 *	Initialize the stuff for keeping track of child processes.
 */
void rad_exec_init(void)
{
	int i;

	/*
	 *	Initialize the mutex used to remember calls to fork.
	 */
	pthread_mutex_init(&fork_mutex, NULL);

	/*
	 *	Initialize the data structure where we remember the
	 *	mappings of thread ID && child PID to exit status.
	 */
	for (i = 0; i < NUM_FORKERS; i++) {
		forkers[i].thread_id = NO_SUCH_CHILD_PID;
		forkers[i].child_pid = -1;
		forkers[i].status = 0;
	}

	exec_initialized = TRUE;
}

/*
 *	We use the PID number as a base for the array index, so that
 *	we can quickly turn the PID into a free array entry, instead
 *	of rooting blindly through the entire array.
 */
#define PID_2_ARRAY(pid) (((int) pid ) & (NUM_FORKERS - 1))

/*
 *	Thread wrapper for fork().
 */
pid_t rad_fork(int exec_wait)
{
	sigset_t set;
	pid_t child_pid;

	/*
	 *	The thread is NOT interested in waiting for the exit
	 *	status of the child process, so we don't bother
	 *	updating our kludgy array.
	 *
	 *	Or, there no NO threads, so we can just do the fork
	 *	thing.
	 */
	if (!exec_wait || !exec_initialized) {
		return fork();
	}

	/*
	 *	Block SIGCLHD until such time as we've saved the PID.
	 *
	 *	Note that we block SIGCHLD for ALL threads associated
	 *	with this process!  This is to prevent race conditions!
	 */
	sigemptyset(&set);
	sigaddset(&set, SIGCHLD);
	sigprocmask(SIG_BLOCK, &set, NULL);

	/*
	 *	Do the fork.
	 */
	child_pid = fork();

	/*
	 *	We managed to fork.  Let's see if we have a free
	 *	array entry.
	 */
	if (child_pid > 0) { /* parent */
		int i;
		int found;
		time_t now = time(NULL);

		/*
		 *	We store the information in the array
		 *	indexed by PID.  This means that we have
		 *	on average an O(1) lookup to find the element,
		 *	instead of rooting through the entire array.
		 */
		i = PID_2_ARRAY(child_pid);
		found = -1;

		/*
		 *	We may have multiple threads trying to find an
		 *	empty position, so we lock the array until
		 *	we've found an entry.
		 */
		pthread_mutex_lock(&fork_mutex);
		do {
			if (forkers[i].thread_id == NO_SUCH_CHILD_PID) {
				found = i;
				break;
			}

			/*
			 *	Clean up any stale forked sessions.
			 *
			 *	This sometimes happens, for crazy reasons.
			 */
			if ((now - forkers[i].time_forked) > 30) {
				forkers[i].thread_id = NO_SUCH_CHILD_PID;

				/*
				 *	Grab the child's exit condition,
				 *	just in case...
				 */
				waitpid(forkers[i].child_pid,
					&forkers[i].status,
					WNOHANG);
				sem_destroy(&forkers[i].child_done);
				found = i;
				break;
			}

			/*
			 *  Increment it, within the array.
			 */
			i++;
			i &= (NUM_FORKERS - 1);
		} while (i != PID_2_ARRAY(child_pid));
		pthread_mutex_unlock(&fork_mutex);

		/*
		 *	Arg.  We did a fork, and there was nowhere to
		 *	put the answer.
		 */
		if (found < 0) {
			return (pid_t) -1;
		}

		/*
		 *	In the parent, set the status, and create the
		 *	semaphore.
		 */
		forkers[found].status = -1;
		forkers[found].child_pid = child_pid;
		forkers[i].thread_id = pthread_self();
		forkers[i].time_forked = now;
		sem_init(&forkers[found].child_done, 0, SEMAPHORE_LOCKED);
	}

	/*
	 *	Unblock SIGCHLD, now that there's no chance of bad entries
	 *	in the array.
	 */
	sigprocmask(SIG_UNBLOCK, &set, NULL);

	/*
	 *	Return whatever we were told.
	 */
	return child_pid;
}

/*
 *	Thread wrapper for waitpid(), so threads can wait for
 *	the PID they forked.
 */
pid_t rad_waitpid(pid_t pid, int *status, int options)
{
	int i, rcode;
	int found;
	pthread_t self = pthread_self();

	/*
	 *	We're only allowed to wait for a SPECIFIC pid.
	 */
	if (pid <= 0) {
		return -1;
	}

	/*
	 *	Find the PID to wait for, starting at an index within
	 *	the array.  This makes the lookups O(1) on average,
	 *	instead of O(n), when the array is filling up.
	 */
	found = -1;
	i = PID_2_ARRAY(pid);
	do {
		/*
		 *	We were the ones who forked this specific
		 *	child.
		 */
		if ((forkers[i].thread_id == self) &&
		    (forkers[i].child_pid == pid)) {
			found = i;
			break;
		}

		i++;
		i &= (NUM_FORKERS - 1);
	} while (i != PID_2_ARRAY(pid));

	/*
	 *	No thread ID found: we're trying to wait for a child
	 *	we've never forked!
	 */
	if (found < 0) {
		return -1;
	}

	/*
	 *	Wait for the signal that the child's status has been
	 *	returned.
	 */
	if (options == WNOHANG) {
		rcode = sem_trywait(&forkers[found].child_done);
		if (rcode != 0) {
			return 0; /* no child available */
		}
	} else {		/* wait forever */
	re_wait:
		rcode = sem_wait(&forkers[found].child_done);
		if ((rcode != 0) && (errno == EINTR)) {
			goto re_wait;
		}
	}

	/*
	 *	We've got the semaphore.  Now destroy it.
	 *
	 *	FIXME: Maybe we want to set up the semaphores in advance,
	 *	to prevent the creation && deletion of lots of them,
	 *	if creating and deleting them is expensive.
	 */
	sem_destroy(&forkers[found].child_done);

	/*
	 *	Save the status BEFORE we re-set the thread ID.
	 */
	*status = forkers[found].status;

	/*
	 *	This next line taints the other array entries,
	 *	due to other threads re-using the data structure.
	 */
	forkers[found].thread_id = NO_SUCH_CHILD_PID;

	return pid;
}

/*
 *	Called by the main signal handler, to save the status of the child
 */
int rad_savepid(pid_t pid, int status)
{
	int i;

	/*
	 *	Find the PID to wait for, starting at an index within
	 *	the array.  This makes the lookups O(1) on average,
	 *	instead of O(n), when the array is filling up.
	 */
	i = PID_2_ARRAY(pid);

	/*
	 *	Do NOT lock the array, as nothing else sets the
	 *	status and posts the semaphore.
	 */
	do {
		/*
		 *	Any thread can get the sigchild...
		 */
		if ((forkers[i].thread_id != NO_SUCH_CHILD_PID) &&
		    (forkers[i].child_pid == pid)) {
			/*
			 *	Save the status, THEN post the
			 *	semaphore.
			 */
			forkers[i].status = status;
			sem_post(&forkers[i].child_done);

			/*
			 *	FIXME: If the child is more than 60
			 *	seconds out of date, then delete it.
			 *
			 *	That is, we've forked, and the forker
			 *	is waiting nearly forever
			 */
			return 0;
		}

		i++;
		i &= (NUM_FORKERS - 1);
	} while (i != PID_2_ARRAY(pid));

	return -1;
}
#endif
