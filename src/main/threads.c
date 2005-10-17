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

/*
 *	Other OS's have sem_init, OS X doesn't.
 */
#ifndef DARWIN
#include <semaphore.h>
#else
#include <mach/task.h>
#include <mach/semaphore.h>

#undef sem_t
#define sem_t semaphore_t
#undef sem_init
#define sem_init(s,p,c) semaphore_create(mach_task_self(),s,SYNC_POLICY_FIFO,c)
#undef sem_wait
#define sem_wait(s) semaphore_wait(*s)
#undef sem_post
#define sem_post(s) semaphore_signal(*s)
#endif

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


#define MAX_WAITERS (256)
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
	 *	If threaded, we have to pay more attention to
	 *	child PID's when we fork...
	 */
	pthread_mutex_t	wait_mutex;
	int		wait_head;
	int		wait_tail;
	pid_t		wait[MAX_WAITERS];

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
	if (thread_pool.wait_head != thread_pool.wait_tail) {
		int num;
		
		pthread_mutex_lock(&thread_pool.wait_mutex);
		for (num = ((thread_pool.wait_tail + MAX_WAITERS) - thread_pool.wait_head) % MAX_WAITERS;
		     num != 0;
		     num--) {
			pid_t pid = thread_pool.wait[thread_pool.wait_head];
			
			thread_pool.wait_head++;
			thread_pool.wait_head %= MAX_WAITERS;
			
			/*
			 *	Child is still alive: move it to the tail.
			 */
			if (waitpid(pid, NULL, WNOHANG) == 0) {
				if (((thread_pool.wait_tail + 1) % MAX_WAITERS)
				    == thread_pool.wait_head) {
					rad_assert(0 == 1);
				}

				thread_pool.wait[thread_pool.wait_tail] = pid;
				thread_pool.wait_tail++;
				thread_pool.wait_tail %= MAX_WAITERS;
			} /* else no child, or was already reaped */
		}
		pthread_mutex_unlock(&thread_pool.wait_mutex);
	}
}


/*
 *	Add a request to the list of waiting requests.
 *	This function gets called ONLY from the main handler thread...
 *
 *	This function should never fail.
 */
static int request_enqueue(REQUEST *request, RAD_REQUEST_FUNP fun)
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
		int i;
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
			radlog(L_ERR|L_CONS, "!!! ERROR !!! The server is blocked: discarding new request %d", request->number);
			request->finished = TRUE;
			return 0;
		}

		/*
		 *	Malloc a new queue, doubled in size, copy the
		 *	data from the current queue over to it, zero
		 *	out the second half of the queue, free the old
		 *	one, and replace thread_pool.queue with the
		 *	new one.
		 */
		new_queue = rad_malloc(sizeof(*new_queue) * thread_pool.queue_size * 2);
		/*
		 *	Copy the queue element by element
		 */
		for (i = 0; i < thread_pool.queue_size; i++) {
			new_queue[i] = thread_pool.queue[(i + thread_pool.queue_head) % thread_pool.queue_size];
		}
		memset(new_queue + thread_pool.queue_size,
		       0, sizeof(*new_queue) * thread_pool.queue_size);

		free(thread_pool.queue);
		thread_pool.queue = new_queue;
		thread_pool.queue_tail = ((thread_pool.queue_tail + thread_pool.queue_size) - thread_pool.queue_head) % thread_pool.queue_size;
		thread_pool.queue_head = 0;
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

	return 1;
}

/*
 *	Remove a request from the queue.
 */
static void request_dequeue(REQUEST **request, RAD_REQUEST_FUNP *fun)
{
	reap_children();

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

	pthread_mutex_unlock(&thread_pool.mutex);

	/*
	 *	If the request is currently being processed, then that
	 *	MAY be OK, if it's a proxy reply.  In that case,
	 *	sending the packet may result in a reply being
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

		thread_pool.wait_head = thread_pool.wait_tail = 0;
		if ((pthread_mutex_init(&thread_pool.wait_mutex,NULL) != 0)) {
			radlog(L_ERR, "FATAL: Failed to initialize mutex: %s",
			       strerror(errno));
			exit(1);
		}		
	}

	pool_cf = cf_section_find("thread");
	if (pool_cf != NULL) {
		cf_section_parse(pool_cf, NULL, thread_config);
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
	 *	Add the new request to the queue.
	 */
	if (!request_enqueue(request, fun)) return 0;

	/*
	 *	If the thread pool is busy handling requests, then
	 *	try to spawn another one.
	 */
	if (thread_pool.active_threads == thread_pool.total_threads) {
		if (spawn_thread(request->timestamp) == NULL) {
			radlog(L_INFO,
			       "The maximum number of threads (%d) are active, cannot spawn new thread to handle request",
			       thread_pool.max_threads);
			return 1;
		}
	}

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
	static time_t last_cleaned = 0;

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
	 *	Only delete spare threads if we haven't already done
	 *	so this second.
	 */
	if (now == last_cleaned) {
		return 0;
	}
	last_cleaned = now;

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
		 *	first idle thread we come across.
		 */
		for (handle = thread_pool.head; (handle != NULL) && (spare > 0) ; handle = next) {
			next = handle->next;

			/*
			 *	If the thread is not handling a
			 *	request, but still live, then tell it
			 *	to exit.
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


/*
 *	Thread wrapper for fork().
 */
pid_t rad_fork(int exec_wait)
{
	pid_t child_pid;

	if (exec_wait) return fork();

	/*
	 *	Ensure that children are reaped always.
	 */
	reap_children();

	/*
	 *	Lock the mutex.
	 */
	pthread_mutex_lock(&thread_pool.wait_mutex);

	/*
	 *	No room to save the PID: die.
	 */
	if (((thread_pool.wait_tail + 1) % MAX_WAITERS)
	    == thread_pool.wait_head) {
		rad_assert(0 == 1);
	}

	/*
	 *	Fork & save the PID for later reaping.
	 */
	child_pid = fork();
	if (child_pid != 0) {
		thread_pool.wait[thread_pool.wait_tail] = child_pid;
		thread_pool.wait_tail++;
		thread_pool.wait_tail %= MAX_WAITERS;

		/*
		 *	Unlock the mutex.
		 */
		pthread_mutex_unlock(&thread_pool.wait_mutex);
	}

	/*
	 *	Return whatever we were told.
	 */
	return child_pid;
}


/*
 *	We may not need this any more...
 */
pid_t rad_waitpid(pid_t pid, int *status, int options)
{
	reap_children();	/* be nice to non-wait thingies */
	return waitpid(pid, status, options);
	
}

#endif
