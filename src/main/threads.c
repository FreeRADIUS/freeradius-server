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

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/autoconf.h>

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

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>
#include <freeradius-devel/modules.h>

#ifdef HAVE_PTHREAD_H

#ifdef HAVE_OPENSSL_CRYPTO_H
#include <openssl/crypto.h>
#endif
#ifdef HAVE_OPENSSL_ERR_H
#include <openssl/err.h>
#endif

#define SEMAPHORE_LOCKED	(0)
#define SEMAPHORE_UNLOCKED	(1)

#define THREAD_RUNNING		(1)
#define THREAD_CANCELLED	(2)
#define THREAD_EXITED		(3)

#define NUM_FIFOS               (2)

/*
 *     Ordered this way because we prefer proxy, then ongoing, then
 *     start.
 */
#define FIFO_START   (1)
#define FIFO_PROXY   (0)

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

typedef struct thread_fork_t {
	pid_t		pid;
	int		status;
	int		exited;
} thread_fork_t;


/*
 *	A data structure to manage the thread pool.  There's no real
 *	need for a data structure, but it makes things conceptually
 *	easier.
 */
typedef struct THREAD_POOL {
	THREAD_HANDLE *head;
	THREAD_HANDLE *tail;

	int total_threads;
	int active_threads;	/* protected by queue_mutex */
	int max_thread_num;
	int start_threads;
	int max_threads;
	int min_spare_threads;
	int max_spare_threads;
	unsigned int max_requests_per_thread;
	unsigned long request_count;
	time_t time_last_spawned;
	int cleanup_delay;
	int spawn_flag;

	pthread_mutex_t	wait_mutex;
	lrad_hash_table_t *waiters;

	/*
	 *	All threads wait on this semaphore, for requests
	 *	to enter the queue.
	 */
	sem_t		semaphore;

	/*
	 *	To ensure only one thread at a time touches the queue.
	 */
	pthread_mutex_t	queue_mutex;

	int		max_queue_size;
	int		num_queued;
	int		fifo_state;
	lrad_fifo_t	*fifo[NUM_FIFOS];
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
	{ "max_queue_size",          PW_TYPE_INTEGER, 0, &thread_pool.max_queue_size,           "65536" },
	{ NULL, -1, 0, NULL, NULL }
};


#ifdef HAVE_OPENSSL_CRYPTO_H

/*
 *	If we're linking against OpenSSL, then it is the
 *	duty of the application, if it is multithreaded,
 *	to provide OpenSSL with appropriate thread id
 *	and mutex locking functions
 *
 *	Note: this only implements static callbacks.
 *	OpenSSL does not use dynamic locking callbacks
 *	right now, but may in the futiure, so we will have
 *	to add them at some point.
 */

static pthread_mutex_t *ssl_mutexes = NULL;

static unsigned long ssl_id_function(void)
{
	return (unsigned long) pthread_self();
}

static void ssl_locking_function(int mode, int n, const char *file, int line)
{
	file = file;		/* -Wunused */
	line = line;		/* -Wunused */

	if (mode & CRYPTO_LOCK) {
		pthread_mutex_lock(&(ssl_mutexes[n]));
	} else {
		pthread_mutex_unlock(&(ssl_mutexes[n]));
	}
}

static int setup_ssl_mutexes(void)
{
	int i;

	ssl_mutexes = rad_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
	if (!ssl_mutexes) {
		radlog(L_ERR, "Error allocating memory for SSL mutexes!");
		return 0;
	}

	for (i = 0; i < CRYPTO_num_locks(); i++) {
		pthread_mutex_init(&(ssl_mutexes[i]), NULL);
	}

	CRYPTO_set_id_callback(ssl_id_function);
	CRYPTO_set_locking_callback(ssl_locking_function);

	return 1;
}
#endif


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

	if (lrad_hash_table_num_elements(thread_pool.waiters) == 0) return;

	pthread_mutex_lock(&thread_pool.wait_mutex);

	while (1) {
		pid = waitpid(0, &status, WNOHANG);
		if (pid <= 0) break;

		mytf.pid = pid;
		tf = lrad_hash_table_finddata(thread_pool.waiters, &mytf);
		if (!tf) continue;
		
		tf->status = status;
		tf->exited = 1;
	}

	pthread_mutex_unlock(&thread_pool.wait_mutex);
}

/*
 *	Add a request to the list of waiting requests.
 *	This function gets called ONLY from the main handler thread...
 *
 *	This function should never fail.
 */
static int request_enqueue(REQUEST *request, RAD_REQUEST_FUNP fun)
{
	int fifo = FIFO_START;
	request_queue_t *entry;

	pthread_mutex_lock(&thread_pool.queue_mutex);

	thread_pool.request_count++;

	/*
	 *	FIXME: Handle proxy replies separately?
	 */
	if (thread_pool.num_queued >= thread_pool.max_queue_size) {
		pthread_mutex_unlock(&thread_pool.queue_mutex);
		
		/*
		 *	Mark the request as done.
		 */
		radlog(L_ERR|L_CONS, "!!! ERROR !!! The server is blocked: discarding new request %d", request->number);
		request->finished = TRUE;
		return 0;
	}

	/*
	 *	Requests get handled in priority.  First, we handle
	 *	replies from a home server, to finish ongoing requests.
	 *
	 *	Then, we handle requests with State, to finish
	 *	multi-packet transactions.
	 *
	 *	Finally, we handle new requests.
	 */
	if (request->proxy_reply) {
		fifo = FIFO_PROXY;
	} else {
		fifo = FIFO_START;
	}

	entry = rad_malloc(sizeof(*entry));
	entry->request = request;
	entry->fun = fun;

	if (!lrad_fifo_push(thread_pool.fifo[fifo], entry)) {
		pthread_mutex_unlock(&thread_pool.queue_mutex);
		radlog(L_ERR, "!!! ERROR !!! Failed inserting request %d into the queue", request->number);
		request->finished = TRUE;
		return 0;
	}

	thread_pool.num_queued++;

	pthread_mutex_unlock(&thread_pool.queue_mutex);

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
static int request_dequeue(REQUEST **request, RAD_REQUEST_FUNP *fun)
{
	int fifo_state;
	request_queue_t *entry;

	reap_children();

	pthread_mutex_lock(&thread_pool.queue_mutex);

	fifo_state = thread_pool.fifo_state;

 retry:
	do {
		/*
		 *	Pop an entry from the current queue, and go to
		 *	the next queue.
		 */
		entry = lrad_fifo_pop(thread_pool.fifo[fifo_state]);
		fifo_state++;
		if (fifo_state >= NUM_FIFOS) fifo_state = 0;
	} while ((fifo_state != thread_pool.fifo_state) && !entry);

	if (!entry) {
		pthread_mutex_unlock(&thread_pool.queue_mutex);
		*request = NULL;
		*fun = NULL;
		return 0;
	}

	rad_assert(thread_pool.num_queued > 0);
	thread_pool.num_queued--;
	*request = entry->request;
	*fun = entry->fun;
	free(entry);

	rad_assert(*request != NULL);
	rad_assert((*request)->magic == REQUEST_MAGIC);
	rad_assert(*fun != NULL);

	/*
	 *	If the request has sat in the queue for too long,
	 *	kill it.
	 *
	 *	The main clean-up code won't delete the request from
	 *	the request list, until it's marked "finished"
	 */
	if ((*request)->options & RAD_REQUEST_OPTION_STOP_NOW) {
		(*request)->finished = 1;
		goto retry;
	}

	/*
	 *	The thread is currently processing a request.
	 */
	thread_pool.active_threads++;
	thread_pool.fifo_state = fifo_state;

	pthread_mutex_unlock(&thread_pool.queue_mutex);

	rad_assert((*request)->child_pid == NO_SUCH_CHILD_PID);

	return 1;
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
		int finished;

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
		if (!request_dequeue(&self->request, &fun)) continue;

		self->request->child_pid = self->pthread_id;
		self->request_count++;

		DEBUG2("Thread %d handling request %d, (%d handled so far)",
		       self->thread_num, self->request->number,
		       self->request_count);

		/*
		 *	Respond, and reset request->child_pid
		 */
		finished = rad_respond(self->request, fun);

		/*
		 *	Update the active threads.
		 */
		pthread_mutex_lock(&thread_pool.queue_mutex);

		/*
		 *	We haven't replied to the client, but we HAVE
		 *	sent a proxied packet, and we have NOT
		 *	received a proxy response.  In that case, send
		 *	the proxied packet now.  Doing this in the mutex
		 *	avoids race conditions.
		 *
		 *	FIXME: this work should really depend on a
		 *	"state", and "next handler", rather than
		 *	horrid hacks like thise.
		 */
		if (!self->request->reply->data &&
		    self->request->proxy && self->request->proxy->data
		    && !self->request->proxy_reply)
			self->request->proxy_listener->send(self->request->proxy_listener,
							    (char *)self->request->proxysecret);

		self->request->child_pid = NO_SUCH_CHILD_PID;
		self->request->finished = finished;
		self->request = NULL;
		
		rad_assert(thread_pool.active_threads > 0);
		thread_pool.active_threads--;
		pthread_mutex_unlock(&thread_pool.queue_mutex);
	} while (self->status != THREAD_CANCELLED);

	DEBUG2("Thread %d exiting...", self->thread_num);

#ifdef HAVE_OPENSSL_ERR_H
	/*
	 *	If we linked with OpenSSL, the application
	 *	must remove the thread's error queue before
	 *	exiting to prevent memory leaks.
	 */
	ERR_remove_state(0);
#endif

	/*
	 *  Do this as the LAST thing before exiting.
	 */
	self->status = THREAD_EXITED;

	return NULL;
}

/*
 *	Take a THREAD_HANDLE, delete it from the thread pool and
 *	free its resources.
 *
 *	This function is called ONLY from the main server thread,
 *	ONLY after the thread has exited.
 */
static void delete_thread(THREAD_HANDLE *handle)
{
	THREAD_HANDLE *prev;
	THREAD_HANDLE *next;

	rad_assert(handle->request == NULL);

	DEBUG2("Deleting thread %d", handle->thread_num);

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

	/*
	 *	Free the handle, now that it's no longer referencable.
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
	/*
	 *	We don't acquire the mutex, so this is just an estimate.
	 *	We can't return with the lock held, so there's no point
	 *	in getting the guaranteed correct value; by the time
	 *	the caller sees it, it can be wrong again.
	 */
	return thread_pool.active_threads;
}


static uint32_t pid_hash(const void *data)
{
	const thread_fork_t *tf = data;

	return lrad_hash(&tf->pid, sizeof(tf->pid));
}

static int pid_cmp(const void *one, const void *two)
{
	const thread_fork_t *a = one;
	const thread_fork_t *b = two;

	return (a->pid - b->pid);
}

/*
 *	Allocate the thread pool, and seed it with an initial number
 *	of threads.
 *
 *	FIXME: What to do on a SIGHUP???
 */
int thread_pool_init(int spawn_flag)
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
		thread_pool.spawn_flag = spawn_flag;

		if ((pthread_mutex_init(&thread_pool.wait_mutex,NULL) != 0)) {
			radlog(L_ERR, "FATAL: Failed to initialize wait mutex: %s",
			       strerror(errno));
			exit(1);
		}		
		
		/*
		 *	Create the hash table of child PID's
		 */
		thread_pool.waiters = lrad_hash_table_create(pid_hash,
							     pid_cmp,
							     free);
		if (!thread_pool.waiters) {
			radlog(L_ERR, "FATAL: Failed to set up wait hash");
			exit(1);
		}
	}

	/*
	 *	We're not spawning new threads, don't do
	 *	anything.
	 */
	if (!spawn_flag) return 0;

	pool_cf = cf_section_find("thread");
	if (pool_cf != NULL) {
		/*
		 *	FIXME: Check for errors?
		 */
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
	memset(&thread_pool.semaphore, 0, sizeof(thread_pool.semaphore));
	rcode = sem_init(&thread_pool.semaphore, 0, SEMAPHORE_LOCKED);
	if (rcode != 0) {
		radlog(L_ERR|L_CONS, "FATAL: Failed to initialize semaphore: %s",
		       strerror(errno));
		exit(1);
	}

	rcode = pthread_mutex_init(&thread_pool.queue_mutex,NULL);
	if (rcode != 0) {
		radlog(L_ERR, "FATAL: Failed to initialize queue mutex: %s",
		       strerror(errno));
		exit(1);
	}

	/*
	 *	Allocate multiple fifos.
	 */
	for (i = 0; i < NUM_FIFOS; i++) {
		thread_pool.fifo[i] = lrad_fifo_create(65536, NULL);
		if (!thread_pool.fifo[i]) {
			radlog(L_ERR, "FATAL: Failed to set up request fifo");
			exit(1);
		}
	}

#ifdef HAVE_OPENSSL_CRYPTO_H
	/*
	 *	If we're linking with OpenSSL too, then we need
	 *	to set up the mutexes and enable the thread callbacks.
	 */
	if (!setup_ssl_mutexes()) {
		radlog(L_ERR, "FATAL: Failed to set up SSL mutexes");
		exit(1);
	}
#endif


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
	 *	We've been told not to spawn threads, so don't.
	 */
	if (!thread_pool.spawn_flag) {
		request->finished = rad_respond(request, fun);
		return 1;
	}

	/*
	 *	Add the new request to the queue.
	 */
	if (!request_enqueue(request, fun)) return 0;

	/*
	 *	If the thread pool is busy handling requests, then
	 *	try to spawn another one.  We don't acquire the mutex
	 *	before reading active_threads, so our thread count is
	 *	just an estimate.  It's fine to go ahead and spawn an
	 *	extra thread in that case.
	 *	NOTE: the log message may be in error since active_threads
	 *	is an estimate, but it's only in error about the thread
	 *	count, not about the fact that we can't create a new one.
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
	 *	active_threads, and not modifying it.  We want a close
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

	reap_children();	/* be nice to non-wait thingies */

	if (lrad_hash_table_num_elements(thread_pool.waiters) >= 1024) {
		return -1;
	}

	/*
	 *	Fork & save the PID for later reaping.
	 */
	child_pid = fork();
	if (child_pid > 0) {
		int rcode;
		thread_fork_t *tf;

		tf = rad_malloc(sizeof(*tf));
		memset(tf, 0, sizeof(*tf));
		
		tf->pid = child_pid;

		/*
		 *	Lock the mutex.
		 */
		pthread_mutex_lock(&thread_pool.wait_mutex);

		rcode = lrad_hash_table_insert(thread_pool.waiters, tf);

		/*
		 *	Unlock the mutex.
		 */
		pthread_mutex_unlock(&thread_pool.wait_mutex);

		if (!rcode) {
			radlog(L_ERR, "Failed to store PID, creating what will be a zombie process %d",
			       (int) child_pid);
		}
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
	thread_fork_t mytf, *tf;

	reap_children();	/* be nice to non-wait thingies */

	if (pid <= 0) return -1;

	if ((options & WNOHANG) == 0) return -1;

	mytf.pid = pid;

	pthread_mutex_lock(&thread_pool.wait_mutex);
	tf = lrad_hash_table_finddata(thread_pool.waiters, &mytf);

	if (!tf) {		/* not found.  It's a problem... */
		pthread_mutex_unlock(&thread_pool.wait_mutex);
		return waitpid(pid, status, options);
	}

	if (tf->exited) {
		*status = tf->status;
		lrad_hash_table_delete(thread_pool.waiters, &mytf);
		pthread_mutex_unlock(&thread_pool.wait_mutex);
		return pid;
	}
	
	/*
	 *	Don't wait, and it hasn't exited.  Return.
	 */
	pthread_mutex_unlock(&thread_pool.wait_mutex);
	return 0;
}

#else /* HAVE_PTHREAD_H */
/*
 *	"thread" code when we don't have threads.
 */
int thread_pool_init(int spawn_flag)
{
	return 0;
}

/*
 *	call "radrespond".
 */
int thread_pool_addrequest(REQUEST *request, RAD_REQUEST_FUNP fun)
{
	rad_respond(request, fun);
	return 1;
}

#endif /* HAVE_PTHREAD_H */
