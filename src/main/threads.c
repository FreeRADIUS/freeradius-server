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

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>

/*
 *	Other OS's have sem_init, OS X doesn't.
 */
#ifdef HAVE_SEMAPHORE_H
#include <semaphore.h>
#endif

#ifdef DARWIN
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

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#ifdef HAVE_PTHREAD_H

#ifdef HAVE_OPENSSL_CRYPTO_H
#include <openssl/crypto.h>
#endif
#ifdef HAVE_OPENSSL_ERR_H
#include <openssl/err.h>
#endif
#ifdef HAVE_OPENSSL_EVP_H
#include <openssl/evp.h>
#endif

#define SEMAPHORE_LOCKED	(0)
#define SEMAPHORE_UNLOCKED	(1)

#define THREAD_RUNNING		(1)
#define THREAD_CANCELLED	(2)
#define THREAD_EXITED		(3)

#define NUM_FIFOS               RAD_LISTEN_MAX


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

#ifdef WNOHANG
	pthread_mutex_t	wait_mutex;
	fr_hash_table_t *waiters;
#endif

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
	fr_fifo_t	*fifo[NUM_FIFOS];
} THREAD_POOL;

static THREAD_POOL thread_pool;
static int pool_initialized = FALSE;
static time_t last_cleaned = 0;
static time_t almost_now = 0;

static void thread_pool_manage(time_t now);

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

#ifdef HAVE_OPENSSL_EVP_H
	/*
	 *	Enable all ciphers and digests.
	 */
	OpenSSL_add_all_algorithms();
#endif

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
#define reap_children()
#endif /* WNOHANG */

/*
 *	Add a request to the list of waiting requests.
 *	This function gets called ONLY from the main handler thread...
 *
 *	This function should never fail.
 */
static int request_enqueue(REQUEST *request, RAD_REQUEST_FUNP fun)
{
	request_queue_t *entry;

	pthread_mutex_lock(&thread_pool.queue_mutex);

	thread_pool.request_count++;

	if (thread_pool.num_queued >= thread_pool.max_queue_size) {
		pthread_mutex_unlock(&thread_pool.queue_mutex);

		/*
		 *	Mark the request as done.
		 */
		radlog(L_ERR, "Something is blocking the server.  There are %d packets in the queue, waiting to be processed.  Ignoring the new request.", thread_pool.max_queue_size);
		request->child_state = REQUEST_DONE;
		return 0;
	}
	request->child_state = REQUEST_QUEUED;
	request->component = "<core>";
	request->module = "<queue>";

	entry = rad_malloc(sizeof(*entry));
	entry->request = request;
	entry->fun = fun;

	/*
	 *	Push the request onto the appropriate fifo for that
	 */
	if (!fr_fifo_push(thread_pool.fifo[request->priority],
			    entry)) {
		pthread_mutex_unlock(&thread_pool.queue_mutex);
		radlog(L_ERR, "!!! ERROR !!! Failed inserting request %d into the queue", request->number);
		request->child_state = REQUEST_DONE;
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
	int blocked;
	RAD_LISTEN_TYPE i, start;
	request_queue_t *entry;

	reap_children();

	pthread_mutex_lock(&thread_pool.queue_mutex);

	/*
	 *	Clear old requests from all queues.
	 *
	 *	We only do one pass over the queue, in order to
	 *	amortize the work across the child threads.  Since we
	 *	do N checks for one request de-queued, the old
	 *	requests will be quickly cleared.
	 */
	for (i = 0; i < RAD_LISTEN_MAX; i++) {
		entry = fr_fifo_peek(thread_pool.fifo[i]);
		if (!entry ||
		    (entry->request->master_state != REQUEST_STOP_PROCESSING)) {
			continue;
}
		/*
		 *	This entry was marked to be stopped.  Acknowledge it.
		 */
		entry = fr_fifo_pop(thread_pool.fifo[i]);
		rad_assert(entry != NULL);
		entry->request->child_state = REQUEST_DONE;
		thread_pool.num_queued--;
		free(entry);
		entry = NULL;
	}

	start = 0;
 retry:
	/*
	 *	Pop results from the top of the queue
	 */
	for (i = start; i < RAD_LISTEN_MAX; i++) {
		entry = fr_fifo_pop(thread_pool.fifo[i]);
		if (entry) {
			start = i;
			break;
		}
	}

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
	entry = NULL;

	rad_assert(*request != NULL);
	rad_assert((*request)->magic == REQUEST_MAGIC);
	rad_assert(*fun != NULL);

	(*request)->component = "<core>";
	(*request)->module = "<thread>";

	/*
	 *	If the request has sat in the queue for too long,
	 *	kill it.
	 *
	 *	The main clean-up code can't delete the request from
	 *	the queue, and therefore won't clean it up until we
	 *	have acknowledged it as "done".
	 */
	if ((*request)->master_state == REQUEST_STOP_PROCESSING) {
		(*request)->module = "<done>";
		(*request)->child_state = REQUEST_DONE;
		goto retry;
	}

	/*
	 *	Produce messages for people who have 10 million rows
	 *	in a database, without indexes.
	 */
	rad_assert(almost_now != 0);
	blocked = almost_now - (*request)->timestamp;
	if (blocked < 5) {
		blocked = 0;
	} else {
		static time_t last_complained = 0;
		
		if (last_complained != almost_now) {
			last_complained = almost_now;
		} else {
			blocked = 0;
		}
	}

	/*
	 *	The thread is currently processing a request.
	 */
	thread_pool.active_threads++;

	pthread_mutex_unlock(&thread_pool.queue_mutex);

	if (blocked) {
		radlog(L_ERR, "Request %u has been waiting in the processing queue for %d seconds.  Check that all databases are running properly!",
		       (*request)->number, blocked);
	}

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

#ifdef HAVE_OPENSSL_ERR_H
 		/*
		 *	Clear the error queue for the current thread.
		 */
		ERR_clear_error ();
#endif

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

		radius_handle_request(self->request, fun);

		/*
		 *	Update the active threads.
		 */
		pthread_mutex_lock(&thread_pool.queue_mutex);
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
	self->request = NULL;
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
		radlog(L_ERR, "Thread create failed: %s",
		       strerror(rcode));
		return NULL;
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


#ifdef WNOHANG
static uint32_t pid_hash(const void *data)
{
	const thread_fork_t *tf = data;

	return fr_hash(&tf->pid, sizeof(tf->pid));
}

static int pid_cmp(const void *one, const void *two)
{
	const thread_fork_t *a = one;
	const thread_fork_t *b = two;

	return (a->pid - b->pid);
}
#endif

/*
 *	Allocate the thread pool, and seed it with an initial number
 *	of threads.
 *
 *	FIXME: What to do on a SIGHUP???
 */
int thread_pool_init(CONF_SECTION *cs, int *spawn_flag)
{
	int		i, rcode;
	CONF_SECTION	*pool_cf;
	time_t		now;

	now = time(NULL);

	rad_assert(spawn_flag != NULL);
	rad_assert(*spawn_flag == TRUE);
	rad_assert(pool_initialized == FALSE); /* not called on HUP */

	pool_cf = cf_subsection_find_next(cs, NULL, "thread");
	if (!pool_cf) *spawn_flag = FALSE;

	/*
	 *	Initialize the thread pool to some reasonable values.
	 */
	memset(&thread_pool, 0, sizeof(THREAD_POOL));
	thread_pool.head = NULL;
	thread_pool.tail = NULL;
	thread_pool.total_threads = 0;
	thread_pool.max_thread_num = 1;
	thread_pool.cleanup_delay = 5;
	thread_pool.spawn_flag = *spawn_flag;
	
	/*
	 *	Don't bother initializing the mutexes or
	 *	creating the hash tables.  They won't be used.
	 */
	if (!*spawn_flag) return 0;
	
#ifdef WNOHANG
	if ((pthread_mutex_init(&thread_pool.wait_mutex,NULL) != 0)) {
		radlog(L_ERR, "FATAL: Failed to initialize wait mutex: %s",
		       strerror(errno));
		return -1;
	}
	
	/*
	 *	Create the hash table of child PID's
	 */
	thread_pool.waiters = fr_hash_table_create(pid_hash,
						   pid_cmp,
						   free);
	if (!thread_pool.waiters) {
		radlog(L_ERR, "FATAL: Failed to set up wait hash");
		return -1;
	}
#endif

	if (cf_section_parse(pool_cf, NULL, thread_config) < 0) {
		return -1;
	}

	/*
	 *	Catch corner cases.
	 */
	if (thread_pool.min_spare_threads < 1)
		thread_pool.min_spare_threads = 1;
	if (thread_pool.max_spare_threads < 1)
		thread_pool.max_spare_threads = 1;
	if (thread_pool.max_spare_threads < thread_pool.min_spare_threads)
		thread_pool.max_spare_threads = thread_pool.min_spare_threads;

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
		radlog(L_ERR, "FATAL: Failed to initialize semaphore: %s",
		       strerror(errno));
		return -1;
	}

	rcode = pthread_mutex_init(&thread_pool.queue_mutex,NULL);
	if (rcode != 0) {
		radlog(L_ERR, "FATAL: Failed to initialize queue mutex: %s",
		       strerror(errno));
		return -1;
	}

	/*
	 *	Allocate multiple fifos.
	 */
	for (i = 0; i < RAD_LISTEN_MAX; i++) {
		thread_pool.fifo[i] = fr_fifo_create(65536, NULL);
		if (!thread_pool.fifo[i]) {
			radlog(L_ERR, "FATAL: Failed to set up request fifo");
			return -1;
		}
	}

#ifdef HAVE_OPENSSL_CRYPTO_H
	/*
	 *	If we're linking with OpenSSL too, then we need
	 *	to set up the mutexes and enable the thread callbacks.
	 */
	if (!setup_ssl_mutexes()) {
		radlog(L_ERR, "FATAL: Failed to set up SSL mutexes");
		return -1;
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
	almost_now = request->timestamp;

	/*
	 *	We've been told not to spawn threads, so don't.
	 */
	if (!thread_pool.spawn_flag) {
		radius_handle_request(request, fun);

#ifdef WNOHANG
		/*
		 *	Requests that care about child process exit
		 *	codes have already either called
		 *	rad_waitpid(), or they've given up.
		 */
		wait(NULL);
#endif
		return 1;
	}

	/*
	 *	Add the new request to the queue.
	 */
	if (!request_enqueue(request, fun)) return 0;

	/*
	 *	If we haven't checked the number of child threads
	 *	in a while, OR if the thread pool appears to be full,
	 *	go manage it.
	 */
	if ((last_cleaned < almost_now) ||
	    (thread_pool.active_threads == thread_pool.total_threads)) {
		thread_pool_manage(almost_now);
	}

	return 1;
}

/*
 *	Check the min_spare_threads and max_spare_threads.
 *
 *	If there are too many or too few threads waiting, then we
 *	either create some more, or delete some.
 */
static void thread_pool_manage(time_t now)
{
	int spare;
	int i, total;
	THREAD_HANDLE *handle, *next;
	int active_threads;

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
	 *	If there are too few spare threads.  Go create some more.
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
				return;
			}
		}

		return;		/* there aren't too many spare threads */
	}

	/*
	 *	Only delete spare threads if we haven't already done
	 *	so this second.
	 */
	if (now == last_cleaned) {
		return;
	}
	last_cleaned = now;

	/*
	 *	Loop over the thread pool, deleting exited threads.
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
	 *	Only delete the spare threads if sufficient time has
	 *	passed since we last created one.  This helps to minimize
	 *	the amount of create/delete cycles.
	 */
	if ((now - thread_pool.time_last_spawned) < thread_pool.cleanup_delay) {
		return;
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
	return;
}


#ifdef WNOHANG
/*
 *	Thread wrapper for fork().
 */
pid_t rad_fork(void)
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

		tf = rad_malloc(sizeof(*tf));
		memset(tf, 0, sizeof(*tf));

		tf->pid = child_pid;

		pthread_mutex_lock(&thread_pool.wait_mutex);
		rcode = fr_hash_table_insert(thread_pool.waiters, tf);
		pthread_mutex_unlock(&thread_pool.wait_mutex);

		if (!rcode) {
			radlog(L_ERR, "Failed to store PID, creating what will be a zombie process %d",
			       (int) child_pid);
			free(tf);
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
pid_t rad_waitpid(pid_t pid, int *status)
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

void thread_pool_lock(void)
{
	pthread_mutex_lock(&thread_pool.queue_mutex);
}

void thread_pool_unlock(void)
{
	pthread_mutex_unlock(&thread_pool.queue_mutex);
}

void thread_pool_queue_stats(int *array)
{
	int i;

	if (pool_initialized) {
		for (i = 0; i < RAD_LISTEN_MAX; i++) {
			array[i] = fr_fifo_num_elements(thread_pool.fifo[i]);
		}
	} else {
		for (i = 0; i < RAD_LISTEN_MAX; i++) {
			array[i] = 0;
		}
	}
}
#else
int thread_pool_addrequest(REQUEST *request, RAD_REQUEST_FUNP fun)
{
	radius_handle_request(request, fun);
	
#ifdef WNOHANG
	/*
	 *	Requests that care about child process exit
	 *	codes have already either called
	 *	rad_waitpid(), or they've given up.
	 */
	wait(NULL);
#endif
	return 1;
}

#endif /* HAVE_PTHREAD_H */
