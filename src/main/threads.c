#include "autoconf.h"

#ifdef WITH_THREAD_POOL

#include <stdlib.h>
#include <string.h>
#include <semaphore.h>
#include <assert.h>
#include <signal.h>

#if HAVE_MALLOC_H
#  include	<malloc.h>
#endif

#include	"radiusd.h"
#include	"conffile.h"

static const char rcsid[] =
"$Id$";

#define SEMAPHORE_LOCKED	(0)
#define SEMAPHORE_UNLOCKED	(1)

#define THREAD_RUNNING		(1)
#define THREAD_CANCELLED	(2)

/*
 *	Prototype to shut the compiler up.
 */
int rad_spawn_child(REQUEST *request, RAD_REQUEST_FUNP fun);

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
 *  request       the current request that the thread is processing.
 *  fun           the function which is handling the request.
 */
typedef struct THREAD_HANDLE {
	struct	THREAD_HANDLE	*prev;
	struct	THREAD_HANDLE	*next;
	pthread_t		pthread_id;
	int			thread_num;
	sem_t			semaphore;
	int			status;
	int			request_count;
	time_t			timestamp;
	REQUEST			*request;
	RAD_REQUEST_FUNP	fun;
} THREAD_HANDLE;

/*
 *	A data structure to manage the thread pool.  There's no real
 *	need for a data structure, but it makes things conceptually
 *	easier.
 */
typedef struct THREAD_POOL {
	THREAD_HANDLE *head;
	THREAD_HANDLE *tail;
	
	int		total_threads;
	int		active_threads;
	int		max_thread_num;
	int		start_threads;
	int		max_threads;
	int		min_spare_threads;
	int		max_spare_threads;
	int		max_requests_per_thread;
	time_t		time_last_spawned;
	int		cleanup_delay;
} THREAD_POOL;

static THREAD_POOL thread_pool;

/*
 *	A mapping of configuration file names to internal integers
 */
static const CONF_PARSER thread_config[] = {
	{ "start_servers",                      PW_TYPE_INTEGER,
	  &thread_pool.start_threads,           "5" }, 
	{ "max_servers",                        PW_TYPE_INTEGER,
	  &thread_pool.max_threads,             "32" }, 
	{ "min_spare_servers",                  PW_TYPE_INTEGER,
	  &thread_pool.min_spare_threads,       "3" }, 
	{ "max_spare_servers",                  PW_TYPE_INTEGER,
	  &thread_pool.max_spare_threads,       "10" }, 
	{ "max_requests_per_server",            PW_TYPE_INTEGER,
	  &thread_pool.max_requests_per_thread, "0"}, 
	{ "cleanup_delay",			PW_TYPE_INTEGER,
	  &thread_pool.cleanup_delay,		"5"}, 
	
	{ NULL, -1, NULL, NULL }
};

/*
 *	The main thread handler for requests.
 *
 *	Wait on the semaphore until we have it, and process the request.
 */
static void *request_handler_thread(void *arg)
{
	THREAD_HANDLE	*self = (THREAD_HANDLE *) arg;
#if HAVE_SIGPROCMASK
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
	sigaddset(&set, SIGCHLD);
	sigprocmask(SIG_BLOCK, &set, NULL);
#endif
	
	/*
	 *	Loop forever, until told to exit.
	 */
	for (;;) {
		/*
		 *	Wait for the semaphore to be given to us.
		 */
		DEBUG2("Thread %d waiting to be assigned a request",
		       self->thread_num);
		sem_wait(&self->semaphore);

		/*
		 *	If we've been told to kill ourselves,
		 *	then exit politely.
		 */
		if (self->status == THREAD_CANCELLED) {
			DEBUG2("Thread %d exiting on request from parent.",
			       self->thread_num);
			break;
		}
		
		DEBUG2("Thread %d handling request %p, number %d",
		       self->thread_num, self->request, self->request_count);
		
		rad_respond(self->request, self->fun);
		self->request = NULL;

		/*
		 *	The semaphore's value is zero, because we've
		 *	locked it.  We now go back to the top of the loop,
		 *	where we wait for it's value to become non-zero.
		 */
	}

	/*
	 *	This thread is exiting.  Delete any additional resources
	 *	associated with it (semaphore, etc), and free the thread
	 *	handle memory.
	 */
	sem_destroy(&self->semaphore);
	free(self);
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

	assert(handle->request == NULL);

	prev = handle->prev;
	next = handle->next;
	assert(thread_pool.total_threads > 0);
	thread_pool.total_threads--;

	if (prev == NULL) {
		assert(thread_pool.head == handle);
		thread_pool.head = next;
	} else {
		prev->next = next;
	}
  
	if (next == NULL) {
		assert(thread_pool.tail == handle);
		thread_pool.tail = prev;
	} else {
		next->prev = prev;
	}
}

/*
 *	Take a THREAD_HANDLE, and move it to the end of the thread pool.
 *
 *	This function is called ONLY from the main server thread.
 *	It's function is to keep the incoming requests rotating among
 *	the threads in the pool.
 */
static void move2tail(THREAD_HANDLE *handle)
{
	THREAD_HANDLE *prev;
	THREAD_HANDLE *next;

	/*
	 *	Empty list: add it to the head.
	 */
	if (thread_pool.head == NULL) {
		assert(thread_pool.tail == NULL);
		assert(thread_pool.total_threads == 1);

		handle->prev = NULL;
		handle->next = NULL;
		thread_pool.head = handle;
		thread_pool.tail = handle;
		return;
	}

	assert(thread_pool.total_threads >= 1);
	prev = handle->prev;
	next = handle->next;
  
	/*
	 *	If the element is in the list, then delete it from where
	 *	it is.
	 */
	if ((next != NULL) ||
	    (prev != NULL)) {
		/*
		 *	If it's already at the tail, exit immediately,
		 *	there's no more work to do.
		 */
		if (next == NULL) {
			assert(thread_pool.tail == handle);
			return;
		}
    
		/*
		 *	Maybe it's at the head of the list?
		 */
		if (prev == NULL) {
			assert(thread_pool.head == handle);
      
			thread_pool.head = next;
			next->prev = NULL;
      
			/*
			 *	Nope, it's really in the middle.
			 *	Unlink it, then.
			 */
		} else {
			assert(prev != NULL); /* be explicit about it. */
			assert(next != NULL); /* be explicit about it. */
      
			prev->next = next;
			next->prev = prev;
		}
	}

	/*
	 *	Finally, add it to the tail, and update the pointers.
	 */
	handle->next = NULL;
	prev = thread_pool.tail;
	assert(prev->next == NULL);

	thread_pool.tail = handle;
	handle->prev = prev;
	prev->next = handle;
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
	handle = (THREAD_HANDLE *) malloc(sizeof(THREAD_HANDLE));
	if (handle == NULL) {
		radlog(L_ERR|L_CONS, "no memory");
		exit(1);
	}
	memset(handle, 0, sizeof(THREAD_HANDLE));
	handle->prev = NULL;
	handle->next = NULL;
	handle->pthread_id = NO_SUCH_CHILD_PID;
	handle->thread_num = thread_pool.max_thread_num++;
	handle->request_count = 0;
	handle->status = THREAD_RUNNING;
	handle->timestamp = time(NULL);

	/*
	 *	Initialize the semaphore to be for this process only,
	 *	and to have the thread block until the server gives it
	 *	the semaphore.
	 */
	rcode = sem_init(&handle->semaphore, 0, SEMAPHORE_LOCKED);
	if (rcode != 0) {
		radlog(L_ERR|L_CONS, "Failed to allocate semaphore: %s",
		    strerror(errno));
		exit(1);
	}

	/*
	 *	The thread isn't currently handling a request.
	 */
	handle->request = NULL;
	handle->fun = NULL;

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
	 */
	rcode = pthread_create(&handle->pthread_id, &attr,
			       request_handler_thread, handle);
	if (rcode != 0) {
		radlog(L_ERR|L_CONS, "Thread create failed: %s", strerror(errno));
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
	 *	Move the thread handle to the tail of the thread pool list.
	 */
	move2tail(handle);

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
 *	Allocate the thread pool, and seed it with an initial number
 *	of threads.
  */
int thread_pool_init(void)
{
	int i;
	THREAD_HANDLE	*handle;
	CONF_SECTION	*pool_cf;
	time_t		now;

	DEBUG("Initializing the thread pool...");
	now = time(NULL);

	/*
	 *	Initialize the thread pool to some reasonable values.
	 */
	memset(&thread_pool, 0, sizeof(THREAD_POOL));
	thread_pool.head = NULL;
	thread_pool.tail = NULL;
	thread_pool.total_threads = 0;
	thread_pool.max_thread_num = 1;
	thread_pool.cleanup_delay = 5;

	pool_cf = cf_section_find("thread");
	if (pool_cf) {
		cf_section_parse(pool_cf, thread_config);
	}

	/*
	 *	Create a number of waiting threads.
	 *
	 *	If we fail while creating them, do something intelligent.
	 */
	for (i = 0; i < thread_pool.start_threads; i++) {
		handle = spawn_thread(now);
		if (handle == NULL) {
			return -1;
		}
	}

	return 0;
}

/*
 *	Assign a new request to a free thread.
 *
 *	If there isn't a free thread, then try to create a new one,
 *	up to the configured limits.
 */
int rad_spawn_child(REQUEST *request, RAD_REQUEST_FUNP fun)
{
	int active_threads;
	THREAD_HANDLE *handle;
	THREAD_HANDLE *found;
	THREAD_HANDLE *next;

	/*
	 *	Loop over the active thread pool, looking for a
	 *	waiting thread.
	 */
	found = NULL;
	active_threads = 0;
	for (handle = thread_pool.head; handle; handle = next) {
		next = handle->next;

		/*
		 *	Ignore threads which aren't running.
		 */
		if (handle->status != THREAD_RUNNING) {
			continue;
		}

		/*
		 *	If we haven't found a free thread yet, then
		 *	check it's semaphore lock.  We don't lock it,
		 *	so if it's locked, then the thread MUST be the
		 *	one locking it, waiting for us to unlock it.
		 */
		if (handle->request == NULL) {
			if (found == NULL) {
				found = handle;
			}
		} else {
			active_threads++;
		}
	} /* loop over all of the threads */

	/*
	 *	If we haven't found an active thread, then spawn a new one.
	 *
	 *	If we can't spawn a new one, complain, and exit.
	 */
	if (found == NULL) {
		found = spawn_thread(request->timestamp);
		if (found == NULL) {
			radlog(L_INFO, "The maximum number of threads (%d) are active, cannot spawn new thread to handle request", thread_pool.max_threads);
			return -1;
		}
	}

	/*
	 *	OK, now 'handle' points to a waiting thread.  We move
	 *	it to the tail of the thread pool, so that we can
	 *	cycle among the threads.
	 *
	 *	We then give it the request, signal its semaphore, and
	 *	return.  The thread eventually wakes up, and handles
	 *	the request.
	 */
	DEBUG2("Thread %d assigned request %p", found->thread_num, request);
	move2tail(found);
	found->request = request;
	found->fun = fun;
	found->request_count++;
	sem_post(&found->semaphore);
	thread_pool.active_threads = active_threads;

	return 0;
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
	 *	Loop over the thread pool, doing stuff.
	 */
	active_threads = 0;
	for (handle = thread_pool.head; handle; handle = handle->next) {
		if (handle->request != NULL) {
			active_threads++;
		}
	}

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
			 *	request, then tell it to exit.
			 *
			 *	Note that we delete it from the thread
			 *	pool BEFORE telling it to kill itself,
			 *	as the child thread can free the 'handle'
			 *	structure, without anyone else using it.
			 */
			if (handle->request == NULL) {
				delete_thread(handle);
				handle->status = THREAD_CANCELLED;
				sem_post(&handle->semaphore);
				spare--;
				return 0;
			}
		}
	}
  
	/*
	 *	Otherwise everything's kosher.  There are not too few,
	 *	or too many spare threads.  Exit happily.
	 */
	return 0;
}
#endif
