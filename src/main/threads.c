#include "autoconf.h"

#ifdef WITH_THREAD_POOL

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <semaphore.h>
#include <assert.h>
#include <time.h>
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
 *	Proxy file descriptor.  Yes, global variables are ugly.
 */
extern int proxyfd;


/*
 *  A data structure which contains the information about
 *  the current thread.
 *
 *  child_pid     thread ID
 *  semaphore     used to block the thread until a request comes in
 *  status        is the thread running or exited?
 *  request_count the number of requests that this thread has handled
 *  timestamp     when the thread started executing.
 *  request       the current request that the thread is processing.
 *  fun           the function which is handling the request.
 */
typedef struct THREAD_HANDLE {
	struct	THREAD_HANDLE *prev;
	struct	THREAD_HANDLE *next;
	pthread_t		child_pid;
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
	int		min_spare_threads;
	int		max_spare_threads;
	int		max_threads;
	int		max_requests_per_thread;
} THREAD_POOL;

static THREAD_POOL thread_pool;

/*
 *	If the child *thread* gets a termination signal,
 *	then exit from the thread.
 *
 *	This is ugly.  REALLY ugly.  It might not even be portable...
 */
static void sig_term(int sig)
{
	pthread_t child_pid;
	THREAD_HANDLE *handle;

	child_pid = pthread_self();
	for (handle = thread_pool.head; handle; handle = handle->next) {
		if (pthread_equal(handle->child_pid, child_pid)) {
			handle->status = THREAD_CANCELLED;
			DEBUG2("Thread %d setting state to cancelled",
			       child_pid);
			break;
		}
	}

	DEBUG2("Thread %d got SIGTERM: exiting thread", child_pid);
	pthread_exit(NULL);
}

/*
 *	The main thread handler for requests.
 *
 *	Wait on the semaphore until we have it, and process the request.
 */
static void *request_handler_thread(void *arg)
{
	THREAD_HANDLE	*self;
	REQUEST		*request;
	RADIUS_PACKET	*packet;
	const char	*secret;
	int		replicating;

	self = (THREAD_HANDLE *) arg;
	
	/*
	 *	Esnsure that any termination signals are caught
	 *	by the child thread, and cause a forced exit.
	 */
	signal(SIGTERM, sig_term);

	/*
	 *	Loop forever, until pthread_cancel()'d, or SIGTERM'd.
	 */
	for (;;) {
		/*
		 *	Wait for the semaphore to be given to us.
		 *
		 *	This is a thread cancellation point.  So if we're
		 *	given a pthread_cancel(), then this function acts
		 *	like pthread_exit().
		 */
		DEBUG2("Thread %d waiting to be assigned a request",
		       self->child_pid);
		sem_wait(&self->semaphore);
		
		DEBUG2("Thread %d handling request %08x, number %d",
		       self->child_pid, self->request, self->request_count);
		
		request = self->request;

		/*
		 *	Put the decoded packet into it's proper place.
		 */
		if (request->proxy_reply != NULL) {
			packet = request->proxy_reply;
			secret = request->proxysecret;
		} else {
			packet = request->packet;
			secret = request->secret;
		}

		/*
		 *	Decode the packet, verifying it's signature,
		 *	and parsing the attributes into structures.
		 *
		 *	Note that we do this CPU-intensive work in
		 *	a child thread, not the master.  This helps to
		 *	spread the load a little bit.
		 */
		if (rad_decode(packet, secret) != 0) {
		    log(L_ERR, "%s", librad_errstr);
		    request->child_pid = NO_SUCH_CHILD_PID;
		    request->finished = TRUE;

		    /*
		     *	Send a reject?
		     */

		    goto next_request;
		}

		/*
		 *	For proxy replies, remove non-allowed
		 *	attributes from the list of VP's.
		 */
		if (request->proxy) {
			replicating = proxy_receive(request);
			if (replicating != 0) {
				goto next_request;
			}
		}
		
		/*
		 *	We should have a User-Name attribute now.
		 */
		if (request->username == NULL) {
			request->username = pairfind(request->packet->vps,
						     PW_USER_NAME);
		}

		/*
		 *	We have the semaphore, and have decoded the packet.
		 *	Let's process the request.
		 */
		(*(self->fun))(request);
		
		/*
		 *	Respond to the request, including any
		 *	proxy or replicate commands.
		 */
		rad_respond(request);

		/*
		 *	We're done processing the request, set the
		 *	request to be finished, clean up as necessary,
		 *	and forget about the request.
		 */
	next_request:
		/*
		 *	The proxy reply VP's aren't going to be used
		 *	any more, so we might as well get rid of them
		 *	in the child thread.
		 */
		if (request->proxy_reply) {
			pairfree(request->proxy_reply->vps);
			request->proxy_reply->vps = NULL;
		}
		self->request = NULL;

		/*
		 *	The semaphore's value is zero, because we've
		 *	locked it.  We now go back to the top of the loop,
		 *	where we wait for it's value to become non-zero.
		 */
	}
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

	/*
	 *	The handle has been removed from the list.
	 *
	 *	Go delete its semaphore, and free the thread handle memory.
	 */
	sem_destroy(&handle->semaphore);
	free(handle);
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

	assert(thread_pool.total_threads > 1);
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
static THREAD_HANDLE *spawn_thread(void)
{
	int rcode;
	THREAD_HANDLE *handle;

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
		log(L_ERR|L_CONS, "no memory");
		exit(1);
	}
	memset(handle, 0, sizeof(THREAD_HANDLE));
	handle->prev = NULL;
	handle->next = NULL;
	handle->child_pid = 0;
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
		log(L_ERR|L_CONS, "Failed to allocate semaphore: %s",
		    strerror(errno));
		exit(1);
	}

	/*
	 *	The thread isn't currently handling a request.
	 */
	handle->request = NULL;
	handle->fun = NULL;

	/*
	 *	Create the thread.
	 */
	rcode = pthread_create(&handle->child_pid, NULL,
			       request_handler_thread, handle);
	if (rcode != 0) {
		log(L_ERR|L_CONS, "Thread create failed: %s", strerror(errno));
		exit(1);
	}

	/*
	 *	One more thread to go into the list.
	 */
	thread_pool.total_threads++;
	DEBUG2("Thread spawned new child %d. Total threads in pool: %d",
	       handle->child_pid, thread_pool.total_threads);

	/*
	 *	Move the thread handle to the tail of the thread pool list.
	 */
	move2tail(handle);

	/*
	 *	And return the new handle to the caller.
	 */
	return handle;
}

/*
 *	Allocate the thread pool, and seed it with an initial number
 *	of threads.
  */
int thread_pool_init(int num_threads)
{
	int i;
	THREAD_HANDLE	*handle;
	CONF_SECTION	*pool_cf;
	CONF_PAIR	*cf;

	/*
	 *	Initialize the thread pool to some reasonable values.
	 */
	memset(&thread_pool, 0, sizeof(THREAD_POOL));
	thread_pool.head = NULL;
	thread_pool.tail = NULL;
	thread_pool.total_threads = 0;
	thread_pool.min_spare_threads = 3;
	thread_pool.max_spare_threads = 10;
	thread_pool.max_threads = 32;

	pool_cf = cf_section_find("thread");
	if (pool_cf) {
		
	}

	/*
	 *	Create a number of waiting threads.
	 *
	 *	If we fail while creating them, do something intelligent.
	 */
	for (i = 0; i < num_threads; i++) {
		handle = spawn_thread();
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
		 *	Prior to seeing if the thread is free, check
		 *	if the thread has exited.
		 */
		if (handle->status == THREAD_CANCELLED) {
			assert(handle->request == NULL);

			DEBUG2("Thread joining child %d. Total threads in pool: %d", handle->child_pid, thread_pool.total_threads);
			pthread_join(handle->child_pid, NULL);
			handle->child_pid = NO_SUCH_CHILD_PID;
			delete_thread(handle);
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
		found = spawn_thread();
		if (found == NULL) {
			log(L_INFO, "The maximum number of threads (%d) are active, cannot spawn new thread to handle request", thread_pool.max_threads);
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
	DEBUG2("Thread %d assigned request %08x", found->child_pid, request);
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
int thread_pool_clean(void)
{
	int spare;
	int i, total;
	THREAD_HANDLE *handle;
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
	DEBUG2("Threads: total/Active/Spare threads = %d/%d/%d",
	       thread_pool.total_threads, active_threads, spare);

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
			handle = spawn_thread();
			if (handle == NULL) {
				return -1;
			}
		}

		/*
		 *	And exit.
		 */
		return 0;
	}

	/*
	 *	If there are too many spare threads, delete some.
	 */
	if (spare > thread_pool.max_spare_threads) {

		spare -= thread_pool.max_spare_threads;

		DEBUG2("Threads: deleting %d spares", spare);
		/*
		 *	Walk through the thread pool, deleting the
		 *	first N idle threads we come across.
		 */
		for (handle = thread_pool.head; (handle != NULL) && (spare > 0) ; handle = handle->next) {

			/*
			 *	If the thread is not handling a
			 *	request, then cancel it, count down of
			 *	the ones we need to signal, and exit.
			 *
			 *	The threads will actually be cleaned
			 *	up from the list later.
			 */
			if (handle->request == NULL) {
#ifdef HAVE_PTHREAD_CANCEL
				pthread_cancel(handle->child_pid);
#else
				child_kill(handle->child_pid, SIGTERM);
#endif
				handle->status = THREAD_CANCELLED;
				spare--;
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
