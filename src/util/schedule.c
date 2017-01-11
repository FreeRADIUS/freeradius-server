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
 * @brief Network / worker thread scheduling
 * @file util/schedule.c
 *
 * @copyright 2016 Alan DeKok <aland@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/autoconf.h>
#include <freeradius-devel/rad_assert.h>

#include <freeradius-devel/util/schedule.h>
#include <freeradius-devel/rbtree.h>

#include <freeradius-devel/util/receiver.h>

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#define PTHREAD_MUTEX_LOCK   pthread_mutex_lock
#define PTHREAD_MUTEX_UNLOCK pthread_mutex_unlock

#else
#define PTHREAD_MUTEX_LOCK
#define PTHREAD_MUTEX_UNLOCK
#endif

/*
 *	Other OS's have sem_init, OS X doesn't.
 */
#ifdef HAVE_SEMAPHORE_H
#include <semaphore.h>
#endif

#define SEMAPHORE_LOCKED	(0)

#ifdef __APPLE__
#include <mach/task.h>
#include <mach/mach_init.h>
#include <mach/semaphore.h>

#undef sem_t
#define sem_t semaphore_t
#undef sem_init
#define sem_init(s,p,c) semaphore_create(mach_task_self(),s,SYNC_POLICY_FIFO,c)
#undef sem_wait
#define sem_wait(s) semaphore_wait(*s)
#undef sem_post
#define sem_post(s) semaphore_signal(*s)
#undef sem_destroy
#define sem_destroy(s) semaphore_destroy(mach_task_self(),*s)
#endif	/* __APPLE__ */

/**
 *  Track the worker thread status.
 */
typedef enum fr_schedule_worker_status_t {
	FR_WORKER_FREE = 0,			//!< worker is free
	FR_WORKER_INITIALIZING,			//!< initialized, but not running
	FR_WORKER_RUNNING,			//!< running, and in the worker queue
	FR_WORKER_EXITED,			//!< exited, and in the done_worker queue
	FR_WORKER_FAIL				//!< failed, and in the done_worker queue
} fr_schedule_worker_status_t;

/**
 *	A data structure to track workers.
 */
typedef struct fr_schedule_worker_t {
	pthread_t	pthread_id;		//!< the thread of this worker

	int		uses;			//!< how many network threads are using it
	fr_time_t	cpu_time;		//!< how much CPU time this worker has used
	int		heap_id;		//!< for the heap of workers

	fr_schedule_t	*sc;			//!< the scheduler we are running under

	fr_schedule_worker_status_t status;	//!< status of the worker
	fr_worker_t	*worker;		//!< the worker data structure
} fr_schedule_worker_t;

/**
 *	A data structure to track network threads / receivers.
 */
typedef struct fr_schedule_receiver_t {
	pthread_t	pthread_id;		//!< the thread of this receiver

	int		kq;			//!< the receivers KQ
	fr_event_list_t *el;			//!< the receivers event list

	fr_receiver_t	*rc;			//!< the receive data structure
} fr_schedule_receiver_t;


/**
 *  The scheduler
 */
struct fr_schedule_t {
	bool		running;		//!< is the scheduler running?

	int		max_inputs;		//!< number of network threads
	int		max_workers;		//!< max number of worker threads

	int		num_workers;		//!< number of worker threads
	int		num_workers_exited;	//!< number of exited workers

#ifdef HAVE_PTHREAD_H
	pthread_mutex_t	mutex;			//!< for thread safey

	sem_t		semaphore;		//!< for exited threads
#endif

	fr_schedule_thread_instantiate_t	worker_thread_instantiate;	//!< thread instantiation callback
	void					*worker_instantiate_ctx;	//!< thread instantiation context

	fr_heap_t	*workers;		//!< heap of workers
	fr_heap_t	*done_workers;		//!< heap of done workers

	uint32_t	num_transports;		//!< how many transport layers we have
	fr_transport_t	**transports;		//!< array of active transports.
};


static int worker_cmp(void const *one, void const *two)
{
	fr_schedule_worker_t const *a = one;
	fr_schedule_worker_t const *b = two;

	if (a->uses < b->uses) return -1;
	if (a->uses > b->uses) return +1;

	if (a->cpu_time < b->cpu_time) return -1;
	if (a->cpu_time > b->cpu_time) return +1;

	return 0;
}


/** Get a workers KQ
 *
 * @param[in] sc the scheduler
 * @return
 *	- <0 on error, or no free worker
 *	- the kq of the worker thread
 */
int fr_schedule_get_worker_kq(fr_schedule_t *sc)
{
	int kq;
	fr_schedule_worker_t *sw;

	PTHREAD_MUTEX_LOCK(&sc->mutex);

	sw = fr_heap_pop(sc->workers);
	if (!sw) {
		PTHREAD_MUTEX_UNLOCK(&sc->mutex);
		return -1;
	}

	kq = fr_worker_kq(sw->worker);
	rad_assert(kq >= 0);
	sw->uses++;
	(void) fr_heap_insert(sc->workers, sw);

	PTHREAD_MUTEX_UNLOCK(&sc->mutex);

	return kq;
}


/** Initialize and run the worker thread.
 *
 * @param[in] arg the fr_schedule_worker_t
 * @return NULL
 */
static void *fr_schedule_worker_thread(void *arg)
{
	TALLOC_CTX *ctx;
	fr_schedule_worker_t *sw = arg;
	fr_schedule_t *sc = sw->sc;

	ctx = talloc_init("worker");
	if (!ctx) {
	fail:
		sw->status = FR_WORKER_FAIL;

		/*
		 *	Tell the scheduler that we've exited.
		 */
		PTHREAD_MUTEX_LOCK(&sc->mutex);
		(void) fr_heap_insert(sc->done_workers, sw);
		sc->num_workers_exited++;
		PTHREAD_MUTEX_UNLOCK(&sc->mutex);

		sem_post(&sc->semaphore);
		return NULL;
	}

	sw->worker = fr_worker_create(ctx, sc->num_transports, sc->transports);
	if (!sw->worker) {
		talloc_free(ctx);
		goto fail;
	}

	/*
	 *	@todo make this a registry
	 */
	if (sc->worker_thread_instantiate &&
	    (sc->worker_thread_instantiate(sc->worker_instantiate_ctx) < 0)) {
		goto fail;
	}

	sw->status = FR_WORKER_RUNNING;

	PTHREAD_MUTEX_LOCK(&sc->mutex);
	(void) fr_heap_insert(sc->workers, sw);
	sc->num_workers++;
	PTHREAD_MUTEX_UNLOCK(&sc->mutex);

	/*
	 *	Do all of the work.
	 *
	 *	@todo check for child processes.
	 */
	fr_worker(sw->worker);

	/*
	 *	Talloc ordering issues. We want to be independent of
	 *	how talloc walks it's children, and ensure that some
	 *	things are freed in a specific order.
	 */
	fr_worker_destroy(sw->worker);
	sw->worker = NULL;

	talloc_free(ctx);

	/*
	 *	Move ourselves from the list of live workers, and add
	 *	ourselves to the list of dead workers.
	 */
	PTHREAD_MUTEX_LOCK(&sc->mutex);
	(void) fr_heap_extract(sc->workers, sw);
	sc->num_workers--;

	(void) fr_heap_insert(sc->done_workers, sw);
	sc->num_workers_exited++;
	PTHREAD_MUTEX_UNLOCK(&sc->mutex);

	sw->status = FR_WORKER_EXITED;

	/*
	 *	Tell the scheduler that we've exited.
	 */
	sem_post(&sc->semaphore);

	return NULL;
}


/** Create a scheduler and spawn the child threads.
 *
 * @param[in] ctx the talloc context
 * @param[in] max_inputs the number of network threads
 * @param[in] max_workers the number of worker threads
 * @param[in] num_transports the number of transports in the transport array
 * @param[in] transports the array of transports.
 * @param[in] worker_thread_instantiate callback for new worker threads
 * @param[in] worker_thread_ctx context for callback
 * @return
 *	- NULL on error
 *	- fr_schedule_t new scheduler
 */
fr_schedule_t *fr_schedule_create(TALLOC_CTX *ctx, int max_inputs, int max_workers,
				  uint32_t num_transports, fr_transport_t **transports,
				  fr_schedule_thread_instantiate_t worker_thread_instantiate,
				  void *worker_thread_ctx)
{
#ifdef HAVE_PTHREAD_H
	int i;
	int rcode;
#endif
	fr_schedule_t *sc;

	/*
	 *	We require inputs and workers.
	 */
	if ((!max_inputs && max_workers) || (max_workers && !max_inputs)) return NULL;

	sc = talloc_zero(ctx, fr_schedule_t);
	if (!sc) return NULL;

	sc->max_inputs = max_inputs;
	sc->max_workers = max_workers;

	sc->worker_thread_instantiate = worker_thread_instantiate;
	sc->worker_instantiate_ctx = worker_thread_ctx;

	sc->running = true;
	sc->num_transports = num_transports;
	sc->transports = transports;

	/*
	 *	No inputs or workers, we're single threaded mode.
	 */
	if (!sc->max_inputs && !sc->max_workers) return sc;

#ifdef HAVE_PTHREAD_H
	rcode = pthread_mutex_init(&sc->mutex, NULL);
	if (rcode != 0) {
		talloc_free(sc);
		return NULL;
	}

	/*
	 *	Create the heap which holds the workers.
	 */
	sc->workers = fr_heap_create(worker_cmp, offsetof(fr_schedule_worker_t, heap_id));
	if (!sc->workers) {
		talloc_free(sc);
		return NULL;
	}

	memset(&sc->semaphore, 0, sizeof(sc->semaphore));
	if (sem_init(&sc->semaphore, 0, SEMAPHORE_LOCKED) != 0) {
		talloc_free(sc);
		return NULL;
	}

	/*
	 *	Create all of the workers.
	 */
	for (i = 0; i < sc->max_workers; i++) {
		fr_schedule_worker_t *sw;
		pthread_attr_t attr;

		(void) pthread_attr_init(&attr);
		(void) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

		/*
		 *	Create a worker "glue" structure
		 */
		sw = talloc_zero(sc, fr_schedule_worker_t);
		if (!sw) {
			fr_schedule_destroy(sc);
			return NULL;
		}

		sw->sc = sc;
		sw->status = FR_WORKER_INITIALIZING;

		rcode = pthread_create(&sw->pthread_id, &attr, fr_schedule_worker_thread, sc);
		if (rcode != 0) {
			fr_schedule_destroy(sc);
			return NULL;
		}
	}

	/*
	 *	@todo create the network threads
	 */

	/*
	 *	@todo check the workers, to see if they all succeeded.
	 */

#endif

	return sc;
}

/** Destroy a scheduler, and tell it's child threads to exit.
 *
 * @param[in] sc the scheduler
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_schedule_destroy(fr_schedule_t *sc)
{
	bool done = false;
	fr_schedule_worker_t *sw;

	sc->running = false;
	rad_assert(sc->num_workers > 0);

	// signal the network threads to exit

	/*
	 *	Signal the workers to exit.  They will push themselves
	 *	onto the "exited" stack when they're done.
	 */
	while ((sw = fr_heap_pop(sc->workers)) != NULL) {
		fr_worker_exit(sw->worker);
	}

	/*
	 *	Wait for all worker threads to finish.  THEN clean up
	 *	modules.  Otherwise, the modules will be removed from
	 *	underneath the workers!
	 */
	while (sem_wait(&sc->semaphore) == 0) {

		/*
		 *	Needs to be done in a lock for thread safety.
		 */
		PTHREAD_MUTEX_LOCK(&sc->mutex);
		done = (sc->num_workers_exited == 0);
		PTHREAD_MUTEX_UNLOCK(&sc->mutex);

		if (done) break;
	}

	sem_destroy(&sc->semaphore);

	/*
	 *	Now that all of the workers are done, we can return to
	 *	the caller, and have him dlclose() the modules.
	 */
	talloc_free(sc);

	return 0;
}


#if 0
int fr_schedule_socket_add(fr_schedule_t *sc, int fd, fr_transport_t *transport, void *ctx)
{
	// send it to a receivers KQ as transport / ctx
	// it receives it via the USERFILT, and adds the transport / ctx
	// transport_ctx is largely rad_listen_t, which is a transport-specific socket
}
#endif

/*
 *	@todo single threaded mode.  Instead of having function
 *	specific to single threaded mode, just fix the event loop.
 *
 *	Allow for it to have multiple EVFILT_USER callbacks.  They are
 *	called in sequence.  A function which "consumes" the event
 *	sets it's type to EVFILT_SYSCOUNT, which is ignored by
 *	everything else.
 */
