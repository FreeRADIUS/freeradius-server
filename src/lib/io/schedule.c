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
 * @file io/schedule.c
 *
 * @copyright 2016 Alan DeKok <aland@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/autoconf.h>
#include <freeradius-devel/rad_assert.h>

#include <freeradius-devel/io/schedule.h>
#include <freeradius-devel/rbtree.h>

#include <freeradius-devel/io/receiver.h>

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

#define SEM_WAIT_INTR(_x) do {if (sem_wait(_x) == 0) break;} while (errno == EINTR)

/**
 *  Track the child thread status.
 */
typedef enum fr_schedule_child_status_t {
	FR_CHILD_FREE = 0,			//!< child is free
	FR_CHILD_INITIALIZING,			//!< initialized, but not running
	FR_CHILD_RUNNING,			//!< running, and in the running queue
	FR_CHILD_EXITED,			//!< exited, and in the exited queue
	FR_CHILD_FAIL				//!< failed, and in the exited queue
} fr_schedule_child_status_t;

/**
 *	A data structure to track workers.
 */
typedef struct fr_schedule_worker_t {
	pthread_t	pthread_id;		//!< the thread of this worker

	int		id;			//!< a unique ID
	int		uses;			//!< how many network threads are using it
	fr_time_t	cpu_time;		//!< how much CPU time this worker has used
	int		heap_id;		//!< for the heap of workers

	fr_schedule_t	*sc;			//!< the scheduler we are running under

	fr_schedule_child_status_t status;	//!< status of the worker
	fr_worker_t	*worker;		//!< the worker data structure
} fr_schedule_worker_t;

/**
 *	A data structure to track network threads / receivers.
 */
typedef struct fr_schedule_receiver_t {
	pthread_t	pthread_id;		//!< the thread of this receiver

	int		id;			//!< a unique ID
	fr_schedule_t	*sc;			//!< the scheduler we are running under

	fr_schedule_child_status_t status;	//!< status of the worker
	fr_receiver_t	*rc;			//!< the receive data structure
} fr_schedule_receiver_t;


/**
 *  The scheduler
 */
struct fr_schedule_t {
	bool		running;		//!< is the scheduler running?

	fr_log_t	*log;			//!< log destination

	int		max_inputs;		//!< number of network threads
	int		max_workers;		//!< max number of worker threads

	int		num_workers;		//!< number of worker threads
	int		num_workers_exited;	//!< number of exited workers

#ifdef HAVE_PTHREAD_H
	pthread_mutex_t	mutex;			//!< for thread safey

	sem_t		semaphore;		//!< for inter-thread signaling
#endif

	fr_schedule_thread_instantiate_t	worker_thread_instantiate;	//!< thread instantiation callback
	void					*worker_instantiate_ctx;	//!< thread instantiation context

	fr_heap_t	*workers;		//!< heap of workers
	fr_heap_t	*done_workers;		//!< heap of done workers

	fr_schedule_receiver_t *sr;		//!< pointer to the (one) network thread

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
	fr_schedule_child_status_t status = FR_CHILD_FAIL;
	char buffer[32];

	fr_log(sc->log, L_INFO, "Worker %d starting\n", sw->id);

	ctx = talloc_init("worker");
	if (!ctx) {
		fr_log(sc->log, L_ERR, "Worker %d - Failed allocating memory", sw->id);
		goto fail;
	}

	sw->worker = fr_worker_create(ctx, sc->log, sc->num_transports, sc->transports);
	if (!sw->worker) {
		fr_log(sc->log, L_ERR, "Worker %d - Failed creating worker: %s", sw->id, fr_strerror());
		goto fail;
	}

	snprintf(buffer, sizeof(buffer), "thread %d - ", sw->id);
	fr_worker_name(sw->worker, buffer);

	/*
	 *	@todo make this a registry
	 */
	if (sc->worker_thread_instantiate &&
	    (sc->worker_thread_instantiate(sc->worker_instantiate_ctx) < 0)) {
		fr_log(sc->log, L_ERR, "Worker %d - Failed calling thread instantiate: %s", sw->id, fr_strerror());
		goto fail;
	}

	sw->status = FR_CHILD_RUNNING;

	PTHREAD_MUTEX_LOCK(&sc->mutex);
	(void) fr_heap_insert(sc->workers, sw);
	sc->num_workers++;
	PTHREAD_MUTEX_UNLOCK(&sc->mutex);

	(void) fr_receiver_worker_add(sc->sr->rc, sw->worker);

	fr_log(sc->log, L_INFO, "Worker %d running\n", sw->id);

	/*
	 *	Tell the originator that the thread has started.
	 */
	sem_post(&sc->semaphore);

	/*
	 *	Do all of the work.
	 *
	 *	@todo check for child processes.
	 */
	fr_worker(sw->worker);

	fr_log(sc->log, L_INFO, "Worker %d finished\n", sw->id);

	/*
	 *	Talloc ordering issues. We want to be independent of
	 *	how talloc walks it's children, and ensure that some
	 *	things are freed in a specific order.
	 */
	fr_worker_destroy(sw->worker);
	sw->worker = NULL;

	/*
	 *	Remove ourselves from the list of live workers.
	 */
	PTHREAD_MUTEX_LOCK(&sc->mutex);
	(void) fr_heap_extract(sc->workers, sw);
	sc->num_workers--;
	PTHREAD_MUTEX_UNLOCK(&sc->mutex);

	status = FR_CHILD_EXITED;

fail:

	/*
	 *	Add outselves to the list of dead workers.
	 */
	PTHREAD_MUTEX_LOCK(&sc->mutex);
	sw->status = status;
	(void) fr_heap_insert(sc->done_workers, sw);
	sc->num_workers_exited++;
	PTHREAD_MUTEX_UNLOCK(&sc->mutex);

	fr_log(sc->log, L_INFO, "Worker %d exiting\n", sw->id);

	/*
	 *	Tell the scheduler we're done.
	 */
	sem_post(&sc->semaphore);

	return NULL;
}


/** Initialize and run the receiver thread.
 *
 * @param[in] arg the fr_schedule_receiver_t
 * @return NULL
 */
static void *fr_schedule_receiver_thread(void *arg)
{
	TALLOC_CTX *ctx;
	fr_schedule_receiver_t *sr = arg;
	fr_schedule_t *sc = sr->sc;
	fr_schedule_child_status_t status = FR_CHILD_FAIL;

	fr_log(sc->log, L_INFO, "Network starting\n");

	ctx = talloc_init("receiver");
	if (!ctx) {
		fr_log(sc->log, L_ERR, "Network %d - Failed allocating memory", sr->id);
		goto fail;
	}

	sr->rc = fr_receiver_create(ctx, sc->log, sc->num_transports, sc->transports);
	if (!sr->rc) {
		fr_log(sc->log, L_ERR, "Network %d - Failed creating network: %s", sr->id, fr_strerror());
		goto fail;
	}

	sr->status = FR_CHILD_RUNNING;

	/*
	 *	Tell the originator that the thread has started.
	 */
	sem_post(&sc->semaphore);

	fr_log(sc->log, L_INFO, "Network running");

	/*
	 *	Do all of the work.
	 */
	fr_receiver(sr->rc);

	/*
	 *	Talloc ordering issues. We want to be independent of
	 *	how talloc walks it's children, and ensure that some
	 *	things are freed in a specific order.
	 */
	fr_receiver_destroy(sr->rc);
	sr->rc = NULL;

	status = FR_CHILD_EXITED;

fail:
	if (ctx) talloc_free(ctx);

	sr->status = status;

	fr_log(sc->log, L_INFO, "Network exiting");

	/*
	 *	Tell the scheduler we're done.
	 */
	sem_post(&sc->semaphore);

	return NULL;
}


/** Create a scheduler and spawn the child threads.
 *
 * @param[in] ctx the talloc context
 * @param[in] logger the destination for all logging messages
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
fr_schedule_t *fr_schedule_create(TALLOC_CTX *ctx, fr_log_t *logger, int max_inputs, int max_workers,
				  uint32_t num_transports, fr_transport_t **transports,
				  fr_schedule_thread_instantiate_t worker_thread_instantiate,
				  void *worker_thread_ctx)
{
#ifdef HAVE_PTHREAD_H
	int i, num_workers;
	int rcode;
	pthread_attr_t attr;

#endif
	fr_schedule_t *sc;

	/*
	 *	We require inputs and workers.
	 */
	if ((!max_inputs && max_workers) || (max_workers && !max_inputs)) return NULL;

	sc = talloc_zero(ctx, fr_schedule_t);
	if (!sc) {
	nomem:
		fr_strerror_printf("Failed allocating memory");
		return NULL;
	}

	sc->max_inputs = max_inputs;
	sc->max_workers = max_workers;
	sc->log = logger;

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
	(void) pthread_attr_init(&attr);
	(void) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	rcode = pthread_mutex_init(&sc->mutex, NULL);
	if (rcode != 0) {
		fr_strerror_printf("Failed initializing mutex");
		talloc_free(sc);
		return NULL;
	}

	/*
	 *	Create the heap which holds the workers.
	 */
	sc->workers = fr_heap_create(worker_cmp, offsetof(fr_schedule_worker_t, heap_id));
	if (!sc->workers) {
		talloc_free(sc);
		goto nomem;
	}

	sc->done_workers = fr_heap_create(worker_cmp, offsetof(fr_schedule_worker_t, heap_id));
	if (!sc->done_workers) {
		talloc_free(sc);
		goto nomem;
	}

	memset(&sc->semaphore, 0, sizeof(sc->semaphore));
	if (sem_init(&sc->semaphore, 0, SEMAPHORE_LOCKED) != 0) {
		fr_strerror_printf("Failed creating semaphore: %s", fr_syserror(errno));
		talloc_free(sc);
		return NULL;
	}

	/*
	 *	Create the network thread first.
	 */
	sc->sr = talloc_zero(sc, fr_schedule_receiver_t);
	sc->sr->sc = sc;
	sc->sr->id = 0;

	rcode = pthread_create(&sc->sr->pthread_id, &attr, fr_schedule_receiver_thread, sc->sr);
	if (rcode != 0) {
		fr_strerror_printf("Failed creating network thread: %s", fr_syserror(errno));
		goto fail;
	}

	SEM_WAIT_INTR(&sc->semaphore);
	if (sc->sr->status != FR_CHILD_RUNNING) {
	fail:
		TALLOC_FREE(sc->sr);
		fr_schedule_destroy(sc);
		return NULL;
	}

	/*
	 *	Create all of the workers.
	 */
	num_workers = 0;
	for (i = 0; i < sc->max_workers; i++) {
		fr_schedule_worker_t *sw;

		fr_log(sc->log, L_DBG, "Creating %d/%d workers\n", i, sc->max_workers);

		/*
		 *	Create a worker "glue" structure
		 */
		sw = talloc_zero(sc, fr_schedule_worker_t);
		if (!sw) break;

		sw->id = i;
		sw->sc = sc;
		sw->status = FR_CHILD_INITIALIZING;

		rcode = pthread_create(&sw->pthread_id, &attr, fr_schedule_worker_thread, sw);
		if (rcode != 0) {
			fr_log(sc->log, L_ERR, "Failed creating worker %d: %s\n", i, fr_syserror(errno));
			talloc_free(sw);
			break;
		}

		num_workers++;
	}

	/*
	 *	Wait for all of the workers to start.
	 */
	for (i = 0; i < num_workers; i++) {
		fr_log(sc->log, L_DBG, "Waiting for semaphore from worker %d/%d\n", i, num_workers);
		SEM_WAIT_INTR(&sc->semaphore);
	}

	PTHREAD_MUTEX_LOCK(&sc->mutex);
	if (sc->num_workers != sc->max_workers) {
		int num_workers_exited = sc->num_workers_exited;
		fr_schedule_worker_t *sw;

		fr_log(sc->log, L_ERR, "Failed to create some workers\n");

		PTHREAD_MUTEX_UNLOCK(&sc->mutex);

		/*
		 *	Clean up the dead ones which caused the
		 *	error(s).
		 */
		for (i = 0; i < num_workers_exited; i++) {
			fr_log(sc->log, L_DBG, "Pop exited %d/%d\n", i, num_workers_exited);

			PTHREAD_MUTEX_LOCK(&sc->mutex);
			sw = fr_heap_pop(sc->done_workers);
			PTHREAD_MUTEX_UNLOCK(&sc->mutex);
			rad_assert(sw != NULL);

			talloc_free(sw);
		}

		/*
		 *	Tell the active workers to exit.
		 */
		for (i = 0; i < num_workers; i++) {
			fr_log(sc->log, L_DBG, "Signal to exit %d/%d\n", i, num_workers);

			PTHREAD_MUTEX_LOCK(&sc->mutex);
			sw = fr_heap_pop(sc->workers);
			PTHREAD_MUTEX_UNLOCK(&sc->mutex);
			rad_assert(sw != NULL);

			fr_worker_exit(sw->worker);
		}

		/*
		 *	Clean up the workers which have no exited, and
		 *	signaled us that they've exited.
		 */
		for (i = 0; i < num_workers; i++) {
			fr_log(sc->log, L_DBG, "Wait for semaphore indicating exit %d/%d\n", i, num_workers);

			SEM_WAIT_INTR(&sc->semaphore);
		}

		talloc_free(sc);
		return NULL;

	}
	PTHREAD_MUTEX_UNLOCK(&sc->mutex);
#endif

	fr_log(sc->log, L_INFO, "Scheduler created successfully\n");

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
	int i, num;		
	fr_schedule_worker_t *sw;

	sc->running = false;

#ifdef HAVE_PTHREAD_H
	rad_assert(sc->num_workers > 0);

	fr_log(sc->log, L_DBG, "Destroying scheduler\n");

	/*
	 *	Signal the workers to exit.  They will push themselves
	 *	onto the "exited" stack when they're done.
	 */
	num = sc->num_workers;

	PTHREAD_MUTEX_LOCK(&sc->mutex);
	while ((sw = fr_heap_pop(sc->workers)) != NULL) {
		fr_worker_exit(sw->worker);
	}
	PTHREAD_MUTEX_UNLOCK(&sc->mutex);

	/*
	 *	Wait for all worker threads to finish.  THEN clean up
	 *	modules.  Otherwise, the modules will be removed from
	 *	underneath the workers!
	 */
	for (i = 0; i < num; i++) {
		fr_log(sc->log, L_DBG, "Wait for semaphore indicating exit %d/%d\n", i, num);
		SEM_WAIT_INTR(&sc->semaphore);
	}

	/*
	 *	Pop the "done" workers, and free their contexts here.
	 */
	while ((sw = fr_heap_pop(sc->done_workers)) != NULL) {
		TALLOC_CTX *ctx;

		ctx = talloc_parent(sw);
		talloc_free(ctx);
	}

	/*
	 *	If the network thread is running, tell it to exit.
	 */
	if (sc->sr->status == FR_CHILD_RUNNING) {
		fr_receiver_exit(sc->sr->rc);
		SEM_WAIT_INTR(&sc->semaphore);
	}

	sem_destroy(&sc->semaphore);
#endif	/* HAVE_PTHREAD_H */

	fr_log(sc->log, L_INFO, "Destroyed scheduler\n");

	/*
	 *	Now that all of the workers are done, we can return to
	 *	the caller, and have him dlclose() the modules.
	 */
	talloc_free(sc);

	return 0;
}

/** Add a socket to a scheduler.
 *
 * @param sc the scheduler
 * @param fd the file descriptor for the socket
 * @param ctx the context for the transport
 * @param transport the transport
 */
int fr_schedule_socket_add(fr_schedule_t *sc, int fd, void *ctx, fr_transport_t *transport)
{
	return fr_receiver_socket_add(sc->sr->rc, fd, ctx, transport);
}


/*
 *	@todo single threaded mode.  Instead of having function
 *	specific to single threaded mode, just fix the event loop.
 *
 *	Allow for it to have multiple EVFILT_USER callbacks.  They are
 *	called in sequence.  A function which "consumes" the event
 *	sets it's type to EVFILT_SYSCOUNT, which is ignored by
 *	everything else.
 */
