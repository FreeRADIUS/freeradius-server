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
 * @copyright 2016 Alan DeKok (aland@freeradius.org)
 */
RCSID("$Id$")

#define LOG_DST sc->log

#include <freeradius-devel/autoconf.h>

#include <freeradius-devel/io/schedule.h>
#include <freeradius-devel/util/dlist.h>
#include <freeradius-devel/util/rbtree.h>
#include <freeradius-devel/util/syserror.h>

#include <pthread.h>

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
typedef struct {
	TALLOC_CTX	*ctx;			//!< our allocation ctx
	fr_event_list_t	*el;			//!< our event list
	pthread_t	pthread_id;		//!< the thread of this worker

	int		id;			//!< a unique ID
	int		uses;			//!< how many network threads are using it
	fr_time_t	cpu_time;		//!< how much CPU time this worker has used

	fr_dlist_t	entry;			//!< our entry into the linked list of workers

	fr_schedule_t	*sc;			//!< the scheduler we are running under

	fr_schedule_child_status_t status;	//!< status of the worker
	fr_worker_t	*worker;		//!< the worker data structure
} fr_schedule_worker_t;

/**
 *	A data structure to track network threads / networks.
 */
typedef struct {
	TALLOC_CTX	*ctx;			//!< our allocation ctx
	pthread_t	pthread_id;		//!< the thread of this network

	int		id;			//!< a unique ID
	fr_schedule_t	*sc;			//!< the scheduler we are running under

	fr_schedule_child_status_t status;	//!< status of the worker
	fr_network_t	*nr;			//!< the receive data structure

	fr_event_timer_t const *ev;		//!< timer for stats_interval
} fr_schedule_network_t;


/**
 *  The scheduler
 */
struct fr_schedule_s {
	bool		running;		//!< is the scheduler running?

	CONF_SECTION	*cs;			//!< thread pool configuration section
	fr_event_list_t	*el;			//!< event list for single-threaded mode.

	fr_log_t	*log;			//!< log destination
	fr_log_lvl_t	lvl;			//!< log level

	fr_schedule_config_t *config;		//!< configuration

	unsigned int	num_workers_exited;	//!< number of exited workers

	sem_t		worker_sem;		//!< for inter-thread signaling
	sem_t		network_sem;		//!< for inter-thread signaling

	fr_schedule_thread_instantiate_t	worker_thread_instantiate;	//!< thread instantiation callback

	fr_dlist_head_t	workers;		//!< list of workers

	fr_network_t	*single_network;	//!< for single-threaded mode
	fr_worker_t	*single_worker;		//!< for single-threaded mode

	fr_schedule_network_t *sn;		//!< pointer to the (one) network thread
};

static _Thread_local int worker_id;		//!< Internal ID of the current worker thread.

/** Return the worker id for the current thread
 *
 * @return worker ID
 */
int fr_schedule_worker_id(void)
{
	return worker_id;
}

/** Entry point for worker threads
 *
 * @param[in] arg	the fr_schedule_worker_t
 * @return NULL
 */
static void *fr_schedule_worker_thread(void *arg)
{
	TALLOC_CTX			*ctx;
	fr_schedule_worker_t		*sw = talloc_get_type_abort(arg, fr_schedule_worker_t);
	fr_schedule_t			*sc = sw->sc;
	fr_schedule_child_status_t	status = FR_CHILD_FAIL;
	char buffer[32];

	worker_id = sw->id;		/* Store the current worker ID */

	sw->ctx = ctx = talloc_init("worker %d", sw->id);
	if (!ctx) {
		ERROR("Worker %d - Failed allocating memory", sw->id);
		goto fail;
	}

	INFO("Worker %d starting", sw->id);

	sw->el = fr_event_list_alloc(ctx, NULL, NULL);
	if (!sw->el) {
		ERROR("Worker %d - Failed creating event list: %s", sw->id, fr_strerror());
		goto fail;
	}

	snprintf(buffer, sizeof(buffer), "Worker %d", sw->id);
	sw->worker = fr_worker_create(ctx, buffer, sw->el, sc->log, sc->lvl);
	if (!sw->worker) {
		ERROR("Worker %d - Failed creating worker: %s", sw->id, fr_strerror());
		goto fail;
	}

	/*
	 *	@todo make this a registry
	 */
	if (sc->worker_thread_instantiate) {
		CONF_SECTION *cs;

		snprintf(buffer, sizeof(buffer), "%d", sw->id);

		cs = cf_section_find(sc->cs, "worker", buffer);
		if (!cs) cs = cf_section_find(sc->cs, "worker", NULL);

		if (sc->worker_thread_instantiate(sw->ctx, sw->el, cs) < 0) {
			ERROR("Worker %d - Failed calling thread instantiate: %s", sw->id, fr_strerror());
			goto fail;
		}
	}

	sw->status = FR_CHILD_RUNNING;

	(void) fr_network_worker_add(sc->sn->nr, sw->worker);

	DEBUG3("Spawned async worker %d", sw->id);

	/*
	 *	Tell the originator that the thread has started.
	 */
	sem_post(&sc->worker_sem);

	/*
	 *	Do all of the work.
	 *
	 *	@todo check for child processes.
	 */
	fr_worker(sw->worker);

	INFO("Worker %d finished", sw->id);

	status = FR_CHILD_EXITED;

fail:
	sw->status = status;

	if (sw->worker) {
		fr_worker_destroy(sw->worker);
		sw->worker = NULL;
	}

	INFO("Worker %d exiting", sw->id);

	/*
	 *	Tell the scheduler we're done.
	 */
	sem_post(&sc->worker_sem);

	return NULL;
}


static void stats_timer(fr_event_list_t *el, fr_time_t now, void *uctx)
{
	fr_schedule_network_t		*sn = talloc_get_type_abort(uctx, fr_schedule_network_t);

	fr_network_stats_log(sn->nr, sn->sc->log);

	(void) fr_event_timer_at(sn, el, &sn->ev, now + sn->sc->config->stats_interval, stats_timer, sn);
}

/** Initialize and run the network thread.
 *
 * @param[in] arg the fr_schedule_network_t
 * @return NULL
 */
static void *fr_schedule_network_thread(void *arg)
{
	TALLOC_CTX			*ctx;
	fr_schedule_network_t		*sn = talloc_get_type_abort(arg, fr_schedule_network_t);
	fr_schedule_t			*sc = sn->sc;
	fr_schedule_child_status_t	status = FR_CHILD_FAIL;
	fr_event_list_t			*el;

	INFO("Network %d starting", sn->id);

	sn->ctx = ctx = talloc_init("network %d", sn->id);
	if (!ctx) {
		ERROR("Network %d - Failed allocating memory", sn->id);
		goto fail;
	}

	el = fr_event_list_alloc(ctx, NULL, NULL);
	if (!el) {
		ERROR("Network %d - Failed creating event list: %s",
		       sn->id, fr_strerror());
		goto fail;
	}

	sn->nr = fr_network_create(ctx, el, sc->log, sc->lvl);
	if (!sn->nr) {
		ERROR("Network %d - Failed creating network: %s", sn->id, fr_strerror());
		goto fail;
	}

	sn->status = FR_CHILD_RUNNING;

	/*
	 *	Tell the originator that the thread has started.
	 */
	sem_post(&sc->network_sem);

	DEBUG3("Spawned asycn network 0");

	/*
	 *	Print out statistics for this network IO handler.
	 */
	if (sc->config->stats_interval) (void) fr_event_timer_in(sn, el, &sn->ev, sn->sc->config->stats_interval, stats_timer, sn);

	/*
	 *	Do all of the work.
	 */
	fr_network(sn->nr);

	status = FR_CHILD_EXITED;

fail:
	sn->status = status;

	INFO("Network exiting");

	/*
	 *	Tell the scheduler we're done.
	 */
	sem_post(&sc->network_sem);

	return NULL;
}

/** Creates a new thread using our standard set of options
 *
 * New threads are:
 * - Joinable, i.e. you can call pthread_join on them to confirm they've exited
 * - Immune to catchable signals.
 *
 * @param[out] thread		handled that was created by pthread_create.
 * @param[in] func		entry point for the thread.
 * @param[in] arg		Argument to pass to func.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_schedule_pthread_create(pthread_t *thread, void *(*func)(void *), void *arg)
{
	pthread_attr_t			attr;
	int				ret;

	/*
	 *	Set the thread to wait around after it's exited
	 *	so it can be joined.  This is more of a useful
	 *	mechanism for the parent to determine if all
	 *	the threads have exited so it can continue with
	 *	a graceful shutdown.
	 */
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	ret = pthread_create(thread, &attr, func, arg);
	if (ret != 0) {
		fr_strerror_printf("Failed creating thread: %s", fr_syserror(ret));
		return -1;
	}

	return 0;
}

/** Create a scheduler and spawn the child threads.
 *
 * @param[in] ctx		talloc context.
 * @param[in] el		event list, only for single-threaded mode.
 * @param[in] logger		destination for all logging messages.
 * @param[in] lvl		log level.
 * @param[in] worker_thread_instantiate		callback for new worker threads.
 * @param[in] config		configuration for the scheduler
 * @return
 *	- NULL on error
 *	- fr_schedule_t new scheduler
 */
fr_schedule_t *fr_schedule_create(TALLOC_CTX *ctx, fr_event_list_t *el,
				  fr_log_t *logger, fr_log_lvl_t lvl,
				  fr_schedule_thread_instantiate_t worker_thread_instantiate,
				  fr_schedule_config_t *config)
{
	unsigned int i;
	fr_schedule_worker_t *sw, *next;
	fr_schedule_t *sc;

	sc = talloc_zero(ctx, fr_schedule_t);
	if (!sc) {
		fr_strerror_printf("Failed allocating memory");
		return NULL;
	}

	sc->config = config;
	sc->el = el;
	sc->log = logger;
	sc->lvl = lvl;

	sc->worker_thread_instantiate = worker_thread_instantiate;
	sc->running = true;

	/*
	 *	If we're single-threaded, create network / worker, and insert them into the event loop.
	 */
	if (el) {
		sc->single_network = fr_network_create(sc, el, sc->log, sc->lvl);
		if (!sc->single_network) {
			ERROR("Failed creating network: %s", fr_strerror());
		st_fail:
			talloc_free(sc);
			return NULL;
		}

		sc->single_worker = fr_worker_create(sc, "0", el, sc->log, sc->lvl);
		if (!sc->single_worker) {
			ERROR("Failed creating worker: %s", fr_strerror());
			goto st_fail;
		}

		/*
		 *	Parent thread-specific data from the single_worker
		 */
		if (sc->worker_thread_instantiate) {
			CONF_SECTION *subcs;

			subcs = cf_section_find(sc->cs, "worker", "0");
			if (!subcs) subcs = cf_section_find(sc->cs, "worker", NULL);

			if (sc->worker_thread_instantiate(sc->single_worker, el, subcs) < 0) {
				ERROR("Failed calling thread instantiate: %s", fr_strerror());
				goto st_fail;
			}
		}

		if (fr_command_register_hook(NULL, "0", sc->single_worker, cmd_worker_table) < 0) {
			ERROR("Failed adding worker commands: %s", fr_strerror());
			goto st_fail;
		}

		if (fr_command_register_hook(NULL, "0", sc->single_network, cmd_network_table) < 0) {
			ERROR("Failed adding network commands: %s", fr_strerror());
			goto st_fail;
		}

		(void) fr_network_worker_add(sc->single_network, sc->single_worker);
		DEBUG("Scheduler created in single-threaded mode");

		if (fr_event_pre_insert(el, fr_worker_pre_event, sc->single_worker) < 0) {
			fr_strerror_printf("Failed adding pre-check to event list");
			goto st_fail;
		}

		/*
		 *	Add the event which processes REQUEST packets.
		 */
		if (fr_event_post_insert(el, fr_worker_post_event, sc->single_worker) < 0) {
			fr_strerror_printf("Failed inserting post-processing event");
			goto st_fail;
		}

		return sc;
	}

	/*
	 *	Parse any scheduler-specific configuration.
	 */
	if (!config) {
		MEM(sc->config = talloc_zero(sc, fr_schedule_config_t));
		sc->config->max_networks = 1;
		sc->config->max_workers = 4;
	} else {
		sc->config = config;

		if (sc->config->max_networks != 1) sc->config->max_networks = 1;
		if (sc->config->max_workers < 1) sc->config->max_workers = 1;
		if (sc->config->max_workers > 64) sc->config->max_workers = 64;

	}

	/*
	 *	Create the list which holds the workers.
	 */
	fr_dlist_init(&sc->workers, fr_schedule_worker_t, entry);

	memset(&sc->network_sem, 0, sizeof(sc->network_sem));
	if (sem_init(&sc->network_sem, 0, SEMAPHORE_LOCKED) != 0) {
		ERROR("Failed creating semaphore: %s", fr_syserror(errno));
		talloc_free(sc);
		return NULL;
	}

	memset(&sc->worker_sem, 0, sizeof(sc->worker_sem));
	if (sem_init(&sc->worker_sem, 0, SEMAPHORE_LOCKED) != 0) {
		ERROR("Failed creating semaphore: %s", fr_syserror(errno));
		talloc_free(sc);
		return NULL;
	}

	/*
	 *	Create the network thread first.
	 *	@todo - create multiple network threads
	 */
	sc->sn = talloc_zero(sc, fr_schedule_network_t);
	sc->sn->sc = sc;
	sc->sn->id = 0;

	if (fr_schedule_pthread_create(&sc->sn->pthread_id, fr_schedule_network_thread, sc->sn) < 0) {
		ERROR("Failed creating network thread %s", fr_strerror());
		goto fail;
	}

	SEM_WAIT_INTR(&sc->network_sem);
	if (sc->sn->status != FR_CHILD_RUNNING) {
	fail:
		fr_schedule_destroy(sc);
		if (sc->sn->ctx) TALLOC_FREE(sc->sn->ctx);
		TALLOC_FREE(sc->sn);
		return NULL;
	}

	/*
	 *	Create all of the workers.
	 */
	for (i = 0; i < sc->config->max_workers; i++) {
		DEBUG3("Creating %u/%u workers", i, sc->config->max_workers);

		/*
		 *	Create a worker "glue" structure
		 */
		sw = talloc_zero(sc, fr_schedule_worker_t);
		if (!sw) {
			ERROR("Worker %u - Failed allocating memory", i);
			break;
		}

		sw->id = i;
		sw->sc = sc;
		sw->status = FR_CHILD_INITIALIZING;
		fr_dlist_insert_head(&sc->workers, sw);

		if (fr_schedule_pthread_create(&sw->pthread_id, fr_schedule_worker_thread, sw) < 0) {
			ERROR("Failed creating worker %u: %s", i, fr_strerror());
			break;
		}
	}


	/*
	 *	Wait for all of the workers to signal us that either
	 *	they've started, OR there's been a problem and they
	 *	can't start.
	 */
	for (i = 0; i < (unsigned int)fr_dlist_num_elements(&sc->workers); i++) {
		DEBUG3("Waiting for semaphore from worker %u/%u",
		       i, (unsigned int)fr_dlist_num_elements(&sc->workers));
		SEM_WAIT_INTR(&sc->worker_sem);
	}

	/*
	 *	See if all of the workers have started.
	 */
	for (sw = fr_dlist_head(&sc->workers);
	     sw != NULL;
	     sw = next) {

		next = fr_dlist_next(&sc->workers, sw);

		if (sw->status != FR_CHILD_RUNNING) {
			fr_dlist_remove(&sc->workers, sw);
			continue;
		}
	}

	/*
	 *	Failed to start some workers, refuse to do anything!
	 */
	if ((unsigned int)fr_dlist_num_elements(&sc->workers) < sc->config->max_workers) {
		fr_schedule_destroy(sc);
		return NULL;
	}

	for (sw = fr_dlist_head(&sc->workers), i = 0;
	     sw != NULL;
	     sw = next, i++) {
		char buffer[32];

		next = fr_dlist_next(&sc->workers, sw);

		snprintf(buffer, sizeof(buffer), "%d", i);
		if (fr_command_register_hook(NULL, buffer, sw->worker, cmd_worker_table) < 0) {
			ERROR("Failed adding worker commands: %s", fr_strerror());
			goto st_fail;
		}
	}

	if (fr_command_register_hook(NULL, "0", sc->sn->nr, cmd_network_table) < 0) {
		ERROR("Failed adding network commands: %s", fr_strerror());
		goto st_fail;
	}

	if (sc) INFO("Scheduler created successfully with %u networks and %u workers",
		     sc->config->max_networks, (unsigned int)fr_dlist_num_elements(&sc->workers));

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
	unsigned int i;
	fr_schedule_worker_t *sw;

	sc->running = false;

	/*
	 *	Single threaded mode: kill the only network / worker we have.
	 */
	if (sc->el) {
		/*
		 *	Destroy the network side first.  It tells the
		 *	workers to close.
		 */
		fr_network_destroy(sc->single_network);
		fr_worker_destroy(sc->single_worker);
		goto done;
	}

	rad_assert(sc->sn);
	rad_assert(fr_dlist_num_elements(&sc->workers) > 0);

	/*
	 *	If the network thread is running, tell it to exit, and
	 *	wait for it to do so.  Once it's exited, we know that
	 *	this thread can use the network channels to tell the
	 *	workers that the network side is going away.
	 */
	if (sc->sn->status == FR_CHILD_RUNNING) {
		fr_network_exit(sc->sn->nr);
		SEM_WAIT_INTR(&sc->network_sem);
		fr_network_destroy(sc->sn->nr);
	}

	/*
	 *	Wait for all worker threads to finish.  THEN clean up
	 *	modules.  Otherwise, the modules will be removed from
	 *	underneath the workers!
	 */
	for (i = 0; i < (unsigned int)fr_dlist_num_elements(&sc->workers); i++) {
		DEBUG2("Waiting for semaphore indicating exit %u/%u", i,
		       (unsigned int)fr_dlist_num_elements(&sc->workers));
		SEM_WAIT_INTR(&sc->worker_sem);
	}

	/*
	 *	Clean up the exited workers.
	 */
	while ((sw = fr_dlist_head(&sc->workers)) != NULL) {
		fr_dlist_remove(&sc->workers, sw);

		/*
		 *	Ensure that the thread has exited before
		 *	cleaning up the context.
		 *
		 *	This also ensures that the child threads have
		 *	exited before the main thread cleans up the
		 *	module instances.
		 */
		if (pthread_join(sw->pthread_id, NULL) != 0) {
			ERROR("Failed joining worker %i: %s", sw->id, fr_syserror(errno));
		} else {
			DEBUG2("Worker %i exited", sw->id);
		}
		talloc_free(sw->ctx);
	}

	TALLOC_FREE(sc->sn->ctx);

	sem_destroy(&sc->network_sem);
	sem_destroy(&sc->worker_sem);
done:
	/*
	 *	Now that all of the workers are done, we can return to
	 *	the caller, and have him dlclose() the modules.
	 */
	talloc_free(sc);

	return 0;
}

/** Add a fr_listen_t to a scheduler.
 *
 * @param[in] sc the scheduler
 * @param[in] li the ctx and callbacks for the transport.
 * @return
 *	- NULL on error
 *	- the fr_network_t that the socket was added to.
 */
fr_network_t *fr_schedule_listen_add(fr_schedule_t *sc, fr_listen_t *li)
{
	fr_network_t *nr;

	(void) talloc_get_type_abort(sc, fr_schedule_t);

	if (sc->el) {
		nr = sc->single_network;
	} else {
		nr = sc->sn->nr;
	}

	if (fr_network_listen_add(nr, li) < 0) return NULL;

	return nr;
}

/** Add a directory NOTE_EXTEND to a scheduler.
 *
 * @param[in] sc the scheduler
 * @param[in] li the ctx and callbacks for the transport.
 * @return
 *	- NULL on error
 *	- the fr_network_t that the socket was added to.
 */
fr_network_t *fr_schedule_directory_add(fr_schedule_t *sc, fr_listen_t *li)
{
	fr_network_t *nr;

	(void) talloc_get_type_abort(sc, fr_schedule_t);

	if (sc->el) {
		nr = sc->single_network;
	} else {
		nr = sc->sn->nr;
	}

	if (fr_network_directory_add(nr, li) < 0) return NULL;

	return nr;
}
