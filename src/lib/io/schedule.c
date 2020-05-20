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
#include <freeradius-devel/server/trigger.h>

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

/** Scheduler specific information for worker threads
 *
 * Wraps a fr_worker_t, tracking additional information that
 * the scheduler uses.
 */
typedef struct {
	TALLOC_CTX	*ctx;			//!< our allocation ctx
	fr_event_list_t	*el;			//!< our event list
	pthread_t	pthread_id;		//!< the thread of this worker

	unsigned int	id;			//!< a unique ID
	int		uses;			//!< how many network threads are using it
	fr_time_t	cpu_time;		//!< how much CPU time this worker has used

	fr_dlist_t	entry;			//!< our entry into the linked list of workers

	fr_schedule_t	*sc;			//!< the scheduler we are running under

	fr_schedule_child_status_t status;	//!< status of the worker
	fr_worker_t	*worker;		//!< the worker data structure
} fr_schedule_worker_t;

/** Scheduler specific information for network threads
 *
 * Wraps a fr_network_t, tracking additional information that
 * the scheduler uses.
 */
typedef struct {
	TALLOC_CTX	*ctx;			//!< our allocation ctx
	pthread_t	pthread_id;		//!< the thread of this network

	unsigned int	id;			//!< a unique ID
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
	fr_schedule_thread_detach_t		worker_thread_detach;

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
	char worker_name[32];

	worker_id = sw->id;		/* Store the current worker ID */

	snprintf(worker_name, sizeof(worker_name), "Worker %d", sw->id);

	sw->ctx = ctx = talloc_init("%s", worker_name);
	if (!ctx) {
		ERROR("%s - Failed allocating memory", worker_name);
		goto fail;
	}

	INFO("%s - Starting", worker_name);

	sw->el = fr_event_list_alloc(ctx, NULL, NULL);
	if (!sw->el) {
		PERROR("%s - Failed creating event list", worker_name);
		goto fail;
	}


	sw->worker = fr_worker_create(ctx, sw->el, worker_name, sc->log, sc->lvl, NULL);
	if (!sw->worker) {
		PERROR("%s - Failed creating worker", worker_name);
		goto fail;
	}

	/*
	 *	@todo make this a registry
	 */
	if (sc->worker_thread_instantiate) {
		CONF_SECTION	*cs;
		char		section_name[32];

		snprintf(section_name, sizeof(section_name), "%u", sw->id);

		cs = cf_section_find(sc->cs, "worker", section_name);
		if (!cs) cs = cf_section_find(sc->cs, "worker", NULL);

		if (sc->worker_thread_instantiate(sw->ctx, sw->el, cs) < 0) {
			PERROR("%s - Failed calling thread instantiate", worker_name);
			goto fail;
		}
	}

	sw->status = FR_CHILD_RUNNING;

	(void) fr_network_worker_add(sc->sn->nr, sw->worker);

	DEBUG3("%s - Started", worker_name);

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

	status = FR_CHILD_EXITED;

fail:
	sw->status = status;

	if (sw->worker) {
		fr_worker_destroy(sw->worker);
		sw->worker = NULL;
	}

	INFO("%s - Exiting", worker_name);

	if (sc->worker_thread_detach) sc->worker_thread_detach(NULL);	/* Fixme once we figure out what uctx should be */

	/*
	 *	Not looping at this point, but may catch timer/fd
	 *	insertions being done after the thread should have
	 *	exited.
	 */
	if (sw->el) fr_event_loop_exit(sw->el, 1);

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
	char				network_name[32];

	snprintf(network_name, sizeof(network_name), "Network %d", sn->id);

	INFO("%s - Starting", network_name);

	sn->ctx = ctx = talloc_init("%s", network_name);
	if (!ctx) {
		ERROR("%s - Failed allocating memory", network_name);
		goto fail;
	}

	el = fr_event_list_alloc(ctx, NULL, NULL);
	if (!el) {
		PERROR("%s - Failed creating event list", network_name);
		goto fail;
	}

	sn->nr = fr_network_create(ctx, el, network_name, sc->log, sc->lvl);
	if (!sn->nr) {
		PERROR("%s - Failed creating network", network_name);
		goto fail;
	}

	sn->status = FR_CHILD_RUNNING;

	/*
	 *	Tell the originator that the thread has started.
	 */
	sem_post(&sc->network_sem);

	DEBUG3("%s - Started", network_name);

	/*
	 *	Print out statistics for this network IO handler.
	 */
	if (sc->config->stats_interval) (void) fr_event_timer_in(sn, el, &sn->ev, sn->sc->config->stats_interval, stats_timer, sn);

	/*
	 *	Call the main event processing loop of the network
	 *	thread Will not return until the worker is about
	 *      to exit.
	 */
	fr_network(sn->nr);

	status = FR_CHILD_EXITED;

fail:
	sn->status = status;

	INFO("%s - Exiting", network_name);

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
 * @param[in] ctx				talloc context.
 * @param[in] el				event list, only for single-threaded mode.
 * @param[in] logger				destination for all logging messages.
 * @param[in] lvl				log level.
 * @param[in] worker_thread_instantiate		callback for new worker threads.
 * @param[in] worker_thread_detach		callback to destroy resources
 *						allocated by worker_thread_instantiate.
 * @param[in] config				configuration for the scheduler
 * @return
 *	- NULL on error
 *	- fr_schedule_t new scheduler
 */
fr_schedule_t *fr_schedule_create(TALLOC_CTX *ctx, fr_event_list_t *el,
				  fr_log_t *logger, fr_log_lvl_t lvl,
				  fr_schedule_thread_instantiate_t worker_thread_instantiate,
				  fr_schedule_thread_detach_t worker_thread_detach,
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

	/*
	 *	Glue workers into the trigger code.
	 */
	trigger_worker_request_add = fr_worker_request_add;

	sc->config = config;
	sc->el = el;
	sc->log = logger;
	sc->lvl = lvl;

	sc->worker_thread_instantiate = worker_thread_instantiate;
	sc->worker_thread_detach = worker_thread_detach;
	sc->running = true;

	/*
	 *	If we're single-threaded, create network / worker, and insert them into the event loop.
	 */
	if (el) {
		sc->single_network = fr_network_create(sc, el, "Network", sc->log, sc->lvl);
		if (!sc->single_network) {
			PERROR("Failed creating network");
		pre_instantiate_st_fail:
			talloc_free(sc);
			return NULL;
		}

		sc->single_worker = fr_worker_create(sc, el, "Worker", sc->log, sc->lvl, NULL);
		if (!sc->single_worker) {
			PERROR("Failed creating worker");
			fr_network_destroy(sc->single_network);
			goto pre_instantiate_st_fail;
		}

		/*
		 *	Parent thread-specific data from the single_worker
		 */
		if (sc->worker_thread_instantiate) {
			CONF_SECTION *subcs;

			subcs = cf_section_find(sc->cs, "worker", "0");
			if (!subcs) subcs = cf_section_find(sc->cs, "worker", NULL);

			if (sc->worker_thread_instantiate(sc->single_worker, el, subcs) < 0) {
				PERROR("Failed calling thread instantiate");
			destroy_both:
				fr_network_destroy(sc->single_network);
				fr_worker_destroy(sc->single_worker);
				goto pre_instantiate_st_fail;
			}
		}

		if (fr_command_register_hook(NULL, "0", sc->single_worker, cmd_worker_table) < 0) {
			PERROR("Failed adding worker commands");
		st_fail:
			if (sc->worker_thread_detach) sc->worker_thread_detach(NULL);
			goto destroy_both;
		}

		if (fr_command_register_hook(NULL, "0", sc->single_network, cmd_network_table) < 0) {
			PERROR("Failed adding network commands");
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
		PERROR("Failed creating network thread");
		goto fail;
	}

	SEM_WAIT_INTR(&sc->network_sem);
	if (sc->sn->status != FR_CHILD_RUNNING) {
	fail:
		if (sc->sn->ctx) TALLOC_FREE(sc->sn->ctx);
		TALLOC_FREE(sc->sn);
		fr_schedule_destroy(&sc);
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
			PERROR("Failed creating worker %u", i);
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
		fr_schedule_destroy(&sc);
		return NULL;
	}

	for (sw = fr_dlist_head(&sc->workers), i = 0;
	     sw != NULL;
	     sw = next, i++) {
		char buffer[32];

		next = fr_dlist_next(&sc->workers, sw);

		snprintf(buffer, sizeof(buffer), "%d", i);
		if (fr_command_register_hook(NULL, buffer, sw->worker, cmd_worker_table) < 0) {
			PERROR("Failed adding worker commands");
			goto st_fail;
		}
	}

	if (fr_command_register_hook(NULL, "0", sc->sn->nr, cmd_network_table) < 0) {
		PERROR("Failed adding network commands");
		goto st_fail;
	}

	if (sc) INFO("Scheduler created successfully with %u networks and %u workers",
		     sc->config->max_networks, (unsigned int)fr_dlist_num_elements(&sc->workers));

	return sc;
}

/** Destroy a scheduler, and tell its child threads to exit.
 *
 * @param[in] sc_to_free the scheduler
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_schedule_destroy(fr_schedule_t **sc_to_free)
{
	fr_schedule_t		*sc = *sc_to_free;
	unsigned int		i;
	fr_schedule_worker_t	*sw;

	if (!sc) return 0;

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

	if (!fr_cond_assert(sc->sn)) return -1;
	if (!fr_cond_assert(fr_dlist_num_elements(&sc->workers) > 0)) return -1;

	/*
	 *	If the network thread is running, tell it to exit, and
	 *	wait for it to do so.  Once it's exited, we know that
	 *	this thread can use the network channels to tell the
	 *	workers that the network side is going away.
	 */
	if (sc->sn->status == FR_CHILD_RUNNING) {
		fr_fatal_assert_msg(fr_network_exit(sc->sn->nr) == 0, "%s", fr_strerror());
		SEM_WAIT_INTR(&sc->network_sem);
	}

	/*
	 *	Wait for all worker threads to finish.  THEN clean up
	 *	modules.  Otherwise, the modules will be removed from
	 *	underneath the workers!
	 */
	for (i = 0; i < (unsigned int)fr_dlist_num_elements(&sc->workers); i++) {
		DEBUG2("Scheduler - Waiting for semaphore indicating worker exit %u/%u", i,
		       (unsigned int)fr_dlist_num_elements(&sc->workers));
		SEM_WAIT_INTR(&sc->worker_sem);
	}
	DEBUG2("Scheduler - All workers indicated exit complete");

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
			DEBUG2("Worker %i joined (cleaned up)", sw->id);
		}
		talloc_free(sw->ctx);
	}

	TALLOC_FREE(sc->sn->ctx);

	sem_destroy(&sc->network_sem);
	sem_destroy(&sc->worker_sem);
done:
	/*
	 *	Now that all of the workers are done, we can return to
	 *	the caller, and have it dlclose() the modules.
	 */
	talloc_free(sc);
	*sc_to_free = NULL;

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
