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
 * @brief Coordination thread management
 * @file io/coord.c
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/io/schedule.h>
#include <freeradius-devel/io/coord_priv.h>
#include <freeradius-devel/server/main_config.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/tls/base.h>
#include <freeradius-devel/util/dlist.h>
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/unlang/base.h>

#include <stdalign.h>

#define FR_CONTROL_ID_COORD_WORKER_ATTACH	(1)	//!< Message sent from worker to attach to a coordinator
#define FR_CONTROL_ID_COORD_WORKER_DETACH	(2)	//!< Message sent from worker to detach from a coordinator
#define FR_CONTROL_ID_COORD_WORKER_ACK		(3)	//!< Message sent to worker to acknowledge attach / detach
#define FR_CONTROL_ID_COORD_CALLBACK		(4)	//!< Worker <-> coordinator message to run a callback

static fr_dlist_head_t	*coord_regs = NULL;
static fr_dlist_head_t	*coord_threads = NULL;
static fr_rb_tree_t	coords = (fr_rb_tree_t){ .num_elements = 0 };
static module_list_t	*coord_modules;

/** A coordinator which receives messages from workers
 */
struct fr_coord_s {
	fr_coord_reg_t			*coord_reg;	//!< Coordinator registration details.
	fr_event_list_t			*el;		//!< Coordinator event list.
	fr_rb_node_t			node;		//!< Entry in the tree of coordinators.
	fr_coord_cb_reg_t		*callbacks;	//!< Array of callbacks for worker -> coordinator messages.
	uint32_t			num_callbacks;	//!< Number of callbacks defined.

	uint32_t			max_workers;	//!< Maximum number of workers we expect.
	uint32_t			num_workers;	//!< How many workers are attached.

	fr_atomic_queue_t		*aq;		//!< Atomic queue for worker -> coordinator control messages.
	fr_control_t			*control;	//!< Control plane for worker -> coordinator messages.
	fr_atomic_queue_t		*data_aq;	//!< Atomic queue for worker -> coordinator
	fr_ring_buffer_t		**rb;		//!< Ring buffers for coordinator -> worker control messages.
	fr_message_set_t		**ms;		//!< Message sets for coordinator -> worker messages.
	fr_control_t			**worker_control;	//!< Control planes for coordinator -> worker messages.
	fr_atomic_queue_t		**worker_data_aq;	//!< Atomic queues for coordinator -> worker data.

	bool				exiting;	//!< Is this coordinator shutting down.
	bool				single_thread;	//!< Are we in single thread mode.
};

/** The worker end of worker <-> coordinator communication.
 */
struct fr_coord_worker_s {
	fr_coord_t			*coord;			//!< Coordinator this worker is related to
	fr_atomic_queue_t		*aq;			//!< Atomic queue for coordinator -> worker control plane
	fr_ring_buffer_t		*rb;			//!< Ring buffer for worker -> coordinator control plane
	fr_control_t			*control;		//!< Coordinator -> worker control plane
	fr_atomic_queue_t		*data_aq;		//!< Atomic queue for coordinator -> worker messages
	fr_message_set_t		*ms;			//!< Message set for worker -> coordinator messages
	fr_coord_worker_cb_reg_t	*callbacks;		//!< Callbacks for coordinator -> worker messages
	uint32_t			num_callbacks;		//!< Number of callbacks registered.
};

/** A coordinator registration
 */
struct fr_coord_reg_s {
	char const			*name;			//!< Name for debugging.
	fr_dlist_t			entry;			//!< Entry in list of registrations.
	fr_coord_cb_reg_t		*inbound_cb;		//!< Callbacks for worker -> coordinator messages.
	fr_coord_worker_cb_reg_t	*outbound_cb;		//!< Callbacks for coordinator -> worker messages.
	size_t				inbound_rb_size;	//!< Initial size for worker -> coordinator ring buffer.
	size_t				outbound_rb_size;	//!< Initial size for coordinator -> worker ring buffer.
	fr_time_delta_t			max_request_time;	//!< Maximum time for coordinator request processing.
	fr_slab_config_t		reuse;			//!< Request slab allocation config.
	CONF_SECTION			*server_cs;		//!< Virtual server containing coordinator process sections.
};

/** Scheduler specific information for coordinator threads
 */
typedef struct {
	TALLOC_CTX			*ctx;			//!< Our allocation ctx
	fr_event_list_t			*el;			//!< Event list for this coordinator.
	pthread_t			pthread_id;		//!< the thread of this coordinator
	uint32_t			max_workers;		//!< Maximum number of workers which will connect to this coordinator.
	fr_coord_reg_t			*coord_reg;		//!< Coordinator registration details.
	fr_coord_t			*coord;			//!< The coordinator data structure.
	fr_sem_t			*sem;			//!< For inter-thread signaling.
	fr_dlist_t			entry;			//!< Entry in list of running coordinator threads.
} fr_schedule_coord_t;

/** Control plane message used for workers attaching / detaching to coordinators
 */
typedef struct {
	uint32_t			worker;			//!< Worker ID
	fr_control_t			*control;		//!< Control plane to send messages to this worker
	fr_atomic_queue_t		*data_aq;		//!< Atomic queue to send data to this worker
} fr_coord_worker_msg_t;

/** Compare coordinators by registration
 */
static int8_t coord_cmp(void const *one, void const *two)
{
	fr_coord_t const *a = one, *b = two;

	return CMP(a->coord_reg, b->coord_reg);
}

/** Free the module list when the registrations are freed
 */
static int _coord_regs_free(UNUSED fr_dlist_head_t *to_free)
{
	TALLOC_FREE(coord_modules);
	return 0;
}

/** Register a coordinator
 *
 * To be called from mod_instantiate of a module which uses a coordinator
 *
 * @param ctx		to allocate registration under
 * @param reg_ctx	Registration data
 * @return
 *	- coordination registration on success
 *	- NULL on failure
 */
fr_coord_reg_t *fr_coord_register(TALLOC_CTX *ctx, fr_coord_reg_ctx_t *reg_ctx)
{
	fr_coord_reg_t		*coord_reg;

	/* Allocate the list of registered coordinators if not already done */
	if (!coord_regs) {
		coord_regs = talloc_zero(NULL, fr_dlist_head_t);
		talloc_set_destructor(coord_regs, _coord_regs_free);
		fr_dlist_init(coord_regs, fr_coord_reg_t, entry);
		MEM(coord_modules = module_list_alloc(NULL, &module_list_type_global, "coord", true));
	}

	coord_reg = talloc(ctx, fr_coord_reg_t);
	*coord_reg = (fr_coord_reg_t) {
		.name = reg_ctx->name,
		.inbound_cb = reg_ctx->inbound_cb,
		.outbound_cb = reg_ctx->outbound_cb,
		.inbound_rb_size = reg_ctx->inbound_rb_size ? reg_ctx->inbound_rb_size : 4096,
		.outbound_rb_size = reg_ctx->outbound_rb_size ? reg_ctx->outbound_rb_size : 4096,
		.max_request_time = fr_time_delta_eq(reg_ctx->max_request_time, fr_time_delta_from_msec(0)) ?
			main_config->worker.max_request_time : reg_ctx->max_request_time,
	};

	fr_dlist_insert_tail(coord_regs, coord_reg);

	return coord_reg;
}

/** De-register a coordinator
 *
 * To be called from mod_detach of a module which uses a coordinator
 *
 * When running in threaded mode, will wait for the coordinator to exit.
 *
 * @param coord_reg	to de-register
 */
void fr_coord_deregister(fr_coord_reg_t *coord_reg)
{
	fr_schedule_coord_t	*sc = NULL;
	int			ret;

	fr_dlist_remove(coord_regs, coord_reg);

	if (!coord_threads) goto free;

	while ((sc = fr_dlist_next(coord_threads, sc))) {
		if (sc->coord_reg == coord_reg) {
			if ((ret = pthread_join(sc->pthread_id, NULL)) != 0) {
				ERROR("Failed joining coordinator %s: %s", coord_reg->name, fr_syserror(ret));
			} else {
				DEBUG2("Coordinator %s joined (cleaned up)", coord_reg->name);
			}
			fr_dlist_remove(coord_threads, sc);
			break;
		}
	}

free:
	talloc_free(sc);
	talloc_free(coord_reg);

	if (fr_dlist_num_elements(coord_regs) == 0) TALLOC_FREE(coord_regs);
}

/** Callback for a coordinator receiving a message from a worker
 */
static void coord_recv_message(void *ctx, void const *data, size_t data_size, fr_time_t now)
{
	fr_coord_t		*coord = talloc_get_type_abort(ctx, fr_coord_t);
	fr_coord_msg_t		cm;
	fr_coord_data_t		*cd;
	fr_dbuff_t		dbuff;

	fr_assert(data_size == sizeof(cm));
	memcpy(&cm, data, data_size);

	if (unlikely(!fr_atomic_queue_pop(coord->data_aq, (void **)&cd))) return;

	DEBUG3("Coordinator %s got message from worker %d for callback %d", coord->coord_reg->name, cm.worker, cd->coord_cb_id);

	if (cd->coord_cb_id >= coord->num_callbacks) {
		ERROR("Received message for callback %d which is not defined", cd->coord_cb_id);
		fr_message_done(&cd->m);
		return;
	}

	fr_dbuff_init(&dbuff, (uint8_t const *)cd->m.data, cd->m.data_size);
	coord->callbacks[cd->coord_cb_id].callback(coord, cm.worker, &dbuff, now, coord->callbacks[cd->coord_cb_id].uctx);
	fr_message_done(&cd->m);
}

/** Callback for a worker receiving a message from a coordinator
 */
static void coord_worker_recv_message(void *ctx, void const *data, size_t data_size, UNUSED fr_time_t now)
{
	fr_coord_worker_t	*cw = talloc_get_type_abort(ctx, fr_coord_worker_t);
	fr_coord_msg_t		cm;
	fr_coord_data_t		*cd;
	fr_dbuff_t		dbuff;

	fr_assert(data_size == sizeof(cm));
	memcpy(&cm, data, data_size);

	if (unlikely(!fr_atomic_queue_pop(cw->data_aq, (void **)&cd))) return;

	DEBUG3("Coordinator %s sent message for callback %d", cw->coord->coord_reg->name, cd->coord_cb_id);

	if (cd->coord_cb_id >= cw->num_callbacks) {
		ERROR("Received message for callback %d which is not defined", cd->coord_cb_id);
		fr_message_done(&cd->m);
		return;
	}

	fr_dbuff_init(&dbuff, (uint8_t const *)cd->m.data, cd->m.data_size);
	cw->callbacks[cd->coord_cb_id].callback(cw, &dbuff, now, cw->callbacks[cd->coord_cb_id].uctx);
	fr_message_done(&cd->m);
}

/** Callback run by a coordinator when a worker attaches
 */
static void coord_worker_attach(void *ctx, void const *data, NDEBUG_UNUSED size_t data_size, UNUSED fr_time_t now)
{
	fr_coord_t			*coord = talloc_get_type_abort(ctx, fr_coord_t);
	fr_coord_worker_msg_t const	*msg = data;
	fr_coord_msg_t			ack;

	fr_assert(data_size == sizeof(fr_coord_worker_msg_t));
	fr_assert(msg->worker < coord->max_workers);

	DEBUG2("Worker %d attached to %s", msg->worker, coord->coord_reg->name);
	coord->num_workers++;
	coord->worker_control[msg->worker] = msg->control;
	coord->worker_data_aq[msg->worker] = msg->data_aq;

	ack.worker = msg->worker;
	fr_control_message_send(coord->worker_control[msg->worker], coord->rb[msg->worker],
				FR_CONTROL_ID_COORD_WORKER_ACK, &ack, sizeof(ack));
}

/** Callback run by a coordinator when a worker detaches
 */
static void coord_worker_detach(void *ctx, void const *data, NDEBUG_UNUSED size_t data_size, UNUSED fr_time_t now)
{
	fr_coord_t			*coord = talloc_get_type_abort(ctx, fr_coord_t);
	fr_coord_worker_msg_t const	*msg = data;
	fr_coord_msg_t			ack;

	fr_assert(data_size == sizeof(fr_coord_worker_msg_t));
	fr_assert(msg->worker < coord->max_workers);

	DEBUG2("Worker %d detached from %s", msg->worker, coord->coord_reg->name);
	coord->num_workers--;

	ack.worker = msg->worker;
	fr_control_message_send(coord->worker_control[msg->worker], coord->rb[msg->worker],
				FR_CONTROL_ID_COORD_WORKER_ACK, &ack, sizeof(fr_coord_msg_t));

	coord->worker_control[msg->worker] = NULL;
	coord->worker_data_aq[msg->worker] = NULL;
	coord->exiting = true;
}

/** Create a coordinator from its registration
 *
 * @param ctx		to allocate the coordinator in
 * @param el		Event list to run this coordinator
 * @param coord_reg	Registration to configure this coordinator
 * @param single_thread	Is the server in single thread mode
 * @param max_workers	The maximum number of workers which will attach
 * @return
 *	- the coordinator on success
 *	- NULL on failure
 */
static fr_coord_t *fr_coord_create(TALLOC_CTX *ctx, fr_event_list_t *el, fr_coord_reg_t *coord_reg,
				   bool single_thread, uint32_t max_workers)
{
	fr_coord_t		*coord;
	uint32_t		i;
	fr_coord_cb_reg_t	*cb = coord_reg->inbound_cb;

	coord = talloc(ctx, fr_coord_t);
	*coord = (fr_coord_t) {
		.el = el,
		.coord_reg = coord_reg,
		.single_thread = single_thread,
		.max_workers = max_workers
	};

	/* Allocate atomic queue / control for receiving messages from workers */
	coord->aq = fr_atomic_queue_alloc(coord, FR_CONTROL_MAX_MESSAGES);
	if (!coord->aq) {
		fr_strerror_const("Failed creating worker -> coordinator atomic queue");
	fail:
		talloc_free(coord);
		return NULL;
	}
	coord->control = fr_control_create(coord, el, coord->aq, 5);
	if (!coord->control) {
		fr_strerror_const("Failed creating worker -> coordinator control plane");
		goto fail;
	}

	/* Allocate atomic queue for workers sending data to coordinators */
	coord->data_aq = fr_atomic_queue_alloc(coord, FR_CONTROL_MAX_MESSAGES);
	if (!coord->data_aq) {
		fr_strerror_const("Failed creating worker -> coordinator data atomic queue");
		goto fail;
	}

	if (fr_control_callback_add(&coord->control, FR_CONTROL_ID_COORD_WORKER_ATTACH,
				    coord, coord_worker_attach) < 0) goto fail;
	if (fr_control_callback_add(&coord->control, FR_CONTROL_ID_COORD_WORKER_DETACH,
				    coord, coord_worker_detach) < 0) goto fail;
	if (fr_control_callback_add(&coord->control, FR_CONTROL_ID_COORD_CALLBACK,
				    coord, coord_recv_message) < 0) goto fail;

	/* Count the number of callbacks defined, for sanity checking messages */
	while (cb->callback) {
		coord->num_callbacks++;
		cb++;
	}
	coord->callbacks = coord_reg->inbound_cb;

	if (fr_control_open(coord->control) < 0) {
		fr_strerror_const("Failed opening control plane");
		goto fail;
	}

	coord->rb = talloc_array(coord, fr_ring_buffer_t *, coord->max_workers);
	coord->ms = talloc_array(coord, fr_message_set_t *, coord->max_workers);
	for (i = 0; i < coord->max_workers; i++) {
		coord->rb[i] = fr_ring_buffer_create(coord, FR_CONTROL_MAX_MESSAGES * FR_CONTROL_MAX_SIZE);
		if (!coord->rb[i]) goto fail;

		coord->ms[i] = fr_message_set_create(coord, FR_CONTROL_MAX_MESSAGES, sizeof(fr_coord_data_t),
						     coord_reg->outbound_rb_size, true);
		if (!coord->ms[i]) goto fail;
	}
	MEM(coord->worker_control = talloc_zero_array(coord, fr_control_t *, coord->max_workers));
	MEM(coord->worker_data_aq = talloc_zero_array(coord, fr_atomic_queue_t *, coord->max_workers));

	return coord;
}

static void fr_coordinate(fr_coord_t *coord)
{
	/*
	 *	Run until we're told to exit AND the number of
	 *	workers has dropped to zero.
	 *
	 *	Whenever a worker detaches, coord->num_workers
	 *	is decremented, so when	coord->num_workers == 0,
	 *	all workers have detached and are no longer using
	 *	the channel.
	 */
	while (likely(!(coord->exiting && (coord->num_workers == 0)))) {
		int num_events;

		/*
		 *	Check the event list.  If there's an error
		 *	(e.g. exit), we stop looping and clean up.
		 */
		DEBUG4("Gathering events");
		num_events = fr_event_corral(coord->el, fr_time(), true);
		DEBUG4("%u event(s) pending%s",
		       num_events == -1 ? 0 : num_events, num_events == -1 ? " - event loop exiting" : "");
		if (num_events < 0) break;

		/*
		 *	Service outstanding events.
		 */
		if (num_events > 0) {
			DEBUG4("Servicing event(s)");
			fr_event_service(coord->el);
		}
	}

	return;
}

/** Entry point for a coordinator thread
 */
static void *fr_coordinate_thread(void *arg)
{
	TALLOC_CTX		*ctx;
	fr_schedule_coord_t	*sc = talloc_get_type_abort(arg, fr_schedule_coord_t);
	fr_coord_reg_t		*coord_reg = sc->coord_reg;
	char			coordinate_name[64];

#ifndef __APPLE__
	sigset_t		sigset;
	sigfillset(&sigset);
	pthread_sigmask(SIG_BLOCK, &sigset, NULL);
#endif

	snprintf(coordinate_name, sizeof(coordinate_name), "Coordinate %s", coord_reg->name);

	INFO("%s - Starting", coordinate_name);

	sc->ctx = ctx = talloc_init("%s", coordinate_name);

	if (!ctx) {
		ERROR("%s - Failed allocating memory", coordinate_name);
		goto fail;
	}

	sc->el = fr_event_list_alloc(ctx, NULL, NULL);
	if (!sc->el) {
		PERROR("%s - Failed creating event list", coordinate_name);
		goto fail;
	}

	sc->coord = fr_coord_create(ctx, sc->el, coord_reg, false, sc->max_workers);

	if (!sc->coord) {
		PERROR("%s - Failed creating coordinator thread", coordinate_name);
		goto fail;
	}

	/*
	 *	Create all the thread specific data for the coordinator thread
	 */
	if (modules_rlm_thread_instantiate(ctx, sc->el) < 0) goto fail;
	if (virtual_servers_thread_instantiate(ctx, sc->el) < 0) goto fail;
	if (xlat_thread_instantiate(ctx, sc->el) < 0) goto fail;
	if (unlang_thread_instantiate(ctx) < 0) goto fail;
#ifdef WITH_TLS
	if (fr_openssl_thread_init(main_config->openssl_async_pool_init,
				   main_config->openssl_async_pool_max) < 0) goto fail;
#endif

	sem_post(sc->sem);

	fr_coordinate(sc->coord);

fail:
	INFO("%s - Exiting", coordinate_name);

	xlat_thread_detach();
	virtual_servers_thread_detach();
	modules_rlm_thread_detach();

	talloc_free(ctx);

	return NULL;
}

#define SEM_WAIT_INTR(_x) do {if (sem_wait(_x) == 0) break;} while (errno == EINTR)

/** Start all registered coordinator threads in multi-threaded mode
 *
 * @param num_workers	The number of workers which will be attaching
 * @param sem		Semaphore to use signalling the threads are ready
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int fr_coord_start(uint32_t num_workers, fr_sem_t *sem)
{
	fr_coord_reg_t		*coord_reg = NULL;
	fr_schedule_coord_t	*sc;

	if (!coord_regs) return 0;

	MEM(coord_threads = talloc(NULL, fr_dlist_head_t));
	fr_dlist_init(coord_threads, fr_schedule_coord_t, entry);
	fr_rb_inline_talloc_init(&coords, fr_coord_t, node, coord_cmp, NULL);

	while ((coord_reg = fr_dlist_next(coord_regs, coord_reg))) {
		MEM(sc = talloc_zero(coord_threads, fr_schedule_coord_t));

		sc->coord_reg = coord_reg;
		sc->max_workers = num_workers;
		sc->sem = sem;
		if (fr_schedule_pthread_create(&sc->pthread_id, fr_coordinate_thread, sc) < 0) {
			PERROR("Failed creating coordinator %s", coord_reg->name);
			return -1;
		};
		fr_dlist_insert_tail(coord_threads, sc);
	}

	/*
	 *	See if all the coordinators have started.
	 */
	sc = NULL;
	while ((sc = fr_dlist_next(coord_threads, sc))) {
		DEBUG3("Waiting for semaphore from coordinator %s", sc->coord_reg->name);
		SEM_WAIT_INTR(sem);
	}

	/*
	 *	Insert the coordinators in the tree
	 */
	sc = NULL;
	while ((sc = fr_dlist_next(coord_threads, sc))) {
		fr_rb_insert(&coords, sc->coord);
	}

	return 0;
}

/** Clean up coordinators in single threaded mode
 */
void fr_coords_destroy(void)
{
	fr_coord_t		*coord;
	fr_rb_iter_inorder_t	iter;

	if (fr_rb_num_elements(&coords) == 0) return;

	while((coord = fr_rb_iter_init_inorder(&coords, &iter))) {
		fr_rb_iter_delete_inorder(&coords, &iter);
		talloc_free(coord);
	}
}

/** Start coordinators in single threaded mode
 */
int fr_coords_create(TALLOC_CTX *ctx, fr_event_list_t *el)
{
	fr_coord_reg_t	*coord_reg = NULL;

	if (!coord_regs) return 0;

	fr_rb_inline_talloc_init(&coords, fr_coord_t, node, coord_cmp, NULL);

	while ((coord_reg = fr_dlist_next(coord_regs, coord_reg))) {
		char		coordinate_name[64];
		fr_coord_t	*coord;

		snprintf(coordinate_name, sizeof(coordinate_name), "Coordinator %s", coord_reg->name);

		INFO("%s - Starting", coordinate_name);

		coord = fr_coord_create(ctx, el, coord_reg, true, 1);

		if (!coord) {
			PERROR("%s - Failed creating coordinator thread", coordinate_name);
			return -1;
		}

		fr_rb_insert(&coords, coord);
	}

	return 0;
}

/** Signal a coordinator that a worker wants to detach
 */
int fr_coord_detach(fr_coord_worker_t *cw)
{
	fr_coord_worker_msg_t	*msg;

	msg = talloc(cw, fr_coord_worker_msg_t);
	msg->control = cw->control;
	msg->data_aq = cw->data_aq;
	msg->worker = fr_schedule_worker_id();

	fr_control_message_send(cw->coord->control, cw->rb, FR_CONTROL_ID_COORD_WORKER_DETACH,
				msg, sizeof(fr_coord_worker_msg_t));
	if (!cw->coord->single_thread) fr_control_wait(cw->control);

	return 0;
}

/** A worker got an ack from a coordinator in response to attach / detach
 */
static void coordinate_worker_ack(UNUSED void *ctx, NDEBUG_UNUSED void const *data, NDEBUG_UNUSED size_t data_size,
				  UNUSED fr_time_t now)
{
#ifndef NDEBUG
	fr_coord_msg_t const		*cm = data;

	fr_assert(data_size == sizeof(fr_coord_msg_t));
	fr_assert(cm->worker == (uint32_t)fr_schedule_worker_id());
#endif
}

/** Attach a worker to a coordinator
 *
 * @param ctx		To allocate worker structure in
 * @param el		Event list for control messages
 * @param coord_reg	Coordinator registration to attach to.
 * @return
 *	- Worker structure for coordinator use on success
 *	- NULL on failure
 */
fr_coord_worker_t *fr_coord_attach(TALLOC_CTX *ctx, fr_event_list_t *el, fr_coord_reg_t *coord_reg)
{
	fr_coord_worker_t		*cw;
	fr_coord_worker_cb_reg_t	*cb_reg = coord_reg->outbound_cb;
	fr_coord_worker_msg_t		msg;
	fr_coord_t			find;

	cw = talloc_zero(ctx, fr_coord_worker_t);

	find = (fr_coord_t) {
		.coord_reg = coord_reg
	};
	cw->coord = fr_rb_find(&coords, &find);
	if (!cw->coord) {
	fail:
		talloc_free(cw);
		return NULL;
	}

	cw->aq = fr_atomic_queue_alloc(cw, 1024);
	cw->data_aq = fr_atomic_queue_alloc(cw, FR_CONTROL_MAX_MESSAGES);
	cw->control = fr_control_create(cw, el, cw->aq, 0);
	cw->rb = fr_ring_buffer_create(cw, FR_CONTROL_MAX_MESSAGES * FR_CONTROL_MAX_SIZE);
	cw->ms = fr_message_set_create(cw, FR_CONTROL_MAX_MESSAGES, sizeof(fr_coord_data_t),
				       coord_reg->inbound_rb_size, true);

	while (cb_reg->callback) {
		cw->num_callbacks++;
		cb_reg++;
	}
	cw->callbacks = coord_reg->outbound_cb;

	if (fr_control_callback_add(&cw->control, FR_CONTROL_ID_COORD_WORKER_ACK,
				    cw, coordinate_worker_ack) < 0) goto fail;
	if (fr_control_callback_add(&cw->control, FR_CONTROL_ID_COORD_CALLBACK,
				    cw, coord_worker_recv_message) < 0) goto fail;

	if (fr_control_open(cw->control) < 0) goto fail;;

	msg.control = cw->control;
	msg.data_aq = cw->data_aq;
	msg.worker = fr_schedule_worker_id();

	if (fr_control_message_send(cw->coord->control, cw->rb, FR_CONTROL_ID_COORD_WORKER_ATTACH,
				    &msg, sizeof(fr_coord_worker_msg_t)) < 0) goto fail;

	if (!cw->coord->single_thread) fr_control_wait(cw->control);

	return cw;
}

/** Send generic data from a coordinator to a worker
 *
 * @param coord		Coordinator which is sending the data.
 * @param worker_id	Worker to send data to.
 * @param cb_id		Callback ID for the worker to run.
 * @param dbuff		Buffer containing data to send.
 * @return
 *	- 0 on success
 *	- <0 on failure
 */
int fr_coord_to_worker_send(fr_coord_t *coord, uint32_t worker_id, uint32_t cb_id, fr_dbuff_t *dbuff)
{
	fr_coord_msg_t		cm;
	fr_coord_data_t		*cd = NULL;

	cm = (fr_coord_msg_t) {
		.worker = worker_id
	};

	cd = (fr_coord_data_t *)fr_message_alloc(coord->ms[worker_id], (fr_message_t *)cd, fr_dbuff_used(dbuff));
	if (!cd) return -1;

	memcpy(cd->m.data, fr_dbuff_buff(dbuff), fr_dbuff_used(dbuff));
	cd->coord_cb_id = cb_id;
	if (!fr_atomic_queue_push(coord->worker_data_aq[worker_id], cd)) {
		fr_message_done((fr_message_t *)cd);
		return -1;
	}
	return fr_control_message_send(coord->worker_control[worker_id], coord->rb[worker_id],
				       FR_CONTROL_ID_COORD_CALLBACK,
				       &cm, sizeof(fr_coord_msg_t));
}

/** Broadcast data from a coordinator to all workers
 *
 * @param coord		Coordinator which is sending the data.
 * @param cb_id		Callback ID for the workers to run.
 * @param dbuff		Buffer containing data to send.
 * @return
 *	- 0 on success
 *	- <0 on failure - indicating the number of sends which failed.
 */
int fr_coord_to_worker_broadcast(fr_coord_t *coord, uint32_t cb_id, fr_dbuff_t *dbuff)
{
	uint32_t	i;
	int		failed = 0;

	for (i = 0; i < coord->max_workers; i++) {
		if (!coord->worker_control[i]) continue;
		if (fr_coord_to_worker_send(coord, i, cb_id, dbuff) < 0) failed++;
	}

	return 0 - failed;
}

/** Send data from a worker to a coordinator
 *
 * @param cw		Worker side of coordinator sending the data.
 * @param cb_id		Callback ID for the coordinator to run.
 * @param dbuff		Buffer containing data to send.
 * @return
 *	- 0 on success
 *	- < 0 on failure
 */
int fr_worker_to_coord_send(fr_coord_worker_t *cw, uint32_t cb_id, fr_dbuff_t *dbuff)
{
	fr_coord_msg_t		cm;
	fr_coord_data_t		*cd = NULL;

	cm = (fr_coord_msg_t) {
		.worker = fr_schedule_worker_id()
	};

	cd = (fr_coord_data_t *)fr_message_alloc(cw->ms, (fr_message_t *)cd, fr_dbuff_used(dbuff));
	if (!cd) return -1;

	memcpy(cd->m.data, fr_dbuff_buff(dbuff), fr_dbuff_used(dbuff));
	cd->coord_cb_id = cb_id;
	if (!fr_atomic_queue_push(cw->coord->data_aq, cd)) {
		fr_message_done((fr_message_t *)cd);
		return -1;
	}

	return fr_control_message_send(cw->coord->control, cw->rb, FR_CONTROL_ID_COORD_CALLBACK,
				       &cm, sizeof(fr_coord_msg_t));
}
