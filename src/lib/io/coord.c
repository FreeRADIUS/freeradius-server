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
#include <freeradius-devel/io/thread.h>
#include <freeradius-devel/io/coord_priv.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/util/syserror.h>

#include <stdalign.h>

#define FR_CONTROL_ID_COORD_WORKER_ATTACH	(1)	//!< Message sent from worker to attach to a coordinator
#define FR_CONTROL_ID_COORD_WORKER_DETACH	(2)	//!< Message sent from worker to detach from a coordinator
#define FR_CONTROL_ID_COORD_WORKER_ACK		(3)	//!< Message sent to worker to acknowledge attach / detach
#define FR_CONTROL_ID_COORD_DATA		(4)	//!< Worker <-> coordinator message to pass data to a callback

static fr_dlist_head_t	*coord_regs = NULL;
static fr_dlist_head_t	*coord_threads = NULL;
static fr_rb_tree_t	coords = (fr_rb_tree_t){ .num_elements = 0 };

/** A coordinator which receives messages from workers
 */
struct fr_coord_s {
	fr_coord_reg_t			*coord_reg;	//!< Coordinator registration details.
	fr_event_list_t			*el;		//!< Coordinator event list.
	fr_rb_node_t			node;		//!< Entry in the tree of coordinators.
	fr_coord_cb_reg_t		*callbacks;	//!< Array of callbacks for worker -> coordinator messages.
	uint32_t			num_callbacks;	//!< Number of callbacks defined.
	fr_coord_cb_inst_t		**cb_inst;	//!< Array of callback instance specific data.

	uint32_t			max_workers;	//!< Maximum number of workers we expect.
	uint32_t			num_workers;	//!< How many workers are attached.

	fr_control_t			*coord_recv_control;	//!< Control plane for worker -> coordinator messages.
	fr_atomic_queue_t		*coord_recv_aq;		//!< Atomic queue for worker -> coordinator
	fr_ring_buffer_t		**coord_send_rb;	//!< Ring buffers for coordinator -> worker control messages.
	fr_control_t			**coord_send_control;	//!< Control planes for coordinator -> worker messages.
	fr_message_set_t		**coord_send_ms;	//!< Message sets for coordinator -> worker data.
	fr_atomic_queue_t		**coord_send_aq;	//!< Atomic queues for coordinator -> worker data.

	bool				exiting;	//!< Is this coordinator shutting down.
	bool				single_thread;	//!< Are we in single thread mode.
};

/** The worker end of worker <-> coordinator communication.
 */
struct fr_coord_worker_s {
	fr_coord_t			*coord;			//!< Coordinator this worker is related to
	fr_ring_buffer_t		*worker_send_rb;	//!< Ring buffer for worker -> coordinator control plane
	fr_message_set_t		*worker_send_ms;	//!< Message set for worker -> coordinator messages
	fr_control_t			*worker_recv_control;	//!< Coordinator -> worker control plane
	fr_atomic_queue_t		*worker_recv_aq;	//!< Atomic queue for coordinator -> worker messages
	fr_coord_worker_cb_reg_t	*callbacks;		//!< Callbacks for coordinator -> worker messages
	uint32_t			num_callbacks;		//!< Number of callbacks registered.
};

/** A coordinator registration
 */
struct fr_coord_reg_s {
	char const			*name;			//!< Name for debugging.
	fr_dlist_t			entry;			//!< Entry in list of registrations.
	fr_coord_cb_reg_t		*coord_cb;		//!< Callbacks for worker -> coordinator messages.
	fr_coord_worker_cb_reg_t	*worker_cb;		//!< Callbacks for coordinator -> worker messages.
	size_t				worker_send_size;	//!< Initial size for worker -> coordinator ring buffer.
	size_t				coord_send_size;	//!< Initial size for coordinator -> worker ring buffer.
};

/** Scheduler specific information for coordinator threads
 */
typedef struct {
	fr_thread_t			thread;			//!< common thread information - must be first!

	uint32_t			max_workers;		//!< Maximum number of workers which will connect to this coordinator.
	fr_coord_reg_t			*coord_reg;		//!< Coordinator registration details.
	fr_coord_t			*coord;			//!< The coordinator data structure.
	fr_sem_t			*sem;			//!< For inter-thread signaling.
} fr_schedule_coord_t;

/** Control plane message used for workers attaching / detaching to coordinators
 */
typedef struct {
	uint32_t			worker;			//!< Worker ID
	fr_control_t			*worker_recv_control;	//!< Control plane to send messages to this worker
	fr_atomic_queue_t		*worker_recv_aq;	//!< Atomic queue to send data to this worker
} fr_coord_worker_attach_msg_t;

typedef struct {
	uint32_t			worker;			//!< Worker ID
	bool				exiting;		//!< Is the server exiting
} fr_coord_worker_detach_msg_t;

/** Compare coordinators by registration
 */
static int8_t coord_cmp(void const *one, void const *two)
{
	fr_coord_t const *a = one, *b = two;

	return CMP(a->coord_reg, b->coord_reg);
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
		MEM(coord_regs = talloc_zero(NULL, fr_dlist_head_t));
		fr_dlist_init(coord_regs, fr_coord_reg_t, entry);
	}

	MEM(coord_reg = talloc(ctx, fr_coord_reg_t));
	*coord_reg = (fr_coord_reg_t) {
		.name = reg_ctx->name,
		.coord_cb = reg_ctx->coord_cb,
		.worker_cb = reg_ctx->worker_cb,
		.worker_send_size = reg_ctx->worker_send_size ? reg_ctx->worker_send_size : 4096,
		.coord_send_size = reg_ctx->coord_send_size ? reg_ctx->coord_send_size : 4096,
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
	int			ret;

	fr_dlist_remove(coord_regs, coord_reg);

	/*
	 *	In single threaded mode just free the registration.
	 */
	if (!coord_threads) goto free;

	fr_dlist_foreach(coord_threads, fr_schedule_coord_t, sc) {
		if (sc->coord_reg == coord_reg) {
			if ((ret = pthread_join(sc->thread.pthread_id, NULL)) != 0) {
				ERROR("Failed joining coordinator %s: %s", coord_reg->name, fr_syserror(ret));
			} else {
				DEBUG2("Coordinator %s joined (cleaned up)", coord_reg->name);
			}

			fr_dlist_remove(coord_threads, sc);
			talloc_free(sc);
			break;
		}
	}

free:
	talloc_free(coord_reg);

	if (fr_dlist_num_elements(coord_regs) == 0) TALLOC_FREE(coord_regs);
}

/** Callback for a coordinator receiving data from a worker
 */
static void coord_data_recv(void *ctx, void const *data, size_t data_size, fr_time_t now)
{
	fr_coord_t		*coord = talloc_get_type_abort(ctx, fr_coord_t);
	fr_coord_msg_t		cm;
	fr_coord_data_t		*cd;
	fr_dbuff_t		dbuff;

	fr_assert(data_size == sizeof(cm));
	memcpy(&cm, data, data_size);

	if (unlikely(!fr_atomic_queue_pop(coord->coord_recv_aq, (void **)&cd))) return;

	DEBUG3("Coordinator %s got data from worker %d for callback %d",
	       coord->coord_reg->name, cm.worker, cd->coord_cb_id);

	if (cd->coord_cb_id >= coord->num_callbacks) {
		ERROR("Received data for callback %d which is not defined", cd->coord_cb_id);
		fr_message_done(&cd->m);
		return;
	}

	fr_dbuff_init(&dbuff, (uint8_t const *)cd->m.data, cd->m.data_size);
	coord->callbacks[cd->coord_cb_id].callback(coord, cm.worker, &dbuff, now,
						   coord->cb_inst[cd->coord_cb_id] ?
						   coord->cb_inst[cd->coord_cb_id]->inst_data : NULL,
						   coord->callbacks[cd->coord_cb_id].uctx);
	fr_message_done(&cd->m);
}

/** Callback for a worker receiving data from a coordinator
 */
static void coord_worker_data_recv(void *ctx, void const *data, size_t data_size, fr_time_t now)
{
	fr_coord_worker_t	*cw = talloc_get_type_abort(ctx, fr_coord_worker_t);
	fr_coord_msg_t		cm;
	fr_coord_data_t		*cd;
	fr_dbuff_t		dbuff;

	fr_assert(data_size == sizeof(cm));
	memcpy(&cm, data, data_size);

	if (unlikely(!fr_atomic_queue_pop(cw->worker_recv_aq, (void **)&cd))) return;

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
	fr_coord_t				*coord = talloc_get_type_abort(ctx, fr_coord_t);
	fr_coord_worker_attach_msg_t const	*msg = data;
	fr_coord_msg_t				ack;

	fr_assert(data_size == sizeof(fr_coord_worker_attach_msg_t));
	fr_assert(msg->worker < coord->max_workers);

	DEBUG2("Worker %d attached to %s", msg->worker, coord->coord_reg->name);
	coord->num_workers++;
	coord->coord_send_control[msg->worker] = msg->worker_recv_control;
	coord->coord_send_aq[msg->worker] = msg->worker_recv_aq;

	ack.worker = msg->worker;
	fr_control_message_send(coord->coord_send_control[msg->worker], coord->coord_send_rb[msg->worker],
				FR_CONTROL_ID_COORD_WORKER_ACK, &ack, sizeof(ack));
}

/** Callback run by a coordinator when a worker detaches
 */
static void coord_worker_detach(void *ctx, void const *data, NDEBUG_UNUSED size_t data_size, UNUSED fr_time_t now)
{
	fr_coord_t				*coord = talloc_get_type_abort(ctx, fr_coord_t);
	fr_coord_worker_detach_msg_t const	*msg = data;
	fr_coord_msg_t				ack;

	fr_assert(data_size == sizeof(fr_coord_worker_detach_msg_t));
	fr_assert(msg->worker < coord->max_workers);

	DEBUG2("Worker %d detached from %s", msg->worker, coord->coord_reg->name);
	coord->num_workers--;

	ack.worker = msg->worker;
	fr_control_message_send(coord->coord_send_control[msg->worker], coord->coord_send_rb[msg->worker],
				FR_CONTROL_ID_COORD_WORKER_ACK, &ack, sizeof(fr_coord_msg_t));

	coord->coord_send_control[msg->worker] = NULL;
	coord->coord_send_aq[msg->worker] = NULL;
	if (msg->exiting) coord->exiting = true;
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
	fr_coord_cb_reg_t	*cb = coord_reg->coord_cb;
	fr_atomic_queue_t	*aq;

	MEM(coord = talloc(ctx, fr_coord_t));
	*coord = (fr_coord_t) {
		.el = el,
		.coord_reg = coord_reg,
		.single_thread = single_thread,
		.max_workers = max_workers
	};

	/* Allocate atomic queue / control for receiving messages from workers */
	aq = fr_atomic_queue_alloc(coord, FR_CONTROL_MAX_MESSAGES);
	if (!aq) {
		fr_strerror_const("Failed creating worker -> coordinator atomic queue");
	fail:
		talloc_free(coord);
		return NULL;
	}
	coord->coord_recv_control = fr_control_create(coord, el, aq, 5);
	if (!coord->coord_recv_control) {
		fr_strerror_const("Failed creating worker -> coordinator control plane");
		goto fail;
	}

	/* Allocate atomic queue for workers sending data to coordinators */
	coord->coord_recv_aq = fr_atomic_queue_alloc(coord, FR_CONTROL_MAX_MESSAGES);
	if (!coord->coord_recv_aq) {
		fr_strerror_const("Failed creating worker -> coordinator data atomic queue");
		goto fail;
	}

	if (fr_control_callback_add(&coord->coord_recv_control, FR_CONTROL_ID_COORD_WORKER_ATTACH,
				    coord, coord_worker_attach) < 0) goto fail;
	if (fr_control_callback_add(&coord->coord_recv_control, FR_CONTROL_ID_COORD_WORKER_DETACH,
				    coord, coord_worker_detach) < 0) goto fail;
	if (fr_control_callback_add(&coord->coord_recv_control, FR_CONTROL_ID_COORD_DATA,
				    coord, coord_data_recv) < 0) goto fail;

	/* Count the number of callbacks defined, for sanity checking messages */
	while (cb->callback) {
		coord->num_callbacks++;
		cb++;
	}
	coord->callbacks = coord_reg->coord_cb;

	if (fr_control_open(coord->coord_recv_control) < 0) {
		fr_strerror_const("Failed opening control plane");
		goto fail;
	}

	MEM(coord->coord_send_rb = talloc_array(coord, fr_ring_buffer_t *, coord->max_workers));
	MEM(coord->coord_send_ms = talloc_array(coord, fr_message_set_t *, coord->max_workers));
	for (i = 0; i < coord->max_workers; i++) {
		coord->coord_send_rb[i] = fr_ring_buffer_create(coord, FR_CONTROL_MAX_MESSAGES * FR_CONTROL_MAX_SIZE);
		if (!coord->coord_send_rb[i]) goto fail;

		coord->coord_send_ms[i] = fr_message_set_create(coord, FR_CONTROL_MAX_MESSAGES, sizeof(fr_coord_data_t),
								coord_reg->coord_send_size, true);
		if (!coord->coord_send_ms[i]) goto fail;
	}
	MEM(coord->coord_send_control = talloc_zero_array(coord, fr_control_t *, coord->max_workers));
	MEM(coord->coord_send_aq = talloc_zero_array(coord, fr_atomic_queue_t *, coord->max_workers));

	MEM(coord->cb_inst = talloc_zero_array(coord, fr_coord_cb_inst_t *, coord->num_callbacks));

	for (i = 0; i < coord->num_callbacks; i++) {
		if (!coord->callbacks[i].inst_create) continue;
		coord->cb_inst[i] = coord->callbacks[i].inst_create(coord, coord, coord->el, coord->single_thread,
								    coord->callbacks[i].uctx);
		if (!coord->cb_inst[i]) goto fail;
	}

	return coord;
}

/** Run the event loop for a coordinator thread when in multi-threaded mode
 */
static void fr_coordinate(fr_coord_t *coord)
{
	uint32_t		i;
	fr_coord_cb_inst_t	*cb_inst;

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

		/*
		 *	Run any registered instance specific event callbacks
		 */
		for (i = 0; i < coord->num_callbacks; i++) {
			cb_inst = coord->cb_inst[i];
			if (cb_inst && cb_inst->event_cb) cb_inst->event_cb(coord->el, cb_inst->inst_data);
		}
	}

	return;
}

/** Entry point for a coordinator thread
 */
static void *fr_coordinate_thread(void *arg)
{
	fr_schedule_coord_t	*sc = talloc_get_type_abort(arg, fr_schedule_coord_t);
	fr_coord_reg_t		*coord_reg = sc->coord_reg;
	fr_thread_status_t	status = FR_THREAD_FAIL;
	char			coordinate_name[64];

	snprintf(coordinate_name, sizeof(coordinate_name), "Coordinate %s", coord_reg->name);

	if (fr_thread_setup(&sc->thread, coordinate_name) < 0) goto fail;

	sc->coord = fr_coord_create(sc->thread.ctx, sc->thread.el, coord_reg, false, sc->max_workers);
	if (!sc->coord) {
		PERROR("%s - Failed creating coordinator thread", coordinate_name);
		goto fail;
	}

	/*
	 *	Create all the thread specific data for the coordinator thread
	 */
	if (fr_thread_instantiate(sc->thread.ctx, sc->thread.el) < 0) goto fail;

	/*
	 *	Tell the originator that the thread has started.
	 */
	fr_thread_start(&sc->thread, sc->sem);

	fr_coordinate(sc->coord);

	status = FR_THREAD_EXITED;

fail:
	fr_thread_detach();

	fr_thread_exit(&sc->thread, status, sc->sem);

	return NULL;
}

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
	int num = 0;

	if (!coord_regs) return 0;

	MEM(coord_threads = talloc(NULL, fr_dlist_head_t));
	fr_dlist_init(coord_threads, fr_schedule_coord_t, thread.entry);
	fr_rb_inline_talloc_init(&coords, fr_coord_t, node, coord_cmp, NULL);

	fr_dlist_foreach(coord_regs, fr_coord_reg_t, coord_reg) {
		fr_schedule_coord_t *sc;

		MEM(sc = talloc_zero(coord_threads, fr_schedule_coord_t));

		sc->thread.id = num++;
		sc->coord_reg = coord_reg;
		sc->max_workers = num_workers;
		sc->sem = sem;

		if (fr_thread_create(&sc->thread.pthread_id, fr_coordinate_thread, sc) < 0) {
			talloc_free(sc);
			PERROR("Failed creating coordinator %s", coord_reg->name);
			return -1;
		};

		fr_dlist_insert_tail(coord_threads, sc);
	}

	/*
	 *	Wait for all the coordinators to start.
	 */
	if (fr_thread_wait_list(sem, coord_threads) < 0) {
		ERROR("Failed creating coordinator threads");
		return -1;
	}

	/*
	 *	Insert the coordinators in the tree
	 */
	fr_dlist_foreach(coord_threads, fr_schedule_coord_t, sc) {
		fr_assert(sc->coord);
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

	while ((coord = fr_rb_iter_init_inorder(&coords, &iter))) {
		fr_rb_iter_delete_inorder(&coords, &iter);
		talloc_free(coord);
	}
}

/** Start coordinators in single threaded mode
 */
int fr_coords_create(TALLOC_CTX *ctx, fr_event_list_t *el)
{
	if (!coord_regs) return 0;

	fr_rb_inline_talloc_init(&coords, fr_coord_t, node, coord_cmp, NULL);

	fr_dlist_foreach(coord_regs, fr_coord_reg_t, coord_reg) {
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
 *
 * @param cw		Worker which is detaching.
 * @param exiting	Is the server exiting.
 */
int fr_coord_detach(fr_coord_worker_t *cw, bool exiting)
{
	fr_coord_worker_detach_msg_t	*msg;

	msg = talloc(cw, fr_coord_worker_detach_msg_t);
	msg->worker = fr_schedule_worker_id();
	msg->exiting = exiting;

	if (fr_control_message_send(cw->coord->coord_recv_control, cw->worker_send_rb,
				    FR_CONTROL_ID_COORD_WORKER_DETACH,
				    msg, sizeof(fr_coord_worker_detach_msg_t)) < 0) return -1;

	if (!cw->coord->single_thread) fr_control_wait(cw->worker_recv_control);

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
	fr_coord_worker_cb_reg_t	*cb_reg = coord_reg->worker_cb;
	fr_coord_worker_attach_msg_t	msg;
	fr_coord_t			find;
	fr_atomic_queue_t		*aq;

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

	aq = fr_atomic_queue_alloc(cw, 1024);
	cw->worker_recv_aq = fr_atomic_queue_alloc(cw, FR_CONTROL_MAX_MESSAGES);
	cw->worker_recv_control = fr_control_create(cw, el, aq, 0);
	cw->worker_send_rb = fr_ring_buffer_create(cw, FR_CONTROL_MAX_MESSAGES * FR_CONTROL_MAX_SIZE);
	cw->worker_send_ms = fr_message_set_create(cw, FR_CONTROL_MAX_MESSAGES, sizeof(fr_coord_data_t),
						   coord_reg->worker_send_size, true);

	while (cb_reg->callback) {
		cw->num_callbacks++;
		cb_reg++;
	}
	cw->callbacks = coord_reg->worker_cb;

	if (fr_control_callback_add(&cw->worker_recv_control, FR_CONTROL_ID_COORD_WORKER_ACK,
				    cw, coordinate_worker_ack) < 0) goto fail;
	if (fr_control_callback_add(&cw->worker_recv_control, FR_CONTROL_ID_COORD_DATA,
				    cw, coord_worker_data_recv) < 0) goto fail;

	if (fr_control_open(cw->worker_recv_control) < 0) goto fail;

	msg.worker_recv_control = cw->worker_recv_control;
	msg.worker_recv_aq = cw->worker_recv_aq;
	msg.worker = fr_schedule_worker_id();

	if (fr_control_message_send(cw->coord->coord_recv_control, cw->worker_send_rb,
				    FR_CONTROL_ID_COORD_WORKER_ATTACH,
				    &msg, sizeof(fr_coord_worker_attach_msg_t)) < 0) goto fail;

	if (!cw->coord->single_thread) fr_control_wait(cw->worker_recv_control);

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

	cd = (fr_coord_data_t *)fr_message_alloc(coord->coord_send_ms[worker_id], (fr_message_t *)cd,
						 fr_dbuff_used(dbuff));
	if (!cd) return -1;

	memcpy(cd->m.data, fr_dbuff_buff(dbuff), fr_dbuff_used(dbuff));
	cd->coord_cb_id = cb_id;
	if (!fr_atomic_queue_push(coord->coord_send_aq[worker_id], cd)) {
		fr_message_done((fr_message_t *)cd);
		return -1;
	}
	return fr_control_message_send(coord->coord_send_control[worker_id], coord->coord_send_rb[worker_id],
				       FR_CONTROL_ID_COORD_DATA,
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
		if (!coord->coord_send_control[i]) continue;
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

	cd = (fr_coord_data_t *) fr_message_alloc(cw->worker_send_ms, (fr_message_t *)cd, fr_dbuff_used(dbuff));
	if (!cd) return -1;

	memcpy(cd->m.data, fr_dbuff_buff(dbuff), fr_dbuff_used(dbuff));
	cd->coord_cb_id = cb_id;
	if (!fr_atomic_queue_push(cw->coord->coord_recv_aq, cd)) {
		fr_message_done((fr_message_t *)cd);
		return -1;
	}

	return fr_control_message_send(cw->coord->coord_recv_control, cw->worker_send_rb,
				       FR_CONTROL_ID_COORD_DATA, &cm, sizeof(fr_coord_msg_t));
}

/** Insert instance specific pre-event callbacks
 */
int fr_coord_pre_event_insert(fr_event_list_t *el)
{
	fr_coord_t		*coord;
	fr_rb_iter_inorder_t	iter;
	fr_coord_cb_inst_t	*cb_inst;
	uint32_t		i;

	if (!coord_regs) return 0;

	for (coord = fr_rb_iter_init_inorder(&coords, &iter);
	     coord != NULL;
	     coord = fr_rb_iter_next_inorder(&coords, &iter)) {
		for (i = 0; i < coord->num_callbacks; i++) {
			cb_inst = coord->cb_inst[i];
			if (cb_inst && cb_inst->event_pre_cb &&
			    fr_event_pre_insert(el, cb_inst->event_pre_cb, cb_inst->inst_data) < 0) {
				return -1;
			}
		}
	}
	return 0;
}

/** Insert instance specific post-event callbacks
 */
int fr_coord_post_event_insert(fr_event_list_t *el)
{
	fr_coord_t		*coord;
	fr_rb_iter_inorder_t	iter;
	fr_coord_cb_inst_t	*cb_inst;
	uint32_t		i;

	if (!coord_regs) return 0;

	for (coord = fr_rb_iter_init_inorder(&coords, &iter);
	     coord != NULL;
	     coord = fr_rb_iter_next_inorder(&coords, &iter)) {
		for (i = 0; i < coord->num_callbacks; i++) {
			cb_inst = coord->cb_inst[i];
			if (cb_inst && cb_inst->event_post_cb &&
			    fr_event_post_insert(el, cb_inst->event_post_cb, cb_inst->inst_data) < 0) {
				return -1;
			}
		}
	}
	return 0;
}
