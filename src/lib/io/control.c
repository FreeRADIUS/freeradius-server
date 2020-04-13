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
 * @brief Control-plane signaling
 * @file io/control.c
 *
 * @copyright 2016 Alan DeKok (aland@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/io/control.h>
#include <freeradius-devel/io/ring_buffer.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/util/misc.h>

#include <fcntl.h>
#include <string.h>
#include <sys/event.h>

#define FR_CONTROL_MAX_TYPES	(32)

/*
 *	Debugging, mainly for channel_test
 */
#if 0
#define MPRINT(...) fprintf(stderr, __VA_ARGS__)
#else
#define MPRINT(...)
#endif

/**
 *  Status of control messages
 */
typedef enum fr_control_message_status_t {
	FR_CONTROL_MESSAGE_FREE = 0,			//!< the message is free
	FR_CONTROL_MESSAGE_USED,			//!< the message is used (set only by originator)
	FR_CONTROL_MESSAGE_DONE				//!< the message is done (set only by receiver)
} fr_control_message_status_t;


/**
 *  The header for the control message
 */
typedef struct {
	fr_control_message_status_t	status;		//!< status of this message
	uint32_t			id;		//!< ID of this message
	size_t				data_size;     	//!< size of the data we're sending
} fr_control_message_t;


typedef struct {
	uint32_t			id;		//!< id of this callback
	void				*ctx;		//!< context for the callback
	fr_control_callback_t		callback;	//!< the function to call
} fr_control_ctx_t;


/**
 *  The control structure.
 */
struct fr_control_s {
	fr_event_list_t		*el;			//!< our event list

	fr_atomic_queue_t	*aq;			//!< destination AQ

	int			pipe[2];       		//!< our pipes

	bool			same_thread;		//!< are the two ends in the same thread

	fr_control_ctx_t 	type[FR_CONTROL_MAX_TYPES];	//!< callbacks
};

static void pipe_read(UNUSED fr_event_list_t *el, int fd, UNUSED int flags, void *uctx)
{
	fr_control_t *c = talloc_get_type_abort(uctx, fr_control_t);
	ssize_t i, num;
	fr_time_t now;
	char read_buffer[256];
	uint8_t	data[256];

	num = read(fd, read_buffer, sizeof(read_buffer));
	if (num <= 0) return;

	now = fr_time();

	for (i = 0; i < num; i++) {
		uint32_t id = 0;
		size_t message_size;

		message_size = fr_control_message_pop(c->aq, &id, data, sizeof(data));
		if (!message_size) return;

		if (id >= FR_CONTROL_MAX_TYPES) continue;

		if (!c->type[id].callback) continue;

		c->type[id].callback(c->type[id].ctx, data, message_size, now);
	}
}

/** Free a control structure
 *
 *  This function really only calls the underlying "garbage collect".
 *
 * @param[in] c the control structure
 */
static int _control_free(fr_control_t *c)
{
	(void) talloc_get_type_abort(c, fr_control_t);

	(void) fr_event_fd_delete(c->el, c->pipe[0], FR_EVENT_FILTER_IO);

	close(c->pipe[0]);
	close(c->pipe[1]);

	return 0;
}

/** Create a control-plane signaling path.
 *
 * @param[in] ctx the talloc context
 * @param[in] el the event list for the control socket
 * @param[in] aq the atomic queue where we will be pushing message data
 * @return
 *	- NULL on error
 *	- fr_control_t on success
 */
fr_control_t *fr_control_create(TALLOC_CTX *ctx, fr_event_list_t *el, fr_atomic_queue_t *aq)
{
	fr_control_t *c;

	c = talloc_zero(ctx, fr_control_t);
	if (!c) {
		fr_strerror_printf("Failed allocating memory");
		return NULL;
	}
	c->el = el;
	c->aq = aq;

	if (pipe((int *) &c->pipe) < 0) {
		talloc_free(c);
		fr_strerror_printf("Failed opening pipe for control socket: %s", fr_syserror(errno));
		return NULL;
	}
	talloc_set_destructor(c, _control_free);

	/*
	 *	We don't want reads from the pipe to be blocking.
	 */
	(void) fcntl(c->pipe[0], F_SETFL, O_NONBLOCK | FD_CLOEXEC);
	(void) fcntl(c->pipe[1], F_SETFL, O_NONBLOCK | FD_CLOEXEC);

	if (fr_event_fd_insert(c, el, c->pipe[0], pipe_read, NULL, NULL, c) < 0) {
		talloc_free(c);
		fr_strerror_printf("Failed adding FD to event list control socket: %s", fr_strerror());
		return NULL;
	}

	return c;
}


/** Clean up messages in a control-plane buffer
 *
 *  Find the oldest messages which are marked FR_CONTROL_MESSAGE_DONE,
 *  and mark them FR_CONTROL_MESSAGE_FREE.
 *
 * @param[in] c the fr_control_t
 * @param[in] rb the callers ring buffer for message allocation.
 * @return
 *	- <0 there are still messages used
 *	- 0 the control list is empty.
 */
int fr_control_gc(UNUSED fr_control_t *c, fr_ring_buffer_t *rb)
{
	while (true) {
		size_t room, message_size;
		fr_control_message_t *m;

		(void) fr_ring_buffer_start(rb, (uint8_t **) &m, &room);
		if (room == 0) break;

		fr_assert(m != NULL);
		fr_assert(room >= sizeof(*m));

		fr_assert(m->status != FR_CONTROL_MESSAGE_FREE);

		if (m->status != FR_CONTROL_MESSAGE_DONE) break;

		m->status = FR_CONTROL_MESSAGE_FREE;

		/*
		 *	Each message is aligned to a 64-byte boundary,
		 *	for cache contention issues.
		 */
		message_size = sizeof(*m);
		message_size += m->data_size;
		message_size += 63;
		message_size &= ~(size_t) 63;
		fr_ring_buffer_free(rb, message_size);
	}

	/*
	 *	Maybe we failed to garbage collect everything?
	 */
	if (fr_ring_buffer_used(rb) > 0) {
		fr_strerror_printf("Data still in control buffers");
		return -1;
	}

	return 0;
}


/** Allocate a control message
 *
 * @param[in] c the control structure
 * @param[in] rb the callers ring buffer for message allocation.
 * @param[in] id the ident of this message.
 * @param[in] data the data to write to the control plane
 * @param[in] data_size the size of the data to write to the control plane.
 * @return
 *	- NULL on error
 *	- fr_message_t on success
 */
static fr_control_message_t *fr_control_message_alloc(fr_control_t *c, fr_ring_buffer_t *rb, uint32_t id, void *data, size_t data_size)
{
	size_t message_size;
	fr_control_message_t *m;
	uint8_t *p;

	message_size = sizeof(*m);
	message_size += data_size;
	message_size += 63;
	message_size &= ~(size_t) 63;

	m = (fr_control_message_t *) fr_ring_buffer_alloc(rb, message_size);
	if (!m) {
		(void) fr_control_gc(c, rb);
		m = (fr_control_message_t *) fr_ring_buffer_alloc(rb, message_size);
		if (!m) {
			fr_strerror_printf_push("Failed allocating from ring buffer");
			return NULL;
		}
	}

	m->status = FR_CONTROL_MESSAGE_USED;
	m->id = id;
	m->data_size = data_size;

	p = (uint8_t *) m;
	memcpy(p + sizeof(*m), data, data_size);

	return m;

}


/** Push a control-plane message
 *
 *  This function is called ONLY from the originating thread.
 *
 * @param[in] c the control structure
 * @param[in] rb the callers ring buffer for message allocation.
 * @param[in] id the ident of this message.
 * @param[in] data the data to write to the control plane
 * @param[in] data_size the size of the data to write to the control plane.
 * @return
 *	- -2 on ring buffer full
 *	- <0 on error
 *	- 0 on success
 */
int fr_control_message_push(fr_control_t *c, fr_ring_buffer_t *rb, uint32_t id, void *data, size_t data_size)
{
	fr_control_message_t *m;

	(void) talloc_get_type_abort(c, fr_control_t);

	MPRINT("CONTROL push aq %p\n", c->aq);

	/*
	 *	Get a message.  If we can't get one, do garbage
	 *	collection.  Get another, and if that fails, we're
	 *	done.
	 */
	m = fr_control_message_alloc(c, rb, id, data, data_size);
	if (!m) {
		(void) fr_control_gc(c, rb);
		m = fr_control_message_alloc(c, rb, id, data, data_size);
		if (!m) {
			fr_strerror_printf("Failed allocationg after GC");
			return -2;
		}
	}

	if (!fr_atomic_queue_push(c->aq, m)) {
		m->status = FR_CONTROL_MESSAGE_DONE;
		fr_strerror_printf("Failed pushing message to atomic queue.");
		return -1;
	}

	return 0;
}

/** Send a control-plane message
 *
 *  This function is called ONLY from the originating thread.
 *
 * @param[in] c the control structure
 * @param[in] rb the callers ring buffer for message allocation.
 * @param[in] id the ident of this message.
 * @param[in] data the data to write to the control plane
 * @param[in] data_size the size of the data to write to the control plane.
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_control_message_send(fr_control_t *c, fr_ring_buffer_t *rb, uint32_t id, void *data, size_t data_size)
{
	(void) talloc_get_type_abort(c, fr_control_t);

	if (c->same_thread) {
		if (!c->type[id].callback) return -1;

		c->type[id].callback(c->type[id].ctx, data, data_size, fr_time());
		return 0;
	}

	if (fr_control_message_push(c, rb, id, data, data_size) < 0) return -1;

	while (write(c->pipe[1], ".", 1) == 0) {
		/* nothing */
	}

	return 0;
}


/** Pop control-plane message
 *
 *  This function is called ONLY from the receiving thread.
 *
 * @param[in] aq the recipients atomic queue for control-plane messages
 * @param[out] p_id the ident of this message.
 * @param[in,out] data where the data is stored
 * @param[in] data_size the size of the buffer where we store the data.
 * @return
 *	- <0 the size of the data we need to read the next message
 *	- 0 this kevent is not for us.
 *	- >0 the amount of data we've read
 */
ssize_t fr_control_message_pop(fr_atomic_queue_t *aq, uint32_t *p_id, void *data, size_t data_size)
{
	uint8_t *p;
	fr_control_message_t *m;

	MPRINT("CONTROL pop aq %p\n", aq);

	if (!fr_atomic_queue_pop(aq, (void **) &m)) return 0;

	fr_assert(m->status == FR_CONTROL_MESSAGE_USED);

	/*
	 *	There isn't enough room to store the data, die.
	 */
	if (data_size < m->data_size) {
		fr_strerror_printf("Allocation size should be at least %zd", m->data_size);
		return -(m->data_size);
	}

	p = (uint8_t *) m;
	data_size = m->data_size;
	memcpy(data, p + sizeof(*m), data_size);

	m->status = FR_CONTROL_MESSAGE_DONE;
	*p_id = m->id;
	return data_size;
}


/** Register a callback for an ID
 *
 * @param[in] c the control structure
 * @param[in] id the ident of this message.
 * @param[in] ctx the context for the callback
 * @param[in] callback the callback function
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_control_callback_add(fr_control_t *c, uint32_t id, void *ctx, fr_control_callback_t callback)
{
	(void) talloc_get_type_abort(c, fr_control_t);

	if (id >= FR_CONTROL_MAX_TYPES) {
		fr_strerror_printf("Failed adding unknown ID %d", id);
		return -1;
	}

	/*
	 *	Re-registering the same thing is OK.
	 */
	if ((c->type[id].ctx == ctx) &&
	    (c->type[id].callback == callback)) {
		return 0;
	}

	if (c->type[id].callback != NULL) {
		fr_strerror_printf("Callback is already set");
		return -1;
	}

	c->type[id].id = id;
	c->type[id].ctx = ctx;
	c->type[id].callback = callback;

	return 0;
}

/** Delete a callback for an ID
 *
 * @param[in] c the control structure
 * @param[in] id the ident of this message.
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_control_callback_delete(fr_control_t *c, uint32_t id)
{
	(void) talloc_get_type_abort(c, fr_control_t);

	if (id >= FR_CONTROL_MAX_TYPES) {
		fr_strerror_printf("Failed adding unknown ID %d", id);
		return -1;
	}

	if (c->type[id].callback == NULL) return 0;

	c->type[id].id = 0;
	c->type[id].ctx = NULL;
	c->type[id].callback = NULL;

	return 0;
}

int fr_control_same_thread(fr_control_t *c)
{
	c->same_thread = true;
	(void) fr_event_fd_delete(c->el, c->pipe[0], FR_EVENT_FILTER_IO);
	close(c->pipe[0]);
	close(c->pipe[1]);

	/*
	 *	Nothing more to do now that everything is gone.
	 */
	talloc_set_destructor(c, NULL);

	return 0;
}
