/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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
 * @file rlm_unbound/io.c
 * @brief Provides interface between libunbound and the FreeRADIUS event loop
 *
 * @copyright 2019 The FreeRADIUS server project
 * @copyright 2019 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#define LOG_PREFIX "rlm_unbound - "

#include <freeradius-devel/server/log.h>
#include <freeradius-devel/util/event.h>
#include <freeradius-devel/util/syserror.h>

#include "io.h"

#ifdef HAVE_WDOCUMENTATION
DIAG_OFF(documentation)
#endif
#include <unbound-event.h>
#ifdef HAVE_WDOCUMENTATION
DIAG_ON(documentation)
#endif

/** Definition for libunbound's event callback
 *
 * Here because they don't provide one.
 */
typedef void(*unbound_cb_t)(int, short flags, void *uctx);

/** Wrapper around event handle for our event loop
 *
 * This stores libunbound specific information for an event in our event loop.
 *
 * Lifetime should be bound to the event base.
 */
typedef struct {
	struct ub_event		base;		//!< Unbound event base, which we populate with
						///< callback functions for adding events for FDs
						///< setting timers etc...
						///< MUST BE LISTED FIRST.

	unbound_io_event_base_t *ev_b;		//!< Event base this handle was created for.

	fr_event_timer_t const	*timer;		//!< Stores the pointer to the enabled timer for
						///< this event handled.  libunbound uses a single
						///< handle for managing related FD events and
						///< timers, which is weird, but ok...

	short			events;		//!< The events this event handle should receive
						///< when activated.

	int			fd;		//!< File descriptor this event handle relates to.

	unbound_cb_t		cb;		//!< The callback we need to call when a specified
						///< event happens.

	void			*uctx;		//!< This is the argument libunbound wants passed to
						///< the callback when it's called.  It usually
						///< contains libunbound's internal connection handled.
						///< We don't have any visibility, it just remains
						///< an opaque blob to us.

	bool			active;		//!< Whether this event is considered active.
} unbound_io_event_t;

/** Alter the enabled flags associated with the event
 *
 * Event *MUST* be disabled before these flags are changed.
 */
static void _unbound_io_event_flags_add(struct ub_event *ub_ev, short flags)
{
	unbound_io_event_t	*ev = talloc_get_type_abort(ub_ev, unbound_io_event_t);
	short			new = ev->events | flags;

	DEBUG4("unbound event %p - Adding flags %i (current %i, new %i)", ev, flags, ev->events, new);

	rad_assert(!ev->active);	/* must not be active */

	ev->events = new;
}

/** Alter the enabled flags associated with the event
 *
 * Event *MUST* be disabled before these flags are changed.
 */
static void _unbound_io_event_flags_del(struct ub_event *ub_ev, short flags)
{
	unbound_io_event_t	*ev = talloc_get_type_abort(ub_ev, unbound_io_event_t);
	short			new = ev->events & ~flags;

	rad_assert(!ev->active);			/* must not be active */

	DEBUG4("unbound event %p - Removing flags %i (current %i, new %i)", ev, flags, ev->events, new);

	ev->events = new;
}

/** Change the file descriptor associated with an event
 *
 * Event *MUST* be disabled before changing the fd.
 */
static void _unbound_io_event_fd_set(struct ub_event *ub_ev, int fd)
{
	unbound_io_event_t	*ev = talloc_get_type_abort(ub_ev, unbound_io_event_t);

	rad_assert(!ev->active);			/* must not be active */

	DEBUG4("unbound event %p - Changed FD from %i to %i", ev, ev->fd, fd);

	ev->fd = fd;
}

/** Free an event, and, by the magic of talloc, any timers or fd events
 *
 */
static void _unbound_io_event_free(struct ub_event *ub_ev)
{
	unbound_io_event_t	*ev = talloc_get_type_abort(ub_ev, unbound_io_event_t);

	DEBUG4("unbound event %p - Freed", ev);

	talloc_free(ev);
}

/** Timeout fired
 *
 */
static void _unbound_io_service_timer_expired(UNUSED fr_event_list_t *el, UNUSED fr_time_t now, void *uctx)
{
	unbound_io_event_t	*ev = talloc_get_type_abort(uctx, unbound_io_event_t);
	int			ret;

	rad_assert(ev->active);			/* must be active */

	DEBUG4("unbound event %p - Timeout", ev);

	ev->cb(-1, UB_EV_TIMEOUT, ev->uctx);	/* Inform libunbound */
}

/** Unbound FD became readable
 *
 * Because we don't have the separation between the IO event loop
 * and the event loop processing results, we call ub_process
 * immediately after calling the IO callback.
 */
static void _unbound_io_service_readable(fr_event_list_t *el, int fd, UNUSED int flags, void *uctx)
{
	unbound_io_event_t	*ev = talloc_get_type_abort(uctx, unbound_io_event_t);
	int			ret;

	rad_assert(ev->active);			/* must be active */

	DEBUG4("unbound event %p - FD %i now readable", ev, fd);

	ev->cb(fd, UB_EV_READ, ev->uctx);		/* Inform libunbound */

	/*
	 *	Remove IO events
	 */
	if (!(ev->events | UB_EV_PERSIST)) {
		DEBUG4("unbound event %p - UB_EV_PERSIST not set - Removing events for FD %i", ev, ev->fd);
		if (fr_event_fd_delete(el, ev->fd, FR_EVENT_FILTER_IO) < 0) {
			PERROR("unbound event %p - De-registration failed for FD %i", ev, ev->fd);
		}
	}
}

/** Unbound FD became writable
 *
 */
static void _unbound_io_service_writable(fr_event_list_t *el, int fd, UNUSED int flags, void *uctx)
{
	unbound_io_event_t	*ev = talloc_get_type_abort(uctx, unbound_io_event_t);

	rad_assert(ev->active);			/* must be active */

	DEBUG4("unbound event %p - FD %i now writable", ev, fd);

	ev->cb(fd, UB_EV_WRITE, ev->uctx);	/* Inform libunbound */

	/*
	 *	Remove IO events
	 */
	if (!(ev->events | UB_EV_PERSIST)) {
		DEBUG4("unbound event %p - UB_EV_PERSIST not set - Removing events for FD %i", ev, ev->fd);
		if (fr_event_fd_delete(el, ev->fd, FR_EVENT_FILTER_IO) < 0) {
			PERROR("unbound event %p - De-registration failed for FD %i", ev, ev->fd);
		}
	}
}

/** Unbound FD errored
 *
 * libunbound doesn't request errors, so tell it a timeout occurred
 *
 * Because we don't have the separation between the IO event loop
 * and the event loop processing results, we call ub_process
 * immediately after calling the IO callback.
 */
static void _unbound_io_service_errored(UNUSED fr_event_list_t *el,
					int fd, UNUSED int flags, int fd_errno, void *uctx)
{
	unbound_io_event_t	*ev = talloc_get_type_abort(uctx, unbound_io_event_t);
	int			ret;

	rad_assert(ev->active);			/* must be active */

	DEBUG4("unbound event %p - FD %i errored: %s", ev, fd, fr_syserror(fd_errno));

	/*
	 *	Delete the timer as we're telling libunbound
	 *	that it fired.  This is imperfect but unbound
	 *	doesn't have a callback for receiving errors.
	 */
	if (fr_event_timer_delete(ev->ev_b->el, &ev->timer) < 0) {
		PERROR("ubound event %p - Failed disarming timeout", ev);
	}

	ev->cb(-1, UB_EV_TIMEOUT, ev->uctx);	/* Call libunbound - pretend this is a timeout */
}


/** Activate FD events and set a timer for a timeout
 *
 */
static int _unbound_io_event_activate(struct ub_event *ub_ev, struct timeval *tv)
{
	unbound_io_event_t	*ev = talloc_get_type_abort(ub_ev, unbound_io_event_t);

	rad_assert(!ev->active);	/* must not be active */

	/*
	 *	File descriptor event
	 */
	if ((ev->events & UB_EV_READ) && (ev->events & UB_EV_WRITE)) {
		rad_assert(ev->fd >= 0);	/* File descriptor must valid */

		DEBUG4("unbound event %p - Registered for read+write events on FD %i", ev, ev->fd);

		if (fr_event_fd_insert(ev, ev->ev_b->el, ev->fd,
				       _unbound_io_service_readable,
				       _unbound_io_service_writable,
				       _unbound_io_service_errored,
				       ev) < 0) {
			PERROR("unbound event %p - Registration failed for read+write+error events on FD %i",
			       ev, ev->fd);

			return -1;
		}
	} else if (ev->events & UB_EV_READ) {
		rad_assert(ev->fd >= 0);	/* File descriptor must valid */

		DEBUG4("unbound event %p - Registered for read+error events on FD %i", ev, ev->fd);

		if (fr_event_fd_insert(ev, ev->ev_b->el, ev->fd,
				       _unbound_io_service_readable,
				       NULL,
				       _unbound_io_service_errored,
				       ev) < 0) {
			PERROR("unbound event %p - Registration failed for read+error events on FD %i",
			       ev, ev->fd);

			return -1;
		}
	} else if (ev->events & UB_EV_WRITE) {
		rad_assert(ev->fd >= 0);	/* File descriptor must valid */

		DEBUG4("unbound event %p - Registered for write+error events on FD %i", ev, ev->fd);

		if (fr_event_fd_insert(ev, ev->ev_b->el, ev->fd,
				       NULL,
				       _unbound_io_service_writable,
				       _unbound_io_service_errored,
				       ev) < 0) {
			PERROR("unbound event %p - Registration failed for write+error events on FD %i",
			       ev, ev->fd);

			return -1;
		}
	}

	/*
	 *	Add a timeout event
	 */
	if (ev->events & UB_EV_TIMEOUT) {
		fr_time_delta_t timeout = fr_time_delta_from_timeval(tv);

		DEBUG4("unbound event %p - Timeout in %pV seconds", ev, fr_box_time_delta(timeout));

		if (fr_event_timer_in(ev, ev->ev_b->el, &ev->timer,
				      timeout, _unbound_io_service_timer_expired, ev) < 0) {
			PERROR("unbound event %p - Failed adding timeout", ev);

			if (ev->events & (UB_EV_READ | UB_EV_WRITE)) {
				fr_event_fd_delete(ev->ev_b->el, ev->fd, FR_EVENT_FILTER_IO);
			}

			return -1;
		}
	}

	ev->active = true;	/* Event is now active! */

	return 0;
}

/* Deactivate FD events and disarm the timeout
 *
 */
static int _unbound_io_event_deactivate(struct ub_event *ub_ev)
{
	unbound_io_event_t	*ev = talloc_get_type_abort(ub_ev, unbound_io_event_t);
	int			ret = 0;

	if (!ev->active) return 0;	/* Allow this to be called multiple times */

	if (ev->events & (UB_EV_READ | UB_EV_WRITE)) {
		DEBUG4("unbound event %p - De-registering FD %i", ev, ev->fd);

		if (fr_event_fd_delete(ev->ev_b->el, ev->fd, FR_EVENT_FILTER_IO) < 0) {
			PERROR("unbound event %p - De-registration failed for FD %i", ev, ev->fd);

			ret = -1;
		}
	}

	if (ev->events & UB_EV_TIMEOUT) {
		DEBUG4("unbound event %p - Disarming timeout", ev);

		if (ev->timer && (fr_event_timer_delete(ev->ev_b->el, &ev->timer) < 0)) {
			PERROR("ubound event %p - Failed disarming timeout", ev);

			ret = -1;
		}
	}

	ev->active = false;	/* Event is now inactive and can be modified */

	return ret;
}

/** Modify an existing timeout
 *
 */
static int _unbound_io_timer_modify(struct ub_event *ub_ev, UNUSED struct ub_event_base *ev_b,
				    void (*cb)(int, short, void*),
				    void *uctx, struct timeval *tv)
{
	unbound_io_event_t	*ev = talloc_get_type_abort(ub_ev, unbound_io_event_t);
	int			ret = 0;
	fr_time_delta_t		timeout;

	rad_assert(ev->events & UB_EV_TIMEOUT);

	if (ev->cb != cb) {
		DEBUG4("unbound event %p - New callback %p (old callback was %p)",
		       ev, cb, ev->cb);
		ev->cb = cb;
	}
	if (ev->uctx != uctx) {
		DEBUG4("unbound event %p - New uctx %p (old uctx was %p)",
		       ev, uctx, ev->uctx);
		ev->uctx = uctx;
	}
	if (ev->timer && (fr_event_timer_delete(ev->ev_b->el, &ev->timer) < 0)) {
		PERROR("ubound event %p - Failed disarming timeout", ev);

		ret = -1;	/* Continue ? */
	}

	timeout = fr_time_delta_from_timeval(tv);

	DEBUG4("unbound event %p - Timeout in %pV seconds", ev, fr_box_time_delta(timeout));

	if (fr_event_timer_in(ev, ev->ev_b->el, &ev->timer,
			      timeout, _unbound_io_service_timer_expired, ev) < 0) {
		PERROR("unbound event %p - Failed adding timeout", ev);

		ret = -1;
	}

	return ret;
}

/** Deactivate a timeout
 *
 */
static int _unbound_io_timer_deactivate(struct ub_event *ub_ev)
{
	unbound_io_event_t	*ev = talloc_get_type_abort(ub_ev, unbound_io_event_t);

	rad_assert(ev->events & UB_EV_TIMEOUT);

	DEBUG4("unbound event %p - Disarming timeout", ev);

	if (ev->timer && (fr_event_timer_delete(ev->ev_b->el, &ev->timer) < 0)) {
		PERROR("unbound event %p - Failed disarming timeout", ev);

		return -1;
	}

	return 0;
}

/** Returns a new libunbound event handle
 *
 * This handle is used by libunbound to interface with the worker's event loop
 */
static struct ub_event *_unbound_io_event_new(struct ub_event_base* base, int fd, short flags,
					      void (*cb)(int, short, void*), void *uctx)
{
	unbound_io_event_base_t	*ev_b = talloc_get_type_abort(base, unbound_io_event_base_t);
	unbound_io_event_t	*ev;

	static struct ub_event_vmt	vmt = {
		.add_bits	= _unbound_io_event_flags_add,
		.del_bits	= _unbound_io_event_flags_del,
		.set_fd		= _unbound_io_event_fd_set,
		.free		= _unbound_io_event_free,
		.add		= _unbound_io_event_activate,
		.del		= _unbound_io_event_deactivate,
		.add_timer	= _unbound_io_timer_modify,
		.del_timer	= _unbound_io_timer_deactivate
	};

	MEM(ev = talloc_zero(ev_b, unbound_io_event_t));
	ev->base.magic = UB_EVENT_MAGIC;	/* Magic value libunbound requires */
	ev->base.vmt = &vmt;			/* Callbacks for adding/removing timers/fd events */
	ev->ev_b = ev_b;			/* Our event base (containing the el ) */
	ev->events = flags;			/* When this event should fire */
	ev->fd = fd;				/* File descriptor to register events for */
	ev->cb = cb;				/* Callback to execute on event */
	ev->uctx = uctx;			/* Lib unbound's arg to pass to the cb */
	ev->active = false;			/* Event is not currently active */

	DEBUG4("unbound event %p - Allocated - Events %i, FD %i, callback %p, uctx %p", ev, flags, fd, cb, uctx);

	return (struct ub_event *)ev;
}

static int _event_base_free(unbound_io_event_base_t *ev_b)
{
	if (ev_b->ub) ub_ctx_delete(ev_b->ub);

	return 0;
}

/** Alloc a new event base, and unbound ctx initialised from that event base
 *
 * The ub_ctx is configured to use the el specified.
 *
 * When the thread ctx is freed, unbound_io_free should be called to gracefully
 * free the ub_ctx, and then the event base structure it depends on.
 *
 * @param[in] ctx	Talloc ctx to allocate even base in.
 * @param[out] ev_b_out	Event base.  Free with talloc_free.
 * @parma[in] el	To use to run the unbound event loop.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int unbound_io_init(TALLOC_CTX *ctx, unbound_io_event_base_t **ev_b_out, fr_event_list_t *el)
{
	unbound_io_event_base_t *ev_b;

	static struct ub_event_base_vmt vmt = {
		.new_event	= _unbound_io_event_new
	};

	/*
	 *	Should be manually freed *AFTER* t->ub
	 *	is freed.  So must be parented from the NULL
	 *	ctx.
	 */
	MEM(ev_b = talloc_zero(ctx, unbound_io_event_base_t));
	ev_b->base.magic = UB_EVENT_MAGIC;
	ev_b->base.vmt = &vmt;
	ev_b->el = el;

	/*
	 *	Create the main ub_ctx using our event base
	 *	which specifies how libunbound integrates
	 *	with our event loop.
	 */
	ev_b->ub = ub_ctx_create_ub_event((struct ub_event_base *)ev_b);
	if (!ev_b->ub) {
		ERROR("Failed creating ub_ctx");
		TALLOC_FREE(ev_b);
		return -1;
	}
	talloc_set_destructor(ev_b, _event_base_free);

	*ev_b_out = ev_b;

	return 0;
}
