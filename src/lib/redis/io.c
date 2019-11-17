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
 * @file lib/redis/io.c
 * @brief Common functions for interacting with Redis via hiredis
 *
 * @copyright 2019 The FreeRADIUS server project
 * @copyright 2019 Network RADIUS SARL (legal@networkradius.com)
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */

#include <freeradius-devel/redis/io.h>
#include <freeradius-devel/server/rad_assert.h>

#include <hiredis/async.h>

/** Store I/O state
 *
 * There are three layers of wrapping structures
 *
 * fr_connection_t -> fr_redis_handle_t -> redisAsyncContext
 *
 */
struct fr_redis_handle_s {
	bool			read_set;		//!< We're listening for reads.
	bool			write_set;		//!< We're listening for writes.
	bool			ignore_disconnect_cb;	//!< Ensure that redisAsyncFree doesn't cause
							///< a callback loop.
	fr_event_timer_t const	*timer;			//!< Connection timer.
	redisAsyncContext	*ac;			//!< Async handle for hiredis.
};

/** Called by hiredis to indicate the connection is dead
 *
 */
static void _redis_disconnected(redisAsyncContext const *ac, UNUSED int status)
{
	fr_connection_t		*conn = talloc_get_type_abort(ac->data, fr_connection_t);
	fr_redis_handle_t	*h = fr_connection_get_handle(conn);

	/*
	 *	redisAsyncFree was called with a live
	 *	connection, but inside the talloc
	 *	destructor of the fr_redis_handle_t.
	 *
	 *	Don't signal the connection state
	 *	machine that it needs reconnecting,
	 *	the connection is being destroyed.
	 */
	if (h->ignore_disconnect_cb) return;

	DEBUG4("Signalled by hiredis, connection disconnected");

	fr_connection_signal_reconnect(conn);
}

/** Called by hiredis to indicate the connection is live
 *
 */
static void _redis_connected(redisAsyncContext const *ac, UNUSED int status)
{
	fr_connection_t		*conn = talloc_get_type_abort(ac->data, fr_connection_t);

	DEBUG4("Signalled by hiredis, connection is open");

	fr_connection_signal_connected(conn);
}

/** Redis FD became readable
 *
 */
static void _redis_io_service_readable(UNUSED fr_event_list_t *el, int fd, UNUSED int flags, void *uctx)
{
	fr_connection_t const	*conn = talloc_get_type_abort_const(uctx, fr_connection_t);
	fr_redis_handle_t	*h = fr_connection_get_handle(conn);

	DEBUG4("redis handle %p - FD %i now readble", h, fd);

	redisAsyncHandleRead(h->ac);
}


/** Redis FD became writable
 *
 */
static void _redis_io_service_writable(UNUSED fr_event_list_t *el, int fd, UNUSED int flags, void *uctx)
{
	fr_connection_t const	*conn = talloc_get_type_abort_const(uctx, fr_connection_t);
	fr_redis_handle_t	*h = fr_connection_get_handle(conn);

	DEBUG4("redis handle %p - FD %i now writable", h, fd);

	redisAsyncHandleWrite(h->ac);
}

/** Redis FD errored - Automatically removes registered events
 *
 */
static void _redis_io_service_errored(UNUSED fr_event_list_t *el, int fd, UNUSED int flags,
				      int fd_errno, void *uctx)
{
	fr_connection_t		*conn = talloc_get_type_abort(uctx, fr_connection_t);
	fr_redis_handle_t	*h = fr_connection_get_handle(conn);

	DEBUG4("redis handle %p - FD %i errored: %s", h, fd, fr_syserror(fd_errno));

	/*
	 *	Connection state machine will handle reconnecting
	 */
	fr_connection_signal_reconnect(conn);
}

/** Deal with the method hiredis uses to register/unregister interest in a file descriptor
 *
 */
static void _redis_io_common(fr_connection_t *conn, fr_redis_handle_t *h, bool read, bool write)
{
	redisContext		*c = &(h->ac->c);
	fr_event_list_t		*el = fr_connection_get_el(conn);

	if (!read && !write) {
		DEBUG4("redis handle %p - De-registering FD %i", h, c->fd);

		if (fr_event_fd_delete(el, c->fd, FR_EVENT_FILTER_IO) < 0) {
			PERROR("redis handle %p - De-registration failed for FD %i", h, c->fd);
		}
	}

	DEBUG4("redis handle %p - Registered for %s%serror events on FD %i",
	       h, read ? "read+" : "", write ? "write+" : "", c->fd);

	if (fr_event_fd_insert(h, el, c->fd,
			       read ? _redis_io_service_readable : NULL,
			       write ? _redis_io_service_writable : NULL,
			       _redis_io_service_errored,
			       conn) < 0) {
		PERROR("redis handle %p - Registeration failed for %s%serror events on FD %i",
		       h, read ? "read+" : "", write ? "write+" : "", c->fd);
		return;
	}

	h->read_set = read;
	h->write_set = write;
}

/** Register FD for reads
 *
 */
static void _redis_io_add_read(void *uctx)
{
	fr_connection_t		*conn = talloc_get_type_abort(uctx, fr_connection_t);
	fr_redis_handle_t	*h = fr_connection_get_handle(conn);

	_redis_io_common(conn, h, true, h->write_set);
}

/** De-register FD for reads
 *
 */
static void _redis_io_del_read(void *uctx)
{
	fr_connection_t		*conn = talloc_get_type_abort(uctx, fr_connection_t);
	fr_redis_handle_t	*h = fr_connection_get_handle(conn);

	_redis_io_common(conn, h, false, h->write_set);
}

/** Register FD for writes
 *
 */
static void _redis_io_add_write(void *uctx)
{
	fr_connection_t		*conn = talloc_get_type_abort(uctx, fr_connection_t);
	fr_redis_handle_t	*h = fr_connection_get_handle(conn);

	_redis_io_common(conn, h, h->read_set, true);
}

/** De-register FD for writes
 *
 */
static void _redis_io_del_write(void *uctx)
{
	fr_connection_t		*conn = talloc_get_type_abort(uctx, fr_connection_t);
	fr_redis_handle_t	*h = fr_connection_get_handle(conn);

	_redis_io_common(conn, h, h->read_set, false);
}

#ifdef HAVE_REDIS_TIMEOUT
/** Connection timer expired
 *
 */
static void _redis_io_service_timer_expired(UNUSED fr_event_list_t *el, UNUSED fr_time_t now, void *uctx)
{
	fr_connection_t const	*conn = talloc_get_type_abort_const(uctx, fr_connection_t);
	fr_redis_handle_t	*h = fr_connection_get_handle(conn);

	DEBUG4("redis handle %p - Timeout", h);

	redisAsyncHandleTimeout(h->ac);
}

/** Modify the connection I/O timer
 *
 */
static void _redis_io_timer_modify(void *uctx, struct timeval tv)
{
	fr_connection_t		*conn = talloc_get_type_abort(uctx, fr_connection_t);
	fr_redis_handle_t	*h = fr_connection_get_handle(conn);
	fr_time_delta_t		timeout;

	timeout = fr_time_delta_from_timeval(&tv);

	DEBUG4("redis handle %p - Timeout in %pV seconds", h, fr_box_time_delta(timeout));

	if (fr_event_timer_in(h, fr_connection_get_el(conn), &h->timer,
			      timeout, _redis_io_service_timer_expired, conn) < 0) {
		PERROR("redis timeout %p - Failed adding timeout", h);
	}
}
#endif

/** Handle freeing the redisAsyncCtx
 *
 * delRead and delWrite don't seem to be called when the redisAsyncCtx is freed
 *
 * As the IO events must be removed from the event loop *before* the FD is closed
 * and as the IO events will only be automatically de-registered when when the
 * fr_redis_handle_t is freed.
 *
 * Unfortunately the destructor for the fr_redis_handle_t will be run before
 * the IO events are de-registered, which'll free the redisAsycCtx, which'll close
 * the FD.
 *
 * This means there'd be a brief period of time between the FD is closed, and
 * it being removed from the event loop.
 *
 * We use the cleanup callback (which is called before the FD is closed) to remove
 * the events now, and ensure there's no chance of issues.
 */
static void _redis_io_free(void *uctx)
{
	fr_connection_t		*conn = talloc_get_type_abort(uctx, fr_connection_t);
	fr_redis_handle_t	*h = fr_connection_get_handle(conn);

	DEBUG4("redis handle %p - Freed", h);

	_redis_io_common(conn, h, false, false);
}

/** Configures async I/O callbacks for an existing redisAsyncContext
 *
 */
static int fr_redis_io_setup(redisAsyncContext *ac, fr_connection_t const *conn)
{
	if (ac->ev.data != NULL) return REDIS_ERR;

	ac->ev.addRead = _redis_io_add_read;
	ac->ev.delRead = _redis_io_del_read;
	ac->ev.addWrite = _redis_io_add_write;
	ac->ev.delWrite = _redis_io_del_write;
#ifdef HAVE_REDIS_TIMEOUT
	ac->ev.scheduleTimer = _redis_io_timer_modify;
#endif
	ac->ev.cleanup = _redis_io_free;
	memcpy(&ac->ev.data, &conn, sizeof(ac->ev.data));

	return REDIS_OK;
}

/** Free the redis async context when the handle is freed
 *
 */
static int _redis_handle_free(fr_redis_handle_t *h)
{
	/*
	 *	Don't fire the reconnect callback if we're
	 *      freeing the handle.
	 */
	h->ignore_disconnect_cb = true;
	if (h->ac) redisAsyncFree(h->ac);

	return 0;
}

/** Callback for the initialise state
 *
 * Should attempt to open a non-blocking connection and return it in h_out.
 *
 * @param[out] h_out	Where to write the new handle
 * @param[in] conn	This connection.  Opaque, should only be used for
 *			signalling the connection state machine.
 * @param[in] uctx	User context.
 * @return
 *	- #FR_CONNECTION_STATE_CONNECTING	if a file descriptor was successfully created.
 *	- #FR_CONNECTION_STATE_FAILED		if we could not open a valid handle.
 */
static fr_connection_state_t _redis_io_connection_init(void **h_out, fr_connection_t *conn, void *uctx)
{
	fr_redis_conf_t		*conf = talloc_get_type_abort(uctx, fr_redis_conf_t);
	char const		*host = *conf->hostname;
	uint16_t		port = conf->port;
	fr_redis_handle_t	*h;
	int			ret;

	/*
	 *	Allocate a structure to wrap the
	 *	redis async context.
	 */
	h = talloc_zero(conn, fr_redis_handle_t);
	if (!h) {
		ERROR("Out of memory");
		return FR_CONNECTION_STATE_FAILED;
	}
	talloc_set_destructor(h, _redis_handle_free);

	h->ac = redisAsyncConnect(host, port);
	if (!h->ac) {
		ERROR("Failed allocating handle for %s:%u", host, port);
		return FR_CONNECTION_STATE_FAILED;
	}

	if (h->ac->err) {
		ERROR("Failed allocating handle for %s:%u: %s", host, port, h->ac->errstr);
	error:
		redisAsyncFree(h->ac);
		return FR_CONNECTION_STATE_FAILED;
	}

	/*
	 *	Store the connection in private data,
	 *	so we can use it for signalling.
	 *
	 *	Comments in the redis src indicate
	 *	it doesn't mess with this.
	 */
	memcpy(&h->ac->data, &conn, sizeof(h->ac->data));

	/*
	 *	Install the I/O service functions
	 *
	 *	Event library must be set first
	 *	before calling redisAsyncSetConnectCallback
	 *	as just setting the callback triggers
	 *	I/O events to be registered.
	 */
	fr_redis_io_setup(h->ac, conn);

	/*
	 *	Setup callbacks so we're notified
	 *	when the connection state changes.
	 *
	 *	We then signal the connection state
	 *      machine, to let it handle
	 *	reconnecting.
	 */
	ret = redisAsyncSetConnectCallback(h->ac, _redis_connected);
	if (ret != REDIS_OK) {
		ERROR("Failed setting connected callback: Error %i", ret);
		goto error;
	}
	if (redisAsyncSetDisconnectCallback(h->ac, _redis_disconnected) != REDIS_OK) {
		ERROR("Failed setting disconnected callback: Error %i", ret);
		goto error;
	}

	*h_out = h;

	return FR_CONNECTION_STATE_CONNECTING;
}

/** Notification that the connection has errored and must be closed
 *
 * This should be used to close the file descriptor.  It is assumed
 * that the file descriptor is invalid after this callback has been executed.
 *
 * If this callback does not close the file descriptor, the server will leak
 * file descriptors.
 *
 * @param[in] h		to close.
 * @param[in] uctx	User context.
 */
static void _redis_io_connection_close(void *h, UNUSED void *uctx)
{
	fr_redis_handle_t	*our_h = talloc_get_type_abort(h, fr_redis_handle_t);

	/*
	 *	The destructor will free the redisAsyncCtx
	 *	which'll close the connection, after removing
	 *	it from the event loop.
	 */
	talloc_free(our_h);
}

/** Allocate an async redis I/O connection
 *
 */
fr_connection_t *fr_redis_connection_alloc(TALLOC_CTX *ctx, fr_event_list_t *el, fr_redis_conf_t const *conf)
{
	/*
	 *	We don't specify an open callback
	 *	as hiredis handles switching over
	 *	all the I/O handlers internally
	 *	within hireds, and calls us when
	 *	the connection is open.
	 */
	return fr_connection_alloc(ctx, el,
				   conf->connection_timeout,
				   conf->reconnection_delay,
				   _redis_io_connection_init,
				   NULL,
				   _redis_io_connection_close,
				   conf->log_prefix,
				   conf);
}

/** Return the redisAsyncCtx associated with the connection
 *
 * This is needed to issue commands to the redis server.
 *
 * @param[in] conn	To retrieve async ctx from.
 * @return The async ctx.
 */
redisAsyncContext *fr_redis_connection_get_async_ctx(fr_connection_t *conn)
{
	fr_redis_handle_t	*h = fr_connection_get_handle(conn);
	return h->ac;
}
