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
 * @file tls/connection.c
 * @brief Run one TLS connection from the first policy section to the last
 *
 * The state machine runs under one connection frame, which fr_tls_connection_push()
 * pushes.  Each state sets up frame->repeat as the next state, and which then
 * lets the current state push children.
 *
 * @copyright 2026 The FreeRADIUS server project
 */
#ifdef WITH_TLS
#define LOG_PREFIX "tls"
#define _TLS_CACHE_PRIVATE 1

#include <freeradius-devel/unlang/function.h>
#include <freeradius-devel/unlang/interpret.h>

#include "base.h"
#include "cache.h"
#include "connection.h"
#include "log.h"

/** Wake the connection's request, if the request is waiting for a record
 *
 * The request yields in two places: the connection frame waiting for
 * a record, and a policy section which pushed under the connection
 * frame.  Only a request which is yielded in the connection frame can
 * be woken from outside.
 *
 * The request may push a subrequest, which runs policies to establish
 * sessions, load / save session cache entries, etc.  The parent
 * request must wait until the subrequest is finished before it can
 * continue.  Erroneously waking a request while the subrequest is
 * running will strand the subrequest on the runnable heap.
 */
static void tls_connection_request_wake(fr_tls_connection_t *conn)
{
	if (!conn->idle) return;

	conn->idle = false;
	unlang_interpret_mark_runnable(conn->request);
}

/** Decide whether the handshake is over, and whether the handshake succeeded
 *
 * The handshake is complete only when SSL_is_init_finished() returns
 * true and every record produced by OpenSSL has reached the peer.
 */
static void tls_connection_check(fr_tls_connection_t *conn)
{
	fr_tls_session_t *tls_session = conn->tls_session;

	/*
	 *	The cache load / save operations can wake the parent
	 *	request, and change the state of the parents
	 *	connection.
	 */
	if (conn->state != TLS_CONNECTION_HANDSHAKE) return;

	if (tls_session->result == FR_TLS_RESULT_ERROR) {
		fr_tls_log(conn->request, "TLS handshake failed");
		conn->failed = true;
		goto finish;
	}

	/*
	 *	The TLS handshake is continuing, OR it's done but
	 *	there's still data to push to the peer.
	 */
	if (!SSL_is_init_finished(tls_session->ssl)) return;
	if (fr_dbuff_remaining(&tls_session->dirty_out) > 0) return;

	INFO("TLS handshake completed");
	INFO("  version    : %s", SSL_get_version(tls_session->ssl));
	INFO("  cipher     : %s", SSL_get_cipher(tls_session->ssl));
	INFO("  resumed    : %s", SSL_session_reused(tls_session->ssl) ? "yes" : "no");

finish:
	/*
	 *	The cache callbacks push work onto the request stack,
	 *	and the request is idle.  We need to wake up the
	 *	request.
	 *
	 *	We're running in a callback, and not as part of a
	 *	frame process function.  We therefore change the state
	 *	(not the process function), and then wake up the
	 *	request.  The frame process function will see that
	 *	state change, and switch to the new function.
	 */
	conn->state = TLS_CONNECTION_COMPLETE;
	tls_connection_request_wake(conn);
}

static unlang_action_t tls_connection_application_data(request_t *request, void *uctx);

/** Tell the application that the connection is over
 *
 * Only for a caller which has already run whatever policy the failure
 * needs.  A caller which has not should use tls_connection_failed(), which
 * hands the failure to the connection frame instead.
 *
 * @param[in] conn	which failed.
 */
static void tls_connection_finished(fr_tls_connection_t *conn)
{
	conn->failed = true;
	conn->idle = false;

	conn->finished(conn->uctx, conn);
}

/** Record a fatal error found outside of the interpreter
 *
 * The IO callbacks run outside of the interpreter, and so have no stack
 * frame of their own.  They cannot run policy.  So they do what
 * tls_connection_check() does for a failed handshake: record the failure,
 * change the state, and wake the request.  The connection frame then runs
 * `fail session { ... }`, discards the session, and tells the application.
 *
 * The wake is not always possible, and does not have to be.  A request
 * which is running a policy subrequest is deliberately not woken, see
 * tls_connection_request_wake().  The state change still stands, and the
 * connection frame acts on the state change when the subrequest finishes.
 *
 * @param[in] conn	which failed.
 */
static void tls_connection_failed(fr_tls_connection_t *conn)
{
	conn->failed = true;

	/*
	 *	The connection frame has already run the last of its
	 *	states, so there is no policy left for it to run, and
	 *	nothing would act on a state change.  Say so directly.
	 */
	if (conn->state != TLS_CONNECTION_HANDSHAKE) {
		tls_connection_finished(conn);
		return;
	}

	conn->state = TLS_CONNECTION_COMPLETE;
	tls_connection_request_wake(conn);
}

/** There is a fatal connection error.
 *
 * The state functions have no way to report a failure to the
 * interpreter, because we're pushing functions onto the stack with
 * unlang_function_push(), instead of unlang_function_push_with_result().
 *
 * We therefore record the failure, discard the session, and return yield.
 *
 * @param[in] request	running the connection frame.
 * @param[in] conn	which failed.
 * @return
 *	- UNLANG_ACTION_PUSHED_CHILD	- `clear session { ... }` is running.
 *	- UNLANG_ACTION_YIELD		- the application has been told.
 */
static unlang_action_t tls_connection_error(request_t *request, fr_tls_connection_t *conn)
{
	unlang_action_t	ua;

	conn->failed = true;
	conn->idle = false;

	/*
	 *	Clear any pending repeat, so that the TLS state machine functions aren't used.
	 */
	IGNORE(unlang_function_clear(request), int);

	/*
	 *	Set our own repeat, which closes the connection, as is
	 *	done in tls_connection_init_finished().  We have to
	 *	set a repeat function to a "connection done" function,
	 *	as fr_tls_session_fail_session() may push a child.  That runs
	 *	`fail session { ... }`, and then the `clear session`
	 *	code.
	 */
	if (unlang_function_repeat_set(request, tls_connection_application_data) < 0) goto finished;

	ua = fr_tls_session_fail_session(request, conn->tls_session);
	if (ua == UNLANG_ACTION_PUSHED_CHILD) return ua;

	/*
	 *	Nothing was pushed, so we clear our repeat and return
	 *	that the TLS connection failed.
	 *
	 *	If the push failed, then nothing should have been
	 *	pushed onto the stack.  The cache operations are
	 *	marked as "need to be run", but we can't do anything
	 *	else.  So we just return, and potentially leave any
	 *	cache entries behind.
	 */
	IGNORE(unlang_function_clear(request), int);

finished:
	tls_connection_finished(conn);
	return UNLANG_ACTION_YIELD;
}

#define TLS_CONNECTION_ERROR_RETURN \
	do { \
		if (ua == UNLANG_ACTION_PUSHED_CHILD) return ua; \
		if (ua == UNLANG_ACTION_FAIL) return tls_connection_error(request, conn); \
	} while (0)

#define TLS_CONNECTION_REPEAT(_func) \
	do { \
		if (unlang_function_repeat_set(request, _func) < 0) { \
			return tls_connection_error(request, conn); \
		} \
	} while (0)

/** Tell the application that the application data is ready
 *
 */
static unlang_action_t tls_connection_application_data(UNUSED request_t *request, void *uctx)
{
	fr_tls_connection_t	*conn = talloc_get_type_abort(uctx, fr_tls_connection_t);

	conn->idle = false;

	/*
	 *	fr_tls_cache_store_session() and fr_tls_cache_clear_session()
	 *	run every queued cache operation before either function
	 *	returns.  An operation still queued here would never run at
	 *	all, and the session would silently not be cached, or would
	 *	silently not be cleared.
	 */
	fr_assert(!fr_tls_cache_pending(conn->tls_session->cache));

	conn->finished(conn->uctx, conn);
	return UNLANG_ACTION_YIELD;
}

/** Decide whether to keep the session once the handshake has stopped
 *
 * The handshakes are done, either due to success or failure.  On
 * failure, we discard any cached session.  On success, we store the
 * session before processing application data.
 */
static unlang_action_t tls_connection_init_finished(request_t *request, void *uctx)
{
	fr_tls_connection_t	*conn = talloc_get_type_abort(uctx, fr_tls_connection_t);
	unlang_action_t		ua;

	conn->idle = false;

	/*
	 *	Arm the repeat before any push.
	 */
	TLS_CONNECTION_REPEAT(tls_connection_application_data);

	if (conn->failed) {
		ua = fr_tls_session_fail_session(request, conn->tls_session);
	} else {
		ua = fr_tls_cache_store_session(request, conn->tls_session);
	}
	TLS_CONNECTION_ERROR_RETURN;

	return tls_connection_application_data(request, conn);
}

/** Run handshake rounds until the handshakes finish.
 *
 * This function is largely a place-holder so that there is a stack
 * frame which holds the current state.  The request is woken up to
 * process data, most of which happens in the async IO callback.  But
 * the frame is still processed.  So we check the connection status
 * here, and then either yield (if there's more handshaking to do), or
 * go to the next state (on success or error).
 */
static unlang_action_t tls_connection_handshake(request_t *request, void *uctx)
{
	fr_tls_connection_t	*conn = talloc_get_type_abort(uctx, fr_tls_connection_t);
	unlang_action_t	ua;

	conn->idle = false;

	/*
	 *	tls_connection_check() runs asynchronously in the IO
	 *	callback, and changes the state we _want_ to be in.
	 *	Check that here, and move to the next state if
	 *	necessary.
	 */
	if (conn->state == TLS_CONNECTION_COMPLETE) return tls_connection_init_finished(request, conn);

	/*
	 *	Arm the repeat function before pushing anything else.
	 */
	TLS_CONNECTION_REPEAT(tls_connection_handshake);

	/*
	 *	No record is waiting for OpenSSL, yield until the next
	 *	record arrives.
	 */
	if (!conn->pending) {
		conn->idle = true;
		return UNLANG_ACTION_YIELD;
	}

	conn->pending = false;

	/*
	 *	fr_tls_session_async_handshake_push() pushes a new
	 *	child frame onto the stack in order to process the
	 *	SSL*.  If that happens, we just tell the interpreter
	 *	that we have a new child on the stack.
	 */
	ua = fr_tls_session_async_handshake_push(request, conn->tls_session);
	if (ua == UNLANG_ACTION_PUSHED_CHILD) return ua;

	fr_tls_log(conn->request, "Failed pushing a TLS handshake round");
	return tls_connection_error(request, conn);
}

/** Run `new session { ... }`, the first state of a connection
 *
 */
static unlang_action_t tls_connection_new_session(request_t *request, void *uctx)
{
	fr_tls_connection_t	*conn = talloc_get_type_abort(uctx, fr_tls_connection_t);
	unlang_action_t	ua;

	/*
	 *	A state is running, so the request is not idle.  The
	 *	idle flag is set again during a handshake, if the
	 *	request needs to wait for more OpenSSL negotiation to
	 *	finish.
	 */
	conn->idle = false;
	conn->state = TLS_CONNECTION_HANDSHAKE;

	if (conn->tls_conf->new_session) {
		fr_assert(conn->tls_conf->virtual_server);

		TLS_CONNECTION_REPEAT(tls_connection_handshake);

		ua = fr_tls_new_session_push(request, conn->tls_conf);
		TLS_CONNECTION_ERROR_RETURN;
	}

	return tls_connection_handshake(request, conn);
}

/** Push the connection frame onto the request's stack
 *
 * Run the interpreter once after fr_tls_connection_push() returns, so that
 * the connection frame yields.  unlang_interpret_mark_runnable() acts only on
 * a yielded frame, and so fr_tls_connection_wake() does nothing until the
 * connection frame has yielded at least once.
 *
 * @param[in] conn	to run.  `conn->request` must be set.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_tls_connection_push(fr_tls_connection_t *conn)
{
	return unlang_function_push(conn->request,
				    tls_connection_new_session,
				    tls_connection_new_session,
				    NULL, 0, UNLANG_TOP_FRAME, conn);
}

/** A TLS record is available, so wake up the connection to process it.
 *
 * The connection frame yields between rounds, so we need to mark the
 * request as runnable in order to process the data through the
 * interpreter.  We can't run the interpreter from an asynchronous IO
 * callback!
 *
 * @param[in] conn	to wake.
 */
void fr_tls_connection_wake(fr_tls_connection_t *conn)
{
	conn->pending = true;

	tls_connection_request_wake(conn);
}

/** Hand a record which arrived on the connection to OpenSSL
 *
 * The caller reads from whatever transport the caller uses, and passes the
 * octets here.  Nothing in the TLS library reads a socket, so the transport
 * stays entirely with the caller.  The EAP code in src/lib/eap/tls.c fills
 * dirty_in the same way, from EAP packets rather than from a socket.
 *
 * @param[in] conn	the record arrived on.
 * @param[in] data	which arrived.
 * @param[in] data_len	how many octets arrived.  Must be greater than zero,
 *			and no more than FR_TLS_MAX_RECORD_SIZE.
 */
void fr_tls_connection_recv(fr_tls_connection_t *conn, uint8_t const *data, size_t data_len)
{
	fr_tls_session_t *tls_session = conn->tls_session;
	request_t *request = conn->request;

	RDEBUG3("Read %zu bytes from the connection", data_len);

	if (fr_dbuff_in_memcpy_partial(&tls_session->dirty_in, data, data_len) != data_len) {
		RERROR("Failed buffering %zu bytes of TLS record data", data_len);
	error:
		tls_connection_failed(conn);
		return;
	}

	/*
	 *	Pushing a handshake round after the handshake has finished is
	 *	a logic error.  See src/lib/tls/session.c.  Application data
	 *	is not handled yet, so a record arriving now is an error.
	 */
	if (SSL_is_init_finished(tls_session->ssl)) {
		RERROR("Received %zu bytes of application data, which is not supported", data_len);
		goto error;
	}

	/*
	 *	Hand the round over to the connection frame, which is sitting
	 *	yielded, waiting for exactly that record.
	 */
	fr_tls_connection_wake(conn);
}

/** Write out any pending records, then re-check the handshake state
 *
 * Write the data to the IO layer, then check if the connection is
 * errored, OK, finished, etc.  We gave to write the data to the IO
 * layer so that any TLS alerts, close-notify, etc. will reach the
 * peer.
 *
 * @param[in] conn	to process.
 */
void fr_tls_connection_process(fr_tls_connection_t *conn)
{
	if (conn->write(conn->uctx, conn) < 0) {
		tls_connection_failed(conn);
		return;
	}

	tls_connection_check(conn);
}
#endif /* WITH_TLS */
