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
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
#ifdef WITH_TLS
#define LOG_PREFIX "tls"
#define _TLS_PRIVATE 1

#include <freeradius-devel/unlang/function.h>
#include <freeradius-devel/unlang/interpret.h>

#include <freeradius-devel/protocol/tls/freeradius.h>

#include "base.h"
#include "ticket.h"
#include "connection.h"
#include "log.h"

fr_table_num_indexed_t const fr_tls_connection_state_table[] = {
	[TLS_CONNECTION_NEW_SESSION]	= { L("new_session"),	TLS_CONNECTION_NEW_SESSION },
	[TLS_CONNECTION_HANDSHAKE]	= { L("handshake"),	TLS_CONNECTION_HANDSHAKE },
	[TLS_CONNECTION_COMPLETE]	= { L("complete"),	TLS_CONNECTION_COMPLETE }
};
size_t fr_tls_connection_state_table_len = NUM_ELEMENTS(fr_tls_connection_state_table);

fr_table_num_indexed_t const fr_tls_connection_fail_table[] = {
	[TLS_CONNECTION_FAIL_NONE]	= { L("none"),		TLS_CONNECTION_FAIL_NONE },
	[TLS_CONNECTION_FAIL_TLS]	= { L("tls"),		TLS_CONNECTION_FAIL_TLS },
	[TLS_CONNECTION_FAIL_SYSCALL]	= { L("syscall"),	TLS_CONNECTION_FAIL_SYSCALL },
	[TLS_CONNECTION_FAIL_APPLICATION] = { L("application"),	TLS_CONNECTION_FAIL_APPLICATION }
};
size_t fr_tls_connection_fail_table_len = NUM_ELEMENTS(fr_tls_connection_fail_table);

fr_table_num_indexed_t const fr_tls_connection_io_state_table[] = {
	[FR_TLS_CONNECTION_IO_OK]	= { L("ok"),		FR_TLS_CONNECTION_IO_OK },
	[FR_TLS_CONNECTION_IO_RETRY]	= { L("retry"),		FR_TLS_CONNECTION_IO_RETRY },
	[FR_TLS_CONNECTION_IO_BLOCKED]	= { L("blocked"),	FR_TLS_CONNECTION_IO_BLOCKED },
	[FR_TLS_CONNECTION_IO_EOF]	= { L("eof"),		FR_TLS_CONNECTION_IO_EOF },
	[FR_TLS_CONNECTION_IO_FATAL]	= { L("fatal"),		FR_TLS_CONNECTION_IO_FATAL }
};
size_t fr_tls_connection_io_state_table_len = NUM_ELEMENTS(fr_tls_connection_io_state_table);

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
 * The handshake is complete only when fr_tls_session_is_init_finished()
 * returns true and every record produced by OpenSSL has reached the peer.
 * That is not the same as OpenSSL's own SSL_is_init_finished(): with a
 * TLS 1.3 stateless ticket there is a `load session` still to run.
 */
static void tls_connection_check(fr_tls_connection_t *conn)
{
	fr_tls_session_t *tls_session = conn->tls_session;
	request_t *request = conn->request;

	/*
	 *	The cache load / save operations can wake the parent
	 *	request, and change the state of the parents
	 *	connection.
	 */
	if (conn->state != TLS_CONNECTION_HANDSHAKE) return;

	/*
	 *	fr_tls_connection_failed() was called while a record was
	 *	still waiting for OpenSSL.  `idle` says the frame has read
	 *	everything and is waiting for a record which is not coming,
	 *	so the failure can be acted on now.
	 */
	if (conn->fail_pending) {
		if (!conn->idle) return;

		conn->fail_pending = false;
		goto finish;
	}

	/*
	 *	The peer closed the connection, and the handshake has read
	 *	every record it was given and now needs another one.  No
	 *	more records will arrive, so the handshake cannot complete.
	 *
	 *	If the last record completed the handshake instead, the
	 *	frame may be idle as well, but fr_tls_session_is_init_finished()
	 *	is true, and the completion is reported below.
	 */
	if (conn->eof && conn->idle && !fr_tls_session_is_init_finished(tls_session)) {
		RERROR("Peer closed the connection before the handshake completed");
		errno = 0;		/* fr_tls_connection_failed() records errno, and no call set one */
		fr_tls_connection_failed(conn, TLS_CONNECTION_FAIL_SYSCALL);
		return;
	}

	if (tls_session->result == FR_TLS_RESULT_ERROR) {
		fr_tls_log_perror(conn->request, "TLS handshake failed");

		/*
		 *	This sets the state and wakes the request, which is
		 *	what the code under `finish` does for the success
		 *	path.  Doing both would do the same work twice.
		 */
		fr_tls_connection_failed(conn, TLS_CONNECTION_FAIL_TLS);
		return;
	}

	/*
	 *	The TLS handshake is continuing, OR it's done but
	 *	there's still data to push to the peer.
	 */
	if (!fr_tls_session_is_init_finished(tls_session)) return;
	if (fr_dbuff_remaining(tls_session->dirty_out) > 0) return;

	INFO("%s - TLS handshake completed", conn->name);
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
 * This function should be used after all policies have been run.  A caller which needs to run policies should
 * use fr_tls_connection_failed() instead.
 *
 * @param[in] conn	which failed.
 */
static void tls_connection_finished(fr_tls_connection_t *conn)
{
	/*
	 *	Both callers record why the connection failed before calling
	 *	this function, so recording a reason here would overwrite the
	 *	one the caller knew.
	 */
	fr_assert(conn->failed != TLS_CONNECTION_FAIL_NONE);

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
 * Typically this means that the connection frame runs the `fail connection` policy.
 *
 * An application should call this function to indicate a socket or other connection failure during TLS
 * negotiation.  The handshake stops, `fail session { ... }` runs, and the `finished` callback reports the
 * failure once the policy is done.
 *
 * The rule is, inside of a frame which is checking the TLS parameters, set conn->failed; outside the frame,
 * call fr_tls_connection_failed().
 *
 * @param[in] conn	which failed.
 */
void fr_tls_connection_failed(fr_tls_connection_t *conn, fr_tls_connection_fail_t reason)
{
	request_t *request = conn->request;

	fr_assert(reason != TLS_CONNECTION_FAIL_NONE);

	if (conn->failed) return;

	conn->failed = reason;
	if (conn->failed == TLS_CONNECTION_FAIL_SYSCALL) conn->error = errno;

	ROPTIONAL(RDEBUG2, DEBUG2, "%s - connection failed: %s", conn->name,
		  fr_table_str_by_value(fr_tls_connection_fail_table, conn->failed, "<INVALID>"));

	/*
	 *	Record the reason where `fail session { ... }` reads it.
	 *
	 *	A failure inside TLS gets no value here.  Either one of the
	 *	rules in src/lib/tls/alerts.md already recorded a value which
	 *	says what the rule was, or OpenSSL raised the error and
	 *	fr_tls_log_perror() has already reported what OpenSSL said.  A value
	 *	meaning "something in TLS went wrong" would displace neither
	 *	and add nothing.
	 */
	switch (reason) {
	case TLS_CONNECTION_FAIL_SYSCALL:
		fr_tls_session_error_add(conn->request, FR_ERROR_VALUE_SYSTEM_CALL_FAILED);
		break;

	case TLS_CONNECTION_FAIL_APPLICATION:
		fr_tls_session_error_add(conn->request, FR_ERROR_VALUE_APPLICATION_FAILED);
		break;

	default:
		break;
	}

	/*
	 *	The connection frame is either initializing, or has finished all TLS negotiation, and has
	 *	received application data.  Just run the callback, and not any policies.
	 */
	if (conn->state != TLS_CONNECTION_HANDSHAKE) {
		tls_connection_finished(conn);
		return;
	}

	/*
	 *	We were called while there's pending data for OpenSSL.  Likely from an IO callback.
	 *
	 *	The connection may be dead (after a read), but the buffer is likely to contain a TLS Alert.
	 *	Keep the TLS state machine alive until we've read and processed any pending TLS alerts
	 *
	 *	Let the handshake read the record.  tls_connection_check() ends the connection once the frame
	 *	has finished it's state machine, and gone idle.
	 */
	if (conn->pending) {
		conn->fail_pending = true;
		tls_connection_request_wake(conn);
		return;
	}

	/*
	 *	We failed during TLS negotiation, we're done with the connection.  Wake up the request so that
	 *	it can run `fail connection`.
	 */
	conn->state = TLS_CONNECTION_COMPLETE;
	tls_connection_request_wake(conn);
}

/** Record that the peer closed the connection
 *
 * The peer may have sent a record just before closing.  If that record is
 * still pending, it may be the one that completes the handshake, so the
 * request is woken to process it.  tls_connection_check() then fails the
 * connection only if the handshake reads the record and determines it
 * needs another one.
 *
 * If nothing is pending, the handshake is waiting for a record that will
 * never arrive, so the connection fails immediately.
 *
 * @param[in] conn	the peer closed.
 */
void fr_tls_connection_eof(fr_tls_connection_t *conn)
{
	request_t *request = conn->request;

	conn->eof = true;

	if (conn->pending) {
		tls_connection_request_wake(conn);
		return;
	}

	RERROR("Peer closed the connection before the handshake completed");
	errno = 0;		/* fr_tls_connection_failed() records errno, and no call set one */
	fr_tls_connection_failed(conn, TLS_CONNECTION_FAIL_SYSCALL);
}

/** Look at slen / errno to see why IO failed, and act on it.
 *
 * The decision is recorded in `conn->io_state` and `errno` in `conn->error`, which lets other code know
 * exactly what went wrong, and why.
 *
 * The application write function should call this function, and then check its return value.  The writer
 * should return on fatal errors or EOF, or otherwise retry.
 *
 * We leave out EMSGSIZE, ENETDOWN, and ENETUNREACH.  These are recoverable only for unconnected datagram
 * sockets, where we can re-send the datagram later, or send other datagrams to different destinations.  For
 * connected sockets, those errors are fatal.
 *
 * @param[in] conn	the call was made on.
 * @param[in] slen	which the call returned.  Zero and negative values are
 *			classified, a positive value is not an error.
 * @return the classification, which is also left in `conn->io_state`.
 */
fr_tls_connection_io_state_t fr_tls_connection_io_error(fr_tls_connection_t *conn, ssize_t slen)
{
	request_t	*request = conn->request;
	int		error = errno;

	/*
	 *	Nothing failed, so there is nothing to classify.
	 */
	if (slen > 0) {
		conn->io_state = FR_TLS_CONNECTION_IO_OK;
		conn->error = 0;
		return conn->io_state;
	}

	/*
	 *	A read() of zero octets is the end of a stream.  errno says
	 *	nothing about an orderly close, so it is not recorded.
	 */
	if (slen == 0) {
		conn->io_state = FR_TLS_CONNECTION_IO_EOF;
		error = 0;
		goto act;
	}

	switch (error) {
	case EINTR:
		conn->io_state = FR_TLS_CONNECTION_IO_RETRY;
		break;

#if defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
	case EWOULDBLOCK:
#endif
	case EAGAIN:
		conn->io_state = FR_TLS_CONNECTION_IO_BLOCKED;
		break;

	/*
	 *	The peer closed the connection, or reset the connection, or
	 *	went away while the connection was being written to.
	 */
	case ECONNRESET:
	case ENOTCONN:
	case EPIPE:
		conn->io_state = FR_TLS_CONNECTION_IO_EOF;
		break;

	default:
		conn->io_state = FR_TLS_CONNECTION_IO_FATAL;
		break;
	}

act:
	switch (conn->io_state) {
	/*
	 *	The caller runs the call again, or waits for the socket.
	 *	Either way the connection carries on.
	 */
	case FR_TLS_CONNECTION_IO_OK:
	case FR_TLS_CONNECTION_IO_RETRY:
	case FR_TLS_CONNECTION_IO_BLOCKED:
		break;

	/*
	 *	A record the peer sent before closing may still be pending,
	 *	and may be the one which completes the handshake, so this
	 *	does not always end the connection at once.
	 */
	case FR_TLS_CONNECTION_IO_EOF:
		fr_tls_connection_eof(conn);
		break;

	case FR_TLS_CONNECTION_IO_FATAL:
		fr_tls_connection_failed(conn, TLS_CONNECTION_FAIL_SYSCALL);
		break;
	}

	/*
	 *	Set this last.  fr_tls_connection_eof() and
	 *	fr_tls_connection_failed() both record errno themselves, and
	 *	the first of those clears errno before it does, which would
	 *	otherwise discard what the socket reported.
	 */
	conn->error = error;

	ROPTIONAL(RDEBUG3, DEBUG3, "%s - IO state is now %s", conn->name,
		  fr_table_str_by_value(fr_tls_connection_io_state_table, conn->io_state, "<INVALID>"));

	return conn->io_state;
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

	/*
	 *	Record the reason, and nothing else.  This function runs
	 *	inside the connection frame, and runs the failure policy
	 *	itself, a few lines below.  fr_tls_connection_failed() is for
	 *	a caller outside the frame which needs the frame to run that
	 *	policy, so calling it here would ask the frame to do what the
	 *	frame is already doing.  Worse, the macros below are also used
	 *	while the cache operations run, and at that point
	 *	fr_tls_connection_failed() tells the application that the
	 *	connection is over, leaving the push below to run against a
	 *	connection which has already reported its result.
	 */
	conn->failed = TLS_CONNECTION_FAIL_TLS;
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
	 *	fr_tls_ticket_stateful_store_session() and fr_tls_ticket_stateful_clear_session()
	 *	run every queued cache operation before either function
	 *	returns.  An operation still queued here would never run at
	 *	all, and the session would silently not be cached, or would
	 *	silently not be cleared.
	 */
	fr_assert(!fr_tls_ticket_stateful_pending(conn->tls_session->cache));

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
		ua = fr_tls_ticket_stateful_store_session(request, conn->tls_session);
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

	fr_tls_log_error("Failed pushing a TLS handshake round");
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

/** Return how many bytes should be written.
 *
 * This is a function in preparation for adding DTLS.
 *
 * @param[in] conn	to read.
 * @return the number of octets to write, or 0 when nothing is waiting.
 */
static size_t tls_connection_write_len(fr_tls_connection_t *conn)
{
	fr_tls_session_t *tls_session = conn->tls_session;

	return fr_dbuff_remaining(tls_session->dirty_out);
}

/** Push the connection frame onto the request's stack
 *
 * Run the interpreter once after fr_tls_connection_push() returns, so that
 * the connection frame yields.  unlang_interpret_mark_runnable() acts only on
 * a yielded frame, and so fr_tls_connection_wake() does nothing until the
 * connection frame has yielded at least once.
 *
 * @param[in] conn	to run.  `conn->request` must be set, and `conn` must be
 *			a talloc chunk, as `conn->name` is allocated from it.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_tls_connection_push(fr_tls_connection_t *conn)
{
	/*
	 *	Give the connection a name for the log, so that nothing has
	 *	to check for NULL before printing one.  The application knows
	 *	what identifies a connection and the library does not, so a
	 *	name the application set is left alone.
	 *
	 *	The name is a child of the connection, so it cannot outlive
	 *	the connection, and an application which sets its own name
	 *	frees this one first.
	 */
	if (!conn->name) MEM(conn->name = talloc_strdup(conn, "(TLS)"));

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

/** Hand octets which arrived on the connection to OpenSSL.
 *
 * The caller reads from whatever transport the caller uses, and
 * passes the data to OpenSSL.  Nothing else in the TLS library
 * (currentl) reads a socket, so the transport stays entirely with the
 * caller.  EAP does the same thing, except the contents are taken
 * from the EAP packets.
 *
 * The data doesn't have to be an entire record, and can be more than
 * one record.  The application doesn't parse TLS, it just reads raw
 * data and hands it to OpenSSL.  OpenSSL reads some or all of it.
 * Any unread data is left in the buffer, as it generally means we
 * read an incomplete TLS record from the wire.
 *
 * We therefore append the received data to the buffer.  The
 * "into_openssl" buffer size is capped at FR_TLS_MAX_PACKET_SIZE, so
 * if a caller tries to overfill the buffer, this function marks the
 * connection as failed.
 *
 * @todo - perhaps make the "into_ssl" dbuff extensable, but with
 * limits.  See tls_session_alloc() for caveats.
 *
 * @param[in] conn	the octets arrived on.
 * @param[in] data	which arrived.
 * @param[in] data_len	how many octets arrived.  Must be greater than zero.
 */
void fr_tls_connection_recv(fr_tls_connection_t *conn, uint8_t const *data, size_t data_len)
{
	fr_tls_session_t *tls_session = conn->tls_session;
	request_t *request = conn->request;

	RDEBUG3("Read %zu bytes from the connection", data_len);

	if (fr_dbuff_in_memcpy_partial(tls_session->dirty_in, data, data_len) != data_len) {
		RERROR("Failed buffering %zu bytes of TLS record data", data_len);
		fr_tls_session_error_alert(request, tls_session,
					   FR_ERROR_VALUE_RECORD_TOO_LARGE, SSL_AD_RECORD_OVERFLOW);
	error:
		fr_tls_connection_failed(conn, TLS_CONNECTION_FAIL_TLS);
		return;
	}

	/*
	 *	Pushing a handshake round after the handshake has finished is
	 *	a logic error.  See src/lib/tls/session.c.  Application data
	 *	is not handled yet, so a record arriving now is an error.
	 */
	if (fr_tls_session_is_init_finished(tls_session)) {
		RERROR("Received %zu bytes of application data, which is not supported", data_len);
		fr_tls_session_error_alert(request, tls_session,
					   FR_ERROR_VALUE_RECORD_AFTER_HANDSHAKE, SSL_AD_UNEXPECTED_MESSAGE);
		goto error;
	}

	/*
	 *	Hand the round over to the connection frame, which is sitting
	 *	yielded, waiting for exactly that record.
	 */
	fr_tls_connection_wake(conn);
}

/** Write all pending data to the peer.
 *
 * Runs the application `write()` callback with the data.  For stream sockets, we try to write all of the data
 * in one swell foop.  For datagram sockets, we write the data one datagram at a time
 *
 * A write which reports zero means it wrote no data.  All data left stays in the buffer, and the application
 * calls us again when the socket becomes writable.
 *
 * @param[in] conn	to write from.
 * @return
 *	- 0 on success, including when the socket filled.
 *	- -1 if the application's write failed.
 */
int fr_tls_connection_write(fr_tls_connection_t *conn)
{
	size_t size;

	while ((size = tls_connection_write_len(conn)) > 0) {
		uint8_t const	*data = fr_dbuff_current(conn->tls_session->dirty_out);
		ssize_t		slen;

		slen = conn->write(conn->uctx, conn, data, size);
		if (slen < 0) return -1;

		/*
		 *	The socket is full.  Nothing was lost, so this is not a failure.
		 */
		if (slen == 0) break;

		fr_assert((size_t) slen <= size);

		fr_dbuff_advance(conn->tls_session->dirty_out, (size_t) slen);
	}

	return 0;
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
	/*
	 *	fr_tls_connection_recv() refuses some records without handing them to a handshake round at
	 *	all, so for those there is no round to put the closing record into the outgoing buffer.  Do
	 *	it here instead, before the write below, so the peer gets the record rather than a socket
	 *	which stops answering.
	 *
	 *	Only a failure inside TLS reaches this.  TLS_CONNECTION_FAIL_SYSCALL and
	 *	TLS_CONNECTION_FAIL_APPLICATION both mean the socket has been closed, and we can't write a
	 *	close notify.
	 *
	 *	Any error inside of a handshake has been handled by OpenSSL, and this call does nothing more.
	 */
	if (conn->failed == TLS_CONNECTION_FAIL_TLS) fr_tls_session_close_send(conn->request, conn->tls_session);

	/*
	 *	Record a failure on error, but keep processing the TLS state machine, so that we can run `fail
	 *	connection`.
	 */
	if (fr_tls_connection_write(conn) < 0) fr_tls_connection_failed(conn, TLS_CONNECTION_FAIL_APPLICATION);

	tls_connection_check(conn);
}
#endif /* WITH_TLS */
