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
 * @file rlm_rest/io.c
 * @brief Implement asynchronous callbacks for curl
 *
 * @copyright 2016 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
#include "rest.h"
#include <freeradius-devel/server/rad_assert.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/unlang/base.h>

/*
 *  CURL headers do:
 *
 *  #define curl_easy_setopt(handle,opt,param) curl_easy_setopt(handle,opt,param)
 */
DIAG_OPTIONAL
DIAG_OFF(disabled-macro-expansion)
#define SET_OPTION(_x, _y)\
do {\
	if ((ret = curl_multi_setopt(mandle, _x, _y)) != CURLM_OK) {\
		option = STRINGIFY(_x);\
		goto error;\
	}\
} while (0)

/** De-queue curl requests and wake up the requests that initiated them
 *
 * @param[in] thread	holding the requests to re-enliven.
 * @param[in] mandle	to dequeue curl easy handles/responses from.
 */
static inline void _rest_io_demux(rlm_rest_thread_t *thread, CURLM *mandle)
{
	struct CURLMsg	*m;
	int		msg_queued = 0;

	while ((m = curl_multi_info_read(mandle, &msg_queued))) {
		switch (m->msg) {
		case CURLMSG_DONE:
		{
			REQUEST		*request = NULL;
			CURL		*candle = m->easy_handle;
			CURLcode	ret;

			rad_assert(candle);

			thread->transfers--;

			ret = curl_easy_getinfo(candle, CURLINFO_PRIVATE, &request);
			if (!fr_cond_assert_msg(ret == CURLE_OK,
						"Failed retrieving request data from CURL easy handle (candle)")) {
				curl_multi_remove_handle(mandle, candle);
				return;
			}

			REQUEST_VERIFY(request);

			/*
			 *	If the request failed, say why...
			 */
			if (m->data.result != CURLE_OK) {
				REDEBUG("REST request failed: %s (%i)",
					curl_easy_strerror(m->data.result), m->data.result);
			}

			/*
			 *	Looks like this needs to be done last,
			 *	else m->data.result ends up being junk.
			 */
			curl_multi_remove_handle(mandle, candle);

			unlang_interpret_resumable(request);
		}
			break;

		default:
#ifndef NDEBUG
			DEBUG4("Got unknown msg (%i) when dequeueing curl responses", msg_queued);
#endif
			break;
		}
	}
}

/** libcurl's timer expired
 *
 * @param[in] el	the timer was inserted into.
 * @param[in] now	The current time according to the event loop.
 * @param[in] ctx	The rlm_rest_thread_t specific to this thread.
 */
static void _rest_io_timer_expired(UNUSED fr_event_list_t *el, UNUSED fr_time_t now, void *ctx)
{
	rlm_rest_thread_t	*t = talloc_get_type_abort(ctx, rlm_rest_thread_t);
	CURLMcode		ret;
	CURLM			*mandle = t->mandle;
	int			running = 0;

	t = talloc_get_type_abort(ctx, rlm_rest_thread_t);

	DEBUG4("libcurl timer expired");

	ret = curl_multi_socket_action(mandle, CURL_SOCKET_TIMEOUT, 0, &running);
	if (ret != CURLM_OK) {
		ERROR("Failed servicing curl multi-handle: %s (%i)", curl_multi_strerror(ret), ret);
		return;
	}

	DEBUG3("multi-handle %p serviced by timer.  %i request(s) in progress, %i requests(s) to dequeue",
	       mandle, running, t->transfers - running);

	_rest_io_demux(t, mandle);
}

/** Service an IO event on a file descriptor
 *
 * @param[in] t		Thread the event ocurred in.
 * @param[in] fd	the IO event occurred for.
 * @param[in] event	type.
 */
static inline void _rest_io_service(rlm_rest_thread_t *t, int fd, int event)
{
	CURLMcode		ret;
	CURLM			*mandle = t->mandle;
	int			running = 0;

	ret = curl_multi_socket_action(mandle, fd, event, &running);
	if (ret != CURLM_OK) {
		ERROR("Failed servicing curl multi-handle: %s (%i)", curl_multi_strerror(ret), ret);
		return;
	}

	if (DEBUG_ENABLED3) {
		char const *event_str;

		switch (event) {
		case CURL_CSELECT_ERR:
			event_str = "error";
			break;

		case CURL_CSELECT_OUT:
			event_str = "socket-writable";
			break;

		case CURL_CSELECT_IN:
			event_str = "socket-readable";
			break;

		default:
			event_str = "<INVALID>";
			break;
		}

		DEBUG3("multi-handle %p serviced on fd %i event (%s).  "
		       "%i request(s) in progress, %i requests(s) to dequeue",
		       mandle, fd, event_str, running, t->transfers - running);
	}


	_rest_io_demux(t, mandle);
}

/** File descriptor experienced an error
 *
 * @param[in] el	fd was registered with.
 * @param[in] fd	that errored.
 * @param[in] flags	from kevent.
 * @param[in] fd_errno	from kevent.
 * @param[in] uctx	The rlm_rest_thread_t specific to this thread.
 */
static void _rest_io_service_errored(UNUSED fr_event_list_t *el, int fd, UNUSED int flags, int fd_errno, void *uctx)
{
	rlm_rest_thread_t *t;

	t = talloc_get_type_abort(uctx, rlm_rest_thread_t);

	DEBUG4("libcurl fd %i errored: %s", fd, fr_syserror(fd_errno));

	_rest_io_service(t, fd, CURL_CSELECT_ERR);
}

/** File descriptor became writable
 *
 * @param[in] el	fd was registered with.
 * @param[in] fd	that became writable.
 * @param[in] flags	from kevent.
 * @param[in] uctx	The rlm_rest_thread_t specific to this thread.
 */
static void _rest_io_service_writable(UNUSED fr_event_list_t *el, int fd, UNUSED int flags, void *uctx)
{
	rlm_rest_thread_t *t;

	t = talloc_get_type_abort(uctx, rlm_rest_thread_t);

	DEBUG4("libcurl fd %i now writable", fd);

	_rest_io_service(t, fd, CURL_CSELECT_OUT);
}

/** File descriptor became readable
 *
 * @param[in] el	fd was registered with.
 * @param[in] fd	that became readable.
 * @param[in] flags	from kevent.
 * @param[in] uctx	The rlm_rest_thread_t specific to this thread.
 */
static void _rest_io_service_readable(UNUSED fr_event_list_t *el, int fd, UNUSED int flags, void *uctx)
{
	rlm_rest_thread_t *t;

	t = talloc_get_type_abort(uctx, rlm_rest_thread_t);

	DEBUG4("libcurl fd %i now readable", fd);

	_rest_io_service(t, fd, CURL_CSELECT_IN);
}

/** Callback called by libcurl to set/unset timers
 *
 * Each rlm_rest_thread_t has a timer event which is controller by libcurl.
 * This allows libcurl to honour timeouts set on requests to remote hosts,
 * and means we don't need to set timeouts for individual I/O events.
 *
 * @param[in] mandle		handle requesting the timer be set/unset.
 * @param[in] timeout_ms	If > 0, how long to wait before calling curl_multi_socket_action.
 *				If == 0, we call curl_multi_socket_action as soon as possible.
 *				If < 0, we delete the timer.
 * @param[in] ctx		The rlm_rest_thread_t specific to this thread.
 * @return
 *	- 0 on success.
 *	- -1 on error.
 */
static int _rest_io_timer_modify(CURLM *mandle, long timeout_ms, void *ctx)
{
	rlm_rest_thread_t	*t = talloc_get_type_abort(ctx, rlm_rest_thread_t);
	CURLMcode		ret;
	int			running = 0;

	if (timeout_ms == 0) {
		ret = curl_multi_socket_action(mandle, CURL_SOCKET_TIMEOUT, 0, &running);
		if (ret != CURLM_OK) {
			ERROR("Failed servicing curl multi-handle: %s (%i)", curl_multi_strerror(ret), ret);
			return -1;
		}

		DEBUG3("multi-handle %p serviced from CURLMOPT_TIMERFUNCTION callback (%s).  "
		       "%i request(s) in progress, %i requests(s) to dequeue",
		        mandle, __FUNCTION__, running, t->transfers - running);
		return 0;
	}

	if (timeout_ms < 0) {
		if (fr_event_timer_delete(&t->ev) < 0) {
			PERROR("Failed deleting multi-handle timer");
			return -1;
		}
		DEBUG3("multi-handle %p timer removed", mandle);
		return 0;
	}

	DEBUG3("multi-handle %p will need servicing in %li ms", mandle, timeout_ms);

	(void) fr_event_timer_in(NULL, t->el, &t->ev,
				 fr_time_delta_from_msec(timeout_ms), _rest_io_timer_expired, t);

	return 0;
}

/** Called by libcurl to register a socket that it's interested in receiving IO events for
 *
 *
 * @param[in] easy	handle this fd relates to.
 * @param[in] fd	File descriptor curl wants to be notified about.
 * @param[in] what	Which events libcurl wants to be notified of, may be one of:
 *			- CURL_POLL_IN		Wait for incoming data. For the socket
 *						to become readable.
 *			- CURL_POLL_OUT		Wait for outgoing data. For the socket
 *						to become writable.
 *			- CURL_POLL_INOUT	Wait for incoming and outgoing data.
 *						For the socket to become readable or writable.
 *			- CURL_POLL_REMOVE	The specified socket/file descriptor is no
 * 						longer used by libcurl.
 * @param[in] ctx	The rlm_rest_thread_t specific to this thread.
 * @param[in] fd_ctx	Private data associated with the socket.
 */
static int _rest_io_event_modify(UNUSED CURL *easy, curl_socket_t fd, int what, void *ctx, UNUSED void *fd_ctx)
{
	rlm_rest_thread_t	*thread = talloc_get_type_abort(ctx, rlm_rest_thread_t);

	switch (what) {
	case CURL_POLL_IN:
		if (fr_event_fd_insert(thread, thread->el, fd,
				       _rest_io_service_readable,
				       NULL,
				       _rest_io_service_errored,
				       thread) < 0) {
			PERROR("multi-handle %p registration failed for read+error events on FD %i",
			       thread->mandle, fd);
			return -1;
		}
		DEBUG4("multi-handle %p registered for read+error events on FD %i", thread->mandle, fd);
		break;

	case CURL_POLL_OUT:
		if (fr_event_fd_insert(thread, thread->el, fd,
				       NULL,
				       _rest_io_service_writable,
				       _rest_io_service_errored,
				       thread) < 0) {
			PERROR("multi-handle %p registration failed for write+error events on FD %i",
			       thread->mandle, fd);
			return -1;
		}
		DEBUG4("multi-handle %p registered for write+error events on FD %i", thread->mandle, fd);
		break;

	case CURL_POLL_INOUT:
		if (fr_event_fd_insert(thread, thread->el, fd,
				       _rest_io_service_readable,
				       _rest_io_service_writable,
				       _rest_io_service_errored,
				       thread) < 0) {
			PERROR("multi-handle %p registration failed for read+write+error events on FD %i",
			       thread->mandle, fd);
			return -1;
		}
		DEBUG4("multi-handle %p registered for read+write+error events on FD %i", thread->mandle, fd);
		break;

	case CURL_POLL_REMOVE:
		if (fr_event_fd_delete(thread->el, fd, FR_EVENT_FILTER_IO) < 0) {
			PERROR("multi-handle %p de-registration failed for FD %i", thread->mandle, fd);
			return -1;
		}
		DEBUG4("multi-handle %p unregistered events for FD %i", thread->mandle, fd);
		break;

	default:
		rad_assert(0);
		return -1;
	}

	return CURLM_OK;
}

/** Handle asynchronous cancellation of a request
 *
 * If we're signalled that the request has been cancelled (FR_SIGNAL_CANCEL).
 * Cleanup any pending state and release the connection handle back into the pool.
 *
 * @param[in] instance	of rlm_rest.
 * @param[in] thread	Thread specific module instance.
 * @param[in] request	being cancelled.
 * @param[in] rctx	rlm_rest_handle_t currently used by the request.
 * @param[in] action	What happened.
 */
void rest_io_module_action(void *instance, void *thread, REQUEST *request, void *rctx, fr_state_signal_t action)
{
	rlm_rest_handle_t	*randle = talloc_get_type_abort(rctx, rlm_rest_handle_t);
	rlm_rest_thread_t	*t = thread;
	CURLMcode		ret;

	if (action != FR_SIGNAL_CANCEL) return;

	RDEBUG2("Forcefully cancelling pending REST request");

	ret = curl_multi_remove_handle(t->mandle, randle->candle);	/* Gracefully terminate the request */
	if (ret != CURLM_OK) {
		RERROR("Failed removing curl handle from multi-handle: %s (%i)", curl_multi_strerror(ret), ret);
		/* Not much we can do */
	}
	t->transfers--;

	rest_request_cleanup(instance, randle);
	fr_pool_connection_release(t->pool, request, randle);
}

/** Handle asynchronous cancellation of a request
 *
 * If we're signalled that the request has been cancelled (FR_SIGNAL_CANCEL).
 * Cleanup any pending state and release the connection handle back into the pool.
 *
 * @param[in] request	being cancelled.
 * @param[in] instance	of rlm_rest.
 * @param[in] thread	Thread specific module instance.
 * @param[in] rctx	rlm_rest_handle_t currently used by the request.
 * @param[in] action	What happened.
 */
void rest_io_xlat_signal(REQUEST *request, UNUSED void *instance, void *thread, void *rctx, fr_state_signal_t action)
{
	rest_xlat_thread_inst_t		*xti = talloc_get_type_abort(thread, rest_xlat_thread_inst_t);
	rlm_rest_t			*mod_inst = xti->inst;
	rlm_rest_thread_t		*t = xti->t;

	rlm_rest_xlat_rctx_t		*our_rctx = talloc_get_type_abort(rctx, rlm_rest_xlat_rctx_t);
	rlm_rest_handle_t		*randle = talloc_get_type_abort(our_rctx->handle, rlm_rest_handle_t);

	rest_io_module_action(mod_inst, t, request, randle, action);
}

/** Sends a REST (HTTP) request.
 *
 * Send the actual REST request to the server. The response will be handled by
 * the numerous callbacks configured in rest_request_config.
 *
 * @param[in] t		Servicing this request.
 * @param[in] request	Current request.
 * @param[in] handle	to use.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int rest_io_request_enqueue(rlm_rest_thread_t *t, REQUEST *request, void *handle)
{
	rlm_rest_handle_t	*randle = handle;
	CURL			*candle = randle->candle;
	CURLcode		ret;

	REQUEST_VERIFY(request);

	/*
	 *	Stick the current request in the curl handle's
	 *	private data.  This makes it simple to resume
	 *	the request in the demux function later...
	 */
	ret = curl_easy_setopt(candle, CURLOPT_PRIVATE, request);
	if (ret != CURLE_OK) {
		REDEBUG("Request failed: %i - %s", ret, curl_easy_strerror(ret));
		return -1;
	}

	/*
	 *	Increment here, else the debug output looks
	 *	messed up is curl_multi_add_handle triggers
	 *      event loop modifications calls immediately.
	 */
	t->transfers++;
	ret = curl_multi_add_handle(t->mandle, candle);
	if (ret != CURLE_OK) {
		t->transfers--;
		REDEBUG("Request failed: %i - %s", ret, curl_easy_strerror(ret));
		return -1;
	}


	return 0;
}

/** Performs the libcurl initialisation of the thread
 *
 * @param[in] thread		to initialise.
 * @param[in] multiplex		Run multiple requests over the same connection simultaneously.
 * @return
 *	- 0 on success.
 *	- -1 on error.
 */
int rest_io_init(rlm_rest_thread_t *thread,
#ifndef CURLPIPE_MULTIPLEX
		 UNUSED
#endif
		 bool multiplex)
{
	CURLMcode	ret;
	CURLM		*mandle;
	char const	*option = "unknown";

	mandle = thread->mandle = curl_multi_init();
	if (!thread->mandle) {
		ERROR("Curl multi-handle instantiation failed");
		return -1;
	}

	SET_OPTION(CURLMOPT_TIMERFUNCTION, _rest_io_timer_modify);
	SET_OPTION(CURLMOPT_TIMERDATA, thread);

	SET_OPTION(CURLMOPT_SOCKETFUNCTION, _rest_io_event_modify);
	SET_OPTION(CURLMOPT_SOCKETDATA, thread);

#ifdef CURLPIPE_MULTIPLEX
	SET_OPTION(CURLMOPT_PIPELINING, multiplex ? CURLPIPE_MULTIPLEX : CURLPIPE_NOTHING);
#endif

	return 0;

error:
	ERROR("Failed setting curl option %s: %s (%i)", option, curl_multi_strerror(ret), ret);

	return -1;
}
