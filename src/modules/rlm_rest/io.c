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
 * @copyright 2016 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
#include "rest.h"
#include <freeradius-devel/rad_assert.h>
#include <freeradius-devel/modules.h>

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

			curl_multi_remove_handle(mandle, candle);

			thread->transfers--;

			ret = curl_easy_getinfo(candle, CURLINFO_PRIVATE, &request);
			if (!fr_cond_assert(ret == CURLE_OK)) return;

			VERIFY_REQUEST(request);

			/*
			 *	If the request failed, say why...
			 */
			if (m->data.result != CURLE_OK) {
				REDEBUG("%s (%i)", curl_easy_strerror(m->data.result), m->data.result);
			}

			unlang_resumable(request);
		}

		default:
#if 0
			DEBUG4("Got unknown msg (%i) when dequeueing curl responses", msg_queued);
#endif
			break;
		}
	}
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

	if (fd == CURL_SOCKET_TIMEOUT) {
		DEBUG3("multi-handle %p serviced by timer event.  %i request(s) in progress, %i requests(s) to dequeue",
		       mandle, running, t->transfers - running);
	} else {
		DEBUG3("multi-handle %p serviced on fd %i event.  %i request(s) in progress, %i requests(s) to dequeue",
		       mandle, fd, running, t->transfers - running);
	}

	_rest_io_demux(t, mandle);
}

/** libcurl's timer expired
 *
 * @param[in] el	the timer was inserted into.
 * @param[in] now	The current time according to the event loop.
 * @param[in] ctx	The rlm_rest_thread_t specific to this thread.
 */
static void _rest_io_timer_expired(UNUSED fr_event_list_t *el, UNUSED struct timeval *now, void *ctx)
{
	rlm_rest_thread_t *t;

	t = talloc_get_type_abort(ctx, rlm_rest_thread_t);

	DEBUG4("libcurl timer expired");

	_rest_io_service(t, CURL_SOCKET_TIMEOUT, 0);
}

/** File descriptor experienced an error
 *
 * @param[in] el	fd was registered with.
 * @param[in] fd	that errored.
 * @param[in] ctx	The rlm_rest_thread_t specific to this thread.
 */
static void _rest_io_service_errored(UNUSED fr_event_list_t *el, int fd, void *ctx)
{
	rlm_rest_thread_t *t;

	t = talloc_get_type_abort(ctx, rlm_rest_thread_t);

	DEBUG4("libcurl fd %i errored", fd);

	_rest_io_service(t, fd, CURL_CSELECT_ERR);
}

/** File descriptor became writable
 *
 * @param[in] el	fd was registered with.
 * @param[in] fd	that became writable.
 * @param[in] ctx	The rlm_rest_thread_t specific to this thread.
 */
static void _rest_io_service_writable(UNUSED fr_event_list_t *el, int fd, void *ctx)
{
	rlm_rest_thread_t *t;

	t = talloc_get_type_abort(ctx, rlm_rest_thread_t);

	DEBUG4("libcurl fd %i now writable", fd);

	_rest_io_service(t, fd, CURL_CSELECT_OUT);
}

/** File descriptor became readable
 *
 * @param[in] el	fd was registered with.
 * @param[in] fd	that became readable.
 * @param[in] ctx	The rlm_rest_thread_t specific to this thread.
 */
static void _rest_io_service_readable(UNUSED fr_event_list_t *el, int fd, void *ctx)
{
	rlm_rest_thread_t *t;

	t = talloc_get_type_abort(ctx, rlm_rest_thread_t);

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
	struct timeval		now, to_add, when;

	if (timeout_ms == 0) {
		ret = curl_multi_socket_action(mandle, CURL_SOCKET_TIMEOUT, 0, &running);
		if (ret != CURLM_OK) {
			ERROR("Failed servicing curl multi-handle: %s (%i)", curl_multi_strerror(ret), ret);
			return -1;
		}

		DEBUG3("multi-handle %p serviced from timer_modify.  %i request(s) in progress, %i requests(s) "
		       "to dequeue", mandle, running, t->transfers - running);
		return 0;
	}

	if (timeout_ms < 0) {
		if (fr_event_timer_delete(t->el, &t->ev) < 0) {
			PERROR("Failed deleting multi-handle timer");
			return -1;
		}
		DEBUG3("multi-handle %p timer removed", mandle);
		return 0;
	}

	DEBUG3("multi-handle %p needs servicing in %li ms", mandle, timeout_ms);

	gettimeofday(&now, NULL);
	fr_timeval_from_ms(&to_add, (uint64_t)timeout_ms);
	fr_timeval_add(&when, &now, &to_add);

	(void) fr_event_timer_insert(t->el, _rest_io_timer_expired, t, &when, &t->ev);

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
		if (fr_event_fd_insert(thread->el, fd,
				       _rest_io_service_readable, NULL, _rest_io_service_errored,
				       thread) < 0) {
			ERROR("multi-handle %p registration failed for read+error events on FD %i: %s",
			      thread->mandle, fd, fr_strerror());
			return -1;
		}
		DEBUG4("multi-handle %p registered for read+error events on FD %i", thread->mandle, fd);
		break;

	case CURL_POLL_OUT:
		if (fr_event_fd_insert(thread->el, fd,
				       NULL, _rest_io_service_writable, _rest_io_service_errored,
				       thread) < 0) {
			ERROR("multi-handle %p registration failed for write+error events on FD %i: %s",
			      thread->mandle, fd, fr_strerror());
			return -1;
		}
		DEBUG4("multi-handle %p registered for write+error events on FD %i", thread->mandle, fd);
		break;

	case CURL_POLL_INOUT:
		if (fr_event_fd_insert(thread->el, fd,
				       _rest_io_service_readable, _rest_io_service_writable, _rest_io_service_errored,
				       thread) < 0) {
			ERROR("multi-handle %p registration failed for read+write+error events on FD %i: %s",
			      thread->mandle, fd, fr_strerror());
			return -1;
		}
		DEBUG4("multi-handle %p registered for read+write+error events on FD %i", thread->mandle, fd);
		break;

	case CURL_POLL_REMOVE:
		if (fr_event_fd_delete(thread->el, fd) < 0) {
			ERROR("multi-handle %p de-registration failed for FD %i %s", thread->mandle, fd, fr_strerror());
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
 * If we're signalled that the request has been cancelled (FR_ACTION_DONE).
 * Cleanup any pending state and release the connection handle back into the pool.
 *
 * @param[in] request	being cancelled.
 * @param[in] instance	of rlm_rest.
 * @param[in] thread	Thread specific module instance.
 * @param[in] ctx	rlm_rest_handle_t currently used by the request.
 * @param[in] action	What happened.
 */
void rest_io_action(REQUEST *request, void *instance, void *thread, void *ctx, fr_state_action_t action)
{
	rlm_rest_handle_t	*randle = talloc_get_type_abort(ctx, rlm_rest_handle_t);
	rlm_rest_thread_t	*t = thread;
	CURLMcode		ret;

	if (action != FR_ACTION_DONE) return;

	RDEBUG("Forcefully cancelling pending REST request");

	ret = curl_multi_remove_handle(t->mandle, randle->candle);	/* Gracefully terminate the request */
	if (ret != CURLM_OK) {
		RERROR("Failed removing curl handle from multi-handle: %s (%i)", curl_multi_strerror(ret), ret);
		/* Not much we can do */
	}
	t->transfers--;

	rest_request_cleanup(instance, randle);
	fr_connection_release(t->pool, request, randle);
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

	VERIFY_REQUEST(request);

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

	ret = curl_multi_add_handle(t->mandle, candle);
	if (ret != CURLE_OK) {
		REDEBUG("Request failed: %i - %s", ret, curl_easy_strerror(ret));
		return -1;
	}
	t->transfers++;

	return 0;
}

/** Performs the libcurl initialisation of the thread
 *
 * @param[in] thread to initialise.
 * @return
 *	- 0 on success.
 *	- -1 on error.
 */
int rest_io_init(rlm_rest_thread_t *thread)
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

	return 0;

error:
	ERROR("Failed setting curl option %s: %s (%i)", option, curl_multi_strerror(ret), ret);

	return -1;
}
