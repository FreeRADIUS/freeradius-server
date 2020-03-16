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
 * @file libfreeradius-curl/io.c
 * @brief Implement asynchronous callbacks for curl
 *
 * @copyright 2020 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
#include <freeradius-devel/curl/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/rad_assert.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/util/syserror.h>

#include <curl/curl.h>
#include <talloc.h>

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
 * @param[in] mhandle	containing the event loop and request counter.
 * @param[in] mandle	to dequeue curl easy handles/responses from.
 */
static inline void _fr_curl_io_demux(fr_curl_handle_t *mhandle, CURLM *mandle)
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

			mhandle->transfers--;

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
				REDEBUG("curl request failed: %s (%i)",
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
 * @param[in] uctx	The rlm_fr_curl_thread_t specific to this thread.
 */
static void _fr_curl_io_timer_expired(UNUSED fr_event_list_t *el, UNUSED fr_time_t now, void *uctx)
{
	fr_curl_handle_t	*mhandle = talloc_get_type_abort(uctx, fr_curl_handle_t);
	CURLM			*mandle = mhandle->mandle;
	CURLMcode		ret;
	int			running = 0;

	DEBUG4("libcurl timer expired");

	ret = curl_multi_socket_action(mandle, CURL_SOCKET_TIMEOUT, 0, &running);
	if (ret != CURLM_OK) {
		ERROR("Failed servicing curl multi-handle: %s (%i)", curl_multi_strerror(ret), ret);
		return;
	}

	DEBUG3("multi-handle %p serviced by timer.  %i request(s) in progress, %" PRIu64 " requests(s) to dequeue",
	       mandle, running, mhandle->transfers - (uint64_t)running);

	_fr_curl_io_demux(mhandle, mandle);
}

/** Service an IO event on a file descriptor
 *
 * @param[in] mhandle	containing the event loop and request counter.
 * @param[in] fd	the IO event occurred for.
 * @param[in] event	type.
 */
static inline void _fr_curl_io_service(fr_curl_handle_t *mhandle, int fd, int event)
{
	CURLMcode		ret;
	CURLM			*mandle = mhandle->mandle;
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
		       "%i request(s) in progress, %" PRIu64 " requests(s) to dequeue",
		       mandle, fd, event_str, running, mhandle->transfers - (uint64_t)running);
	}


	_fr_curl_io_demux(mhandle, mandle);
}

/** File descriptor experienced an error
 *
 * @param[in] el	fd was registered with.
 * @param[in] fd	that errored.
 * @param[in] flags	from kevent.
 * @param[in] fd_errno	from kevent.
 * @param[in] uctx	The rlm_fr_curl_thread_t specific to this thread.
 */
static void _fr_curl_io_service_errored(UNUSED fr_event_list_t *el, int fd, UNUSED int flags, int fd_errno, void *uctx)
{
	fr_curl_handle_t	*mhandle = talloc_get_type_abort(uctx, fr_curl_handle_t);

	DEBUG4("libcurl fd %i errored: %s", fd, fr_syserror(fd_errno));

	_fr_curl_io_service(mhandle, fd, CURL_CSELECT_ERR);
}

/** File descriptor became writable
 *
 * @param[in] el	fd was registered with.
 * @param[in] fd	that became writable.
 * @param[in] flags	from kevent.
 * @param[in] uctx	The rlm_fr_curl_thread_t specific to this thread.
 */
static void _fr_curl_io_service_writable(UNUSED fr_event_list_t *el, int fd, UNUSED int flags, void *uctx)
{
	fr_curl_handle_t	*mhandle = talloc_get_type_abort(uctx, fr_curl_handle_t);

	DEBUG4("libcurl fd %i now writable", fd);

	_fr_curl_io_service(mhandle, fd, CURL_CSELECT_OUT);
}

/** File descriptor became readable
 *
 * @param[in] el	fd was registered with.
 * @param[in] fd	that became readable.
 * @param[in] flags	from kevent.
 * @param[in] uctx	The rlm_fr_curl_thread_t specific to this thread.
 */
static void _fr_curl_io_service_readable(UNUSED fr_event_list_t *el, int fd, UNUSED int flags, void *uctx)
{
	fr_curl_handle_t	*mhandle = talloc_get_type_abort(uctx, fr_curl_handle_t);

	DEBUG4("libcurl fd %i now readable", fd);

	_fr_curl_io_service(mhandle, fd, CURL_CSELECT_IN);
}

/** Callback called by libcurl to set/unset timers
 *
 * Each rlm_fr_curl_thread_t has a timer event which is controller by libcurl.
 * This allows libcurl to honour timeouts set on requests to remote hosts,
 * and means we don't need to set timeouts for individual I/O events.
 *
 * @param[in] mandle		handle requesting the timer be set/unset.
 * @param[in] timeout_ms	If > 0, how long to wait before calling curl_multi_socket_action.
 *				If == 0, we call curl_multi_socket_action as soon as possible.
 *				If < 0, we delete the timer.
 * @param[in] ctx		The rlm_fr_curl_thread_t specific to this thread.
 * @return
 *	- 0 on success.
 *	- -1 on error.
 */
static int _fr_curl_io_timer_modify(CURLM *mandle, long timeout_ms, void *ctx)
{
	fr_curl_handle_t	*mhandle = talloc_get_type_abort(ctx, fr_curl_handle_t);
	CURLMcode		ret;
	int			running = 0;

	if (timeout_ms == 0) {
		ret = curl_multi_socket_action(mandle, CURL_SOCKET_TIMEOUT, 0, &running);
		if (ret != CURLM_OK) {
			ERROR("Failed servicing curl multi-handle: %s (%i)", curl_multi_strerror(ret), ret);
			return -1;
		}

		DEBUG3("multi-handle %p serviced from CURLMOPT_TIMERFUNCTION callback (%s).  "
		       "%i request(s) in progress, %" PRIu64 " requests(s) to dequeue",
		        mandle, __FUNCTION__, running, mhandle->transfers - (uint64_t)running);
		return 0;
	}

	if (timeout_ms < 0) {
		if (fr_event_timer_delete(&mhandle->ev) < 0) {
			PERROR("Failed deleting multi-handle timer");
			return -1;
		}
		DEBUG3("multi-handle %p timer removed", mandle);
		return 0;
	}

	DEBUG3("multi-handle %p will need servicing in %li ms", mandle, timeout_ms);

	(void) fr_event_timer_in(NULL, mhandle->el, &mhandle->ev,
				 fr_time_delta_from_msec(timeout_ms), _fr_curl_io_timer_expired, mhandle);

	return 0;
}

/** Called by libcurl to register a socket that it's intefr_curled in receiving IO events for
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
 * @param[in] ctx	The fr_curl_handle_t specific to this thread.
 * @param[in] fd_ctx	Private data associated with the socket.
 */
static int _fr_curl_io_event_modify(UNUSED CURL *easy, curl_socket_t fd, int what, void *ctx, UNUSED void *fd_ctx)
{
	fr_curl_handle_t	*mhandle = talloc_get_type_abort(ctx, fr_curl_handle_t);

	switch (what) {
	case CURL_POLL_IN:
		if (fr_event_fd_insert(mhandle, mhandle->el, fd,
				       _fr_curl_io_service_readable,
				       NULL,
				       _fr_curl_io_service_errored,
				       mhandle) < 0) {
			PERROR("multi-handle %p registration failed for read+error events on FD %i",
			       mhandle->mandle, fd);
			return -1;
		}
		DEBUG4("multi-handle %p registered for read+error events on FD %i", mhandle->mandle, fd);
		break;

	case CURL_POLL_OUT:
		if (fr_event_fd_insert(mhandle, mhandle->el, fd,
				       NULL,
				       _fr_curl_io_service_writable,
				       _fr_curl_io_service_errored,
				       mhandle) < 0) {
			PERROR("multi-handle %p registration failed for write+error events on FD %i",
			       mhandle->mandle, fd);
			return -1;
		}
		DEBUG4("multi-handle %p registered for write+error events on FD %i", mhandle->mandle, fd);
		break;

	case CURL_POLL_INOUT:
		if (fr_event_fd_insert(mhandle, mhandle->el, fd,
				       _fr_curl_io_service_readable,
				       _fr_curl_io_service_writable,
				       _fr_curl_io_service_errored,
				       mhandle) < 0) {
			PERROR("multi-handle %p registration failed for read+write+error events on FD %i",
			       mhandle->mandle, fd);
			return -1;
		}
		DEBUG4("multi-handle %p registered for read+write+error events on FD %i", mhandle->mandle, fd);
		break;

	case CURL_POLL_REMOVE:
		if (fr_event_fd_delete(mhandle->el, fd, FR_EVENT_FILTER_IO) < 0) {
			PERROR("multi-handle %p de-registration failed for FD %i", mhandle->mandle, fd);
			return -1;
		}
		DEBUG4("multi-handle %p unregistered events for FD %i", mhandle->mandle, fd);
		break;

	default:
		rad_assert(0);
		return -1;
	}

	return CURLM_OK;
}

/** Sends a request using libcurl
 *
 * Send the actual curl request to the server. The response will be handled by
 * the numerous callbacks configured for the easy handle.
 *
 * @param[in] mhandle			Thread-specific mhandle wrapper.
 * @param[in] request			Current request.
 * @param[in] candle			representing the request.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_curl_io_request_enqueue(fr_curl_handle_t *mhandle, REQUEST *request, CURL *candle)
{
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
	mhandle->transfers++;
	ret = curl_multi_add_handle(mhandle->mandle, candle);
	if (ret != CURLE_OK) {
		mhandle->transfers--;
		REDEBUG("Request failed: %i - %s", ret, curl_easy_strerror(ret));
		return -1;
	}

	return 0;
}

/** Free the multi-handle
 *
 */
static int _mhandle_free(fr_curl_handle_t *mhandle)
{
	curl_multi_cleanup(mhandle->mandle);

	return 0;
}

/** Performs the libcurl initialisation of the thread
 *
 * @param[in] ctx		to alloc handle in.
 * @param[in] el		to initial.
 * @param[in] multiplex		Run multiple requests over the same connection simultaneously.
 *				HTTP/2 only.
 * @return
 *	- 0 on success.
 *	- -1 on error.
 */
fr_curl_handle_t *fr_curl_io_init(TALLOC_CTX *ctx,
				   fr_event_list_t *el,
#ifndef CURLPIPE_MULTIPLEX
				   UNUSED
#endif
				   bool multiplex)
{
	CURLMcode		ret;
	CURLM			*mandle;
	fr_curl_handle_t	*mhandle;
	char const		*option = "unknown";

	mandle = curl_multi_init();
	if (!mandle) {
		ERROR("Curl multi-handle instantiation failed");
		return NULL;
	}

	/*
	 *	Structure to store extra data.
	 *
	 *	Passed to all curl I/O and timer callbacks.
	 *
	 *	If uctx data is needed in the future, can be added here.
	 */
	MEM(mhandle = talloc_zero(ctx, fr_curl_handle_t));
	mhandle->el = el;
	mhandle->mandle = mandle;
	talloc_set_destructor(mhandle, _mhandle_free);

	SET_OPTION(CURLMOPT_TIMERFUNCTION, _fr_curl_io_timer_modify);
	SET_OPTION(CURLMOPT_TIMERDATA, mhandle);

	SET_OPTION(CURLMOPT_SOCKETFUNCTION, _fr_curl_io_event_modify);
	SET_OPTION(CURLMOPT_SOCKETDATA, mhandle);

#ifdef CURLPIPE_MULTIPLEX
	SET_OPTION(CURLMOPT_PIPELINING, multiplex ? CURLPIPE_MULTIPLEX : CURLPIPE_NOTHING);
#endif

	return mhandle;

error:
	ERROR("Failed setting curl option %s: %s (%i)", option, curl_multi_strerror(ret), ret);

	return NULL;
}
