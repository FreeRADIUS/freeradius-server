#pragma once

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
 * @file lib/redis/io.h
 * @brief Redis asynchronous I/O connection allocation
 *
 * @copyright 2019 The FreeRADIUS server project
 * @copyright 2019 Network RADIUS SARL (legal@networkradius.com)
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(redis_io_h, "$Id$")

#include <freeradius-devel/redis/base.h>
#include <freeradius-devel/util/event.h>
#include <freeradius-devel/server/connection.h>

#include <hiredis/async.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	char			*hostname;
	uint16_t		port;
	uint32_t		database;	//!< number on Redis server.

	char const		*password;	//!< to authenticate to Redis.
	fr_time_delta_t		connection_timeout;
	fr_time_delta_t		reconnection_delay;
	char const		*log_prefix;
} fr_redis_io_conf_t;

typedef uint64_t fr_redis_sqn_t;

typedef struct {
	fr_dlist_t	entry;
	fr_redis_sqn_t	sqn;
} fr_redis_sqn_ignore_t;

/** Store I/O state
 *
 * There are three layers of wrapping structures
 *
 * fr_connection_t -> fr_redis_handle_t -> redisAsyncContext
 *
 */
typedef struct {
	bool			read_set;		//!< We're listening for reads.
	bool			write_set;		//!< We're listening for writes.
	bool			ignore_disconnect_cb;	//!< Ensure that redisAsyncFree doesn't cause
							///< a callback loop.
	fr_event_timer_t const	*timer;			//!< Connection timer.


	redisAsyncContext	*ac;			//!< Async handle for hiredis.

	fr_dlist_head_t		ignore;			//!< Contains SQNs for responses that should be ignored.

	fr_redis_sqn_t		req_sqn;		//!< Current redis request number.
							///< Note: It would take 5.8 million years running
							///< at 100,000 requests/s to overflow, but my OCD
							///< requires that the max uses for trunk connections
							///< is set to UINT64_MAX if not specified by
							///< the user. It's one branch, and it makes me
							///< happy, deal with it.
	fr_redis_sqn_t		rsp_sqn;		//!< Current redis response number.
} fr_redis_handle_t;

/** Tell the handle we sent a command, and get the SQN that command was assigned
 *
 * *MUST* be called for every command sent using the handle. Relies on the fact
 * that responses from REDIS are FIFO with requests.
 *
 * @param[in] h	the request was sent on.
 * @return the handle specific SQN.
 */
static inline fr_redis_sqn_t fr_redis_connection_sent_request(fr_redis_handle_t *h)
{
	return h->req_sqn++;
}

/** Ignore a response with a specific sequence number
 *
 * @param[in] h		to ignore the response on.
 * @param[in] sqn	the command to ignore.
 */
static inline void fr_redis_connection_ignore_response(fr_redis_handle_t *h, fr_redis_sqn_t sqn)
{
	fr_redis_sqn_ignore_t *ignore;

	rad_assert(sqn <= h->rsp_sqn);

	MEM(ignore = talloc_zero(h, fr_redis_sqn_ignore_t));
	ignore->sqn = sqn;
	fr_dlist_insert_tail(&h->ignore, ignore);
}

/** Update the response sequence number and check if we should ignore the response
 *
 * *MUST* be called for every reply received using the handle. Relies on the fact
 * that responses from REDIS are FIFO with requests.
 *
 * @param[in] h		to check for ignored responses.
 */
static inline bool fr_redis_connection_process_response(fr_redis_handle_t *h)
{
	fr_redis_sqn_t		check = h->rsp_sqn++;
	fr_redis_sqn_ignore_t	*head;

	rad_assert(h->rsp_sqn <= h->req_sqn);		/* Can't have more responses than requests */

	head = fr_dlist_head(&h->ignore);
	if (!head || (head->sqn > check)) return true;	/* First response to ignore is some time after this one */
	rad_assert(head->sqn == check);

	fr_dlist_remove(&h->ignore, head);
	talloc_free(head);

	return false;
}

fr_connection_t		*fr_redis_connection_alloc(TALLOC_CTX *ctx, fr_event_list_t *el,
						   fr_connection_conf_t const *conn_conf,
						   fr_redis_io_conf_t const *io_conf,
						   char const *log_prefix);

redisAsyncContext	*fr_redis_connection_get_async_ctx(fr_connection_t *conn);

#ifdef __cplusplus
}
#endif
