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
 *
 * @file src/lib/server/trunk.c
 * @brief A management API for bonding multiple connections together.
 *
 * @copyright 2019-2020 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2019-2020 The FreeRADIUS server project
 */

#define LOG_PREFIX trunk->log_prefix

#ifdef NDEBUG
#  define TALLOC_GET_TYPE_ABORT_NOOP 1
#endif

typedef struct trunk_request_s trunk_request_t;
typedef struct trunk_connection_s trunk_connection_t;
typedef struct trunk_s trunk_t;
#define _TRUNK_PRIVATE 1
#include <freeradius-devel/server/trunk.h>

#include <freeradius-devel/server/trigger.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/util/minmax_heap.h>

#ifdef HAVE_STDATOMIC_H
#  include <stdatomic.h>
#  ifndef ATOMIC_VAR_INIT
#    define ATOMIC_VAR_INIT(_x) (_x)
#  endif
#else
#  include <freeradius-devel/util/stdatomic.h>
#endif

static atomic_uint_fast64_t request_counter = ATOMIC_VAR_INIT(1);

#ifdef TESTING_TRUNK
static fr_time_t test_time_base = fr_time_wrap(1);

static fr_time_t test_time(void)
{
	return test_time_base;
}

#define fr_time test_time
#endif

#ifndef NDEBUG
/** The maximum number of state logs to record per request
 *
 */
#define TRUNK_REQUEST_STATE_LOG_MAX	20

/** Trace state machine changes for a particular request
 *
 */
typedef struct {
	fr_dlist_head_t			*log_head;	//!< To allow the log entry to remove itself on free.
	fr_dlist_t			entry;		//!< Entry in the linked list.
	trunk_request_state_t	from;		//!< What state we transitioned from.
	trunk_request_state_t	to;		//!< What state we transitioned to.

	trunk_connection_t		*tconn;		//!< The request was associated with.
							///< Pointer may now be invalid, do no de-reference.

	uint64_t			tconn_id;	//!< If the treq was associated with a connection
							///< the connection ID.
	trunk_connection_state_t	tconn_state;	//!< If the treq was associated with a connection
							///< the connection state at the time of the
							///< state transition.

	char const		        *function;	//!< State change occurred in.
	int				line;		//!< Line change occurred on.
} trunk_request_state_log_t;
#endif

/** Wraps a normal request
 *
 */
struct trunk_request_s {
	struct trunk_request_pub_s	pub;		//!< Public fields in the trunk request.
							///< This *MUST* be the first field in this
							///< structure.

	uint64_t 		id;			//!< Trunk request ID.

	fr_heap_index_t		heap_id;		//!< Used to track the request conn->pending heap.

	fr_dlist_t		entry;			//!< Used to track the trunk request in the conn->sent
							///< or trunk->backlog request.

	trunk_cancel_reason_t cancel_reason;		//!< Why this request was cancelled.

	fr_time_t		last_freed;		//!< Last time this request was freed.

	bool			bound_to_conn;		//!< Fail the request if there's an attempt to
							///< re-enqueue it.

	bool			sent;			//!< Trunk request has been sent at least once.
							///< Used so that re-queueing doesn't increase trunk
							///< `sent` count.

#ifndef NDEBUG
	fr_dlist_head_t		log;			//!< State change log.
#endif
};


/** Associates request queues with a connection
 *
 * @dotfile src/lib/server/trunk_conn.gv "Trunk connection state machine"
 * @dotfile src/lib/server/trunk_req.gv "Trunk request state machine"
 */
struct trunk_connection_s {
	struct trunk_connection_pub_s pub;		//!< Public fields in the trunk connection.
							///< This *MUST* be the first field in this
							///< structure.

	fr_heap_index_t		heap_id;		//!< Used to track the connection in the connected
							///< heap.

	fr_dlist_t		entry;			//!< Used to track the connection in the connecting,
							///< full and failed lists.

	/** @name State
	 * @{
 	 */
	trunk_connection_event_t events;		//!< The current events we expect to be notified on.
	/** @} */

	/** @name Request lists
	 * @{
 	 */
	fr_heap_t		*pending;		//!< Requests waiting to be sent.

	trunk_request_t	*partial;		//!< Partially written request.

	fr_dlist_head_t		sent;			//!< Sent request.

	fr_dlist_head_t		reapable;			//!< Idle request.

	fr_dlist_head_t		cancel;			//!< Requests in the cancel state.

	trunk_request_t	*cancel_partial;	//!< Partially written cancellation request.

	fr_dlist_head_t		cancel_sent;		//!< Sent cancellation request.
	/** @} */

	/** @name Statistics
	 * @{
 	 */
 	uint64_t		sent_count;		//!< The number of requests that have been sent using
 							///< this connection.
 	/** @} */

	/** @name Timers
	 * @{
 	 */
  	fr_timer_t	*lifetime_ev;		//!< Maximum time this connection can be open.
  	/** @} */
};

/** An entry in a trunk watch function list
 *
 */
typedef struct trunk_watch_entry_s {
	fr_dlist_t		entry;			//!< List entry.
	trunk_watch_t	func;			//!< Function to call when a trunk enters
							///< the state this list belongs to
	bool			oneshot;		//!< Remove the function after it's called once.
	bool			enabled;		//!< Whether the watch entry is enabled.
	void			*uctx;			//!< User data to pass to the function.
} trunk_watch_entry_t;

/** Map connection states to trigger names
 *
 * Must stay in the same order as #trunk_connection_state_t
 */
static fr_table_num_indexed_bit_pos_t const trunk_conn_trigger_names[] = {
	{ L("pool.connection_halted"),			TRUNK_CONN_HALTED			},	/* 0x0000 - bit 0 */
	{ L("pool.connection_init"),			TRUNK_CONN_INIT				},	/* 0x0001 - bit 1 */
	{ L("pool.connection_connecting"),		TRUNK_CONN_CONNECTING			},	/* 0x0002 - bit 2 */
	{ L("pool.connection_active"),			TRUNK_CONN_ACTIVE			},	/* 0x0004 - bit 3 */
	{ L("pool.connection_closed"),			TRUNK_CONN_CLOSED			},	/* 0x0008 - bit 4 */
	{ L("pool.connection_full"),			TRUNK_CONN_FULL				},	/* 0x0010 - bit 5 */
	{ L("pool.connection_inactive"),		TRUNK_CONN_INACTIVE			},	/* 0x0020 - bit 6 */
	{ L("pool.connection_inactive_draining"),	TRUNK_CONN_INACTIVE_DRAINING		},	/* 0x0040 - bit 7 */
	{ L("pool.connection_draining"),		TRUNK_CONN_DRAINING			},	/* 0x0080 - bit 8 */
	{ L("pool.connection_draining_to_free"),	TRUNK_CONN_DRAINING_TO_FREE		}	/* 0x0100 - bit 9 */
};
static size_t trunk_conn_trigger_names_len = NUM_ELEMENTS(trunk_conn_trigger_names);

/** Main trunk management handle
 *
 */
struct trunk_s {
	struct trunk_pub_s	pub;			//!< Public fields in the trunk connection.
							///< This *MUST* be the first field in this
							///< structure.

	char const		*log_prefix;		//!< What to prepend to messages.

	fr_event_list_t		*el;			//!< Event list used by this trunk and the connection.

	trunk_conf_t		conf;			//!< Trunk common configuration.

	fr_dlist_head_t		free_requests;		//!< Requests in the unassigned state.  Waiting to be
							///< enqueued.

	fr_heap_t		*backlog;		//!< The request backlog.  Requests we couldn't
							///< immediately assign to a connection.

	/** @name Connection lists
	 *
	 * A connection must always be in exactly one of these lists
	 * or trees.
	 *
	 * @{
 	 */
 	fr_dlist_head_t		init;			//!< Connections which have not yet started
 							///< connecting.

 	fr_dlist_head_t		connecting;		//!< Connections which are not yet in the open state.

	fr_minmax_heap_t	*active;		//!< Connections which can service requests.

	fr_dlist_head_t		full;			//!< Connections which have too many outstanding
							///< requests.

	fr_dlist_head_t		inactive;		//!< Connections which have been signalled to be
							///< inactive by the API client.

	fr_dlist_head_t		inactive_draining;	//!< Connections which have been signalled to be
							///< inactive by the API client, which the trunk
							///< manager is draining to close.

	fr_dlist_head_t		failed;			//!< Connections that'll be reconnected shortly.

	fr_dlist_head_t		closed;			//!< Connections that have closed. Either due to
							///< shutdown, reconnection or failure.

	fr_dlist_head_t		draining;		//!< Connections that will be freed once all their
							///< requests are complete, but can be reactivated.

	fr_dlist_head_t		draining_to_free;	//!< Connections that will be freed once all their
							///< requests are complete.

	fr_dlist_head_t		to_free;		//!< Connections we're done with and will free on
							//!< the next call to trunk_manage.
							//!< This prevents connections from being freed
							//!< whilst we're inside callbacks.
	/** @} */

	/** @name Callbacks
	 * @{
 	 */
	trunk_io_funcs_t	funcs;			//!< I/O functions.

	void			*in_handler;		//!< Which handler we're inside.

	void			*uctx;			//!< Uctx data to pass to alloc.

	fr_dlist_head_t		watch[TRUNK_STATE_MAX];	//!< To be called when trunk changes state.

	trunk_watch_entry_t	*next_watcher;		//!< Watcher about to be run. Used to prevent nested watchers.
	/** @} */

	/** @name Timers
	 * @{
 	 */
 	fr_timer_t		*manage_ev;		//!< Periodic connection management event.
	/** @} */

	/** @name Log rate limiting entries
	 * @{
 	 */
	fr_rate_limit_t		limit_max_requests_alloc_log;	//!< Rate limit on "Refusing to alloc requests - Limit of * requests reached"

	fr_rate_limit_t		limit_last_failure_log;	//!< Rate limit on "Refusing to enqueue requests - No active conns"
 	/** @} */

	/** @name State
	 * @{
 	 */
	bool			freeing;		//!< Trunk is being freed, don't spawn new
							///< connections or re-enqueue.

	bool			started;		//!< Has the trunk been started.

	bool			managing_connections;	//!< Whether the trunk is allowed to manage
							///< (open/close) connections.

	uint64_t		last_req_per_conn;	//!< The last request to connection ratio we calculated.
	/** @} */

	fr_pair_list_t		*trigger_args;		//!< Passed to trigger

	bool			trigger_undef[NUM_ELEMENTS(trunk_conn_trigger_names)];	//!< Record that a specific trigger is undefined.

	CONF_PAIR		*trigger_cp[NUM_ELEMENTS(trunk_conn_trigger_names)];	//!< Cached trigger CONF_PAIRs
};

int trunk_trigger_cf_parse(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, conf_parser_t const *rule);

static conf_parser_t const trunk_config_request[] = {
	{ FR_CONF_OFFSET("per_connection_max", trunk_conf_t, max_req_per_conn), .dflt = "2000" },
	{ FR_CONF_OFFSET("per_connection_target", trunk_conf_t, target_req_per_conn), .dflt = "1000" },
	{ FR_CONF_OFFSET("free_delay", trunk_conf_t, req_cleanup_delay), .dflt = "10.0" },
	{ FR_CONF_OFFSET("triggers", trunk_conf_t, req_triggers), .func = trunk_trigger_cf_parse },

	CONF_PARSER_TERMINATOR
};

static conf_parser_t const trunk_config_connection[] = {
	{ FR_CONF_OFFSET("connect_timeout", connection_conf_t, connection_timeout), .dflt = "3.0" },
	{ FR_CONF_OFFSET("reconnect_delay", connection_conf_t, reconnection_delay), .dflt = "1" },

	CONF_PARSER_TERMINATOR
};

#ifndef TRUNK_TESTS
conf_parser_t const trunk_config[] = {
	{ FR_CONF_OFFSET("start", trunk_conf_t, start), .dflt = "1" },
	{ FR_CONF_OFFSET("min", trunk_conf_t, min), .dflt = "1" },
	{ FR_CONF_OFFSET("max", trunk_conf_t, max), .dflt = "5" },
	{ FR_CONF_OFFSET("connecting", trunk_conf_t, connecting), .dflt = "2" },
	{ FR_CONF_OFFSET("uses", trunk_conf_t, max_uses), .dflt = "0" },
	{ FR_CONF_OFFSET("lifetime", trunk_conf_t, lifetime), .dflt = "0" },
	{ FR_CONF_OFFSET("idle_timeout", trunk_conf_t, idle_timeout), .dflt = "0" },

	{ FR_CONF_OFFSET("open_delay", trunk_conf_t, open_delay), .dflt = "0.2" },
	{ FR_CONF_OFFSET("close_delay", trunk_conf_t, close_delay), .dflt = "10.0" },

	{ FR_CONF_OFFSET("manage_interval", trunk_conf_t, manage_interval), .dflt = "0.2" },

	{ FR_CONF_OFFSET("max_backlog", trunk_conf_t, max_backlog), .dflt = "1000" },

	{ FR_CONF_OFFSET("backlog_on_failed_conn", trunk_conf_t, backlog_on_failed_conn), },

	{ FR_CONF_OFFSET("triggers", trunk_conf_t, conn_triggers), .func = trunk_trigger_cf_parse },

	{ FR_CONF_OFFSET_SUBSECTION("connection", 0, trunk_conf_t, conn_conf, trunk_config_connection), .subcs_size = sizeof(trunk_config_connection) },
	{ FR_CONF_POINTER("request", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) trunk_config_request },

	CONF_PARSER_TERMINATOR
};
#endif

#ifndef NDEBUG
/** Map request states to trigger names
 *
 * Must stay in the same order as #trunk_connection_state_t
 */
static fr_table_num_indexed_bit_pos_t const trunk_req_trigger_names[] = {
	{ L("pool.request_init"),			TRUNK_REQUEST_STATE_INIT		},	/* 0x0000 - bit 0 */
	{ L("pool.request_unassigned"),			TRUNK_REQUEST_STATE_UNASSIGNED		},	/* 0x0001 - bit 1 */
	{ L("pool.request_backlog"),			TRUNK_REQUEST_STATE_BACKLOG		},	/* 0x0002 - bit 2 */
	{ L("pool.request_pending"),			TRUNK_REQUEST_STATE_PENDING		},	/* 0x0004 - bit 3 */
	{ L("pool.request_partial"),			TRUNK_REQUEST_STATE_PARTIAL		},	/* 0x0008 - bit 4 */
	{ L("pool.request_sent"),			TRUNK_REQUEST_STATE_SENT		},	/* 0x0010 - bit 5 */
	{ L("pool.request_state_reapable"),		TRUNK_REQUEST_STATE_REAPABLE		},	/* 0x0020 - bit 6 */
	{ L("pool.request_complete"),			TRUNK_REQUEST_STATE_COMPLETE		},	/* 0x0040 - bit 7 */
	{ L("pool.request_state_failed"),		TRUNK_REQUEST_STATE_FAILED		},	/* 0x0080 - bit 8 */
	{ L("pool.request_state_cancel"),		TRUNK_REQUEST_STATE_CANCEL		},	/* 0x0100 - bit 9 */
	{ L("pool.request_state_cancel_sent"),		TRUNK_REQUEST_STATE_CANCEL_SENT		},	/* 0x0200 - bit 10 */
	{ L("pool.request_state_cancel_partial"),	TRUNK_REQUEST_STATE_CANCEL_PARTIAL	},	/* 0x0400 - bit 11 */
	{ L("pool.request_state_cancel_complete"),	TRUNK_REQUEST_STATE_CANCEL_COMPLETE	},	/* 0x0800 - bit 12 */
};
static size_t trunk_req_trigger_names_len = NUM_ELEMENTS(trunk_req_trigger_names);
#endif

static fr_table_num_ordered_t const trunk_request_states[] = {
	{ L("INIT"),					TRUNK_REQUEST_STATE_INIT		},
	{ L("UNASSIGNED"),				TRUNK_REQUEST_STATE_UNASSIGNED		},
	{ L("BACKLOG"),					TRUNK_REQUEST_STATE_BACKLOG		},
	{ L("PENDING"),					TRUNK_REQUEST_STATE_PENDING		},
	{ L("PARTIAL"),					TRUNK_REQUEST_STATE_PARTIAL		},
	{ L("SENT"),					TRUNK_REQUEST_STATE_SENT		},
	{ L("REAPABLE"),				TRUNK_REQUEST_STATE_REAPABLE		},
	{ L("COMPLETE"),				TRUNK_REQUEST_STATE_COMPLETE		},
	{ L("FAILED"),					TRUNK_REQUEST_STATE_FAILED		},
	{ L("CANCEL"),					TRUNK_REQUEST_STATE_CANCEL		},
	{ L("CANCEL-SENT"),				TRUNK_REQUEST_STATE_CANCEL_SENT		},
	{ L("CANCEL-PARTIAL"),				TRUNK_REQUEST_STATE_CANCEL_PARTIAL	},
	{ L("CANCEL-COMPLETE"),				TRUNK_REQUEST_STATE_CANCEL_COMPLETE	}
};
static size_t trunk_request_states_len = NUM_ELEMENTS(trunk_request_states);

static fr_table_num_ordered_t const trunk_states[] = {
	{ L("IDLE"),					TRUNK_STATE_IDLE			},
	{ L("ACTIVE"),					TRUNK_STATE_ACTIVE			},
	{ L("PENDING"),					TRUNK_STATE_PENDING			}
};
static size_t trunk_states_len = NUM_ELEMENTS(trunk_states);

static fr_table_num_ordered_t const trunk_connection_states[] = {
	{ L("INIT"),					TRUNK_CONN_INIT				},
	{ L("HALTED"),					TRUNK_CONN_HALTED			},
	{ L("CONNECTING"),				TRUNK_CONN_CONNECTING			},
	{ L("ACTIVE"),					TRUNK_CONN_ACTIVE			},
	{ L("CLOSED"),					TRUNK_CONN_CLOSED			},
	{ L("FULL"),					TRUNK_CONN_FULL				},
	{ L("INACTIVE"),				TRUNK_CONN_INACTIVE			},
	{ L("INACTIVE-DRAINING"),			TRUNK_CONN_INACTIVE_DRAINING		},
	{ L("DRAINING"),				TRUNK_CONN_DRAINING			},
	{ L("DRAINING-TO-FREE"),			TRUNK_CONN_DRAINING_TO_FREE		}
};
static size_t trunk_connection_states_len = NUM_ELEMENTS(trunk_connection_states);

static fr_table_num_ordered_t const trunk_cancellation_reasons[] = {
	{ L("TRUNK_CANCEL_REASON_NONE"),		TRUNK_CANCEL_REASON_NONE		},
	{ L("TRUNK_CANCEL_REASON_SIGNAL"),		TRUNK_CANCEL_REASON_SIGNAL		},
	{ L("TRUNK_CANCEL_REASON_MOVE"),		TRUNK_CANCEL_REASON_MOVE		},
	{ L("TRUNK_CANCEL_REASON_REQUEUE"),		TRUNK_CANCEL_REASON_REQUEUE		}
};
static size_t trunk_cancellation_reasons_len = NUM_ELEMENTS(trunk_cancellation_reasons);

static fr_table_num_ordered_t const trunk_connection_events[] = {
	{ L("TRUNK_CONN_EVENT_NONE"),		TRUNK_CONN_EVENT_NONE 		},
	{ L("TRUNK_CONN_EVENT_READ"),		TRUNK_CONN_EVENT_READ		},
	{ L("TRUNK_CONN_EVENT_WRITE"),		TRUNK_CONN_EVENT_WRITE		},
	{ L("TRUNK_CONN_EVENT_BOTH"),		TRUNK_CONN_EVENT_BOTH		},
};
static size_t trunk_connection_events_len = NUM_ELEMENTS(trunk_connection_events);

#define CONN_TRIGGER(_state) do { \
	uint8_t idx = fr_high_bit_pos(_state); \
	if (trunk->conf.conn_triggers && !trunk->trigger_undef[idx]) { \
		if (trigger(unlang_interpret_get_thread_default(), trunk->conf.conn_trigger_cs, \
			    &trunk->trigger_cp[idx], \
			    fr_table_str_by_value(trunk_conn_trigger_names, _state, \
						  "<INVALID>"), true, trunk->trigger_args) == -1) { \
			trunk->trigger_undef[idx] = true; \
		} \
	} \
} while (0)

#define CONN_STATE_TRANSITION(_new, _log) \
do { \
	_log("[%" PRIu64 "] Trunk connection changed state %s -> %s", \
	     tconn->pub.conn->id, \
	     fr_table_str_by_value(trunk_connection_states, tconn->pub.state, "<INVALID>"), \
	     fr_table_str_by_value(trunk_connection_states, _new, "<INVALID>")); \
	tconn->pub.state = _new; \
	CONN_TRIGGER(_new); \
	trunk_requests_per_connection(NULL, NULL, trunk, fr_time(), false); \
} while (0)

#define CONN_BAD_STATE_TRANSITION(_new) \
do { \
	if (!fr_cond_assert_msg(0, "[%" PRIu64 "] Trunk connection invalid transition %s -> %s", \
				tconn->pub.conn->id, \
				fr_table_str_by_value(trunk_connection_states, tconn->pub.state, "<INVALID>"),	\
				fr_table_str_by_value(trunk_connection_states, _new, "<INVALID>"))) return;	\
} while (0)

#ifndef NDEBUG
void trunk_request_state_log_entry_add(char const *function, int line,
				       trunk_request_t *treq, trunk_request_state_t new) CC_HINT(nonnull);

#define REQUEST_TRIGGER(_state) do { \
	if (trunk->conf.req_triggers) { \
		trigger(unlang_interpret_get_thread_default(), \
			trunk->conf.req_trigger_cs, NULL, fr_table_str_by_value(trunk_req_trigger_names, _state, \
							 "<INVALID>"), true, trunk->trigger_args); \
	} \
} while (0)

/** Record a request state transition and log appropriate output
 *
 */
#define REQUEST_STATE_TRANSITION(_new) \
do { \
	request_t *request = treq->pub.request; \
	ROPTIONAL(RDEBUG3, DEBUG3, "Trunk request %" PRIu64 " changed state %s -> %s", \
		  treq->id, \
		  fr_table_str_by_value(trunk_request_states, treq->pub.state, "<INVALID>"), \
		  fr_table_str_by_value(trunk_request_states, _new, "<INVALID>")); \
	trunk_request_state_log_entry_add(__FUNCTION__, __LINE__, treq, _new); \
	treq->pub.state = _new; \
	REQUEST_TRIGGER(_new); \
} while (0)
#define REQUEST_BAD_STATE_TRANSITION(_new) \
do { \
	trunk_request_state_log(&default_log, L_ERR, __FILE__, __LINE__, treq); \
	if (!fr_cond_assert_msg(0, "Trunk request %" PRIu64 " invalid transition %s -> %s", \
				treq->id, \
				fr_table_str_by_value(trunk_request_states, treq->pub.state, "<INVALID>"), \
				fr_table_str_by_value(trunk_request_states, _new, "<INVALID>"))) return; \
} while (0)
#else
/** Record a request state transition
 *
 */
#define REQUEST_STATE_TRANSITION(_new) \
do { \
	request_t *request = treq->pub.request; \
	ROPTIONAL(RDEBUG3, DEBUG3, "Trunk request %" PRIu64 " changed state %s -> %s", \
		  treq->id, \
		  fr_table_str_by_value(trunk_request_states, treq->pub.state, "<INVALID>"), \
		  fr_table_str_by_value(trunk_request_states, _new, "<INVALID>")); \
	treq->pub.state = _new; \
} while (0)
#define REQUEST_BAD_STATE_TRANSITION(_new) \
do { \
	if (!fr_cond_assert_msg(0, "Trunk request %" PRIu64 " invalid transition %s -> %s", \
				treq->id, \
				fr_table_str_by_value(trunk_request_states, treq->pub.state, "<INVALID>"), \
				fr_table_str_by_value(trunk_request_states, _new, "<INVALID>"))) return; \
} while (0)
#endif


/** Call the cancel callback if set
 *
 */
#define DO_REQUEST_CANCEL(_treq, _reason) \
do { \
	if ((_treq)->pub.trunk->funcs.request_cancel) { \
		request_t *request = (_treq)->pub.request; \
		void *_prev = (_treq)->pub.trunk->in_handler; \
		(_treq)->pub.trunk->in_handler = (void *)(_treq)->pub.trunk->funcs.request_cancel; \
		ROPTIONAL(RDEBUG3, DEBUG3, "Calling request_cancel(conn=%p, preq=%p, reason=%s, uctx=%p)", \
			  (_treq)->pub.tconn->pub.conn, \
			  (_treq)->pub.preq, \
			  fr_table_str_by_value(trunk_cancellation_reasons, \
			  (_reason), \
			  "<INVALID>"), \
			  (_treq)->pub.trunk->uctx); \
		(_treq)->pub.trunk->funcs.request_cancel((_treq)->pub.tconn->pub.conn, (_treq)->pub.preq, (_reason), (_treq)->pub.trunk->uctx); \
		(_treq)->pub.trunk->in_handler = _prev; \
	} \
} while(0)

/** Call the "conn_release" callback (if set)
 *
 */
#define DO_REQUEST_CONN_RELEASE(_treq) \
do { \
	if ((_treq)->pub.trunk->funcs.request_conn_release) { \
		request_t *request = (_treq)->pub.request; \
		void *_prev = (_treq)->pub.trunk->in_handler; \
		(_treq)->pub.trunk->in_handler = (void *)(_treq)->pub.trunk->funcs.request_conn_release; \
		ROPTIONAL(RDEBUG3, DEBUG3, "Calling request_conn_release(conn=%p, preq=%p, uctx=%p)", \
			  (_treq)->pub.tconn->pub.conn, \
			  (_treq)->pub.preq, \
			  (_treq)->pub.trunk->uctx); \
		(_treq)->pub.trunk->funcs.request_conn_release((_treq)->pub.tconn->pub.conn, (_treq)->pub.preq, (_treq)->pub.trunk->uctx); \
		(_treq)->pub.trunk->in_handler = _prev; \
	} \
} while(0)

/** Call the complete callback (if set)
 *
 */
#define DO_REQUEST_COMPLETE(_treq) \
do { \
	if ((_treq)->pub.trunk->funcs.request_complete) { \
		request_t *request = (_treq)->pub.request; \
		void *_prev = (_treq)->pub.trunk->in_handler; \
		ROPTIONAL(RDEBUG3, DEBUG3, "Calling request_complete(request=%p, preq=%p, rctx=%p, uctx=%p)", \
			  (_treq)->pub.request, \
			  (_treq)->pub.preq, \
			  (_treq)->pub.rctx, \
			  (_treq)->pub.trunk->uctx); \
		(_treq)->pub.trunk->in_handler = (void *)(_treq)->pub.trunk->funcs.request_complete; \
		(_treq)->pub.trunk->funcs.request_complete((_treq)->pub.request, (_treq)->pub.preq, (_treq)->pub.rctx, (_treq)->pub.trunk->uctx); \
		(_treq)->pub.trunk->in_handler = _prev; \
	} \
} while(0)

/** Call the fail callback (if set)
 *
 */
#define DO_REQUEST_FAIL(_treq, _prev_state) \
do { \
	if ((_treq)->pub.trunk->funcs.request_fail) { \
		request_t *request = (_treq)->pub.request; \
		void *_prev = (_treq)->pub.trunk->in_handler; \
		ROPTIONAL(RDEBUG3, DEBUG3, "Calling request_fail(request=%p, preq=%p, rctx=%p, state=%s uctx=%p)", \
			  (_treq)->pub.request, \
			  (_treq)->pub.preq, \
			  (_treq)->pub.rctx, \
			  fr_table_str_by_value(trunk_request_states, (_prev_state), "<INVALID>"), \
			  (_treq)->pub.trunk->uctx); \
		(_treq)->pub.trunk->in_handler = (void *)(_treq)->pub.trunk->funcs.request_fail; \
		(_treq)->pub.trunk->funcs.request_fail((_treq)->pub.request, (_treq)->pub.preq, (_treq)->pub.rctx, _prev_state, (_treq)->pub.trunk->uctx); \
		(_treq)->pub.trunk->in_handler = _prev; \
	} \
} while(0)

/** Call the free callback (if set)
 *
 */
#define DO_REQUEST_FREE(_treq) \
do { \
	if ((_treq)->pub.trunk->funcs.request_free) { \
		request_t *request = (_treq)->pub.request; \
		void *_prev = (_treq)->pub.trunk->in_handler; \
		ROPTIONAL(RDEBUG3, DEBUG3, "Calling request_free(request=%p, preq=%p, uctx=%p)", \
			  (_treq)->pub.request, \
			  (_treq)->pub.preq, \
			  (_treq)->pub.trunk->uctx); \
		(_treq)->pub.trunk->in_handler = (void *)(_treq)->pub.trunk->funcs.request_free; \
		(_treq)->pub.trunk->funcs.request_free((_treq)->pub.request, (_treq)->pub.preq, (_treq)->pub.trunk->uctx); \
		(_treq)->pub.trunk->in_handler = _prev; \
	} \
} while(0)

/** Write one or more requests to a connection
 *
 */
#define DO_REQUEST_MUX(_tconn) \
do { \
	void *_prev = (_tconn)->pub.trunk->in_handler; \
	DEBUG3("[%" PRIu64 "] Calling request_mux(el=%p, tconn=%p, conn=%p, uctx=%p)", \
	       (_tconn)->pub.conn->id, \
	       (_tconn)->pub.trunk->el, \
	       (_tconn), \
	       (_tconn)->pub.conn, \
	       (_tconn)->pub.trunk->uctx); \
	(_tconn)->pub.trunk->in_handler = (void *)(_tconn)->pub.trunk->funcs.request_mux; \
	(_tconn)->pub.trunk->funcs.request_mux((_tconn)->pub.trunk->el, (_tconn), (_tconn)->pub.conn, (_tconn)->pub.trunk->uctx); \
	(_tconn)->pub.trunk->in_handler = _prev; \
} while(0)

/** Read one or more requests from a connection
 *
 */
#define DO_REQUEST_DEMUX(_tconn) \
do { \
	void *_prev = (_tconn)->pub.trunk->in_handler; \
	DEBUG3("[%" PRIu64 "] Calling request_demux(tconn=%p, conn=%p, uctx=%p)", \
	       (_tconn)->pub.conn->id, \
	       (_tconn), \
	       (_tconn)->pub.conn, \
	       (_tconn)->pub.trunk->uctx); \
	(_tconn)->pub.trunk->in_handler = (void *)(_tconn)->pub.trunk->funcs.request_demux; \
	(_tconn)->pub.trunk->funcs.request_demux((_tconn)->pub.trunk->el, (_tconn), (_tconn)->pub.conn, (_tconn)->pub.trunk->uctx); \
	(_tconn)->pub.trunk->in_handler = _prev; \
} while(0)

/** Write one or more cancellation requests to a connection
 *
 */
#define DO_REQUEST_CANCEL_MUX(_tconn) \
do { \
	if ((_tconn)->pub.trunk->funcs.request_cancel_mux) { \
		void *_prev = (_tconn)->pub.trunk->in_handler; \
		DEBUG3("[%" PRIu64 "] Calling request_cancel_mux(tconn=%p, conn=%p, uctx=%p)", \
		       (_tconn)->pub.conn->id, \
		       (_tconn), \
		       (_tconn)->pub.conn, \
		       (_tconn)->pub.trunk->uctx); \
		(_tconn)->pub.trunk->in_handler = (void *)(_tconn)->pub.trunk->funcs.request_cancel_mux; \
		(_tconn)->pub.trunk->funcs.request_cancel_mux((_tconn)->pub.trunk->el, (_tconn), (_tconn)->pub.conn, (_tconn)->pub.trunk->uctx); \
		(_tconn)->pub.trunk->in_handler = _prev; \
	} \
} while(0)

/** Allocate a new connection
 *
 */
#define DO_CONNECTION_ALLOC(_tconn) \
do { \
	void *_prev = trunk->in_handler; \
	DEBUG3("Calling connection_alloc(tconn=%p, el=%p, conf=%p, log_prefix=\"%s\", uctx=%p)", \
	       (_tconn), \
	       (_tconn)->pub.trunk->el, \
	       (_tconn)->pub.trunk->conf.conn_conf, \
	       trunk->log_prefix, \
	       (_tconn)->pub.trunk->uctx); \
	(_tconn)->pub.trunk->in_handler = (void *) (_tconn)->pub.trunk->funcs.connection_alloc; \
	(_tconn)->pub.conn = trunk->funcs.connection_alloc((_tconn), (_tconn)->pub.trunk->el, (_tconn)->pub.trunk->conf.conn_conf, (_tconn)->pub.trunk->log_prefix, trunk->uctx); \
	(_tconn)->pub.trunk->in_handler = _prev; \
	if (!(_tconn)->pub.conn) { \
		ERROR("Failed creating new connection"); \
		talloc_free(tconn); \
		return -1; \
	} \
} while(0)

/** Change what events the connection should be notified about
 *
 */
#define DO_CONNECTION_NOTIFY(_tconn, _events) \
do { \
	if ((_tconn)->pub.trunk->funcs.connection_notify) { \
		void *_prev = (_tconn)->pub.trunk->in_handler; \
		DEBUG3("[%" PRIu64 "] Calling connection_notify(tconn=%p, conn=%p, el=%p, events=%s, uctx=%p)", \
		       (_tconn)->pub.conn->id, \
		       (_tconn), \
		       (_tconn)->pub.conn, \
		       (_tconn)->pub.trunk->el, \
		       fr_table_str_by_value(trunk_connection_events, (_events), "<INVALID>"), \
		       (_tconn)->pub.trunk->uctx); \
		(_tconn)->pub.trunk->in_handler = (void *)(_tconn)->pub.trunk->funcs.connection_notify; \
		(_tconn)->pub.trunk->funcs.connection_notify((_tconn), (_tconn)->pub.conn, (_tconn)->pub.trunk->el, (_events), (_tconn)->pub.trunk->uctx); \
		(_tconn)->pub.trunk->in_handler = _prev; \
	} \
} while(0)

#define IN_HANDLER(_trunk)		(((_trunk)->in_handler) != NULL)
#define IN_REQUEST_MUX(_trunk)		(((_trunk)->funcs.request_mux) && ((_trunk)->in_handler == (void *)(_trunk)->funcs.request_mux))
#define IN_REQUEST_DEMUX(_trunk)	(((_trunk)->funcs.request_demux) && ((_trunk)->in_handler == (void *)(_trunk)->funcs.request_demux))
#define IN_REQUEST_CANCEL_MUX(_trunk)	(((_trunk)->funcs.request_cancel_mux) && ((_trunk)->in_handler == (void *)(_trunk)->funcs.request_cancel_mux))

#define IS_SERVICEABLE(_tconn)		((_tconn)->pub.state & TRUNK_CONN_SERVICEABLE)
#define IS_PROCESSING(_tconn)		((tconn)->pub.state & TRUNK_CONN_PROCESSING)

/** Remove the current request from the backlog
 *
 */
#define REQUEST_EXTRACT_BACKLOG(_treq) \
do { \
	int _ret; \
	_ret = fr_heap_extract(&(_treq)->pub.trunk->backlog, _treq); \
	if (!fr_cond_assert_msg(_ret == 0, "Failed extracting conn from backlog heap: %s", fr_strerror())) break; \
} while (0)

/** Remove the current request from the pending list
 *
 */
#define REQUEST_EXTRACT_PENDING(_treq) \
do { \
	int _ret; \
	_ret = fr_heap_extract(&(_treq)->pub.tconn->pending, _treq); \
	if (!fr_cond_assert_msg(_ret == 0, "Failed extracting conn from pending heap: %s", fr_strerror())) break; \
} while (0)

/** Remove the current request from the partial slot
 *
 */
#define REQUEST_EXTRACT_PARTIAL(_treq) \
do { \
	fr_assert((_treq)->pub.tconn->partial == treq); \
	tconn->partial = NULL; \
} while (0)

/** Remove the current request from the sent list
 *
 */
#define REQUEST_EXTRACT_SENT(_treq) fr_dlist_remove(&tconn->sent, treq)

/** Remove the current request from the reapable list
 *
 */
#define REQUEST_EXTRACT_REAPABLE(_treq) fr_dlist_remove(&tconn->reapable, treq)

/** Remove the current request from the cancel list
 *
 */
#define REQUEST_EXTRACT_CANCEL(_treq) fr_dlist_remove(&tconn->cancel, treq)

/** Remove the current request from the cancel_partial slot
 *
 */
#define REQUEST_EXTRACT_CANCEL_PARTIAL(_treq) \
do { \
	fr_assert((_treq)->pub.tconn->cancel_partial == treq); \
	tconn->cancel_partial = NULL; \
} while (0)

/** Remove the current request from the cancel sent list
 *
 */
#define REQUEST_EXTRACT_CANCEL_SENT(_treq) fr_dlist_remove(&tconn->cancel_sent, treq)

/** Reorder the connections in the active heap
 *
 * fr_heap_extract will also error out if heap_id is bad - no need for assert
 */
#define CONN_REORDER(_tconn) \
do { \
	int _ret; \
	if ((fr_minmax_heap_num_elements((_tconn)->pub.trunk->active) == 1)) break; \
	if (!fr_cond_assert((_tconn)->pub.state == TRUNK_CONN_ACTIVE)) break; \
	_ret = fr_minmax_heap_extract((_tconn)->pub.trunk->active, (_tconn)); \
	if (!fr_cond_assert_msg(_ret == 0, "Failed extracting conn from active heap: %s", fr_strerror())) break; \
	fr_minmax_heap_insert((_tconn)->pub.trunk->active, (_tconn)); \
} while (0)

/** Call a list of watch functions associated with a state
 *
 */
static inline void trunk_watch_call(trunk_t *trunk, fr_dlist_head_t *list, trunk_state_t state)
{
	/*
	 *	Nested watcher calls are not allowed
	 *	and shouldn't be possible because of
	 *	deferred signal processing.
	 */
	fr_assert(trunk->next_watcher == NULL);

	while ((trunk->next_watcher = fr_dlist_next(list, trunk->next_watcher))) {
		trunk_watch_entry_t	*entry = trunk->next_watcher;
		bool			oneshot = entry->oneshot;	/* Watcher could be freed, so store now */

		if (!entry->enabled) continue;
		if (oneshot) trunk->next_watcher = fr_dlist_remove(list, entry);

		entry->func(trunk, trunk->pub.state, state, entry->uctx);

		if (oneshot) talloc_free(entry);
	}
	trunk->next_watcher = NULL;
}

/** Call the state change watch functions
 *
 */
#define CALL_WATCHERS(_trunk, _state) \
do { \
	if (fr_dlist_empty(&(_trunk)->watch[_state])) break; \
	trunk_watch_call((_trunk), &(_trunk)->watch[_state], _state); \
} while(0)

/** Remove a watch function from a trunk state list
 *
 * @param[in] trunk	The trunk to remove the watcher from.
 * @param[in] state	to remove the watch from.
 * @param[in] watch	Function to remove.
 * @return
 *	- 0 if the function was removed successfully.
 *	- -1 if the function wasn't present in the watch list.
 *	- -2 if an invalid state was passed.
 */
int trunk_del_watch(trunk_t *trunk, trunk_state_t state, trunk_watch_t watch)
{
	trunk_watch_entry_t	*entry = NULL;
	fr_dlist_head_t	        *list;

	if (state >= TRUNK_STATE_MAX) return -2;

	list = &trunk->watch[state];
	while ((entry = fr_dlist_next(list, entry))) {
		if (entry->func == watch) {
			if (trunk->next_watcher == entry) {
				trunk->next_watcher = fr_dlist_remove(list, entry);
			} else {
				fr_dlist_remove(list, entry);
			}
			talloc_free(entry);
			return 0;
		}
	}

	return -1;
}

/** Add a watch entry to the trunk state list
 *
 * @param[in] trunk	The trunk to add the watcher to.
 * @param[in] state	to watch for.
 * @param[in] watch	Function to add.
 * @param[in] oneshot	Should this watcher only be run once.
 * @param[in] uctx	Context to pass to function.
 * @return
 *	- NULL if an invalid state is passed.
 *	- A new watch entry handle on success.
 */
trunk_watch_entry_t *trunk_add_watch(trunk_t *trunk, trunk_state_t state,
					   trunk_watch_t watch, bool oneshot, void const *uctx)
{
	trunk_watch_entry_t	*entry;
	fr_dlist_head_t		*list;

	if (state >= TRUNK_STATE_MAX) return NULL;

	list = &trunk->watch[state];
	MEM(entry = talloc_zero(trunk, trunk_watch_entry_t));

	entry->func = watch;
	entry->oneshot = oneshot;
	entry->enabled = true;
	memcpy(&entry->uctx, &uctx, sizeof(entry->uctx));
	fr_dlist_insert_tail(list, entry);

	return entry;
}

#define TRUNK_STATE_TRANSITION(_new) \
do { \
	DEBUG3("Trunk changed state %s -> %s", \
	       fr_table_str_by_value(trunk_states, trunk->pub.state, "<INVALID>"), \
	       fr_table_str_by_value(trunk_states, _new, "<INVALID>")); \
	CALL_WATCHERS(trunk, _new); \
	trunk->pub.state = _new; \
} while (0)

static void trunk_request_enter_backlog(trunk_request_t *treq, bool new);
static void trunk_request_enter_pending(trunk_request_t *treq, trunk_connection_t *tconn, bool new);
static void trunk_request_enter_partial(trunk_request_t *treq);
static void trunk_request_enter_sent(trunk_request_t *treq);
static void trunk_request_enter_reapable(trunk_request_t *treq);
static void trunk_request_enter_failed(trunk_request_t *treq);
static void trunk_request_enter_complete(trunk_request_t *treq);
static void trunk_request_enter_cancel(trunk_request_t *treq, trunk_cancel_reason_t reason);
static void trunk_request_enter_cancel_sent(trunk_request_t *treq);
static void trunk_request_enter_cancel_complete(trunk_request_t *treq);

static uint64_t trunk_requests_per_connection(uint16_t *conn_count_out, uint32_t *req_conn_out,
					      trunk_t *trunk, fr_time_t now, NDEBUG_UNUSED bool verify);

static int trunk_connection_spawn(trunk_t *trunk, fr_time_t now);
static inline void trunk_connection_auto_full(trunk_connection_t *tconn);
static inline void trunk_connection_auto_unfull(trunk_connection_t *tconn);
static inline void trunk_connection_readable(trunk_connection_t *tconn);
static inline void trunk_connection_writable(trunk_connection_t *tconn);
static void trunk_connection_event_update(trunk_connection_t *tconn);
static void trunk_connection_enter_full(trunk_connection_t *tconn);
static void trunk_connection_enter_inactive(trunk_connection_t *tconn);
static void trunk_connection_enter_inactive_draining(trunk_connection_t *tconn);
static void trunk_connection_enter_draining(trunk_connection_t *tconn);
static void trunk_connection_enter_draining_to_free(trunk_connection_t *tconn);
static void trunk_connection_enter_active(trunk_connection_t *tconn);

static void trunk_rebalance(trunk_t *trunk);
static void trunk_manage(trunk_t *trunk, fr_time_t now);
static void _trunk_timer(fr_timer_list_t *tl, fr_time_t now, void *uctx);
static void trunk_backlog_drain(trunk_t *trunk);

/** Compare two protocol requests
 *
 * Allows protocol requests to be prioritised with a function
 * specified by the API client.  Defaults to by pointer address
 * if no function is specified.
 *
 * @param[in] a	treq to compare to b.
 * @param[in] b treq to compare to a.
 * @return
 *	- +1 if a > b.
 *	- 0 if a == b.
 *	- -1 if a < b.
 */
static int8_t _trunk_request_prioritise(void const *a, void const *b)
{
	trunk_request_t const *treq_a = talloc_get_type_abort_const(a, trunk_request_t);
	trunk_request_t const *treq_b = talloc_get_type_abort_const(b, trunk_request_t);

	fr_assert(treq_a->pub.trunk == treq_b->pub.trunk);

	return treq_a->pub.trunk->funcs.request_prioritise(treq_a->pub.preq, treq_b->pub.preq);
}

/** Remove a request from all connection lists
 *
 * A common function used by init, fail, complete state functions to disassociate
 * a request from a connection in preparation for freeing or reassignment.
 *
 * Despite its unassuming name, this function is *the* place to put calls to
 * functions which need to be called when the number of requests associated with
 * a connection changes.
 *
 * Trunk requests will always be passed to this function before they're removed
 * from a connection, even if the requests are being freed.
 *
 * @param[in] treq	to trigger a state change for.
 */
static void trunk_request_remove_from_conn(trunk_request_t *treq)
{
	trunk_connection_t	*tconn = treq->pub.tconn;
	trunk_t		*trunk = treq->pub.trunk;

	if (!fr_cond_assert(!tconn || (tconn->pub.trunk == trunk))) return;

	switch (treq->pub.state) {
	case TRUNK_REQUEST_STATE_UNASSIGNED:
		return;	/* Not associated with connection */

	case TRUNK_REQUEST_STATE_PENDING:
		REQUEST_EXTRACT_PENDING(treq);
		break;

	case TRUNK_REQUEST_STATE_PARTIAL:
		REQUEST_EXTRACT_PARTIAL(treq);
		break;

	case TRUNK_REQUEST_STATE_SENT:
		REQUEST_EXTRACT_SENT(treq);
		break;

	case TRUNK_REQUEST_STATE_REAPABLE:
		REQUEST_EXTRACT_REAPABLE(treq);
		break;

	case TRUNK_REQUEST_STATE_CANCEL:
		REQUEST_EXTRACT_CANCEL(treq);
		break;

	case TRUNK_REQUEST_STATE_CANCEL_PARTIAL:
		REQUEST_EXTRACT_CANCEL_PARTIAL(treq);
		break;

	case TRUNK_REQUEST_STATE_CANCEL_SENT:
		REQUEST_EXTRACT_CANCEL_SENT(treq);
		break;

	default:
		fr_assert(0);
		break;
	}

	/*
	 *	If the request wasn't associated with a
	 *	connection, then there's nothing more
	 *	to do.
	 */
	if (!tconn) return;

	{
		request_t *request = treq->pub.request;

		ROPTIONAL(RDEBUG3, DEBUG3, "%s Trunk connection released request %" PRIu64,
			  tconn->pub.conn->name, treq->id);
	}
	/*
	 *	Release any connection specific resources the
	 *	treq holds.
	 */
	DO_REQUEST_CONN_RELEASE(treq);

	switch (tconn->pub.state){
	case TRUNK_CONN_FULL:
		trunk_connection_auto_unfull(tconn);		/* Check if we can switch back to active */
		if (tconn->pub.state == TRUNK_CONN_FULL) break;	/* Only fallthrough if conn is now active */
		FALL_THROUGH;

	case TRUNK_CONN_ACTIVE:
		CONN_REORDER(tconn);
		break;

	default:
		break;
	}

	treq->pub.tconn = NULL;

	/*
	 *	Request removed from the connection
	 *	see if we need up deregister I/O events.
	 */
	trunk_connection_event_update(tconn);
}

/** Transition a request to the unassigned state, in preparation for re-assignment
 *
 * @note treq->tconn may be inviable after calling
 *	if treq->conn and connection_signals_pause are not used.
 *	This is due to call to trunk_request_remove_from_conn.
 *
 * @param[in] treq	to trigger a state change for.
 */
static void trunk_request_enter_unassigned(trunk_request_t *treq)
{
	trunk_t		*trunk = treq->pub.trunk;

	switch (treq->pub.state) {
	case TRUNK_REQUEST_STATE_UNASSIGNED:
		return;

	case TRUNK_REQUEST_STATE_BACKLOG:
		REQUEST_EXTRACT_BACKLOG(treq);
		break;

	case TRUNK_REQUEST_STATE_PENDING:
	case TRUNK_REQUEST_STATE_CANCEL:
	case TRUNK_REQUEST_STATE_CANCEL_PARTIAL:
	case TRUNK_REQUEST_STATE_CANCEL_SENT:
		trunk_request_remove_from_conn(treq);
		break;

	default:
		REQUEST_BAD_STATE_TRANSITION(TRUNK_REQUEST_STATE_UNASSIGNED);
	}

	REQUEST_STATE_TRANSITION(TRUNK_REQUEST_STATE_UNASSIGNED);
}

/** Transition a request to the backlog state, adding it to the backlog of the trunk
 *
 * @note treq->tconn and treq may be inviable after calling
 *	if treq->conn and connection_signals_pause are not used.
 *	This is due to call to trunk_manage.
 *
 * @param[in] treq	to trigger a state change for.
 * @param[in] new	Whether this is a new request.
 */
static void trunk_request_enter_backlog(trunk_request_t *treq, bool new)
{
	trunk_connection_t	*tconn = treq->pub.tconn;
	trunk_t		*trunk = treq->pub.trunk;

	switch (treq->pub.state) {
	case TRUNK_REQUEST_STATE_INIT:
	case TRUNK_REQUEST_STATE_UNASSIGNED:
		break;

	case TRUNK_REQUEST_STATE_PENDING:
		REQUEST_EXTRACT_PENDING(treq);
		break;

	case TRUNK_REQUEST_STATE_CANCEL:
		REQUEST_EXTRACT_CANCEL(treq);
		break;

	default:
		REQUEST_BAD_STATE_TRANSITION(TRUNK_REQUEST_STATE_BACKLOG);
	}

	REQUEST_STATE_TRANSITION(TRUNK_REQUEST_STATE_BACKLOG);
	fr_heap_insert(&trunk->backlog, treq);	/* Insert into the backlog heap */

	/*
	 *	A new request has entered the trunk.
	 *	Re-calculate request/connection ratios.
	 */
	if (new) trunk_requests_per_connection(NULL, NULL, trunk, fr_time(), false);

	/*
	 *	To reduce latency, if there's no connections
	 *      in the connecting state, call the trunk manage
	 *	function immediately.
	 *
	 *	Likewise, if there's draining connections
	 *	which could be moved back to active call
	 *	the trunk manage function.
	 *
	 *	Remember requests only enter the backlog if
	 *	there's no connections which can service them.
	 */
	if ((trunk_connection_count_by_state(treq->pub.trunk, TRUNK_CONN_CONNECTING) == 0) ||
	    (trunk_connection_count_by_state(treq->pub.trunk, TRUNK_CONN_DRAINING) > 0)) {
		trunk_connection_manage_schedule(treq->pub.trunk);
	}
}

/** Transition a request to the pending state, adding it to the backlog of an active connection
 *
 * All trunk requests being added to a connection get passed to this function.
 * All trunk requests being removed from a connection get passed to #trunk_request_remove_from_conn.
 *
 * @note treq->tconn and treq may be inviable after calling
 *	if treq->conn and connection_signals_pause is not used.
 *	This is due to call to trunk_connection_event_update.
 *
 * @param[in] treq	to trigger a state change for.
 * @param[in] tconn	to enqueue the request on.
 * @param[in] new	Whether this is a new request.
 */
static void trunk_request_enter_pending(trunk_request_t *treq, trunk_connection_t *tconn, bool new)
{
	trunk_t		*trunk = treq->pub.trunk;

	fr_assert(tconn->pub.trunk == trunk);
	fr_assert(IS_PROCESSING(tconn));

	switch (treq->pub.state) {
	case TRUNK_REQUEST_STATE_INIT:
	case TRUNK_REQUEST_STATE_UNASSIGNED:
		fr_assert(!treq->pub.tconn);
		break;

	case TRUNK_REQUEST_STATE_BACKLOG:
		fr_assert(!treq->pub.tconn);
		REQUEST_EXTRACT_BACKLOG(treq);
		break;

	case TRUNK_REQUEST_STATE_CANCEL:	/* Moved from another connection */
		REQUEST_EXTRACT_CANCEL(treq);
		break;

	default:
		REQUEST_BAD_STATE_TRANSITION(TRUNK_REQUEST_STATE_PENDING);
	}

	/*
	 *	Assign the new connection first this first so
	 *      it appears in the state log.
	 */
	treq->pub.tconn = tconn;

	REQUEST_STATE_TRANSITION(TRUNK_REQUEST_STATE_PENDING);

	{
		request_t *request = treq->pub.request;

		ROPTIONAL(RDEBUG, DEBUG3, "%s Trunk connection assigned request %"PRIu64,
			  tconn->pub.conn->name, treq->id);
	}
	fr_heap_insert(&tconn->pending, treq);

	/*
	 *	A new request has entered the trunk.
	 *	Re-calculate request/connection ratios.
	 */
	if (new) trunk_requests_per_connection(NULL, NULL, trunk, fr_time(), false);

	/*
	 *	Check if we need to automatically transition the
	 *	connection to full.
	 */
	trunk_connection_auto_full(tconn);

	/*
	 *	Reorder the connection in the heap now it has an
	 *	additional request.
	 */
	if (tconn->pub.state == TRUNK_CONN_ACTIVE) CONN_REORDER(tconn);

	/*
	 *	We have a new request, see if we need to register
	 *	for I/O events.
	 */
	trunk_connection_event_update(tconn);
}

/** Transition a request to the partial state, indicating that is has been partially sent
 *
 * @param[in] treq	to trigger a state change for.
 */
static void trunk_request_enter_partial(trunk_request_t *treq)
{
	trunk_connection_t *tconn = treq->pub.tconn;
	trunk_t	*trunk = treq->pub.trunk;

	if (!fr_cond_assert(!tconn || (tconn->pub.trunk == trunk))) return;

	switch (treq->pub.state) {
	case TRUNK_REQUEST_STATE_PENDING:	/* All requests go through pending, even requeued ones */
		REQUEST_EXTRACT_PENDING(treq);
		break;

	default:
		REQUEST_BAD_STATE_TRANSITION(TRUNK_REQUEST_STATE_PARTIAL);
	}

	fr_assert(!tconn->partial);
	tconn->partial = treq;

	REQUEST_STATE_TRANSITION(TRUNK_REQUEST_STATE_PARTIAL);
}

/** Transition a request to the sent state, indicating that it's been sent in its entirety
 *
 * @note treq->tconn and treq may be inviable after calling
 *	if treq->conn and connection_signals_pause is not used.
 *	This is due to call to trunk_connection_event_update.
 *
 * @param[in] treq	to trigger a state change for.
 */
static void trunk_request_enter_sent(trunk_request_t *treq)
{
	trunk_connection_t	*tconn = treq->pub.tconn;
	trunk_t		*trunk = treq->pub.trunk;

	if (!fr_cond_assert(!tconn || (tconn->pub.trunk == trunk))) return;

	switch (treq->pub.state) {
	case TRUNK_REQUEST_STATE_PENDING:
		REQUEST_EXTRACT_PENDING(treq);
		break;

	case TRUNK_REQUEST_STATE_PARTIAL:
		REQUEST_EXTRACT_PARTIAL(treq);
		break;

	default:
		REQUEST_BAD_STATE_TRANSITION(TRUNK_REQUEST_STATE_SENT);
	}

	REQUEST_STATE_TRANSITION(TRUNK_REQUEST_STATE_SENT);
	fr_dlist_insert_tail(&tconn->sent, treq);

	/*
	 *	Update the connection's sent stats if this is the
	 *	first time this request is being sent.
	 */
	if (!treq->sent) {
		trunk->pub.last_write_success = fr_time();

		tconn->pub.last_write_success = trunk->pub.last_write_success;
		tconn->sent_count++;
		treq->sent = true;

		/*
		 *	Enforces max_uses
		 */
		if ((trunk->conf.max_uses > 0) && (tconn->sent_count >= trunk->conf.max_uses)) {
			DEBUG3("Trunk hit max uses %" PRIu64 " at %d", trunk->conf.max_uses, __LINE__);
			trunk_connection_enter_draining_to_free(tconn);
		}
	}

	/*
	 *	We just sent a request, we probably need
	 *	to tell the event loop we want to be
	 *	notified if there's data available.
	 */
	trunk_connection_event_update(tconn);
}

/** Transition a request to the reapable state, indicating that it's been sent in its entirety, but no response is expected
 *
 * @note Largely a replica of trunk_request_enter_sent.
 *
 * @param[in] treq	to trigger a state change for.
 */
static void trunk_request_enter_reapable(trunk_request_t *treq)
{
	trunk_connection_t	*tconn = treq->pub.tconn;
	trunk_t		*trunk = treq->pub.trunk;

	if (!fr_cond_assert(!tconn || (tconn->pub.trunk == trunk))) return;

	switch (treq->pub.state) {
	case TRUNK_REQUEST_STATE_PENDING:
		REQUEST_EXTRACT_PENDING(treq);
		break;

	case TRUNK_REQUEST_STATE_PARTIAL:
		REQUEST_EXTRACT_PARTIAL(treq);
		break;

	default:
		REQUEST_BAD_STATE_TRANSITION(TRUNK_REQUEST_STATE_SENT);
	}

	REQUEST_STATE_TRANSITION(TRUNK_REQUEST_STATE_REAPABLE);
	fr_dlist_insert_tail(&tconn->reapable, treq);

	if (!treq->sent) {
		tconn->sent_count++;
		treq->sent = true;

		if ((trunk->conf.max_uses > 0) && (tconn->sent_count >= trunk->conf.max_uses)) {
			DEBUG3("Trunk hit max uses %" PRIu64 " at %d", trunk->conf.max_uses, __LINE__);
			trunk_connection_enter_draining_to_free(tconn);
		}
	}

	trunk_connection_event_update(tconn);
}

/** Transition a request to the cancel state, placing it in a connection's cancellation list
 *
 * If a request_cancel_send callback is provided, that callback will
 * be called periodically for requests which were cancelled due to
 * a signal.
 *
 * The request_cancel_send callback will dequeue cancelled requests
 * and inform a remote server that the result is no longer required.
 *
 * A request must enter this state before being added to the backlog
 * of another connection if it's been sent or partially sent.
 *
 * @note treq->tconn and treq may be inviable after calling
 *	if treq->conn and connection_signals_pause is not used.
 *	This is due to call to trunk_connection_event_update.
 *
 * @param[in] treq	to trigger a state change for.
 * @param[in] reason	Why the request was cancelled.
 *			Should be one of:
 *			- TRUNK_CANCEL_REASON_SIGNAL request cancelled
 *			  because of a signal from the interpreter.
 *			- TRUNK_CANCEL_REASON_MOVE request cancelled
 *			  because the connection failed and it needs
 *			  to be assigned to a new connection.
 *			- TRUNK_CANCEL_REASON_REQUEUE request cancelled
 *			  as it needs to be resent on the same connection.
 */
static void trunk_request_enter_cancel(trunk_request_t *treq, trunk_cancel_reason_t reason)
{
	trunk_connection_t	*tconn = treq->pub.tconn;
	trunk_t		*trunk = treq->pub.trunk;

	if (!fr_cond_assert(!tconn || (tconn->pub.trunk == trunk))) return;

	switch (treq->pub.state) {
	case TRUNK_REQUEST_STATE_PARTIAL:
		REQUEST_EXTRACT_PARTIAL(treq);
		break;

	case TRUNK_REQUEST_STATE_SENT:
		REQUEST_EXTRACT_SENT(treq);
		break;

	case TRUNK_REQUEST_STATE_REAPABLE:
		REQUEST_EXTRACT_REAPABLE(treq);
		break;

	default:
		REQUEST_BAD_STATE_TRANSITION(TRUNK_REQUEST_STATE_CANCEL);
	}

	REQUEST_STATE_TRANSITION(TRUNK_REQUEST_STATE_CANCEL);
	fr_dlist_insert_tail(&tconn->cancel, treq);
	treq->cancel_reason = reason;

	DO_REQUEST_CANCEL(treq, reason);

	/*
	 *	Our treq is no longer bound to an actual
	 *      request_t *, as we can't guarantee the
	 *	lifetime of the original request_t *.
	 */
	if (treq->cancel_reason == TRUNK_CANCEL_REASON_SIGNAL) treq->pub.request = NULL;

	/*
	 *	Register for I/O write events if we need to.
	 */
	trunk_connection_event_update(treq->pub.tconn);
}

/** Transition a request to the cancel_partial state, placing it in a connection's cancel_partial slot
 *
 * The request_demux function is then responsible for signalling
 * that the cancel request is complete when the remote server
 * acknowledges the cancellation request.
 *
 * @param[in] treq	to trigger a state change for.
 */
static void trunk_request_enter_cancel_partial(trunk_request_t *treq)
{
	trunk_connection_t	*tconn = treq->pub.tconn;
	trunk_t		*trunk = treq->pub.trunk;

	if (!fr_cond_assert(!tconn || (tconn->pub.trunk == trunk))) return;
	fr_assert(trunk->funcs.request_cancel_mux);
	fr_assert(treq->cancel_reason == TRUNK_CANCEL_REASON_SIGNAL);

	switch (treq->pub.state) {
	case TRUNK_REQUEST_STATE_CANCEL:	/* The only valid state cancel_sent can be reached from */
		REQUEST_EXTRACT_CANCEL(treq);
		break;

	default:
		REQUEST_BAD_STATE_TRANSITION(TRUNK_REQUEST_STATE_CANCEL_PARTIAL);
	}

	REQUEST_STATE_TRANSITION(TRUNK_REQUEST_STATE_CANCEL_PARTIAL);
	fr_assert(!tconn->partial);
	tconn->cancel_partial = treq;
}

/** Transition a request to the cancel_sent state, placing it in a connection's cancel_sent list
 *
 * The request_demux function is then responsible for signalling
 * that the cancel request is complete when the remote server
 * acknowledges the cancellation request.
 *
 * @note treq->tconn and treq may be inviable after calling
 *	if treq->conn and connection_signals_pause is not used.
 *	This is due to call to trunk_connection_event_update.
 *
 * @param[in] treq	to trigger a state change for.
 */
static void trunk_request_enter_cancel_sent(trunk_request_t *treq)
{
	trunk_connection_t	*tconn = treq->pub.tconn;
	trunk_t		*trunk = treq->pub.trunk;

	if (!fr_cond_assert(!tconn || (tconn->pub.trunk == trunk))) return;
	fr_assert(trunk->funcs.request_cancel_mux);
	fr_assert(treq->cancel_reason == TRUNK_CANCEL_REASON_SIGNAL);

	switch (treq->pub.state) {
	case TRUNK_REQUEST_STATE_CANCEL_PARTIAL:
		REQUEST_EXTRACT_CANCEL_PARTIAL(treq);
		break;

	case TRUNK_REQUEST_STATE_CANCEL:
		REQUEST_EXTRACT_CANCEL(treq);
		break;

	default:
		REQUEST_BAD_STATE_TRANSITION(TRUNK_REQUEST_STATE_CANCEL_SENT);
	}

	REQUEST_STATE_TRANSITION(TRUNK_REQUEST_STATE_CANCEL_SENT);
	fr_dlist_insert_tail(&tconn->cancel_sent, treq);

	/*
	 *	De-register for I/O write events
	 *	and register the read events
	 *	to drain the cancel ACKs.
	 */
	trunk_connection_event_update(treq->pub.tconn);
}

/** Cancellation was acked, the request is complete, free it
 *
 * The API client will not be informed, as the original request_t *
 * will likely have been freed by this point.
 *
 * @note treq will be inviable after a call to this function.
 *      treq->tconn may be inviable after calling
 *	if treq->conn and connection_signals_pause is not used.
 *	This is due to call to trunk_request_remove_from_conn.
 *
 * @param[in] treq	to mark as complete.
 */
static void trunk_request_enter_cancel_complete(trunk_request_t *treq)
{
	trunk_connection_t	*tconn = treq->pub.tconn;
	trunk_t		*trunk = treq->pub.trunk;

	if (!fr_cond_assert(!tconn || (tconn->pub.trunk == trunk))) return;
	if (!fr_cond_assert(!treq->pub.request)) return;	/* Only a valid state for request_t * which have been cancelled */

	switch (treq->pub.state) {
	case TRUNK_REQUEST_STATE_CANCEL_SENT:
	case TRUNK_REQUEST_STATE_CANCEL:
		break;

	default:
		REQUEST_BAD_STATE_TRANSITION(TRUNK_REQUEST_STATE_CANCEL_COMPLETE);
	}

	trunk_request_remove_from_conn(treq);

	REQUEST_STATE_TRANSITION(TRUNK_REQUEST_STATE_CANCEL_COMPLETE);
	trunk_request_free(&treq);	/* Free the request */
}

/** Request completed successfully, inform the API client and free the request
 *
 * @note treq will be inviable after a call to this function.
 *	treq->tconn may also be inviable due to call to
 *	trunk_request_remove_from_conn.
 *
 * @param[in] treq	to mark as complete.
 */
static void trunk_request_enter_complete(trunk_request_t *treq)
{
	trunk_connection_t	*tconn = treq->pub.tconn;
	trunk_t		*trunk = treq->pub.trunk;

	if (!fr_cond_assert(!tconn || (tconn->pub.trunk == trunk))) return;

	switch (treq->pub.state) {
	case TRUNK_REQUEST_STATE_SENT:
	case TRUNK_REQUEST_STATE_PENDING:
	case TRUNK_REQUEST_STATE_REAPABLE:
		trunk_request_remove_from_conn(treq);
		break;

	default:
		REQUEST_BAD_STATE_TRANSITION(TRUNK_REQUEST_STATE_COMPLETE);
	}

	REQUEST_STATE_TRANSITION(TRUNK_REQUEST_STATE_COMPLETE);
	DO_REQUEST_COMPLETE(treq);
	trunk_request_free(&treq);	/* Free the request */
}

/** Request failed, inform the API client and free the request
 *
 * @note treq will be inviable after a call to this function.
 *	treq->tconn may also be inviable due to call to
 *	trunk_request_remove_from_conn.
 *
 * @param[in] treq	to mark as failed.
 */
static void trunk_request_enter_failed(trunk_request_t *treq)
{
	trunk_connection_t		*tconn = treq->pub.tconn;
	trunk_t			*trunk = treq->pub.trunk;
	trunk_request_state_t	prev = treq->pub.state;

	if (!fr_cond_assert(!tconn || (tconn->pub.trunk == trunk))) return;

	switch (treq->pub.state) {
	case TRUNK_REQUEST_STATE_BACKLOG:
		REQUEST_EXTRACT_BACKLOG(treq);
		break;

	default:
		trunk_request_remove_from_conn(treq);
		break;
	}

	REQUEST_STATE_TRANSITION(TRUNK_REQUEST_STATE_FAILED);
	DO_REQUEST_FAIL(treq, prev);
	trunk_request_free(&treq);	/* Free the request */
}

/** Check to see if a trunk request can be enqueued
 *
 * @param[out] tconn_out	Connection the request may be enqueued on.
 * @param[in] trunk		To enqueue requests on.
 * @param[in] request		associated with the treq (if any).
 * @return
 *	- TRUNK_ENQUEUE_OK			caller should enqueue request on provided tconn.
 *	- TRUNK_ENQUEUE_IN_BACKLOG		Request should be queued in the backlog.
 *	- TRUNK_ENQUEUE_NO_CAPACITY		Unable to enqueue request as we have no spare
 *						connections or backlog space.
 *	- TRUNK_ENQUEUE_DST_UNAVAILABLE	Can't enqueue because the destination is
 *						unreachable.
 */
static trunk_enqueue_t trunk_request_check_enqueue(trunk_connection_t **tconn_out, trunk_t *trunk,
						      request_t *request)
{
	trunk_connection_t	*tconn;
	/*
	 *	If we have an active connection then
	 *	return that.
	 */
	tconn = fr_minmax_heap_min_peek(trunk->active);
	if (tconn) {
		*tconn_out = tconn;
		return TRUNK_ENQUEUE_OK;
	}

	/*
	 *	Unlike the connection pool, we don't need
	 *	to drive any internal processes by feeding
	 *	it requests.
	 *
	 *	If the last event to occur was a failure
	 *	we refuse to enqueue new requests until
	 *	one or more connections comes online.
	 */
	if (!trunk->conf.backlog_on_failed_conn &&
	    fr_time_gt(trunk->pub.last_failed, fr_time_wrap(0)) &&
	    fr_time_lt(trunk->pub.last_connected, trunk->pub.last_failed)) {
	    	RATE_LIMIT_LOCAL_ROPTIONAL(&trunk->limit_last_failure_log,
					   RWARN, WARN, "Refusing to enqueue requests - "
					   "No active connections and last event was a connection failure");

		return TRUNK_ENQUEUE_DST_UNAVAILABLE;
	}


	/*
	 *	Only enforce if we're limiting maximum
	 *	number of connections, and maximum
	 *	number of requests per connection.
	 *
	 *	The alloc function also checks this
	 *	which is why this is only done for
	 *	debug builds.
	 */
	if (trunk->conf.max_req_per_conn && trunk->conf.max) {
		uint64_t	limit;

		limit = trunk->conf.max * (uint64_t)trunk->conf.max_req_per_conn;
		if (limit > 0) {
			uint64_t	total_reqs;

			total_reqs = trunk_request_count_by_state(trunk, TRUNK_CONN_ALL,
								     TRUNK_REQUEST_STATE_ALL);
			if (total_reqs >= (limit + trunk->conf.max_backlog)) {
				RATE_LIMIT_LOCAL_ROPTIONAL(&trunk->limit_max_requests_alloc_log,
							   RWARN, WARN, "Refusing to alloc requests - "
							   "Limit of %"PRIu64" (max = %u * per_connection_max = %u) "
							   "plus %u backlog requests reached",
							   limit, trunk->conf.max, trunk->conf.max_req_per_conn,
							   trunk->conf.max_backlog);
				return TRUNK_ENQUEUE_NO_CAPACITY;
			}
		}
	}

	return TRUNK_ENQUEUE_IN_BACKLOG;
}

/** Enqueue a request which has never been assigned to a connection or was previously cancelled
 *
 * @param[in] treq	to re enqueue.  Must have been removed
 *			from its existing connection with
 *			#trunk_connection_requests_dequeue.
 * @return
 *	- TRUNK_ENQUEUE_OK			Request was re-enqueued.
 *	- TRUNK_ENQUEUE_NO_CAPACITY		Request enqueueing failed because we're at capacity.
 *	- TRUNK_ENQUEUE_DST_UNAVAILABLE	Enqueuing failed for some reason.
 *      					Usually because the connection to the resource is down.
 */
static trunk_enqueue_t trunk_request_enqueue_existing(trunk_request_t *treq)
{
	trunk_t		*trunk = treq->pub.trunk;
	trunk_connection_t	*tconn = NULL;
	trunk_enqueue_t	ret;

	/*
	 *	Must *NOT* still be assigned to another connection
	 */
	fr_assert(!treq->pub.tconn);

	ret = trunk_request_check_enqueue(&tconn, trunk, treq->pub.request);
	switch (ret) {
	case TRUNK_ENQUEUE_OK:
		if (trunk->conf.always_writable) {
			connection_signals_pause(tconn->pub.conn);
			trunk_request_enter_pending(treq, tconn, false);
			trunk_connection_writable(tconn);
			connection_signals_resume(tconn->pub.conn);
		} else {
			trunk_request_enter_pending(treq, tconn, false);
		}
		break;

	case TRUNK_ENQUEUE_IN_BACKLOG:
		/*
		 *	No more connections and request
		 *	is already in the backlog.
		 *
		 *	Signal our caller it should stop
		 *	trying to drain the backlog.
		 */
		if (treq->pub.state == TRUNK_REQUEST_STATE_BACKLOG) return TRUNK_ENQUEUE_NO_CAPACITY;
		trunk_request_enter_backlog(treq, false);
		break;

	default:
		break;
	}

	return ret;
}

/** Shift requests in the specified states onto new connections
 *
 * This function will blindly dequeue any requests in the specified state and get
 * them back to the unassigned state, cancelling any sent or partially sent requests.
 *
 * This function does not check that dequeuing a request in a particular state is a
 * sane or sensible thing to do, that's up to the caller!
 *
 * @param[out] out	A list to insert the newly dequeued and unassigned
 *			requests into.
 * @param[in] tconn	to dequeue requests from.
 * @param[in] states	Dequeue request in these states.
 * @param[in] max	The maximum number of requests to dequeue. 0 for unlimited.
 */
static uint64_t trunk_connection_requests_dequeue(fr_dlist_head_t *out, trunk_connection_t *tconn,
						  int states, uint64_t max)
{
	trunk_request_t	*treq;
	uint64_t		count = 0;

	if (max == 0) max = UINT64_MAX;

#define OVER_MAX_CHECK if (++count > max) return (count - 1)

#define DEQUEUE_ALL(_src_list, _state) do { \
	while ((treq = fr_dlist_head(_src_list))) { \
		OVER_MAX_CHECK; \
		fr_assert(treq->pub.state == (_state)); \
		trunk_request_enter_unassigned(treq); \
		fr_dlist_insert_tail(out, treq); \
	} } while (0)

	/*
	 *	Don't need to do anything with
	 *	cancellation requests.
	 */
	if (states & TRUNK_REQUEST_STATE_CANCEL) DEQUEUE_ALL(&tconn->cancel,
								TRUNK_REQUEST_STATE_CANCEL);

	/*
	 *	...same with cancel inform
	 */
	if (states & TRUNK_REQUEST_STATE_CANCEL_SENT) DEQUEUE_ALL(&tconn->cancel_sent,
								     TRUNK_REQUEST_STATE_CANCEL_SENT);

	/*
	 *	....same with cancel partial
	 */
	if (states & TRUNK_REQUEST_STATE_CANCEL_PARTIAL) {
		OVER_MAX_CHECK;
		treq = tconn->cancel_partial;
		if (treq) {
			fr_assert(treq->pub.state == TRUNK_REQUEST_STATE_CANCEL_PARTIAL);
			trunk_request_enter_unassigned(treq);
			fr_dlist_insert_tail(out, treq);
		}
	}

	/*
	 *	...and pending.
	 */
	if (states & TRUNK_REQUEST_STATE_PENDING) {
		while ((treq = fr_heap_peek(tconn->pending))) {
			OVER_MAX_CHECK;
			fr_assert(treq->pub.state == TRUNK_REQUEST_STATE_PENDING);
			trunk_request_enter_unassigned(treq);
			fr_dlist_insert_tail(out, treq);
		}
	}

	/*
	 *	Cancel partially sent requests
	 */
	if (states & TRUNK_REQUEST_STATE_PARTIAL) {
		OVER_MAX_CHECK;
		treq = tconn->partial;
		if (treq) {
			fr_assert(treq->pub.state == TRUNK_REQUEST_STATE_PARTIAL);

			/*
			 *	Don't allow the connection to change state whilst
			 *	we're draining requests from it.
			 */
			connection_signals_pause(tconn->pub.conn);
			trunk_request_enter_cancel(treq, TRUNK_CANCEL_REASON_MOVE);
			trunk_request_enter_unassigned(treq);
			fr_dlist_insert_tail(out, treq);
			connection_signals_resume(tconn->pub.conn);
		}
	}

	/*
	 *	Cancel sent requests
	 */
	if (states & TRUNK_REQUEST_STATE_SENT) {
		/*
		 *	Don't allow the connection to change state whilst
		 *	we're draining requests from it.
		 */
		connection_signals_pause(tconn->pub.conn);
		while ((treq = fr_dlist_head(&tconn->sent))) {
			OVER_MAX_CHECK;
			fr_assert(treq->pub.state == TRUNK_REQUEST_STATE_SENT);

			trunk_request_enter_cancel(treq, TRUNK_CANCEL_REASON_MOVE);
			trunk_request_enter_unassigned(treq);
			fr_dlist_insert_tail(out, treq);
		}
		connection_signals_resume(tconn->pub.conn);
	}

	return count;
}

/** Remove requests in specified states from a connection, attempting to distribute them to new connections
 *
 * @param[in] tconn		To remove requests from.
 * @param[in] states		One or more states or'd together.
 * @param[in] max		The maximum number of requests to dequeue.
 *				0 for unlimited.
 * @param[in] fail_bound	If true causes any requests bound to the connection to fail.
 *      			If false bound requests will not be moved.
 *
 * @return the number of requests re-queued.
 */
static uint64_t trunk_connection_requests_requeue_priv(trunk_connection_t *tconn, int states, uint64_t max, bool fail_bound)
{
	trunk_t			*trunk = tconn->pub.trunk;
	fr_dlist_head_t			to_process;
	trunk_request_t		*treq = NULL;
	uint64_t			moved = 0;

	if (max == 0) max = UINT64_MAX;

	fr_dlist_talloc_init(&to_process, trunk_request_t, entry);

	/*
	 *	Prevent the connection changing state whilst we're
	 *	working with it.
	 *
	 *	There's a user callback that can be called by
	 *	trunk_request_enqueue_existing which can reconnect
	 *	the connection.
	 */
	connection_signals_pause(tconn->pub.conn);

	/*
	 *	Remove non-cancelled requests from the connection
	 */
	moved += trunk_connection_requests_dequeue(&to_process, tconn, states & ~TRUNK_REQUEST_STATE_CANCEL_ALL, max);

	/*
	 *	Prevent requests being requeued on the same trunk
	 *	connection, which would break rebalancing.
	 *
	 *	This is a bit of a hack, but nothing should test
	 *	for connection/list consistency in this code,
	 *      and if something is added later, it'll be flagged
	 *	by the tests.
	 */
	if (tconn->pub.state == TRUNK_CONN_ACTIVE) {
		int ret;

		ret = fr_minmax_heap_extract(trunk->active, tconn);
		if (!fr_cond_assert_msg(ret == 0,
					"Failed extracting conn from active heap: %s", fr_strerror())) goto done;

	}

	/*
	 *	Loop over all the requests we gathered and
	 *	redistribute them to new connections.
	 */
	while ((treq = fr_dlist_next(&to_process, treq))) {
		trunk_request_t *prev;

		prev = fr_dlist_remove(&to_process, treq);

		/*
		 *	Attempts to re-queue a request
		 *	that's bound to a connection
		 *	results in a failure.
		 */
		if (treq->bound_to_conn) {
			if (fail_bound || !IS_SERVICEABLE(tconn)) {
				trunk_request_enter_failed(treq);
			} else {
				trunk_request_enter_pending(treq, tconn, false);
			}
			goto next;
		}

		switch (trunk_request_enqueue_existing(treq)) {
		case TRUNK_ENQUEUE_OK:
			break;

		/*
		 *	A connection failed, and
		 *	there's no other connections
		 *	available to deal with the
		 *	load, it's been placed back
		 *	in the backlog.
		 */
		case TRUNK_ENQUEUE_IN_BACKLOG:
			break;

		/*
		 *	If we fail to re-enqueue then
		 *	there's nothing to do except
		 *	fail the request.
		 */
		case TRUNK_ENQUEUE_DST_UNAVAILABLE:
		case TRUNK_ENQUEUE_NO_CAPACITY:
		case TRUNK_ENQUEUE_FAIL:
			trunk_request_enter_failed(treq);
			break;
		}
	next:
		treq = prev;
	}

	/*
	 *	Add the connection back into the active list
	 */
	if (tconn->pub.state == TRUNK_CONN_ACTIVE) {
		int ret;

		ret = fr_minmax_heap_insert(trunk->active, tconn);
		if (!fr_cond_assert_msg(ret == 0,
				        "Failed re-inserting conn into active heap: %s", fr_strerror())) goto done;
	}
	if (moved >= max) goto done;

	/*
	 *	Deal with the cancelled requests specially we can't
	 *      queue them up again as they were only valid on that
	 *	specific connection.
	 *
	 *	We just need to run them to completion which, as
	 *	they should already be in the unassigned state,
	 *	just means freeing them.
	 */
	moved += trunk_connection_requests_dequeue(&to_process, tconn,
						   states & TRUNK_REQUEST_STATE_CANCEL_ALL, max - moved);
	while ((treq = fr_dlist_next(&to_process, treq))) {
		trunk_request_t *prev;

		prev = fr_dlist_remove(&to_process, treq);
		trunk_request_free(&treq);
		treq = prev;
	}

done:

	/*
	 *	Always re-calculate the request/connection
	 *	ratio at the end.
	 *
	 *	This avoids having the state transition
	 *	functions do it.
	 *
	 *	The ratio would be wrong when they calculated
	 *	it anyway, because a bunch of requests are
	 *	dequeued from the connection and temporarily
	 *	cease to exist from the perspective of the
	 *	trunk_requests_per_connection code.
	 */
	trunk_requests_per_connection(NULL, NULL, trunk, fr_time(), false);

	connection_signals_resume(tconn->pub.conn);
	return moved;
}

/** Move requests off of a connection and requeue elsewhere
 *
 * @note We don't re-queue on draining or draining to free, as requests should have already been
 *	 moved off of the connection.  It's also dangerous as the trunk management code main
 *	 clean up a connection in this state when it's run on re-queue, and then the caller
 *	 may try and access a now freed connection.
 *
 * @param[in] tconn		to move requests off of.
 * @param[in] states		Only move requests in this state.
 * @param[in] max		The maximum number of requests to dequeue. 0 for unlimited.
 * @param[in] fail_bound	If true causes any requests bound to the connection to fail.
 *      			If false bound requests will not be moved.
 * @return The number of requests requeued.
 */
uint64_t trunk_connection_requests_requeue(trunk_connection_t *tconn, int states, uint64_t max, bool fail_bound)
{
	switch (tconn->pub.state) {
	case TRUNK_CONN_ACTIVE:
	case TRUNK_CONN_FULL:
	case TRUNK_CONN_INACTIVE:
		return trunk_connection_requests_requeue_priv(tconn, states, max, fail_bound);

	default:
		return 0;
	}
}

/** Signal a partial write
 *
 * Where there's high load, and the outbound write buffer is full
 *
 * @param[in] treq	to signal state change for.
 */
void trunk_request_signal_partial(trunk_request_t *treq)
{
	if (!fr_cond_assert_msg(treq->pub.trunk, "treq not associated with trunk")) return;

	if (!fr_cond_assert_msg(IN_REQUEST_MUX(treq->pub.trunk),
				"%s can only be called from within request_mux handler", __FUNCTION__)) return;

	switch (treq->pub.state) {
	case TRUNK_REQUEST_STATE_PENDING:
		trunk_request_enter_partial(treq);
		break;

	default:
		return;
	}
}

/** Signal that the request was written to a connection successfully
 *
 * @param[in] treq	to signal state change for.
 */
void trunk_request_signal_sent(trunk_request_t *treq)
{
	if (!fr_cond_assert_msg(treq->pub.trunk, "treq not associated with trunk")) return;

	if (!fr_cond_assert_msg(IN_REQUEST_MUX(treq->pub.trunk),
				"%s can only be called from within request_mux handler", __FUNCTION__)) return;

	switch (treq->pub.state) {
	case TRUNK_REQUEST_STATE_PENDING:
	case TRUNK_REQUEST_STATE_PARTIAL:
		trunk_request_enter_sent(treq);
		break;

	default:
		return;
	}
}

/** Signal that the request was written to a connection successfully, but no response is expected
 *
 * @param[in] treq	to signal state change for.
 */
void trunk_request_signal_reapable(trunk_request_t *treq)
{
	if (!fr_cond_assert_msg(treq->pub.trunk, "treq not associated with trunk")) return;

	if (!fr_cond_assert_msg(IN_REQUEST_MUX(treq->pub.trunk),
				"%s can only be called from within request_mux handler", __FUNCTION__)) return;

	switch (treq->pub.state) {
	case TRUNK_REQUEST_STATE_PENDING:
	case TRUNK_REQUEST_STATE_PARTIAL:
		trunk_request_enter_reapable(treq);
		break;

	default:
		return;
	}
}

/** Signal that a trunk request is complete
 *
 * The API client will be informed that the request is now complete.
 */
void trunk_request_signal_complete(trunk_request_t *treq)
{
	trunk_t *trunk = treq->pub.trunk;

	if (!fr_cond_assert_msg(trunk, "treq not associated with trunk")) return;

	/*
	 *	We assume that if the request is being signalled
	 *	as complete from the demux function, that it was
	 *	a successful read.
	 *
	 *	If this assumption turns out to be incorrect
	 *	then we need to add an argument to signal_complete
	 *	to indicate if this is a successful read.
	 */
	if (IN_REQUEST_DEMUX(trunk)) {
		trunk_connection_t *tconn = treq->pub.tconn;

		trunk->pub.last_read_success = fr_time();
		tconn->pub.last_read_success = trunk->pub.last_read_success;
	}

	switch (treq->pub.state) {
	case TRUNK_REQUEST_STATE_SENT:
	case TRUNK_REQUEST_STATE_PENDING:	/* Got immediate response, i.e. cached */
	case TRUNK_REQUEST_STATE_REAPABLE:
		trunk_request_enter_complete(treq);
		break;

	default:
		return;
	}
}

/** Signal that a trunk request failed
 *
 * The API client will be informed that the request has failed.
 */
void trunk_request_signal_fail(trunk_request_t *treq)
{
	if (!fr_cond_assert_msg(treq->pub.trunk, "treq not associated with trunk")) return;

	trunk_request_enter_failed(treq);
}

/** Cancel a trunk request
 *
 * treq can be in any state, but requests to cancel if the treq is not in
 * the TRUNK_REQUEST_STATE_PARTIAL or TRUNK_REQUEST_STATE_SENT state will be ignored.
 *
 * The complete or failed callbacks will not be called here, as it's assumed the request_t *
 * is now inviable as it's being cancelled.
 *
 * The free function however, is called, and that should be used to perform necessary
 * cleanup.
 *
 * @param[in] treq	to signal state change for.
 */
void trunk_request_signal_cancel(trunk_request_t *treq)
{
	trunk_t	*trunk;

	/*
	 *	Ensure treq hasn't been freed
	 */
	(void)talloc_get_type_abort(treq, trunk_request_t);

	if (!fr_cond_assert_msg(treq->pub.trunk, "treq not associated with trunk")) return;

	if (!fr_cond_assert_msg(!IN_HANDLER(treq->pub.trunk),
				"%s cannot be called within a handler", __FUNCTION__)) return;

 	trunk = treq->pub.trunk;

	switch (treq->pub.state) {
	/*
	 *	We don't call the complete or failed callbacks
	 *	as the request and rctx are no longer viable.
	 */
	case TRUNK_REQUEST_STATE_PARTIAL:
	case TRUNK_REQUEST_STATE_SENT:
	{
		trunk_connection_t *tconn = treq->pub.tconn;

		/*
		 *	Don't allow connection state changes
		 */
		connection_signals_pause(tconn->pub.conn);
		trunk_request_enter_cancel(treq, TRUNK_CANCEL_REASON_SIGNAL);
		if (!fr_cond_assert_msg(treq->pub.state == TRUNK_REQUEST_STATE_CANCEL,
					"Bad state %s after cancellation",
					fr_table_str_by_value(trunk_request_states, treq->pub.state, "<INVALID>"))) {
			connection_signals_resume(tconn->pub.conn);
			return;
		}
		/*
		 *	No cancel muxer.  We're done.
		 *
		 *	If we do have a cancel mux function,
		 *	the next time this connection becomes
		 *	writable, we'll call the cancel mux
		 *	function.
		 *
		 *	We don't run the complete or failed
		 *	callbacks here as the request is
		 *	being cancelled.
		 */
		if (!trunk->funcs.request_cancel_mux) {
			trunk_request_enter_unassigned(treq);
			trunk_request_free(&treq);
		}
		connection_signals_resume(tconn->pub.conn);
	}
		break;

	/*
	 *	We're already in the process of cancelling a
	 *	request, so ignore duplicate signals.
	 */
	case TRUNK_REQUEST_STATE_CANCEL:
	case TRUNK_REQUEST_STATE_CANCEL_PARTIAL:
	case TRUNK_REQUEST_STATE_CANCEL_SENT:
	case TRUNK_REQUEST_STATE_CANCEL_COMPLETE:
		break;

	/*
	 *	For any other state, we just release the request
	 *	from its current connection and free it.
	 */
	default:
		trunk_request_enter_unassigned(treq);
		trunk_request_free(&treq);
		break;
	}
}

/** Signal a partial cancel write
 *
 * Where there's high load, and the outbound write buffer is full
 *
 * @param[in] treq	to signal state change for.
 */
void trunk_request_signal_cancel_partial(trunk_request_t *treq)
{
	if (!fr_cond_assert_msg(treq->pub.trunk, "treq not associated with trunk")) return;

	if (!fr_cond_assert_msg(IN_REQUEST_CANCEL_MUX(treq->pub.trunk),
				"%s can only be called from within request_cancel_mux handler", __FUNCTION__)) return;

	switch (treq->pub.state) {
	case TRUNK_REQUEST_STATE_CANCEL:
		trunk_request_enter_cancel_partial(treq);
		break;

	default:
		return;
	}
}

/** Signal that a remote server has been notified of the cancellation
 *
 * Called from request_cancel_mux to indicate that the datastore has been informed
 * that the response is no longer needed.
 *
 * @param[in] treq	to signal state change for.
 */
void trunk_request_signal_cancel_sent(trunk_request_t *treq)
{
	if (!fr_cond_assert_msg(treq->pub.trunk, "treq not associated with trunk")) return;

	if (!fr_cond_assert_msg(IN_REQUEST_CANCEL_MUX(treq->pub.trunk),
				"%s can only be called from within request_cancel_mux handler", __FUNCTION__)) return;

	switch (treq->pub.state) {
	case TRUNK_REQUEST_STATE_CANCEL:
	case TRUNK_REQUEST_STATE_CANCEL_PARTIAL:
		trunk_request_enter_cancel_sent(treq);
		break;

	default:
		break;
	}
}

/** Signal that a remote server acked our cancellation
 *
 * Called from request_demux to indicate that it got an ack for the cancellation.
 *
 * @param[in] treq	to signal state change for.
 */
void trunk_request_signal_cancel_complete(trunk_request_t *treq)
{
	if (!fr_cond_assert_msg(treq->pub.trunk, "treq not associated with trunk")) return;

	if (!fr_cond_assert_msg(IN_REQUEST_DEMUX(treq->pub.trunk) || IN_REQUEST_CANCEL_MUX(treq->pub.trunk),
				"%s can only be called from within request_demux or request_cancel_mux handlers",
				__FUNCTION__)) return;

	switch (treq->pub.state) {
	case TRUNK_REQUEST_STATE_CANCEL_SENT:
	/*
	 *	This is allowed, as we may not need to wait
	 *	for the database to ACK our cancellation
	 *	request.
	 *
	 *	Note: TRUNK_REQUEST_STATE_CANCEL_PARTIAL
	 *	is not allowed here, as that'd mean we'd half
	 *	written the cancellation request out to the
	 *	socket, and then decided to abandon it.
	 *
	 *	That'd leave the socket in an unusable state.
	 */
	case TRUNK_REQUEST_STATE_CANCEL:
		trunk_request_enter_cancel_complete(treq);
		break;

	default:
		break;
	}
}

/** If the trunk request is freed then update the target requests
 *
 * gperftools showed calling the request free function directly was slightly faster
 * than using talloc_free.
 *
 * @param[in] treq_to_free	request.
 */
void trunk_request_free(trunk_request_t **treq_to_free)
{
	trunk_request_t	*treq = *treq_to_free;
	trunk_t		*trunk = treq->pub.trunk;

	if (unlikely(!treq)) return;

	/*
	 *	The only valid states a trunk request can be
	 *	freed from.
	 */
	switch (treq->pub.state) {
	case TRUNK_REQUEST_STATE_INIT:
	case TRUNK_REQUEST_STATE_UNASSIGNED:
	case TRUNK_REQUEST_STATE_COMPLETE:
	case TRUNK_REQUEST_STATE_FAILED:
	case TRUNK_REQUEST_STATE_CANCEL_COMPLETE:
		break;

	default:
		if (!fr_cond_assert(0)) return;
	}

	/*
	 *	Zero out the pointer to prevent double frees
	 */
	*treq_to_free = NULL;

	/*
	 *	Call the API client callback to free
	 *	any associated memory.
	 */
	DO_REQUEST_FREE(treq);

	/*
	 *	Update the last above/below target stats
	 *	We only do this when we alloc or free
	 *	connections, or on connection
	 *      state changes.
	 */
	trunk_requests_per_connection(NULL, NULL, treq->pub.trunk, fr_time(), false);

	/*
	 *	This tracks the total number of requests
	 *	allocated and not freed or returned to
	 *	the free list.
	 */
	if (fr_cond_assert(trunk->pub.req_alloc > 0)) trunk->pub.req_alloc--;

	/*
	 *	No cleanup delay, means cleanup immediately
	 */
	if (!fr_time_delta_ispos(trunk->conf.req_cleanup_delay)) {
		treq->pub.state = TRUNK_REQUEST_STATE_INIT;

#ifndef NDEBUG
		/*
		 *	Ensure anything parented off the treq
		 *	is freed.  We do this to trigger
		 *	the destructors for the log entries.
		 */
		talloc_free_children(treq);

		/*
		 *	State log should now be empty as entries
		 *	remove themselves from the dlist
		 *	on free.
		 */
		fr_assert_msg(fr_dlist_num_elements(&treq->log) == 0,
			      "Should have 0 remaining log entries, have %u", fr_dlist_num_elements(&treq->log));
#endif

		talloc_free(treq);
		return;
	}

	/*
	 *	Ensure anything parented off the treq
	 *	is freed.
	 */
	talloc_free_children(treq);

#ifndef NDEBUG
	/*
	 *	State log should now be empty as entries
	 *	remove themselves from the dlist
	 *	on free.
	 */
	fr_assert_msg(fr_dlist_num_elements(&treq->log) == 0,
		      "Should have 0 remaining log entries, have %u", fr_dlist_num_elements(&treq->log));
#endif

	/*
	 *
	 *  Return the trunk request back to the init state.
	 */
	*treq = (trunk_request_t){
		.pub = {
			.state = TRUNK_REQUEST_STATE_INIT,
			.trunk = treq->pub.trunk,
		},
		.cancel_reason = TRUNK_CANCEL_REASON_NONE,
		.last_freed = fr_time(),
#ifndef NDEBUG
		.log = treq->log        /* Keep the list head, to save reinitialisation */
#endif
	};

	/*
	 *	Insert at the head, so that we can free
	 *	requests that have been unused for N
	 *	seconds from the tail.
	 */
	fr_dlist_insert_tail(&trunk->free_requests, treq);
}

/** Actually free the trunk request
 *
 */
static int _trunk_request_free(trunk_request_t *treq)
{
	trunk_t	*trunk = treq->pub.trunk;

	switch (treq->pub.state) {
	case TRUNK_REQUEST_STATE_INIT:
	case TRUNK_REQUEST_STATE_UNASSIGNED:
		break;

	default:
		fr_assert(0);
		break;
	}

	fr_dlist_remove(&trunk->free_requests, treq);

	return 0;
}

/** (Pre-)Allocate a new trunk request
 *
 * If trunk->conf.req_pool_headers or trunk->conf.req_pool_size are not zero then the
 * request will be a talloc pool, which can be used to hold the preq.
 *
 * @note Do not use MEM to check the result of this allocated as it may fail for
 * non-fatal reasons.
 *
 * @param[in] trunk	to add request to.
 * @param[in] request	to wrap in a trunk request (treq).
 * @return
 *	- A newly allocated request.
 *	- NULL if too many requests are allocated.
 */
trunk_request_t *trunk_request_alloc(trunk_t *trunk, request_t *request)
{
	trunk_request_t *treq;

	/*
	 *	The number of treqs currently allocated
	 *	exceeds the maximum number allowed.
	 */
	if (trunk->conf.max_req_per_conn && trunk->conf.max) {
		uint64_t limit;

		limit = (uint64_t) trunk->conf.max_req_per_conn * trunk->conf.max;
		if (trunk->pub.req_alloc >= (limit + trunk->conf.max_backlog)) {
			RATE_LIMIT_LOCAL_ROPTIONAL(&trunk->limit_max_requests_alloc_log,
						   RWARN, WARN, "Refusing to alloc requests - "
						   "Limit of %"PRIu64" (max = %u * per_connection_max = %u) "
						   "plus %u backlog requests reached",
						   limit, trunk->conf.max, trunk->conf.max_req_per_conn,
						   trunk->conf.max_backlog);
			return NULL;
		}
	}

	/*
	 *	Allocate or reuse an existing request
	 */
	treq = fr_dlist_head(&trunk->free_requests);
	if (treq) {
		fr_dlist_remove(&trunk->free_requests, treq);
		fr_assert(treq->pub.state == TRUNK_REQUEST_STATE_INIT);
		fr_assert(treq->pub.trunk == trunk);
		fr_assert(treq->pub.tconn == NULL);
		fr_assert(treq->cancel_reason == TRUNK_CANCEL_REASON_NONE);
		fr_assert(fr_time_gt(treq->last_freed, fr_time_wrap(0)));
		trunk->pub.req_alloc_reused++;
	} else {
		MEM(treq = talloc_pooled_object(trunk, trunk_request_t,
						trunk->conf.req_pool_headers, trunk->conf.req_pool_size));
		talloc_set_destructor(treq, _trunk_request_free);

		*treq = (trunk_request_t){
			.pub = {
				.state = TRUNK_REQUEST_STATE_INIT,
				.trunk = trunk
			},
			.cancel_reason = TRUNK_CANCEL_REASON_NONE
		};
		trunk->pub.req_alloc_new++;
#ifndef NDEBUG
		fr_dlist_init(&treq->log, trunk_request_state_log_t, entry);
#endif
	}

	trunk->pub.req_alloc++;
	treq->id = atomic_fetch_add_explicit(&request_counter, 1, memory_order_relaxed);
	/* heap_id	- initialised when treq inserted into pending */
	/* list		- empty */
	/* preq		- populated later */
	/* rctx		- populated later */
	treq->pub.request = request;

	return treq;
}

/** Enqueue a request that needs data written to the trunk
 *
 * When a request_t * needs to make an asynchronous request to an external datastore
 * it should call this function, specifying a preq (protocol request) containing
 * the data necessary to request information from the external datastore, and an
 * rctx (resume ctx) used to hold the decoded response and/or any error codes.
 *
 * After a treq is successfully enqueued it will either be assigned immediately
 * to the pending queue of a connection, or if no connections are available,
 * (depending on the trunk configuration) the treq will be placed in the trunk's
 * global backlog.
 *
 * After receiving a positive return code from this function the caller should
 * immediately yield, to allow the various timers and I/O handlers that drive tconn
 * (trunk connection) and treq state changes to be called.
 *
 * When a tconn becomes writable (or the trunk is configured to be always writable)
 * the #trunk_request_mux_t callback will be called to dequeue, encode and
 * send any pending requests for that tconn.  The #trunk_request_mux_t callback
 * is also responsible for tracking the outbound requests to allow the
 * #trunk_request_demux_t callback to match inbound responses with the original
 * treq.  Once the #trunk_request_mux_t callback is done processing the treq
 * it signals what state the treq should enter next using one of the
 * trunk_request_signal_* functions.
 *
 * When a tconn becomes readable the user specified #trunk_request_demux_t
 * callback is called to process any responses, match them with the original treq.
 * and signal what state they should enter next using one of the
 * trunk_request_signal_* functions.
 *
 * @param[in,out] treq_out	A trunk request handle.  If the memory pointed to
 *				is NULL, a new treq will be allocated.
 *				Otherwise treq should point to memory allocated
 *				with trunk_request_alloc.
 * @param[in] trunk		to enqueue request on.
 * @param[in] request		to enqueue.
 * @param[in] preq		Protocol request to write out.  Will be freed when
 *				treq is freed. Should ideally be parented by the
 *				treq if possible.
 *				Use #trunk_request_alloc for pre-allocation of
 *				the treq.
 * @param[in] rctx		The resume context to write any result to.
 * @return
 *	- TRUNK_ENQUEUE_OK.
 *	- TRUNK_ENQUEUE_IN_BACKLOG.
 *	- TRUNK_ENQUEUE_NO_CAPACITY.
 *	- TRUNK_ENQUEUE_DST_UNAVAILABLE
 *	- TRUNK_ENQUEUE_FAIL
 */
trunk_enqueue_t trunk_request_enqueue(trunk_request_t **treq_out, trunk_t *trunk,
					    request_t *request, void *preq, void *rctx)
{
	trunk_connection_t	*tconn = NULL;
	trunk_request_t	*treq;
	trunk_enqueue_t	ret;

	if (!fr_cond_assert_msg(!IN_HANDLER(trunk),
				"%s cannot be called within a handler", __FUNCTION__)) return TRUNK_ENQUEUE_FAIL;

	if (!fr_cond_assert_msg(!*treq_out || ((*treq_out)->pub.state == TRUNK_REQUEST_STATE_INIT),
				"%s requests must be in \"init\" state", __FUNCTION__)) return TRUNK_ENQUEUE_FAIL;

	/*
	 *	If delay_start was set, we may need
	 *	to insert the timer for the connection manager.
	 */
	if (unlikely(!trunk->started)) {
		if (trunk_start(trunk) < 0) return TRUNK_ENQUEUE_FAIL;
	}

	ret = trunk_request_check_enqueue(&tconn, trunk, request);
	switch (ret) {
	case TRUNK_ENQUEUE_OK:
		if (*treq_out) {
			treq = *treq_out;
		} else {
			*treq_out = treq = trunk_request_alloc(trunk, request);
			if (!treq) return TRUNK_ENQUEUE_FAIL;
		}
		treq->pub.preq = preq;
		treq->pub.rctx = rctx;
		if (trunk->conf.always_writable) {
			connection_signals_pause(tconn->pub.conn);
			trunk_request_enter_pending(treq, tconn, true);
			trunk_connection_writable(tconn);
			connection_signals_resume(tconn->pub.conn);
		} else {
			trunk_request_enter_pending(treq, tconn, true);
		}
		break;

	case TRUNK_ENQUEUE_IN_BACKLOG:
		if (*treq_out) {
			treq = *treq_out;
		} else {
			*treq_out = treq = trunk_request_alloc(trunk, request);
			if (!treq) return TRUNK_ENQUEUE_FAIL;
		}
		treq->pub.preq = preq;
		treq->pub.rctx = rctx;
		trunk_request_enter_backlog(treq, true);
		break;

	default:
		/*
		 *	If a trunk request was provided
		 *	populate the preq and rctx fields
		 *	so that if it's freed with
		 *	trunk_request_free, the free
		 *	function works as intended.
		 */
		if (*treq_out) {
			treq = *treq_out;
			treq->pub.preq = preq;
			treq->pub.rctx = rctx;
		}
		return ret;
	}

	return ret;
}

/** Re-enqueue a request on the same connection
 *
 * If the treq has been sent, we assume that we're being signalled to requeue
 * because something outside of the trunk API has determined that a retransmission
 * is required.  The easiest way to perform that retransmission is to clean up
 * any tracking information for the request, and the requeue it for transmission.
 *
 * IF re-queueing fails, the request will enter the fail state.  It should not be
 * accessed if this occurs.
 *
 * @param[in] treq	to requeue (retransmit).
 * @return
 *	- TRUNK_ENQUEUE_OK.
 *	- TRUNK_ENQUEUE_DST_UNAVAILABLE - Connection cannot service requests.
 *	- TRUNK_ENQUEUE_FAIL - Request isn't in a valid state to be reassigned.
 */
trunk_enqueue_t trunk_request_requeue(trunk_request_t *treq)
{
	trunk_connection_t	*tconn = treq->pub.tconn;	/* Existing conn */

	if (!tconn) return TRUNK_ENQUEUE_FAIL;

	if (!IS_PROCESSING(tconn)) {
		trunk_request_enter_failed(treq);
		return TRUNK_ENQUEUE_DST_UNAVAILABLE;
	}

	switch (treq->pub.state) {
	case TRUNK_REQUEST_STATE_PARTIAL:
	case TRUNK_REQUEST_STATE_SENT:
	case TRUNK_REQUEST_STATE_REAPABLE:
		connection_signals_pause(tconn->pub.conn);
		trunk_request_enter_cancel(treq, TRUNK_CANCEL_REASON_REQUEUE);
		trunk_request_enter_pending(treq, tconn, false);
		if (treq->pub.trunk->conf.always_writable) {
			trunk_connection_writable(tconn);
		}
		connection_signals_resume(tconn->pub.conn);
		break;

	case TRUNK_REQUEST_STATE_BACKLOG:	/* Do nothing.... */
	case TRUNK_REQUEST_STATE_PENDING:	/* Do nothing.... */
		break;

	default:
		trunk_request_enter_failed(treq);
		return TRUNK_ENQUEUE_FAIL;
	}

	return TRUNK_ENQUEUE_OK;
}

/** Enqueue additional requests on a specific connection
 *
 * This may be used to create a series of requests on a single connection, or to generate
 * in-band status checks.
 *
 * @note If conf->always_writable, then the muxer will be called immediately.  The caller
 *	 must be able to handle multiple calls to its muxer gracefully.
 *
 * @param[in,out] treq_out	A trunk request handle.  If the memory pointed to
 *				is NULL, a new treq will be allocated.
 *				Otherwise treq should point to memory allocated
 *				with trunk_request_alloc.
 * @param[in] tconn		to enqueue request on.
 * @param[in] request		to enqueue.
 * @param[in] preq		Protocol request to write out.  Will be freed when
 *				treq is freed. Should ideally be parented by the
 *				treq if possible.
 *				Use #trunk_request_alloc for pre-allocation of
 *				the treq.
 * @param[in] rctx		The resume context to write any result to.
 * @param[in] ignore_limits	Ignore max_req_per_conn.  Useful to force status
 *				checks through even if the connection is at capacity.
 *				Will also allow enqueuing on "inactive", "draining",
 *				"draining-to-free" connections.
 * @return
 *	- TRUNK_ENQUEUE_OK.
 *	- TRUNK_ENQUEUE_NO_CAPACITY - At max_req_per_conn_limit
 *	- TRUNK_ENQUEUE_DST_UNAVAILABLE - Connection cannot service requests.
 */
trunk_enqueue_t trunk_request_enqueue_on_conn(trunk_request_t **treq_out, trunk_connection_t *tconn,
						    request_t *request, void *preq, void *rctx,
						    bool ignore_limits)
{
	trunk_request_t	*treq;
	trunk_t		*trunk = tconn->pub.trunk;

	if (!fr_cond_assert_msg(!*treq_out || ((*treq_out)->pub.state == TRUNK_REQUEST_STATE_INIT),
				"%s requests must be in \"init\" state", __FUNCTION__)) return TRUNK_ENQUEUE_FAIL;

	if (!IS_SERVICEABLE(tconn)) return TRUNK_ENQUEUE_DST_UNAVAILABLE;

	/*
	 *	Limits check
	 */
	if (!ignore_limits) {
		if (trunk->conf.max_req_per_conn &&
		    (trunk_request_count_by_connection(tconn, TRUNK_REQUEST_STATE_ALL) >=
		     trunk->conf.max_req_per_conn)) return TRUNK_ENQUEUE_NO_CAPACITY;

		if (tconn->pub.state != TRUNK_CONN_ACTIVE) return TRUNK_ENQUEUE_NO_CAPACITY;
	}

	if (*treq_out) {
		treq = *treq_out;
	} else {
		MEM(*treq_out = treq = trunk_request_alloc(trunk, request));
	}

	treq->pub.preq = preq;
	treq->pub.rctx = rctx;
	treq->bound_to_conn = true;	/* Don't let the request be transferred */

	if (trunk->conf.always_writable) {
		connection_signals_pause(tconn->pub.conn);
		trunk_request_enter_pending(treq, tconn, true);
		trunk_connection_writable(tconn);
		connection_signals_resume(tconn->pub.conn);
	} else {
		trunk_request_enter_pending(treq, tconn, true);
	}

	return TRUNK_ENQUEUE_OK;
}

#ifndef NDEBUG
/** Used for sanity checks to ensure all log entries have been freed
 *
 */
static int _state_log_entry_free(trunk_request_state_log_t *slog)
{
	fr_dlist_remove(slog->log_head, slog);

	return 0;
}

void trunk_request_state_log_entry_add(char const *function, int line,
				       trunk_request_t *treq, trunk_request_state_t new)
{
	trunk_request_state_log_t	*slog = NULL;

	if (fr_dlist_num_elements(&treq->log) >= TRUNK_REQUEST_STATE_LOG_MAX) {
		slog = fr_dlist_head(&treq->log);
		fr_assert_msg(slog, "slog list head NULL but element counter was %u",
			      fr_dlist_num_elements(&treq->log));
		(void)fr_dlist_remove(&treq->log, slog);	/* Returns NULL when removing the list head */
		memset(slog, 0, sizeof(*slog));
	} else {
		MEM(slog = talloc_zero(treq, trunk_request_state_log_t));
		talloc_set_destructor(slog, _state_log_entry_free);
	}

	slog->log_head = &treq->log;
	slog->from = treq->pub.state;
	slog->to = new;
	slog->function = function;
	slog->line = line;
	if (treq->pub.tconn) {
		slog->tconn = treq->pub.tconn;
		slog->tconn_id = treq->pub.tconn->pub.conn->id;
		slog->tconn_state = treq->pub.tconn->pub.state;
	}

	fr_dlist_insert_tail(&treq->log, slog);

}

void trunk_request_state_log(fr_log_t const *log, fr_log_type_t log_type, char const *file, int line,
				trunk_request_t const *treq)
{
	trunk_request_state_log_t	*slog = NULL;

	int i;

	for (slog = fr_dlist_head(&treq->log), i = 0;
	     slog;
	     slog = fr_dlist_next(&treq->log, slog), i++) {
		fr_log(log, log_type, file, line, "[%u] %s:%i - in conn %"PRIu64" in state %s - %s -> %s",
		       i, slog->function, slog->line,
		       slog->tconn_id,
		       slog->tconn ? fr_table_str_by_value(trunk_connection_states,
		       					    slog->tconn_state, "<INVALID>") : "none",
		       fr_table_str_by_value(trunk_request_states, slog->from, "<INVALID>"),
		       fr_table_str_by_value(trunk_request_states, slog->to, "<INVALID>"));
	}
}
#endif

/** Return the count number of connections in the specified states
 *
 * @param[in] trunk		to retrieve counts for.
 * @param[in] conn_state	One or more #trunk_connection_state_t states or'd together.
 * @return The number of connections in the specified states.
 */
uint16_t trunk_connection_count_by_state(trunk_t *trunk, int conn_state)
{
	uint16_t count = 0;

	if (conn_state & TRUNK_CONN_INIT) count += fr_dlist_num_elements(&trunk->init);
	if (conn_state & TRUNK_CONN_CONNECTING) count += fr_dlist_num_elements(&trunk->connecting);
	if (conn_state & TRUNK_CONN_ACTIVE) count += fr_minmax_heap_num_elements(trunk->active);
	if (conn_state & TRUNK_CONN_FULL) count += fr_dlist_num_elements(&trunk->full);
	if (conn_state & TRUNK_CONN_INACTIVE) count += fr_dlist_num_elements(&trunk->inactive);
	if (conn_state & TRUNK_CONN_INACTIVE_DRAINING) count += fr_dlist_num_elements(&trunk->inactive_draining);
	if (conn_state & TRUNK_CONN_CLOSED) count += fr_dlist_num_elements(&trunk->closed);
	if (conn_state & TRUNK_CONN_DRAINING) count += fr_dlist_num_elements(&trunk->draining);
	if (conn_state & TRUNK_CONN_DRAINING_TO_FREE) count += fr_dlist_num_elements(&trunk->draining_to_free);

	return count;
}

/** Return the count number of requests associated with a trunk connection
 *
 * @param[in] tconn		to return request count for.
 * @param[in] req_state		One or more request states or'd together.
 *
 * @return The number of requests in the specified states, associated with a tconn.
 */
uint32_t trunk_request_count_by_connection(trunk_connection_t const *tconn, int req_state)
{
	uint32_t count = 0;

	if (req_state & TRUNK_REQUEST_STATE_PENDING) count += fr_heap_num_elements(tconn->pending);
	if (req_state & TRUNK_REQUEST_STATE_PARTIAL) count += tconn->partial ? 1 : 0;
	if (req_state & TRUNK_REQUEST_STATE_SENT) count += fr_dlist_num_elements(&tconn->sent);
	if (req_state & TRUNK_REQUEST_STATE_REAPABLE) count += fr_dlist_num_elements(&tconn->reapable);
	if (req_state & TRUNK_REQUEST_STATE_CANCEL) count += fr_dlist_num_elements(&tconn->cancel);
	if (req_state & TRUNK_REQUEST_STATE_CANCEL_PARTIAL) count += tconn->cancel_partial ? 1 : 0;
	if (req_state & TRUNK_REQUEST_STATE_CANCEL_SENT) count += fr_dlist_num_elements(&tconn->cancel_sent);

	return count;
}

/** Automatically mark a connection as full
 *
 * @param[in] tconn	to potentially mark as full.
 */
static inline void trunk_connection_auto_full(trunk_connection_t *tconn)
{
	trunk_t	*trunk = tconn->pub.trunk;
	uint32_t	count;

	if (tconn->pub.state != TRUNK_CONN_ACTIVE) return;

	/*
	 *	Enforces max_req_per_conn
	 */
	if (trunk->conf.max_req_per_conn > 0) {
		count = trunk_request_count_by_connection(tconn, TRUNK_REQUEST_STATE_ALL);
		if (count >= trunk->conf.max_req_per_conn) trunk_connection_enter_full(tconn);
	}
}

/** Return whether a trunk connection should currently be considered full
 *
 * @param[in] tconn	to check.
 * @return
 *	- true if the connection is full.
 *	- false if the connection is not full.
 */
static inline bool trunk_connection_is_full(trunk_connection_t *tconn)
{
	trunk_t	*trunk = tconn->pub.trunk;
	uint32_t	count;

	/*
	 *	Enforces max_req_per_conn
	 */
	count = trunk_request_count_by_connection(tconn, TRUNK_REQUEST_STATE_ALL);
	if ((trunk->conf.max_req_per_conn == 0) || (count < trunk->conf.max_req_per_conn)) return false;

	return true;
}

/** Automatically mark a connection as active or reconnect it
 *
 * @param[in] tconn	to potentially mark as active or reconnect.
 */
static inline void trunk_connection_auto_unfull(trunk_connection_t *tconn)
{
	if (tconn->pub.state != TRUNK_CONN_FULL) return;

	/*
	 *	Enforces max_req_per_conn
	 */
	if (!trunk_connection_is_full(tconn)) trunk_connection_enter_active(tconn);
}

/** A connection is readable.  Call the request_demux function to read pending requests
 *
 */
static inline void trunk_connection_readable(trunk_connection_t *tconn)
{
	trunk_t *trunk = tconn->pub.trunk;

	DO_REQUEST_DEMUX(tconn);
}

/** A connection is writable.  Call the request_mux function to write pending requests
 *
 */
static inline void trunk_connection_writable(trunk_connection_t *tconn)
{
	trunk_t *trunk = tconn->pub.trunk;

	/*
	 *	Call the cancel_sent function (if we have one)
	 *      to inform a backend datastore we no longer
	 *	care about the result
	 */
	if (trunk->funcs.request_cancel_mux && trunk_request_count_by_connection(tconn,
										    TRUNK_REQUEST_STATE_CANCEL |
										    TRUNK_REQUEST_STATE_CANCEL_PARTIAL)) {
		DO_REQUEST_CANCEL_MUX(tconn);
	}
	if (!trunk_request_count_by_connection(tconn,
						  TRUNK_REQUEST_STATE_PENDING |
						  TRUNK_REQUEST_STATE_PARTIAL)) return;
	DO_REQUEST_MUX(tconn);
}

/** Update the registrations for I/O events we're interested in
 *
 */
static void trunk_connection_event_update(trunk_connection_t *tconn)
{
	trunk_t			*trunk = tconn->pub.trunk;
	trunk_connection_event_t	events = TRUNK_CONN_EVENT_NONE;

	switch (tconn->pub.state) {
	/*
	 *	We only register I/O events if the trunk connection is
	 *	in one of these states.
	 *
	 *	For the other states the trunk shouldn't be processing
	 *	requests.
	 */
	case TRUNK_CONN_ACTIVE:
	case TRUNK_CONN_FULL:
	case TRUNK_CONN_INACTIVE:
	case TRUNK_CONN_INACTIVE_DRAINING:
	case TRUNK_CONN_DRAINING:
	case TRUNK_CONN_DRAINING_TO_FREE:
		/*
		 *	If the connection is always writable,
		 *	then we don't care about write events.
		 */
		if (!trunk->conf.always_writable &&
		    trunk_request_count_by_connection(tconn,
							 TRUNK_REQUEST_STATE_PARTIAL |
						       	 TRUNK_REQUEST_STATE_PENDING |
							 (trunk->funcs.request_cancel_mux ?
							 TRUNK_REQUEST_STATE_CANCEL |
							 TRUNK_REQUEST_STATE_CANCEL_PARTIAL : 0)) > 0) {
			events |= TRUNK_CONN_EVENT_WRITE;
		}

		if (trunk_request_count_by_connection(tconn,
							 TRUNK_REQUEST_STATE_SENT |
							 (trunk->funcs.request_cancel_mux ?
							 TRUNK_REQUEST_STATE_CANCEL_SENT : 0)) > 0) {
			events |= TRUNK_CONN_EVENT_READ;
		}
		break;

	default:
		break;
	}

	if (tconn->events != events) {
		/*
		 *	There may be a fatal error which results
		 *	in the connection being freed.
		 *
		 *	Stop that from happening until after
		 *	we're done using it.
		 */
		connection_signals_pause(tconn->pub.conn);
		DO_CONNECTION_NOTIFY(tconn, events);
		tconn->events = events;
		connection_signals_resume(tconn->pub.conn);
	}
}

/** Remove a trunk connection from whichever list it's currently in
 *
 * @param[in] tconn to remove.
 */
static void trunk_connection_remove(trunk_connection_t *tconn)
{
	trunk_t *trunk = tconn->pub.trunk;

	switch (tconn->pub.state) {
	case TRUNK_CONN_ACTIVE:
	{
		int ret;

		ret = fr_minmax_heap_extract(trunk->active, tconn);
		if (!fr_cond_assert_msg(ret == 0, "Failed extracting conn from active heap: %s", fr_strerror())) return;
	}
		return;

	case TRUNK_CONN_INIT:
		fr_dlist_remove(&trunk->init, tconn);
		break;

	case TRUNK_CONN_CONNECTING:
		fr_dlist_remove(&trunk->connecting, tconn);
		return;

	case TRUNK_CONN_CLOSED:
		fr_dlist_remove(&trunk->closed, tconn);
		return;

	case TRUNK_CONN_FULL:
		fr_dlist_remove(&trunk->full, tconn);
		return;

	case TRUNK_CONN_INACTIVE:
		fr_dlist_remove(&trunk->inactive, tconn);
		return;

	case TRUNK_CONN_INACTIVE_DRAINING:
		fr_dlist_remove(&trunk->inactive_draining, tconn);
		return;

	case TRUNK_CONN_DRAINING:
		fr_dlist_remove(&trunk->draining, tconn);
		return;

	case TRUNK_CONN_DRAINING_TO_FREE:
		fr_dlist_remove(&trunk->draining_to_free, tconn);
		return;

	case TRUNK_CONN_HALTED:
		return;
	}
}

/** Transition a connection to the full state
 *
 * Called whenever a trunk connection is at the maximum number of requests.
 * Removes the connection from the connected heap, and places it in the full list.
 */
static void trunk_connection_enter_full(trunk_connection_t *tconn)
{
	trunk_t		*trunk = tconn->pub.trunk;

	switch (tconn->pub.state) {
	case TRUNK_CONN_ACTIVE:
		trunk_connection_remove(tconn);
		break;

	default:
		CONN_BAD_STATE_TRANSITION(TRUNK_CONN_FULL);
	}

	fr_dlist_insert_head(&trunk->full, tconn);
	CONN_STATE_TRANSITION(TRUNK_CONN_FULL, DEBUG2);
}

/** Transition a connection to the inactive state
 *
 * Called whenever the API client wants to stop new requests being enqueued
 * on a trunk connection.
 */
static void trunk_connection_enter_inactive(trunk_connection_t *tconn)
{
	trunk_t		*trunk = tconn->pub.trunk;

	switch (tconn->pub.state) {
	case TRUNK_CONN_ACTIVE:
	case TRUNK_CONN_FULL:
		trunk_connection_remove(tconn);
		break;

	default:
		CONN_BAD_STATE_TRANSITION(TRUNK_CONN_INACTIVE);
	}

	fr_dlist_insert_head(&trunk->inactive, tconn);
	CONN_STATE_TRANSITION(TRUNK_CONN_INACTIVE, DEBUG2);
}

/** Transition a connection to the inactive-draining state
 *
 * Called whenever the trunk manager wants to drain an inactive connection
 * of its requests.
 */
static void trunk_connection_enter_inactive_draining(trunk_connection_t *tconn)
{
	trunk_t		*trunk = tconn->pub.trunk;

	switch (tconn->pub.state) {
	case TRUNK_CONN_INACTIVE:
	case TRUNK_CONN_DRAINING:
		trunk_connection_remove(tconn);
		break;

	default:
		CONN_BAD_STATE_TRANSITION(TRUNK_CONN_INACTIVE_DRAINING);
	}

	fr_dlist_insert_head(&trunk->inactive_draining, tconn);
	CONN_STATE_TRANSITION(TRUNK_CONN_INACTIVE_DRAINING, INFO);

	/*
	 *	Immediately re-enqueue all pending
	 *	requests, so the connection is drained
	 *	quicker.
	 */
	trunk_connection_requests_requeue_priv(tconn, TRUNK_REQUEST_STATE_PENDING, 0, false);
}

/** Transition a connection to the draining state
 *
 * Removes the connection from the active heap so it won't be assigned any new
 * connections.
 */
static void trunk_connection_enter_draining(trunk_connection_t *tconn)
{
	trunk_t		*trunk = tconn->pub.trunk;

	switch (tconn->pub.state) {
	case TRUNK_CONN_ACTIVE:
	case TRUNK_CONN_FULL:
	case TRUNK_CONN_INACTIVE:
	case TRUNK_CONN_INACTIVE_DRAINING:
		trunk_connection_remove(tconn);
		break;

	default:
		CONN_BAD_STATE_TRANSITION(TRUNK_CONN_DRAINING);
	}

	fr_dlist_insert_head(&trunk->draining, tconn);
	CONN_STATE_TRANSITION(TRUNK_CONN_DRAINING, INFO);

	/*
	 *	Immediately re-enqueue all pending
	 *	requests, so the connection is drained
	 *	quicker.
	 */
	trunk_connection_requests_requeue_priv(tconn, TRUNK_REQUEST_STATE_PENDING, 0, false);
}

/** Transition a connection to the draining-to-reconnect state
 *
 * Removes the connection from the active heap so it won't be assigned any new
 * connections.
 */
static void trunk_connection_enter_draining_to_free(trunk_connection_t *tconn)
{
	trunk_t		*trunk = tconn->pub.trunk;

	FR_TIMER_DISARM(tconn->lifetime_ev);

	switch (tconn->pub.state) {
	case TRUNK_CONN_ACTIVE:
	case TRUNK_CONN_FULL:
	case TRUNK_CONN_INACTIVE:
	case TRUNK_CONN_INACTIVE_DRAINING:
	case TRUNK_CONN_DRAINING:
		trunk_connection_remove(tconn);
		break;

	default:
		CONN_BAD_STATE_TRANSITION(TRUNK_CONN_DRAINING_TO_FREE);
	}

	fr_dlist_insert_head(&trunk->draining_to_free, tconn);
	CONN_STATE_TRANSITION(TRUNK_CONN_DRAINING_TO_FREE, INFO);

	/*
	 *	Immediately re-enqueue all pending
	 *	requests, so the connection is drained
	 *	quicker.
	 */
	trunk_connection_requests_requeue_priv(tconn, TRUNK_REQUEST_STATE_PENDING, 0, false);
}


/** Transition a connection back to the active state
 *
 * This should only be called on a connection which is in the full state,
 * inactive state, draining state or connecting state.
 */
static void trunk_connection_enter_active(trunk_connection_t *tconn)
{
	trunk_t		*trunk = tconn->pub.trunk;
	int			ret;

	switch (tconn->pub.state) {
	case TRUNK_CONN_FULL:
	case TRUNK_CONN_INACTIVE:
	case TRUNK_CONN_INACTIVE_DRAINING:
	case TRUNK_CONN_DRAINING:
		trunk_connection_remove(tconn);
		break;

	case TRUNK_CONN_INIT:
	case TRUNK_CONN_CONNECTING:
		trunk_connection_remove(tconn);
		fr_assert(trunk_request_count_by_connection(tconn, TRUNK_REQUEST_STATE_ALL) == trunk_request_count_by_connection(tconn, TRUNK_REQUEST_STATE_PENDING));
		break;

	default:
		CONN_BAD_STATE_TRANSITION(TRUNK_CONN_ACTIVE);
	}

	ret = fr_minmax_heap_insert(trunk->active, tconn);	/* re-insert into the active heap*/
	if (!fr_cond_assert_msg(ret == 0, "Failed inserting connection into active heap: %s", fr_strerror())) {
		trunk_connection_enter_inactive_draining(tconn);
		return;
	}

	CONN_STATE_TRANSITION(TRUNK_CONN_ACTIVE, DEBUG2);

	/*
	 *	Reorder the connections
	 */
	CONN_REORDER(tconn);

	/*
	 *	Rebalance requests
	 */
	trunk_rebalance(trunk);

	/*
	 *	We place requests into the backlog
	 *      because there were no connections
	 *	available to handle them.
	 *
	 *	If a connection has become active
	 *	chances are those backlogged requests
	 *      can now be enqueued, so try and do
	 *	that now.
	 *
	 *	If there's requests sitting in the
	 *	backlog indefinitely, it's because
	 *	they were inserted there erroneously
	 *	when there were active connections
	 *	which could have handled them.
	 */
	trunk_backlog_drain(trunk);
}

/** Connection transitioned to the the init state
 *
 * Reflect the connection state change in the lists we use to track connections.
 *
 * @note This function is only called from the connection API as a watcher.
 *
 * @param[in] conn	The connection which changes state.
 * @param[in] prev	The connection is was in.
 * @param[in] state	The connection is now in.
 * @param[in] uctx	The trunk_connection_t wrapping the connection.
 */
static void _trunk_connection_on_init(UNUSED connection_t *conn,
				      UNUSED connection_state_t prev,
				      UNUSED connection_state_t state,
				      void *uctx)
{
	trunk_connection_t	*tconn = talloc_get_type_abort(uctx, trunk_connection_t);
	trunk_t		*trunk = tconn->pub.trunk;

	switch (tconn->pub.state) {
	case TRUNK_CONN_HALTED:
		break;

	case TRUNK_CONN_CLOSED:
		trunk_connection_remove(tconn);
		break;

	default:
		CONN_BAD_STATE_TRANSITION(TRUNK_CONN_INIT);
	}

	fr_dlist_insert_head(&trunk->init, tconn);
	CONN_STATE_TRANSITION(TRUNK_CONN_INIT, DEBUG2);
}

/** Connection transitioned to the connecting state
 *
 * Reflect the connection state change in the lists we use to track connections.
 *
 * @note This function is only called from the connection API as a watcher.
 *
 * @param[in] conn	The connection which changes state.
 * @param[in] prev	The connection is was in.
 * @param[in] state	The connection is now in.
 * @param[in] uctx	The trunk_connection_t wrapping the connection.
 */
static void _trunk_connection_on_connecting(UNUSED connection_t *conn,
					    UNUSED connection_state_t prev,
					    UNUSED connection_state_t state,
					    void *uctx)
{
	trunk_connection_t	*tconn = talloc_get_type_abort(uctx, trunk_connection_t);
	trunk_t		*trunk = tconn->pub.trunk;

	switch (tconn->pub.state) {
	case TRUNK_CONN_INIT:
	case TRUNK_CONN_CLOSED:
		trunk_connection_remove(tconn);
		break;

	default:
		CONN_BAD_STATE_TRANSITION(TRUNK_CONN_CONNECTING);
	}

	/*
	 *	If a connection just entered the
	 *	connecting state, it should have
	 *	no requests associated with it.
	 */
	fr_assert(trunk_request_count_by_connection(tconn, TRUNK_REQUEST_STATE_ALL) == 0);

	fr_dlist_insert_head(&trunk->connecting, tconn);	/* MUST remain a head insertion for reconnect logic */
	CONN_STATE_TRANSITION(TRUNK_CONN_CONNECTING, INFO);
}

/** Connection transitioned to the shutdown state
 *
 * If we're not already in the draining-to-free state, transition there now.
 *
 * The idea is that if something signalled the connection to shutdown, we need
 * to reflect that by dequeuing any pending requests, not accepting new ones,
 * and waiting for the existing requests to complete.
 *
 * @note This function is only called from the connection API as a watcher.
 *
 * @param[in] conn	The connection which changes state.
 * @param[in] prev	The connection is was in.
 * @param[in] state	The connection is now in.
 * @param[in] uctx	The trunk_connection_t wrapping the connection.
 */
static void _trunk_connection_on_shutdown(UNUSED connection_t *conn,
					  UNUSED connection_state_t prev,
					  UNUSED connection_state_t state,
					  void *uctx)
{
	trunk_connection_t	*tconn = talloc_get_type_abort(uctx, trunk_connection_t);

	switch (tconn->pub.state) {
	case TRUNK_CONN_DRAINING_TO_FREE:	/* Do Nothing */
		return;

	case TRUNK_CONN_ACTIVE:		/* Transition to draining-to-free */
	case TRUNK_CONN_FULL:
	case TRUNK_CONN_INACTIVE:
	case TRUNK_CONN_INACTIVE_DRAINING:
	case TRUNK_CONN_DRAINING:
		break;

	case TRUNK_CONN_INIT:
	case TRUNK_CONN_CONNECTING:
	case TRUNK_CONN_CLOSED:
	case TRUNK_CONN_HALTED:
		CONN_BAD_STATE_TRANSITION(TRUNK_CONN_DRAINING_TO_FREE);
	}

	trunk_connection_enter_draining_to_free(tconn);
}

/** Trigger a reconnection of the trunk connection
 *
 * @param[in] tl	timer list the timer was inserted into.
 * @param[in] now	Current time.
 * @param[in] uctx	The tconn.
 */
static void  _trunk_connection_lifetime_expire(UNUSED fr_timer_list_t *tl, UNUSED fr_time_t now, void *uctx)
{
	trunk_connection_t	*tconn = talloc_get_type_abort(uctx, trunk_connection_t);

	trunk_connection_enter_draining_to_free(tconn);
}

/** Connection transitioned to the connected state
 *
 * Reflect the connection state change in the lists we use to track connections.
 *
 * @note This function is only called from the connection API as a watcher.
 *
 * @param[in] conn	The connection which changes state.
 * @param[in] prev	The connection is was in.
 * @param[in] state	The connection is now in.
 * @param[in] uctx	The trunk_connection_t wrapping the connection.
 */
static void _trunk_connection_on_connected(UNUSED connection_t *conn,
					   UNUSED connection_state_t prev,
					   UNUSED connection_state_t state,
					   void *uctx)
{
	trunk_connection_t	*tconn = talloc_get_type_abort(uctx, trunk_connection_t);
	trunk_t		*trunk = tconn->pub.trunk;

	/*
	 *	If a connection was just connected, it should only
	 *	have a pending list of requests.  This state is found
	 *	in the rlm_radius module, which starts a new trunk,
	 *	and then immediately enqueues a request onto it.  The
	 *	alternative for rlm_radius is to keep it's own queue
	 *	of pending requests before the trunk is fully
	 *	initialized.  And then enqueue them onto the trunk
	 *	when the trunk is connected.
	 *
	 *	It's instead easier (and makes more sense) to allow
	 *	the trunk to accept packets into its queue.  If there
	 *	are no connections within a period of time, then the
	 *	requests will retry, or will time out.
	 */
	fr_assert(trunk_request_count_by_connection(tconn, TRUNK_REQUEST_STATE_ALL) == trunk_request_count_by_connection(tconn, TRUNK_REQUEST_STATE_PENDING));

 	/*
	 *	Set here, as the active state can
	 *	be transitioned to from full and
	 *	draining too.
	 */
	trunk->pub.last_connected = fr_time();

	/*
	 *	Insert a timer to reconnect the
	 *	connection periodically.
	 */
	if (fr_time_delta_ispos(trunk->conf.lifetime)) {
		if (fr_timer_in(tconn, trunk->el->tl, &tconn->lifetime_ev,
				trunk->conf.lifetime, false, _trunk_connection_lifetime_expire, tconn) < 0) {
			PERROR("Failed inserting connection reconnection timer event, halting connection");
			connection_signal_shutdown(tconn->pub.conn);
			return;
		}
	}

 	trunk_connection_enter_active(tconn);
}

/** Connection failed after it was connected
 *
 * Reflect the connection state change in the lists we use to track connections.
 *
 * @note This function is only called from the connection API as a watcher.
 *
 * @param[in] conn	The connection which changes state.
 * @param[in] prev	The connection is was in.
 * @param[in] state	The connection is now in.
 * @param[in] uctx	The trunk_connection_t wrapping the connection.
 */
static void _trunk_connection_on_closed(UNUSED connection_t *conn,
			  		UNUSED connection_state_t prev,
					UNUSED connection_state_t state,
					void *uctx)
{
	trunk_connection_t	*tconn = talloc_get_type_abort(uctx, trunk_connection_t);
	trunk_t		*trunk = tconn->pub.trunk;
	bool			need_requeue = false;

	switch (tconn->pub.state) {
	case TRUNK_CONN_ACTIVE:
	case TRUNK_CONN_FULL:
	case TRUNK_CONN_INACTIVE:
	case TRUNK_CONN_INACTIVE_DRAINING:
	case TRUNK_CONN_DRAINING:
	case TRUNK_CONN_DRAINING_TO_FREE:
		need_requeue = true;
		trunk_connection_remove(tconn);
		break;

	case TRUNK_CONN_INIT:			/* Initialisation failed */
	case TRUNK_CONN_CONNECTING:
		trunk_connection_remove(tconn);
		fr_assert(trunk_request_count_by_connection(tconn, TRUNK_REQUEST_STATE_ALL) == 0);
		break;

	case TRUNK_CONN_CLOSED:
	case TRUNK_CONN_HALTED:	/* Can't move backwards? */
		CONN_BAD_STATE_TRANSITION(TRUNK_CONN_CLOSED);
	}

	fr_dlist_insert_head(&trunk->closed, tconn);	/* MUST remain a head insertion for reconnect logic */
	CONN_STATE_TRANSITION(TRUNK_CONN_CLOSED, INFO);

	/*
	 *	Now *AFTER* the connection has been
	 *	removed from the active, pool
	 *	re-enqueue the requests.
	 */
	if (need_requeue) trunk_connection_requests_requeue_priv(tconn, TRUNK_REQUEST_STATE_ALL, 0, true);

	/*
	 *	There should be no requests left on this
	 *	connection.  They should have all been
	 *	moved off or failed.
	 */
	fr_assert(trunk_request_count_by_connection(tconn, TRUNK_REQUEST_STATE_ALL) == 0);

	/*
	 *	Clear statistics and flags
	 */
	tconn->sent_count = 0;

	/*
	 *	Remove the reconnect event
	 */
	if (fr_time_delta_ispos(trunk->conf.lifetime)) FR_TIMER_DELETE(&tconn->lifetime_ev);

	/*
	 *	Remove the I/O events
	 */
	trunk_connection_event_update(tconn);
}

/** Connection failed
 *
 * @param[in] conn	The connection which changes state.
 * @param[in] prev	The connection is was in.
 * @param[in] state	The connection is now in.
 * @param[in] uctx	The trunk_connection_t wrapping the connection.
 */
static void _trunk_connection_on_failed(connection_t *conn,
					connection_state_t prev,
					connection_state_t state,
					void *uctx)
{
	trunk_connection_t	*tconn = talloc_get_type_abort(uctx, trunk_connection_t);
	trunk_t		*trunk = tconn->pub.trunk;

	/*
	 *	Need to set this first as it
	 *	determines whether requests are
	 *	re-queued or fail outright.
	 */
	trunk->pub.last_failed = fr_time();

	/*
	 *	Failed in the init state, transition the
	 *	connection to closed, else we get an
	 *	INIT -> INIT transition which triggers
	 *	an assert.
	 */
	if (prev == CONNECTION_STATE_INIT) _trunk_connection_on_closed(conn, prev, state, uctx);

	/*
	 *	See what the state of the trunk is
	 *	if there are no connections that could
	 *	potentially accept requests in the near
	 *	future, then fail all the requests in the
	 *	trunk backlog.
	 */
	if ((state == CONNECTION_STATE_CONNECTED) &&
	    (trunk_connection_count_by_state(trunk,
						(TRUNK_CONN_ACTIVE |
						 TRUNK_CONN_FULL |
						 TRUNK_CONN_DRAINING)) == 0)) trunk_backlog_drain(trunk);
}

/** Connection transitioned to the halted state
 *
 * Remove the connection remove all lists, as it's likely about to be freed.
 *
 * Setting the trunk back to the init state ensures that if the code is ever
 * refactored and #connection_signal_reconnect is used after a connection
 * is halted, then everything is maintained in a valid state.
 *
 * @note This function is only called from the connection API as a watcher.
 *
 * @param[in] conn	The connection which changes state.
 * @param[in] prev	The connection is was in.
 * @param[in] state	The connection is now in.
 * @param[in] uctx	The trunk_connection_t wrapping the connection.
 */
static void _trunk_connection_on_halted(UNUSED connection_t *conn,
					UNUSED connection_state_t prev,
					UNUSED connection_state_t state,
					void *uctx)
{
	trunk_connection_t	*tconn = talloc_get_type_abort(uctx, trunk_connection_t);
	trunk_t		*trunk = tconn->pub.trunk;

	switch (tconn->pub.state) {
	case TRUNK_CONN_INIT:
	case TRUNK_CONN_CLOSED:
		trunk_connection_remove(tconn);
		break;

	default:
		CONN_BAD_STATE_TRANSITION(TRUNK_CONN_HALTED);
	}

	/*
	 *	It began life in the halted state,
	 *	and will end life in the halted state.
	 */
	CONN_STATE_TRANSITION(TRUNK_CONN_HALTED, DEBUG2);

	/*
	 *	There should be no requests left on this
	 *	connection.  They should have all been
	 *	moved off or failed.
	 */
	fr_assert(trunk_request_count_by_connection(tconn, TRUNK_REQUEST_STATE_ALL) == 0);

	/*
	 *	And free the connection...
	 */
	if (trunk->in_handler) {
		/*
		 *	...later.
		 */
		fr_dlist_insert_tail(&trunk->to_free, tconn);
		return;
	}
	talloc_free(tconn);
}

/** Free a connection
 *
 * Enforces orderly free order of children of the tconn
 */
static int _trunk_connection_free(trunk_connection_t *tconn)
{
	fr_assert(tconn->pub.state == TRUNK_CONN_HALTED);
	fr_assert(!fr_dlist_entry_in_list(&tconn->entry));	/* Should not be in a list */

	/*
	 *	Loop over all the requests we gathered
	 *	and transition them to the failed state,
	 *	freeing them.
	 *
	 *	Usually, requests will be re-queued when
	 *	a connection enters the closed state,
	 *	but in this case because the whole trunk
	 *	is being freed, we don't bother, and
	 *	just signal to the API client that the
	 *	requests failed.
	 */
	if (tconn->pub.trunk->freeing) {
		fr_dlist_head_t	to_fail;
		trunk_request_t *treq = NULL;

		fr_dlist_talloc_init(&to_fail, trunk_request_t, entry);

		/*
		 *	Remove requests from this connection
		 */
		trunk_connection_requests_dequeue(&to_fail, tconn, TRUNK_REQUEST_STATE_ALL, 0);
		while ((treq = fr_dlist_next(&to_fail, treq))) {
			trunk_request_t *prev;

			prev = fr_dlist_remove(&to_fail, treq);
			trunk_request_enter_failed(treq);
			treq = prev;
		}
	}

	/*
	 *	Ensure we're not signalled by the connection
	 *	as it processes its backlog of state changes,
	 *	as we are about to be freed.
	 */
	connection_del_watch_pre(tconn->pub.conn, CONNECTION_STATE_INIT, _trunk_connection_on_init);
	connection_del_watch_post(tconn->pub.conn, CONNECTION_STATE_CONNECTING, _trunk_connection_on_connecting);
	connection_del_watch_post(tconn->pub.conn, CONNECTION_STATE_CONNECTED, _trunk_connection_on_connected);
	connection_del_watch_pre(tconn->pub.conn, CONNECTION_STATE_CLOSED, _trunk_connection_on_closed);
	connection_del_watch_post(tconn->pub.conn, CONNECTION_STATE_SHUTDOWN, _trunk_connection_on_shutdown);
	connection_del_watch_pre(tconn->pub.conn, CONNECTION_STATE_FAILED, _trunk_connection_on_failed);
	connection_del_watch_post(tconn->pub.conn, CONNECTION_STATE_HALTED, _trunk_connection_on_halted);

	/*
	 *	This may return -1, indicating the free was deferred
	 *	this is fine.  It just means the conn will be freed
	 *	after all the handlers have exited.
	 */
	(void)talloc_free(tconn->pub.conn);
	tconn->pub.conn = NULL;

	return 0;
}

/** Attempt to spawn a new connection
 *
 * Calls the API client's alloc() callback to create a new connection_t,
 * then inserts the connection into the 'connecting' list.
 *
 * @param[in] trunk	to spawn connection in.
 * @param[in] now	The current time.
 */
static int trunk_connection_spawn(trunk_t *trunk, fr_time_t now)
{
	trunk_connection_t	*tconn;


	/*
	 *	Call the API client's callback to create
	 *	a new connection_t.
	 */
	MEM(tconn = talloc_zero(trunk, trunk_connection_t));
	tconn->pub.trunk = trunk;
	tconn->pub.state = TRUNK_CONN_HALTED;	/* All connections start in the halted state */

	/*
	 *	Allocate a new connection_t or fail.
	 */
	DO_CONNECTION_ALLOC(tconn);

	MEM(tconn->pending = fr_heap_talloc_alloc(tconn, _trunk_request_prioritise, trunk_request_t, heap_id, 0));
	fr_dlist_talloc_init(&tconn->sent, trunk_request_t, entry);
	fr_dlist_talloc_init(&tconn->reapable, trunk_request_t, entry);
	fr_dlist_talloc_init(&tconn->cancel, trunk_request_t, entry);
	fr_dlist_talloc_init(&tconn->cancel_sent, trunk_request_t, entry);

	/*
	 *	OK, we have the connection, now setup watch
	 *	points so we know when it changes state.
	 *
	 *	This lets us automatically move the tconn
	 *	between the different lists in the trunk
	 *	with minimum extra code.
	 */
	connection_add_watch_pre(tconn->pub.conn, CONNECTION_STATE_INIT,
				    _trunk_connection_on_init, false, tconn);		/* Before init() has been called */

	connection_add_watch_post(tconn->pub.conn, CONNECTION_STATE_CONNECTING,
				     _trunk_connection_on_connecting, false, tconn);	/* After init() has been called */

	connection_add_watch_post(tconn->pub.conn, CONNECTION_STATE_CONNECTED,
				     _trunk_connection_on_connected, false, tconn);	/* After open() has been called */

	connection_add_watch_pre(tconn->pub.conn, CONNECTION_STATE_CLOSED,
				    _trunk_connection_on_closed, false, tconn);		/* Before close() has been called */

	connection_add_watch_pre(tconn->pub.conn, CONNECTION_STATE_FAILED,
				    _trunk_connection_on_failed, false, tconn);		/* Before failed() has been called */

	connection_add_watch_post(tconn->pub.conn, CONNECTION_STATE_SHUTDOWN,
				     _trunk_connection_on_shutdown, false, tconn);	/* After shutdown() has been called */

	connection_add_watch_post(tconn->pub.conn, CONNECTION_STATE_HALTED,
				     _trunk_connection_on_halted, false, tconn);	/* About to be freed */

	talloc_set_destructor(tconn, _trunk_connection_free);

	connection_signal_init(tconn->pub.conn);	/* annnnd GO! */

	trunk->pub.last_open = now;

	return 0;
}

/** Pop a cancellation request off a connection's cancellation queue
 *
 * The request we return is advanced by the request moving out of the
 * cancel state and into the cancel_sent or cancel_complete state.
 *
 * One of these signalling functions must be called after the request
 * has been popped:
 *
 * - #trunk_request_signal_cancel_sent
 *   The remote datastore has been informed, but we need to wait for acknowledgement.
 *   The #trunk_request_demux_t callback must handle the acks calling
 *   #trunk_request_signal_cancel_complete when an ack is received.
 *
 * - #trunk_request_signal_cancel_complete
 *   The request was cancelled and we don't need to wait, clean it up immediately.
 *
 * @param[out] treq_out	to process
 * @param[in] tconn	Connection to drain cancellation request from.
 * @return
 *	- 1 if no more requests.
 *	- 0 if a new request was written to treq_out.
 *	- -1 if the connection was previously freed.  Caller *MUST NOT* touch any
 *	  memory or requests associated with the connection.
 *	- -2 if called outside of the cancel muxer.
 */
int trunk_connection_pop_cancellation(trunk_request_t **treq_out, trunk_connection_t *tconn)
{
	if (unlikely(tconn->pub.state == TRUNK_CONN_HALTED)) return -1;

	if (!fr_cond_assert_msg(IN_REQUEST_CANCEL_MUX(tconn->pub.trunk),
				"%s can only be called from within request_cancel_mux handler",
				__FUNCTION__)) return -2;

	*treq_out = tconn->cancel_partial ? tconn->cancel_partial : fr_dlist_head(&tconn->cancel);
	if (!*treq_out) return 1;

	return 0;
}

/** Pop a request off a connection's pending queue
 *
 * The request we return is advanced by the request moving out of the partial or
 * pending states, when the mux function signals us.
 *
 * If the same request is returned again and again, it means the muxer isn't actually
 * doing anything with the request we returned, and it's and error in the muxer code.
 *
 * One of these signalling functions must be used after the request has been popped:
 *
 * - #trunk_request_signal_complete
 *   The request was completed. Either we got a synchronous response, or we knew the
 *   response without contacting an external server (cache).
 *
 * - #trunk_request_signal_fail
 *   Failed muxing the request due to a permanent issue, i.e. an invalid request.
 *
 * - #trunk_request_signal_partial
 *   Wrote part of a request.  This request will be returned on the next call to this
 *   function so that the request_mux function can finish writing it. Only useful
 *   for stream type connections.  Datagram type connections cannot have partial
 *   writes.
 *
 * - #trunk_request_signal_sent Successfully sent a request.
 *
 * @param[out] treq_out	to process
 * @param[in] tconn	to pop a request from.
 * @return
 *	- 1 if no more requests.
 *	- 0 if a new request was written to treq_out.
 *	- -1 if the connection was previously freed.  Caller *MUST NOT* touch any
 *	  memory or requests associated with the connection.
 *	- -2 if called outside of the muxer.
 */
int trunk_connection_pop_request(trunk_request_t **treq_out, trunk_connection_t *tconn)
{
	if (unlikely(tconn->pub.state == TRUNK_CONN_HALTED)) return -1;

	if (!fr_cond_assert_msg(IN_REQUEST_MUX(tconn->pub.trunk),
				"%s can only be called from within request_mux handler",
				__FUNCTION__)) return -2;

	*treq_out = tconn->partial ? tconn->partial : fr_heap_peek(tconn->pending);
	if (!*treq_out) return 1;

	return 0;
}

/** Signal that a trunk connection is writable
 *
 * Should be called from the 'write' I/O handler to signal that requests can be enqueued.
 *
 * @param[in] tconn to signal.
 */
void trunk_connection_signal_writable(trunk_connection_t *tconn)
{
	trunk_t *trunk = tconn->pub.trunk;

	if (!fr_cond_assert_msg(!IN_HANDLER(tconn->pub.trunk),
				"%s cannot be called within a handler", __FUNCTION__)) return;

	DEBUG3("[%" PRIu64 "] Signalled writable", tconn->pub.conn->id);

	trunk_connection_writable(tconn);
}

/** Signal that a trunk connection is readable
 *
 * Should be called from the 'read' I/O handler to signal that requests should be dequeued.
 *
 * @param[in] tconn to signal.
 */
void trunk_connection_signal_readable(trunk_connection_t *tconn)
{
	trunk_t *trunk = tconn->pub.trunk;

	if (!fr_cond_assert_msg(!IN_HANDLER(tconn->pub.trunk),
				"%s cannot be called within a handler", __FUNCTION__)) return;

	DEBUG3("[%" PRIu64 "] Signalled readable", tconn->pub.conn->id);

	trunk_connection_readable(tconn);
}

/** Signal a trunk connection cannot accept more requests
 *
 * @param[in] tconn to signal.
 */
void trunk_connection_signal_inactive(trunk_connection_t *tconn)
{
	/* Can be called anywhere */

	switch (tconn->pub.state) {
	case TRUNK_CONN_ACTIVE:
	case TRUNK_CONN_FULL:
		trunk_connection_enter_inactive(tconn);
		break;

	case TRUNK_CONN_DRAINING:
		trunk_connection_enter_inactive_draining(tconn);
		break;

	default:
		return;
	}
}

/** Signal a trunk connection is no longer full
 *
 * @param[in] tconn to signal.
 */
void trunk_connection_signal_active(trunk_connection_t *tconn)
{
	switch (tconn->pub.state) {
	case TRUNK_CONN_FULL:
		trunk_connection_auto_unfull(tconn);	/* Mark as active if it should be active */
		break;

	case TRUNK_CONN_INACTIVE:
		/*
		 *	Do the appropriate state transition based on
		 *	how many requests the trunk connection is
		 *	currently servicing.
		 */
		if (trunk_connection_is_full(tconn)) {
			trunk_connection_enter_full(tconn);
			break;
		}
		trunk_connection_enter_active(tconn);
		break;

	/*
	 *	Unsetting the active flag just moves
	 *	the connection back to the normal
	 *	draining state.
	 */
	case TRUNK_CONN_INACTIVE_DRAINING:		/* Only an external signal can trigger this transition */
		trunk_connection_enter_draining(tconn);
		break;

	default:
		return;
	}
}

/** Signal a trunk connection is no longer viable
 *
 * @param[in] tconn	to signal.
 * @param[in] reason	the connection is being reconnected.
 */
void trunk_connection_signal_reconnect(trunk_connection_t *tconn, connection_reason_t reason)
{
	connection_signal_reconnect(tconn->pub.conn, reason);
}

/** Standard I/O read function
 *
 * Underlying FD in now readable, so call the trunk to read any pending requests
 * from this connection.
 *
 * @param[in] el	The event list signalling.
 * @param[in] fd	that's now readable.
 * @param[in] flags	describing the read event.
 * @param[in] uctx	The trunk connection handle (tconn).
 */
void trunk_connection_callback_readable(UNUSED fr_event_list_t *el, UNUSED int fd, UNUSED int flags, void *uctx)
{
	trunk_connection_t	*tconn = talloc_get_type_abort(uctx, trunk_connection_t);

	trunk_connection_signal_readable(tconn);
}

/** Standard I/O write function
 *
 * Underlying FD is now writable, so call the trunk to write any pending requests
 * to this connection.
 *
 * @param[in] el	The event list signalling.
 * @param[in] fd	that's now writable.
 * @param[in] flags	describing the write event.
 * @param[in] uctx	The trunk connection handle (tcon).
 */
void trunk_connection_callback_writable(UNUSED fr_event_list_t *el, UNUSED int fd, UNUSED int flags, void *uctx)
{
	trunk_connection_t	*tconn = talloc_get_type_abort(uctx, trunk_connection_t);

	trunk_connection_signal_writable(tconn);
}


/** Returns true if the trunk connection is in one of the specified states
 *
 * @param[in] tconn	To check state for.
 * @param[in] state	to check
 * @return
 *	- True if trunk connection is in a particular state.
 *	- False if trunk connection is not in a particular state.
 */
bool trunk_connection_in_state(trunk_connection_t *tconn, int state)
{
	return (bool)(tconn->pub.state & state);
}

/** Close connections in a particular connection list if they have no requests associated with them
 *
 * @param[in] trunk	containing connections we want to close.
 * @param[in] head	of list of connections to examine.
 */
static void trunk_connection_close_if_empty(trunk_t *trunk, fr_dlist_head_t *head)
{
	trunk_connection_t *tconn = NULL;

	while ((tconn = fr_dlist_next(head, tconn))) {
		trunk_connection_t *prev;

		if (trunk_request_count_by_connection(tconn, TRUNK_REQUEST_STATE_ALL) != 0) continue;

		prev = fr_dlist_prev(head, tconn);

		DEBUG3("Closing %s connection with no requests",
		       fr_table_str_by_value(trunk_connection_states, tconn->pub.state, "<INVALID>"));
		/*
		 *	Close the connection as gracefully
		 *	as possible by signalling it should
		 *	shutdown.
		 *
		 *	The connection, should, if serviced
		 *	correctly by the underlying library,
		 *	automatically transition to halted after
		 *	all pending reads/writes are
		 *	complete at which point we'll be informed
		 *	and free our tconn wrapper.
		 */
		connection_signal_shutdown(tconn->pub.conn);
		tconn = prev;
	}
}

/** Rebalance connections across active trunk members when a new connection becomes active
 *
 * We don't have any visibility into the connection prioritisation algorithm
 * it's essentially a black box.
 *
 * We can however determine when the correct level of requests per connection
 * has been reached, by dequeuing and requeing  requests up until the point
 * where the connection that just had a request dequeued, receives the same
 * request back.
 *
 * @param[in] trunk	The trunk to rebalance.
 */
static void trunk_rebalance(trunk_t *trunk)
{
	trunk_connection_t	*head;

	head = fr_minmax_heap_min_peek(trunk->active);

	/*
	 *	Only rebalance if the top and bottom of
	 *	the heap are not equal.
	 */
	if (trunk->funcs.connection_prioritise(fr_minmax_heap_max_peek(trunk->active), head) == 0) return;

	DEBUG3("Rebalancing requests");

	/*
	 *	Keep requeuing requests from the connection
	 *	at the bottom of the heap until the
	 *	connection at the top is shifted from that
	 *	position.
	 */
	while ((fr_minmax_heap_min_peek(trunk->active) == head) &&
	       trunk_connection_requests_requeue_priv(fr_minmax_heap_max_peek(trunk->active),
	       					      TRUNK_REQUEST_STATE_PENDING, 1, false));
}

/** Implements the algorithm we use to manage requests per connection levels
 *
 * This is executed periodically using a timer event, and opens/closes
 * connections.
 *
 * The aim is to try and keep the request per connection level in a sweet spot,
 * where there's enough outstanding work for the connection/pipelining to work
 * efficiently, but not so much so that we encounter increased latency.
 *
 * In the request enqueue and dequeue functions we record every time the
 * average number of requests per connection goes above the target count
 * and record every time the average number of requests per connection goes
 * below the target count.
 *
 * This may sound expensive, but in all cases we're just summing counters.
 * CPU time required does not increase with additional requests, only with
 * large numbers of connections.
 *
 * If we do encounter scaling issues, we can always maintain the counters
 * as aggregates as an optimisation later.
 *
 * If when the management function runs, the trunk was above the target
 * most recently, we:
 * - Return if we've been in this state for a shorter period than 'open_delay'.
 * - Return if we're at max.
 * - Return if opening a new connection will take us below the load target.
 * - Return if we last opened a connection within 'open_delay'.
 * - Otherwise we attempt to open a new connection.
 *
 * If the trunk we below the target most recently, we:
 * - Return if we've been in this state for a shorter period than 'close_delay'.
 * - Return if we're at min.
 * - Return if we have no connections.
 * - Close a connection if min is 0, and we have no outstanding
 *   requests.  Then return.
 * - Return if closing a new connection will take us above the load target.
 * - Return if we last closed a connection within 'closed_delay'.
 * - Otherwise we move a connection to draining state.
 */
static void trunk_manage(trunk_t *trunk, fr_time_t now)
{
	trunk_connection_t	*tconn = NULL;
	trunk_request_t	*treq;
	uint32_t		average = 0;
	uint32_t		req_count;
	uint16_t		conn_count;
	trunk_state_t	new_state;

	DEBUG4("Managing trunk");

	/*
	 *	Cleanup requests in our request cache which
	 *	have been reapable for too long.
	 */
	while ((treq = fr_dlist_tail(&trunk->free_requests)) &&
	       fr_time_lteq(fr_time_add(treq->last_freed, trunk->conf.req_cleanup_delay), now)) talloc_free(treq);

	/*
	 *	If we have idle connections, then close them.
	 */
	if (fr_time_delta_ispos(trunk->conf.idle_timeout)) {
		fr_minmax_heap_iter_t	iter;
		fr_time_t idle_cutoff = fr_time_sub(now, trunk->conf.idle_timeout);

		for (tconn = fr_minmax_heap_iter_init(trunk->active, &iter);
		     tconn;
		     tconn = fr_minmax_heap_iter_next(trunk->active, &iter)) {
			/*
			 *	The connection has outstanding requests without replies, don't do anything.
			 */
			if (fr_heap_num_elements(tconn->pending) > 0) continue;

			/*
			 *	The connection was last active after the idle cutoff time, don't do anything.
			 */
			if (fr_time_gt(tconn->pub.last_write_success, idle_cutoff)) continue;

			/*
			 *	This connection has been inactive since before the idle timeout.  Drain it,
			 *	and free it.
			 */
			trunk_connection_enter_draining_to_free(tconn);
		}
	}

	/*
	 *	Free any connections which have drained
	 *	and we didn't reactivate during the last
	 *	round of management.
	 */
	trunk_connection_close_if_empty(trunk, &trunk->inactive_draining);
	trunk_connection_close_if_empty(trunk, &trunk->draining);
	trunk_connection_close_if_empty(trunk, &trunk->draining_to_free);

	/*
	 *	Process deferred connection freeing
	 */
	if (!trunk->in_handler) {
		while ((tconn = fr_dlist_head(&trunk->to_free))) talloc_free(fr_dlist_remove(&trunk->to_free, tconn));
	}

	/*
	 *	Update the state of the trunk
	 */
	if (trunk_connection_count_by_state(trunk, TRUNK_CONN_ACTIVE)) {
		new_state = TRUNK_STATE_ACTIVE;
	} else {
		/*
		 *	INIT / CONNECTING / FULL mean connections will become active
		 *	so the trunk is PENDING
		 */
		new_state = trunk_connection_count_by_state(trunk, TRUNK_CONN_INIT |
							       TRUNK_CONN_CONNECTING |
							       TRUNK_CONN_FULL) ?
			     TRUNK_STATE_PENDING : TRUNK_STATE_IDLE;
	}

	if (new_state != trunk->pub.state) TRUNK_STATE_TRANSITION(new_state);

	/*
	 *	A trunk can be signalled to not proactively
	 *	manage connections if a destination is known
	 *	to be unreachable, and doing so would result
	 *	in spurious connections still being opened.
	 *
	 *	We still run other connection management
	 *	functions and just short circuit the function
	 *	here.
	 */
	if (!trunk->managing_connections) return;

	/*
	 *	We're above the target requests per connection
	 *	spawn more connections!
	 */
	if (fr_time_gteq(trunk->pub.last_above_target, trunk->pub.last_below_target)) {
		/*
		 *	If connecting is provided, check we
		 *	wouldn't have too many connections in
		 *	the connecting state.
		 *
		 *	This is a throttle in the case of transitory
		 *	load spikes, or a backend becoming
		 *	unavailable.
		 */
		if ((trunk->conf.connecting > 0) &&
		    (trunk_connection_count_by_state(trunk, TRUNK_CONN_CONNECTING) >=
		     trunk->conf.connecting)) {
			DEBUG4("Not opening connection - Too many (%u) connections in the connecting state",
			       trunk->conf.connecting);
			return;
		}

		trunk_requests_per_connection(&conn_count, &req_count, trunk, now, true);

		/*
		 *	Only apply hysteresis if we have at least
		 *	one available connection.
		 */
		if (conn_count && fr_time_gt(fr_time_add(trunk->pub.last_above_target, trunk->conf.open_delay), now)) {
			DEBUG4("Not opening connection - Need to be above target for %pVs.  It's been %pVs",
			       fr_box_time_delta(trunk->conf.open_delay),
			       fr_box_time_delta(fr_time_sub(now, trunk->pub.last_above_target)));
			return;	/* too soon */
		}

		/*
		 *	We don't consider 'draining' connections
		 *	in the max calculation, as if we do
		 *	determine that we need to spawn a new
		 *	request, then we'd move all 'draining'
		 *	connections to active before spawning
		 *	any new connections.
		 */
		if ((trunk->conf.max > 0) && (conn_count >= trunk->conf.max)) {
			DEBUG4("Not opening connection - Have %u connections, need %u or below",
			       conn_count, trunk->conf.max);
			return;
		}

		/*
		 *	We consider requests pending on all connections
		 *      and the trunk's backlog as that's the current count
		 *	load.
		 */
		if (!req_count) {
			DEBUG4("Not opening connection - No outstanding requests");
			return;
		}

		/*
		 *	Do the n+1 check, i.e. if we open one connection
		 *	will that take us below our target threshold.
		 */
		if (conn_count > 0) {
			average = ROUND_UP_DIV(req_count, (conn_count + 1));
			if (average < trunk->conf.target_req_per_conn) {
				DEBUG4("Not opening connection - Would leave us below our target requests "
				       "per connection (now %u, after open %u)",
				       ROUND_UP_DIV(req_count, conn_count), average);
				return;
			}
		} else {
			(void)trunk_connection_spawn(trunk, now);
			return;
		}

		/*
		 *	If we've got a connection in the draining list
		 *      move it back into the active list if we've
		 *      been requested to add a connection back in.
		 */
		tconn = fr_dlist_head(&trunk->draining);
		if (tconn) {
			if (trunk_connection_is_full(tconn)) {
				trunk_connection_enter_full(tconn);
			} else {
				trunk_connection_enter_active(tconn);
			}
			return;
		}

		/*
		 *	Implement delay if there's no connections that
		 *	could be immediately re-activated.
		 */
		if (fr_time_gt(fr_time_add(trunk->pub.last_open, trunk->conf.open_delay), now)) {
			DEBUG4("Not opening connection - Need to wait %pVs before opening another connection.  "
			       "It's been %pVs",
			       fr_box_time_delta(trunk->conf.open_delay),
			       fr_box_time_delta(fr_time_sub(now, trunk->pub.last_open)));
			return;
		}

		DEBUG4("Opening connection - Above target requests per connection (now %u, target %u)",
		       ROUND_UP_DIV(req_count, conn_count), trunk->conf.target_req_per_conn);
		/* last_open set by trunk_connection_spawn */
		(void)trunk_connection_spawn(trunk, now);
	}

	/*
	 *	We're below the target requests per connection.
	 *	Free some connections...
	 */
	else if (fr_time_gt(trunk->pub.last_below_target, trunk->pub.last_above_target)) {
		if (fr_time_gt(fr_time_add(trunk->pub.last_below_target, trunk->conf.close_delay), now)) {
			DEBUG4("Not closing connection - Need to be below target for %pVs. It's been %pVs",
			       fr_box_time_delta(trunk->conf.close_delay),
			       fr_box_time_delta(fr_time_sub(now, trunk->pub.last_below_target)));
			return;	/* too soon */
		}

		trunk_requests_per_connection(&conn_count, &req_count, trunk, now, true);

		if (!conn_count) {
			DEBUG4("Not closing connection - No connections to close!");
			return;
		}

		if ((trunk->conf.min > 0) && ((conn_count - 1) < trunk->conf.min)) {
			DEBUG4("Not closing connection - Have %u connections, need %u or above",
			       conn_count, trunk->conf.min);
			return;
		}

		if (!req_count) {
			DEBUG4("Closing connection - No outstanding requests");
			goto close;
		}

		/*
		 *	The minimum number of connections must be set
		 *	to zero for this to work.
		 *	min == 0, no requests, close all the connections.
		 *      This is useful for backup databases, when
		 *	maintaining the connection would lead to lots of
		 *	log file churn.
		 */
		if (conn_count == 1) {
			DEBUG4("Not closing connection - Would leave connections "
			       "and there are still %u outstanding requests", req_count);
			return;
		}

		/*
		 *	Do the n-1 check, i.e. if we close one connection
		 *	will that take us above our target threshold.
		 */
		average = ROUND_UP_DIV(req_count, (conn_count - 1));
		if (average > trunk->conf.target_req_per_conn) {
			DEBUG4("Not closing connection - Would leave us above our target requests per connection "
			       "(now %u, after close %u)", ROUND_UP_DIV(req_count, conn_count), average);
			return;
		}

		DEBUG4("Closing connection - Below target requests per connection (now %u, target %u)",
		       ROUND_UP_DIV(req_count, conn_count), trunk->conf.target_req_per_conn);

	close:
		if (fr_time_gt(fr_time_add(trunk->pub.last_closed, trunk->conf.close_delay), now)) {
			DEBUG4("Not closing connection - Need to wait %pVs before closing another connection.  "
			       "It's been %pVs",
			       fr_box_time_delta(trunk->conf.close_delay),
			       fr_box_time_delta(fr_time_sub(now, trunk->pub.last_closed)));
			return;
		}

		/*
		 *	If the last event on the trunk was a connection failure and
		 *	there is only one connection, this may well be a reconnect
		 *	attempt after a failure - and needs to persist otherwise
		 *	the last event will be a failure and no new connection will
		 *	be made, leading to no new requests being enqueued.
		 */
		if (fr_time_gt(trunk->pub.last_failed, fr_time_wrap(0)) &&
		    fr_time_lt(trunk->pub.last_connected, trunk->pub.last_failed) && (conn_count == 1)) {
			DEBUG4("Not closing remaining connection - last event was a failure");
			return;
		}

		/*
		 *	Inactive connections get counted in the
		 *	set of viable connections, but are likely
		 *	to be congested or dead, so we drain
		 *	(and possibly eventually free) those first.
		 */
		if ((tconn = fr_dlist_tail(&trunk->inactive))) {
			/*
			 *	If the connection has no requests associated
			 *	with it then immediately free.
			 */
			if (trunk_request_count_by_connection(tconn, TRUNK_REQUEST_STATE_ALL) == 0) {
				connection_signal_halt(tconn->pub.conn);	/* Also frees the tconn */
			} else {
				trunk_connection_enter_inactive_draining(tconn);
			}
		/*
		 *	It is possible to have too may connecting
		 *	connections when the connections are
		 *	taking a while to open and the number
		 *	of requests decreases.
		 */
		} else if ((tconn = fr_dlist_tail(&trunk->connecting))) {
			connection_signal_halt(tconn->pub.conn);	/* Also frees the tconn */

		/*
		 *	Finally if there are no "connecting"
		 *	connections to close, and no "inactive"
		 *	connections, start draining "active"
		 *	connections.
		 */
		} else if ((tconn = fr_minmax_heap_max_peek(trunk->active))) {
			/*
			 *	If the connection has no requests associated
			 *	with it then immediately free.
			 */
			if (trunk_request_count_by_connection(tconn, TRUNK_REQUEST_STATE_ALL) == 0) {
				connection_signal_halt(tconn->pub.conn);	/* Also frees the tconn */
			} else {
				trunk_connection_enter_draining(tconn);
			}
		}

		trunk->pub.last_closed = now;

		return;
	}
}

/** Event to periodically call the connection management function
 *
 * @param[in] tl	this event belongs to.
 * @param[in] now	current time.
 * @param[in] uctx	The trunk.
 */
static void _trunk_timer(fr_timer_list_t *tl, fr_time_t now, void *uctx)
{
	trunk_t *trunk = talloc_get_type_abort(uctx, trunk_t);

	trunk_manage(trunk, now);

	if (fr_time_delta_ispos(trunk->conf.manage_interval)) {
		if (fr_timer_in(trunk, tl, &trunk->manage_ev, trunk->conf.manage_interval,
			false, _trunk_timer, trunk) < 0) {
			PERROR("Failed inserting trunk management event");
			/* Not much we can do, hopefully the trunk will be freed soon */
		}
	}
}

/** Return a count of requests on a connection in a specific state
 *
 * @param[in] trunk		to retrieve counts for.
 * @param[in] conn_state	One or more connection states or'd together.
 * @param[in] req_state		One or more request states or'd together.
 * @return The number of requests in a particular state, on connection in a particular state.
 */
uint64_t trunk_request_count_by_state(trunk_t *trunk, int conn_state, int req_state)
{
	uint64_t		count = 0;
	trunk_connection_t	*tconn = NULL;
	fr_minmax_heap_iter_t	iter;

#define COUNT_BY_STATE(_state, _list) \
do { \
	if (conn_state & (_state)) { \
		tconn = NULL; \
		while ((tconn = fr_dlist_next(&trunk->_list, tconn))) { \
			count += trunk_request_count_by_connection(tconn, req_state); \
		} \
	} \
} while (0)

	if (conn_state & TRUNK_CONN_ACTIVE) {
		for (tconn = fr_minmax_heap_iter_init(trunk->active, &iter);
		     tconn;
		     tconn = fr_minmax_heap_iter_next(trunk->active, &iter)) {
			count += trunk_request_count_by_connection(tconn, req_state);
		}
	}

	COUNT_BY_STATE(TRUNK_CONN_FULL, full);
	COUNT_BY_STATE(TRUNK_CONN_INACTIVE, inactive);
	COUNT_BY_STATE(TRUNK_CONN_INACTIVE_DRAINING, inactive_draining);
	COUNT_BY_STATE(TRUNK_CONN_DRAINING, draining);
	COUNT_BY_STATE(TRUNK_CONN_DRAINING_TO_FREE, draining_to_free);

	if (req_state & TRUNK_REQUEST_STATE_BACKLOG) count += fr_heap_num_elements(trunk->backlog);

	return count;
}

/** Update timestamps for when we last had a transition from above target to below target or vice versa
 *
 * Should be called on every time a connection or request is allocated or freed.
 *
 * @param[out] conn_count_out	How many connections we considered.
 * @param[out] req_count_out	How many requests we considered.
 * @param[in] trunk		to operate on.
 * @param[in] now		The current time.
 * @param[in] verify		if true (and this is a debug build), then assert if req_per_conn
 *				has changed.
 * @return
 *	- 0 if the average couldn't be calculated (no requests or no connections).
 *	- The average number of requests per connection.
 */
static uint64_t trunk_requests_per_connection(uint16_t *conn_count_out, uint32_t *req_count_out,
					      trunk_t *trunk, fr_time_t now,
					      NDEBUG_UNUSED bool verify)
{
	uint32_t req_count = 0;
	uint16_t conn_count = 0;
	uint64_t req_per_conn = 0;

	fr_assert(fr_time_gt(now, fr_time_wrap(0)));

	/*
	 *	No need to update these as the trunk is being freed
	 */
	if (trunk->freeing) goto done;

	/*
	 *	Count all connections except draining and draining to free.
	 *
	 *	Omitting these connection states artificially raises the
	 *	request to connection ratio, so that we can preemptively spawn
	 *	new connections.
	 *
	 *	In the case of TRUNK_CONN_DRAINING | TRUNK_CONN_INACTIVE_DRAINING
	 *	the trunk management code has enough hysteresis to not
	 *	immediately reactivate the connection.
	 *
	 *	In the case of TRUNK_CONN_DRAINING_TO_FREE the trunk
	 *	management code should spawn a new connection to takes its place.
	 *
	 *	Connections placed in the DRAINING_TO_FREE state are being
	 *	closed preemptively to deal with bugs on the server we're
	 *	talking to, or misconfigured firewalls which are trashing
	 *	TCP/UDP connection states.
	 */
	conn_count = trunk_connection_count_by_state(trunk, TRUNK_CONN_ALL ^
							(TRUNK_CONN_DRAINING |
							 TRUNK_CONN_INACTIVE_DRAINING |
							 TRUNK_CONN_DRAINING_TO_FREE));

	/*
	 *	Requests on all connections
	 */
	req_count = trunk_request_count_by_state(trunk,
						    TRUNK_CONN_ALL ^
						    TRUNK_CONN_DRAINING_TO_FREE, TRUNK_REQUEST_STATE_ALL);

	/*
	 *	No connections, but we do have requests
	 */
	if (conn_count == 0) {
		if ((req_count > 0) && (trunk->conf.target_req_per_conn > 0)) goto above_target;
		goto done;
	}

	if (req_count == 0) {
		if (trunk->conf.target_req_per_conn > 0) goto below_target;
		goto done;
	}

	/*
	 *	Calculate the req_per_conn
	 */
	req_per_conn = ROUND_UP_DIV(req_count, conn_count);
	if (req_per_conn > trunk->conf.target_req_per_conn) {
	above_target:
		/*
		 *	Edge - Below target to above target (too many requests per conn - spawn more)
		 *
		 *	The equality check is correct here as both values start at 0.
		 */
		if (fr_time_lteq(trunk->pub.last_above_target, trunk->pub.last_below_target)) trunk->pub.last_above_target = now;
	} else if (req_per_conn < trunk->conf.target_req_per_conn) {
	below_target:
		/*
		 *	Edge - Above target to below target (too few requests per conn - close some)
		 *
		 *	The equality check is correct here as both values start at 0.
		 */
		if (fr_time_lteq(trunk->pub.last_below_target, trunk->pub.last_above_target)) trunk->pub.last_below_target = now;
	}

done:
	if (conn_count_out) *conn_count_out = conn_count;
	if (req_count_out) *req_count_out = req_count;

	/*
	 *	Check we haven't missed a call to trunk_requests_per_connection
	 */
	fr_assert(!verify || (trunk->last_req_per_conn == 0) || (req_per_conn == trunk->last_req_per_conn));

	trunk->last_req_per_conn = req_per_conn;

	return req_per_conn;
}

/** Drain the backlog of as many requests as possible
 *
 * @param[in] trunk	To drain backlog requests for.
 */
static void trunk_backlog_drain(trunk_t *trunk)
{
	trunk_request_t *treq;

	if (fr_heap_num_elements(trunk->backlog) == 0) return;

	/*
	 *	If it's always writable, this isn't
	 *	really a noteworthy event.
	 */
	if (!trunk->conf.always_writable) DEBUG3("Draining backlog of requests");

	/*
	 *	Do *NOT* add an artificial limit
	 *	here.  We rely on all available
	 *	connections entering the full
	 *	state and transitioning back to
	 *	active in order to drain the
	 *	backlog.
	 */
	while ((treq = fr_heap_peek(trunk->backlog))) {
		switch (trunk_request_enqueue_existing(treq)) {
		case TRUNK_ENQUEUE_OK:
			continue;

		/*
		 *	Signal to stop
		 */
		case TRUNK_ENQUEUE_IN_BACKLOG:
			break;

		/*
		 *	Failed enqueueing the request,
		 *	have it enter the failed state
		 *	which will free it and
		 *	re-enliven the yielded request.
		 */
		case TRUNK_ENQUEUE_DST_UNAVAILABLE:
		case TRUNK_ENQUEUE_FAIL:
			trunk_request_enter_failed(treq);
			continue;

		case TRUNK_ENQUEUE_NO_CAPACITY:
			fr_assert(fr_minmax_heap_num_elements(trunk->active) == 0);
			return;
		}
	}
}

/** Force the trunk to re-establish its connections
 *
 * @param[in] trunk		to signal.
 * @param[in] states		One or more states or'd together.
 * @param[in] reason		Why the connections are being signalled to reconnect.
 */
void trunk_reconnect(trunk_t *trunk, int states, connection_reason_t reason)
{

#define RECONNECT_BY_STATE(_state, _list) \
do { \
	if (states & (_state)) { \
		size_t i; \
		for (i = fr_dlist_num_elements(&trunk->_list); i > 0; i--) { \
			connection_signal_reconnect(((trunk_connection_t *)fr_dlist_tail(&trunk->_list))->pub.conn, reason); \
		} \
	} \
} while (0)

	/*
	 *	Connections in the 'connecting' state
	 *	may re-enter that state, so we need to
	 *	be careful not to enter an infinite
	 *	loop, as we iterate over the list
	 *	again and again.
	 */
	RECONNECT_BY_STATE(TRUNK_CONN_CONNECTING, connecting);

	if (states & TRUNK_CONN_ACTIVE) {
		trunk_connection_t *tconn;
		while ((tconn = fr_minmax_heap_min_peek(trunk->active))) connection_signal_reconnect(tconn->pub.conn, reason);
	}

	RECONNECT_BY_STATE(TRUNK_CONN_INIT, init);
	RECONNECT_BY_STATE(TRUNK_CONN_FULL, full);
	RECONNECT_BY_STATE(TRUNK_CONN_INACTIVE, inactive);
	RECONNECT_BY_STATE(TRUNK_CONN_INACTIVE_DRAINING, inactive_draining);
	RECONNECT_BY_STATE(TRUNK_CONN_CLOSED, closed);
	RECONNECT_BY_STATE(TRUNK_CONN_DRAINING, draining);
	RECONNECT_BY_STATE(TRUNK_CONN_DRAINING_TO_FREE, draining_to_free);
}

/** Start the trunk running
 *
 */
int trunk_start(trunk_t *trunk)
{
	uint16_t i;

	if (unlikely(trunk->started)) return 0;

	/*
	 *	Spawn the initial set of connections
	 */
	for (i = 0; i < trunk->conf.start; i++) {
		DEBUG("[%i] Starting initial connection", i);
		if (trunk_connection_spawn(trunk, fr_time()) != 0) return -1;
	}

	/*
	 *	If the idle timeout is set, AND there's no management interval, OR the management interval is
	 *	less than the idle timeout, update the management interval.
	 */
	if (fr_time_delta_ispos(trunk->conf.idle_timeout) &&
	    (!fr_time_delta_ispos(trunk->conf.manage_interval) ||
	    fr_time_delta_gt(trunk->conf.manage_interval, trunk->conf.idle_timeout))) {
		trunk->conf.manage_interval = trunk->conf.idle_timeout;
	}

	if (fr_time_delta_ispos(trunk->conf.manage_interval)) {
		/*
		 *	Insert the event timer to manage
		 *	the interval between managing connections.
		 */
		if (fr_timer_in(trunk, trunk->el->tl, &trunk->manage_ev, trunk->conf.manage_interval,
				false, _trunk_timer, trunk) < 0) {
			PERROR("Failed inserting trunk management event");
			return -1;
		}
	}
	trunk->started = true;
	trunk->managing_connections = true;

	return 0;
}

/** Allow the trunk to open and close connections in response to load
 *
 */
void trunk_connection_manage_start(trunk_t *trunk)
{
	if (!trunk->started || trunk->managing_connections) return;

	DEBUG3("Connection management enabled");
	trunk->managing_connections = true;
}

/** Stop the trunk from opening and closing connections in response to load
 *
 */
void trunk_connection_manage_stop(trunk_t *trunk)
{
	if (!trunk->started || !trunk->managing_connections) return;

	DEBUG3("Connection management disabled");
	trunk->managing_connections = false;
}

/** Schedule a trunk management event for the next time the event loop is executed
 */
int trunk_connection_manage_schedule(trunk_t *trunk)
{
	if (!trunk->started || !trunk->managing_connections) return 0;

	if (fr_timer_in(trunk, trunk->el->tl, &trunk->manage_ev, fr_time_delta_wrap(0),
			false, _trunk_timer, trunk) < 0) {
		PERROR("Failed inserting trunk management event");
		return -1;
	}

	return 0;
}

/** Order connections by queue depth
 *
 */
static int8_t _trunk_connection_order_by_shortest_queue(void const *one, void const *two)
{
	trunk_connection_t const	*a = talloc_get_type_abort_const(one, trunk_connection_t);
	trunk_connection_t const	*b = talloc_get_type_abort_const(two, trunk_connection_t);

	uint32_t			a_count = trunk_request_count_by_connection(a, TRUNK_REQUEST_STATE_ALL);
	uint32_t			b_count = trunk_request_count_by_connection(b, TRUNK_REQUEST_STATE_ALL);

	/*
	 *	Add a fudge factor of 1 to reduce spurious rebalancing
	 */
	return ((a_count > b_count) && ((a_count - b_count) > 1)) - ((b_count > a_count) && ((b_count - a_count) > 1));
}

/** Free a trunk, gracefully closing all connections.
 *
 */
static int _trunk_free(trunk_t *trunk)
{
	trunk_connection_t	*tconn;
	trunk_request_t	*treq;
	trunk_watch_entry_t	*watch;
	size_t			i;

	DEBUG4("Trunk free %p", trunk);

	trunk->freeing = true;	/* Prevent re-enqueuing */

	/*
	 *	We really don't want this firing after
	 *	we've freed everything.
	 */
	FR_TIMER_DELETE_RETURN(&trunk->manage_ev);

	/*
	 *	Now free the connections in each of the lists.
	 *
	 *	Each time a connection is freed it removes itself from the list
	 *	its in, which means the head should keep advancing automatically.
	 */
	while ((tconn = fr_minmax_heap_min_peek(trunk->active))) connection_signal_halt(tconn->pub.conn);
	while ((tconn = fr_dlist_head(&trunk->init))) connection_signal_halt(tconn->pub.conn);
	while ((tconn = fr_dlist_head(&trunk->connecting))) connection_signal_halt(tconn->pub.conn);
	while ((tconn = fr_dlist_head(&trunk->full))) connection_signal_halt(tconn->pub.conn);
	while ((tconn = fr_dlist_head(&trunk->inactive))) connection_signal_halt(tconn->pub.conn);
	while ((tconn = fr_dlist_head(&trunk->inactive_draining))) connection_signal_halt(tconn->pub.conn);
	while ((tconn = fr_dlist_head(&trunk->closed))) connection_signal_halt(tconn->pub.conn);
	while ((tconn = fr_dlist_head(&trunk->draining))) connection_signal_halt(tconn->pub.conn);
	while ((tconn = fr_dlist_head(&trunk->draining_to_free))) connection_signal_halt(tconn->pub.conn);

	/*
	 *	Process any deferred connection frees
	 */
	while ((tconn = fr_dlist_head(&trunk->to_free))) talloc_free(fr_dlist_remove(&trunk->to_free, tconn));

	/*
	 *	Free any requests left in the backlog
	 */
	while ((treq = fr_heap_peek(trunk->backlog))) trunk_request_enter_failed(treq);

	/*
	 *	Free any requests in our request cache
	 */
	while ((treq = fr_dlist_head(&trunk->free_requests))) talloc_free(treq);

	/*
	 *	Free any entries in the watch lists
	 */
	for (i = 0; i < NUM_ELEMENTS(trunk->watch); i++) {
		while ((watch = fr_dlist_pop_head(&trunk->watch[i]))) talloc_free(watch);
	}

	return 0;
}

/** Allocate a new collection of connections
 *
 * This function should be called first to allocate a new trunk connection.
 *
 * After the trunk has been allocated, #trunk_request_alloc and
 * #trunk_request_enqueue should be used to allocate memory for trunk
 * requests, and pass a preq (protocol request) to the trunk for
 * processing.
 *
 * The trunk will then asynchronously process the request, writing the result
 * to a specified rctx.  See #trunk_request_enqueue for more details.
 *
 * @note Trunks may not be shared between multiple threads under any circumstances.
 *
 * @param[in] ctx		To use for any memory allocations.  Must be thread local.
 * @param[in] el		to use for I/O and timer events.
 * @param[in] funcs		Callback functions.
 * @param[in] conf		Common user configurable parameters.
 * @param[in] log_prefix	To prepend to global messages.
 * @param[in] uctx		User data to pass to the alloc function.
 * @param[in] delay_start	If true, then we will not spawn any connections
 *				until the first request is enqueued.
 * @param[in] trigger_args	Pairs to pass to trigger requests, if triggers are enabled.
 * @return
 *	- New trunk handle on success.
 *	- NULL on error.
 */
trunk_t *trunk_alloc(TALLOC_CTX *ctx, fr_event_list_t *el,
			   trunk_io_funcs_t const *funcs, trunk_conf_t const *conf,
			   char const *log_prefix, void const *uctx, bool delay_start, fr_pair_list_t *trigger_args)
{
	trunk_t	*trunk;
	size_t		i;

	/*
	 *	Check we have the functions we need
	 */
	if (!fr_cond_assert(funcs->connection_alloc)) return NULL;

	MEM(trunk = talloc_zero(ctx, trunk_t));
	trunk->el = el;
	trunk->log_prefix = talloc_strdup(trunk, log_prefix);
	trunk->trigger_args = trigger_args;

	memcpy(&trunk->funcs, funcs, sizeof(trunk->funcs));
	if (!trunk->funcs.connection_prioritise) {
		trunk->funcs.connection_prioritise = _trunk_connection_order_by_shortest_queue;
	}
	if (!trunk->funcs.request_prioritise) trunk->funcs.request_prioritise = fr_pointer_cmp;

	memcpy(&trunk->conf, conf, sizeof(trunk->conf));

	memcpy(&trunk->uctx, &uctx, sizeof(trunk->uctx));
	talloc_set_destructor(trunk, _trunk_free);

	/*
	 *	Unused request list...
	 */
	fr_dlist_talloc_init(&trunk->free_requests, trunk_request_t, entry);

	/*
	 *	Request backlog queue
	 */
	MEM(trunk->backlog = fr_heap_talloc_alloc(trunk, _trunk_request_prioritise,
						   trunk_request_t, heap_id, 0));

	/*
	 *	Connection queues and trees
	 */
	MEM(trunk->active = fr_minmax_heap_talloc_alloc(trunk, trunk->funcs.connection_prioritise,
						  trunk_connection_t, heap_id, 0));
	fr_dlist_talloc_init(&trunk->init, trunk_connection_t, entry);
	fr_dlist_talloc_init(&trunk->connecting, trunk_connection_t, entry);
	fr_dlist_talloc_init(&trunk->full, trunk_connection_t, entry);
	fr_dlist_talloc_init(&trunk->inactive, trunk_connection_t, entry);
	fr_dlist_talloc_init(&trunk->inactive_draining, trunk_connection_t, entry);
	fr_dlist_talloc_init(&trunk->closed, trunk_connection_t, entry);
	fr_dlist_talloc_init(&trunk->draining, trunk_connection_t, entry);
	fr_dlist_talloc_init(&trunk->draining_to_free, trunk_connection_t, entry);
	fr_dlist_talloc_init(&trunk->to_free, trunk_connection_t, entry);

	/*
	 *	Watch lists
	 */
	for (i = 0; i < NUM_ELEMENTS(trunk->watch); i++) {
		fr_dlist_talloc_init(&trunk->watch[i], trunk_watch_entry_t, entry);
	}

	DEBUG4("Trunk allocated %p", trunk);

	if (!delay_start) {
		if (trunk_start(trunk) < 0) {
			talloc_free(trunk);
			return NULL;
		}
	}

	return trunk;
}

/** Check for a module trigger section when parsing the `triggers` option.
 *
 */
int trunk_trigger_cf_parse(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, conf_parser_t const *rule)
{
	trunk_conf_t	*conf = parent;
	CONF_SECTION	*cs = cf_item_to_section(cf_parent(ci));

	if (cf_pair_parse_value(ctx, out, parent, ci, rule)< 0) return -1;

	/*
	 *	If the parent section of the `triggers` option contains a trigger
	 *	section then store it as the module CONF SECTION for the appropriate
	 *	trigger group.
	 */
	if (cf_section_find(cs, "trigger", NULL)) {
		if (strcmp(cf_section_name(cs), "request") == 0) {
			conf->req_trigger_cs = cs;
		} else {
			conf->conn_trigger_cs = cs;
		}
	}

	return 0;
}

#ifndef TALLOC_GET_TYPE_ABORT_NOOP
/** Verify a trunk
 *
 * A trunk has some number of connections, which each have some number of requests. The connections and
 * requests are in differing kinds of containers depending on their state and how they are used, and may
 * have fields that can only be validated by comparison with a parent.  We had planned on passing a "context"
 * down with the ancestral values, but that breaks the foo_verify() API. Each foo_verify() will only verify the
 * foo's children.
 */
void trunk_verify(char const *file, int line, trunk_t *trunk)
{
	fr_fatal_assert_msg(trunk, "CONSISTENCY CHECK FAILED %s[%i]: trunk_t pointer was NULL", file, line);
	(void) talloc_get_type_abort(trunk, trunk_t);

	for (size_t i = 0; i < NUM_ELEMENTS(trunk->watch); i++) {
		_fr_dlist_verify(file, line, &trunk->watch[i]);
	}

#define IO_FUNC_VERIFY(_func) \
	fr_fatal_assert_msg(trunk->funcs._func, "CONSISTENCY_CHECK_FAILED %s[%i}: " #_func " was NULL", file, line)

	/*
	 *	Only a few of the function pointers *must* be non-NULL..
	 */
	IO_FUNC_VERIFY(connection_alloc);
	IO_FUNC_VERIFY(connection_prioritise);
	IO_FUNC_VERIFY(request_prioritise);

#define TRUNK_TCONN_CHECKS(_tconn, _state) \
do { \
	fr_fatal_assert_msg(trunk == _tconn->pub.trunk, \
			    "CONSISTENCY_CHECK_FAILED %s[%i}: connection-trunk mismatch", file, line); \
	fr_fatal_assert_msg(_state == _tconn->pub.state, \
			    "CONSISTENCY_CHECK_FAILED %s[%i}: connection-state mismatch", file, line); \
} while (0)

#define TCONN_DLIST_VERIFY(_dlist, _state) \
do { \
	_fr_dlist_verify(file, line, &(trunk->_dlist)); \
	fr_dlist_foreach(&(trunk->_dlist), trunk_connection_t, tconn)  { \
		trunk_connection_verify(file, line, tconn); \
		TRUNK_TCONN_CHECKS(tconn, _state); \
	} \
} while (0)

#define TCONN_MINMAX_HEAP_VERIFY(_heap, _state) \
do {\
	fr_minmax_heap_verify(file, line, trunk->_heap); \
	fr_minmax_heap_foreach(trunk->_heap, trunk_connection_t, tconn) { \
		trunk_connection_verify(file, line, tconn); \
		TRUNK_TCONN_CHECKS(tconn, _state); \
	}} \
} while (0)

	fr_dlist_verify(&(trunk->free_requests));
	FR_HEAP_VERIFY(trunk->backlog);

	TCONN_DLIST_VERIFY(init, TRUNK_CONN_INIT);
	TCONN_DLIST_VERIFY(connecting, TRUNK_CONN_CONNECTING);
	TCONN_MINMAX_HEAP_VERIFY(active, TRUNK_CONN_ACTIVE);
	TCONN_DLIST_VERIFY(full, TRUNK_CONN_FULL);
	TCONN_DLIST_VERIFY(inactive, TRUNK_CONN_INACTIVE);
	TCONN_DLIST_VERIFY(inactive_draining, TRUNK_CONN_INACTIVE_DRAINING);
	/* TCONN_DLIST_VERIFY(failed, ???); */
	TCONN_DLIST_VERIFY(closed, TRUNK_CONN_CLOSED);
	TCONN_DLIST_VERIFY(draining, TRUNK_CONN_DRAINING);
	TCONN_DLIST_VERIFY(draining_to_free, TRUNK_CONN_DRAINING_TO_FREE);
	TCONN_DLIST_VERIFY(to_free, TRUNK_CONN_HALTED);
}

void trunk_connection_verify(char const *file, int line, trunk_connection_t *tconn)
{
	fr_fatal_assert_msg(tconn, "CONSISTENCY CHECK FAILED %s[%i]: trunk_connection_t pointer was NULL", file, line);
	(void) talloc_get_type_abort(tconn, trunk_connection_t);

	(void) talloc_get_type_abort(tconn->pub.trunk, trunk_t);

	/*
	 *	shouldn't be both in heap and on list--but it doesn't look like moves
	 *	to active heap wipe the dlist pointers.
	 */

#define TCONN_TREQ_CHECKS(_treq, _state) \
do { \
	fr_fatal_assert_msg(tconn == _treq->pub.tconn, \
			    "CONSISTENCY_CHECK_FAILED %s[%i}: trunk request-tconn mismatch", file, line); \
	fr_fatal_assert_msg(tconn->pub.trunk == _treq->pub.trunk, \
			    "CONSISTENCY_CHECK_FAILED %s[%i}: trunk request-trunk mismatch", file, line); \
	fr_fatal_assert_msg(_state == _treq->pub.state, \
			    "CONSISTENCY_CHECK_FAILED %s[%i}: trunk request-state mismatch", file, line); \
} while (0)

#define TREQ_DLIST_VERIFY(_dlist, _state) \
do { \
	_fr_dlist_verify(file, line, &(tconn->_dlist)); \
	fr_dlist_foreach(&(tconn->_dlist), trunk_request_t, treq)  { \
		trunk_request_verify(file, line, treq); \
		TCONN_TREQ_CHECKS(treq, _state); \
	} \
} while (0)

#define TREQ_HEAP_VERIFY(_heap, _state) \
do { \
	fr_heap_iter_t _iter; \
	fr_heap_verify(file, line, tconn->_heap); \
	for (trunk_request_t *treq = fr_heap_iter_init(tconn->_heap, &_iter); \
	     treq; \
	     treq = fr_heap_iter_next(tconn->_heap, &_iter)) { \
		trunk_request_verify(file, line, treq); \
		TCONN_TREQ_CHECKS(treq, _state); \
	} \
} while (0)

#define TREQ_OPTION_VERIFY(_option, _state) \
do { \
	if (tconn->_option) { \
		trunk_request_verify(file, line, tconn->_option); \
		TCONN_TREQ_CHECKS(tconn->_option, _state); \
	} \
} while (0)

	/* verify associated requests */
	TREQ_HEAP_VERIFY(pending, TRUNK_REQUEST_STATE_PENDING);
	TREQ_DLIST_VERIFY(sent, TRUNK_REQUEST_STATE_SENT);
	TREQ_DLIST_VERIFY(cancel, TRUNK_REQUEST_STATE_CANCEL);
	TREQ_DLIST_VERIFY(cancel_sent, TRUNK_REQUEST_STATE_CANCEL_SENT);
	TREQ_OPTION_VERIFY(partial, TRUNK_REQUEST_STATE_PARTIAL);
	TREQ_OPTION_VERIFY(cancel_partial, TRUNK_REQUEST_STATE_CANCEL_PARTIAL);
}

void trunk_request_verify(char const *file, int line, trunk_request_t *treq)
{
	fr_fatal_assert_msg(treq, "CONSISTENCY CHECK FAILED %s[%i]: trunk_request_t pointer was NULL", file, line);
	(void) talloc_get_type_abort(treq, trunk_request_t);

#ifdef WITH_VERIFY_PTR
	if (treq->pub.request) request_verify(file, line, treq->pub.request);
#endif
}


bool trunk_search(trunk_t *trunk, void *ptr)
{
#define TCONN_DLIST_SEARCH(_dlist) \
do { \
	fr_dlist_foreach(&(trunk->_dlist), trunk_connection_t, tconn)  { \
		if (ptr == tconn) { \
			fr_fprintf(stderr, "trunk_search: tconn %p on " #_dlist "\n", ptr); \
			return true; \
		} \
		if (trunk_connection_search(tconn, ptr)) { \
			fr_fprintf(stderr, " in tconn %p on " #_dlist "\n", tconn); \
			return true; \
		} \
	} \
} while (0)

#define TCONN_MINMAX_HEAP_SEARCH(_heap) \
do { \
	fr_minmax_heap_foreach(trunk->_heap, trunk_connection_t, tconn) { \
		if (ptr == tconn) { \
			fr_fprintf(stderr, "trunk_search: tconn %p on " #_heap "\n", ptr); \
			return true; \
		} \
		if (trunk_connection_search(tconn, ptr)) { \
			fr_fprintf(stderr, " on tconn %p on " #_heap "\n", tconn); \
			return true; \
		} \
	}}\
} while (0)

	TCONN_DLIST_SEARCH(init);
	TCONN_DLIST_SEARCH(connecting);
	TCONN_MINMAX_HEAP_SEARCH(active);
	TCONN_DLIST_SEARCH(full);
	TCONN_DLIST_SEARCH(inactive);
	TCONN_DLIST_SEARCH(inactive_draining);
	TCONN_DLIST_SEARCH(failed);
	TCONN_DLIST_SEARCH(closed);
	TCONN_DLIST_SEARCH(draining);
	TCONN_DLIST_SEARCH(draining_to_free);
	TCONN_DLIST_SEARCH(to_free);

	return false;
}

bool trunk_connection_search(trunk_connection_t *tconn, void *ptr)
{
#define TREQ_DLIST_SEARCH(_dlist) \
do { \
	fr_dlist_foreach(&(tconn->_dlist), trunk_request_t, treq)  { \
		if (ptr == treq) { \
			fr_fprintf(stderr, "trunk_search: treq %p on " #_dlist "\n", ptr); \
			return true; \
		} \
		if (trunk_request_search(treq, ptr)) { \
			fr_fprintf(stderr, "trunk_search: preq %p found on " #_dlist, ptr); \
			return true; \
		} \
	} \
} while (0)

#define TREQ_HEAP_SEARCH(_heap) \
do { \
	fr_heap_iter_t _iter; \
	for (trunk_request_t *treq = fr_heap_iter_init(tconn->_heap, &_iter); \
	     treq; \
	     treq = fr_heap_iter_next(tconn->_heap, &_iter)) { \
		if (ptr == treq) { \
			fr_fprintf(stderr, "trunk_search: treq %p in " #_heap "\n", ptr); \
			return true; \
		} \
		if (trunk_request_search(treq, ptr)) { \
			fr_fprintf(stderr, "trunk_search: preq %p found in " #_heap, ptr); \
			return true; \
		} \
	} \
} while (0)

#define TREQ_OPTION_SEARCH(_option) \
do { \
	if (tconn->_option) { \
		if (ptr == tconn->_option) { \
			fr_fprintf(stderr, "trunk_search: treq %p is " #_option "\n", ptr); \
			return true; \
		} \
		if (trunk_request_search(tconn->_option, ptr)) { \
			fr_fprintf(stderr, "trunk_search: preq %p found in " #_option, ptr); \
			return true; \
		} \
	} \
} while (0)

	/* search associated requests */
	TREQ_HEAP_SEARCH(pending);
	TREQ_DLIST_SEARCH(sent);
	TREQ_DLIST_SEARCH(cancel);
	TREQ_DLIST_SEARCH(cancel_sent);
	TREQ_OPTION_SEARCH(partial);
	TREQ_OPTION_SEARCH(cancel_partial);

	return false;
}

bool trunk_request_search(trunk_request_t *treq, void *ptr)
{
	return treq->pub.preq == ptr;
}
#endif
