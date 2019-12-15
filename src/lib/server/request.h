#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @file lib/server/request.h
 * @brief The main request structure, and allocation functions.
 *
 * @copyright 1999-2018 The FreeRADIUS server project
 */
RCSIDH(request_h, "$Id$")

/*
 *	Forward declarations to avoid dependency loops
 */
#ifdef __cplusplus
extern "C" {
#endif

typedef struct fr_async_s fr_async_t;
typedef struct fr_request_s REQUEST;

typedef struct rad_listen rad_listen_t;
typedef struct rad_client RADCLIENT;

#ifdef __cplusplus
}
#endif

#include <freeradius-devel/server/log.h>
#include <freeradius-devel/server/main_config.h>
#include <freeradius-devel/server/rcode.h>
#include <freeradius-devel/server/signal.h>
#include <freeradius-devel/util/event.h>
#include <freeradius-devel/util/heap.h>
#include <freeradius-devel/util/packet.h>
#include <freeradius-devel/util/dlist.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef NDEBUG
#  define REQUEST_MAGIC (0xdeadbeef)
#endif

typedef enum {
	REQUEST_ACTIVE = 1,
	REQUEST_STOP_PROCESSING,
	REQUEST_COUNTED
} rad_master_state_t;
#define REQUEST_MASTER_NUM_STATES (REQUEST_COUNTED + 1)

typedef enum fr_request_state_t {
	REQUEST_INIT = 0,
	REQUEST_RECV,
	REQUEST_PROCESS,
	REQUEST_SEND,
	REQUEST_OTHER_1,
	REQUEST_OTHER_2,
	REQUEST_OTHER_3,
	REQUEST_OTHER_4,
} fr_request_state_t;

typedef	void (*fr_request_process_t)(REQUEST *, fr_state_signal_t);	//!< Function handler for requests.
typedef	rlm_rcode_t (*RAD_REQUEST_FUNP)(REQUEST *);

struct fr_request_s {
#ifndef NDEBUG
	uint32_t		magic; 		//!< Magic number used to detect memory corruption,
						//!< or request structs that have not been properly initialised.
#endif
	uint64_t		number; 	//!< Monotonically increasing request number. Reset on server restart.
	uint64_t		child_number; 	//!< Monotonically increasing number for children of this request
	char const		*name;		//!< for debug printing, as (%d) is no longer sufficient

	fr_dict_t const		*dict;		//!< Dictionary of the protocol that this request belongs to.

	fr_event_list_t		*el;		//!< thread-specific event list.
	fr_heap_t		*backlog;	//!< thread-specific backlog
	fr_request_state_t	request_state;	//!< state for the various protocol handlers.

	fr_dlist_head_t		data;		//!< Request metadata.

	rad_listen_t		*listener;	//!< The listener that received the request.
	RADCLIENT		*client;	//!< The client that originally sent us the request.

	RADIUS_PACKET		*packet;	//!< Incoming request.
	RADIUS_PACKET		*reply;		//!< Outgoing response.

	VALUE_PAIR		*control;	//!< #VALUE_PAIR (s) used to set per request parameters
						//!< for modules and the server core at runtime.

	uint64_t		seq_start;	//!< State sequence ID.  Stable identifier for a sequence of requests
						//!< and responses.
	TALLOC_CTX		*state_ctx;	//!< for request->state
	VALUE_PAIR		*state;		//!< #VALUE_PAIR (s) available over the lifetime of the authentication
						//!< attempt. Useful where the attempt involves a sequence of
						//!< many request/challenge packets, like OTP, and EAP.

	rad_master_state_t	master_state;	//!< Set by the master thread to signal the child that's currently
						//!< working with the request, to do something.

	REQUEST			*proxy;		//!< proxied packet

	fr_request_process_t	process;	//!< The function to call to move the request through the state machine.

	rlm_rcode_t		rcode;		//!< Last rcode returned by a module
	CONF_SECTION		*server_cs;	//!< virtual server which is processing the request.

	char const		*component; 	//!< Section the request is in.
	char const		*module;	//!< Module the request is currently being processed by.

	void			*stack;		//!< unlang interpreter stack.

	REQUEST			*parent;

	fr_event_timer_t const	*ev;		//!< Event in event loop tied to this request.

	int32_t			runnable_id;	//!< entry in the queue / heap of runnable packets
	int32_t			time_order_id;	//!< entry in the queue / heap of time ordered packets

	main_config_t const	*config;	//!< Pointer to the main config hack to try and deal with hup.

	struct {
		log_dst_t	*dst;		//!< First in a list of log destinations.

		fr_log_lvl_t	lvl;		//!< Log messages with lvl >= to this should be logged.

		uint8_t		unlang_indent;	//!< By how much to indent log messages. uin8_t so it's obvious
						//!< when a request has been exdented too much.
		uint8_t		module_indent;	//!< Indentation after the module prefix name.
	} log;

	uint32_t		options;	//!< mainly for proxying EAP-MSCHAPv2.

	fr_async_t		*async;		//!< for new async listeners

	fr_dlist_t		free_entry;	//!< Request's entry in the free list.
};				/* REQUEST typedef */

#ifdef WITH_VERIFY_PTR
#  define REQUEST_VERIFY(_x) request_verify(__FILE__, __LINE__, _x)
#else
/*
 *  Even if were building without WITH_VERIFY_PTR
 *  the pointer must not be NULL when these various macros are used
 *  so we can add some sneaky asserts.
 */
#  define REQUEST_VERIFY(_x) rad_assert(_x)
#endif


#define RAD_REQUEST_LVL_NONE	(0)		//!< No debug messages should be printed.
#define RAD_REQUEST_LVL_DEBUG	(1)
#define RAD_REQUEST_LVL_DEBUG2	(2)
#define RAD_REQUEST_LVL_DEBUG3	(3)
#define RAD_REQUEST_LVL_DEBUG4	(4)

#define RAD_REQUEST_OPTION_CTX	(1 << 1)
#define RAD_REQUEST_OPTION_DETAIL (1 << 2)

REQUEST		*request_alloc(TALLOC_CTX *ctx);

REQUEST		*request_local_alloc(TALLOC_CTX *ctx);

REQUEST		*request_alloc_fake(REQUEST *parent, fr_dict_t const *namespace);

REQUEST		*request_alloc_detachable(REQUEST *request, fr_dict_t const *namespace);

int		request_detach(REQUEST *fake, bool will_free);

#ifdef WITH_VERIFY_PTR
void		request_verify(char const *file, int line, REQUEST const *request);	/* only for special debug builds */
#endif

#ifdef __cplusplus
}
#endif
