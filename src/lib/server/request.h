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
typedef struct request_s request_t;

typedef struct fr_client_s fr_client_t;

#ifdef __cplusplus
}
#endif

#include <freeradius-devel/server/log.h>
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

/*
 *	Stack pool +
 *	Stack Frames +
 *	packets +
 *	extra
 */
#define REQUEST_POOL_HEADERS	( \
					1 + \
					UNLANG_STACK_MAX + \
					2 + \
					10 \
				)

/*
 *	Stack memory +
 *	pair lists and root +
 *	packets +
 *	extra
 */
#define REQUEST_POOL_SIZE	( \
					(UNLANG_FRAME_PRE_ALLOC * UNLANG_STACK_MAX) + \
					(sizeof(fr_pair_t) * 5) + \
					(sizeof(fr_packet_t) * 2) + \
					128 \
				)

typedef enum {
	REQUEST_ACTIVE = 1,		//!< Request is active (running or runnable)
	REQUEST_STOP_PROCESSING,	//!< Request has been signalled to stop
	REQUEST_DONE,			//!< Request has completed
} request_master_state_t;
#define REQUEST_MASTER_NUM_STATES (REQUEST_COUNTED + 1)

typedef enum request_state_t {
	REQUEST_INIT = 0,
	REQUEST_RECV,
	REQUEST_PROCESS,
	REQUEST_SEND,
	REQUEST_OTHER_1,
	REQUEST_OTHER_2,
	REQUEST_OTHER_3,
	REQUEST_OTHER_4,
} request_state_t;

extern HIDDEN fr_dict_attr_t const *request_attr_root;
extern fr_dict_attr_t const *request_attr_request;
extern fr_dict_attr_t const *request_attr_reply;
extern fr_dict_attr_t const *request_attr_control;
extern fr_dict_attr_t const *request_attr_state;
extern fr_dict_attr_t const *request_attr_local;

/** Convenience macro for accessing the request list
 *
 * This should be used in the form `&request->request_pairs`
 * to get a pointer to the head of the request list.
 */
#define request_pairs		pair_list.request->children

/** Talloc ctx for allocating request pairs under
 */
#define request_ctx		pair_list.request

/** Convenience macro for accessing the reply list
 *
 * This should be used in the form `&request->reply_pairs`
 * to get a pointer to the head of the request list.
 */
#define	reply_pairs		pair_list.reply->children

/** Talloc ctx for allocating reply pairs under
 */
#define reply_ctx		pair_list.reply

/** Convenience macro for accessing the control list
 *
 * This should be used in the form `&request->control_pairs`
 * to get a pointer to the head of the request list.
 */
#define control_pairs		pair_list.control->children

/** Talloc ctx for allocating control pairs under
 */
#define control_ctx		pair_list.control

/** Convenience macro for accessing the state list
 *
 * This should be used in the form `&request->session_state_pairs`
 * to get a pointer to the head of the request list.
 */
#define session_state_pairs	pair_list.state->children

/** Talloc ctx for allocating reply pairs under
 */
#define session_state_ctx	pair_list.state

/** Convenience macro for accessing the state list
 *
 * This should be used in the form `&request->local_pairs`
 * to get a pointer to the head of the local list.
 */
#define local_pairs	pair_list.local->children

/** Talloc ctx for allocating local variagbles
 */
#define local_ctx	pair_list.local

/** Pair lists accessible from the request
 *
 */
typedef struct {
	fr_pair_t		*request;	//!< Pair containing the request list.
	fr_pair_t		*reply;		//!< Pair containing the reply list.
	fr_pair_t		*control;	//!< Pair containing the control list.
	fr_pair_t		*state;		//!< Pair containing the state list.
	fr_pair_t		*local;		//!< Pair containing local variables
} request_pair_lists_t;

typedef enum {
	REQUEST_TYPE_EXTERNAL = 0,		//!< A request received on the wire.
	REQUEST_TYPE_INTERNAL,			//!< A request generated internally.
	REQUEST_TYPE_DETACHED 			//!< A request that was generated internally, but is now detached
						///< (not associated with a parent request.)
} request_type_t;

#define request_is_external(_x) ((_x)->type == REQUEST_TYPE_EXTERNAL)
#define request_is_internal(_x) ((_x)->type == REQUEST_TYPE_INTERNAL)
#define request_is_detached(_x) ((_x)->type == REQUEST_TYPE_DETACHED)
#define request_is_detachable(_x) ((_x)->flags.detachable)
#define request_is_dynamic_client(_x) ((_x)->flags.dynamic_client)
#define request_set_dynamic_client(_x) ((_x)->flags.dynamic_client = true)

struct request_s {
#ifndef NDEBUG
	uint32_t		magic; 		//!< Magic number used to detect memory corruption,
						//!< or request structs that have not been properly initialised.

	uint64_t		ins_count;	//!< count of instructions we've ran
	uint64_t		ins_max;	//!< max instruction to bail out at

#endif
	void			*stack;		//!< unlang interpreter stack.

	request_type_t		type;		//!< What type of request this is.

	request_t		*parent;	//!< Request that generated this request.

	uint64_t		number; 	//!< Monotonically increasing request number. Reset on server restart.
	uint64_t		child_number; 	//!< Monotonically increasing number for children of this request
	char const		*name;		//!< for debug printing, as (%d) is no longer sufficient

	uint64_t		seq_start;	//!< State sequence ID.  Stable identifier for a sequence of requests
						//!< and responses.
	fr_dict_t const		*proto_dict;   	//!< Dictionary of the protocol that this request belongs to.
	fr_dict_t const		*local_dict;	//!< dictionary for local variables

	fr_pair_t		*pair_root;	//!< Root attribute which contains the
						///< other list attributes as children.

	/** Pair lists associated with the request
	 *
	 * @warning DO NOT allocate pairs directly beneath the root
	 *	    or in the ctx of the request.
	 *	    They MUST be allocated beneath their appropriate
	 *	    list attribute.
	 */
	request_pair_lists_t	pair_list;	//!< Structure containing all pair lists.

	fr_dlist_head_t		data;		//!< Request data.

	/** Capabilities flags for this request
	 *
	 */
	struct {
		uint8_t			detachable : 1;		//!< This request may be detached from its parent..
		uint8_t			dynamic_client : 1;	//!< this is a dynamic client request
	} flags;

	/** Logging information
	 *
	 */
	struct {
		log_dst_t		*dst;		//!< First in a list of log destinations.

		fr_log_lvl_t		lvl;		//!< Log messages with lvl >= to this should be logged.

		rindent_t		indent;		//!< Indentation for log messages.
	} log;

	char const		*component; 	//!< Section the request is in.
	char const		*module;	//!< Module the request is currently being processed by.

	fr_packet_t		*packet;	//!< Incoming request.
	fr_packet_t		*reply;		//!< Outgoing response.

	fr_client_t		*client;	//!< The client that originally sent us the request.

	request_master_state_t	master_state;	//!< Set by the master thread to signal the child that's currently
						//!< working with the request, to do something.
	bool			counted;	//!< Set if the request has been counted in the stats.

	rlm_rcode_t		rcode;		//!< Last rcode returned by a module

	fr_rb_node_t		dedup_node;	//!< entry in the deduplication tree.

	fr_timer_t		*timeout;	//!< Timer event for this request.  This tracks when we need to
						///< forcefully terminate a request.

	uint32_t		options;	//!< mainly for proxying EAP-MSCHAPv2.

	fr_async_t		*async;		//!< for new async listeners

	char const		*alloc_file;	//!< File the request was allocated in.

	int			alloc_line;	//!< Line the request was allocated on.

	fr_dlist_t		listen_entry;	//!< request's entry in the list for this listener / socket

	uint32_t		priority;	//!< higher == higher priority
	uint32_t		sequence;	//!< higher == higher priority, too

	fr_heap_index_t		runnable;	//!< entry in the heap of runnable packets

};				/* request_t typedef */

/** Optional arguments for initialising requests
 *
 */
typedef struct {
	fr_dict_t const		*namespace;	//!< The namespace this request implements.

	request_t		*parent;	//!< If set, the request is a child request used to run
						///< policy sections and additional virtual servers.

	request_pair_lists_t	pair_list;	//!< Alternative pair list heads.
						///< These allow a request to expose nested attributes as
						///< request or reply lists from the parent.

	bool			detachable;	//!< Request should be detachable, i.e. able to run even
						///< if its parent exits.
} request_init_args_t;

#ifdef WITH_VERIFY_PTR
#  define REQUEST_VERIFY(_x) request_verify(__FILE__, __LINE__, _x)
#else
/*
 *  Even if were building without WITH_VERIFY_PTR
 *  the pointer must not be NULL when these various macros are used
 *  so we can add some sneaky asserts.
 */
#  define REQUEST_VERIFY(_x) fr_assert(_x)
#endif

#define RAD_REQUEST_LVL_NONE	(0)		//!< No debug messages should be printed.
#define RAD_REQUEST_LVL_DEBUG	(1)
#define RAD_REQUEST_LVL_DEBUG2	(2)
#define RAD_REQUEST_LVL_DEBUG3	(3)
#define RAD_REQUEST_LVL_DEBUG4	(4)

#define RAD_REQUEST_OPTION_CTX	(1 << 1)
#define RAD_REQUEST_OPTION_DETAIL (1 << 2)

#define		request_init(_ctx, _type, _args) \
		_request_init(__FILE__, __LINE__, _ctx, _type, _args)

int		_request_init(char const *file, int line,
			      request_t *request, request_type_t type,
			      request_init_args_t const *args);

int		request_slab_deinit(request_t *request);

/** Allocate a new external request outside of the request pool
 *
 * @param[in] _ctx	Talloc ctx to allocate the request in.
 * @param[in] _args	Optional arguments that control how the request is initialised.
 */
#define		request_local_alloc_external(_ctx, _args) \
		_request_local_alloc(__FILE__, __LINE__, (_ctx), REQUEST_TYPE_EXTERNAL, (_args))

/** Allocate a new internal request outside of the request pool
 *
 * @param[in] _ctx	Talloc ctx to allocate the request in.
 * @param[in] _args	Optional arguments that control how the request is initialised.
 */
#define		request_local_alloc_internal(_ctx, _args) \
		_request_local_alloc(__FILE__, __LINE__, (_ctx), REQUEST_TYPE_INTERNAL, (_args))

request_t	*_request_local_alloc(char const *file, int line, TALLOC_CTX *ctx,
				      request_type_t type, request_init_args_t const *args);

fr_pair_t	*request_state_replace(request_t *request, fr_pair_t *state) CC_HINT(nonnull(1));

int		request_detach(request_t *child);

int		request_global_init(void);
void		request_global_free(void);

void		request_log_prepend(request_t *request, fr_log_t *log, fr_log_lvl_t lvl);

#ifdef WITH_VERIFY_PTR
void		request_verify(char const *file, int line, request_t const *request);	/* only for special debug builds */
#endif

static inline bool request_attr_is_list(fr_dict_attr_t const *da)
{
	return (da == request_attr_request) ||
		(da == request_attr_reply) ||
		(da == request_attr_control) ||
		(da == request_attr_state) ||
		(da == request_attr_local);
}

#ifdef __cplusplus
}
#endif
