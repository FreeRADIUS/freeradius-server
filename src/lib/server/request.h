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

typedef	void (*fr_request_process_t)(request_t *, fr_state_signal_t);	//!< Function handler for requests.
typedef	rlm_rcode_t (*RAD_REQUEST_FUNP)(request_t *);

extern fr_dict_attr_t const *request_attr_root;
extern fr_dict_attr_t const *request_attr_request;
extern fr_dict_attr_t const *request_attr_reply;
extern fr_dict_attr_t const *request_attr_control;
extern fr_dict_attr_t const *request_attr_state;

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

/** Pair lists accessible from the request
 *
 */
typedef struct {
	fr_pair_t		*request;	//!< Pair containing the request list.
	fr_pair_t		*reply;		//!< Pair containing the reply list.
	fr_pair_t		*control;	//!< Pair containing the control list.
	fr_pair_t		*state;		//!< Pair containing the state list.
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

struct request_s {
#ifndef NDEBUG
	uint32_t		magic; 		//!< Magic number used to detect memory corruption,
						//!< or request structs that have not been properly initialised.
#endif
	void			*stack;		//!< unlang interpreter stack.

	request_type_t		type;		//!< What type of request this is.

	request_t		*parent;	//!< Request that generated this request.

	uint64_t		number; 	//!< Monotonically increasing request number. Reset on server restart.
	uint64_t		child_number; 	//!< Monotonically increasing number for children of this request
	char const		*name;		//!< for debug printing, as (%d) is no longer sufficient

	uint64_t		seq_start;	//!< State sequence ID.  Stable identifier for a sequence of requests
						//!< and responses.
	fr_dict_t const		*dict;		//!< Dictionary of the protocol that this request belongs to.

	fr_pair_t		*pair_root;	//!< Root atribute which contains the
						///< other list attributes as children.

	/** Pair lists associated with the request
	 *
	 * @warn DO NOT allocate pairs directly beneath the root
	 *	 or in the ctx of the request.
	 *	 They MUST be allocated beneath their appropriate
	 *	 list attribute.
	 */
	request_pair_lists_t	pair_list;	//!< Structure containing all pair lists.

	fr_dlist_head_t		data;		//!< Request data.

	/** Capabilities flags for this request
	 *
	 */
	struct {
		uint8_t			detachable : 1;		//!< This request may be detached from its parent..
	} flags;

	/** Logging information
	 *
	 */
	struct {
		log_dst_t		*dst;		//!< First in a list of log destinations.

		fr_log_lvl_t		lvl;		//!< Log messages with lvl >= to this should be logged.

		uint8_t			unlang_indent;	//!< By how much to indent log messages. uin8_t so it's obvious
							//!< when a request has been exdented too much.
		uint8_t			module_indent;	//!< Indentation after the module prefix name.
	} log;

	char const		*component; 	//!< Section the request is in.
	char const		*module;	//!< Module the request is currently being processed by.

	fr_radius_packet_t	*packet;	//!< Incoming request.
	fr_radius_packet_t	*reply;		//!< Outgoing response.

	RADCLIENT		*client;	//!< The client that originally sent us the request.

	request_master_state_t	master_state;	//!< Set by the master thread to signal the child that's currently
						//!< working with the request, to do something.

	rlm_rcode_t		rcode;		//!< Last rcode returned by a module

	fr_rb_node_t		dedup_node;	//!< entry in the deduplication tree.
	fr_heap_index_t		runnable_id;	//!< entry in the heap of runnable packets
	fr_heap_index_t		time_order_id;	//!< entry in the heap of time ordered packets

	uint32_t		options;	//!< mainly for proxying EAP-MSCHAPv2.

	fr_async_t		*async;		//!< for new async listeners

	char const		*alloc_file;	//!< File the request was allocated in.

	int			alloc_line;	//!< Line the request was allocated on.

	fr_dlist_t		free_entry;	//!< Request's entry in the free list.
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

/** Allocate a new external request
 *
 * Use for requests produced by listeners
 *
 * @param[in] _ctx	Talloc ctx to bind the request to.
 * @param[in] _args	Optional arguments that control how the request is initialised.
 */
#define		request_alloc_external(_ctx, _args) \
		_request_alloc( __FILE__, __LINE__, (_ctx), REQUEST_TYPE_EXTERNAL, (_args))

/** Allocate a new internal request
 *
 * Use for requests produced by modules and unlang
 *
 * @param[in] _ctx	Talloc ctx to bind the request to.
 * @param[in] _args	Optional arguments that control how the request is initialised.
 */
#define		request_alloc_internal(_ctx, _args) \
		_request_alloc( __FILE__, __LINE__, (_ctx), REQUEST_TYPE_INTERNAL, (_args))

request_t	*_request_alloc(char const *file, int line, TALLOC_CTX *ctx,
				request_type_t type, request_init_args_t const *args);

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

int		request_detach(request_t *child);

int		request_global_init(void);
void		request_global_free(void);

#ifdef WITH_VERIFY_PTR
void		request_verify(char const *file, int line, request_t const *request);	/* only for special debug builds */
#endif

#ifdef __cplusplus
}
#endif
