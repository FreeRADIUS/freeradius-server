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
#include <freeradius-devel/io/atomic_queue.h>
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/map.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/trunk.h>
#include <freeradius-devel/util/dlist.h>
#include <freeradius-devel/util/retry.h>
#include <freeradius-devel/unlang/module.h>

/*
 * $Id$
 *
 * @file rlm_radius.h
 * @brief Structures for the RADIUS client packets
 *
 * @copyright 2017 Alan DeKok (aland@freeradius.org)
 */

typedef struct rlm_radius_s rlm_radius_t;


/** Push a REQUEST to an IO submodule
 *
 */
typedef rlm_rcode_t (*rlm_radius_io_push_t)(void *instance, REQUEST *request, void *request_io_ctx, void *thread);
typedef void (*rlm_radius_io_signal_t)(REQUEST *request, void *instance, void *thread, void *request_io_ctx, fr_state_signal_t action);
typedef int (*rlm_radius_io_instantiate_t)(rlm_radius_t *inst, void *io_instance, CONF_SECTION *cs);


/** Public structure describing an I/O path for an outgoing socket.
 *
 * This structure is exported by client I/O modules e.g. rlm_radius_udp.
 */
typedef struct {
	DL_MODULE_COMMON;				//!< Common fields to all loadable modules.

	fr_app_bootstrap_t		bootstrap;
	rlm_radius_io_instantiate_t	instantiate;

	module_thread_instantiate_t			thread_instantiate;	//!< Callback to configure a module's instance for
								//!< a new worker thread.
	module_thread_detach_t		thread_detach;		//!< Destroy thread specific data.
	size_t				thread_inst_size;	//!< Size of data to allocate to the thread instance.
	char const			*thread_inst_type;	//!< Talloc type of the thread instance

	size_t				request_inst_size;	//!< size of the data per request
	char const			*request_inst_type;	//!< Talloc type of the request_inst.

	rlm_radius_io_push_t		push;			//!< push a REQUEST to an IO submodule
	rlm_radius_io_signal_t		signal;			//!< send a signal to an IO module
	fr_unlang_module_resume_t	resume;			//!< resume a request, and get rcode
} rlm_radius_io_t;

/*
 *	Define a structure for our module configuration.
 */
struct rlm_radius_s {
	char const		*name;			//!< Module instance name.

	dl_module_inst_t	*io_submodule;		//!< As provided by the transport_parse
	rlm_radius_io_t const	*io;			//!< Easy access to the IO handle
	void			*io_instance;		//!< Easy access to the IO instance
	CONF_SECTION		*io_conf;		//!< Easy access to the IO config section

	fr_time_delta_t		zombie_period;
	fr_time_delta_t		revive_interval;

	bool			replicate;		//!< Ignore responses.
	bool			synchronous;		//!< Retransmit when receiving a duplicate request.
	bool			no_connection_fail;	//!< Fail immediately if there are no active connections.
	bool			originate;  		//!< Originating packets, instead of proxying existing ones.
							///< Controls whether Proxy-State is added to the outbound
							///< request.

	uint32_t		max_attributes;   	//!< Maximum number of attributes to decode in response.

	uint32_t		proxy_state;  		//!< Unique ID (mostly) of this module.
	uint32_t		*types;			//!< array of allowed packet types
	uint32_t		status_check;  		//!< code of status-check type
	vp_map_t		*status_check_map;	//!< attributes for the status-server checks

	bool			allowed[FR_RADIUS_MAX_PACKET_CODE];
	fr_retry_config_t      	retry[FR_RADIUS_MAX_PACKET_CODE];

	fr_trunk_conf_t		trunk_conf;		//!< trunk configuration
};


/** Per-thread instance data
 *
 * Contains buffers and connection handles specific to the thread.
 */
typedef struct {
	rlm_radius_t const	*inst;			//!< Instance of the module.
	fr_event_list_t		*el;			//!< This thread's event list.

	void			*thread_io_ctx;		//!< thread context for the IO submodule
} rlm_radius_thread_t;
