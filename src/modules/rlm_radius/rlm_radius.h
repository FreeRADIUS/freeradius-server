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
#include <freeradius-devel/radius/radius.h>

/*
 * $Id$
 *
 * @file rlm_radius.h
 * @brief Structures for the RADIUS client packets
 *
 * @copyright 2017 Alan DeKok (aland@freeradius.org)
 */

typedef struct rlm_radius_s rlm_radius_t;
typedef struct rlm_radius_io_s rlm_radius_io_t;

/** Per-thread instance data
 *
 * Contains buffers and connection handles specific to the thread.
 */
typedef struct {
	rlm_radius_t const	*inst;			//!< Instance of the module.
	void			*io_thread;		//!< thread context for the IO submodule
} rlm_radius_thread_t;

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
	bool			originate;  		//!< Originating packets, instead of proxying existing ones.
							///< Controls whether Proxy-State is added to the outbound
							///< request.

	uint32_t		max_attributes;   	//!< Maximum number of attributes to decode in response.

	uint32_t		proxy_state;  		//!< Unique ID (mostly) of this module.
	uint32_t		*types;			//!< array of allowed packet types
	uint32_t		status_check;  		//!< code of status-check type
	map_t		*status_check_map;	//!< attributes for the status-server checks
	uint32_t		num_answers_to_alive;		//!< How many status check responses we need to
							///< mark the connection as alive.

	bool			allowed[FR_RADIUS_MAX_PACKET_CODE];
	fr_retry_config_t      	retry[FR_RADIUS_MAX_PACKET_CODE];

	fr_trunk_conf_t		trunk_conf;		//!< trunk configuration
};

/** Enqueue a request_t to an IO submodule
 *
 */
typedef unlang_action_t (*rlm_radius_io_enqueue_t)(rlm_rcode_t *p_result, void **rctx, void *instance, void *thread, request_t *request);

/** Public structure describing an I/O path for an outgoing socket.
 *
 * This structure is exported by client I/O modules e.g. rlm_radius_udp.
 */
struct rlm_radius_io_s {
	DL_MODULE_COMMON;				//!< Common fields to all loadable modules.
	FR_MODULE_COMMON;
	FR_MODULE_THREADED_COMMON;

	rlm_radius_io_enqueue_t		enqueue;	//!< Enqueue a request_t with an IO submodule.
	unlang_module_signal_t	signal;		//!< Send a signal to an IO module.
	unlang_module_resume_t	resume;		//!< Resume a request, and get rcode.
};
