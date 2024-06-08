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
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/server/trunk.h>
#include <freeradius-devel/util/dlist.h>
#include <freeradius-devel/util/retry.h>
#include <freeradius-devel/unlang/module.h>
#include <freeradius-devel/tacacs/tacacs.h>

/*
 * $Id$
 *
 * @file rlm_tacacs.h
 * @brief Structures for the TACACS+ client packets
 *
 * @copyright 2023 Network RADIUS SAS (legal@networkradius.com)
 */

typedef struct rlm_tacacs_s rlm_tacacs_t;
typedef struct rlm_tacacs_io_s rlm_tacacs_io_t;

#define FR_TACACS_PACKET_TYPE_MAX (10)

/*
 *	Define a structure for our module configuration.
 */
struct rlm_tacacs_s {
	char const		*name;
	module_instance_t	*io_submodule;
	rlm_tacacs_io_t	const	*io;			//!< Public symbol exported by the submodule.

	fr_time_delta_t		response_window;
	fr_time_delta_t		zombie_period;
	fr_time_delta_t		revive_interval;

	uint32_t		max_attributes;   	//!< Maximum number of attributes to decode in response.

	uint32_t		*types;			//!< array of allowed packet types

	fr_retry_config_t	retry;			//!< retries shared by all packet types

	bool			allowed[FR_TACACS_CODE_MAX];

	trunk_conf_t		trunk_conf;		//!< trunk configuration
};

/** Enqueue a request_t to an IO submodule
 *
 */
typedef unlang_action_t (*rlm_tacacs_io_enqueue_t)(rlm_rcode_t *p_result, void **rctx, void *instance, void *thread, request_t *request);

/** Public structure describing an I/O path for an outgoing socket.
 *
 * This structure is exported by client I/O modules e.g. rlm_tacacs_udp.
 */
struct rlm_tacacs_io_s {
	module_t		common;			//!< Common fields to all loadable modules.
	rlm_tacacs_io_enqueue_t	enqueue;		//!< Enqueue a request_t with an IO submodule.
	unlang_module_signal_t	signal;			//!< Send a signal to an IO module.
	module_method_t	resume;			//!< Resume a request, and get rcode.
};
