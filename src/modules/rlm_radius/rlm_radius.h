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
#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/radius/bio.h>

#include <freeradius-devel/bio/fd.h>

/*
 * $Id$
 *
 * @file rlm_radius.h
 * @brief Structures for the RADIUS client packets
 *
 * @copyright 2017 Alan DeKok (aland@freeradius.org)
 */

typedef struct rlm_radius_s rlm_radius_t;

typedef enum {
	RLM_RADIUS_MODE_INVALID = 0,
	RLM_RADIUS_MODE_PROXY,
	RLM_RADIUS_MODE_CLIENT,
	RLM_RADIUS_MODE_REPLICATE,
	RLM_RADIUS_MODE_UNCONNECTED_REPLICATE,
	RLM_RADIUS_MODE_XLAT_PROXY,
} rlm_radius_mode_t;

/*
 *	Define a structure for our module configuration.
 */
struct rlm_radius_s {
	fr_bio_fd_config_t	fd_config;		//!< for now MUST be at the start!

	char const		*name;

	fr_time_delta_t		response_window;
	fr_time_delta_t		zombie_period;
	fr_time_delta_t		revive_interval;

	char const		*secret;		//!< Shared secret.

	uint32_t		max_packet_size;	//!< Maximum packet size.
	uint16_t		max_send_coalesce;	//!< Maximum number of packets to coalesce into one mmsg call.

	fr_radius_ctx_t		common_ctx;

	bool			replicate;		//!< Ignore responses.
	bool			synchronous;		//!< Retransmit when receiving a duplicate request.
	bool			originate;		//!< Originating packets, instead of proxying existing ones.
							///< Controls whether Proxy-State is added to the outbound
							///< request
	rlm_radius_mode_t	mode;			//!< proxy, client, etc.

	uint32_t		max_attributes;   	//!< Maximum number of attributes to decode in response.

	fr_radius_require_ma_t	require_message_authenticator;	//!< Require Message-Authenticator in responses.
	bool			*received_message_authenticator;	//!< Received Message-Authenticator in responses.

	uint32_t		*types;			//!< array of allowed packet types
	uint32_t		status_check;  		//!< code of status-check type
	map_list_t		status_check_map;	//!< attributes for the status-server checks
	uint32_t		num_answers_to_alive;	//!< How many status check responses we need to
							///< mark the connection as alive.

	bool			allowed[FR_RADIUS_CODE_MAX];

	fr_retry_config_t	timeout_retry;
	fr_retry_config_t      	retry[FR_RADIUS_CODE_MAX];

	trunk_conf_t		trunk_conf;		//!< trunk configuration
};
