/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
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
 * @file dynamic_clients.c
 * @brief Track dynamic clients
 *
 * @copyright 2018 The FreeRADIUS server project.
 * @copyright 2018 Alan DeKok (aland@deployingradius.com)
 */
#include <netdb.h>
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/protocol.h>
#include <freeradius-devel/udp.h>
#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/io/io.h>
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/io/track.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/io/schedule.h>
#include <freeradius-devel/rad_assert.h>
#include "proto_radius.h"

typedef struct {
	dl_instance_t			*submodule;		//!< proto_radius_dynamic_client
	fr_ipaddr_t			*network;		//!< dynamic networks to allow

	RADCLIENT_LIST			*clients;		//!< local clients
	RADCLIENT_LIST			*expired;		//!< expired local clients

	fr_dlist_t			packets;       		//!< list of accepted packets
	fr_dlist_t			pending;		//!< pending clients

	uint32_t			max_clients;		//!< maximum number of dynamic clients
	uint32_t			num_clients;		//!< total number of active clients
	uint32_t			max_pending_clients;	//!< maximum number of pending clients
	uint32_t			num_pending_clients;	//!< number of pending clients
	uint32_t			max_pending_packets;	//!< maximum accepted pending packets
	uint32_t			num_pending_packets;	//!< how many packets are received, but not accepted

	uint32_t			lifetime;		//!< of the dynamic client, in seconds.
} dynamic_client_t;

typedef struct {
	uint8_t			*packet;
	fr_tracking_entry_t	*track;
	fr_dlist_t		entry;
} dynamic_packet_t;

static const CONF_PARSER dynamic_client_config[] = {
	{ FR_CONF_OFFSET("network", FR_TYPE_COMBO_IP_PREFIX | FR_TYPE_MULTI, dynamic_client_t, network) },

	{ FR_CONF_OFFSET("max_clients", FR_TYPE_UINT32, dynamic_client_t, max_clients), .dflt = "65536" },
	{ FR_CONF_OFFSET("max_pending_clients", FR_TYPE_UINT32, dynamic_client_t, max_pending_clients), .dflt = "256" },
	{ FR_CONF_OFFSET("max_pending_packets", FR_TYPE_UINT32, dynamic_client_t, max_pending_packets), .dflt = "65536" },

	{ FR_CONF_OFFSET("lifetime", FR_TYPE_UINT32, dynamic_client_t, lifetime), .dflt = "600" },

	CONF_PARSER_TERMINATOR
};
