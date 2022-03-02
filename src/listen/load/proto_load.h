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
 *  GNU General Public License for more loads.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @file proto_load.h
 * @brief Load master protocol handler.
 *
 * @copyright 2017 Alan DeKok (alan@freeradius.org)
 */
RCSIDH(proto_load_h, "$Id$")

#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/io/master.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	fr_io_instance_t		io;				//!< wrapper for IO abstraction

	CONF_SECTION			*server_cs;			//!< server CS for this listener
	CONF_SECTION			*cs;				//!< my configuration
	fr_app_t			*self;				//!< child / parent linking issues
	char const			*type;				//!< packet type name

	fr_dict_t const			*dict;				//!< root dictionary
	fr_dict_attr_t const		*attr_packet_type;

	uint32_t			code;				//!< packet code to use for incoming packets
	uint32_t			max_packet_size;		//!< for message ring buffer
	uint32_t			num_messages;			//!< for message ring buffer
	uint32_t			priority;			//!< for packet processing, larger == higher
} proto_load_t;

#include <pthread.h>

#ifdef __cplusplus
}
#endif
