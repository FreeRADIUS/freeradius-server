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

/*
 * $Id$
 *
 * @file proto_arp.h
 * @brief Structures for the ARP protocol
 *
 * @copyright 2020 Network RADIUS SARL <legal@networkradius.com>
 */
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/arp/arp.h>

typedef struct {
	CONF_SECTION			*server_cs;			//!< server CS for this listener
	CONF_SECTION			*cs;				//!< my configuration

	dl_module_inst_t	       	*io_submodule;			//!< As provided by the transport_parse
									///< callback.  Broken out into the
									///< app_io_* fields below for convenience.

	CONF_SECTION			*app_io_conf;			//!< for the APP IO
	fr_app_io_t const		*app_io;			//!< Easy access to the app_io handle.
	void				*app_io_instance;		//!< Easy access to the app_io instance.

	dl_module_inst_t		*app_process;			//!< app_process pointer
	void				*process_instance;		//!< app_process instance

	fr_dict_t			*dict;				//!< root dictionary

	bool				active;				//!< do we respond to anything?
	uint32_t			num_messages;			//!< for message ring buffer
	uint32_t			priority;			//!< for packet processing, larger == higher

	fr_schedule_t			*sc;				//!< the scheduler, where we insert new readers

	fr_listen_t			*listen;			//!< The listener structure which describes
									//!< the I/O path.
} proto_arp_t;


