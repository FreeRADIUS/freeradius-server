#pragma once
/*
 * proto_tacacs.h	TACACS+ processing.
 *
 * Version:	$Id$
 *
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
 *
 * @copyright 2020 The FreeRADIUS server project
 * @copyright 2020 Network RADIUS SARL (legal@networkradius.com)
 */

#include <freeradius-devel/io/master.h>
#include <freeradius-devel/tacacs/tacacs.h>
#include <freeradius-devel/protocol/tacacs/tacacs.h>

#define FR_PACKET_TYPE_MAX (FR_PACKET_TYPE_VALUE_DO_NOT_RESPOND + 1)

/** An instance of a proto_tacacs listen section
 *
 */
typedef struct {
	fr_io_instance_t	io;				//!< wrapper for IO abstraction

	dl_module_inst_t	**type_submodule;		//!< Instance of the various types
	dl_module_inst_t	*type_submodule_by_code[FR_PACKET_TYPE_MAX];	//!< Lookup process entry point by code.

	uint32_t		max_packet_size;		//!< for message ring buffer.
	uint32_t		num_messages;			//!< for message ring buffer.

	uint32_t		priorities[FR_PACKET_TYPE_MAX];	//!< priorities for individual packets
} proto_tacacs_t;

/*
 *	Shorter version of the packet for deduping
 */
typedef struct {
	uint8_t		type;
	uint32_t	session_id;
} proto_tacacs_track_t;
