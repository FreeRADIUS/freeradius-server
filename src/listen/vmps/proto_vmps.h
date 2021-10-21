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
 * @file proto_vmps.h
 * @brief Structures for the VMPS protocol
 *
 * @copyright 2018 Alan DeKok (aland@freeradius.org)
 */
#include <freeradius-devel/io/master.h>
#include <freeradius-devel/vmps/vmps.h>

/** An instance of a proto_vmps listen section
 *
 */
typedef struct {
	fr_io_instance_t		io;				//!< wrapper for IO abstraction

	char				**allowed_types;		//!< names for for 'type = ...'
	bool				allowed[FR_VMPS_CODE_MAX];	//!< indexed by value

	uint32_t			max_packet_size;		//!< for message ring buffer.
	uint32_t			num_messages;			//!< for message ring buffer.

	uint32_t			priorities[FR_VMPS_CODE_MAX];	//!< priorities for individual packets
} proto_vmps_t;

/*
 *	Shorter version of the packet for deduping
 */
typedef struct {
	uint32_t 	transaction_id;
	uint8_t		opcode;
} proto_vmps_track_t;
