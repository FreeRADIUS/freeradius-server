#pragma once
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
 *
 * @file src/lib/server/process.h
 * @brief Declarations for functions which process packet state machines
 *
 * @copyright 2021 The FreeRADIUS server project
 * @copyright 2021 Network RADIUS SARL <legal@networkradius.com>
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/server/virtual_servers.h>

/*
 *	Define a processing module.
 */
typedef struct fr_process_module_s {
	DL_MODULE_COMMON;				//!< Common fields for all loadable modules.
	FR_MODULE_COMMON;				//!< bootstrap, instantiate

	module_method_t			process;	//!< Process packets
	virtual_server_compile_t const	*compile_list;	//!< list of processing sections
	fr_dict_t const			**dict;			//!< pointer to local fr_dict_t *
} fr_process_module_t;

#ifndef NDEBUG
#  define PROCESS_TRACE	RDEBUG3("Entered state %s", __FUNCTION__)
#else
#  define PROCESS_TRACE
#endif

#ifndef process_packet_code_t
#define process_packet_code_t uint32_t
#endif

typedef process_packet_code_t fr_process_rcode_t[RLM_MODULE_NUMCODES];

/*
 *	RADIUS state machine tables for rcode to packet.
 */
typedef struct {
	process_packet_code_t	packet_type[RLM_MODULE_NUMCODES];	//!< rcode to packet type mapping.
	size_t			section_offset;	//!< Where to look in the process instance for
						///< a pointer to the section we should execute.
	rlm_rcode_t		rcode;		//!< Default rcode
	process_packet_code_t	reject;		//!< Reject packet type.
	module_method_t		recv;		//!< Method to call when receiving this type of packet.
	unlang_module_resume_t	resume;		//!< Function to call after running a recv section.
	unlang_module_resume_t	send;		//!< Method to call when sending this type of packet.
} fr_process_state_t;


#ifdef __cplusplus
}
#endif
