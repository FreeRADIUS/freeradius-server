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
#ifndef _FR_APPLICATION_H
#define _FR_APPLICATION_H

#include <freeradius-devel/cf_util.h>
#include <freeradius-devel/dl.h>
#include <freeradius-devel/io/io.h>

/**
 * $Id$
 *
 * @file io/application.h
 * @brief Application interfaces.
 *
 * @copyright 2017 The FreeRADIUS project
 */

/*
 *	src/lib/io/schedule.h
 */
typedef struct fr_schedule_t fr_schedule_t;

/*
 *	src/lib/io/io.h
 */
typedef struct fr_io_op_t fr_io_op_t;

/** Set the next state executed by the request to be one of the application subtype's entry points
 *
 * @param[in] request	To set the next state function for.
 */
typedef void (*fr_app_op_set_process_t)(REQUEST *request);

/** Public functions exported by the application
 *
 */
 typedef struct {
	fr_app_op_set_process_t		set_process;
 } fr_app_op_t;

typedef int (*fr_app_instantiate_t)(fr_schedule_t *sc, fr_conf_section_t *cs, bool validate_config);
typedef int (*fr_app_bootstrap_t)(fr_conf_section_t *cs);

/** Describes a new application (protocol)
 *
 */
typedef struct {
	RAD_MODULE_COMMON;				//!< Common fields to all loadable modules.

	fr_app_bootstrap_t		bootstrap;
	fr_app_instantiate_t		instantiate;

	fr_app_op_t			op;		//!< Public functions for apps.
} fr_app_t;

typedef int (*fr_app_subtype_instantiate_t)(fr_conf_section_t *cs);

/** Public structure describing an application (protocol) specialisation
 *
 * Some protocols perform multiple distinct functions, and use
 * different state machines to perform those functions.
 */
typedef struct fr_app_subtype_t {
	RAD_MODULE_COMMON;				//!< Common fields to all loadable modules.

	fr_app_subtype_instantiate_t	instantiate;	//!< Perform any config validation, and per-instance work.
	fr_io_process_t			process;	//!< Entry point into the protocol subtype's state machine.
} fr_app_subtype_t;

/** Validate configurable elements of an fr_ctx_t
 *
 * @param[in] io_cs		Configuration describing the I/O mechanism.
 * @param[in] instance		data.  Pre-populated by parsing io_cs.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
typedef int (*fr_app_io_instantiate_t)(fr_conf_section_t *io_cs, void *instance);

/** Public structure describing an I/O path for a protocol
 *
 * This structure is exported by I/O modules e.g. proto_radius_udp.
 */
typedef struct fr_app_io_t {
	RAD_MODULE_COMMON;				//!< Common fields to all loadable modules.

	fr_app_io_instantiate_t		instantiate;	//!< Perform any config validation, and per-instance work.
	fr_io_op_t			op;		//!< Open/close/read/write functions for sending/receiving
							//!< protocol data.
} fr_app_io_t;
#endif
