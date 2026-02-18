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

/**
 * $Id$
 *
 * @file io/coord_priv.h
 * @brief Coordination thread management private structures and functions
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(coord_priv_h, "$Id$")

#include <freeradius-devel/io/coord.h>

/** Generic control message used between workers and coordinators
 */
typedef struct {
	uint32_t			worker;			//!< Worker ID
} fr_coord_msg_t;

/** List / data message used between workers and coordinators
 */
typedef struct {
	fr_message_t			m;			//!< Message containing data being sent.
	uint32_t			coord_cb_id;		//!< Callback ID for this message.
} fr_coord_data_t;
