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
 * @file lib/server/components.h
 * @brief Module components.
 *
 * @copyright 2018 The FreeRADIUS server project
 */
RCSIDH(components_h, "$Id$")

/** The different section components of the server
 *
 * Used as indexes in the methods array in the module_t struct.
 */
typedef enum rlm_components {
	MOD_AUTHENTICATE = 0,			//!< 0 methods index for authenticate section.
	MOD_AUTHORIZE,				//!< 1 methods index for authorize section.
	MOD_PREACCT,				//!< 2 methods index for preacct section.
	MOD_ACCOUNTING,				//!< 3 methods index for accounting section.
	MOD_PRE_PROXY,				//!< 5 methods index for preproxy section.
	MOD_POST_PROXY,				//!< 6 methods index for postproxy section.
	MOD_POST_AUTH,				//!< 7 methods index for postauth section.
	MOD_COUNT				//!< 10 how many components there are.
} rlm_components_t;
