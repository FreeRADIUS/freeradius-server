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

/*
 * $Id$
 *
 * @file src/lib/server/rcode.c
 * @brief Textual descriptions of rcodes.
 *
 * Rcodes are used at multiple places in the server.  They're usually
 * used by modules to indicate the end result of processing a request,
 * but are also used in virtual servers and unlang to determine the
 * end result of processing unlang snippers.
 *
 * @copyright 2018 The FreeRADIUS server project
 */

RCSID("$Id$")

#include <freeradius-devel/server/rcode.h>

fr_table_num_sorted_t const rcode_table[] = {
	{ "fail",		RLM_MODULE_FAIL	 	},
	{ "handled",		RLM_MODULE_HANDLED      },
	{ "invalid",		RLM_MODULE_INVALID      },
	{ "noop",		RLM_MODULE_NOOP	 	},
	{ "notfound", 		RLM_MODULE_NOTFOUND     },
	{ "ok",			RLM_MODULE_OK	   	},
	{ "reject",		RLM_MODULE_REJECT       },
	{ "updated",		RLM_MODULE_UPDATED      },
	{ "userlock",		RLM_MODULE_USERLOCK     }
};
size_t rcode_table_len = NUM_ELEMENTS(rcode_table);
