/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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
 * @file rlm_eap/lib/sim/base.c
 * @brief Code common to EAP-SIM/AKA/AKA' clients and servers.
 *
 * The development of the EAP-SIM support was funded by Internet Foundation
 * Austria (http://www.nic.at/ipa).
 *
 * @copyright 2003 Michael Richardson <mcr@sandelman.ottawa.on.ca>
 * @copyright 2003-2016 The FreeRADIUS server project
 */

RCSID("$Id$")

#include <freeradius-devel/libradius.h>
#include <freeradius-devel/sha1.h>
#include <freeradius-devel/rad_assert.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/tls.h>

#include "eap_types.h"
#include "eap_sim_common.h"
#include "sim_proto.h"

fr_dict_attr_t const *dict_sim_root;
fr_dict_attr_t const *dict_aka_root;

/*
 * definitions changed to take a buffer for unknowns
 * as this is more thread safe.
 */
char const *fr_sim_session_to_name(char *out, size_t outlen, eap_sim_client_states_t state)
{
	static char const *sim_states[] = { "init", "start", NULL };

	if (state >= EAP_SIM_CLIENT_MAX_STATES) {
		snprintf(out, outlen, "eapstate:%d", state);
		return out;
	}

	return sim_states[state];
}

int fr_sim_global_init(void)
{
	static bool done_init;

	if (done_init) return 0;

	dict_aka_root = fr_dict_attr_child_by_num(fr_dict_root(fr_dict_internal), FR_EAP_AKA_ROOT);
	if (!dict_aka_root) {
		fr_strerror_printf("Missing AKA root");
		return -1;
	}

	dict_sim_root = fr_dict_attr_child_by_num(fr_dict_root(fr_dict_internal), FR_EAP_SIM_ROOT);
	if (!dict_sim_root) {
		fr_strerror_printf("Missing SIM root");
		return -1;
	}

	done_init = true;

	return 0;
}

