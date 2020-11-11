/*
 * rlm_simulchk.c
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
 * Copyright 2020  The FreeRADIUS server project
 * Copyright 2020  Anton Volokha <antonvolokha@gmail.com>
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct rlm_simulchk_t {
	int		reset;
} rlm_simulchk_t;

/*
 *	A mapping of configuration file names to internal variables.
 *
 *	Note that the string is dynamically allocated, so it MUST
 *	be freed.  When the configuration file parse re-reads the string,
 *	it free's the old one, and strdup's the new one, placing the pointer
 *	to the strdup'd string into 'config.string'.  This gets around
 *	buffer over-flows.
 */
static const CONF_PARSER module_config[] = {
  { "reset", PW_TYPE_BOOLEAN,    offsetof(rlm_simulchk_t,reset), NULL, "yes"},

  { NULL, -1, 0, NULL, NULL }		/* end the list */
};

/*
 *	Instantiate the module.
 */
static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	rlm_simulchk_t *data = instance;

	/*
	 *	If the configuration parameters can't be parsed, then
	 *	fail.
	 */
	if (cf_section_parse(conf, data, module_config) < 0) {
		free(data);
		return -1;
	}

	return 0;
}

/*
 *	See if a user is already logged in. Sets request->simul_count to the
 *	current session count for this user and sets request->simul_mpp to 2
 *	if it looks like a multilink attempt based on the requested IP
 *	address, otherwise leaves request->simul_mpp alone.
 *
 *	Check twice. If on the first pass the user exceeds his
 *	max. number of logins, do a second pass and validate all
 *	logins by querying the terminal server (using eg. SNMP).
 */
static rlm_rcode_t CC_HINT(nonnull) simulchk_check(void *instance, REQUEST *request)
{
  rlm_simulchk_t *inst = (rlm_simulchk_t *) instance;
  rlm_rcode_t ret = RLM_MODULE_REJECT;

  radlog(L_DBG, "rlm_simulchk: count - %d, max - %d, mpp - %d\n",
    request->simul_count, request->simul_max, request->simul_mpp);

  if (request->simul_count < request->simul_max) {
    ret = RLM_MODULE_OK;
  }

  if (inst->reset) {
    request->simul_count = 0;
    request->simul_mpp = 1;
  }

  return ret;
}

extern module_t rlm_simulchk;
module_t rlm_simulchk = {
	.magic		= RLM_MODULE_INIT,
	.name		= "simulchk",
	.type		= RLM_TYPE_THREAD_SAFE,
	.inst_size	= sizeof(rlm_simulchk_t),
	.config		= module_config,
	.instantiate	= mod_instantiate,
	.methods = {
		[MOD_SESSION]	= simulchk_check,
	},
};
