/*
 * rlm_exe.c
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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2002  The FreeRADIUS server project
 * Copyright 2002  Alan DeKok <aland@ox.org>
 */

#include "autoconf.h"
#include "libradius.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "radiusd.h"
#include "modules.h"
#include "conffile.h"

static const char rcsid[] = "$Id$";

/*
 *	Define a structure for our module configuration.
 */
typedef struct rlm_exec_t {
	char *xlat_name;
	int wait;
} rlm_exec_t;

/*
 *	A mapping of configuration file names to internal variables.
 *
 *	Note that the string is dynamically allocated, so it MUST
 *	be freed.  When the configuration file parse re-reads the string,
 *	it free's the old one, and strdup's the new one, placing the pointer
 *	to the strdup'd string into 'config.string'.  This gets around
 *	buffer over-flows.
 */
static CONF_PARSER module_config[] = {
	{ "wait", PW_TYPE_BOOLEAN,    offsetof(rlm_exec_t,wait), NULL, "yes" },
	{ NULL, -1, 0, NULL, NULL }		/* end the list */
};

/*
 *  Do xlat of strings!
 */ 
static int exec_xlat(void *instance, REQUEST *request,
		     char *fmt, char *out, int outlen,
		     RADIUS_ESCAPE_STRING func)
{
	int		result;
	rlm_exec_t	*inst = instance;
	char		buffer[256];

	inst = inst;		/* -Wunused */

	/*
	 * Do an xlat on the provided string (nice recursive operation).
	 */
	if (!radius_xlat(buffer, sizeof(buffer), fmt, request, NULL)) {
		radlog(L_ERR, "rlm_exec: xlat failed.");
		return 0;
	}

	DEBUG2("rlm_exec: %d %s", inst->wait, buffer);
	result = radius_exec_program(buffer, request, inst->wait,
				     out, outlen, NULL);
	DEBUG2("rlm_exec: result %d", result);
	if (result != 0) {
		out[0] = '\0';
		return 0;
	}

	return strlen(out);
}

/*
 *	Do any per-module initialization that is separate to each
 *	configured instance of the module.  e.g. set up connections
 *	to external databases, read configuration files, set up
 *	dictionary entries, etc.
 *
 *	If configuration information is given in the config section
 *	that must be referenced in later calls, store a handle to it
 *	in *instance otherwise put a null pointer there.
 */
static int exec_instantiate(CONF_SECTION *conf, void **instance)
{
	rlm_exec_t	*inst;
	char		*xlat_name;
	
	/*
	 *	Set up a storage area for instance data
	 */
	
	inst = rad_malloc(sizeof(rlm_exec_t));
	memset(inst, 0, sizeof(rlm_exec_t));
		
	/*
	 *	If the configuration parameters can't be parsed, then
	 *	fail.
	 */
	if (cf_section_parse(conf, inst, module_config) < 0) {
		free(inst);
		return -1;
	}
	
	xlat_name = cf_section_name2(conf);
	if (xlat_name == NULL) 
		xlat_name = cf_section_name1(conf);
	if (xlat_name){ 
		inst->xlat_name = strdup(xlat_name);
		xlat_register(xlat_name, exec_xlat, inst); 
	} 

	*instance = inst;
	
	return 0;
}

/*
 * Detach a instance free all ..
 */
static int exec_detach(void *instance)
{
	rlm_exec_t	*inst = instance;

	xlat_unregister(inst->xlat_name, exec_xlat);
	free(inst->xlat_name);

	free(inst);
	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
module_t rlm_exec = {
	"exec",				/* Name */
	RLM_TYPE_THREAD_SAFE,		/* type */
	NULL,				/* initialization */
	exec_instantiate,		/* instantiation */
	{
		NULL,			/* authentication */
		NULL,			/* authorization */
		NULL,			/* pre-accounting */
		NULL,			/* accounting */
		NULL,			/* check simul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		NULL			/* post-auth */
	},
	exec_detach,			/* detach */
	NULL,				/* destroy */
};
