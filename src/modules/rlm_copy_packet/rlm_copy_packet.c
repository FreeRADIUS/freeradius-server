/*
 * rlm_copy_packet.c
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
 * Copyright 2004,2006  The FreeRADIUS server project
 * Copyright 2004  Alan DeKok <aland@cladju.com>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

/*
 *	Define a structure for our module configuration.
 *
 *	It doesn't take any configuration right now...
 */
typedef struct rlm_packet_t {
	char		*string;
} rlm_packet_t;


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
  { "string",  PW_TYPE_STRING_PTR, offsetof(rlm_packet_t,string), NULL,  NULL},

  { NULL, -1, 0, NULL, NULL }		/* end the list */
};


static int packet_detach(void *instance)
{
	free(instance);
	return 0;
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
static int packet_instantiate(CONF_SECTION *conf, void **instance)
{
	rlm_packet_t *inst;

	/*
	 *	Set up a storage area for instance data
	 */
	inst = rad_malloc(sizeof(*inst));
	if (!inst) {
		return -1;
	}
	memset(inst, 0, sizeof(*inst));

	/*
	 *	If the configuration parameters can't be parsed, then
	 *	fail.
	 */
	if (cf_section_parse(conf, inst, module_config) < 0) {
		packet_detach(inst);
		return -1;
	}

	*instance = inst;

	return 0;
}


/*
 *	Initialize the reply with the request.
 */
static int packet_authorize(void *instance, REQUEST *request)
{
	VALUE_PAIR	*vps;

	instance = instance;	/* -Wunused */

	vps = paircopy(request->packet->vps);
	pairadd(&(request->reply->vps), vps);
	return RLM_MODULE_UPDATED;
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
module_t rlm_copy_packet = {
	 RLM_MODULE_INIT,
	"copy_packet",
	RLM_TYPE_THREAD_SAFE,		/* type */
	packet_instantiate,		/* instantiation */
	packet_detach,			/* detach */
	{
		NULL,			/* authentication */
		packet_authorize,	/* authorization */
		NULL,			/* preaccounting */
		NULL,			/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		NULL			/* post-auth */
	},
};
