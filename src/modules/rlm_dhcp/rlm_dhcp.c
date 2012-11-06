/*
 * rlm_dhcp.c
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
 * Copyright 2012  The FreeRADIUS server project
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/libradius.h>

#ifdef WITH_DHCP

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/dhcp.h>

#include <ctype.h>

/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct rlm_dhcp_t {
} rlm_dhcp_t;


/*
 *	Allow single attribute values to be retrieved from the dhcp.
 */
static size_t dhcp_options_xlat(UNUSED void *instance, REQUEST *request,
			 	const char *fmt, char *out, size_t freespace)
{
	VALUE_PAIR *vp, *head = NULL, *next;
	int decoded = 0;
	
	while (isspace((int) *fmt)) fmt++;
	
	
	if (!radius_get_vp(request, fmt, &vp) || !vp) {
		 *out = '\0';
		 
		 return 0;
	}
	
	if ((fr_dhcp_decode_options(vp->vp_octets, vp->length, &head) < 0) ||
	    (head == NULL)) {
		RDEBUG("WARNING: DHCP option decoding failed");
		goto fail;
	}
	
	next = head;
	
	do {
		 next = next->next;
		 decoded++;
	} while (next);
	
	pairmove(&(request->packet->vps), &head);
	
	/* Free any unmoved pairs */
	pairfree(&head);
	
	fail:
	
	snprintf(out, freespace, "%i", decoded);
			 
	return strlen(out);
}


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
	{ NULL, -1, 0, NULL, NULL }		/* end the list */
};


/*
 *	Only free memory we allocated.  The strings allocated via
 *	cf_section_parse() do not need to be freed.
 */
static int dhcp_detach(void *instance)
{
	free(instance);
	return 0;
}


/*
 *	Instantiate the module.
 */
static int dhcp_instantiate(CONF_SECTION *conf, void **instance)
{
	rlm_dhcp_t *inst;

	inst = rad_malloc(sizeof(*inst));
	if (!inst) {
		return -1;
	}
	memset(inst, 0, sizeof(*inst));
	
	xlat_register("dhcp_options", dhcp_options_xlat, inst);

	/*
	 *	If the configuration parameters can't be parsed, then
	 *	fail.
	 */
	if (cf_section_parse(conf, inst, module_config) < 0) {
		free(inst);
		return -1;
	}

	*instance = inst;

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
module_t rlm_dhcp = {
	RLM_MODULE_INIT,
	"dhcp",
	0,				/* type */
	dhcp_instantiate,		/* instantiation */
	dhcp_detach,			/* detach */
	{
		NULL,			/* authentication */
		NULL,			/* authorization */
		NULL,			/* preaccounting */
		NULL,			/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		NULL,		 	/* post-proxy */
		NULL,			/* post-auth */
	},
};

#endif
