/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2 if the
 *   License as published by the Free Software Foundation.
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
 * @file rlm_dhcp.c
 * @brief Will contain dhcp listener code.
 *
 * @copyright 2012  The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/libradius.h>

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/dhcp.h>

#include <ctype.h>

#define PW_DHCP_PARAMETER_REQUEST_LIST 55

/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct rlm_dhcp_t {
	int nothing;
} rlm_dhcp_t;


/*
 *	Allow single attribute values to be retrieved from the dhcp.
 */
static ssize_t dhcp_options_xlat(UNUSED void *instance, REQUEST *request,
				 char const *fmt, char *out, size_t freespace)
{
	vp_cursor_t cursor;
	VALUE_PAIR *vp, *head = NULL;
	int decoded = 0;

	while (isspace((int) *fmt)) fmt++;

	if ((radius_get_vp(&vp, request, fmt) < 0) || !vp) {
		 *out = '\0';
		 return 0;
	}

	if ((fr_dhcp_decode_options(&head, request->packet, vp->vp_octets, vp->length) < 0) || (!head)) {
		RWDEBUG("DHCP option decoding failed: %s", fr_strerror());
		*out = '\0';
		return -1;
	}


	for (vp = fr_cursor_init(&cursor, &head);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		decoded++;
	}

	pairmove(request->packet, &(request->packet->vps), &head);

	/* Free any unmoved pairs */
	pairfree(&head);

	snprintf(out, freespace, "%i", decoded);

	return strlen(out);
}

static ssize_t dhcp_xlat(UNUSED void *instance, REQUEST *request, char const *fmt, char *out, size_t freespace)
{
	vp_cursor_t cursor;
	VALUE_PAIR *vp;
	uint8_t binbuf[255];
	ssize_t len;

	while (isspace((int) *fmt)) fmt++;

	if ((radius_copy_vp(request, &vp, request, fmt) < 0) || !vp) {
		 *out = '\0';
		 return 0;
	}
	fr_cursor_init(&cursor, &vp);

	len = fr_dhcp_encode_option(binbuf, sizeof(binbuf), request, &cursor);
	talloc_free(vp);
	if (len <= 0) {
		REDEBUG("DHCP option encoding failed: %s", fr_strerror());

		return -1;
	}

	if ((size_t)((len * 2) + 1) > freespace) {
		REDEBUG("DHCP option encoding failed: Output buffer exhausted, needed %zd bytes, have %zd bytes",
			(len * 2) + 1, freespace);

		return -1;
	}

	return fr_bin2hex(out, binbuf, len);
}

/*
 *	Only free memory we allocated.  The strings allocated via
 *	cf_section_parse() do not need to be freed.
 */
static int mod_detach(void *instance)
{
	xlat_unregister("dhcp_options", dhcp_options_xlat, instance);
	xlat_unregister("dhcp", dhcp_xlat, instance);
	return 0;
}


/*
 *	Instantiate the module.
 */
static int mod_instantiate(UNUSED CONF_SECTION *conf, void *instance)
{
	rlm_dhcp_t *inst = instance;
	DICT_ATTR const *da;

	xlat_register("dhcp_options", dhcp_options_xlat, NULL, inst);
	xlat_register("dhcp", dhcp_xlat, NULL, inst);

	/*
	 *	Fixup dictionary entry for DHCP-Paramter-Request-List adding all the options
	 */
	da = dict_attrbyvalue(PW_DHCP_PARAMETER_REQUEST_LIST, DHCP_MAGIC_VENDOR);
	if (da) {
		DICT_ATTR const *value;
		int i;

		/* No padding or termination options */
		DEBUG3("Adding values for %s", da->name);
		for (i = 1; i < 255; i++) {
			value = dict_attrbyvalue(i, DHCP_MAGIC_VENDOR);
			if (!value) {
				DEBUG3("No DHCP RFC space attribute at %i", i);
				continue;
			}

			DEBUG3("Adding %s value %i %s", da->name, i, value->name);
			if (dict_addvalue(value->name, da->name, i) < 0) {
				DEBUG3("Failed adding value: %s", fr_strerror());
			}
		}
	}

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
	sizeof(rlm_dhcp_t),
	NULL,				/* CONF_PARSER */
	mod_instantiate,		/* instantiation */
	mod_detach,			/* detach */
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
