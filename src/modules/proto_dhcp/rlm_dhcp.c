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
	vp_cursor_t	cursor, src_cursor;
	vp_tmpl_t	src;
	VALUE_PAIR	*vp, *head = NULL;
	int		decoded = 0;
	ssize_t		slen;

	while (isspace((int) *fmt)) fmt++;

	slen = tmpl_from_attr_str(&src, fmt, REQUEST_CURRENT, PAIR_LIST_REQUEST, false, false);
	if (slen <= 0) {
		REMARKER(fmt, slen, fr_strerror());
	error:
		*out = '\0';
		return -1;
	}

	if (src.type != TMPL_TYPE_ATTR) {
		REDEBUG("dhcp_options cannot operate on a %s", fr_int2str(tmpl_names, src.type, "<INVALID>"));
		goto error;
	}

	if (src.tmpl_da->type != PW_TYPE_OCTETS) {
		REDEBUG("dhcp_options got a %s attribute needed octets",
			fr_int2str(dict_attr_types, src.tmpl_da->type, "<INVALID>"));
		goto error;
	}

	for (vp = tmpl_cursor_init(NULL, &src_cursor, request, &src);
	     vp;
	     vp = tmpl_cursor_next(&src_cursor, &src)) {
		/*
		 *	@fixme: we should pass in a cursor, then decoding multiple
		 *	source attributes can be made atomic.
		 */
		if ((fr_dhcp_decode_options(request->packet, &head, vp->vp_octets, vp->vp_length) < 0) || (!head)) {
			RWDEBUG("DHCP option decoding failed: %s", fr_strerror());
			goto error;
		}

		for (vp = fr_cursor_init(&cursor, &head);
		     vp;
		     vp = fr_cursor_next(&cursor)) {
			rdebug_pair(L_DBG_LVL_2, request, vp, "dhcp_options: ");
			decoded++;
		}

		fr_pair_list_move(request->packet, &(request->packet->vps), &head);

		/* Free any unmoved pairs */
		fr_pair_list_free(&head);
	}

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

	len = fr_dhcp_encode_option(request, binbuf, sizeof(binbuf), &cursor);
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
 *	Instantiate the module.
 */
static int mod_bootstrap(UNUSED CONF_SECTION *conf, void *instance)
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
extern module_t rlm_dhcp;
module_t rlm_dhcp = {
	.magic		= RLM_MODULE_INIT,
	.name		= "dhcp",
	.inst_size	= sizeof(rlm_dhcp_t),
	.bootstrap	= mod_bootstrap,
};
