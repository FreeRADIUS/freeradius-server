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
 * @file rlm_unpack.c
 * @brief Unpack binary data
 *
 * @copyright 2014 The FreeRADIUS server project
 * @copyright 2014 Alan DeKok <aland@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <ctype.h>

#define PW_CAST_BASE (1850)

#define GOTO_ERROR do { RDEBUG("Unexpected text at '%s'", p); goto error;} while (0)

/** Unpack data
 *
 *  Example: %{unpack:&Class, 1, integer}
 *
 *  Expands Class, treating octet 1 as an "integer".
 */
static ssize_t unpack_xlat(UNUSED void *instance, REQUEST *request,
			 char const *fmt, char *out, size_t outlen)
{
	char *data_name, *data_size, *data_type;
	char *p;
	size_t len;
	int offset;
	PW_TYPE type;
	DICT_ATTR const *da;
	VALUE_PAIR *vp, *cast;
	char buffer[256];

	strlcpy(buffer, fmt, sizeof(buffer));

	p = buffer;
	if (*p != '&') {
	error:
		RDEBUG("Format string should be like '&Class, 1, integer'");
	nothing:
		*out = '\0';
		return 0;
	}

	p++;

	data_name = p;
	while (*p && !isspace((int) *p)) p++;
	if (!*p) GOTO_ERROR;

	while (isspace((int) *p)) *(p++) = '\0';
	if (!*p) GOTO_ERROR;

	data_size = p;

	while (*p && !isspace((int) *p)) p++;
	if (!*p) GOTO_ERROR;

	while (isspace((int) *p)) *(p++) = '\0';
	if (!*p) GOTO_ERROR;

	data_type = p;

	while (*p && !isspace((int) *p)) p++;
	if (*p) GOTO_ERROR;	/* anything after the type is an error */

	if (radius_get_vp(&vp, request, data_name) < 0) goto nothing;

	if ((vp->da->type != PW_TYPE_OCTETS) &&
	    (vp->da->type != PW_TYPE_STRING)) {
		RDEBUG("unpack requires the input attribute to be 'string' or 'octets'");
		goto nothing;
	}

	offset = (int) strtoul(data_size, &p, 10);
	if (*p) {
		RDEBUG("unpack requires a decimal number, not '%s'", data_size);
		goto nothing;
	}

	type = fr_str2int(dict_attr_types, data_type, PW_TYPE_INVALID);
	if (type == PW_TYPE_INVALID) {
		RDEBUG("Invalid data type '%s'", data_type);
		goto nothing;
	}

	/*
	 *	Output must be a non-zero limited size.
	 */
	if ((dict_attr_sizes[type][0] ==  0) ||
	    (dict_attr_sizes[type][0] != dict_attr_sizes[type][1])) {
		RDEBUG("unpack requires fixed-size output type, not '%s'", data_type);
		goto nothing;
	}

	if (vp->length < (offset + dict_attr_sizes[type][0])) {
		RDEBUG("Cannot unpack attribute '%s', it is too short", data_name);
		goto nothing;
	}

	da = dict_attrbyvalue(PW_CAST_BASE + type, 0);
	if (!da) {
		RDEBUG("Cannot decode type '%s'", data_type);
		goto nothing;
	}

	cast = pairalloc(request, da);
	if (!cast) goto nothing;

	memcpy(&(cast->data), vp->vp_octets + offset, dict_attr_sizes[type][0]);
	cast->length = dict_attr_sizes[type][0];

	/*
	 *	Hacks
	 */
	switch (type) {
	case PW_TYPE_SIGNED:
	case PW_TYPE_INTEGER:
	case PW_TYPE_DATE:
		cast->vp_integer = ntohl(cast->vp_integer);
		break;

	case PW_TYPE_SHORT:
		cast->vp_short = ((vp->vp_octets[offset] << 8) |
				vp->vp_octets[offset + 1]);
		break;

	case PW_TYPE_INTEGER64:
		cast->vp_integer64 = ntohll(cast->vp_integer64);
		break;

	default:
		break;
	}

	len = vp_prints_value(out, outlen, cast, 0);
	talloc_free(cast);

	return len;
}


/*
 *	Register the xlats
 */
static int mod_instantiate(UNUSED CONF_SECTION *conf, void *instance)
{
	xlat_register("unpack", unpack_xlat, NULL, instance);

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
module_t rlm_unpack = {
	RLM_MODULE_INIT,
	"unpack",
	RLM_TYPE_THREAD_SAFE,		/* type */
	0,
	NULL,
	mod_instantiate,		/* instantiation */
	NULL,			/* detach */
	{
		NULL,	/* authentication */
		NULL,	/* authorization */
		NULL, NULL, NULL,
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		NULL			/* post-auth */
	},
};
