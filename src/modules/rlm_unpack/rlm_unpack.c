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

#define GOTO_ERROR do { REDEBUG("Unexpected text at '%s'", p); goto error;} while (0)

/** Unpack data
 *
 *  Example: %{unpack:&Class 0 integer}
 *
 *  Expands Class, treating octet at offset 0 (bytes 0-3) as an "integer".
 */
static ssize_t unpack_xlat(UNUSED void *instance, REQUEST *request, char const *fmt,
			   char *out, size_t outlen)
{
	char *data_name, *data_size, *data_type;
	char *p;
	size_t len, input_len;
	int offset;
	PW_TYPE type;
	DICT_ATTR const *da;
	VALUE_PAIR *vp, *cast;
	uint8_t const *input;
	char buffer[256];
	uint8_t blob[256];

	/*
	 *	FIXME: copy only the fields here, as we parse them.
	 */
	strlcpy(buffer, fmt, sizeof(buffer));

	p = buffer;
	while (isspace((int) *p)) p++; /* skip leading spaces */

	data_name = p;

	while (*p && !isspace((int) *p)) p++;

	if (!*p) {
	error:
		REDEBUG("Format string should be '<data> <offset> <type>' e.g. '&Class 1 integer'");
	nothing:
		*out = '\0';
		return -1;
	}

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

	/*
	 *	Attribute reference
	 */
	if (*data_name == '&') {
		if (radius_get_vp(&vp, request, data_name) < 0) goto nothing;

		if ((vp->da->type != PW_TYPE_OCTETS) &&
		    (vp->da->type != PW_TYPE_STRING)) {
			REDEBUG("unpack requires the input attribute to be 'string' or 'octets'");
			goto nothing;
		}
		input = vp->vp_octets;
		input_len = vp->vp_length;

	} else if ((data_name[0] == '0') && (data_name[1] == 'x')) {
		/*
		 *	Hex data.
		 */
		len = strlen(data_name + 2);
		if ((len & 0x01) != 0) {
			RDEBUG("Invalid hex string in '%s'", data_name);
			goto nothing;
		}
		input = blob;
		input_len = fr_hex2bin(blob, sizeof(blob), data_name + 2, len);

	} else {
		GOTO_ERROR;
	}

	offset = (int) strtoul(data_size, &p, 10);
	if (*p) {
		REDEBUG("unpack requires a decimal number, not '%s'", data_size);
		goto nothing;
	}

	type = fr_str2int(dict_attr_types, data_type, PW_TYPE_INVALID);
	if (type == PW_TYPE_INVALID) {
		REDEBUG("Invalid data type '%s'", data_type);
		goto nothing;
	}

	/*
	 *	Output must be a non-zero limited size.
	 */
	if ((dict_attr_sizes[type][0] ==  0) ||
	    (dict_attr_sizes[type][0] != dict_attr_sizes[type][1])) {
		REDEBUG("unpack requires fixed-size output type, not '%s'", data_type);
		goto nothing;
	}

	if (input_len < (offset + dict_attr_sizes[type][0])) {
		REDEBUG("Insufficient data to unpack '%s' from '%s'", data_type, data_name);
		goto nothing;
	}

	da = dict_attrbyvalue(PW_CAST_BASE + type, 0);
	if (!da) {
		REDEBUG("Cannot decode type '%s'", data_type);
		goto nothing;
	}

	cast = fr_pair_afrom_da(request, da);
	if (!cast) goto nothing;

	memcpy(&(cast->data), input + offset, dict_attr_sizes[type][0]);
	cast->vp_length = dict_attr_sizes[type][0];

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
		cast->vp_short = ((input[offset] << 8) | input[offset + 1]);
		break;

	case PW_TYPE_INTEGER64:
		cast->vp_integer64 = ntohll(cast->vp_integer64);
		break;

	default:
		break;
	}

	len = vp_prints_value(out, outlen, cast, 0);
	talloc_free(cast);
	if (is_truncated(len, outlen)) {
		REDEBUG("Insufficient buffer space to unpack data");
		goto nothing;
	}

	return len;
}


/*
 *	Register the xlats
 */
static int mod_bootstrap(CONF_SECTION *conf, void *instance)
{
	if (cf_section_name2(conf)) return 0;

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
extern module_t rlm_unpack;
module_t rlm_unpack = {
	.magic		= RLM_MODULE_INIT,
	.name		= "unpack",
	.type		= RLM_TYPE_THREAD_SAFE,
	.bootstrap	= mod_bootstrap
};
