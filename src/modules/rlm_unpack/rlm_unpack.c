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
 * @copyright 2014 Alan DeKok (aland@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <ctype.h>

static fr_dict_t *dict_freeradius;

extern fr_dict_autoload_t rlm_unpack_dict[];
fr_dict_autoload_t rlm_unpack_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_cast_base;

extern fr_dict_attr_autoload_t rlm_unpack_dict_attr[];
fr_dict_attr_autoload_t rlm_unpack_dict_attr[] = {
	{ .out = &attr_cast_base, .name = "Cast-Base", .type = FR_TYPE_UINT8, .dict = &dict_freeradius },
	{ NULL }
};

#define GOTO_ERROR do { REDEBUG("Unexpected text at '%s'", p); goto error;} while (0)

/** Unpack data
 *
 *  Example: %{unpack:&Class 0 integer}
 *
 *  Expands Class, treating octet at offset 0 (bytes 0-3) as an "integer".
 */
static ssize_t unpack_xlat(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			   UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			   REQUEST *request, char const *fmt)
{
	char *data_name, *data_size, *data_type;
	char *p;
	size_t len, input_len;
	int offset;
	fr_type_t type;
	fr_dict_attr_t const *da;
	VALUE_PAIR *vp, *cast;
	uint8_t const *input;
	char buffer[256];
	uint8_t blob[256];

	/*
	 *	FIXME: copy only the fields here, as we parse them.
	 */
	strlcpy(buffer, fmt, sizeof(buffer));

	p = buffer;
	fr_skip_whitespace(p); /* skip leading spaces */

	data_name = p;

	fr_skip_not_whitespace(p);

	if (!*p) {
	error:
		REDEBUG("Format string should be '<data> <offset> <type>' e.g. '&Class 1 integer'");
	nothing:
		return -1;
	}

	fr_zero_whitespace(p);
	if (!*p) GOTO_ERROR;

	data_size = p;

	fr_skip_not_whitespace(p);
	if (!*p) GOTO_ERROR;

	fr_zero_whitespace(p);
	if (!*p) GOTO_ERROR;

	data_type = p;

	fr_skip_not_whitespace(p);
	if (*p) GOTO_ERROR;	/* anything after the type is an error */

	/*
	 *	Attribute reference
	 */
	if (*data_name == '&') {
		if (xlat_fmt_get_vp(&vp, request, data_name) < 0) goto nothing;

		if ((vp->vp_type != FR_TYPE_OCTETS) &&
		    (vp->vp_type != FR_TYPE_STRING)) {
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
			REDEBUG("Invalid hex string in '%s'", data_name);
			goto nothing;
		}
		input = blob;
		input_len = fr_hex2bin(blob, sizeof(blob), data_name + 2, len);

	} else {
		GOTO_ERROR;
	}

	offset = (int) strtoul(data_size, &p, 10);
	if (*p) {
		REDEBUG("unpack requires a float64 number, not '%s'", data_size);
		goto nothing;
	}

	type = fr_table_value_by_str(fr_value_box_type_table, data_type, FR_TYPE_INVALID);
	if (type == FR_TYPE_INVALID) {
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

	da = fr_dict_attr_child_by_num(fr_dict_root(dict_freeradius), attr_cast_base->attr + type);
	if (!da) {
		REDEBUG("Cannot decode type '%s'", data_type);
		goto nothing;
	}

	MEM(cast = fr_pair_afrom_da(request, da));

	memcpy(&(cast->data), input + offset, dict_attr_sizes[type][0]);

	/*
	 *	Hacks
	 */
	switch (type) {
	case FR_TYPE_INT32:
	case FR_TYPE_UINT32:
		cast->vp_uint32 = ntohl(cast->vp_uint32);
		break;

	case FR_TYPE_UINT16:
		cast->vp_uint16 = ((input[offset] << 8) | input[offset + 1]);
		break;

	case FR_TYPE_UINT64:
		cast->vp_uint64 = ntohll(cast->vp_uint64);
		break;

	case FR_TYPE_DATE:
		cast->vp_date = fr_time_from_timeval(&(struct timeval) {.tv_sec = ntohl(cast->vp_uint32)});
		break;

	default:
		break;
	}

	len = fr_pair_value_snprint(*out, outlen, cast, 0);
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
static int mod_bootstrap(UNUSED void *instance, CONF_SECTION *conf)
{
	if (cf_section_name2(conf)) return 0;

	xlat_register(NULL, "unpack", unpack_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);

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
