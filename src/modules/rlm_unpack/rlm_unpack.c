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

#include <freeradius-devel/util/hex.h>

#include <ctype.h>

static fr_dict_t const *dict_freeradius;

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
 * Example:
@verbatim
%{unpack:&Class 0 integer}
@endverbatim
 * Expands Class, treating octet at offset 0 (bytes 0-3) as an "integer".
 *
 * @ingroup xlat_functions
 */
static ssize_t unpack_xlat(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			   UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			   request_t *request, char const *fmt)
{
	bool tainted = false;
	char *data_name, *data_size, *data_type;
	char *p;
	size_t len, input_len, offset;
	ssize_t slen;
	fr_type_t type;
	fr_dict_attr_t const *da;
	fr_pair_t *vp;;
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
		fr_pair_t *from_vp;

		if (xlat_fmt_get_vp(&from_vp, request, data_name) < 0) goto nothing;

		if ((from_vp->vp_type != FR_TYPE_OCTETS) &&
		    (from_vp->vp_type != FR_TYPE_STRING)) {
			REDEBUG("unpack requires the input attribute to be 'string' or 'octets'");
			goto nothing;
		}
		input = from_vp->vp_octets;
		input_len = from_vp->vp_length;
		tainted = from_vp->vp_tainted;

	} else if ((data_name[0] == '0') && (data_name[1] == 'x')) {
		/*
		 *	Hex data.
		 */
		len = strlen(data_name + 2);
		if (len > 0) {
			fr_sbuff_parse_error_t err;

			input = blob;
			input_len = fr_hex2bin(&err, &FR_DBUFF_TMP(blob, sizeof(blob)),
					       &FR_SBUFF_IN(data_name + 2, len), true);
			if (err) {
				REDEBUG("Invalid hex string in '%s'", data_name);
				goto nothing;
			}
		} else {
			GOTO_ERROR;
		}
	} else {
		GOTO_ERROR;
	}

	offset = (int) strtoul(data_size, &p, 10);
	if (*p) {
		REDEBUG("unpack requires a decimal number, not '%s'", data_size);
		goto nothing;
	}

	if (offset >= input_len) {
		REDEBUG("unpack offset %zu is larger than input data length %zu", offset, input_len);
		goto nothing;
	}

	type = fr_table_value_by_str(fr_value_box_type_table, data_type, FR_TYPE_INVALID);
	if (type == FR_TYPE_INVALID) {
		REDEBUG("Invalid data type '%s'", data_type);
		goto nothing;
	}

	da = fr_dict_attr_child_by_num(fr_dict_root(dict_freeradius), attr_cast_base->attr + type);
	if (!da) {
		REDEBUG("Cannot decode type '%s'", data_type);
		goto nothing;
	}

	MEM(vp = fr_pair_afrom_da(request, da));

	/*
	 *	Call the generic routines to get data from the
	 *	"network" buffer.
	 *
	 *	@todo - just parse / print the value-box directly,
	 *	instead of putting it into a VP.
	 *
	 *	@todo - make this function 'async', and just return a
	 *	copy of the value-box, instead of printing it to a string.
	 */
	if (fr_value_box_from_network(vp, &vp->data, da->type, NULL, input + offset, input_len - offset, tainted) < 0) {
		RPEDEBUG("Failed decoding %s", vp->da->name);
		goto nothing;
	}

	slen = fr_pair_print_value_quoted(&FR_SBUFF_OUT(*out, outlen), vp, T_BARE_WORD);
	talloc_free(vp);
	if (slen < 0) {
		REDEBUG("Insufficient buffer space to unpack data");
		goto nothing;
	}

	return slen;
}

/*
 *	Register the xlats
 */
static int mod_bootstrap(UNUSED void *instance, CONF_SECTION *conf)
{
	if (cf_section_name2(conf)) return 0;

	xlat_register_legacy(NULL, "unpack", unpack_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN);

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
