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
#include <freeradius-devel/server/module_rlm.h>

#include <freeradius-devel/util/base16.h>

#include <ctype.h>

static xlat_arg_parser_t const unpack_xlat_args[] = {
	{ .required = true, .single = true, .type = FR_TYPE_VOID },
	{ .required = true, .single = true, .type = FR_TYPE_UINT32 },
	{ .required = true, .single = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Unpack data
 *
 * Example:
@verbatim
%(unpack:%{Class} 0 integer)
@endverbatim
 * Expands Class, treating octet at offset 0 (bytes 0-3) as an "integer".
 *
 * @ingroup xlat_functions
 */
static xlat_action_t unpack_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
				 UNUSED xlat_ctx_t const *xctx, request_t *request,
				 fr_value_box_list_t *in)
{
	size_t		len, input_len, offset;
	fr_type_t	type;
	uint8_t const	*input;
	uint8_t		blob[256];
	fr_value_box_t	*data_vb = fr_dlist_head(in);
	fr_value_box_t	*offset_vb = fr_dlist_next(in, data_vb);
	fr_value_box_t	*type_vb = fr_dlist_next(in, offset_vb);
	fr_value_box_t	*vb;

	if ((data_vb->type != FR_TYPE_OCTETS) && (data_vb->type != FR_TYPE_STRING)) {
		REDEBUG("unpack requires the input attribute to be 'string' or 'octets'");
		return XLAT_ACTION_FAIL;
	}

	if ((data_vb->type == FR_TYPE_STRING) && (data_vb->vb_length > 1) &&
	    (data_vb->vb_strvalue[0] == '0') && (data_vb->vb_strvalue[1] == 'x')) {
		/*
		 *	Hex data.
		 */
		len = strlen(data_vb->vb_strvalue + 2);
		if (len > 0) {
			fr_sbuff_parse_error_t err;

			input = blob;
			input_len = fr_base16_decode(&err, &FR_DBUFF_TMP(blob, sizeof(blob)),
					       &FR_SBUFF_IN(data_vb->vb_strvalue + 2, len), true);
			if (err) {
				REDEBUG("Invalid hex string in '%s'", data_vb->vb_strvalue);
				return XLAT_ACTION_FAIL;
			}
		} else {
			REDEBUG("Zero length hex string in '%s'", data_vb->vb_strvalue);
			return XLAT_ACTION_FAIL;
		}
	} else if (data_vb->type == FR_TYPE_STRING) {
		input = (uint8_t const *)data_vb->vb_strvalue;
		input_len = data_vb->length;
	} else {
		input = data_vb->vb_octets;
		input_len = data_vb->length;
	}

	offset = offset_vb->vb_uint32;

	if (offset >= input_len) {
		REDEBUG("unpack offset %zu is larger than input data length %zu", offset, input_len);
		return XLAT_ACTION_FAIL;
	}

	/* coverity[dereference] */
	type = fr_type_from_str(type_vb->vb_strvalue);
	if (fr_type_is_null(type)) {
		REDEBUG("Invalid data type '%s'", type_vb->vb_strvalue);
		return XLAT_ACTION_FAIL;
	}

	MEM(vb = fr_value_box_alloc_null(ctx));

	/*
	 *	Call the generic routines to get data from the
	 *	"network" buffer.
	 */
	if (fr_value_box_from_network(ctx, vb, type, NULL,
				      &FR_DBUFF_TMP(input + offset, input_len - offset),
				      input_len - offset, data_vb->tainted) < 0) {
		RPEDEBUG("Failed decoding %s", type_vb->vb_strvalue);
		talloc_free(vb);
		return XLAT_ACTION_FAIL;
	}

	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

/*
 *	Register the xlats
 */
static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	xlat_t	*xlat;

	xlat = xlat_register_module(NULL, mctx, "unpack", unpack_xlat, XLAT_FLAG_PURE);
	if (xlat) xlat_func_args(xlat, unpack_xlat_args);

	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to MODULE_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern module_rlm_t rlm_unpack;
module_rlm_t rlm_unpack = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "unpack",
		.type		= MODULE_TYPE_THREAD_SAFE,
		.bootstrap	= mod_bootstrap
	}
};
