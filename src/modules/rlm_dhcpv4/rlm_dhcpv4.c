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
 * @file src/modules/rlm_dhcpv4/rlm_dhcpv4.c
 * @brief DHCP client and relay
 *
 * @copyright 2012-2018 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/util/base.h>

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/io/pair.h>
#include <freeradius-devel/dhcpv4/dhcpv4.h>

#include <ctype.h>

static fr_dict_t const *dict_dhcpv4;

extern fr_dict_autoload_t rlm_dhcpv4_dict[];
fr_dict_autoload_t rlm_dhcpv4_dict[] = {
	{ .out = &dict_dhcpv4, .proto = "dhcpv4" },
	{ NULL }
};

/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct {
	int nothing;
} rlm_dhcpv4_t;

static xlat_arg_parser_t const dhcpv4_decode_xlat_args[] = {
	{ .single = true, .variadic = true, .type = FR_TYPE_VOID },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Decode DHCP option data
 *
 * Creates DHCP attributes based on the given binary option data
 *
 * Example:
@verbatim
%(dhcpv4_decode:%{Tmp-Octets-0})
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t dhcpv4_decode_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
				        request_t *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
				        fr_value_box_list_t *in)
{
	int		decoded;
	fr_value_box_t	*vb;
	fr_pair_list_t	head;
	fr_dcursor_t	cursor;

	fr_pair_list_init(&head);
	fr_dcursor_init(&cursor, &head);

	decoded = fr_pair_decode_value_box_list(request->request_ctx, &cursor, request, NULL, fr_dhcpv4_decode_option, in);
	if (decoded <= 0) {
		RPERROR("DHCP option decoding failed");
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Append the decoded options to the request list.
	 */
	fr_pair_list_append(&request->request_pairs, &head);

	/*
	 *	Create a value box to hold the decoded count, and add
	 *	it to the output list.
	 */
	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_UINT32, NULL, false));
	vb->vb_uint32 = decoded;
	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const dhcpv4_encode_xlat_args[] = {
	{ .required = true, .single = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Encode DHCP option data
 *
 * Returns octet string created from the provided DHCP attributes
 *
 * Example:
@verbatim
%(dhcpv4_encode:&request[*])
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t dhcpv4_encode_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
					request_t *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
					fr_value_box_list_t *in)
{
	tmpl_t		*vpt;
	fr_pair_t	*vp;
	fr_dcursor_t	*cursor;
	tmpl_pair_cursor_ctx_t	cc;
	bool		tainted = false;
	fr_value_box_t	*encoded;

	uint8_t		binbuf[2048];
	uint8_t		*p = binbuf, *end = p + sizeof(binbuf);
	ssize_t		len = 0;
	fr_value_box_t	*in_head = fr_dlist_head(in);

	if (tmpl_afrom_attr_str(NULL, NULL, &vpt, in_head->vb_strvalue,
				&(tmpl_rules_t){
					.dict_def = request->dict,
					.prefix = TMPL_ATTR_REF_PREFIX_AUTO
				}) <= 0) {
		RPEDEBUG("Failed parsing attribute reference");
		return XLAT_ACTION_FAIL;
	}

	MEM(cursor = talloc(ctx, fr_dcursor_t));
	talloc_steal(cursor, vpt);
	vp = tmpl_pair_cursor_init(NULL, NULL, &cc, cursor, request, vpt);

	if (!vp) return XLAT_ACTION_DONE; /* Nothing to encode */

	while (fr_dcursor_filter_current(cursor, fr_dhcpv4_is_encodable, NULL)) {
		vp = fr_dcursor_current(cursor);
		if (vp->vp_tainted) tainted = true;
		len = fr_dhcpv4_encode_option(&FR_DBUFF_TMP(p, end), cursor,
					      &(fr_dhcpv4_ctx_t){ .root = fr_dict_root(dict_dhcpv4) });
		if (len < 0) {
			RPEDEBUG("DHCP option encoding failed");
			talloc_free(cursor);
			tmpl_pair_cursor_clear(&cc);
			return XLAT_ACTION_FAIL;
		}
		p += len;
	}
	talloc_free(cursor);
	tmpl_pair_cursor_clear(&cc);

	/*
	 *	Pass the options string back
	 */
	MEM(encoded = fr_value_box_alloc_null(ctx));
	fr_value_box_memdup(encoded, encoded, NULL, binbuf, (size_t)len, tainted);
	fr_dcursor_append(out, encoded);

	return XLAT_ACTION_DONE;
}

static int dhcp_load(void)
{
	xlat_t	*xlat;

	if (fr_dhcpv4_global_init() < 0) {
		PERROR("Failed initialising protocol library");
		return -1;
	}

	xlat = xlat_register(NULL, "dhcpv4_decode", dhcpv4_decode_xlat, false);
	xlat_func_args(xlat, dhcpv4_decode_xlat_args);
	xlat = xlat_register(NULL, "dhcpv4_encode", dhcpv4_encode_xlat, false);
	xlat_func_args(xlat, dhcpv4_encode_xlat_args);

	return 0;
}

static void dhcp_unload(void)
{
	fr_dhcpv4_global_free();
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
extern module_t rlm_dhcpv4;
module_t rlm_dhcpv4 = {
	.magic		= RLM_MODULE_INIT,
	.name		= "dhcpv4",
	.inst_size	= sizeof(rlm_dhcpv4_t),

	.onload		= dhcp_load,
	.unload		= dhcp_unload,
};
