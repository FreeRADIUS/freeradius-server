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

static xlat_action_t dhcpv4_decode_xlat(TALLOC_CTX *ctx, fr_cursor_t *out,
				        REQUEST *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
				        fr_value_box_t **in)
{
	fr_cursor_t	in_cursor, cursor;
	fr_value_box_t	*vb, *vb_decoded;
	VALUE_PAIR	*vp, *head = NULL;
	int		decoded = 0;

	fr_cursor_init(&cursor, &head);

	for (vb = fr_cursor_talloc_init(&in_cursor, in, fr_value_box_t);
	     vb;
	     vb = fr_cursor_next(&in_cursor)) {
		uint8_t const	*p, *end;
		ssize_t		len;
		VALUE_PAIR	*vps = NULL;
		fr_cursor_t	options_cursor;

		if (vb->type != FR_TYPE_OCTETS) {
			RWDEBUG("Skipping value \"%pV\", expected value of type %s, got type %s",
				vb,
				fr_table_str_by_value(fr_value_box_type_table, FR_TYPE_OCTETS, "<INVALID>"),
				fr_table_str_by_value(fr_value_box_type_table, vb->type, "<INVALID>"));
			continue;
		}

		fr_cursor_init(&options_cursor, &vps);

		p = vb->vb_octets;
		end = vb->vb_octets + vb->vb_length;

		/*
		 *	Loop over all the options data
		 */
		while (p < end) {
			len = fr_dhcpv4_decode_option(request->packet, &options_cursor, dict_dhcpv4,
						      p, end - p, NULL);
			if (len <= 0) {
				RWDEBUG("DHCP option decoding failed: %s", fr_strerror());
				fr_pair_list_free(&head);
				return XLAT_ACTION_FAIL;
			}
			p += len;
		}
		fr_cursor_head(&options_cursor);
		fr_cursor_merge(&cursor, &options_cursor);
	}

	for (vp = fr_cursor_head(&cursor);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		RDEBUG2("dhcp_option: &%pP", vp);
		decoded++;
	}

	fr_pair_list_move(&(request->packet->vps), &head);

	/* Free any unmoved pairs */
	fr_pair_list_free(&head);

	/* create a value box to hold the decoded count */
	MEM(vb_decoded = fr_value_box_alloc(ctx, FR_TYPE_UINT16, NULL, false));
	vb_decoded->vb_uint16 = decoded;
	fr_cursor_append(out, vb_decoded);

	return XLAT_ACTION_DONE;
}

static xlat_action_t dhcpv4_encode_xlat(TALLOC_CTX *ctx, fr_cursor_t *out,
					REQUEST *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
					fr_value_box_t **in)
{
	fr_cursor_t	*cursor;
	bool		tainted = false;
	fr_value_box_t	*encoded;
	VALUE_PAIR	*vp;

	uint8_t		binbuf[2048];
	uint8_t		*p = binbuf, *end = p + sizeof(binbuf);
	ssize_t		len = 0;

	if (!*in) return XLAT_ACTION_DONE;

	if (fr_value_box_list_concat(ctx, *in, in, FR_TYPE_STRING, true) < 0) {
		RPEDEBUG("Failed concatenating input string for attribute reference");
		return XLAT_ACTION_FAIL;
	}

	if (xlat_fmt_to_cursor(NULL, &cursor, &tainted, request, (*in)->vb_strvalue) < 0) return XLAT_ACTION_FAIL;

	if (!fr_cursor_head(cursor)) return XLAT_ACTION_DONE;	/* Nothing to encode */

	while ((vp = fr_cursor_current(cursor))) {
		len = fr_dhcpv4_encode_option(p, end - p, cursor,
					      &(fr_dhcpv4_ctx_t){ .root = fr_dict_root(dict_dhcpv4) });
		if (len < 0) {
			RPEDEBUG("DHCP option encoding failed");
			talloc_free(cursor);
			return XLAT_ACTION_FAIL;
		}
		p += len;
	}
	talloc_free(cursor);

	/*
	 *	Pass the options string back
	 */
	MEM(encoded = fr_value_box_alloc_null(ctx));
	fr_value_box_memcpy(encoded, encoded, NULL, binbuf, (size_t)len, tainted);
	fr_cursor_append(out, encoded);

	return XLAT_ACTION_DONE;
}

static int dhcp_load(void)
{
	if (fr_dhcpv4_global_init() < 0) {
		PERROR("Failed initialising protocol library");
		return -1;
	}

	xlat_async_register(NULL, "dhcpv4_decode", dhcpv4_decode_xlat);
	xlat_async_register(NULL, "dhcpv4_encode", dhcpv4_encode_xlat);

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
