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
#include <freeradius-devel/server/modules.h>
#include <freeradius-devel/dhcpv4/dhcpv4.h>

#include <ctype.h>

/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct rlm_dhcpv4_t {
	int nothing;
} rlm_dhcpv4_t;


/*
 *	Allow single attribute values to be retrieved from the dhcp.
 */
static ssize_t dhcp_options_xlat(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			   	 UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			   	 REQUEST *request, char const *fmt)
{
	fr_cursor_t	cursor;
	fr_cursor_t	src_cursor;
	vp_tmpl_t	*src;
	VALUE_PAIR	*vp, *head = NULL;
	int		decoded = 0;
	ssize_t		slen;
	fr_dhcp_ctx_t	packet_ctx = {
				.root = fr_dict_root(fr_dict_internal)
			};

	while (isspace((int) *fmt)) fmt++;

	slen = tmpl_afrom_attr_str(request, &src, fmt, &(vp_tmpl_rules_t){ .dict_def = request->dict });
	if (slen <= 0) {
		REMARKER(fmt, slen, fr_strerror());
	error:
		talloc_free(src);
		return -1;
	}

	if (src->type != TMPL_TYPE_ATTR) {
		RPEDEBUG("dhcp_options cannot operate on a %s", fr_int2str(tmpl_names, src->type, "<INVALID>"));
		goto error;
	}

	if (src->tmpl_da->type != FR_TYPE_OCTETS) {
		REDEBUG("dhcp_options got a %s attribute needed octets",
			fr_int2str(fr_value_box_type_names, src->tmpl_da->type, "<INVALID>"));
		goto error;
	}

	fr_cursor_init(&cursor, &head);

	for (vp = tmpl_cursor_init(NULL, &src_cursor, request, src);
	     vp;
	     vp = fr_cursor_next(&src_cursor)) {
		uint8_t const	*p = vp->vp_octets, *end = p + vp->vp_length;
		ssize_t		len;
		VALUE_PAIR	*vps = NULL;
		fr_cursor_t	options_cursor;

		fr_cursor_init(&options_cursor, &vps);
		/*
		 *	Loop over all the options data
		 */
		while (p < end) {
			len = fr_dhcpv4_decode_option(request->packet, &options_cursor, p, end - p, &packet_ctx);
			if (len <= 0) {
				RWDEBUG("DHCP option decoding failed: %s", fr_strerror());
				fr_pair_list_free(&head);
				goto error;
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

	fr_pair_list_move(request->packet, &(request->packet->vps), &head);

	/* Free any unmoved pairs */
	fr_pair_list_free(&head);

	snprintf(*out, outlen, "%i", decoded);

	talloc_free(src);

	return strlen(*out);
}

static ssize_t dhcp_xlat(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			 UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			 REQUEST *request, char const *fmt)
{
	fr_cursor_t cursor;
	VALUE_PAIR *vp;
	uint8_t binbuf[255];
	ssize_t len;

	while (isspace((int) *fmt)) fmt++;

	if ((xlat_fmt_copy_vp(request, &vp, request, fmt) < 0) || !vp) return 0;
	fr_cursor_init(&cursor, &vp);

	len = fr_dhcpv4_encode_option(binbuf, sizeof(binbuf), &cursor, NULL);
	talloc_free(vp);
	if (len <= 0) {
		RPEDEBUG("DHCP option encoding failed");

		return -1;
	}

	if ((size_t)((len * 2) + 1) > outlen) {
		REDEBUG("DHCP option encoding failed: Output buffer exhausted, needed %zd bytes, have %zd bytes",
			(len * 2) + 1, outlen);

		return -1;
	}

	return fr_bin2hex(*out, binbuf, len);
}


/*
 *	Instantiate the module.
 */
static int mod_bootstrap(void *instance, UNUSED CONF_SECTION *conf)
{
	rlm_dhcpv4_t *inst = instance;


	xlat_register(inst, "dhcp_options", dhcp_options_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);
	xlat_register(inst, "dhcp", dhcp_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);

	return 0;
}

static int dhcp_load(void)
{
	if (fr_dhcpv4_init() < 0) {
		PERROR("Failed initialising protocol library");
		return -1;
	}

	return 0;
}

static void dhcp_unload(void)
{
	fr_dhcpv4_free();
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
extern rad_module_t rlm_dhcpv4;
rad_module_t rlm_dhcpv4 = {
	.magic		= RLM_MODULE_INIT,
	.name		= "dhcpv4",
	.inst_size	= sizeof(rlm_dhcpv4_t),

	.load		= dhcp_load,
	.unload		= dhcp_unload,
	.bootstrap	= mod_bootstrap,
};
