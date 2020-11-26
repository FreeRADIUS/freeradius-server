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
 * @file rlm_soh.c
 * @brief Decodes Microsoft's Statement of Health sub-protocol.
 *
 * @copyright 2010 Phil Mayers (p.mayers@imperial.ac.uk)
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/dhcpv4/dhcpv4.h>
#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/soh/base.h>

typedef struct {
	char const *xlat_name;
	bool dhcp;
} rlm_soh_t;

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_dhcpv4;
static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t rlm_soh_dict[];
fr_dict_autoload_t rlm_soh_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_dhcpv4, .proto = "dhcpv4" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_soh_supported;
static fr_dict_attr_t const *attr_soh_ms_machine_os_vendor;
static fr_dict_attr_t const *attr_soh_ms_machine_os_version;
static fr_dict_attr_t const *attr_soh_ms_machine_os_release;
static fr_dict_attr_t const *attr_soh_ms_machine_os_build;
static fr_dict_attr_t const *attr_soh_ms_machine_sp_version;
static fr_dict_attr_t const *attr_soh_ms_machine_sp_release;
static fr_dict_attr_t const *attr_ms_quarantine_soh;
static fr_dict_attr_t const *attr_dhcp_vendor;

extern fr_dict_attr_autoload_t rlm_soh_dict_attr[];
fr_dict_attr_autoload_t rlm_soh_dict_attr[] = {
	{ .out = &attr_soh_supported, .name = "SoH-Supported", .type = FR_TYPE_BOOL, .dict = &dict_freeradius },
	{ .out = &attr_soh_ms_machine_os_vendor, .name = "SoH-MS-Machine-OS-vendor", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_soh_ms_machine_os_version, .name = "SoH-MS-Machine-OS-version", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_soh_ms_machine_os_release, .name = "SoH-MS-Machine-OS-release", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_soh_ms_machine_os_build, .name = "SoH-MS-Machine-OS-build", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_soh_ms_machine_sp_version, .name = "SoH-MS-Machine-SP-version", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_soh_ms_machine_sp_release, .name = "SoH-MS-Machine-SP-release", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_ms_quarantine_soh, .name = "Vendor-Specific.Microsoft.Quarantine-SOH", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_dhcp_vendor, .name = "DHCP-Vendor", .type = FR_TYPE_OCTETS, .dict = &dict_dhcpv4 },
	{ NULL }
};

/** SoH xlat
 *
 * Not sure how to make this useful yet...
 *
 * @ingroup xlat_functions
 */
static ssize_t soh_xlat(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			request_t *request, char const *fmt)
{
	fr_pair_t* vp[6];
	char const *osname;

	/*
	 * There will be no point unless SoH-Supported = yes
	 */
	vp[0] = fr_pair_find_by_da(&request->request_pairs, attr_soh_supported);
	if (!vp[0])
		return 0;


	if (strncasecmp(fmt, "OS", 2) == 0) {
		/* OS vendor */
		vp[0] = fr_pair_find_by_da(&request->request_pairs, attr_soh_ms_machine_os_vendor);
		vp[1] = fr_pair_find_by_da(&request->request_pairs, attr_soh_ms_machine_os_version);
		vp[2] = fr_pair_find_by_da(&request->request_pairs, attr_soh_ms_machine_os_release);
		vp[3] = fr_pair_find_by_da(&request->request_pairs, attr_soh_ms_machine_os_build);
		vp[4] = fr_pair_find_by_da(&request->request_pairs, attr_soh_ms_machine_sp_version);
		vp[5] = fr_pair_find_by_da(&request->request_pairs, attr_soh_ms_machine_sp_release);

		if (vp[0] && vp[0]->vp_uint32 == VENDORPEC_MICROSOFT) {
			if (!vp[1]) {
				snprintf(*out, outlen, "Windows unknown");
			} else {
				switch (vp[1]->vp_uint32) {
				case 7:
					osname = "7";
					break;

				case 6:
					osname = "Vista";
					break;

				case 5:
					osname = "XP";
					break;

				default:
					osname = "Other";
					break;
				}
				snprintf(*out, outlen, "Windows %s %d.%d.%d sp %d.%d", osname, vp[1]->vp_uint32,
					 vp[2] ? vp[2]->vp_uint32 : 0,
					 vp[3] ? vp[3]->vp_uint32 : 0,
					 vp[4] ? vp[4]->vp_uint32 : 0,
					 vp[5] ? vp[5]->vp_uint32 : 0);
			}
			return strlen(*out);
		}
	}

	return 0;
}


static const CONF_PARSER module_config[] = {
	/*
	 * Do SoH over DHCP?
	 */
	{ FR_CONF_OFFSET("dhcp", FR_TYPE_BOOL, rlm_soh_t, dhcp), .dflt = "no" },
	CONF_PARSER_TERMINATOR
};

static unlang_action_t CC_HINT(nonnull) mod_post_auth(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	int			rcode;
	fr_pair_t		*vp;
	rlm_soh_t const		*inst = talloc_get_type_abort_const(mctx->instance, rlm_soh_t);

	if (!inst->dhcp) RETURN_MODULE_NOOP;

	vp = fr_pair_find_by_da(&request->request_pairs, attr_dhcp_vendor);
	if (vp) {
		/*
		 * vendor-specific options contain
		 *
		 * vendor opt 220/0xdc - SoH payload, or null byte to probe, or string
		 * "NAP" to indicate server-side support for SoH in OFFERs
		 *
		 * vendor opt 222/0xde - SoH correlation ID as utf-16 string, yuck...
		 */
		uint8_t vopt, vlen;
		uint8_t const *data;

		data = vp->vp_octets;
		while (data < vp->vp_octets + vp->vp_length) {
			vopt = *data++;
			vlen = *data++;
			switch (vopt) {
			case 220:
				if (vlen <= 1) {
					uint8_t *p;

					RDEBUG2("SoH adding NAP marker to DHCP reply");
					/* client probe; send "NAP" in the reply */
					MEM(vp = fr_pair_afrom_da(request->reply, attr_dhcp_vendor));
					MEM(fr_pair_value_mem_alloc(vp, &p, 5, false) == 0);
					p[0] = 220;
					p[1] = 3;
					p[4] = 'N';
					p[3] = 'A';
					p[2] = 'P';
					fr_pair_add(&request->reply_pairs, vp);

				} else {
					RDEBUG2("SoH decoding NAP from DHCP request");
					/* SoH payload */
					rcode = soh_verify(request, data, vlen);
					if (rcode < 0) {
						RETURN_MODULE_FAIL;
					}
				}
				break;

			default:
				/* nothing to do */
				break;
			}
			data += vlen;
		}
		RETURN_MODULE_OK;
	}

	RETURN_MODULE_NOOP;
}

static unlang_action_t CC_HINT(nonnull) mod_authorize(rlm_rcode_t *p_result, UNUSED module_ctx_t const *mctx, request_t *request)
{
	fr_pair_t *vp;
	int rv;

	/* try to find the MS-SoH payload */
	vp = fr_pair_find_by_da(&request->request_pairs, attr_ms_quarantine_soh);
	if (!vp) {
		RDEBUG2("SoH radius VP not found");
		RETURN_MODULE_NOOP;
	}

	RDEBUG2("SoH radius VP found");
	/* decode it */
	rv = soh_verify(request, vp->vp_octets, vp->vp_length);
	if (rv < 0) {
		RETURN_MODULE_FAIL;
	}

	RETURN_MODULE_OK;
}

static int mod_bootstrap(void *instance, CONF_SECTION *conf)
{
	char const	*name;
	rlm_soh_t	*inst = instance;

	name = cf_section_name2(conf);
	if (!name) name = cf_section_name1(conf);
	inst->xlat_name = name;
	if (!inst->xlat_name) return -1;

	xlat_register_legacy(inst, inst->xlat_name, soh_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN);

	return 0;
}

static int mod_load(void)
{
	if (fr_soh_init() < 0) return -1;

	return 0;
}

static void mod_unload(void)
{
	fr_soh_free();
}

extern module_t rlm_soh;
module_t rlm_soh = {
	.magic		= RLM_MODULE_INIT,
	.name		= "soh",
	.type		= RLM_TYPE_THREAD_SAFE,
	.inst_size	= sizeof(rlm_soh_t),
	.config		= module_config,
	.onload		= mod_load,
	.unload		= mod_unload,
	.bootstrap	= mod_bootstrap,
	.methods = {
		[MOD_AUTHORIZE]		= mod_authorize,
		[MOD_POST_AUTH]		= mod_post_auth
	},
};
