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
 * @copyright 2010 Phil Mayers <p.mayers@imperial.ac.uk>
 */
RCSID("$Id$")

#include	<freeradius-devel/radiusd.h>
#include	<freeradius-devel/modules.h>
#include	<freeradius-devel/dhcp.h>
#include	<freeradius-devel/soh.h>


typedef struct rlm_soh_t {
	char const *xlat_name;
	bool dhcp;
} rlm_soh_t;


/*
 * Not sure how to make this useful yet...
 */
static ssize_t soh_xlat(UNUSED void *instance, REQUEST *request, char const *fmt, char *out, size_t outlen) {

	VALUE_PAIR* vp[6];
	char const *osname;

	/*
	 * There will be no point unless SoH-Supported = yes
	 */
	vp[0] = fr_pair_find_by_num(request->packet->vps, PW_SOH_SUPPORTED, 0, TAG_ANY);
	if (!vp[0])
		return 0;


	if (strncasecmp(fmt, "OS", 2) == 0) {
		/* OS vendor */
		vp[0] = fr_pair_find_by_num(request->packet->vps, PW_SOH_MS_MACHINE_OS_VENDOR,  0, TAG_ANY);
		vp[1] = fr_pair_find_by_num(request->packet->vps, PW_SOH_MS_MACHINE_OS_VERSION, 0, TAG_ANY);
		vp[2] = fr_pair_find_by_num(request->packet->vps, PW_SOH_MS_MACHINE_OS_RELEASE, 0, TAG_ANY);
		vp[3] = fr_pair_find_by_num(request->packet->vps, PW_SOH_MS_MACHINE_OS_BUILD,   0, TAG_ANY);
		vp[4] = fr_pair_find_by_num(request->packet->vps, PW_SOH_MS_MACHINE_SP_VERSION, 0, TAG_ANY);
		vp[5] = fr_pair_find_by_num(request->packet->vps, PW_SOH_MS_MACHINE_SP_RELEASE, 0, TAG_ANY);

		if (vp[0] && vp[0]->vp_integer == VENDORPEC_MICROSOFT) {
			if (!vp[1]) {
				snprintf(out, outlen, "Windows unknown");
			} else {
				switch (vp[1]->vp_integer) {
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
				snprintf(out, outlen, "Windows %s %d.%d.%d sp %d.%d", osname, vp[1]->vp_integer,
						vp[2] ? vp[2]->vp_integer : 0,
						vp[3] ? vp[3]->vp_integer : 0,
						vp[4] ? vp[4]->vp_integer : 0,
						vp[5] ? vp[5]->vp_integer : 0
					);
			}
			return strlen(out);
		}
	}

	return 0;
}


static const CONF_PARSER module_config[] = {
	/*
	 * Do SoH over DHCP?
	 */
	{ "dhcp", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_soh_t, dhcp), "no" },
	CONF_PARSER_TERMINATOR
};


static int mod_bootstrap(CONF_SECTION *conf, void *instance)
{
	char const *name;
	rlm_soh_t *inst = instance;

	name = cf_section_name2(conf);
	if (!name) name = cf_section_name1(conf);
	inst->xlat_name = name;
	if (!inst->xlat_name) return -1;

	xlat_register(inst->xlat_name, soh_xlat, NULL, inst);

	return 0;
}

#ifdef WITH_DHCP
static rlm_rcode_t CC_HINT(nonnull) mod_post_auth(void *instance, REQUEST *request)
{
	int rcode;
	VALUE_PAIR *vp;
	rlm_soh_t *inst = instance;

	if (!inst->dhcp) return RLM_MODULE_NOOP;

	vp = fr_pair_find_by_num(request->packet->vps, 43, DHCP_MAGIC_VENDOR, TAG_ANY);
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

					RDEBUG("SoH adding NAP marker to DHCP reply");
					/* client probe; send "NAP" in the reply */
					vp = fr_pair_afrom_num(request->reply, 43, DHCP_MAGIC_VENDOR);
					vp->vp_length = 5;
					vp->vp_octets = p = talloc_array(vp, uint8_t, vp->vp_length);

					p[0] = 220;
					p[1] = 3;
					p[4] = 'N';
					p[3] = 'A';
					p[2] = 'P';

					fr_pair_add(&request->reply->vps, vp);

				} else {
					RDEBUG("SoH decoding NAP from DHCP request");
					/* SoH payload */
					rcode = soh_verify(request, data, vlen);
					if (rcode < 0) {
						return RLM_MODULE_FAIL;
					}
				}
				break;

			default:
				/* nothing to do */
				break;
			}
			data += vlen;
		}
		return RLM_MODULE_OK;
	}
	return RLM_MODULE_NOOP;
}
#endif

static rlm_rcode_t CC_HINT(nonnull) mod_authorize(UNUSED void * instance, REQUEST *request)
{
	VALUE_PAIR *vp;
	int rv;

	/* try to find the MS-SoH payload */
	vp = fr_pair_find_by_num(request->packet->vps, 55, VENDORPEC_MICROSOFT, TAG_ANY);
	if (!vp) {
		RDEBUG("SoH radius VP not found");
		return RLM_MODULE_NOOP;
	}

	RDEBUG("SoH radius VP found");
	/* decode it */
	rv = soh_verify(request, vp->vp_octets, vp->vp_length);
	if (rv < 0) {
		return RLM_MODULE_FAIL;
	}

	return RLM_MODULE_OK;
}

extern module_t rlm_soh;
module_t rlm_soh = {
	.magic		= RLM_MODULE_INIT,
	.name		= "soh",
	.type		= RLM_TYPE_THREAD_SAFE,
	.inst_size	= sizeof(rlm_soh_t),
	.config		= module_config,
	.bootstrap	= mod_bootstrap,
	.methods = {
		[MOD_AUTHORIZE]		= mod_authorize,
#ifdef WITH_DHCP
		[MOD_POST_AUTH]		= mod_post_auth
#endif
	},
};
