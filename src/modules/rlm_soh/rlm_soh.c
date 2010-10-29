/*
 * rlm_soh.c
 *
 * Version:	$Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2010 Phil Mayers <p.mayers@imperial.ac.uk>
 */

#include	<freeradius-devel/ident.h>
RCSID("$Id$")

#include        <freeradius-devel/radiusd.h>
#include        <freeradius-devel/modules.h>
#include	<freeradius-devel/dhcp.h>
#include	<freeradius-devel/soh.h>


typedef struct rlm_soh_t {
	const char *xlat_name;
	int dhcp;
} rlm_soh_t;


/*
 * Not sure how to make this useful yet...
 */
static size_t soh_xlat(UNUSED void *instance, REQUEST *request, char *fmt, char *out, size_t outlen, UNUSED RADIUS_ESCAPE_STRING func) {

	VALUE_PAIR* vp[6];
	const char *osname;

	/* there will be no point unless SoH-Supported = yes
	 *
	 * FIXME: should have a #define for the attribute...
	 * SoH-Supported == 2119 in dictionary.freeradius.internal
	 */
	vp[0] = pairfind(request->packet->vps, 2119);
	if (!vp[0])
		return 0;


	if (strncasecmp(fmt, "OS", 2) == 0) {
		/* OS vendor */
		vp[0] = pairfind(request->packet->vps, 2100);
		vp[1] = pairfind(request->packet->vps, 2101);
		vp[2] = pairfind(request->packet->vps, 2102);
		vp[3] = pairfind(request->packet->vps, 2103);
		vp[4] = pairfind(request->packet->vps, 2104);
		vp[5] = pairfind(request->packet->vps, 2105);

		if (vp[0] && vp[0]->vp_integer == 311) {
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
	{ "dhcp",    PW_TYPE_BOOLEAN, offsetof(rlm_soh_t,dhcp), NULL, "no" },

	{ NULL, -1, 0, NULL, NULL }		/* end the list */
};

static int soh_detach(void *instance) {
	rlm_soh_t	*inst = instance;

	if (inst->xlat_name) {
		xlat_unregister(inst->xlat_name, soh_xlat);
		free(inst->xlat_name);
	}
	free(instance);
	return 0;
}

static int soh_instantiate(CONF_SECTION *conf, void **instance) {
	rlm_soh_t *inst;

	inst = *instance = rad_malloc(sizeof(*inst));
	if (!inst) {
		return -1;
	}
	memset(inst, 0, sizeof(*inst));

	if (cf_section_parse(conf, inst, module_config) < 0) {
		free(inst);
		return -1;
	}

	inst->xlat_name = cf_section_name2(conf);
	if (!inst->xlat_name) inst->xlat_name = cf_section_name1(conf);
	inst->xlat_name = strdup(inst->xlat_name);
	xlat_register(inst->xlat_name, soh_xlat, inst);

	return 0;
}

static int soh_postauth(UNUSED void * instance, REQUEST *request)
{
#ifdef WITH_DHCP
	int rcode;
	VALUE_PAIR *vp;

	vp = pairfind(request->packet->vps, DHCP2ATTR(43));
	if (vp) {
		/*
		 * vendor-specific options contain
		 *
		 * vendor opt 220/0xdc - SoH payload, or null byte to probe, or string
		 * "NAP" to indicate server-side support for SoH in OFFERs
		 *
		 * vendor opt 222/0xde - SoH correlation ID as utf-16 string, yuck...
		 */
		uint8_t vopt, vlen, *data;

		data = vp->vp_octets;
		while (data < vp->vp_octets + vp->length) {
			vopt = *data++;
			vlen = *data++;
			switch (vopt) {
				case 220:
					if (vlen <= 1) {
						RDEBUG("SoH adding NAP marker to DHCP reply");
						/* client probe; send "NAP" in the reply */
						vp = paircreate(DHCP2ATTR(43), PW_TYPE_OCTETS);
						vp->vp_octets[0] = 220;
						vp->vp_octets[1] = 3;
						vp->vp_octets[4] = 'N';
						vp->vp_octets[3] = 'A';
						vp->vp_octets[2] = 'P';
						vp->length = 5;

						pairadd(&request->reply->vps, vp);

					} else {
						RDEBUG("SoH decoding NAP from DHCP request");
						/* SoH payload */
						rcode = soh_verify(request, request->packet->vps, data, vlen);
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
#endif
	return RLM_MODULE_NOOP;
}

static int soh_authorize(UNUSED void * instance, REQUEST *request)
{
	VALUE_PAIR *vp;
	int rv;

	/* try to find the MS-SoH payload */
	vp = pairfind(request->packet->vps, (311 << 16) | 55);
	if (!vp) {
		RDEBUG("SoH radius VP not found");
		return RLM_MODULE_NOOP;
	}

	RDEBUG("SoH radius VP found");
	/* decode it */
	rv = soh_verify(request, request->packet->vps, vp->vp_octets, vp->length);
	if (rv < 0) {
		return RLM_MODULE_FAIL;
	}

	return RLM_MODULE_OK;
}

module_t rlm_soh = {
	RLM_MODULE_INIT,
	"SoH",
	RLM_TYPE_THREAD_SAFE,		/* type */
	soh_instantiate,		/* instantiation */
	soh_detach,		/* detach */
	{
		NULL,			/* authenticate */
		soh_authorize,		/* authorize */
		NULL,			/* pre-accounting */
		NULL,			/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		soh_postauth		/* post-auth */
	},
};
