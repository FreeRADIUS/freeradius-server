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
 * @file src/lib/sim/base.c
 * @brief Code common to EAP-SIM/AKA/AKA' clients and servers.
 *
 * The development of the EAP-SIM support was funded by Internet Foundation
 * Austria (http://www.nic.at/ipa).
 *
 * @copyright 2003 Michael Richardson (mcr@sandelman.ottawa.on.ca)
 * @copyright 2003-2016 The FreeRADIUS server project
 */

RCSID("$Id$")

#include <freeradius-devel/util/base.h>
#include <freeradius-devel/util/sha1.h>
#include <freeradius-devel/server/rad_assert.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/tls/base.h>

#include <freeradius-devel/eap/types.h>
#include "eap_sim_common.h"
#include "base.h"
#include "attrs.h"

static int instance_count = 0;

fr_dict_t *dict_freeradius;
fr_dict_t *dict_radius;
fr_dict_t *dict_eap_sim;
fr_dict_t *dict_eap_aka;

extern fr_dict_autoload_t libfreeradius_sim_dict[];
fr_dict_autoload_t libfreeradius_sim_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ .out = &dict_eap_sim, .proto = "eap-sim", .base_dir = "eap/sim" },
	{ .out = &dict_eap_aka, .proto = "eap-aka", .base_dir = "eap/aka" },

	{ NULL }
};

fr_dict_attr_t const *attr_eap_aka_ak;
fr_dict_attr_t const *attr_eap_aka_autn;
fr_dict_attr_t const *attr_eap_aka_auts;
fr_dict_attr_t const *attr_eap_aka_checkcode;
fr_dict_attr_t const *attr_eap_aka_ck;
fr_dict_attr_t const *attr_eap_aka_counter;
fr_dict_attr_t const *attr_eap_aka_identity;
fr_dict_attr_t const *attr_eap_aka_ik;
fr_dict_attr_t const *attr_eap_aka_iv;
fr_dict_attr_t const *attr_eap_aka_mac;
fr_dict_attr_t const *attr_eap_aka_mk;
fr_dict_attr_t const *attr_eap_aka_padding;
fr_dict_attr_t const *attr_eap_aka_rand;
fr_dict_attr_t const *attr_eap_aka_res;
fr_dict_attr_t const *attr_eap_aka_subtype;
fr_dict_attr_t const *attr_eap_aka_xres;

fr_dict_attr_t const *attr_eap_sim_identity;
fr_dict_attr_t const *attr_eap_sim_iv;
fr_dict_attr_t const *attr_eap_sim_kc;
fr_dict_attr_t const *attr_eap_sim_mac;
fr_dict_attr_t const *attr_eap_sim_padding;
fr_dict_attr_t const *attr_eap_sim_rand;
fr_dict_attr_t const *attr_eap_sim_sres;
fr_dict_attr_t const *attr_eap_sim_subtype;

fr_dict_attr_t const *attr_eap_type;
fr_dict_attr_t const *attr_sim_algo_version;
fr_dict_attr_t const *attr_sim_amf;
fr_dict_attr_t const *attr_sim_identity_type;
fr_dict_attr_t const *attr_sim_ki;
fr_dict_attr_t const *attr_sim_method_hint;
fr_dict_attr_t const *attr_sim_op;
fr_dict_attr_t const *attr_sim_opc;
fr_dict_attr_t const *attr_sim_sqn;

extern fr_dict_attr_autoload_t libfreeradius_sim_dict_attr[];
fr_dict_attr_autoload_t libfreeradius_sim_dict_attr[] = {
	{ .out = &attr_eap_aka_ak, .name = "EAP-AKA-AK", .type = FR_TYPE_OCTETS, .dict = &dict_eap_aka },
	{ .out = &attr_eap_aka_autn, .name = "EAP-AKA-AUTN", .type = FR_TYPE_OCTETS, .dict = &dict_eap_aka },
	{ .out = &attr_eap_aka_auts, .name = "EAP-AKA-AUTS", .type = FR_TYPE_OCTETS, .dict = &dict_eap_aka },
	{ .out = &attr_eap_aka_counter, .name = "EAP-AKA-Counter", .type = FR_TYPE_UINT16, .dict = &dict_eap_aka },
	{ .out = &attr_eap_aka_checkcode, .name = "EAP-AKA-Checkcode", .type = FR_TYPE_OCTETS, .dict = &dict_eap_aka },
	{ .out = &attr_eap_aka_ck, .name = "EAP-AKA-CK", .type = FR_TYPE_OCTETS, .dict = &dict_eap_aka },
	{ .out = &attr_eap_aka_identity, .name = "EAP-AKA-Identity", .type = FR_TYPE_STRING, .dict = &dict_eap_aka },
	{ .out = &attr_eap_aka_ik, .name = "EAP-AKA-IK", .type = FR_TYPE_OCTETS, .dict = &dict_eap_aka },
	{ .out = &attr_eap_aka_iv, .name = "EAP-AKA-IV", .type = FR_TYPE_OCTETS, .dict = &dict_eap_aka },
	{ .out = &attr_eap_aka_mac, .name = "EAP-AKA-MAC", .type = FR_TYPE_OCTETS, .dict = &dict_eap_aka },
	{ .out = &attr_eap_aka_mk, .name = "EAP-AKA-MK", .type = FR_TYPE_OCTETS, .dict = &dict_eap_aka },
	{ .out = &attr_eap_aka_padding, .name = "EAP-AKA-Padding", .type = FR_TYPE_OCTETS, .dict = &dict_eap_aka },
	{ .out = &attr_eap_aka_rand, .name = "EAP-AKA-RAND", .type = FR_TYPE_OCTETS, .dict = &dict_eap_aka },
	{ .out = &attr_eap_aka_res, .name = "EAP-AKA-RES", .type = FR_TYPE_OCTETS, .dict = &dict_eap_aka },
	{ .out = &attr_eap_aka_subtype, .name = "EAP-AKA-Subtype", .type = FR_TYPE_UINT32, .dict = &dict_eap_aka },
	{ .out = &attr_eap_aka_xres, .name = "EAP-AKA-XRES", .type = FR_TYPE_OCTETS, .dict = &dict_eap_aka },

	{ .out = &attr_eap_sim_identity, .name = "EAP-SIM-Identity", .type = FR_TYPE_STRING, .dict = &dict_eap_sim },
	{ .out = &attr_eap_sim_iv, .name = "EAP-SIM-IV", .type = FR_TYPE_OCTETS, .dict = &dict_eap_sim },
	{ .out = &attr_eap_sim_kc, .name = "EAP-SIM-KC", .type = FR_TYPE_OCTETS, .dict = &dict_eap_sim },
	{ .out = &attr_eap_sim_mac, .name = "EAP-SIM-MAC", .type = FR_TYPE_OCTETS, .dict = &dict_eap_sim },
	{ .out = &attr_eap_sim_padding, .name = "EAP-SIM-Padding", .type = FR_TYPE_OCTETS, .dict = &dict_eap_sim },
	{ .out = &attr_eap_sim_rand, .name = "EAP-SIM-RAND", .type = FR_TYPE_OCTETS, .dict = &dict_eap_sim },
	{ .out = &attr_eap_sim_sres, .name = "EAP-SIM-SRES", .type = FR_TYPE_OCTETS, .dict = &dict_eap_sim },
	{ .out = &attr_eap_sim_subtype, .name = "EAP-SIM-Subtype", .type = FR_TYPE_UINT32, .dict = &dict_eap_sim },

	{ .out = &attr_eap_type, .name = "EAP-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_sim_algo_version, .name = "SIM-Algo-Version", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_sim_amf, .name = "SIM-AMF", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_sim_identity_type, .name = "SIM-Identity-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_sim_ki, .name = "SIM-Ki", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_sim_method_hint, .name = "SIM-Method-Hint", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_sim_op, .name = "SIM-OP", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_sim_opc, .name = "SIM-OPc", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_sim_sqn, .name = "SIM-SQN", .type = FR_TYPE_UINT64, .dict = &dict_freeradius },

	{ NULL }
};

/** SIM AT on-the-wire format attribute sizes
 *
 * Holds the min/max sizes of all supported SIM AT attribute values as they
 * would be found in a SIM AT packet.
 *
 * These sizes may be different than the sizes of INTERNAL formats, PRESENTATION
 * formats and generic NETWORK formats.
 */
size_t const fr_sim_attr_sizes[FR_TYPE_MAX + 1][2] = {
	[FR_TYPE_INVALID]		= {~0, 0},

	[FR_TYPE_STRING]		= {0, ~0},
	[FR_TYPE_OCTETS]		= {0, ~0},

	[FR_TYPE_BOOL]			= {2, 2},
	[FR_TYPE_UINT8]			= {1, 1},
	[FR_TYPE_UINT16]		= {2, 2},
	[FR_TYPE_UINT32]		= {4, 4},
	[FR_TYPE_UINT64]		= {8, 8},

	[FR_TYPE_TLV]			= {2, ~0},

	[FR_TYPE_MAX]			= {~0, 0}	//!< Ensure array covers all types.
};

/** Return the on-the-wire length of an attribute value
 *
 * @param[in] vp to return the length of.
 * @return the length of the attribute.
 */
size_t fr_sim_attr_len(VALUE_PAIR const *vp)
{
	switch (vp->vp_type) {
	case FR_TYPE_VARIABLE_SIZE:
		return vp->vp_length;

	default:
		return fr_sim_attr_sizes[vp->vp_type][0];

	case FR_TYPE_STRUCTURAL:
		if (!fr_cond_assert(0)) return 0;
		return 0;
	}
}

/** Return the number of bytes before the octets value
 *
 */
size_t fr_sim_octets_prefix_len(fr_dict_attr_t const *da)
{
	if (da->flags.array) return 0;		/* Array elements have no padding */
	if (!da->flags.length) return 2;	/* Variable length attributes need length field */
	if (!(da->flags.length % 4)) return 2;	/* Values that are multiples of four have 2 reserved bytes */
	return 0;				/* Everything else has zero padding bytes */
}

int fr_sim_init(void)
{
	if (instance_count > 0) {
		instance_count++;
		return 0;
	}

	if (fr_dict_autoload(libfreeradius_sim_dict) < 0) {
		PERROR("Failed loading libfreeradius-sim dictionaries");
		return -1;
	}
	if (fr_dict_attr_autoload(libfreeradius_sim_dict_attr) < 0) {
		PERROR("Failed loading libfreeradius-sim attributes");
		fr_dict_autofree(libfreeradius_sim_dict);
		return -1;
	}
	instance_count++;

	return 0;
}

void fr_sim_free(void)
{
	if (--instance_count > 0) return;

	fr_dict_autofree(libfreeradius_sim_dict);
}

