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
 * @file  src/lib/eap_aka_sim/base.c
 * @brief Code common to EAP-SIM/AKA/AKA' clients and servers.
 *
 * The development of the EAP-SIM support was funded by Internet Foundation
 * Austria (http://www.nic.at/ipa).
 *
 * @copyright 2003 Michael Richardson <mcr@sandelman.ottawa.on.ca>
 * @copyright 2003-2016 The FreeRADIUS server project
 */

RCSID("$Id$")

#include <freeradius-devel/util/base.h>
#include <freeradius-devel/util/sha1.h>

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/server/module.h>

#include <freeradius-devel/tls/base.h>

#include <freeradius-devel/eap/types.h>

#include <freeradius-devel/eap_aka_sim/base.h>
#include <freeradius-devel/eap_aka_sim/attrs.h>

static uint32_t instance_count = 0;

fr_dict_t const *dict_freeradius;
fr_dict_t const *dict_radius;
fr_dict_t const *dict_eap_aka_sim;

extern fr_dict_autoload_t libfreeradius_aka_sim_dict[];
fr_dict_autoload_t libfreeradius_aka_sim_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ .out = &dict_eap_aka_sim, .base_dir = "eap/aka-sim", .proto = "eap-aka-sim" },

	{ NULL }
};

fr_dict_attr_t const *attr_eap_aka_sim_ak;
fr_dict_attr_t const *attr_eap_aka_sim_any_id_req;
fr_dict_attr_t const *attr_eap_aka_sim_autn;
fr_dict_attr_t const *attr_eap_aka_sim_auts;
fr_dict_attr_t const *attr_eap_aka_sim_bidding;
fr_dict_attr_t const *attr_eap_aka_sim_checkcode;
fr_dict_attr_t const *attr_eap_aka_sim_ck;
fr_dict_attr_t const *attr_eap_aka_sim_client_error_code;
fr_dict_attr_t const *attr_eap_aka_sim_counter_too_small;
fr_dict_attr_t const *attr_eap_aka_sim_counter;
fr_dict_attr_t const *attr_eap_aka_sim_encr_data;
fr_dict_attr_t const *attr_eap_aka_sim_fullauth_id_req;
fr_dict_attr_t const *attr_eap_aka_sim_identity_type;
fr_dict_attr_t const *attr_eap_aka_sim_identity;
fr_dict_attr_t const *attr_eap_aka_sim_ik;
fr_dict_attr_t const *attr_eap_aka_sim_iv;
fr_dict_attr_t const *attr_eap_aka_sim_k_re;
fr_dict_attr_t const *attr_eap_aka_sim_kc;
fr_dict_attr_t const *attr_eap_aka_sim_kdf_identity;
fr_dict_attr_t const *attr_eap_aka_sim_kdf_input;
fr_dict_attr_t const *attr_eap_aka_sim_kdf;
fr_dict_attr_t const *attr_eap_aka_sim_mac;
fr_dict_attr_t const *attr_eap_aka_sim_method_hint;
fr_dict_attr_t const *attr_eap_aka_sim_mk;
fr_dict_attr_t const *attr_eap_aka_sim_next_pseudonym;
fr_dict_attr_t const *attr_eap_aka_sim_next_reauth_id;
fr_dict_attr_t const *attr_eap_aka_sim_nonce_mt;
fr_dict_attr_t const *attr_eap_aka_sim_nonce_s;
fr_dict_attr_t const *attr_eap_aka_sim_notification;
fr_dict_attr_t const *attr_eap_aka_sim_padding;
fr_dict_attr_t const *attr_eap_aka_sim_permanent_id_req;
fr_dict_attr_t const *attr_eap_aka_sim_permanent_identity;
fr_dict_attr_t const *attr_eap_aka_sim_rand;
fr_dict_attr_t const *attr_eap_aka_sim_res;
fr_dict_attr_t const *attr_eap_aka_sim_result_ind;
fr_dict_attr_t const *attr_eap_aka_sim_sres;
fr_dict_attr_t const *attr_eap_aka_sim_selected_version;
fr_dict_attr_t const *attr_eap_aka_sim_subtype;
fr_dict_attr_t const *attr_eap_aka_sim_version_list;
fr_dict_attr_t const *attr_eap_aka_sim_xres;

fr_dict_attr_t const *attr_ms_mppe_recv_key;
fr_dict_attr_t const *attr_ms_mppe_send_key;

fr_dict_attr_t const *attr_eap_identity;
fr_dict_attr_t const *attr_eap_type;
fr_dict_attr_t const *attr_session_data;
fr_dict_attr_t const *attr_session_id;
fr_dict_attr_t const *attr_sim_algo_version;
fr_dict_attr_t const *attr_sim_amf;
fr_dict_attr_t const *attr_sim_ki;
fr_dict_attr_t const *attr_sim_op;
fr_dict_attr_t const *attr_sim_opc;
fr_dict_attr_t const *attr_sim_sqn;

extern fr_dict_attr_autoload_t libfreeradius_aka_sim_dict_attr[];
fr_dict_attr_autoload_t libfreeradius_aka_sim_dict_attr[] = {
	{ .out = &attr_eap_aka_sim_ak, .name = "AK", .type = FR_TYPE_OCTETS, .dict = &dict_eap_aka_sim },
	{ .out = &attr_eap_aka_sim_any_id_req, .name = "Any-ID-Req", .type = FR_TYPE_BOOL, .dict = &dict_eap_aka_sim },
	{ .out = &attr_eap_aka_sim_autn, .name = "AUTN", .type = FR_TYPE_OCTETS, .dict = &dict_eap_aka_sim },
	{ .out = &attr_eap_aka_sim_auts, .name = "AUTS", .type = FR_TYPE_OCTETS, .dict = &dict_eap_aka_sim },
	{ .out = &attr_eap_aka_sim_bidding, .name = "Bidding", .type = FR_TYPE_UINT16, .dict = &dict_eap_aka_sim },
	{ .out = &attr_eap_aka_sim_checkcode, .name = "Checkcode", .type = FR_TYPE_OCTETS, .dict = &dict_eap_aka_sim },
	{ .out = &attr_eap_aka_sim_ck, .name = "CK", .type = FR_TYPE_OCTETS, .dict = &dict_eap_aka_sim },
	{ .out = &attr_eap_aka_sim_client_error_code, .name = "Client-Error-Code", .type = FR_TYPE_UINT16, .dict = &dict_eap_aka_sim },
	{ .out = &attr_eap_aka_sim_counter_too_small, .name = "Encr-Data.Counter-Too-Small", .type = FR_TYPE_BOOL, .dict = &dict_eap_aka_sim },
	{ .out = &attr_eap_aka_sim_counter, .name = "Encr-Data.Counter", .type = FR_TYPE_UINT16, .dict = &dict_eap_aka_sim },
	{ .out = &attr_eap_aka_sim_encr_data, .name = "Encr-Data", .type = FR_TYPE_TLV, .dict = &dict_eap_aka_sim },
	{ .out = &attr_eap_aka_sim_fullauth_id_req, .name = "Fullauth-ID-Req", .type = FR_TYPE_BOOL, .dict = &dict_eap_aka_sim },
	{ .out = &attr_eap_aka_sim_identity_type, .name = "Identity-Type", .type = FR_TYPE_UINT32, .dict = &dict_eap_aka_sim },
	{ .out = &attr_eap_aka_sim_identity, .name = "Identity", .type = FR_TYPE_STRING, .dict = &dict_eap_aka_sim },
	{ .out = &attr_eap_aka_sim_ik, .name = "IK", .type = FR_TYPE_OCTETS, .dict = &dict_eap_aka_sim },
	{ .out = &attr_eap_aka_sim_iv, .name = "IV", .type = FR_TYPE_OCTETS, .dict = &dict_eap_aka_sim },
	{ .out = &attr_eap_aka_sim_k_re, .name = "K-Re", .type = FR_TYPE_OCTETS, .dict = &dict_eap_aka_sim },
	{ .out = &attr_eap_aka_sim_kc, .name = "KC", .type = FR_TYPE_OCTETS, .dict = &dict_eap_aka_sim },
	{ .out = &attr_eap_aka_sim_kdf_identity, .name = "KDF-Identity", .type = FR_TYPE_STRING, .dict = &dict_eap_aka_sim },
	{ .out = &attr_eap_aka_sim_kdf_input, .name = "KDF-Input", .type = FR_TYPE_STRING, .dict = &dict_eap_aka_sim },
	{ .out = &attr_eap_aka_sim_kdf, .name = "KDF", .type = FR_TYPE_UINT16, .dict = &dict_eap_aka_sim },
	{ .out = &attr_eap_aka_sim_mac, .name = "MAC", .type = FR_TYPE_OCTETS, .dict = &dict_eap_aka_sim },
	{ .out = &attr_eap_aka_sim_method_hint, .name = "Method-Hint", .type = FR_TYPE_UINT32, .dict = &dict_eap_aka_sim },
	{ .out = &attr_eap_aka_sim_mk, .name = "MK", .type = FR_TYPE_OCTETS, .dict = &dict_eap_aka_sim },
	{ .out = &attr_eap_aka_sim_next_pseudonym, .name = "Encr-Data.Next-Pseudonym", .type = FR_TYPE_STRING, .dict = &dict_eap_aka_sim },
	{ .out = &attr_eap_aka_sim_next_reauth_id, .name = "Encr-Data.Next-Reauth-ID", .type = FR_TYPE_STRING, .dict = &dict_eap_aka_sim },
	{ .out = &attr_eap_aka_sim_nonce_mt, .name = "Nonce-MT", .type = FR_TYPE_OCTETS, .dict = &dict_eap_aka_sim },
	{ .out = &attr_eap_aka_sim_nonce_s, .name = "Encr-Data.Nonce-S", .type = FR_TYPE_OCTETS, .dict = &dict_eap_aka_sim },
	{ .out = &attr_eap_aka_sim_notification, .name = "Notification", .type = FR_TYPE_UINT16, .dict = &dict_eap_aka_sim },
	{ .out = &attr_eap_aka_sim_padding, .name = "Encr-Data.Padding", .type = FR_TYPE_OCTETS, .dict = &dict_eap_aka_sim },
	{ .out = &attr_eap_aka_sim_permanent_id_req, .name = "Permanent-Id-Req", .type = FR_TYPE_BOOL, .dict = &dict_eap_aka_sim },
	{ .out = &attr_eap_aka_sim_permanent_identity, .name = "Permanent-Identity", .type = FR_TYPE_STRING, .dict = &dict_eap_aka_sim },
	{ .out = &attr_eap_aka_sim_rand, .name = "RAND", .type = FR_TYPE_OCTETS, .dict = &dict_eap_aka_sim },
	{ .out = &attr_eap_aka_sim_res, .name = "RES", .type = FR_TYPE_OCTETS, .dict = &dict_eap_aka_sim },
	{ .out = &attr_eap_aka_sim_result_ind, .name = "Result-Ind", .type = FR_TYPE_BOOL, .dict = &dict_eap_aka_sim },
	{ .out = &attr_eap_aka_sim_sres, .name = "RES", .type = FR_TYPE_OCTETS, .dict = &dict_eap_aka_sim },
	{ .out = &attr_eap_aka_sim_selected_version, .name = "Selected-Version", .type = FR_TYPE_UINT16, .dict = &dict_eap_aka_sim },
	{ .out = &attr_eap_aka_sim_subtype, .name = "Subtype", .type = FR_TYPE_UINT32, .dict = &dict_eap_aka_sim },
	{ .out = &attr_eap_aka_sim_version_list, .name = "Version-List", .type = FR_TYPE_UINT16, .dict = &dict_eap_aka_sim },
	{ .out = &attr_eap_aka_sim_xres, .name = "XRES", .type = FR_TYPE_OCTETS, .dict = &dict_eap_aka_sim },

	{ .out = &attr_ms_mppe_send_key, .name = "Vendor-Specific.Microsoft.MPPE-Send-Key", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_ms_mppe_recv_key, .name = "Vendor-Specific.Microsoft.MPPE-Recv-Key", .type = FR_TYPE_OCTETS, .dict = &dict_radius },

	/*
	 *	Separate from the EAP-AKA-AND-SIM dictionary
	 *	as they're outside the notional numberspace.
	 */
	{ .out = &attr_eap_identity, .name = "EAP-Identity", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_eap_type, .name = "EAP-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },

	{ .out = &attr_session_data, .name = "Session-Data", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_session_id, .name = "Session-Id", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_sim_algo_version, .name = "SIM-Algo-Version", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_sim_amf, .name = "SIM-AMF", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_sim_ki, .name = "SIM-Ki", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_sim_op, .name = "SIM-OP", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_sim_opc, .name = "SIM-OPc", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_sim_sqn, .name = "SIM-SQN", .type = FR_TYPE_UINT64, .dict = &dict_freeradius },
	{ NULL }
};

fr_value_box_t const	*enum_eap_type_sim;
fr_value_box_t const	*enum_eap_type_aka;
fr_value_box_t const	*enum_eap_type_aka_prime;

extern fr_dict_enum_autoload_t libfreeradius_aka_sim_dict_enum[];
fr_dict_enum_autoload_t libfreeradius_aka_sim_dict_enum[] = {
	{ .out = &enum_eap_type_sim, .name = "SIM", .attr = &attr_eap_type },
	{ .out = &enum_eap_type_aka, .name = "AKA", .attr = &attr_eap_type },
	{ .out = &enum_eap_type_aka_prime, .name = "AKA-Prime", .attr = &attr_eap_type },
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
size_t const fr_aka_sim_attr_sizes[FR_TYPE_MAX + 1][2] = {
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
size_t fr_aka_sim_attr_len(fr_pair_t const *vp)
{
	switch (vp->vp_type) {
	case FR_TYPE_VARIABLE_SIZE:
		return vp->vp_length;

	default:
		return fr_aka_sim_attr_sizes[vp->vp_type][0];

	case FR_TYPE_STRUCTURAL:
		if (!fr_cond_assert(0)) return 0;
	}
}

/** Return the number of bytes before the octets value
 *
 */
size_t fr_aka_sim_octets_prefix_len(fr_dict_attr_t const *da)
{
	if (da->flags.array) return 0;		/* Array elements have no padding */
	if (!da->flags.length) return 2;	/* Variable length attributes need length field */
	if (!(da->flags.length % 4)) return 2;	/* Values that are multiples of four have 2 reserved bytes */
	return 0;				/* Everything else has zero padding bytes */
}

int fr_aka_sim_init(void)
{
	if (instance_count > 0) {
		instance_count++;
		return 0;
	}

	if (fr_dict_autoload(libfreeradius_aka_sim_dict) < 0) {
		PERROR("Failed loading libfreeradius-eap-aka-sim dictionaries");
		return -1;
	}
	if (fr_dict_attr_autoload(libfreeradius_aka_sim_dict_attr) < 0) {
		PERROR("Failed loading libfreeradius-eap-aka-sim attributes");
		fr_dict_autofree(libfreeradius_aka_sim_dict);
		return -1;
	}
	instance_count++;

	return 0;
}

void fr_aka_sim_free(void)
{
	if (--instance_count > 0) return;

	fr_dict_autofree(libfreeradius_aka_sim_dict);
}

static fr_table_num_ordered_t const subtype_table[] = {
	{ L("encrypt=aes-cbc"),		1 }, /* any non-zero value will do */
};

extern fr_dict_protocol_t libfreeradius_eap_aka_sim_dict_protocol;
fr_dict_protocol_t libfreeradius_eap_aka_sim_dict_protocol = {
	.name = "eap_aka_sim",
	.default_type_size = 1,
	.default_type_length = 1,
	.subtype_table = subtype_table,
	.subtype_table_len = NUM_ELEMENTS(subtype_table),
};
