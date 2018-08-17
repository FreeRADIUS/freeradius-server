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
 * @file rlm_eap/lib/sim/sim_attrs.h
 * @brief Attributes to EAP-SIM/AKA/AKA' clients and servers.
 *
 * @copyright 2003-2016 The FreeRADIUS server project
 */
#include <freeradius-devel/server/rad_assert.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/eap.sim.h>
#include <freeradius-devel/eap.aka.h>

/*
 *	Sanity check on dictionaries...
 *
 *	EAP-SIM/AKA/AKA' attributes are allocated from
 *	the same IANA number space, so they should
 *	by identical
 */
#define DICT_SANITY_CHECK(_name) \
	static_assert(FR_EAP_SIM_##_name == FR_EAP_AKA_##_name, \
		      "Number mismatch between FR_EAP_SIM_##_name and FR_EAP_AKA_##_name")

DICT_SANITY_CHECK(IDENTITY);
DICT_SANITY_CHECK(IV);
DICT_SANITY_CHECK(PADDING);
DICT_SANITY_CHECK(MAC);

#define FR_SIM_IDENTITY				(FR_EAP_SIM_IDENTITY & FR_EAP_AKA_IDENTITY)
#define FR_SIM_IV				(FR_EAP_SIM_IV & FR_EAP_AKA_IV)
#define FR_SIM_PADDING				(FR_EAP_SIM_PADDING & FR_EAP_AKA_PADDING)
#define FR_SIM_MAC				(FR_EAP_SIM_MAC & FR_EAP_AKA_MAC)

/*
 *	Common internal attributes
 */
DICT_SANITY_CHECK(SUBTYPE);
#define FR_SIM_SUBTYPE				(FR_EAP_SIM_SUBTYPE & FR_EAP_AKA_SUBTYPE)

extern fr_dict_attr_t const *attr_eap_aka_ak;
extern fr_dict_attr_t const *attr_eap_aka_ck;
extern fr_dict_attr_t const *attr_eap_aka_ik;
extern fr_dict_attr_t const *attr_eap_aka_root;
extern fr_dict_attr_t const *attr_eap_aka_subtype;
extern fr_dict_attr_t const *attr_eap_aka_xres;
extern fr_dict_attr_t const *attr_eap_sim_kc;
extern fr_dict_attr_t const *attr_eap_sim_root;
extern fr_dict_attr_t const *attr_eap_sim_sres;
extern fr_dict_attr_t const *attr_eap_sim_subtype;
extern fr_dict_attr_t const *attr_sim_amf;
extern fr_dict_attr_t const *attr_sim_algo_version;
extern fr_dict_attr_t const *attr_sim_identity_type;
extern fr_dict_attr_t const *attr_sim_ki;
extern fr_dict_attr_t const *attr_sim_method_hint;
extern fr_dict_attr_t const *attr_sim_op;
extern fr_dict_attr_t const *attr_sim_opc;
extern fr_dict_attr_t const *attr_sim_sqn;
extern fr_dict_attr_t const *attr_eap_aka_autn;
extern fr_dict_attr_t const *attr_eap_aka_checkcode;
extern fr_dict_attr_t const *attr_eap_aka_iv;
extern fr_dict_attr_t const *attr_eap_aka_identity;
extern fr_dict_attr_t const *attr_eap_aka_mac;
extern fr_dict_attr_t const *attr_eap_aka_padding;
extern fr_dict_attr_t const *attr_eap_aka_rand;
extern fr_dict_attr_t const *attr_eap_aka_res;
extern fr_dict_attr_t const *attr_eap_sim_iv;
extern fr_dict_attr_t const *attr_eap_sim_identity;
extern fr_dict_attr_t const *attr_eap_sim_mac;
extern fr_dict_attr_t const *attr_eap_sim_padding;
extern fr_dict_attr_t const *attr_eap_sim_rand;
