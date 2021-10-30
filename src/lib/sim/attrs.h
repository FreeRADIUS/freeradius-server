#pragma once
/*
 *   This program is free software; you can redistribute it and/or modify
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
 * @file src/lib/sim/attrs.h
 * @brief Attributes to EAP-SIM/AKA/AKA' clients and servers.
 *
 * @copyright 2003-2016 The FreeRADIUS server project
 */
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/protocol/eap/sim/dictionary.h>
#include <freeradius-devel/protocol/eap/sim/rfc4187.h>
#include <freeradius-devel/protocol/eap/aka/dictionary.h>
#include <freeradius-devel/protocol/eap/aka/rfc4187.h>
#include <freeradius-devel/protocol/eap/aka/freeradius.h>

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

extern HIDDEN fr_dict_t *dict_freeradius;
extern HIDDEN fr_dict_t *dict_radius;
extern HIDDEN fr_dict_t *dict_eap_sim;
extern HIDDEN fr_dict_t *dict_eap_aka;

extern HIDDEN fr_dict_attr_t const *attr_eap_aka_ak;
extern HIDDEN fr_dict_attr_t const *attr_eap_aka_autn;
extern HIDDEN fr_dict_attr_t const *attr_eap_aka_auts;
extern HIDDEN fr_dict_attr_t const *attr_eap_aka_checkcode;
extern HIDDEN fr_dict_attr_t const *attr_eap_aka_ck;
extern HIDDEN fr_dict_attr_t const *attr_eap_aka_counter;
extern HIDDEN fr_dict_attr_t const *attr_eap_aka_identity;
extern HIDDEN fr_dict_attr_t const *attr_eap_aka_ik;
extern HIDDEN fr_dict_attr_t const *attr_eap_aka_iv;
extern HIDDEN fr_dict_attr_t const *attr_eap_aka_mac;
extern HIDDEN fr_dict_attr_t const *attr_eap_aka_mk;
extern HIDDEN fr_dict_attr_t const *attr_eap_aka_padding;
extern HIDDEN fr_dict_attr_t const *attr_eap_aka_rand;
extern HIDDEN fr_dict_attr_t const *attr_eap_aka_res;
extern HIDDEN fr_dict_attr_t const *attr_eap_aka_subtype;
extern HIDDEN fr_dict_attr_t const *attr_eap_aka_xres;

extern HIDDEN fr_dict_attr_t const *attr_eap_sim_identity;
extern HIDDEN fr_dict_attr_t const *attr_eap_sim_iv;
extern HIDDEN fr_dict_attr_t const *attr_eap_sim_kc;
extern HIDDEN fr_dict_attr_t const *attr_eap_sim_mac;
extern HIDDEN fr_dict_attr_t const *attr_eap_sim_padding;
extern HIDDEN fr_dict_attr_t const *attr_eap_sim_rand;
extern HIDDEN fr_dict_attr_t const *attr_eap_sim_sres;
extern HIDDEN fr_dict_attr_t const *attr_eap_sim_subtype;

extern HIDDEN fr_dict_attr_t const *attr_eap_type;
extern HIDDEN fr_dict_attr_t const *attr_sim_algo_version;
extern HIDDEN fr_dict_attr_t const *attr_sim_amf;
extern HIDDEN fr_dict_attr_t const *attr_sim_identity_type;
extern HIDDEN fr_dict_attr_t const *attr_sim_ki;
extern HIDDEN fr_dict_attr_t const *attr_sim_method_hint;
extern HIDDEN fr_dict_attr_t const *attr_sim_op;
extern HIDDEN fr_dict_attr_t const *attr_sim_opc;
extern HIDDEN fr_dict_attr_t const *attr_sim_sqn;
