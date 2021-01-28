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
 * @file src/lib/eap_aka_sim/attrs.h
 * @brief Attributes to EAP-SIM/AKA/AKA' clients and servers.
 *
 * @copyright 2003-2016 The FreeRADIUS server project
 */
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/protocol/eap/aka-sim/dictionary.h>
#include <freeradius-devel/protocol/eap/aka-sim/rfc4187.h>
#include <freeradius-devel/protocol/eap/aka-sim/freeradius.h>

extern fr_dict_t const *dict_freeradius;
extern fr_dict_t const *dict_radius;
extern fr_dict_t const *dict_eap_aka_sim;

extern fr_dict_attr_t const *attr_eap_aka_sim_ak;
extern fr_dict_attr_t const *attr_eap_aka_sim_any_id_req;
extern fr_dict_attr_t const *attr_eap_aka_sim_autn;
extern fr_dict_attr_t const *attr_eap_aka_sim_auts;
extern fr_dict_attr_t const *attr_eap_aka_sim_bidding;
extern fr_dict_attr_t const *attr_eap_aka_sim_checkcode;
extern fr_dict_attr_t const *attr_eap_aka_sim_ck;
extern fr_dict_attr_t const *attr_eap_aka_sim_client_error_code;
extern fr_dict_attr_t const *attr_eap_aka_sim_counter_too_small;
extern fr_dict_attr_t const *attr_eap_aka_sim_counter;
extern fr_dict_attr_t const *attr_eap_aka_sim_encr_data;
extern fr_dict_attr_t const *attr_eap_aka_sim_fullauth_id_req;
extern fr_dict_attr_t const *attr_eap_aka_sim_identity_type;
extern fr_dict_attr_t const *attr_eap_aka_sim_identity;
extern fr_dict_attr_t const *attr_eap_aka_sim_ik;
extern fr_dict_attr_t const *attr_eap_aka_sim_iv;
extern fr_dict_attr_t const *attr_eap_aka_sim_k_re;
extern fr_dict_attr_t const *attr_eap_aka_sim_kc;
extern fr_dict_attr_t const *attr_eap_aka_sim_kdf_identity;
extern fr_dict_attr_t const *attr_eap_aka_sim_kdf_input;
extern fr_dict_attr_t const *attr_eap_aka_sim_kdf;
extern fr_dict_attr_t const *attr_eap_aka_sim_mac;
extern fr_dict_attr_t const *attr_eap_aka_sim_method_hint;
extern fr_dict_attr_t const *attr_eap_aka_sim_mk;
extern fr_dict_attr_t const *attr_eap_aka_sim_next_pseudonym;
extern fr_dict_attr_t const *attr_eap_aka_sim_next_reauth_id;
extern fr_dict_attr_t const *attr_eap_aka_sim_nonce_mt;
extern fr_dict_attr_t const *attr_eap_aka_sim_nonce_s;
extern fr_dict_attr_t const *attr_eap_aka_sim_notification;
extern fr_dict_attr_t const *attr_eap_aka_sim_padding;
extern fr_dict_attr_t const *attr_eap_aka_sim_permanent_id_req;
extern fr_dict_attr_t const *attr_eap_aka_sim_permanent_identity;
extern fr_dict_attr_t const *attr_eap_aka_sim_rand;
extern fr_dict_attr_t const *attr_eap_aka_sim_res;
extern fr_dict_attr_t const *attr_eap_aka_sim_result_ind;
extern fr_dict_attr_t const *attr_eap_aka_sim_sres;
extern fr_dict_attr_t const *attr_eap_aka_sim_subtype;
extern fr_dict_attr_t const *attr_eap_aka_sim_selected_version;
extern fr_dict_attr_t const *attr_eap_aka_sim_version_list;
extern fr_dict_attr_t const *attr_eap_aka_sim_xres;


extern fr_dict_attr_t const *attr_ms_mppe_recv_key;
extern fr_dict_attr_t const *attr_ms_mppe_send_key;

extern fr_dict_attr_t const *attr_eap_identity;
extern fr_dict_attr_t const *attr_eap_type;
extern fr_dict_attr_t const *attr_session_data;
extern fr_dict_attr_t const *attr_session_id;
extern fr_dict_attr_t const *attr_sim_algo_version;
extern fr_dict_attr_t const *attr_sim_amf;
extern fr_dict_attr_t const *attr_sim_ki;
extern fr_dict_attr_t const *attr_sim_op;
extern fr_dict_attr_t const *attr_sim_opc;
extern fr_dict_attr_t const *attr_sim_sqn;

extern fr_value_box_t const *enum_eap_type_sim;
extern fr_value_box_t const *enum_eap_type_aka;
extern fr_value_box_t const *enum_eap_type_aka_prime;
