#pragma once
/*
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
 */

/**
 * $Id$
 * @file src/lib/tls/attrs.h
 * @brief Attribute definitions used by the FreeRADIUS OpenSSL wrapper library
 *
 * @copyright 2018 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(tls_attrs_h, "$Id$")

#include <freeradius-devel/util/dict.h>

extern fr_dict_t const *dict_freeradius;
extern fr_dict_t const *dict_radius;
extern fr_dict_t const *dict_tls;

extern fr_dict_attr_t const *attr_allow_session_resumption;
extern fr_dict_attr_t const *attr_session_resumed;

extern fr_dict_attr_t const *attr_tls_cert;
extern fr_dict_attr_t const *attr_tls_cert_serial;
extern fr_dict_attr_t const *attr_tls_cert_signature;
extern fr_dict_attr_t const *attr_tls_cert_signature_algorithm;
extern fr_dict_attr_t const *attr_tls_cert_issuer;
extern fr_dict_attr_t const *attr_tls_cert_not_before;
extern fr_dict_attr_t const *attr_tls_cert_not_after;
extern fr_dict_attr_t const *attr_tls_cert_subject;
extern fr_dict_attr_t const *attr_tls_cert_common_name;
extern fr_dict_attr_t const *attr_tls_cert_subject_alt_name_dns;
extern fr_dict_attr_t const *attr_tls_cert_subject_alt_name_email;
extern fr_dict_attr_t const *attr_tls_cert_subject_alt_name_upn;
extern fr_dict_attr_t const *attr_tls_cert_x509v3_extended_key_usage;
extern fr_dict_attr_t const *attr_tls_cert_x509v3_subject_key_identifier;
extern fr_dict_attr_t const *attr_tls_cert_x509v3_authority_key_identifier;
extern fr_dict_attr_t const *attr_tls_cert_x509v3_basic_constraints;

extern fr_dict_attr_t const *attr_tls_client_error_code;
extern fr_dict_attr_t const *attr_tls_ocsp_cert_valid;
extern fr_dict_attr_t const *attr_tls_ocsp_next_update;
extern fr_dict_attr_t const *attr_tls_ocsp_response;
extern fr_dict_attr_t const *attr_tls_psk_identity;

extern fr_dict_attr_t const *attr_tls_session_cert_file;
extern fr_dict_attr_t const *attr_tls_session_cipher_suite;
extern fr_dict_attr_t const *attr_tls_session_version;

extern fr_dict_attr_t const *attr_tls_packet_type;
extern fr_dict_attr_t const *attr_tls_session_data;
extern fr_dict_attr_t const *attr_tls_session_id;
extern fr_dict_attr_t const *attr_tls_session_resumed;
extern fr_dict_attr_t const *attr_tls_session_ttl;

extern fr_dict_attr_t const *attr_framed_mtu;

extern fr_value_box_t const *enum_tls_packet_type_load_session;
extern fr_value_box_t const *enum_tls_packet_type_store_session;
extern fr_value_box_t const *enum_tls_packet_type_clear_session;
extern fr_value_box_t const *enum_tls_packet_type_verify_certificate;

extern fr_value_box_t const *enum_tls_packet_type_success;
extern fr_value_box_t const *enum_tls_packet_type_failure;
extern fr_value_box_t const *enum_tls_packet_type_notfound;
