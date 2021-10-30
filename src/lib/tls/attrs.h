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

extern HIDDEN fr_dict_t const *dict_freeradius;
extern HIDDEN fr_dict_t const *dict_radius;
extern HIDDEN fr_dict_t const *dict_tls;

extern HIDDEN fr_dict_attr_t const *attr_allow_session_resumption;
extern HIDDEN fr_dict_attr_t const *attr_session_resumed;

extern HIDDEN fr_dict_attr_t const *attr_tls_certificate;
extern HIDDEN fr_dict_attr_t const *attr_tls_certificate_serial;
extern HIDDEN fr_dict_attr_t const *attr_tls_certificate_signature;
extern HIDDEN fr_dict_attr_t const *attr_tls_certificate_signature_algorithm;
extern HIDDEN fr_dict_attr_t const *attr_tls_certificate_issuer;
extern HIDDEN fr_dict_attr_t const *attr_tls_certificate_not_before;
extern HIDDEN fr_dict_attr_t const *attr_tls_certificate_not_after;
extern HIDDEN fr_dict_attr_t const *attr_tls_certificate_subject;
extern HIDDEN fr_dict_attr_t const *attr_tls_certificate_common_name;
extern HIDDEN fr_dict_attr_t const *attr_tls_certificate_subject_alt_name_dns;
extern HIDDEN fr_dict_attr_t const *attr_tls_certificate_subject_alt_name_email;
extern HIDDEN fr_dict_attr_t const *attr_tls_certificate_subject_alt_name_upn;
extern HIDDEN fr_dict_attr_t const *attr_tls_certificate_x509v3_extended_key_usage;
extern HIDDEN fr_dict_attr_t const *attr_tls_certificate_x509v3_subject_key_identifier;
extern HIDDEN fr_dict_attr_t const *attr_tls_certificate_x509v3_authority_key_identifier;
extern HIDDEN fr_dict_attr_t const *attr_tls_certificate_x509v3_basic_constraints;

extern HIDDEN fr_dict_attr_t const *attr_tls_client_error_code;
extern HIDDEN fr_dict_attr_t const *attr_tls_ocsp_cert_valid;
extern HIDDEN fr_dict_attr_t const *attr_tls_ocsp_next_update;
extern HIDDEN fr_dict_attr_t const *attr_tls_ocsp_response;
extern HIDDEN fr_dict_attr_t const *attr_tls_psk_identity;

extern HIDDEN fr_dict_attr_t const *attr_tls_session_cert_file;
extern HIDDEN fr_dict_attr_t const *attr_tls_session_require_client_cert;
extern HIDDEN fr_dict_attr_t const *attr_tls_session_cipher_suite;
extern HIDDEN fr_dict_attr_t const *attr_tls_session_version;

extern HIDDEN fr_dict_attr_t const *attr_tls_packet_type;
extern HIDDEN fr_dict_attr_t const *attr_tls_session_data;
extern HIDDEN fr_dict_attr_t const *attr_tls_session_id;
extern HIDDEN fr_dict_attr_t const *attr_tls_session_resumed;
extern HIDDEN fr_dict_attr_t const *attr_tls_session_ttl;

extern HIDDEN fr_dict_attr_t const *attr_framed_mtu;

extern fr_value_box_t const *enum_tls_packet_type_load_session;
extern fr_value_box_t const *enum_tls_packet_type_store_session;
extern fr_value_box_t const *enum_tls_packet_type_clear_session;
extern fr_value_box_t const *enum_tls_packet_type_verify_certificate;

extern fr_value_box_t const *enum_tls_packet_type_success;
extern fr_value_box_t const *enum_tls_packet_type_failure;
extern fr_value_box_t const *enum_tls_packet_type_notfound;
