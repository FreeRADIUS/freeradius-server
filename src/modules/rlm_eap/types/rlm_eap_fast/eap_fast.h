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
 * $Id$
 * @file eap_fast.h
 * @brief Function declarations and packet structures
 *
 * @author Alexander Clouter (alex@digriz.org.uk)
 *
 * @copyright 2016 Alan DeKok (aland@freeradius.org)
 * @copyright 2016 The FreeRADIUS server project
 */
RCSIDH(eap_fast_h, "$Id$")

#include <freeradius-devel/eap/tls.h>
#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/util/chap.h>

#define EAP_FAST_VERSION			1

#define EAP_FAST_KEY_LEN			64
#define EAP_EMSK_LEN				64
#define EAP_FAST_SKS_LEN			40
#define EAP_FAST_SIMCK_LEN			40
#define EAP_FAST_CMK_LEN			20

#define EAP_FAST_TLV_MANDATORY			0x8000
#define EAP_FAST_TLV_TYPE			0x3fff

#define EAP_FAST_FATAL_ERROR			2000
#define EAP_FAST_ERR_TUNNEL_COMPROMISED		2001
#define EAP_FAST_ERR_UNEXPECTED_TLV		2002

#define EAP_FAST_TLV_RESULT_SUCCESS		1
#define EAP_FAST_TLV_RESULT_FAILURE		2

typedef enum {
	EAP_FAST_TLS_SESSION_HANDSHAKE = 0,
	EAP_FAST_AUTHENTICATION,
	EAP_FAST_CRYPTOBIND_CHECK,
	EAP_FAST_PROVISIONING,
	EAP_FAST_COMPLETE
} eap_fast_stage_t;

typedef enum {
	EAP_FAST_UNKNOWN = 0,
	EAP_FAST_PROVISIONING_ANON,
	EAP_FAST_PROVISIONING_AUTH,
	EAP_FAST_NORMAL_AUTH
} eap_fast_auth_type_t;

typedef enum {
	PAC_TYPE_TUNNEL = 1,	// 1
	PAC_TYPE_MACHINE_AUTH,	// 2
	PAC_TYPE_USER_AUTHZ,	// 3
	PAC_TYPE_MAX
} eap_fast_pac_type_t;

#define PAC_KEY_LENGTH		32
#define PAC_A_ID_LENGTH		16
#define PAC_I_ID_LENGTH		16
#define PAC_A_ID_INFO_LENGTH	32

typedef struct {
	uint16_t			type;
	uint16_t			length;
} CC_HINT(__packed__) eap_fast_pac_attr_hdr_t;

typedef struct {
	eap_fast_pac_attr_hdr_t		hdr;
	uint32_t			data;	// secs since epoch
} CC_HINT(__packed__) eap_fast_pac_attr_lifetime_t;

typedef struct {
	eap_fast_pac_attr_hdr_t		hdr;
	uint8_t				data[PAC_A_ID_LENGTH];
} CC_HINT(__packed__) eap_fast_pac_attr_a_id_t;

typedef struct {
	eap_fast_pac_attr_hdr_t		hdr;
	uint8_t				data[PAC_I_ID_LENGTH];
} CC_HINT(__packed__) eap_fast_pac_attr_i_id_t;

typedef struct {
	eap_fast_pac_attr_hdr_t		hdr;
	uint8_t				data[PAC_A_ID_INFO_LENGTH];
} CC_HINT(__packed__) eap_fast_pac_attr_a_id_info_t;

typedef struct {
	eap_fast_pac_attr_hdr_t		hdr;
	uint16_t			data;
} CC_HINT(__packed__) eap_fast_pac_attr_pac_type_t;

typedef struct {
	eap_fast_pac_attr_hdr_t		hdr;
	uint8_t				data[PAC_KEY_LENGTH];
} CC_HINT(__packed__) eap_fast_pac_attr_pac_key_t;

typedef struct {
	eap_fast_pac_attr_pac_type_t	type;
	eap_fast_pac_attr_lifetime_t	lifetime;
	eap_fast_pac_attr_pac_key_t	key;
} CC_HINT(__packed__) eap_fast_attr_pac_opaque_plaintext_t;

typedef struct {
	eap_fast_pac_attr_hdr_t		hdr;
	unsigned char			aad[PAC_A_ID_LENGTH];
	unsigned char			iv[EVP_MAX_IV_LENGTH];
	unsigned char			tag[EVP_GCM_TLS_TAG_LEN];
	uint8_t				data[sizeof(eap_fast_attr_pac_opaque_plaintext_t) * 2]; // space for EVP
} CC_HINT(__packed__) eap_fast_attr_pac_opaque_t;

typedef struct {
	eap_fast_pac_attr_hdr_t		hdr;
	eap_fast_pac_attr_lifetime_t	lifetime;
	eap_fast_pac_attr_a_id_t	a_id;
	eap_fast_pac_attr_a_id_info_t	a_id_info;
	eap_fast_pac_attr_pac_type_t	type;
} CC_HINT(__packed__) eap_fast_attr_pac_info_t;

typedef struct {
	eap_fast_pac_attr_pac_key_t	key;
	eap_fast_attr_pac_info_t	info;
	eap_fast_attr_pac_opaque_t	opaque;	// has to be last!
} CC_HINT(__packed__) eap_fast_pac_t;

/* RFC 4851, Section 4.2.8 - Crypto-Binding TLV */
typedef struct {
        uint16_t tlv_type;
        uint16_t length;
        uint8_t reserved;
        uint8_t version;
        uint8_t received_version;
        uint8_t subtype;
        uint8_t nonce[32];
        uint8_t compound_mac[20];
} CC_HINT(__packed__) eap_tlv_crypto_binding_tlv_t;

typedef enum eap_fast_tlv_crypto_binding_tlv_subtype_t {
	EAP_FAST_TLV_CRYPTO_BINDING_SUBTYPE_REQUEST = 0,	// 0
	EAP_FAST_TLV_CRYPTO_BINDING_SUBTYPE_RESPONSE		// 1
} eap_fast_tlv_crypto_binding_tlv_subtype_t;

/* RFC 5422: Section 3.3 - Key Derivations Used in the EAP-FAST Provisioning Exchange */
typedef struct {
	uint8_t	session_key_seed[EAP_FAST_SKS_LEN];
	uint8_t	server_challenge[MD5_DIGEST_LENGTH];
	uint8_t	client_challenge[MD5_DIGEST_LENGTH];
} CC_HINT(__packed__) eap_fast_keyblock_t;

typedef struct {
	fr_pair_t		*username;

	bool			authenticated;

	int			mode;
	eap_fast_stage_t	stage;
	eap_fast_keyblock_t	*keyblock;
	uint8_t			*s_imck;
	uint8_t			*cmk;
	int			imck_count;
	struct {
		uint8_t		mppe_send[MD5_DIGEST_LENGTH];
		uint8_t		mppe_recv[MD5_DIGEST_LENGTH];
	} CC_HINT(__packed__)	isk;
	uint8_t			*msk;
	uint8_t			*emsk;

	int			default_method;
	int			default_provisioning_method;

	fr_time_delta_t		pac_lifetime;
	char const		*authority_identity;
	uint8_t const 		*a_id;
	uint8_t const 		*pac_opaque_key;

	struct {
		uint8_t			*key;
		eap_fast_pac_type_t	type;
		fr_time_t		expires;
		bool			expired;
		bool			send;
	}			pac;

	bool			result_final;

#ifdef WITH_PROXY
	bool		proxy_tunneled_request_as_eap;	//!< Proxy tunneled session as EAP, or as de-capsulated
							//!< protocol.
#endif
	CONF_SECTION	*server_cs;
} eap_fast_tunnel_t;
