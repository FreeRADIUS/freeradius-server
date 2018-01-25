/*
 * eap_fast.h
 *
 * Version:     $Id$
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
 * Copyright 2003 Alan DeKok <aland@freeradius.org>
 * Copyright 2006 The FreeRADIUS server project
 */
#ifndef _EAP_FAST_H
#define _EAP_FAST_H

RCSIDH(eap_fast_h, "$Id$")

#include "eap_tls.h"

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

typedef enum eap_fast_stage_t {
	TLS_SESSION_HANDSHAKE = 0,
	AUTHENTICATION,
	CRYPTOBIND_CHECK,
	PROVISIONING,
	COMPLETE
} eap_fast_stage_t;

typedef enum eap_fast_auth_type {
	EAP_FAST_UNKNOWN = 0,
	EAP_FAST_PROVISIONING_ANON,
	EAP_FAST_PROVISIONING_AUTH,
	EAP_FAST_NORMAL_AUTH
} eap_fast_auth_type_t;

typedef enum eap_fast_pac_info_attr_type_t {
	PAC_INFO_PAC_KEY = 1,	// 1
	PAC_INFO_PAC_OPAQUE,	// 2
	PAC_INFO_PAC_LIFETIME,	// 3
	PAC_INFO_A_ID,		// 4
	PAC_INFO_I_ID,		// 5
	PAC_INFO_PAC_RESERVED6,	// 6
	PAC_INFO_A_ID_INFO,	// 7
	PAC_INFO_PAC_ACK,	// 8
	PAC_INFO_PAC_INFO,	// 9
	PAC_INFO_PAC_TYPE,	// 10
	PAC_INFO_MAX
} eap_fast_pac_info_attr_type_t;

typedef enum eap_fast_pac_type_t {
	PAC_TYPE_TUNNEL = 1,	// 1
	PAC_TYPE_MACHINE_AUTH,	// 2
	PAC_TYPE_USER_AUTHZ,	// 3
	PAC_TYPE_MAX
} eap_fast_pac_type_t;

#define PAC_KEY_LENGTH		32
#define PAC_A_ID_LENGTH		16
#define PAC_I_ID_LENGTH		16
#define PAC_A_ID_INFO_LENGTH	32

typedef struct eap_fast_pac_attr_hdr_t {
	uint16_t			type;
	uint16_t			length;
} CC_HINT(__packed__) eap_fast_pac_attr_hdr_t;

typedef struct eap_fast_pac_attr_lifetime_t {
	eap_fast_pac_attr_hdr_t		hdr;
	uint32_t			data;	// secs since epoch
} CC_HINT(__packed__) eap_fast_pac_attr_lifetime_t;

typedef struct eap_fast_pac_attr_a_id_t {
	eap_fast_pac_attr_hdr_t		hdr;
	uint8_t				data[PAC_A_ID_LENGTH];
} CC_HINT(__packed__) eap_fast_pac_attr_a_id_t;

typedef struct eap_fast_pac_attr_i_id_t {
	eap_fast_pac_attr_hdr_t		hdr;
	uint8_t				data[PAC_I_ID_LENGTH];
} CC_HINT(__packed__) eap_fast_pac_attr_i_id_t;

typedef struct eap_fast_pac_attr_a_id_info_t {
	eap_fast_pac_attr_hdr_t		hdr;
	uint8_t				data[PAC_A_ID_INFO_LENGTH];
} CC_HINT(__packed__) eap_fast_pac_attr_a_id_info_t;

typedef struct eap_fast_pac_attr_pac_type_t {
	eap_fast_pac_attr_hdr_t		hdr;
	uint16_t			data;
} CC_HINT(__packed__) eap_fast_pac_attr_pac_type_t;

typedef struct eap_fast_pac_attr_pac_key_t {
	eap_fast_pac_attr_hdr_t		hdr;
	uint8_t				data[PAC_KEY_LENGTH];
} CC_HINT(__packed__) eap_fast_pac_attr_pac_key_t;

typedef struct eap_fast_attr_pac_opaque_plaintext_t {
	eap_fast_pac_attr_pac_type_t	type;
	eap_fast_pac_attr_lifetime_t	lifetime;
	eap_fast_pac_attr_pac_key_t	key;
} CC_HINT(__packed__) eap_fast_attr_pac_opaque_plaintext_t;

typedef struct eap_fast_attr_pac_opaque_t {
	eap_fast_pac_attr_hdr_t		hdr;
	unsigned char			aad[PAC_A_ID_LENGTH];
	unsigned char			iv[EVP_MAX_IV_LENGTH];
	unsigned char			tag[EVP_GCM_TLS_TAG_LEN];
	uint8_t				data[sizeof(eap_fast_attr_pac_opaque_plaintext_t) * 2]; // space for EVP
} CC_HINT(__packed__) eap_fast_attr_pac_opaque_t;

typedef struct eap_fast_attr_pac_info_t {
	eap_fast_pac_attr_hdr_t		hdr;
	eap_fast_pac_attr_lifetime_t	lifetime;
	eap_fast_pac_attr_a_id_t	a_id;
	eap_fast_pac_attr_a_id_info_t	a_id_info;
	eap_fast_pac_attr_pac_type_t	type;
} CC_HINT(__packed__) eap_fast_attr_pac_info_t;

typedef struct eap_fast_pac_t {
	eap_fast_pac_attr_pac_key_t	key;
	eap_fast_attr_pac_info_t	info;
	eap_fast_attr_pac_opaque_t	opaque;	// has to be last!
} CC_HINT(__packed__) eap_fast_pac_t;

/* RFC 4851, Section 4.2.8 - Crypto-Binding TLV */
typedef struct eap_tlv_crypto_binding_tlv_t {
        uint16_t tlv_type;
        uint16_t length;
        uint8_t reserved;
        uint8_t version;
        uint8_t received_version;
        uint8_t subtype;
        uint8_t nonce[32];
        uint8_t compound_mac[20];
} CC_HINT(__packed__) eap_tlv_crypto_binding_tlv_t;

typedef enum eap_fast_tlv_type_t {
	EAP_FAST_TLV_RESERVED_0 = 0,	// 0
	EAP_FAST_TLV_RESERVED_1,  	// 1
	EAP_FAST_TLV_RESERVED_2,  	// 2
	EAP_FAST_TLV_RESULT,     	// 3
	EAP_FAST_TLV_NAK,        	// 4
	EAP_FAST_TLV_ERROR,      	// 5
	EAP_FAST_TLV_RESERVED6,  	// 6
	EAP_FAST_TLV_VENDOR_SPECIFIC,	// 7
	EAP_FAST_TLV_RESERVED8,		// 8
	EAP_FAST_TLV_EAP_PAYLOAD,       // 9
	EAP_FAST_TLV_INTERMED_RESULT,	// 10
	EAP_FAST_TLV_PAC,		// 11
	EAP_FAST_TLV_CRYPTO_BINDING,	// 12
	EAP_FAST_TLV_RESERVED_13,	// 13
	EAP_FAST_TLV_RESERVED_14, 	// 14
	EAP_FAST_TLV_RESERVED_15, 	// 15
	EAP_FAST_TLV_RESERVED_16,	// 16
	EAP_FAST_TLV_RESERVED_17, 	// 17
	EAP_FAST_TLV_TRUSTED_ROOT, 	// 18
	EAP_FAST_TLV_REQ_ACTION, 	// 19
	EAP_FAST_TLV_PKCS,		// 20
	EAP_FAST_TLV_MAX
} eap_fast_tlv_type_t;

typedef enum eap_fast_tlv_crypto_binding_tlv_subtype_t {
	EAP_FAST_TLV_CRYPTO_BINDING_SUBTYPE_REQUEST = 0,	// 0
	EAP_FAST_TLV_CRYPTO_BINDING_SUBTYPE_RESPONSE		// 1
} eap_fast_tlv_crypto_binding_tlv_subtype_t;

/* RFC 5422: Section 3.3 - Key Derivations Used in the EAP-FAST Provisioning Exchange */
typedef struct eap_fast_keyblock_t {
	uint8_t	session_key_seed[EAP_FAST_SKS_LEN];
	uint8_t	server_challenge[CHAP_VALUE_LENGTH];
	uint8_t	client_challenge[CHAP_VALUE_LENGTH];
} CC_HINT(__packed__) eap_fast_keyblock_t;

typedef struct eap_fast_tunnel_t {
	VALUE_PAIR		*username;
	VALUE_PAIR	*state;
	VALUE_PAIR	*accept_vps;
	bool		copy_request_to_tunnel;
	bool		use_tunneled_reply;

	bool			authenticated;

	int			mode;
	eap_fast_stage_t	stage;
	eap_fast_keyblock_t	*keyblock;
	uint8_t			*simck;
	uint8_t			*cmk;
	int			imckc;
	struct {
		uint8_t		mppe_send[CHAP_VALUE_LENGTH];
		uint8_t		mppe_recv[CHAP_VALUE_LENGTH];
	} CC_HINT(__packed__)	isk;
	uint8_t			*msk;
	uint8_t			*emsk;

	int			default_method;

	uint32_t		pac_lifetime;
	char const		*authority_identity;
	uint8_t const 		*a_id;
	uint8_t const 		*pac_opaque_key;

	struct {
		uint8_t			*key;
		eap_fast_pac_type_t	type;
		uint32_t		expires;
		bool			expired;
		bool			send;
	}			pac;

	bool			result_final;

#ifdef WITH_PROXY
	bool		proxy_tunneled_request_as_eap;	//!< Proxy tunneled session as EAP, or as de-capsulated
							//!< protocol.
#endif
	char const	*virtual_server;
} eap_fast_tunnel_t;

/*
 *	Process the FAST portion of an EAP-FAST request.
 */
void eap_fast_tlv_append(tls_session_t *tls_session, int tlv, bool mandatory,
			 int length, const void *data) CC_HINT(nonnull);
PW_CODE eap_fast_process(eap_handler_t *eap_session, tls_session_t *tls_session) CC_HINT(nonnull);

/*
 *	A bunch of EAP-FAST helper functions.
 */
VALUE_PAIR *eap_fast_fast2vp(REQUEST *request, UNUSED SSL *ssl, uint8_t const *data,
			     size_t data_len, DICT_ATTR const *fast_da, vp_cursor_t *out);

#endif /* _EAP_FAST_H */
