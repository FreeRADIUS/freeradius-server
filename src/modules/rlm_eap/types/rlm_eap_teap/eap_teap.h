/*
 * eap_teap.h
 *
 * Version:     $Id$
 *
 * Copyright (C) 2022 Network RADIUS SARL <legal@networkradius.com>
 *
 * This software may not be redistributed in any form without the prior
 * written consent of Network RADIUS.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#ifndef _EAP_TEAP_H
#define _EAP_TEAP_H

RCSIDH(eap_teap_h, "$Id$")

#include "eap_tls.h"

#define EAP_TEAP_VERSION			1

#define EAP_TEAP_MSK_LEN			64
#define EAP_TEAP_EMSK_LEN			64
#define EAP_TEAP_IMSK_LEN			32
#define EAP_TEAP_SKS_LEN			40
#define EAP_TEAP_SIMCK_LEN			40
#define EAP_TEAP_CMK_LEN			20

#define EAP_TEAP_TLV_MANDATORY			0x8000
#define EAP_TEAP_TLV_TYPE			0x3fff

#define EAP_TEAP_ERR_TUNNEL_COMPROMISED		2001
#define EAP_TEAP_ERR_UNEXPECTED_TLV		2002

#define EAP_TEAP_TLV_RESULT_SUCCESS		1
#define EAP_TEAP_TLV_RESULT_FAILURE		2

typedef enum eap_teap_stage_t {
	TLS_SESSION_HANDSHAKE = 0,
	AUTHENTICATION,
	CRYPTOBIND_CHECK,
	PROVISIONING,
	COMPLETE
} eap_teap_stage_t;

typedef enum eap_teap_auth_type {
	EAP_TEAP_UNKNOWN = 0,
	EAP_TEAP_PROVISIONING_ANON,
	EAP_TEAP_PROVISIONING_AUTH,
	EAP_TEAP_NORMAL_AUTH
} eap_teap_auth_type_t;

typedef enum eap_teap_pac_info_attr_type_t {
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
} eap_teap_pac_info_attr_type_t;

typedef enum eap_teap_pac_type_t {
	PAC_TYPE_TUNNEL = 1,	// 1
	PAC_TYPE_MACHINE_AUTH,	// 2
	PAC_TYPE_USER_AUTHZ,	// 3
	PAC_TYPE_MAX
} eap_teap_pac_type_t;

#define PAC_KEY_LENGTH		32
#define PAC_A_ID_LENGTH		16
#define PAC_I_ID_LENGTH		16
#define PAC_A_ID_INFO_LENGTH	32

/*
 *	11 - PAC TLV
 */
typedef struct eap_teap_pac_attr_hdr_t {
	uint16_t			type;
	uint16_t			length;
} CC_HINT(__packed__) eap_teap_pac_attr_hdr_t;

/*
 *	11.1 - Key
 */
typedef struct eap_teap_pac_attr_key_t {
	eap_teap_pac_attr_hdr_t		hdr;
	uint8_t				data[1];
} CC_HINT(__packed__) eap_teap_pac_attr_key_t;

/*
 *	11.2 - Opaque
 */
typedef struct eap_teap_pac_attr_opaque_t {
	eap_teap_pac_attr_hdr_t		hdr;
	uint8_t				data[1];
} CC_HINT(__packed__) eap_teap_pac_attr_opaque_t;

/*
 *	11.3 and 11.9.3 - lifetime
 */
typedef struct eap_teap_pac_attr_lifetime_t {
	eap_teap_pac_attr_hdr_t		hdr;
	uint32_t			data;	// secs since epoch
} CC_HINT(__packed__) eap_teap_pac_attr_lifetime_t;

/*
 *	11.4 and 11.9.4 - A-ID
 */
typedef struct eap_teap_pac_attr_a_id_t {
	eap_teap_pac_attr_hdr_t		hdr;
	uint8_t				data[1];
} CC_HINT(__packed__) eap_teap_pac_attr_a_id_t;

/*
 *	11.5 and 11.9.5 - I-ID
 */
typedef struct eap_teap_pac_attr_i_id_t {
	eap_teap_pac_attr_hdr_t		hdr;
	uint8_t				data[1];
} CC_HINT(__packed__) eap_teap_pac_attr_i_id_t;

/*
 *	11.7 and 11.9.7 - A-ID-Info
 */
typedef struct eap_teap_pac_attr_a_id_info_t {
	eap_teap_pac_attr_hdr_t		hdr;
	uint8_t				data[1];
} CC_HINT(__packed__) eap_teap_pac_attr_a_id_info_t;

/*
 *	11.8 - Acknowledgement
 */
typedef struct eap_teap_pac_pac_attr_acknowlegement_t {
	eap_teap_pac_attr_hdr_t		hdr;
	uint16_t			data; /* 1 = success, 2 = failure */
} CC_HINT(__packed__) eap_teap_pac_pac_attr_acknowlegement_t;

/*
 *	11.9 - Info
 *
 *	MUST contain A-ID (4), A-ID-Info (7), and PAC-Type (10).  MAY contain others.
 */
typedef struct eap_teap_pac_pac_attr_info_t {
	eap_teap_pac_attr_hdr_t		hdr;
	uint8_t				data[1]; /* sub TLVs */
} CC_HINT(__packed__) eap_teap_pac_pac_attr_info_t;

/*
 *	11.10 and 11.9.10 - PAC Type
 */
typedef struct eap_teap_pac_attr_pac_type_t {
	eap_teap_pac_attr_hdr_t		hdr;
	uint16_t			data; /* 1 = Tunnel-PAC */
} CC_HINT(__packed__) eap_teap_pac_attr_pac_type_t;

/* RFC 7170, Section 4.2.13 - Crypto-Binding TLV */
typedef struct eap_tlv_crypto_binding_tlv_t {
        uint8_t reserved;
        uint8_t version;
        uint8_t received_version;
        uint8_t subtype;	/* Flags[4b] and Sub-Type[4b] */
        uint8_t nonce[32];
        uint8_t emsk_compound_mac[20];
        uint8_t msk_compound_mac[20];
} CC_HINT(__packed__) eap_tlv_crypto_binding_tlv_t;

typedef enum eap_teap_tlv_type_t {
	EAP_TEAP_TLV_RESERVED_0 = 0,	// 0
	EAP_TEAP_TLV_RESERVED_1,  	// 1
	EAP_TEAP_TLV_RESERVED_2,  	// 2
	EAP_TEAP_TLV_RESULT,     	// 3
	EAP_TEAP_TLV_NAK,        	// 4
	EAP_TEAP_TLV_ERROR,      	// 5
	EAP_TEAP_TLV_RESERVED6,  	// 6
	EAP_TEAP_TLV_VENDOR_SPECIFIC,	// 7
	EAP_TEAP_TLV_REQUEST_ACTION,	// 8
	EAP_TEAP_TLV_EAP_PAYLOAD,       // 9
	EAP_TEAP_TLV_INTERMED_RESULT,	// 10
	EAP_TEAP_TLV_PAC,		// 11
	EAP_TEAP_TLV_CRYPTO_BINDING,	// 12
	EAP_TEAP_TLV_RESERVED_13,	// 13
	EAP_TEAP_TLV_RESERVED_14, 	// 14
	EAP_TEAP_TLV_RESERVED_15, 	// 15
	EAP_TEAP_TLV_RESERVED_16,	// 16
	EAP_TEAP_TLV_RESERVED_17, 	// 17
	EAP_TEAP_TLV_TRUSTED_ROOT, 	// 18
	EAP_TEAP_TLV_REQ_ACTION, 	// 19
	EAP_TEAP_TLV_PKCS,		// 20
	EAP_TEAP_TLV_MAX
} eap_teap_tlv_type_t;

typedef enum eap_teap_tlv_crypto_binding_tlv_flags_t {
	EAP_TEAP_TLV_CRYPTO_BINDING_FLAGS_CMAC_EMSK = 1,	// 1
	EAP_TEAP_TLV_CRYPTO_BINDING_FLAGS_CMAC_MSK,		// 2
	EAP_TEAP_TLV_CRYPTO_BINDING_FLAGS_CMAC_BOTH		// 3
} eap_teap_tlv_crypto_binding_tlv_flags_t;

typedef enum eap_teap_tlv_crypto_binding_tlv_subtype_t {
	EAP_TEAP_TLV_CRYPTO_BINDING_SUBTYPE_REQUEST = 0,	// 0
	EAP_TEAP_TLV_CRYPTO_BINDING_SUBTYPE_RESPONSE		// 1
} eap_teap_tlv_crypto_binding_tlv_subtype_t;

typedef struct teap_tunnel_t {
	VALUE_PAIR	*username;
	VALUE_PAIR	*state;
	VALUE_PAIR	*accept_vps;
	bool		copy_request_to_tunnel;
	bool		use_tunneled_reply;

	bool			authenticated;
	int			received_version;

	int			mode;
	eap_teap_stage_t	stage;

	int			imckc;
	struct {
		uint8_t		simck[EAP_TEAP_SIMCK_LEN];
		uint8_t		cmk[EAP_TEAP_CMK_LEN];
	} CC_HINT(__packed__)	imck;
	uint8_t			msk[EAP_TEAP_MSK_LEN];
	uint8_t			emsk[EAP_TEAP_EMSK_LEN];

	int			default_method;

	uint32_t		pac_lifetime;
	char const		*authority_identity;
	uint8_t const 		*a_id;
	uint8_t const 		*pac_opaque_key;

	struct {
		uint8_t			*key;
		eap_teap_pac_type_t	type;
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
} teap_tunnel_t;

/*
 *	Process the TEAP portion of an EAP-TEAP request.
 */
PW_CODE eap_teap_process(eap_handler_t *handler, tls_session_t *tls_session) CC_HINT(nonnull);

/*
 *	A bunch of EAP-TEAP helper functions.
 */
VALUE_PAIR *eap_teap_teap2vp(REQUEST *request, UNUSED SSL *ssl, uint8_t const *data,
			     size_t data_len, DICT_ATTR const *teap_da, vp_cursor_t *out);

#endif /* _EAP_TEAP_H */
