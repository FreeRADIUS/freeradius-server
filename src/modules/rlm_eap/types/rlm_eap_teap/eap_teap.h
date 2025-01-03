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

/* intermediate result values also match */
#define EAP_TEAP_TLV_RESULT_SUCCESS		1
#define EAP_TEAP_TLV_RESULT_FAILURE		2

#define EAP_TEAP_IDENTITY_TYPE_USER		1
#define EAP_TEAP_IDENTITY_TYPE_MACHINE		2

#define PW_EAP_TEAP_TLV_IDENTITY_TYPE (PW_FREERADIUS_EAP_TEAP_TLV | (EAP_TEAP_TLV_IDENTITY_TYPE << 8))
#define PW_EAP_TEAP_TLV_BASIC_PASSWORD_AUTH_REQ (PW_FREERADIUS_EAP_TEAP_TLV | (EAP_TEAP_TLV_BASIC_PASSWORD_AUTH_REQ << 8))
#define PW_EAP_TEAP_TLV_BASIC_PASSWORD_AUTH_RESP (PW_FREERADIUS_EAP_TEAP_TLV | (EAP_TEAP_TLV_BASIC_PASSWORD_AUTH_RESP << 8))

typedef enum eap_teap_stage_t {
	TLS_SESSION_HANDSHAKE = 0,
	AUTHENTICATION,
	PROVISIONING,
	COMPLETE
} eap_teap_stage_t;

typedef enum eap_teap_auth_type {
	EAP_TEAP_UNKNOWN = 0,
	EAP_TEAP_PROVISIONING_ANON,
	EAP_TEAP_PROVISIONING_AUTH,
	EAP_TEAP_NORMAL_AUTH
} eap_teap_auth_type_t;

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
	EAP_TEAP_TLV_RESERVED_0 = 0,		// 0
	EAP_TEAP_TLV_AUTHORITY,  		// 1
	EAP_TEAP_TLV_IDENTITY_TYPE,  		// 2
	EAP_TEAP_TLV_RESULT,     		// 3
	EAP_TEAP_TLV_NAK,        		// 4
	EAP_TEAP_TLV_ERROR,      		// 5
	EAP_TEAP_TLV_CHANNEL_BINDING,  		// 6
	EAP_TEAP_TLV_VENDOR_SPECIFIC,		// 7
	EAP_TEAP_TLV_REQUEST_ACTION,		// 8
	EAP_TEAP_TLV_EAP_PAYLOAD,       	// 9
	EAP_TEAP_TLV_INTERMED_RESULT,		// 10
	EAP_TEAP_TLV_PAC,			// 11
	EAP_TEAP_TLV_CRYPTO_BINDING,		// 12
	EAP_TEAP_TLV_BASIC_PASSWORD_AUTH_REQ,	// 13
	EAP_TEAP_TLV_BASIC_PASSWORD_AUTH_RESP, 	// 14
	EAP_TEAP_TLV_PKCS7,	 		// 15
	EAP_TEAP_TLV_PKCS10,			// 16
	EAP_TEAP_TLV_TRUSTED_ROOT, 		// 17
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

typedef struct teap_imck_t {
	uint8_t		simck[EAP_TEAP_SIMCK_LEN];
	uint8_t		cmk[EAP_TEAP_CMK_LEN];
} CC_HINT(__packed__) teap_imck_t;

typedef struct {
	bool		required;
	bool		sent;
	uint8_t		received;
} teap_auth_t;

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

	int			num_identities;
	uint16_t		identity_types[2];

	teap_auth_t		auths[3]; /* so we can index by Identity-Type */

	int			imckc;
	bool			imck_emsk_available;
	struct teap_imck_t	imck_msk;
	struct teap_imck_t	imck_emsk;

	uint8_t			msk[EAP_TEAP_MSK_LEN];
	uint8_t			emsk[EAP_TEAP_EMSK_LEN];

	int			default_method;
	int			eap_method[3];

	bool			result_final;
	bool			auto_chain;		//!< do we automatically chain identities
	bool			sent_basic_password;

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
