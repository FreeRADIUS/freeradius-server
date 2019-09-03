#pragma once
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
 * $Id$
 * @file src/lib/aka-sim/base.h
 * @brief Functions common to SIM protocols (EAP-SIM/EAP-AKA/EAP-AKA')
 *
 * The development of the EAP/SIM support was funded by Internet Foundation
 * Austria (http://www.nic.at/ipa).
 *
 * @copyright 2003 Michael Richardson <mcr@sandelman.ottawa.on.ca>
 * @copyright 2003-2016 The FreeRADIUS server project
 */
RCSIDH(sim_h, "$Id$")

#include <assert.h>
#include <openssl/evp.h>
#include <freeradius-devel/eap/compose.h>
#include <freeradius-devel/eap/types.h>

#include "id.h"

#define AKA_SIM_MAX_STRING_LENGTH		1016		//!< Maximum size of a SIM/AKA['] string ((4 * 255) - 4).
#define AKA_SIM_IV_SIZE				16		//!< Length of the IV used when processing AT_ENCR.
#define AKA_SIM_MAC_DIGEST_SIZE			16		//!< Length of MAC used to prevent packet modification.
#define AKA_SIM_MAC_SIZE			20		//!< Length of MAC used to prevent packet modification.
#define AKA_SIM_AUTH_SIZE			16
#define AKA_SIM_SQN_AK_SIZE			6
#define AKA_SIM_NONCE_S_SIZE			16		//!< Length of re-authentication nonce

#define AKA_SIM_KI_SIZE				16		//!< Length of secret data shared between SIM and AuC.
#define AKA_SIM_OP_SIZE				16		//!< Length of Operator Algorithm Configuration.
#define AKA_SIM_OPC_SIZE			16		//!< Length of modified Operator Algorithm Configuration.

#define AKA_SIM_MK_SIZE				20		//!< Master key size
#define AKA_SIM_K_RE_SIZE			32		//!< Reauthentication key size.

#define AKA_SIM_SKIPPABLE_MAX			127		//!< The last non-skippable attribute.

#define AKA_SIM_VECTOR_GSM_RAND_SIZE		16		//!< Length of RAND in GSM triplet.
#define AKA_SIM_VECTOR_GSM_SRES_SIZE		4		//!< Length of SRES in GSM triplet.
#define AKA_SIM_VECTOR_GSM_KC_SIZE		8		//!< Length of Kc in GSM triplet.

#define AKA_SIM_VECTOR_UMTS_AUTN_SIZE		16
#define AKA_SIM_VECTOR_UMTS_CK_SIZE		16
#define AKA_SIM_VECTOR_UMTS_IK_SIZE		16
#define AKA_SIM_VECTOR_UMTS_AK_SIZE		6
#define AKA_SIM_VECTOR_UMTS_RAND_SIZE		16
#define AKA_SIM_VECTOR_UMTS_XRES_MAX_SIZE	16

#define EAP_SIM_VERSION				1
#define EAP_SIM_NONCE_MT_SIZE			16		//!< Length of challenge from SIM client.

#define EAP_AKA_SIM_AUTH_SIZE			16


#define EAP_AKA_AUTS_SIZE			14		//!< Server sequence number.  SIM checks this
								//!< is within the correct range.
#define EAP_AKA_AUTH_SIZE			16
#define EAP_AKA_PRIME_AUTH_SIZE			32

/** The type of auth vector held by a fr_aka_sim_keys_t
 */
typedef enum {
	AKA_SIM_VECTOR_NONE = 0,
	AKA_SIM_VECTOR_GSM,					//!< Vector is GSM triplets.
	AKA_SIM_VECTOR_UMTS,					//!< Vector is UMTS quintuplets.
	AKA_SIM_VECTOR_UMTS_REAUTH_KDF_0_REAUTH,
	AKA_SIM_VECTOR_UMTS_REAUTH_KDF_1_REAUTH
} fr_aka_sim_vector_type_t;

/** Where to get EAP-SIM vectors from
 */
typedef enum {
	AKA_SIM_VECTOR_SRC_AUTO,				//!< Discover where to get Triplets from automatically.
	AKA_SIM_VECTOR_SRC_TRIPLETS,				//!< Source of triplets is EAP-SIM-* attributes.
	AKA_SIM_VECTOR_SRC_QUINTUPLETS,				//!< Source of triplets is derived from EAP-AKA-*
								///< quintuplets.
	AKA_SIM_VECTOR_SRC_KI,					//!< Should generate triplets locally using a Ki.
	AKA_SIM_VECTOR_SRC_REAUTH,				//!< Not a vector.  Result of running KDF 0 reauth
								///< function.
} fr_aka_sim_vector_src_t;

typedef struct {
	uint8_t		rand[AKA_SIM_VECTOR_GSM_RAND_SIZE];		//!< RAND challenge to the SIM.
	union {
		uint8_t		sres[AKA_SIM_VECTOR_GSM_SRES_SIZE];	//!< Signing response.
		uint32_t	sres_uint32;
	};

	union {
		uint8_t		kc[AKA_SIM_VECTOR_GSM_KC_SIZE];		//!< Keying response.
		uint64_t	kc_uint64;
	};
} fr_aka_sim_vector_gsm_t;

typedef struct {
	uint8_t		autn[AKA_SIM_VECTOR_UMTS_AUTN_SIZE];	//!< Authentication vector from the AuC.
	uint8_t		ck[AKA_SIM_VECTOR_UMTS_CK_SIZE];	//!< Ciphering key.
	uint8_t		ik[AKA_SIM_VECTOR_UMTS_IK_SIZE];	//!< Integrity key.
	uint8_t		ak[AKA_SIM_VECTOR_UMTS_AK_SIZE];	//!< Anonymity key.
	uint8_t		rand[AKA_SIM_VECTOR_UMTS_RAND_SIZE];	//!< RAND challenge to the SIM.
	uint8_t		xres[AKA_SIM_VECTOR_UMTS_XRES_MAX_SIZE];//!< Signing response.
	size_t		xres_len;				//!< Length of res (it's variable).
} fr_aka_sim_vector_umts_t;

/** Stores our checkcode state
 *
 * The checkcode is a hash of all identity packets exchanged
 * up until the challenge is sent.
 *
 * It allows both parties to verify that they've seen the same
 * sequence of packets.
 */
typedef struct {
	EVP_MD_CTX	*md_ctx;				//!< Context to hold state of digest as we
								///< consume packets.
} fr_aka_sim_checkcode_t;

/** Master key state struct for all SIMlike EAP protocols
 *
 */
typedef struct {
	/*
	 *	Inputs
	 */
	uint8_t		*identity;				//!< Identity from AT_IDENTITY.
	size_t		identity_len;				//!< Length of the identity.

	uint8_t		*network;				//!< Network name (EAP-AKA-Prime only).
	size_t		network_len;				//!< Length of the network name (EAP-AKA-Prime only).

	uint64_t	sqn;					//!< Sequence number

	struct {
		/*
		 *	Authentication vectors from HLR or local AuC
		 */
		union {
			/** Input to kdf_0_gsm
			 */
			struct {
				fr_aka_sim_vector_gsm_t	vector[3];	//!< GSM vectors.
				uint32_t		num_vectors;	//!< Number of input vectors
									//!< we're using (2 or 3).

				uint8_t	nonce_mt[EAP_SIM_NONCE_MT_SIZE];//!< Nonce provided by the client.
				uint8_t	version_list[FR_MAX_STRING_LEN];//!< Version list from negotiation.
				uint8_t	version_list_len;		//!< Length of version list.
				uint8_t	version_select[2];		//!< Version we agreed.
			} gsm;

			/** Input to kdf_*_umts
			 */
			struct {
				fr_aka_sim_vector_umts_t	vector;		//!< UMTS vector.
				uint16_t			kdf_selected;
			} umts;

			/** Input/output from kdf_*_reauth_*
			 */
			struct {
				uint16_t	counter;			//!< Re-authentication counter.
				uint8_t		nonce_s[AKA_SIM_NONCE_S_SIZE];	//!< Re-authentication challenge.
				uint8_t		xkey_prime[20];			//!< Derived reauthentication key
										//!< for AKA (kdf 0).
			} reauth;
		};

		/*
		 *	Original ki and OPc to allow AUTS validation
		 */
		struct {
			uint8_t ki[AKA_SIM_KI_SIZE];		//!< Secret shared between AuC and SIM.
			uint8_t opc[AKA_SIM_OPC_SIZE];		//!< Operator algorithm input.
		} auc;

		fr_aka_sim_vector_type_t	vector_type;	//!< What type of authentication vector
								//!< we're using to authenticate the SIM.
		fr_aka_sim_vector_src_t		vector_src;	//!< Where the vector came from.
	};

	/*
	 *	Inputs/outputs
	 */
	uint8_t		mk[AKA_SIM_MK_SIZE];			//!< Master key from session attributes.
	size_t		mk_len;
	uint8_t		k_re[AKA_SIM_K_RE_SIZE];		//!< Derived reauthentication key for AKA'(kdf 1).

	/*
	 *	Intermediates
	 */
	uint8_t		ck_prime[AKA_SIM_VECTOR_UMTS_CK_SIZE];	//!< Derived from CK, for AKA'.
	uint8_t		ik_prime[AKA_SIM_VECTOR_UMTS_IK_SIZE];	//!< Derived from IK, for AKA'.

	/*
	 *	Outputs
	 */
	uint8_t		k_aut[32];				//!< Derived authentication key.
	size_t		k_aut_len;				//!< Length of k_aut.  16 for AKA/SIM, 32 for AKA'.
	uint8_t		k_encr[16];				//!< Derived encryption key.
	uint8_t		msk[64];				//!< Derived master session key.
	uint8_t		emsk[64];				//!< Derived extended master session key.
} fr_aka_sim_keys_t;

typedef struct {
	fr_aka_sim_keys_t const		*keys;			//!< From the EAP session.
	uint8_t				iv[AKA_SIM_IV_SIZE];	//!< From the current packet.
	bool				have_iv;		//!< Whether we found the IV already.
} fr_aka_sim_decode_ctx_t;

typedef struct {
	fr_dict_attr_t const		*root;			//!< Root attribute of the dictionary.
	fr_aka_sim_keys_t const	*keys;				//!< From the EAP session.
	uint8_t				iv[AKA_SIM_IV_SIZE];	//!< Generated by us using our PRNG.
	bool				iv_included;		//!< Whether we've already added an IV to this packet.

	/*
	 *	Additional HMAC inputs
	 */
	EVP_MD const			*hmac_md;		//!< HMAC digest algorithm, usually EVP_sha1().
	eap_packet_t			*eap_packet;		//!< Needed for HMAC generation so we can construct
								///< the EAP packet header.
	uint8_t const			*hmac_extra;		//!< Extra data for the HMAC function.
	size_t				hmac_extra_len;		//!< The length of the HMAC data.
} fr_aka_sim_encode_ctx_t;

extern size_t const fr_aka_sim_attr_sizes[FR_TYPE_MAX + 1][2];

/*
 *	decode.c
 */
ssize_t		fr_aka_sim_decode_pair(TALLOC_CTX *ctx, fr_cursor_t *cursor, fr_dict_t const *dict,
					   uint8_t const *data, size_t data_len, void *decoder_ctx);

int		fr_aka_sim_decode(REQUEST *request, fr_cursor_t *decoded, fr_dict_t const *dict,
				      uint8_t const *data, size_t data_len, fr_aka_sim_decode_ctx_t *ctx);

/*
 *	encode.c
 */
ssize_t		fr_aka_sim_encode_pair(uint8_t *out, size_t outlen, fr_cursor_t *cursor, void *encoder_ctx);

ssize_t		fr_aka_sim_encode(REQUEST *request, VALUE_PAIR *to_encode, void *encode_ctx);

/*
 *	base.c
 */
size_t		fr_aka_sim_attr_len(VALUE_PAIR const *vp);

size_t		fr_aka_sim_octets_prefix_len(fr_dict_attr_t const *da);

int		fr_aka_sim_init(void);

void		fr_aka_sim_free(void);

/*
 *	crypto.c
 */
int		fr_aka_sim_crypto_init_checkcode(TALLOC_CTX *ctx, fr_aka_sim_checkcode_t **checkcode,
						     EVP_MD const *md);

int		fr_aka_sim_crypto_update_checkcode(fr_aka_sim_checkcode_t *checkcode, eap_packet_t *eap_packet);

ssize_t		fr_aka_sim_crypto_finalise_checkcode(uint8_t *out, fr_aka_sim_checkcode_t **checkcode);

ssize_t		fr_aka_sim_crypto_sign_packet(uint8_t out[static AKA_SIM_MAC_DIGEST_SIZE],
						  eap_packet_t *eap_packet, bool zero_mac,
						  EVP_MD const *md, uint8_t const *key, size_t const key_len,
						  uint8_t const *hmac_extra, size_t const hmac_extra_len);

int		fr_aka_sim_crypto_gsm_kdf_0(fr_aka_sim_keys_t *keys);

int		fr_aka_sim_crypto_umts_kdf_0(fr_aka_sim_keys_t *keys);

int		fr_aka_sim_crypto_umts_kdf_1(fr_aka_sim_keys_t *keys);

void		fr_aka_sim_crypto_keys_init_kdf_0_reauth(fr_aka_sim_keys_t *keys,
							 uint8_t const mk[static AKA_SIM_MK_SIZE],
							 uint16_t counter);

void		fr_aka_sim_crypto_keys_init_umts_kdf_1_reauth(fr_aka_sim_keys_t *keys,
							      uint8_t const k_re[static AKA_SIM_K_RE_SIZE],
							      uint16_t counter);

int		fr_aka_sim_crypto_kdf_0_reauth(fr_aka_sim_keys_t *keys);

int		fr_aka_sim_crypto_umts_kdf_1_reauth(fr_aka_sim_keys_t *keys);

void		fr_aka_sim_crypto_keys_log(REQUEST *request, fr_aka_sim_keys_t *keys);

/*
 *	vector.c
 */
int		fr_aka_sim_vector_gsm_from_attrs(REQUEST *request, VALUE_PAIR *vps,
						 int idx,
						 fr_aka_sim_keys_t *keys,
						 fr_aka_sim_vector_src_t *src);

int		fr_aka_sim_vector_umts_from_attrs(REQUEST *request, VALUE_PAIR *vps,
						  fr_aka_sim_keys_t *keys,
						  fr_aka_sim_vector_src_t *src);

int		fr_aka_sim_vector_gsm_umts_kdf_0_reauth_from_attrs(REQUEST *request, VALUE_PAIR *vps,
								   fr_aka_sim_keys_t *keys);

int		fr_aka_sim_vector_umts_kdf_1_reauth_from_attrs(REQUEST *request, VALUE_PAIR *vps,
							       fr_aka_sim_keys_t *keys);

void		fr_aka_sim_vector_umts_reauth_clear(fr_aka_sim_keys_t *keys);

int		fr_aka_sim_umts_resync_from_attrs(uint64_t *new_sqn,
						  REQUEST *request, VALUE_PAIR *auts_vp,
						  fr_aka_sim_keys_t *keys);

/*
 *	fips186prf.c
 */
void		fr_aka_sim_fips186_2prf(uint8_t out[static 160], uint8_t mk[static 20]);

/*
 *	xlat.c
 */
void		fr_aka_sim_xlat_register(void);
void		fr_aka_sim_xlat_unregister(void);
