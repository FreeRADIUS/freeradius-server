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
 * @file rlm_eap/lib/sim/sim_proto.h
 * @brief Functions common to SIM protocols (EAP-SIM/EAP-AKA/EAP-AKA')
 *
 * The development of the EAP/SIM support was funded by Internet Foundation
 * Austria (http://www.nic.at/ipa).
 *
 * @copyright 2003 Michael Richardson <mcr@sandelman.ottawa.on.ca>
 * @copyright 2003-2016 The FreeRADIUS server project
 */
#ifndef _SIM_PROTO_H
#define _SIM_PROTO_H

RCSIDH(sim_h, "$Id$")

#include <assert.h>
#include "dict.h"
#include "id.h"
#include "eap_types.h"
#include "eap_sim_common.h"
#include "eap_aka_common.h"

#define SIM_IV_SIZE			16		//!< Length of the IV used when processing AT_ENCR.
#define SIM_CALC_MAC_SIZE		20		//!< Length of MAC used to prevent packet modification.
#define SIM_AUTH_SIZE			16
#define SIM_SKIPPABLE_MAX		127		//!< The last non-skippable attribute.

#define SIM_VECTOR_GSM_RAND_SIZE	16		//!< Length of RAND in GSM triplet.
#define SIM_VECTOR_GSM_SRES_SIZE	4		//!< Length of SRES in GSM triplet.
#define SIM_VECTOR_GSM_KC_SIZE		8		//!< Length of Kc in GSM triplet.

#define SIM_VECTOR_UMTS_AUTN_SIZE	16
#define SIM_VECTOR_UMTS_CK_SIZE		16
#define SIM_VECTOR_UMTS_IK_SIZE		16
#define SIM_VECTOR_UMTS_RAND_SIZE	16
#define SIM_VECTOR_UMTS_XRES_MAX_SIZE	16
#define SIM_VECTOR_UMTS_RES_MAX_SIZE	16

/** The type of auth vector held by a fr_sim_keys_t
 */
typedef enum {
	SIM_VECTOR_NONE = 0,
	SIM_VECTOR_GSM,						//!< Vector is GSM triplets.
	SIM_VECTOR_UMTS						//!< Vector is UMTS quintuplets.
} fr_sim_vector_type_t;

/** Where to get EAP-SIM vectors from
 */
typedef enum {
	SIM_VECTOR_SRC_AUTO,					//!< Discover where to get Triplets from automatically.
	SIM_VECTOR_SRC_TRIPLETS,				//!< Source of triplets is EAP-SIM-* attributes.
	SIM_VECTOR_SRC_QUINTUPLETS,				//!< Source of triplets is derived from EAP-AKA-*
								///< quintuplets.
	SIM_VECTOR_SRC_KI					//!< Should generate triplets locally using a Ki.
} fr_sim_vector_src_t;

typedef struct gsm_vector {
	uint8_t		rand[SIM_VECTOR_GSM_RAND_SIZE];		//!< RAND challenge to the SIM.
	union {
		uint8_t		sres[SIM_VECTOR_GSM_SRES_SIZE];		//!< Signing response.
		uint32_t	sres_uint32;
	};

	union {
		uint8_t		kc[SIM_VECTOR_GSM_KC_SIZE];		//!< Keying response.
		uint64_t	kc_uint64;
	};
} fr_sim_vector_gsm_t;

typedef struct umts_vector {
	uint8_t		autn[SIM_VECTOR_UMTS_AUTN_SIZE];	//!< Authentication vector from the AuC.
	uint8_t		ck[SIM_VECTOR_UMTS_CK_SIZE];		//!< Ciphering key.
	uint8_t		ik[SIM_VECTOR_UMTS_IK_SIZE];		//!< Integrity key.
	uint8_t		rand[SIM_VECTOR_UMTS_RAND_SIZE];	//!< RAND challenge to the SIM.
	uint8_t		xres[SIM_VECTOR_UMTS_RES_MAX_SIZE];	//!< Signing response.
	size_t		xres_len;				//!< Length of res (it's variable).
} fr_sim_vector_umts_t;

/** Master key state struct for all SIMlike EAP protocols
 *
 */
typedef struct fr_sim_keys {
	uint8_t		*identity;				//!< Identity from AT_IDENTITY.
	size_t		identity_len;				//!< Length of the identity.

	/*
	 *	The vectors we acquired during the challenge phase.
	 */
	union {
		/** Input to kdf_0_gsm
		 */
		struct {
			fr_sim_vector_gsm_t	vector[3];			//!< GSM vectors.
			uint32_t		num_vectors;			//!< Number of input vectors
										//!< we're using (2 or 3).

			uint8_t			nonce_mt[EAP_SIM_NONCE_MT_SIZE];//!< Nonce provided by the client.
			uint8_t			version_list[FR_MAX_STRING_LEN];//!< Version list from negotiation.
			uint8_t			version_list_len;		//!< Length of version list.
			uint8_t			version_select[2];		//!< Version we agreed.
		} gsm;

		/** Input to kdf_*_umts
		 */
		struct {
			fr_sim_vector_umts_t	vector;		//!< UMTS vector.
		} umts;
	};

	fr_sim_vector_type_t	vector_type;			//!< What type of authentication vector
								//!< we're using to authenticate the SIM.
	/*
	 *	Outputs
	 */
	uint8_t		master_key[20];			//!< Master key from session attributes.

	uint8_t		k_aut[SIM_AUTH_SIZE];		//!< Derived authentication key.
	uint8_t		k_encr[16];			//!< Derived encryption key.

	uint8_t		msk[64];			//!< Derived master session key.
	uint8_t		emsk[64];			//!< Derived extended master session key.
} fr_sim_keys_t;

typedef struct fr_sim_decode_ctx {
	fr_sim_keys_t	*keys;				//!< From the EAP session.
	uint8_t		iv[SIM_IV_SIZE];		//!< From the current packet.
	bool		have_iv;			//!< Whether we found the IV already.
} fr_sim_decode_ctx_t;

typedef struct fr_sim_encode_ctx {
	fr_sim_keys_t	*keys;				//!< From the EAP session.
	uint8_t		iv[SIM_IV_SIZE];		//!< Generated by us using our PRNG.
	bool		iv_included;			//!< Whether we've already added an IV to this packet.
} fr_sim_encode_ctx_t;

typedef struct _eap_session eap_session_t;

extern fr_dict_attr_t const *dict_sim_root;
extern fr_dict_attr_t const *dict_aka_root;

/*
 *	proto.c
 */
ssize_t		fr_sim_decode_pair(TALLOC_CTX *ctx, vp_cursor_t *cursor, fr_dict_attr_t const *parent,
				   uint8_t const *data, size_t data_len,
				   void *decoder_ctx);

int		fr_sim_decode(REQUEST *request, vp_cursor_t *decoded, fr_dict_attr_t const *parent,
			      uint8_t const *data, size_t data_len,
			      fr_sim_decode_ctx_t *ctx);

ssize_t		fr_sim_encode(REQUEST *request, fr_dict_attr_t const *parent, uint8_t type,
			      VALUE_PAIR *to_encode, eap_packet_t *eap_packet,
			      uint8_t const *hmac_extra, size_t hmac_extra_len);

char const	*fr_sim_session_to_name(char *out, size_t outlen, eap_sim_client_states_t state);

int		fr_sim_global_init(void);

/*
 *	crypto.c
 */
ssize_t		fr_sim_crypto_sign_packet(uint8_t out[16], eap_packet_t *eap_packet,
					  uint8_t const *key, size_t const key_len,
					  uint8_t const *hmac_extra, size_t const hmac_extra_len);

int		fr_sim_crypto_mac_verify(TALLOC_CTX *ctx, fr_dict_attr_t const *root,
					 VALUE_PAIR *rvps,
					 uint8_t key[8],
					 uint8_t *extra, int extra_len,
					 uint8_t calc_mac[20])
					 CC_BOUNDED(__size__, 3, 8, 8)
					 CC_BOUNDED(__size__, 6, 20, 20);

void		fr_sim_crypto_kdf_0_gsm(fr_sim_keys_t *keys);

void		fr_sim_crypto_kdf_0_umts(fr_sim_keys_t *keys);

void		fr_sim_crypto_keys_log(REQUEST *request, fr_sim_keys_t *keys);

/*
 *	vector.c
 */
int		fr_sim_vector_gsm_from_attrs(eap_session_t *eap_session, VALUE_PAIR *vps,
					     int idx, fr_sim_keys_t *keys, fr_sim_vector_src_t *src);

int		fr_sim_vector_umts_from_attrs(eap_session_t *eap_session, VALUE_PAIR *vps,
					      fr_sim_keys_t *keys, fr_sim_vector_src_t *src);

/*
 *	fips186prf.c
 */
void		fr_sim_fips186_2prf(uint8_t out[160], uint8_t mk[20])
				    CC_BOUNDED(__size__, 2, 160, 160)
				    CC_BOUNDED(__size__, 1, 20, 20);

/*
 *	xlat.c
 */
void		sim_xlat_register(void);
void		sim_xlat_unregister(void);
#endif /* _SIM_PROTO_H */
