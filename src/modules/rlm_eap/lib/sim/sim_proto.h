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

#include "eap_types.h"
#include "eap_sim_common.h"

typedef struct eap_sim_vector {
	uint8_t		rand[EAP_SIM_RAND_SIZE];		//!< RAND challenge to the SIM.
	union {
		uint8_t		sres[EAP_SIM_SRES_SIZE];	//!< Signing response.
		uint32_t	sres_uint32;
	};

	union {
		uint8_t		kc[EAP_SIM_KC_SIZE];		//!< Keying response.
		uint64_t	kc_uint64;
	};
} eap_sim_vector_t;

typedef struct fr_sim_keys {
	/*
	 *	Inputs
	 */
	uint8_t			*identity;
	size_t			identity_len;
	uint8_t			nonce_mt[EAP_SIM_NONCE_MT_SIZE];	//!< Nonce provided by the client.

	/*
	 *	The GSM vectors we acquired during the
	 *	challenge phase.
	 */
	eap_sim_vector_t	vector[3];				//!< EAP-SIM GSM vectors
	uint32_t		num_vectors;				//!< Number of input vectors
									//!< we're using (2 or 3).

	uint8_t			version_list[FR_MAX_STRING_LEN];
	uint8_t			version_list_len;
	uint8_t			version_select[2];

	/*
	 *	Outputs
	 */
	uint8_t			master_key[20];
	uint8_t			k_aut[EAP_SIM_AUTH_SIZE];		//!< Derived authentication key.
	uint8_t			k_encr[16];				//!< Derived encryption key.

	uint8_t			msk[64];				//!< Derived master session key.
	uint8_t			emsk[64];				//!< Derived extended master session key.
} fr_sim_keys_t;

/*
 *	proto.c
 */
int fr_sim_encode(RADIUS_PACKET *r, eap_packet_t *ep);
int fr_sim_decode(RADIUS_PACKET *r, uint8_t *attr, unsigned int attrlen);

char const *fr_sim_session_to_name(char *out, size_t outlen, eap_sim_client_states_t state);
char const *fr_sim_subtype_to_name(char *out, size_t outlen, eap_sim_subtype_t subtype);

/*
 *	crypto.c
 */
int fr_sim_crypto_mac_verify(TALLOC_CTX *ctx, VALUE_PAIR *rvps,
		       	     uint8_t key[8],
			     uint8_t *extra, int extra_len,
			     uint8_t calc_mac[20])
			     CC_BOUNDED(__size__, 3, 8, 8)
			     CC_BOUNDED(__size__, 6, 20, 20);

void fr_sim_crypto_keys_derive(fr_sim_keys_t *ek);
void fr_sim_crypto_keys_log(REQUEST *request, fr_sim_keys_t *ek);


/*
 *	fips186prf.c
 */
void fr_sim_fips186_2prf(uint8_t out[160], uint8_t mk[20])
			 CC_BOUNDED(__size__, 2, 160, 160)
			 CC_BOUNDED(__size__, 1, 20, 20);

#endif /* _SIM_PROTO_H */
