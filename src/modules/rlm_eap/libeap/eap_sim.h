/*
 * eap_sim.h    Header file containing the EAP-SIM types
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
 * Copyright 2003  Michael Richardson <mcr@sandelman.ottawa.on.ca>
 * Copyright 2006  The FreeRADIUS server project
 *
 */
#ifndef _EAP_SIM_H
#define _EAP_SIM_H

RCSIDH(eap_sim_h, "$Id$")

#include "eap_types.h"

#define EAP_SIM_VERSION 0x0001

typedef enum eap_sim_subtype {
	EAP_SIM_START		= 10,
	EAP_SIM_CHALLENGE	= 11,
	EAP_SIM_NOTIFICATION	= 12,
	EAP_SIM_REAUTH		= 13,
	EAP_SIM_CLIENT_ERROR	= 14,
	EAP_SIM_MAX_SUBTYPE	= 15
} eap_sim_subtype_t;

typedef enum eap_sim_client_states {
	EAP_SIM_CLIENT_INIT	= 0,
	EAP_SIM_CLIENT_START	= 1,
	EAP_SIM_CLIENT_MAX_STATES
} eap_sim_client_states_t;

#define EAP_SIM_SRES_SIZE	4
#define EAP_SIM_RAND_SIZE	16
#define EAP_SIM_KC_SIZE		8
#define EAP_SIM_CALCMAC_SIZE	20
#define EAP_SIM_NONCEMT_SIZE	16
#define EAP_SIM_AUTH_SIZE	16

typedef struct eap_sim_keys {
	/* inputs */
	uint8_t		identity[FR_MAX_STRING_LEN];
	unsigned int	identity_len;
	uint8_t		nonce_mt[EAP_SIM_NONCEMT_SIZE];

	uint8_t		rand[3][EAP_SIM_RAND_SIZE];

	union {
		uint8_t		sres[3][EAP_SIM_SRES_SIZE];
		uint32_t	sres_uint32[3];
	};

	union {
		uint8_t		kc[3][EAP_SIM_KC_SIZE];
		uint64_t	kc_uint64[3];
	};

	uint8_t		version_list[FR_MAX_STRING_LEN];
	uint8_t		version_list_len;
	uint8_t		version_select[2];

	/* outputs */
	uint8_t		master_key[20];
	uint8_t		k_aut[EAP_SIM_AUTH_SIZE];
	uint8_t		k_encr[16];
	uint8_t		msk[64];
	uint8_t		emsk[64];
} eap_sim_keys_t;



/*
 *	eap_simlib.c
 */
int eap_sim_encode(RADIUS_PACKET *r, eap_packet_t *ep);
int eap_sim_decode(RADIUS_PACKET *r, uint8_t *attr, unsigned int attrlen);
char const *eap_sim_session_to_name(char *out, size_t outlen, eap_sim_client_states_t state);
char const *eap_sim_subtype_to_name(char *out, size_t outlen, eap_sim_subtype_t subtype);

/************************/
/*   CRYPTO FUNCTIONS   */
/************************/
/*
 * key derivation functions/structures
 */

/*
 * interfaces in eap_simlib.c
 */
int eap_sim_check_mac(TALLOC_CTX *ctx, VALUE_PAIR *rvps,
		      uint8_t key[8],
		      uint8_t *extra, int extralen,
		      uint8_t calcmac[20]);

/*
 * in eapcrypto.c
 */
void eap_sim_calculate_keys(struct eap_sim_keys *ek);
void eap_sim_dump_mk(struct eap_sim_keys *ek);
#endif /* _EAP_SIM_H */
