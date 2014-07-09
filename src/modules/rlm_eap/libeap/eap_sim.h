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

enum eapsim_subtype {
	EAPSIM_START		= 10,
	EAPSIM_CHALLENGE	= 11,
	EAPSIM_NOTIFICATION	= 12,
	EAPSIM_REAUTH		= 13,
	EAPSIM_CLIENT_ERROR	= 14,
	EAPSIM_MAX_SUBTYPE	= 15
};

enum eapsim_clientstates {
	EAPSIM_CLIENT_INIT	= 0,
	EAPSIM_CLIENT_START	= 1,
	EAPSIM_CLIENT_MAXSTATES
};

/* server states
 *
 * in server_start, we send a EAP-SIM Start message.
 *
 */
enum eapsim_serverstates {
	EAPSIM_SERVER_START	= 0,
	EAPSIM_SERVER_CHALLENGE	= 1,
	EAPSIM_SERVER_SUCCESS	= 10,
	EAPSIM_SERVER_MAXSTATES
};


/*
 * interfaces in eapsimlib.c
 */
int map_eapsim_basictypes(RADIUS_PACKET *r, eap_packet_t *ep);
char const *sim_state2name(enum eapsim_clientstates state, char *buf, int buflen);
char const *sim_subtype2name(enum eapsim_subtype subtype, char *buf, int buflen);
int unmap_eapsim_basictypes(RADIUS_PACKET *r, uint8_t *attr, unsigned int attrlen);


/************************/
/*   CRYPTO FUNCTIONS   */
/************************/

/*
 * key derivation functions/structures
 *
 */

#define EAPSIM_SRES_SIZE	4
#define EAPSIM_RAND_SIZE	16
#define EAPSIM_KC_SIZE		8
#define EAPSIM_CALCMAC_SIZE	20
#define EAPSIM_NONCEMT_SIZE	16
#define EAPSIM_AUTH_SIZE	16

struct eapsim_keys {
	/* inputs */
	uint8_t identity[MAX_STRING_LEN];
	unsigned int  identitylen;
	uint8_t nonce_mt[EAPSIM_NONCEMT_SIZE];
	uint8_t rand[3][EAPSIM_RAND_SIZE];
	uint8_t sres[3][EAPSIM_SRES_SIZE];
	uint8_t Kc[3][EAPSIM_KC_SIZE];
	uint8_t versionlist[MAX_STRING_LEN];
	uint8_t versionlistlen;
	uint8_t versionselect[2];

	/* outputs */
	uint8_t master_key[20];
	uint8_t K_aut[EAPSIM_AUTH_SIZE];
	uint8_t K_encr[16];
	uint8_t msk[64];
	uint8_t emsk[64];
};


/*
 * interfaces in eapsimlib.c
 */
int eapsim_checkmac(TALLOC_CTX *ctx, VALUE_PAIR *rvps,
		    uint8_t key[8],
		    uint8_t *extra, int extralen,
		    uint8_t calcmac[20]);

/*
 * in eapcrypto.c
 */
void eapsim_calculate_keys(struct eapsim_keys *ek);
void eapsim_dump_mk(struct eapsim_keys *ek);


#endif /* _EAP_SIM_H */
