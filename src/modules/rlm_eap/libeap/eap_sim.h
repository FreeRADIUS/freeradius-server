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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2001  hereUare Communications, Inc. <raghud@hereuare.com>
 * Copyright 2003  Michael Richardson <mcr@sandelman.ottawa.on.ca>
 *
 */
#ifndef _EAP_SIM_H
#define _EAP_SIM_H

#include "eap_types.h"

#define EAP_SIM_VERSION 0x0001

/* base for dictionary values */
#define ATTRIBUTE_EAP_SIM_BASE      (6*256)

#define ATTRIBUTE_EAP_SIM_SUBTYPE   1023
#define ATTRIBUTE_EAP_SIM_CHAL1           1024	
#define ATTRIBUTE_EAP_SIM_CHAL2           1025	
#define ATTRIBUTE_EAP_SIM_CHAL3           1026	

#define ATTRIBUTE_EAP_SIM_SRES1           1027	
#define ATTRIBUTE_EAP_SIM_SRES2           1028	
#define ATTRIBUTE_EAP_SIM_SRES3           1029	

#define ATTRIBUTE_EAP_SIM_STATE           1030
#define ATTRIBUTE_EAP_SIM_IMSI            1031
#define ATTRIBUTE_EAP_SIM_HMAC            1032
#define ATTRIBUTE_EAP_SIM_KEY             1033
#define ATTRIBUTE_EAP_SIM_EXTRA           1034

#define ATTRIBUTE_EAP_SIM_KC1             1035
#define ATTRIBUTE_EAP_SIM_KC2             1036
#define ATTRIBUTE_EAP_SIM_KC3             1037

enum eapsim_subtype {
  eapsim_start       = 10,
  eapsim_challenge   = 11,
  eapsim_notification= 12,
  eapsim_reauth      = 13,
  eapsim_max_subtype = 14
};

enum eapsim_clientstates {
  eapsim_client_init = 0,
  eapsim_client_start = 1,
  eapsim_client_maxstates 
};

/* server states
 * 
 * in server_start, we send a EAP-SIM Start message.
 *
 */
enum eapsim_serverstates {
  eapsim_server_start = 0,
  eapsim_server_challenge=1,
  eapsim_server_success=10,
  eapsim_server_maxstates
};

#define PW_EAP_SIM_RAND                 1
#define PW_EAP_SIM_PADDING              6
#define PW_EAP_SIM_NONCE_MT             7
#define PW_EAP_SIM_PERMANENT_ID_REQ    10
#define PW_EAP_SIM_MAC                 11
#define PW_EAP_SIM_NOTIFICATION        12
#define PW_EAP_SIM_ANY_ID_REQ          13
#define PW_EAP_SIM_IDENTITY            14
#define PW_EAP_SIM_VERSION_LIST        15
#define PW_EAP_SIM_SELECTED_VERSION    16
#define PW_EAP_SIM_FULLAUTH_ID_REQ     17
#define PW_EAP_SIM_COUNTER             19
#define PW_EAP_SIM_COUNTER_TOO_SMALL   20
#define PW_EAP_SIM_NONCE_S             21
#define PW_EAP_SIM_IV                 129
#define PW_EAP_SIM_ENCR_DATA          130
#define PW_EAP_SIM_NEXT_PSEUDONUM     132
#define PW_EAP_SIM_NEXT_REAUTH_ID     133
#define PW_EAP_SIM_CHECKCODE          134

/*
 * interfaces in eapsimlib.c
 */
extern int map_eapsim_types(RADIUS_PACKET *r);
extern int map_eapsim_basictypes(RADIUS_PACKET *r, EAP_PACKET *ep);
extern int unmap_eapsim_types(RADIUS_PACKET *r);
extern const char *sim_state2name(enum eapsim_clientstates state, char *buf, int buflen);
extern const char *sim_subtype2name(enum eapsim_subtype subtype, char *buf, int buflen);
extern int unmap_eapsim_basictypes(RADIUS_PACKET *r, 
				   uint8_t *attr, unsigned int attrlen);


/************************/
/*   CRYPTO FUNCTIONS   */
/************************/
 
/*
 * key derivation functions/structures
 *
 */

#define EAPSIM_SRES_SIZE 4
#define EAPSIM_RAND_SIZE 16
#define EAPSIM_Kc_SIZE   8
#define EAPSIM_CALCMAC_SIZE 20
#define EAPSIM_NONCEMT_SIZE 16
#define EAPSIM_AUTH_SIZE    16

struct eapsim_keys {
  /* inputs */
  unsigned char identity[MAX_STRING_LEN];
  unsigned int  identitylen;
  unsigned char nonce_mt[EAPSIM_NONCEMT_SIZE];
  unsigned char rand[3][EAPSIM_RAND_SIZE];
  unsigned char sres[3][EAPSIM_SRES_SIZE];
  unsigned char Kc[3][EAPSIM_Kc_SIZE];
  unsigned char versionlist[MAX_STRING_LEN];
  unsigned char versionlistlen;
  unsigned char versionselect[2];

  /* outputs */
  unsigned char master_key[20];
  unsigned char K_aut[EAPSIM_AUTH_SIZE];
  unsigned char K_encr[16];
  unsigned char msk[64];
  unsigned char emsk[64];
};  


/*
 * interfaces in eapsimlib.c
 */
extern int  eapsim_checkmac(VALUE_PAIR *rvps,
			    u_int8_t key[8],
			    u_int8_t *extra, int extralen,
			    u_int8_t calcmac[20]);

/*
 * in eapcrypto.c
 */
extern void eapsim_calculate_keys(struct eapsim_keys *ek);
extern void eapsim_dump_mk(struct eapsim_keys *ek);


#endif /* _EAP_SIM_H */
