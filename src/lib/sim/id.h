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
 * @file src/lib/sim/id.h
 * @brief EAP-SIM/EAP-AKA identity detection, creation, and decyption.
 *
 * @copyright 2017 The FreeRADIUS server project
 */
#include <sys/types.h>
#include <freeradius-devel/util/table.h>

#define SIM_3GPP_PSEUDONYM_LEN			23	//!< Length of a base64 encoded 3gpp pseudonym.
#define SIM_IMSI_MAX_LEN			15	//!< Length of an IMSI number in ASCII.
#define SIM_IMSI_MIN_LEN			14	//!< Minimum length of an IMSI number in ASCII.

/** SIM/AKA method hints
 *
 * Derived from processing the provided identity.
 */
typedef enum {
	SIM_METHOD_HINT_UNKNOWN			= 0,	//!< We don't know what method the identity hints at.
	SIM_METHOD_HINT_SIM			= 1,	//!< The identity hints the supplicant wants to use
							///< EAP-SIM.
	SIM_METHOD_HINT_AKA			= 2,	//!< The identity hints the supplicant wants to use
							///< EAP-AKA.
	SIM_METHOD_HINT_AKA_PRIME		= 3
} fr_sim_method_hint_t;

/** SIM/AKA identity type hints
 *
 * Derived from the processing the provided identity.
 */
typedef enum {
	SIM_ID_TYPE_UNKNOWN			= 0,	//!< We don't know what type of identity this is.
	SIM_ID_TYPE_PERMANENT			= 1,	//!< This is a permanent identity (the IMSI of the SIM).
	SIM_ID_TYPE_PSEUDONYM			= 2,	//!< This is a custom pseudonym.
	SIM_ID_TYPE_FASTAUTH			= 5	//!< This is a fastauth (session-resumption) id.
} fr_sim_id_type_t;

typedef enum {
	SIM_ID_TAG_PERMANENT_SIM		= '1',  //!< IMSI, and hint that client wants to do EAP-SIM
	SIM_ID_TAG_PSEUDONYM_SIM		= '3',	//!< Pseudonym, continue EAP-SIM
	SIM_ID_TAG_FASTAUTH_SIM			= '5',	//!< Fastauth, continue EAP-SIM

	SIM_ID_TAG_PERMANENT_AKA		= '0',	//!< IMSI, and hint that client wants to do EAP-AKA
	SIM_ID_TAG_PSEUDONYM_AKA		= '2',	//!< Pseudonym, continue EAP-AKA
	SIM_ID_TAG_FASTAUTH_AKA			= '4',	//!< Fastauth, continue EAP-AKA

	SIM_ID_TAG_PERMANENT_AKA_PRIME          = '6',	//!< IMSI, and hint that client wants to do EAP-AKA-Prime.
	SIM_ID_TAG_PSEUDONYM_AKA_PRIME		= '7',	//!< Pseudonym, continue EAP-AKA-Prime
	SIM_ID_TAG_FASTAUTH_AKA_PRIME		= '8'	//!< Fastuath, continue EAP-AKA-Prime
} fr_sim_id_tag_t;

/** Identity request types
 */
typedef enum {
	SIM_NO_ID_REQ = 0,			//!< We're not requesting any ID.
	SIM_ANY_ID_REQ,				//!< Request IMSI, Pseudonym or Fast-reauth.
	SIM_FULLAUTH_ID_REQ,			//!< Request IMSI or Pseudonym.
	SIM_PERMANENT_ID_REQ,			//!< Request IMSI.
} fr_sim_id_req_type_t;

extern fr_table_num_sorted_t const sim_id_request_table[];
extern size_t sim_id_request_table_len;
extern fr_table_num_sorted_t const sim_id_method_hint_table[];
extern size_t sim_id_method_hint_table_len;

#define SIM_ID_TAG_PSEUDONYM_SIM_B64		55
#define SIM_ID_TAG_PSEUDONYM_AKA_B64		54
#define SIM_ID_TAG_PSEUDONYM_AKA_PRIME_B64	59

size_t		fr_sim_id_user_len(char const *nai, size_t nai_len);

char const	*fr_sim_domain(char const *nai, size_t nai_len);

ssize_t		fr_sim_3gpp_root_nai_domain_mcc_mnc(uint16_t *mnc, uint16_t *mcc,
						    char const *domain, size_t domain_len);

int		fr_sim_id_type(fr_sim_id_type_t *type, fr_sim_method_hint_t *hint,
			       char const *id, size_t id_len);

int		fr_sim_id_3gpp_pseudonym_encrypt(char out[SIM_3GPP_PSEUDONYM_LEN + 1],
						 char const *imsi, size_t imsi_len,
						 uint8_t tag,  uint8_t key_ind, uint8_t const key[16]);

uint8_t		fr_sim_id_3gpp_pseudonym_tag(char const encr_id[SIM_3GPP_PSEUDONYM_LEN]);

uint8_t		fr_sim_id_3gpp_pseudonym_key_index(char const encr_id[SIM_3GPP_PSEUDONYM_LEN]);

int		fr_sim_id_3gpp_pseudonym_decrypt(char out[SIM_IMSI_MAX_LEN],
				     		 char const encr_id[SIM_3GPP_PSEUDONYM_LEN], uint8_t const key[16]);
