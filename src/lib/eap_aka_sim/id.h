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
 * @file src/lib/eap_aka_sim/id.h
 * @brief EAP-SIM/EAP-AKA identity detection, creation, and decyption.
 *
 * @copyright 2017 The FreeRADIUS server project
 */
#include <sys/types.h>
#include <freeradius-devel/util/token.h>

#define AKA_SIM_3GPP_PSEUDONYM_LEN		23	//!< Length of a base64 encoded 3gpp pseudonym.
#define AKA_SIM_IMSI_MAX_LEN			15	//!< Length of an IMSI number in ASCII.
#define AKA_SIM_IMSI_MIN_LEN			14	//!< Minimum length of an IMSI number in ASCII.

/** SIM/AKA method hints
 *
 * Derived from processing the provided identity.
 */
typedef enum {
	AKA_SIM_METHOD_HINT_UNKNOWN = 0,		//!< We don't know what method the identity hints at.
	AKA_SIM_METHOD_HINT_SIM,			//!< The identity hints the supplicant wants to use
							///< EAP-SIM.
	AKA_SIM_METHOD_HINT_AKA,			//!< The identity hints the supplicant wants to use
							///< EAP-AKA.
	AKA_SIM_METHOD_HINT_AKA_PRIME,
	AKA_SIM_METHOD_HINT_MAX
} fr_aka_sim_method_hint_t;

/** SIM/AKA identity type hints
 *
 * Derived from the processing the provided identity.
 */
typedef enum {
	AKA_SIM_ID_TYPE_UNKNOWN	= 0,			//!< We don't know what type of identity this is.
	AKA_SIM_ID_TYPE_PERMANENT,			//!< This is a permanent identity (the IMSI of the SIM).
	AKA_SIM_ID_TYPE_PSEUDONYM,			//!< This is a custom pseudonym.
	AKA_SIM_ID_TYPE_FASTAUTH,			//!< This is a fastauth (session-resumption) id.
	AKA_SIM_ID_TYPE_MAX
} fr_aka_sim_id_type_t;

typedef enum {
	ID_TAG_SIM_PERMANENT			= '1',  //!< IMSI, and hint that client wants to do EAP-SIM
	ID_TAG_SIM_PSEUDONYM			= '3',	//!< Pseudonym, continue EAP-SIM
	ID_TAG_SIM_FASTAUTH			= '5',	//!< Fastauth, continue EAP-SIM

	ID_TAG_AKA_PERMANENT			= '0',	//!< IMSI, and hint that client wants to do EAP-AKA
	ID_TAG_AKA_PSEUDONYM			= '2',	//!< Pseudonym, continue EAP-AKA
	ID_TAG_AKA_FASTAUTH			= '4',	//!< Fastauth, continue EAP-AKA

	ID_TAG_AKA_PRIME_PERMANENT         	= '6',	//!< IMSI, and hint that client wants to do EAP-AKA-Prime.
	ID_TAG_AKA_PRIME_PSEUDONYM		= '7',	//!< Pseudonym, continue EAP-AKA-Prime
	ID_TAG_AKA_PRIME_FASTAUTH		= '8'	//!< Fastuath, continue EAP-AKA-Prime
} fr_aka_sim_id_tag_t;

/** Identity request types
 */
typedef enum {
	AKA_SIM_NO_ID_REQ = 0,			//!< We're not requesting any ID.
	AKA_SIM_ANY_ID_REQ,			//!< Request IMSI, Pseudonym or Fast-reauth.
	AKA_SIM_FULLAUTH_ID_REQ,		//!< Request IMSI or Pseudonym.
	AKA_SIM_PERMANENT_ID_REQ,		//!< Request IMSI.
} fr_aka_sim_id_req_type_t;

extern fr_table_num_sorted_t const fr_aka_sim_id_request_table[];
extern size_t fr_aka_sim_id_request_table_len;
extern fr_table_num_sorted_t const fr_aka_sim_id_method_table[];
extern size_t fr_aka_sim_id_method_table_len;

#define ID_TAG_SIM_PSEUDONYM_B64		55
#define ID_TAG_AKA_PSEUDONYM_B64		54
#define ID_TAG_AKA_PRIME_PSEUDONYM_B64		59

size_t		fr_aka_sim_id_user_len(char const *nai, size_t nai_len);

char const	*fr_aka_sim_domain(char const *nai, size_t nai_len);

ssize_t		fr_aka_sim_3gpp_root_nai_domain_mcc_mnc(uint16_t *mnc, uint16_t *mcc,
						    char const *domain, size_t domain_len);

int		fr_aka_sim_id_type(fr_aka_sim_id_type_t *type, fr_aka_sim_method_hint_t *hint,
				   char const *id, size_t id_len);

char		fr_aka_sim_hint_byte(fr_aka_sim_id_type_t type, fr_aka_sim_method_hint_t method);

int		fr_aka_sim_id_3gpp_pseudonym_encrypt(char out[AKA_SIM_3GPP_PSEUDONYM_LEN + 1],
						     char const *imsi, size_t imsi_len,
						     uint8_t tag,  uint8_t key_ind, uint8_t const key[16]);

uint8_t		fr_aka_sim_id_3gpp_pseudonym_tag(char const encr_id[AKA_SIM_3GPP_PSEUDONYM_LEN]);

uint8_t		fr_aka_sim_id_3gpp_pseudonym_key_index(char const encr_id[AKA_SIM_3GPP_PSEUDONYM_LEN]);

int		fr_aka_sim_id_3gpp_pseudonym_decrypt(char out[AKA_SIM_IMSI_MAX_LEN],
				     		     char const encr_id[AKA_SIM_3GPP_PSEUDONYM_LEN],
				     		     uint8_t const key[16]);
