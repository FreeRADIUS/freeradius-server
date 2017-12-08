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
 * @file rlm_eap/lib/sim/id.h
 * @brief EAP-SIM/EAP-AKA identity detection, creation, and decyption.
 *
 * @copyright 2017 The FreeRADIUS server project
 */
#ifndef _EAP_SIM_ID_TYPE_H
#define _EAP_SIM_ID_TYPE_H

#include <sys/types.h>

#define SIM_3GPP_PSEUDONYM_LEN			23	//!< Length of a base64 encoded 3gpp pseudonym.
#define SIM_IMSI_MAX_LEN			15	//!< Length of an IMSI number in ASCII.

/** SIM/AKA method hints
 *
 * Derived from processing the provided identity.
 */
typedef enum {
	SIM_METHOD_HINT_UNKNOWN			= 0,	//!< We don't know what method the identity hints at.
	SIM_METHOD_HINT_SIM			= 1,	//!< The identity hints the supplicant wants to use
							///< EAP-SIM.
	SIM_METHOD_HINT_AKA			= 2	//!< The identity hints the supplicant wants to use
							///< EAP-AKA.
} fr_sim_method_hint_t;

/** SIM/AKA identity type hints
 *
 * Derived from the processing the provided identity.
 */
typedef enum {
	SIM_ID_TYPE_UNKNOWN			= 0,	//!< We don't know what type of identity this is.
	SIM_ID_TYPE_PERMANENT			= 1,	//!< This is a permanent identity (the IMSI of the SIM).
	SIM_ID_TYPE_PSEUDONYM			= 2,	//!< This is a custom pseudonym.
	SIM_ID_TYPE_3GPP_PSEUDONYM		= 3,	//!< This is a reversibly encrypted 3gpp pseudonym.
	SIM_ID_TYPE_FASTAUTH			= 4	//!< This is a fastauth (session-resumption) id.
} fr_sim_id_type_t;

typedef enum {
	SIM_ID_TAG_PERMANENT_AKA		= '0',
	SIM_ID_TAG_PERMANENT_SIM		= '1',
	SIM_ID_TAG_PSEUDONYM_AKA		= '2',
	SIM_ID_TAG_PSEUDONYM_SIM		= '3',
	SIM_ID_TAG_3GPP_PSEUDONYM_AKA		= '6',
	SIM_ID_TAG_3GPP_PSEUDONYM_SIM		= '7',
	SIM_ID_TAG_FASTAUTH_AKA			= '4',
	SIM_ID_TAG_FASTAUTH_SIM			= '5'
} fr_sim_id_tag_t;

size_t		fr_sim_id_user_len(char const *nai, size_t nai_len);

char const	*fr_sim_domain(char const *nai, size_t nai_len);

ssize_t		fr_sim_3gpp_root_nai_domain_mcc_mnc(uint16_t *mnc, uint16_t *mcc,
						    char const *domain, size_t domain_len);

int		fr_sim_id_type(fr_sim_id_type_t *type, fr_sim_method_hint_t *hint,
			       char const *id, size_t id_len);

int		fr_sim_id_3gpp_pseudonym_encrypt(char out[SIM_3GPP_PSEUDONYM_LEN + 1],
						 char const *imsi, size_t imsi_len,
						 uint8_t tag,  uint8_t key_ind, uint8_t const key[8]);

uint8_t		fr_sim_id_3gpp_pseudonym_tag(char const encr_id[SIM_3GPP_PSEUDONYM_LEN]);

uint8_t		fr_sim_id_3gpp_pseudonym_key_index(char const encr_id[SIM_3GPP_PSEUDONYM_LEN]);

int		fr_sim_id_3gpp_pseudonym_decrypt(char out[SIM_IMSI_MAX_LEN],
				     		 char const encr_id[SIM_3GPP_PSEUDONYM_LEN], uint8_t const key[8]);
#endif	/* _EAP_SIM_ID_TYPE_H */
