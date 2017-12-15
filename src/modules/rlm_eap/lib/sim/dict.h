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
 * @file rlm_eap/lib/sim/dict.h
 * @brief Attributes to EAP-SIM/AKA/AKA' clients and servers.
 *
 * @copyright 2003-2016 The FreeRADIUS server project
 */
#include <freeradius-devel/rad_assert.h>
#include <freeradius-devel/eap.sim.h>
#include <freeradius-devel/eap.aka.h>

/*
 *	Sanity check on dictionaries...
 *
 *	EAP-SIM/AKA/AKA' attributes are allocated from
 *	the same IANA number space, so they should
 *	by identical
 */
#define DICT_SANITY_CHECK(_name) \
	static_assert(FR_EAP_SIM_##_name == FR_EAP_AKA_##_name, \
		      "Number mismatch between FR_EAP_SIM_##_name and FR_EAP_AKA_##_name")

DICT_SANITY_CHECK(PERMANENT_ID_REQ);
DICT_SANITY_CHECK(ANY_ID_REQ);
DICT_SANITY_CHECK(FULLAUTH_ID_REQ);
DICT_SANITY_CHECK(IDENTITY);
DICT_SANITY_CHECK(RAND);
DICT_SANITY_CHECK(NEXT_PSEUDONYM);
DICT_SANITY_CHECK(NEXT_REAUTH_ID);
DICT_SANITY_CHECK(IV);
DICT_SANITY_CHECK(ENCR_DATA);
DICT_SANITY_CHECK(PADDING);
DICT_SANITY_CHECK(RESULT_IND);
DICT_SANITY_CHECK(MAC);
DICT_SANITY_CHECK(COUNTER);
DICT_SANITY_CHECK(COUNTER_TOO_SMALL);
DICT_SANITY_CHECK(NONCE_S);
DICT_SANITY_CHECK(NOTIFICATION);
DICT_SANITY_CHECK(CLIENT_ERROR_CODE);

#define FR_SIM_PERMANENT_ID_REQ			(FR_EAP_SIM_PERMANENT_ID_REQ & FR_EAP_AKA_PERMANENT_ID_REQ)
#define FR_SIM_ANY_ID_REQ			(FR_EAP_SIM_ANY_ID_REQ & FR_EAP_AKA_ANY_ID_REQ)
#define FR_SIM_FULLAUTH_ID_REQ			(FR_EAP_SIM_FULLAUTH_ID_REQ & FR_EAP_AKA_FULLAUTH_ID_REQ)
#define FR_SIM_IDENTITY				(FR_EAP_SIM_IDENTITY & FR_EAP_AKA_IDENTITY)
#define FR_SIM_RAND				(FR_EAP_SIM_RAND & FR_EAP_AKA_RAND)
#define FR_SIM_NEXT_PSEUDONYM			(FR_EAP_SIM_NEXT_PSEUDONYM & FR_EAP_AKA_NEXT_PSEUDONYM)
#define FR_SIM_NEXT_REAUTH_ID			(FR_EAP_SIM_NEXT_REAUTH_ID & FR_EAP_AKA_NEXT_REAUTH_ID)
#define FR_SIM_IV				(FR_EAP_SIM_IV & FR_EAP_AKA_IV)
#define FR_SIM_ENCR_DATA			(FR_EAP_SIM_ENCR_DATA & FR_EAP_AKA_ENCR_DATA)
#define FR_SIM_PADDING				(FR_EAP_SIM_PADDING & FR_EAP_AKA_PADDING)
#define FR_SIM_RESULT_IND			(FR_EAP_SIM_RESULT_IND & FR_EAP_AKA_RESULT_IND)
#define FR_SIM_MAC				(FR_EAP_SIM_MAC & FR_EAP_AKA_MAC)
#define FR_SIM_COUNTER				(FR_EAP_SIM_COUNTER & FR_EAP_AKA_COUNTER)
#define FR_SIM_COUNTER_TOO_SMALL		(FR_EAP_SIM_COUNTER_TOO_SMALL & FR_EAP_AKA_COUNTER_TOO_SMALL)
#define FR_SIM_NONCE_S				(FR_EAP_SIM_NONCE_S & FR_EAP_AKA_NONCE_S)
#define FR_SIM_NOTIFICATION			(FR_EAP_SIM_NOTIFICATION & FR_EAP_AKA_NOTIFICATION)
#define FR_SIM_CLIENT_ERROR_CODE		(FR_EAP_SIM_CLIENT_ERROR_CODE & FR_EAP_AKA_CLIENT_ERROR_CODE)

/*
 *	Common internal attributes
 */
DICT_SANITY_CHECK(SUBTYPE);
#define FR_SIM_SUBTYPE				(FR_EAP_SIM_SUBTYPE & FR_EAP_AKA_SUBTYPE)
