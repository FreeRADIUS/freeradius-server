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
	static_assert(PW_EAP_SIM_##_name == PW_EAP_AKA_##_name, \
		      "Number mismatch between PW_EAP_SIM_##_name and PW_EAP_AKA_##_name")

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

#define PW_SIM_PERMANENT_ID_REQ			(PW_EAP_SIM_PERMANENT_ID_REQ & PW_EAP_AKA_PERMANENT_ID_REQ)
#define PW_SIM_ANY_ID_REQ			(PW_EAP_SIM_ANY_ID_REQ & PW_EAP_AKA_ANY_ID_REQ)
#define PW_SIM_FULLAUTH_ID_REQ			(PW_EAP_SIM_FULLAUTH_ID_REQ & PW_EAP_AKA_FULLAUTH_ID_REQ)
#define PW_SIM_IDENTITY				(PW_EAP_SIM_IDENTITY & PW_EAP_AKA_IDENTITY)
#define PW_SIM_RAND				(PW_EAP_SIM_RAND & PW_EAP_AKA_RAND)
#define PW_SIM_NEXT_PSEUDONYM			(PW_EAP_SIM_NEXT_PSEUDONYM & PW_EAP_AKA_NEXT_PSEUDONYM)
#define PW_SIM_NEXT_REAUTH_ID			(PW_EAP_SIM_NEXT_REAUTH_ID & PW_EAP_AKA_NEXT_REAUTH_ID)
#define PW_SIM_IV				(PW_EAP_SIM_IV & PW_EAP_AKA_IV)
#define PW_SIM_ENCR_DATA			(PW_EAP_SIM_ENCR_DATA & PW_EAP_AKA_ENCR_DATA)
#define PW_SIM_PADDING				(PW_EAP_SIM_PADDING & PW_EAP_AKA_PADDING)
#define PW_SIM_RESULT_IND			(PW_EAP_SIM_RESULT_IND & PW_EAP_AKA_RESULT_IND)
#define PW_SIM_MAC				(PW_EAP_SIM_MAC & PW_EAP_AKA_MAC)
#define PW_SIM_COUNTER				(PW_EAP_SIM_COUNTER & PW_EAP_AKA_COUNTER)
#define PW_SIM_COUNTER_TOO_SMALL		(PW_EAP_SIM_COUNTER_TOO_SMALL & PW_EAP_AKA_COUNTER_TOO_SMALL)
#define PW_SIM_NONCE_S				(PW_EAP_SIM_NONCE_S & PW_EAP_AKA_NONCE_S)
#define PW_SIM_NOTIFICATION			(PW_EAP_SIM_NOTIFICATION & PW_EAP_AKA_NOTIFICATION)
#define PW_SIM_CLIENT_ERROR_CODE		(PW_EAP_SIM_CLIENT_ERROR_CODE & PW_EAP_AKA_CLIENT_ERROR_CODE)

/*
 *	Common internal attributes
 */
DICT_SANITY_CHECK(SUBTYPE);
DICT_SANITY_CHECK(HMAC);
DICT_SANITY_CHECK(KEY);
DICT_SANITY_CHECK(EXTRA);

#define PW_SIM_SUBTYPE				(PW_EAP_SIM_SUBTYPE & PW_EAP_AKA_SUBTYPE)
#define PW_SIM_HMAC				(PW_EAP_SIM_HMAC & PW_EAP_AKA_HMAC)
#define PW_SIM_KEY				(PW_EAP_SIM_KEY & PW_EAP_AKA_KEY)
#define PW_SIM_EXTRA				(PW_EAP_SIM_EXTRA & PW_EAP_AKA_EXTRA)
