#pragma once
/*
 *   This program is free software; you can redistribute it and/or modify
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
 * @file lib/eap/types.h
 * @brief Header file containing the interfaces for all EAP types
 *
 * @copyright 2001 hereUare Communications, Inc. (raghud@hereuare.com)
 * @copyright 2003 Alan DeKok (aland@freeradius.org)
 * @copyright 2006 The FreeRADIUS server project
 */

RCSIDH(lib_eap_types, "$Id$")

#include <stdint.h>
#include <stddef.h>

/* Code (1) + Identifier (1) + Length (2) */
#define EAP_HEADER_LEN 		4

typedef enum eap_code {
	FR_EAP_CODE_REQUEST = 1,
	FR_EAP_CODE_RESPONSE,
	FR_EAP_CODE_SUCCESS,
	FR_EAP_CODE_FAILURE,
	FR_EAP_CODE_MAX
} eap_code_t;

typedef enum eap_method {
	FR_EAP_METHOD_INVALID = 0,		/* 0 */
	FR_EAP_METHOD_IDENTITY,			/* 1 */
	FR_EAP_METHOD_NOTIFICATION,		/* 2 */
	FR_EAP_METHOD_NAK,			/* 3 */
	FR_EAP_METHOD_MD5,			/* 4 */
	FR_EAP_METHOD_OTP,			/* 5 */
	FR_EAP_METHOD_GTC,			/* 6 */
	FR_EAP_METHOD_7,			/* 7  - unused */
	FR_EAP_METHOD_8,			/* 8  - unused */
	FR_EAP_METHOD_RSA_PUBLIC_KEY,		/* 9 */
	FR_EAP_METHOD_DSS_UNILATERAL,		/* 10 */
	FR_EAP_METHOD_KEA,			/* 11 */
	FR_EAP_METHOD_KEA_VALIDATE,		/* 12 */
	FR_EAP_METHOD_TLS,			/* 13 */
	FR_EAP_METHOD_DEFENDER_TOKEN,		/* 14 */
	FR_EAP_METHOD_RSA_SECURID,		/* 15 */
	FR_EAP_METHOD_ARCOT_SYSTEMS,		/* 16 */
	FR_EAP_METHOD_LEAP,			/* 17 */
	FR_EAP_METHOD_SIM,			/* 18 */
	FR_EAP_METHOD_SRP_SHA1,			/* 19 */
	FR_EAP_METHOD_20,			/* 20 - unassigned */
	FR_EAP_METHOD_TTLS,			/* 21 */
	FR_EAP_METHOD_REMOTE_ACCESS_SERVICE,	/* 22 */
	FR_EAP_METHOD_AKA,			/* 23 */
	FR_EAP_METHOD_3COM,			/* 24 - should this be EAP-HP now? */
	FR_EAP_METHOD_PEAP,			/* 25 */
	FR_EAP_METHOD_MSCHAPV2,			/* 26 */
	FR_EAP_METHOD_MAKE,			/* 27 */
	FR_EAP_METHOD_CRYPTOCARD,		/* 28 */
	FR_EAP_METHOD_CISCO_MSCHAPV2,		/* 29 */
	FR_EAP_METHOD_DYNAMID,			/* 30 */
	FR_EAP_METHOD_ROB,			/* 31 */
	FR_EAP_METHOD_POTP,			/* 32 */
	FR_EAP_METHOD_MS_ATLV,			/* 33 */
	FR_EAP_METHOD_SENTRINET,		/* 34 */
	FR_EAP_METHOD_ACTIONTEC,		/* 35 */
	FR_EAP_METHOD_COGENT_BIOMETRIC,		/* 36 */
	FR_EAP_METHOD_AIRFORTRESS,		/* 37 */
	FR_EAP_METHOD_TNC,			/* 38 - fixme conflicts with HTTP DIGEST */
//	FR_EAP_METHOD_HTTP_DIGEST,		/* 38 */
	FR_EAP_METHOD_SECURISUITE,		/* 39 */
	FR_EAP_METHOD_DEVICECONNECT,		/* 40 */
	FR_EAP_METHOD_SPEKE,			/* 41 */
	FR_EAP_METHOD_MOBAC,			/* 42 */
	FR_EAP_METHOD_FAST,			/* 43 */
	FR_EAP_METHOD_ZONELABS,			/* 44 */
	FR_EAP_METHOD_LINK,			/* 45 */
	FR_EAP_METHOD_PAX,			/* 46 */
	FR_EAP_METHOD_PSK,			/* 47 */
	FR_EAP_METHOD_SAKE,			/* 48 */
	FR_EAP_METHOD_IKEV2,			/* 49 */
	FR_EAP_METHOD_AKA_PRIME,		/* 50 */
	FR_EAP_METHOD_GPSK,			/* 51 */
	FR_EAP_METHOD_PWD,			/* 52 */
	FR_EAP_METHOD_EKE,			/* 53 */
	FR_EAP_METHOD_PT,			/* 54 */
	FR_EAP_METHOD_TEAP,			/* 55 */
	FR_EAP_METHOD_MAX			/* 56 - for validation */
} eap_type_t;

#define FR_EAP_EXPANDED_TYPE	(254)

/** EAP-Type specific data
 */
typedef struct {
	eap_type_t	num;
	size_t		length;
	uint8_t		*data;
} eap_type_data_t;

/** Structure to represent packet format of eap *on wire*
 *
 * @note Do not change field order, or field size. Code depends on
 * sizeof(eap_packet_raw_t), and uses this structure for
 * on the wire parsing.
 */
typedef struct CC_HINT(__packed__) {
	uint8_t		code;
	uint8_t		id;
	uint8_t		length[2];
	uint8_t		data[1];
} eap_packet_raw_t;

eap_type_t	eap_name2type(char const *name);
char const	*eap_type2name(eap_type_t method);
