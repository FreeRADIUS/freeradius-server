#pragma once
/*
 * eap_types.h  Header file containing the interfaces for all EAP types.
 *
 * most contents moved from modules/rlm_eap/eap.h
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
 * @copyright 2001  hereUare Communications, Inc. <raghud@hereuare.com>
 * @copyright 2003  Alan DeKok <aland@freeradius.org>
 * @copyright 2006  The FreeRADIUS server project
 */
RCSIDH(eap_methods_h, "$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/modules.h>

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
	FR_EAP_INVALID = 0,		/* 0 */
	FR_EAP_IDENTITY,		/* 1 */
	FR_EAP_NOTIFICATION,		/* 2 */
	FR_EAP_NAK,			/* 3 */
	FR_EAP_MD5,			/* 4 */
	FR_EAP_OTP,			/* 5 */
	FR_EAP_GTC,			/* 6 */
	FR_EAP_7,			/* 7  - unused */
	FR_EAP_8,			/* 8  - unused */
	FR_EAP_RSA_PUBLIC_KEY,		/* 9 */
	FR_EAP_DSS_UNILATERAL,		/* 10 */
	FR_EAP_KEA,			/* 11 */
	FR_EAP_KEA_VALIDATE,		/* 12 */
	FR_EAP_TLS,			/* 13 */
	FR_EAP_DEFENDER_TOKEN,		/* 14 */
	FR_EAP_RSA_SECURID,		/* 15 */
	FR_EAP_ARCOT_SYSTEMS,		/* 16 */
	FR_EAP_LEAP,			/* 17 */
	FR_EAP_SIM,			/* 18 */
	FR_EAP_SRP_SHA1,		/* 19 */
	FR_EAP_20,			/* 20 - unassigned */
	FR_EAP_TTLS,			/* 21 */
	FR_EAP_REMOTE_ACCESS_SERVICE,	/* 22 */
	FR_EAP_AKA,			/* 23 */
	FR_EAP_3COM,			/* 24 - should this be EAP-HP now? */
	FR_EAP_PEAP,			/* 25 */
	FR_EAP_MSCHAPV2,		/* 26 */
	FR_EAP_MAKE,			/* 27 */
	FR_EAP_CRYPTOCARD,		/* 28 */
	FR_EAP_CISCO_MSCHAPV2,		/* 29 */
	FR_EAP_DYNAMID,			/* 30 */
	FR_EAP_ROB,			/* 31 */
	FR_EAP_POTP,			/* 32 */
	FR_EAP_MS_ATLV,			/* 33 */
	FR_EAP_SENTRINET,		/* 34 */
	FR_EAP_ACTIONTEC,		/* 35 */
	FR_EAP_COGENT_BIOMETRIC,	/* 36 */
	FR_EAP_AIRFORTRESS,		/* 37 */
	FR_EAP_TNC,			/* 38 - fixme conflicts with HTTP DIGEST */
//	FR_EAP_HTTP_DIGEST,		/* 38 */
	FR_EAP_SECURISUITE,		/* 39 */
	FR_EAP_DEVICECONNECT,		/* 40 */
	FR_EAP_SPEKE,			/* 41 */
	FR_EAP_MOBAC,			/* 42 */
	FR_EAP_FAST,			/* 43 */
	FR_EAP_ZONELABS,		/* 44 */
	FR_EAP_LINK,			/* 45 */
	FR_EAP_PAX,			/* 46 */
	FR_EAP_PSK,			/* 47 */
	FR_EAP_SAKE,			/* 48 */
	FR_EAP_IKEV2,			/* 49 */
	FR_EAP_AKA_PRIME,		/* 50 */
	FR_EAP_GPSK,			/* 51 */
	FR_EAP_PWD,			/* 52 */
	FR_EAP_EKE,			/* 53 */
	FR_EAP_PT,			/* 54 */
	FR_EAP_TEAP,			/* 55 */
	FR_EAP_MAX_TYPES		/* 56 - for validation */
} eap_type_t;

#define FR_EAP_EXPANDED_TYPE	(254)

/** EAP-Type specific data
 */
typedef struct eap_type_data {
	eap_type_t	num;
	size_t		length;
	uint8_t		*data;
} eap_type_data_t;

/** Structure to hold EAP data
 *
 * length = code + id + length + type + type.data
 *	=  1   +  1 +   2    +  1   +  X
 */
typedef struct eap_packet {
	eap_code_t	code;
	uint8_t		id;
	size_t		length;
	eap_type_data_t	type;

	uint8_t		*packet;
} eap_packet_t;

/** Structure to represent packet format of eap *on wire*
 */
typedef struct CC_HINT(__packed__) eap_packet_raw {
	uint8_t		code;
	uint8_t		id;
	uint8_t		length[2];
	uint8_t		data[1];
} eap_packet_raw_t;

typedef struct _eap_session eap_session_t;
