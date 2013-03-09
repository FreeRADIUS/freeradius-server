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
 * Copyright 2001  hereUare Communications, Inc. <raghud@hereuare.com>
 * Copyright 2003  Alan DeKok <aland@freeradius.org>
 * Copyright 2006  The FreeRADIUS server project
 */
#ifndef _EAP_TYPES_H
#define _EAP_TYPES_H

#include <freeradius-devel/ident.h>
RCSIDH(eap_types_h, "$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#define PW_EAP_REQUEST		1
#define PW_EAP_RESPONSE		2
#define PW_EAP_SUCCESS		3
#define PW_EAP_FAILURE		4
#define PW_EAP_MAX_CODES	4

/* base for dictionary values */
#define ATTRIBUTE_EAP_ID        1020
#define ATTRIBUTE_EAP_CODE      1021
#define ATTRIBUTE_EAP_BASE      1280

#define PW_EAP_IDENTITY		1
#define PW_EAP_NOTIFICATION	2
#define PW_EAP_NAK		3
#define PW_EAP_MD5		4
#define PW_EAP_OTP		5
#define PW_EAP_GTC		6
#define PW_EAP_TLS		13
#define PW_EAP_LEAP		17
#define PW_EAP_SIM              18
#define PW_EAP_TTLS		21
#define PW_EAP_PEAP		25
#define PW_EAP_MSCHAPV2		26
#define PW_EAP_CISCO_MSCHAPV2	29
#define PW_EAP_TNC		38
#define PW_EAP_IKEV2		49
#define PW_EAP_PWD              52
     /* same number as last type */
#define PW_EAP_MAX_TYPES	52

#define EAP_HEADER_LEN 		4

#define EAP_START		2
#define NAME_LEN		32

enum {
	EAP_NOTFOUND,    /* not found */
	EAP_FOUND,       /* found, continue */
	EAP_OK,		 /* ok, continue */
	EAP_FAIL,        /* failed, don't reply */
	EAP_NOOP,        /* succeeded without doing anything */
	EAP_INVALID,     /* invalid, don't reply */
	EAP_VALID        /* valid, continue */
};

/*
 * EAP-Type specific data.
 */
typedef struct eaptype_t {
	uint8_t	type;
	size_t	length;
	uint8_t	*data;
} eaptype_t;

/*
 * Structure to hold EAP data.
 *
 * length = code + id + length + type + type.data
 *        =  1   +  1 +   2    +  1   +  X
 */
typedef struct eap_packet {
	unsigned char	code;
	unsigned char	id;
	unsigned int	length;
	eaptype_t	type;

	unsigned char   *packet;
} EAP_PACKET;

/*
 * Structure to represent packet format of eap *on wire*
 */
typedef struct eap_packet_t {
	uint8_t		code;
	uint8_t		id;
	uint8_t		length[2];
	uint8_t		data[1];
} eap_packet_t;


/*
 * interfaces in eapcommon.c
 */
extern int eaptype_name2type(const char *name);
extern const char *eaptype_type2name(unsigned int type, char *buffer, size_t buflen);
extern int eap_wireformat(EAP_PACKET *reply);
extern int eap_basic_compose(RADIUS_PACKET *packet, EAP_PACKET *reply);
extern VALUE_PAIR *eap_packet2vp(RADIUS_PACKET *packet,
				 const eap_packet_t *reply);
extern eap_packet_t *eap_vp2packet(VALUE_PAIR *vps);

#endif /* _EAP_TYPES_H */
