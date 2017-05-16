/*
 * eap_chbind.c
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
 * Copyright 2014  Network RADIUS SARL
 * Copyright 2014  The FreeRADIUS server project
 */

#ifndef _EAP_CHBIND_H
#define _EAP_CHBIND_H

RCSIDH(eap_chbind_h, "$Id$")

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <ctype.h>

#include <freeradius-devel/radiusd.h>

#include "eap.h"

/* Structure to represent eap channel binding packet format */
typedef struct chbind_packet_t {
	uint8_t	code;
	uint8_t data[1];
} chbind_packet_t;

/* Structure to hold channel bindings req/resp information */
typedef struct CHBIND_REQ {
	VALUE_PAIR	*username;		/* the username */
	chbind_packet_t *request;		/* channel binding request buffer */
	chbind_packet_t *response;		/* channel binding response buffer */
} CHBIND_REQ;

/* Protocol constants */
#define CHBIND_NSID_RADIUS		1

#define CHBIND_CODE_REQUEST		1
#define CHBIND_CODE_SUCCESS             2
#define CHBIND_CODE_FAILURE             3

/* Channel binding function prototypes */
PW_CODE chbind_process(REQUEST *request, CHBIND_REQ *chbind_req);

VALUE_PAIR *eap_chbind_packet2vp(RADIUS_PACKET *packet, chbind_packet_t *chbind);
chbind_packet_t *eap_chbind_vp2packet(TALLOC_CTX *ctx, VALUE_PAIR *vps);

#endif /*_EAP_CHBIND_H*/
