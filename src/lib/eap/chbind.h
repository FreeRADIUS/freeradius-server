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
 * @file lib/eap/chbind.h
 * @brief Channel binding
 *
 * @copyright 2014 Network RADIUS SARL
 * @copyright 2014 The FreeRADIUS server project
 */

RCSIDH(lib_eap_chbind_h, "$Id$")

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <ctype.h>

#include <freeradius-devel/eap/base.h>
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/radius/defs.h>

/* Structure to represent eap channel binding packet format */
typedef struct {
	uint8_t	code;
	uint8_t data[1];
} chbind_packet_t;

/* Structure to hold channel bindings req/resp information */
typedef struct {
	fr_pair_t	*username;		/* the username */
	chbind_packet_t *request;		/* channel binding request buffer */
	chbind_packet_t *response;		/* channel binding response buffer */
} CHBIND_REQ;

/* Protocol constants */
#define CHBIND_NSID_RADIUS		1

#define CHBIND_CODE_REQUEST		1
#define CHBIND_CODE_SUCCESS             2
#define CHBIND_CODE_FAILURE             3

/* Channel binding function prototypes */
FR_CODE chbind_process(request_t *request, CHBIND_REQ *chbind_req);

fr_pair_t *eap_chbind_packet2vp(fr_radius_packet_t *packet, chbind_packet_t *chbind);
chbind_packet_t *eap_chbind_vp2packet(TALLOC_CTX *ctx, fr_pair_t *vps);
