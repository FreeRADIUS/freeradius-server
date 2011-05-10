/*
 * eap_tls.h
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
#ifndef _EAP_TLS_H
#define _EAP_TLS_H

#include <freeradius-devel/ident.h>
RCSIDH(eap_tls_h, "$Id$")

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>

#include <ctype.h>
#include <sys/time.h>
#include <arpa/inet.h>

#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <freeradius-devel/tls.h>

#include "eap.h"

/*
 *	Externally exported TLS functions.
 */
fr_tls_status_t eaptls_process(EAP_HANDLER *handler);

int 		eaptls_success(EAP_HANDLER *handler, int peap_flag);
int 		eaptls_fail(EAP_HANDLER *handler, int peap_flag);
int 		eaptls_request(EAP_DS *eap_ds, tls_session_t *ssn);


/* MPPE key generation */
void            eaptls_gen_mppe_keys(VALUE_PAIR **reply_vps, SSL *s,
				     const char *prf_label);
void		eapttls_gen_challenge(SSL *s, uint8_t *buffer, size_t size);

#define BUFFER_SIZE 1024

#define EAP_TLS_START          	1
#define EAP_TLS_ACK          	2
#define EAP_TLS_SUCCESS         3
#define EAP_TLS_FAIL          	4
#define EAP_TLS_ALERT          	9

#define TLS_HEADER_LEN          4

typedef struct tls_packet_t {
	uint8_t		flags;
	uint8_t		data[1];
} eaptls_packet_t;

typedef struct tls_packet {
	uint8_t		code;
	uint8_t		id;
	uint32_t	length;
	uint8_t		flags;
	uint8_t		*data;
	uint32_t	dlen;

	//uint8_t		*packet;  /* Wired EAP-TLS packet as found in typdedata of EAP_PACKET */
} EAPTLS_PACKET;


/* EAP-TLS framework */
EAPTLS_PACKET 	*eaptls_alloc(void);
void 		eaptls_free(EAPTLS_PACKET **eaptls_packet_ptr);
int 		eaptls_start(EAP_DS *eap_ds, int peap);
int 		eaptls_compose(EAP_DS *eap_ds, EAPTLS_PACKET *reply);

#endif /*_EAP_TLS_H*/
