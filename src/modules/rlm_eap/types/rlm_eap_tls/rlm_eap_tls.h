/*
 * rlm_eap_tls.h 
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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2001  hereUare Communications, Inc. <raghud@hereuare.com>
 * Copyright 2003  Alan DeKok <aland@freeradius.org>
 */
#ifndef _RLM_EAP_TLS_H
#define _RLM_EAP_TLS_H

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

#include "config.h"

#ifndef NO_OPENSSL
/*
 *	For RH 9, which apparently needs this.
 */
#ifndef OPENSSL_NO_KRB5
#define OPENSSL_NO_KRB5
#endif
#include <openssl/err.h>
#ifdef HAVE_OPENSSL_ENGINE_H
#include <openssl/engine.h>
#endif
#include <openssl/ssl.h>
#endif /* !defined(NO_OPENSSL) */

#include "eap.h"

typedef enum {
        EAPTLS_INVALID = 0,	  	/* invalid, don't reply */
        EAPTLS_REQUEST,       		/* request, ok to send, invalid to receive */
        EAPTLS_RESPONSE,       		/* response, ok to receive, invalid to send */
        EAPTLS_SUCCESS,       		/* success, send success */
        EAPTLS_FAIL,       		/* fail, send fail */
        EAPTLS_NOOP,       		/* noop, continue */

        EAPTLS_START,       		/* start, ok to send, invalid to receive */
        EAPTLS_OK, 	         	/* ok, continue */
        EAPTLS_ACK,       		/* acknowledge, continue */
        EAPTLS_FIRST_FRAGMENT,    	/* first fragment */
        EAPTLS_MORE_FRAGMENTS,    	/* more fragments, to send/receive */
        EAPTLS_LENGTH_INCLUDED,          	/* length included */
        EAPTLS_MORE_FRAGMENTS_WITH_LENGTH,   /* more fragments with length */
        EAPTLS_HANDLED	  		/* tls code has handled it */
} eaptls_status_t;

#define MAX_RECORD_SIZE 16384

/*
 *	A single TLS record may be up to 16384 octets in length, but a
 *	TLS message may span multiple TLS records, and a TLS
 *	certificate message may in principle be as long as 16MB.
 *
 *	However, note that in order to protect against reassembly
 *	lockup and denial of service attacks, it may be desirable for
 *	an implementation to set a maximum size for one such group of
 *	TLS messages.
 *
 *	The TLS Message Length field is four octets, and provides the
 *	total length of the TLS message or set of messages that is
 *	being fragmented; this simplifies buffer allocation.
 */

/*
 * FIXME: Dynamic allocation of buffer to overcome MAX_RECORD_SIZE overflows.
 * 	or configure TLS not to exceed MAX_RECORD_SIZE.
 */
typedef struct _record_t {
	unsigned char data[MAX_RECORD_SIZE];
	unsigned int  used; 
} record_t;

typedef struct _tls_info_t {
	unsigned char	origin;
	unsigned char	content_type;
	unsigned char	handshake_type;
	unsigned char	alert_level;
	unsigned char	alert_description;
	char 		info_description[256];
	size_t		record_len;
	int		version;
} tls_info_t;

/*
 * tls_session_t Structure gets stored as opaque in EAP_HANDLER
 * This contains EAP-REQUEST specific data 
 * (ie EAPTLS_DATA(fragment), EAPTLS-ALERT, EAPTLS-REQUEST ...)
 *
 * clean_in  - data that needs to be sent but only after it is soiled.
 * dirty_in  - data EAP server receives.
 * clean_out - data that is cleaned after receiving.
 * dirty_out - data EAP server sends. 
 * offset    - current fragment size transmitted
 * fragment  - Flag, In fragment mode or not.
 * tls_msg_len - Actual/Total TLS message length.
 * length_flag - A flag to include length in every TLS Data/Alert packet
 * 					if set to no then only the first fragment contains length
 */
typedef struct _tls_session_t {
	SSL 		*ssl;
	tls_info_t	info;

	BIO 		*into_ssl;
	BIO 		*from_ssl;
	record_t 	clean_in;
	record_t 	clean_out;
	record_t 	dirty_in;
	record_t 	dirty_out;

	/*
	 * Framed-MTU attribute in RADIUS, 
	 * if present, can also be used to set this
	 */
	unsigned int 	offset;
	unsigned int 	tls_msg_len;
	int 		fragment;
	int		length_flag;
	int		peap_flag;

	/*
	 *	Used by TTLS & PEAP to keep track of other per-session
	 *	data.
	 */
	void 		*opaque;
	void 		(*free_opaque)(void *opaque);
} tls_session_t;


/*
 *	Externally exported TLS functions.
 */
eaptls_status_t eaptls_process(EAP_HANDLER *handler);

int 		eaptls_success(EAP_DS *eap_ds, int peap_flag);
int 		eaptls_fail(EAP_DS *eap_ds, int peap_flag);
int 		eaptls_request(EAP_DS *eap_ds, tls_session_t *ssn);


/* MPPE key generation */
void            eaptls_gen_mppe_keys(VALUE_PAIR **reply_vps, SSL *s,
				     const char *prf_label);
void		eapttls_gen_challenge(SSL *s, char *buffer, int size);

#endif /* _RLM_EAP_TLS_H */
