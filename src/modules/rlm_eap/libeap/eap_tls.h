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
	char		initialized;
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
	SSL_CTX		*ctx;
	SSL 		*ssl;
	tls_info_t	info;

	BIO 		*into_ssl;
	BIO 		*from_ssl;
	record_t 	clean_in;
	record_t 	clean_out;
	record_t 	dirty_in;
	record_t 	dirty_out;

	void 		(*record_init)(record_t *buf);
	void 		(*record_close)(record_t *buf);
	unsigned int 	(*record_plus)(record_t *buf, const void *ptr,
				       unsigned int size);
	unsigned int 	(*record_minus)(record_t *buf, void *ptr,
					unsigned int size);


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

	const char	*prf_label;
	int		allow_session_resumption;
} tls_session_t;


/*
 *	Externally exported TLS functions.
 */
eaptls_status_t eaptls_process(EAP_HANDLER *handler);

int 		eaptls_success(EAP_HANDLER *handler, int peap_flag);
int 		eaptls_fail(EAP_HANDLER *handler, int peap_flag);
int 		eaptls_request(EAP_DS *eap_ds, tls_session_t *ssn);


/* MPPE key generation */
void            eaptls_gen_mppe_keys(VALUE_PAIR **reply_vps, SSL *s,
				     const char *prf_label);
void		eapttls_gen_challenge(SSL *s, uint8_t *buffer, size_t size);
void		eaptls_gen_eap_key(SSL *s, uint32_t header, REQUEST *request);

#define BUFFER_SIZE 1024

#define EAP_TLS_START          	1
#define EAP_TLS_ACK          	2
#define EAP_TLS_SUCCESS         3
#define EAP_TLS_FAIL          	4
#define EAP_TLS_ALERT          	9

#define TLS_HEADER_LEN          4

/*
 *	RFC 2716, Section 4.2:
 *
 *	   Flags
 *
 *      0 1 2 3 4 5 6 7 8
 *      +-+-+-+-+-+-+-+-+
 *      |L M S R R R R R|
 *      +-+-+-+-+-+-+-+-+
 *
 *      L = Length included
 *      M = More fragments
 *      S = EAP-TLS start
 *      R = Reserved
 */
#define TLS_START(x) 		(((x) & 0x20) != 0)
#define TLS_MORE_FRAGMENTS(x) 	(((x) & 0x40) != 0)
#define TLS_LENGTH_INCLUDED(x) 	(((x) & 0x80) != 0)

#define TLS_CHANGE_CIPHER_SPEC(x) 	(((x) & 0x0014) == 0x0014)
#define TLS_ALERT(x) 			(((x) & 0x0015) == 0x0015)
#define TLS_HANDSHAKE(x) 		(((x) & 0x0016) == 0x0016)

#define SET_START(x) 		((x) | (0x20))
#define SET_MORE_FRAGMENTS(x) 	((x) | (0x40))
#define SET_LENGTH_INCLUDED(x) 	((x) | (0x80))

/*
 *	Following enums from rfc2246
 *
 *	Hmm... since we dpeend on OpenSSL, it would be smarter to
 *	use the OpenSSL names for these.
 */
enum ContentType {
	change_cipher_spec = 20,
	alert = 21,
	handshake = 22,
	application_data = 23
};

enum AlertLevel {
	warning = 1,
	fatal = 2
};

enum AlertDescription {
	close_notify = 0,
	unexpected_message = 10,
	bad_record_mac = 20,
	decryption_failed = 21,
	record_overflow = 22,
	decompression_failure = 30,
	handshake_failure = 40,
	bad_certificate = 42,
	unsupported_certificate = 43,
	certificate_revoked = 44,
	certificate_expired = 45,
	certificate_unknown = 46,
	illegal_parameter = 47,
	unknown_ca = 48,
	access_denied = 49,
	decode_error = 50,
	decrypt_error = 51,
	export_restriction = 60,
	protocol_version = 70,
	insufficient_security = 71,
	internal_error = 80,
	user_canceled = 90,
	no_renegotiation = 100
};

enum HandshakeType {
	hello_request = 0,
	client_hello = 1,
	server_hello = 2,
	certificate = 11,
	server_key_exchange  = 12,
	certificate_request = 13,
	server_hello_done = 14,
	certificate_verify = 15,
	client_key_exchange = 16,
	finished = 20
};


/*
 * From rfc
   Flags

      0 1 2 3 4 5 6 7 8
      +-+-+-+-+-+-+-+-+
      |L M S R R R R R|
      +-+-+-+-+-+-+-+-+

      L = Length included
      M = More fragments
      S = EAP-TLS start
      R = Reserved

      The L bit (length included) is set to indicate the presence of the
      four octet TLS Message Length field, and MUST be set for the first
      fragment of a fragmented TLS message or set of messages. The M bit
      (more fragments) is set on all but the last fragment. The S bit
      (EAP-TLS start) is set in an EAP-TLS Start message.  This
      differentiates the EAP-TLS Start message from a fragment
      acknowledgement.

   TLS Message Length

      The TLS Message Length field is four octets, and is present only
      if the L bit is set. This field provides the total length of the
      TLS message or set of messages that is being fragmented.

   TLS data

      The TLS data consists of the encapsulated TLS packet in TLS record
      format.
 *
 * The data structures present here
 * maps only to the typedata in the EAP packet
 *
 * Based on the L bit flag, first 4 bytes of data indicate the length
 */
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

/* Callbacks */
int 		cbtls_password(char *buf, int num, int rwflag, void *userdata);
void 		cbtls_info(const SSL *s, int where, int ret);
void 		cbtls_msg(int write_p, int msg_version, int content_type,
	       		const void *buf, size_t len, SSL *ssl, void *arg);

/* TLS */
tls_session_t 	*eaptls_new_session(SSL_CTX *ssl_ctx, int client_cert);
int 		tls_handshake_recv(REQUEST *, tls_session_t *ssn);
int 		tls_handshake_send(REQUEST *,tls_session_t *ssn);
void 		tls_session_information(tls_session_t *tls_session);

/* Session */
void 		session_free(void *ssn);
void 		session_close(tls_session_t *ssn);
void 		session_init(tls_session_t *ssn);

/* SSL Indicies for ex data */
extern int	eaptls_handle_idx;
extern int	eaptls_conf_idx;
extern int	eaptls_store_idx;	/* OCSP Store */
extern int	eaptls_session_idx;

#endif /*_EAP_TLS_H*/
