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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2001  hereUare Communications, Inc. <raghud@hereuare.com>
 * Copyright 2003  Alan DeKok <aland@freeradius.org>
 */
#ifndef _EAP_TLS_H
#define _EAP_TLS_H

#include "rlm_eap_tls.h"

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


/* configured values goes right here */
typedef struct eap_tls_conf {
	char		*private_key_password;
	char		*private_key_file;
	char		*certificate_file;
	char		*random_file;
	char		*ca_path;
	char		*ca_file;
	char		*dh_file;
	char		*rsa_file;
	int		rsa_key;
	int		dh_key;
	int		rsa_key_length;
	int		dh_key_length;
	int		verify_depth;
	int		file_type;
	int		include_length;

	/*
	 *	Always < 4096 (due to radius limit), 0 by default = 2048
	 */
	int		fragment_size;
} EAP_TLS_CONF;


/* This structure gets stored in arg */
typedef struct _eap_tls_t {
	EAP_TLS_CONF 	*conf;
	SSL_CTX		*ctx;
} eap_tls_t;


/* EAP-TLS framework */
EAPTLS_PACKET 	*eaptls_alloc(void);
void 		eaptls_free(EAPTLS_PACKET **eaptls_packet_ptr);
int 		eaptls_start(EAP_DS *eap_ds, int peap);
int 		eaptls_compose(EAP_DS *eap_ds, EAPTLS_PACKET *reply);

/* Callbacks */
int 		cbtls_password(char *buf, int num, int rwflag, void *userdata);
void 		cbtls_info(const SSL *s, int where, int ret);
int 		cbtls_verify(int ok, X509_STORE_CTX *ctx);
void 		cbtls_msg(int write_p, int msg_version, int content_type,
	       		const void *buf, size_t len, SSL *ssl, void *arg);
RSA		*cbtls_rsa(SSL *s, int is_export, int keylength);

/* TLS */
tls_session_t 	*eaptls_new_session(SSL_CTX *ssl_ctx, int client_cert);
int 		tls_handshake_recv(tls_session_t *ssn);
int 		tls_handshake_send(tls_session_t *ssn);
void 		tls_session_information(tls_session_t *tls_session);

/* Session */
void 		session_free(void *ssn);
void 		session_close(tls_session_t *ssn);
void 		session_init(tls_session_t *ssn);

/* record */
void 		record_init(record_t *buf);
void 		record_close(record_t *buf);
unsigned int 	record_plus(record_t *buf, const unsigned char *ptr, 
			    unsigned int size);
unsigned int 	record_minus(record_t *buf, unsigned char *ptr, 
			     unsigned int size);

/* TTLS processing */
int		eapttls_process(REQUEST *request, tls_session_t *tls_session);

#endif /*_EAP_TLS_H*/
