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
 * @file lib/eap/tls.h
 * @brief Generic EAP over TLS API
 *
 * @copyright 2001 hereUare Communications, Inc. (raghud@hereuare.com)
 * @copyright 2003 Alan DeKok (aland@freeradius.org)
 * @copyright 2006 The FreeRADIUS server project
 */

RCSIDH(lib_eap_tls_h, "$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

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

#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/tls/base.h>
#include <freeradius-devel/eap/base.h>

#define TLS_HEADER_LEN 4
#define TLS_HEADER_LENGTH_FIELD_LEN 4

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
#define TLS_RESERVED4(x) 	(((x) & 0x01) != 0)
#define TLS_RESERVED3(x) 	(((x) & 0x02) != 0)
#define TLS_RESERVED2(x) 	(((x) & 0x04) != 0)
#define TLS_RESERVED1(x) 	(((x) & 0x08) != 0)
#define TLS_RESERVED0(x) 	(((x) & 0x10) != 0)
#define TLS_START(x) 		(((x) & 0x20) != 0)
#define TLS_MORE_FRAGMENTS(x) 	(((x) & 0x40) != 0)
#define TLS_LENGTH_INCLUDED(x) 	(((x) & 0x80) != 0)

#define TLS_CHANGE_CIPHER_SPEC(x) 	(((x) & 0x0014) == 0x0014)
#define TLS_ALERT(x) 			(((x) & 0x0015) == 0x0015)
#define TLS_HANDSHAKE(x) 		(((x) & 0x0016) == 0x0016)

#define SET_START(x) 		((x) | (0x20))
#define SET_MORE_FRAGMENTS(x) 	((x) | (0x40))
#define SET_LENGTH_INCLUDED(x) 	((x) | (0x80))

typedef enum {
	EAP_TLS_INVALID = 0,	  			//!< Invalid, don't reply.
	EAP_TLS_ESTABLISHED,       			//!< Session established, send success (or start phase2).
	EAP_TLS_FAIL,       				//!< Fail, send fail.
	EAP_TLS_HANDLED,	  			//!< TLS code has handled it.

	/*
	 *	Composition states, we need to
	 *	compose a request of this type.
	 */
	EAP_TLS_START_SEND,       			//!< We're starting a new TLS session.
	EAP_TLS_RECORD_SEND,       			//!< We're sending a record.
	EAP_TLS_ACK_SEND,       			//!< Acknowledge receipt of a record or record fragment.

	/*
	 *	Receive states, we received a
	 *	response containing a fragment of a
	 *	record.
	 */
	EAP_TLS_RECORD_RECV_FIRST,    			//!< Received first fragment of a record.
	EAP_TLS_RECORD_RECV_MORE,    			//!< Received additional fragment of a record.
	EAP_TLS_RECORD_RECV_COMPLETE 			//!< Received final fragment of a record.
} eap_tls_status_t;

typedef struct {
	uint8_t		flags;
	uint8_t		data[1];
} eap_tls_data_t;

/** Tracks the state of an EAP-TLS session
 *
 * Contains any EAP-TLS specific state information, such as whether we're
 * sending/receiving fragments, and the progress of those operations.
 *
 * TLS session state is stored in a tls_session_t accessed via the tls_session field.
 */
typedef struct {
	eap_tls_status_t	state;			//!< The state of the EAP-TLS session.

	tls_session_t		*tls_session;		//!< TLS session used to authenticate peer
							//!< or tunnel sensitive data.

	bool			phase2;			//!< Whether we're in phase 2

	bool			include_length;		//!< A flag to include length in every TLS Data/Alert packet.
							//!< If set to no then only the first fragment contains length.
	int			base_flags;		//!< Some protocols use the reserved bits of the EAP-TLS
							//!< flags (such as PEAP).  This allows the base flags to
							//!< be set.

	bool			record_out_started;	//!< Whether a record transfer to the peer is currently
							//!< in progress.
	size_t			record_out_total_len;	//!< Actual/Total TLS message length we're sending.

	bool			record_in_started;	//!< Whether a record transfer from the peer is currently
							//!< in progress.
	size_t			record_in_total_len;	//!< How long the peer indicated the complete tls record
							//!< would be.
	size_t			record_in_recvd_len;	//!< How much of the record we've received so far.
} eap_tls_session_t;

extern fr_table_num_ordered_t const eap_tls_status_table[];
extern size_t eap_tls_status_table_len;

/*
 *	Externally exported TLS functions.
 */
eap_tls_status_t	eap_tls_process(REQUEST *request, eap_session_t *eap_session) CC_HINT(nonnull);

int			eap_tls_start(REQUEST *request, eap_session_t *eap_session) CC_HINT(nonnull);

int			eap_tls_success(REQUEST *request, eap_session_t *eap_session,
					char const *keying_prf_label, size_t keying_prf_label_len,
					char const *sessid_prf_label, size_t sessid_prf_label_len) CC_HINT(nonnull(1));

int			eap_tls_fail(REQUEST *request, eap_session_t *eap_session) CC_HINT(nonnull);

int			eap_tls_request(REQUEST *request, eap_session_t *eap_session) CC_HINT(nonnull);

int			eap_tls_compose(REQUEST *request, eap_session_t *eap_session,
					eap_tls_status_t status, uint8_t flags,
		    			tls_record_t *record, size_t record_len, size_t frag_len);

/* MPPE key generation */
int			eap_crypto_mppe_keys(REQUEST *request, SSL *ssl,
					     char const *prf_label, size_t prf_label_len) CC_HINT(nonnull);

int			eap_crypto_tls_session_id(TALLOC_CTX *ctx, REQUEST *request, SSL *ssl, uint8_t **out,
						  uint8_t eap_type, char const *prf_label, size_t prf_label_len);

/* EAP-TLS framework */
eap_tls_session_t	*eap_tls_session_init(REQUEST *request, eap_session_t *eap_session,
					      fr_tls_conf_t *tls_conf, bool client_cert) CC_HINT(nonnull);


fr_tls_conf_t		*eap_tls_conf_parse(CONF_SECTION *cs, char const *key) CC_HINT(nonnull);
