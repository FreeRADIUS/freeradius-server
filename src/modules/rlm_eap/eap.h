/*
 * eap.h    Header file containing the interfaces for all EAP types.
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
 */
#ifndef _EAP_H
#define _EAP_H

#include "autoconf.h"

#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <string.h>
#include <stdlib.h>

#include "radiusd.h"
#include "modules.h"

#include "rad_assert.h"

#define PW_EAP_REQUEST		1
#define PW_EAP_RESPONSE		2
#define PW_EAP_SUCCESS		3
#define PW_EAP_FAILURE		4
#define PW_EAP_MAX_CODES	4

#define PW_EAP_IDENTITY		1
#define PW_EAP_NOTIFICATION	2
#define PW_EAP_NAK		3
#define PW_EAP_MD5		4
#define PW_EAP_OTP		5
#define PW_EAP_GTC		6
#define PW_EAP_TLS		13
#define PW_EAP_LEAP		17
#define PW_EAP_TTLS		21
#define PW_EAP_PEAP		25
#define PW_EAP_MAX_TYPES	25

#define EAP_HEADER_LEN 		4

/*
 * EAP-Type specific data.
 */
typedef struct eaptype_t {
	unsigned char	type;
	unsigned int	length;
	unsigned char	*data;
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
 * EAP_DS contains all the received/sending information
 * response = Received EAP packet
 * request = Sending EAP packet
 *
 * Note: We are authentication server, 
 *  we get ONLY EAP-Responses and 
 *  we send EAP-Request/EAP-success/EAP-failure
 */
typedef struct eap_ds {
	EAP_PACKET	*response;
	EAP_PACKET	*request;
	int		set_request_id;
} EAP_DS;

/*
 * Currently there are only 2 types
 * of operations defined, 
 * apart from attach & detach for each EAP-Type.
 */
typedef enum operation_t {
	INITIATE = 0,
	AUTHORIZE,
	AUTHENTICATE
} operation_t;


/*
 * EAP_HANDLER is the interface for any EAP-Type.
 * Each handler contains information for one specific EAP-Type.
 * This way we don't need to change any interfaces in future.
 * It is also a list of EAP-request handlers waiting for EAP-response
 * eap_id = copy of the eap packet we sent to the 
 *
 * next = pointer to next
 * state = state attribute from the reply we sent
 * state_len = length of data in the state attribute.
 * src_ipaddr = client which sent us the RADIUS request containing
 *              this EAP conversation.
 * eap_id = copy of EAP id we sent to the client.
 * timestamp  = timestamp when this handler was last used.
 * identity = Identity, as obtained, from EAP-Identity response.
 * username = as obtained in Radius request, It might differ from identity.
 * request = RADIUS request data structure
 * prev_eapds = Previous EAP request, for which eap_ds contains the response.
 * eap_ds   = Current EAP response.
 * opaque   = EAP-Type holds some data that corresponds to the current
 *		EAP-request/response
 * free_opaque = To release memory held by opaque, 
 * 		when this handler is timedout & needs to be deleted.
 * 		It is the responsibility of the specific EAP-TYPE 
 * 		to avoid any memory leaks in opaque
 *		Hence this pointer should be provided by the EAP-Type
 *		if opaque is not NULL
 * status   = finished/onhold/..
 */
#define EAP_STATE_LEN (AUTH_VECTOR_LEN)
typedef struct _eap_handler {
	struct _eap_handler *next;

	uint8_t		state[EAP_STATE_LEN];
	uint32_t	src_ipaddr;
	int		eap_id;

	time_t		timestamp;

	VALUE_PAIR	*username; /* SHOULD get rid of this! */
	REQUEST		*request;

	char		*identity; /* user identity? Huh? */

	EAP_DS 		*prev_eapds;
	EAP_DS 		*eap_ds;

	void 		*opaque;
	void 		(*free_opaque)(void *opaque);

	int		status;

	int		stage;
} EAP_HANDLER;

/* 
 * Interface to call EAP sub mdoules
 */
typedef struct eap_type_t {
	const 	char *name;
	int	(*attach)(CONF_SECTION *conf, void **type_data);
	int	(*initiate)(void *type_data, EAP_HANDLER *handler);
	int	(*authorize)(void *type_data, EAP_HANDLER *handler);
	int	(*authenticate)(void *type_data, EAP_HANDLER *handler);
	int	(*detach)(void *type_data);
} EAP_TYPE;

#endif /*_EAP_H*/
