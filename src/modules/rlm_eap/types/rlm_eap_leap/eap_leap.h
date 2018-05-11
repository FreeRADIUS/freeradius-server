#pragma once
RCSIDH(eap_leap_h, "$Id$")

#include "eap.h"

#define FR_LEAP_CHALLENGE	1
#define FR_LEAP_RESPONSE	2
#define FR_LEAP_SUCCESS		3
#define FR_LEAP_FAILURE		4
#define FR_LEAP_MAX_CODES	4

/*
 *  Version + unused + count
 */
#define LEAP_HEADER_LEN 	3

/*
 ****
 * EAP - LEAP does not specify code, id & length but chap specifies them,
 *	for generalization purpose, complete header should be sent
 *	and not just value_size, value and name.
 *	future implementation.
 */

/* eap packet structure */
typedef struct leap_packet_raw_t {
	/*
	 *  EAP header, followed by type comes before this.
	 */
	uint8_t version;
	uint8_t unused;
	uint8_t count;
	uint8_t challenge[1];	/* 8 or 24, followed by user name */
} leap_packet_raw_t;

/*
 *	Which is decoded into this.
 */
typedef struct leap_packet {
	unsigned char	code;
	unsigned char	id;
	size_t		length;
	int		count;
	unsigned char	*challenge;
	size_t		name_len;
	char		*name;
} leap_packet_t;

/*
 *	The information which must be kept around
 *	during the LEAP session.
 */
typedef struct leap_session_t {
	int		stage;
	uint8_t		peer_challenge[8];
	uint8_t		peer_response[24];
} leap_session_t;

extern fr_dict_attr_t const *attr_cleartext_password;
extern fr_dict_attr_t const *attr_nt_password;
extern fr_dict_attr_t const *attr_cisco_avpair;
extern fr_dict_attr_t const *attr_user_password;

/* function declarations here */

int 		eap_leap_compose(REQUEST *request, eap_round_t *auth, leap_packet_t *reply);
leap_packet_t 	*eap_leap_extract(REQUEST *request, eap_round_t *eap_round);
leap_packet_t 	*eap_leap_initiate(REQUEST *request, eap_round_t *eap_round, VALUE_PAIR *user_name);
int		eap_leap_stage4(REQUEST *request, leap_packet_t *packet, VALUE_PAIR* password, leap_session_t *session);
leap_packet_t	*eap_leap_stage6(REQUEST *request, leap_packet_t *packet, VALUE_PAIR *user_name, VALUE_PAIR* password,
				leap_session_t *session);

void eap_leap_mschap(unsigned char const *win_password, unsigned char const *challenge, unsigned char *response);
