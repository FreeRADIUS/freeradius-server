#ifndef _EAP_LEAP_H
#define _EAP_LEAP_H

#include <freeradius-devel/ident.h>
RCSIDH(eap_leap_h, "$Id$")

#include "eap.h"

#define PW_LEAP_CHALLENGE	1
#define PW_LEAP_RESPONSE	2
#define PW_LEAP_SUCCESS		3
#define PW_LEAP_FAILURE		4
#define PW_LEAP_MAX_CODES	4

/*
 *  Version + unused + count
 */
#define LEAP_HEADER_LEN 	3

/*
 ****
 * EAP - LEAP doesnot specify code, id & length but chap specifies them,
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
	int		length;
	int		count;
	unsigned char	*challenge;
	int		name_len;
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

/* function declarations here */

leap_packet_t 	*eapleap_alloc(void);
void 		eapleap_free(leap_packet_t **leap_packet_ptr);

int 		eapleap_compose(EAP_DS *auth, leap_packet_t *reply);
leap_packet_t 	*eapleap_extract(EAP_DS *auth);
leap_packet_t 	*eapleap_initiate(EAP_DS *eap_ds, VALUE_PAIR *user_name);
int		eapleap_stage4(leap_packet_t *packet, VALUE_PAIR* password,
			       leap_session_t *session);
leap_packet_t	*eapleap_stage6(leap_packet_t *packet, REQUEST *request,
				VALUE_PAIR *user_name, VALUE_PAIR* password,
				leap_session_t *session,
				VALUE_PAIR **reply_vps);

void eapleap_lmpwdhash(const unsigned char *password,unsigned char *lmhash);
void eapleap_mschap(const unsigned char *win_password,
		 const unsigned char *challenge, unsigned char *response);

#endif /*_EAP_LEAP_H*/
