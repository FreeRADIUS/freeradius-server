#pragma once
RCSIDH(eap_md5_h, "$Id$")

#include <freeradius-devel/eap/base.h>

#define FR_MD5_CHALLENGE	1
#define FR_MD5_RESPONSE		2
#define FR_MD5_SUCCESS		3
#define FR_MD5_FAILURE		4
#define FR_MD5_MAX_CODES	4

#define MD5_HEADER_LEN 		4
#define MD5_CHALLENGE_LEN 	16

/*
 ****
 * EAP - MD5 does not specify code, id & length but chap specifies them,
 *	for generalization purpose, complete header should be sent
 *	and not just value_size, value and name.
 *	future implementation.
 *
 *	Huh? What does that mean?
 */

/* eap packet structure */
typedef struct {
/*
	uint8_t	code;
	uint8_t	id;
	uint16_t	length;
*/
	uint8_t	value_size;
	uint8_t	value_name[1];
} md5_packet_t;

typedef struct {
	unsigned char	code;
	unsigned char	id;
	unsigned short	length;
	unsigned char	value_size;
	unsigned char	*value;
	char		*name;
} MD5_PACKET;

/* function declarations here */

int 		eap_md5_compose(eap_round_t *auth, MD5_PACKET *reply);
MD5_PACKET 	*eap_md5_extract(eap_round_t *auth);
int 		eap_md5_verify(MD5_PACKET *pkt, fr_pair_t* pwd, uint8_t *ch);
