#ifndef _EAP_MD5_H
#define _EAP_MD5_H

#include "eap.h"

#define PW_MD5_CHALLENGE	1
#define PW_MD5_RESPONSE		2
#define PW_MD5_SUCCESS		3
#define PW_MD5_FAILURE		4
#define PW_MD5_MAX_CODES	4

#define MD5_HEADER_LEN 		4

/*
 ****
 * EAP - MD5 doesnot specify code, id & length but chap specifies them,
 *	for generalization purpose, complete header should be sent
 *	and not just value_size, value and name.
 *	A future implementation.
 */

/* eap packet structure */
typedef struct md5_packet_t {
/*
  uint8_t	code;
  uint8_t	id;
  uint16_t	length;
*/
  uint8_t	value_size;
  uint8_t	value_name[1];
} md5_packet_t;

typedef struct md5_packet {
	int		code;
	int		id;
	int		length;
	int		value_size;
	uint8_t		*value;
	char		*name;
/*	char		*message; */
} MD5_PACKET;

typedef struct md5_list {
	struct md5_list *next;
	MD5_PACKET 	*packet;
	char		username[MAX_STRING_LEN];
	int		processed;
	time_t		time;
} MD5_LIST;

/* function declarations here */

MD5_PACKET *md5_alloc(void);
void md5_free(MD5_PACKET **md5_packet_ptr);
MD5_PACKET *extract_md5(EAP_DS *auth);
MD5_PACKET *md5_initial_request(EAP_DS *eap_ds);
MD5_PACKET * process_md5(MD5_PACKET *packet, int id, VALUE_PAIR *username, VALUE_PAIR* password, md5_packet_t *req);
int chap_challenge(int id, char *password, int pass_len, char *challenge, int challenge_len, char *output);
int compose_md5(EAP_DS *auth, MD5_PACKET *reply);

#endif /*_EAP_MD5_H*/
