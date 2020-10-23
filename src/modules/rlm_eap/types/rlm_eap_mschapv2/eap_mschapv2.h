#pragma once
RCSIDH(eap_mschapv2_h, "$Id$")

#include <freeradius-devel/eap/base.h>

/*
 *	draft-kamath-pppext-eap-mschapv2-00.txt says:
 *
 *	Supplicant		FreeRADIUS
 *			<--	challenge
 *	response	-->
 *			<--	success
 *	success		-->
 *
 *	But what we often see is:
 *
 *	Supplicant		FreeRADIUS
 *			<--	challenge
 *	response	-->
 *			<--	success
 *	ack		-->
 */
#define FR_EAP_MSCHAPV2_ACK		0
#define FR_EAP_MSCHAPV2_CHALLENGE	1
#define FR_EAP_MSCHAPV2_RESPONSE	2
#define FR_EAP_MSCHAPV2_SUCCESS		3
#define FR_EAP_MSCHAPV2_FAILURE		4
#define FR_EAP_MSCHAPV2_CHGPASSWD	7
#define FR_EAP_MSCHAPV2_MAX_CODES	7

#define MSCHAPV2_HEADER_LEN 	5
#define MSCHAPV2_CHALLENGE_LEN  16
#define MSCHAPV2_RESPONSE_LEN  50

typedef struct {
	uint8_t opcode;
	uint8_t mschapv2_id;
	uint8_t ms_length[2];
	uint8_t value_size;
} mschapv2_header_t;

typedef struct {
	int		code;
	bool		has_peer_challenge;
	uint8_t		auth_challenge[MSCHAPV2_CHALLENGE_LEN];
	uint8_t		peer_challenge[MSCHAPV2_CHALLENGE_LEN];
	fr_pair_t	*mppe_keys;
	fr_pair_t	*reply;
} mschapv2_opaque_t;
