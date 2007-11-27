/*
 *   This software is Copyright (C) 2006,2007 FH Hannover
 *
 *   Portions of this code unrelated to FreeRADIUS are available
 *   separately under a commercial license.  If you require an
 *   implementation of EAP-TNC that is not under the GPLv2, please
 *   contact tnc@inform.fh-hannover.de for details.
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
 */

#ifndef _EAP_TNC_H
#define _EAP_TNC_H

#include "eap.h"

#define PW_TNC_REQUEST	1
#define PW_TNC_RESPONSE		2
#define PW_TNC_SUCCESS		3
#define PW_TNC_FAILURE		4
#define PW_TNC_MAX_CODES	4

#define TNC_HEADER_LEN 		4
#define TNC_CHALLENGE_LEN 	16
#define TNC_START_LEN 	8

#define TNC_PACKET_LENGTH_WITHOUT_DATA_LENGTH 6
#define TNC_PACKET_LENGTH 10
#define TNC_DATA_LENGTH_LENGTH 4
#define TNC_FLAGS_VERSION_LENGTH 1

typedef unsigned int VlanAccessMode;

#define VLAN_ISOLATE 97
#define VLAN_ACCESS 2
/*
 ****
 * EAP - MD5 doesnot specify code, id & length but chap specifies them,
 *	for generalization purpose, complete header should be sent
 *	and not just value_size, value and name.
 *	future implementation.
 *
 *	Huh? What does that mean?
 */

/*
 *
 *  MD5 Packet Format in EAP Type-Data
 *  --- ------ ------ -- --- ---------
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Value-Size   |  Value ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Name ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * EAP-TNC Packet Format in EAP Type-Data
 * 
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Flags  |Ver  | Data Length ...                                   
 * |L M S R R|=1   |                                               
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |...            |  Data ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 
 *
 */

/* eap packet structure */
typedef struct tnc_packet_t {
/*
	uint8_t	code;
	uint8_t	id;
	uint16_t	length;
*/
	uint8_t	flags_ver;
	uint32_t data_length;
	uint8_t *data;
} tnc_packet_t;

typedef struct tnc_packet {
	uint8_t		code;
	uint8_t		id;
	uint16_t	length;
	uint8_t	flags_ver;
	uint32_t data_length;
	uint8_t *data;
} TNC_PACKET;

#define TNC_START(x) 		(((x) & 0x20) != 0)
#define TNC_MORE_FRAGMENTS(x) 	(((x) & 0x40) != 0)
#define TNC_LENGTH_INCLUDED(x) 	(((x) & 0x80) != 0)
#define TNC_RESERVED_EQ_NULL(x) (((x) & 0x10) == 0 && ((x) & 0x8) == 0)
#define TNC_VERSION_EQ_ONE(x) (((x) & 0x07) == 1)

#define SET_START(x) 		((x) | (0x20))
#define SET_MORE_FRAGMENTS(x) 	((x) | (0x40))
#define SET_LENGTH_INCLUDED(x) 	((x) | (0x80))


/* function declarations here */

TNC_PACKET 	*eaptnc_alloc(void);
void 		eaptnc_free(TNC_PACKET **tnc_packet_ptr);

int 		eaptnc_compose(EAP_DS *auth, TNC_PACKET *reply);
TNC_PACKET 	*eaptnc_extract(EAP_DS *auth);
int 		eaptnc_verify(TNC_PACKET *pkt, VALUE_PAIR* pwd, uint8_t *ch);





#endif /*_EAP_TNC_H*/
