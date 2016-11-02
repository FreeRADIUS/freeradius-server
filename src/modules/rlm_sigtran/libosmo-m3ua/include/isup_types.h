/*
 * (C) 2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by On-Waves
 * All Rights Reserved
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef isup_types_h
#define isup_types_h

#include <stdint.h>

#ifdef __APPLE__
#include <machine/endian.h>
#define __BYTE_ORDER BYTE_ORDER
#define __LITTLE_ENDIAN LITTLE_ENDIAN
#define __BIG_ENDIAN BIG_ENDIAN
#else
#include <endian.h>
#endif

struct msgb;
struct mtp_link_set;

/* This is from Table 4/Q.763 */
#define ISUP_MSG_GRS	0x17
#define ISUP_MSG_GRA	0x29
#define ISUP_MSG_CGB	0x18
#define ISUP_MSG_CGBA	0x1A
#define ISUP_MSG_RLC	0x10
#define ISUP_MSG_RSC	0x12
#define ISUP_MSG_CGU	0x19
#define ISUP_MSG_CGUA	0x1B


struct isup_msg_hdr {
	uint16_t cic;
	uint8_t  msg_type;
	uint8_t  data[0];
} __attribute__((packed));

struct isup_msg_grs {
	uint8_t  pointer_int;
};

uint16_t isup_cic_to_local(const struct isup_msg_hdr *hdr);
int mtp_link_set_isup(struct mtp_link_set *set, struct msgb *msg, int sls);

int isup_parse_status(const uint8_t *data, uint8_t length);

#endif
