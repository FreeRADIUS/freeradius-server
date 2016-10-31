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
/* UDP Input for the SNMP On-Waves packets */

#ifndef c7_udp_input_h
#define c7_udp_input_h

#include <stdint.h>
#include <osmocom/core/write_queue.h>

#define UDP_FORMAT_SIMPLE_UDP	2
#define UDP_FORMAT_SIMPLE_TCP	3

#define UDP_DATA_MSU_PRIO_0	0
#define UDP_DATA_MSU_PRIO_1	1
#define UDP_DATA_MSU_PRIO_2	2
#define UDP_DATA_MSU_PRIO_3	3
#define UDP_DATA_RETR_PRIO_0	16
#define UDP_DATA_RETR_PRIO_1	17
#define UDP_DATA_RETR_PRIO_2	18
#define UDP_DATA_RETR_PRIO_3	19
#define UDP_DATA_RETR_COMPL	32
#define UDP_DATA_RETR_IMPOS	33
#define UDP_DATA_LINK_UP	34
#define UDP_DATA_LINK_DOWN	35


struct udp_data_hdr {
	uint8_t format_type;
	uint8_t data_type;
	uint16_t data_link_index;
	uint32_t user_context;
	uint32_t data_length;
	uint8_t data[0];
} __attribute__((packed));

#endif
