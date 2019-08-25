/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */
#ifndef _FR_DETAIL_H
#define _FR_DETAIL_H
/**
 * $Id$
 *
 * @file proto_detail_file.h
 * @brief API to deserialise packets in detail file format and inject them into the server.
 *
 * @copyright 2015  The FreeRADIUS server project
 */
RCSIDH(detail_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

typedef enum detail_file_state_t {
	STATE_UNOPENED = 0,
	STATE_UNLOCKED,
	STATE_PROCESSING,
} detail_file_state_t;

typedef enum detail_entry_state_t {
	STATE_HEADER = 0,
	STATE_VPS,
	STATE_QUEUED,
	STATE_RUNNING,
	STATE_NO_REPLY,
	STATE_REPLIED
} detail_entry_state_t;

typedef struct listen_detail_t {
	fr_event_timer_t const	*ev;	/* has to be first entry (ugh) */
	char const 	*name;			//!< Identifier used in log messages
	int		delay_time;
	char const	*filename;
	char const	*filename_work;
	VALUE_PAIR	*vps;
	int		work_fd;

	int		master_pipe[2];
	int		child_pipe[2];
	pthread_t	pthread_id;

	FILE		*fp;
	off_t		offset;
	detail_file_state_t 	file_state;
	detail_entry_state_t 	entry_state;
	time_t		timestamp;
	time_t		running;
	fr_ipaddr_t	client_ip;

	off_t		last_offset;
	off_t		timestamp_offset;
	bool		done_entry;		//!< Are we done reading this entry?
	bool		track;			//!< Do we track progress through the file?

	uint32_t	load_factor; /* 1..100 */
	uint32_t	poll_interval;
	uint32_t	retry_interval;

	int		signal;
	int		packets;
	int		tries;
	bool		one_shot;
	int		outstanding;
	int		has_rtt;
	int		srtt;
	int		rttvar;
	uint32_t	counter;
	struct timeval  last_packet;
	RADCLIENT	detail_client;
} listen_detail_t;

#ifdef __cplusplus
}
#endif

#endif /* _FR_DETAIL_H */
