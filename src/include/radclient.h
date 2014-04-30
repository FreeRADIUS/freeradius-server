/*
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
 */
#ifndef _RADCLIENT_H
#define _RADCLIENT_H
/*
 * $Id$
 *
 * @file radclient.h
 * @brief Structures for the radclient utility.
 *
 * @copyright 2014  The FreeRADIUS server project
 */
#include <freeradius-devel/libradius.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rc_stats {
	uint64_t accepted;		//!< Requests to which we received a accept
	uint64_t rejected;		//!< Requests to which we received a reject
	uint64_t lost;			//!< Requests to which we received no response
	uint64_t passed;		//!< Requests which passed a filter
	uint64_t failed;		//!< Requests which failed a fitler
} rc_stats_t;

typedef struct rc_file_pair {
	char const *packets;		//!< The file containing the request packet
	char const *filters;		//!< The file containing the definition of the
					//!< packet we want to match.
} rc_file_pair_t;

typedef struct rc_request rc_request_t;

struct rc_request {
	rc_request_t	*prev;
	rc_request_t	*next;

	rc_file_pair_t	*files;		//!< Request and response file names.

	int		request_number; //!< The number (within the file) of the request were reading.

	char		password[256];
	time_t		timestamp;

	RADIUS_PACKET	*packet;	//!< The outgoing request.
	PW_CODE		packet_code;	//!< The code in the outgoing request.
	RADIUS_PACKET	*reply;		//!< The incoming response.
	VALUE_PAIR	*filter;	//!< If the reply passes the filter, then the request passes.
	PW_CODE		filter_code;	//!< Expected code of the response packet.

	int		resend;
	int		tries;
	bool		done;		//!< Whether the request is complete.
};

#ifdef __cplusplus
}
#endif

#endif /* _RADCLIENT_H */
