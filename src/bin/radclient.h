#pragma once
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

/**
 * $Id$
 *
 * @file radclient.h
 * @brief Structures for the radclient utility.
 *
 * @copyright 2014 The FreeRADIUS server project
 */
RCSIDH(radclient_h, "$Id$")

#include <freeradius-devel/util/base.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 *	Logging macros
 */
 #undef DEBUG
#define DEBUG(fmt, ...)		if (do_output && (fr_debug_lvl > 0)) fprintf(fr_log_fp, fmt "\n", ## __VA_ARGS__)
#undef DEBUG2
#define DEBUG2(fmt, ...)	if (do_output && (fr_debug_lvl > 1)) fprintf(fr_log_fp, fmt "\n", ## __VA_ARGS__)


#define ERROR(fmt, ...)		if (do_output) fr_perror("radclient: " fmt, ## __VA_ARGS__)
#define WARN(fmt, ...)		if (do_output) fprintf(stderr, fmt "\n", ## __VA_ARGS__)

#define RDEBUG_ENABLED()	(do_output && (fr_debug_lvl > 0))
#define RDEBUG_ENABLED2()	(do_output && (fr_debug_lvl > 1))

#define REDEBUG(fmt, ...)	if (do_output) fr_perror("(%" PRIu64 ") " fmt , request->num, ## __VA_ARGS__)
#define RDEBUG(fmt, ...)	if (do_output && (fr_debug_lvl > 0)) fprintf(fr_log_fp, "(%" PRIu64 ") " fmt "\n", request->num, ## __VA_ARGS__)
#define RDEBUG2(fmt, ...)	if (do_output && (fr_debug_lvl > 1)) fprintf(fr_log_fp, "(%" PRIu64 ") " fmt "\n", request->num, ## __VA_ARGS__)

typedef struct {
	uint64_t accepted;		//!< Requests to which we received a accept
	uint64_t rejected;		//!< Requests to which we received a reject
	uint64_t lost;			//!< Requests to which we received no response
	uint64_t passed;		//!< Requests which passed a filter
	uint64_t failed;		//!< Requests which failed a fitler
} rc_stats_t;

typedef struct {
	char const *packets;		//!< The file containing the request packet
	char const *filters;		//!< The file containing the definition of the
					//!< packet we want to match.
} rc_file_pair_t;

typedef struct rc_request rc_request_t;

struct rc_request {
	uint64_t	num;		//!< The number (within the file) of the request were reading.

	rc_request_t	*prev;
	rc_request_t	*next;

	rc_file_pair_t	*files;		//!< Request and response file names.

	fr_pair_t	*password;	//!< Password.Cleartext
	fr_time_delta_t	timestamp;

	fr_radius_packet_t	*packet;	//!< The outgoing request.
	fr_radius_packet_t	*reply;		//!< The incoming response.
	fr_pair_list_t	filter;		//!< If the reply passes the filter, then the request passes.
	FR_CODE		filter_code;	//!< Expected code of the response packet.

	int		resend;
	int		tries;
	bool		done;		//!< Whether the request is complete.

	char const	*name;		//!< Test name (as specified in the request).
};

#ifdef __cplusplus
}
#endif
