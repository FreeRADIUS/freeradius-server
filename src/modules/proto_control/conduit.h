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
 * @file conduit.h
 * @brief API to provide distinct communication conduits for the radmin protocol.
 *
 * @copyright 2015 Alan DeKok (aland@deployingradius.com)
 */
RCSIDH(conduit_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#define FR_CONDUIT_MAGIC (0xf7eead17)

typedef enum fr_conduit_type_t {
	FR_CONDUIT_STDIN = 0,
	FR_CONDUIT_STDOUT,
	FR_CONDUIT_STDERR,
	FR_CONDUIT_CMD_STATUS,
	FR_CONDUIT_INIT_ACK,
	FR_CONDUIT_AUTH_CHALLENGE,
	FR_CONDUIT_AUTH_RESPONSE,
	FR_CONDUIT_NOTIFY,
	FR_CONDUIT_HELP,
	FR_CONDUIT_COMPLETE,
} fr_conduit_type_t;

typedef enum fr_conduit_origin_t {
	FR_ORIGIN_SIGNAL = 0,
	FR_ORIGIN_DEBUG,
	FR_ORIGIN_WORKER,
} fr_conduit_origin_t;

typedef enum fr_conduit_result_t {
	FR_CONDUIT_FAIL = 0,
	FR_CONDUIT_PARTIAL,
	FR_CONDUIT_SUCCESS
} fr_conduit_result_t;

typedef enum fr_conduit_notify_t {
	FR_NOTIFY_NONE = 0,
	FR_NOTIFY_BUFFERED,
	FR_NOTIFY_UNBUFFERED
} fr_conduit_notify_t;

#define COMMAND_BUFFER_SIZE (1024)

typedef struct {
	int		auth;
	int		mode;
	ssize_t		offset;
	ssize_t		next;
	char		buffer[COMMAND_BUFFER_SIZE];
} fr_cs_buffer_t;

typedef struct {
	uint16_t	origin;
	uint16_t	conduit;
	uint32_t	length;
} fr_conduit_hdr_t;


ssize_t fr_conduit_read_async(int fd, fr_conduit_type_t *pconduit, void *inbuf, size_t buflen,
			      size_t *leftover, bool *want_more);
ssize_t fr_conduit_read(int fd, fr_conduit_type_t *pconduit, void *buffer, size_t buflen);
ssize_t fr_conduit_write(int fd, fr_conduit_type_t conduit, void const *buffer, size_t buflen);

#ifdef __cplusplus
}
#endif
