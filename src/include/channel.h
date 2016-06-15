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
#ifndef _FR_CHANNEL_H
#define _FR_CHANNEL_H
/**
 * $Id$
 *
 * @file include/channel.h
 * @brief API to provide distinct communication channels for the radmin protocol.
 *
 * @copyright 2015 Alan DeKok <aland@deployingradius.com>
 */
RCSIDH(channel_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

typedef enum fr_channel_type_t {
	FR_CHANNEL_STDIN = 0,
	FR_CHANNEL_STDOUT,
	FR_CHANNEL_STDERR,
	FR_CHANNEL_CMD_STATUS,
	FR_CHANNEL_INIT_ACK,
	FR_CHANNEL_AUTH_CHALLENGE,
	FR_CHANNEL_AUTH_RESPONSE,
	FR_CHANNEL_WANT_MORE,
	FR_CHANNEL_NOTIFY
} fr_channel_type_t;

typedef enum fr_channel_result_t {
	FR_CHANNEL_FAIL = 0,
	FR_CHANNEL_SUCCESS
} fr_channel_result_t;

typedef enum fr_channel_notify_t {
	FR_NOTIFY_NONE = 0,
	FR_NOTIFY_BUFFERED,
	FR_NOTIFY_UNBUFFERED
} fr_channel_notify_t;


ssize_t fr_channel_drain(int fd, fr_channel_type_t *pchannel, void *inbuf, size_t buflen, uint8_t **outbuf, ssize_t *have_read);
ssize_t fr_channel_read(int fd, fr_channel_type_t *pchannel, void *buffer, size_t buflen);
ssize_t fr_channel_write(int fd, fr_channel_type_t channel, void const *buffer, size_t buflen);

#ifdef __cplusplus
}
#endif
#endif /* _FR_CHANNEL_H */
