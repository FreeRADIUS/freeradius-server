#pragma once
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

/**
 * $Id$
 * @file lib/bio/fd_priv.h
 * @brief Private binary IO abstractions for file descriptors
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(lib_bio_fd_privh, "$Id$")

#include <freeradius-devel/util/syserror.h>

#include <freeradius-devel/bio/bio_priv.h>
#include <freeradius-devel/bio/fd.h>

/** Our FD bio structure.
 *
 */
typedef struct fr_bio_fd_s {
	FR_BIO_COMMON;
	fr_bio_callback_t  user_shutdown;	//!< user shutdown

	fr_bio_fd_info_t  info;

	struct {
		fr_bio_callback_t  success;    	//!< for fr_bio_fd_connect()
		fr_bio_callback_t  error;	//!< for fr_bio_fd_connect()
		fr_bio_callback_t  timeout;	//!< for fr_bio_fd_connect()
		fr_event_list_t	   *el;		//!< for fr_bio_fd_connect()
		fr_event_timer_t const *ev;	//!< for fr_bio_fd_connect()
	} connect;

	int		max_tries;		//!< how many times we retry on EINTR
	size_t		offset;			//!< where #fr_bio_fd_packet_ctx_t is stored

#if defined(IP_PKTINFO) || defined(IP_RECVDSTADDR) || defined(IPV6_PKTINFO)
	struct iovec	iov;			//!< for recvfromto
	struct msghdr	msgh;			//!< for recvfromto
	uint8_t		cbuf[sizeof(struct cmsghdr) * 2]; //!< for recvfromto
#endif
} fr_bio_fd_t;

#define fr_bio_fd_packet_ctx(_my, _packet_ctx) ((fr_bio_fd_packet_ctx_t *) (((uint8_t *) _packet_ctx) + _my->offset))

int	fr_filename_to_sockaddr(struct sockaddr_un *sun, socklen_t *sunlen, char const *filename) CC_HINT(nonnull);

int	fr_bio_fd_init_common(fr_bio_fd_t *my);

int	fr_bio_fd_init_connected(fr_bio_fd_t *my);

int	fr_bio_fd_init_listen(fr_bio_fd_t *my);

int	fr_bio_fd_socket_name(fr_bio_fd_t *my);
