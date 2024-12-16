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
 * @file lib/bio/fd.h
 * @brief Binary IO abstractions for file descriptors
 *
 * Allow reads and writes from file descriptors.
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(lib_bio_fd_h, "$Id$")

#include <freeradius-devel/bio/base.h>
#include <freeradius-devel/util/socket.h>
#include <freeradius-devel/util/event.h>

#include <freeradius-devel/server/cf_parse.h>

#include <fcntl.h>

/*
 *	Local hack.  AF_FILE is a synonym for AF_LOCAL on some platforms.
 */
#define AF_FILE_BIO (INT_MAX)

/** Per-packet context
 *
 *	For reading packets src_ip is *their* IP, and dst_ip is *our* IP.
 *
 *	For writing packets, src_ip is *our* IP, and dst_ip is *their* IP.
 *
 *	This context is returned only for datagram sockets.  For stream sockets (TCP and Unix domain), it
 *	isn't used.  The caller can look at the socket information to determine src/dst ip/port.
 */
typedef struct {
	fr_socket_t	socket;		//!< socket information, including FD.
	fr_time_t	when;		//!< when the packet was received
} fr_bio_fd_packet_ctx_t;

typedef enum {
	FR_BIO_FD_STATE_INVALID = 0,
	FR_BIO_FD_STATE_CLOSED,
	FR_BIO_FD_STATE_OPEN,		//!< error states must be before this
	FR_BIO_FD_STATE_CONNECTING,
} fr_bio_fd_state_t;

typedef enum {
	FR_BIO_FD_INVALID,		//!< not set
	FR_BIO_FD_UNCONNECTED,		//!< unconnected UDP / datagram only
					// updates #fr_bio_fd_packet_ctx_t for reads,
					// uses #fr_bio_fd_packet_ctx_t for writes
	FR_BIO_FD_CONNECTED,		//!< connected client sockets (UDP or TCP)
	FR_BIO_FD_LISTEN,		//!< returns new fd in buffer on fr_bio_read() or fr_bio_fd_accept()
					// updates #fr_bio_fd_packet_ctx_t on successful FD read.
	FR_BIO_FD_ACCEPTED,		//!< temporarily until it's connected.
} fr_bio_fd_type_t;

/** Configuration for sockets
 *
 *  Each piece of information is broken out into a separate field, so that the configuration file parser can
 *  parse each field independently.
 *
 *  We also include more information here than we need in an #fr_socket_t.
 */
typedef struct {
	fr_bio_fd_type_t type;		//!< accept, connected, unconnected, etc.

	int		socket_type;   	//!< SOCK_STREAM or SOCK_DGRAM
	char const	*transport;	//!< name of the transport protocol
	bool		server;		//!< is this a client or a server?

	fr_ipaddr_t	src_ipaddr;	//!< our IP address
	fr_ipaddr_t	dst_ipaddr;	//!< their IP address

	uint16_t	src_port;	//!< our port
	uint16_t	dst_port;	//!< their port

	char const	*interface;	//!< for binding to an interface

	uint32_t	recv_buff;	//!< How big the kernel's receive buffer should be.
	uint32_t	send_buff;	//!< How big the kernel's send buffer should be.

	char const	*path;		//!< for Unix domain sockets
	mode_t		perm;		//!< permissions for domain sockets
	uid_t		uid;		//!< who owns the socket
	gid_t		gid;		//!< who owns the socket
	bool		mkdir;		//!< make intermediate directories

	char const	*filename;	//!< for files
	int		flags;		//!< O_RDONLY, etc.

	bool		async;		//!< is it async
	bool		tcp_delay;	//!< We do tcp_nodelay by default.

	/*
	 *	Extra fields for conf_parser_t
	 */
	bool		recv_buff_is_set;	//!< Whether we were provided with a recv_buf
	bool		send_buff_is_set;	//!< Whether we were provided with a send_buf
} fr_bio_fd_config_t;

extern const conf_parser_t fr_bio_fd_client_config[];
extern const conf_parser_t fr_bio_fd_server_config[];

/** Run-time status of the socket.
 *
 */
typedef struct {
	fr_socket_t	socket;		//!< as connected socket

	fr_bio_fd_type_t type;		//!< type of the socket
	fr_bio_fd_state_t state;	//!< connecting, open, closed, etc.

	char const	*name;		//!< printable name of this BIO

	bool		read_blocked;	//!< did we block on read?
	bool		write_blocked;	//!< did we block on write?
	bool		eof;		//!< are we at EOF?

	int		connect_errno;	//!< from connect() or other APIs

	fr_bio_fd_config_t const *cfg;	//!< so we know what was asked, vs what was granted.
} fr_bio_fd_info_t;

fr_bio_t	*fr_bio_fd_alloc(TALLOC_CTX *ctx, fr_bio_fd_config_t const *cfg, size_t offset) CC_HINT(nonnull(1));

int		fr_bio_fd_close(fr_bio_t *bio) CC_HINT(nonnull);

int		fr_bio_fd_connect_full(fr_bio_t *bio, fr_event_list_t *el,
				       fr_bio_callback_t connected_cb, fr_bio_callback_t error_cb,
				       fr_time_delta_t *timeout, fr_bio_callback_t timeout_cb) CC_HINT(nonnull(1));

#define fr_bio_fd_connect(_x) fr_bio_fd_connect_full(_x, NULL, NULL, NULL, NULL, NULL)

fr_bio_fd_info_t const *fr_bio_fd_info(fr_bio_t *bio) CC_HINT(nonnull);

int		fr_bio_fd_check_config(fr_bio_fd_config_t const *cfg) CC_HINT(nonnull);

int		fr_bio_fd_open(fr_bio_t *bio, fr_bio_fd_config_t const *cfg) CC_HINT(nonnull);

int		fr_bio_fd_write_only(fr_bio_t *bio) CC_HINT(nonnull);

int		fr_bio_fd_reopen(fr_bio_t *bio) CC_HINT(nonnull);

int		fr_bio_fd_accept(TALLOC_CTX *ctx, fr_bio_t **out, fr_bio_t *bio)  CC_HINT(nonnull);
