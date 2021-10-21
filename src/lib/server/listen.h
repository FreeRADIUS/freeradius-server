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
 * @file lib/server/listen.h
 * @brief Listener API.  Binds sockets to protocol encoders/decoders.
 *
 * @copyright 2015 The FreeRADIUS server project
 */
RCSIDH(listen_h, "$Id$")

#include <freeradius-devel/server/client.h>
#include <freeradius-devel/server/socket.h>
#include <freeradius-devel/server/stats.h>
#include <freeradius-devel/util/event.h>
#include <freeradius-devel/util/packet.h>
#include <freeradius-devel/util/pcap.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 *	Types of listeners.
 *
 *	Ordered by priority!
 */
typedef enum RAD_LISTEN_TYPE {
	RAD_LISTEN_NONE = 0,
	RAD_LISTEN_PROXY,
	RAD_LISTEN_AUTH,
	RAD_LISTEN_ACCT,
	RAD_LISTEN_DETAIL,
	RAD_LISTEN_VQP,
	RAD_LISTEN_DHCP,
	RAD_LISTEN_COMMAND,
	RAD_LISTEN_COA,
	RAD_LISTEN_MAX
} RAD_LISTEN_TYPE;

typedef enum RAD_LISTEN_STATUS {
	RAD_LISTEN_STATUS_INIT = 0,
	RAD_LISTEN_STATUS_KNOWN,
	RAD_LISTEN_STATUS_FROZEN,
	RAD_LISTEN_STATUS_EOL,
	RAD_LISTEN_STATUS_REMOVE_NOW
} RAD_LISTEN_STATUS;

typedef struct rad_protocol_s rad_protocol_t;
typedef struct rad_listen rad_listen_t;

typedef int (*rad_listen_recv_t)(rad_listen_t *);
typedef int (*rad_listen_send_t)(rad_listen_t *, request_t *);
typedef int (*rad_listen_error_t)(rad_listen_t *, int);
typedef int (*rad_listen_print_t)(rad_listen_t const *, char *, size_t);
typedef void (*rad_listen_debug_t)(request_t *, fr_radius_packet_t *, fr_pair_list_t *, bool received);
typedef int (*rad_listen_encode_t)(rad_listen_t *, request_t *);
typedef int (*rad_listen_decode_t)(rad_listen_t *, request_t *);

struct rad_listen {
	rad_listen_t		*next; /* should be rbtree stuff */
	rad_protocol_t const	*proto;

	/*
	 *	For normal sockets.
	 */
	RAD_LISTEN_TYPE		type;
	int			fd;
	char const		*server;	//!< Name of the virtual server that the listener is associated with
	CONF_SECTION		*server_cs;	//!< Virtual server that the listener is associated with
	RAD_LISTEN_STATUS	status;
	bool			old_style;

	int			count;
	bool			dual;
	fr_rb_tree_t		*children;
	rad_listen_t		*parent;
	bool			nodup;

	rad_listen_recv_t	recv;
	rad_listen_send_t	send;
	rad_listen_error_t	error;
	rad_listen_encode_t	encode;
	rad_listen_decode_t	decode;
	rad_listen_debug_t	debug;
	rad_listen_print_t	print;

	CONF_SECTION const	*cs;
	void			*data;
};
#ifdef __cplusplus
}
#endif
