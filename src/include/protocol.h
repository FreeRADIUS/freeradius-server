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
#ifndef _FR_PROTOCOL_H
#define _FR_PROTOCOL_H
/**
 * $Id$
 *
 * @file include/protocol.h
 * @brief Protocol module API.
 *
 * @copyright 2013 Alan DeKok
 */
RCSIDH(protocol_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/dl.h>
#include <freeradius-devel/io/transport.h>

/*
 *	We'll use this below.
 */
typedef int (*rad_listen_parse_t)(CONF_SECTION *, rad_listen_t *);
typedef int (*rad_listen_unlang_t)(CONF_SECTION *, CONF_SECTION *);
typedef void (*rad_listen_free_t)(rad_listen_t *);

/** Struct exported by a proto_* module
 *
 * Used to pass information common to proto_* modules to the server core,
 * and to register callbacks that get executed when processing packets of this
 * protocol type.
 */
typedef struct rad_protocol_t {
	RAD_MODULE_COMMON;				//!< Common fields to all loadable modules.

	uint32_t		transports;		//!< What can transport this protocol.
	bool			tls;			//!< Whether protocol can be wrapped in TLS.

	rad_listen_unlang_t	bootstrap;		//!< Phase1 - Basic validation checks of virtual server.
	rad_listen_unlang_t	compile;		//!< Phase2 - Compile unlang sections in the virtual
							//!< server that map to packet types used by the protocol.

	rad_listen_parse_t	parse;			//!< Perform extra processing of the configuration data
							//!< specified by config.

	rad_listen_parse_t	open;			//!< Open a descriptor.

	rad_listen_recv_t	recv;			//!< Read an incoming packet from the descriptor.
	rad_listen_send_t	send;			//!< Write an outgoing packet to the descriptor.
	rad_listen_error_t	error;			//!< Handle error/eol on the descriptor.

	rad_listen_print_t	print;			//!< Print a line describing the packet being sent or the
							//!< packet that was received.
	rad_listen_debug_t	debug;			//!< Print an attribute list for debugging.

	rad_listen_encode_t	encode;			//!< Encode an outgoing packet.
	rad_listen_decode_t	decode;			//!< Decode an incoming packet.
} rad_protocol_t;

#define TRANSPORT_NONE 0
#define TRANSPORT_TCP (1 << IPPROTO_TCP)
#define TRANSPORT_UDP (1 << IPPROTO_UDP)
#define TRANSPORT_DUAL (TRANSPORT_UDP | TRANSPORT_TCP)

/*
 *	@todo: fix for later
 */
int common_socket_parse(CONF_SECTION *cs, rad_listen_t *this);
int common_socket_open(CONF_SECTION *cs, rad_listen_t *this);
int common_socket_print(rad_listen_t const *this, char *buffer, size_t bufsize);
void common_packet_debug(REQUEST *request, RADIUS_PACKET *packet, bool received);


typedef int (*fr_app_bootstrap_t)(CONF_SECTION *);

/*
 *	src/lib/io/transport.h
 */
typedef struct fr_transport_t fr_transport_t;

/*
 *	src/lib/io/schedule.h
 */
typedef struct fr_schedule_t fr_schedule_t;

typedef int (*fr_app_parse_t)(fr_schedule_t *sc, CONF_SECTION *, bool);

/*
 *	Functions for new virtual servers and listeners
 */
typedef struct fr_app_t {
	RAD_MODULE_COMMON;				//!< Common fields to all loadable modules.

	fr_app_bootstrap_t	bootstrap;
	fr_app_parse_t		parse;
} fr_app_t;

typedef int (*fr_app_io_open_t)(TALLOC_CTX *ctx, int *, void **, fr_transport_t **, CONF_SECTION *, bool);

/*
 *	Functions for new virtual servers and listeners
 */
typedef struct fr_app_io_t {
	RAD_MODULE_COMMON;				//!< Common fields to all loadable modules.

	fr_app_io_open_t	open;
} fr_app_io_t;

typedef int (*fr_app_subtype_compile_t)(CONF_SECTION *cs);

/*
 *	Functions for new virtual servers and listeners
 */
typedef struct fr_app_subtype_t {
	RAD_MODULE_COMMON;				//!< Common fields to all loadable modules.

	fr_app_subtype_compile_t  compile;
	fr_transport_process_t	  process;
} fr_app_subtype_t;

#ifdef __cplusplus
}
#endif

#endif /* _FR_PROTOCOL_H */
