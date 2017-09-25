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
 * @file proto_detail.h
 * @brief Detail master protocol handler.
 *
 * @copyright 2017  Alan DeKok <alan@freeradius.org>
 */
RCSIDH(detail_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

typedef struct proto_detail_t {
	CONF_SECTION			*server_cs;			//!< server CS for this listener

	dl_instance_t			*io_submodule;			//!< As provided by the transport_parse
									///< callback.  Broken out into the
									///< app_io_* fields below for convenience.

	fr_app_io_t const		*app_io;			//!< Easy access to the app_io handle.
	void				*app_io_instance;		//!< Easy access to the app_io instance.
	CONF_SECTION			*app_io_conf;			//!< Easy access to the app_io's config section.
//	proto_detail_app_io_t		*app_io_private;		//!< Internal interface for proto_radius.

	dl_instance_t			**type_submodule;		//!< Instance of the various types
									//!< only one instance per type allowed.

	uint32_t			code;				//!< RADIUS code to use for incoming packets
	uint32_t			max_packet_size;		//!< for message ring buffer
	uint32_t			num_messages;			//!< for message ring buffer

	fr_listen_t const		*listen;			//!< The listener structure which describes
									///< the I/O path.
} proto_detail_t;

#ifdef __cplusplus
}
#endif

#endif /* _FR_DETAIL_H */
