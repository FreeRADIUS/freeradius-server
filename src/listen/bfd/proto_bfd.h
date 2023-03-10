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

/*
 * $Id$
 *
 * @file proto_bfd.h
 * @brief Structures for the RADIUS protocol
 *
 * @copyright 2023 Network RADIUS SAS (legal@networkradius.com)
 */
#include <freeradius-devel/io/master.h>
#include <freeradius-devel/bfd/bfd.h>

/** An instance of a proto_radius listen section
 *
 */
typedef struct {
	fr_io_instance_t		io;				//!< wrapper for IO abstraction

	uint32_t			max_packet_size;		//!< for message ring buffer.
	uint32_t			num_messages;			//!< for message ring buffer.

	fr_rb_tree_t     		*peers;
} proto_bfd_t;

typedef struct {
	fr_client_t			client;			//!< might as well re-use this, others need it

	uint16_t			port;			//!< peer port where packets are sent to

	/*
	 *	Peers are defined globally to a virtual server.  Each
	 *	peer can only have one session associated with it.
	 */
	void				*inst;			//!< proto_bfd_udp instance using this session
	fr_listen_t			*listen;		//!< associated listener

	int				sockfd;			//!< cached for laziness
	fr_event_list_t			*el;			//!< event list
	fr_network_t			*nr;			//!< network side of things

	struct sockaddr_storage remote_sockaddr;		//!< cached for laziness
	socklen_t	remote_salen;

	struct sockaddr_storage local_sockaddr;		//!< cached for laziness
	socklen_t	local_salen;

	/*
	 *	Internal state management
	 */
	fr_event_timer_t const	*ev_timeout;			//!< when we time out for not receiving a packet
	fr_event_timer_t const	*ev_packet;			//!< for when we next send a packet
	fr_time_t	last_recv;				//!< last received packet
	fr_time_t	next_recv;				//!< when we next expect to receive a packet
	fr_time_t	last_sent;				//!< the last time we sent a packet

	bfd_session_state_t session_state;			//!< our view of the session state
	bfd_session_state_t remote_session_state;		//!< their view of the session state

	/*
	 *	BFD state machine, and fields we use to manage it.
	 *
	 *	The public names in the configuration files are what makes sense.
	 *
	 *	The names here are the names from the protocol, so that we can be sure the state machine is
	 *	implemented correctly.
	 */
	uint32_t	local_disc;				//!< our session ID, which is unique to this session
	uint32_t	remote_disc;				//!< their session ID

	bfd_diag_t	local_diag;				//!< diagnostics for errors

	uint32_t	detect_multi;

	fr_time_delta_t	desired_min_tx_interval;		//!< intervals between transmits
	fr_time_delta_t	required_min_rx_interval;		//!< intervals between receives

	fr_time_delta_t	remote_min_rx_interval;			//!< their min_rx_interval

	fr_time_delta_t	my_min_echo_rx_interval;		//!< what we send for echo_rx_interval

	fr_time_delta_t	next_min_tx_interval;			//!< how to update this when we're polling


	bool		demand_mode;				//!< demand is "once session is up, stop sending packets"
	bool		remote_demand_mode;			//!< their demand mode

	bool		doing_poll;

	/*
	 *	Authentication configuration and states.
	 */
	bool		auth_seq_known;				//!< do we know the authentication sequence number?

	bfd_auth_type_t auth_type;				//!< what kind of authentication is used

	uint32_t       	recv_auth_seq;				//!< their auth_seq number
	uint32_t	xmit_auth_seq;				//!< our auth_seq number

	size_t		secret_len;				//!< doesn't change while we're running

	fr_time_delta_t	detection_time;				//!< used to set ev_timeout
	int		detection_timeouts;			//!< too many timeouts means !auth_seq_known

	bool		passive;				//!< active or passive role from RFC 5880 - unused
} proto_bfd_peer_t;
