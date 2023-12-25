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
 * @file src/listen/bfd/session.h
 * @brief BFD Session handling
 *
 * @copyright 2023 Network RADIUS SAS (legal@networkradius.com)
 */
#include "proto_bfd.h"

typedef struct {
	fr_client_t			client;			//!< might as well reuse this, others need it

	uint16_t			port;			//!< peer port where packets are sent to

	char const			*server_name;		//!< our name

	bool				only_state_changes;	//!< copied from proto_bfd_udp.c

	/*
	 *	Peers are defined globally to a virtual server.  Each
	 *	peer can only have one session associated with it.
	 */
	void				*inst;			//!< proto_bfd_udp instance using this session
	fr_listen_t			*listen;		//!< associated listener

	int				sockfd;			//!< cached for laziness
	fr_event_list_t			*el;			//!< event list
	fr_network_t			*nr;			//!< network side of things

	struct sockaddr_storage		remote_sockaddr;		//!< cached for laziness
	socklen_t			remote_salen;

	struct sockaddr_storage		local_sockaddr;		//!< cached for laziness
	socklen_t			local_salen;

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
} bfd_session_t;

/*
 *	Common APIs between the listen and process routines.  There's no real reason for these definitions to
 *	be here, other than it's an easy place to put common code and definitions.
 *
 *	Unlike other protocols, BFD has no association between request and reply.  Instead, there are two
 *	independent streams of packets.  One is sent by us to the peer, and the other is sent by the peer to
 *	us.
 *
 *	In addition, there are state changes associated with BFD packets.
 */
typedef enum {
	BFD_WRAPPER_INVALID = 0,
	BFD_WRAPPER_RECV_PACKET,
	BFD_WRAPPER_SEND_PACKET,
	BFD_WRAPPER_STATE_CHANGE,
} bfd_wrapper_type_t;

typedef enum {
	BFD_STATE_CHANGE_INVALID = 0,
	BFD_STATE_CHANGE_NONE,			//!< no state change
	BFD_STATE_CHANGE_ADMIN_DOWN,		//!< we are admin-down
	BFD_STATE_CHANGE_PEER_DOWN,		//!< the peer has signalled us that he's Down.
	BFD_STATE_CHANGE_INIT,			//!< we are going to INIT
	BFD_STATE_CHANGE_UP,			//!< we are going to UP
	BFD_STATE_CHANGE_TIMEOUT_DOWN,
} bfd_state_change_t;

typedef struct {
	uint32_t		type;
	bfd_state_change_t	state_change;
	bfd_session_t		*session;
	uint8_t			packet[];
} bfd_wrapper_t;

int	bfd_session_init(bfd_session_t *session);

void	bfd_session_start(bfd_session_t *session);

void	bfd_session_admin_down(bfd_session_t *session);

bfd_state_change_t bfd_session_process(bfd_session_t *session, bfd_packet_t *bfd);
