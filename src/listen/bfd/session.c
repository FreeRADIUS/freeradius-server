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
 *
 */

/**
 * $Id$
 * @file src/listen/bfd/session.c
 * @brief BFD Session handling
 *
 * @copyright 2023 Network RADIUS SAS (legal@networkradius.com)
 */

#include <freeradius-devel/util/debug.h>

#include <freeradius-devel/util/time.h>
#include <freeradius-devel/util/event.h>
#include <freeradius-devel/util/base16.h>
#include <freeradius-devel/util/md5.h>
#include <freeradius-devel/util/rand.h>
#include <freeradius-devel/util/sha1.h>
#include <freeradius-devel/util/socket.h>
#include <freeradius-devel/util/time.h>

#include "session.h"

static void bfd_sign(bfd_session_t *session, bfd_packet_t *bfd);
static int bfd_authenticate(bfd_session_t *session, bfd_packet_t *bfd);
static void bfd_control_packet_init(bfd_session_t *session, bfd_packet_t *bfd);

static void bfd_set_desired_min_tx_interval(bfd_session_t *session, fr_time_delta_t value);

static void bfd_start_packets(bfd_session_t *session);
static void bfd_start_control(bfd_session_t *session);
static int bfd_stop_control(bfd_session_t *session);
static void bfd_set_timeout(bfd_session_t *session, fr_time_t when);

/*
 *	Wrapper to run a trigger.
 *
 *	@todo - push the trigger name, and various other VPs to the worker side?
 *	we will need to define some other kind of fake packet to send to the process
 *	module.
 */
static void bfd_trigger(UNUSED bfd_session_t *session, UNUSED bfd_state_change_t change)
{
#if 0
	bfd_wrapper_t wrapper;
	fr_io_track_t *track;

	wrapper.type = BFD_WRAPPER_STATE_CHANGE;
	wrapper.state_change = change;
	wrapper.session = session;

	track = fr_master_io_track_alloc(session->listen, &session->client, &session->client.ipaddr, session->port,
					 &session->client.src_ipaddr, session->port);
	if (!track) return;

	(void) fr_network_sendto_worker(session->nr, session->listen, track, (uint8_t const *) &wrapper, sizeof(wrapper), fr_time());
#endif
}

void bfd_session_admin_down(bfd_session_t *session)
{
	bfd_stop_control(session);

	session->session_state = BFD_STATE_ADMIN_DOWN;
	bfd_trigger(session,  BFD_STATE_CHANGE_ADMIN_DOWN);
}


/*
 *	Stop polling for packets.
 */
static int bfd_stop_poll(bfd_session_t *session)
{
	if (!session->doing_poll) return 0;

	session->doing_poll = false;

	/*
	 *	We tried to increase the min_tx during a polling
	 *	sequence.  That isn't kosher, so we instead waited
	 *	until now.
	 */
	if (fr_time_delta_unwrap(session->next_min_tx_interval) > 0) {
		session->desired_min_tx_interval = session->next_min_tx_interval;
		session->next_min_tx_interval = fr_time_delta_wrap(0);
	}

	/*
	 *	Already sending packets.  Clear the poll bit and
	 *	re-set the timers.
	 */
	if (!session->remote_demand_mode) {
		fr_assert(session->ev_timeout != NULL);
		fr_assert(session->ev_packet != NULL);

		bfd_stop_control(session);
		bfd_start_control(session);
		return 1;
	}

	return bfd_stop_control(session);
}

/*
 *	Send an immediate response to a poll request.
 *
 *	Note that this doesn't affect our "last_sent" timer.
 *	That's set only when we intend to send a packet.
 */
static void bfd_poll_response(bfd_session_t *session)
{
	bfd_packet_t bfd;

	bfd_control_packet_init(session, &bfd);
	bfd.poll = 0;		/* Section 6.5 */
	bfd.final = 1;

	/*
	 *	TO DO: rate limit poll responses.
	 */

	bfd_sign(session, &bfd);

	if (sendfromto(session->sockfd, &bfd, bfd.length, 0, 0,
		       (struct sockaddr *) &session->local_sockaddr, session->local_salen,
		       (struct sockaddr *) &session->remote_sockaddr, session->remote_salen) < 0) {
		ERROR("Failed sending packet: %s", fr_syserror(errno));
		bfd_session_admin_down(session);
	}
}

/*
 *	Implement the requirements of RFC 5880 Section 6.8.6.
 */
bfd_state_change_t bfd_session_process(bfd_session_t *session, bfd_packet_t *bfd)
{
	bfd_state_change_t state_change = BFD_STATE_CHANGE_NONE;

	/*
	 *
	 *	If the Your Discriminator field is nonzero, it MUST be used to
	 *	select the session with which this BFD packet is associated.  If
	 *	no session is found, the packet MUST be discarded.
	 */
	if ((bfd->your_disc != 0) && (bfd->your_disc != session->local_disc)) {
		DEBUG("BFD %s peer %s packet has unexpected Your-Discriminator (got %08x, expected %08x",
		      session->server_name, session->client.shortname, bfd->your_disc, session->local_disc);
		return BFD_STATE_CHANGE_INVALID;
	}

	/*
	 *	If the A bit is set and no authentication is in use (bfd.AuthType
	 *	is zero), the packet MUST be discarded.
	 */
	if (bfd->auth_present &&
	    (session->auth_type == BFD_AUTH_RESERVED)) {
		DEBUG("BFD %s peer %s packet asked to authenticate an unauthenticated session.",
		      session->server_name, session->client.shortname);
		return BFD_STATE_CHANGE_INVALID;
	}

	/*
	 *	If the A bit is clear and authentication is in use (bfd.AuthType
	 *	is nonzero), the packet MUST be discarded.
	 */
	if (!bfd->auth_present &&
	    (session->auth_type != BFD_AUTH_RESERVED)) {
		DEBUG("BFD %s peer %s packet failed to authenticate an authenticated session.",
		      session->server_name, session->client.shortname);
		return BFD_STATE_CHANGE_INVALID;
	}

	/*
	 *	 If the A bit is set, the packet MUST be authenticated under the
	 *	rules of section 6.7, based on the authentication type in use
	 *	(bfd.AuthType).  This may cause the packet to be discarded.
	 */
	if (bfd->auth_present && !bfd_authenticate(session, bfd)) {
		DEBUG("BFD %s peer %s authentication failed for packet",
		      session->server_name, session->client.shortname);
		return BFD_STATE_CHANGE_INVALID;
	}

	/*
	 *	Set bfd.RemoteDiscr to the value of My Discriminator.
	 *
	 *	Set bfd.RemoteState to the value of the State (Sta) field.
	 *
	 *	Set bfd.RemoteDemandMode to the value of the Demand (D) bit.
	 */
	session->remote_disc = bfd->my_disc;
	session->remote_session_state = bfd->state;
	session->remote_demand_mode = bfd->demand;

	/*
	 *	Set bfd.RemoteMinRxInterval to the value of Required Min RX
	 *	Interval.
	 *
	 *	Addendum: clamp it to be between 32ms and 1s.
	 */
	if ((bfd->required_min_rx_interval > 32) && (bfd->required_min_rx_interval < USEC)) {
		session->remote_min_rx_interval = fr_time_delta_from_usec(bfd->required_min_rx_interval);
	}

	/*
	 *	If the Required Min Echo RX Interval field is zero, the
	 *	transmission of Echo packets, if any, MUST cease.
	 */
	if (bfd->min_echo_rx_interval == 0) {
#if 0
		/*
		 *	Echo packets are BFD packets with
		 *	application-layer data echoed back to the
		 *	sender.  We don't do that.
		 */
		bfd_stop_echo(session);
#endif
	}

	/*
	 *	If a Poll Sequence is being transmitted by the local system and
	 *	the Final (F) bit in the received packet is set, the Poll Sequence
	 *	MUST be terminated.
	 */
	if (session->doing_poll && bfd->final) {
		bfd_stop_poll(session);
	}

	/*
	 *	Update transmit intervals as in 6.8.2
	 */

	/*
	 *	Update detection times as in 6.8.4
	 */
	if (!session->demand_mode) {
		if (fr_time_delta_gteq(session->required_min_rx_interval, fr_time_delta_from_usec(bfd->desired_min_tx_interval))) {
			session->detection_time = session->required_min_rx_interval;
		} else {
			session->detection_time = fr_time_delta_from_usec(bfd->desired_min_tx_interval);
		}
	} else {
		if (fr_time_delta_gteq(session->desired_min_tx_interval, session->remote_min_rx_interval)) {
			session->detection_time = session->desired_min_tx_interval;
		} else {
			session->detection_time = session->remote_min_rx_interval;
		}
	}

	/*
	 *	If bfd.SessionState is AdminDown
	 *
	 *		Discard the packet.
	 */
	if (session->session_state == BFD_STATE_ADMIN_DOWN) {
		DEBUG("Discarding BFD packet (admin down)");
		return BFD_STATE_CHANGE_ADMIN_DOWN;
	}

	/*
	 *	If received state is AdminDown
	 *		If bfd.SessionState is not Down
	 *			Set bfd.LocalDiag to 3 (Neighbor signaled session down)
	 *			Set bfd.SessionState to Down
	 */
	if (bfd->state == BFD_STATE_ADMIN_DOWN) {
		if (bfd->state != BFD_STATE_DOWN) {
		down:
			session->local_diag = BFD_NEIGHBOR_DOWN;

			DEBUG("BFD %s peer %s State %s -> DOWN (neighbour %s)",
			      session->server_name, session->client.shortname,
			      fr_bfd_packet_names[session->session_state],
			      fr_bfd_packet_names[bfd->state]);
			session->session_state = BFD_STATE_DOWN;
			state_change = BFD_STATE_CHANGE_PEER_DOWN;
		}

	} else {
		switch (session->session_state) {
		case BFD_STATE_DOWN:
			switch (bfd->state) {
			case BFD_STATE_DOWN:
				DEBUG("BFD %s peer %s State DOWN -> INIT (neighbor DOWN)",
				      session->server_name, session->client.shortname);
				session->session_state = BFD_STATE_INIT;
				state_change = BFD_STATE_CHANGE_INIT;
				break;

			case BFD_STATE_INIT:
				DEBUG("BFD %s peer %s State DOWN -> UP (neighbor INIT)",
				      session->server_name, session->client.shortname);
				session->session_state = BFD_STATE_UP;
				state_change = BFD_STATE_CHANGE_UP;
				break;

			default: /* don't change anything */
				break;
			}
			break;

		case BFD_STATE_INIT:
			switch (bfd->state) {
			case BFD_STATE_INIT:
			case BFD_STATE_UP:
				DEBUG("BFD %s peer %s State INIT -> UP",
				      session->server_name, session->client.shortname);
				session->session_state = BFD_STATE_UP;
				state_change = BFD_STATE_CHANGE_UP;
				break;

			default: /* don't change anything */
				break;
			}
			break;

		case BFD_STATE_UP:
			switch (bfd->state) {
			case BFD_STATE_DOWN:
				goto down;

			default:
				break;
			}
			break;

		default:
			DEBUG("Internal sanity check failed");
			return BFD_STATE_CHANGE_INVALID;
		}
	}

	/*
	 *	Section 6.8.3
	 *
	 *	When bfd.SessionState is not Up, the system MUST set
	 *	bfd.DesiredMinTxInterval to a value of not less than one second
	 *	(1,000,000 microseconds).  This is intended to ensure that the
	 *	bandwidth consumed by BFD sessions that are not Up is negligible,
	 *	particularly in the case where a neighbor may not be running BFD.
	 */
	if (state_change && (session->session_state != BFD_STATE_UP)) {
		bfd_set_desired_min_tx_interval(session, fr_time_delta_from_sec(1));
	}

	/*
	 *	Check if demand mode should be active (Section 6.6)
	 *
	 *	If bfd.RemoteDemandMode is 1, bfd.SessionState is Up, and
	 *	bfd.RemoteSessionState is Up, Demand mode is active on the remote
	 *	system and the local system MUST cease the periodic transmission
	 *	of BFD Control packets (see section 6.8.7).
	 */
	if (session->remote_demand_mode &&
	    (session->session_state == BFD_STATE_UP) &&
	    (session->remote_session_state == BFD_STATE_UP)) {
		DEBUG("BFD %s peer %s demand mode UP / UP, stopping packets",
		      session->server_name, session->client.shortname);
		bfd_stop_control(session);
	}

	/*
	 *	If bfd.RemoteDemandMode is 0, or bfd.SessionState is not Up, or
	 *	bfd.RemoteSessionState is not Up, Demand mode is not active on the
	 *	remote system and the local system MUST send periodic BFD Control
	 *	packets.
	 */
	if ((!session->remote_demand_mode) ||
	    (session->session_state != BFD_STATE_UP) ||
	    (session->remote_session_state != BFD_STATE_UP)) {
		bfd_start_control(session);
	}

	/*
	 *	If the Poll (P) bit is set, send a BFD Control packet to the
	 *	remote system with the Poll (P) bit clear, and the Final (F) bit
	 *	set (see section 6.8.7).
	 */
	if (bfd->poll) {
		bfd_poll_response(session);
	}

	/*
	 *	If the packet was not discarded, it has been received for purposes
	 *	of the Detection Time expiration rules in section 6.8.4.
	 */
	session->last_recv = fr_time();

	/*
	 *	The other end is reducing the RX interval.  Do that
	 *	now.
	 */
	if (fr_time_delta_lt(fr_time_delta_from_usec(bfd->required_min_rx_interval), session->remote_min_rx_interval) &&
	    !session->demand_mode) {
		bfd_stop_control(session);
		bfd_start_control(session);
	}

	/*
	 *	@todo - warn about missing packets?
	 */
#if 0
	if ((session->detect_multi >= 2) && (fr_time_gt(session->last_recv, session->next_recv))) {
		...
	}
#endif

	return state_change;
}


/*
 *	Requirements of 6.8.3
 *
 *	Changes to:
 *
 *		session->desired_min_tx_interval
 *		session->required_min_rx_interval
 *
 *	mean we start polling.
 */

/*
 *	Verify and/or calculate passwords
 */
static void bfd_calc_simple(bfd_session_t *session, bfd_packet_t *bfd)
{
	bfd_auth_simple_t *simple = &bfd->auth.password;

	fr_assert(session->secret_len <= sizeof(simple->password));

	memcpy(simple->password, session->client.secret, session->secret_len);
	simple->auth_len = 3 + session->secret_len;
}

static void bfd_auth_simple(bfd_session_t *session, bfd_packet_t *bfd)
{
	bfd_auth_simple_t *simple = &bfd->auth.password;

	simple->auth_type = session->auth_type;
	simple->auth_len = 3 + session->secret_len;
	bfd->length = FR_BFD_HEADER_LENGTH + simple->auth_len;

	simple->key_id = 0;

	bfd_calc_simple(session, bfd);
}

/*
 *	Verify and/or calculate auth-type digests.
 */
static void bfd_calc_md5(bfd_session_t *session, bfd_packet_t *bfd)
{
	bfd_auth_md5_t *md5 = &bfd->auth.md5;

	fr_assert(session->secret_len <= sizeof(md5->digest));
	fr_assert(md5->auth_len == sizeof(*md5));

	memset(md5->digest, 0, sizeof(md5->digest));
	memcpy(md5->digest, session->client.secret, session->secret_len);

	fr_md5_calc(md5->digest,(const uint8_t *) bfd, bfd->length);
}

static void bfd_auth_md5(bfd_session_t *session, bfd_packet_t *bfd)
{
	bfd_auth_md5_t *md5 = &bfd->auth.md5;

	md5->auth_type = session->auth_type;
	md5->auth_len = sizeof(*md5);
	bfd->length = FR_BFD_HEADER_LENGTH + md5->auth_len;

	md5->key_id = 0;
	md5->sequence_no = session->xmit_auth_seq++;

	bfd_calc_md5(session, bfd);
}

static void bfd_calc_sha1(bfd_session_t *session, bfd_packet_t *bfd)
{
	fr_sha1_ctx ctx;
	bfd_auth_sha1_t *sha1 = &bfd->auth.sha1;

	fr_assert(session->secret_len <= sizeof(sha1->digest));
	fr_assert(sha1->auth_len == sizeof(*sha1));

	memset(sha1->digest, 0, sizeof(sha1->digest));
	memcpy(sha1->digest, session->client.secret, session->secret_len);

	fr_sha1_init(&ctx);
	fr_sha1_update(&ctx, (const uint8_t *) bfd, bfd->length);
	fr_sha1_final(sha1->digest, &ctx);
}

static void bfd_auth_sha1(bfd_session_t *session, bfd_packet_t *bfd)
{
	bfd_auth_sha1_t *sha1 = &bfd->auth.sha1;

	sha1->auth_type = session->auth_type;
	sha1->auth_len = sizeof(*sha1);
	bfd->length = FR_BFD_HEADER_LENGTH + sha1->auth_len;

	sha1->key_id = 0;
	sha1->sequence_no = session->xmit_auth_seq++;

	bfd_calc_sha1(session, bfd);
}

static int bfd_verify_sequence(bfd_session_t *session, uint32_t sequence_no,
			       int keyed)
{
	uint32_t start, stop;

	start = session->recv_auth_seq;
	if (keyed) {
		start++;
	}
	stop = start + 3 * session->detect_multi;

	if (start < stop) {
		if ((sequence_no < start) ||
		    (sequence_no > stop)) {
			return 0;
		}

	} else {	/* start is ~2^32, stop is ~10 */
		if ((sequence_no > start) &&
		    (sequence_no < stop)) {
			return 0;
		}
	}

	return 1;
}

static int bfd_verify_simple(bfd_session_t *session, bfd_packet_t *bfd)
{
	bfd_auth_simple_t *simple = &bfd->auth.password;

	if ((size_t) simple->auth_len != (3 + session->secret_len)) return 0;

	if (simple->key_id != 0) return 0;

	return (fr_digest_cmp((uint8_t const *) session->client.secret, simple->password, session->secret_len) == 0);
}

static int bfd_verify_md5(bfd_session_t *session, bfd_packet_t *bfd)
{
	int rcode;
	bfd_auth_md5_t *md5 = &bfd->auth.md5;
	uint8_t digest[sizeof(md5->digest)];

	if (md5->auth_len != sizeof(*md5)) return 0;

	if (md5->key_id != 0) return 0;

	memcpy(digest, md5->digest, sizeof(digest));

	bfd_calc_md5(session, bfd);
	rcode = fr_digest_cmp(digest, md5->digest, sizeof(digest));

	memcpy(md5->digest, digest, sizeof(md5->digest)); /* pedantic */

	if (rcode != 0) {
		DEBUG("BFD %s peer %s MD5 Digest failed: **** RE-ENTER THE SECRET ON BOTH ENDS ****",
		      session->server_name, session->client.shortname);
		return 0;
	}

	/*
	 *	Do this AFTER the authentication instead of before!
	 */
	if (!session->auth_seq_known) {
		session->auth_seq_known = 1;

	} else if (!bfd_verify_sequence(session, md5->sequence_no,
					(md5->auth_type == BFD_AUTH_MET_KEYED_MD5))) {
		DEBUG("MD5 sequence out of window");
		return 0;
	}

	session->recv_auth_seq = md5->sequence_no;

	return 1;
}

static int bfd_verify_sha1(bfd_session_t *session, bfd_packet_t *bfd)
{
	int rcode;
	bfd_auth_sha1_t *sha1 = &bfd->auth.sha1;
	uint8_t digest[sizeof(sha1->digest)];

	if (sha1->auth_len != sizeof(*sha1)) return 0;

	if (sha1->key_id != 0) return 0;

	memcpy(digest, sha1->digest, sizeof(digest));

	bfd_calc_sha1(session, bfd);
	rcode = fr_digest_cmp(digest, sha1->digest, sizeof(digest));

	memcpy(sha1->digest, digest, sizeof(sha1->digest)); /* pedantic */

	if (rcode != 0) {
		DEBUG("BFD %s peer %s SHA1 Digest failed: **** RE-ENTER THE SECRET ON BOTH ENDS ****",
		      session->server_name, session->client.shortname);
		return 0;
	}

	/*
	 *	Do this AFTER the authentication instead of before!
	 */
	if (!session->auth_seq_known) {
		session->auth_seq_known = 1;

	} else if (!bfd_verify_sequence(session, sha1->sequence_no,
					(sha1->auth_type == BFD_AUTH_MET_KEYED_SHA1))) {
		DEBUG("SHA1 sequence out of window");
		return 0;
	}

	session->recv_auth_seq = sha1->sequence_no;

	return 1;
}

static int bfd_authenticate(bfd_session_t *session, bfd_packet_t *bfd)
{
	switch (bfd->auth.basic.auth_type) {
	case BFD_AUTH_RESERVED:
		return 0;

	case BFD_AUTH_SIMPLE:
		return bfd_verify_simple(session, bfd);

	case BFD_AUTH_KEYED_MD5:
	case BFD_AUTH_MET_KEYED_MD5:
		return bfd_verify_md5(session, bfd);

	case BFD_AUTH_KEYED_SHA1:
	case BFD_AUTH_MET_KEYED_SHA1:
		return bfd_verify_sha1(session, bfd);
	}

	return 0;
}


static void bfd_sign(bfd_session_t *session, bfd_packet_t *bfd)
{
	if (bfd->auth_present) {
		switch (session->auth_type) {
		case BFD_AUTH_RESERVED:
			break;

		case BFD_AUTH_SIMPLE:
			bfd_auth_simple(session, bfd);
			break;

		case BFD_AUTH_KEYED_MD5:
		case BFD_AUTH_MET_KEYED_MD5:
			bfd_auth_md5(session, bfd);
			break;

		case BFD_AUTH_KEYED_SHA1:
		case BFD_AUTH_MET_KEYED_SHA1:
			bfd_auth_sha1(session, bfd);
			break;
		}
	}
}


/*
 *	Initialize a control packet.
 */
static void bfd_control_packet_init(bfd_session_t *session, bfd_packet_t *bfd)
{
	memset(bfd, 0, sizeof(*bfd));

	bfd->version = 1;
	bfd->diag = session->local_diag;
	bfd->state = session->session_state;
	bfd->poll = 0;	/* fixed by poll response */
	bfd->final = 0;	/* fixed by poll response */
	bfd->control_plane_independent = 0;

	bfd->auth_present = (session->auth_type != BFD_AUTH_RESERVED);

	/*
	 *	If we're UP / UP, signal that we've entered demand
	 *	mode, and stop sending packets.
	 */
	if (session->demand_mode &&
	    (session->session_state == BFD_STATE_UP) &&
	    (session->remote_session_state == BFD_STATE_UP)) {
		bfd->demand = true;

		DEBUG("BFD %s peer %s demand mode UP / UP, sending ACK and done.",
		      session->server_name, session->client.shortname);
		bfd_stop_control(session);
	} else {
		bfd->demand = false;
	}

	bfd->multipoint = 0;
	bfd->detect_multi = session->detect_multi;
	bfd->length = FR_BFD_HEADER_LENGTH;

	bfd->my_disc = session->local_disc;
	bfd->your_disc = session->remote_disc;

	bfd->desired_min_tx_interval = fr_time_delta_to_usec(session->desired_min_tx_interval);
	bfd->required_min_rx_interval = fr_time_delta_to_usec(session->required_min_rx_interval);

	bfd->min_echo_rx_interval = fr_time_delta_to_usec(session->my_min_echo_rx_interval);
}

static void bfd_send_init(bfd_session_t *session, bfd_packet_t *bfd)
{
	bfd_control_packet_init(session, bfd);

	bfd->poll = session->doing_poll;

	if (!bfd->demand) {
		bfd_start_packets(session);
	}

	bfd_sign(session, bfd);
}

/*
 *	Send one BFD packet.
 */
static void bfd_send_packet(UNUSED fr_event_list_t *el, UNUSED fr_time_t now, void *ctx)
{
	bfd_session_t *session = ctx;
	bfd_packet_t bfd;

	bfd_send_init(session, &bfd);

	DEBUG("BFD %s peer %s sending %s",
	      session->server_name, session->client.shortname, fr_bfd_packet_names[session->session_state]);

	session->last_sent = fr_time();

	if (sendfromto(session->sockfd, &bfd, bfd.length, 0, 0,
		       (struct sockaddr *) &session->local_sockaddr, session->local_salen,
		       (struct sockaddr *) &session->remote_sockaddr, session->remote_salen) < 0) {
		ERROR("Failed sending packet: %s", fr_syserror(errno));
		bfd_session_admin_down(session);
	}
}

/*
 *	Send one BFD packet.
 */
static void bfd_unlang_send_packet(UNUSED fr_event_list_t *el, UNUSED fr_time_t now, void *ctx)
{
	bfd_session_t *session = ctx;
	bfd_packet_t *bfd;
	bfd_wrapper_t *wrapper;
	fr_io_track_t *track;
	fr_listen_t *parent;
	uint8_t buffer[sizeof(bfd_wrapper_t) + sizeof(*bfd)];

	wrapper = (bfd_wrapper_t *) buffer;
	bfd = (bfd_packet_t *) wrapper->packet;

	bfd_send_init(session, bfd);

	session->last_sent = fr_time();

	wrapper->type = BFD_WRAPPER_SEND_PACKET;
	wrapper->state_change = BFD_STATE_CHANGE_NONE;
	wrapper->session = session;

	parent = talloc_parent(session->listen);
	(void) talloc_get_type_abort(parent, fr_listen_t);

	track = fr_master_io_track_alloc(session->listen, &session->client, &session->client.ipaddr, session->port,
					 &session->client.src_ipaddr, session->port);
	if (!track) return;

	(void) fr_network_sendto_worker(session->nr, parent, track, (uint8_t const *) wrapper, (wrapper->packet + bfd->length) - (uint8_t *) wrapper, fr_time());
}

/*
 *	Start sending packets.
 */
static void bfd_start_packets(bfd_session_t *session)
{
	uint64_t	interval, base;
	uint64_t	jitter;
	fr_event_timer_cb_t cb;

	if (session->ev_packet) return;

	/*
	 *	Reset the timers.
	 */
	fr_event_timer_delete(&session->ev_packet);

	if (fr_time_delta_cmp(session->desired_min_tx_interval, session->remote_min_rx_interval) >= 0) {
		interval = fr_time_delta_unwrap(session->desired_min_tx_interval);
	} else {
		interval = fr_time_delta_unwrap(session->remote_min_rx_interval);

		/*
		 *	The other end doesn't want to receive control packets.  So we stop sending them.
		 */
		if (!interval) return;
	}

	/*
	 *	If bfd.DetectMult is equal to 1, the interval between transmitted BFD
	 *	Control packets MUST be no more than 90% of the negotiated
	 *	transmission interval, and MUST be no less than 75% of the negotiated
	 *	transmission interval.  This is to ensure that, on the remote system,
	 *	the calculated Detection Time does not pass prior to the receipt of
	 *	the next BFD Control packet.
	 */
	base = (interval * 3) / 4;
	jitter = fr_rand();	/* 32-bit number */

	if (session->detect_multi == 1) {
		jitter *= 644245094;	/* 15% of 2^32 */

	} else {
		jitter *= (1 << 30); /* 25% of 2^32 */
	}

	jitter >>= 32;
	jitter *= interval;
	jitter >>= 32;
	interval = base;
	interval += jitter;

	if (!session->only_state_changes) {
		cb = bfd_unlang_send_packet;
	} else {
		cb = bfd_send_packet;
	}

	if (fr_event_timer_in(session, session->el, &session->ev_packet,
			      fr_time_delta_wrap(interval),
			      cb, session) < 0) {
		fr_assert("Failed to insert event" == NULL);
	}
}


/*
 *	Start polling for the peer.
 */
static void bfd_start_poll(bfd_session_t *session)
{
	if (session->doing_poll) return;

	/*
	 *	Already sending packets.  Reset the timers and set the
	 *	poll bit.
	 */
	if (!session->remote_demand_mode) {
		bfd_stop_control(session);
	}

	session->doing_poll = true;

	/*
	 *	Send POLL packets, even if we're not sending CONTROL
	 *	packets.
	 */
	bfd_start_packets(session);
}

/*
 *	Timer functions
 */
static void bfd_set_desired_min_tx_interval(bfd_session_t *session, fr_time_delta_t value)
{
	/*
	 *	Increasing the value: don't change it if we're already
	 *	polling.
	 */
	if (session->doing_poll &&
	    (session->session_state == BFD_STATE_UP) &&
	    (fr_time_delta_cmp(value, session->desired_min_tx_interval) > 0)) {
		session->next_min_tx_interval = value;
		return;
	}

	/*
	 *	Don't poll more than once per second.
	 */
	if (session->session_state != BFD_STATE_UP) {
		if (fr_time_delta_cmp(value, fr_time_delta_from_sec(1)) < 0) value = fr_time_delta_from_sec(1);
	}

	/*
	 *	If either bfd.DesiredMinTxInterval is changed or
	 *	bfd.RequiredMinRxInterval is changed, a Poll Sequence MUST be
	 *	initiated (see section 6.5).  If the timing is such that a system
	 *	receiving a Poll Sequence wishes to change the parameters described
	 *	in this paragraph, the new parameter values MAY be carried in packets
	 *	with the Final (F) bit set, even if the Poll Sequence has not yet
	 *	been sent.
	 */

	session->desired_min_tx_interval = value;

	/*
	 *	Already polling, don't change anything.
	 */
	if (session->doing_poll) return;

	bfd_stop_control(session);
	bfd_start_poll(session);
}


/*
 *	We failed to see a packet.
 */
static void bfd_detection_timeout(UNUSED fr_event_list_t *el, fr_time_t now, void *ctx)
{
	bfd_session_t *session = ctx;

	DEBUG("BFD %s peer %s TIMEOUT state %s",
	      session->server_name, session->client.shortname,
	      fr_bfd_packet_names[session->session_state]);

	if (!session->demand_mode) {
		switch (session->session_state) {
		case BFD_STATE_INIT:
		case BFD_STATE_UP:
			goto start_poll;

		default:
			break;
		}

	} else if (!session->doing_poll) {
	start_poll:
		DEBUG("BFD %s peer %s State <timeout> -> DOWN (control expired)",
		      session->server_name, session->client.shortname);
		session->session_state = BFD_STATE_DOWN;
		session->local_diag =  BFD_CTRL_EXPIRED;
		bfd_trigger(session, BFD_STATE_CHANGE_TIMEOUT_DOWN);

		bfd_set_desired_min_tx_interval(session, fr_time_delta_from_sec(1));
	}

	session->remote_disc = 0;

	if (session->detection_timeouts >= 2) {
		session->auth_seq_known = 0;
	}

	session->detection_timeouts++;

	bfd_set_timeout(session, now);
}

/*
 *	Set the timeout for when we've lost enough packets to be
 *	worried.
 */
static void bfd_set_timeout(bfd_session_t *session, fr_time_t when)
{
	fr_time_t timeout;
	uint64_t delay;
	fr_time_delta_t delta;

	fr_event_timer_delete(&session->ev_timeout);

	delay = fr_time_delta_unwrap(session->detection_time);
	delay *= session->detect_multi;

	delay += fr_time_delta_unwrap(session->detection_time) / 2;
	delta = fr_time_delta_from_usec(delay);

	timeout = fr_time_add(when, delta);

	if (fr_event_timer_at(session, session->el, &session->ev_timeout,
			      timeout, bfd_detection_timeout, session) < 0) {
		fr_assert("Failed to insert event" == NULL);
	}
}


/*
 *	Start / stop control packets.
 */
static int bfd_stop_control(bfd_session_t *session)
{
	fr_event_timer_delete(&session->ev_timeout);
	fr_event_timer_delete(&session->ev_packet);
	return 1;
}

static void bfd_start_control(bfd_session_t *session)
{
	/*
	 *	@todo - change our discriminator?
	 */

	/*
	 *	We don't expect to see remote packets, so don't do anything.
	 */
	if (fr_time_delta_unwrap(session->remote_min_rx_interval) == 0) return;

	/*
	 *	@todo - support passive.  From 6.1:
	 *
	 *	A system may take either an Active role or a Passive role in session
	 *	initialization.  A system taking the Active role MUST send BFD
	 *	Control packets for a particular session, regardless of whether it
	 *	has received any BFD packets for that session.  A system taking the
	 *	Passive role MUST NOT begin sending BFD packets for a particular
	 *	session until it has received a BFD packet for that session, and thus
	 *	has learned the remote system's discriminator value.
	 */
	if ((session->remote_disc == 0) && session->passive) return;

	/*
	 *	We were asked to go "up" when we were already "up"
	 */
	if (session->remote_demand_mode &&
	    (session->session_state == BFD_STATE_UP) &&
	    (session->remote_session_state == BFD_STATE_UP) &&
	    !session->doing_poll) {
		DEBUG("BFD %s peer %s warning: asked to start UP / UP ?",
		      session->server_name, session->client.shortname);
		bfd_session_admin_down(session);
		return;
	}

	bfd_set_timeout(session, session->last_recv);

	/*
	 *	Start sending packets.
	 */
	bfd_start_packets(session);
}


int bfd_session_init(bfd_session_t *session)
{
	session->session_state = BFD_STATE_DOWN;
	session->local_disc = fr_rand();
	session->remote_disc = 0;
	session->local_diag = BFD_DIAG_NONE;
	session->remote_min_rx_interval = fr_time_delta_wrap(1);
	session->remote_demand_mode = false;
	session->recv_auth_seq = 0;
	session->xmit_auth_seq = fr_rand();
	session->auth_seq_known = 0;

	/*
	 *	Initialize the detection time.
	 */
	if (!session->demand_mode) {
		session->detection_time = session->required_min_rx_interval;
	} else {
		session->detection_time = session->desired_min_tx_interval;
	}

	return 0;
}

void bfd_session_start(bfd_session_t *session)
{
	DEBUG("Starting BFD for %s", session->client.shortname);

	fr_assert(session->el);

	bfd_start_control(session);
}
