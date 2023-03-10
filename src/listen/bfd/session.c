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
#include <freeradius-devel/server/trigger.h>

#include "session.h"

static void bfd_sign(proto_bfd_peer_t *session, bfd_packet_t *bfd);
static int bfd_authenticate(proto_bfd_peer_t *session, bfd_packet_t *bfd);
static void bfd_control_packet_init(proto_bfd_peer_t *session, bfd_packet_t *bfd);

static void bfd_set_desired_min_tx_interval(proto_bfd_peer_t *session, fr_time_delta_t value);

static void bfd_start_packets(proto_bfd_peer_t *session);
static void bfd_start_control(proto_bfd_peer_t *session);
static int bfd_stop_control(proto_bfd_peer_t *session);
static void bfd_set_timeout(proto_bfd_peer_t *session, fr_time_t when);


/*
 *	Wrapper to run a trigger.
 *
 *	@todo - push the trigger name, and various other VPs to the worker side?
 *	we will need to define some other kind of fake packet to send to the process
 *	module.
 */
static void bfd_trigger(proto_bfd_peer_t *session)
{
//	fr_radius_packet_t	packet;
//	request_t		*request = request_local_alloc_external(session, NULL);
	char			buffer[256];

	snprintf(buffer, sizeof(buffer), "server.bfd.%s",
		 fr_bfd_packet_names[session->session_state]);

	DEBUG("BFD %s trigger %s", session->client.shortname, buffer);

//	bfd_request(session, request, &packet);

//	trigger_exec(unlang_interpret_get_thread_default(), NULL, buffer, false, NULL);
}

/*
 *	Stop polling for packets.
 */
static int bfd_stop_poll(proto_bfd_peer_t *session)
{
	if (!session->doing_poll) return 0;

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
		session->doing_poll = false;

		bfd_stop_control(session);
		bfd_start_control(session);
		return 1;
	}

	session->doing_poll = false;

	return bfd_stop_control(session);
}

/*
 *	Send an immediate response to a poll request.
 *
 *	Note that this doesn't affect our "last_sent" timer.
 *	That's set only when we intend to send a packet.
 */
static void bfd_poll_response(proto_bfd_peer_t *session)
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
		fr_assert(0);
	}
}


int bfd_session_process(proto_bfd_peer_t *session, bfd_packet_t *bfd)
{
	bool state_change = false;

	if (bfd->auth_present &&
	    (session->auth_type == BFD_AUTH_RESERVED)) {
		DEBUG("BFD %s packet asked to authenticate an unauthenticated session.", session->client.shortname);
		return 0;
	}

	if (!bfd->auth_present &&
	    (session->auth_type != BFD_AUTH_RESERVED)) {
		DEBUG("BFD %s packet failed to authenticate an authenticated session.", session->client.shortname);
		return 0;
	}

	if (bfd->auth_present && !bfd_authenticate(session, bfd)) {
		DEBUG("BFD %s authentication failed", session->client.shortname);
		return 0;
	}

	DEBUG("BFD %s processing packet", session->client.shortname);
	session->remote_disc = bfd->my_disc;
	session->remote_session_state = bfd->state;
	session->remote_demand_mode = bfd->demand;

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
	 *	@todo - clamp these at some reasonable value, or maybe
	 *	just trust the other side.
	 */
	session->remote_min_rx_interval = fr_time_delta_from_usec(bfd->required_min_rx_interval);
	session->remote_min_echo_rx_interval = fr_time_delta_from_usec(bfd->min_echo_rx_interval);

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

	if (session->doing_poll && bfd->final) {
		bfd_stop_poll(session);
	}

	/*
	 *	Update transmit intervals as in 6.8.7
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
	session->detection_time = fr_time_delta_wrap(session->detect_multi * fr_time_delta_unwrap(session->detection_time));

	if (session->session_state == BFD_STATE_ADMIN_DOWN) {
		DEBUG("Discarding BFD packet (admin down)");
		return 0;
	}

	if (bfd->state == BFD_STATE_ADMIN_DOWN) {
		if (bfd->state != BFD_STATE_DOWN) {
			session->local_diag = BFD_NEIGHBOR_DOWN;
		}

		DEBUG("BFD %s State %s -> DOWN (admin down)",
		      session->client.shortname, fr_bfd_packet_names[session->session_state]);
		session->session_state = BFD_STATE_DOWN;
		bfd_trigger(session);
		state_change = true;

		bfd_set_desired_min_tx_interval(session, fr_time_delta_from_usec(1));

	} else {
		switch (session->session_state) {
		case BFD_STATE_DOWN:
			switch (bfd->state) {
			case BFD_STATE_DOWN:
				DEBUG("BFD %s State DOWN -> INIT (neighbor down)",
				      session->client.shortname);
				session->session_state = BFD_STATE_INIT;
				bfd_trigger(session);
				state_change = true;

				bfd_set_desired_min_tx_interval(session, fr_time_delta_from_sec(1));
				break;

			case BFD_STATE_INIT:
				DEBUG("BFD %s State DOWN -> UP (neighbor INIT)",
				      session->client.shortname);
				session->session_state = BFD_STATE_UP;
				bfd_trigger(session);
				state_change = true;
				break;

			default: /* don't change anything */
				break;
			}
			break;

		case BFD_STATE_INIT:
			switch (bfd->state) {
			case BFD_STATE_INIT:
			case BFD_STATE_UP:
				DEBUG("BFD %s State INIT -> UP",
				      session->client.shortname);
				session->session_state = BFD_STATE_UP;
				bfd_trigger(session);
				state_change = true;
				break;

			default: /* don't change anything */
				break;
			}
			break;

		case BFD_STATE_UP:
			switch (bfd->state) {
			case BFD_STATE_DOWN:
				session->local_diag = BFD_NEIGHBOR_DOWN;

				DEBUG("BFD %s State UP -> DOWN (neighbor down)", session->client.shortname);
				session->session_state = BFD_STATE_DOWN;
				bfd_trigger(session);
				state_change = true;

				bfd_set_desired_min_tx_interval(session, fr_time_delta_from_sec(1));
				break;

			default:
				break;
			}
			break;

		default:
			DEBUG("Internal sanity check failed");
			return 0;
		}
	}

	/*
	 *	Check if demand mode should be active (Section 6.6)
	 */
	if (session->remote_demand_mode &&
	    (session->session_state == BFD_STATE_UP) &&
	    (session->remote_session_state == BFD_STATE_UP)) {
		DEBUG("BFD %s demand mode UP / UP, stopping packets", session->client.shortname);
		bfd_stop_control(session);
	}

	if (bfd->poll) {
		bfd_poll_response(session);
	}

	/*
	 *	We've received the packet for the purpose of Section
	 *	6.8.4.
	 */
	session->last_recv = fr_time();

#if 0
	/*
	 *	We've received a packet, but missed the previous one.
	 *	Warn about it.
	 */
	if ((session->detect_multi >= 2) && (fr_time_gt(session->last_recv, session->next_recv))) {
		fr_radius_packet_t packet;
		request_t request;

		bfd_request(session, &request, &packet);

		trigger_exec(unlang_interpret_get_thread_default(), NULL, "server.bfd.warn", false, NULL);
	}
#endif

	if ((!session->remote_demand_mode) ||
	    (session->session_state != BFD_STATE_UP) ||
	    (session->remote_session_state != BFD_STATE_UP)) {
		bfd_start_control(session);
	}

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
static void bfd_calc_simple(proto_bfd_peer_t *session, bfd_packet_t *bfd)
{
	bfd_auth_simple_t *simple = &bfd->auth.password;

	fr_assert(session->secret_len <= sizeof(simple->password));

	memcpy(simple->password, session->client.secret, session->secret_len);
	simple->auth_len = session->secret_len;
}

static void bfd_auth_simple(proto_bfd_peer_t *session, bfd_packet_t *bfd)
{
	bfd_auth_simple_t *simple = &bfd->auth.password;

	simple->auth_type = session->auth_type;
	simple->auth_len = session->secret_len;
	bfd->length += simple->auth_len;

	simple->key_id = 0;

	bfd_calc_simple(session, bfd);
}

/*
 *	Verify and/or calculate auth-type digests.
 */
static void bfd_calc_md5(proto_bfd_peer_t *session, bfd_packet_t *bfd)
{
	bfd_auth_md5_t *md5 = &bfd->auth.md5;

	fr_assert(session->secret_len <= sizeof(md5->digest));
	fr_assert(md5->auth_len == sizeof(*md5));

	memset(md5->digest, 0, sizeof(md5->digest));
	memcpy(md5->digest, session->client.secret, session->secret_len);

	fr_md5_calc(md5->digest,(const uint8_t *) bfd, bfd->length);
}

static void bfd_auth_md5(proto_bfd_peer_t *session, bfd_packet_t *bfd)
{
	bfd_auth_md5_t *md5 = &bfd->auth.md5;

	md5->auth_type = session->auth_type;
	md5->auth_len = sizeof(*md5);
	bfd->length += md5->auth_len;

	md5->key_id = 0;
	md5->sequence_no = session->xmit_auth_seq++;

	bfd_calc_md5(session, bfd);
}

static void bfd_calc_sha1(proto_bfd_peer_t *session, bfd_packet_t *bfd)
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

static void bfd_auth_sha1(proto_bfd_peer_t *session, bfd_packet_t *bfd)
{
	bfd_auth_sha1_t *sha1 = &bfd->auth.sha1;

	sha1->auth_type = session->auth_type;
	sha1->auth_len = sizeof(*sha1);
	bfd->length += sha1->auth_len;

	sha1->key_id = 0;
	sha1->sequence_no = session->xmit_auth_seq++;

	bfd_calc_sha1(session, bfd);
}

static int bfd_verify_sequence(proto_bfd_peer_t *session, uint32_t sequence_no,
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

static int bfd_verify_simple(proto_bfd_peer_t *session, bfd_packet_t *bfd)
{
	bfd_auth_simple_t *simple = &bfd->auth.password;

	if (simple->auth_len != session->secret_len) return 0;

	if (simple->key_id != 0) return 0;

	return (fr_digest_cmp((uint8_t const *) session->client.secret, simple->password, session->secret_len) == 0);
}

static int bfd_verify_md5(proto_bfd_peer_t *session, bfd_packet_t *bfd)
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
		DEBUG("BFD %s MD5 Digest failed: **** RE-ENTER THE SECRET ON BOTH ENDS ****", session->client.shortname);
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

static int bfd_verify_sha1(proto_bfd_peer_t *session, bfd_packet_t *bfd)
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
		DEBUG("BFD %s SHA1 Digest failed: **** RE-ENTER THE SECRET ON BOTH ENDS ****", session->client.shortname);
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

static int bfd_authenticate(proto_bfd_peer_t *session, bfd_packet_t *bfd)
{
	switch (bfd->auth.basic.auth_type) {
	case BFD_AUTH_RESERVED:
		return 0;

	case BFD_AUTH_SIMPLE:
		bfd_verify_simple(session, bfd);
		break;

	case BFD_AUTH_KEYED_MD5:
	case BFD_AUTH_MET_KEYED_MD5:
		return bfd_verify_md5(session, bfd);

	case BFD_AUTH_KEYED_SHA1:
	case BFD_AUTH_MET_KEYED_SHA1:
		return bfd_verify_sha1(session, bfd);
	}

	return 0;
}


static void bfd_sign(proto_bfd_peer_t *session, bfd_packet_t *bfd)
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
static void bfd_control_packet_init(proto_bfd_peer_t *session, bfd_packet_t *bfd)
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

		DEBUG("BFD %s demand mode UP / UP, sending ACK and done.",
		      session->client.shortname);
		bfd_stop_control(session);
	} else {
		bfd->demand = false;
	}

	bfd->multipoint = 0;
	bfd->detect_multi = session->detect_multi;
	bfd->length = 24;	/* auth types add to this later */

	bfd->my_disc = session->local_disc;
	bfd->your_disc = session->remote_disc;

	bfd->desired_min_tx_interval = fr_time_delta_to_usec(session->desired_min_tx_interval);
	bfd->required_min_rx_interval = fr_time_delta_to_usec(session->required_min_rx_interval);

	bfd->min_echo_rx_interval = fr_time_delta_to_usec(session->my_min_echo_rx_interval);
}


/*
 *	Send one BFD packet.
 */
static void bfd_send_packet(UNUSED fr_event_list_t *el, UNUSED fr_time_t now, void *ctx)
{
	proto_bfd_peer_t *session = ctx;
	bfd_packet_t bfd;

	bfd_control_packet_init(session, &bfd);

	bfd.poll = session->doing_poll;

	if (!bfd.demand) {
		bfd_start_packets(session);
	}

	bfd_sign(session, &bfd);

	DEBUG("BFD %s sending packet state %s",
	      session->client.shortname, fr_bfd_packet_names[session->session_state]);

	if (sendfromto(session->sockfd, &bfd, bfd.length, 0, 0,
		       (struct sockaddr *) &session->local_sockaddr, session->local_salen,
		       (struct sockaddr *) &session->remote_sockaddr, session->remote_salen) < 0) {
		ERROR("Failed sending packet: %s", fr_syserror(errno));
		fr_assert(0);
	}
}

/*
 *	Start sending packets.
 */
static void bfd_start_packets(proto_bfd_peer_t *session)
{
	uint64_t	interval, base;
	uint64_t	jitter;

	/*
	 *	Reset the timers.
	 */
	fr_event_timer_delete(&session->ev_packet);

	session->last_sent = fr_time();
	
	if (fr_time_delta_cmp(session->desired_min_tx_interval, session->remote_min_rx_interval) >= 0) {
		interval = fr_time_delta_unwrap(session->desired_min_tx_interval);
	} else {
		interval = fr_time_delta_unwrap(session->remote_min_rx_interval);

		/*
		 *	The other end doesn't want to receive control packets.  So we stop sending them.
		 */
		if (!interval) return;

	}
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

	if (fr_event_timer_in(session, session->el, &session->ev_packet,
			      fr_time_delta_wrap(interval),
			      bfd_send_packet, session) < 0) {
		fr_assert("Failed to insert event" == NULL);
	}
}


/*
 *	Start polling for the peer.
 */
static void bfd_start_poll(proto_bfd_peer_t *session)
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
static void bfd_set_desired_min_tx_interval(proto_bfd_peer_t *session, fr_time_delta_t value)
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

	session->desired_min_tx_interval = value;
	bfd_stop_control(session);
	session->doing_poll = 0;

	bfd_start_poll(session);
}


/*
 *	We failed to see a packet.
 */
static void bfd_detection_timeout(UNUSED fr_event_list_t *el, fr_time_t now, void *ctx)
{
	proto_bfd_peer_t *session = ctx;

	DEBUG("BFD %s Timeout state %s ****** ", session->client.shortname,
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
		DEBUG("BFD %s State <timeout> -> DOWN (control expired)", session->client.shortname);
		session->session_state = BFD_STATE_DOWN;
		session->local_diag =  BFD_CTRL_EXPIRED;
		bfd_trigger(session); /* @todo - send timeout state change to unlang */

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
static void bfd_set_timeout(proto_bfd_peer_t *session, fr_time_t when)
{
	fr_time_t timeout;
	uint64_t delay;

	fr_event_timer_delete(&session->ev_timeout);

	timeout = fr_time_add(when, session->detection_time);

	/*
	 *	When we SHOULD have received the next packet.
	 */
	if (session->detect_multi >= 2) {
		delay = fr_time_delta_unwrap(session->detection_time) / session->detect_multi;
	} else {
		delay = fr_time_delta_unwrap(session->detection_time);
	}
	delay += delay / 2;

	session->next_recv = fr_time_add(when, fr_time_delta_from_usec(delay));
	
	if (fr_event_timer_at(session, session->el, &session->ev_timeout,
			      timeout, bfd_detection_timeout, session) < 0) {
		fr_assert("Failed to insert event" == NULL);
	}
}


/*
 *	Start / stop control packets.
 */
static int bfd_stop_control(proto_bfd_peer_t *session)
{
	fr_event_timer_delete(&session->ev_timeout);
	fr_event_timer_delete(&session->ev_packet);
	return 1;
}

static void bfd_start_control(proto_bfd_peer_t *session)
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
	 *	We were asked to go "up" when we were alread "up" 
	 */
	if (session->remote_demand_mode &&
	    (session->session_state == BFD_STATE_UP) &&
	    (session->remote_session_state == BFD_STATE_UP) &&
	    !session->doing_poll) {
		DEBUG("BFD %s warning: asked to start UP / UP ?",
		      session->client.shortname);
		fr_assert(0 == 1);
		bfd_stop_control(session);
		return;
	}

	bfd_set_timeout(session, session->last_recv);

	if (session->ev_packet) return;


	/*
	 *	Start sending packets.
	 */
	bfd_start_packets(session);
}


int bfd_session_init(proto_bfd_peer_t *session)
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
	session->detection_time = fr_time_delta_wrap(session->detect_multi * fr_time_delta_unwrap(session->detection_time));

	return 0;
}

void bfd_session_start(proto_bfd_peer_t *session, fr_event_list_t *el, int sockfd)
{
	DEBUG("Starting BFD for %s", session->client.shortname);

	fr_assert(!session->el);

	session->el = el;
	session->sockfd = sockfd;

	bfd_start_control(session);
}
