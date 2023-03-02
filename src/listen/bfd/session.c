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


#define BFD_MAX_SECRET_LENGTH 20

#if 0
typedef struct {
	uint8_t		auth_type;
	uint8_t		auth_len;
	uint8_t		key_id;
} __attribute__ ((packed)) bfd_auth_basic_t;


typedef struct {
	uint8_t		auth_type;
	uint8_t		auth_len;
	uint8_t		key_id;
	uint8_t		password[16];
} __attribute__ ((packed)) bfd_auth_simple_t;

typedef struct {
	uint8_t		auth_type;
	uint8_t		auth_len;
	uint8_t		key_id;
	uint8_t		reserved;
	uint32_t	sequence_no;
	uint8_t		digest[MD5_DIGEST_LENGTH];
} __attribute__ ((packed)) bfd_auth_md5_t;

typedef struct {
	uint8_t		auth_type;
	uint8_t		auth_len;
	uint8_t		key_id;
	uint8_t		reserved;
	uint32_t	sequence_no;
	uint8_t		digest[SHA1_DIGEST_LENGTH];
} __attribute__ ((packed)) bfd_auth_sha1_t;

typedef union bfd_auth_t {
	bfd_auth_basic_t        basic;
	bfd_auth_simple_t	password;
	bfd_auth_md5_t		md5;
	bfd_auth_sha1_t		sha1;
} __attribute__ ((packed)) bfd_auth_t;


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

static void bfd_calc_md5(proto_bfd_peer_t *session, bfd_packet_t *bfd)
{
	bfd_auth_md5_t *md5 = &bfd->auth.md5;

	fr_assert(session->secret_len <= sizeof(md5->digest));
	fr_assert(md5->auth_len == sizeof(*md5));

	memset(md5->digest, 0, sizeof(md5->digest));
	memcpy(md5->digest, session->secret, session->secret_len);

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

static void bfd_calc_sha1(proto_bfd_peer_t *session, bfd_packet_t *bfd)
{
	fr_sha1_ctx ctx;
	bfd_auth_sha1_t *sha1 = &bfd->auth.sha1;

	fr_assert(session->secret_len <= sizeof(sha1->digest));
	fr_assert(sha1->auth_len == sizeof(*sha1));

	memset(sha1->digest, 0, sizeof(sha1->digest));
	memcpy(sha1->digest, session->secret, session->secret_len);

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
		DEBUG("BFD %d SHA1 Digest failed: **** RE-ENTER THE SECRET ON BOTH ENDS ****", session->number);
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

	if (sendto(session->socket.fd, &bfd, bfd.length, 0,
		   (struct sockaddr *) &session->remote_sockaddr,
		   session->salen) < 0) {
		ERROR("Failed sending poll response: %s", fr_syserror(errno));
	}
}


static int bfd_process(proto_bfd_peer_t *session, bfd_packet_t *bfd)
{
	if (bfd->auth_present &&
	    (session->auth_type == BFD_AUTH_RESERVED)) {
		DEBUG("BFD %d packet asked to authenticate an unauthenticated session.", session->number);
		return 0;
	}

	if (!bfd->auth_present &&
	    (session->auth_type != BFD_AUTH_RESERVED)) {
		DEBUG("BFD %d packet failed to authenticate an authenticated session.", session->number);
		return 0;
	}

	if (bfd->auth_present && !bfd_authenticate(session, bfd)) {
		return 0;
	}

	DEBUG("BFD %d processing packet", session->number);
	session->remote_disc = bfd->my_disc;
	session->remote_session_state = bfd->state;
	session->remote_demand_mode = bfd->demand;

	/*
	 *	The other end is reducing the RX interval.  Do that
	 *	now.
	 */
	if ((bfd->required_min_rx_interval < session->remote_min_rx_interval) &&
	    !session->demand_mode) {
		bfd_stop_control(session);
		bfd_start_control(session);
	}
	session->remote_min_rx_interval = bfd->required_min_rx_interval;

	session->remote_min_echo_rx_interval = bfd->min_echo_rx_interval;
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
		if (session->required_min_rx_interval >= bfd->desired_min_tx_interval) {
			session->detection_time = session->required_min_rx_interval;
		} else {
			session->detection_time = bfd->desired_min_tx_interval;
		}
	} else {
		if (session->desired_min_tx_interval >= session->remote_min_rx_interval) {
			session->detection_time = session->desired_min_tx_interval;
		} else {
			session->detection_time = session->remote_min_rx_interval;
		}
	}
	session->detection_time *= session->detect_multi;

	if (session->session_state == BFD_STATE_ADMIN_DOWN) {
		DEBUG("Discarding BFD packet (admin down)");
		return 0;
	}

	if (bfd->state == BFD_STATE_ADMIN_DOWN) {
		if (bfd->state != BFD_STATE_DOWN) {
			session->local_diag = BFD_NEIGHBOR_DOWN;
		}

		DEBUG("BFD %d State %s -> DOWN (admin down)",
		      session->number, bfd_state[session->session_state]);
		session->session_state = BFD_STATE_DOWN;
		bfd_trigger(session);

		bfd_set_desired_min_tx_interval(session, USEC);

	} else {
		switch (session->session_state) {
		case BFD_STATE_DOWN:
			switch (bfd->state) {
			case BFD_STATE_DOWN:
				DEBUG("BFD %d State DOWN -> INIT (neighbor down)",
				      session->number);
				session->session_state = BFD_STATE_INIT;
				bfd_trigger(session);

				bfd_set_desired_min_tx_interval(session, USEC);
				break;

			case BFD_STATE_INIT:
				DEBUG("BFD %d State DOWN -> UP (neighbor INIT)",
				      session->number);
				session->session_state = BFD_STATE_UP;
				bfd_trigger(session);
				break;

			default: /* don't change anything */
				break;
			}
			break;

		case BFD_STATE_INIT:
			switch (bfd->state) {
			case BFD_STATE_INIT:
			case BFD_STATE_UP:
				DEBUG("BFD %d State INIT -> UP",
				      session->number);
				session->session_state = BFD_STATE_UP;
				bfd_trigger(session);
				break;

			default: /* don't change anything */
				break;
			}
			break;

		case BFD_STATE_UP:
			switch (bfd->state) {
			case BFD_STATE_DOWN:
				session->local_diag = BFD_NEIGHBOR_DOWN;

				DEBUG("BFD %d State UP -> DOWN (neighbor down)", session->number);
				session->session_state = BFD_STATE_DOWN;
				bfd_trigger(session);

				bfd_set_desired_min_tx_interval(session, USEC);
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
		DEBUG("BFD %d demand mode UP / UP, stopping packets", session->number);
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


	if ((!session->remote_demand_mode) ||
	    (session->session_state != BFD_STATE_UP) ||
	    (session->remote_session_state != BFD_STATE_UP)) {
		bfd_start_control(session);
	}

	if (session->server_cs) {
		request_t *request;
		fr_radius_packet_t *packet, *reply;

		request = request_alloc_internal(session, NULL);
		packet = fr_radius_packet_alloc(request, 0);
		reply = fr_radius_packet_alloc(request, 0);

		bfd_request(session, request, packet);

		memset(reply, 0, sizeof(*reply));

		request->reply = reply;
		fr_socket_addr_swap(&request->reply->socket, &session->socket);

		/*
		 *	FIXME: add my state, remote state as VPs?
		 */
		if (fr_debug_lvl) {
			request->log.dst = talloc_zero(request, log_dst_t);
			request->log.dst->func = vlog_request;
			request->log.dst->uctx = &default_log;

			request->log.lvl = fr_debug_lvl;
		}
		request->component = NULL;
		request->module = NULL;

		DEBUG2("server %s {", cf_section_name2(unlang_call_current(request)));
		if (unlang_interpret_push_section(request, session->unlang, RLM_MODULE_NOTFOUND, UNLANG_TOP_FRAME) < 0) {
			talloc_free(request);
			return 0;
		}
		unlang_interpret_synchronous(unlang_interpret_event_list(request), request);
		DEBUG("}");

		/*
		 *	FIXME: grab attributes from the reply
		 *	and cache them for use in the next request.
		 */
		talloc_free(request);
	}

	return 1;
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
 *	Check if an incoming request is "ok"
 *
 *	It takes packets, not requests.  It sees if the packet looks
 *	OK.  If so, it does a number of sanity checks on it.
 */
static int bfd_socket_recv(rad_listen_t *listener)
{
	ssize_t		rcode;
	bfd_socket_t	*sock = listener->data;
	proto_bfd_peer_t	*session;
	proto_bfd_peer_t	my_session;
	struct sockaddr_storage src;
	socklen_t	sizeof_src = sizeof(src);
	bfd_packet_t	bfd;

	rcode = recvfrom(listener->fd, &bfd, sizeof(bfd), 0,
			 (struct sockaddr *)&src, &sizeof_src);
	if (rcode < 0) {
		ERROR("Failed receiving packet: %s", fr_syserror(errno));
		return 0;
	}

	if (rcode < 24) {
		DEBUG("BFD packet is too short (%d < 24)", (int) rcode);
		return 0;
	}

	if (bfd.version != 1) {
		DEBUG("BFD packet has wrong version (%d != 1)", bfd.version);
		return 0;
	}

	if (bfd.length < 24) {
		DEBUG("BFD packet has wrong length (%d < 24)", bfd.length);
		return 0;
	}

	if (bfd.length > sizeof(bfd)) {
		DEBUG("BFD packet has wrong length (%d > %zd)", bfd.length, sizeof(bfd));
		return 0;
	}

	if (bfd.auth_present) {
		if (bfd.length < 26) {
			DEBUG("BFD packet has wrong length (%d < 26)",
			      bfd.length);
			return 0;
		}

		if (bfd.length < 24 + bfd.auth.basic.auth_len) {
			DEBUG("BFD packet is too short (%d < %d)",
			      bfd.length, 24 + bfd.auth.basic.auth_len);
			return 0;

		}

		if (bfd.length != 24 + bfd.auth.basic.auth_len) {
			DEBUG("WARNING: What is the extra data?");
		}

	}

	if (bfd.detect_multi == 0) {
		DEBUG("BFD packet has detect_multi == 0");
		return 0;
	}

	if (bfd.multipoint != 0) {
		DEBUG("BFD packet has multi != 0");
		return 0;
	}

	if (bfd.my_disc == 0) {
		DEBUG("BFD packet has my_disc == 0");
		return 0;
	}

	if ((bfd.your_disc == 0) &&
	    !((bfd.state == BFD_STATE_DOWN) ||
	      (bfd.state == BFD_STATE_ADMIN_DOWN))) {
		DEBUG("BFD packet has invalid your-disc / state");
		return 0;
	}

	/*
	 *	We SHOULD use "your_disc", but what the heck.
	 */
	fr_ipaddr_from_sockaddr(&my_session.socket.inet.dst_ipaddr,
				&my_session.socket.inet.dst_port, &src, sizeof_src);

	session = fr_rb_find(sock->session_tree, &my_session);
	if (!session) {
		DEBUG("BFD unknown peer");
		return 0;
	}

	if (!event_list) {
		uint8_t *p = (uint8_t *) &bfd;
		size_t total = bfd.length;

		/*
		 *	A child has had a problem.  Do some cleanups.
		 */
		if (session->blocked) bfd_pthread_free(session);

		/*
		 *	No event list, try to create a new one.
		 */
		if (!session->el && !bfd_pthread_create(session)) {
			DEBUG("BFD %d - error trying to create child thread",
			      session->number);
			return 0;
		}

		do {
			rcode = write(session->pipefd[1], p, total);
			if ((rcode < 0) && (errno == EINTR)) continue;

			if (rcode < 0) {
				session->blocked = true;
				return 0;
			}

			total -= rcode;
			p += rcode;
		} while (total > 0);
		return 0;
	}

	return bfd_process(session, &bfd);
}

static int bfd_parse_ip_port(CONF_SECTION *cs, fr_ipaddr_t *ipaddr, uint16_t *port)
{
	int rcode;

	/*
	 *	Try IPv4 first
	 */
	memset(ipaddr, 0, sizeof(*ipaddr));
	ipaddr->addr.v4.s_addr = htonl(INADDR_NONE);
	rcode = cf_pair_parse(NULL, cs, "ipaddr", FR_ITEM_POINTER(FR_TYPE_IPV4_ADDR, ipaddr), NULL, T_INVALID);
	if (rcode < 0) return -1;

	if (rcode == 0) { /* successfully parsed IPv4 */
		ipaddr->af = AF_INET;

	} else {	/* maybe IPv6? */
		rcode = cf_pair_parse(NULL, cs, "ipv6addr", FR_ITEM_POINTER(FR_TYPE_IPV6_ADDR, ipaddr), NULL, T_INVALID);
		if (rcode < 0) return -1;

		if (rcode == 1) {
			cf_log_err(cf_section_to_item(cs),
				   "No address specified in section");
			return -1;
		}
		ipaddr->af = AF_INET6;
	}

	rcode = cf_pair_parse(NULL, cs, "port", FR_ITEM_POINTER(FR_TYPE_UINT16, port), "0", T_INVALID);
	if (rcode < 0) return -1;

	return 0;
}

/*
 *	@fixme: move some of this to parse
 */
static int bfd_init_sessions(CONF_SECTION *cs, bfd_socket_t *sock, int sockfd)
{
	CONF_ITEM *ci;
	CONF_SECTION *peer;
	uint16_t port;
	fr_ipaddr_t ipaddr;

	for (ci=cf_item_next(cs, NULL);
	     ci != NULL;
	     ci=cf_item_next(cs, ci)) {
		proto_bfd_peer_t *session, my_session;

	       if (!cf_item_is_section(ci)) continue;

	       peer = cf_item_to_section(ci);

	       if (strcmp(cf_section_name1(peer), "peer") != 0) continue;

	       if (bfd_parse_ip_port(peer, &ipaddr, &port) < 0) {
		       return -1;
	       }

	       my_session.socket.inet.dst_ipaddr = ipaddr;
	       my_session.socket.inet.dst_port = port;
	       if (fr_rb_find(sock->session_tree, &my_session) != NULL) {
		       cf_log_err(ci, "Peers must have unique IP addresses");
		       return -1;
	       }

	       session = bfd_new_session(sock, sockfd, peer, &ipaddr, port);
	       if (!session) return -1;
	}

	return 0;
}


/*
 *	None of these functions are used.
 */
static int bfd_socket_send(UNUSED rad_listen_t *listener, UNUSED request_t *request)
{
	fr_assert(0 == 1);
	return 0;
}


static int bfd_socket_encode(UNUSED rad_listen_t *listener, UNUSED request_t *request)
{
	fr_assert(0 == 1);
	return 0;
}


static int bfd_socket_decode(UNUSED rad_listen_t *listener, UNUSED request_t *request)
{
	fr_assert(0 == 1);
	return 0;
}

static fr_table_num_sorted_t const auth_types[] = {
	{ L("keyed-md5"),		BFD_AUTH_KEYED_MD5	},
	{ L("keyed-sha1"),		BFD_AUTH_KEYED_SHA1	},
	{ L("met-keyed-md5"),	BFD_AUTH_MET_KEYED_MD5	},
	{ L("met-keyed-sha1"),	BFD_AUTH_MET_KEYED_SHA1 },
	{ L("none"),		BFD_AUTH_RESERVED	},
	{ L("simple"),		BFD_AUTH_SIMPLE		}
};
static size_t auth_types_len = NUM_ELEMENTS(auth_types);

static int bfd_socket_parse(CONF_SECTION *cs, rad_listen_t *this)
{
	bfd_socket_t *sock = this->data;
	char const *auth_type_str = NULL;
	uint16_t listen_port;
	fr_ipaddr_t ipaddr;

	fr_assert(sock != NULL);

	if (bfd_parse_ip_port(cs, &ipaddr, &listen_port) < 0) {
		return -1;
	}

	sock->my_ipaddr = ipaddr;
	sock->my_port = listen_port;

	if (cf_pair_parse(sock, cs, "interface", FR_ITEM_POINTER(FR_TYPE_STRING, &sock->interface), NULL, T_INVALID) < 0) return -1;

	if (cf_pair_parse(sock, cs, "min_receive_interval", FR_ITEM_POINTER(FR_TYPE_UINT32,
			  &sock->min_rx_interval), "1000", T_BARE_WORD) < 0) return -1;
	if (cf_pair_parse(sock, cs, "max_timeouts", FR_ITEM_POINTER(FR_TYPE_UINT32,
			  &sock->max_timeouts), "3", T_BARE_WORD) < 0) return -1;
	if (cf_pair_parse(sock, cs, "demand", FR_ITEM_POINTER(FR_TYPE_BOOL, &sock->demand),
			  "no", T_DOUBLE_QUOTED_STRING) < 0) return -1;
	if (cf_pair_parse(NULL, cs, "auth_type", FR_ITEM_POINTER(FR_TYPE_STRING, &auth_type_str),
			  NULL, T_INVALID) < 0) return -1;

	if (!this->server) {
		char const *server;
		if (cf_pair_parse(sock, cs, "server", FR_ITEM_POINTER(FR_TYPE_STRING, &server),
				  NULL, T_INVALID) < 0) return -1;
		sock->server_cs = virtual_server_find(server);
	} else {
		sock->server_cs = this->server_cs;
	}

	if (sock->min_tx_interval < 100) sock->min_tx_interval = 100;
	if (sock->min_tx_interval > 10000) sock->min_tx_interval = 10000;

	if (sock->min_rx_interval < 100) sock->min_rx_interval = 100;
	if (sock->min_rx_interval > 10000) sock->min_rx_interval = 10000;

	if (sock->max_timeouts == 0) sock->max_timeouts = 1;
	if (sock->max_timeouts > 10) sock->max_timeouts = 10;

	sock->auth_type = fr_table_value_by_str(auth_types, auth_type_str, BFD_AUTH_INVALID);
	if (sock->auth_type == BFD_AUTH_INVALID) {
		ERROR("Unknown auth_type '%s'", auth_type_str);
		return -1;
	}

	if (sock->auth_type == BFD_AUTH_SIMPLE) {
		ERROR("'simple' authentication is insecure and is not supported");
		return -1;
	}

	if (sock->auth_type != BFD_AUTH_RESERVED) {
		sock->secret_len = bfd_parse_secret(cs, sock->secret);

		if (sock->secret_len == 0) {
			ERROR("Cannot have empty secret");
			return -1;
		}

		if (((sock->auth_type == BFD_AUTH_KEYED_MD5) ||
		     (sock->auth_type == BFD_AUTH_MET_KEYED_MD5)) &&
		    (sock->secret_len > 16)) {
			ERROR("Secret must be no more than 16 bytes when using MD5");
			return -1;
		}
	}

	sock->session_tree = fr_rb_inline_talloc_alloc(sock, proto_bfd_peer_t, node, bfd_session_cmp, bfd_session_free);
	if (!sock->session_tree) {
		ERROR("Failed creating session tree!");
		return -1;
	}

	/*
	 *	Find the sibling "bfd" section of the "listen" section.
	 */
	sock->unlang = cf_section_find(cf_item_to_section(cf_parent(cs)), "bfd", NULL);

	return 0;
}

	/*
	 *	Bootstrap the initial set of connections.
	 */
	if (bfd_init_sessions(cs, sock, this->fd) < 0) {
		return -1;
	}

	return 0;
}
#endif

//static int bfd_start_packets(proto_bfd_peer_t *session);
static int bfd_start_control(proto_bfd_peer_t *session);
static int bfd_stop_control(proto_bfd_peer_t *session);
//static int bfd_process(proto_bfd_peer_t *session, bfd_packet_t *bfd);
static void bfd_set_timeout(proto_bfd_peer_t *session, fr_time_t when);

static int bfd_start_packets(proto_bfd_peer_t *session);

static const char *bfd_state[] = {
	"admin-down",
	"down",
	"init",
	"up"
};


static void bfd_control_packet_init(proto_bfd_peer_t *session,
				   bfd_packet_t *bfd)
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

//	bfd_sign(session, &bfd);

	DEBUG("BFD %s sending packet state %s",
	      session->client.shortname, bfd_state[session->session_state]);

#if 0
	if (sendto(session->socket.fd, &bfd, bfd.length, 0,
		   (struct sockaddr *) &session->remote_sockaddr,
		   session->salen) < 0) {
		ERROR("Failed sending packet: %s", fr_syserror(errno));
	}
#endif
}

/*
 *	Start sending packets.
 */
static int bfd_start_packets(proto_bfd_peer_t *session)
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

	return 0;
}


/*
 *	Start polling for the peer.
 */
static int bfd_start_poll(proto_bfd_peer_t *session)
{
	if (session->doing_poll) return 0;

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
	return bfd_start_packets(session);
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
	      bfd_state[session->session_state]);

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
//		bfd_trigger(session);

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

static int bfd_start_control(proto_bfd_peer_t *session)
{
	/*
	 *	@todo - change our discriminator?
	 */

	/*
	 *	We don't expect to see remote packets, so don't do anything.
	 */
	if (fr_time_delta_unwrap(session->remote_min_rx_interval) == 0) return 0;

	if ((session->remote_disc == 0) && session->passive) return 0;

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
		return 0;
	}

	bfd_set_timeout(session, session->last_recv);

	if (session->ev_packet) return 0;

	/*
	 *	Start sending packets.
	 */
	return bfd_start_packets(session);
}


int bfd_session_init(proto_bfd_peer_t *session)
{
	session->session_state = BFD_STATE_DOWN;
	session->local_disc = fr_rand();
	session->remote_disc = 0;
	session->local_diag = BFD_DIAG_NONE;
	session->remote_min_rx_interval = fr_time_delta_wrap(0);
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

	bfd_stop_poll(session);	/* compilation hack for now */

	return 0;
}
