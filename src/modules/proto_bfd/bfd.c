/*
 * bfd.c	BFD processing.
 *
 * Version:	$Id$
 *
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
 * Copyright (C) 2012 Network RADIUS SARL <info@networkradius.com>
 */

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/protocol.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>
#include <freeradius-devel/event.h>
#include <freeradius-devel/md5.h>
#include <freeradius-devel/sha1.h>

#define USEC (1000000)
extern bool check_config;

typedef enum bfd_session_state_t {
	BFD_STATE_ADMIN_DOWN = 0,
	BFD_STATE_DOWN,
	BFD_STATE_INIT,
	BFD_STATE_UP
} bfd_session_state_t;

typedef enum bfd_diag_t {
	BFD_DIAG_NONE = 0,
	BFD_CTRL_EXPIRED,
	BFD_ECHO_FAILED,
	BFD_NEIGHBOR_DOWN,
	BFD_FORWARD_PLANE_RESET,
	BFD_PATH_DOWN,
	BFD_CONCATENATED_PATH_DOWN,
	BFD_ADMIN_DOWN,
	BFD_REVERSE_CONCAT_PATH_DOWN
} bfd_diag_t;

typedef enum bfd_auth_type_t {
	BFD_AUTH_RESERVED = 0,
	BFD_AUTH_SIMPLE,
	BFD_AUTH_KEYED_MD5,
	BFD_AUTH_MET_KEYED_MD5,
	BFD_AUTH_KEYED_SHA1,
	BFD_AUTH_MET_KEYED_SHA1,
} bfd_auth_type_t;

#define BFD_AUTH_INVALID (BFD_AUTH_MET_KEYED_SHA1 + 1)

typedef struct bfd_state_t {
	int		number;
	int		sockfd;

	fr_event_list_t *el;
	const char	*server;

#ifdef HAVE_PTHREAD_H
	bool		blocked;
	int		pipefd[2];
	pthread_t	pthread_id;
#endif

	bfd_auth_type_t auth_type;
	uint8_t		secret[20];
	size_t		secret_len;

	fr_ipaddr_t	local_ipaddr;
	fr_ipaddr_t	remote_ipaddr;
	int		local_port;
	int		remote_port;

	/*
	 *	To simplify sending the packets.
	 */
	struct sockaddr_storage remote_sockaddr;
	socklen_t	salen;

	fr_event_t	*ev_timeout;
	fr_event_t	*ev_packet;
	struct timeval	last_recv;
	struct timeval	next_recv;
	struct timeval	last_sent;

	bfd_session_state_t session_state;
	bfd_session_state_t remote_session_state;

	uint32_t	local_disc;
	uint32_t	remote_disc;

	bfd_diag_t	local_diag;

	uint32_t       	desired_min_tx_interval; /* in usec */
	uint32_t       	required_min_rx_interval;
	uint32_t	remote_min_rx_interval;
	uint32_t       	remote_min_echo_rx_interval;

	uint32_t       	next_min_tx_interval;

	bool		demand_mode;
	bool		remote_demand_mode;

	int		detect_multi;

	uint32_t       	recv_auth_seq;
	uint32_t	xmit_auth_seq;

	int		auth_seq_known;

	int		doing_poll;
	uint32_t	my_min_echo_rx_interval;

	uint32_t	detection_time;
	int		detection_timeouts;

	int		passive;
} bfd_state_t;

typedef struct bfd_auth_basic_t {
	uint8_t		auth_type;
	uint8_t		auth_len;
	uint8_t		key_id;
} bfd_auth_basic_t;


typedef struct bfd_auth_simple_t {
	uint8_t		auth_type;
	uint8_t		auth_len;
	uint8_t		key_id;
	uint8_t		password[16];
} bfd_auth_simple_t;

typedef struct bfd_auth_md5_t {
	uint8_t		auth_type;
	uint8_t		auth_len;
	uint8_t		key_id;
	uint8_t		reserved;
	uint32_t	sequence_no;
	uint8_t		digest[16];
} bfd_auth_md5_t;

typedef struct bfd_auth_sha1_t {
	uint8_t		auth_type;
	uint8_t		auth_len;
	uint8_t		key_id;
	uint8_t		reserved;
	uint32_t	sequence_no;
	uint8_t		digest[20];
} bfd_auth_sha1_t;

typedef union bfd_auth_t {
	bfd_auth_basic_t        basic;
	bfd_auth_simple_t	password;
	bfd_auth_md5_t		md5;
	bfd_auth_sha1_t		sha1;
} bfd_auth_t;


/*
 *	A packet
 */
typedef struct bfd_packet_t {
#if BYTE_ORDER == BIG_ENDIAN
	unsigned int	version : 3;
	unsigned int	diag : 5;
	unsigned int	state : 2;
	unsigned int	poll : 1;
	unsigned int	final : 1;
	unsigned int	control_plane_independent : 1;
	unsigned int	auth_present : 1;
	unsigned int	demand : 1;
	unsigned int	multipoint : 1;
#elif BYTE_ORDER == LITTLE_ENDIAN
	unsigned int	diag : 5;
	unsigned int	version : 3;

	unsigned int	multipoint : 1;
	unsigned int	demand : 1;
	unsigned int	auth_present : 1;
	unsigned int	control_plane_independent : 1;
	unsigned int	final : 1;
	unsigned int	poll : 1;
	unsigned int	state : 2;
#else
#error "Please define BYTE_ORDER"
#endif
	uint8_t		detect_multi;
	uint8_t		length;
	uint32_t	my_disc;
	uint32_t	your_disc;
	uint32_t	desired_min_tx_interval;
	uint32_t	required_min_rx_interval;
	uint32_t	min_echo_rx_interval;
	bfd_auth_t	auth;
} __attribute__ ((packed)) bfd_packet_t;


typedef struct bfd_socket_t {
	fr_ipaddr_t	my_ipaddr;
	int		my_port;

	int		number;
	const char	*server;

	int		min_tx_interval;
	int		min_rx_interval;
	int		max_timeouts;
	bool		demand;

	bfd_auth_type_t	auth_type;
	uint8_t		secret[20];
	size_t		secret_len;

	rbtree_t	*session_tree;
} bfd_socket_t;

static int bfd_start_packets(bfd_state_t *session);
static int bfd_start_control(bfd_state_t *session);
static int bfd_stop_control(bfd_state_t *session);
static void bfd_detection_timeout(void *ctx);
static int bfd_process(bfd_state_t *session, bfd_packet_t *bfd);

static fr_event_list_t *el = NULL; /* don't ask */

void bfd_init(fr_event_list_t *xel);

void bfd_init(fr_event_list_t *xel)
{
	el = xel;
}


#ifdef HAVE_PTHREAD_H
static void bfd_pthread_free(bfd_state_t *session)
{
	session->blocked = true;

	close(session->pipefd[0]);
	close(session->pipefd[1]);

	talloc_free(session->el);

	session->el = NULL;
	session->pipefd[0] = session->pipefd[1] = -1;

	session->blocked = false;
}

/*
 *	A child thread reads the packet from a pipe, and processes it.
 */
static void bfd_pipe_recv(UNUSED fr_event_list_t *xel, int fd, void *ctx)
{
	ssize_t num;
	bfd_state_t *session = ctx;
	bfd_packet_t bfd;

	if (session->blocked) return;

	/*
	 *	Read the header
	 */
	num = read(fd, &bfd, 4);
	if ((num < 4) || (bfd.length < 4)) {
	fail:
		radlog(L_ERR, "BFD Failed reading from pipe!");
		session->blocked = true;
		return;
	}

	/*
	 *	Read the rest of the packet.
	 */
	num = read(fd, ((uint8_t *) &bfd) + 4, bfd.length - 4);
	if ((num < 0) || ((num + 4) != bfd.length)) goto fail;

	bfd_process(session, &bfd);
}

/*
 *	Do nothing more than read from the sockets and process the
 *	timers.
 */
static void *bfd_child_thread(void *ctx)
{
	bfd_state_t *session = ctx;

	DEBUG("BFD %d starting child thread", session->number);
	bfd_start_control(session);

	fr_event_loop(session->el);

	bfd_pthread_free(session);

	return NULL;
}


static int bfd_pthread_create(bfd_state_t *session)
{
	int rcode;
	pthread_attr_t attr;

	if (pipe(session->pipefd) < 0) {
		radlog(L_ERR, "Failed opening pipe: %s",
		       strerror(errno));
		return 0;
	}

	session->el = fr_event_list_create(session, NULL);
	if (!session->el) {
		radlog(L_ERR, "Failed creating event list");
	close_pipes:
		close(session->pipefd[0]);
		close(session->pipefd[1]);
		session->pipefd[0] = session->pipefd[1] = -1;
		return 0;
	}

#ifdef O_NONBLOCK
	fcntl(session->pipefd[0], F_SETFL, O_NONBLOCK | FD_CLOEXEC);
	fcntl(session->pipefd[1], F_SETFL, O_NONBLOCK | FD_CLOEXEC);
#endif

	fr_event_fd_insert(session->el, 0, session->pipefd[0],
			   bfd_pipe_recv, session);


	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	/*
	 *	Create the thread detached, so that it cleans up it's
	 *	own memory when it exits.
	 *
	 *	Note that the function returns non-zero on error, NOT
	 *	-1.  The return code is the error, and errno isn't set.
	 */
	rcode = pthread_create(&session->pthread_id, &attr,
			       bfd_child_thread, session);
	if (rcode != 0) {
		talloc_free(session->el);
		session->el = NULL;
		radlog(L_ERR, "Thread create failed: %s",
		       strerror(rcode));
		goto close_pipes;
	}
	pthread_attr_destroy(&attr);

	return 1;
}
#endif	/* HAVE_PTHREAD_H */


static const char *bfd_state[] = {
	"admin-down",
	"down",
	"init",
	"up"
};


static void bfd_request(bfd_state_t *session, REQUEST *request,
		   RADIUS_PACKET *packet)
{
	memset(request, 0, sizeof(*request));
	memset(packet, 0, sizeof(*packet));

	request->packet = packet;
	request->server = session->server;
	packet->src_ipaddr = session->local_ipaddr;
	packet->src_port = session->local_port;
	packet->dst_ipaddr = session->remote_ipaddr;
	packet->dst_port = session->remote_port;
	/*	request->heap_offset = -1; */
}


static void bfd_trigger(bfd_state_t *session)
{
	RADIUS_PACKET packet;
	REQUEST request;
	char buffer[256];

	snprintf(buffer, sizeof(buffer), "server.bfd.%s",
		 bfd_state[session->session_state]);

	bfd_request(session, &request, &packet);

	exec_trigger(&request, NULL, buffer, false);
}


static void bfd_session_free(void *ctx)
{
	bfd_state_t *session = ctx;

#ifdef WITH_PTHREAD_H
	if (el != session->el) {
		/*
		 *	FIXME: this isn't particularly safe.
		 */
		bfd_pthread_free(session);
	}
#endif

	talloc_free(session);
}


static ssize_t bfd_parse_secret(CONF_SECTION *cs, uint8_t secret[20])
{
	int rcode;
	size_t len;
	char *value = NULL;

	rcode = cf_item_parse(cs, "secret", PW_TYPE_STRING_PTR, &value, NULL);
	if (rcode != 0) return 0;

	len = strlen(value);

	if ((value[0] == '0') && (value[1] == 'x')) {
		if (len > 42) {
			cf_log_err(cf_sectiontoitem(cs), "Secret is too long");
			return -1;
		}

		if ((len & 0x01) != 0) {
			cf_log_err(cf_sectiontoitem(cs), "Invalid hex length");
			return -1;
		}

		return fr_hex2bin(secret, value + 2, (len - 2) / 2);
	}

	if (len >= 20) {
		cf_log_err(cf_sectiontoitem(cs), "Secret is too long");
		return -1;
	}

	memset(secret, 0, 20);
	memcpy(secret, value, len);
	return len;
}



/*
 *	Create a new session.
 */
static bfd_state_t *bfd_new_session(bfd_socket_t *sock, int sockfd,
				    CONF_SECTION *cs,
				    const fr_ipaddr_t *ipaddr, int port)
{
	int rcode;
	bool flag;
	int number;
	bfd_state_t *session;

	session = talloc_zero(sock, bfd_state_t);

	/*
	 *	Initialize according to RFC.
	 */
	session->number = sock->number++;
	session->sockfd = sockfd;
	session->session_state = BFD_STATE_DOWN;
	session->server = sock->server;
	session->local_disc = fr_rand();
	session->remote_disc = 0;
	session->local_diag = BFD_DIAG_NONE;
	session->desired_min_tx_interval = sock->min_tx_interval * 1000;
	session->required_min_rx_interval = sock->min_rx_interval * 1000;
	session->remote_min_rx_interval = 1;
	session->demand_mode = sock->demand;
	session->remote_demand_mode = false;
	session->detect_multi = sock->max_timeouts;
	session->auth_type = BFD_AUTH_RESERVED;
	session->recv_auth_seq = 0;
	session->xmit_auth_seq = fr_rand();
	session->auth_seq_known = 0;

	/*
	 *	Allow over-riding of variables per session.
	 */
	rcode = cf_item_parse(cs, "demand", PW_TYPE_BOOLEAN, &flag, NULL);
	if (rcode == 0) {
		session->demand_mode = flag;
	}

	rcode = cf_item_parse(cs, "min_transmit_interval", PW_TYPE_INTEGER,
			      &number, NULL);
	if (rcode == 0) {
		if (number < 100) number = 100;
		if (number > 10000) number = 10000;

		session->desired_min_tx_interval = number * 1000;
	}
	rcode = cf_item_parse(cs, "min_receive_interval", PW_TYPE_INTEGER,
			      &number, NULL);
	if (rcode == 0) {
		if (number < 100) number = 100;
		if (number > 10000) number = 10000;

		session->required_min_rx_interval = number * 1000;
	}
	rcode = cf_item_parse(cs, "max_timeouts", PW_TYPE_INTEGER,
			      &number,NULL);
	if (rcode == 0) {
		if (number == 0) number = 1;
		if (number > 10) number = 10;

		session->detect_multi = number;
	}

	session->auth_type = sock->auth_type;

	/*
	 *	Parse / over-ride the secrets.
	 */
	session->secret_len = bfd_parse_secret(cs, session->secret);
	if ((session->secret_len == 0) &&
	    (session->auth_type != BFD_AUTH_RESERVED)) {
		if (sock->secret_len == 0) {
			cf_log_err(cf_sectiontoitem(cs), "auth_type requires a secret");
			talloc_free(session);
			return NULL;
		}

		session->secret_len = sock->secret_len;
		memcpy(session->secret, sock->secret, sizeof(session->secret));
	}

	/*
	 *	Initialize the detection time.
	 */
	if (!session->demand_mode) {
		session->detection_time = session->required_min_rx_interval;
	} else {
		session->detection_time = session->desired_min_tx_interval;
	}
	session->detection_time *= session->detect_multi;

	/*
	 *	And finally remember the session.
	 */
	session->remote_ipaddr = *ipaddr;
	session->remote_port = port;

	session->local_ipaddr = sock->my_ipaddr;
	session->local_port = sock->my_port;

	fr_ipaddr2sockaddr(ipaddr, port,
			   &session->remote_sockaddr, &session->salen);

	if (!rbtree_insert(sock->session_tree, session)) {
		radlog(L_ERR, "FAILED creating new session!");
		talloc_free(session);
		return NULL;
	}

	bfd_trigger(session);

	/*
	 *	Check for threaded / non-threaded operation.
	 */
	if (el) {
		session->el = el;

		bfd_start_control(session);

#ifdef HAVE_PTHREAD_H
		session->pipefd[0] = session->pipefd[1] = -1;
		session->pthread_id = pthread_self();
	} else {
		if (!bfd_pthread_create(session)) {
			rbtree_deletebydata(sock->session_tree, session);
			talloc_free(session);
			return NULL;
		}
#endif
	}

	return session;
}


static int bfd_verify_sequence(bfd_state_t *session, uint32_t sequence_no,
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

static void bfd_calc_md5(bfd_state_t *session, bfd_packet_t *bfd)
{
	FR_MD5_CTX ctx;
	bfd_auth_md5_t *md5 = &bfd->auth.md5;

	rad_assert(session->secret_len <= sizeof(md5->digest));
	rad_assert(md5->auth_len == sizeof(*md5));

	memset(md5->digest, 0, sizeof(md5->digest));
	memcpy(md5->digest, session->secret, session->secret_len);

	fr_MD5Init(&ctx);
	fr_MD5Update(&ctx, (const uint8_t *) bfd, bfd->length);
	fr_MD5Final(md5->digest, &ctx);
}

static void bfd_auth_md5(bfd_state_t *session, bfd_packet_t *bfd)
{
	bfd_auth_md5_t *md5 = &bfd->auth.md5;

	md5->auth_type = session->auth_type;
	md5->auth_len = sizeof(*md5);
	bfd->length += md5->auth_len;

	md5->key_id = 0;
	md5->sequence_no = session->xmit_auth_seq++;

	bfd_calc_md5(session, bfd);
}

static int bfd_verify_md5(bfd_state_t *session, bfd_packet_t *bfd)
{
	int rcode;
	bfd_auth_md5_t *md5 = &bfd->auth.md5;
	uint8_t digest[sizeof(md5->digest)];

	if (md5->auth_len != sizeof(*md5)) return 0;

	if (md5->key_id != 0) return 0;

	memcpy(digest, md5->digest, sizeof(digest));

	bfd_calc_md5(session, bfd);
	rcode = rad_digest_cmp(digest, md5->digest, sizeof(digest));

	memcpy(md5->digest, digest, sizeof(md5->digest)); /* pedantic */

	if (rcode != 0) {
		DEBUG("BFD %d MD5 Digest failed: **** RE-ENTER THE SECRET ON BOTH ENDS ****", session->number);
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

static void bfd_calc_sha1(bfd_state_t *session, bfd_packet_t *bfd)
{
	fr_SHA1_CTX ctx;
	bfd_auth_sha1_t *sha1 = &bfd->auth.sha1;

	rad_assert(session->secret_len <= sizeof(sha1->digest));
	rad_assert(sha1->auth_len == sizeof(*sha1));

	memset(sha1->digest, 0, sizeof(sha1->digest));
	memcpy(sha1->digest, session->secret, session->secret_len);

	fr_SHA1Init(&ctx);
	fr_SHA1Update(&ctx, (const uint8_t *) bfd, bfd->length);
	fr_SHA1Final(sha1->digest, &ctx);
}

static void bfd_auth_sha1(bfd_state_t *session, bfd_packet_t *bfd)
{
	bfd_auth_sha1_t *sha1 = &bfd->auth.sha1;

	sha1->auth_type = session->auth_type;
	sha1->auth_len = sizeof(*sha1);
	bfd->length += sha1->auth_len;

	sha1->key_id = 0;
	sha1->sequence_no = session->xmit_auth_seq++;

	bfd_calc_sha1(session, bfd);
}

static int bfd_verify_sha1(bfd_state_t *session, bfd_packet_t *bfd)
{
	int rcode;
	bfd_auth_sha1_t *sha1 = &bfd->auth.sha1;
	uint8_t digest[sizeof(sha1->digest)];

	if (sha1->auth_len != sizeof(*sha1)) return 0;

	if (sha1->key_id != 0) return 0;

	memcpy(digest, sha1->digest, sizeof(digest));

	bfd_calc_sha1(session, bfd);
	rcode = rad_digest_cmp(digest, sha1->digest, sizeof(digest));

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


static int bfd_authenticate(bfd_state_t *session, bfd_packet_t *bfd)
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

static void bfd_control_packet_init(bfd_state_t *session,
				   bfd_packet_t *bfd)
{
	memset(bfd, 0, sizeof(*bfd));

	bfd->version = 1;
	bfd->diag = session->local_diag;
	bfd->state = session->session_state;
	bfd->poll = 0;	/* fixed by poll response */
	bfd->final = 0;	/* fixed by poll response */
	bfd->control_plane_independent = 0;

	if (session->auth_type == BFD_AUTH_RESERVED) {
		bfd->auth_present = 0;
	} else {
		bfd->auth_present = 1;
	}

	/*
	 *	If we're UP / UP, signal that we've entered demand
	 *	mode, and stop sending packets.
	 */
	if (session->demand_mode &&
	    (session->session_state == BFD_STATE_UP) &&
	    (session->remote_session_state == BFD_STATE_UP)) {
		bfd->demand = true;

		DEBUG("BFD %d demand mode UP / UP, sending ACK and done.",
		      session->number);
		bfd_stop_control(session);
	} else {
		bfd->demand = false;
	}

	bfd->multipoint = 0;
	bfd->detect_multi = session->detect_multi;
	bfd->length = 24;	/* auth types add to this later */

	bfd->my_disc = session->local_disc;
	bfd->your_disc = session->remote_disc;

	bfd->desired_min_tx_interval = session->desired_min_tx_interval;
	bfd->required_min_rx_interval = session->required_min_rx_interval;

	bfd->min_echo_rx_interval = session->my_min_echo_rx_interval;
}


static void bfd_sign(bfd_state_t *session, bfd_packet_t *bfd)
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
 *	Send a packet.
 */
static void bfd_send_packet(void *ctx)
{
	bfd_state_t *session = ctx;
	bfd_packet_t bfd;

	bfd_control_packet_init(session, &bfd);

	if (session->doing_poll) {
		bfd.poll = 1;
	}

	if (!bfd.demand) {
		bfd_start_packets(session);
	}

	bfd_sign(session, &bfd);

	DEBUG("BFD %d sending packet state %s",
	      session->number, bfd_state[session->session_state]);
	if (sendto(session->sockfd, &bfd, bfd.length, 0,
		   (struct sockaddr *) &session->remote_sockaddr,
		   session->salen) < 0) {
		radlog(L_ERR, "Failed sending packet: %s",
		       strerror(errno));
	}
}

static int bfd_start_packets(bfd_state_t *session)
{
	uint32_t interval, base;
	uint64_t jitter;
	struct timeval now;

	/*
	 *	Reset the timers.
	 */
	fr_event_delete(session->el, &session->ev_packet);

	gettimeofday(&session->last_sent, NULL);
	now = session->last_sent;

	if (session->desired_min_tx_interval >= session->remote_min_rx_interval) {
		interval = session->desired_min_tx_interval;
	} else {
		interval = session->remote_min_rx_interval;
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

	if (interval >= USEC) {
		now.tv_sec += interval / USEC;
	}
	now.tv_usec += interval % USEC;
	if (now.tv_usec >= USEC) {
		now.tv_sec++;
		now.tv_usec -= USEC;
	}

	if (!fr_event_insert(session->el, bfd_send_packet, session, &now,
			     &session->ev_packet)) {
		rad_assert("Failed to insert event" == NULL);
	}

	return 0;
}


static void bfd_set_timeout(bfd_state_t *session, struct timeval *when)
{
	struct timeval now = *when;

	fr_event_delete(session->el, &session->ev_timeout);

	if (session->detection_time >= USEC) {
		now.tv_sec += session->detection_time / USEC;
	}
	now.tv_usec += session->detection_time % USEC;
	if (now.tv_usec >= USEC) {
		now.tv_sec++;
		now.tv_usec -= USEC;
	}

	if (session->detect_multi >= 2) {
		uint32_t delay;

		session->next_recv = *when;
		delay = session->detection_time / session->detect_multi;
		delay += delay / 2;

		if (delay > USEC) {
			session->next_recv.tv_sec += delay / USEC;
		}
		session->next_recv.tv_usec += delay % USEC;
		if (session->next_recv.tv_usec >= USEC) {
			session->next_recv.tv_sec++;
			session->next_recv.tv_usec -= USEC;
		}
	}

	if (!fr_event_insert(session->el, bfd_detection_timeout, session, &now,
			     &session->ev_timeout)) {
		rad_assert("Failed to insert event" == NULL);
	}
}


static int bfd_start_control(bfd_state_t *session)
{
	if (session->remote_min_rx_interval == 0) return 0;

	if ((session->remote_disc == 0) && session->passive) return 0;

	if (session->remote_demand_mode &&
	    (session->session_state == BFD_STATE_UP) &&
	    (session->remote_session_state == BFD_STATE_UP) &&
	    !session->doing_poll) {
		DEBUG("BFD %d warning: asked to start UP / UP ?",
		      session->number);
		rad_assert(0 == 1);
		bfd_stop_control(session);
		return 0;
	}

	bfd_set_timeout(session, &session->last_recv);

	if (session->ev_packet) return 0;

	return bfd_start_packets(session);
}

static int bfd_stop_control(bfd_state_t *session)
{
	fr_event_delete(session->el, &session->ev_timeout);
	fr_event_delete(session->el, &session->ev_packet);
	return 1;
}


static int bfd_start_poll(bfd_state_t *session)
{
	if (session->doing_poll) return 0;

	/*
	 *	Already sending packets.  Reset the timers and set the
	 *	poll bit.
	 */
	if (!session->remote_demand_mode) {
		bfd_stop_control(session);
	}

	session->doing_poll = 1;

	/*
	 *	Send POLL packets, even if we're not sending CONTROL
	 *	packets.
	 */
	return bfd_start_packets(session);
}

static int bfd_stop_poll(bfd_state_t *session)
{
	if (!session->doing_poll) return 0;

	/*
	 *	We tried to increase the min_tx during a polling
	 *	sequence.  That isn't kosher, so we instead waited
	 *	until now.
	 */
	if (session->next_min_tx_interval) {
		session->desired_min_tx_interval = session->next_min_tx_interval;
		session->next_min_tx_interval = 0;
	}

	/*
	 *	Already sending packets.  Clear the poll bit and
	 *	re-set the timers.
	 */
	if (!session->remote_demand_mode) {
		rad_assert(session->ev_timeout != NULL);
		rad_assert(session->ev_packet != NULL);
		session->doing_poll = 0;

		bfd_stop_control(session);
		bfd_start_control(session);
		return 1;
	}

	session->doing_poll = 0;

	return bfd_stop_control(session);
}

static void bfd_set_desired_min_tx_interval(bfd_state_t *session,
					    uint32_t value)
{
	/*
	 *	Increasing the value: don't change it if we're already
	 *	polling.
	 */
	if (session->doing_poll &&
	    (session->session_state == BFD_STATE_UP) &&
	    (value > session->desired_min_tx_interval)) {
		session->next_min_tx_interval = value;
		return;
	}

	if (session->session_state != BFD_STATE_UP) {
		if (value < USEC) value = USEC;
	}

	session->desired_min_tx_interval = value;
	bfd_stop_control(session);
	session->doing_poll = 0;

	bfd_start_poll(session);
}


static void bfd_detection_timeout(void *ctx)
{
	bfd_state_t *session = ctx;
	struct timeval now;

	DEBUG("BFD %d Timeout state %s ****** ", session->number,
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
		DEBUG("BFD %d State <timeout> -> DOWN (control expired)", session->number);
		session->session_state = BFD_STATE_DOWN;
		session->local_diag =  BFD_CTRL_EXPIRED;
		bfd_trigger(session);

		bfd_set_desired_min_tx_interval(session, USEC);
	}

	session->remote_disc = 0;

	if (session->detection_timeouts >= 2) {
		session->auth_seq_known = 0;
	}

	session->detection_timeouts++;

	gettimeofday(&now, NULL);

	bfd_set_timeout(session, &now);
}


/*
 *	Send an immediate response to a poll request.
 *
 *	Note that this doesn't affect our "last_sent" timer.
 *	That's set only when we intend to send a packet.
 */
static void bfd_poll_response(bfd_state_t *session)
{
	bfd_packet_t bfd;

	bfd_control_packet_init(session, &bfd);
	bfd.poll = 0;		/* Section 6.5 */
	bfd.final = 1;

	/*
	 *	TO DO: rate limit poll responses.
	 */

	bfd_sign(session, &bfd);

	if (sendto(session->sockfd, &bfd, bfd.length, 0,
		   (struct sockaddr *) &session->remote_sockaddr,
		   session->salen) < 0) {
		radlog(L_ERR, "Failed sending poll response: %s",
		       strerror(errno));
	}
}


static int bfd_process(bfd_state_t *session, bfd_packet_t *bfd)
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

				DEBUG("BFD %d State UP -> DOWN (neighbor down)",
				      session->number);
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
		DEBUG("BFD %d demand mode UP / UP, stopping packets",
		      session->number);
		bfd_stop_control(session);
	}

	if (bfd->poll) {
		bfd_poll_response(session);
	}

	/*
	 *	We've received the packet for the purpose of Section
	 *	6.8.4.
	 */
	gettimeofday(&session->last_recv, NULL);

	/*
	 *	We've received a packet, but missed the previous one.
	 *	Warn about it.
	 */
	if ((session->detect_multi >= 2) &&
	    ((session->last_recv.tv_sec > session->next_recv.tv_sec) ||
	     ((session->last_recv.tv_sec == session->next_recv.tv_sec) &&
	      (session->last_recv.tv_usec > session->next_recv.tv_usec)))) {
		RADIUS_PACKET packet;
		REQUEST request;

		bfd_request(session, &request, &packet);

		exec_trigger(&request, NULL, "server.bfd.warn", false);
	}


	if ((!session->remote_demand_mode) ||
	    (session->session_state != BFD_STATE_UP) ||
	    (session->remote_session_state != BFD_STATE_UP)) {
		bfd_start_control(session);
	}

	if (session->server) {
		REQUEST *request;
		RADIUS_PACKET *packet, *reply;

		request = request_alloc(session);
		packet = rad_alloc(request, 0);
		reply = rad_alloc(request, 0);

		bfd_request(session, request, packet);

		memset(reply, 0, sizeof(*reply));

		request->reply = reply;
		request->reply->src_ipaddr = session->remote_ipaddr;
		request->reply->src_port = session->remote_port;
		request->reply->dst_ipaddr = session->local_ipaddr;
		request->reply->dst_port = session->local_port;

		/*
		 *	FIXME: add my state, remote state as VPs?
		 */

		if (debug_flag) {
			request->options = RAD_REQUEST_OPTION_DEBUG2;
			request->radlog = radlog_request;
		}
		request->component = "";
		request->module = "";

		DEBUG2("server %s {", request->server);
		process_authorize(0, request);
		DEBUG("}");

		/*
		 *	FIXME: grab attributes from the reply
		 *	and cache them for use in the next request.
		 */

		request_free(&request);
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
	bfd_state_t	*session;
	bfd_state_t	my_session;
	struct sockaddr_storage src;
	socklen_t	sizeof_src = sizeof(src);
	bfd_packet_t	bfd;

	rcode = recvfrom(listener->fd, &bfd, sizeof(bfd), 0,
			 (struct sockaddr *)&src, &sizeof_src);
	if (rcode < 0) {
		radlog(L_ERR, "Failed receiving packet: %s",
		       strerror(errno));
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

	if (bfd.length < (unsigned) 24) {
		DEBUG("BFD packet has wrong length (%d < 24)", bfd.length);
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
	fr_sockaddr2ipaddr(&src, sizeof_src,
			   &my_session.remote_ipaddr,
			   &my_session.remote_port);

	session = rbtree_finddata(sock->session_tree, &my_session);
	if (!session) {
		DEBUG("BFD unknown peer");
		return 0;
	}

#ifdef HAVE_PTHREAD_H
	if (!el) {
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
#endif

	return bfd_process(session, &bfd);
}

static int bfd_parse_ip_port(CONF_SECTION *cs, fr_ipaddr_t *ipaddr, int *port)
{
	int rcode;

	/*
	 *	Try IPv4 first
	 */
	memset(ipaddr, 0, sizeof(*ipaddr));
	ipaddr->ipaddr.ip4addr.s_addr = htonl(INADDR_NONE);
	rcode = cf_item_parse(cs, "ipaddr", PW_TYPE_IPADDR,
			      &ipaddr->ipaddr.ip4addr, NULL);
	if (rcode < 0) return -1;

	if (rcode == 0) { /* successfully parsed IPv4 */
		ipaddr->af = AF_INET;

	} else {	/* maybe IPv6? */
		rcode = cf_item_parse(cs, "ipv6addr", PW_TYPE_IPV6ADDR,
				      &ipaddr->ipaddr.ip6addr, NULL);
		if (rcode < 0) return -1;

		if (rcode == 1) {
			cf_log_err(cf_sectiontoitem(cs),
				   "No address specified in section");
			return -1;
		}
		ipaddr->af = AF_INET6;
	}

	rcode = cf_item_parse(cs, "port", PW_TYPE_INTEGER,
			      port, "0");
	if (rcode < 0) return -1;

	if ((*port < 0) || (*port > 65535)) {
			cf_log_err(cf_sectiontoitem(cs),
				   "Invalid value for \"port\"");
			return -1;
	}

	return 0;
}


static int bfd_init_sessions(CONF_SECTION *cs, bfd_socket_t *sock, int sockfd)
{
	CONF_ITEM *ci;
	CONF_SECTION *peer;
	int port;
	fr_ipaddr_t ipaddr;

	for (ci=cf_item_find_next(cs, NULL);
	     ci != NULL;
	     ci=cf_item_find_next(cs, ci)) {
		bfd_state_t *session, my_session;

	       if (!cf_item_is_section(ci)) continue;

	       peer = cf_itemtosection(ci);

	       if (strcmp(cf_section_name1(peer), "peer") != 0) continue;

	       if (bfd_parse_ip_port(peer, &ipaddr, &port) < 0) {
		       return -1;
	       }

	       my_session.remote_ipaddr = ipaddr;
	       my_session.remote_port = port;
	       if (rbtree_finddata(sock->session_tree, &my_session) != NULL) {
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
static int bfd_socket_send(UNUSED rad_listen_t *listener, UNUSED REQUEST *request)
{
	rad_assert(0 == 1);
	return 0;
}


static int bfd_socket_encode(UNUSED rad_listen_t *listener, UNUSED REQUEST *request)
{
	rad_assert(0 == 1);
	return 0;
}


static int bfd_socket_decode(UNUSED rad_listen_t *listener, UNUSED REQUEST *request)
{
	rad_assert(0 == 1);
	return 0;
}

static int bfd_session_cmp(const void *one, const void *two)
{
	const bfd_state_t *a = one;
	const bfd_state_t *b = two;

	return fr_ipaddr_cmp(&a->remote_ipaddr, &b->remote_ipaddr);
}

static void bfd_socket_free(rad_listen_t *this)
{
	bfd_socket_t *sock = this->data;

	rbtree_free(sock->session_tree);
	talloc_free(sock);
	this->data = NULL;
}

const FR_NAME_NUMBER auth_types[] = {
	{ "none", BFD_AUTH_RESERVED },
	{ "simple", BFD_AUTH_SIMPLE },
	{ "keyed-md5", BFD_AUTH_KEYED_MD5 },
	{ "met-keyed-md5", BFD_AUTH_MET_KEYED_MD5 },
	{ "keyed-sha1", BFD_AUTH_KEYED_SHA1 },
	{ "met-keyed-sha1", BFD_AUTH_MET_KEYED_SHA1 },

	{ NULL, 0 }
};


static int bfd_socket_parse(CONF_SECTION *cs, rad_listen_t *this)
{
	int rcode;
	bfd_socket_t *sock = this->data;
	char *auth_type_str = NULL;
	int listen_port;
	fr_ipaddr_t ipaddr;

	rad_assert(sock != NULL);

	/* largely copied from common_socket_parse */
	this->cs = cs;

	if (bfd_parse_ip_port(cs, &ipaddr, &listen_port) < 0) {
		return -1;
	}

	sock->my_ipaddr = ipaddr;
	sock->my_port = listen_port;

	/* end of code copied from common_socket_parse */

	/* code copied from listen_init() <sigh> */
	/*
	 *	Don't open sockets if we're checking the config.
	 */
	if (check_config) {
		this->fd = -1;
		return 0;
	}

	/*
	 *	Copy fr_socket() here, as we may need to bind to a device.
	 */
	this->fd = socket(sock->my_ipaddr.af, SOCK_DGRAM, 0);
	if (this->fd < 0) {
		char buffer[256];

		this->print(this, buffer, sizeof(buffer));

		radlog(L_ERR, "Failed opening %s: %s", buffer, strerror(errno));
		return -1;
	}

#ifdef FD_CLOEXEC
	/*
	 *	We don't want child processes inheriting these
	 *	file descriptors.
	 */
	rcode = fcntl(this->fd, F_GETFD);
	if (rcode >= 0) {
		if (fcntl(this->fd, F_SETFD, rcode | FD_CLOEXEC) < 0) {
			close(this->fd);
			radlog(L_ERR, "Failed setting close on exec: %s", strerror(errno));
			return -1;
		}
	}
#endif

#ifdef HAVE_STRUCT_SOCKADDR_IN6
	if (sock->my_ipaddr.af == AF_INET6) {
		/*
		 *	Listening on '::' does NOT get you IPv4 to
		 *	IPv6 mapping.  You've got to listen on an IPv4
		 *	address, too.  This makes the rest of the server
		 *	design a little simpler.
		 */
#ifdef IPV6_V6ONLY

		if (IN6_IS_ADDR_UNSPECIFIED(&sock->my_ipaddr.ipaddr.ip6addr)) {
			int on = 1;

			setsockopt(this->fd, IPPROTO_IPV6, IPV6_V6ONLY,
				   (char *)&on, sizeof(on));
		}
#endif /* IPV6_V6ONLY */
	}
#endif /* HAVE_STRUCT_SOCKADDR_IN6 */

	/*
	 *	May be binding to priviledged ports.
	 */
	if (sock->my_port != 0) {
		struct sockaddr_storage salocal;
		socklen_t	salen;

#ifdef SO_REUSEADDR
		int on = 1;

		if (setsockopt(this->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
			radlog(L_ERR, "Can't set re-use address option: %s\n",
			       strerror(errno));
			return -1;
		}
#endif

		/*
		 *	Set up sockaddr stuff.
		 */
		if (!fr_ipaddr2sockaddr(&sock->my_ipaddr, sock->my_port, &salocal, &salen)) {
			close(this->fd);
			return -1;
		}

		fr_suid_up();
		rcode = bind(this->fd, (struct sockaddr *) &salocal, salen);
		fr_suid_down();
		if (rcode < 0) {
			char buffer[256];
			close(this->fd);

			this->print(this, buffer, sizeof(buffer));
			radlog(L_ERR, "Failed binding to %s: %s\n",
			       buffer, strerror(errno));
			return -1;
		}

		/*
		 *	FreeBSD jail issues.  We bind to 0.0.0.0, but the
		 *	kernel instead binds us to a 1.2.3.4.  If this
		 *	happens, notice, and remember our real IP.
		 */
		{
			struct sockaddr_storage	src;
			socklen_t	        sizeof_src = sizeof(src);

			memset(&src, 0, sizeof_src);
			if (getsockname(this->fd, (struct sockaddr *) &src,
					&sizeof_src) < 0) {
				radlog(L_ERR, "Failed getting socket name: %s",
				       strerror(errno));
				return -1;
			}

			if (!fr_sockaddr2ipaddr(&src, sizeof_src,
						&sock->my_ipaddr, &sock->my_port)) {
				radlog(L_ERR, "Socket has unsupported address family");
				return -1;
			}
		}
	}

	if (fr_nonblock(this->fd) < 0) {
		close(this->fd);
		radlog(L_ERR, "Failed setting non-blocking on socket: %s",
		       strerror(errno));
		return -1;
	}

	/* end of code copied from listen_init() */

	cf_item_parse(cs, "min_transmit_interval", PW_TYPE_INTEGER,
		      &sock->min_tx_interval, "1000");
	cf_item_parse(cs, "min_receive_interval", PW_TYPE_INTEGER,
		      &sock->min_rx_interval, "1000");
	cf_item_parse(cs, "max_timeouts", PW_TYPE_INTEGER,
		      &sock->max_timeouts, "3");
	cf_item_parse(cs, "demand", PW_TYPE_BOOLEAN,
		      &sock->demand, "no");
	cf_item_parse(cs, "auth_type", PW_TYPE_STRING_PTR,
		      &auth_type_str, NULL);

	if (!this->server) {
		cf_item_parse(cs, "server", PW_TYPE_STRING_PTR,
			      &sock->server, NULL);
	} else {
		sock->server = this->server;
	}

	if (sock->min_tx_interval < 100) sock->min_tx_interval = 100;
	if (sock->min_tx_interval > 10000) sock->min_tx_interval = 10000;

	if (sock->min_rx_interval < 100) sock->min_rx_interval = 100;
	if (sock->min_rx_interval > 10000) sock->min_rx_interval = 10000;

	if (sock->max_timeouts == 0) sock->max_timeouts = 1;
	if (sock->max_timeouts > 10) sock->max_timeouts = 10;

	sock->auth_type = fr_str2int(auth_types, auth_type_str,
				     BFD_AUTH_INVALID);
	if (sock->auth_type == BFD_AUTH_INVALID) {
		radlog(L_ERR, "Unknown auth_type '%s'", auth_type_str);
		exit(1);
	}

	if (sock->auth_type == BFD_AUTH_SIMPLE) {
		radlog(L_ERR, "'simple' authentication is insecure and is not supported.");
		exit(1);
	}

	if (sock->auth_type != BFD_AUTH_RESERVED) {
		sock->secret_len = bfd_parse_secret(cs, sock->secret);

		if (sock->secret_len == 0) {
			radlog(L_ERR, "Cannot have empty secret");
			exit(1);
		}

		if (((sock->auth_type == BFD_AUTH_KEYED_MD5) ||
		     (sock->auth_type == BFD_AUTH_MET_KEYED_MD5)) &&
		    (sock->secret_len > 16)) {
			radlog(L_ERR, "Secret must be no more than 16 bytes when using MD5");
			exit(1);
		}
	}


	sock->session_tree = rbtree_create(bfd_session_cmp, bfd_session_free, 0);
	if (!sock->session_tree) {
		radlog(L_ERR, "Failed creating session tree!");
		exit(1);
	}

	/*
	 *	Bootstrap the initial set of connections.
	 */
	if (bfd_init_sessions(cs, sock, this->fd) < 0) {
		exit(1);
	}

	return 0;
}

static int bfd_socket_print(const rad_listen_t *this, char *buffer, size_t bufsize)
{
	size_t len;
	bfd_socket_t *sock = this->data;

#define FORWARD len = strlen(buffer); if (len >= (bufsize + 1)) return 0;buffer += len;bufsize -= len

	strlcpy(buffer, "bfd address ", bufsize);
	FORWARD;

	if ((sock->my_ipaddr.af == AF_INET) &&
	    (sock->my_ipaddr.ipaddr.ip4addr.s_addr == htonl(INADDR_ANY))) {
		strlcpy(buffer, "*", bufsize);
	} else {
		ip_ntoh(&sock->my_ipaddr, buffer, bufsize);
	}
	FORWARD;

	strlcpy(buffer, " port ", bufsize);
	FORWARD;

	snprintf(buffer, bufsize, "%d", sock->my_port);
	FORWARD;

	return 1;
}

fr_protocol_t proto_bfd = {
	RLM_MODULE_INIT,
	"bfd",
	sizeof(bfd_socket_t),
	NULL,
	bfd_socket_parse, bfd_socket_free,
	bfd_socket_recv, bfd_socket_send,
	bfd_socket_print, bfd_socket_encode, bfd_socket_decode
};
