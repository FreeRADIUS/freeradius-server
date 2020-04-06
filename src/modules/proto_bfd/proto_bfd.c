/*
 * proto_bfd.c	BFD processing.
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
 * @copyright 2012 Network RADIUS SARL (legal@networkradius.com)
 */

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/server/rad_assert.h>

#include <freeradius-devel/unlang/base.h>

#include <freeradius-devel/util/event.h>
#include <freeradius-devel/util/md5.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/rand.h>
#include <freeradius-devel/util/sha1.h>
#include <freeradius-devel/util/socket.h>
#include <freeradius-devel/util/time.h>

#define BFD_MAX_SECRET_LENGTH 20

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

typedef struct {
	int		number;
	int		sockfd;

	fr_event_list_t *el;
	CONF_SECTION	*server_cs;
	CONF_SECTION	*unlang;

	bool		blocked;
	int		pipefd[2];
	pthread_t	pthread_id;

	bfd_auth_type_t auth_type;
	uint8_t		secret[BFD_MAX_SECRET_LENGTH];
	size_t		secret_len;

	fr_ipaddr_t	local_ipaddr;
	fr_ipaddr_t	remote_ipaddr;
	uint16_t	local_port;
	uint16_t	remote_port;

	/*
	 *	To simplify sending the packets.
	 */
	struct sockaddr_storage remote_sockaddr;
	socklen_t	salen;

	fr_event_timer_t const	*ev_timeout;
	fr_event_timer_t const	*ev_packet;
	fr_time_t	last_recv;
	fr_time_t	next_recv;
	fr_time_t	last_sent;

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


/*
 *	A packet
 */
typedef struct {
#ifdef WORDS_BIGENDIAN
	unsigned int	version : 3;
	unsigned int	diag : 5;
	unsigned int	state : 2;
	unsigned int	poll : 1;
	unsigned int	final : 1;
	unsigned int	control_plane_independent : 1;
	unsigned int	auth_present : 1;
	unsigned int	demand : 1;
	unsigned int	multipoint : 1;
#else
	unsigned int	diag : 5;
	unsigned int	version : 3;

	unsigned int	multipoint : 1;
	unsigned int	demand : 1;
	unsigned int	auth_present : 1;
	unsigned int	control_plane_independent : 1;
	unsigned int	final : 1;
	unsigned int	poll : 1;
	unsigned int	state : 2;
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


typedef struct {
	fr_ipaddr_t	my_ipaddr;
	uint16_t	my_port;

	char		const *interface;

	int		number;
	CONF_SECTION	*server_cs;
	CONF_SECTION	*unlang;

	uint32_t	min_tx_interval;
	uint32_t	min_rx_interval;
	uint32_t	max_timeouts;
	bool		demand;

	bfd_auth_type_t	auth_type;
	uint8_t		secret[BFD_MAX_SECRET_LENGTH];
	size_t		secret_len;

	rbtree_t	*session_tree;
} bfd_socket_t;

static fr_dict_t const *dict_bfd;

extern fr_dict_autoload_t proto_bfd_dict[];
fr_dict_autoload_t proto_bfd_dict[] = {
	{ .out = &dict_bfd, .proto = "bfd" },
	{ NULL }
};

static int bfd_start_packets(bfd_state_t *session);
static int bfd_start_control(bfd_state_t *session);
static int bfd_stop_control(bfd_state_t *session);
static void bfd_detection_timeout(UNUSED fr_event_list_t *eel, fr_time_t now, void *ctx);
static int bfd_process(bfd_state_t *session, bfd_packet_t *bfd);

static fr_event_list_t *event_list = NULL; /* don't ask */

void bfd_init(fr_event_list_t *xel);

void bfd_init(fr_event_list_t *xel)
{
	event_list = xel;
}

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
static void bfd_pipe_recv(UNUSED fr_event_list_t *xel, int fd, UNUSED int flags, void *ctx)
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
		ERROR("BFD Failed reading from pipe!");
		session->blocked = true;
		return;
	}

	/*
	 *	This is already checked in the caller, but what the heck...
	 */
	if (bfd.length > sizeof(bfd)) goto fail;

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
	pthread_attr_t attr;

	if (pipe(session->pipefd) < 0) {
		ERROR("Failed opening pipe: %s", fr_syserror(errno));
		return 0;
	}

	session->el = fr_event_list_alloc(session, NULL, NULL);
	if (!session->el) {
		ERROR("Failed creating event list");
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

	if (fr_event_fd_insert(session, session->el, session->pipefd[0],
			       bfd_pipe_recv,
			       NULL,
			       NULL,
			       session) < 0) {
		PERROR("Failed inserting file descriptor into event list");
		goto close_pipes;
	}

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	/*
	 *	Create the thread detached, so that it cleans up it's
	 *	own memory when it exits.
	 *
	 *	Note that the function returns non-zero on error, NOT
	 *	-1.  The return code is the error, and errno isn't set.
	 */
	if (fr_schedule_pthread_create(&session->pthread_id, bfd_child_thread, session) < 0) {
		talloc_free(session->el);
		session->el = NULL;
		PERROR("Thread create failed");
		goto close_pipes;
	}
	pthread_attr_destroy(&attr);

	return 1;
}

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
	request->server_cs = session->server_cs;
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

	trigger_exec(&request, NULL, buffer, false, NULL);
}


static void bfd_session_free(void *ctx)
{
	bfd_state_t *session = ctx;

	if (event_list != session->el) {
		/*
		 *	FIXME: this isn't particularly safe.
		 */
		bfd_pthread_free(session);
	}

	talloc_free(session);
}


static ssize_t bfd_parse_secret(CONF_SECTION *cs, uint8_t secret[BFD_MAX_SECRET_LENGTH])
{
	int rcode;
	size_t len;
	char const *value = NULL;

	rcode = cf_pair_parse(NULL, cs, "secret", FR_ITEM_POINTER(FR_TYPE_STRING, &value), NULL, T_INVALID);
	if (rcode != 0) return 0;

	len = strlen(value);

	if ((value[0] == '0') && (value[1] == 'x')) {
		if (len > 42) {
			cf_log_err(cf_section_to_item(cs), "Secret is too long");
			return -1;
		}

		if ((len & 0x01) != 0) {
			cf_log_err(cf_section_to_item(cs), "Invalid hex length");
			return -1;
		}

		return fr_hex2bin(secret, BFD_MAX_SECRET_LENGTH, value + 2, (len - 2));
	}

	if (len >= 20) {
		cf_log_err(cf_section_to_item(cs), "Secret is too long");
		return -1;
	}

	memset(secret, 0, BFD_MAX_SECRET_LENGTH);
	memcpy(secret, value, len);
	return len;
}



/*
 *	Create a new session.
 */
static bfd_state_t *bfd_new_session(bfd_socket_t *sock, int sockfd,
				    CONF_SECTION *cs,
				    const fr_ipaddr_t *ipaddr, uint16_t port)
{
	int rcode;
	bool flag;
	bfd_state_t *session;

	session = talloc_zero(sock, bfd_state_t);

	/*
	 *	Initialize according to RFC.
	 */
	session->number = sock->number++;
	session->sockfd = sockfd;
	session->session_state = BFD_STATE_DOWN;
	session->server_cs = sock->server_cs;
	session->unlang = sock->unlang;
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
	rcode = cf_pair_parse(NULL, cs, "demand", FR_ITEM_POINTER(FR_TYPE_BOOL, &flag), NULL, T_INVALID);
	if (rcode == 0) {
		session->demand_mode = flag;
	}

	/*
	 *	Number is moved out of scope to shut up lgtm
	 *      static analysis, but really these should be
	 *	moved into conf_parser callback functions.
	 */
	{
		uint32_t number;

		rcode = cf_pair_parse(NULL, cs, "min_transmit_interval", FR_ITEM_POINTER(FR_TYPE_UINT32, &number), NULL, T_INVALID);
		if (rcode == 0) {
			if (number < 100) number = 100;
			if (number > 10000) number = 10000;

			session->desired_min_tx_interval = number * 1000;
		}
	}

	{
		uint32_t number;

		rcode = cf_pair_parse(NULL, cs, "min_receive_interval", FR_ITEM_POINTER(FR_TYPE_UINT32, &number), NULL, T_INVALID);
		if (rcode == 0) {
			if (number < 100) number = 100;
			if (number > 10000) number = 10000;

			session->required_min_rx_interval = number * 1000;
		}
	}

	{
		uint32_t number;

		rcode = cf_pair_parse(NULL, cs, "max_timeouts", FR_ITEM_POINTER(FR_TYPE_UINT32, &number), NULL, T_INVALID);
		if (rcode == 0) {
			if (number == 0) number = 1;
			if (number > 10) number = 10;

			session->detect_multi = number;
		}
	}
	session->auth_type = sock->auth_type;

	/*
	 *	Parse / over-ride the secrets.
	 */
	session->secret_len = bfd_parse_secret(cs, session->secret);
	if ((session->secret_len == 0) &&
	    (session->auth_type != BFD_AUTH_RESERVED)) {
		if (sock->secret_len == 0) {
			cf_log_err(cf_section_to_item(cs), "auth_type requires a secret");
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

	fr_ipaddr_to_sockaddr(ipaddr, port,
			   &session->remote_sockaddr, &session->salen);

	if (!rbtree_insert(sock->session_tree, session)) {
		ERROR("FAILED creating new session!");
		talloc_free(session);
		return NULL;
	}

	bfd_trigger(session);

	/*
	 *	Check for threaded / non-threaded operation.
	 */
	if (event_list) {
		session->el = event_list;

		bfd_start_control(session);

		session->pipefd[0] = session->pipefd[1] = -1;
		session->pthread_id = pthread_self();
	} else {
		if (!bfd_pthread_create(session)) {
			rbtree_deletebydata(sock->session_tree, session);
			talloc_free(session);
			return NULL;
		}
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
	bfd_auth_md5_t *md5 = &bfd->auth.md5;

	rad_assert(session->secret_len <= sizeof(md5->digest));
	rad_assert(md5->auth_len == sizeof(*md5));

	memset(md5->digest, 0, sizeof(md5->digest));
	memcpy(md5->digest, session->secret, session->secret_len);

	fr_md5_calc(md5->digest,(const uint8_t *) bfd, bfd->length);
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
	rcode = fr_digest_cmp(digest, md5->digest, sizeof(digest));

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
	fr_sha1_ctx ctx;
	bfd_auth_sha1_t *sha1 = &bfd->auth.sha1;

	rad_assert(session->secret_len <= sizeof(sha1->digest));
	rad_assert(sha1->auth_len == sizeof(*sha1));

	memset(sha1->digest, 0, sizeof(sha1->digest));
	memcpy(sha1->digest, session->secret, session->secret_len);

	fr_sha1_init(&ctx);
	fr_sha1_update(&ctx, (const uint8_t *) bfd, bfd->length);
	fr_sha1_final(sha1->digest, &ctx);
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
static void bfd_send_packet(UNUSED fr_event_list_t *eel, UNUSED fr_time_t now, void *ctx)
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
		ERROR("Failed sending packet: %s", fr_syserror(errno));
	}
}

static int bfd_start_packets(bfd_state_t *session)
{
	uint32_t	interval, base;
	uint64_t	jitter;

	/*
	 *	Reset the timers.
	 */
	fr_event_timer_delete(&session->ev_packet);

	session->last_sent = fr_time();

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

	if (fr_event_timer_in(session, session->el, &session->ev_packet,
			      fr_time_delta_from_usec(interval),
			      bfd_send_packet, session) < 0) {
		rad_assert("Failed to insert event" == NULL);
	}

	return 0;
}


static void bfd_set_timeout(bfd_state_t *session, fr_time_t when)
{
	fr_time_t now = when;

	fr_event_timer_delete(&session->ev_timeout);

	now += fr_time_delta_from_usec(session->detection_time);

	if (session->detect_multi >= 2) {
		uint32_t delay;

		session->next_recv = when;
		delay = session->detection_time / session->detect_multi;
		delay += delay / 2;

		session->next_recv += fr_time_delta_from_usec(delay);
	}

	if (fr_event_timer_at(session, session->el, &session->ev_timeout,
			      now, bfd_detection_timeout, session) < 0) {
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

	bfd_set_timeout(session, session->last_recv);

	if (session->ev_packet) return 0;

	return bfd_start_packets(session);
}

static int bfd_stop_control(bfd_state_t *session)
{
	fr_event_timer_delete(&session->ev_timeout);
	fr_event_timer_delete(&session->ev_packet);
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

static void bfd_set_desired_min_tx_interval(bfd_state_t *session, uint32_t value)
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

static void bfd_detection_timeout(UNUSED fr_event_list_t *eel, fr_time_t now, void *ctx)
{
	bfd_state_t *session = ctx;

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

	bfd_set_timeout(session, now);
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
		ERROR("Failed sending poll response: %s", fr_syserror(errno));
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
	if ((session->detect_multi >= 2) && (session->last_recv > session->next_recv)) {
		RADIUS_PACKET packet;
		REQUEST request;

		bfd_request(session, &request, &packet);

		trigger_exec(&request, NULL, "server.bfd.warn", false, NULL);
	}


	if ((!session->remote_demand_mode) ||
	    (session->session_state != BFD_STATE_UP) ||
	    (session->remote_session_state != BFD_STATE_UP)) {
		bfd_start_control(session);
	}

	if (session->server_cs) {
		REQUEST *request;
		RADIUS_PACKET *packet, *reply;

		request = request_alloc(session);
		packet = fr_radius_alloc(request, 0);
		reply = fr_radius_alloc(request, 0);

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

		if (fr_debug_lvl) {
			request->log.dst = talloc_zero(request, log_dst_t);
			request->log.dst->func = vlog_request;
			request->log.dst->uctx = &default_log;

			request->log.lvl = fr_debug_lvl;
		}
		request->component = NULL;
		request->module = NULL;

		DEBUG2("server %s {", cf_section_name2(request->server_cs));
		unlang_interpret_section(request, session->unlang, RLM_MODULE_NOTFOUND);
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
	bfd_state_t	*session;
	bfd_state_t	my_session;
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
	fr_ipaddr_from_sockaddr(&src, sizeof_src,
			   &my_session.remote_ipaddr,
			   &my_session.remote_port);

	session = rbtree_finddata(sock->session_tree, &my_session);
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
		bfd_state_t *session, my_session;

	       if (!cf_item_is_section(ci)) continue;

	       peer = cf_item_to_section(ci);

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
	const bfd_state_t *a = one, *b = two;

	return fr_ipaddr_cmp(&a->remote_ipaddr, &b->remote_ipaddr);
}

static fr_table_num_sorted_t const auth_types[] = {
	{ "keyed-md5",		BFD_AUTH_KEYED_MD5	},
	{ "keyed-sha1",		BFD_AUTH_KEYED_SHA1	},
	{ "met-keyed-md5",	BFD_AUTH_MET_KEYED_MD5	},
	{ "met-keyed-sha1",	BFD_AUTH_MET_KEYED_SHA1 },
	{ "none",		BFD_AUTH_RESERVED	},
	{ "simple",		BFD_AUTH_SIMPLE		}
};
static size_t auth_types_len = NUM_ELEMENTS(auth_types);

static int bfd_socket_parse(CONF_SECTION *cs, rad_listen_t *this)
{
	bfd_socket_t *sock = this->data;
	char const *auth_type_str = NULL;
	uint16_t listen_port;
	fr_ipaddr_t ipaddr;

	rad_assert(sock != NULL);

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

	sock->session_tree = rbtree_talloc_create(sock, bfd_session_cmp, bfd_state_t, bfd_session_free, 0);
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

static int bfd_socket_open(CONF_SECTION *cs, rad_listen_t *this)
{
	int rcode;
	uint16_t port;
	bfd_socket_t *sock = this->data;

	port = sock->my_port;

	this->fd = fr_socket_server_udp(&sock->my_ipaddr, &port, "bfd-control", true);
	if (this->fd < 0) {
		char buffer[256];

		this->print(this, buffer, sizeof(buffer));

		ERROR("Failed opening %s: %s", buffer, fr_syserror(errno));
		return -1;
	}

	rad_suid_up();
	rcode = fr_socket_bind(this->fd, &sock->my_ipaddr, &port, sock->interface);
	rad_suid_down();
	sock->my_port = port;

	if (rcode < 0) {
		char buffer[256];
		close(this->fd);

		this->print(this, buffer, sizeof(buffer));
		ERROR("Failed binding to %s: %s", buffer, fr_syserror(errno));
		return -1;
	}

	/*
	 *	Bootstrap the initial set of connections.
	 */
	if (bfd_init_sessions(cs, sock, this->fd) < 0) {
		return -1;
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
	    (sock->my_ipaddr.addr.v4.s_addr == htonl(INADDR_ANY))) {
		strlcpy(buffer, "*", bufsize);
	} else {
		fr_inet_ntoh(&sock->my_ipaddr, buffer, bufsize);
	}
	FORWARD;

	strlcpy(buffer, " port ", bufsize);
	FORWARD;

	snprintf(buffer, bufsize, "%d", sock->my_port);
	FORWARD;

	return 1;
}

/*
 *	If there's no "bfd" section, we can't bootstrap anything.
 */
static int bfd_socket_bootstrap(CONF_SECTION *server_cs, UNUSED CONF_SECTION *listen_cs)
{
	CONF_SECTION *cs;

	cs = cf_section_find(server_cs, "bfd", NULL);
	if (!cs) {
		cf_log_err(server_cs, "No 'bfd' sub-section found");
		return -1;
	}

	return 0;
}

/*
 *	Ensure that the "bfd" section is compiled.
 */
static int bfd_socket_compile(CONF_SECTION *server_cs, UNUSED CONF_SECTION *listen_cs)
{
	CONF_SECTION *cs;

	cs = cf_section_find(server_cs, "bfd", NULL);
	if (!cs) {
		cf_log_err(server_cs, "No 'bfd' sub-section found");
		return -1;
	}

	cf_log_debug(cs, "Loading bfd {...}");

	if (unlang_compile(cs, MOD_AUTHORIZE, NULL, NULL) < 0) {
		cf_log_err(cs, "Failed compiling 'bfd' section");
		return -1;
	}

	return 0;
}


extern rad_protocol_t proto_bfd;
rad_protocol_t proto_bfd = {
	.magic		= RLM_MODULE_INIT,
	.name		= "bfd",
	.inst_size	= sizeof(bfd_socket_t),
	.transports	= TRANSPORT_UDP,
	.tls		= false,
	.bootstrap	= bfd_socket_bootstrap,
	.compile	= bfd_socket_compile,
	.parse		= bfd_socket_parse,
	.open		= bfd_socket_open,
	.recv		= bfd_socket_recv,
	.send		= bfd_socket_send,
	.print		= bfd_socket_print,
	.debug		= common_packet_debug,
	.encode		= bfd_socket_encode,
	.decode		= bfd_socket_decode
};
