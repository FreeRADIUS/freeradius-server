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
 */
/**
 * $Id$
 *
 * @file unit_test_tls.c
 * @brief TLS server test framework
 *
 * This program loads the "tls" protocol and reads two top-level sections
 * from unit_test_tls.conf.  The "tls" section supplies the TLS server
 * context, and takes exactly the items that a TLS configuration takes
 * anywhere else in the server.  The "unit_test_tls" section supplies what
 * steers the test program itself, which is the address of the listening TCP
 * socket and whether a client certificate is required.
 *
 * One connection is accepted, and the TLS handshake for that connection is
 * run to completion.
 *
 * The handshake runs on a persistent asynchronous interpreter, the same way
 * radiusd runs one.  A persistent interpreter keeps the handshake state
 * across the several rounds of a single connection.
 *
 * The "virtual_server" item in the "tls" section names a virtual server.
 * That virtual server supplies the "verify certificate", "load session",
 * "store session" and "clear session" sections which the handshake calls.
 *
 * To run the test, start unit_test_tls with the test configuration, then
 * connect to the listening socket:
 *
 * @code
 * ./scripts/bin/unit_test_tls -d src/tests/tls -X
 *
 * openssl s_client -connect 127.0.0.1:2083 \
 *         -cert raddb/certs/rsa/client.pem \
 *         -key raddb/certs/rsa/client.key -pass pass:whatever \
 *         -CAfile raddb/certs/rsa/ca.pem
 * @endcode
 *
 * src/tests/tls/unit_test_tls.conf documents every configuration item.
 *
 * @copyright 2025 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module_rlm.h>

#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/io/thread.h>

#include <freeradius-devel/tls/base.h>
#include <freeradius-devel/tls/strerror.h>
#include <freeradius-devel/tls/version.h>
#include <freeradius-devel/tls/connection.h>

#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/unlang/function.h>
#include <freeradius-devel/unlang/interpret.h>

#include <freeradius-devel/util/socket.h>

#include <freeradius-devel/protocol/freeradius/freeradius.internal.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

#define EXIT_WITH_FAILURE \
do { \
	ret = EXIT_FAILURE; \
	goto cleanup; \
} while (0)

char const *radiusd_version = RADIUSD_VERSION_BUILD("unit_test_tls");

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_tls;

extern fr_dict_autoload_t unit_test_tls_dict[];
fr_dict_autoload_t unit_test_tls_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_tls, .proto = "tls" },
	DICT_AUTOLOAD_TERMINATOR
};

/** The "unit_test_tls" section
 *
 * These items steer the test program, and have nothing to do with TLS itself.
 * Keeping them out of the "tls" section leaves that section holding only what
 * fr_tls_conf_parse_server() understands.
 */
typedef struct {
	fr_ipaddr_t	ipaddr;				//!< Address of the listening socket.  Server mode only.
	uint16_t	port;				//!< Port of the listening socket, and the default
							///< port for -s.
	bool		require_client_certificate;	//!< Whether the client has to present a certificate.
} unit_test_tls_conf_t;

static const conf_parser_t unit_test_tls_config[] = {
	{ FR_CONF_OFFSET_TYPE_FLAGS("ipaddr", FR_TYPE_COMBO_IP_ADDR, 0, unit_test_tls_conf_t, ipaddr) },
	{ FR_CONF_OFFSET_TYPE_FLAGS("ipv4addr", FR_TYPE_IPV4_ADDR, 0, unit_test_tls_conf_t, ipaddr) },
	{ FR_CONF_OFFSET_TYPE_FLAGS("ipv6addr", FR_TYPE_IPV6_ADDR, 0, unit_test_tls_conf_t, ipaddr) },

	{ FR_CONF_OFFSET("port", unit_test_tls_conf_t, port) },

	{ FR_CONF_OFFSET("require_client_certificate", unit_test_tls_conf_t, require_client_certificate),
	  .dflt = "no" },

	CONF_PARSER_TERMINATOR
};

/** State of the test program
 *
 * The interpreter and the runnable heap live for the whole of the connection.
 * A TLS handshake takes several rounds, and each round may yield while a
 * virtual server section runs.  The interpreter and the runnable heap
 * therefore cannot be allocated once per round.
 */
typedef struct {
	fr_event_list_t		*el;			//!< Event list everything runs on.
	unlang_interpret_t	*intp;			//!< Interpreter for the connection.
	fr_heap_t		*runnable;		//!< Requests the interpreter has marked runnable.
	int			yielded;		//!< How many requests are currently yielded.

	unit_test_tls_conf_t	conf;			//!< Parsed "unit_test_tls" section.
	SSL_CTX			*ssl_ctx;		//!< Context built from the "tls" section.

	fr_tls_connection_t	*conn;			//!< State of the connection being run.

	unsigned int		count;			//!< How many connections to run.
	bool			alert;			//!< Reject the peer with a TLS alert, see -A.
	fr_ipaddr_t		server_ipaddr;		//!< Server named by -s.
	uint16_t		server_port;		//!< Port from -s, or from the configuration.

	int			sockfd;			//!< Listening socket.
	int			fd;			//!< Accepted or connected socket.
	fr_event_fd_t		*ef;			//!< Read event for fd.

	bool			done;			//!< Set once the connection has a result.
	int			ret;			//!< Exit status.
} unit_test_tls_t;

static void usage(main_config_t const *config, int status);

/*
 *	Interpreter callbacks.
 *
 *	The callbacks below mirror the set in
 *	src/lib/unlang/interpret_synchronous.c and src/lib/io/coord_pair.c.  The
 *	one difference is that a post-event handler drains the runnable heap,
 *	rather than a loop inside the caller, so the event loop decides when
 *	each request runs.
 */

/** Schedule a request, once
 *
 * A request reaches the heap from two directions: the interpreter creating it,
 * and the interpreter marking it runnable again.  Inserting a request which is
 * already on the heap puts it there twice, and popping it then returns a
 * request which the heap still holds, which the interpreter refuses to run.
 */
static void tls_runnable_insert(unit_test_tls_t *utt, request_t *request)
{
	if (fr_heap_entry_inserted(request->runnable)) return;

	fr_heap_insert(&utt->runnable, request);
}

/** An internal request created by the interpreter has to run on ours
 *
 * The subrequests created for the "verify certificate" section and for the
 * session cache sections reach this callback.
 *
 * fr_tls_call_push() pushes each of them as a detachable subrequest, which
 * the parent waits on rather than running inline, so the subrequest has to be
 * scheduled here or nothing ever runs it.
 */
static void _request_init_internal(request_t *request, void *uctx)
{
	unit_test_tls_t *utt = talloc_get_type_abort(uctx, unit_test_tls_t);

	RDEBUG3("Initialising internal request");

	unlang_interpret_set(request, utt->intp);

	/*
	 *	interpret_child_init() calls this, and nothing else schedules
	 *	the child, so a subrequest which is not put on the heap here
	 *	never runs at all.
	 */
	tls_runnable_insert(utt, request);
}

static void _request_done_external(request_t *request, UNUSED rlm_rcode_t rcode, UNUSED void *uctx)
{
	RDEBUG3("Done external request");

	/*
	 *	main() allocated the request, and the request has to survive
	 *	until the connection is done with, so this callback does not
	 *	free the request.
	 */
}

static void _request_done_internal(request_t *request, UNUSED rlm_rcode_t rcode, UNUSED void *uctx)
{
	RDEBUG3("Done internal request");

	/* The code which created the internal request frees the request */
}

static void _request_done_detached(request_t *request, UNUSED rlm_rcode_t rcode, UNUSED void *uctx)
{
	RDEBUG3("Done detached request");

	/*
	 *	Nothing else can free a detached request, so this callback
	 *	frees the detached request.
	 */
	talloc_free(request);
}

static void _request_detach(request_t *request, UNUSED void *uctx)
{
	RDEBUG3("Request detached");

	if (request_detach(request) < 0) RPEDEBUG("Failed detaching request");
}

static void _request_yield(request_t *request, void *uctx)
{
	unit_test_tls_t *utt = talloc_get_type_abort(uctx, unit_test_tls_t);

	utt->yielded++;

	RDEBUG3("Request yielded");
}

static void _request_resume(request_t *request, UNUSED void *uctx)
{
	RDEBUG3("Request resumed");
}

static void _request_runnable(request_t *request, void *uctx)
{
	unit_test_tls_t *utt = talloc_get_type_abort(uctx, unit_test_tls_t);

	fr_assert(utt->yielded > 0);
	utt->yielded--;

	tls_runnable_insert(utt, request);
}

static bool _request_scheduled(request_t const *request, UNUSED void *uctx)
{
	return fr_heap_entry_inserted(request->runnable);
}

/** Stop the event loop, recording why
 *
 * The connection carries the result, so the exit status is decided here
 * rather than by the state machine.  A process exit status is this program's
 * notion of a result, and no part of a TLS connection should have to know
 * about one.
 */
static void tls_request_finished(void *uctx, fr_tls_connection_t *conn)
{
	unit_test_tls_t *utt = talloc_get_type_abort(uctx, unit_test_tls_t);

	if (utt->done) return;

	utt->done = true;
	utt->ret = conn->failed ? EXIT_FAILURE : EXIT_SUCCESS;

	fr_event_loop_exit(utt->el, 1);
}

/** Record a failure this program cannot recover from, and stop
 *
 * tls_request_finished() reads the result from the connection, so a failure
 * has to reach the connection before the callback runs.
 */
static void tls_request_failed(unit_test_tls_t *utt)
{
	utt->conn->failed = true;
	tls_request_finished(utt, utt->conn);
}

/** Write whatever OpenSSL has produced out to the connection
 *
 * The TLS session reads and writes memory BIOs, which are OpenSSL's in-memory
 * I/O buffers, and never a socket.  Writing each record to the socket is
 * therefore the caller's job.  The EAP code in src/lib/eap/tls.c writes
 * records the same way.
 */
static int tls_connection_write(void *uctx, fr_tls_connection_t *conn)
{
	unit_test_tls_t		*utt = talloc_get_type_abort(uctx, unit_test_tls_t);
	fr_tls_session_t	*tls_session = conn->tls_session;
	uint8_t			buf[FR_TLS_MAX_RECORD_SIZE];

	while (fr_dbuff_remaining(&tls_session->dirty_out) > 0) {
		size_t		len;
		size_t		written = 0;

		len = fr_tls_record_to_buff(&tls_session->dirty_out, buf, sizeof(buf));

		while (written < (size_t) len) {
			ssize_t slen;

			slen = write(utt->fd, buf + written, len - written);
			if (slen < 0) {
				if (errno == EINTR) continue;

				ERROR("Failed writing to connection: %s", fr_syserror(errno));
				return -1;
			}
			written += (size_t) slen;
		}

		DEBUG3("Wrote %zu bytes to the connection", len);
	}

	return 0;
}

/** A record arrived on the connection, so hand the record to the connection
 *
 * Reading the socket is all this program does here.  Everything the record
 * means to TLS is fr_tls_connection_recv()'s business.
 */
static void _tls_connection_read(UNUSED fr_event_list_t *el, int fd, UNUSED int flags, void *uctx)
{
	unit_test_tls_t		*utt = talloc_get_type_abort(uctx, unit_test_tls_t);
	uint8_t			buf[FR_TLS_MAX_RECORD_SIZE];
	ssize_t			slen;

	if (utt->done) return;

	slen = read(fd, buf, sizeof(buf));
	if (slen < 0) {
		if ((errno == EINTR) || (errno == EAGAIN) || (errno == EWOULDBLOCK)) return;

		ERROR("Failed reading from connection: %s", fr_syserror(errno));
		tls_request_failed(utt);
		return;
	}

	if (slen == 0) {
		ERROR("Connection closed by the peer before the handshake completed");
		tls_request_failed(utt);
		return;
	}

	/*
	 *	Reject the peer now that a record has arrived, so that the
	 *	alert goes out in place of the first record this end would
	 *	otherwise have sent.  Raising the alert any earlier races the
	 *	peer: the round which sends the alert can run before the
	 *	peer's first record has arrived, and the alert is then sent
	 *	into an empty handshake and lost.
	 */
	if (utt->alert) {
		utt->alert = false;

		if (fr_tls_session_alert(utt->conn->request, utt->conn->tls_session,
					 SSL3_AL_FATAL, SSL_AD_ACCESS_DENIED) < 0) {
			ERROR("Failed raising the TLS alert");
			tls_request_failed(utt);
			return;
		}
	}

	fr_tls_connection_recv(utt->conn, buf, (size_t) slen);
}

/** The connection failed at the socket level
 *
 */
static void _tls_connection_error(UNUSED fr_event_list_t *el, UNUSED int fd, UNUSED int flags, int fd_errno, void *uctx)
{
	unit_test_tls_t *utt = talloc_get_type_abort(uctx, unit_test_tls_t);

	ERROR("Error on connection: %s", fr_syserror(fd_errno));
	tls_request_failed(utt);
}

/** Drain the runnable heap once per pass of the event loop
 *
 * A handshake round yields whenever the round runs a virtual server section.
 * When that section finishes, unlang_interpret_mark_runnable() puts the
 * request on the runnable heap, and this drains the heap again.
 */
static void _tls_runnable(UNUSED fr_event_list_t *el, UNUSED fr_time_t now, void *uctx)
{
	unit_test_tls_t *utt = talloc_get_type_abort(uctx, unit_test_tls_t);
	request_t	*request;

	while (fr_heap_pop((void **)&request, &utt->runnable) == 0) {
		if (!request) break;

		(void) unlang_interpret(request, UNLANG_REQUEST_RESUME);

		/*
		 *	Only the connection's own request advances the
		 *	handshake.  A subrequest returns the subrequest's
		 *	result through the interpreter.
		 */
		if (request == utt->conn->request) fr_tls_connection_process(utt->conn);

		if (utt->done) return;
	}
}

/** Open the listening socket described by the "unit_test_tls" section
 *
 */
static int tls_socket_open(unit_test_tls_t *utt)
{
	int		sockfd;
	fr_ipaddr_t	ipaddr = utt->conf.ipaddr;
	uint16_t	port = utt->conf.port;

	/*
	 *	The items are not marked as required, because a client has no
	 *	listening socket, and so needs neither of them.
	 */
	if ((ipaddr.af == AF_UNSPEC) || !port) {
		ERROR("Both 'ipaddr' and 'port' must be set in the 'unit_test_tls' section "
		      "when listening for a connection");
		return -1;
	}

	sockfd = fr_socket_server_tcp(&ipaddr, &port, NULL, false);
	if (sockfd < 0) {
		PERROR("Failed opening TCP socket");
		return -1;
	}

	if (fr_socket_bind(sockfd, NULL, &ipaddr, &port) < 0) {
		PERROR("Failed binding TCP socket");
		close(sockfd);
		return -1;
	}

	if (listen(sockfd, 8) < 0) {
		ERROR("Failed listening on TCP socket: %s", fr_syserror(errno));
		close(sockfd);
		return -1;
	}

	INFO("Listening on %pV port %u", fr_box_ipaddr(ipaddr), port);

	utt->sockfd = sockfd;

	return 0;
}

/** Connect to the server named by -s
 *
 */
static int tls_socket_connect(unit_test_tls_t *utt)
{
	int	fd;
	char	buffer[FR_IPADDR_STRLEN];

	fr_inet_ntop(buffer, sizeof(buffer), &utt->server_ipaddr);

	fd = fr_socket_client_tcp(NULL, NULL, &utt->server_ipaddr, utt->server_port, false);
	if (fd < 0) {
		PERROR("Failed connecting to %s port %u", buffer, utt->server_port);
		return -1;
	}

	INFO("Connected to %s port %u", buffer, utt->server_port);

	utt->fd = fd;

	return 0;
}

/** Build an internal client.
 *
 * unit_test_tls accepts packets from anywhere (for now), and doesn't read "client" configuration sections.
 *
 * The client is built by allocating a CONF_SECTION rather than by filling in #fr_client_t manually, which
 * allows fields to be examined by `%request.client()`.
 *
 * "proto = tls" sets both the protocol and tls_required.  It also fixes the
 * secret at "radsec", so that is the secret set here.
 */
static fr_client_t *tls_client_alloc(TALLOC_CTX *ctx, fr_ipaddr_t const *ipaddr)
{
	CONF_SECTION	*cs;
	fr_client_t	*client;
	char		buffer[FR_IPADDR_STRLEN];

	/*
	 *	Written without a prefix, the way a person would write it in
	 *	a "client" section.  The "ipaddr" item is a COMBO_IP_PREFIX,
	 *	so a bare host address parses as a /32 or a /128.
	 */
	fr_inet_ntop(buffer, sizeof(buffer), ipaddr);

	MEM(cs = cf_section_alloc(ctx, NULL, "client", "unit_test_tls"));
	MEM(cf_pair_alloc(cs, "ipaddr", buffer, T_OP_EQ, T_BARE_WORD, T_BARE_WORD));
	MEM(cf_pair_alloc(cs, "proto", "tls", T_OP_EQ, T_BARE_WORD, T_BARE_WORD));
	MEM(cf_pair_alloc(cs, "secret", "radsec", T_OP_EQ, T_BARE_WORD, T_DOUBLE_QUOTED_STRING));
	MEM(cf_pair_alloc(cs, "shortname", "unit_test_tls", T_OP_EQ, T_BARE_WORD, T_DOUBLE_QUOTED_STRING));
	MEM(cf_pair_alloc(cs, "nas_type", "test", T_OP_EQ, T_BARE_WORD, T_DOUBLE_QUOTED_STRING));

	client = client_afrom_cs(ctx, cs, NULL, 0);
	if (!client) {
		PERROR("Failed creating the client for %s", buffer);
		talloc_free(cs);
		return NULL;
	}

	/*
	 *	The client has to outlive the section it was built from,
	 *	because %request.client() reads the section.
	 */
	talloc_steal(client, cs);

	return client;
}

/** Build the request the handshake runs under
 *
 * The TLS code reads the control list for TLS-Session-Cert-File and
 * TLS-Session-Require-Client-Certificate, and writes the negotiated version
 * and cipher suite into the session-state list, so a real request is needed.
 */
static request_t *tls_request_alloc(TALLOC_CTX *ctx, int fd)
{
	request_t		*request;
	struct sockaddr_storage	sa;
	socklen_t		salen;

	static uint64_t		number = 0;

	request = request_local_alloc_internal(ctx, NULL);
	if (!request) return NULL;

	if (!request->packet) request->packet = fr_packet_alloc(request, false);
	if (!request->reply) request->reply = fr_packet_alloc(request, false);

	request->packet->timestamp = fr_time();

	request->packet->socket.type = SOCK_STREAM;
	request->packet->socket.fd = fd;

	salen = sizeof(sa);
	if (getpeername(fd, (struct sockaddr *) &sa, &salen) == 0) {
		(void) fr_ipaddr_from_sockaddr(&request->packet->socket.inet.src_ipaddr,
					       &request->packet->socket.inet.src_port, &sa, salen);
		request->packet->socket.af = request->packet->socket.inet.src_ipaddr.af;
	}

	salen = sizeof(sa);
	if (getsockname(fd, (struct sockaddr *) &sa, &salen) == 0) {
		(void) fr_ipaddr_from_sockaddr(&request->packet->socket.inet.dst_ipaddr,
					       &request->packet->socket.inet.dst_port, &sa, salen);
	}

	/*
	 *	The client is the far end of the connection we just accepted.
	 */
	request->client = tls_client_alloc(request, &request->packet->socket.inet.src_ipaddr);
	if (!request->client) {
		talloc_free(request);
		return NULL;
	}

	request->number = number++;
	request->name = talloc_typed_asprintf(request, "%" PRIu64, request->number);
	request->master_state = REQUEST_ACTIVE;

	request->log.dst = talloc_zero(request, log_dst_t);
	request->log.dst->func = vlog_request;
	request->log.dst->uctx = &default_log;
	request->log.dst->lvl = fr_debug_lvl;

	request->log.lvl = fr_debug_lvl;
	request->async = talloc_zero(request, fr_async_t);
	request->async->request = request;

	if (fr_packet_pairs_from_packet(request->request_ctx, &request->request_pairs, request->packet) < 0) {
		ERROR("Failed converting connection addresses to attributes");
		talloc_free(request);
		return NULL;
	}

	return request;
}

/** Add the connection to the event loop, and get it moving
 *
 * Runs from inside the event loop, see tls_connection_run().
 */
static void _tls_connection_start(fr_event_list_t *el, void *uctx)
{
	unit_test_tls_t *utt = talloc_get_type_abort(uctx, unit_test_tls_t);

	/*
	 *	Nothing polls.  A handshake round starts when a record arrives,
	 *	and a yielded round resumes when the interpreter marks the
	 *	request runnable.
	 */
	if (fr_event_fd_insert(utt, &utt->ef, el, utt->fd, _tls_connection_read, NULL, _tls_connection_error, utt) < 0) {
		PERROR("Failed adding the connection to the event loop");
		tls_request_failed(utt);
		return;
	}

	/*
	 *	Run `new session { ... }` and, for a client, `load session`.
	 *	A server then waits for the ClientHello.  A client has to send
	 *	it.
	 */
	fr_tls_connection_wake(utt->conn);
}

/** Run one connection from the first byte to the last
 *
 * Everything which belongs to a single connection is allocated here and freed
 * again at the end, so that the next connection starts clean.  What survives
 * is what the cache needs: the interpreter, the modules, and so the sessions
 * a policy stored.
 */
static int tls_connection_run(unit_test_tls_t *utt)
{
	int		ret = -1;
	fr_event_user_t	*ev = NULL;
	request_t	*stale;

	utt->conn->state = TLS_CONNECTION_NEW_SESSION;
	utt->conn->pending = utt->conn->failed = utt->conn->idle = false;
	utt->conn->request = NULL;
	utt->conn->tls_session = NULL;

	utt->done = false;
	utt->ret = EXIT_SUCCESS;
	utt->fd = -1;
	utt->ef = NULL;

	/*
	 *	Get a connection, one way or the other.
	 */
	if (utt->conn->client) {
		if (tls_socket_connect(utt) < 0) return -1;
	} else {
		INFO("Waiting for a connection");

		utt->fd = accept(utt->sockfd, NULL, NULL);
		if (utt->fd < 0) {
			ERROR("Failed accepting connection: %s", fr_syserror(errno));
			return -1;
		}
	}

	utt->conn->request = tls_request_alloc(utt, utt->fd);
	if (!utt->conn->request) goto finish;

	unlang_interpret_set(utt->conn->request, utt->intp);

	/*
	 *	Both roles run the same handshake driver.  Passing the request
	 *	to fr_tls_session_alloc_client() is what gives a client the
	 *	memory BIOs and the certificate validation callback which the
	 *	driver needs, see src/lib/tls/session.c.
	 */
	if (utt->conn->client) {
		utt->conn->tls_session = fr_tls_session_alloc_client(utt->conn->request, utt->ssl_ctx, utt->conn->request);
	} else {
		INFO("Accepted connection from %pV",
		     fr_box_ipaddr(utt->conn->request->packet->socket.inet.src_ipaddr));

		utt->conn->tls_session = fr_tls_session_alloc_server(utt->conn->request, utt->ssl_ctx, utt->conn->request,
							       0, utt->conf.require_client_certificate);
	}

	if (!utt->conn->tls_session) {
		PERROR("Failed creating the TLS session");
		goto finish;
	}

	/*
	 *	Start the request with a new session, then run the
	 *	interpreter once so that the first frame yields.
	 *	unlang_interpret_mark_runnable() acts only on a
	 *	yielded frame.
	 */
	if (fr_tls_connection_push(utt->conn) < 0) {
		PERROR("Failed starting new TLS connection");
		goto finish;
	}

	(void) unlang_interpret(utt->conn->request, UNLANG_REQUEST_RESUME);

	if (fr_event_post_insert(utt->el, _tls_runnable, utt) < 0) {
		PERROR("Failed adding the runnable handler to the event loop");
		goto finish;
	}

	/*
	 *	The connection is started from inside the event loop rather
	 *	than here.  Ending the previous connection left the loop
	 *	flagged as exiting, and fr_event_fd_insert() refuses to add a
	 *	socket to a loop in that state.  fr_event_loop() clears the
	 *	flag as it starts, so a user event which fires immediately is
	 *	the first point at which the socket can be added.
	 */
	if (fr_event_user_insert(utt, utt->el, &ev, true, _tls_connection_start, utt) < 0) {
		PERROR("Failed scheduling the start of the connection");
		goto finish;
	}

	(void) fr_event_loop(utt->el);

	ret = 0;

finish:
	if (utt->ef) {
		(void) fr_event_fd_delete(utt->el, utt->fd, FR_EVENT_FILTER_IO);
		utt->ef = NULL;
	}
	(void) fr_event_post_delete(utt->el, _tls_runnable, utt);

	/*
	 *	The connection frame is still yielded, so cancel the request to
	 *	unwind the stack before the request is freed.
	 */
	if (utt->conn->request) unlang_interpret_signal(utt->conn->request, FR_SIGNAL_CANCEL);

	/*
	 *	Empty the heap before the requests on it are freed.  Popping
	 *	clears each entry's index, so nothing is left pointing at
	 *	memory the request pool is about to hand out again.
	 */
	while (fr_heap_pop((void **)&stale, &utt->runnable) == 0) {
		if (!stale) break;
	}
	utt->yielded = 0;

	TALLOC_FREE(utt->conn->tls_session);
	TALLOC_FREE(utt->conn->request);

	if (utt->fd >= 0) {
		close(utt->fd);
		utt->fd = -1;
	}

	return ret;
}

int main(int argc, char *argv[])
{
	int			ret = EXIT_SUCCESS;
	int			c;
	char const		*receipt_file = NULL;
	char const		*server = NULL;
	unsigned int		count = 1;
	bool			alert = false;
	unsigned int		i;

	TALLOC_CTX		*autofree;
	TALLOC_CTX		*thread_ctx;

	char			*p;
	main_config_t		*config;

	fr_dict_t		*dict = NULL;
	fr_dict_t const		*dict_check;

	virtual_server_t const	*vs;
	CONF_SECTION		*tls_cs;
	CONF_SECTION		*utt_cs;

	unit_test_tls_t		*utt = NULL;

	/*
	 *	Must be called first, so the handler is called last
	 */
	fr_atexit_global_setup();

	autofree = talloc_autofree_context();
	thread_ctx = talloc_new(autofree);

	config = main_config_alloc(autofree);
	if (!config) {
		fr_perror("unit_test_tls");
		fr_exit_now(EXIT_FAILURE);
	}

	p = strrchr(argv[0], FR_DIR_SEP);
	if (!p) {
		main_config_name_set_default(config, argv[0], false);
	} else {
		main_config_name_set_default(config, p + 1, false);
	}

	fr_talloc_fault_setup();

	if (fr_fault_setup(autofree, getenv("PANIC_ACTION"), argv[0], PANIC_ACTION_SIGNALS) < 0) {
		fr_perror("%s", config->name);
		fr_exit_now(EXIT_FAILURE);
	}
#ifdef NDEBUG
	fr_disable_null_tracking_on_free(autofree);
#endif

	fr_debug_lvl = 0;
	fr_time_start();

	/*
	 *	The tests should have only IPs, not host names.
	 */
	fr_hostname_lookups = fr_reverse_lookups = false;

	/*
	 *	We always log to stdout.
	 */
	default_log.dst = L_DST_STDOUT;
	default_log.fd = STDOUT_FILENO;
	default_log.print_level = true;

	/*  Process the options.  */
	while ((c = getopt(argc, argv, "Ac:Cd:D:hMn:r:s:xX")) != -1) {
		switch (c) {
			case 'A':
				alert = true;
				break;

			case 'c':
				count = (unsigned int) atoi(optarg);
				if (!count) {
					fprintf(stderr, "Invalid value \"%s\" for -c\n", optarg);
					fr_exit_now(EXIT_FAILURE);
				}
				break;

			case 'C':
				check_config = true;
				break;

			case 'd':
				main_config_confdir_set(config, optarg);
				break;

			case 'D':
				main_config_dict_dir_set(config, optarg);
				break;

			case 'h':
				usage(config, EXIT_SUCCESS);
				break;

			case 'M':
				talloc_enable_leak_report();
				break;

			case 'n':
				config->name = optarg;
				break;

			case 'r':
				receipt_file = optarg;
				break;

			case 's':
				server = optarg;
				break;

			case 'X':
				fr_debug_lvl += 2;
				default_log.print_level = true;
				break;

			case 'x':
				fr_debug_lvl++;
				if (fr_debug_lvl > 2) default_log.print_level = true;
				break;

			default:
				usage(config, EXIT_FAILURE);
				break;
		}
	}

	if (receipt_file && (fr_unlink(receipt_file) < 0)) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

	/*
	 *  A mismatch between the OpenSSL headers used at build time and the
	 *  linked OpenSSL library makes this program exit now, rather than
	 *  crash later.
	 */
	if (fr_openssl_version_consistent() < 0) EXIT_WITH_FAILURE;

	/*
	 *  fr_openssl_init() must be called before *ANY* OpenSSL functions are
	 *  used, which is why
	 *  fr_openssl_init() is called so early.
	 */
	if (fr_openssl_init() < 0) EXIT_WITH_FAILURE;

	if (fr_debug_lvl) dependency_version_print();

	/*
	 *	Mismatch between the binary and the libraries it links against
	 */
	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

	/*
	 *	Initialise the dynamic loader infrastructure, which the config
	 *	file parser uses.
	 */
	modules_init(config->lib_dir);

	if (!fr_dict_global_ctx_init(NULL, true, config->dict_dir)) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

	if (fr_dict_internal_afrom_file(&dict, FR_DICTIONARY_INTERNAL_DIR, __FILE__) < 0) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

	if (fr_tls_dict_init() < 0) EXIT_WITH_FAILURE;

	/*
	 *	Load the custom dictionary
	 */
	if (fr_dict_read(dict, config->confdir, FR_DICTIONARY_FILE) == -1) {
		PERROR("Failed to initialize the dictionaries");
		EXIT_WITH_FAILURE;
	}

	if (fr_dict_autoload(unit_test_tls_dict) < 0) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

	if (request_global_init() < 0) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

	/*
	 *	The triggers are run-time expansions, so the triggers need the
	 *	main event loop.
	 */
	if (main_loop_init() < 0) {
		PERROR("Failed initialising main event loop");
		EXIT_WITH_FAILURE;
	}

	if (unlang_global_init() < 0) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

	if (modules_rlm_init() < 0) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

	if (virtual_servers_init() < 0) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

	if (main_config_init(config) < 0) EXIT_WITH_FAILURE;

	MEM(utt = talloc_zero(autofree, unit_test_tls_t));
	utt->sockfd = utt->fd = -1;
	utt->ret = EXIT_SUCCESS;
	utt->count = count;
	utt->alert = alert;

	/*
	 *	`utt` is the argument both callbacks take, so the state
	 *	machine stops the event loop and writes to the socket
	 *	without reading any field of `utt`.  See fr_tls_connection_t
	 *	for why the two callbacks exist.
	 */
	MEM(utt->conn = talloc_zero(utt, fr_tls_connection_t));
	utt->conn->uctx = utt;
	utt->conn->finished = tls_request_finished;
	utt->conn->write = tls_connection_write;

	/*
	 *	The settings which steer the test program, and which are
	 *	nothing to do with TLS.
	 *
	 *	These are parsed before server_init(), so that a mistake in
	 *	them is reported before the modules and virtual servers are
	 *	brought up.  The "tls" section cannot be parsed this early,
	 *	see below.
	 */
	utt_cs = cf_section_find(config->root_cs, "unit_test_tls", NULL);
	if (!utt_cs) {
		ERROR("Cannot find a top-level 'unit_test_tls { ... }' section in %s.conf", config->name);
		EXIT_WITH_FAILURE;
	}

	if (cf_section_rules_push(utt_cs, unit_test_tls_config) < 0) EXIT_WITH_FAILURE;

	if (cf_section_parse(utt, &utt->conf, utt_cs) < 0) {
		cf_log_perr(utt_cs, "Failed parsing the 'unit_test_tls' section");
		EXIT_WITH_FAILURE;
	}

	/*
	 *	-s turns the program around: instead of listening for a
	 *	connection, it makes one.
	 */
	if (server) {
		utt->conn->client = true;

		if (fr_inet_pton_port(&utt->server_ipaddr, &utt->server_port, server,
				      -1, AF_UNSPEC, true, false) < 0) {
			PERROR("Invalid value \"%s\" for -s", server);
			EXIT_WITH_FAILURE;
		}

		/*
		 *	fr_inet_pton_port() clears the port before it starts,
		 *	so a missing port is zero here, and not the default.
		 */
		if (!utt->server_port) utt->server_port = utt->conf.port;

		if (!utt->server_port) {
			ERROR("No port given in -s, and no 'port' in the 'unit_test_tls' section");
			EXIT_WITH_FAILURE;
		}
	}

	/*
	 *	Bootstrap and instantiate the virtual servers and the modules
	 *	the virtual servers use.  The "tls" section names a virtual
	 *	server, so server_init() has to run before that section is
	 *	parsed.
	 */
	if (server_init(config->root_cs, config->confdir, dict) < 0) EXIT_WITH_FAILURE;

	vs = virtual_server_find("tls");
	if (!vs) {
		ERROR("Cannot find virtual server 'tls'");
		EXIT_WITH_FAILURE;
	}

	dict_check = virtual_server_dict_by_name("tls");
	if (!dict_check || !fr_dict_compatible(dict_check, dict_tls)) {
		ERROR("Virtual server 'tls' must have 'namespace = tls'");
		EXIT_WITH_FAILURE;
	}

	/*
	 *	The TLS configuration is a top-level section, not part of a
	 *	"listen" section.  A "listen" section would need a transport
	 *	and a proto_tls module, and there is no proto_tls.
	 *
	 *	This has to run after server_init().  The "virtual_server"
	 *	item in the section is resolved by virtual_server_cf_parse(),
	 *	which needs the virtual servers to exist already.
	 */
	if (utt->conn->client) {
		tls_cs = cf_section_find(config->root_cs, "tls", "client");
		if (!tls_cs) {
			ERROR("Cannot find a top-level 'tls client { ... }' section in %s.conf",
			      config->name);
			EXIT_WITH_FAILURE;
		}

		utt->conn->tls_conf = fr_tls_conf_parse_client(tls_cs);
	} else {
		/*
		 *	Prefer 'tls server', so that one file can hold the
		 *	configuration for both roles.  Fall back to a plain
		 *	'tls' section, which is what a file with only a
		 *	server in it will have.
		 */
		tls_cs = cf_section_find(config->root_cs, "tls", "server");
		if (!tls_cs) tls_cs = cf_section_find(config->root_cs, "tls", NULL);
		if (!tls_cs) {
			ERROR("Cannot find a top-level 'tls server { ... }' or 'tls { ... }' section in %s.conf",
			      config->name);
			EXIT_WITH_FAILURE;
		}

		utt->conn->tls_conf = fr_tls_conf_parse_server(tls_cs);
	}

	if (!utt->conn->tls_conf) {
		cf_log_perr(tls_cs, "Failed parsing the TLS configuration");
		EXIT_WITH_FAILURE;
	}

	utt->ssl_ctx = fr_tls_ctx_alloc(utt->conn->tls_conf, utt->conn->client);
	if (!utt->ssl_ctx) {
		cf_log_perr(tls_cs, "Failed creating the TLS context");
		EXIT_WITH_FAILURE;
	}

	/*
	 *	The configuration parsed without error, so exit with success.
	 */
	if (check_config) {
		DEBUG("Configuration appears to be OK");
		goto cleanup;
	}

	utt->el = main_loop_event_list();
	fr_assert(utt->el != NULL);

	fr_coords_create(autofree, utt->el);

	/*
	 *	Simulate thread-specific instantiation
	 */
	fr_schedule_worker_id_set(0);
	if (fr_thread_instantiate(thread_ctx, utt->el) < 0) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

	if (modules_rlm_coord_attach(utt->el) < 0) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

	if (fr_coord_pre_event_insert(utt->el) < 0) {
		fr_strerror_const("Failed adding coordinator pre-check to event list");
		EXIT_WITH_FAILURE;
	}

	if (fr_coord_post_event_insert(utt->el) < 0) {
		fr_strerror_const("Failed adding coordinator post-check to event list");
		EXIT_WITH_FAILURE;
	}

	/*
	 *  Set the panic action (if required)
	 */
	{
		char const *panic_action = NULL;

		panic_action = getenv("PANIC_ACTION");
		if (!panic_action) panic_action = config->panic_action;

		if (panic_action && (fr_fault_setup(autofree, panic_action, argv[0], PANIC_ACTION_SIGNALS) < 0)) {
			fr_perror("%s", config->name);
			EXIT_WITH_FAILURE;
		}
	}

	setlinebuf(stdout); /* line buffered output */

	/*
	 *	One interpreter, one runnable heap and one request for the
	 *	whole connection.  The unit_test_tls_t documentation says why.
	 */
	MEM(utt->runnable = fr_heap_talloc_alloc(utt, fr_pointer_cmp, request_t, runnable, 0));

	utt->intp = unlang_interpret_init(utt, utt->el,
					  &(unlang_request_func_t){
						.init_internal	= _request_init_internal,

						.done_external	= _request_done_external,
						.done_internal	= _request_done_internal,
						.done_detached	= _request_done_detached,

						.detach		= _request_detach,
						.yield		= _request_yield,
						.resume		= _request_resume,
						.mark_runnable	= _request_runnable,
						.scheduled	= _request_scheduled,
					  }, utt);
	if (!utt->intp) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

	/*
	 *	Subrequests created by the TLS code inherit the thread default,
	 *	so the thread default has to point at the connection's
	 *	interpreter.
	 */
	unlang_interpret_set_thread_default(utt->intp);

	/*
	 *	A server has one listening socket for every connection it
	 *	accepts, so it is opened once, here.
	 */
	if (!utt->conn->client && (tls_socket_open(utt) < 0)) EXIT_WITH_FAILURE;

	for (i = 0; i < utt->count; i++) {
		if (tls_connection_run(utt) < 0) EXIT_WITH_FAILURE;

		if (utt->ret != EXIT_SUCCESS) break;
	}

	ret = utt->ret;

cleanup:
	if (utt) {
		/*
		 *	tls_connection_run() cleans up everything which belongs
		 *	to one connection.  What is left here is what outlives
		 *	them.
		 */
		if (utt->ssl_ctx) SSL_CTX_free(utt->ssl_ctx);

		if (utt->sockfd >= 0) close(utt->sockfd);
	}

	unlang_interpret_set_thread_default(NULL);

	/*
	 *	Detach from coordinators.
	 */
	if (utt && utt->el && (modules_rlm_coord_detach() > 0)) {
		if (unlikely(fr_coord_close_event_insert(utt->el) < 0)) {
			ERROR("Failed setting up coordinator close events");
		}
		fr_event_loop(utt->el);
	}

	/*
	 *	Free thread data
	 */
	talloc_free(thread_ctx);

	fr_coords_destroy();

	fr_atexit_thread_trigger_all();

	if (utt && utt->el) fr_event_list_reap_signal(utt->el, fr_time_delta_from_sec(5), SIGKILL);

	main_loop_free();

	fr_atexit_thread_trigger_all();

	server_free();

	/*
	 *	Virtual servers need to be freed before modules
	 *	as state entries containing data with module-specific
	 *	destructors may exist.
	 */
	virtual_servers_free();

	modules_rlm_free();

	main_config_free(&config);

	fr_tls_dict_free();

	fr_dict_autofree(unit_test_tls_dict);

	if (fr_dict_free(&dict, __FILE__) < 0) {
		fr_perror("unit_test_tls - dict");
		ret = EXIT_FAILURE;
	}

	fr_openssl_free();

	if (receipt_file && (ret == EXIT_SUCCESS) && (fr_touch(NULL, receipt_file, 0644, true, 0755) <= 0)) {
		fr_perror("unit_test_tls");
		ret = EXIT_FAILURE;
	}

	if (talloc_free(autofree) < 0) {
		fr_perror("unit_test_tls - autofree");
		ret = EXIT_FAILURE;
	}

	/*
	 *	Ensure our atexit handlers run before any other
	 *	atexit handlers registered by third party libraries.
	 */
	fr_atexit_global_trigger_all();

	return ret;
}

/*
 *  Display the syntax for starting this program.
 */
static NEVER_RETURNS void usage(main_config_t const *config, int status)
{
	FILE *output = status ? stderr : stdout;

	fprintf(output, "Usage: %s [options]\n", config->name);
	fprintf(output, "Options:\n");
	fprintf(output, "  -A                 Reject the peer with a fatal TLS alert, rather than completing\n");
	fprintf(output, "                     the handshake.  Used to test the alert path.\n");
	fprintf(output, "  -c <count>         Run <count> connections, one after another.  Session resumption\n");
	fprintf(output, "                     needs two: one to fill the cache, one to resume from it.\n");
	fprintf(output, "  -C                 Check configuration and exit.\n");
	fprintf(output, "  -d <confdir>       Configuration file directory. (defaults to " CONFDIR ").\n");
	fprintf(output, "  -D <dict_dir>      Dictionary files are in \"dict_dir/*\".\n");
	fprintf(output, "  -h                 Print this help message.\n");
	fprintf(output, "  -M                 Enable talloc leak reporting.\n");
	fprintf(output, "  -n <name>          Read ${confdir}/name.conf instead of ${confdir}/unit_test_tls.conf.\n");
	fprintf(output, "  -r <receipt_file>  Create <receipt_file> when the program exits successfully.\n");
	fprintf(output, "  -s <server[:port]> Connect to <server> as a TLS client, instead of listening\n");
	fprintf(output, "                     for a connection.  Reads the 'tls client' section.  The port\n");
	fprintf(output, "                     defaults to 'port' from the 'unit_test_tls' section.\n");
	fprintf(output, "  -X                 Turn on full debugging.\n");
	fprintf(output, "  -x                 Turn on additional debugging. (-xx gives more debugging).\n");

	fr_exit_now(status);
}
