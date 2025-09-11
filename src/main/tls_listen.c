/*
 * tls.c
 *
 * Version:     $Id$
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
 * Copyright 2001  hereUare Communications, Inc. <raghud@hereuare.com>
 * Copyright 2003  Alan DeKok <aland@freeradius.org>
 * Copyright 2006  The FreeRADIUS server project
 */

RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/process.h>
#include <freeradius-devel/rad_assert.h>

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef WITH_TCP
#ifdef WITH_TLS
#ifdef HAVE_OPENSSL_RAND_H
#include <openssl/rand.h>
#endif

#ifdef HAVE_OPENSSL_OCSP_H
#include <openssl/ocsp.h>
#endif

#ifdef HAVE_PTHREAD_H
#define PTHREAD_MUTEX_LOCK pthread_mutex_lock
#define PTHREAD_MUTEX_UNLOCK pthread_mutex_unlock
#else
#define PTHREAD_MUTEX_LOCK(_x)
#define PTHREAD_MUTEX_UNLOCK(_x)
#endif

#define LOG_PREFIX "TLS"

static void dump_hex(char const *msg, uint8_t const *data, size_t data_len)
{
	size_t i;

	if (rad_debug_lvl < 3) return;

	printf("%s %d\n", msg, (int) data_len);
	if (data_len > 256) data_len = 256;

	for (i = 0; i < data_len; i++) {
		if ((i & 0x0f) == 0x00) printf ("%02x: ", (unsigned int) i);
		printf("%02x ", data[i]);
		if ((i & 0x0f) == 0x0f) printf ("\n");
	}
	printf("\n");
	fflush(stdout);
}

static void tls_socket_close(rad_listen_t *listener)
{
	listen_socket_t *sock = listener->data;
	REQUEST *request = sock->request;

	if (!sock->client_closed) SSL_shutdown(sock->ssn->ssl);

	listener->status = RAD_LISTEN_STATUS_EOL;
	listener->tls = NULL; /* parent owns this! */

	/*
	 *	Tell the event handler that an FD has disappeared.
	 */
	ROPTIONAL(RDEBUG3, DEBUG3, "(TLS) Closing connection");
	radius_update_listener(listener);

	/*
	 *	Do NOT free the listener here.  It may be in use by
	 *	a request, and will need to hang around until
	 *	all of the requests are done.
	 *
	 *	It is instead free'd when all of the requests using it
	 *	are done.
	 */
}

static void tls_write_available(fr_event_list_t *el, int sock, void *ctx);

static int CC_HINT(nonnull) tls_socket_write(rad_listen_t *listener)
{
	ssize_t rcode;
	listen_socket_t *sock = listener->data;

	/*
	 *	It's not writable, so we don't bother writing to it.
	 */
	if (listener->blocked) return 0;

	/*
	 *	Write as much as possible.
	 */
	rcode = write(listener->fd, sock->ssn->dirty_out.data, sock->ssn->dirty_out.used);
	if (rcode <= 0) {
#ifdef EWOULDBLOCK
		/*
		 *	Writing to the socket would cause it to block.
		 *	As a result, we just mark it as "don't use"
		 *	until such time as it becomes writable.
		 */
		if (errno == EWOULDBLOCK) {
			proxy_listener_freeze(listener, tls_write_available);
			return 0;
		}
#endif


		ERROR("(TLS) Error writing to socket: %s", fr_syserror(errno));
		tls_socket_close(listener);
		return -1;
	}

	/*
	 *	All of the data was written.  It's fine.
	 */
	if ((size_t) rcode == sock->ssn->dirty_out.used) {
		sock->ssn->dirty_out.used = 0;
		return 0;
	}

	/*
	 *	Move the data to the start of the buffer.
	 *
	 *	Yes, this is horrible.  But doing this means that we
	 *	don't have to modify the rest of the code which mangles dirty_out, and assumes that the write offset is always &data[used].
	 */
	memmove(&sock->ssn->dirty_out.data[0], &sock->ssn->dirty_out.data[rcode], sock->ssn->dirty_out.used - rcode);
	sock->ssn->dirty_out.used -= rcode;

	return 0;
}

static int try_connect(rad_listen_t *listener);

static void tls_write_available(UNUSED fr_event_list_t *el, UNUSED int fd, void *ctx)
{
	rad_listen_t *listener = ctx;
	listen_socket_t *sock = listener->data;

	/*
	 *	Try to connect once the socket has become writeable.
	 */
	if (!sock->ssn->connected) {
		int rcode;

		rcode = try_connect(listener);
		if (rcode <= 0) {
			tls_socket_close(listener);
			return;
		}

		if (!sock->ssn->connected) {
			return;
		}
	}

	proxy_listener_thaw(listener);

	PTHREAD_MUTEX_LOCK(&sock->mutex);
	if (sock->ssn->dirty_out.used) (void) tls_socket_write(listener);
	PTHREAD_MUTEX_UNLOCK(&sock->mutex);
}


/*
 *	Check for PROXY protocol.  Once that's done, clear
 *	listener->proxy_protocol.
 */
static int proxy_protocol_check(rad_listen_t *listener, REQUEST *request)
{
	listen_socket_t *sock = listener->data;
	uint8_t const *p, *end, *eol;
	int af, argc, src_port, dst_port;
	unsigned long num;
	fr_ipaddr_t src, dst;
	char *argv[5], *eos;
	ssize_t rcode;
	RADCLIENT *client;

	/*
	 *	Begin by trying to fill the buffer.
	 */
	rcode = read(request->packet->sockfd,
		     sock->ssn->dirty_in.data + sock->ssn->dirty_in.used,
		     sizeof(sock->ssn->dirty_in.data) - sock->ssn->dirty_in.used);
	if (rcode < 0) {
		if (errno == EINTR) return 0;
		RDEBUG("(TLS) Closing PROXY socket from client port %u due to read error - %s", sock->other_port, fr_syserror(errno));
		return -1;
	}

	if (rcode == 0) {
		DEBUG("(TLS) Closing PROXY socket from client port %u - other end closed connection", sock->other_port);
		return -1;
	}

	/*
	 *	We've read data, scan the buffer for a CRLF.
	 */
	sock->ssn->dirty_in.used += rcode;

	dump_hex("READ FROM PROXY PROTOCOL SOCKET", sock->ssn->dirty_in.data, sock->ssn->dirty_in.used);

	p = sock->ssn->dirty_in.data;

	/*
	 *	CRLF MUST be within the first 107 bytes.
	 */
	if (sock->ssn->dirty_in.used < 107) {
		end = p + sock->ssn->dirty_in.used;
	} else {
		end = p + 107;
	}
	eol = NULL;

	/*
	 *	Scan for CRLF.
	 */
	while ((p + 1) < end) {
		if ((p[0] == 0x0d) && (p[1] == 0x0a)) {
			eol = p;
			break;
		}

		/*
		 *	Other control characters, or non-ASCII data.
		 *	That's a problem.
		 */
		if ((*p < ' ') || (*p >= 0x80)) {
		invalid_data:
			DEBUG("(TLS) Closing PROXY socket from client port %u - received invalid data", sock->other_port);
			return -1;
		}

		p++;
	}

	/*
	 *	No CRLF, keep reading until we have it.
	 */
	if (!eol) return 0;

	p = sock->ssn->dirty_in.data;

	/*
	 *	Let's see if the PROXY line is well-formed.
	 */
	if ((eol - p) < 14) goto invalid_data;

	/*
	 *	We only support TCP4 and TCP6.
	 */
	if (memcmp(p, "PROXY TCP", 9) != 0) goto invalid_data;

	p += 9;

	if (*p == '4') {
		af = AF_INET;

	} else if (*p == '6') {
		af = AF_INET6;

	} else goto invalid_data;

	p++;
	if (*p != ' ') goto invalid_data;
	p++;

	sock->ssn->dirty_in.data[eol - sock->ssn->dirty_in.data] = '\0'; /* overwite the CRLF */

	/*
	 *	Parse the fields (being a little forgiving), while
	 *	checking for too many / too few fields.
	 */
	argc = str2argv((char *) &sock->ssn->dirty_in.data[p - sock->ssn->dirty_in.data], (char **) &argv, 5);
	if (argc != 4) goto invalid_data;

	memset(&src, 0, sizeof(src));
	memset(&dst, 0, sizeof(dst));

	if (fr_pton(&src, argv[0], -1, af, false) < 0) goto invalid_data;
	if (fr_pton(&dst, argv[1], -1, af, false) < 0) goto invalid_data;

	num = strtoul(argv[2], &eos, 10);
	if (num > 65535) goto invalid_data;
	if (*eos) goto invalid_data;
	src_port = num;

	num = strtoul(argv[3], &eos, 10);
	if (num > 65535) goto invalid_data;
	if (*eos) goto invalid_data;
	dst_port = num;

	/*
	 *	And copy the various fields around.
	 */
	sock->haproxy_src_ipaddr = sock->other_ipaddr;
	sock->haproxy_src_port = sock->other_port;

	sock->haproxy_dst_ipaddr = sock->my_ipaddr;
	sock->haproxy_dst_port = sock->my_port;

	sock->my_ipaddr = dst;
	sock->my_port = dst_port;

	sock->other_ipaddr = src;
	sock->other_port = src_port;

	/*
	 *	Print out what we've changed.  Note that the TCP
	 *	socket address family and the PROXY address family may
	 *	be different!
	 */
	if (RDEBUG_ENABLED) {
		char src_buf[128], dst_buf[128];

		RDEBUG("(TLS) Received PROXY protocol connection from client %s:%s -> %s:%s, via proxy %s:%u -> %s:%u",
		       argv[0], argv[2], argv[1], argv[3],
		       inet_ntop(af, &sock->haproxy_src_ipaddr.ipaddr, src_buf, sizeof(src_buf)),
		       sock->haproxy_src_port,
		       inet_ntop(af, &sock->haproxy_dst_ipaddr.ipaddr, dst_buf, sizeof(dst_buf)),
		       sock->haproxy_dst_port);
	}

        /*
         *      Ensure that the source IP indicated by the PROXY
         *      protocol is a known TLS client.
         */
        if ((client = client_listener_find(listener, &src, src_port)) == NULL ||
             client->proto != IPPROTO_TCP) {
		RDEBUG("(TLS) Unknown client %s - dropping PROXY protocol connection", argv[0]);
		return -1;
        }

        /*
         *      Use the client indicated by the proxy.
         */
        sock->client = client;

	/*
         *      Fix up the current request so that the first packet's
         *      src/dst is valid.  Subsequent packets will get the
         *      clients IP from the listener and listen_sock
         *      structures.
         */
        request->packet->dst_ipaddr = dst;
        request->packet->dst_port = dst_port;
        request->packet->src_ipaddr = src;
        request->packet->src_port = src_port;

	/*
	 *	Move any remaining TLS data to the start of the buffer.
	 */
	eol += 2;
	end = sock->ssn->dirty_in.data + sock->ssn->dirty_in.used;
	if (eol < end) {
		memmove(sock->ssn->dirty_in.data, eol, end - eol);
		sock->ssn->dirty_in.used = end - eol;
	} else {
		sock->ssn->dirty_in.used = 0;
	}

	/*
	 *	It's no longer a PROXY protocol, but just straight TLS.
	 */
	listener->proxy_protocol = false;

	return 1;
}

static int tls_socket_recv(rad_listen_t *listener)
{
	bool doing_init = false, already_read = false;
	ssize_t rcode;
	size_t data_len;
	RADIUS_PACKET *packet;
	REQUEST *request;
	listen_socket_t *sock = listener->data;
	fr_tls_status_t status;

	if (!sock->packet) {
		sock->packet = rad_alloc(sock, false);
		if (!sock->packet) return 0;

		sock->packet->sockfd = listener->fd;
		sock->packet->src_ipaddr = sock->other_ipaddr;
		sock->packet->src_port = sock->other_port;
		sock->packet->dst_ipaddr = sock->my_ipaddr;
		sock->packet->dst_port = sock->my_port;

		if (sock->request) sock->request->packet = talloc_steal(sock->request, sock->packet);
	}

	/*
	 *	Allocate a REQUEST for debugging, and initialize the TLS session.
	 */
	if (!sock->request) {
		sock->request = request = request_alloc(sock);
		if (!sock->request) {
			ERROR("Out of memory");
			return 0;
		}

		rad_assert(request->packet == NULL);
		rad_assert(sock->packet != NULL);
		request->packet = talloc_steal(request, sock->packet);

		request->component = "<tls-connect>";

		request->reply = rad_alloc(request, false);
		if (!request->reply) return 0;

		rad_assert(sock->ssn == NULL);

		sock->ssn = tls_new_session(sock, listener->tls, sock->request,
					    listener->tls->require_client_cert, true);
		if (!sock->ssn) {
			TALLOC_FREE(sock->request);
			sock->packet = NULL;
			return 0;
		}

		SSL_set_ex_data(sock->ssn->ssl, FR_TLS_EX_INDEX_REQUEST, (void *)request);
		SSL_set_ex_data(sock->ssn->ssl, fr_tls_ex_index_certs, (void *) &sock->certs);
		SSL_set_ex_data(sock->ssn->ssl, FR_TLS_EX_INDEX_TALLOC, sock);

		sock->ssn->quick_session_tickets = true; /* we don't have inner-tunnel authentication */

		doing_init = true;
	}

	rad_assert(sock->request != NULL);
	rad_assert(sock->request->packet != NULL);
	rad_assert(sock->packet != NULL);
	rad_assert(sock->ssn != NULL);

	request = sock->request;

	/*
	 *	Bypass ALL of the TLS stuff until we've read the PROXY
	 *	header.
	 *
	 *	If the PROXY header checks pass, then the flag is
	 *	cleared, as we don't need it any more.
	 */
	if (listener->proxy_protocol) {
		rcode = proxy_protocol_check(listener, request);
		if (rcode < 0) {
			RDEBUG("(TLS) Closing PROXY TLS socket from client port %u", sock->other_port);
			tls_socket_close(listener);
			return 0;
		}
		if (rcode == 0) return 1;

		/*
		 *	The buffer might already have data.  In that
		 *	case, we don't want to do a blocking read
		 *	later.
		 */
		already_read = (sock->ssn->dirty_in.used > 0);
	}

	if (sock->state == LISTEN_TLS_SETUP) {
		RDEBUG3("(TLS) Setting connection state to RUNNING");
		sock->state = LISTEN_TLS_RUNNING;

		if (sock->ssn->clean_out.used < 20) {
			goto get_application_data;
		}

		goto read_application_data;
	}

	RDEBUG3("(TLS) Reading from socket %d", request->packet->sockfd);
	PTHREAD_MUTEX_LOCK(&sock->mutex);

	/*
	 *	If there is pending application data, as set up by
	 *	SSL_peek(), read that before reading more data from
	 *	the socket.
	 */
	if (SSL_pending(sock->ssn->ssl)) {
		RDEBUG3("(TLS) Reading pending buffered data");
		sock->ssn->dirty_in.used = 0;
		goto check_for_setup;
	}

	/*
	 *	Is there already enough application data in the buffer for the
	 *	next RADIUS packet?
	 */
	if (sock->ssn->clean_out.used >= 20 &&
	    ((int) sock->ssn->clean_out.used) >= ((sock->ssn->clean_out.data[2] << 8) | sock->ssn->clean_out.data[3])) {
		goto read_application_data;
	}

	if (!already_read) {
		rcode = read(request->packet->sockfd,
			     sock->ssn->dirty_in.data,
			     sizeof(sock->ssn->dirty_in.data));
		if ((rcode < 0) && (errno == ECONNRESET)) {
		do_close:
			RDEBUG("(TLS) Closing socket from client port %u", sock->other_port);
			tls_socket_close(listener);
			PTHREAD_MUTEX_UNLOCK(&sock->mutex);
			return 0;
		}

		if (rcode < 0) {
			RDEBUG("(TLS) Error reading socket: %s", fr_syserror(errno));
			goto do_close;
		}

		/*
		 *	Normal socket close.
		 */
		if (rcode == 0) {
			RDEBUG("(TLS) Client has closed the TCP connection");
			sock->client_closed = true;
			goto do_close;
		}

		sock->ssn->dirty_in.used = rcode;
	}

	dump_hex("READ FROM SSL", sock->ssn->dirty_in.data, sock->ssn->dirty_in.used);

	/*
	 *	Catch attempts to use non-SSL.
	 */
	if (doing_init && (sock->ssn->dirty_in.data[0] != handshake)) {
		RDEBUG("(TLS) Non-TLS data sent to TLS socket: closing");
		goto do_close;
	}

	/*
	 *	If we need to do more initialization, do that here.
	 */
check_for_setup:
	if (!sock->ssn->is_init_finished) {
		if (!tls_handshake_recv(request, sock->ssn)) {
			RDEBUG("(TLS) Failed in TLS handshake receive");
			goto do_close;
		}

		/*
		 *	More ACK data to send.  Do so.
		 */
		if (sock->ssn->dirty_out.used > 0) {
			RDEBUG3("(TLS) Writing to socket %d", listener->fd);
			tls_socket_write(listener);
			PTHREAD_MUTEX_UNLOCK(&sock->mutex);
			return 0;
		}

		/*
		 *      If SSL handshake still isn't finished, then there
		 *      is more data to read.  Release the mutex and
		 *      return so this function will be called again
		 */
		if (!SSL_is_init_finished(sock->ssn->ssl)) {
			PTHREAD_MUTEX_UNLOCK(&sock->mutex);
			return 0;
		}
	}

	/*
	 *	Run the request through a virtual server in
	 *	order to see if we like the certificate
	 *	presented by the client.
	 */
	if (sock->state == LISTEN_TLS_INIT) {
		if (!SSL_is_init_finished(sock->ssn->ssl)) {
			RDEBUG("(TLS) OpenSSL says that the TLS session is still negotiating, but there's no more data to send!");
			goto do_close;
		}

		sock->ssn->is_init_finished = true;
		if (!listener->check_client_connections) {
			sock->state = LISTEN_TLS_RUNNING;
			goto get_application_data;
		}

		request->packet->vps = fr_pair_list_copy(request->packet, sock->certs);

		/*
		 *	Fake out a Status-Server packet, which
		 *	does NOT have a Message-Authenticator,
		 *	or any other contents.
		 */
		request->packet->code = PW_CODE_STATUS_SERVER;
		request->packet->id = request->reply->id = 0;
		request->packet->data = talloc_zero_array(request->packet, uint8_t, 20);
		request->packet->data[0] = PW_CODE_STATUS_SERVER;
		request->packet->data[3] = 20;
		request->listener = listener;
		sock->state = LISTEN_TLS_CHECKING;
		PTHREAD_MUTEX_UNLOCK(&sock->mutex);

		/*
		 *	Don't read from the socket until the request
		 *	returns.
		 */
		listener->status = RAD_LISTEN_STATUS_PAUSE;
		radius_update_listener(listener);

		return 1;
	}

	/*
	 *	Try to get application data.
	 */
get_application_data:
	/*
	 *	More data to send.  Do so.
	 */
	if (sock->ssn->dirty_out.used > 0) {
		RDEBUG3("(TLS) Writing to socket %d", listener->fd);
		rcode = tls_socket_write(listener);
		if (rcode < 0) {
			PTHREAD_MUTEX_UNLOCK(&sock->mutex);
			return rcode;
		}
	}

	status = tls_application_data(sock->ssn, request);
	RDEBUG3("(TLS) Application data status %d", status);

	/*
	 *	Some kind of failure.  Close the socket.
	 */
	if (status == FR_TLS_FAIL) {
		DEBUG("(TLS) Unable to recover from TLS error, closing socket from client port %u", sock->other_port);
		tls_socket_close(listener);
		PTHREAD_MUTEX_UNLOCK(&sock->mutex);
		return 0;
	}

	if (status == FR_TLS_MORE_FRAGMENTS) {
		PTHREAD_MUTEX_UNLOCK(&sock->mutex);
		return 0;
	}

	if (sock->ssn->clean_out.used == 0) {
		PTHREAD_MUTEX_UNLOCK(&sock->mutex);
		return 0;
	}

	/*
	 *	Hold application data if we're not yet in the RUNNING
	 *	state.
	 */
	if (sock->state != LISTEN_TLS_RUNNING) {
		RDEBUG3("(TLS) Holding application data until setup is complete");
		PTHREAD_MUTEX_UNLOCK(&sock->mutex);
		return 0;
	}

read_application_data:
	/*
	 *	We now have a bunch of application data.
	 */
	dump_hex("TUNNELED DATA > ", sock->ssn->clean_out.data, sock->ssn->clean_out.used);

	/*
	 *	If the packet is a complete RADIUS packet, return it to
	 *	the caller.  Otherwise...
	 */
	if (sock->ssn->clean_out.used < 20) {
		RDEBUG3("(TLS) Received partial packet (have %zu, want >=20), waiting for more.",
			sock->ssn->clean_out.used);
		PTHREAD_MUTEX_UNLOCK(&sock->mutex);
		return 0;
	}

	if (((int) sock->ssn->clean_out.used) < ((sock->ssn->clean_out.data[2] << 8) | sock->ssn->clean_out.data[3])) {
		RDEBUG3("(TLS) Received partial packet (have %zu, want %u), waiting for more.",
			sock->ssn->clean_out.used, (sock->ssn->clean_out.data[2] << 8) | sock->ssn->clean_out.data[3]);
		PTHREAD_MUTEX_UNLOCK(&sock->mutex);
		return 0;
	}

	data_len = (sock->ssn->clean_out.data[2] << 8) | sock->ssn->clean_out.data[3];

	packet = sock->packet;
	packet->data = talloc_array(packet, uint8_t, data_len);
	packet->data_len = data_len;
	sock->ssn->record_minus(&sock->ssn->clean_out, packet->data, packet->data_len);
	packet->vps = NULL;
	PTHREAD_MUTEX_UNLOCK(&sock->mutex);

#ifdef WITH_RADIUSV11
	packet->radiusv11 = sock->radiusv11;
#endif
	packet->tls = true;

	if (!rad_packet_ok(packet, 0, NULL)) {
		if (DEBUG_ENABLED) ERROR("Receive - %s", fr_strerror());
		DEBUG("(TLS) Closing TLS socket from client");
		PTHREAD_MUTEX_LOCK(&sock->mutex);
		tls_socket_close(listener);
		PTHREAD_MUTEX_UNLOCK(&sock->mutex);
		return 0;	/* do_close unlocks the mutex */
	}

	/*
	 *	Copied from src/lib/radius.c, rad_recv();
	 */
	if (fr_debug_lvl) {
		char host_ipaddr[128];

		if (is_radius_code(packet->code)) {
			RDEBUG("(TLS): %s packet from host %s port %d, id=%d, length=%d",
			       fr_packet_codes[packet->code],
			       inet_ntop(packet->src_ipaddr.af,
					 &packet->src_ipaddr.ipaddr,
					 host_ipaddr, sizeof(host_ipaddr)),
			       packet->src_port,
			       packet->id, (int) packet->data_len);
		} else {
			RDEBUG("(TLS): Packet from host %s port %d code=%d, id=%d, length=%d",
			       inet_ntop(packet->src_ipaddr.af,
					 &packet->src_ipaddr.ipaddr,
					 host_ipaddr, sizeof(host_ipaddr)),
			       packet->src_port,
			       packet->code,
			       packet->id, (int) packet->data_len);
		}
	}

	return 1;
}

int dual_tls_recv(rad_listen_t *listener)
{
	RADIUS_PACKET *packet;
	RAD_REQUEST_FUNP fun = NULL;
	listen_socket_t *sock = listener->data;
	RADCLIENT	*client = sock->client;
	BIO		*rbio;
#ifdef WITH_COA_TUNNEL
	bool		is_reply = false;
#endif

	if (listener->status != RAD_LISTEN_STATUS_KNOWN) return 0;

redo:
	if (!tls_socket_recv(listener)) {
		return 0;
	}

	rad_assert(sock->packet != NULL);
	rad_assert(sock->ssn != NULL);
	rad_assert(client != NULL);

	packet = talloc_steal(NULL, sock->packet);
	sock->request->packet = NULL;
	sock->packet = NULL;

	/*
	 *	Some sanity checks, based on the packet code.
	 *
	 *	"auth+acct" are marked as "auth", with the "dual" flag
	 *	set.
	 */
	switch (packet->code) {
	case PW_CODE_ACCESS_REQUEST:
		if (listener->type != RAD_LISTEN_AUTH) goto bad_packet;
		FR_STATS_INC(auth, total_requests);
		fun = rad_authenticate;
		break;

#ifdef WITH_ACCOUNTING
	case PW_CODE_ACCOUNTING_REQUEST:
		if (listener->type != RAD_LISTEN_ACCT) {
			/*
			 *	Allow auth + dual.  Disallow
			 *	everything else.
			 */
			if (!((listener->type == RAD_LISTEN_AUTH) &&
			      (listener->dual))) {
				    goto bad_packet;
			}
		}
		FR_STATS_INC(acct, total_requests);
		fun = rad_accounting;
		break;
#endif

#ifdef WITH_COA
	case PW_CODE_COA_REQUEST:
		if (listener->type != RAD_LISTEN_COA) goto bad_packet;
		FR_STATS_INC(coa, total_requests);
		fun = rad_coa_recv;
		break;

	case PW_CODE_DISCONNECT_REQUEST:
		if (listener->type != RAD_LISTEN_COA) goto bad_packet;
		FR_STATS_INC(dsc, total_requests);
		fun = rad_coa_recv;
		break;

#ifdef WITH_COA_TUNNEL
	case PW_CODE_COA_ACK:
	case PW_CODE_COA_NAK:
		if (!listener->send_coa) goto bad_packet;
		is_reply = true;
                break;
#endif
#endif

	case PW_CODE_STATUS_SERVER:
		if (!main_config.status_server
#ifdef WITH_TLS
		    && !listener->check_client_connections
#endif
			) {
			FR_STATS_INC(auth, total_unknown_types);
			WARN("Ignoring Status-Server request due to security configuration");
			rad_free(&packet);
			return 0;
		}
		fun = rad_status_server;
		break;

	default:
	bad_packet:
		FR_STATS_INC(auth, total_unknown_types);

		DEBUG("(TLS) Invalid packet code %d sent from client %s port %d : IGNORED",
		      packet->code, client->shortname, packet->src_port);
		rad_free(&packet);
		return 0;
	} /* switch over packet types */

#ifdef WITH_COA_TUNNEL
	if (is_reply) {
		if (!request_proxy_reply(packet)) {
			rad_free(&packet);
			return 0;
		}
	} else
#endif

	if (!request_receive(NULL, listener, packet, client, fun)) {
		FR_STATS_INC(auth, total_packets_dropped);
		rad_free(&packet);
		return 0;
	}

	/*
	 *	Check for more application data.
	 *
	 *	If there is pending SSL data, "peek" at the
	 *	application data.  If we get at least one byte of
	 *	application data, go back to tls_socket_recv().
	 *	SSL_peek() will set SSL_pending(), and
	 *	tls_socket_recv() will read another packet.
	 */
	rbio = SSL_get_rbio(sock->ssn->ssl);
	if (BIO_ctrl_pending(rbio)) {
		char buf[1];
		int peek = SSL_peek(sock->ssn->ssl, buf, 1);

		if (peek > 0) {
			DEBUG("(TLS) more TLS records after dual_tls_recv");
			goto redo;
		}
	}

	/*
	 *	If there is enough remaining application data in the buffer for another
	 *	RADIUS packet, re-run tls_socket_recv() to process it.
	 */
	if (sock->ssn->clean_out.used >= 20 &&
	    ((int) sock->ssn->clean_out.used) >= ((sock->ssn->clean_out.data[2] << 8) | sock->ssn->clean_out.data[3])) {
		DEBUG3("(TLS) %ld bytes of application data remaining", sock->ssn->clean_out.used);
		goto redo;
	}

	return 1;
}


/*
 *	Send a response packet
 */
int dual_tls_send(rad_listen_t *listener, REQUEST *request)
{
	listen_socket_t *sock = listener->data;

	VERIFY_REQUEST(request);

	rad_assert(request->listener == listener);
	rad_assert(listener->send == dual_tls_send);

	/*
	 *	If the socket is vaguely alive, then write to it.
	 *	Otherwise it's dead, and we don't do anything.
	 */
	switch (listener->status) {
	case RAD_LISTEN_STATUS_KNOWN:
	case RAD_LISTEN_STATUS_FROZEN:
	case RAD_LISTEN_STATUS_PAUSE:
	case RAD_LISTEN_STATUS_RESUME:
		break;

	case RAD_LISTEN_STATUS_INIT:
	case RAD_LISTEN_STATUS_EOL:
	case RAD_LISTEN_STATUS_REMOVE_NOW:
		return 0;
	}

	/*
	 *	We're trying to send a reply to the "check
	 *	client connection" packet.  Instead, just
	 *	finish the session setup.
	 */
	if (sock->state == LISTEN_TLS_SETUP) {
		RDEBUG("(TLS) Finishing session setup");
		return 0;
	}

	/*
	 *	The code in rad_status_server() looks for this state,
	 *	and either swaps it to LISTEN_TLS_SETUP, or else
	 *	changes listener->status to EOL.  As a result, this
	 *	state should never be reachable in the send() routine.
	 */
	fr_assert(sock->state != LISTEN_TLS_CHECKING);

	/*
	 *	Accounting reject's are silently dropped.
	 *
	 *	We do it here to avoid polluting the rest of the
	 *	code with this knowledge
	 */
	if (request->reply->code == 0) return 0;

#ifdef WITH_COA_TUNNEL
	/*
	 *	Save the key, if we haven't already done that.
	 */
	if (listener->send_coa && !listener->key) {
		VALUE_PAIR *vp = NULL;

		vp = fr_pair_find_by_num(request->config, PW_ORIGINATING_REALM_KEY, 0, TAG_ANY);
		if (vp) {
			RDEBUG("Adding send CoA listener with key %s", vp->vp_strvalue);
			listen_coa_add(request->listener, vp->vp_strvalue);
		}
	}
#endif

	/*
	 *	Pack the VPs
	 */
	if (rad_encode(request->reply, request->packet,
		       request->client->secret) < 0) {
		RERROR("Failed encoding packet: %s", fr_strerror());
		return 0;
	}

	if (request->reply->data_len > (MAX_PACKET_LEN - 100)) {
		RWARN("Packet is large, and possibly truncated - %zd vs max %d",
		      request->reply->data_len, MAX_PACKET_LEN);
	}

	/*
	 *	Sign the packet.
	 */
	if (rad_sign(request->reply, request->packet,
		       request->client->secret) < 0) {
		RERROR("Failed signing packet: %s", fr_strerror());
		return 0;
	}

	PTHREAD_MUTEX_LOCK(&sock->mutex);

	/*
	 *	Write the packet to the SSL buffers.
	 */
	sock->ssn->record_plus(&sock->ssn->clean_in,
			       request->reply->data, request->reply->data_len);

	dump_hex("TUNNELED DATA < ", sock->ssn->clean_in.data, sock->ssn->clean_in.used);

	/*
	 *	Do SSL magic to get encrypted data.
	 */
	tls_handshake_send(request, sock->ssn);

	/*
	 *	And finally write the data to the socket.
	 */
	if (sock->ssn->dirty_out.used > 0) {
		dump_hex("WRITE TO SSL", sock->ssn->dirty_out.data, sock->ssn->dirty_out.used);

		RDEBUG3("(TLS) Writing to socket %d", listener->fd);
		tls_socket_write(listener);
	}
	PTHREAD_MUTEX_UNLOCK(&sock->mutex);

	return 0;
}

#ifdef WITH_COA_TUNNEL
/*
 *	Send a CoA request to a NAS, as a proxied packet.
 *
 *	The proxied packet MUST already have been encoded.
 */
int dual_tls_send_coa_request(rad_listen_t *listener, REQUEST *request)
{
	listen_socket_t *sock = listener->data;

	VERIFY_REQUEST(request);

	rad_assert(listener->proxy_send == dual_tls_send_coa_request);

	if (listener->status != RAD_LISTEN_STATUS_KNOWN) return 0;

	rad_assert(request->proxy->data);

	if (request->proxy->data_len > (MAX_PACKET_LEN - 100)) {
		RWARN("Packet is large, and possibly truncated - %zd vs max %d",
		      request->proxy->data_len, MAX_PACKET_LEN);
	}

	PTHREAD_MUTEX_LOCK(&sock->mutex);

	/*
	 *	Write the packet to the SSL buffers.
	 */
	sock->ssn->record_plus(&sock->ssn->clean_in,
			       request->proxy->data, request->proxy->data_len);

	dump_hex("TUNNELED DATA < ", sock->ssn->clean_in.data, sock->ssn->clean_in.used);

	/*
	 *	Do SSL magic to get encrypted data.
	 */
	tls_handshake_send(request, sock->ssn);

	/*
	 *	And finally write the data to the socket.
	 */
	if (sock->ssn->dirty_out.used > 0) {
		dump_hex("WRITE TO SSL", sock->ssn->dirty_out.data, sock->ssn->dirty_out.used);

		RDEBUG3("(TLS) Writing to socket %d", listener->fd);
		tls_socket_write(listener);
	}
	PTHREAD_MUTEX_UNLOCK(&sock->mutex);

	return 0;
}
#endif

static int try_connect(rad_listen_t *this)
{
	int ret;
	time_t now;
	listen_socket_t *sock = this->data;

	now = time(NULL);
	if ((sock->opened + sock->connect_timeout) < now) {
		tls_error_io_log(NULL, sock->ssn, 0, "Timeout in SSL_connect");
		return -1;
	}

	ret = SSL_connect(sock->ssn->ssl);
	if (ret <= 0) {
		switch (SSL_get_error(sock->ssn->ssl, ret)) {
		default:
			tls_error_io_log(NULL, sock->ssn, ret, "Failed in " STRINGIFY(__FUNCTION__) " (SSL_connect)");
			return -1;

		case SSL_ERROR_WANT_READ:
			if (this->blocked) proxy_listener_thaw(this);
			DEBUG3("(TLS) SSL_connect() returned WANT_READ");
			return 2;

		case SSL_ERROR_WANT_WRITE:
			if (!this->blocked) proxy_listener_freeze(this, tls_write_available);
			DEBUG3("(TLS) SSL_connect() returned WANT_WRITE");
			return 2;
		}
	}

	sock->ssn->connected = true;
	return 1;
}


#ifdef WITH_PROXY
#ifdef WITH_RADIUSV11
extern int fr_radiusv11_client_get_alpn(rad_listen_t *listener);
#endif

/*
 *	Read from the SSL socket.  Safe with either blocking or
 *	non-blocking IO.  This level of complexity is probably not
 *	necessary, as each packet gets put into one SSL application
 *	record.  When SSL has a full record, we should be able to read
 *	the entire packet via one SSL_read().
 *
 *	When SSL has a partial record, SSL_read() will return
 *	WANT_READ or WANT_WRITE, and zero application data.
 *
 *	Called with the mutex held.
 */
static ssize_t proxy_tls_read(rad_listen_t *listener)
{
	int rcode;
	size_t length;
	uint8_t *data;
	listen_socket_t *sock = listener->data;

	if (!sock->ssn->connected) {
		rcode = try_connect(listener);
		if (rcode <= 0) return rcode;

		if (rcode == 2) return 0; /* more negotiation needed */

#ifdef WITH_RADIUSV11
		if (!sock->alpn_checked && (fr_radiusv11_client_get_alpn(listener) < 0)) {
			tls_socket_close(listener);
			return -1;
		}
#endif
	}

	if (sock->ssn->clean_out.used) {
		DEBUG3("(TLS) proxy writing %zu to socket", sock->ssn->clean_out.used);
		/*
		 *	Write to SSL.
		 */
		rcode = SSL_write(sock->ssn->ssl, sock->ssn->clean_out.data, sock->ssn->clean_out.used);
		if (rcode > 0) {
			if ((size_t) rcode < sock->ssn->clean_out.used) {
				memmove(sock->ssn->clean_out.data,  sock->ssn->clean_out.data + rcode,
					sock->ssn->clean_out.used - rcode);
				sock->ssn->clean_out.used -= rcode;
			} else {
				sock->ssn->clean_out.used = 0;
			}
		}
	}

	/*
	 *	Get the maximum size of data to receive.
	 */
	if (!sock->data) sock->data = talloc_array(sock, uint8_t,
						   sock->ssn->mtu);

	data = sock->data;

	if (sock->partial < 4) {
		rcode = SSL_read(sock->ssn->ssl, data + sock->partial,
				 4 - sock->partial);
		if (rcode <= 0) {
			int err = SSL_get_error(sock->ssn->ssl, rcode);
			switch (err) {

			case SSL_ERROR_WANT_READ:
				DEBUG3("(TLS) OpenSSL returned WANT_READ");
				return 0;

			case SSL_ERROR_WANT_WRITE:
				DEBUG3("(TLS) OpenSSL returned WANT_WRITE");
				return 0;

			case SSL_ERROR_ZERO_RETURN:
				/* remote end sent close_notify, send one back */
				SSL_shutdown(sock->ssn->ssl);
				/* FALL-THROUGH */

			case SSL_ERROR_SYSCALL:
			do_close:
				return -1;

			case SSL_ERROR_SSL:
				DEBUG("(TLS) Home server has closed the connection");
				goto do_close;

			default:
				tls_error_log(NULL, "Failed in proxy receive with OpenSSL error %d", err);
				goto do_close;
			}
		}

		sock->partial = rcode;
	} /* try reading the packet header */

	if (sock->partial < 4) return 0; /* read more data */

	length = (data[2] << 8) | data[3];

	/*
	 *	Do these checks only once, when we read the header.
	 */
	if (sock->partial == 4) {
		DEBUG3("Proxy received header saying we have a packet of %u bytes",
		       (unsigned int) length);

		/*
		 *	FIXME: allocate a RADIUS_PACKET, and set
		 *	"data" to be as large as necessary.
		 */
		if (length > sock->ssn->mtu) {
			INFO("Received packet will be too large! Set \"fragment_size = %u\"",
			     (data[2] << 8) | data[3]);
			goto do_close;
		}
	}

	/*
	 *	Try to read some more.
	 */
	if (sock->partial < length) {
		rcode = SSL_read(sock->ssn->ssl, data + sock->partial,
				 length - sock->partial);
		if (rcode <= 0) {
			int err = SSL_get_error(sock->ssn->ssl, rcode);
			switch (err) {

			case SSL_ERROR_WANT_READ:
				DEBUG3("(TLS) OpenSSL returned WANT_READ");
				return 0;

			case SSL_ERROR_WANT_WRITE:
				DEBUG3("(TLS) OpenSSL returned WANT_WRITE");
				return 0;

			case SSL_ERROR_ZERO_RETURN:
				/* remote end sent close_notify, send one back */
				SSL_shutdown(sock->ssn->ssl);
				goto do_close;

			case SSL_ERROR_SSL:
				DEBUG("(TLS) Home server has closed the connection");
				goto do_close;

			default:
				DEBUG("(TLS) Unexpected OpenSSL error %d", err);
				goto do_close;
			}
		}

		sock->partial += rcode;
	}

	/*
	 *	If we're not done, say so.
	 *
	 *	Otherwise, reset the partially read data flag, and say
	 *	we have a packet.
	 */
	if (sock->partial < length) {
		return 0;
	}

	sock->partial = 0;	/* we've now read the packet */
	return length;
}


int proxy_tls_recv(rad_listen_t *listener)
{
	listen_socket_t *sock = listener->data;
	char buffer[256];
	RADIUS_PACKET *packet;
	uint8_t *data;
	ssize_t data_len;
#ifdef WITH_COA_TUNNEL
	bool is_request = false;
	RADCLIENT *client = sock->client;
#endif

	if (listener->status != RAD_LISTEN_STATUS_KNOWN) return 0;

	rad_assert(sock->ssn != NULL);

	DEBUG3("(TLS) Proxy socket has data to read");
	PTHREAD_MUTEX_LOCK(&sock->mutex);
	data_len = proxy_tls_read(listener);
	if (data_len < 0) {
		tls_socket_close(listener);
		PTHREAD_MUTEX_UNLOCK(&sock->mutex);
		DEBUG("(TLS) Closing connection to home server");
		return 0;
	}
	PTHREAD_MUTEX_UNLOCK(&sock->mutex);

	if (data_len == 0) {
		DEBUG3("(TLS) Proxy socket read no data from the network");
		return 0; /* not done yet */
	}

	data = sock->data;

	packet = rad_alloc(sock, false);
	packet->sockfd = listener->fd;
	packet->src_ipaddr = sock->other_ipaddr;
	packet->src_port = sock->other_port;
	packet->dst_ipaddr = sock->my_ipaddr;
	packet->dst_port = sock->my_port;
	packet->code = data[0];
	packet->id = data[1];
	packet->data_len = data_len;
	packet->data = talloc_array(packet, uint8_t, packet->data_len);
	memcpy(packet->data, data, packet->data_len);
	memcpy(packet->vector, packet->data + 4, 16);

#ifdef WITH_RADIUSV11
	packet->radiusv11 = sock->radiusv11;

	if (sock->radiusv11) {
		uint32_t id;

		memcpy(&id, data + 4, sizeof(id));
		packet->id = ntohl(id);
	}

#endif
	packet->tls = true;

	/*
	 *	FIXME: Client MIB updates?
	 */
	switch (packet->code) {
	case PW_CODE_ACCESS_ACCEPT:
	case PW_CODE_ACCESS_CHALLENGE:
	case PW_CODE_ACCESS_REJECT:
		break;

#ifdef WITH_ACCOUNTING
	case PW_CODE_ACCOUNTING_RESPONSE:
		break;
#endif

#ifdef WITH_COA
	case PW_CODE_COA_ACK:
	case PW_CODE_COA_NAK:
	case PW_CODE_DISCONNECT_ACK:
	case PW_CODE_DISCONNECT_NAK:
		break;

#ifdef WITH_COA_TUNNEL
	case PW_CODE_COA_REQUEST:
		if (!listener->send_coa) goto bad_packet;
		FR_STATS_INC(coa, total_requests);
		is_request = true;
		break;

	case PW_CODE_DISCONNECT_REQUEST:
		if (!listener->send_coa) goto bad_packet;
		FR_STATS_INC(dsc, total_requests);
		is_request = true;
		break;
#endif
#endif

	default:
#ifdef WITH_COA_TUNNEL
	bad_packet:
#endif
		/*
		 *	FIXME: Update MIB for packet types?
		 */
		ERROR("Invalid packet code %d sent to a proxy port "
		       "from home server %s port %d - ID %d : IGNORED",
		       packet->code,
		       ip_ntoh(&packet->src_ipaddr, buffer, sizeof(buffer)),
		       packet->src_port, packet->id);
		rad_free(&packet);
		return 0;
	}

#ifdef WITH_COA_TUNNEL
	if (is_request) {
		if (!request_receive(NULL, listener, packet, client, rad_coa_recv)) {
			FR_STATS_INC(auth, total_packets_dropped);
			rad_free(&packet);
			return 0;
		}
	} else
#endif
	if (!request_proxy_reply(packet)) {
		rad_free(&packet);
		return 0;
	}

	return 1;
}


int proxy_tls_send(rad_listen_t *listener, REQUEST *request)
{
	int rcode;
	listen_socket_t *sock = listener->data;

	VERIFY_REQUEST(request);

	if ((listener->status != RAD_LISTEN_STATUS_INIT) &&
	    (listener->status != RAD_LISTEN_STATUS_KNOWN)) return 0;

	/*
	 *	Normal proxying calls us with the data already
	 *	encoded.  The "ping home server" code does not.  So,
	 *	if there's no packet, encode it here.
	 */
	if (!request->proxy->data) {
		request->reply->tls = true;
		request->proxy_listener->proxy_encode(request->proxy_listener,
						      request);
	}

	rad_assert(sock->ssn != NULL);

	if (!sock->ssn->connected) {
		PTHREAD_MUTEX_LOCK(&sock->mutex);
		rcode = try_connect(listener);
		if (rcode <= 0) {
			tls_socket_close(listener);
			PTHREAD_MUTEX_UNLOCK(&sock->mutex);
			return rcode;
		}
		PTHREAD_MUTEX_UNLOCK(&sock->mutex);

		/*
		 *	More negotiation is needed, but remember to
		 *	save this packet to an intermediate buffer.
		 *	Once the SSL connection is established, the
		 *	later code writes the packet to the
		 *	connection.
		 */
		if (rcode == 2) {
			PTHREAD_MUTEX_LOCK(&sock->mutex);
			if ((sock->ssn->clean_out.used + request->proxy->data_len) > MAX_RECORD_SIZE) {
				PTHREAD_MUTEX_UNLOCK(&sock->mutex);
				RERROR("(TLS) Too much data buffered during SSL_connect()");
				listener->status = RAD_LISTEN_STATUS_EOL;
				radius_update_listener(listener);
				return -1;
			}

			RDEBUG3("(TLS) has %zu bytes in the buffer", sock->ssn->clean_out.used);

			memcpy(sock->ssn->clean_out.data + sock->ssn->clean_out.used, request->proxy->data, request->proxy->data_len);
			sock->ssn->clean_out.used += request->proxy->data_len;
			RDEBUG3("(TLS) Saving %zu bytes of RADIUS traffic for later (total %zu)", request->proxy->data_len, sock->ssn->clean_out.used);

			PTHREAD_MUTEX_UNLOCK(&sock->mutex);
			return 0;
		}

#ifdef WITH_RADIUSV11
		if (!sock->alpn_checked && (fr_radiusv11_client_get_alpn(listener) < 0)) {
			listener->status = RAD_LISTEN_STATUS_EOL;
			radius_update_listener(listener);
			return -1;
		}
#endif
	}

	DEBUG3("Proxy is writing %u bytes to SSL",
	       (unsigned int) request->proxy->data_len);
	PTHREAD_MUTEX_LOCK(&sock->mutex);

	/*
	 *	We may have previously cached data on SSL_connect(), which now needs to be written to the home server.
	 */
	if (sock->ssn->clean_out.used > 0) {
		if ((sock->ssn->clean_out.used + request->proxy->data_len) > MAX_RECORD_SIZE) {
			PTHREAD_MUTEX_UNLOCK(&sock->mutex);
			RERROR("(TLS) Too much data buffered after SSL_connect()");
			listener->status = RAD_LISTEN_STATUS_EOL;
			radius_update_listener(listener);
			return -1;
		}

		/*
		 *	Add in our packet.
		 */
		memcpy(sock->ssn->clean_out.data + sock->ssn->clean_out.used, request->proxy->data, request->proxy->data_len);
		sock->ssn->clean_out.used += request->proxy->data_len;

		/*
		 *	Write to SSL.
		 */
		DEBUG3("(TLS) proxy writing %zu to socket", sock->ssn->clean_out.used);

		rcode = SSL_write(sock->ssn->ssl, sock->ssn->clean_out.data, sock->ssn->clean_out.used);
		if (rcode > 0) {
			if ((size_t) rcode < sock->ssn->clean_out.used) {
				memmove(sock->ssn->clean_out.data,  sock->ssn->clean_out.data + rcode,
					sock->ssn->clean_out.used - rcode);
				sock->ssn->clean_out.used -= rcode;
			} else {
				sock->ssn->clean_out.used = 0;
			}
			PTHREAD_MUTEX_UNLOCK(&sock->mutex);
			return 1;
		}
	} else {
		rcode = SSL_write(sock->ssn->ssl, request->proxy->data,
				  request->proxy->data_len);
	}
	if (rcode < 0) {
		int err;

		err = ERR_get_error();
		switch (err) {
		case SSL_ERROR_NONE:
			break;

		case SSL_ERROR_WANT_READ:
			DEBUG3("(TLS) OpenSSL returned WANT_READ");
			break;

		case SSL_ERROR_WANT_WRITE:
			DEBUG3("(TLS) OpenSSL returned WANT_WRITE");
			break;

		default:
			tls_error_log(NULL, "Failed in proxy send with OpenSSL error %d", err);
			DEBUG("(TLS) Closing socket to home server");
			tls_socket_close(listener);
			PTHREAD_MUTEX_UNLOCK(&sock->mutex);
			return 0;
		}
	}
	PTHREAD_MUTEX_UNLOCK(&sock->mutex);

	return 1;
}

#ifdef WITH_COA_TUNNEL
int proxy_tls_send_reply(rad_listen_t *listener, REQUEST *request)
{
	int rcode;
	listen_socket_t *sock = listener->data;

	VERIFY_REQUEST(request);

	rad_assert(sock->ssn->connected);

	if ((listener->status != RAD_LISTEN_STATUS_INIT &&
	    (listener->status != RAD_LISTEN_STATUS_KNOWN))) return 0;

	request->reply->tls = true;

	/*
	 *	Pack the VPs
	 */
	if (rad_encode(request->reply, request->packet,
		       request->client->secret) < 0) {
		RERROR("Failed encoding packet: %s", fr_strerror());
		return 0;
	}

	if (request->reply->data_len > (MAX_PACKET_LEN - 100)) {
		RWARN("Packet is large, and possibly truncated - %zd vs max %d",
		      request->reply->data_len, MAX_PACKET_LEN);
	}

	/*
	 *	Sign the packet.
	 */
	if (rad_sign(request->reply, request->packet,
		       request->client->secret) < 0) {
		RERROR("Failed signing packet: %s", fr_strerror());
		return 0;
	}

	rad_assert(sock->ssn != NULL);

	DEBUG3("Proxy is writing %u bytes to SSL",
	       (unsigned int) request->reply->data_len);
	PTHREAD_MUTEX_LOCK(&sock->mutex);
	rcode = SSL_write(sock->ssn->ssl, request->reply->data,
			  request->reply->data_len);
	if (rcode < 0) {
		int err;

		err = ERR_get_error();
		switch (err) {
		case SSL_ERROR_NONE:
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			DEBUG3("(TLS) SSL_write() returned %s", ERR_reason_error_string(err));
			break;	/* let someone else retry */

		default:
			tls_error_log(NULL, "Failed in proxy send with OpenSSL error %d", err);
			DEBUG("Closing TLS socket to home server");
			tls_socket_close(listener);
			PTHREAD_MUTEX_UNLOCK(&sock->mutex);
			return 0;
		}
	}
	PTHREAD_MUTEX_UNLOCK(&sock->mutex);

	return 1;
}
#endif	/* WITH_COA_TUNNEL */
#endif	/* WITH_PROXY */

#endif	/* WITH_TLS */
#endif	/* WITH_TCP */
