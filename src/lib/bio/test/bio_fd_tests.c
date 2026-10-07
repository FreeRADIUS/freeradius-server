/*
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** Tests for the FD bio
 *
 * @file src/lib/bio/test/bio_fd_tests.c
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
#include <freeradius-devel/util/test/acutest_common_init.h>
#include <freeradius-devel/util/test/acutest_helpers.h>

#define _BIO_PRIVATE 1
#include <freeradius-devel/bio/bio_priv.h>
#include <freeradius-devel/bio/fd.h>

static int	connected_count;
static int	error_count;
static int	timeout_count;

static void	cb_connected(fr_bio_t *bio)	{ (void) bio; connected_count++; }
static void	cb_error(fr_bio_t *bio)		{ (void) bio; error_count++; }
static void	cb_timeout(fr_bio_t *bio)	{ (void) bio; timeout_count++; }

/** Open a TCP socket listening on loopback
 *
 *  The kernel completes the TCP handshake for any listening socket, and the test needs only the
 *  handshake.  The test never calls accept(), so the kernel holds the new connection in the backlog of
 *  the listening socket.
 *
 * @param[out] port	the port which the kernel picked.
 * @return
 *	- >=0 the listening socket.
 *	- <0 on error.
 */
static int loopback_listen(uint16_t *port)
{
	struct sockaddr_in	sin = {
					.sin_family = AF_INET,
					.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
				};
	socklen_t		len = sizeof(sin);
	int			fd;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) return -1;

	if ((bind(fd, (struct sockaddr *) &sin, sizeof(sin)) < 0) ||
	    (listen(fd, 5) < 0) ||
	    (getsockname(fd, (struct sockaddr *) &sin, &len) < 0)) {
		close(fd);
		return -1;
	}

	*port = ntohs(sin.sin_port);
	return fd;
}

/** A deferred connect which succeeds has to call the connected callback
 *
 *  A non-blocking connect() to a listening loopback port can return EINPROGRESS.  On EINPROGRESS,
 *  fr_bio_fd_connect_full() defers the connect, and the event loop calls fr_bio_fd_el_connect() once
 *  the socket is writable.  fr_bio_fd_el_connect() then calls connect() a second time.  If the
 *  handshake has finished, the second connect() can fail with EISCONN, so fr_bio_fd_try_connect() has
 *  to treat EISCONN as success.
 *
 *  The test needs a connect which succeeds, because a connect which fails may not reach
 *  fr_bio_fd_el_connect().  kqueue can report a refused connect with EV_EOF, and event.c passes EV_EOF
 *  to the error callback, fr_bio_fd_el_error().
 */
static void test_deferred_connect_success_calls_connected_cb(void)
{
	TALLOC_CTX		*ctx = talloc_init_const("test");
	fr_bio_fd_config_t	cfg;
	fr_bio_t		*bio;
	fr_event_list_t		*el;
	fr_time_delta_t		timeout = fr_time_delta_from_sec(5);
	uint16_t		port;
	int			listen_fd;
	int			rcode;

	connected_count = 0;
	error_count = 0;
	timeout_count = 0;

	listen_fd = loopback_listen(&port);
	TEST_CHECK(listen_fd >= 0);
	if (listen_fd < 0) goto done;

	el = fr_event_list_alloc(ctx, NULL, NULL);
	TEST_CHECK(el != NULL);
	if (!el) goto done;

	cfg = (fr_bio_fd_config_t) {
		.type = FR_BIO_FD_CONNECTED,
		.socket_type = SOCK_STREAM,
		.transport_type = FR_BIO_FD_TRANSPORT_TCP,
		.async = true,
		.src_ipaddr = {
			.af = AF_INET,
			.addr.v4.s_addr = htonl(INADDR_LOOPBACK),
			.prefix = 32,
		},
		.dst_port = port,
	};
	cfg.dst_ipaddr = cfg.src_ipaddr;

	bio = fr_bio_fd_alloc(ctx, &cfg, 0);
	TEST_CHECK(bio != NULL);
	if (!bio) goto done;

	rcode = fr_bio_fd_connect_full(bio, el, cb_connected, cb_error, &timeout, cb_timeout);

	TEST_CASE("the connect is deferred");
	TEST_CHECK(rcode == 0);
	TEST_MSG("connect_full returned %d.  0 means deferred, 1 means connected at once, <0 means failed", rcode);
	if (rcode != 0) goto done;

	/*
	 *	Wait in the event loop until one of the three callbacks runs.  The connect timeout
	 *	is a timer, so a wait always ends, and a connect which never finishes cannot hang
	 *	the test.
	 */
	while (!connected_count && !error_count && !timeout_count) {
		if (fr_event_corral(el, fr_time(), true) < 0) break;
		fr_event_service(el);
	}

	TEST_CASE("the connected callback ran");
	TEST_CHECK(connected_count == 1);
	TEST_MSG("connected_count = %d, error_count = %d, timeout_count = %d, connect_errno = %d",
		 connected_count, error_count, timeout_count, fr_bio_fd_info(bio)->connect_errno);

	TEST_CASE("neither the error callback nor the timeout callback ran");
	TEST_CHECK(error_count == 0);
	TEST_CHECK(timeout_count == 0);

	TEST_CASE("the bio is open");
	TEST_CHECK(fr_bio_fd_info(bio)->state == FR_BIO_FD_STATE_OPEN);

done:
	if (listen_fd >= 0) close(listen_fd);
	talloc_free(ctx);
}

TEST_LIST = {
	{ "deferred_connect_success_calls_connected_cb",	test_deferred_connect_success_calls_connected_cb },
	TEST_TERMINATOR
};
