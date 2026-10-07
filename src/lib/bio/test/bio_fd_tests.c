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

static void	cb_connected(fr_bio_t *bio)	{ (void) bio; connected_count++; }
static void	cb_error(fr_bio_t *bio)		{ (void) bio; error_count++; }

/** Connect to a port which nothing is listening on
 *
 *  A connect() to a closed port on loopback returns EINPROGRESS on a non-blocking socket, and fails
 *  afterwards with ECONNREFUSED.  That is the deferred connect path, and it is the one path which has
 *  to tell the application that the connection failed.
 */
static fr_bio_t *fd_bio_to_closed_port(TALLOC_CTX *ctx, fr_bio_fd_config_t *cfg)
{
	memset(cfg, 0, sizeof(*cfg));

	cfg->type = FR_BIO_FD_CONNECTED;
	cfg->socket_type = SOCK_STREAM;
	cfg->transport_type = FR_BIO_FD_TRANSPORT_TCP;
	cfg->async = true;

	cfg->src_ipaddr = (fr_ipaddr_t) {
		.af = AF_INET,
		.addr.v4.s_addr = htonl(INADDR_LOOPBACK),
		.prefix = 32,
	};
	cfg->dst_ipaddr = cfg->src_ipaddr;

	/*
	 *	Port 1 is reserved, and nothing listens on it.  A connect() there is refused rather
	 *	than left hanging, which is what makes the failure arrive quickly and reliably.
	 */
	cfg->dst_port = 1;

	return fr_bio_fd_alloc(ctx, cfg, 0);
}

/** A deferred connect which fails has to call the error callback
 *
 */
static void test_deferred_connect_failure_calls_error_cb(void)
{
	TALLOC_CTX		*ctx = talloc_init_const("test");
	fr_bio_fd_config_t	cfg;
	fr_bio_t		*bio;
	fr_event_list_t		*el;
	int			rcode;
	int			i;

	connected_count = 0;
	error_count = 0;

	el = fr_event_list_alloc(ctx, NULL, NULL);
	TEST_CHECK(el != NULL);
	if (!el) goto done;

	bio = fd_bio_to_closed_port(ctx, &cfg);
	TEST_CHECK(bio != NULL);
	if (!bio) goto done;

	/*
	 *	Either the connect fails here, or it is deferred.  Both have to reach the error
	 *	callback, which is the whole point of the test.
	 */
	rcode = fr_bio_fd_connect_full(bio, el, cb_connected, cb_error, NULL, NULL);

	TEST_CASE("a connect to a closed port does not succeed");
	TEST_CHECK(rcode <= 0);
	TEST_MSG("connect_full returned %d (0 means deferred, <0 means it failed here)", rcode);

	/*
	 *	Service the event loop until the connect resolves.  A refused connect on loopback
	 *	needs only one pass, and the bound loop keeps a failure from hanging the test.
	 */
	for (i = 0; (i < 20) && !error_count; i++) {
		fr_time_t when = fr_time_wrap(0);

		if (fr_event_corral(el, fr_time(), false) > 0) fr_event_service(el);
		(void) when;
	}

	TEST_CASE("the error callback ran");
	TEST_CHECK(error_count == 1);
	TEST_MSG("error_count = %d, connected_count = %d", error_count, connected_count);

	TEST_CASE("the connected callback did not run");
	TEST_CHECK(connected_count == 0);

done:
	talloc_free(ctx);
}

TEST_LIST = {
	{ "deferred_connect_failure_calls_error_cb",	test_deferred_connect_failure_calls_error_cb },
	TEST_TERMINATOR
};
