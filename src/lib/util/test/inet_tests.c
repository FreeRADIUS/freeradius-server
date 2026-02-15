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

/** Tests for IP address parsing and formatting
 *
 * @file src/lib/util/test/inet_tests.c
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
#include "acutest.h"
#include "acutest_helpers.h"

#include <freeradius-devel/util/inet.h>

/*
 *	Test parsing simple IPv4 addresses.
 */
static void test_inet_pton4_basic(void)
{
	fr_ipaddr_t	addr;

	TEST_CASE("Parse 192.168.1.1");
	TEST_CHECK(fr_inet_pton4(&addr, "192.168.1.1", -1, false, false, false) == 0);
	TEST_CHECK(addr.af == AF_INET);
	TEST_CHECK(addr.prefix == 32);
	TEST_CHECK(ntohl(addr.addr.v4.s_addr) == 0xc0a80101);

	TEST_CASE("Parse 10.0.0.1");
	TEST_CHECK(fr_inet_pton4(&addr, "10.0.0.1", -1, false, false, false) == 0);
	TEST_CHECK(addr.af == AF_INET);
	TEST_CHECK(ntohl(addr.addr.v4.s_addr) == 0x0a000001);

	TEST_CASE("Parse 0.0.0.0");
	TEST_CHECK(fr_inet_pton4(&addr, "0.0.0.0", -1, false, false, false) == 0);
	TEST_CHECK(addr.addr.v4.s_addr == 0);

	TEST_CASE("Parse 255.255.255.255");
	TEST_CHECK(fr_inet_pton4(&addr, "255.255.255.255", -1, false, false, false) == 0);
	TEST_CHECK(ntohl(addr.addr.v4.s_addr) == 0xffffffff);
}

/*
 *	Test parsing IPv4 with prefixes.
 */
static void test_inet_pton4_prefix(void)
{
	fr_ipaddr_t	addr;

	TEST_CASE("Parse 192.168.0.0/16");
	TEST_CHECK(fr_inet_pton4(&addr, "192.168.0.0/16", -1, false, false, true) == 0);
	TEST_CHECK(addr.af == AF_INET);
	TEST_CHECK(addr.prefix == 16);

	TEST_CASE("Parse 10.0.0.0/8");
	TEST_CHECK(fr_inet_pton4(&addr, "10.0.0.0/8", -1, false, false, true) == 0);
	TEST_CHECK(addr.prefix == 8);

	TEST_CASE("Parse 0.0.0.0/0");
	TEST_CHECK(fr_inet_pton4(&addr, "0.0.0.0/0", -1, false, false, true) == 0);
	TEST_CHECK(addr.prefix == 0);
}

/*
 *	Test parsing invalid IPv4 addresses.
 */
static void test_inet_pton4_invalid(void)
{
	fr_ipaddr_t	addr;

	TEST_CASE("Invalid: empty string");
	TEST_CHECK(fr_inet_pton4(&addr, "", -1, false, false, false) < 0);

	TEST_CASE("Invalid: too many octets");
	TEST_CHECK(fr_inet_pton4(&addr, "1.2.3.4.5", -1, false, false, false) < 0);

	TEST_CASE("Invalid: prefix > 32");
	TEST_CHECK(fr_inet_pton4(&addr, "10.0.0.0/33", -1, false, false, true) < 0);
}

/*
 *	Test parsing IPv6 addresses.
 */
static void test_inet_pton6_basic(void)
{
	fr_ipaddr_t	addr;

	TEST_CASE("Parse ::1");
	TEST_CHECK(fr_inet_pton6(&addr, "::1", -1, false, false, false) == 0);
	TEST_CHECK(addr.af == AF_INET6);
	TEST_CHECK(addr.prefix == 128);
	TEST_CHECK(addr.addr.v6.s6_addr[15] == 1);

	TEST_CASE("Parse ::");
	TEST_CHECK(fr_inet_pton6(&addr, "::", -1, false, false, false) == 0);
	TEST_CHECK(addr.af == AF_INET6);
	{
		struct in6_addr zero = {};
		TEST_CHECK(memcmp(&addr.addr.v6, &zero, sizeof(zero)) == 0);
	}

	TEST_CASE("Parse fe80::1");
	TEST_CHECK(fr_inet_pton6(&addr, "fe80::1", -1, false, false, false) == 0);
	TEST_CHECK(addr.af == AF_INET6);
	TEST_CHECK(addr.addr.v6.s6_addr[0] == 0xfe);
	TEST_CHECK(addr.addr.v6.s6_addr[1] == 0x80);
	TEST_CHECK(addr.addr.v6.s6_addr[15] == 1);
}

/*
 *	Test parsing IPv6 with prefixes.
 */
static void test_inet_pton6_prefix(void)
{
	fr_ipaddr_t	addr;

	TEST_CASE("Parse 2001:db8::/32");
	TEST_CHECK(fr_inet_pton6(&addr, "2001:db8::/32", -1, false, false, true) == 0);
	TEST_CHECK(addr.af == AF_INET6);
	TEST_CHECK(addr.prefix == 32);

	TEST_CASE("Parse ::/0");
	TEST_CHECK(fr_inet_pton6(&addr, "::/0", -1, false, false, true) == 0);
	TEST_CHECK(addr.prefix == 0);

	TEST_CASE("Parse fe80::/10");
	TEST_CHECK(fr_inet_pton6(&addr, "fe80::/10", -1, false, false, true) == 0);
	TEST_CHECK(addr.prefix == 10);
}

/*
 *	Test the generic fr_inet_pton which auto-detects v4/v6.
 */
static void test_inet_pton_auto(void)
{
	fr_ipaddr_t	addr;

	TEST_CASE("Auto-detect IPv4");
	TEST_CHECK(fr_inet_pton(&addr, "192.168.1.1", -1, AF_UNSPEC, false, false) == 0);
	TEST_CHECK(addr.af == AF_INET);

	TEST_CASE("Auto-detect IPv6");
	TEST_CHECK(fr_inet_pton(&addr, "::1", -1, AF_UNSPEC, false, false) == 0);
	TEST_CHECK(addr.af == AF_INET6);

	TEST_CASE("Force AF_INET");
	TEST_CHECK(fr_inet_pton(&addr, "10.0.0.1", -1, AF_INET, false, false) == 0);
	TEST_CHECK(addr.af == AF_INET);

	TEST_CASE("Force AF_INET6");
	TEST_CHECK(fr_inet_pton(&addr, "::1", -1, AF_INET6, false, false) == 0);
	TEST_CHECK(addr.af == AF_INET6);
}

/*
 *	Test fr_inet_ntop (address to string).
 */
static void test_inet_ntop(void)
{
	fr_ipaddr_t	addr;
	char		buf[FR_IPADDR_STRLEN];

	TEST_CASE("IPv4 to string");
	fr_inet_pton4(&addr, "192.168.1.1", -1, false, false, false);
	TEST_CHECK(fr_inet_ntop(buf, sizeof(buf), &addr) != NULL);
	TEST_CHECK(strcmp(buf, "192.168.1.1") == 0);
	TEST_MSG("expected 192.168.1.1, got %s", buf);

	TEST_CASE("IPv6 loopback to string");
	fr_inet_pton6(&addr, "::1", -1, false, false, false);
	TEST_CHECK(fr_inet_ntop(buf, sizeof(buf), &addr) != NULL);
	TEST_CHECK(strcmp(buf, "::1") == 0);
	TEST_MSG("expected ::1, got %s", buf);
}

/*
 *	Test fr_inet_ntop_prefix (address with prefix to string).
 */
static void test_inet_ntop_prefix(void)
{
	fr_ipaddr_t	addr;
	char		buf[FR_IPADDR_PREFIX_STRLEN];

	TEST_CASE("IPv4 prefix to string");
	fr_inet_pton4(&addr, "10.0.0.0/8", -1, false, false, true);
	TEST_CHECK(fr_inet_ntop_prefix(buf, sizeof(buf), &addr) != NULL);
	TEST_CHECK(strcmp(buf, "10.0.0.0/8") == 0);
	TEST_MSG("expected 10.0.0.0/8, got %s", buf);
}

/*
 *	Test fr_ipaddr_cmp.
 */
static void test_ipaddr_cmp(void)
{
	fr_ipaddr_t	a, b;

	TEST_CASE("Same address compares equal");
	fr_inet_pton4(&a, "10.0.0.1", -1, false, false, false);
	fr_inet_pton4(&b, "10.0.0.1", -1, false, false, false);
	TEST_CHECK(fr_ipaddr_cmp(&a, &b) == 0);

	TEST_CASE("Different addresses compare non-equal");
	fr_inet_pton4(&b, "10.0.0.2", -1, false, false, false);
	TEST_CHECK(fr_ipaddr_cmp(&a, &b) != 0);

	TEST_CASE("Less-than comparison");
	TEST_CHECK(fr_ipaddr_cmp(&a, &b) < 0);

	TEST_CASE("Greater-than comparison");
	TEST_CHECK(fr_ipaddr_cmp(&b, &a) > 0);

	TEST_CASE("IPv4 vs IPv6 comparison (different af)");
	fr_inet_pton4(&a, "10.0.0.1", -1, false, false, false);
	fr_inet_pton6(&b, "::1", -1, false, false, false);
	TEST_CHECK(fr_ipaddr_cmp(&a, &b) != 0);
}

/*
 *	Test fr_ipaddr_mask.
 */
static void test_ipaddr_mask(void)
{
	fr_ipaddr_t	addr;

	TEST_CASE("Mask 192.168.1.100 to /24");
	fr_inet_pton4(&addr, "192.168.1.100", -1, false, false, false);
	fr_ipaddr_mask(&addr, 24);
	TEST_CHECK(ntohl(addr.addr.v4.s_addr) == 0xc0a80100);

	TEST_CASE("Mask 10.1.2.3 to /8");
	fr_inet_pton4(&addr, "10.1.2.3", -1, false, false, false);
	fr_ipaddr_mask(&addr, 8);
	TEST_CHECK(ntohl(addr.addr.v4.s_addr) == 0x0a000000);

	TEST_CASE("Mask to /0 clears everything");
	fr_inet_pton4(&addr, "255.255.255.255", -1, false, false, false);
	fr_ipaddr_mask(&addr, 0);
	TEST_CHECK(addr.addr.v4.s_addr == 0);
}

/*
 *	Test fr_ipaddr_is_inaddr_any.
 */
static void test_ipaddr_is_inaddr_any(void)
{
	fr_ipaddr_t	addr;

	TEST_CASE("0.0.0.0 is INADDR_ANY");
	fr_inet_pton4(&addr, "0.0.0.0", -1, false, false, false);
	TEST_CHECK(fr_ipaddr_is_inaddr_any(&addr) == 1);

	TEST_CASE("10.0.0.1 is not INADDR_ANY");
	fr_inet_pton4(&addr, "10.0.0.1", -1, false, false, false);
	TEST_CHECK(fr_ipaddr_is_inaddr_any(&addr) == 0);

	TEST_CASE(":: is IN6ADDR_ANY");
	fr_inet_pton6(&addr, "::", -1, false, false, false);
	TEST_CHECK(fr_ipaddr_is_inaddr_any(&addr) == 1);

	TEST_CASE("::1 is not IN6ADDR_ANY");
	fr_inet_pton6(&addr, "::1", -1, false, false, false);
	TEST_CHECK(fr_ipaddr_is_inaddr_any(&addr) == 0);
}

/*
 *	Test fr_ipaddr_is_prefix.
 */
static void test_ipaddr_is_prefix(void)
{
	fr_ipaddr_t	addr;

	TEST_CASE("/32 is not a prefix");
	fr_inet_pton4(&addr, "10.0.0.1", -1, false, false, false);
	TEST_CHECK(fr_ipaddr_is_prefix(&addr) == 0);

	TEST_CASE("/24 is a prefix");
	fr_inet_pton4(&addr, "10.0.0.0/24", -1, false, false, true);
	TEST_CHECK(fr_ipaddr_is_prefix(&addr) == 1);

	TEST_CASE("/128 is not a prefix (IPv6)");
	fr_inet_pton6(&addr, "::1", -1, false, false, false);
	TEST_CHECK(fr_ipaddr_is_prefix(&addr) == 0);

	TEST_CASE("/64 is a prefix (IPv6)");
	fr_inet_pton6(&addr, "fe80::/64", -1, false, false, true);
	TEST_CHECK(fr_ipaddr_is_prefix(&addr) == 1);
}

/*
 *	Test fr_inet_pton_port.
 */
static void test_inet_pton_port(void)
{
	fr_ipaddr_t	addr;
	uint16_t	port = 0;

	TEST_CASE("Parse 192.168.1.1:8080");
	TEST_CHECK(fr_inet_pton_port(&addr, &port, "192.168.1.1:8080", -1, AF_UNSPEC, false, false) == 0);
	TEST_CHECK(addr.af == AF_INET);
	TEST_CHECK(ntohl(addr.addr.v4.s_addr) == 0xc0a80101);
	TEST_CHECK(port == 8080);

	TEST_CASE("Parse [::1]:443");
	port = 0;
	TEST_CHECK(fr_inet_pton_port(&addr, &port, "[::1]:443", -1, AF_UNSPEC, false, false) == 0);
	TEST_CHECK(addr.af == AF_INET6);
	TEST_CHECK(port == 443);

	TEST_CASE("Parse address without port");
	TEST_CHECK(fr_inet_pton_port(&addr, &port, "10.0.0.1", -1, AF_UNSPEC, false, false) == 0);
	TEST_CHECK(port == 0);
}

/*
 *	Test sockaddr round-trip conversion.
 */
static void test_ipaddr_sockaddr(void)
{
	fr_ipaddr_t		addr, recovered;
	struct sockaddr_storage	sa;
	socklen_t		salen;
	uint16_t		port, recovered_port;

	TEST_CASE("IPv4 to sockaddr and back");
	fr_inet_pton4(&addr, "192.168.1.1", -1, false, false, false);
	port = 1812;
	TEST_CHECK(fr_ipaddr_to_sockaddr(&sa, &salen, &addr, port) == 0);
	TEST_CHECK(fr_ipaddr_from_sockaddr(&recovered, &recovered_port, &sa, salen) == 0);
	TEST_CHECK(fr_ipaddr_cmp(&addr, &recovered) == 0);
	TEST_CHECK(recovered_port == port);

	TEST_CASE("IPv6 to sockaddr and back");
	fr_inet_pton6(&addr, "::1", -1, false, false, false);
	port = 1813;
	TEST_CHECK(fr_ipaddr_to_sockaddr(&sa, &salen, &addr, port) == 0);
	TEST_CHECK(fr_ipaddr_from_sockaddr(&recovered, &recovered_port, &sa, salen) == 0);
	TEST_CHECK(fr_ipaddr_cmp(&addr, &recovered) == 0);
	TEST_CHECK(recovered_port == port);
}

TEST_LIST = {
	{ "inet_pton4_basic",		test_inet_pton4_basic },
	{ "inet_pton4_prefix",		test_inet_pton4_prefix },
	{ "inet_pton4_invalid",		test_inet_pton4_invalid },
	{ "inet_pton6_basic",		test_inet_pton6_basic },
	{ "inet_pton6_prefix",		test_inet_pton6_prefix },
	{ "inet_pton_auto",		test_inet_pton_auto },
	{ "inet_ntop",			test_inet_ntop },
	{ "inet_ntop_prefix",		test_inet_ntop_prefix },
	{ "ipaddr_cmp",			test_ipaddr_cmp },
	{ "ipaddr_mask",		test_ipaddr_mask },
	{ "ipaddr_is_inaddr_any",	test_ipaddr_is_inaddr_any },
	{ "ipaddr_is_prefix",		test_ipaddr_is_prefix },
	{ "inet_pton_port",		test_inet_pton_port },
	{ "ipaddr_sockaddr",		test_ipaddr_sockaddr },
	TEST_TERMINATOR
};
