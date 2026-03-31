/*
 *  ipaddr_test.c	Test that fr_pton6 initializes all fields of fr_ipaddr_t,
 *			specifically the scope field used by fr_ipaddr_cmp.
 *
 *			Regression test for GitHub issue #4954:
 *			"checkrad: Unknown NAS (IPv6 address), not checking"
 *
 *  The root cause was that fr_pton6() did not initialize the scope
 *  field of fr_ipaddr_t. When callers used a stack-allocated (not
 *  zeroed) fr_ipaddr_t, the scope field contained garbage, causing
 *  fr_ipaddr_cmp() to fail even though the addresses were identical.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <freeradius-devel/libradius.h>

#define TEST_PASS 0
#define TEST_FAIL 1

static int test_fr_pton6_scope_initialized(void)
{
	fr_ipaddr_t addr_zeroed;
	fr_ipaddr_t addr_dirty;
	int ret;

	/*
	 *  Simulate a client stored in the tree (allocated via talloc_zero,
	 *  so all fields including scope start at 0).
	 */
	memset(&addr_zeroed, 0, sizeof(addr_zeroed));
	if (fr_pton6(&addr_zeroed, "2001:db8::1", -1, false, false) < 0) {
		fprintf(stderr, "FAIL: fr_pton6 failed for zeroed addr: %s\n",
			fr_strerror());
		return TEST_FAIL;
	}

	/*
	 *  Simulate a stack-allocated fr_ipaddr_t (as used in rlm_sql.c
	 *  for nas_addr). Fill with garbage to ensure fr_pton6 initializes
	 *  all fields it needs to.
	 */
	memset(&addr_dirty, 0xAB, sizeof(addr_dirty));
	if (fr_pton6(&addr_dirty, "2001:db8::1", -1, false, false) < 0) {
		fprintf(stderr, "FAIL: fr_pton6 failed for dirty addr: %s\n",
			fr_strerror());
		return TEST_FAIL;
	}

	/*
	 *  Verify scope is initialized to 0 in both cases.
	 */
	if (addr_zeroed.scope != 0) {
		fprintf(stderr, "FAIL: zeroed addr scope = %u, expected 0\n",
			addr_zeroed.scope);
		return TEST_FAIL;
	}

	if (addr_dirty.scope != 0) {
		fprintf(stderr, "FAIL: dirty addr scope = %u, expected 0\n",
			addr_dirty.scope);
		return TEST_FAIL;
	}

	/*
	 *  The key test: fr_ipaddr_cmp must return 0 for identical addresses
	 *  regardless of how the structs were initialized before fr_pton6.
	 */
	ret = fr_ipaddr_cmp(&addr_zeroed, &addr_dirty);
	if (ret != 0) {
		fprintf(stderr, "FAIL: fr_ipaddr_cmp returned %d, expected 0\n",
			ret);
		return TEST_FAIL;
	}

	return TEST_PASS;
}

static int test_fr_pton6_with_prefix_scope_initialized(void)
{
	fr_ipaddr_t addr_zeroed;
	fr_ipaddr_t addr_dirty;
	int ret;

	/*
	 *  Same test but with a prefix (e.g. "2001:db8::/32").
	 *  fr_pton6 has two code paths: with and without prefix.
	 */
	memset(&addr_zeroed, 0, sizeof(addr_zeroed));
	if (fr_pton6(&addr_zeroed, "2001:db8::/32", -1, false, false) < 0) {
		fprintf(stderr, "FAIL: fr_pton6 failed for zeroed prefix addr: %s\n",
			fr_strerror());
		return TEST_FAIL;
	}

	memset(&addr_dirty, 0xAB, sizeof(addr_dirty));
	if (fr_pton6(&addr_dirty, "2001:db8::/32", -1, false, false) < 0) {
		fprintf(stderr, "FAIL: fr_pton6 failed for dirty prefix addr: %s\n",
			fr_strerror());
		return TEST_FAIL;
	}

	if (addr_dirty.scope != 0) {
		fprintf(stderr, "FAIL: dirty prefix addr scope = %u, expected 0\n",
			addr_dirty.scope);
		return TEST_FAIL;
	}

	ret = fr_ipaddr_cmp(&addr_zeroed, &addr_dirty);
	if (ret != 0) {
		fprintf(stderr, "FAIL: fr_ipaddr_cmp (prefix) returned %d, expected 0\n",
			ret);
		return TEST_FAIL;
	}

	return TEST_PASS;
}

int main(void)
{
	int ret = TEST_PASS;

	fprintf(stdout, "TEST: fr_pton6 scope initialized (no prefix)... ");
	if (test_fr_pton6_scope_initialized() != TEST_PASS) {
		fprintf(stdout, "FAIL\n");
		ret = TEST_FAIL;
	} else {
		fprintf(stdout, "OK\n");
	}

	fprintf(stdout, "TEST: fr_pton6 scope initialized (with prefix)... ");
	if (test_fr_pton6_with_prefix_scope_initialized() != TEST_PASS) {
		fprintf(stdout, "FAIL\n");
		ret = TEST_FAIL;
	} else {
		fprintf(stdout, "OK\n");
	}

	return ret;
}
