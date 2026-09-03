/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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

/** Tests for the LDAP DN and filter escape functions
 *
 * @file src/lib/ldap/test/ldap_util_tests.c
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
#include <freeradius-devel/util/test/acutest_common_init.h>
#include <freeradius-devel/util/test/acutest_helpers.h>

#include <freeradius-devel/ldap/base.h>

/** Check a value box holds exactly the expected bytes, NUL bytes included
 *
 * A strcmp based check stops at the first NUL, which is the failure mode
 * these tests exist to catch.
 */
#define TEST_CHECK_BOX_BYTES(_vb, _exp) \
do { \
	fr_value_box_t const *_our_vb = (_vb); \
	TEST_CHECK_LEN(_our_vb->vb_length, sizeof(_exp) - 1); \
	TEST_CHECK(memcmp(_our_vb->vb_strvalue, _exp, sizeof(_exp) - 1) == 0); \
	TEST_MSG("Expected : \"%s\"", _exp); \
	TEST_MSG("Got      : \"%s\"", _our_vb->vb_strvalue); \
} while (0)

/** Allocate a tainted string box from a literal, NUL bytes included
 */
#define BOX_FROM_LITERAL(_str) box_from_bytes(_str, sizeof(_str) - 1)

static fr_value_box_t *box_from_bytes(char const *bytes, size_t len)
{
	fr_value_box_t *vb;

	vb = fr_value_box_alloc(NULL, FR_TYPE_STRING, NULL);
	TEST_ASSERT(vb != NULL);
	TEST_ASSERT(fr_value_box_bstrndup(vb, vb, NULL, bytes, len, true) == 0);

	return vb;
}

static void test_filter_box_escape_plain(void)
{
	fr_value_box_t *vb = BOX_FROM_LITERAL("bob");

	TEST_CASE("Filter value with no special characters is unchanged");
	TEST_CHECK_RET(fr_ldap_filter_box_escape(vb, NULL), 0);
	TEST_CHECK_BOX_BYTES(vb, "bob");

	talloc_free(vb);
}

static void test_filter_box_escape_specials(void)
{
	fr_value_box_t *vb = BOX_FROM_LITERAL("*)(\\");

	TEST_CASE("RFC 4515 special characters are hex escaped");
	TEST_CHECK_RET(fr_ldap_filter_box_escape(vb, NULL), 0);
	TEST_CHECK_BOX_BYTES(vb, "\\2a\\29\\28\\5c");

	talloc_free(vb);
}

static void test_filter_box_escape_nul_truncation(void)
{
	fr_value_box_t *vb = BOX_FROM_LITERAL("victim\0junk");

	TEST_CASE("Embedded NUL is escaped rather than truncating the value");
	TEST_CHECK_RET(fr_ldap_filter_box_escape(vb, NULL), 0);
	TEST_CHECK_BOX_BYTES(vb, "victim\\00junk");

	talloc_free(vb);
}

static void test_filter_box_escape_nul_length_collision(void)
{
	/*
	 *	Escaping "*)" yields six bytes, the same as the six byte
	 *	input.  A length comparison cannot tell the two apart.
	 */
	fr_value_box_t *vb = BOX_FROM_LITERAL("*)\0AAA");

	TEST_CASE("Specials before an embedded NUL are escaped when lengths collide");
	TEST_CHECK_RET(fr_ldap_filter_box_escape(vb, NULL), 0);
	TEST_CHECK_BOX_BYTES(vb, "\\2a\\29\\00AAA");

	talloc_free(vb);
}

static void test_filter_box_escape_empty(void)
{
	fr_value_box_t *vb = BOX_FROM_LITERAL("");

	TEST_CASE("Empty filter value stays empty");
	TEST_CHECK_RET(fr_ldap_filter_box_escape(vb, NULL), 0);
	TEST_CHECK_BOX_BYTES(vb, "");

	talloc_free(vb);
}

static void test_dn_box_escape_plain(void)
{
	fr_value_box_t *vb = BOX_FROM_LITERAL("bob smith");

	TEST_CASE("DN value with no special characters is unchanged");
	TEST_CHECK_RET(fr_ldap_dn_box_escape(vb, NULL), 0);
	TEST_CHECK_BOX_BYTES(vb, "bob smith");

	talloc_free(vb);
}

static void test_dn_box_escape_specials(void)
{
	fr_value_box_t *vb = BOX_FROM_LITERAL("a,b+c\"d\\e<f>g;h*i=j(k)");

	TEST_CASE("RFC 4514 special characters are hex escaped");
	TEST_CHECK_RET(fr_ldap_dn_box_escape(vb, NULL), 0);
	TEST_CHECK_BOX_BYTES(vb, "a\\2cb\\2bc\\22d\\5ce\\3cf\\3eg\\3bh\\2ai\\3dj\\28k\\29");

	talloc_free(vb);
}

static void test_dn_box_escape_leading(void)
{
	fr_value_box_t *vb;

	TEST_CASE("Leading space is escaped");
	vb = BOX_FROM_LITERAL(" bob");
	TEST_CHECK_RET(fr_ldap_dn_box_escape(vb, NULL), 0);
	TEST_CHECK_BOX_BYTES(vb, "\\20bob");
	talloc_free(vb);

	TEST_CASE("Leading '#' is escaped");
	vb = BOX_FROM_LITERAL("#bob");
	TEST_CHECK_RET(fr_ldap_dn_box_escape(vb, NULL), 0);
	TEST_CHECK_BOX_BYTES(vb, "\\23bob");
	talloc_free(vb);

	TEST_CASE("Interior '#' is not escaped");
	vb = BOX_FROM_LITERAL("bob#1");
	TEST_CHECK_RET(fr_ldap_dn_box_escape(vb, NULL), 0);
	TEST_CHECK_BOX_BYTES(vb, "bob#1");
	talloc_free(vb);
}

static void test_dn_box_escape_nul_length_collision(void)
{
	/*
	 *	Escaping "x,ou=other" yields fourteen bytes, the same as the
	 *	fourteen byte input.
	 */
	fr_value_box_t *vb = BOX_FROM_LITERAL("x,ou=other\0AAA");

	TEST_CASE("Specials before an embedded NUL are escaped when lengths collide");
	TEST_CHECK_RET(fr_ldap_dn_box_escape(vb, NULL), 0);
	TEST_CHECK_BOX_BYTES(vb, "x\\2cou\\3dother\\00AAA");

	talloc_free(vb);
}

static void test_filter_escape_sbuff(void)
{
	char		buff[32] = {};
	fr_sbuff_t	out = FR_SBUFF_OUT(buff, sizeof(buff));
	fr_sbuff_t	in = FR_SBUFF_IN("a*b\0c", sizeof("a*b\0c") - 1);

	TEST_CASE("Escaping consumes the whole input, NUL included");
	TEST_CHECK_SLEN(fr_ldap_filter_escape(&out, &in), 9);
	TEST_CHECK_LEN(fr_sbuff_remaining(&in), 0);
	TEST_CHECK_LEN(fr_sbuff_used(&out), 9);
	TEST_CHECK(memcmp(buff, "a\\2ab\\00c", 9) == 0);
	TEST_CHECK(buff[9] == '\0');
}

static void test_filter_escape_sbuff_no_space(void)
{
	char		buff[6];
	fr_sbuff_t	out = FR_SBUFF_OUT(buff, sizeof(buff));
	fr_sbuff_t	in = FR_SBUFF_IN_STR("ab*cd");

	TEST_CASE("Escaping into a buffer that is too small fails and advances neither sbuff");
	TEST_CHECK(fr_ldap_filter_escape(&out, &in) < 0);
	TEST_CHECK_LEN(fr_sbuff_used(&out), 0);
	TEST_CHECK_LEN(fr_sbuff_used(&in), 0);
}

static void test_dn_escape_sbuff(void)
{
	char		buff[32] = {};
	fr_sbuff_t	out = FR_SBUFF_OUT(buff, sizeof(buff));
	fr_sbuff_t	in = FR_SBUFF_IN_STR("#a,b");

	TEST_CASE("Leading '#' and interior ',' are escaped");
	TEST_CHECK_SLEN(fr_ldap_dn_escape(&out, &in), 8);
	TEST_CHECK_LEN(fr_sbuff_remaining(&in), 0);
	TEST_CHECK_STRCMP(buff, "\\23a\\2cb");
}

static void test_dn_escape_sbuff_empty(void)
{
	char		buff[8];
	fr_sbuff_t	out = FR_SBUFF_OUT(buff, sizeof(buff));
	fr_sbuff_t	in = FR_SBUFF_IN_STR("");

	TEST_CASE("Empty DN value writes nothing");
	TEST_CHECK_SLEN(fr_ldap_dn_escape(&out, &in), 0);
	TEST_CHECK_LEN(fr_sbuff_used(&out), 0);
}

static void test_filter_afrom_dn_list(void)
{
	char const * const	dn_list[] = { "cn=a*b,dc=example", "cn=c(d),dc=example", NULL };
	char			*filter;

	TEST_CASE("DN list filter escapes each DN and ANDs the extra filter");
	filter = fr_ldap_filter_afrom_dn_list(NULL, "entryDN", "(objectClass=groupOfNames)", dn_list);
	TEST_CHECK_STRCMP(filter,
			  "(&(objectClass=groupOfNames)(|(entryDN=cn=a\\2ab,dc=example)(entryDN=cn=c\\28d\\29,dc=example)))");
	talloc_free(filter);

	TEST_CASE("DN list filter without an extra filter");
	filter = fr_ldap_filter_afrom_dn_list(NULL, "entryDN", NULL, dn_list);
	TEST_CHECK_STRCMP(filter, "(|(entryDN=cn=a\\2ab,dc=example)(entryDN=cn=c\\28d\\29,dc=example))");
	talloc_free(filter);
}

TEST_LIST = {
	{ "filter_box_escape_plain",			test_filter_box_escape_plain },
	{ "filter_box_escape_specials",			test_filter_box_escape_specials },
	{ "filter_box_escape_nul_truncation",		test_filter_box_escape_nul_truncation },
	{ "filter_box_escape_nul_length_collision",	test_filter_box_escape_nul_length_collision },
	{ "filter_box_escape_empty",			test_filter_box_escape_empty },
	{ "dn_box_escape_plain",			test_dn_box_escape_plain },
	{ "dn_box_escape_specials",			test_dn_box_escape_specials },
	{ "dn_box_escape_leading",			test_dn_box_escape_leading },
	{ "dn_box_escape_nul_length_collision",		test_dn_box_escape_nul_length_collision },
	{ "filter_escape_sbuff",			test_filter_escape_sbuff },
	{ "filter_escape_sbuff_no_space",		test_filter_escape_sbuff_no_space },
	{ "dn_escape_sbuff",				test_dn_escape_sbuff },
	{ "dn_escape_sbuff_empty",			test_dn_escape_sbuff_empty },
	{ "filter_afrom_dn_list",			test_filter_afrom_dn_list },
	TEST_TERMINATOR
};
