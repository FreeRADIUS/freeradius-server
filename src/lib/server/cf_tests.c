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

/** Tests for cf_file, cf_util, and cf_parse
 *
 * @file src/lib/server/cf_tests.c
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */

static void test_init(void);
#  define TEST_INIT  test_init()

#include <freeradius-devel/util/test/acutest.h>
#include <freeradius-devel/util/test/acutest_helpers.h>
#include <freeradius-devel/server/cf_file.h>
#include <freeradius-devel/server/cf_util.h>
#include <freeradius-devel/server/cf_priv.h>

static TALLOC_CTX	*autofree;

/** Global initialisation
 */
static void test_init(void)
{
	autofree = talloc_autofree_context();
	if (!autofree) {
		fr_perror("cf_tests");
		fr_exit_now(EXIT_FAILURE);
	}

	/*
	 *	Mismatch between the binary and the libraries it depends on
	 */
	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) {
		fr_perror("cf_tests");
		fr_exit_now(EXIT_FAILURE);
	}
}


/*
 *	Section allocation and accessors
 */

static void test_section_alloc_name1_only(void)
{
	CONF_SECTION *cs;

	cs = cf_section_alloc(autofree, NULL, "server", NULL);
	TEST_ASSERT(cs != NULL);

	TEST_CHECK(strcmp(cf_section_name1(cs), "server") == 0);
	TEST_CHECK(cf_section_name2(cs) == NULL);
	TEST_CHECK(strcmp(cf_section_name(cs), "server") == 0);

	talloc_free(cs);
}

static void test_section_alloc_name1_name2(void)
{
	CONF_SECTION *cs;

	cs = cf_section_alloc(autofree, NULL, "server", "default");
	TEST_ASSERT(cs != NULL);

	TEST_CHECK(strcmp(cf_section_name1(cs), "server") == 0);
	TEST_CHECK(strcmp(cf_section_name2(cs), "default") == 0);

	talloc_free(cs);
}

static void test_section_alloc_parent(void)
{
	CONF_SECTION *parent, *child;

	parent = cf_section_alloc(autofree, NULL, "root", NULL);
	TEST_ASSERT(parent != NULL);

	child = cf_section_alloc(autofree, parent, "child", NULL);
	TEST_ASSERT(child != NULL);

	TEST_CHECK(cf_parent(child) == cf_section_to_item(parent));
	TEST_CHECK(cf_root(child) == parent);

	talloc_free(parent);
}

static void test_section_name_cmp(void)
{
	CONF_SECTION *cs;

	cs = cf_section_alloc(autofree, NULL, "server", "default");
	TEST_ASSERT(cs != NULL);

	TEST_CHECK(cf_section_name_cmp(cs, "server", "default") == 0);
	TEST_CHECK(cf_section_name_cmp(cs, "server", "other") != 0);
	TEST_CHECK(cf_section_name_cmp(cs, "other", NULL) != 0);

	talloc_free(cs);
}

static void test_section_to_item_roundtrip(void)
{
	CONF_SECTION	*cs;
	CONF_ITEM	*ci;

	cs = cf_section_alloc(autofree, NULL, "test", NULL);
	TEST_ASSERT(cs != NULL);

	ci = cf_section_to_item(cs);
	TEST_ASSERT(ci != NULL);
	TEST_CHECK(cf_item_is_section(ci));
	TEST_CHECK(!cf_item_is_pair(ci));
	TEST_CHECK(!cf_item_is_data(ci));
	TEST_CHECK(cf_item_to_section(ci) == cs);

	talloc_free(cs);
}


/*
 *	Pair allocation and accessors
 */

static void test_pair_alloc_basic(void)
{
	CONF_SECTION	*cs;
	CONF_PAIR	*cp;

	cs = cf_section_alloc(autofree, NULL, "test", NULL);
	TEST_ASSERT(cs != NULL);

	cp = cf_pair_alloc(cs, "key", "value", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);
	TEST_ASSERT(cp != NULL);

	TEST_CHECK(strcmp(cf_pair_attr(cp), "key") == 0);
	TEST_CHECK(strcmp(cf_pair_value(cp), "value") == 0);
	TEST_CHECK(cf_pair_operator(cp) == T_OP_EQ);

	talloc_free(cs);
}

static void test_pair_alloc_quoted(void)
{
	CONF_SECTION	*cs;
	CONF_PAIR	*cp;

	cs = cf_section_alloc(autofree, NULL, "test", NULL);
	TEST_ASSERT(cs != NULL);

	cp = cf_pair_alloc(cs, "msg", "hello world", T_OP_EQ, T_BARE_WORD, T_DOUBLE_QUOTED_STRING);
	TEST_ASSERT(cp != NULL);

	TEST_CHECK(cf_pair_attr_quote(cp) == T_BARE_WORD);
	TEST_CHECK(cf_pair_value_quote(cp) == T_DOUBLE_QUOTED_STRING);

	talloc_free(cs);
}

static void test_pair_alloc_no_value(void)
{
	CONF_SECTION	*cs;
	CONF_PAIR	*cp;

	cs = cf_section_alloc(autofree, NULL, "test", NULL);
	TEST_ASSERT(cs != NULL);

	cp = cf_pair_alloc(cs, "flag", NULL, T_OP_EQ, T_BARE_WORD, T_BARE_WORD);
	TEST_ASSERT(cp != NULL);

	TEST_CHECK(strcmp(cf_pair_attr(cp), "flag") == 0);
	TEST_CHECK(cf_pair_value(cp) == NULL);

	talloc_free(cs);
}

static void test_pair_alloc_operators(void)
{
	CONF_SECTION	*cs;
	CONF_PAIR	*cp_set, *cp_add, *cp_cmp;

	cs = cf_section_alloc(autofree, NULL, "test", NULL);
	TEST_ASSERT(cs != NULL);

	cp_set = cf_pair_alloc(cs, "a", "1", T_OP_SET, T_BARE_WORD, T_BARE_WORD);
	TEST_ASSERT(cp_set != NULL);
	TEST_CHECK(cf_pair_operator(cp_set) == T_OP_SET);

	cp_add = cf_pair_alloc(cs, "b", "2", T_OP_ADD_EQ, T_BARE_WORD, T_BARE_WORD);
	TEST_ASSERT(cp_add != NULL);
	TEST_CHECK(cf_pair_operator(cp_add) == T_OP_ADD_EQ);

	cp_cmp = cf_pair_alloc(cs, "c", "3", T_OP_CMP_EQ, T_BARE_WORD, T_BARE_WORD);
	TEST_ASSERT(cp_cmp != NULL);
	TEST_CHECK(cf_pair_operator(cp_cmp) == T_OP_CMP_EQ);

	talloc_free(cs);
}

static void test_pair_replace(void)
{
	CONF_SECTION	*cs;
	CONF_PAIR	*cp;
	int		ret;

	cs = cf_section_alloc(autofree, NULL, "test", NULL);
	TEST_ASSERT(cs != NULL);

	cp = cf_pair_alloc(cs, "key", "old", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);
	TEST_ASSERT(cp != NULL);

	ret = cf_pair_replace(cs, cp, "new");
	TEST_CHECK(ret == 0);
	TEST_CHECK(strcmp(cf_pair_value(cp), "new") == 0);

	talloc_free(cs);
}

static void test_pair_to_item_roundtrip(void)
{
	CONF_SECTION	*cs;
	CONF_PAIR	*cp;
	CONF_ITEM	*ci;

	cs = cf_section_alloc(autofree, NULL, "test", NULL);
	TEST_ASSERT(cs != NULL);

	cp = cf_pair_alloc(cs, "attr", "val", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);
	TEST_ASSERT(cp != NULL);

	ci = cf_pair_to_item(cp);
	TEST_ASSERT(ci != NULL);
	TEST_CHECK(cf_item_is_pair(ci));
	TEST_CHECK(!cf_item_is_section(ci));
	TEST_CHECK(cf_item_to_pair(ci) == cp);

	talloc_free(cs);
}


/*
 *	Section search and traversal
 */

static void test_section_find_child(void)
{
	CONF_SECTION *parent, *c1, *c2, *c3, *found;

	parent = cf_section_alloc(autofree, NULL, "root", NULL);
	TEST_ASSERT(parent != NULL);

	c1 = cf_section_alloc(autofree, parent, "alpha", NULL);
	TEST_ASSERT(c1 != NULL);

	c2 = cf_section_alloc(autofree, parent, "beta", NULL);
	TEST_ASSERT(c2 != NULL);

	c3 = cf_section_alloc(autofree, parent, "gamma", NULL);
	TEST_ASSERT(c3 != NULL);

	found = cf_section_find(parent, "beta", NULL);
	TEST_CHECK(found == c2);

	found = cf_section_find(parent, "gamma", NULL);
	TEST_CHECK(found == c3);

	talloc_free(parent);
}

static void test_section_find_name1_name2(void)
{
	CONF_SECTION *parent, *s1, *s2, *found;

	parent = cf_section_alloc(autofree, NULL, "root", NULL);
	TEST_ASSERT(parent != NULL);

	s1 = cf_section_alloc(autofree, parent, "server", "default");
	TEST_ASSERT(s1 != NULL);

	s2 = cf_section_alloc(autofree, parent, "server", "inner");
	TEST_ASSERT(s2 != NULL);

	found = cf_section_find(parent, "server", "default");
	TEST_CHECK(found == s1);

	found = cf_section_find(parent, "server", "inner");
	TEST_CHECK(found == s2);

	talloc_free(parent);
}

static void test_section_find_missing(void)
{
	CONF_SECTION *parent, *found;

	parent = cf_section_alloc(autofree, NULL, "root", NULL);
	TEST_ASSERT(parent != NULL);

	cf_section_alloc(autofree, parent, "exists", NULL);

	found = cf_section_find(parent, "nope", NULL);
	TEST_CHECK(found == NULL);

	talloc_free(parent);
}

static void test_section_find_next(void)
{
	CONF_SECTION *parent, *s1, *s2, *found;

	parent = cf_section_alloc(autofree, NULL, "root", NULL);
	TEST_ASSERT(parent != NULL);

	s1 = cf_section_alloc(autofree, parent, "server", "a");
	TEST_ASSERT(s1 != NULL);

	s2 = cf_section_alloc(autofree, parent, "server", "b");
	TEST_ASSERT(s2 != NULL);

	found = cf_section_find(parent, "server", CF_IDENT_ANY);
	TEST_CHECK(found == s1);

	found = cf_section_find_next(parent, found, "server", CF_IDENT_ANY);
	TEST_CHECK(found == s2);

	found = cf_section_find_next(parent, found, "server", CF_IDENT_ANY);
	TEST_CHECK(found == NULL);

	talloc_free(parent);
}

static void test_section_first_next(void)
{
	CONF_SECTION *parent, *c1, *c2, *c3, *iter;

	parent = cf_section_alloc(autofree, NULL, "root", NULL);
	TEST_ASSERT(parent != NULL);

	c1 = cf_section_alloc(autofree, parent, "a", NULL);
	TEST_ASSERT(c1 != NULL);

	c2 = cf_section_alloc(autofree, parent, "b", NULL);
	TEST_ASSERT(c2 != NULL);

	c3 = cf_section_alloc(autofree, parent, "c", NULL);
	TEST_ASSERT(c3 != NULL);

	iter = cf_section_first(parent);
	TEST_CHECK(iter == c1);

	iter = cf_section_next(parent, iter);
	TEST_CHECK(iter == c2);

	iter = cf_section_next(parent, iter);
	TEST_CHECK(iter == c3);

	iter = cf_section_next(parent, iter);
	TEST_CHECK(iter == NULL);

	talloc_free(parent);
}

static void test_section_prev(void)
{
	CONF_SECTION *parent, *c1, *c2, *c3, *iter;

	parent = cf_section_alloc(autofree, NULL, "root", NULL);
	TEST_ASSERT(parent != NULL);

	c1 = cf_section_alloc(autofree, parent, "a", NULL);
	TEST_ASSERT(c1 != NULL);

	c2 = cf_section_alloc(autofree, parent, "b", NULL);
	TEST_ASSERT(c2 != NULL);

	c3 = cf_section_alloc(autofree, parent, "c", NULL);
	TEST_ASSERT(c3 != NULL);

	iter = cf_section_prev(parent, c3);
	TEST_CHECK(iter == c2);

	iter = cf_section_prev(parent, c2);
	TEST_CHECK(iter == c1);

	iter = cf_section_prev(parent, c1);
	TEST_CHECK(iter == NULL);

	talloc_free(parent);
}

static void test_section_value_find(void)
{
	CONF_SECTION	*cs;
	char const	*val;

	cs = cf_section_alloc(autofree, NULL, "test", NULL);
	TEST_ASSERT(cs != NULL);

	cf_pair_alloc(cs, "name", "myvalue", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);

	val = cf_section_value_find(cs, "name");
	TEST_ASSERT(val != NULL);
	TEST_CHECK(strcmp(val, "myvalue") == 0);

	val = cf_section_value_find(cs, "missing");
	TEST_CHECK(val == NULL);

	talloc_free(cs);
}


/*
 *	Pair search and traversal
 */

static void test_pair_find_basic(void)
{
	CONF_SECTION	*cs;
	CONF_PAIR	*cp, *found;

	cs = cf_section_alloc(autofree, NULL, "test", NULL);
	TEST_ASSERT(cs != NULL);

	cf_pair_alloc(cs, "key1", "val1", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);
	cp = cf_pair_alloc(cs, "key2", "val2", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);

	found = cf_pair_find(cs, "key2");
	TEST_CHECK(found == cp);
	TEST_CHECK(strcmp(cf_pair_value(found), "val2") == 0);

	talloc_free(cs);
}

static void test_pair_find_missing(void)
{
	CONF_SECTION	*cs;
	CONF_PAIR	*found;

	cs = cf_section_alloc(autofree, NULL, "test", NULL);
	TEST_ASSERT(cs != NULL);

	cf_pair_alloc(cs, "exists", "val", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);

	found = cf_pair_find(cs, "nope");
	TEST_CHECK(found == NULL);

	talloc_free(cs);
}

static void test_pair_find_next(void)
{
	CONF_SECTION	*cs;
	CONF_PAIR	*cp1, *cp2, *found;

	cs = cf_section_alloc(autofree, NULL, "test", NULL);
	TEST_ASSERT(cs != NULL);

	cp1 = cf_pair_alloc(cs, "host", "a", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);
	TEST_ASSERT(cp1 != NULL);

	cp2 = cf_pair_alloc(cs, "host", "b", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);
	TEST_ASSERT(cp2 != NULL);

	found = cf_pair_find(cs, "host");
	TEST_CHECK(found == cp1);

	found = cf_pair_find_next(cs, found, "host");
	TEST_CHECK(found == cp2);

	found = cf_pair_find_next(cs, found, "host");
	TEST_CHECK(found == NULL);

	talloc_free(cs);
}

static void test_pair_first_next(void)
{
	CONF_SECTION	*cs;
	CONF_PAIR	*cp1, *cp2, *cp3, *iter;

	cs = cf_section_alloc(autofree, NULL, "test", NULL);
	TEST_ASSERT(cs != NULL);

	cp1 = cf_pair_alloc(cs, "a", "1", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);
	TEST_ASSERT(cp1 != NULL);

	cp2 = cf_pair_alloc(cs, "b", "2", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);
	TEST_ASSERT(cp2 != NULL);

	cp3 = cf_pair_alloc(cs, "c", "3", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);
	TEST_ASSERT(cp3 != NULL);

	iter = cf_pair_first(cs);
	TEST_CHECK(iter == cp1);

	iter = cf_pair_next(cs, iter);
	TEST_CHECK(iter == cp2);

	iter = cf_pair_next(cs, iter);
	TEST_CHECK(iter == cp3);

	iter = cf_pair_next(cs, iter);
	TEST_CHECK(iter == NULL);

	talloc_free(cs);
}

static void test_pair_prev(void)
{
	CONF_SECTION	*cs;
	CONF_PAIR	*cp1, *cp2, *cp3, *iter;

	cs = cf_section_alloc(autofree, NULL, "test", NULL);
	TEST_ASSERT(cs != NULL);

	cp1 = cf_pair_alloc(cs, "a", "1", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);
	cp2 = cf_pair_alloc(cs, "b", "2", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);
	cp3 = cf_pair_alloc(cs, "c", "3", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);

	iter = cf_pair_prev(cs, cp3);
	TEST_CHECK(iter == cp2);

	iter = cf_pair_prev(cs, cp2);
	TEST_CHECK(iter == cp1);

	iter = cf_pair_prev(cs, cp1);
	TEST_CHECK(iter == NULL);

	talloc_free(cs);
}

static void test_pair_count(void)
{
	CONF_SECTION	*cs;

	cs = cf_section_alloc(autofree, NULL, "test", NULL);
	TEST_ASSERT(cs != NULL);

	cf_pair_alloc(cs, "x", "1", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);
	cf_pair_alloc(cs, "x", "2", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);
	cf_pair_alloc(cs, "x", "3", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);
	cf_pair_alloc(cs, "y", "a", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);
	cf_pair_alloc(cs, "y", "b", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);

	TEST_CHECK(cf_pair_count(cs, "x") == 3);
	TEST_CHECK(cf_pair_count(cs, "y") == 2);
	TEST_CHECK(cf_pair_count(cs, "z") == 0);

	talloc_free(cs);
}

static void test_pair_count_descendents(void)
{
	CONF_SECTION	*parent, *child;

	parent = cf_section_alloc(autofree, NULL, "root", NULL);
	TEST_ASSERT(parent != NULL);

	cf_pair_alloc(parent, "a", "1", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);
	cf_pair_alloc(parent, "b", "2", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);

	child = cf_section_alloc(autofree, parent, "sub", NULL);
	TEST_ASSERT(child != NULL);

	cf_pair_alloc(child, "c", "3", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);

	TEST_CHECK(cf_pair_count_descendents(parent) == 3);
	TEST_CHECK(cf_pair_count_descendents(child) == 1);

	talloc_free(parent);
}


/*
 *	Item manipulation
 */

static void test_item_remove_pair(void)
{
	CONF_SECTION	*cs;
	CONF_PAIR	*cp;

	cs = cf_section_alloc(autofree, NULL, "test", NULL);
	TEST_ASSERT(cs != NULL);

	cp = cf_pair_alloc(cs, "remove_me", "val", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);
	TEST_ASSERT(cp != NULL);

	TEST_CHECK(cf_pair_find(cs, "remove_me") == cp);

	cf_item_remove(cs, cp);
	TEST_CHECK(cf_pair_find(cs, "remove_me") == NULL);

	talloc_free(cp);
	talloc_free(cs);
}

static void test_item_remove_section(void)
{
	CONF_SECTION	*parent, *child;

	parent = cf_section_alloc(autofree, NULL, "root", NULL);
	TEST_ASSERT(parent != NULL);

	child = cf_section_alloc(autofree, parent, "removable", NULL);
	TEST_ASSERT(child != NULL);

	TEST_CHECK(cf_section_find(parent, "removable", NULL) == child);

	cf_item_remove(parent, child);
	TEST_CHECK(cf_section_find(parent, "removable", NULL) == NULL);

	talloc_free(child);
	talloc_free(parent);
}

static void test_item_next_mixed(void)
{
	CONF_SECTION	*parent;
	CONF_PAIR	*cp;
	CONF_SECTION	*cs;
	CONF_ITEM	*ci;
	int		count = 0;

	parent = cf_section_alloc(autofree, NULL, "root", NULL);
	TEST_ASSERT(parent != NULL);

	cp = cf_pair_alloc(parent, "key", "val", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);
	TEST_ASSERT(cp != NULL);

	cs = cf_section_alloc(autofree, parent, "sub", NULL);
	TEST_ASSERT(cs != NULL);

	cf_pair_alloc(parent, "key2", "val2", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);

	/*
	 *	cf_item_next iterates all children regardless of type.
	 */
	for (ci = cf_item_next(parent, NULL); ci; ci = cf_item_next(parent, ci)) {
		count++;
	}
	TEST_CHECK(count == 3);
	TEST_MSG("Expected 3 items, got %d", count);

	talloc_free(parent);
}

static void test_item_free_children(void)
{
	CONF_SECTION	*cs;

	cs = cf_section_alloc(autofree, NULL, "test", NULL);
	TEST_ASSERT(cs != NULL);

	cf_pair_alloc(cs, "a", "1", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);
	cf_pair_alloc(cs, "b", "2", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);
	cf_section_alloc(autofree, cs, "child", NULL);

	TEST_CHECK(cf_pair_first(cs) != NULL);
	TEST_CHECK(cf_section_first(cs) != NULL);

	cf_section_free_children(cs);

	TEST_CHECK(cf_pair_first(cs) == NULL);
	TEST_CHECK(cf_section_first(cs) == NULL);

	talloc_free(cs);
}

static void test_item_mark_parsed(void)
{
	CONF_SECTION	*cs;
	CONF_PAIR	*cp;

	cs = cf_section_alloc(autofree, NULL, "test", NULL);
	TEST_ASSERT(cs != NULL);

	cp = cf_pair_alloc(cs, "key", "val", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);
	TEST_ASSERT(cp != NULL);

	TEST_CHECK(!cf_item_is_parsed(cp));

	cf_item_mark_parsed(cp);
	TEST_CHECK(cf_item_is_parsed(cp));

	talloc_free(cs);
}


/*
 *	Section duplication
 */

static void test_section_dup_basic(void)
{
	CONF_SECTION	*cs, *dup;
	CONF_PAIR	*cp;

	cs = cf_section_alloc(autofree, NULL, "server", "main");
	TEST_ASSERT(cs != NULL);

	cp = cf_pair_alloc(cs, "listen", "1812", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);
	TEST_ASSERT(cp != NULL);
	cf_filename_set(cp, "test.conf");

	cp = cf_pair_alloc(cs, "type", "auth", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);
	TEST_ASSERT(cp != NULL);
	cf_filename_set(cp, "test.conf");

	dup = cf_section_dup(autofree, NULL, cs, cf_section_name1(cs), cf_section_name2(cs), false);
	TEST_ASSERT(dup != NULL);
	TEST_CHECK(dup != cs);
	TEST_CHECK(strcmp(cf_section_name1(dup), "server") == 0);
	TEST_CHECK(strcmp(cf_section_name2(dup), "main") == 0);

	cp = cf_pair_find(dup, "listen");
	TEST_ASSERT(cp != NULL);
	TEST_CHECK(strcmp(cf_pair_value(cp), "1812") == 0);

	cp = cf_pair_find(dup, "type");
	TEST_ASSERT(cp != NULL);
	TEST_CHECK(strcmp(cf_pair_value(cp), "auth") == 0);

	talloc_free(cs);
	talloc_free(dup);
}

static void test_section_dup_rename(void)
{
	CONF_SECTION	*cs, *dup;
	CONF_PAIR	*cp;

	cs = cf_section_alloc(autofree, NULL, "server", "old");
	TEST_ASSERT(cs != NULL);

	cp = cf_pair_alloc(cs, "port", "1812", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);
	TEST_ASSERT(cp != NULL);
	cf_filename_set(cp, "test.conf");

	dup = cf_section_dup(autofree, NULL, cs, "newname", "newname2", false);
	TEST_ASSERT(dup != NULL);
	TEST_CHECK(strcmp(cf_section_name1(dup), "newname") == 0);
	TEST_CHECK(strcmp(cf_section_name2(dup), "newname2") == 0);

	/*
	 *	Children should still be present.
	 */
	TEST_CHECK(cf_pair_find(dup, "port") != NULL);

	talloc_free(cs);
	talloc_free(dup);
}

static void test_pair_dup(void)
{
	CONF_SECTION	*cs1, *cs2;
	CONF_PAIR	*cp, *dup;

	cs1 = cf_section_alloc(autofree, NULL, "src", NULL);
	TEST_ASSERT(cs1 != NULL);

	cs2 = cf_section_alloc(autofree, NULL, "dst", NULL);
	TEST_ASSERT(cs2 != NULL);

	cp = cf_pair_alloc(cs1, "key", "val", T_OP_SET, T_BARE_WORD, T_SINGLE_QUOTED_STRING);
	TEST_ASSERT(cp != NULL);

	dup = cf_pair_dup(cs2, cp, false);
	TEST_ASSERT(dup != NULL);
	TEST_CHECK(dup != cp);
	TEST_CHECK(strcmp(cf_pair_attr(dup), "key") == 0);
	TEST_CHECK(strcmp(cf_pair_value(dup), "val") == 0);
	TEST_CHECK(cf_pair_operator(dup) == T_OP_SET);
	TEST_CHECK(cf_pair_value_quote(dup) == T_SINGLE_QUOTED_STRING);

	talloc_free(cs1);
	talloc_free(cs2);
}


/*
 *	Metadata
 */

static void test_filename_lineno(void)
{
	CONF_SECTION	*cs;

	cs = cf_section_alloc(autofree, NULL, "test", NULL);
	TEST_ASSERT(cs != NULL);

	/*
	 *	In debug builds, cf_section_alloc sets filename to __FILE__
	 *	and lineno to __LINE__.  Just verify they are set to something.
	 */
#ifndef NDEBUG
	TEST_CHECK(cf_filename(cs) != NULL);
	TEST_CHECK(cf_lineno(cs) > 0);
#endif

	talloc_free(cs);
}

static void test_filename_set(void)
{
	CONF_SECTION	*cs;

	cs = cf_section_alloc(autofree, NULL, "test", NULL);
	TEST_ASSERT(cs != NULL);

	cf_filename_set(cs, "test.conf");
	TEST_CHECK(strcmp(cf_filename(cs), "test.conf") == 0);

	talloc_free(cs);
}

static void test_lineno_set(void)
{
	CONF_SECTION	*cs;

	cs = cf_section_alloc(autofree, NULL, "test", NULL);
	TEST_ASSERT(cs != NULL);

	cf_lineno_set(cs, 42);
	TEST_CHECK(cf_lineno(cs) == 42);

	talloc_free(cs);
}

static void test_cf_root(void)
{
	CONF_SECTION *root, *mid, *leaf;

	root = cf_section_alloc(autofree, NULL, "root", NULL);
	TEST_ASSERT(root != NULL);

	mid = cf_section_alloc(autofree, root, "mid", NULL);
	TEST_ASSERT(mid != NULL);

	leaf = cf_section_alloc(autofree, mid, "leaf", NULL);
	TEST_ASSERT(leaf != NULL);

	TEST_CHECK(cf_root(leaf) == root);
	TEST_CHECK(cf_root(mid) == root);
	TEST_CHECK(cf_root(root) == root);

	talloc_free(root);
}


/*
 *	CONF_DATA
 */

static void test_data_add_find(void)
{
	CONF_SECTION		*cs;
	uint32_t		*val;
	CONF_DATA const		*cd;
	void			*found;

	cs = cf_section_alloc(autofree, NULL, "test", NULL);
	TEST_ASSERT(cs != NULL);

	val = talloc(cs, uint32_t);
	TEST_ASSERT(val != NULL);
	*val = 12345;

	cd = cf_data_add(cs, val, "counter", false);
	TEST_CHECK(cd != NULL);

	found = cf_data_value(cd);
	TEST_CHECK(found == val);
	TEST_CHECK(*(uint32_t *)found == 12345);

	talloc_free(cs);
}

static void test_data_find_missing(void)
{
	CONF_SECTION	*cs;
	CONF_DATA const	*cd;

	cs = cf_section_alloc(autofree, NULL, "test", NULL);
	TEST_ASSERT(cs != NULL);

	cd = _cf_data_find(cf_section_to_item(cs), "uint32_t", "nonexistent");
	TEST_CHECK(cd == NULL);

	talloc_free(cs);
}

static void test_data_remove(void)
{
	CONF_SECTION		*cs;
	uint32_t		*val;
	CONF_DATA const		*cd;

	cs = cf_section_alloc(autofree, NULL, "test", NULL);
	TEST_ASSERT(cs != NULL);

	val = talloc(cs, uint32_t);
	*val = 99;

	cd = cf_data_add(cs, val, "remove_me", false);
	TEST_CHECK(cd != NULL);

	_cf_data_remove(cf_section_to_item(cs), cd);

	cd = _cf_data_find(cf_section_to_item(cs), "uint32_t", "remove_me");
	TEST_CHECK(cd == NULL);

	talloc_free(cs);
}


/*
 *	Variable expansion - cf_expand_variables
 */

static void test_expand_no_variables(void)
{
	CONF_SECTION	*cs;
	char		output[256];
	char const	*result;

	cs = cf_section_alloc(autofree, NULL, "root", NULL);
	TEST_ASSERT(cs != NULL);

	result = cf_expand_variables("test.conf", 1, cs,
				     output, sizeof(output),
				     "hello world", -1, NULL);
	TEST_CHECK(result != NULL);
	if (result) {
		TEST_CHECK(strcmp(result, "hello world") == 0);
		TEST_MSG("Expected 'hello world', got '%s'", result);
	}

	talloc_free(cs);
}

static void test_expand_section_ref(void)
{
	CONF_SECTION	*cs;
	char		output[256];
	char const	*result;

	cs = cf_section_alloc(autofree, NULL, "root", NULL);
	TEST_ASSERT(cs != NULL);

	cf_pair_alloc(cs, "name", "testval", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);

	result = cf_expand_variables("test.conf", 1, cs,
				     output, sizeof(output),
				     "${name}", -1, NULL);
	TEST_CHECK(result != NULL);
	if (result) {
		TEST_CHECK(strcmp(result, "testval") == 0);
		TEST_MSG("Expected 'testval', got '%s'", result);
	}

	talloc_free(cs);
}

static void test_expand_nested_ref(void)
{
	CONF_SECTION	*root, *sub;
	char		output[256];
	char const	*result;

	root = cf_section_alloc(autofree, NULL, "root", NULL);
	TEST_ASSERT(root != NULL);

	sub = cf_section_alloc(autofree, root, "server", NULL);
	TEST_ASSERT(sub != NULL);

	cf_pair_alloc(sub, "name", "myserver", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);

	result = cf_expand_variables("test.conf", 1, root,
				     output, sizeof(output),
				     "${server.name}", -1, NULL);
	TEST_CHECK(result != NULL);
	if (result) {
		TEST_CHECK(strcmp(result, "myserver") == 0);
		TEST_MSG("Expected 'myserver', got '%s'", result);
	}

	talloc_free(root);
}

static void test_expand_missing_ref(void)
{
	CONF_SECTION	*cs;
	char		output[256];
	char const	*result;
	bool		soft_fail = false;

	cs = cf_section_alloc(autofree, NULL, "root", NULL);
	TEST_ASSERT(cs != NULL);

	result = cf_expand_variables("test.conf", 1, cs,
				     output, sizeof(output),
				     "${nonexistent}", -1, &soft_fail);
	TEST_CHECK(result == NULL);
	TEST_CHECK(soft_fail == true);
	TEST_MSG("Expected soft_fail to be set for missing reference");

	talloc_free(cs);
}


/*
 *	Pair value concatenation
 */

static void test_pair_values_concat(void)
{
	CONF_SECTION	*cs;
	char		buffer[256];
	fr_sbuff_t	sbuff = FR_SBUFF_OUT(buffer, sizeof(buffer));
	fr_slen_t	slen;

	cs = cf_section_alloc(autofree, NULL, "test", NULL);
	TEST_ASSERT(cs != NULL);

	cf_pair_alloc(cs, "host", "a", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);
	cf_pair_alloc(cs, "host", "b", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);
	cf_pair_alloc(cs, "host", "c", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);

	slen = cf_pair_values_concat(&sbuff, cs, "host", ", ");
	TEST_CHECK(slen > 0);
	TEST_MSG("cf_pair_values_concat returned %zd", slen);

	fr_sbuff_terminate(&sbuff);
	TEST_CHECK(strcmp(buffer, "a, b, c") == 0);
	TEST_MSG("Expected 'a, b, c', got '%s'", buffer);

	talloc_free(cs);
}

static void test_pair_values_concat_missing(void)
{
	CONF_SECTION	*cs;
	char		buffer[256];
	fr_sbuff_t	sbuff = FR_SBUFF_OUT(buffer, sizeof(buffer));
	fr_slen_t	slen;

	cs = cf_section_alloc(autofree, NULL, "test", NULL);
	TEST_ASSERT(cs != NULL);

	slen = cf_pair_values_concat(&sbuff, cs, "nope", ", ");
	TEST_CHECK(slen == 0);

	talloc_free(cs);
}


/*
 *	cf_reference_item
 */

static void test_reference_item_pair(void)
{
	CONF_SECTION	*cs;
	CONF_PAIR	*cp;
	CONF_ITEM	*ci;

	cs = cf_section_alloc(autofree, NULL, "root", NULL);
	TEST_ASSERT(cs != NULL);

	cp = cf_pair_alloc(cs, "mykey", "myval", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);
	TEST_ASSERT(cp != NULL);

	ci = cf_reference_item(cs, cs, "mykey");
	TEST_CHECK(ci != NULL);
	if (ci) {
		TEST_CHECK(cf_item_is_pair(ci));
		TEST_CHECK(cf_item_to_pair(ci) == cp);
	}

	talloc_free(cs);
}

static void test_reference_item_section(void)
{
	CONF_SECTION	*root, *child;
	CONF_ITEM	*ci;

	root = cf_section_alloc(autofree, NULL, "root", NULL);
	TEST_ASSERT(root != NULL);

	child = cf_section_alloc(autofree, root, "child", NULL);
	TEST_ASSERT(child != NULL);

	ci = cf_reference_item(root, root, "child");
	TEST_CHECK(ci != NULL);
	if (ci) {
		TEST_CHECK(cf_item_is_section(ci));
		TEST_CHECK(cf_item_to_section(ci) == child);
	}

	talloc_free(root);
}

static void test_reference_item_missing(void)
{
	CONF_SECTION	*cs;
	CONF_ITEM	*ci;

	cs = cf_section_alloc(autofree, NULL, "root", NULL);
	TEST_ASSERT(cs != NULL);

	ci = cf_reference_item(cs, cs, "nonexistent");
	TEST_CHECK(ci == NULL);

	talloc_free(cs);
}


/*
 *	cf_pair_in_table
 */

static fr_table_num_sorted_t const test_table[] = {
	{ L("bar"),	2 },
	{ L("foo"),	1 },
};
static size_t test_table_len = NUM_ELEMENTS(test_table);

static void test_pair_in_table_found(void)
{
	CONF_SECTION	*cs;
	CONF_PAIR	*cp;
	int32_t		out = 0;
	int		ret;

	cs = cf_section_alloc(autofree, NULL, "test", NULL);
	TEST_ASSERT(cs != NULL);

	cp = cf_pair_alloc(cs, "type", "foo", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);
	TEST_ASSERT(cp != NULL);

	ret = cf_pair_in_table(&out, test_table, test_table_len, cp);
	TEST_CHECK(ret == 0);
	TEST_CHECK(out == 1);

	talloc_free(cs);
}

static void test_pair_in_table_invalid(void)
{
	CONF_SECTION	*cs;
	CONF_PAIR	*cp;
	int32_t		out = 0;
	int		ret;

	cs = cf_section_alloc(autofree, NULL, "test", NULL);
	TEST_ASSERT(cs != NULL);

	cp = cf_pair_alloc(cs, "type", "invalid_value", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);
	TEST_ASSERT(cp != NULL);

	ret = cf_pair_in_table(&out, test_table, test_table_len, cp);
	TEST_CHECK(ret == -1);

	talloc_free(cs);
}


TEST_LIST = {
	/* Section allocation and accessors */
	{ "test_section_alloc_name1_only",	test_section_alloc_name1_only },
	{ "test_section_alloc_name1_name2",	test_section_alloc_name1_name2 },
	{ "test_section_alloc_parent",		test_section_alloc_parent },
	{ "test_section_name_cmp",		test_section_name_cmp },
	{ "test_section_to_item_roundtrip",	test_section_to_item_roundtrip },

	/* Pair allocation and accessors */
	{ "test_pair_alloc_basic",		test_pair_alloc_basic },
	{ "test_pair_alloc_quoted",		test_pair_alloc_quoted },
	{ "test_pair_alloc_no_value",		test_pair_alloc_no_value },
	{ "test_pair_alloc_operators",		test_pair_alloc_operators },
	{ "test_pair_replace",			test_pair_replace },
	{ "test_pair_to_item_roundtrip",	test_pair_to_item_roundtrip },

	/* Section search and traversal */
	{ "test_section_find_child",		test_section_find_child },
	{ "test_section_find_name1_name2",	test_section_find_name1_name2 },
	{ "test_section_find_missing",		test_section_find_missing },
	{ "test_section_find_next",		test_section_find_next },
	{ "test_section_first_next",		test_section_first_next },
	{ "test_section_prev",			test_section_prev },
	{ "test_section_value_find",		test_section_value_find },

	/* Pair search and traversal */
	{ "test_pair_find_basic",		test_pair_find_basic },
	{ "test_pair_find_missing",		test_pair_find_missing },
	{ "test_pair_find_next",		test_pair_find_next },
	{ "test_pair_first_next",		test_pair_first_next },
	{ "test_pair_prev",			test_pair_prev },
	{ "test_pair_count",			test_pair_count },
	{ "test_pair_count_descendents",	test_pair_count_descendents },

	/* Item manipulation */
	{ "test_item_remove_pair",		test_item_remove_pair },
	{ "test_item_remove_section",		test_item_remove_section },
	{ "test_item_next_mixed",		test_item_next_mixed },
	{ "test_item_free_children",		test_item_free_children },
	{ "test_item_mark_parsed",		test_item_mark_parsed },

	/* Section duplication */
	{ "test_section_dup_basic",		test_section_dup_basic },
	{ "test_section_dup_rename",		test_section_dup_rename },
	{ "test_pair_dup",			test_pair_dup },

	/* Metadata */
	{ "test_filename_lineno",		test_filename_lineno },
	{ "test_filename_set",			test_filename_set },
	{ "test_lineno_set",			test_lineno_set },
	{ "test_cf_root",			test_cf_root },

	/* CONF_DATA */
	{ "test_data_add_find",		test_data_add_find },
	{ "test_data_find_missing",		test_data_find_missing },
	{ "test_data_remove",			test_data_remove },

	/* Variable expansion */
	{ "test_expand_no_variables",		test_expand_no_variables },
	{ "test_expand_section_ref",		test_expand_section_ref },
	{ "test_expand_nested_ref",		test_expand_nested_ref },
	{ "test_expand_missing_ref",		test_expand_missing_ref },

	/* Pair value concatenation */
	{ "test_pair_values_concat",		test_pair_values_concat },
	{ "test_pair_values_concat_missing",	test_pair_values_concat_missing },

	/* cf_reference_item */
	{ "test_reference_item_pair",		test_reference_item_pair },
	{ "test_reference_item_section",	test_reference_item_section },
	{ "test_reference_item_missing",	test_reference_item_missing },

	/* cf_pair_in_table */
	{ "test_pair_in_table_found",		test_pair_in_table_found },
	{ "test_pair_in_table_invalid",		test_pair_in_table_invalid },

	TEST_TERMINATOR
};
