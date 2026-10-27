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

/** Tests for `radius_pairmove()`
 *
 * @file src/tests/pairmove/pairmove_tests.c
 *
 * `radius_pairmove()` merges the pairs of the `from` list into the `to` list,
 * and applies the operator of each pair in the `from` list.  These tests
 * record the behaviour of `radius_pairmove()`.  A developer who rewrites the
 * function runs the tests to check that the behaviour is unchanged.
 *
 * Each test writes a list as short text, for example `s0=a i0+=5`.  Each
 * entry has a name, an operator, and a value:
 *
 *	s0, s1, s2	`Tmp-String-0`, `Tmp-String-1`, `Tmp-String-2`
 *	i0, i1		`Tmp-Integer-0`, `Tmp-Integer-1`
 *	p4, p6		`Tmp-Cast-IPv4Prefix`, `Tmp-Cast-IPv6Prefix`
 *	un, up		`User-Name`, `User-Password`
 *
 * Each test renders the merged `to` list in the same text form, and compares
 * the result with the expected text.  Each case runs against the packet list,
 * the reply list, and the config list of a request.  After the merge, the test
 * frees the `to` list and checks that the number of talloc blocks under the
 * request equals the number before the merge.  The check catches a leak of
 * pairs, or of the temporary arrays that `radius_pairmove()` allocates.
 *
 * These tests do not cover the dynamic expansion of values (xlat).  Every call
 * passes `false` for the `do_xlat` argument.
 *
 * @copyright 2026 The FreeRADIUS server project
 */
#include <freeradius-devel/libradius.h>
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/conf.h>	/* RADIUS_DICTIONARY */

#include "../api/acutest_common_init.h"
#include "../api/acutest_helpers.h"

#define NUM_ELEMENTS(_x) (sizeof(_x) / sizeof((_x)[0]))

static TALLOC_CTX	*autofree;

/*
 *	`threads.c` defines `rad_fork()` and `rad_waitpid()`, and
 *	`libfreeradius-server` calls both functions.  The tests do not run
 *	programs and do not link `threads.c`.  Because of that, the tests
 *	define both functions here.
 */
#ifdef HAVE_PTHREAD_H
#  include <sys/wait.h>

pid_t rad_fork(void)
{
	return fork();
}

pid_t rad_waitpid(pid_t pid, int *status)
{
	return waitpid(pid, status, 0);
}
#endif

static void test_init(void) __attribute__((constructor));
static void test_init(void)
{
	char const *dict_dir = getenv("DICT_DIR");

DIAG_OFF(deprecated-declarations)
	autofree = talloc_autofree_context();
DIAG_ON(deprecated-declarations)
	if (!autofree) {
		fr_perror("pairmove_tests");
		exit(EXIT_FAILURE);
	}

	/*
	 *	Check that the binary matches the libraries that the binary depends on.
	 */
	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) {
		fr_perror("pairmove_tests");
		exit(EXIT_FAILURE);
	}

	if (!dict_dir) dict_dir = "share";

	if (dict_init(dict_dir, RADIUS_DICTIONARY) < 0) {
		fr_perror("pairmove_tests: failed loading dictionaries from \"%s\"", dict_dir);
		fprintf(stderr, "Set DICT_DIR to the directory holding \"dictionary\"\n");
		exit(EXIT_FAILURE);
	}
}

/*
 *	The text form of a list uses these short names for attributes.
 */
static struct {
	char const	*name;
	char const	*attr;
} const attr_names[] = {
	{ "s0", "Tmp-String-0" },
	{ "s1", "Tmp-String-1" },
	{ "s2", "Tmp-String-2" },
	{ "i0", "Tmp-Integer-0" },
	{ "i1", "Tmp-Integer-1" },
	{ "p4", "Tmp-Cast-IPv4Prefix" },
	{ "p6", "Tmp-Cast-IPv6Prefix" },
	{ "un", "User-Name" },
	{ "up", "User-Password" },
};

/*
 *	`list_alloc()` uses the first operator in this table that matches the
 *	text.  An operator that is the prefix of another operator, such as '='
 *	in '==', must come after the longer operator.
 */
static struct {
	char const	*str;
	FR_TOKEN	op;
} const op_names[] = {
	{ ":=", T_OP_SET },
	{ "+=", T_OP_ADD },
	{ "-=", T_OP_SUB },
	{ "==", T_OP_CMP_EQ },
	{ "<=", T_OP_LE },
	{ ">=", T_OP_GE },
	{ "!*", T_OP_CMP_FALSE },
	{ "^=", T_OP_PREPEND },
	{ "=", T_OP_EQ },
};

/** Build a list of pairs from the text in `spec`
 *
 * `list_alloc()` allocates the pairs in `ctx`.  Because the '!*' operator
 * does not take a value, `list_alloc()` gives the pair an empty string, or
 * zero for an integer.
 */
static VALUE_PAIR *list_alloc(TALLOC_CTX *ctx, char const *spec)
{
	VALUE_PAIR	*head = NULL;
	char const	*p = spec;

	while (*p) {
		char		name[3];
		char		value[64];
		char const	*attr = NULL;
		FR_TOKEN	op = T_INVALID;
		size_t		i, len;
		VALUE_PAIR	*vp;

		while (*p == ' ') p++;
		if (!*p) break;

		TEST_ASSERT(p[0] && p[1]);
		name[0] = p[0];
		name[1] = p[1];
		name[2] = '\0';
		p += 2;

		for (i = 0; i < NUM_ELEMENTS(attr_names); i++) {
			if (strcmp(attr_names[i].name, name) == 0) {
				attr = attr_names[i].attr;
				break;
			}
		}
		TEST_ASSERT(attr != NULL);

		for (i = 0; i < NUM_ELEMENTS(op_names); i++) {
			len = strlen(op_names[i].str);
			if (strncmp(p, op_names[i].str, len) == 0) {
				op = op_names[i].op;
				p += len;
				break;
			}
		}
		TEST_ASSERT(op != T_INVALID);

		len = strcspn(p, " ");
		TEST_ASSERT(len < sizeof(value));
		memcpy(value, p, len);
		value[len] = '\0';
		p += len;

		if ((len == 0) && (name[0] == 'i')) strcpy(value, "0");

		vp = fr_pair_make(ctx, &head, attr, value, op);
		TEST_ASSERT(vp != NULL);
	}

	return head;
}

/** Render a list in the text form that `list_alloc()` accepts
 *
 * Because `list_str()` omits the '=' operator, a result pair that still has
 * an operator from the `from` list shows the operator in the output.
 */
static char const *list_str(VALUE_PAIR *head)
{
	static char	buffer[4096];
	char		*p = buffer, *end = buffer + sizeof(buffer);
	VALUE_PAIR	*vp;

	buffer[0] = '\0';

	for (vp = head; vp; vp = vp->next) {
		char		value[256];
		char const	*name = NULL;
		size_t		i;

		for (i = 0; i < NUM_ELEMENTS(attr_names); i++) {
			if (strcmp(attr_names[i].attr, vp->da->name) == 0) {
				name = attr_names[i].name;
				break;
			}
		}
		if (!name) name = vp->da->name;

		(void) vp_prints_value(value, sizeof(value), vp, 0);

		p += snprintf(p, end - p, "%s%s%s%s", (p == buffer) ? "" : " ", name,
			      (vp->op == T_OP_EQ) ? "=" : fr_int2str(fr_tokens, vp->op, "?"), value);
		if (p >= end) break;
	}

	return buffer;
}

static size_t list_len(VALUE_PAIR *head)
{
	size_t		count = 0;
	VALUE_PAIR	*vp;

	for (vp = head; vp; vp = vp->next) count++;

	return count;
}

typedef enum {
	LIST_PACKET = 0,
	LIST_REPLY,
	LIST_CONFIG,
	LIST_NUM
} list_target_t;

static char const *list_target_names[LIST_NUM] = { "packet", "reply", "config" };

/** Make a request that has a packet and a reply, with empty pair lists
 */
static REQUEST *request_make(TALLOC_CTX *ctx)
{
	REQUEST *request;

	request = request_alloc(ctx);
	TEST_ASSERT(request != NULL);

	request->packet = rad_alloc(request, false);
	TEST_ASSERT(request->packet != NULL);

	request->reply = rad_alloc(request, false);
	TEST_ASSERT(request->reply != NULL);

	return request;
}

/** Get the pair list and the talloc context for a target
 *
 * `list_target()` sets `*ctx` to the talloc context in which the server
 * allocates the pairs of the list.
 */
static VALUE_PAIR **list_target(TALLOC_CTX **ctx, REQUEST *request, list_target_t target)
{
	switch (target) {
	case LIST_PACKET:
		*ctx = request->packet;
		return &request->packet->vps;

	case LIST_REPLY:
		*ctx = request->reply;
		return &request->reply->vps;

	default:
		*ctx = request;
		return &request->config;
	}
}

typedef struct {
	char const	*name;
	char const	*to;		//!< Text form of the `to` list before the merge.
	char const	*from;		//!< Text form of the `from` list.
	char const	*expect;	//!< Expected text form of the `to` list after the merge.
} pairmove_case_t;

static void pairmove_run(pairmove_case_t const *tc, list_target_t target)
{
	REQUEST		*request;
	TALLOC_CTX	*ctx;
	VALUE_PAIR	**to;
	VALUE_PAIR	*from;
	size_t		before, after;

	request = request_make(autofree);
	to = list_target(&ctx, request, target);

	before = talloc_total_blocks(request);

	*to = list_alloc(ctx, tc->to);
	from = list_alloc(ctx, tc->from);

	radius_pairmove(request, to, from, false);	/* consumes `from` */

	TEST_CASE_("%s: %s", tc->name, list_target_names[target]);
	TEST_CHECK_STRCMP(list_str(*to), tc->expect);

	/*
	 *	Each pair must be in the `to` list or freed by `radius_pairmove()`.
	 *	Freeing the `to` list then returns the number of talloc blocks to the
	 *	value before the merge.
	 */
	fr_pair_list_free(to);
	after = talloc_total_blocks(request);
	TEST_CHECK(after == before);
	TEST_MSG("Blocks before : %zu", before);
	TEST_MSG("Blocks after  : %zu", after);

	talloc_free(request);
}

static void pairmove_run_cases(pairmove_case_t const *cases, size_t num)
{
	size_t		i;
	list_target_t	target;

	for (i = 0; i < num; i++) {
		for (target = 0; target < LIST_NUM; target++) pairmove_run(&cases[i], target);
	}
}

/*
 *	The '=' operator adds an attribute to the `to` list only if the `to`
 *	list does not already have an instance of the attribute.
 */
static void test_op_eq(void)
{
	static pairmove_case_t const cases[] = {
		{ "empty into empty",		"",		"",		"" },
		{ "= into empty",		"",		"s0=a",		"s0=a" },
		{ "= absent attribute",		"s0=a",		"s1=b",		"s0=a s1=b" },
		{ "= present attribute",	"s0=a",		"s0=b",		"s0=a" },
		{ "= present, others",		"s1=x s0=a",	"s0=b s2=c",	"s1=x s0=a s2=c" },

		/*
		 *	Because '=' checks the original `to` list only, and the original
		 *	`to` list is empty, the merge adds both `s0=a` and `s0=b`.
		 */
		{ "= twice, absent",		"",		"s0=a s0=b",	"s0=a s0=b" },
	};

	pairmove_run_cases(cases, NUM_ELEMENTS(cases));
}

/*
 *	The ':=' operator replaces the first instance of the attribute in the
 *	`to` list.  The operator adds the attribute when the `to` list does
 *	not have an instance.
 */
static void test_op_set(void)
{
	static pairmove_case_t const cases[] = {
		{ ":= into empty",		"",		"s0:=c",	"s0=c" },
		{ ":= absent attribute",	"s1=x",		"s0:=c",	"s1=x s0=c" },
		{ ":= replaces in place",	"s1=x s0=a i0=1", "s0:=b",	"s1=x s0=b i0=1" },
		{ ":= replaces first only",	"s0=a s0=b",	"s0:=c",	"s0=c s0=b" },

		/*
		 *	Because the merge does not replace an instance twice, the second ':='
		 *	replaces the second instance of the attribute, or adds a new instance
		 *	when the `to` list has only one instance.
		 */
		{ ":= twice, one instance",	"s0=a",		"s0:=b s0:=c",	"s0=b s0=c" },
		{ ":= twice, two instances",	"s0=a s0=x",	"s0:=b s0:=c",	"s0=b s0=c" },
		{ ":= thrice, two instances",	"s0=a s0=x",	"s0:=b s0:=c s0:=d", "s0=b s0=c s0=d" },
		{ ":= integer",			"i0=1",		"i0:=2",	"i0=2" },
	};

	pairmove_run_cases(cases, NUM_ELEMENTS(cases));
}

/*
 *	The '+=' operator always adds the attribute at the end of the `to` list.
 */
static void test_op_add(void)
{
	static pairmove_case_t const cases[] = {
		{ "+= into empty",		"",		"s0+=a",	"s0=a" },
		{ "+= present attribute",	"s0=a",		"s0+=b",	"s0=a s0=b" },
		{ "+= same value",		"s0=a",		"s0+=a",	"s0=a s0=a" },
		{ "+= keeps from order",	"s0=a",		"s1+=x s2+=y s1+=z", "s0=a s1=x s2=y s1=z" },
		{ "+= integer",			"i0=1",		"i0+=2",	"i0=1 i0=2" },
	};

	pairmove_run_cases(cases, NUM_ELEMENTS(cases));
}

/*
 *	The '^=' operator adds the attribute at the start of the `to` list.
 *
 *	The merge applies the '^=' pairs in the order of the `from` list.
 *	Because each '^=' pair goes to the start of the `to` list, a later
 *	'^=' pair comes before an earlier '^=' pair.  The result lists the '^='
 *	attributes in the reverse of the order of the `from` list.
 */
static void test_op_prepend(void)
{
	static pairmove_case_t const cases[] = {
		{ "^= into empty",		"",		"s0^=a",	"s0=a" },
		{ "^= one attribute",		"s0=a",		"s1^=x",	"s1=x s0=a" },
		{ "^= present attribute",	"s0=a",		"s0^=b",	"s0=b s0=a" },
		{ "^= two attributes",		"s0=a",		"s1^=x s2^=y",	"s2=y s1=x s0=a" },
		{ "^= three attributes",	"",		"s0^=a s1^=b s2^=c", "s2=c s1=b s0=a" },
		{ "^= and +=",			"s0=a",		"s1+=x s2^=y",	"s2=y s0=a s1=x" },
	};

	pairmove_run_cases(cases, NUM_ELEMENTS(cases));
}

/*
 *	The '-=' operator deletes every instance of the attribute from the
 *	`to` list when the value of the instance matches the value of the
 *	`from` pair.
 */
static void test_op_sub(void)
{
	static pairmove_case_t const cases[] = {
		{ "-= from empty",		"",		"s0-=a",	"" },
		{ "-= absent attribute",	"s1=x",		"s0-=a",	"s1=x" },
		{ "-= no matching value",	"s0=a",		"s0-=b",	"s0=a" },
		{ "-= matching value",		"s0=a",		"s0-=a",	"" },
		{ "-= all matching values",	"s0=a s0=b s0=a", "s0-=a",	"s0=b" },
		{ "-= keeps others",		"s1=x s0=a i0=1", "s0-=a",	"s1=x i0=1" },
		{ "-= integer",			"i0=1 i0=2",	"i0-=2",	"i0=1" },
		{ "-= twice",			"s0=a s0=b s0=c", "s0-=a s0-=c", "s0=b" },
	};

	pairmove_run_cases(cases, NUM_ELEMENTS(cases));
}

/*
 *	The '!*' operator deletes every instance of the attribute from the
 *	`to` list, regardless of the value.
 */
static void test_op_cmp_false(void)
{
	static pairmove_case_t const cases[] = {
		{ "!* from empty",		"",		"s0!*",		"" },
		{ "!* absent attribute",	"s1=x",		"s0!*",		"s1=x" },
		{ "!* one instance",		"s0=a",		"s0!*",		"" },
		{ "!* all instances",		"s0=a s1=b s0=c", "s0!*",	"s1=b" },
		{ "!* integer",			"i0=1 i0=2",	"i0!*",		"" },
	};

	pairmove_run_cases(cases, NUM_ELEMENTS(cases));
}

/*
 *	The '==' operator deletes every instance of the attribute that does
 *	not have the value of the `from` pair.  The operator keeps every
 *	instance that has the value, and does not add the attribute.
 */
static void test_op_cmp_eq(void)
{
	static pairmove_case_t const cases[] = {
		{ "== from empty",		"",		"s0==a",	"" },
		{ "== absent attribute",	"s1=x",		"s0==a",	"s1=x" },
		{ "== matching value",		"s0=a",		"s0==a",	"s0=a" },
		{ "== no matching value",	"s0=a",		"s0==b",	"" },
		{ "== some matching",		"s0=a s0=b s0=a", "s0==a",	"s0=a s0=a" },
		{ "== keeps others",		"s1=x s0=b",	"s0==a",	"s1=x" },
	};

	pairmove_run_cases(cases, NUM_ELEMENTS(cases));
}

/*
 *	The '<=' operator replaces the first instance of the attribute that
 *	has a value greater than the value of the `from` pair.
 *	The '>=' operator replaces the first instance of the attribute that
 *	has a value less than the value of the `from` pair.
 */
static void test_op_le_ge(void)
{
	static pairmove_case_t const cases[] = {
		{ "<= larger value",		"i0=10",	"i0<=5",	"i0=5" },

		/*
		 *	When the existing value already satisfies the operator, the merge
		 *	keeps the existing value and does not add the value from the `from`
		 *	list.
		 */
		{ "<= equal value",		"i0=5",		"i0<=5",	"i0=5" },
		{ "<= smaller value",		"i0=3",		"i0<=5",	"i0=3" },
		{ "<= absent attribute",	"i1=1",		"i0<=5",	"i1=1 i0=5" },
		{ "<= into empty",		"",		"i0<=5",	"i0=5" },
		{ "<= replaces in place",	"i1=1 i0=10 s0=a", "i0<=5",	"i1=1 i0=5 s0=a" },
		{ "<= all instances",		"i0=10 i0=20",	"i0<=5",	"i0=5 i0=20" },

		{ ">= smaller value",		"i0=3",		"i0>=5",	"i0=5" },
		{ ">= equal value",		"i0=5",		"i0>=5",	"i0=5" },
		{ ">= larger value",		"i0=9",		"i0>=5",	"i0=9" },
		{ ">= absent attribute",	"i1=1",		"i0>=5",	"i1=1 i0=5" },
		{ ">= into empty",		"",		"i0>=5",	"i0=5" },
		{ ">= replaces in place",	"i1=1 i0=3 s0=a", "i0>=5",	"i1=1 i0=5 s0=a" },
	};

	pairmove_run_cases(cases, NUM_ELEMENTS(cases));
}

/*
 *	The '<=' and '>=' operators with prefixes.
 *
 *	`radius_pairmove()` compares the values with the '==' operator, and
 *	prefixes only compare as equal or not equal.  There is no ordering, so
 *	'<=' never replaces a prefix, and '>=' replaces a prefix whenever the
 *	prefixes are different.  This is true even when one prefix contains
 *	the other.
 */
static void test_op_le_ge_prefix(void)
{
	static pairmove_case_t const cases[] = {
		/*
		 *	IPv4.
		 */
		{ "<= ipv4 prefix, inside",	"p4=10.0.0.0/8", "p4<=10.1.0.0/16",	"p4=10.0.0.0/8" },
		{ "<= ipv4 prefix, equal",	"p4=10.0.0.0/8", "p4<=10.0.0.0/8",	"p4=10.0.0.0/8" },
		{ "<= ipv4 prefix, contains",	"p4=10.0.0.0/8", "p4<=0.0.0.0/0",	"p4=10.0.0.0/8" },
		{ "<= ipv4 prefix, disjoint",	"p4=10.0.0.0/8", "p4<=192.168.0.0/16",	"p4=10.0.0.0/8" },
		{ ">= ipv4 prefix, inside",	"p4=10.0.0.0/8", "p4>=10.1.0.0/16",	"p4=10.1.0.0/16" },
		{ ">= ipv4 prefix, equal",	"p4=10.0.0.0/8", "p4>=10.0.0.0/8",	"p4=10.0.0.0/8" },
		{ ">= ipv4 prefix, contains",	"p4=10.0.0.0/8", "p4>=0.0.0.0/0",	"p4=0.0.0.0/0" },
		{ ">= ipv4 prefix, disjoint",	"p4=10.0.0.0/8", "p4>=192.168.0.0/16",	"p4=192.168.0.0/16" },

		/*
		 *	IPv6.
		 */
		{ "<= ipv6 prefix, inside",	"p6=2001:db8::/32", "p6<=2001:db8:1::/48",	"p6=2001:db8::/32" },
		{ "<= ipv6 prefix, equal",	"p6=2001:db8::/32", "p6<=2001:db8::/32",	"p6=2001:db8::/32" },
		{ "<= ipv6 prefix, contains",	"p6=2001:db8::/32", "p6<=::/0",			"p6=2001:db8::/32" },
		{ "<= ipv6 prefix, disjoint",	"p6=2001:db8::/32", "p6<=fe80::/10",		"p6=2001:db8::/32" },
		{ ">= ipv6 prefix, inside",	"p6=2001:db8::/32", "p6>=2001:db8:1::/48",	"p6=2001:db8:1::/48" },
		{ ">= ipv6 prefix, equal",	"p6=2001:db8::/32", "p6>=2001:db8::/32",	"p6=2001:db8::/32" },
		{ ">= ipv6 prefix, contains",	"p6=2001:db8::/32", "p6>=::/0",			"p6=::/0" },
		{ ">= ipv6 prefix, disjoint",	"p6=2001:db8::/32", "p6>=fe80::/10",		"p6=fe80::/10" },

		/*
		 *	No existing prefix, so the pair is added.
		 */
		{ "<= prefix, absent",		"",		"p4<=10.0.0.0/8",	"p4=10.0.0.0/8" },
		{ ">= prefix, absent",		"",		"p6>=2001:db8::/32",	"p6=2001:db8::/32" },
	};

	pairmove_run_cases(cases, NUM_ELEMENTS(cases));
}

/*
 *	The operators apply to the original `to` list only.  The operators do
 *	not apply to attributes that the same `radius_pairmove()` call adds.
 */
static void test_original_list_only(void)
{
	static pairmove_case_t const cases[] = {
		{ "+= then :=",			"s0=a",		"s0+=x s0:=y",	"s0=y s0=x" },
		{ "+= then -=",			"s0=a",		"s0+=a s0-=a",	"s0=a" },
		{ "+= then !*",			"s0=a",		"s0+=b s0!*",	"s0=b" },
		{ ":= then -=",			"s0=a",		"s0:=b s0-=b",	"s0=b" },
		{ "^= then !*",			"s0=a",		"s0^=b s0!*",	"s0=b" },
	};

	pairmove_run_cases(cases, NUM_ELEMENTS(cases));
}

/*
 *	The '=' operator looks for an instance of the attribute in the `to`
 *	list as the earlier pairs of the `from` list have left it.  An
 *	instance which an earlier pair replaced, or deleted, does not count.
 *	An instance which no earlier pair touched does count.
 */
static void test_op_eq_after_edit(void)
{
	static pairmove_case_t const cases[] = {
		{ ":= then =",			"s0=a",		"s0:=b s0=c",	"s0=b s0=c" },
		{ "-= then =",			"s0=a",		"s0-=a s0=b",	"s0=b" },
		{ "!* then =",			"s0=a s0=x",	"s0!* s0=b",	"s0=b" },
		{ "<= then =",			"i0=10",	"i0<=5 i0=7",	"i0=5 i0=7" },
		{ ">= then =",			"i0=1",		"i0>=5 i0=7",	"i0=5 i0=7" },

		/*
		 *	The second instance was not touched, so '=' finds it.
		 */
		{ ":= then =, two instances",	"s0=a s0=x",	"s0:=b s0=c",	"s0=b s0=x" },
		{ "-= then =, two instances",	"s0=a s0=x",	"s0-=a s0=c",	"s0=x" },

		/*
		 *	An edit of another attribute has no effect.
		 */
		{ "other attribute then =",	"s0=a s1=x",	"s1:=y s0=c",	"s0=a s1=y" },
	};

	pairmove_run_cases(cases, NUM_ELEMENTS(cases));
}

/*
 *	A pair which `radius_pairmove()` moves out of the `from` list must not
 *	keep its `next` pointer.  In each case below, a pair which stays in the
 *	result is followed in the `from` list by a pair which is freed, replaces
 *	an existing pair, or goes to the start of the list.  If the first pair
 *	keeps the pointer to the second one, then the result has extra entries
 *	at the end, or it ends in a pair which has been freed.
 */
static void test_stale_next(void)
{
	static pairmove_case_t const cases[] = {
		/*
		 *	The pair which follows is freed.
		 */
		{ "+= then -=",			"s0=a",		"s1+=x s0-=a",	"s1=x" },
		{ "+= then !*",			"s0=a s1=b",	"i0+=1 s0!*",	"s1=b i0=1" },
		{ "+= then == (no match)",	"s0=a",		"s1+=x s0==b",	"s1=x" },
		{ "+= then = (present)",	"s0=a",		"s1+=x s0=b",	"s0=a s1=x" },
		{ "+= then <= (kept)",		"i0=3",		"s1+=x i0<=5",	"i0=3 s1=x" },
		{ "+= then >= (kept)",		"i0=9",		"s1+=x i0>=5",	"i0=9 s1=x" },
		{ "+= then two freed",		"s0=a s2=c",	"s1+=x s0-=a s2!*", "s1=x" },
		{ "two += then freed",		"s0=a",		"s1+=x s2+=y s0-=a", "s1=x s2=y" },

		/*
		 *	The pair which follows replaces an existing pair.
		 */
		{ "+= then :=",			"s0=a",		"s1+=x s0:=y",	"s0=y s1=x" },
		{ "+= then <= (replaced)",	"i0=10",	"s1+=x i0<=5",	"i0=5 s1=x" },
		{ "+= then >= (replaced)",	"i0=1",		"s1+=x i0>=5",	"i0=5 s1=x" },

		/*
		 *	The pair which follows goes to the start of the list.
		 */
		{ "+= then ^=",			"s0=a",		"s1+=x s2^=y",	"s2=y s0=a s1=x" },
		{ "^= then -=",			"s0=a s2=z",	"s1^=x s0-=a",	"s1=x s2=z" },

		/*
		 *	The replacing pair is followed by a pair which is freed.
		 */
		{ ":= then -=",			"s0=a s2=z",	"s0:=b s1-=q",	"s0=b s2=z" },
		{ ":= then !*",			"s0=a s2=z",	"s0:=b s2!*",	"s0=b" },

		/*
		 *	A pair which is added is followed by one which is added.
		 */
		{ "= then +=",			"",		"s0=a s1+=b",	"s0=a s1=b" },
		{ ":= (absent) then -=",	"",		"s0:=a s1-=b",	"s0=a" },
	};

	pairmove_run_cases(cases, NUM_ELEMENTS(cases));
}

/*
 *	These cases use several operators and several attributes in one call
 *	to `radius_pairmove()`.
 */
static void test_mixed(void)
{
	static pairmove_case_t const cases[] = {
		{ "all operators",
		  "s0=a s1=b s2=c i0=1 i1=2",
		  "s0:=A s1-=b s2!* i0<=0 i1+=3 un=bob",
		  "s0=A i0=0 i1=2 i1=3 un=bob" },
		{ "different attributes",
		  "s0=a i0=1",
		  "s1=b i1=2 s2=c",
		  "s0=a i0=1 s1=b i1=2 s2=c" },
		{ "prepend, replace, append",
		  "s0=a s1=b",
		  "i0^=1 s1:=B i1+=2",
		  "i0=1 s0=a s1=B i1=2" },
	};

	pairmove_run_cases(cases, NUM_ELEMENTS(cases));
}

/** Merge lists of up to 100 pairs
 *
 * This test checks the sizes of the temporary arrays that
 * `radius_pairmove()` allocates.  The lengths of the `to` list and the
 * `from` list are 1 and 100, 100 and 1, 100 and 100, 0 and 100, and 100
 * and 0.
 */
static void test_long_lists(void)
{
	static struct {
		size_t	to_num;
		size_t	from_num;
	} const sizes[] = { { 1, 100 }, { 100, 1 }, { 100, 100 }, { 0, 100 }, { 100, 0 } };

	size_t		i, j;
	list_target_t	target;

	for (i = 0; i < NUM_ELEMENTS(sizes); i++) {
		for (target = 0; target < LIST_NUM; target++) {
			REQUEST		*request;
			TALLOC_CTX	*ctx;
			VALUE_PAIR	**to;
			VALUE_PAIR	*from = NULL, *vp;
			size_t		before;

			request = request_make(autofree);
			to = list_target(&ctx, request, target);
			before = talloc_total_blocks(request);

			for (j = 0; j < sizes[i].to_num; j++) {
				vp = fr_pair_make(ctx, to, "Tmp-String-0", "to", T_OP_EQ);
				TEST_ASSERT(vp != NULL);
			}

			for (j = 0; j < sizes[i].from_num; j++) {
				vp = fr_pair_make(ctx, &from, "Tmp-String-1", "from", T_OP_ADD);
				TEST_ASSERT(vp != NULL);
			}

			/*
			 *	Do not pass a NULL `from` list to `radius_pairmove()`.  `from` is
			 *	NULL when `from_num` is zero.
			 */
			if (from) radius_pairmove(request, to, from, false);

			TEST_CASE_("long lists %zu and %zu: %s", sizes[i].to_num, sizes[i].from_num,
				   list_target_names[target]);
			TEST_CHECK(list_len(*to) == (sizes[i].to_num + sizes[i].from_num));
			TEST_MSG("Expected length : %zu", sizes[i].to_num + sizes[i].from_num);
			TEST_MSG("Got length      : %zu", list_len(*to));

			/*
			 *	The `to` attributes come first, then the `from` attributes.
			 */
			for (j = 0, vp = *to; vp; j++, vp = vp->next) {
				TEST_CHECK(vp->da == dict_attrbyname((j < sizes[i].to_num) ?
								     "Tmp-String-0" : "Tmp-String-1"));
			}

			fr_pair_list_free(to);
			TEST_CHECK(talloc_total_blocks(request) == before);

			talloc_free(request);
		}
	}
}

/*
 *	When `radius_pairmove()` changes the packet list of a request,
 *	`radius_pairmove()` must update `request->username` and
 *	`request->password`.
 */
static void test_username_password(void)
{
	REQUEST		*request;
	VALUE_PAIR	*from, *vp;

	TEST_CASE("username and password: packet list");
	request = request_make(autofree);

	request->packet->vps = list_alloc(request->packet, "un=bob up=hello s0=a");
	request->username = request->packet->vps;
	request->password = request->packet->vps->next;

	from = list_alloc(request->packet, "un:=alice up:=secret");
	radius_pairmove(request, &request->packet->vps, from, false);

	TEST_CHECK_STRCMP(list_str(request->packet->vps), "un=alice up=secret s0=a");

	TEST_ASSERT(request->username != NULL);
	TEST_CHECK(request->username->da->attr == PW_USER_NAME);
	TEST_CHECK_STRCMP(request->username->vp_strvalue, "alice");

	TEST_ASSERT(request->password != NULL);
	TEST_CHECK(request->password->da->attr == PW_USER_PASSWORD);
	TEST_CHECK_STRCMP(request->password->vp_strvalue, "secret");

	/*
	 *	`request->username` and `request->password` must point at pairs in the
	 *	packet list, and must not point at freed pairs.
	 */
	for (vp = request->packet->vps; vp; vp = vp->next) if (vp == request->username) break;
	TEST_CHECK(vp != NULL);

	for (vp = request->packet->vps; vp; vp = vp->next) if (vp == request->password) break;
	TEST_CHECK(vp != NULL);

	TEST_CASE("username and password: deleted");
	from = list_alloc(request->packet, "un!* up!*");
	radius_pairmove(request, &request->packet->vps, from, false);

	TEST_CHECK_STRCMP(list_str(request->packet->vps), "s0=a");
	TEST_CHECK(request->username == NULL);
	TEST_CHECK(request->password == NULL);

	TEST_CASE("username and password: added");
	from = list_alloc(request->packet, "un=carol up=pw");
	radius_pairmove(request, &request->packet->vps, from, false);

	TEST_CHECK_STRCMP(list_str(request->packet->vps), "s0=a un=carol up=pw");
	TEST_ASSERT(request->username != NULL);
	TEST_CHECK_STRCMP(request->username->vp_strvalue, "carol");
	TEST_ASSERT(request->password != NULL);
	TEST_CHECK_STRCMP(request->password->vp_strvalue, "pw");

	fr_pair_list_free(&request->packet->vps);
	talloc_free(request);
}

/*
 *	Because the reply list and the config list do not have cached pointers
 *	to the username and password, a merge into either list does not change
 *	`request->username` or `request->password`.
 */
static void test_username_password_other_lists(void)
{
	REQUEST		*request;
	VALUE_PAIR	*from;

	TEST_CASE("username and password: other lists");
	request = request_make(autofree);

	request->packet->vps = list_alloc(request->packet, "un=bob up=hello");
	request->username = request->packet->vps;
	request->password = request->packet->vps->next;

	from = list_alloc(request->reply, "un=alice");
	radius_pairmove(request, &request->reply->vps, from, false);

	from = list_alloc(request, "un=alice");
	radius_pairmove(request, &request->config, from, false);

	TEST_CHECK(request->username == request->packet->vps);
	TEST_CHECK(request->password == request->packet->vps->next);

	fr_pair_list_free(&request->packet->vps);
	fr_pair_list_free(&request->reply->vps);
	fr_pair_list_free(&request->config);
	talloc_free(request);
}

/*
 *	When a child request changes the packet list of the parent request,
 *	`radius_pairmove()` must update the `username` and `password` pointers
 *	of the parent request, and must not update the `username` and
 *	`password` pointers of the child request.
 */
static void test_username_password_parent(void)
{
	REQUEST		*parent, *child;
	VALUE_PAIR	*from;

	TEST_CASE("username and password: parent request");
	parent = request_make(autofree);
	child = request_make(autofree);
	child->parent = parent;

	parent->packet->vps = list_alloc(parent->packet, "un=bob up=hello");
	parent->username = parent->packet->vps;
	parent->password = parent->packet->vps->next;

	child->packet->vps = list_alloc(child->packet, "un=child");
	child->username = child->packet->vps;

	from = list_alloc(parent->packet, "un:=alice up:=secret");
	radius_pairmove(child, &parent->packet->vps, from, false);

	TEST_CHECK_STRCMP(list_str(parent->packet->vps), "un=alice up=secret");

	TEST_ASSERT(parent->username != NULL);
	TEST_CHECK_STRCMP(parent->username->vp_strvalue, "alice");
	TEST_ASSERT(parent->password != NULL);
	TEST_CHECK_STRCMP(parent->password->vp_strvalue, "secret");

	TEST_CHECK(child->username == child->packet->vps);
	TEST_CHECK_STRCMP(child->username->vp_strvalue, "child");

	fr_pair_list_free(&parent->packet->vps);
	fr_pair_list_free(&child->packet->vps);
	child->parent = NULL;
	talloc_free(child);
	talloc_free(parent);
}

/*
 *	This test checks which talloc context owns the pairs of the `to` list
 *	after the merge.
 *
 *	`radius_pairmove()` rebuilds the `to` list from copies, and allocates
 *	the copies in the talloc parent of the first pair of the `to` list.
 *	The pairs of the `from` list stay in the talloc context where they were
 *	allocated.  Because of that, freeing the packet, the reply, or the
 *	request frees every pair.
 */
static void test_ownership(void)
{
	REQUEST		*request;
	VALUE_PAIR	*from, *vp;

	TEST_CASE("pairs are owned by the list context");
	request = request_make(autofree);

	request->packet->vps = list_alloc(request->packet, "s0=a s1=b");
	from = list_alloc(request->packet, "s0:=c i0+=1");
	radius_pairmove(request, &request->packet->vps, from, false);

	TEST_CHECK_STRCMP(list_str(request->packet->vps), "s0=c s1=b i0=1");

	for (vp = request->packet->vps; vp; vp = vp->next) {
		TEST_CHECK(talloc_parent(vp) == request->packet);
		TEST_MSG("Attribute %s has the wrong parent", vp->da->name);
	}

	/*
	 *	Freeing the packet frees the pairs.
	 */
	talloc_free(request->packet);
	request->packet = NULL;
	talloc_free(request);
}

TEST_LIST = {
	{ "op_eq",				test_op_eq },
	{ "op_set",				test_op_set },
	{ "op_add",				test_op_add },
	{ "op_prepend",				test_op_prepend },
	{ "op_sub",				test_op_sub },
	{ "op_cmp_false",			test_op_cmp_false },
	{ "op_cmp_eq",				test_op_cmp_eq },
	{ "op_le_ge",				test_op_le_ge },
	{ "op_le_ge_prefix",			test_op_le_ge_prefix },
	{ "original_list_only",			test_original_list_only },
	{ "op_eq_after_edit",			test_op_eq_after_edit },
	{ "stale_next",				test_stale_next },
	{ "mixed",				test_mixed },
	{ "long_lists",				test_long_lists },
	{ "username_password",			test_username_password },
	{ "username_password_other_lists",	test_username_password_other_lists },
	{ "username_password_parent",		test_username_password_parent },
	{ "ownership",				test_ownership },

	{ NULL, NULL }
};
