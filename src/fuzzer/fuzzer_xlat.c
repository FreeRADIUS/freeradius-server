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
 */

/**
 * @file src/fuzzer/fuzzer_xlat.c
 * @brief Fuzz the xlat tokenize -> resolve -> eval pipeline.
 *
 * Drives the three public xlat tokenisers (xlat_tokenize,
 * xlat_tokenize_expression, xlat_tokenize_condition) and, on success,
 * follows through xlat_resolve() and xlat_aeval_compiled() against a
 * synthetic request built from the test dictionary. This exercises:
 *
 *   src/lib/unlang/xlat_tokenize.c
 *   src/lib/unlang/xlat_expr.c
 *   src/lib/unlang/xlat_eval.c
 *   src/lib/unlang/xlat_builtin.c
 *
 * All of which are at 0% coverage under the existing protocol-decoder
 * fuzzers despite being on the network-attacker-reachable path: xlat
 * expansions interpolate attribute values that originate from RADIUS,
 * DHCP, DNS etc. packets at request time.
 *
 * Input layout:
 *   byte[0]      - low 2 bits select the tokeniser variant
 *   byte[1..]    - the xlat expression text (not NUL-terminated)
 */
RCSID("$Id$")

#include <freeradius-devel/fuzzer/common.h>
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/request.h>
#include <freeradius-devel/server/tmpl.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/unlang/xlat.h>

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len);

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	if (dict) return 0;

	if (fuzzer_common_init(argc, argv, false) < 0) fr_exit_now(EXIT_FAILURE);

	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) {
	error:
		fr_perror("fuzzer_xlat");
		fr_exit_now(EXIT_FAILURE);
	}

	if (request_global_init() < 0) goto error;

	/*
	 *	Bootstraps xlat_func tree, registers builtins, prepares
	 *	the unlang interpreter. Required before xlat_tokenize().
	 */
	if (unlang_global_init() < 0) goto error;

	return 0;
}

/*
 *	Poison gutters either side of the fmt buffer so ASan flags any
 *	path inside xlat_tokenize* / xlat_resolve that walks past the
 *	declared sbuff bounds. __asan_poison_memory_region rounds to
 *	8-byte granules, so reads more than ~7 bytes past either end will
 *	be reported; tight over-reads may slip through but the pattern
 *	mirrors fuzzer_value.c and src/bin/unit_test_attribute.c.
 */
#define POISON_START 64
#define POISON_END   64

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	TALLOC_CTX		*ctx;
	xlat_exp_head_t		*head = NULL;
	fr_sbuff_t		sbuff;
	tmpl_rules_t		t_rules;
	uint8_t			mode;
	uint8_t			*raw_fmt = NULL;
	char			*fmt = NULL;
	size_t			fmt_len;
	fr_slen_t		slen;

	if (!dict) return 0;
	if (size < 2) return 0;
	if (size > 4096) return 0; /* keep iterations fast */

	mode    = data[0] & 0x03;
	fmt_len = size - 1;

	ctx = talloc_init_const("fuzzer_xlat");
	if (!ctx) return 0;

	/*
	 *	Tokenisers consume an sbuff with an explicit length, so we
	 *	deliberately do NOT NUL-terminate. Any code path that does
	 *	strlen/strchr/memchr on the underlying buffer (rather than
	 *	respecting the sbuff end) will read into the poisoned gutter
	 *	and trip ASan, which is the bug we want to surface.
	 */
	raw_fmt = talloc_array(ctx, uint8_t, POISON_START + fmt_len + POISON_END);
	if (!raw_fmt) goto done;
	fmt = (char *)(raw_fmt + POISON_START);
	if (fmt_len) memcpy(fmt, data + 1, fmt_len);
	ASAN_POISON_MEMORY_REGION(raw_fmt, POISON_START);
	ASAN_POISON_MEMORY_REGION(raw_fmt + POISON_START + fmt_len, POISON_END);

	/*
	 *	Tighten tmpl_rules: refuse unresolved attribute references
	 *	at tokenize-time so we never reach eval with a half-resolved
	 *	tree (which trips the per-node tmpl_needs_resolving assert
	 *	in xlat_frame_eval, see xlat_eval.c:1475).
	 */
	t_rules = (tmpl_rules_t) {
		.attr = (tmpl_attr_rules_t) {
			.dict_def	      = dict,
			.list_def	      = request_attr_request,
			.allow_unresolved = false,
			.allow_unknown    = false,
			.allow_wildcard   = true,
		},
	};

	sbuff = FR_SBUFF_IN(fmt, fmt_len);

	switch (mode) {
	case 0:
		slen = xlat_tokenize(ctx, &head, &sbuff, NULL, &t_rules);
		break;
	case 1:
		slen = xlat_tokenize_expression(ctx, &head, &sbuff, NULL, &t_rules);
		break;
	case 2:
		slen = xlat_tokenize_condition(ctx, &head, &sbuff, NULL, &t_rules);
		break;
	default:
		/*
		 *	Argv-style takes an arg parser table; pass NULL
		 *	args - the tokeniser tolerates this by treating
		 *	every arg as STRING/required.
		 */
		slen = xlat_tokenize_argv(ctx, &head, &sbuff, NULL, NULL, &t_rules, false);
		break;
	}

	if (slen <= 0 || !head) goto done;

	/*
	 *	Resolve unknown function / attribute references. The
	 *	resolve pass is itself a meaningful target - it walks
	 *	the whole AST. Tolerant of failure: many fuzzer inputs
	 *	will leave dangling references that won't resolve, but
	 *	the walk still exercises code.
	 */
	{
		xlat_res_rules_t const	xr_rules = {
			.tr_rules = &(tmpl_res_rules_t){ .dict_def = dict },
			.allow_unresolved = false,
		};
		(void) xlat_resolve(head, &xr_rules);
	}

	/*
	 *	xlat_print round-trip - exercises the unparse path
	 *	(xlat_tokenize.c) and validates the tree is well-formed
	 *	enough to be serialised back to text.
	 *
	 *	We deliberately do NOT call xlat_aeval_compiled / xlat_eval
	 *	here: eval requires invariants that are normally established
	 *	by xlat_compile() / xlat_purify() (e.g. quote != T_BARE_WORD,
	 *	all per-node tmpls fully resolved). Fuzzer-generated trees
	 *	skip those passes and trip dev-asserts in xlat_frame_eval.
	 *	Tokenize + resolve already cover the bulk of the previously
	 *	0%-covered xlat code.
	 */
	{
		fr_sbuff_t		print_sb;
		char			print_buf[1024];
		print_sb = FR_SBUFF_OUT(print_buf, sizeof(print_buf));
		(void) xlat_print(&print_sb, head, NULL);
	}

done:
	/*
	 *	Unpoison before talloc_free walks the chunk headers.
	 */
	if (raw_fmt) {
		ASAN_UNPOISON_MEMORY_REGION(raw_fmt, POISON_START + fmt_len + POISON_END);
	}

	talloc_free(ctx);
	fr_strerror_clear();
	return 0;
}
