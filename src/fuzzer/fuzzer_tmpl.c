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
 * @file src/fuzzer/fuzzer_tmpl.c
 * @brief Fuzz the tmpl tokenize -> resolve pipeline.
 *
 * Drives the two public tmpl parsers:
 *
 *   tmpl_afrom_substr()      - the general parser, dispatches by quote.
 *                              Reads from an fr_sbuff_t with explicit length,
 *                              i.e. the input is NOT required to be
 *                              NUL-terminated.  Network-attacker-reachable
 *                              via every place a config string or xlat
 *                              operand is turned into a tmpl.
 *
 *   tmpl_afrom_attr_str()    - the attribute-only convenience wrapper.
 *                              Takes a NUL-terminated C string.  Used by
 *                              callers that already have a flat name
 *                              (e.g. legacy callers, some unit tests).
 *
 *  The APIs are called based on mode (see below), and then
 *  tmpl_resolve() and tmpl_print() are called to fully exercise the
 *  tmpl code.
 *
 * Input layout:
 *   byte[0]      - mode selector, used mod the number of variants.
 *   byte[1..]    - the tmpl text.  For tmpl_afrom_substr() the bytes are
 *                  used verbatim and NOT NUL-terminated; for
 *                  tmpl_afrom_attr_str() they are copied into a separate
 *                  NUL-terminated scratch buffer first (the function's
 *                  contract requires that).
 */
RCSID("$Id$")

#include <freeradius-devel/fuzzer/common.h>
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/tmpl.h>
#include <freeradius-devel/unlang/base.h>

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len);

static tmpl_res_rules_t tr_rules;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	if (dict) return 0;

	if (fuzzer_common_init(argc, argv, false) < 0) fr_exit_now(EXIT_FAILURE);

	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) {
	error:
		fr_perror("fuzzer_tmpl");
		fr_exit_now(EXIT_FAILURE);
	}

	tr_rules = (tmpl_res_rules_t) { .dict_def = dict };

	/*
	 *	tmpl_global_init() sets up tmpl_attr_unspec which the
	 *	[<filter>]-only path of tmpl_attr_afrom_attr_substr()
	 *	dereferences unconditionally - without it, an input like
	 *	"[0]" SIGSEGVs on a NULL ar_da.  See tmpl_eval.c:1378.
	 */
	if (tmpl_global_init() < 0) goto error;

	/*
	 *	request_attr_request and friends are read out of the
	 *	tmpl_rules .list_def below, so request_global_init() has to
	 *	have populated them before we tokenise anything.
	 */
	if (request_global_init() < 0) goto error;

	/*
	 *	Pull in the xlat infrastructure too: tmpl_afrom_substr()
	 *	hands a TMPL_TYPE_XLAT subtree off to xlat_tokenize_*, and
	 *	xlat_tmpl_normalize() is called from inside that path.
	 *	Without unlang_global_init() the xlat function tree is
	 *	empty and every "%foo(...)" tail-call short-circuits to
	 *	"unknown function" before reaching the parser surface we
	 *	want to fuzz.
	 */
	if (unlang_global_init() < 0) goto error;

	return 0;
}

/*
 *	Use the same poison scheme as fuzzer_xlat.c: ASan poisons
 *	either side of the live fmt region so any code path that walks
 *	past the declared sbuff bounds (instead of respecting the
 *	explicit length) trips a report.  fr_sbuff lengths are honest,
 *	but a bug in one of the dispatched parsers -
 *	tmpl_request_ref_list_from_substr, the OID branch in
 *	tmpl_attr_afrom_attr_substr, etc. - that does strlen() or
 *	memchr() over the underlying buffer will get caught here.
 */
#define POISON_START 64
#define POISON_END   64

/*
 *	The four tmpl_afrom_substr() quote variants, plus
 *	tmpl_afrom_attr_str().  Keep these contiguous so that a single
 *	mode selects between them.
 */
#define MODE_SUBSTR_BARE	0
#define MODE_SUBSTR_DOUBLE	1
#define MODE_SUBSTR_SINGLE	2
#define MODE_SUBSTR_BACK	3
#define MODE_ATTR_STR		4
#define MODE_COUNT		5

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	TALLOC_CTX		*ctx;
	tmpl_t			*vpt = NULL;
	tmpl_rules_t		t_rules;
	tmpl_attr_error_t	attr_err = TMPL_ATTR_ERROR_NONE;
	uint8_t			mode;
	uint8_t			*raw_fmt = NULL;
	char			*fmt = NULL;
	size_t			fmt_len;
	fr_slen_t		slen = -1;

	if (!dict) return 0;
	if (size < 2) return 0;
	if (size > 4096) return 0;	/* keep iterations fast */

	mode    = data[0] % MODE_COUNT;
	fmt_len = size - 1;

	ctx = talloc_init_const("fuzzer_tmpl");
	if (!ctx) return 0;

	/*
	 *	Tokenisers consume an sbuff with an explicit length, so we
	 *	deliberately do NOT NUL-terminate. Any code path that does
	 *	strlen/strchr/memchr on the underlying buffer (rather than
	 *	respecting the sbuff end) will read into the poisoned gutter
	 *	and trip ASan, which is the bug we want to surface.
	 *
	 *	We allocate an extra byte to NUL terminate the input
	 *	for functions which need that.
	 */
	raw_fmt = talloc_array(ctx, uint8_t, POISON_START + fmt_len + 1 + POISON_END);
	if (!raw_fmt) goto done;
	fmt = (char *)(raw_fmt + POISON_START);
	if (fmt_len) memcpy(fmt, data + 1, fmt_len);
	fmt[fmt_len] = '\0';	/* always present, _str needs it, substr ignores it */

	ASAN_POISON_MEMORY_REGION(raw_fmt, POISON_START);
	ASAN_POISON_MEMORY_REGION(raw_fmt + POISON_START + fmt_len + 1, POISON_END);

	/*
	 *	Tighten tmpl_rules: refuse unresolved attribute references
	 *	at tokenize-time so we never reach eval with a half-resolved
	 *	tree (which trips the per-node tmpl_needs_resolving assert
	 *	in xlat_frame_eval, see xlat_eval.c:1475).
	 */
	t_rules = (tmpl_rules_t) {
		.attr = (tmpl_attr_rules_t) {
			.dict_def	  = dict,
			.list_def	  = request_attr_request,
			.allow_unresolved = false,
			.allow_unknown    = false,
			.allow_wildcard   = true,
		},
	};

	switch (mode) {
	case MODE_SUBSTR_BARE:
	case MODE_SUBSTR_DOUBLE:
	case MODE_SUBSTR_SINGLE:
	case MODE_SUBSTR_BACK:
	{
		fr_token_t	quote;
		fr_sbuff_t	sbuff;

		switch (mode) {
		default:
		case MODE_SUBSTR_BARE:
			quote = T_BARE_WORD;
			break;

		case MODE_SUBSTR_DOUBLE:
			quote = T_DOUBLE_QUOTED_STRING;
			break;

		case MODE_SUBSTR_SINGLE:
			quote = T_SINGLE_QUOTED_STRING;
			break;

		case MODE_SUBSTR_BACK:
			quote = T_BACK_QUOTED_STRING;
			break;
		}

		sbuff = FR_SBUFF_IN(fmt, fmt_len);
		slen = tmpl_afrom_substr(ctx, &vpt, &sbuff, quote, NULL, &t_rules);
		break;
	}

	case MODE_ATTR_STR:
		/*
		 *	The _str signature takes a length too, but its body
		 *	uses strlen() internally for the substr it builds.
		 *	Pass fmt_len so the explicit-length API stays
		 *	honest, but the NUL we wrote at fmt[fmt_len] is what
		 *	the function actually relies on.
		 */
		slen = tmpl_afrom_attr_str(ctx, &attr_err, &vpt, fmt, &t_rules);
		break;
	}

	if (slen <= 0 || !vpt) goto done;

	/*
	 *	Resolve walks the whole tmpl AST: request refs, attr
	 *	refs, nested xlats inside TMPL_TYPE_XLAT. Most fuzzer
	 *	inputs leave unresolved refs, but the resolution walk
	 *	still exercises the code.
	 */
	(void) tmpl_resolve(vpt, &tr_rules);

	/*
	 *	Write the tmpl out.  This check exercises every
	 *	per-type print branch in tmpl_tokenize.c (attr OID
	 *	rendering, request-ref prefixing, xlat unparse via
	 *	xlat_print, escape rules, etc.) and validates the tree
	 *	is well-formed enough to serialise back to text.
	 *
	 *	We deliberately do not chase further (tmpl_eval / map_proc)
	 *	for the same reason fuzzer_xlat doesn't: eval requires
	 *	invariants that only a full compile pass establishes, and
	 *	fuzzer-generated trees skip those.
	 */
	{
		fr_sbuff_t	print_sb;
		char		print_buf[1024];

		print_sb = FR_SBUFF_OUT(print_buf, sizeof(print_buf));
		(void) tmpl_print(&print_sb, vpt, NULL);
	}

done:
	if (raw_fmt) {
		ASAN_UNPOISON_MEMORY_REGION(raw_fmt, POISON_START + fmt_len + 1 + POISON_END);
	}

	talloc_free(ctx);
	fr_strerror_clear();
	return 0;
}
