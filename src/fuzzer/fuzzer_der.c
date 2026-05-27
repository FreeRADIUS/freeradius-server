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
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * @file src/fuzzer/fuzzer_der.c
 * @brief Fuzz the DER (ASN.1) decoder against an explicit list of root attributes.
 *
 * The DER decoder is unusual among FreeRADIUS protocol decoders in that
 * it cannot meaningfully run with the dictionary root as its starting
 * attribute - fr_der_decode_proto() explicitly rejects that. Each useful
 * DER decode begins at a top-level ASN.1 structure such as Certificate
 * (RFC 5280) or CertificationRequest (RFC 2986). This harness keeps an
 * explicit list of those roots and selects one per input so a single
 * binary exercises all DER entry points instead of being pinned to one
 * via the FR_FUZZER_ROOT_ATTR environment variable.
 *
 * Input layout:
 *   byte[0]      - selects which root attribute to decode against,
 *                  modulo the size of the root table
 *   byte[1..]    - DER-encoded payload passed to fr_der_decode_proto()
 */
RCSID("$Id$")

#include <freeradius-devel/fuzzer/common.h>

/*
 *	The set of DER root attributes this harness fuzzes against.
 *	These names must exist as top-level attributes (DEFINE) in the
 *	DER dictionary - share/dictionary/der/. Adding a new root here
 *	is sufficient to extend coverage; no other change is required.
 */
static char const *der_root_names[] = {
	"Certificate",			/* RFC 5280 - X.509 */
	"CertificateRequest",		/* RFC 2986 - PKCS#10 CSR */
};

#define NUM_DER_ROOTS (sizeof(der_root_names) / sizeof(der_root_names[0]))

static fr_dict_attr_t const	*der_roots[NUM_DER_ROOTS];

extern fr_test_point_proto_decode_t der_tp_decode_proto;

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len);

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	size_t i;
	fr_dict_t const *dict_der;

	if (fuzzer_common_init(argc, argv, true) < 0) fr_exit_now(EXIT_FAILURE);

	/*
	 *	The DER protocol dictionary is loaded by fuzzer_common_init()
	 *	via libfreeradius_der_dict_protocol's autoload table. The
	 *	global `dict` in common.c is the internal dictionary; the
	 *	per-protocol dict (which holds Certificate, CertificateRequest
	 *	etc.) must be looked up by protocol name.
	 */
	dict_der = fr_dict_by_protocol_name("der");
	if (!dict_der) {
		fr_perror("fuzzer_der: DER protocol dictionary is not loaded");
		fr_exit_now(EXIT_FAILURE);
	}

	/*
	 *	Resolve each root attribute once. A missing root is a
	 *	hard failure: it means the harness is out of sync with
	 *	the DER dictionary and the next time CI runs the fuzzer
	 *	would silently skip that path.
	 */
	for (i = 0; i < NUM_DER_ROOTS; i++) {
		der_roots[i] = fr_dict_attr_by_name(NULL, fr_dict_root(dict_der), der_root_names[i]);
		if (!der_roots[i]) {
			fr_perror("fuzzer_der: failed to find DER root attribute '%s'", der_root_names[i]);
			fr_exit_now(EXIT_FAILURE);
		}
	}

	return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
	TALLOC_CTX			*ctx;
	fr_pair_list_t			vps;
	void				*decode_ctx = NULL;
	fr_dict_attr_t const		*root;
	fr_test_point_proto_decode_t	*tp = &der_tp_decode_proto;

	if (!dict) LLVMFuzzerInitialize(NULL, NULL);

	/*
	 *	Need at least one selector byte plus one DER byte to
	 *	have a non-trivial payload.
	 */
	if (len < 2) return 0;

	root = der_roots[buf[0] % NUM_DER_ROOTS];
	buf++;
	len--;

	ctx = talloc_init_const("fuzzer_der");
	fr_pair_list_init(&vps);

	if (tp->test_ctx && (tp->test_ctx(&decode_ctx, NULL, dict, root) < 0)) {
		fr_perror("fuzzer_der: failed initializing decode_ctx");
		fr_exit_now(EXIT_FAILURE);
	}

	if (tp->func(ctx, &vps, buf, len, decode_ctx) > 0) {
		PAIR_LIST_VERIFY_WITH_CTX(ctx, &vps);
		if (fr_debug_lvl > 3) fr_pair_list_debug(stderr, &vps);
	}

	talloc_free(decode_ctx);
	talloc_free(ctx);

	/*
	 *	Drop accumulated strerror messages so libFuzzer's leak
	 *	heuristics don't see growing allocations.
	 */
	fr_strerror_clear();

	return 0;
}
