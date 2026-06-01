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
 * $Id$
 *
 * @file src/fuzzer/fuzzer_radius.c
 * @brief Fuzz RADIUS packet decoding and encoding (round-trip).
 *
 * This is a hand-written copy of the generic src/fuzzer/fuzzer.c with the
 * encode path enabled. It is NOT generated from fuzzer.c (see
 * FUZZER_PROTOCOL_CUSTOM_SRC in src/fuzzer/all.mk) so that the RADIUS
 * encoder can be exercised in addition to the decoder.
 *
 * The harness:
 *   1. decodes the fuzz bytes into a RADIUS pair list (decode.c);
 *   2. re-encodes that pair list (encode.c - VSA tail packing, tunnel /
 *      Ascend password encryption, long-extended attribute splitting,
 *      Message-Authenticator handling, signing);
 *   3. decodes the re-encoded packet again, as a sanity oracle that the
 *      encoder produced something the decoder accepts.
 *
 * encode.c is otherwise only reachable from a syntactically valid pair
 * list produced upstream of the network, so decoding a network-shaped
 * input first is the cleanest way to drive it. The decode/encode test
 * points supply their own protocol context (shared secret "testing123",
 * a fixed request authenticator); see encode_test_ctx() /
 * decode_test_ctx() in src/protocols/radius/.
 *
 * To add an encode round-trip fuzzer for another protocol, copy this file
 * to fuzzer_<proto>.c, replace "radius" with "<proto>", and add "<proto>"
 * to FUZZER_PROTOCOL_CUSTOM_SRC in src/fuzzer/all.mk.
 */
RCSID("$Id$")

#include <freeradius-devel/fuzzer/common.h>

/*
 *	Unlike the generic fuzzer.c (decode only), this protocol-specific
 *	harness drives the encoder too.
 */
static bool			do_encode = true;

extern fr_test_point_proto_decode_t radius_tp_decode_proto;
extern fr_test_point_proto_encode_t radius_tp_encode_proto;

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len);

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	if (fuzzer_common_init(argc, argv, true) < 0) fr_exit_now(EXIT_FAILURE);

	return 1;
}

static uint8_t encoded_data[65536];

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
	TALLOC_CTX *   ctx = talloc_init_const("fuzzer");
	fr_pair_list_t vps;
	void *decode_ctx = NULL;
	void *encode_ctx = NULL;
	fr_test_point_proto_decode_t *tp_decode = &radius_tp_decode_proto;
	fr_test_point_proto_encode_t *tp_encode = &radius_tp_encode_proto;

	fr_pair_list_init(&vps);
	if (!dict) LLVMFuzzerInitialize(NULL, NULL);

	if (tp_decode->test_ctx && (tp_decode->test_ctx(&decode_ctx, NULL, dict, root_da) < 0)) {
		fr_perror("fuzzer: Failed initializing test point decode_ctx");
		fr_exit_now(EXIT_FAILURE);
	}

	if (tp_encode->test_ctx && (tp_encode->test_ctx(&encode_ctx, NULL, dict, root_da) < 0)) {
		fr_perror("fuzzer: Failed initializing test point encode_ctx");
		fr_exit_now(EXIT_FAILURE);
	}

	if (fr_debug_lvl > 3) {
		FR_PROTO_TRACE("Fuzzer input");

		FR_PROTO_HEX_DUMP(buf, len, "");
	}

	/*
	 *	Decode the input, and print the resulting data if we
	 *	decoded it successfully.
	 *
	 *	If we have successfully decoded the data, then encode
	 *	it again, too.
	 */
	if (tp_decode->func(ctx, &vps, buf, len, decode_ctx) > 0) {
		PAIR_LIST_VERIFY_WITH_CTX(ctx, &vps);

		if (fr_debug_lvl > 3) fr_pair_list_debug(stderr, &vps);

		if (do_encode) {
			ssize_t slen;

			slen = tp_encode->func(ctx, &vps, encoded_data, sizeof(encoded_data), encode_ctx);

			/*
			 *	Round-trip: if the encoder produced a packet,
			 *	decode it again into a fresh pair list. The
			 *	result is discarded - the point is that the
			 *	encoder's output must be something the decoder
			 *	accepts without crashing.
			 */
			if (slen > 0) {
				TALLOC_CTX	*ctx2 = talloc_init_const("fuzzer-roundtrip");
				fr_pair_list_t	vps2;

				fr_pair_list_init(&vps2);
				(void) tp_decode->func(ctx2, &vps2, encoded_data, (size_t) slen, decode_ctx);
				talloc_free(ctx2);
			}
		}
	}

	talloc_free(decode_ctx);
	talloc_free(encode_ctx);
	talloc_free(ctx);

	/*
	 *	Clear error messages from the run.  Clearing these
	 *	keeps malloc/free balanced, which helps to avoid the
	 *	fuzzers leak heuristics from firing.
	 */
	fr_strerror_clear();

	return 0;
}
