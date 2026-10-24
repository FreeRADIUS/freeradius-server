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
 *   along with this program; if not, write to the Free Software Foundation,
 *   Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @file src/fuzzer/fuzzer_enc.c
 * @brief Functions to fuzz protocol encoding
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/fuzzer/common.h>
#include <freeradius-devel/util/dbuff.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/value.h>

extern fr_test_point_proto_encode_t XX_PROTOCOL_XX_tp_encode_proto;

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len);

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	if (fuzzer_common_init(argc, argv, true) < 0) fr_exit_now(EXIT_FAILURE);

	return 1;
}

/** Count the leaf attributes amongst a parent's children.
 */
static size_t pair_attr_count(fr_dict_attr_t const *parent)
{
	fr_dict_attr_t const *da = NULL;
	size_t count = 0;

	while ((da = fr_dict_attr_iterate_children(parent, &da))) {
		if (fr_type_is_leaf(da->type)) count++;
	}

	return count;
}

/** Find a leaf attribute by its index amongst a parent's children.
 *
 *	Skipping structural attributes keeps the bytecode compact while ensuring
 *	the value bytes can be decoded directly into a value box.
 */
static fr_dict_attr_t const *pair_attr_by_index(fr_dict_attr_t const *parent, size_t index)
{
	fr_dict_attr_t const *da = NULL;
	size_t count = 0;

	while ((da = fr_dict_attr_iterate_children(parent, &da))) {
		// TODO support these
		if (!fr_type_is_leaf(da->type)) continue;

		if (count++ == index) return da;
	}

	return NULL;
}

/** Return the fixed network size for a value type, or zero if it varies.
 */
static size_t pair_value_fixed_len(fr_type_t type)
{
	switch (type) {
	case FR_TYPE_BOOL:
	case FR_TYPE_UINT8:
	case FR_TYPE_INT8:
		return 1;

	case FR_TYPE_UINT16:
	case FR_TYPE_INT16:
		return 2;

	case FR_TYPE_UINT32:
	case FR_TYPE_INT32:
	case FR_TYPE_FLOAT32:
	case FR_TYPE_IPV4_ADDR:
		return 4;

	case FR_TYPE_IPV4_PREFIX:
		return 5;

	case FR_TYPE_ETHERNET:
		return 6;

	case FR_TYPE_UINT64:
	case FR_TYPE_INT64:
	case FR_TYPE_FLOAT64:
	case FR_TYPE_SIZE:
	case FR_TYPE_IFID:
		return 8;

	default:
		return 0;
	}
}

/** Deserialize pairs from compact binary records.
 *
 *	The input comprises records of:
 *
 *	[attribute index (uint16)][network-format value bytes]
 *
 *	Values with a variable network size include a value-length byte between
 *	the attribute index and the value bytes.
 *
 *	The dictionary attribute, rather than the fuzz input, determines the
 *	value type.  Invalid value encodings are discarded.
 */
static int pair_list_deserialize(TALLOC_CTX *ctx, fr_dict_t const *protocol_dict, fr_pair_list_t *vps,
				 uint8_t const *buf, size_t len)
{
	fr_dict_attr_t const *parent;
	size_t attr_count;

	parent = root_da ? root_da : fr_dict_root(protocol_dict);
	attr_count = pair_attr_count(parent);
	if (attr_count == 0) return -1;
	fr_fatal_assert_msg(attr_count <= UINT16_MAX,
			    "Dictionary root \"%s\" has %zu leaf attributes, exceeding the fuzzer selector limit",
			    parent->name, attr_count);

	while (len >= 2) {
		fr_dict_attr_t const *da;
		fr_pair_t *vp;
		size_t value_len;

		da = pair_attr_by_index(parent, (((size_t)buf[0] << 8) | buf[1]) % attr_count);
		buf += 2;
		len -= 2;

		value_len = pair_value_fixed_len(da->type);
		if (value_len == 0) {
			if (len == 0) break;

			value_len = *buf++;
			len--;
		}

		if (value_len > len) value_len = len;

		if (da) {
			ssize_t slen;

			vp = fr_pair_afrom_da(ctx, da);
			if (!vp) return -1;

			slen = fr_value_box_from_network(vp, &vp->data, vp->vp_type, vp->da,
							 &FR_DBUFF_TMP(buf, value_len), value_len, true);
			if (slen >= 0) {
				FR_PAIR_APPEND(vps, vp);
			} else {
				talloc_free(vp);
			}
		}

		buf += value_len;
		len -= value_len;
	}

	return fr_pair_list_empty(vps) ? -1 : 0;
}

static size_t const encoded_data_sizes[] = {
	0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64,
	127, 128, 255, 256, 511, 512, 1023, 1024,
	2047, 2048, 4095, 4096, 8191, 8192,
	16383, 16384, 32767, 32768, 65534, 65535, 65536
};

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
	TALLOC_CTX *ctx = talloc_init_const("fuzzer");
	fr_pair_list_t vps;
	void *encode_ctx = NULL;
	fr_test_point_proto_encode_t *tp_encode = &XX_PROTOCOL_XX_tp_encode_proto;
	fr_dict_t const *protocol_dict = dict;
	size_t encoded_data_len;
	uint8_t *encoded_data = NULL;

	fr_pair_list_init(&vps);
	if (!dict) LLVMFuzzerInitialize(NULL, NULL);

	protocol_dict = dict;

	if (tp_encode->test_ctx && (tp_encode->test_ctx(&encode_ctx, NULL, protocol_dict, root_da) < 0)) {
		fr_perror("fuzzer: Failed initializing test point encode_ctx");
		fr_exit_now(EXIT_FAILURE);
	}

	if (dl_proto) protocol_dict = fr_dict_by_protocol_name(dl_proto->name);
	if (!protocol_dict && fuzzer_protocol) protocol_dict = fr_dict_by_protocol_name(fuzzer_protocol);
	if (!protocol_dict) protocol_dict = dict;

	if (len == 0) goto cleanup;

	encoded_data_len = encoded_data_sizes[buf[0] % (sizeof(encoded_data_sizes) / sizeof(encoded_data_sizes[0]))];

	if (pair_list_deserialize(ctx, protocol_dict, &vps, buf + 1, len - 1) < 0) goto cleanup;

	encoded_data = talloc_array(ctx, uint8_t, encoded_data_len);
	if (!encoded_data) {
		fr_strerror_const("Failed allocating encoded data");
		fr_perror("fuzzer: %s", fr_strerror());
		fr_exit_now(EXIT_FAILURE);
	}

	if (fr_debug_lvl > 3) fr_pair_list_debug(stderr, &vps);

	(void) tp_encode->func(ctx, &vps, encoded_data, encoded_data_len, encode_ctx);

cleanup:
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
