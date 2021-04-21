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

/** Common functions for test files which need to programatically create test dictionaries
 *
 * @file src/lib/util/dict_test.c
 *
 * @copyright 2021 The FreeRADIUS server project
 */

#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/dict_priv.h>
#include "dict_test.h"

fr_dict_t *fr_dict_test;

fr_dict_attr_t const *fr_dict_attr_test_string;
fr_dict_attr_t const *fr_dict_attr_test_octets;

fr_dict_attr_t const *fr_dict_attr_test_ipv4_addr;
fr_dict_attr_t const *fr_dict_attr_test_ipv4_prefix;

fr_dict_attr_t const *fr_dict_attr_test_ipv6_addr;
fr_dict_attr_t const *fr_dict_attr_test_ipv6_prefix;

fr_dict_attr_t const *fr_dict_attr_test_ifid;
fr_dict_attr_t const *fr_dict_attr_test_combo_ip_addr;
fr_dict_attr_t const *fr_dict_attr_test_combo_ip_prefix;
fr_dict_attr_t const *fr_dict_attr_test_ethernet;
fr_dict_attr_t const *fr_dict_attr_test_bool;

fr_dict_attr_t const *fr_dict_attr_test_uint8;
fr_dict_attr_t const *fr_dict_attr_test_uint16;
fr_dict_attr_t const *fr_dict_attr_test_uint32;
fr_dict_attr_t const *fr_dict_attr_test_uint64;

fr_dict_attr_t const *fr_dict_attr_test_int8;
fr_dict_attr_t const *fr_dict_attr_test_int16;
fr_dict_attr_t const *fr_dict_attr_test_int32;
fr_dict_attr_t const *fr_dict_attr_test_int64;

fr_dict_attr_t const *fr_dict_attr_test_float32;
fr_dict_attr_t const *fr_dict_attr_test_float64;

fr_dict_attr_t const *fr_dict_attr_test_date;

fr_dict_attr_t const *fr_dict_attr_test_time_delta;

fr_dict_attr_t const *fr_dict_attr_test_size;

fr_dict_attr_t const *fr_dict_attr_test_tlv;
fr_dict_attr_t const *fr_dict_attr_test_tlv_string;

fr_dict_attr_t const *fr_dict_attr_test_struct;
fr_dict_attr_t const *fr_dict_attr_test_struct_uint32;

fr_dict_attr_t const *fr_dict_attr_test_vsa;
fr_dict_attr_t const *fr_dict_attr_test_vendor;
fr_dict_attr_t const *fr_dict_attr_test_vendor_string;

fr_dict_attr_t const *fr_dict_attr_test_group;

fr_dict_attr_t const *fr_dict_attr_test_enum;

fr_dict_test_attr_t const fr_dict_test_attrs[] = {
	/*
	 *	Variable length
	 */
	{ .attr = FR_TEST_ATTR_STRING, .da = &fr_dict_attr_test_string, .name = "Test-String", .type = FR_TYPE_STRING },
	{ .attr = FR_TEST_ATTR_OCTETS, .da = &fr_dict_attr_test_octets, .name = "Test-Octets", .type = FR_TYPE_OCTETS },

	/*
	 *	Networking
	 */
	{ .attr = FR_TEST_ATTR_IPV4_ADDR, .da = &fr_dict_attr_test_ipv4_addr, .name = "Test-IPv4-Addr", .type = FR_TYPE_IPV4_ADDR },
	{ .attr = FR_TEST_ATTR_IPV4_PREFIX, .da = &fr_dict_attr_test_ipv4_prefix, .name = "Test-IPv4-Prefix", .type = FR_TYPE_IPV4_PREFIX },

	{ .attr = FR_TEST_ATTR_IPV6_ADDR, .da = &fr_dict_attr_test_ipv6_addr, .name = "Test-IPv6-Addr", .type = FR_TYPE_IPV6_ADDR },
	{ .attr = FR_TEST_ATTR_IPV6_PREFIX, .da = &fr_dict_attr_test_ipv6_prefix, .name = "Test-IPv6-Prefix", .type = FR_TYPE_IPV6_PREFIX },

	{ .attr = FR_TEST_ATTR_IFID, .da = &fr_dict_attr_test_ifid, .name = "Test-IFID", .type = FR_TYPE_IFID },
	{ .attr = FR_TEST_ATTR_ETHERNET, .da = &fr_dict_attr_test_ethernet, .name = "Test-Ethernet", .type = FR_TYPE_ETHERNET },

	/*
	 *	Numeric
	 */
	{ .attr = FR_TEST_ATTR_UINT8, .da = &fr_dict_attr_test_uint8, .name = "Test-Uint8", .type = FR_TYPE_UINT8 },
	{ .attr = FR_TEST_ATTR_UINT16, .da = &fr_dict_attr_test_uint16, .name = "Test-Uint16", .type = FR_TYPE_UINT16 },
	{ .attr = FR_TEST_ATTR_UINT32, .da = &fr_dict_attr_test_uint32, .name = "Test-Uint32", .type = FR_TYPE_UINT32 },
	{ .attr = FR_TEST_ATTR_UINT64, .da = &fr_dict_attr_test_uint64, .name = "Test-Uint64", .type = FR_TYPE_UINT64 },

	{ .attr = FR_TEST_ATTR_INT8, .da = &fr_dict_attr_test_int8, .name = "Test-Int8", .type = FR_TYPE_INT8 },
	{ .attr = FR_TEST_ATTR_INT16, .da = &fr_dict_attr_test_int16, .name = "Test-Int16", .type = FR_TYPE_INT16 },
	{ .attr = FR_TEST_ATTR_INT32, .da = &fr_dict_attr_test_int32, .name = "Test-Int32", .type = FR_TYPE_INT32 },
	{ .attr = FR_TEST_ATTR_INT64, .da = &fr_dict_attr_test_int64, .name = "Test-Int64", .type = FR_TYPE_INT64 },

	{ .attr = FR_TEST_ATTR_FLOAT32, .da = &fr_dict_attr_test_float32, .name = "Test-Float32", .type = FR_TYPE_FLOAT32 },
	{ .attr = FR_TEST_ATTR_FLOAT64, .da = &fr_dict_attr_test_float64, .name = "Test-Float64", .type = FR_TYPE_FLOAT64 },

	{ .attr = FR_TEST_ATTR_DATE, .da = &fr_dict_attr_test_date, .name = "Test-Date", .type = FR_TYPE_DATE },

	{ .attr = FR_TEST_ATTR_TIME_DELTA, .da = &fr_dict_attr_test_date, .name = "Test-Time-Delta", .type = FR_TYPE_TIME_DELTA },

	{ .attr = FR_TEST_ATTR_SIZE, .da = &fr_dict_attr_test_size, .name = "Test-Time-Size", .type = FR_TYPE_SIZE },

	/*
	 *	Grouping
	 */
	{ .attr = FR_TEST_ATTR_TLV, .da = &fr_dict_attr_test_tlv, .name = "Test-TLV", .type = FR_TYPE_TLV },
	{ .attr = FR_TEST_ATTR_TLV_STRING, .parent = &fr_dict_attr_test_tlv, .da = &fr_dict_attr_test_tlv_string, .name = "String", .type = FR_TYPE_STRING },

	{ .attr = FR_TEST_ATTR_STRUCT, .da = &fr_dict_attr_test_struct, .name = "Test-Struct", .type = FR_TYPE_STRUCT },
	{ .attr = 1, .parent = &fr_dict_attr_test_struct, .da = &fr_dict_attr_test_struct_uint32, .name = "uint32", .type = FR_TYPE_UINT32 },

	{ .attr = FR_TEST_ATTR_VSA, .da = &fr_dict_attr_test_vsa, .name = "Test-VSA", .type = FR_TYPE_VSA },
	{ .attr = FR_TEST_ATTR_VENDOR, .parent = &fr_dict_attr_test_vsa, .da = &fr_dict_attr_test_vendor, .name = "Test-Vendor", .type = FR_TYPE_VENDOR },
	{ .attr = FR_TEST_ATTR_VENDOR_STRING, .parent = &fr_dict_attr_test_vendor, .da = &fr_dict_attr_test_vendor_string, .name = "String", .type = FR_TYPE_STRING },

	{ .attr = FR_TEST_ATTR_GROUP, .da = &fr_dict_attr_test_group, .name = "Test-Group", .type = FR_TYPE_GROUP },

	/*
	 *	Enumeration
	 */
	{ .attr = FR_TEST_ATTR_ENUM, .da = &fr_dict_attr_test_enum, .name = "Test-Enum", .type = FR_TYPE_UINT32,
	  .values = (fr_dict_test_attr_value_t[]){
		{ .key = "test123", .val = { .type = FR_TYPE_UINT32, .vb_uint32 = 123 } },
		{ .key = "test321", .val = { .type = FR_TYPE_UINT32, .vb_uint32 = 321 } },
		{ .key = NULL, },
	  }
	},
	{ .attr = FR_TEST_ATTR_INVALID }
};

/** Add our test attributes to our test dictionary
 *
 * @param[in] dict		Test dictionary to add.
 * @param[in] test_defs		Test attribute definitions to add.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int dict_test_attrs_init(fr_dict_t *dict, fr_dict_test_attr_t const *test_defs)
{
	fr_dict_test_attr_t const	*p;
	fr_dict_attr_flags_t		dict_flags = {};

	for (p = test_defs; p->attr != FR_TEST_ATTR_INVALID; p++) {
		fr_dict_attr_t const *parent = p->parent ? *p->parent : fr_dict_root(dict);
		fr_dict_attr_t const *attr;

		if (fr_dict_attr_add(dict, parent, p->name, p->attr, p->type, &dict_flags) < 0) return -1;

		attr = fr_dict_attr_by_name(NULL, parent, p->name);
		if (!attr) {
			fr_strerror_printf("Failed adding test attribute \"%s\"", p->name);
			return -1;
		}

		/* Add the enumeration values */
		if (p->values) {
			fr_dict_test_attr_value_t *v;

			for (v = p->values;
			     v->key != NULL;
			     v++) fr_dict_enum_add_name(fr_dict_attr_unconst(attr), v->key, &v->val, false, false);
		}

		*p->da = attr;
	}

	return 0;
}

/** Initialise a test dictionary and add our test_defs to it
 *
 * @param[in] ctx		to bind the global dictionary ctx lifetim to.
 * @param[out] dict_p		Where to write a pointer to our test dictionary.
 *				May be NULL.
 * @param[in] test_defs		Test attributes.  If NULL will default to the
 *				default test attributes.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_dict_test_init(TALLOC_CTX *ctx, fr_dict_t **dict_p, fr_dict_test_attr_t const *test_defs)
{
	fr_dict_gctx_t const	*our_dict_gctx;
	fr_dict_t		*dict;

	our_dict_gctx = fr_dict_global_ctx_init(ctx, "share/dictionary");
	if (!our_dict_gctx) return -1;

	if (!test_defs) test_defs = fr_dict_test_attrs;

	/*
	 *	Set the root name of the dictionary
	 */
	dict = fr_dict_alloc("test", 42);
	if (!dict) {
	error:
		fr_dict_global_ctx_free(our_dict_gctx);
		return -1;
	}

	if (dict_test_attrs_init(dict, test_defs) < 0) goto error;

	fr_dict_test = dict;

	if (dict_p) *dict_p = dict;

	return 0;
}
