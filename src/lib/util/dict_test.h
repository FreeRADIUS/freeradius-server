#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** Functions to create test dictionaries for unit tests
 *
 * @file src/lib/util/dict_test.h
 *
 * @copyright 2021 The FreeRADIUS server project
 */
RCSIDH(dict_test_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

/** Test attribute numbers
 */
typedef enum {
	FR_TEST_ATTR_INVALID = -1,
	FR_TEST_ATTR_STRING = 1,
	FR_TEST_ATTR_OCTETS,

	FR_TEST_ATTR_IPV4_ADDR,
	FR_TEST_ATTR_IPV4_PREFIX,
	FR_TEST_ATTR_IPV6_ADDR,
	FR_TEST_ATTR_IPV6_PREFIX,
	FR_TEST_ATTR_IFID,
	FR_TEST_ATTR_COMBO_IP_ADDR,
	FR_TEST_ATTR_COMBO_IP_PREFIX,
	FR_TEST_ATTR_ETHERNET,

	FR_TEST_ATTR_BOOL,

	FR_TEST_ATTR_UINT8,
	FR_TEST_ATTR_UINT16,
	FR_TEST_ATTR_UINT32,
	FR_TEST_ATTR_UINT64,


	FR_TEST_ATTR_INT8,
	FR_TEST_ATTR_INT16,
	FR_TEST_ATTR_INT32,
	FR_TEST_ATTR_INT64,

	FR_TEST_ATTR_FLOAT32,
	FR_TEST_ATTR_FLOAT64,

	FR_TEST_ATTR_DATE,

	FR_TEST_ATTR_TIME_DELTA,

	FR_TEST_ATTR_SIZE,

	FR_TEST_ATTR_TLV,
	FR_TEST_ATTR_TLV_STRING,

	FR_TEST_ATTR_STRUCT,

	FR_TEST_ATTR_VSA,
	FR_TEST_ATTR_VENDOR,
	FR_TEST_ATTR_VENDOR_STRING,

	FR_TEST_ATTR_GROUP,

	FR_TEST_ATTR_ENUM
} fr_dict_test_attr_number_t;

/** Test enumeration values
 */
typedef struct value {
	char const			*key;		//!< Enumeration name.
	fr_value_box_t			val;		//!< Enumeration value
} fr_dict_test_attr_value_t;

/** Test enumeration attributes
 */
typedef struct {
	fr_dict_test_attr_number_t	attr;		//!< Attribute number to create.
	fr_dict_attr_t const		**parent;	//!< The parent of this attribute.
	fr_dict_attr_t const		**da;		//!< Where to write a pointer to this attribute.
	char const			*name;		//!< What to call this attribute.
	fr_type_t			type;		//!< What type the attribute.
	fr_dict_test_attr_value_t	*values;	//!< Array of enumeration values to add to this attribute.
} fr_dict_test_attr_t;

extern fr_dict_t *fr_dict_test;
extern fr_dict_attr_t const *fr_dict_attr_test_string;
extern fr_dict_attr_t const *fr_dict_attr_test_octets;

extern fr_dict_attr_t const *fr_dict_attr_test_ipv4_addr;
extern fr_dict_attr_t const *fr_dict_attr_test_ipv4_prefix;

extern fr_dict_attr_t const *fr_dict_attr_test_ipv6_addr;
extern fr_dict_attr_t const *fr_dict_attr_test_ipv6_prefix;

extern fr_dict_attr_t const *fr_dict_attr_test_ifid;
extern fr_dict_attr_t const *fr_dict_attr_test_combo_ip_addr;
extern fr_dict_attr_t const *fr_dict_attr_test_combo_ip_prefix;
extern fr_dict_attr_t const *fr_dict_attr_test_ethernet;
extern fr_dict_attr_t const *fr_dict_attr_test_bool;

extern fr_dict_attr_t const *fr_dict_attr_test_uint8;
extern fr_dict_attr_t const *fr_dict_attr_test_uint16;
extern fr_dict_attr_t const *fr_dict_attr_test_uint32;
extern fr_dict_attr_t const *fr_dict_attr_test_uint64;

extern fr_dict_attr_t const *fr_dict_attr_test_int8;
extern fr_dict_attr_t const *fr_dict_attr_test_int16;
extern fr_dict_attr_t const *fr_dict_attr_test_int32;
extern fr_dict_attr_t const *fr_dict_attr_test_int64;

extern fr_dict_attr_t const *fr_dict_attr_test_float32;
extern fr_dict_attr_t const *fr_dict_attr_test_float64;

extern fr_dict_attr_t const *fr_dict_attr_test_date;

extern fr_dict_attr_t const *fr_dict_attr_test_time_delta;

extern fr_dict_attr_t const *fr_dict_attr_test_size;

extern fr_dict_attr_t const *fr_dict_attr_test_tlv;
extern fr_dict_attr_t const *fr_dict_attr_test_tlv_string;

extern fr_dict_attr_t const *fr_dict_attr_test_struct;
extern fr_dict_attr_t const *fr_dict_attr_test_struct_uint32;

extern fr_dict_attr_t const *fr_dict_attr_test_vsa;
extern fr_dict_attr_t const *fr_dict_attr_test_vendor;
extern fr_dict_attr_t const *fr_dict_attr_test_vendor_string;

extern fr_dict_attr_t const *fr_dict_attr_test_group;

extern fr_dict_attr_t const *fr_dict_attr_test_enum;

extern fr_dict_test_attr_t const fr_dict_test_attrs[];

int fr_dict_test_init(TALLOC_CTX *ctx, fr_dict_t **dict_p, fr_dict_test_attr_t const *test_defs);

#ifdef __cplusplus
}
#endif
