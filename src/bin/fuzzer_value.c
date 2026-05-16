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
 * @file src/bin/fuzzer_value.c
 * @brief Functions to fuzz fr_value_box_from_str()
 *
 * fr_value_box_from_str() is the universal text -> typed-value parser in
 * FreeRADIUS. Every string-form value (config files, dictionaries, CLI
 * input, radclient, JSON) flows through it. It dispatches to per-type
 * sub-parsers for IP addresses, IPv6 prefixes, MAC addresses, integers,
 * dates, hex octets, floats, ifid, etc. Each is a potential bug surface,
 * so a single harness covers a wide attack surface.
 *
 * Input layout:
 *   byte[0]  - type selector (mod number of leaf types)
 *   byte[1+] - string to parse for that type
 */
RCSID("$Id$")

#include <freeradius-devel/build.h>
#include <freeradius-devel/util/talloc.h>
#include <freeradius-devel/util/types.h>
#include <freeradius-devel/util/value.h>

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len);

/*
 *	Leaf data types that fr_value_box_from_str() actually parses.
 *	Excludes structural (TLV, STRUCT, GROUP, UNION, VSA, VENDOR, ATTR)
 *	and pseudo (NULL, MAX, VOID, *_CURSOR) types.
 */
static fr_type_t const fuzz_types[] = {
	FR_TYPE_STRING,
	FR_TYPE_OCTETS,
	FR_TYPE_IPV4_ADDR,
	FR_TYPE_IPV4_PREFIX,
	FR_TYPE_IPV6_ADDR,
	FR_TYPE_IPV6_PREFIX,
	FR_TYPE_IFID,
	FR_TYPE_COMBO_IP_ADDR,
	FR_TYPE_COMBO_IP_PREFIX,
	FR_TYPE_ETHERNET,
	FR_TYPE_BOOL,
	FR_TYPE_UINT8,
	FR_TYPE_UINT16,
	FR_TYPE_UINT32,
	FR_TYPE_UINT64,
	FR_TYPE_INT8,
	FR_TYPE_INT16,
	FR_TYPE_INT32,
	FR_TYPE_INT64,
	FR_TYPE_FLOAT32,
	FR_TYPE_FLOAT64,
	FR_TYPE_DATE,
	FR_TYPE_TIME_DELTA,
	FR_TYPE_SIZE,
};

int LLVMFuzzerInitialize(UNUSED int *argc, UNUSED char ***argv)
{
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	TALLOC_CTX	*ctx;
	fr_value_box_t	*dst;
	fr_type_t	type;
	char		*str;

	if (size < 1) return 0;
	if (size > 8192) return 0; /* keep iterations fast */

	type = fuzz_types[data[0] % (sizeof(fuzz_types) / sizeof(fuzz_types[0]))];

	ctx = talloc_init_const("fuzzer_value");
	if (!ctx) return 0;

	/*
	 *	Pass the rest of the buffer as the string. NUL-terminate to be
	 *	defensive even though the API takes (in, inlen).
	 */
	str = talloc_array(ctx, char, size); /* size bytes; index 0 unused payload */
	if (!str) goto out;
	if (size > 1) memcpy(str, (char const *)(data + 1), size - 1);
	str[size - 1] = '\0';

	dst = talloc_zero(ctx, fr_value_box_t);
	if (!dst) goto out;

	(void) fr_value_box_from_str(ctx, dst, type, NULL,
				     str, size - 1, NULL);

out:
	talloc_free(ctx);
	return 0;
}
