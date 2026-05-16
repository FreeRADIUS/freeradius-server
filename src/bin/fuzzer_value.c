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

#ifdef __clangd__
#  undef HAVE_SANITIZER_LSAN_INTERFACE_H
#endif
#ifdef HAVE_SANITIZER_LSAN_INTERFACE_H
#  include <sanitizer/asan_interface.h>
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#ifndef HAVE_SANITIZER_LSAN_INTERFACE_H
#  define ASAN_POISON_MEMORY_REGION(_start, _size)
#  define ASAN_UNPOISON_MEMORY_REGION(_start, _size)
#endif

/*
 *	Poison gutters either side of the input string and the value
 *	box. __asan_poison_memory_region() rounds to 8-byte granules,
 *	so reads more than ~7 bytes past either end of the live region
 *	will be reported by ASan. 64 bytes per side is plenty without
 *	bloating each iteration noticeably.
 */
#define POISON_START 64
#define POISON_END   64

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
	uint8_t		*raw_str = NULL, *raw_box = NULL;
	char		*str;
	size_t		inlen;

	if (size < 1) return 0;
	if (size > 8192) return 0; /* keep iterations fast */

	inlen = size - 1;
	type = fuzz_types[data[0] % (sizeof(fuzz_types) / sizeof(fuzz_types[0]))];

	ctx = talloc_init_const("fuzzer_value");
	if (!ctx) return 0;

	/*
	 *	Input string with poison gutters either side. We deliberately
	 *	do NOT NUL-terminate: if fr_value_box_from_str() reads past
	 *	the declared inlen, the poison (or talloc redzone) should
	 *	flag it under ASan rather than the read landing on a
	 *	convenient stop byte.
	 */
	raw_str = talloc_array(ctx, uint8_t, POISON_START + inlen + POISON_END);
	if (!raw_str) goto out;
	str = (char *)(raw_str + POISON_START);
	if (inlen) memcpy(str, data + 1, inlen);
	ASAN_POISON_MEMORY_REGION(raw_str, POISON_START);
	ASAN_POISON_MEMORY_REGION(raw_str + POISON_START + inlen, POISON_END);

	/*
	 *	Value box with poison gutters around the struct. Catches
	 *	per-type sub-parsers that write past the end (or before
	 *	the start) of the destination box.
	 */
	raw_box = talloc_zero_array(ctx, uint8_t,
				    POISON_START + sizeof(fr_value_box_t) + POISON_END);
	if (!raw_box) goto out;
	dst = (fr_value_box_t *)(raw_box + POISON_START);
	ASAN_POISON_MEMORY_REGION(raw_box, POISON_START);
	ASAN_POISON_MEMORY_REGION(raw_box + POISON_START + sizeof(fr_value_box_t), POISON_END);

	(void) fr_value_box_from_str(ctx, dst, type, NULL, str, inlen, NULL);

	/*
	 *	Unpoison before talloc_free walks the chunks.
	 */
	ASAN_UNPOISON_MEMORY_REGION(raw_str, POISON_START + inlen + POISON_END);
	ASAN_UNPOISON_MEMORY_REGION(raw_box, POISON_START + sizeof(fr_value_box_t) + POISON_END);

out:
	talloc_free(ctx);
	return 0;
}
