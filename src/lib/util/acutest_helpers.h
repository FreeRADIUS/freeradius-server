#pragma once
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

/** Type specific TEST_CHECK macros for acutest
 *
 * @file src/lib/util/acutest_helpers.h
 *
 * @copyright 2020 Arran Cudbard-Bell
 */
RCSIDH(ascend_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#define TEST_CHECK_LEN(_got, _exp) \
do { \
	size_t _our_got = (_got); \
	TEST_CHECK(_exp == _our_got); \
	TEST_MSG("Expected length : %zu", (ssize_t)_exp); \
	TEST_MSG("Got length      : %zu", (ssize_t)_our_got); \
} while(0)

#define TEST_CHECK_RET(_got, _exp) \
do { \
	int _our_got = (_got); \
	TEST_CHECK(_exp == _our_got); \
	TEST_MSG("Expected ret    : %"PRId64, (int64_t)_exp); \
	TEST_MSG("Got ret         : %"PRId64, (int64_t)_our_got); \
} while(0)
#define TEST_CHECK_SLEN(_got, _exp) \
do { \
	ssize_t _our_got = (_got); \
	TEST_CHECK(_exp == _our_got); \
	TEST_MSG("Expected length : %zd", (ssize_t)_exp); \
	TEST_MSG("Got length      : %zd", (ssize_t)_our_got); \
} while(0)

#define TEST_CHECK_STRCMP(_got, _exp) \
do { \
	char const *_our_got = (_got); \
	TEST_CHECK(((_exp) != NULL) && ((_got) != NULL) && (strcmp(_exp, _our_got) == 0)); \
	TEST_MSG("Expected : \"%s\"", _exp); \
	TEST_MSG("Got      : \"%s\"", _our_got); \
} while(0)

#ifdef __cplusplus
}
#endif
