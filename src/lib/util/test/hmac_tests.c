/*
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** Tests for the internal hmac functions
 *
 * @file src/lib/util/test//hmac_tests.c
 *
 * @copyright 2021 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */

#include "acutest.h"
#include"acutest_helpers.h"
#include <freeradius-devel/util/md5.h>
#include <freeradius-devel/util/sha1.h>

/*
Test Vectors (Trailing '\0' of a character string not included in test):

  key =  0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
  key_len =     16 bytes
  data =	"Hi There"
  data_len =    8  bytes
  digest =      0x9294727a3638bb1c13f48ef8158bfc9d

  key =	 "Jefe"
  data =	"what do ya want for nothing?"
  data_len =    28 bytes
  digest =      0x750c783e6ab0b503eaa86e310a5db738

  key =	 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

  key_len       16 bytes
  data =	0xDDDDDDDDDDDDDDDDDDDD...
		..DDDDDDDDDDDDDDDDDDDD...
		..DDDDDDDDDDDDDDDDDDDD...
		..DDDDDDDDDDDDDDDDDDDD...
		..DDDDDDDDDDDDDDDDDDDD
  data_len =    50 bytes
  digest =      0x56be34521d144c88dbb8c733f0e8b3f6
*/
static void test_hmac_md5(void)
{
	uint8_t digest[16];
	uint8_t const *key;
	int key_len;
	uint8_t const *text;
	int text_len;

	/*
	 *	Test 1
	 */
	key = (uint8_t[]){
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x00
	};
	key_len = strlen((char const *)key);

	text = (uint8_t const *)"Hi There";
	text_len = strlen((char const *)text);

	fr_hmac_md5(digest, text, text_len, key, key_len);

	TEST_CHECK_RET(memcmp(digest,
			      (uint8_t[]){
 					0x92, 0x94, 0x72, 0x7a, 0x36, 0x38, 0xbb, 0x1c,
 					0x13, 0xf4, 0x8e, 0xf8, 0x15, 0x8b, 0xfc, 0x9d
			      },
			      sizeof(digest)), 0);

	/*
	 *	Test 2
	 */
	key = (uint8_t const *)"Jefe";
	key_len = strlen((char const *)key);

	text = (uint8_t const *)"what do ya want for nothing?";
	text_len = strlen((char const *)text);

	fr_hmac_md5(digest, text, text_len, key, key_len);

	TEST_CHECK_RET(memcmp(digest,
			      (uint8_t[]){
					0x75, 0x0c, 0x78, 0x3e, 0x6a, 0xb0, 0xb5, 0x03,
					0xea, 0xa8, 0x6e, 0x31, 0x0a, 0x5d, 0xb7, 0x38
			      },
			      sizeof(digest)), 0);

	/*
	 *	Test 3
	 */
	key = (uint8_t[]){
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0x00
	};
	key_len = strlen((char const *)key);

	text = (uint8_t[]){
		0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD,
		0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD,
		0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD,
		0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD,
		0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD,
		0x00
	};
	text_len = strlen((char const *)text);

	fr_hmac_md5(digest, text, text_len, key, key_len);

	TEST_CHECK_RET(memcmp(digest,
			      (uint8_t[]){
					0x56, 0xbe, 0x34, 0x52, 0x1d, 0x14, 0x4c, 0x88,
					0xdb, 0xb8, 0xc7, 0x33, 0xf0, 0xe8, 0xb3, 0xf6
			      },
			      sizeof(digest)), 0);
}

/*
Test Vectors (Trailing '\0' of a character string not included in test):

  key =	 "Jefe"
  data =	"what do ya want for nothing?"
  data_len =    28 bytes
  digest =	0xeffcdf6ae5eb2fa2d27416d5f184df9c259a7c79

  key =	 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

  key_len       16 bytes
  data =	0xDDDDDDDDDDDDDDDDDDDD...
		..DDDDDDDDDDDDDDDDDDDD...
		..DDDDDDDDDDDDDDDDDDDD...
		..DDDDDDDDDDDDDDDDDDDD...
		..DDDDDDDDDDDDDDDDDDDD
  data_len =    50 bytes
  digest =      0xd730594d167e35d5956fd8003d0db3d3f46dc7bb
*/
static void test_hmac_sha1(void)
{

	uint8_t digest[20];
	uint8_t const *key;
	int key_len;
	uint8_t const *text;
	int text_len;

	/*
	 *	Test 1
	 */
	key = (uint8_t const *)"Jefe";
	key_len = strlen((char const *)key);

	text = (uint8_t const *)"what do ya want for nothing?";
	text_len = strlen((char const *)text);

	fr_hmac_sha1(digest, text, text_len, key, key_len);

	TEST_CHECK_RET(memcmp(digest,
			      (uint8_t[]){
					0xef, 0xfc, 0xdf, 0x6a, 0xe5, 0xeb, 0x2f, 0xa2, 0xd2, 0x74,
					0x16, 0xd5, 0xf1, 0x84, 0xdf, 0x9c, 0x25, 0x9a, 0x7c, 0x79
			      },
			      sizeof(digest)), 0);

	/*
	 *	Test 2
	 */
	key = (uint8_t[]){
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0x00
	};
	key_len = strlen((char const *)key);

	text = (uint8_t[]){
		0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD,
		0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD,
		0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD,
		0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD,
		0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD,
		0x00
	};
	text_len = strlen((char const *)text);

	fr_hmac_sha1(digest, text, text_len, key, key_len);

	TEST_CHECK_RET(memcmp(digest,
			      (uint8_t[]){
					0xd7, 0x30, 0x59, 0x4d, 0x16, 0x7e, 0x35, 0xd5, 0x95, 0x6f,
					0xd8, 0x00, 0x3d, 0x0d, 0xb3, 0xd3, 0xf4, 0x6d, 0xc7, 0xbb
			      },
			      sizeof(digest)), 0);
}

TEST_LIST = {
	/*
	 *	Allocation and management
	 */
	{ "hmac-md5",			test_hmac_md5	},
	{ "hmac-sha1",			test_hmac_sha1	},

	TEST_TERMINATOR
};
