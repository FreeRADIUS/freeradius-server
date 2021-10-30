#include <freeradius-devel/util/acutest.h>
#include <freeradius-devel/util/acutest_helpers.h>

#include "base16.h"
#include "base32.h"
#include "base64.h"

typedef struct {
	struct {
		char const *str;
		size_t len;
	} cleartext;

	struct {
		char const *str;
		size_t len;
	} encoded;
} test_vector;


static const test_vector base16_vectors[] = {
	{ L(""),	L("")			},
	{ L("f"),	L("66")			},
	{ L("fo"),	L("666f")		},
	{ L("foo"),	L("666f6f")		},
	{ L("foob"),	L("666f6f62")		},
	{ L("fooba"),	L("666f6f6261")		},
	{ L("foobar"),	L("666f6f626172")	}
};

static const test_vector base32_vectors[] = {
	{ L(""),	L("")			},
	{ L("f"),	L("MY======")		},
	{ L("fo"),	L("MZXQ====")		},
	{ L("foo"),	L("MZXW6===")		},
	{ L("foob"),	L("MZXW6YQ=")		},
	{ L("fooba"),	L("MZXW6YTB")		},
	{ L("foobar"),	L("MZXW6YTBOI======")	}
};

static const test_vector base32_hex_vectors[] = {
	{ L(""),	L("")			},
	{ L("f"),	L("CO======")		},
	{ L("fo"),	L("CPNG====")		},
	{ L("foo"),	L("CPNMU===")		},
	{ L("foob"),	L("CPNMUOG=")		},
	{ L("fooba"),	L("CPNMUOJ1")		},
	{ L("foobar"),	L("CPNMUOJ1E8======")	}
};

static const test_vector base64_vectors[] = {
	{ L(""),	L("")			},
	{ L("f"),	L("Zg==")		},
	{ L("fo"),	L("Zm8=")		},
	{ L("foo"),	L("Zm9v")		},
	{ L("foob"),	L("Zm9vYg==")		},
	{ L("fooba"),	L("Zm9vYmE=")		},
	{ L("foobar"),	L("Zm9vYmFy")		}
};

static void test_base16_encode(void)
{
	char		buffer[17];
	fr_sbuff_t	out;
	size_t		i;

	fr_sbuff_init_out(&out, buffer, sizeof(buffer));

	for (i = 0; i < NUM_ELEMENTS(base16_vectors); i++) {
		fr_sbuff_set_to_start(&out);
		TEST_CHECK_SLEN(fr_base16_encode(&out,
					   	 &FR_DBUFF_TMP((uint8_t const *)base16_vectors[i].cleartext.str,
							       base16_vectors[i].cleartext.len)),
				(ssize_t)base16_vectors[i].encoded.len);
		TEST_MSG("%s", fr_strerror());

		fr_sbuff_set_to_start(&out);
		TEST_CHECK_STRCMP(fr_sbuff_current(&out), base16_vectors[i].encoded.str);
	}
}

static void test_base16_decode(void)
{
	char		buffer[7] = { '\0' };
	fr_dbuff_t	out;
	size_t		i;

	fr_dbuff_init(&out, (uint8_t *)buffer, sizeof(buffer));

	for (i = 0; i < NUM_ELEMENTS(base16_vectors); i++) {
		fr_dbuff_set_to_start(&out);
		TEST_CHECK_SLEN(fr_base16_decode(NULL, &out,
					   &FR_SBUFF_IN(base16_vectors[i].encoded.str,
							base16_vectors[i].encoded.len), true),
				(ssize_t)base16_vectors[i].cleartext.len);
		TEST_MSG("%s", fr_strerror());

		fr_dbuff_in_bytes(&out, 0x00);	/* Terminate */

		fr_dbuff_set_to_start(&out);
		TEST_CHECK_STRCMP((char *)fr_dbuff_current(&out), base16_vectors[i].cleartext.str);
	}
}

static void test_base32_encode(void)
{
	char		buffer[17];
	fr_sbuff_t	out;
	size_t		i;

	fr_sbuff_init_out(&out, buffer, sizeof(buffer));

	for (i = 0; i < NUM_ELEMENTS(base32_vectors); i++) {
		fr_sbuff_set_to_start(&out);
		TEST_CHECK_SLEN(fr_base32_encode(&out,
						 &FR_DBUFF_TMP((uint8_t const *)base32_vectors[i].cleartext.str,
							      base32_vectors[i].cleartext.len),
						 true),
				(ssize_t)base32_vectors[i].encoded.len);
		TEST_MSG("%s", fr_strerror());

		fr_sbuff_set_to_start(&out);
		TEST_CHECK_STRCMP(fr_sbuff_current(&out), base32_vectors[i].encoded.str);
	}
}

static void test_base32_decode(void)
{
	char		buffer[7] = { '\0' };
	fr_dbuff_t	out;
	size_t		i;

	fr_dbuff_init(&out, (uint8_t *)buffer, sizeof(buffer));

	for (i = 0; i < NUM_ELEMENTS(base32_vectors); i++) {
		fr_dbuff_set_to_start(&out);
		TEST_CHECK_SLEN(fr_base32_decode(&out,
						 &FR_SBUFF_IN(base32_vectors[i].encoded.str,
							      base32_vectors[i].encoded.len),
						 true, true),
				(ssize_t)base32_vectors[i].cleartext.len);
		TEST_MSG("%s", fr_strerror());

		fr_dbuff_in_bytes(&out, 0x00);	/* Terminate */

		fr_dbuff_set_to_start(&out);
		TEST_CHECK_STRCMP((char *)fr_dbuff_current(&out), base32_vectors[i].cleartext.str);

	}
}

static void test_base32_hex_encode(void)
{
	char		buffer[17];
	fr_sbuff_t	out;
	size_t		i;

	fr_sbuff_init_out(&out, buffer, sizeof(buffer));

	for (i = 0; i < NUM_ELEMENTS(base32_hex_vectors); i++) {
		fr_sbuff_set_to_start(&out);
		TEST_CHECK_SLEN(fr_base32_encode_nstd(&out,
						      &FR_DBUFF_TMP((uint8_t const *)base32_hex_vectors[i].cleartext.str,
								    base32_hex_vectors[i].cleartext.len),
						      true, fr_base32_hex_alphabet_encode),
				(ssize_t)base32_hex_vectors[i].encoded.len);
		TEST_MSG("%s", fr_strerror());

		fr_sbuff_set_to_start(&out);
		TEST_CHECK_STRCMP(fr_sbuff_current(&out), base32_hex_vectors[i].encoded.str);
	}
}

static void test_base32_hex_decode(void)
{
	char		buffer[7] = { '\0' };
	fr_dbuff_t	out;
	size_t		i;

	fr_dbuff_init(&out, (uint8_t *)buffer, sizeof(buffer));

	for (i = 0; i < NUM_ELEMENTS(base32_vectors); i++) {
		fr_dbuff_set_to_start(&out);
		TEST_CHECK_SLEN(fr_base32_decode_nstd(NULL, &out,
						      &FR_SBUFF_IN(base32_hex_vectors[i].encoded.str,
								   base32_hex_vectors[i].encoded.len),
						      true, true, fr_base32_hex_alphabet_decode),
				(ssize_t)base32_hex_vectors[i].cleartext.len);
		TEST_MSG("%s", fr_strerror());

		fr_dbuff_in_bytes(&out, 0x00);	/* Terminate */

		fr_dbuff_set_to_start(&out);
		TEST_CHECK_STRCMP((char *)fr_dbuff_current(&out), base32_hex_vectors[i].cleartext.str);

	}
}

static void test_base64_encode(void)
{
	char		buffer[17];
	fr_sbuff_t	out;
	size_t		i;

	fr_sbuff_init_out(&out, buffer, sizeof(buffer));

	for (i = 0; i < NUM_ELEMENTS(base64_vectors); i++) {
		fr_sbuff_set_to_start(&out);
		TEST_CHECK_SLEN(fr_base64_encode(&out,
						 &FR_DBUFF_TMP((uint8_t const *)base64_vectors[i].cleartext.str,
							      base64_vectors[i].cleartext.len),
						 true),
				(ssize_t)base64_vectors[i].encoded.len);
		TEST_MSG("%s", fr_strerror());

		fr_sbuff_set_to_start(&out);
		TEST_CHECK_STRCMP(fr_sbuff_current(&out), base64_vectors[i].encoded.str);
	}
}

static void test_base64_decode(void)
{
	char		buffer[7] = { '\0' };
	fr_dbuff_t	out;
	size_t		i;

	fr_dbuff_init(&out, (uint8_t *)buffer, sizeof(buffer));

	for (i = 0; i < NUM_ELEMENTS(base64_vectors); i++) {
		fr_dbuff_set_to_start(&out);
		TEST_CHECK_SLEN(fr_base64_decode(&out,
						 &FR_SBUFF_IN(base64_vectors[i].encoded.str,
							      base64_vectors[i].encoded.len),
						 true, true),
				(ssize_t)base64_vectors[i].cleartext.len);
		TEST_MSG("%s", fr_strerror());

		fr_dbuff_in_bytes(&out, 0x00);	/* Terminate */

		fr_dbuff_set_to_start(&out);
		TEST_CHECK_STRCMP((char *)fr_dbuff_current(&out), base64_vectors[i].cleartext.str);

	}
}

TEST_LIST = {
	{ "base16_encode",		test_base16_encode },
	{ "base16_decode",		test_base16_decode },

	{ "base32_encode",		test_base32_encode },
	{ "base32_decode",		test_base32_decode },
	{ "base32_hex_encode",		test_base32_hex_encode },
	{ "base32_hex_decode",		test_base32_hex_decode },

	{ "base64_encode",		test_base64_encode },
	{ "base64_decode",		test_base64_decode },
	{ NULL }
};
