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
 * @file src/lib/server/password.c
 * @brief Password normalisation functions
 *
 * @copyright 2019 The FreeRADIUS server project
 * @copyright 2019 Arran Cudbard-Bell \<a.cudbardb@freeradius.org\>
 */
RCSID("$Id$")

#include <freeradius-devel/server/password.h>

#include <freeradius-devel/util/base64.h>
#include <freeradius-devel/util/hex.h>
#include <freeradius-devel/util/md4.h>
#include <freeradius-devel/util/md5.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/sha1.h>
#include <freeradius-devel/util/value.h>

#include <freeradius-devel/protocol/freeradius/freeradius.internal.password.h>

#ifdef HAVE_OPENSSL_EVP_H
#  include <openssl/evp.h>
#  include <openssl/sha.h>
#endif

typedef enum {
	PASSWORD_CLEARTEXT = 0,			//!< Variable length.
	PASSWORD_HASH,				//!< Fixed lenth.
	PASSWORD_HASH_SALTED,			//!< Fixed length hash, variable length salt.
	PASSWORD_HASH_VARIABLE			//!< Variable length everything.
} password_type_t;

/** Apply preprocessing logic to a password value
 *
 * @param[in] ctx	to allocate returned value in.
 * @
 */
typedef fr_pair_t *(*password_preprocess_t)(TALLOC_CTX *ctx, request_t *request, fr_pair_t *in);

/** Password information
 *
 */
typedef struct {
	password_type_t		type;		//!< What type of password value this is.
	fr_dict_attr_t const	**da;		//!< Dictionary attribute representing this type of password.
	password_preprocess_t	func;		//!< Preprocessing function.
	size_t			min_hash_len;	//!< Minimum length of the decoded string if normifying.
						///< If 0, will be ignored.
	size_t			max_hash_len;	//!< Maximum length of the decoded string if normifying.
						///< If 0, will be ignored.
	bool			no_normify;	//!< Don't attempt to normalise the contents of this
						///< attribute using the hex/base64 decoders.
	bool			always_allow;	//!< Always allow processing of this attribute, irrespective
						///< of what the caller says.
} password_info_t;

static fr_dict_t const *dict_freeradius = NULL;
static fr_dict_t const *dict_radius = NULL;

static fr_dict_attr_t const *attr_cleartext;
static fr_dict_attr_t const *attr_with_header;
static fr_dict_attr_t const *attr_root;

static fr_dict_attr_t const *attr_md5;
static fr_dict_attr_t const *attr_smd5;
static fr_dict_attr_t const *attr_crypt;

static fr_dict_attr_t const *attr_sha1;
static fr_dict_attr_t const *attr_ssha1;

static fr_dict_attr_t const *attr_sha2;
static fr_dict_attr_t const *attr_sha2_224;
static fr_dict_attr_t const *attr_sha2_256;
static fr_dict_attr_t const *attr_sha2_384;
static fr_dict_attr_t const *attr_sha2_512;

static fr_dict_attr_t const *attr_ssha2_224;
static fr_dict_attr_t const *attr_ssha2_256;
static fr_dict_attr_t const *attr_ssha2_384;
static fr_dict_attr_t const *attr_ssha2_512;

static fr_dict_attr_t const *attr_sha3;
static fr_dict_attr_t const *attr_sha3_224;
static fr_dict_attr_t const *attr_sha3_256;
static fr_dict_attr_t const *attr_sha3_384;
static fr_dict_attr_t const *attr_sha3_512;

static fr_dict_attr_t const *attr_ssha3_224;
static fr_dict_attr_t const *attr_ssha3_256;
static fr_dict_attr_t const *attr_ssha3_384;
static fr_dict_attr_t const *attr_ssha3_512;

static fr_dict_attr_t const *attr_pbkdf2;
static fr_dict_attr_t const *attr_lm;
static fr_dict_attr_t const *attr_nt;
static fr_dict_attr_t const *attr_ns_mta_md5;

static fr_dict_attr_t const *attr_user;

extern fr_dict_autoload_t password_dict[];
fr_dict_autoload_t password_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

extern fr_dict_attr_autoload_t password_dict_attr[];
fr_dict_attr_autoload_t password_dict_attr[] = {
	{ .out = &attr_cleartext, .name = "Password.Cleartext", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_with_header, .name = "Password.With-Header", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_root, .name = "Password", .type = FR_TYPE_TLV, .dict = &dict_freeradius },

	{ .out = &attr_md5, .name = "Password.MD5", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_smd5, .name = "Password.SMD5", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_crypt, .name = "Password.Crypt", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_sha1, .name = "Password.SHA1", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_ssha1, .name = "Password.SSHA1", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },

	{ .out = &attr_sha2, .name = "Password.SHA2", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_sha2_224, .name = "Password.SHA2-224", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_sha2_256, .name = "Password.SHA2-256", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_sha2_384, .name = "Password.SHA2-384", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_sha2_512, .name = "Password.SHA2-512", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },

	{ .out = &attr_ssha2_224, .name = "Password.SSHA2-224", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_ssha2_256, .name = "Password.SSHA2-256", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_ssha2_384, .name = "Password.SSHA2-384", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_ssha2_512, .name = "Password.SSHA2-512", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },

	{ .out = &attr_sha3, .name = "Password.SHA3", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_sha3_224, .name = "Password.SHA3-224", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_sha3_256, .name = "Password.SHA3-256", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_sha3_384, .name = "Password.SHA3-384", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_sha3_512, .name = "Password.SHA3-512", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },

	{ .out = &attr_ssha3_224, .name = "Password.SSHA3-224", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_ssha3_256, .name = "Password.SSHA3-256", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_ssha3_384, .name = "Password.SSHA3-384", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_ssha3_512, .name = "Password.SSHA3-512", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },

	{ .out = &attr_pbkdf2, .name = "Password.PBKDF2", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_lm, .name = "Password.LM", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_nt, .name = "Password.NT", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_ns_mta_md5, .name = "Password.NS-MTA-MD5", .type = FR_TYPE_STRING, .dict = &dict_freeradius },

	{ .out = &attr_user, .name = "User-Password", .type = FR_TYPE_STRING, .dict = &dict_radius },

	{ NULL }
};

typedef enum {
	NORMALISED_NOTHING = 0,
	NORMALISED_B64,
	NORMALISED_HEX
} normalise_t;

static fr_table_num_sorted_t const normalise_table[] = {
	{ L("base64"),			NORMALISED_B64		},
	{ L("hex"),			NORMALISED_HEX		},
	{ L("nothing"),			NORMALISED_NOTHING	}
};
static size_t normalise_table_len = NUM_ELEMENTS(normalise_table);

static fr_table_num_sorted_t const password_type_table[] = {
	{ L("cleartext"),			PASSWORD_CLEARTEXT	},
	{ L("hashed"),			PASSWORD_HASH		},
	{ L("salted-hash"),		PASSWORD_HASH_SALTED	},
	{ L("variable-length-hash"),	PASSWORD_HASH_VARIABLE	}
};
static size_t password_type_table_len = NUM_ELEMENTS(password_type_table);

/*
 *	Headers for the Password-with-Header attribute
 *
 *	@note Header comparison is case insensitive.
 */
static fr_table_num_sorted_t const password_header_table[] = {
	{ L("{base64_md5}"),			FR_MD5		},
	{ L("{clear}"),				FR_CLEARTEXT	},
	{ L("{cleartext}"),			FR_CLEARTEXT	},
	{ L("{crypt}"),				FR_CRYPT	},
	{ L("{md4}"),				FR_NT		},
	{ L("{md5}"),				FR_MD5		},
	{ L("{ns-mta-md5}"),			FR_NS_MTA_MD5	},
	{ L("{nt}"),				FR_NT		},
	{ L("{nthash}"),			FR_NT		},

#ifdef HAVE_OPENSSL_EVP_H
	{ L("{sha224}"),			FR_SHA2	},
	{ L("{sha256}"),			FR_SHA2	},
	{ L("{sha2}"),				FR_SHA2	},
	{ L("{sha384}"),			FR_SHA2_384	},
	{ L("{sha512}"),			FR_SHA2_512	},
#endif
	{ L("{sha}"),				FR_SHA1	},
	{ L("{smd5}"),				FR_SMD5	},
#ifdef HAVE_OPENSSL_EVP_H
	{ L("{ssha224}"),			FR_SSHA2_224	},
	{ L("{ssha256}"),			FR_SSHA2_256	},
#  if OPENSSL_VERSION_NUMBER >= 0x10101000L
	{ L("{ssha3-224}"),			FR_SSHA3_224	},
	{ L("{ssha3-256}"),			FR_SSHA3_256	},
	{ L("{ssha3-384}"),			FR_SSHA3_384	},
	{ L("{ssha3-512}"),			FR_SSHA3_512	},
#  endif
	{ L("{ssha384}"),			FR_SSHA2_384	},
	{ L("{ssha512}"),			FR_SSHA2_512	},
#endif
	{ L("{ssha}"),				FR_SSHA1	},
	{ L("{x- orcllmv}"),			FR_LM		},
	{ L("{x- orclntv}"),			FR_NT		},
	{ L("{x-nthash}"),			FR_NT		},
	{ L("{x-pbkdf2}"),			FR_PBKDF2	},
};
static size_t password_header_table_len = NUM_ELEMENTS(password_header_table);

#ifdef HAVE_OPENSSL_EVP_H
static fr_pair_t *password_process_sha2(TALLOC_CTX *ctx, request_t *request, fr_pair_t *known_good);
#  if OPENSSL_VERSION_NUMBER >= 0x10101000L
static fr_pair_t *password_process_sha3(TALLOC_CTX *ctx, request_t *request, fr_pair_t *known_good);
#  endif
#endif
static fr_pair_t *password_process_header(TALLOC_CTX *ctx, request_t *request, fr_pair_t *known_good);

/** Metdata for various password attributes
 *
 */
static password_info_t password_info[] = {
	[FR_CLEARTEXT]			= {
						.type = PASSWORD_CLEARTEXT,
						.da = &attr_cleartext,
						.no_normify = true
					},
	[FR_CRYPT]			= {
						.type = PASSWORD_HASH,
						.da = &attr_crypt
					},
	[FR_LM]				= {
						.type = PASSWORD_HASH,
						.da = &attr_lm,
						.min_hash_len = MD4_DIGEST_LENGTH
					},
	[FR_MD5]			= {
						.type = PASSWORD_HASH,
						.da = &attr_md5,
						.min_hash_len = MD5_DIGEST_LENGTH
					},
	[FR_NS_MTA_MD5]			= {
						.type = PASSWORD_HASH,
						.da = &attr_ns_mta_md5
					},
	[FR_NT]				= {
						.type = PASSWORD_HASH,
						.da = &attr_nt,
						.min_hash_len = MD4_DIGEST_LENGTH
					},
	[FR_WITH_HEADER]		= {
						.type = PASSWORD_HASH_VARIABLE,
						.da = &attr_with_header,
						.func = password_process_header,
						.always_allow = true
					},
	[FR_PBKDF2]			= {
						.type = PASSWORD_HASH_VARIABLE,
						.da = &attr_pbkdf2
					},
	[FR_SHA1]			= {
						.type = PASSWORD_HASH,
						.da = &attr_sha1,
						.min_hash_len = SHA1_DIGEST_LENGTH
					},
#ifdef HAVE_OPENSSL_EVP_H
	[FR_SHA2]			= {
						.type = PASSWORD_HASH_VARIABLE,
						.da = &attr_sha2,
						.func = password_process_sha2,
						.min_hash_len = SHA224_DIGEST_LENGTH,
						.max_hash_len = SHA512_DIGEST_LENGTH
					},
	[FR_SHA2_224]			= {
						.type = PASSWORD_HASH,
						.da = &attr_sha2_224,
						.min_hash_len = SHA224_DIGEST_LENGTH,
					},
	[FR_SHA2_256]			= {
						.type = PASSWORD_HASH,
						.da = &attr_sha2_256,
						.min_hash_len = SHA256_DIGEST_LENGTH,
					},
	[FR_SHA2_384]			= {
						.type = PASSWORD_HASH,
						.da = &attr_sha2_384,
						.min_hash_len = SHA384_DIGEST_LENGTH,
					},
	[FR_SHA2_512]			= {
						.type = PASSWORD_HASH,
						.da = &attr_sha2_512,
						.min_hash_len = SHA512_DIGEST_LENGTH,
					},
#  if OPENSSL_VERSION_NUMBER >= 0x10101000L
	[FR_SHA3]			= {
						.type = PASSWORD_HASH_VARIABLE,
						.da = &attr_sha3,
						.func = password_process_sha3,
						.min_hash_len = SHA224_DIGEST_LENGTH,
					},
	[FR_SHA3_224]			= {
						.type = PASSWORD_HASH,
						.da = &attr_sha3_224,
						.min_hash_len = SHA224_DIGEST_LENGTH,
					},
	[FR_SHA3_256]			= {
						.type = PASSWORD_HASH,
						.da = &attr_sha3_256,
						.min_hash_len = SHA256_DIGEST_LENGTH,
					},
	[FR_SHA3_384]			= {
						.type = PASSWORD_HASH,
						.da = &attr_sha3_384,
						.min_hash_len = SHA384_DIGEST_LENGTH,
					},
	[FR_SHA3_512]			= {
						.type = PASSWORD_HASH,
						.da = &attr_sha3_512,
						.min_hash_len = SHA512_DIGEST_LENGTH
					},
#  endif
#endif
	[FR_SMD5]			= {
						.type = PASSWORD_HASH,
						.da = &attr_smd5,
						.min_hash_len = MD5_DIGEST_LENGTH
					},
	[FR_SSHA1]			= {
						.type = PASSWORD_HASH_SALTED,
						.da = &attr_ssha1,
						.min_hash_len = SHA1_DIGEST_LENGTH
					},
#ifdef HAVE_OPENSSL_EVP_H
	[FR_SSHA2_224]			= {
						.type = PASSWORD_HASH_SALTED,
						.da = &attr_ssha2_224,
						.min_hash_len = SHA224_DIGEST_LENGTH
					},
	[FR_SSHA2_256]			= {
						.type = PASSWORD_HASH_SALTED,
						.da = &attr_ssha2_256,
						.min_hash_len = SHA256_DIGEST_LENGTH
					},
	[FR_SSHA2_384]			= {
						.type = PASSWORD_HASH_SALTED,
						.da = &attr_ssha2_384,
						.min_hash_len = SHA384_DIGEST_LENGTH
					},
	[FR_SSHA2_512]			= {
						.type = PASSWORD_HASH_SALTED,
						.da = &attr_ssha2_512,
						.min_hash_len = SHA512_DIGEST_LENGTH
					},
#  if OPENSSL_VERSION_NUMBER >= 0x10101000L
	[FR_SSHA3_224]			= {
						.type = PASSWORD_HASH_SALTED,
						.da = &attr_ssha3_224,
						.min_hash_len = SHA224_DIGEST_LENGTH,
					},
	[FR_SSHA3_256]			= {
						.type = PASSWORD_HASH_SALTED,
						.da = &attr_ssha3_256,
						.min_hash_len = SHA256_DIGEST_LENGTH
					},
	[FR_SSHA3_384]			= {
						.type = PASSWORD_HASH_SALTED,
						.da = &attr_ssha3_384,
						.min_hash_len = SHA384_DIGEST_LENGTH
					},
	[FR_SSHA3_512]			= {
						.type = PASSWORD_HASH_SALTED,
						.da = &attr_ssha3_512,
						.min_hash_len = SHA512_DIGEST_LENGTH
					}
#  endif
#endif
};

#define MIN_LEN(_info) (info->type == PASSWORD_HASH_SALTED ? (info->min_hash_len + 1) : info->min_hash_len)

static ssize_t normify(normalise_t *action, uint8_t *buffer, size_t bufflen,
		       char const *known_good, size_t len, size_t min_len)
{
	/*
	 *	Else unknown encoding, or already binary.  Leave it.
	 */
	if (action) *action = NORMALISED_NOTHING;

	if (min_len >= bufflen) return 0; /* paranoia */

	/*
	 *	Hex encoding. Length is even, and it's greater than
	 *	twice the minimum length.
	 */
	if (!(len & 0x01) && len >= (2 * min_len)) {
		ssize_t	decoded;

		buffer[0] = 0x00;	/* clang scan */

		decoded = fr_hex2bin(NULL, &FR_DBUFF_TMP(buffer, bufflen), &FR_SBUFF_IN(known_good, len), true);
		if (decoded == (ssize_t)(len >> 1)) {
			if (action) *action = NORMALISED_HEX;
			return decoded;
		}
	}

	/*
	 *	Base 64 encoding.  It's at least 4/3 the original size,
	 *	and we want to avoid division...
	 */
	if ((len * 3) >= ((min_len * 4))) {
		ssize_t decoded;

		decoded = fr_base64_decode(buffer, bufflen, known_good, len);
		if (decoded < 0) return 0;
		if (decoded >= (ssize_t) min_len) {
			if (action) *action = NORMALISED_B64;
			return decoded;
		}
	}

	return 0;
}

/** Hex or base64 or bin auto-discovery
 *
 * Here we try and autodiscover what encoding was used for the password/hash, and
 * convert it back to binary or plaintext.
 *
 * @note Earlier versions used a 0x prefix as a hard indicator that the string was
 *       hex encoded, and would fail if the 0x was present but the string didn't
 *       consist of hexits. The base64 char set is a superset of hex, and it was
 *       observed in the wild, that occasionally base64 encoded data really could
 *       start with 0x. That's why min_len (and decodability) are used as the
 *       only heuristics now.
 *
 * @param[in] ctx		to allocate new pairs in.
 * @param[in] request		The current request.
 * @param[in] known_good	password to normify.
 * @return
 *	- NULL if known_good was already normalised, or couldn't be normalised.
 *	- A new normalised password pair.
 */
static fr_pair_t *password_normify(TALLOC_CTX *ctx, request_t *request, fr_pair_t const *known_good)
{
	uint8_t			buffer[256];
	ssize_t			decoded;
	fr_pair_t		*out;
	normalise_t		normalised;
	password_info_t		*info;
	size_t			min_len;

	if (!fr_cond_assert(known_good->da->attr < NUM_ELEMENTS(password_info))) return NULL;

	info = &password_info[known_good->da->attr];
	min_len = MIN_LEN(info);
	if (min_len >= sizeof(buffer)) return NULL; /* paranoia */

	switch (known_good->da->type) {
	case FR_TYPE_OCTETS:
		decoded = normify(&normalised, buffer, sizeof(buffer),
				  (char const *)known_good->vp_octets, known_good->vp_length, min_len);
		break;

	case FR_TYPE_STRING:
		decoded = normify(&normalised, buffer, sizeof(buffer),
				  known_good->vp_strvalue, known_good->vp_length, min_len);
		break;

	default:
		return NULL;
	}

	if (normalised != NORMALISED_NOTHING) {
		RDEBUG2("Normalizing %s %s encoding, %zu bytes -> %zu bytes",
			known_good->da->name, fr_table_str_by_value(normalise_table, normalised, 0),
			known_good->vp_length, decoded);
		MEM(out = fr_pair_afrom_da(ctx, known_good->da));
		fr_pair_value_memdup(out, buffer, decoded, known_good->vp_tainted);
		return out;
	}

	/*
	 *	Else unknown encoding, or already binary.  Leave it.
	 */
	return NULL;
}

#ifdef HAVE_OPENSSL_EVP_H
/** Split SHA2 hashes into separate attributes based on their length
 *
 * @param[in] ctx		to allocate attributes in.
 * @param[in] request		The current request.
 * @param[in] known_good	attribute to split.
 * @return
 *	- A SHA2 length specific attribute.
 *	- NULL on error.
 */
static fr_pair_t *password_process_sha2(TALLOC_CTX *ctx, request_t *request, fr_pair_t *known_good)
{
	fr_pair_t	*out, *normalised;

	switch (known_good->vp_length) {
	case SHA224_DIGEST_LENGTH:
		MEM(out = fr_pair_afrom_da(ctx, attr_sha2_224));
		fr_pair_value_copy(out, known_good);
		return out;

	case SHA256_DIGEST_LENGTH:
		MEM(out = fr_pair_afrom_da(ctx, attr_sha2_256));
		fr_pair_value_copy(out, known_good);
		return out;

	case SHA384_DIGEST_LENGTH:
		MEM(out = fr_pair_afrom_da(ctx, attr_sha2_384));
		fr_pair_value_copy(out, known_good);
		return out;

	case SHA512_DIGEST_LENGTH:
		MEM(out = fr_pair_afrom_da(ctx, attr_sha2_512));
		fr_pair_value_copy(out, known_good);
		return out;

	default:
		out = password_normify(ctx, request, known_good);
		if (!out) return NULL;

		normalised = password_process_sha2(ctx, request, out);
		talloc_list_free(&out);

		return normalised;
	}
}

#  if OPENSSL_VERSION_NUMBER >= 0x10101000L
/** Split SHA3 hashes into separate attributes based on their length
 *
 * @param[in] ctx		to allocate attributes in.
 * @param[in] request		The current request.
 * @param[in] known_good	attribute to split.
 * @return
 *	- A SHA3 length specific attribute.
 *	- NULL on error.
 */
static fr_pair_t *password_process_sha3(TALLOC_CTX *ctx, request_t *request, fr_pair_t *known_good)
{
	fr_pair_t	*out, *normalised;

	switch (known_good->vp_length) {
	case SHA224_DIGEST_LENGTH:
		MEM(out = fr_pair_afrom_da(ctx, attr_sha3_224));
		fr_pair_value_copy(out, known_good);
		return out;

	case SHA256_DIGEST_LENGTH:
		MEM(out = fr_pair_afrom_da(ctx, attr_sha3_256));
		fr_pair_value_copy(out, known_good);
		return out;

	case SHA384_DIGEST_LENGTH:
		out = fr_pair_afrom_da(ctx, attr_sha3_384);
		fr_pair_value_copy(out, known_good);
		return out;

	case SHA512_DIGEST_LENGTH:
		MEM(out = fr_pair_afrom_da(ctx, attr_sha3_512));
		fr_pair_value_copy(out, known_good);
		return out;

	default:
		MEM(out = password_normify(ctx, request, known_good));
		if (!out) return NULL;

		normalised = password_process_sha3(ctx, request, out);
		talloc_list_free(&out);

		return normalised;
	}
}
#  endif
#endif

/** Convert a Password.With-Header attribute to the correct type
 *
 * Attribute may be base64 encoded, in which case it will be decoded
 * first, then evaluated.
 *
 * @note The buffer for octets types\ attributes is extended by one byte
 *	and '\0' terminated, to allow it to be used as a char buff.
 *
 * @param[in] ctx		to allocate new pairs in.
 * @param[in] request		Current request.
 * @param[in] known_good	Password.With-Header attribute to convert.
 * @return
 *	- Buffer containing normified value on success.
 *	- NULL on error.
 */
static fr_pair_t *password_process_header(TALLOC_CTX *ctx, request_t *request, fr_pair_t *known_good)
{
	char const			*p, *q, *end;

	uint8_t				n1[256], n2[256];
	ssize_t				decoded;

	char				header[128];
	normalise_t			normalised;

	fr_pair_t			*new;
	fr_dict_attr_t const		*def = attr_cleartext;

	VP_VERIFY(known_good);

	/*
	 *	Ensure this is only ever called with a
	 *	string type attribute.
	 */
	fr_assert(known_good->da->type == FR_TYPE_STRING);

	p = known_good->vp_strvalue;
	end = p + known_good->vp_length;

	/*
	 *	Has a header {...} prefix
	 */
do_header:
	if ((*p == '{') && (q = memchr(p, '}', end - p))) {
		size_t			hlen;
		int			attr;
		password_info_t		*info;

		hlen = (q - p) + 1;
		if (hlen >= sizeof(header)) {
			REDEBUG("Password header too long.  Got %zu bytes must be less than %zu bytes",
				hlen, sizeof(header));
			return NULL;
		}

		memcpy(header, p, hlen);
		header[hlen] = '\0';

		attr = fr_table_value_by_substr(password_header_table, header, hlen, -1);
		if (attr < 0) {
			/*
			 *	header buffer retains { and }
			 */
			if (RDEBUG_ENABLED3) {
				RDEBUG3("Unknown header %s in %pP, re-writing to %s",
					header, known_good, def->name);
			} else {
				RDEBUG2("Unknown header %s in %s, re-writing to %s",
					header, known_good->da->name, def->name);
			}
			p = q + 1;
			goto bad_header;
		}

		p = q + 1;

		if (!fr_cond_assert(known_good->da->attr < NUM_ELEMENTS(password_info))) return NULL;
		info = &password_info[attr];

		MEM(new = fr_pair_afrom_da(ctx, *(info->da)));
		switch ((*(info->da))->type) {
		case FR_TYPE_OCTETS:
			fr_pair_value_memdup(new, (uint8_t const *)p, end - p, true);
			break;

		case FR_TYPE_STRING:
			fr_pair_value_bstrndup(new, p, end - p, true);
			break;

		default:
			fr_assert_fail(NULL);
			return NULL;
		}
		return new;
	}

	/*
	 *	Doesn't have a header {...} prefix
	 *
	 *	See if it's base64 or hex, if it is, decode it and check again!
	 *
	 *	We ignore request not to normify, as curly braces aren't
	 *	in either of the character sets for the encoding schemes
	 *	we're normifying, so there's not the possibility for error
	 *	as there is normifying other password hashes.
	 */
	decoded = normify(&normalised, n1, sizeof(n1), p, end - p, 4);	/* { + <char> + } + <char> */
	if (decoded > 0) {
		if ((n1[0] == '{') && (memchr(n1, '}', decoded) != NULL)) {
			RDEBUG2("Normalizing %s %s encoding, %zu bytes -> %zu bytes",
				known_good->da->name, fr_table_str_by_value(normalise_table, normalised, 0),
				known_good->vp_length, decoded);

			/*
			 *	Password.With-Header is a string attribute.
			 *	Even though we're handling binary data, the header
			 *	must be \0 terminated.
			 */
			memcpy(n2, n1, decoded);
			p = (char const *)n2;
			end = p + decoded;
			goto do_header;
		}
	}

	/*
	 *	Rewrite to the default attribute type
	 *	currently Password.Cleartext.
	 *
	 *	This is usually correct if there's no
	 *	header to indicate hash type.
	 */
	if (RDEBUG_ENABLED3) {
		RDEBUG3("No {...} in &control.%pP, re-writing to %s", known_good, def->name);
	} else {
		RDEBUG2("No {...} in &control.%s, re-writing to %s", known_good->da->name, def->name);
	}

bad_header:
	MEM(new = fr_pair_afrom_da(request, def));
	fr_pair_value_bstrndup(new, p, end - p, true);

	return new;
}

/** Apply any processing and normification
 *
 */
static fr_pair_t *password_process(TALLOC_CTX *ctx, request_t *request, fr_pair_t *known_good, bool normify)
{
	password_info_t		*info;
	fr_pair_t		*out;

	info = &password_info[known_good->da->attr];
	if (info->func) {
		fr_pair_t	*from_func, *from_recurse;

		/*
		 *	Pass our input attribute to a custom preprocessing
		 *	function to manipulate it.
		 */
		from_func = info->func(ctx, request, known_good);
		if (!from_func) return NULL;

		/*
		 *	Processing function may have produced a different
		 *	password type, recurse to deal with it...
		 */
		from_recurse = password_process(ctx, request, from_func, normify);

		/*
		 *	Cleanup any intermediary password attributes created
		 *	from running the different normalisation and parsing
		 *	operations.
		 */
		if (!from_recurse) {
			if (from_func != known_good) talloc_list_free(&from_func);
			return NULL;
		}
		if ((from_func != known_good) && (from_recurse != from_func)) talloc_list_free(&from_func);

		return from_recurse;
	}

	/*
	 *	Only normify if we're told to, and we have more data
	 *	than the minimum length.
	 */
	if (normify && !info->no_normify && (known_good->vp_length > info->min_hash_len)) {
		fr_pair_t *from_normify;

		from_normify = password_normify(ctx, request, known_good);
		out = from_normify ? from_normify : known_good;
	} else {
		out = known_good;
	}

	/*
	 *	Sanity checks - Too short
	 */
	if (info->min_hash_len && (out->vp_length < MIN_LEN(info))) {
		if (RDEBUG_ENABLED3) {
			RWDEBUG3("&control.%pP too short, expected %zu bytes, got %zu bytes",
				 out, MIN_LEN(info), out->vp_length);
		} else {
			RWDEBUG2("&control.%s too short, expected %zu bytes, got %zu bytes",
				 out->da->name, MIN_LEN(info), out->vp_length);
		}
	invalid:
		if (out != known_good) talloc_list_free(&out);	/* Free attribute we won't be returning */
		return NULL;
	}

	/*
	 *	Sanity checks - Too long
	 */
	if (info->max_hash_len && (out->vp_length > info->max_hash_len)) {
		if (RDEBUG_ENABLED3) {
			RWDEBUG3("&control.%pP too long, expected %zu bytes, got %zu bytes",
				 out, info->max_hash_len, out->vp_length);
		} else {
			RWDEBUG2("&control.%s too long, expected %zu bytes, got %zu bytes",
				 out->da->name, info->max_hash_len, out->vp_length);
		}
		goto invalid;
	}

	/*
	 *	Sanity checks - Hashes are a fixed length
	 */
	if ((info->type == PASSWORD_HASH) && (out->vp_length != info->min_hash_len)) {

		if (RDEBUG_ENABLED3) {
			RWDEBUG3("&control.%pP incorrect length, expected %zu bytes, got %zu bytes",
				 out, info->min_hash_len, out->vp_length);
		} else {
			RWDEBUG2("&control.%s incorrect length, expected %zu bytes, got %zu bytes",
				 out->da->name, info->min_hash_len, out->vp_length);
		}
		goto invalid;
	}

	return out;
}

/** Find all password attributes in the control list of a request and normalise them
 *
 * @param[in] request	The current request.
 * @param[in] normify	Apply hex/base64 normalisation to attributes.
 * @return the number of attributes normalised.
 */
int password_normalise_and_replace(request_t *request, bool normify)
{
	fr_cursor_t	cursor;
	int		replaced = 0;
	fr_pair_t	*known_good, *new;

	for (known_good = fr_cursor_iter_by_ancestor_init(&cursor, &request->control_pairs, attr_root);
	     known_good;
	     known_good = fr_cursor_next(&cursor)) {
		if (!fr_cond_assert(known_good->da->attr < NUM_ELEMENTS(password_info))) return -1;

		/*
		 *	Apply preprocessing steps and normalisation.
		 */
		new = password_process(request, request, known_good, normify);
		if (!new) break;		/* Process next input attribute */

		if (RDEBUG_ENABLED3) {
			RDEBUG3("Replacing &control.%pP with &control.%pP",
				known_good, new);

		} else {
			RDEBUG2("Replacing &control.%s with &control.%s",
				known_good->da->name, new->da->name);
		}
		fr_cursor_free_item(&cursor);
		fr_cursor_prepend(&cursor, new);
		replaced++;
	}

	return replaced;
}

static fr_pair_t *password_normalise_and_recheck(TALLOC_CTX *ctx, request_t *request,
						  fr_dict_attr_t const *allowed_attrs[], size_t allowed_attrs_len,
						  bool normify, fr_pair_t *const known_good)
{
	fr_pair_t	*new;
	size_t		j;

	if (!fr_cond_assert(known_good->da->attr < NUM_ELEMENTS(password_info))) return NULL;

	/*
	 *	Apply preprocessing steps and normalisation.
	 */
	new = password_process(ctx, request, known_good, normify);
	if (!new) return NULL;

	/*
	 *	If new != known_good, then we need
	 *	to check what was produced is still
	 *	acceptable.
	 */
	if (new->da != known_good->da) {
		for (j = 0; j < allowed_attrs_len; j++) if (allowed_attrs[j] == new->da) return new;

		/*
		 *	New attribute not in our allowed list
		 */
		talloc_list_free(&new);		/* da didn't match, treat as ephemeral */
		return NULL;			/* Process next input attribute */
	}

	/*
	 *	Return attribute for processing
	 */
	return new;
}

/** Find a "known good" password in the control list of a request
 *
 * Searches for a "known good" password attribute, and applies any processing
 * and normification operations to it, returning a new mormalised fr_pair_t.
 *
 * The ctx passed in should be freed when the caller is done with the returned
 * fr_pair_t, or alternatively, a persistent ctx may be used and the value
 * of ephemeral checked.
 * If ephemeral is false the returned pair *MUST NOT BE FREED*, it may be an
 * attribute in the request->control_pairs list.  If ephemeral is true, the returned
 * pair *MUST* be freed, or added to one of the pair lists appropriate to the
 * ctx passed in.
 *
 * @param[out] ephemeral	If true, the caller must use talloc_list_free
 *				to free the return value of this function.
 *				Alternatively 'ctx' can be freed, which is
 *				simpler and cleaner, but some people have
 *				religious objections to that.
 * @param[in] ctx		Ephemeral ctx to allocate new attributes in.
 * @param[in] request		The current request.
 * @param[in] allowed_attrs	Optional list of allowed attributes.
 * @param[in] allowed_attrs_len	Length of allowed attributes list.
 * @param[in] normify		Apply hex/base64 normalisation to attributes.
 * @return
 *	- A fr_pair_t containing a "known good" password.
 *	- NULL on error, or if no usable password attributes were found.
 */
fr_pair_t *password_find(bool *ephemeral, TALLOC_CTX *ctx, request_t *request,
			  fr_dict_attr_t const *allowed_attrs[], size_t allowed_attrs_len, bool normify)
{
	fr_cursor_t	cursor;
	fr_pair_t	*known_good;

	for (known_good = fr_cursor_iter_by_ancestor_init(&cursor, &request->control_pairs, attr_root);
	     known_good;
	     known_good = fr_cursor_next(&cursor)) {
		password_info_t		*info;
		fr_pair_t		*out;
		size_t			i;

		if (known_good->da == attr_user) {
			RWDEBUG("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
			RWDEBUG("!!! Ignoring control.User-Password.  Update your        !!!");
			RWDEBUG("!!! configuration so that the \"known good\" clear text !!!");
			RWDEBUG("!!! password is in Password.Cleartext and NOT in        !!!");
			RWDEBUG("!!! User-Password.                                      !!!");
			RWDEBUG("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
			continue;
		}

		if (known_good->da->attr >= NUM_ELEMENTS(password_info)) continue;

		info = &password_info[known_good->da->attr];

		/*
		 *	Minor reduction in work for the caller
		 *	for a moderate increase in code complexity.
		 */
		if (info->always_allow) {
			out = password_normalise_and_recheck(ctx, request,
						  	     allowed_attrs, allowed_attrs_len,
						  	     normify, known_good);
			if (!out) continue;
		done:
			if (RDEBUG_ENABLED3) {
				RDEBUG3("Using \"known good\" %s password %pP",
					fr_table_str_by_value(password_type_table,
							      password_info[out->da->attr].type,
							      "<INVALID>"), out);
			} else {
				RDEBUG2("Using \"known good\" %s password %s",
					fr_table_str_by_value(password_type_table,
							      password_info[out->da->attr].type,
							      "<INVALID>"), out->da->name);
			}
			if (ephemeral) *ephemeral = (known_good != out);
			return out;
		}

		for (i = 0; i < allowed_attrs_len; i++) {
			if (allowed_attrs[i] != known_good->da) continue;

			out = password_normalise_and_recheck(ctx, request,
						  	     allowed_attrs, allowed_attrs_len,
						  	     normify, known_good);
			if (!out) continue;
			goto done;
		}
	}

	return NULL;
}

/** Load our dictionaries
 *
 */
int password_init(void)
{
	if (fr_dict_autoload(password_dict) < 0) {
		PERROR("%s", __FUNCTION__);
		return -1;
	}
	if (fr_dict_attr_autoload(password_dict_attr) < 0) {
		PERROR("%s", __FUNCTION__);
		fr_dict_autofree(password_dict);
		return -1;
	}

	return 0;
}

void password_free(void)
{
	fr_dict_autofree(password_dict);
}
