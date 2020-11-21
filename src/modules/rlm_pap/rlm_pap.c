/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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
 * @file rlm_pap.c
 * @brief Hashes plaintext passwords to compare against a prehashed reference.
 *
 * @copyright 2001-2012 The FreeRADIUS server project.
 * @copyright 2012 Matthew Newton (matthew@newtoncomputing.co.uk)
 * @copyright 2001 Kostas Kalevras (kkalev@noc.ntua.gr)
 */
RCSID("$Id$")
USES_APPLE_DEPRECATED_API

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/crypt.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/password.h>
#include <freeradius-devel/tls/base.h>

#include <freeradius-devel/util/base64.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/hex.h>
#include <freeradius-devel/util/md5.h>
#include <freeradius-devel/util/sha1.h>

#include <freeradius-devel/protocol/freeradius/freeradius.internal.password.h>

#include <ctype.h>

#ifdef HAVE_OPENSSL_EVP_H
#  include <openssl/evp.h>
#endif

/*
 *      Define a structure for our module configuration.
 *
 *      These variables do not need to be in a structure, but it's
 *      a lot cleaner to do so, and a pointer to the structure can
 *      be used as the instance handle.
 */
typedef struct {
	char const		*name;
	fr_dict_enum_t		*auth_type;
	bool			normify;
} rlm_pap_t;

typedef unlang_action_t (*pap_auth_func_t)(rlm_rcode_t *p_result, rlm_pap_t const *inst, request_t *request, fr_pair_t const *, fr_pair_t const *);

static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("normalise", FR_TYPE_BOOL, rlm_pap_t, normify), .dflt = "yes" },
	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;

static fr_dict_autoload_t rlm_pap_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_auth_type;
static fr_dict_attr_t const *attr_root;

static fr_dict_attr_t const *attr_user;

static fr_dict_attr_autoload_t rlm_pap_dict_attr[] = {
	{ .out = &attr_auth_type, .name = "Auth-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_root, .name = "Password-Root", .type = FR_TYPE_TLV, .dict = &dict_freeradius },

	{ .out = &attr_user, .name = "User-Password", .type = FR_TYPE_STRING, .dict = &dict_radius },

	{ NULL }
};

#ifdef HAVE_OPENSSL_EVP_H
static fr_table_num_sorted_t const pbkdf2_crypt_names[] = {
	{ L("HMACSHA1"),	FR_SSHA1 },
	{ L("HMACSHA2+224"),	FR_SSHA2_224 },
	{ L("HMACSHA2+256"),	FR_SSHA2_256 },
	{ L("HMACSHA2+384"),	FR_SSHA2_384 },
	{ L("HMACSHA2+512"),	FR_SSHA2_512 },
#  if OPENSSL_VERSION_NUMBER >= 0x10101000L
	{ L("HMACSHA3+224"),	FR_SSHA3_224 },
	{ L("HMACSHA3+256"),	FR_SSHA3_256 },
	{ L("HMACSHA3+384"),	FR_SSHA3_384 },
	{ L("HMACSHA3+512"),	FR_SSHA3_512 },
#  endif
};
static size_t pbkdf2_crypt_names_len = NUM_ELEMENTS(pbkdf2_crypt_names);

static fr_table_num_sorted_t const pbkdf2_passlib_names[] = {
	{ L("sha1"),		FR_SSHA1 },
	{ L("sha256"),		FR_SSHA2_256 },
	{ L("sha512"),		FR_SSHA2_512 }
};
static size_t pbkdf2_passlib_names_len = NUM_ELEMENTS(pbkdf2_passlib_names);
#endif

static fr_dict_attr_t const **pap_alloweds;

/*
 *	Authorize the user for PAP authentication.
 *
 *	This isn't strictly necessary, but it does make the
 *	server simpler to configure.
 */
static unlang_action_t CC_HINT(nonnull) mod_authorize(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_pap_t const 	*inst = talloc_get_type_abort_const(mctx->instance, rlm_pap_t);
	fr_pair_t		*password;

	if (fr_pair_find_by_da(&request->control_pairs, attr_auth_type) != NULL) {
		RDEBUG3("Auth-Type is already set.  Not setting 'Auth-Type := %s'", inst->name);
		RETURN_MODULE_NOOP;
	}

	password = fr_pair_find_by_da(&request->request_pairs, attr_user);
	if (!password) {
		RDEBUG2("No %s attribute in the request.  Cannot do PAP", attr_user->name);
		RETURN_MODULE_NOOP;
	}

	if (!inst->auth_type) {
		WARN("No 'authenticate %s {...}' section or 'Auth-Type = %s' set.  Cannot setup PAP authentication.",
		     inst->name, inst->name);
		RETURN_MODULE_NOOP;
	}

	if (!module_section_type_set(request, attr_auth_type, inst->auth_type)) RETURN_MODULE_NOOP;

	RETURN_MODULE_UPDATED;
}

/*
 *	PAP authentication functions
 */

static unlang_action_t CC_HINT(nonnull) pap_auth_clear(rlm_rcode_t *p_result,
						       UNUSED rlm_pap_t const *inst, request_t *request,
						       fr_pair_t const *known_good, fr_pair_t const *password)
{
	if ((known_good->vp_length != password->vp_length) ||
	    (fr_digest_cmp(known_good->vp_octets, password->vp_octets, known_good->vp_length) != 0)) {
		REDEBUG("Cleartext password does not match \"known good\" password");
		REDEBUG3("Password   : %pV", &password->data);
		REDEBUG3("Expected   : %pV", &known_good->data);
		RETURN_MODULE_REJECT;
	}
	RETURN_MODULE_OK;
}

#ifdef HAVE_CRYPT
static unlang_action_t CC_HINT(nonnull) pap_auth_crypt(rlm_rcode_t *p_result,
						       UNUSED rlm_pap_t const *inst, request_t *request,
						       fr_pair_t const *known_good, fr_pair_t const *password)
{
	if (fr_crypt_check(password->vp_strvalue, known_good->vp_strvalue) != 0) {
		REDEBUG("Crypt digest does not match \"known good\" digest");
		RETURN_MODULE_REJECT;
	}
	RETURN_MODULE_OK;
}
#endif

static unlang_action_t CC_HINT(nonnull) pap_auth_md5(rlm_rcode_t *p_result,
						     UNUSED rlm_pap_t const *inst, request_t *request,
						     fr_pair_t const *known_good, fr_pair_t const *password)
{
	uint8_t digest[MD5_DIGEST_LENGTH];

	if (known_good->vp_length != MD5_DIGEST_LENGTH) {
		REDEBUG("\"known-good\" MD5 password has incorrect length, expected 16 got %zu", known_good->vp_length);
		RETURN_MODULE_INVALID;
	}

	fr_md5_calc(digest, password->vp_octets, password->vp_length);

	if (fr_digest_cmp(digest, known_good->vp_octets, known_good->vp_length) != 0) {
		REDEBUG("MD5 digest does not match \"known good\" digest");
		REDEBUG3("Password   : %pV", &password->data);
		REDEBUG3("Calculated : %pH", fr_box_octets(digest, MD5_DIGEST_LENGTH));
		REDEBUG3("Expected   : %pH", fr_box_octets(known_good->vp_octets, MD5_DIGEST_LENGTH));
		RETURN_MODULE_REJECT;
	}

	RETURN_MODULE_OK;
}


static unlang_action_t CC_HINT(nonnull) pap_auth_smd5(rlm_rcode_t *p_result,
						      UNUSED rlm_pap_t const *inst, request_t *request,
						      fr_pair_t const *known_good, fr_pair_t const *password)
{
	fr_md5_ctx_t	*md5_ctx;
	uint8_t		digest[MD5_DIGEST_LENGTH];

	if (known_good->vp_length <= MD5_DIGEST_LENGTH) {
		REDEBUG("\"known-good\" SMD5-Password has incorrect length, expected 16 got %zu", known_good->vp_length);
		RETURN_MODULE_INVALID;
	}

	md5_ctx = fr_md5_ctx_alloc(true);
	fr_md5_update(md5_ctx, password->vp_octets, password->vp_length);
	fr_md5_update(md5_ctx, known_good->vp_octets + MD5_DIGEST_LENGTH, known_good->vp_length - MD5_DIGEST_LENGTH);
	fr_md5_final(digest, md5_ctx);
	fr_md5_ctx_free(&md5_ctx);

	/*
	 *	Compare only the MD5 hash results, not the salt.
	 */
	if (fr_digest_cmp(digest, known_good->vp_octets, MD5_DIGEST_LENGTH) != 0) {
		REDEBUG("SMD5 digest does not match \"known good\" digest");
		REDEBUG3("Password   : %pV", &password->data);
		REDEBUG3("Calculated : %pH", fr_box_octets(digest, MD5_DIGEST_LENGTH));
		REDEBUG3("Expected   : %pH", fr_box_octets(known_good->vp_octets, MD5_DIGEST_LENGTH));
		RETURN_MODULE_REJECT;
	}

	RETURN_MODULE_OK;
}

static unlang_action_t CC_HINT(nonnull) pap_auth_sha1(rlm_rcode_t *p_result,
						      UNUSED rlm_pap_t const *inst, request_t *request,
						      fr_pair_t const *known_good, fr_pair_t const *password)
{
	fr_sha1_ctx	sha1_context;
	uint8_t		digest[SHA1_DIGEST_LENGTH];

	if (known_good->vp_length != SHA1_DIGEST_LENGTH) {
		REDEBUG("\"known-good\" SHA1-password has incorrect length, expected 20 got %zu", known_good->vp_length);
		RETURN_MODULE_INVALID;
	}

	fr_sha1_init(&sha1_context);
	fr_sha1_update(&sha1_context, password->vp_octets, password->vp_length);
	fr_sha1_final(digest,&sha1_context);

	if (fr_digest_cmp(digest, known_good->vp_octets, known_good->vp_length) != 0) {
		REDEBUG("SHA1 digest does not match \"known good\" digest");
		REDEBUG3("Password   : %pV", &password->data);
		REDEBUG3("Calculated : %pH", fr_box_octets(digest, SHA1_DIGEST_LENGTH));
		REDEBUG3("Expected   : %pH", fr_box_octets(known_good->vp_octets, SHA1_DIGEST_LENGTH));
		RETURN_MODULE_REJECT;
	}

	RETURN_MODULE_OK;
}

static unlang_action_t CC_HINT(nonnull) pap_auth_ssha1(rlm_rcode_t *p_result,
						       UNUSED rlm_pap_t const *inst, request_t *request,
						       fr_pair_t const *known_good, fr_pair_t const *password)
{
	fr_sha1_ctx	sha1_context;
	uint8_t		digest[SHA1_DIGEST_LENGTH];

	if (known_good->vp_length <= SHA1_DIGEST_LENGTH) {
		REDEBUG("\"known-good\" SSHA-Password has incorrect length, expected > 20 got %zu", known_good->vp_length);
		RETURN_MODULE_INVALID;
	}

	fr_sha1_init(&sha1_context);
	fr_sha1_update(&sha1_context, password->vp_octets, password->vp_length);

	fr_sha1_update(&sha1_context, known_good->vp_octets + SHA1_DIGEST_LENGTH, known_good->vp_length - SHA1_DIGEST_LENGTH);
	fr_sha1_final(digest, &sha1_context);

	if (fr_digest_cmp(digest, known_good->vp_octets, SHA1_DIGEST_LENGTH) != 0) {
		REDEBUG("SSHA digest does not match \"known good\" digest");
		REDEBUG3("Password   : %pV", &password->data);
		REDEBUG3("Salt       : %pH", fr_box_octets(known_good->vp_octets + SHA1_DIGEST_LENGTH,
							   known_good->vp_length - SHA1_DIGEST_LENGTH));
		REDEBUG3("Calculated : %pH", fr_box_octets(digest, SHA1_DIGEST_LENGTH));
		REDEBUG3("Expected   : %pH", fr_box_octets(known_good->vp_octets, SHA1_DIGEST_LENGTH));
		RETURN_MODULE_REJECT;
	}

	RETURN_MODULE_OK;
}

#ifdef HAVE_OPENSSL_EVP_H
static unlang_action_t CC_HINT(nonnull) pap_auth_evp_md(rlm_rcode_t *p_result,
						    	UNUSED rlm_pap_t const *inst, request_t *request,
						    	fr_pair_t const *known_good, fr_pair_t const *password,
						    	char const *name, EVP_MD const *md)
{
	EVP_MD_CTX	*ctx;
	uint8_t		digest[EVP_MAX_MD_SIZE];
	unsigned int	digest_len;

	ctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(ctx, md, NULL);
	EVP_DigestUpdate(ctx, password->vp_octets, password->vp_length);
	EVP_DigestFinal_ex(ctx, digest, &digest_len);
	EVP_MD_CTX_destroy(ctx);

	fr_assert((size_t) digest_len == known_good->vp_length);	/* This would be an OpenSSL bug... */

	if (fr_digest_cmp(digest, known_good->vp_octets, known_good->vp_length) != 0) {
		REDEBUG("%s digest does not match \"known good\" digest", name);
		REDEBUG3("Password   : %pV", &password->data);
		REDEBUG3("Calculated : %pH", fr_box_octets(digest, digest_len));
		REDEBUG3("Expected   : %pH", &known_good->data);
		RETURN_MODULE_REJECT;
	}

	RETURN_MODULE_OK;
}

static unlang_action_t CC_HINT(nonnull) pap_auth_evp_md_salted(rlm_rcode_t *p_result,
							       UNUSED rlm_pap_t const *inst, request_t *request,
							       fr_pair_t const *known_good, fr_pair_t const *password,
							       char const *name, EVP_MD const *md)
{
	EVP_MD_CTX	*ctx;
	uint8_t		digest[EVP_MAX_MD_SIZE];
	unsigned int	digest_len, min_len;

	min_len = EVP_MD_size(md);
	ctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(ctx, md, NULL);
	EVP_DigestUpdate(ctx, password->vp_octets, password->vp_length);
	EVP_DigestUpdate(ctx, known_good->vp_octets + min_len, known_good->vp_length - min_len);
	EVP_DigestFinal_ex(ctx, digest, &digest_len);
	EVP_MD_CTX_destroy(ctx);

	fr_assert((size_t) digest_len == min_len);	/* This would be an OpenSSL bug... */

	/*
	 *	Only compare digest_len bytes, the rest is salt.
	 */
	if (fr_digest_cmp(digest, known_good->vp_octets, (size_t)digest_len) != 0) {
		REDEBUG("%s digest does not match \"known good\" digest", name);
		REDEBUG3("Password   : %pV", &password->data);
		REDEBUG3("Salt       : %pH",
			 fr_box_octets(known_good->vp_octets + digest_len, known_good->vp_length - digest_len));
		REDEBUG3("Calculated : %pH", fr_box_octets(digest, digest_len));
		REDEBUG3("Expected   : %pH", fr_box_octets(known_good->vp_octets, digest_len));
		RETURN_MODULE_REJECT;
	}

	RETURN_MODULE_OK;
}

/** Define a new OpenSSL EVP based password hashing function
 *
 */
#define PAP_AUTH_EVP_MD(_func, _new_func, _name, _md) \
static unlang_action_t CC_HINT(nonnull) _new_func(rlm_rcode_t *p_result, \
					          rlm_pap_t const *inst, request_t *request, \
						  fr_pair_t const *known_good, fr_pair_t const *password) \
{ \
	return _func(p_result, inst, request, known_good, password, _name, _md); \
}

PAP_AUTH_EVP_MD(pap_auth_evp_md, pap_auth_sha2_224, "SHA2-224", EVP_sha224())
PAP_AUTH_EVP_MD(pap_auth_evp_md, pap_auth_sha2_256, "SHA2-256", EVP_sha256())
PAP_AUTH_EVP_MD(pap_auth_evp_md, pap_auth_sha2_384, "SHA2-384", EVP_sha384())
PAP_AUTH_EVP_MD(pap_auth_evp_md, pap_auth_sha2_512, "SHA2-512", EVP_sha512())
PAP_AUTH_EVP_MD(pap_auth_evp_md_salted, pap_auth_ssha2_224, "SSHA2-224", EVP_sha224())
PAP_AUTH_EVP_MD(pap_auth_evp_md_salted, pap_auth_ssha2_256, "SSHA2-256", EVP_sha256())
PAP_AUTH_EVP_MD(pap_auth_evp_md_salted, pap_auth_ssha2_384, "SSHA2-384", EVP_sha384())
PAP_AUTH_EVP_MD(pap_auth_evp_md_salted, pap_auth_ssha2_512, "SSHA2-512", EVP_sha512())

#  if OPENSSL_VERSION_NUMBER >= 0x10101000L
PAP_AUTH_EVP_MD(pap_auth_evp_md, pap_auth_sha3_224, "SHA3-224", EVP_sha3_224())
PAP_AUTH_EVP_MD(pap_auth_evp_md, pap_auth_sha3_256, "SHA3-256", EVP_sha3_256())
PAP_AUTH_EVP_MD(pap_auth_evp_md, pap_auth_sha3_384, "SHA3-384", EVP_sha3_384())
PAP_AUTH_EVP_MD(pap_auth_evp_md, pap_auth_sha3_512, "SHA3-512", EVP_sha3_512())
PAP_AUTH_EVP_MD(pap_auth_evp_md_salted, pap_auth_ssha3_224, "SSHA3-224", EVP_sha3_224())
PAP_AUTH_EVP_MD(pap_auth_evp_md_salted, pap_auth_ssha3_256, "SSHA3-256", EVP_sha3_256())
PAP_AUTH_EVP_MD(pap_auth_evp_md_salted, pap_auth_ssha3_384, "SSHA3-384", EVP_sha3_384())
PAP_AUTH_EVP_MD(pap_auth_evp_md_salted, pap_auth_ssha3_512, "SSHA3-512", EVP_sha3_512())
#  endif

/** Validates Crypt::PBKDF2 LDAP format strings
 *
 * @param[out] p_result		The result of comparing the pbkdf2 hash with the password.
 * @param[in] request		The current request.
 * @param[in] str		Raw PBKDF2 string.
 * @param[in] len		Length of string.
 * @param[in] hash_names	Table containing valid hash names.
 * @param[in] hash_names_len	How long the table is.
 * @param[in] scheme_sep	Separation character between the scheme and the next component.
 * @param[in] iter_sep		Separation character between the iterations and the next component.
 * @param[in] salt_sep		Separation character between the salt and the next component.
 * @param[in] iter_is_base64	Whether the iterations is are encoded as base64.
 * @param[in] password		to validate.
 * @return
 *	- RLM_MODULE_REJECT
 *	- RLM_MODULE_OK
 */
static inline CC_HINT(nonnull) unlang_action_t pap_auth_pbkdf2_parse(rlm_rcode_t *p_result,
								     request_t *request, const uint8_t *str, size_t len,
								     fr_table_num_sorted_t const hash_names[], size_t hash_names_len,
								     char scheme_sep, char iter_sep, char salt_sep,
								     bool iter_is_base64, fr_pair_t const *password)
{
	rlm_rcode_t		rcode = RLM_MODULE_INVALID;

	uint8_t const		*p, *q, *end;
	ssize_t			slen;

	EVP_MD const		*evp_md;
	int			digest_type;
	size_t			digest_len;

	uint32_t		iterations;

	uint8_t			*salt = NULL;
	size_t			salt_len;
	uint8_t			hash[EVP_MAX_MD_SIZE];
	uint8_t			digest[EVP_MAX_MD_SIZE];

	RDEBUG2("Comparing with \"known-good\" PBKDF2-Password");

	if (len <= 1) {
		REDEBUG("PBKDF2-Password is too short");
		goto finish;
	}

	/*
	 *	Parse PBKDF string = {hash_algorithm}<scheme_sep><iterations><iter_sep>b64(<salt>)<salt_sep>b64(<hash>)
	 */
	p = str;
	end = p + len;

	q = memchr(p, scheme_sep, end - p);
	if (!q) {
		REDEBUG("PBKDF2-Password has no component separators");
		goto finish;
	}

	digest_type = fr_table_value_by_substr(hash_names, (char const *)p, q - p, -1);
	switch (digest_type) {
	case FR_SSHA1:
		evp_md = EVP_sha1();
		digest_len = SHA1_DIGEST_LENGTH;
		break;

	case FR_SSHA2_224:
		evp_md = EVP_sha224();
		digest_len = SHA224_DIGEST_LENGTH;
		break;

	case FR_SSHA2_256:
		evp_md = EVP_sha256();
		digest_len = SHA256_DIGEST_LENGTH;
		break;

	case FR_SSHA2_384:
		evp_md = EVP_sha384();
		digest_len = SHA384_DIGEST_LENGTH;
		break;

	case FR_SSHA2_512:
		evp_md = EVP_sha512();
		digest_len = SHA512_DIGEST_LENGTH;
		break;

#  if OPENSSL_VERSION_NUMBER >= 0x10101000L
	case FR_SSHA3_224:
		evp_md = EVP_sha3_224();
		digest_len = SHA224_DIGEST_LENGTH;
		break;

	case FR_SSHA3_256:
		evp_md = EVP_sha3_256();
		digest_len = SHA256_DIGEST_LENGTH;
		break;

	case FR_SSHA3_384:
		evp_md = EVP_sha3_384();
		digest_len = SHA384_DIGEST_LENGTH;
		break;

	case FR_SSHA3_512:
		evp_md = EVP_sha3_512();
		digest_len = SHA512_DIGEST_LENGTH;
		break;
#  endif

	default:
		REDEBUG("Unknown PBKDF2 hash method \"%.*s\"", (int)(q - p), p);
		goto finish;
	}

	p = q + 1;

	if (((end - p) < 1) || !(q = memchr(p, iter_sep, end - p))) {
		REDEBUG("PBKDF2-Password missing iterations component");
		goto finish;
	}

	if ((q - p) == 0) {
		REDEBUG("PBKDF2-Password iterations component too short");
		goto finish;
	}

	/*
	 *	If it's not base64 encoded, assume it's ascii
	 */
	if (!iter_is_base64) {
		char iterations_buff[sizeof("4294967295") + 1];
		char *qq;

		strlcpy(iterations_buff, (char const *)p, (q - p) + 1);

		iterations = strtoul(iterations_buff, &qq, 10);
		if (*qq != '\0') {
			REMARKER(iterations_buff, qq - iterations_buff,
				 "PBKDF2-Password iterations field contains an invalid character");

			goto finish;
		}
		p = q + 1;
	/*
	 *	base64 encoded and big endian
	 */
	} else {
		(void)fr_strerror();
		slen = fr_base64_decode((uint8_t *)&iterations, sizeof(iterations), (char const *)p, q - p);
		if (slen < 0) {
			RPEDEBUG("Failed decoding PBKDF2-Password iterations component (%.*s)", (int)(q - p), p);
			goto finish;
		}
		if (slen != sizeof(iterations)) {
			REDEBUG("Decoded PBKDF2-Password iterations component is wrong size");
		}

		iterations = ntohl(iterations);

		p = q + 1;
	}

	if (((end - p) < 1) || !(q = memchr(p, salt_sep, end - p))) {
		REDEBUG("PBKDF2-Password missing salt component");
		goto finish;
	}

	if ((q - p) == 0) {
		REDEBUG("PBKDF2-Password salt component too short");
		goto finish;
	}

	MEM(salt = talloc_array(request, uint8_t, FR_BASE64_DEC_LENGTH(q - p)));
	slen = fr_base64_decode(salt, talloc_array_length(salt), (char const *) p, q - p);
	if (slen < 0) {
		RPEDEBUG("Failed decoding PBKDF2-Password salt component");
		goto finish;
	}
	salt_len = (size_t)slen;

	p = q + 1;

	if ((q - p) == 0) {
		REDEBUG("PBKDF2-Password hash component too short");
		goto finish;
	}

	slen = fr_base64_decode(hash, sizeof(hash), (char const *)p, end - p);
	if (slen < 0) {
		RPEDEBUG("Failed decoding PBKDF2-Password hash component");
		goto finish;
	}

	if ((size_t)slen != digest_len) {
		REDEBUG("PBKDF2-Password hash component length is incorrect for hash type, expected %zu, got %zd",
			digest_len, slen);

		RHEXDUMP2(hash, slen, "hash component");

		goto finish;
	}

	RDEBUG2("PBKDF2 %s: Iterations %u, salt length %zu, hash length %zd",
		fr_table_str_by_value(pbkdf2_crypt_names, digest_type, "<UNKNOWN>"),
		iterations, salt_len, slen);

	/*
	 *	Hash and compare
	 */
	if (PKCS5_PBKDF2_HMAC((char const *)password->vp_octets, (int)password->vp_length,
			      (unsigned char const *)salt, (int)salt_len,
			      (int)iterations,
			      evp_md,
			      (int)digest_len, (unsigned char *)digest) == 0) {
		REDEBUG("PBKDF2 digest failure");
		goto finish;
	}

	if (fr_digest_cmp(digest, hash, (size_t)digest_len) != 0) {
		REDEBUG("PBKDF2 digest does not match \"known good\" digest");
		REDEBUG3("Salt       : %pH", fr_box_octets(salt, salt_len));
		REDEBUG3("Calculated : %pH", fr_box_octets(digest, digest_len));
		REDEBUG3("Expected   : %pH", fr_box_octets(hash, slen));
		rcode = RLM_MODULE_REJECT;
	} else {
		rcode = RLM_MODULE_OK;
	}

finish:
	talloc_free(salt);

	RETURN_MODULE_RCODE(rcode);
}

static inline unlang_action_t CC_HINT(nonnull) pap_auth_pbkdf2(rlm_rcode_t *p_result,
							       UNUSED rlm_pap_t const *inst,
							       request_t *request,
							       fr_pair_t const *known_good, fr_pair_t const *password)
{
	uint8_t const *p = known_good->vp_octets, *q, *end = p + known_good->vp_length;

	if (end - p < 2) {
		REDEBUG("PBKDF2-Password too short");
		RETURN_MODULE_INVALID;
	}

	/*
	 *	If it doesn't begin with a $ assume
	 *	It's Crypt::PBKDF2 LDAP format
	 *
	 *	{X-PBKDF2}<digest>:<b64 rounds>:<b64_salt>:<b64_hash>
	 */
	if (*p != '$') {
		/*
		 *	Strip the header if it's present
		 */
		if (*p == '{') {
			q = memchr(p, '}', end - p);
			p = q + 1;
		}
		return pap_auth_pbkdf2_parse(p_result, request, p, end - p,
					     pbkdf2_crypt_names, pbkdf2_crypt_names_len,
					     ':', ':', ':', true, password);
	}

	/*
	 *	Crypt::PBKDF2 Crypt format
	 *
	 *	$PBKDF2$<digest>:<rounds>:<b64_salt>$<b64_hash>
	 */
	if ((size_t)(end - p) >= sizeof("$PBKDF2$") && (memcmp(p, "$PBKDF2$", sizeof("$PBKDF2$") - 1) == 0)) {
		p += sizeof("$PBKDF2$") - 1;
		return pap_auth_pbkdf2_parse(p_result, request, p, end - p,
					     pbkdf2_crypt_names, pbkdf2_crypt_names_len,
					     ':', ':', '$', false, password);
	}

	/*
	 *	Python's passlib format
	 *
	 *	$pbkdf2-<digest>$<rounds>$<alt_b64_salt>$<alt_b64_hash>
	 *
	 *	Note: Our base64 functions also work with alt_b64
	 */
	if ((size_t)(end - p) >= sizeof("$pbkdf2-") && (memcmp(p, "$pbkdf2-", sizeof("$pbkdf2-") - 1) == 0)) {
		p += sizeof("$pbkdf2-") - 1;
		return pap_auth_pbkdf2_parse(p_result, request, p, end - p,
					     pbkdf2_passlib_names, pbkdf2_passlib_names_len,
					     '$', '$', '$', false, password);
	}

	REDEBUG("Can't determine format of PBKDF2-Password");

	RETURN_MODULE_INVALID;
}
#endif

static unlang_action_t CC_HINT(nonnull) pap_auth_nt(rlm_rcode_t *p_result,
						    UNUSED rlm_pap_t const *inst, request_t *request,
						    fr_pair_t const *known_good, fr_pair_t const *password)
{
	ssize_t len;
	uint8_t digest[MD4_DIGEST_LENGTH];
	uint8_t ucs2[512];

	RDEBUG2("Comparing with \"known-good\" NT-Password");

	fr_assert(password->da == attr_user);

	if (known_good->vp_length != MD4_DIGEST_LENGTH) {
		REDEBUG("\"known good\" NT-Password has incorrect length, expected 16 got %zu", known_good->vp_length);
		RETURN_MODULE_INVALID;
	}

	len = fr_utf8_to_ucs2(ucs2, sizeof(ucs2),
			      password->vp_strvalue, password->vp_length);
	if (len < 0) {
		REDEBUG("User-Password is not in UCS2 format");
		RETURN_MODULE_INVALID;
	}

	fr_md4_calc(digest, (uint8_t *)ucs2, len);

	if (fr_digest_cmp(digest, known_good->vp_octets, known_good->vp_length) != 0) {
		REDEBUG("NT digest does not match \"known good\" digest");
		REDEBUG3("Calculated : %pH", fr_box_octets(digest, sizeof(digest)));
		REDEBUG3("Expected   : %pH", &known_good->data);
		RETURN_MODULE_REJECT;
	}

	RETURN_MODULE_OK;
}

static unlang_action_t CC_HINT(nonnull) pap_auth_lm(rlm_rcode_t *p_result,
						    UNUSED rlm_pap_t const *inst, request_t *request,
						    fr_pair_t const *known_good, UNUSED fr_pair_t const *password)
{
	uint8_t	digest[MD4_DIGEST_LENGTH];
	char	charbuf[32 + 1];
	ssize_t	len;

	RDEBUG2("Comparing with \"known-good\" LM-Password");

	if (known_good->vp_length != MD4_DIGEST_LENGTH) {
		REDEBUG("\"known good\" LM-Password has incorrect length, expected 16 got %zu", known_good->vp_length);
		RETURN_MODULE_INVALID;
	}

	len = xlat_eval(charbuf, sizeof(charbuf), request, "%{mschap:LM-Hash %{User-Password}}", NULL, NULL);
	if (len < 0) RETURN_MODULE_FAIL;

	if ((fr_hex2bin(NULL, &FR_DBUFF_TMP(digest, sizeof(digest)), &FR_SBUFF_IN(charbuf, len), false) !=
	     (ssize_t)known_good->vp_length) ||
	    (fr_digest_cmp(digest, known_good->vp_octets, known_good->vp_length) != 0)) {
		REDEBUG("LM digest does not match \"known good\" digest");
		REDEBUG3("Calculated : %pH", fr_box_octets(digest, sizeof(digest)));
		REDEBUG3("Expected   : %pH", &known_good->data);
		RETURN_MODULE_REJECT;
	}

	RETURN_MODULE_OK;
}

static unlang_action_t CC_HINT(nonnull) pap_auth_ns_mta_md5(rlm_rcode_t *p_result,
							    UNUSED rlm_pap_t const *inst, request_t *request,
							    fr_pair_t const *known_good, fr_pair_t const *password)
{
	uint8_t digest[128];
	uint8_t buff[FR_MAX_STRING_LEN];
	uint8_t buff2[FR_MAX_STRING_LEN + 50];

	RDEBUG2("Using NT-MTA-MD5-Password");

	if (known_good->vp_length != 64) {
		REDEBUG("\"known good\" NS-MTA-MD5-Password has incorrect length, expected 64 got %zu",
			known_good->vp_length);
		RETURN_MODULE_INVALID;
	}

	/*
	 *	Sanity check the value of NS-MTA-MD5-Password
	 */
	if (fr_hex2bin(NULL, &FR_DBUFF_TMP(digest, sizeof(digest)),
		       &FR_SBUFF_IN(known_good->vp_strvalue, known_good->vp_length), false) != 16) {
		REDEBUG("\"known good\" NS-MTA-MD5-Password has invalid value");
		RETURN_MODULE_INVALID;
	}

	/*
	 *	Ensure we don't have buffer overflows.
	 *
	 *	This really: sizeof(buff) - 2 - 2*32 - strlen(passwd)
	 */
	if (password->vp_length >= (sizeof(buff) - 2 - 2 * 32)) {
		REDEBUG("\"known good\" NS-MTA-MD5-Password is too long");
		RETURN_MODULE_INVALID;
	}

	/*
	 *	Set up the algorithm.
	 */
	{
		uint8_t *p = buff2;

		memcpy(p, &known_good->vp_octets[32], 32);
		p += 32;
		*(p++) = 89;
		memcpy(p, password->vp_strvalue, password->vp_length);
		p += password->vp_length;
		*(p++) = 247;
		memcpy(p, &known_good->vp_octets[32], 32);
		p += 32;

		fr_md5_calc(buff, (uint8_t *) buff2, p - buff2);
	}

	if (fr_digest_cmp(digest, buff, 16) != 0) {
		REDEBUG("NS-MTA-MD5 digest does not match \"known good\" digest");
		RETURN_MODULE_REJECT;
	}

	RETURN_MODULE_OK;
}

/** Auth func for password types that should have been normalised away
 *
 */
static unlang_action_t CC_HINT(nonnull) pap_auth_dummy(rlm_rcode_t *p_result,
						       UNUSED rlm_pap_t const *inst, UNUSED request_t *request,
						       UNUSED fr_pair_t const *known_good, UNUSED fr_pair_t const *password)
{
	RETURN_MODULE_FAIL;
}

/** Table of password types we can process
 *
 */
static const pap_auth_func_t auth_func_table[] = {
	[FR_CLEARTEXT]	= pap_auth_clear,
	[FR_LM]	= pap_auth_lm,
	[FR_MD5]	= pap_auth_md5,
	[FR_SMD5]	= pap_auth_smd5,

#ifdef HAVE_CRYPT
	[FR_CRYPT]	= pap_auth_crypt,
#endif
	[FR_NS_MTA_MD5] = pap_auth_ns_mta_md5,
	[FR_NT]	= pap_auth_nt,
	[FR_WITH_HEADER] = pap_auth_dummy,
	[FR_SHA1]	= pap_auth_sha1,
	[FR_SSHA1]	= pap_auth_ssha1,

#ifdef HAVE_OPENSSL_EVP_H
	[FR_PBKDF2]	= pap_auth_pbkdf2,
	[FR_SHA2]	= pap_auth_dummy,
	[FR_SHA2_224]	= pap_auth_sha2_224,
	[FR_SHA2_256]	= pap_auth_sha2_256,
	[FR_SHA2_384]	= pap_auth_sha2_384,
	[FR_SHA2_512]	= pap_auth_sha2_512,
	[FR_SSHA2_224]	= pap_auth_ssha2_224,
	[FR_SSHA2_256]	= pap_auth_ssha2_256,
	[FR_SSHA2_384]	= pap_auth_ssha2_384,
	[FR_SSHA2_512]	= pap_auth_ssha2_512,

#  if OPENSSL_VERSION_NUMBER >= 0x10101000L
	[FR_SHA3]	= pap_auth_dummy,
	[FR_SHA3_224]	= pap_auth_sha3_224,
	[FR_SHA3_256]	= pap_auth_sha3_256,
	[FR_SHA3_384]	= pap_auth_sha3_384,
	[FR_SHA3_512]	= pap_auth_sha3_512,
	[FR_SSHA3_224]	= pap_auth_ssha3_224,
	[FR_SSHA3_256]	= pap_auth_ssha3_256,
	[FR_SSHA3_384]	= pap_auth_ssha3_384,
	[FR_SSHA3_512]	= pap_auth_ssha3_512,
#  endif
#endif	/* HAVE_OPENSSL_EVP_H */
};

/*
 *	Authenticate the user via one of any well-known password.
 */
static unlang_action_t CC_HINT(nonnull) mod_authenticate(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_pap_t const 	*inst = talloc_get_type_abort_const(mctx->instance, rlm_pap_t);
	fr_pair_t		*known_good;
	fr_pair_t		*password;
	rlm_rcode_t		rcode = RLM_MODULE_INVALID;
	pap_auth_func_t		auth_func;
	bool			ephemeral;

	password = fr_pair_find_by_da(&request->request_pairs, attr_user);
	if (!password) {
		REDEBUG("You set 'Auth-Type = PAP' for a request that does not contain a User-Password attribute!");
		RETURN_MODULE_INVALID;
	}

	/*
	 *	The user MUST supply a non-zero-length password.
	 */
	if (password->vp_length == 0) {
		REDEBUG("Password must not be empty");
		RETURN_MODULE_INVALID;
	}

	if (RDEBUG_ENABLED3) {
		RDEBUG3("Login attempt with %pP (%zd)", password, password->vp_length);
	} else {
		RDEBUG2("Login attempt with password");
	}

	/*
	 *	Retrieve the normalised version of
	 *	the known_good password, without
	 *	mangling the current password attributes
	 *	in the request.
	 */
	known_good = password_find(&ephemeral, request, request,
				   pap_alloweds, talloc_array_length(pap_alloweds),
				   inst->normify);
	if (!known_good) {
		REDEBUG("No \"known good\" password found for user");
		RETURN_MODULE_FAIL;
	}

	fr_assert(known_good->da->attr < NUM_ELEMENTS(auth_func_table));

	auth_func = auth_func_table[known_good->da->attr];
	fr_assert(auth_func);

	if (RDEBUG_ENABLED3) {
		RDEBUG3("Comparing with \"known good\" %pP (%zu)", known_good, known_good->vp_length);
	} else {
		RDEBUG2("Comparing with \"known-good\" %s (%zu)", known_good->da->name, known_good->vp_length);
	}

	/*
	 *	Authenticate, and return.
	 */
	auth_func(&rcode, inst, request, known_good, password);
	if (ephemeral) talloc_list_free(&known_good);
	switch (rcode) {
	case RLM_MODULE_REJECT:
		REDEBUG("Password incorrect");
		break;

	case RLM_MODULE_OK:
		RDEBUG2("User authenticated successfully");
		break;

	default:
		break;
	}

	RETURN_MODULE_RCODE(rcode);
}

static int mod_bootstrap(void *instance, CONF_SECTION *conf)
{
	char const		*name;
	rlm_pap_t		*inst = instance;

	/*
	 *	Create the dynamic translation.
	 */
	name = cf_section_name2(conf);
	if (!name) name = cf_section_name1(conf);
	inst->name = name;

	return 0;
}

static int mod_instantiate(void *instance, UNUSED CONF_SECTION *cs)
{
	rlm_pap_t	*inst = talloc_get_type_abort(instance, rlm_pap_t);

	inst->auth_type = fr_dict_enum_by_name(attr_auth_type, inst->name, -1);
	if (!inst->auth_type) {
		WARN("Failed to find 'authenticate %s {...}' section.  PAP will likely not work",
		     inst->name);
	}

	return 0;
}

static int mod_load(void)
{
	size_t	i, j = 0;
	size_t	allowed = 0;

	/*
	 *	Load the dictionaries early
	 */
	if (fr_dict_autoload(rlm_pap_dict) < 0) {
		PERROR("%s", __FUNCTION__);
		return -1;
	}
	if (fr_dict_attr_autoload(rlm_pap_dict_attr) < 0) {
		PERROR("%s", __FUNCTION__);
		fr_dict_autofree(rlm_pap_dict);
		return -1;
	}

	/*
	 *	Figure out how many password types we allow
	 */
	for (i = 0; i < NUM_ELEMENTS(auth_func_table); i++) {
		if (auth_func_table[i] == NULL) continue;

		allowed++;
	}

	/*
	 *	Get a list of the DAs that match are allowed
	 *	functions.
	 */
	pap_alloweds = talloc_array(NULL, fr_dict_attr_t const *, allowed);
	for (i = 0; i < NUM_ELEMENTS(auth_func_table); i++) {
		fr_dict_attr_t const *password_da;

		if (auth_func_table[i] == NULL) continue;

		password_da = fr_dict_attr_child_by_num(attr_root, i);
		if (!fr_cond_assert(password_da)) {
			ERROR("Could not resolve password attribute %zu", i);
			talloc_free(pap_alloweds);
			return -1;
		}

		pap_alloweds[j++] = password_da;
	}

	return 0;
}

static void mod_unload(void)
{
	talloc_free(pap_alloweds);
	fr_dict_autofree(rlm_pap_dict);
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern module_t rlm_pap;
module_t rlm_pap = {
	.magic		= RLM_MODULE_INIT,
	.name		= "pap",
	.inst_size	= sizeof(rlm_pap_t),
	.onload		= mod_load,
	.unload		= mod_unload,
	.config		= module_config,
	.bootstrap	= mod_bootstrap,
	.instantiate	= mod_instantiate,
	.methods = {
		[MOD_AUTHENTICATE]	= mod_authenticate,
		[MOD_AUTHORIZE]		= mod_authorize
	},
};
