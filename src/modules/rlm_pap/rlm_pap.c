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
 * @copyright 2001-2012  The FreeRADIUS server project.
 * @copyright 2012       Matthew Newton <matthew@newtoncomputing.co.uk>
 * @copyright 2001       Kostas Kalevras <kkalev@noc.ntua.gr>
 */
RCSID("$Id$")
USES_APPLE_DEPRECATED_API

#include <ctype.h>

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/modules.h>
#include <freeradius-devel/util/base64.h>
#include <freeradius-devel/server/rad_assert.h>

#include <freeradius-devel/util/md5.h>
#include <freeradius-devel/util/sha1.h>
#include <freeradius-devel/tls/base.h>

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
typedef struct rlm_pap_t {
	char const		*name;
	fr_dict_enum_t		*auth_type;
	bool			normify;
} rlm_pap_t;

static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("normalise", FR_TYPE_BOOL, rlm_pap_t, normify), .dflt = "yes" },
	CONF_PARSER_TERMINATOR
};

static fr_dict_t *dict_freeradius;
static fr_dict_t *dict_radius;

extern fr_dict_autoload_t rlm_pap_dict[];
fr_dict_autoload_t rlm_pap_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_auth_type;
static fr_dict_attr_t const *attr_proxy_to_realm;
static fr_dict_attr_t const *attr_realm;

static fr_dict_attr_t const *attr_password_with_header;
static fr_dict_attr_t const *attr_cleartext_password;

static fr_dict_attr_t const *attr_md5_password;
static fr_dict_attr_t const *attr_smd5_password;
static fr_dict_attr_t const *attr_crypt_password;
static fr_dict_attr_t const *attr_sha_password;
static fr_dict_attr_t const *attr_ssha_password;

static fr_dict_attr_t const *attr_sha2_password;
static fr_dict_attr_t const *attr_ssha2_224_password;
static fr_dict_attr_t const *attr_ssha2_256_password;
static fr_dict_attr_t const *attr_ssha2_384_password;
static fr_dict_attr_t const *attr_ssha2_512_password;

static fr_dict_attr_t const *attr_sha3_password;
static fr_dict_attr_t const *attr_ssha3_224_password;
static fr_dict_attr_t const *attr_ssha3_256_password;
static fr_dict_attr_t const *attr_ssha3_384_password;
static fr_dict_attr_t const *attr_ssha3_512_password;

static fr_dict_attr_t const *attr_pbkdf2_password;
static fr_dict_attr_t const *attr_lm_password;
static fr_dict_attr_t const *attr_nt_password;
static fr_dict_attr_t const *attr_ns_mta_md5_password;

static fr_dict_attr_t const *attr_user_password;

extern fr_dict_attr_autoload_t rlm_pap_dict_attr[];
fr_dict_attr_autoload_t rlm_pap_dict_attr[] = {
	{ .out = &attr_auth_type, .name = "Auth-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_proxy_to_realm, .name = "Proxy-To-Realm", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_realm, .name = "Realm", .type = FR_TYPE_STRING, .dict = &dict_freeradius },

	{ .out = &attr_password_with_header, .name = "Password-With-Header", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_cleartext_password, .name = "Cleartext-Password", .type = FR_TYPE_STRING, .dict = &dict_freeradius },

	{ .out = &attr_md5_password, .name = "MD5-Password", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_smd5_password, .name = "SMD5-Password", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_crypt_password, .name = "Crypt-Password", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_sha_password, .name = "SHA-Password", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_ssha_password, .name = "SSHA-Password", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },

	{ .out = &attr_sha2_password, .name = "SHA2-Password", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_ssha2_224_password, .name = "SSHA2-224-Password", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_ssha2_256_password, .name = "SSHA2-256-Password", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_ssha2_384_password, .name = "SSHA2-384-Password", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_ssha2_512_password, .name = "SSHA2-512-Password", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },

	{ .out = &attr_sha3_password, .name = "SHA3-Password", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_ssha3_224_password, .name = "SSHA3-224-Password", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_ssha3_256_password, .name = "SSHA3-256-Password", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_ssha3_384_password, .name = "SSHA3-384-Password", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_ssha3_512_password, .name = "SSHA3-512-Password", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },

	{ .out = &attr_pbkdf2_password, .name = "PBKDF2-Password", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_lm_password, .name = "LM-Password", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_nt_password, .name = "NT-Password", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_ns_mta_md5_password, .name = "NS-MTA-MD5-Password", .type = FR_TYPE_STRING, .dict = &dict_freeradius },

	{ .out = &attr_user_password, .name = "User-Password", .type = FR_TYPE_STRING, .dict = &dict_radius },

	{ NULL }
};

/*
 *	For auto-header discovery.
 *
 *	@note Header comparison is case insensitive.
 */
static const FR_NAME_NUMBER header_names[] = {
	{ "{clear}",		FR_CLEARTEXT_PASSWORD },
	{ "{cleartext}",	FR_CLEARTEXT_PASSWORD },
	{ "{md5}",		FR_MD5_PASSWORD },
	{ "{base64_md5}",	FR_MD5_PASSWORD },
	{ "{smd5}",		FR_SMD5_PASSWORD },
	{ "{crypt}",		FR_CRYPT_PASSWORD },
#ifdef HAVE_OPENSSL_EVP_H
	{ "{sha2}",		FR_SHA2_PASSWORD },
	{ "{sha224}",		FR_SHA2_PASSWORD },
	{ "{sha256}",		FR_SHA2_PASSWORD },
	{ "{sha384}",		FR_SHA2_PASSWORD },
	{ "{sha512}",		FR_SHA2_PASSWORD },
	{ "{ssha224}",		FR_SSHA2_224_PASSWORD },
	{ "{ssha256}",		FR_SSHA2_256_PASSWORD },
	{ "{ssha384}",		FR_SSHA2_384_PASSWORD },
	{ "{ssha512}",		FR_SSHA2_512_PASSWORD },
#  ifdef HAVE_EVP_SHA3_512
	{ "{ssha3-224}",	FR_SSHA3_224_PASSWORD },
	{ "{ssha3-256}",	FR_SSHA3_256_PASSWORD },
	{ "{ssha3-384}",	FR_SSHA3_384_PASSWORD },
	{ "{ssha3-512}",	FR_SSHA3_512_PASSWORD },
#  endif
	{ "{x-pbkdf2}",		FR_PBKDF2_PASSWORD },
#endif
	{ "{sha}",		FR_SHA_PASSWORD },
	{ "{ssha}",		FR_SSHA_PASSWORD },
	{ "{md4}",		FR_NT_PASSWORD },
	{ "{nt}",		FR_NT_PASSWORD },
	{ "{nthash}",		FR_NT_PASSWORD },
	{ "{x-nthash}",		FR_NT_PASSWORD },
	{ "{ns-mta-md5}",	FR_NS_MTA_MD5_PASSWORD },
	{ "{x- orcllmv}",	FR_LM_PASSWORD },
	{ "{X- orclntv}",	FR_NT_PASSWORD },
	{ NULL, 0 }
};

#ifdef HAVE_OPENSSL_EVP_H
static const FR_NAME_NUMBER pbkdf2_crypt_names[] = {
	{ "HMACSHA1",		FR_SSHA_PASSWORD },
	{ "HMACSHA2+224",	FR_SSHA2_224_PASSWORD },
	{ "HMACSHA2+256",	FR_SSHA2_256_PASSWORD },
	{ "HMACSHA2+384",	FR_SSHA2_384_PASSWORD },
	{ "HMACSHA2+512",	FR_SSHA2_512_PASSWORD },
#  ifdef HAVE_EVP_SHA3_512
	{ "HMACSHA3+224",	FR_SSHA3_224_PASSWORD },
	{ "HMACSHA3+256",	FR_SSHA3_256_PASSWORD },
	{ "HMACSHA3+384",	FR_SSHA3_384_PASSWORD },
	{ "HMACSHA3+512",	FR_SSHA3_512_PASSWORD },
#  endif
	{ NULL, 0 }
};

static const FR_NAME_NUMBER pbkdf2_passlib_names[] = {
	{ "sha1",		FR_SSHA_PASSWORD },
	{ "sha256",		FR_SSHA2_256_PASSWORD },
	{ "sha512",		FR_SSHA2_512_PASSWORD },

	{ NULL, 0 }
};
#endif

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
 * @param[in] request Current request.
 * @param[in,out] vp to normify.
 * @param[in] min_len we expect the decoded version to be.
 */
static void normify(REQUEST *request, VALUE_PAIR *vp, size_t min_len)
{
	uint8_t buffer[256];

	if (min_len >= sizeof(buffer)) return; /* paranoia */

	rad_assert((vp->da->type == FR_TYPE_OCTETS) || (vp->da->type == FR_TYPE_STRING));

	/*
	 *	Hex encoding. Length is even, and it's greater than
	 *	twice the minimum length.
	 */
	if (!(vp->vp_length & 0x01) && vp->vp_length >= (2 * min_len)) {
		size_t decoded;

		decoded = fr_hex2bin(buffer, sizeof(buffer), vp->vp_strvalue, vp->vp_length);
		if (decoded == (vp->vp_length >> 1)) {
			RDEBUG2("Normalizing %s from hex encoding, %zu bytes -> %zu bytes",
				vp->da->name, vp->vp_length, decoded);
			fr_pair_value_memcpy(vp, buffer, decoded);
			return;
		}
	}

	/*
	 *	Base 64 encoding.  It's at least 4/3 the original size,
	 *	and we want to avoid division...
	 */
	if ((vp->vp_length * 3) >= ((min_len * 4))) {
		ssize_t decoded;
		decoded = fr_base64_decode(buffer, sizeof(buffer), vp->vp_strvalue, vp->vp_length);
		if (decoded < 0) return;
		if (decoded >= (ssize_t) min_len) {
			RDEBUG2("Normalizing %s from base64 encoding, %zu bytes -> %zu bytes",
				vp->da->name, vp->vp_length, decoded);
			fr_pair_value_memcpy(vp, buffer, decoded);
			return;
		}
	}

	/*
	 *	Else unknown encoding, or already binary.  Leave it.
	 */
}

/** Convert a Password-With-Header attribute to the correct type
 *
 * Attribute may be base64 encoded, in which case it will be decoded
 * first, then evaluated.
 *
 * @note The buffer for octets types\ attributes is extended by one byte
 *	and '\0' terminated, to allow it to be used as a char buff.
 *
 * @param[in] ctx to allocate new attributes in.
 * @param[in] request Current request.
 * @param[in] vp Password-With-Header attribute to convert.
 * @return
 *	- New #VALUE_PAIR on success.
 *	- NULL on error.
 */
static VALUE_PAIR *normify_with_header(TALLOC_CTX *ctx, REQUEST *request, VALUE_PAIR *vp)
{
	char const	*p, *q;
	size_t		len;

	uint8_t		digest[256];
	ssize_t		decoded;

	char		buffer[256];

	VALUE_PAIR	*new;

	VP_VERIFY(vp);

	/*
	 *	Ensure this is only ever called with a
	 *	string type attribute.
	 */
	rad_assert(vp->da->type == FR_TYPE_STRING);

redo:
	p = vp->vp_strvalue;
	len = vp->vp_length;

	/*
	 *	Has a header {...} prefix
	 */
	q = strchr(p, '}');
	if (q) {
		size_t			hlen;
		fr_dict_attr_t const	*da;

		hlen = (q + 1) - p;
		if (hlen >= sizeof(buffer)) {
			REDEBUG("Password header too long.  Got %zu bytes must be less than %zu bytes",
				hlen, sizeof(buffer));
			return NULL;
		}

		memcpy(buffer, p, hlen);
		buffer[hlen] = '\0';

		/*
		 *	The data after the '}' may be binary, so we copy it via
		 *	memcpy.  BUT it might be a string (or used as one), so
		 *	we ensure that there's a trailing zero, too.
		 */
		switch (fr_str2int(header_names, buffer, 0)) {
		case FR_CLEARTEXT_PASSWORD:
			da = attr_cleartext_password;
			break;

		case FR_MD5_PASSWORD:
			da = attr_md5_password;
			break;

		case FR_SMD5_PASSWORD:
			da = attr_smd5_password;
			break;

		case FR_CRYPT_PASSWORD:
			da = attr_crypt_password;
			break;

		case FR_SHA2_PASSWORD:
			da = attr_sha2_password;
			break;

		case FR_SSHA2_224_PASSWORD:
			da = attr_ssha2_224_password;
			break;

		case FR_SSHA2_256_PASSWORD:
			da = attr_ssha2_256_password;
			break;

		case FR_SSHA2_384_PASSWORD:
			da = attr_ssha2_384_password;
			break;

		case FR_SSHA2_512_PASSWORD:
			da = attr_ssha2_512_password;
			break;

		case FR_SSHA3_224_PASSWORD:
			da = attr_ssha3_224_password;
			break;

		case FR_SSHA3_256_PASSWORD:
			da = attr_ssha3_256_password;
			break;

		case FR_SSHA3_384_PASSWORD:
			da = attr_ssha3_384_password;
			break;

		case FR_SSHA3_512_PASSWORD:
			da = attr_ssha3_512_password;
			break;

		case FR_PBKDF2_PASSWORD:
			da = attr_pbkdf2_password;
			break;

		case FR_SHA_PASSWORD:
			da = attr_sha_password;
			break;

		case FR_SSHA_PASSWORD:
			da = attr_ssha_password;
			break;

		case FR_NS_MTA_MD5_PASSWORD:
			da = attr_ns_mta_md5_password;
			break;

		case FR_LM_PASSWORD:
			da = attr_lm_password;
			break;

		case FR_NT_PASSWORD:
			da = attr_nt_password;
			break;

		default:
			if (RDEBUG_ENABLED3) {
				RDEBUG3("Unknown header {%s} in Password-With-Header = \"%s\", re-writing to "
					"Cleartext-Password", buffer, vp->vp_strvalue);
			} else {
				RDEBUG("Unknown header {%s} in Password-With-Header, re-writing to "
				       "Cleartext-Password", buffer);
			}
			goto unknown_header;
		}

		new = fr_pair_afrom_da(ctx, da);
		switch (da->type) {
		case FR_TYPE_OCTETS:
			fr_pair_value_memcpy(new, (uint8_t const *)q + 1, len - hlen);
			break;

		case FR_TYPE_STRING:
			fr_pair_value_bstrncpy(new, (uint8_t const *)q + 1, len - hlen);
			break;

		default:
			if (!fr_cond_assert(0)) return NULL;
		}

		if (RDEBUG_ENABLED3) {
			RDEBUG3("Converted: &control:%s = '%pV' -> &control:%s = '%pV'",
				vp->da->name, &vp->data, new->da->name, &new->data);
		} else {
			RDEBUG2("Converted: &control:%s -> &control:%s", vp->da->name, new->da->name);
		}

		return new;
	}

	/*
	 *	Doesn't have a header {...} prefix
	 *
	 *	See if it's base64, if it is, decode it and check again!
	 */
	decoded = fr_base64_decode(digest, sizeof(digest), vp->vp_strvalue, len);
	if ((decoded > 0) && (digest[0] == '{') && (memchr(digest, '}', decoded) != NULL)) {
		RDEBUG2("Normalizing %s from base64 encoding, %zu bytes -> %zu bytes",
			vp->da->name, vp->vp_length, decoded);
		/*
		 *	Password-With-Header is a string attribute.
		 *	Even though we're handling binary data, the buffer
		 *	must be \0 terminated.
		 */
		fr_pair_value_bstrncpy(vp, digest, decoded);

		goto redo;
	}

	if (RDEBUG_ENABLED3) {
		RDEBUG3("No {...} in &Password-With-Header = \"%s\", re-writing to Cleartext-Password",
			vp->vp_strvalue);
	} else {
		RDEBUG("No {...} in &Password-With-Header, re-writing to Cleartext-Password");
	}
unknown_header:
	new = fr_pair_afrom_da(request, attr_cleartext_password);
	fr_pair_value_strcpy(new, vp->vp_strvalue);

	return new;
}

/*
 *	Authorize the user for PAP authentication.
 *
 *	This isn't strictly necessary, but it does make the
 *	server simpler to configure.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authorize(void *instance, UNUSED void *thread, REQUEST *request)
{
	rlm_pap_t const 	*inst = instance;
	bool			found_pw = false;
	VALUE_PAIR		*vp;
	fr_cursor_t		cursor;

	for (vp = fr_cursor_init(&cursor, &request->control);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
	     	VP_VERIFY(vp);
	next:
		if (vp->da == attr_user_password) {
			RWDEBUG("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
			RWDEBUG("!!! Ignoring control:User-Password.  Update your        !!!");
			RWDEBUG("!!! configuration so that the \"known good\" clear text !!!");
			RWDEBUG("!!! password is in Cleartext-Password and NOT in        !!!");
			RWDEBUG("!!! User-Password.                                      !!!");
			RWDEBUG("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
		} else if (vp->da == attr_password_with_header) {
			VALUE_PAIR *new;

			/*
			 *	Password already exists: use that instead of this one.
			 */
			if (fr_pair_find_by_da(request->control, attr_cleartext_password, TAG_ANY)) {
				RWDEBUG("Config already contains a \"known good\" password "
					"(&control:Cleartext-Password).  Ignoring &config:Password-With-Header");
				break;
			}

			new = normify_with_header(request, request, vp);
			if (new) fr_cursor_append(&cursor, new); /* inserts at the end of the list */

			RDEBUG2("Removing &control:Password-With-Header");
			vp = fr_cursor_remove(&cursor);	/* advances the cursor for us */
			talloc_free(vp);

			found_pw = true;

			vp = fr_cursor_current(&cursor);
			if (vp) goto next;
		} else if ((vp->da == attr_cleartext_password) ||
			   (vp->da == attr_crypt_password) ||
			   (vp->da == attr_ns_mta_md5_password)) {
			found_pw = true;
		} else if ((vp->da == attr_md5_password) ||
			   (vp->da == attr_smd5_password) ||
			   (vp->da == attr_nt_password) ||
			   (vp->da == attr_lm_password)) {
			if (inst->normify) normify(request, vp, 16); /* ensure it's in the right format */
			found_pw = true;
		}
#ifdef HAVE_OPENSSL_EVP_H
		else if (vp->da == attr_sha2_password) {
			if (inst->normify) normify(request, vp, 28); /* ensure it's in the right format */
			found_pw = true;
		} else if (vp->da == attr_ssha2_224_password) {
			if (inst->normify) normify(request, vp, 28); /* ensure it's in the right format */
			found_pw = true;
		} else if (vp->da == attr_ssha2_256_password) {
			if (inst->normify) normify(request, vp, 32); /* ensure it's in the right format */
			found_pw = true;
		} else if (vp->da == attr_ssha2_384_password) {
			if (inst->normify) normify(request, vp, 48); /* ensure it's in the right format */
			found_pw = true;
		} else if (vp->da == attr_ssha2_512_password) {
			if (inst->normify) normify(request, vp, 64); /* ensure it's in the right format */
			found_pw = true;
		}
#  ifdef HAVE_EVP_SHA3_512
		else if (vp->da == attr_sha3_password) {
			if (inst->normify) normify(request, vp, 28); /* ensure it's in the right format */
			found_pw = true;
		} else if (vp->da == attr_ssha3_224_password) {}
			if (inst->normify) normify(request, vp, 28); /* ensure it's in the right format */
			found_pw = true;
		} else if (vp->da == attr_ssha3_256_password) {
			if (inst->normify) normify(request, vp, 32); /* ensure it's in the right format */
			found_pw = true;
		} else if (vp->da == attr_ssha3_384_password) {
			if (inst->normify) normify(request, vp, 48); /* ensure it's in the right format */
			found_pw = true;
		} else if (vp->da == attr_ssha3_512_password) {
			if (inst->normify) normify(request, vp, 64); /* ensure it's in the right format */
			found_pw = true;
		}
#  endif
		else if (vp->da == attr_pbkdf2_password) {
			found_pw = true; /* Already base64 standardized */
		}
#endif
		else if ((vp->da == attr_sha_password) ||
			 (vp->da == attr_ssha_password)) {
			if (inst->normify) normify(request, vp, 20); /* ensure it's in the right format */
			found_pw = true;
		}
	}

	/*
	 *	Can't do PAP if there's no password.
	 */
	if (!request->password ||
	    (request->password->da != attr_user_password)) {
		RDEBUG2("No User-Password attribute in the request.  Cannot do PAP");
		return RLM_MODULE_NOOP;
	}

	/*
	 *	Print helpful warnings if there was no password.
	 */
	if (!found_pw) {
		/*
		 *	Likely going to be proxied.  Avoid printing
		 *	warning message.
		 */
		if (fr_pair_find_by_da(request->control, attr_realm, TAG_ANY) ||
		    (fr_pair_find_by_da(request->control, attr_proxy_to_realm, TAG_ANY))) {
			return RLM_MODULE_NOOP;
		}

		RWDEBUG("No \"known good\" password found for the user.  Not setting Auth-Type");
		RWDEBUG("Authentication will fail unless a \"known good\" password is available");

		return RLM_MODULE_NOOP;
	}

	if (!module_section_type_set(request, attr_auth_type, inst->auth_type)) return RLM_MODULE_NOOP;

	return RLM_MODULE_UPDATED;
}

/*
 *	PAP authentication functions
 */

static rlm_rcode_t CC_HINT(nonnull) pap_auth_clear(UNUSED rlm_pap_t const *inst, REQUEST *request, VALUE_PAIR *vp)
{
	if (RDEBUG_ENABLED3) {
		RDEBUG3("Comparing with \"known good\" Cleartext-Password \"%s\" (%zd)", vp->vp_strvalue, vp->vp_length);
	} else {
		RDEBUG("Comparing with \"known good\" Cleartext-Password");
	}

	if ((vp->vp_length != request->password->vp_length) ||
	    (fr_digest_cmp(vp->vp_octets, request->password->vp_octets, vp->vp_length) != 0)) {
		REDEBUG("Cleartext password does not match \"known good\" password");
		REDEBUG3("Password   : %pV", &request->password->data);
		REDEBUG3("Expected   : %pV", &vp->data);
		return RLM_MODULE_REJECT;
	}
	return RLM_MODULE_OK;
}

static rlm_rcode_t CC_HINT(nonnull) pap_auth_crypt(UNUSED rlm_pap_t const *inst, REQUEST *request, VALUE_PAIR *vp)
{
	if (RDEBUG_ENABLED3) {
		RDEBUG3("Comparing with \"known good\" Crypt-Password \"%s\"", vp->vp_strvalue);
	} else {
		RDEBUG("Comparing with \"known-good\" Crypt-password");
	}

	if (fr_crypt_check(request->password->vp_strvalue, vp->vp_strvalue) != 0) {
		REDEBUG("Crypt digest does not match \"known good\" digest");
		return RLM_MODULE_REJECT;
	}
	return RLM_MODULE_OK;
}

static rlm_rcode_t CC_HINT(nonnull) pap_auth_md5(rlm_pap_t const *inst, REQUEST *request, VALUE_PAIR *vp)
{
	FR_MD5_CTX md5_context;
	uint8_t digest[128];

	RDEBUG("Comparing with \"known-good\" MD5-Password");

	if (inst->normify) {
		normify(request, vp, MD5_DIGEST_LENGTH);
	}
	if (vp->vp_length != MD5_DIGEST_LENGTH) {
		REDEBUG("\"known-good\" MD5 password has incorrect length, expected 16 got %zu", vp->vp_length);
		return RLM_MODULE_INVALID;
	}

	fr_md5_init(&md5_context);
	fr_md5_update(&md5_context, request->password->vp_octets, request->password->vp_length);
	fr_md5_final(digest, &md5_context);

	if (fr_digest_cmp(digest, vp->vp_octets, vp->vp_length) != 0) {
		REDEBUG("MD5 digest does not match \"known good\" digest");
		REDEBUG3("Password   : %pV", &request->password->data);
		REDEBUG3("Calculated : %pV", fr_box_octets(digest, MD5_DIGEST_LENGTH));
		REDEBUG3("Expected   : %pV", fr_box_octets(vp->vp_octets, MD5_DIGEST_LENGTH));
		return RLM_MODULE_REJECT;
	}

	return RLM_MODULE_OK;
}


static rlm_rcode_t CC_HINT(nonnull) pap_auth_smd5(rlm_pap_t const *inst, REQUEST *request, VALUE_PAIR *vp)
{
	FR_MD5_CTX md5_context;
	uint8_t digest[128];

	RDEBUG("Comparing with \"known-good\" SMD5-Password");

	if (inst->normify) normify(request, vp, MD5_DIGEST_LENGTH);
	if (vp->vp_length <= MD5_DIGEST_LENGTH) {
		REDEBUG("\"known-good\" SMD5-Password has incorrect length, expected 16 got %zu", vp->vp_length);
		return RLM_MODULE_INVALID;
	}

	fr_md5_init(&md5_context);
	fr_md5_update(&md5_context, request->password->vp_octets, request->password->vp_length);
	fr_md5_update(&md5_context, vp->vp_octets + MD5_DIGEST_LENGTH, vp->vp_length - MD5_DIGEST_LENGTH);
	fr_md5_final(digest, &md5_context);

	/*
	 *	Compare only the MD5 hash results, not the salt.
	 */
	if (fr_digest_cmp(digest, vp->vp_octets, MD5_DIGEST_LENGTH) != 0) {
		REDEBUG("SMD5 digest does not match \"known good\" digest");
		REDEBUG3("Password   : %pV", &request->password->data);
		REDEBUG3("Calculated : %pV", fr_box_octets(digest, MD5_DIGEST_LENGTH));
		REDEBUG3("Expected   : %pV", fr_box_octets(vp->vp_octets, MD5_DIGEST_LENGTH));
		return RLM_MODULE_REJECT;
	}

	return RLM_MODULE_OK;
}

static rlm_rcode_t CC_HINT(nonnull) pap_auth_sha(rlm_pap_t const *inst, REQUEST *request, VALUE_PAIR *vp)
{
	fr_sha1_ctx sha1_context;
	uint8_t digest[128];

	RDEBUG("Comparing with \"known-good\" SHA-Password");

	if (inst->normify) normify(request, vp, SHA1_DIGEST_LENGTH);

	if (vp->vp_length != SHA1_DIGEST_LENGTH) {
		REDEBUG("\"known-good\" SHA1-password has incorrect length, expected 20 got %zu", vp->vp_length);
		return RLM_MODULE_INVALID;
	}

	fr_sha1_init(&sha1_context);
	fr_sha1_update(&sha1_context, request->password->vp_octets, request->password->vp_length);
	fr_sha1_final(digest,&sha1_context);

	if (fr_digest_cmp(digest, vp->vp_octets, vp->vp_length) != 0) {
		REDEBUG("SHA1 digest does not match \"known good\" digest");
		REDEBUG3("Password   : %pV", &request->password->data);
		REDEBUG3("Calculated : %pV", fr_box_octets(digest, SHA1_DIGEST_LENGTH));
		REDEBUG3("Expected   : %pV", fr_box_octets(vp->vp_octets, SHA1_DIGEST_LENGTH));
		return RLM_MODULE_REJECT;
	}

	return RLM_MODULE_OK;
}

static rlm_rcode_t CC_HINT(nonnull) pap_auth_ssha(rlm_pap_t const *inst, REQUEST *request, VALUE_PAIR *vp)
{
	fr_sha1_ctx sha1_context;
	uint8_t digest[128];

	RDEBUG("Comparing with \"known-good\" SSHA-Password");

	if (inst->normify) normify(request, vp, SHA1_DIGEST_LENGTH);

	if (vp->vp_length <= SHA1_DIGEST_LENGTH) {
		REDEBUG("\"known-good\" SSHA-Password has incorrect length, expected > 20 got %zu", vp->vp_length);
		return RLM_MODULE_INVALID;
	}

	fr_sha1_init(&sha1_context);
	fr_sha1_update(&sha1_context, request->password->vp_octets, request->password->vp_length);

	fr_sha1_update(&sha1_context, vp->vp_octets + SHA1_DIGEST_LENGTH, vp->vp_length - SHA1_DIGEST_LENGTH);
	fr_sha1_final(digest, &sha1_context);

	if (fr_digest_cmp(digest, vp->vp_octets, SHA1_DIGEST_LENGTH) != 0) {
		REDEBUG("SSHA digest does not match \"known good\" digest");
		REDEBUG3("Password   : %pV", &request->password->data);
		REDEBUG3("Salt       : %pV", fr_box_octets(vp->vp_octets + SHA1_DIGEST_LENGTH,
							   vp->vp_length - SHA1_DIGEST_LENGTH));
		REDEBUG3("Calculated : %pV", fr_box_octets(digest, SHA1_DIGEST_LENGTH));
		REDEBUG3("Expected   : %pV", fr_box_octets(vp->vp_octets, SHA1_DIGEST_LENGTH));
		return RLM_MODULE_REJECT;
	}

	return RLM_MODULE_OK;
}

#ifdef HAVE_OPENSSL_EVP_H
static rlm_rcode_t CC_HINT(nonnull) pap_auth_sha_evp(rlm_pap_t const *inst, REQUEST *request, VALUE_PAIR *vp)
{
	EVP_MD_CTX *ctx;
	EVP_MD const *md;
	char const *name;
	uint8_t digest[EVP_MAX_MD_SIZE];
	unsigned int digest_len;

	if (inst->normify) normify(request, vp, SHA224_DIGEST_LENGTH);

	if (vp->da == attr_sha2_password) {
		RDEBUG("Comparing with \"known-good\" SHA2-Password");

		/*
		 *	All the SHA-2 algorithms produce digests of different lengths,
		 *	so it's trivial to determine which EVP_MD to use.
		 */
		switch (vp->vp_length) {
		/* SHA2-224 */
		case SHA224_DIGEST_LENGTH:
			name = "SHA2-224";
			md = EVP_sha224();
			break;

		/* SHA2-256 */
		case SHA256_DIGEST_LENGTH:
			name = "SHA2-256";
			md = EVP_sha256();
			break;

		/* SHA2-384 */
		case SHA384_DIGEST_LENGTH:
			name = "SHA2-384";
			md = EVP_sha384();
			break;

		/* SHA2-512 */
		case SHA512_DIGEST_LENGTH:
			name = "SHA2-512";
			md = EVP_sha512();
			break;

		default:
			REDEBUG("\"known good\" digest length (%zu) does not match output length of any SHA-2 digests",
				vp->vp_length);
			return RLM_MODULE_INVALID;
		}
	}
# ifdef HAVE_EVP_SHA3_512
	else if (vp->da == attr_sha3_password) {
		RDEBUG("Comparing with \"known-good\" SHA3-Password");
		/*
		 *	All the SHA-3 algorithms produce digests of different lengths,
		 *	so it's trivial to determine which EVP_MD to use.
		 */
		switch (vp->vp_length) {
		/* SHA3-224 */
		case SHA224_DIGEST_LENGTH:
			name = "SHA3-224";
			md = EVP_sha3_224();
			break;

		/* SHA3-256 */
		case SHA256_DIGEST_LENGTH:
			name = "SHA3-256";
			md = EVP_sha3_256();
			break;

		/* SHA3-384 */
		case SHA384_DIGEST_LENGTH:
			name = "SHA3-384";
			md = EVP_sha3_384();
			break;

		/* SHA3-512 */
		case SHA512_DIGEST_LENGTH:
			name = "SHA3-512";
			md = EVP_sha3_512();
			break;

		default:
			REDEBUG("\"known good\" digest length (%zu) does not match output length of any SHA-3 digests",
				vp->vp_length);
			return RLM_MODULE_INVALID;
		}
		break;
	}
#  endif
	else {
		rad_assert(0);
		return RLM_MODULE_INVALID;
	}

	ctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(ctx, md, NULL);
	EVP_DigestUpdate(ctx, request->password->vp_octets, request->password->vp_length);
	EVP_DigestFinal_ex(ctx, digest, &digest_len);
	EVP_MD_CTX_destroy(ctx);

	rad_assert((size_t) digest_len == vp->vp_length);	/* This would be an OpenSSL bug... */

	if (fr_digest_cmp(digest, vp->vp_octets, vp->vp_length) != 0) {
		REDEBUG("%s digest does not match \"known good\" digest", name);
		REDEBUG3("Password   : %pV", &request->password->data);
		REDEBUG3("Calculated : %pV", fr_box_octets(digest, digest_len));
		REDEBUG3("Expected   : %pV", &vp->data);
		return RLM_MODULE_REJECT;
	}

	return RLM_MODULE_OK;
}

static rlm_rcode_t CC_HINT(nonnull) pap_auth_ssha_evp(rlm_pap_t const *inst, REQUEST *request, VALUE_PAIR *vp)
{
	EVP_MD_CTX *ctx;
	EVP_MD const *md = NULL;
	char const *name = NULL;
	uint8_t digest[EVP_MAX_MD_SIZE];
	unsigned int digest_len, min_len = 0;

	if (vp->da == attr_ssha2_224_password) {
		name = "SSHA2-224";
		md = EVP_sha224();
		min_len = SHA224_DIGEST_LENGTH;
	} else if (vp->da == attr_ssha2_256_password) {
		name = "SSHA2-256";
		md = EVP_sha256();
		min_len = SHA256_DIGEST_LENGTH;
	} else if (vp->da == attr_ssha2_384_password) {
		name = "SSHA2-384";
		md = EVP_sha384();
		min_len = SHA384_DIGEST_LENGTH;
	} else if (vp->da == attr_ssha2_512_password) {
		name = "SSHA2-512";
		min_len = SHA512_DIGEST_LENGTH;
		md = EVP_sha512();
	}
#ifdef HAVE_EVP_SHA3_512
	else if (vp->da == attr_ssha3_224_password) {
		name = "SSHA3-224";
		md = EVP_sha3_224();
		min_len = SHA224_DIGEST_LENGTH;
	} else if (vp->da == attr_ssha3_256_password) {
		name = "SSHA3-256";
		md = EVP_sha3_256();
		min_len = SHA256_DIGEST_LENGTH;
	} else if (vp->da == attr_ssha3_384_password) {
		name = "SSHA3-384";
		md = EVP_sha3_384();
		min_len = SHA384_DIGEST_LENGTH;
	} else if (vp->da == attr_ssha3_512_password) {
		name = "SSHA3-512";
		min_len = SHA512_DIGEST_LENGTH;
		md = EVP_sha3_512();
	}
#endif
	else {
		rad_assert(0);
		return RLM_MODULE_INVALID;
	}

	RDEBUG("Comparing with \"known-good\" %s-Password", name);

	/*
	 *	Unlike plain SHA2/3 we already know what length
	 *	to expect, so can be more specific with the
	 *	minimum digest length.
	 */
	if (inst->normify) normify(request, vp, min_len + 1);

	if (vp->vp_length <= min_len) {
		REDEBUG("\"known-good\" %s-Password has incorrect length, got %zu bytes, need at least %u bytes",
			name, vp->vp_length, min_len + 1);
		return RLM_MODULE_INVALID;
	}

	ctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(ctx, md, NULL);
	EVP_DigestUpdate(ctx, request->password->vp_octets, request->password->vp_length);
	EVP_DigestUpdate(ctx, vp->vp_octets + min_len, vp->vp_length - min_len);
	EVP_DigestFinal_ex(ctx, digest, &digest_len);
	EVP_MD_CTX_destroy(ctx);

	rad_assert((size_t) digest_len == min_len);	/* This would be an OpenSSL bug... */

	/*
	 *	Only compare digest_len bytes, the rest is salt.
	 */
	if (fr_digest_cmp(digest, vp->vp_octets, (size_t)digest_len) != 0) {
		REDEBUG("%s digest does not match \"known good\" digest", name);
		REDEBUG3("Password   : %pV", &request->password->data);
		REDEBUG3("Salt       : %pV", fr_box_octets(vp->vp_octets + min_len, vp->vp_length - min_len));
		REDEBUG3("Calculated : %pV", fr_box_octets(digest, digest_len));
		REDEBUG3("Expected   : %pV", &vp->data);
		return RLM_MODULE_REJECT;
	}

	return RLM_MODULE_OK;
}

/** Validates Crypt::PBKDF2 LDAP format strings
 *
 * @param[in] request	The current request.
 * @param[in] str	Raw PBKDF2 string.
 * @param[in] len	Length of string.
 * @return
 *	- RLM_MODULE_REJECT
 *	- RLM_MODULE_OK
 */
static inline rlm_rcode_t CC_HINT(nonnull) pap_auth_pbkdf2_parse(REQUEST *request, const uint8_t *str, size_t len,
								 FR_NAME_NUMBER const hash_names[],
								 char scheme_sep, char iter_sep, char salt_sep,
								 bool iter_is_base64)
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

	RDEBUG("Comparing with \"known-good\" PBKDF2-Password");

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

	digest_type = fr_substr2int(hash_names, (char const *)p, -1, q - p);
	switch (digest_type) {
	case FR_SSHA_PASSWORD:
		evp_md = EVP_sha1();
		digest_len = SHA1_DIGEST_LENGTH;
		break;

	case FR_SSHA2_224_PASSWORD:
		evp_md = EVP_sha224();
		digest_len = SHA224_DIGEST_LENGTH;
		break;

	case FR_SSHA2_256_PASSWORD:
		evp_md = EVP_sha256();
		digest_len = SHA256_DIGEST_LENGTH;
		break;

	case FR_SSHA2_384_PASSWORD:
		evp_md = EVP_sha384();
		digest_len = SHA384_DIGEST_LENGTH;
		break;

	case FR_SSHA2_512_PASSWORD:
		evp_md = EVP_sha512();
		digest_len = SHA512_DIGEST_LENGTH;
		break;

#  ifdef HAVE_EVP_SHA3_512
	case FR_SSHA3_224_PASSWORD:
		evp_md = EVP_sha3_224();
		digest_len = SHA224_DIGEST_LENGTH;
		break;

	case FR_SSHA3_256_PASSWORD:
		evp_md = EVP_sha3_256();
		digest_len = SHA256_DIGEST_LENGTH;
		break;

	case FR_SSHA3_384_PASSWORD:
		evp_md = EVP_sha3_384();
		digest_len = SHA384_DIGEST_LENGTH;
		break;

	case FR_SSHA3_512_PASSWORD:
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

		RHEXDUMP(L_DBG_LVL_2, hash, slen, "hash component");

		goto finish;
	}

	RDEBUG2("PBKDF2 %s: Iterations %u, salt length %zu, hash length %zd",
		fr_int2str(pbkdf2_crypt_names, digest_type, "<UNKNOWN>"),
		iterations, salt_len, slen);

	/*
	 *	Hash and compare
	 */
	if (PKCS5_PBKDF2_HMAC((char const *)request->password->vp_octets, (int)request->password->vp_length,
			      (unsigned char const *)salt, (int)salt_len,
			      (int)iterations,
			      evp_md,
			      (int)digest_len, (unsigned char *)digest) == 0) {
		REDEBUG("PBKDF2 digest failure");
		goto finish;
	}

	if (fr_digest_cmp(digest, hash, (size_t)digest_len) != 0) {
		REDEBUG("PBKDF2 digest does not match \"known good\" digest");
		REDEBUG3("Salt       : %pV", fr_box_octets(salt, salt_len));
		REDEBUG3("Calculated : %pV", fr_box_octets(digest, digest_len));
		REDEBUG3("Expected   : %pV", fr_box_octets(hash, slen));
		rcode = RLM_MODULE_REJECT;
	} else {
		rcode = RLM_MODULE_OK;
	}

finish:
	talloc_free(salt);

	return rcode;
}

static inline rlm_rcode_t CC_HINT(nonnull) pap_auth_pbkdf2(UNUSED rlm_pap_t const *inst,
							   REQUEST *request, VALUE_PAIR *vp)
{
	uint8_t const *p = vp->vp_octets, *q, *end = p + vp->vp_length;

	if (end - p < 2) {
		REDEBUG("PBKDF2-Password too short");
		return RLM_MODULE_INVALID;
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
		return pap_auth_pbkdf2_parse(request, p, end - p,
					     pbkdf2_crypt_names, ':', ':', ':', true);
	}

	/*
	 *	Crypt::PBKDF2 Crypt format
	 *
	 *	$PBKDF2$<digest>:<rounds>:<b64_salt>$<b64_hash>
	 */
	if ((size_t)(end - p) >= sizeof("$PBKDF2$") && (memcmp(p, "$PBKDF2$", sizeof("$PBKDF2$") - 1) == 0)) {
		p += sizeof("$PBKDF2$") - 1;
		return pap_auth_pbkdf2_parse(request, p, end - p,
					     pbkdf2_crypt_names, ':', ':', '$', false);
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
		return pap_auth_pbkdf2_parse(request, p, end - p,
					     pbkdf2_passlib_names, '$', '$', '$', false);
	}

	REDEBUG("Can't determine format of PBKDF2-Password");

	return RLM_MODULE_INVALID;
}
#endif

static rlm_rcode_t CC_HINT(nonnull) pap_auth_nt(rlm_pap_t const *inst, REQUEST *request, VALUE_PAIR *vp)
{
	ssize_t len;
	uint8_t digest[MD4_DIGEST_LENGTH];
	uint8_t ucs2_password[512];

	RDEBUG("Comparing with \"known-good\" NT-Password");

	rad_assert(request->password != NULL);
	rad_assert(request->password->da == attr_user_password);

	if (inst->normify) normify(request, vp, MD4_DIGEST_LENGTH);

	if (vp->vp_length != MD4_DIGEST_LENGTH) {
		REDEBUG("\"known good\" NT-Password has incorrect length, expected 16 got %zu", vp->vp_length);
		return RLM_MODULE_INVALID;
	}

	len = fr_utf8_to_ucs2(ucs2_password, sizeof(ucs2_password),
			      request->password->vp_strvalue, request->password->vp_length);
	if (len < 0) {
		REDEBUG("User-Password is not in UCS2 format");
		return RLM_MODULE_INVALID;
	}

	fr_md4_calc(digest, (uint8_t *)ucs2_password, len);

	if (fr_digest_cmp(digest, vp->vp_octets, vp->vp_length) != 0) {
		REDEBUG("NT digest does not match \"known good\" digest");
		REDEBUG3("Calculated : %pV", fr_box_octets(digest, sizeof(digest)));
		REDEBUG3("Expected   : %pV", &vp->data);
		return RLM_MODULE_REJECT;
	}

	return RLM_MODULE_OK;
}

static rlm_rcode_t CC_HINT(nonnull) pap_auth_lm(rlm_pap_t const *inst, REQUEST *request, VALUE_PAIR *vp)
{
	uint8_t	digest[MD4_DIGEST_LENGTH];
	char	charbuf[32 + 1];
	ssize_t	len;

	RDEBUG("Comparing with \"known-good\" LM-Password");

	if (inst->normify) normify(request, vp, MD4_DIGEST_LENGTH);

	if (vp->vp_length != MD4_DIGEST_LENGTH) {
		REDEBUG("\"known good\" LM-Password has incorrect length, expected 16 got %zu", vp->vp_length);
		return RLM_MODULE_INVALID;
	}

	len = xlat_eval(charbuf, sizeof(charbuf), request, "%{mschap:LM-Hash %{User-Password}}", NULL, NULL);
	if (len < 0) return RLM_MODULE_FAIL;

	if ((fr_hex2bin(digest, sizeof(digest), charbuf, len) != vp->vp_length) ||
	    (fr_digest_cmp(digest, vp->vp_octets, vp->vp_length) != 0)) {
		REDEBUG("LM digest does not match \"known good\" digest");
		REDEBUG3("Calculated : %pV", fr_box_octets(digest, sizeof(digest)));
		REDEBUG3("Expected   : %pV", &vp->data);
		return RLM_MODULE_REJECT;
	}

	return RLM_MODULE_OK;
}

static rlm_rcode_t CC_HINT(nonnull) pap_auth_ns_mta_md5(UNUSED rlm_pap_t const *inst, REQUEST *request, VALUE_PAIR *vp)
{
	FR_MD5_CTX md5_context;
	uint8_t digest[128];
	uint8_t buff[FR_MAX_STRING_LEN];
	uint8_t buff2[FR_MAX_STRING_LEN + 50];

	RDEBUG("Using NT-MTA-MD5-Password");

	if (vp->vp_length != 64) {
		REDEBUG("\"known good\" NS-MTA-MD5-Password has incorrect length, expected 64 got %zu", vp->vp_length);
		return RLM_MODULE_INVALID;
	}

	/*
	 *	Sanity check the value of NS-MTA-MD5-Password
	 */
	if (fr_hex2bin(digest, sizeof(digest), vp->vp_strvalue, vp->vp_length) != 16) {
		REDEBUG("\"known good\" NS-MTA-MD5-Password has invalid value");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	Ensure we don't have buffer overflows.
	 *
	 *	This really: sizeof(buff) - 2 - 2*32 - strlen(passwd)
	 */
	if (request->password->vp_length >= (sizeof(buff) - 2 - 2 * 32)) {
		REDEBUG("\"known good\" NS-MTA-MD5-Password is too long");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	Set up the algorithm.
	 */
	{
		uint8_t *p = buff2;

		memcpy(p, &vp->vp_octets[32], 32);
		p += 32;
		*(p++) = 89;
		memcpy(p, request->password->vp_strvalue, request->password->vp_length);
		p += request->password->vp_length;
		*(p++) = 247;
		memcpy(p, &vp->vp_octets[32], 32);
		p += 32;

		fr_md5_init(&md5_context);
		fr_md5_update(&md5_context, (uint8_t *) buff2, p - buff2);
		fr_md5_final(buff, &md5_context);
	}

	if (fr_digest_cmp(digest, buff, 16) != 0) {
		REDEBUG("NS-MTA-MD5 digest does not match \"known good\" digest");
		return RLM_MODULE_REJECT;
	}

	return RLM_MODULE_OK;
}


/*
 *	Authenticate the user via one of any well-known password.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authenticate(void *instance, UNUSED void *thread, REQUEST *request)
{
	rlm_pap_t const *inst = instance;
	VALUE_PAIR	*vp;
	rlm_rcode_t	rc = RLM_MODULE_INVALID;
	fr_cursor_t	cursor;
	rlm_rcode_t	(*auth_func)(rlm_pap_t const *, REQUEST *, VALUE_PAIR *) = NULL;

	if (!request->password || !fr_dict_attr_is_top_level(request->password->da) ||
	    (request->password->da != attr_user_password)) {
		REDEBUG("You set 'Auth-Type = PAP' for a request that does not contain a User-Password attribute!");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	The user MUST supply a non-zero-length password.
	 */
	if (request->password->vp_length == 0) {
		REDEBUG("Password must not be empty");
		return RLM_MODULE_INVALID;
	}

	if (RDEBUG_ENABLED3) {
		RDEBUG3("Login attempt with password \"%s\" (%zd)",
			request->password->vp_strvalue, request->password->vp_length);
	} else {
		RDEBUG("Login attempt with password");
	}

	/*
	 *	Auto-detect passwords, by attribute in the
	 *	config items, to find out which authentication
	 *	function to call.
	 */
	for (vp = fr_cursor_init(&cursor, &request->control);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		if (!fr_dict_attr_is_top_level(vp->da)) continue;

		if (vp->da == attr_cleartext_password) {
			auth_func = &pap_auth_clear;
		} else if (vp->da == attr_crypt_password) {
			auth_func = &pap_auth_crypt;
		} else if (vp->da == attr_md5_password) {
			auth_func = &pap_auth_md5;
		} else if (vp->da == attr_smd5_password) {
			auth_func = &pap_auth_smd5;
		}
#ifdef HAVE_OPENSSL_EVP_H
		else if (vp->da == attr_sha2_password
#  ifdef HAVE_EVP_SHA3_512
			 || (vp->da == attr_sha3_password)
#  endif
			) {
			auth_func = &pap_auth_sha_evp;
		} else if ((vp->da == attr_ssha2_224_password) ||
		    (vp->da == attr_ssha2_256_password) ||
		    (vp->da == attr_ssha2_384_password) ||
		    (vp->da == attr_ssha2_512_password)
#  ifdef HAVE_EVP_SHA3_512
		    || (vp->da == attr_ssha3_224_password) ||
		    (vp->da == attr_ssha3_256_password) ||
		    (vp->da == attr_ssha3_384_password) ||
		    (vp->da == attr_ssha3_512_password)
#  endif
		    ) {
			auth_func = &pap_auth_ssha_evp;
		} else if (vp->da == attr_pbkdf2_password) {
			auth_func = &pap_auth_pbkdf2;
		}
#endif
		else if (vp->da == attr_sha_password) {
			auth_func = &pap_auth_sha;
		} else if (vp->da == attr_ssha_password) {
			auth_func = &pap_auth_ssha;
		} else if (vp->da == attr_nt_password) {
			auth_func = &pap_auth_nt;
		} else if (vp->da == attr_lm_password) {
			auth_func = &pap_auth_lm;
		} else if (vp->da == attr_ns_mta_md5_password) {
			auth_func = &pap_auth_ns_mta_md5;
		}

		if (auth_func != NULL) break;
	}

	/*
	 *	No attribute was found that looked like a password to match.
	 */
	if (!auth_func) {
		RDEBUG("No password configured for the user.  Cannot do authentication");
		return RLM_MODULE_FAIL;
	}

	/*
	 *	Authenticate, and return.
	 */
	rc = auth_func(inst, request, vp);

	if (rc == RLM_MODULE_REJECT) {
		RDEBUG("Passwords don't match");
	}

	if (rc == RLM_MODULE_OK) {
		RDEBUG("User authenticated successfully");
	}

	return rc;
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

	if (fr_dict_enum_add_alias_next(attr_auth_type, inst->name) < 0) {
		PERROR("Failed adding %s alias", attr_auth_type->name);
		return -1;
	}
	inst->auth_type = fr_dict_enum_by_alias(attr_auth_type, inst->name, -1);
	rad_assert(inst->auth_type);

	return 0;
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
extern rad_module_t rlm_pap;
rad_module_t rlm_pap = {
	.magic		= RLM_MODULE_INIT,
	.name		= "pap",
	.inst_size	= sizeof(rlm_pap_t),
	.config		= module_config,
	.bootstrap	= mod_bootstrap,
	.methods = {
		[MOD_AUTHENTICATE]	= mod_authenticate,
		[MOD_AUTHORIZE]		= mod_authorize
	},
};
