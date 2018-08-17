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

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/base64.h>
#include <freeradius-devel/rad_assert.h>

#include <ctype.h>

#include "../../include/md5.h"
#include "../../include/sha1.h"

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
	char const	*name;	/* CONF_SECTION->name, not strdup'd */
	int		auth_type;
	bool		normify;
} rlm_pap_t;

/*
 *      A mapping of configuration file names to internal variables.
 *
 *      Note that the string is dynamically allocated, so it MUST
 *      be freed.  When the configuration file parse re-reads the string,
 *      it free's the old one, and strdup's the new one, placing the pointer
 *      to the strdup'd string into 'config.string'.  This gets around
 *      buffer over-flows.
 */
static const CONF_PARSER module_config[] = {
	{ "normalise", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_pap_t, normify), "yes" },
	CONF_PARSER_TERMINATOR
};


/*
 *	For auto-header discovery.
 *
 *	@note Header comparison is case insensitive.
 */
static const FR_NAME_NUMBER header_names[] = {
	{ "{clear}",		PW_CLEARTEXT_PASSWORD },
	{ "{cleartext}",	PW_CLEARTEXT_PASSWORD },
	{ "{md5}",		PW_MD5_PASSWORD },
	{ "{base64_md5}",	PW_MD5_PASSWORD },
	{ "{smd5}",		PW_SMD5_PASSWORD },
	{ "{crypt}",		PW_CRYPT_PASSWORD },
#ifdef HAVE_OPENSSL_EVP_H
	/*
	 *	It'd make more sense for the headers to be
	 *	ssha2-* with SHA3 coming soon but we're at
	 *	the mercy of directory implementors.
	 */
	{ "{sha2}",		PW_SHA2_PASSWORD },
	{ "{sha224}",		PW_SHA2_PASSWORD },
	{ "{sha256}",		PW_SHA2_PASSWORD },
	{ "{sha384}",		PW_SHA2_PASSWORD },
	{ "{sha512}",		PW_SHA2_PASSWORD },
	{ "{ssha224}",		PW_SSHA2_224_PASSWORD },
	{ "{ssha256}",		PW_SSHA2_256_PASSWORD },
	{ "{ssha384}",		PW_SSHA2_384_PASSWORD },
	{ "{ssha512}",		PW_SSHA2_512_PASSWORD },
#endif
	{ "{sha}",		PW_SHA_PASSWORD },
	{ "{ssha}",		PW_SSHA_PASSWORD },
	{ "{md4}",		PW_NT_PASSWORD },
	{ "{nt}",		PW_NT_PASSWORD },
	{ "{nthash}",		PW_NT_PASSWORD },
	{ "{x-nthash}",		PW_NT_PASSWORD },
	{ "{ns-mta-md5}",	PW_NS_MTA_MD5_PASSWORD },
	{ "{x- orcllmv}",	PW_LM_PASSWORD },
	{ "{X- orclntv}",	PW_NT_PASSWORD },
	{ NULL, 0 }
};

static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	rlm_pap_t *inst = instance;
	DICT_VALUE *dval;

	inst->name = cf_section_name2(conf);
	if (!inst->name) {
		inst->name = cf_section_name1(conf);
	}

	dval = dict_valbyname(PW_AUTH_TYPE, 0, inst->name);
	if (dval) {
		inst->auth_type = dval->value;
	} else {
		inst->auth_type = 0;
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
 * @param[in] request Current request.
 * @param[in,out] vp to normify.
 * @param[in] min_len we expect the decoded version to be.
 */
static void normify(REQUEST *request, VALUE_PAIR *vp, size_t min_len)
{
	uint8_t buffer[256];

	if (min_len >= sizeof(buffer)) return; /* paranoia */

	rad_assert((vp->da->type == PW_TYPE_OCTETS) || (vp->da->type == PW_TYPE_STRING));

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
 * @param request Current request.
 * @param vp Password-With-Header attribute to convert.
 * @return a new VALUE_PAIR on success, NULL on error.
 */
static VALUE_PAIR *normify_with_header(REQUEST *request, VALUE_PAIR *vp)
{
	int		attr;
	char const	*p, *q;
	size_t		len;

	uint8_t		digest[257];	/* +1 for \0 */
	ssize_t		decoded;

	char		buffer[256];

	VALUE_PAIR	*new;

	VERIFY_VP(vp);

	/*
	 *	Ensure this is only ever called with a
	 *	string type attribute.
	 */
	rad_assert(vp->da->type == PW_TYPE_STRING);

redo:
	p = vp->vp_strvalue;
	len = vp->vp_length;

	/*
	 *	Has a header {...} prefix
	 */
	q = strchr(p, '}');
	if (q) {
		size_t hlen;

		hlen = (q + 1) - p;
		if (hlen >= sizeof(buffer)) {
			REDEBUG("Password header too long.  Got %zu bytes must be less than %zu bytes",
				hlen, sizeof(buffer));
			return NULL;
		}

		memcpy(buffer, p, hlen);
		buffer[hlen] = '\0';

		attr = fr_str2int(header_names, buffer, 0);
		if (!attr) {
			if (RDEBUG_ENABLED3) {
				RDEBUG3("Unknown header {%s} in Password-With-Header = \"%s\", re-writing to "
					"Cleartext-Password", buffer, vp->vp_strvalue);
			} else {
				RDEBUG("Unknown header {%s} in Password-With-Header, re-writing to "
				       "Cleartext-Password", buffer);
			}
			goto unknown_header;
		}

		/*
		 *	The data after the '}' may be binary, so we copy it via
		 *	memcpy.  BUT it might be a string (or used as one), so
		 *	we ensure that there's a trailing zero, too.
		 */
		new = fr_pair_afrom_num(request, attr, 0);
		if (new->da->type == PW_TYPE_OCTETS) {
			fr_pair_value_memcpy(new, (uint8_t const *) q + 1, (len - hlen) + 1);
			new->vp_length = (len - hlen);	/* lie about the length */
		} else {
			fr_pair_value_strcpy(new, q + 1);
		}

		if (RDEBUG_ENABLED3) {
			char *old_value, *new_value;

			old_value = vp_aprints_value(request, vp, '\'');
			new_value = vp_aprints_value(request, new, '\'');
			RDEBUG3("Converted: &control:%s = '%s' -> &control:%s = '%s'",
				vp->da->name, old_value, new->da->name, new_value);
			talloc_free(old_value);
			talloc_free(new_value);
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
	decoded = fr_base64_decode(digest, sizeof(digest) - 1, vp->vp_strvalue, len);
	if ((decoded > 0) && (digest[0] == '{') && (memchr(digest, '}', decoded) != NULL)) {
		RDEBUG2("Normalizing %s from base64 encoding, %zu bytes -> %zu bytes",
			vp->da->name, vp->vp_length, decoded);
		/*
		 *	Password-With-Header is a string attribute.
		 *	Even though we're handling binary data, the buffer
		 *	must be \0 terminated.
		 */
		digest[decoded] = '\0';
		fr_pair_value_memcpy(vp, digest, decoded + 1);
		vp->vp_length = decoded;		/* lie about the length */

		goto redo;
	}

	if (RDEBUG_ENABLED3) {
		RDEBUG3("No {...} in Password-With-Header = \"%s\", re-writing to "
			"Cleartext-Password", vp->vp_strvalue);
	} else {
		RDEBUG("No {...} in Password-With-Header, re-writing to Cleartext-Password");
	}

unknown_header:
	new = fr_pair_afrom_num(request, PW_CLEARTEXT_PASSWORD, 0);
	fr_pair_value_strcpy(new, vp->vp_strvalue);

	return new;
}

/*
 *	Authorize the user for PAP authentication.
 *
 *	This isn't strictly necessary, but it does make the
 *	server simpler to configure.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authorize(void *instance, REQUEST *request)
{
	rlm_pap_t *inst = instance;
	bool auth_type = false;
	bool found_pw = false;
	VALUE_PAIR *vp;
	vp_cursor_t cursor;

	for (vp = fr_cursor_init(&cursor, &request->config);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
	     	VERIFY_VP(vp);
	next:
		switch (vp->da->attr) {
		case PW_USER_PASSWORD: /* deprecated */
			RWDEBUG("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
			RWDEBUG("!!! Ignoring control:User-Password.  Update your        !!!");
			RWDEBUG("!!! configuration so that the \"known good\" clear text !!!");
			RWDEBUG("!!! password is in Cleartext-Password and NOT in        !!!");
			RWDEBUG("!!! User-Password.                                      !!!");
			RWDEBUG("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
			break;

		case PW_PASSWORD_WITH_HEADER:	/* preferred */
		{
			VALUE_PAIR *new;

			/*
			 *	Password already exists: use that instead of this one.
			 */
			if (fr_pair_find_by_num(request->config, PW_CLEARTEXT_PASSWORD, 0, TAG_ANY)) {
				RWDEBUG("Config already contains a \"known good\" password "
					"(&control:Cleartext-Password).  Ignoring &config:Password-With-Header");
				break;
			}

			new = normify_with_header(request, vp);
			if (new) fr_cursor_insert(&cursor, new); /* inserts at the end of the list */

			RDEBUG2("Removing &control:Password-With-Header");
			vp = fr_cursor_remove(&cursor);	/* advances the cursor for us */
			talloc_free(vp);

			found_pw = true;

			vp = fr_cursor_current(&cursor);
			if (vp) goto next;
		}
			break;

		case PW_CLEARTEXT_PASSWORD:
		case PW_CRYPT_PASSWORD:
		case PW_NS_MTA_MD5_PASSWORD:
			found_pw = true;
			break;	/* don't touch these */

		case PW_MD5_PASSWORD:
		case PW_SMD5_PASSWORD:
		case PW_NT_PASSWORD:
		case PW_LM_PASSWORD:
			if (inst->normify) {
				normify(request, vp, 16); /* ensure it's in the right format */
			}
			found_pw = true;
			break;

#ifdef HAVE_OPENSSL_EVP_H
		case PW_SHA2_PASSWORD:
			if (inst->normify) {
				normify(request, vp, 28); /* ensure it's in the right format */
			}
			found_pw = true;
			break;

		case PW_SSHA2_224_PASSWORD:
			if (inst->normify) {
				normify(request, vp, 28); /* ensure it's in the right format */
			}
			found_pw = true;
			break;

		case PW_SSHA2_256_PASSWORD:
			if (inst->normify) {
				normify(request, vp, 32); /* ensure it's in the right format */
			}
			found_pw = true;
			break;

		case PW_SSHA2_384_PASSWORD:
			if (inst->normify) {
				normify(request, vp, 48); /* ensure it's in the right format */
			}
			found_pw = true;
			break;

		case PW_SSHA2_512_PASSWORD:
			if (inst->normify) {
				normify(request, vp, 64); /* ensure it's in the right format */
			}
			found_pw = true;
			break;
#endif

		case PW_SHA_PASSWORD:
		case PW_SSHA_PASSWORD:
			if (inst->normify) {
				normify(request, vp, 20); /* ensure it's in the right format */
			}
			found_pw = true;
			break;

			/*
			 *	If it's proxied somewhere, don't complain
			 *	about not having passwords or Auth-Type.
			 */
		case PW_PROXY_TO_REALM:
		{
			REALM *realm = realm_find(vp->vp_strvalue);
			if (realm && realm->auth_pool) {
				return RLM_MODULE_NOOP;
			}
			break;
		}

		case PW_AUTH_TYPE:
			auth_type = true;

			/*
			 *	Auth-Type := Accept
			 *	Auth-Type := Reject
			 */
			if ((vp->vp_integer == 254) ||
			    (vp->vp_integer == 4)) {
			    found_pw = true;
			}
			break;

		default:
			break;	/* ignore it */

		}
	}

	/*
	 *	Print helpful warnings if there was no password.
	 */
	if (!found_pw) {
		/*
		 *	Likely going to be proxied.  Avoid printing
		 *	warning message.
		 */
		if (fr_pair_find_by_num(request->config, PW_REALM, 0, TAG_ANY) ||
		    (fr_pair_find_by_num(request->config, PW_PROXY_TO_REALM, 0, TAG_ANY))) {
			return RLM_MODULE_NOOP;
		}

		/*
		 *	The TLS types don't need passwords.
		 */
		vp = fr_pair_find_by_num(request->packet->vps, PW_EAP_TYPE, 0, TAG_ANY);
		if (vp &&
		    ((vp->vp_integer == 13) || /* EAP-TLS */
		     (vp->vp_integer == 21) || /* EAP-TTLS */
		     (vp->vp_integer == 25))) {	/* PEAP */
			return RLM_MODULE_NOOP;
		}

		RWDEBUG("No \"known good\" password found for the user.  Not setting Auth-Type");
		RWDEBUG("Authentication will fail unless a \"known good\" password is available");
		return RLM_MODULE_NOOP;
	}

	/*
	 *	Don't touch existing Auth-Types.
	 */
	if (auth_type) {
		if (auth_type != inst->auth_type) RWDEBUG2("Auth-Type already set.  Not setting to PAP");
		return RLM_MODULE_NOOP;
	}

	/*
	 *	Can't do PAP if there's no password.
	 */
	if (!request->password ||
	    (request->password->da->attr != PW_USER_PASSWORD)) {
		RDEBUG2("No User-Password attribute in the request.  Cannot do PAP");
		return RLM_MODULE_NOOP;
	}

	if (inst->auth_type) {
		vp = radius_pair_create(request, &request->config,
				       PW_AUTH_TYPE, 0);
		vp->vp_integer = inst->auth_type;
	}

	return RLM_MODULE_UPDATED;
}

/*
 *	PAP authentication functions
 */

static rlm_rcode_t CC_HINT(nonnull) pap_auth_clear(UNUSED rlm_pap_t *inst, REQUEST *request, VALUE_PAIR *vp)
{
	if (RDEBUG_ENABLED3) {
		RDEBUG3("Comparing with \"known good\" Cleartext-Password \"%s\" (%zd)", vp->vp_strvalue, vp->vp_length);
	} else {
		RDEBUG("Comparing with \"known good\" Cleartext-Password");
	}

	if ((vp->vp_length != request->password->vp_length) ||
	    (rad_digest_cmp(vp->vp_octets,
			    request->password->vp_octets,
			    vp->vp_length) != 0)) {
		REDEBUG("Cleartext password does not match \"known good\" password");
		return RLM_MODULE_REJECT;
	}
	return RLM_MODULE_OK;
}

static rlm_rcode_t CC_HINT(nonnull) pap_auth_crypt(UNUSED rlm_pap_t *inst, REQUEST *request, VALUE_PAIR *vp)
{
	if (RDEBUG_ENABLED3) {
		RDEBUG3("Comparing with \"known good\" Crypt-Password \"%s\"", vp->vp_strvalue);
	} else {
		RDEBUG("Comparing with \"known-good\" Crypt-password");
	}

	if (fr_crypt_check(request->password->vp_strvalue,
			   vp->vp_strvalue) != 0) {
		REDEBUG("Crypt digest does not match \"known good\" digest");
		return RLM_MODULE_REJECT;
	}
	return RLM_MODULE_OK;
}

static rlm_rcode_t CC_HINT(nonnull) pap_auth_md5(rlm_pap_t *inst, REQUEST *request, VALUE_PAIR *vp)
{
	FR_MD5_CTX md5_context;
	uint8_t digest[128];

	RDEBUG("Comparing with \"known-good\" MD5-Password");

	if (inst->normify) {
		normify(request, vp, 16);
	}
	if (vp->vp_length != 16) {
		REDEBUG("\"known-good\" MD5 password has incorrect length");
		return RLM_MODULE_INVALID;
	}

	fr_md5_init(&md5_context);
	fr_md5_update(&md5_context, request->password->vp_octets,
		     request->password->vp_length);
	fr_md5_final(digest, &md5_context);

	if (rad_digest_cmp(digest, vp->vp_octets, vp->vp_length) != 0) {
		REDEBUG("MD5 digest does not match \"known good\" digest");
		return RLM_MODULE_REJECT;
	}

	return RLM_MODULE_OK;
}


static rlm_rcode_t CC_HINT(nonnull) pap_auth_smd5(rlm_pap_t *inst, REQUEST *request, VALUE_PAIR *vp)
{
	FR_MD5_CTX md5_context;
	uint8_t digest[128];

	RDEBUG("Comparing with \"known-good\" SMD5-Password");

	if (inst->normify) {
		normify(request, vp, 16);
	}
	if (vp->vp_length <= 16) {
		REDEBUG("\"known-good\" SMD5-Password has incorrect length");
		return RLM_MODULE_INVALID;
	}

	fr_md5_init(&md5_context);
	fr_md5_update(&md5_context, request->password->vp_octets,
		     request->password->vp_length);
	fr_md5_update(&md5_context, &vp->vp_octets[16], vp->vp_length - 16);
	fr_md5_final(digest, &md5_context);

	/*
	 *	Compare only the MD5 hash results, not the salt.
	 */
	if (rad_digest_cmp(digest, vp->vp_octets, 16) != 0) {
		REDEBUG("SMD5 digest does not match \"known good\" digest");
		return RLM_MODULE_REJECT;
	}

	return RLM_MODULE_OK;
}

static rlm_rcode_t CC_HINT(nonnull) pap_auth_sha(rlm_pap_t *inst, REQUEST *request, VALUE_PAIR *vp)
{
	fr_sha1_ctx sha1_context;
	uint8_t digest[128];

	RDEBUG("Comparing with \"known-good\" SHA-Password");

	if (inst->normify) {
		normify(request, vp, 20);
	}
	if (vp->vp_length != 20) {
		REDEBUG("\"known-good\" SHA1-password has incorrect length");
		return RLM_MODULE_INVALID;
	}

	fr_sha1_init(&sha1_context);
	fr_sha1_update(&sha1_context, request->password->vp_octets,
		      request->password->vp_length);
	fr_sha1_final(digest,&sha1_context);

	if (rad_digest_cmp(digest, vp->vp_octets, vp->vp_length) != 0) {
		REDEBUG("SHA1 digest does not match \"known good\" digest");
		return RLM_MODULE_REJECT;
	}

	return RLM_MODULE_OK;
}

static rlm_rcode_t CC_HINT(nonnull) pap_auth_ssha(rlm_pap_t *inst, REQUEST *request, VALUE_PAIR *vp)
{
	fr_sha1_ctx sha1_context;
	uint8_t digest[128];

	RDEBUG("Comparing with \"known-good\" SSHA-Password");

	if (inst->normify) {
		normify(request, vp, 20);
	}
	if (vp->vp_length <= 20) {
		REDEBUG("\"known-good\" SSHA-Password has incorrect length");
		return RLM_MODULE_INVALID;
	}

	fr_sha1_init(&sha1_context);
	fr_sha1_update(&sha1_context, request->password->vp_octets, request->password->vp_length);

	fr_sha1_update(&sha1_context, &vp->vp_octets[20], vp->vp_length - 20);
	fr_sha1_final(digest, &sha1_context);

	if (rad_digest_cmp(digest, vp->vp_octets, 20) != 0) {
		REDEBUG("SSHA digest does not match \"known good\" digest");
		return RLM_MODULE_REJECT;
	}

	return RLM_MODULE_OK;
}

#ifdef HAVE_OPENSSL_EVP_H
static rlm_rcode_t CC_HINT(nonnull) pap_auth_sha2(rlm_pap_t *inst, REQUEST *request, VALUE_PAIR *vp)
{
	EVP_MD_CTX *ctx;
	EVP_MD const *md;
	char const *name;
	uint8_t digest[EVP_MAX_MD_SIZE];
	unsigned int digest_len;

	RDEBUG("Comparing with \"known-good\" SHA2-Password");

	if (inst->normify) normify(request, vp, 28);

	/*
	 *	All the SHA-2 algorithms produce digests of different lengths,
	 *	so it's trivial to determine which EVP_MD to use.
	 */
	switch (vp->vp_length) {
	/* SHA-224 */
	case 28:
		name = "SHA2-224";
		md = EVP_sha224();
		break;

	/* SHA-256 */
	case 32:
		name = "SHA2-256";
		md = EVP_sha256();
		break;

	/* SHA-384 */
	case 48:
		name = "SHA2-384";
		md = EVP_sha384();
		break;

	/* SHA-512 */
	case 64:
		name = "SHA2-512";
		md = EVP_sha512();
		break;

	default:
		REDEBUG("\"known good\" digest length (%zu) does not match output length of any SHA-2 digests",
			vp->vp_length);
		return RLM_MODULE_INVALID;
	}

	ctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(ctx, md, NULL);
	EVP_DigestUpdate(ctx, request->password->vp_octets, request->password->vp_length);
	EVP_DigestFinal_ex(ctx, digest, &digest_len);
	EVP_MD_CTX_destroy(ctx);

	rad_assert((size_t) digest_len == vp->vp_length);	/* This would be an OpenSSL bug... */

	if (rad_digest_cmp(digest, vp->vp_octets, vp->vp_length) != 0) {
		REDEBUG("%s digest does not match \"known good\" digest", name);
		return RLM_MODULE_REJECT;
	}

	return RLM_MODULE_OK;
}

static rlm_rcode_t CC_HINT(nonnull) pap_auth_ssha2(rlm_pap_t *inst, REQUEST *request, VALUE_PAIR *vp)
{
	EVP_MD_CTX *ctx;
	EVP_MD const *md = NULL;
	char const *name = NULL;
	uint8_t digest[EVP_MAX_MD_SIZE];
	unsigned int digest_len, min_len = 0;

	switch (vp->da->attr) {
	case PW_SSHA2_224_PASSWORD:
		name = "SSHA2-224";
		md = EVP_sha224();
		min_len = 28;
		break;

	case PW_SSHA2_256_PASSWORD:
		name = "SSHA2-256";
		md = EVP_sha256();
		min_len = 32;
		break;

	case PW_SSHA2_384_PASSWORD:
		name = "SSHA2-384";
		md = EVP_sha384();
		min_len = 48;
		break;

	case PW_SSHA2_512_PASSWORD:
		name = "SSHA2-512";
		min_len = 64;
		md = EVP_sha512();
		break;

	default:
		rad_assert(0);
	}

	RDEBUG("Comparing with \"known-good\" %s-Password", name);

	/*
	 *	Unlike plain SHA2 we already know what length
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
	EVP_DigestUpdate(ctx, &vp->vp_octets[min_len], vp->vp_length - min_len);
	EVP_DigestFinal_ex(ctx, digest, &digest_len);
	EVP_MD_CTX_destroy(ctx);

	rad_assert((size_t) digest_len == min_len);	/* This would be an OpenSSL bug... */

	/*
	 *	Only compare digest_len bytes, the rest is salt.
	 */
	if (rad_digest_cmp(digest, vp->vp_octets, (size_t)digest_len) != 0) {
		REDEBUG("%s digest does not match \"known good\" digest", name);
		return RLM_MODULE_REJECT;
	}

	return RLM_MODULE_OK;
}
#endif

static rlm_rcode_t CC_HINT(nonnull) pap_auth_nt(rlm_pap_t *inst, REQUEST *request, VALUE_PAIR *vp)
{
	ssize_t len;
	uint8_t digest[16];
	uint8_t ucs2_password[512];

	RDEBUG("Comparing with \"known-good\" NT-Password");

	rad_assert(request->password != NULL);
	rad_assert(request->password->da->attr == PW_USER_PASSWORD);

	if (inst->normify) {
		normify(request, vp, 16);
	}

	if (vp->vp_length != 16) {
		REDEBUG("\"known good\" NT-Password has incorrect length");
		return RLM_MODULE_INVALID;
	}

	len = fr_utf8_to_ucs2(ucs2_password, sizeof(ucs2_password), request->password->vp_strvalue, request->password->vp_length);
	if (len < 0) {
		REDEBUG("User-Password is not in UCS2 format");
		return RLM_MODULE_INVALID;
	}

	fr_md4_calc(digest, (uint8_t *) ucs2_password, len);

	if (rad_digest_cmp(digest, vp->vp_octets, vp->vp_length) != 0) {
		REDEBUG("NT digest does not match \"known good\" digest");
		return RLM_MODULE_REJECT;
	}

	return RLM_MODULE_OK;
}


static rlm_rcode_t CC_HINT(nonnull) pap_auth_lm(rlm_pap_t *inst, REQUEST *request, VALUE_PAIR *vp)
{
	uint8_t digest[16];
	char charbuf[32 + 1];
	ssize_t len;

	RDEBUG("Comparing with \"known-good\" LM-Password");

	if (inst->normify) {
		normify(request, vp, 16);
	}
	if (vp->vp_length != 16) {
		REDEBUG("\"known good\" LM-Password has incorrect length");
		return RLM_MODULE_INVALID;
	}

	len = radius_xlat(charbuf, sizeof(charbuf), request, "%{mschap:LM-Hash %{User-Password}}", NULL, NULL);
	if (len < 0){
		return RLM_MODULE_FAIL;
	}

	if ((fr_hex2bin(digest, sizeof(digest), charbuf, len) != vp->vp_length) ||
	    (rad_digest_cmp(digest, vp->vp_octets, vp->vp_length) != 0)) {
		REDEBUG("LM digest does not match \"known good\" digest");
		return RLM_MODULE_REJECT;
	}

	return RLM_MODULE_OK;
}

static rlm_rcode_t CC_HINT(nonnull) pap_auth_ns_mta_md5(UNUSED rlm_pap_t *inst, REQUEST *request, VALUE_PAIR *vp)
{
	FR_MD5_CTX md5_context;
	uint8_t digest[128];
	uint8_t buff[MAX_STRING_LEN];
	uint8_t buff2[MAX_STRING_LEN + 50];

	RDEBUG("Using NT-MTA-MD5-Password");

	if (vp->vp_length != 64) {
		REDEBUG("\"known good\" NS-MTA-MD5-Password has incorrect length");
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
		memcpy(p, (uint8_t const *)request->password->vp_strvalue, request->password->vp_length);
		p += request->password->vp_length;
		*(p++) = 247;
		memcpy(p, &vp->vp_octets[32], 32);
		p += 32;

		fr_md5_init(&md5_context);
		fr_md5_update(&md5_context, buff2, p - buff2);
		fr_md5_final(buff, &md5_context);
	}

	if (rad_digest_cmp(digest, buff, 16) != 0) {
		REDEBUG("NS-MTA-MD5 digest does not match \"known good\" digest");
		return RLM_MODULE_REJECT;
	}

	return RLM_MODULE_OK;
}


/*
 *	Authenticate the user via one of any well-known password.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authenticate(void *instance, REQUEST *request)
{
	rlm_pap_t *inst = instance;
	VALUE_PAIR *vp;
	rlm_rcode_t rc = RLM_MODULE_INVALID;
	vp_cursor_t cursor;
	rlm_rcode_t (*auth_func)(rlm_pap_t *, REQUEST *, VALUE_PAIR *) = NULL;

	if (!request->password ||
	    (request->password->da->vendor != 0) ||
	    (request->password->da->attr != PW_USER_PASSWORD)) {
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
		RDEBUG3("Login attempt with password \"%s\" (%zd)", request->password->vp_strvalue, request->password->vp_length);
	} else {
		RDEBUG("Login attempt with password");
	}

	/*
	 *	Auto-detect passwords, by attribute in the
	 *	config items, to find out which authentication
	 *	function to call.
	 */
	for (vp = fr_cursor_init(&cursor, &request->config);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		if (!vp->da->vendor) switch (vp->da->attr) {
		case PW_CLEARTEXT_PASSWORD:
			auth_func = &pap_auth_clear;
			break;

		case PW_CRYPT_PASSWORD:
			auth_func = &pap_auth_crypt;
			break;

		case PW_MD5_PASSWORD:
			auth_func = &pap_auth_md5;
			break;

		case PW_SMD5_PASSWORD:
			auth_func = &pap_auth_smd5;
			break;

#ifdef HAVE_OPENSSL_EVP_H
		case PW_SHA2_PASSWORD:
			auth_func = &pap_auth_sha2;
			break;

		case PW_SSHA2_224_PASSWORD:
		case PW_SSHA2_256_PASSWORD:
		case PW_SSHA2_384_PASSWORD:
		case PW_SSHA2_512_PASSWORD:
			auth_func = &pap_auth_ssha2;
			break;
#endif

		case PW_SHA_PASSWORD:
			auth_func = &pap_auth_sha;
			break;

		case PW_SSHA_PASSWORD:
			auth_func = &pap_auth_ssha;
			break;

		case PW_NT_PASSWORD:
			auth_func = &pap_auth_nt;
			break;

		case PW_LM_PASSWORD:
			auth_func = &pap_auth_lm;
			break;

		case PW_NS_MTA_MD5_PASSWORD:
			auth_func = &pap_auth_ns_mta_md5;
			break;

		default:
			break;
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
	.type		= RLM_TYPE_HUP_SAFE,
	.inst_size	= sizeof(rlm_pap_t),
	.config		= module_config,
	.instantiate	= mod_instantiate,
	.methods = {
		[MOD_AUTHENTICATE]	= mod_authenticate,
		[MOD_AUTHORIZE]		= mod_authorize
	},
};
