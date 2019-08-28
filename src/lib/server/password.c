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

#include <freeradius-devel/util/value.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/base64.h>

#include <freeradius-devel/protocol/freeradius/freeradius.internal.password.h>

#ifdef HAVE_OPENSSL_EVP_H
#  include <openssl/evp.h>
#endif

static fr_dict_t *dict_freeradius = NULL;

static fr_dict_attr_t const *attr_cleartext_password;
static fr_dict_attr_t const *attr_password_with_header;

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

extern fr_dict_autoload_t password_dict[];
fr_dict_autoload_t password_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ NULL }
};

extern fr_dict_attr_autoload_t password_dict_attr[];
fr_dict_attr_autoload_t password_dict_attr[] = {
	{ .out = &attr_cleartext_password, .name = "Cleartext-Password", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_password_with_header, .name = "Password-With-Header", .type = FR_TYPE_STRING, .dict = &dict_freeradius },

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

	{ NULL }
};


typedef enum {
	NORMALISED_NOTHING = 0,
	NORMALISED_B64,
	NORMALISED_HEX
} normalise_t;

static fr_table_num_sorted_t const normalise_table[] = {
	{ "base64",	NORMALISED_B64		},
	{ "hex",	NORMALISED_HEX		},
	{ "nothing",	NORMALISED_NOTHING	}
};
static size_t normalise_table_len = NUM_ELEMENTS(normalise_table);

static ssize_t normify(normalise_t *action, uint8_t *buffer, size_t bufflen,
		       char const *known_good, size_t len, size_t min_len)
{
	if (min_len >= bufflen) return 0; /* paranoia */

	/*
	 *	Hex encoding. Length is even, and it's greater than
	 *	twice the minimum length.
	 */
	if (!(len & 0x01) && len >= (2 * min_len)) {
		size_t	decoded;

		decoded = fr_hex2bin(buffer, bufflen, known_good, len);
		if (decoded == (len >> 1)) {
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

	/*
	 *	Else unknown encoding, or already binary.  Leave it.
	 */
	if (action) *action = NORMALISED_NOTHING;
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
 * @param[in] min_len		we expect the decoded version to be.
 * @return
 *	- NULL if known_good was already normalised.
 *	- A new normalised password pair.
 */
VALUE_PAIR *password_normify(TALLOC_CTX *ctx, REQUEST *request, VALUE_PAIR const *known_good, size_t min_len)
{
	uint8_t			buffer[256];
	ssize_t			decoded;
	VALUE_PAIR		*out;
	normalise_t		normalised = NORMALISED_NOTHING;

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
		fr_pair_value_memcpy(out, buffer, decoded, known_good->vp_tainted);
	}

	/*
	 *	Else unknown encoding, or already binary.  Leave it.
	 */
	return NULL;
}

/** Convert a Password-With-Header attribute to the correct type
 *
 * Attribute may be base64 encoded, in which case it will be decoded
 * first, then evaluated.
 *
 * @note The buffer for octets type attributes is extended by one byte
 *	and '\0' terminated, to allow it to be used as a char buff.
 *
 * @param[in] ctx		to allocate new pairs in.
 * @param[in] request		Current request.
 * @param[in] known_good	Password-With-Header attribute to convert.
 * @param[in] func		to convert header strings to fr_dict_attr_t.
 * @param[in] def		Default attribute to copy value to if we
 *				don't recognise the header.
 * @return
 *	- New #VALUE_PAIR on success.
 *	- NULL on error.
 */
VALUE_PAIR *password_normify_with_header(TALLOC_CTX *ctx, REQUEST *request, VALUE_PAIR *known_good,
					 password_header_lookup_t func, fr_dict_attr_t const *def)
{
	char const		*p, *q, *end;

	uint8_t			n1[256], n2[256];
	ssize_t			decoded;

	char			header[128];
	normalise_t		normalised;

	int			i;

	VALUE_PAIR		*new;

	VP_VERIFY(known_good);

	/*
	 *	Ensure this is only ever called with a
	 *	string type attribute.
	 */
	rad_assert(known_good->da->type == FR_TYPE_STRING);

	p = known_good->vp_strvalue;
	end = p + known_good->vp_length;

	/*
	 *	Only allow one additional level of
	 *	normification and header parsing.
	 */
	for (i = 0; i <= 1; i++) {
		/*
		 *	Has a header {...} prefix
		 */
		if ((*p == '{') && (q = memchr(p, '}', end - p))) {
			size_t			hlen;
			fr_dict_attr_t const	*da;
			ssize_t			slen;

			hlen = (q - p) + 1;
			if (hlen >= sizeof(header)) {
				REDEBUG("Password header too long.  Got %zu bytes must be less than %zu bytes",
					hlen, sizeof(header));
				return NULL;
			}

			memcpy(header, p, hlen);
			header[hlen] = '\0';

			slen = func(&da, header);
			if (slen <= 0) {
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
				goto unknown_header;
			}

			p = q + 1;

			/*
			 *	Try and base64 decode, and if we can
			 *	use the decoded value.
			 *
			 *	FIXME: Should pass in min length for
			 *	password hash da represents.
			 */
			decoded = normify(&normalised, n1, sizeof(n1), p, end - p, 1);
			if (decoded > 0) {
				RDEBUG2("Normalizing %s %s encoding, %zu bytes -> %zu bytes",
					da->name, fr_table_str_by_value(normalise_table, normalised, 0),
					(end - p), decoded);
				p = (char const *)n1;
				end = p + decoded;
			}

			new = fr_pair_afrom_da(ctx, da);
			switch (da->type) {
			case FR_TYPE_OCTETS:
				fr_pair_value_memcpy(new, (uint8_t const *)p, end - p, true);
				break;

			case FR_TYPE_STRING:
				fr_pair_value_bstrncpy(new, (uint8_t const *)p, end - p);
				break;

			default:
				if (!fr_cond_assert(0)) return NULL;
			}
			return new;
		}

		/*
		 *	Doesn't have a header {...} prefix
		 *
		 *	See if it's base64 or hex, if it is, decode it and check again!
		 */
		decoded = normify(&normalised, n1, sizeof(n1), p, end - p, 1);
		if (decoded > 0) {
			if ((n1[0] == '{') && (memchr(n1, '}', decoded) != NULL)) {
				RDEBUG2("Normalizing %s %s encoding, %zu bytes -> %zu bytes",
					known_good->da->name, fr_table_str_by_value(normalise_table, normalised, 0),
					known_good->vp_length, decoded);

				/*
				 *	Password-With-Header is a string attribute.
				 *	Even though we're handling binary data, the header
				 *	must be \0 terminated.
				 */
				memcpy(n2, n1, decoded);
				p = (char const *)n2;
				end = p + decoded;
				continue;
			}
		}

		break;
	}

	if (RDEBUG_ENABLED3) {
		RDEBUG3("No {...} in &%pP, re-writing to %s", known_good, def->name);
	} else {
		RDEBUG2("No {...} in &%s, re-writing to %s", known_good->da->name, def->name);
	}

unknown_header:
	new = fr_pair_afrom_da(request, def);
	fr_pair_value_bstrncpy(new, p, end - p);

	return new;
}


/*
 *	For auto-header discovery.
 *
 *	@note Header comparison is case insensitive.
 *
 *	We don't put the *value* of "attr_foo" here, as those
 *	values are loaded at run time.  Instead, we point to
 *	the attr_foo definition, which is then a static pointer
 *	to a known variable.
 */
static fr_table_ptr_ordered_t const header_names[] = {
	{ "X- orclntv}",	&attr_nt_password },
	{ "{base64_md5}",	&attr_md5_password },
	{ "{cleartext}",	&attr_cleartext_password },
	{ "{clear}",		&attr_cleartext_password },
	{ "{crypt}",		&attr_crypt_password },
	{ "{md4}",		&attr_nt_password },
	{ "{md5}",		&attr_md5_password },
	{ "{ns-mta-md5}",	&attr_ns_mta_md5_password },
	{ "{nthash}",		&attr_nt_password },
	{ "{nt}",		&attr_nt_password },
#ifdef HAVE_OPENSSL_EVP_H
	{ "{sha224}",		&attr_sha2_password },
	{ "{sha256}",		&attr_sha2_password },
	{ "{sha2}",		&attr_sha2_password },
	{ "{sha384}",		&attr_sha2_password },
	{ "{sha512}",		&attr_sha2_password },
#endif
	{ "{sha}",		&attr_sha_password },
	{ "{smd5}",		&attr_smd5_password },
#ifdef HAVE_OPENSSL_EVP_H
	{ "{ssha224}",		&attr_ssha2_224_password },
	{ "{ssha256}",		&attr_ssha2_256_password },
#  if OPENSSL_VERSION_NUMBER >= 0x10101000L
	{ "{ssha3-224}",	&attr_ssha3_224_password },
	{ "{ssha3-256}",	&attr_ssha3_256_password },
	{ "{ssha3-384}",	&attr_ssha3_384_password },
	{ "{ssha3-512}",	&attr_ssha3_512_password },
#  endif
	{ "{ssha384}",		&attr_ssha2_384_password },
	{ "{ssha512}",		&attr_ssha2_512_password },
#endif
	{ "{ssha}",		&attr_ssha_password },
	{ "{x- orcllmv}",	&attr_lm_password },
	{ "{x-nthash}",		&attr_nt_password },
	{ "{x-pbkdf2}",		&attr_pbkdf2_password },
};
static size_t header_names_len = NUM_ELEMENTS(header_names);


static ssize_t known_password_header(fr_dict_attr_t const **out, char const *header)
{
	fr_dict_attr_t const **da;

	da = fr_table_value_by_str(header_names, header, NULL);
	if (!da || !*da) return -1;

	*out = *da;
	return strlen(header);
}

static const size_t fr_password_length[] = {
	[FR_LM_PASSWORD - 5000 ]	= 16,
	[FR_MD5_PASSWORD - 5000 ]	= 16,
	[FR_MS_CHAP_PASSWORD - 5000 ]	= 0, /* used only by radclient */
	[FR_NS_MTA_MD5_PASSWORD - 5000 ] = 0, /* not used at all by anyone/// */
	[FR_NT_PASSWORD - 5000 ]	= 16,
	[FR_PBKDF2_PASSWORD - 5000 ]	= 0, /* already normalized */
	[FR_SHA_PASSWORD - 5000 ]	= 20,
	[FR_SHA1_PASSWORD - 5000 ]	= 20,
	[FR_SHA2_PASSWORD - 5000 ]	= 28,
	[FR_SHA3_PASSWORD - 5000 ]	= 28,
	[FR_SMD5_PASSWORD - 5000 ]	= 16,
	[FR_SSHA_PASSWORD - 5000 ]	= 20,
	[FR_SSHA1_PASSWORD - 5000 ]	= 20,
	[FR_SSHA2_224_PASSWORD - 5000 ]	= 28,
	[FR_SSHA2_256_PASSWORD - 5000 ]	= 32,
	[FR_SSHA2_384_PASSWORD - 5000 ]	= 48,
	[FR_SSHA2_512_PASSWORD - 5000 ]	= 64,
	[FR_SSHA3_224_PASSWORD - 5000 ]	= 28,
	[FR_SSHA3_256_PASSWORD - 5000 ]	= 32,
	[FR_SSHA3_384_PASSWORD - 5000 ]	= 48,
	[FR_SSHA3_512_PASSWORD - 5000 ]	= 64,
};
#define MAX_KNOWN_PASSWORD (sizeof(fr_password_length) / sizeof(fr_password_length[0]))


/** Normalise passwords.
 *
 * @param request the request to process
 * @param normalise whether or not we normalise the passwords
 *
 */
VALUE_PAIR *password_normalise(REQUEST *request, bool normalise)
{
	VALUE_PAIR		*vp, *found_pw = NULL;
	fr_cursor_t		cursor;
	fr_dict_attr_t const	*root;

	root = fr_dict_root(dict_freeradius);
	if (!root) return NULL;

	for (vp = fr_cursor_init(&cursor, &request->control);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		VP_VERIFY(vp);
		VALUE_PAIR *new;

	next:
		/*
		 *	Look only for out attributes.  Note that we no
		 *	longer complain about User-Password being in
		 *	the control list.  That functionality has been
		 *	deprecated for 10 years.  If the admins still
		 *	do it, too bad.
		 */
		if (vp->da->parent != root) continue;

		if ((vp->da->attr < 5000) || (vp->da->attr >= (5000 + MAX_KNOWN_PASSWORD))) continue;

		/*
		 *	Remove the header, and convert it to something sane.
		 */
		if (vp->da->attr == FR_PASSWORD_WITH_HEADER) {
			/*
			 *	Password already exists: use that instead of this one.
			 */
			if (fr_pair_find_by_da(request->control, attr_cleartext_password, TAG_ANY)) {
				RWDEBUG("Config already contains a \"known good\" password "
					"(&control:%s).  Ignoring &control:%s",
					attr_cleartext_password->name, vp->da->name);
				break;
			}

			MEM(new = password_normify_with_header(request, request, vp,
							       known_password_header,
							       attr_cleartext_password));
			if (RDEBUG_ENABLED3) {
				RDEBUG3("Normalized &control:%pP -> &control:%pP", vp, new);
			} else {
				RDEBUG2("Normalized &control:%s -> &control:%s", vp->da->name, new->da->name);
			}

			RDEBUG2("Removing &control:%s", vp->da->name);
			fr_cursor_free_item(&cursor);			/* advances the cursor for us */
			fr_cursor_append(&cursor, new);			/* inserts at the end of the list */

			found_pw = new;

			vp = fr_cursor_current(&cursor);
			if (vp) goto next;
			break;
		}

		found_pw = vp;

		/*
		 *	Don't normalise Cleartext Passwords
		 */
		if (vp->da->attr == FR_CLEARTEXT_PASSWORD) break;

		if (!normalise) break;

		if (!fr_password_length[vp->da->attr - 5000]) break;

		new = password_normify(request, request, vp, fr_password_length[vp->da->attr - 5000]);
		if (new) {
			fr_cursor_free_item(&cursor);		/* free the old pasword */
			fr_cursor_append(&cursor, new);		/* inserts at the end of the list */

			vp = fr_cursor_current(&cursor);
			if (vp) goto next;
			break;
		}

		/*
		 *	Can't normalise this one, but there might be
		 *	another one that we can normalise.
		 */
	}

	/*
	 *	Print helpful warnings if there was no password.
	 */
	if (found_pw) {
		if (RDEBUG_ENABLED3) {
			RDEBUG("Found \"known good\" password in &control:%s = \"%pV\"", found_pw->da->name, &found_pw->data);
		} else {
			RDEBUG("Found \"known good\" password in &control:%s", found_pw->da->name);
		}

	} else {
		RWDEBUG("No \"known good\" password found for the user.");
		RWDEBUG("Authentication may fail unless a \"known good\" password is available");
	}

	return found_pw;
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
