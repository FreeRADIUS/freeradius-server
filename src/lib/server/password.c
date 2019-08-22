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
	normalise_t		normalised;

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
 * @note The buffer for octets types\ attributes is extended by one byte
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
