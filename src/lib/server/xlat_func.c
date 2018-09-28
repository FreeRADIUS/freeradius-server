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
 * @file xlat_func.c
 * @brief String expansion ("translation").  Baked in expansions.
 *
 * @copyright 2000,2006  The FreeRADIUS server project
 * @copyright 2000  Alan DeKok <aland@ox.org>
 */

RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/parser.h>
#include <freeradius-devel/server/rad_assert.h>
#include <freeradius-devel/util/base64.h>
#include <freeradius-devel/util/md5.h>
#include <freeradius-devel/util/sha1.h>
#include <freeradius-devel/util/value.h>
#ifdef HAVE_OPENSSL_EVP_H
#  include <openssl/evp.h>
#endif

#include <ctype.h>
#include "xlat_priv.h"

static rbtree_t *xlat_root = NULL;

#ifdef WITH_UNLANG
static char const * const xlat_foreach_names[] = {"Foreach-Variable-0",
						  "Foreach-Variable-1",
						  "Foreach-Variable-2",
						  "Foreach-Variable-3",
						  "Foreach-Variable-4",
						  "Foreach-Variable-5",
						  "Foreach-Variable-6",
						  "Foreach-Variable-7",
						  "Foreach-Variable-8",
						  "Foreach-Variable-9",
						  NULL};
#endif

/*
 *	Lookup tables for randstr char classes
 */
static char randstr_punc[] = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
static char randstr_salt[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmopqrstuvwxyz/.";

/*
 *	Characters humans rarely confuse. Reduces char set considerably
 *	should only be used for things such as one time passwords.
 */
static char randstr_otp[] = "469ACGHJKLMNPQRUVWXYabdfhijkprstuvwxyz";

static char const hextab[] = "0123456789abcdef";

static int xlat_foreach_inst[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };	/* up to 10 for foreach */

/** Return a VP from the specified request.
 *
 * @param out where to write the pointer to the resolved VP. Will be NULL if the attribute couldn't
 *	be resolved.
 * @param request current request.
 * @param name attribute name including qualifiers.
 * @return
 *	- -4 if either the attribute or qualifier were invalid.
 *	- The same error codes as #tmpl_find_vp for other error conditions.
 */
int xlat_fmt_get_vp(VALUE_PAIR **out, REQUEST *request, char const *name)
{
	int rcode;
	vp_tmpl_t *vpt;

	*out = NULL;

	if (tmpl_afrom_attr_str(request, &vpt, name, &(vp_tmpl_rules_t){ .dict_def = request->dict }) <= 0) return -4;

	rcode = tmpl_find_vp(out, request, vpt);
	talloc_free(vpt);

	return rcode;
}

/** Copy VP(s) from the specified request.
 *
 * @param ctx to alloc new VALUE_PAIRs in.
 * @param out where to write the pointer to the copied VP. Will be NULL if the attribute couldn't be
 *	resolved.
 * @param request current request.
 * @param name attribute name including qualifiers.
 * @return
 *	- -4 if either the attribute or qualifier were invalid.
 *	- The same error codes as #tmpl_find_vp for other error conditions.
 */
int xlat_fmt_copy_vp(TALLOC_CTX *ctx, VALUE_PAIR **out, REQUEST *request, char const *name)
{
	int rcode;
	vp_tmpl_t *vpt;

	*out = NULL;

	if (tmpl_afrom_attr_str(request, &vpt, name, &(vp_tmpl_rules_t){ .dict_def = request->dict }) <= 0) return -4;

	rcode = tmpl_copy_vps(ctx, out, request, vpt);
	talloc_free(vpt);

	return rcode;
}

/** Print length of its RHS.
 *
 */
static ssize_t xlat_strlen(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			   UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			   UNUSED REQUEST *request, char const *fmt)
{
	snprintf(*out, outlen, "%u", (unsigned int) strlen(fmt));
	return strlen(*out);
}

/** Print the size of the attribute in bytes.
 *
 */
static ssize_t xlat_length(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			   UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			   REQUEST *request, char const *fmt)
{
	VALUE_PAIR *vp;

	while (isspace((int) *fmt)) fmt++;

	if ((xlat_fmt_get_vp(&vp, request, fmt) < 0) || !vp) return 0;

	snprintf(*out, outlen, "%zu", fr_value_box_network_length(&vp->data));
	return strlen(*out);
}

/** Print data as integer, not as VALUE.
 *
 */
static ssize_t xlat_integer(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			    UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			    REQUEST *request, char const *fmt)
{
	VALUE_PAIR 	*vp;

	uint64_t 	int64 = 0;	/* Needs to be initialised to zero */
	uint32_t	int32 = 0;	/* Needs to be initialised to zero */

	while (isspace((int) *fmt)) fmt++;

	if ((xlat_fmt_get_vp(&vp, request, fmt) < 0) || !vp) return 0;

	switch (vp->vp_type) {
	case FR_TYPE_OCTETS:
	case FR_TYPE_STRING:
		if (vp->vp_length > 8) {
			break;
		}

		if (vp->vp_length > 4) {
			memcpy(&int64, vp->vp_octets, vp->vp_length);
			return snprintf(*out, outlen, "%" PRIu64, htonll(int64));
		}

		memcpy(&int32, vp->vp_octets, vp->vp_length);
		return snprintf(*out, outlen, "%i", htonl(int32));

	case FR_TYPE_UINT64:
		return snprintf(*out, outlen, "%" PRIu64, vp->vp_uint64);

	/*
	 *	IP addresses are treated specially, as parsing functions assume the value
	 *	is bigendian and will convert it for us.
	 */
	case FR_TYPE_IPV4_ADDR:
	case FR_TYPE_IPV4_PREFIX:	/* Same addr field */
		return snprintf(*out, outlen, "%u", htonl(vp->vp_ipv4addr));

	case FR_TYPE_UINT32:
		return snprintf(*out, outlen, "%u", vp->vp_uint32);

	case FR_TYPE_DATE:
		return snprintf(*out, outlen, "%u", vp->vp_date);

	case FR_TYPE_UINT8:
		return snprintf(*out, outlen, "%u", (unsigned int) vp->vp_uint8);

	case FR_TYPE_UINT16:
		return snprintf(*out, outlen, "%u", (unsigned int) vp->vp_uint16);

	/*
	 *	Ethernet is weird... It's network related, so we assume to it should be
	 *	bigendian.
	 */
	case FR_TYPE_ETHERNET:
		memcpy(&int64, vp->vp_ether, sizeof(vp->vp_ether));
		return snprintf(*out, outlen, "%" PRIu64, htonll(int64));

	case FR_TYPE_INT32:
		return snprintf(*out, outlen, "%i", vp->vp_int32);

	case FR_TYPE_IPV6_ADDR:
	case FR_TYPE_IPV6_PREFIX:
		return fr_snprint_uint128(*out, outlen, ntohlll(*(uint128_t const *) &vp->vp_ipv6addr));

	default:
		break;
	}

	REDEBUG("Type '%s' cannot be converted to integer", fr_int2str(fr_value_box_type_names, vp->vp_type, "???"));

	return -1;
}

/** Print data as hex, not as VALUE.
 *
 */
static ssize_t xlat_hex(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			REQUEST *request, char const *fmt)
{
	size_t i;
	VALUE_PAIR *vp;
	uint8_t const *p;
	size_t	len;
	fr_value_box_t dst;
	uint8_t const *buff = NULL;

	while (isspace((int) *fmt)) fmt++;

	if ((xlat_fmt_get_vp(&vp, request, fmt) < 0) || !vp) {
	error:
		return -1;
	}

	/*
	 *	The easy case.
	 */
	if (vp->vp_type == FR_TYPE_OCTETS) {
		p = vp->vp_octets;
		len = vp->vp_length;
	/*
	 *	Cast the fr_value_box_t of the VP to an octets string and
	 *	print that as hex.
	 */
	} else {
		if (fr_value_box_cast(request, &dst, FR_TYPE_OCTETS, NULL, &vp->data) < 0) {
			RPEDEBUG("Invalid cast");
			goto error;
		}
		len = (size_t)dst.datum.length;
		p = buff = dst.vb_octets;
	}

	rad_assert(p);

	/*
	 *	Don't truncate the data.
	 */
	if (outlen < (len * 2)) {
		talloc_const_free(buff);
		goto error;
	}

	for (i = 0; i < len; i++) {
		snprintf((*out) + (2 * i), 3, "%02x", p[i]);
	}
	talloc_const_free(buff);

	return len * 2;
}

/** Return the tag of an attribute reference
 *
 */
static ssize_t xlat_tag(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			REQUEST *request, char const *fmt)
{
	VALUE_PAIR *vp;

	while (isspace((int) *fmt)) fmt++;

	if ((xlat_fmt_get_vp(&vp, request, fmt) < 0) || !vp) return 0;

	if (!vp->da->flags.has_tag || !TAG_VALID(vp->tag)) return 0;

	return snprintf(*out, outlen, "%u", vp->tag);
}

/** Print out attribute info
 *
 * Prints out all instances of a current attribute, or all attributes in a list.
 *
 * At higher debugging levels, also prints out alternative decodings of the same
 * value. This is helpful to determine types for unknown attributes of long
 * passed vendors, or just crazy/broken NAS.
 *
 * This expands to a zero length string.
 */
static ssize_t xlat_debug_attr(UNUSED TALLOC_CTX *ctx, UNUSED char **out, UNUSED size_t outlen,
			       UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			       REQUEST *request, char const *fmt)
{
	VALUE_PAIR	*vp;
	fr_cursor_t	cursor;
	vp_tmpl_t	*vpt;

	if (!RDEBUG_ENABLED2) return -1;

	while (isspace((int) *fmt)) fmt++;

	if (tmpl_afrom_attr_str(request, &vpt, fmt, &(vp_tmpl_rules_t){ .dict_def = request->dict }) <= 0) {
		RPEDEBUG("Invalid input");
		return -1;
	}

	RIDEBUG("Attributes matching \"%s\"", fmt);

	RINDENT();
	for (vp = tmpl_cursor_init(NULL, &cursor, request, vpt);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		fr_dict_vendor_t const	*vendor;
		FR_NAME_NUMBER const	*type;

		if (vp->da->flags.has_tag) {
			RIDEBUG2("&%s:%s:%i %s %pV",
				fr_int2str(pair_lists, vpt->tmpl_list, "<INVALID>"),
				vp->da->name,
				vp->tag,
				fr_int2str(fr_tokens_table, vp->op, "<INVALID>"),
				&vp->data);
		} else {
			RIDEBUG2("&%s:%s %s %pV",
				fr_int2str(pair_lists, vpt->tmpl_list, "<INVALID>"),
				vp->da->name,
				fr_int2str(fr_tokens_table, vp->op, "<INVALID>"),
				&vp->data);
		}

		if (!RDEBUG_ENABLED3) continue;

		vendor = fr_dict_vendor_by_da(vp->da);
		if (vendor) RIDEBUG2("Vendor : %i (%s)", vendor->pen, vendor->name);
		RIDEBUG2("Type   : %s", fr_int2str(fr_value_box_type_names, vp->vp_type, "<INVALID>"));

		switch (vp->vp_type) {
		case FR_TYPE_VARIABLE_SIZE:
			RIDEBUG2("Length : %zu", vp->vp_length);
			break;

		default:
			break;
		}

		if (!RDEBUG_ENABLED4) continue;

		type = fr_value_box_type_names;
		while (type->name) {
			int pad;

			fr_value_box_t *dst = NULL;

			if ((fr_type_t) type->number == vp->vp_type) goto next_type;

			switch (type->number) {
			case FR_TYPE_INVALID:		/* Not real type */
			case FR_TYPE_MAX:		/* Not real type */
			case FR_TYPE_COMBO_IP_ADDR:	/* Covered by IPv4 address IPv6 address */
			case FR_TYPE_COMBO_IP_PREFIX:	/* Covered by IPv4 address IPv6 address */
			case FR_TYPE_TIMEVAL:		/* Not a VALUE_PAIR type */
			case FR_TYPE_STRUCTURAL:
				goto next_type;

			default:
				break;
			}

			dst = fr_value_box_alloc_null(vp);
			/* We expect some to fail */
			if (fr_value_box_cast(dst, dst, type->number, NULL, &vp->data) < 0) {
				goto next_type;
			}

			if ((pad = (11 - strlen(type->name))) < 0) pad = 0;

			RINDENT();
			RDEBUG2("as %s%*s: %pV", type->name, pad, " ", dst);
			REXDENT();

		next_type:
			talloc_free(dst);
			type++;
		}
	}
	REXDENT();

	talloc_free(vpt);

	return 0;
}

/** Processes fmt as a map string and applies it to the current request
 *
 * e.g. "%{map:&User-Name := 'foo'}"
 *
 * Allows sets of modifications to be cached and then applied.
 * Useful for processing generic attributes from LDAP.
 */
static ssize_t xlat_map(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			REQUEST *request, char const *fmt)
{
	vp_map_t	*map = NULL;
	int		ret;

	vp_tmpl_rules_t parse_rules = {
		.dict_def = request->dict
	};


	if (map_afrom_attr_str(request, &map, fmt, &parse_rules, &parse_rules) < 0) {
		RPEDEBUG("Failed parsing \"%s\" as map", fmt);
		return -1;
	}

	RINDENT();
	ret = map_to_request(request, map, map_to_vp, NULL);
	REXDENT();
	talloc_free(map);
	if (ret < 0) return strlcpy(*out, "0", outlen);

	return strlcpy(*out, "1", outlen);
}

/** Prints the current module processing the request
 *
 */
static ssize_t xlat_module(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			   UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			   REQUEST *request, UNUSED char const *fmt)
{
	strlcpy(*out, request->module, outlen);

	return strlen(*out);
}

#if defined(HAVE_REGEX) && defined(HAVE_REGEX_PCRE)
static ssize_t xlat_regex(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			  UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			  REQUEST *request, char const *fmt)
{
	char *p;
	size_t len;

	if (regex_request_to_sub_named(request, &p, request, fmt) < 0) return 0;

	len = talloc_array_length(p);
	if (len > outlen) {
		RDEBUG("Insufficient buffer space to write subcapture value, needed %zu bytes, have %zu bytes",
		       len, outlen);
		return -1;
	}
	strlcpy(*out, p, outlen);

	return len - 1; /* - \0 */
}
#endif

#ifdef WITH_UNLANG
/** Implements the Foreach-Variable-X
 *
 * @see modcall()
 */
static ssize_t xlat_foreach(TALLOC_CTX *ctx, char **out, UNUSED size_t outlen,
			    void const *mod_inst, UNUSED void const *xlat_inst,
			    REQUEST *request, UNUSED char const *fmt)
{
	VALUE_PAIR	**pvp;

	/*
	 *	See modcall, "FOREACH" for how this works.
	 */
	pvp = (VALUE_PAIR **) request_data_reference(request, (void *)xlat_fmt_get_vp, *(int const *) mod_inst);
	if (!pvp || !*pvp) return 0;

	*out = fr_pair_value_asprint(ctx, *pvp, '\0');
	return 	talloc_array_length(*out) - 1;
}
#endif

/** Print data as string, if possible.
 *
 * If attribute "Foo" is defined as "octets" it will normally
 * be printed as 0x0a0a0a. The xlat "%{string:Foo}" will instead
 * expand to "\n\n\n"
 */
static ssize_t xlat_string(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			   UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			   REQUEST *request, char const *fmt)
{
	ssize_t		ret;
	VALUE_PAIR	*vp;
	uint8_t		buffer[64];

	while (isspace((int) *fmt)) fmt++;

	if (outlen < 3) {
	nothing:
		return 0;
	}

	if ((xlat_fmt_get_vp(&vp, request, fmt) < 0) || !vp) goto nothing;

	/*
	 *	These are printed specially.
	 */
	switch (vp->vp_type) {
	case FR_TYPE_OCTETS:
		return fr_snprint(*out, outlen, (char const *) vp->vp_octets, vp->vp_length, '"');

		/*
		 *	Note that "%{string:...}" is NOT binary safe!
		 *	It is explicitly used to get rid of embedded zeros.
		 */
	case FR_TYPE_STRING:
		return strlcpy(*out, vp->vp_strvalue, outlen);

	default:
		break;
	}

	ret = fr_value_box_to_network(NULL, buffer, sizeof(buffer), &vp->data);
	if (ret < 0) return ret;

	return fr_snprint(*out, outlen, (char const *) buffer, ret, '\0');
}

/** xlat expand string attribute value
 *
 */
static ssize_t xlat_xlat(TALLOC_CTX *ctx, char **out, size_t outlen,
			 UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			 REQUEST *request, char const *fmt)
{
	ssize_t slen;
	VALUE_PAIR *vp;

	while (isspace((int) *fmt)) fmt++;

	if (outlen < 3) {
	nothing:
		return 0;
	}

	if ((xlat_fmt_get_vp(&vp, request, fmt) < 0) || !vp) goto nothing;

	RDEBUG2("EXPAND %s", fmt);
	RINDENT();

	/*
	 *	If it's a string, expand it again
	 */
	if (vp->vp_type == FR_TYPE_STRING) {
		slen = xlat_eval(*out, outlen, request, vp->vp_strvalue, NULL, NULL);
		if (slen <= 0) return slen;
	/*
	 *	If it's not a string, treat it as a literal
	 */
	} else {
		*out = fr_pair_value_asprint(ctx, vp, '\0');
		if (!*out) return -1;
		slen = talloc_array_length(*out) - 1;
	}

	REXDENT();
	RDEBUG2("--> %s", *out);

	return slen;
}

/** Dynamically change the debugging level for the current request
 *
 * Example %{debug:3}
 */
static ssize_t xlat_debug(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			  UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			  REQUEST *request, char const *fmt)
{
	int level = 0;

	/*
	 *  Expand to previous (or current) level
	 */
	snprintf(*out, outlen, "%d", request->log.lvl);

	/*
	 *  Assume we just want to get the current value and NOT set it to 0
	 */
	if (!*fmt)
		goto done;

	level = atoi(fmt);
	if (level == 0) {
		request->log.lvl = RAD_REQUEST_LVL_NONE;
	} else {
		if (level > 4) level = 4;
		request->log.lvl = level;
	}

done:
	return strlen(*out);
}

/** Generate a random integer value
 *
 */
static xlat_action_t xlat_rand(TALLOC_CTX *ctx, fr_cursor_t *out,
			       REQUEST *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
			       fr_value_box_t **in)
{
	int64_t		result;
	fr_value_box_t*	vb;

	/* Make sure input can be converted to an unsigned 32 bit integer */
	if (fr_value_box_cast_in_place(ctx, (*in), FR_TYPE_UINT32, NULL) < 0) {
		RPEDEBUG("Failed converting input to uint32");
		return XLAT_ACTION_FAIL;
	}

	result = (*in)->vb_uint32;

	/* Make sure it isn't too big */
	if (result > (1 << 30)) result = (1 << 30);

	result *= fr_rand();	/* 0..2^32-1 */
	result >>= 32;

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_UINT64, NULL, false));
	vb->vb_uint64 = result;

	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

/** Generate a string of random chars
 *
 *  Build strings of random chars, useful for generating tokens and passcodes
 *  Format similar to String::Random.
 */
static xlat_action_t xlat_randstr(TALLOC_CTX *ctx, fr_cursor_t *out,
				  REQUEST *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
				  fr_value_box_t **in)
{
	char const 	*p, *end;
	char		*endptr;
	char		*buff, *buff_p;
	unsigned int	result;
	unsigned int	number;
	size_t		outlen = 0;
	fr_value_box_t*	vb;

	/*
	 * Nothing to do if input is empty
	 */
	if (!(*in)) {
		return XLAT_ACTION_DONE;
	}

	/*
	 * Concatenate all input
	 */
	if (fr_value_box_list_concat(ctx, *in, in, FR_TYPE_STRING, true) < 0) {
		RPEDEBUG("Failed concatenating input");
		return XLAT_ACTION_FAIL;
	}

	p = (*in)->vb_strvalue;
	end = p + (*in)->vb_length;

	/*
	 * Calculate size of output
	 */
	while (p < end) {
		if (isdigit((int) *p)) {
			number = strtol(p, &endptr, 10);
			if (number > 100) number = 100;
			/* hexits take up 2 characters */
			if (*endptr == 'h' || *endptr == 'H') number *= 2;
			outlen += number;
			p = endptr;
		} else {
			outlen++;
		}
		p++;
	}

	buff = buff_p = talloc_array(NULL, char, outlen + 1);

	/* Reset p to start position */
	p = (*in)->vb_strvalue;

	while (p < end) {
		number = 0;

		/*
		 *	Modifiers are polite.
		 *
		 *	But we limit it to 100, because we don't want
		 *	utter stupidity.
		 */
		if (isdigit((int) *p)) {
			number = strtol(p, &endptr, 10);
			p = endptr;
			if (number > 100) number = 100;
		}

	redo:
		result = fr_rand();

		switch (*p) {
		/*
		 *  Lowercase letters
		 */
		case 'c':
			*buff_p++ = 'a' + (result % 26);
			break;

		/*
		 *  Uppercase letters
		 */
		case 'C':
			*buff_p++ = 'A' + (result % 26);
			break;

		/*
		 *  Numbers
		 */
		case 'n':
			*buff_p++ = '0' + (result % 10);
			break;

		/*
		 *  Alpha numeric
		 */
		case 'a':
			*buff_p++ = randstr_salt[result % (sizeof(randstr_salt) - 3)];
			break;

		/*
		 *  Punctuation
		 */
		case '!':
			*buff_p++ = randstr_punc[result % (sizeof(randstr_punc) - 1)];
			break;

		/*
		 *  Alpa numeric + punctuation
		 */
		case '.':
			*buff_p++ = '!' + (result % 95);
			break;

		/*
		 *  Alpha numeric + salt chars './'
		 */
		case 's':
			*buff_p++ = randstr_salt[result % (sizeof(randstr_salt) - 1)];
			break;

		/*
		 *  Chars suitable for One Time Password tokens.
		 *  Alpha numeric with easily confused char pairs removed.
		 */
		case 'o':
			*buff_p++ = randstr_otp[result % (sizeof(randstr_otp) - 1)];
			break;

		/*
		 *  Binary data as hexits (we don't really support
		 *  non printable chars).
		 */
		case 'h':
			snprintf(buff_p, 3, "%02x", result % 256);

			buff_p += 2;
			break;

		/*
		 *  Binary data with uppercase hexits
		 */
		case 'H':
			snprintf(buff_p, 3, "%02X", result % 256);

			buff_p += 2;
			break;

		default:
			REDEBUG("Invalid character class '%c'", *p);
			talloc_free(buff);

			return XLAT_ACTION_FAIL;
		}

		if (number > 1) {
			number--;
			goto redo;
		}

		p++;
	}

	*buff_p++ = '\0';

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_STRING, NULL, false));
	fr_value_box_bstrsteal(vb, vb, NULL, buff, false);

	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

/** URLencode special characters
 *
 * Example: "%{urlquote:http://example.org/}" == "http%3A%47%47example.org%47"
 */
static xlat_action_t xlat_urlquote(TALLOC_CTX *ctx, fr_cursor_t *out,
				   REQUEST *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
				   fr_value_box_t **in)
{
	char const 	*p, *end;
	char		*buff, *buff_p;
	size_t		outlen = 0;
	fr_value_box_t	*vb;

	/*
	 * Nothing to do if input is empty
	 */
	if (!(*in)) {
		return XLAT_ACTION_DONE;
	}

	/*
	 * Concatenate all input
	 */
	if (fr_value_box_list_concat(ctx, *in, in, FR_TYPE_STRING, true) < 0) {
		RPEDEBUG("Failed concatenating input");
		return XLAT_ACTION_FAIL;
	}

	p = (*in)->vb_strvalue;
	end = p + (*in)->vb_length;

	/*
	 * Calculate size of output
	 */
	while (p < end) {
		if (isalnum(*p) ||
		    *p == '-' ||
		    *p == '_' ||
		    *p == '.' ||
		    *p == '~') {
			outlen++;
		} else {
			outlen += 3;
		}
		p++;
	}

	buff = buff_p = talloc_array(NULL, char, outlen + 1);

	/* Reset p to start position */
	p = (*in)->vb_strvalue;

	while (p < end) {
		if (isalnum(*p)) {
			*buff_p++ = *p++;
			continue;
		}

		switch (*p) {
		case '-':
		case '_':
		case '.':
		case '~':
			*buff_p++ = *p++;
			break;

		default:
			/* MUST be upper case hex to be compliant */
			snprintf(buff_p, 4, "%%%02X", (uint8_t) *p++); /* %XX */

			buff_p += 3;
		}
	}

	*buff_p = '\0';

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_STRING, NULL, false));
	fr_value_box_bstrsteal(vb, vb, NULL, buff, false);

	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

/** URLdecode special characters
 *
 * Example: "%{urlunquote:http%%3A%%47%%47example.org%%47}" == "http://example.org/"
 *
 * Remember to escape % with %% in strings, else xlat will try to parse it.
 */
static xlat_action_t xlat_urlunquote(TALLOC_CTX *ctx, fr_cursor_t *out,
				   REQUEST *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
				   fr_value_box_t **in)
{
	char const 	*p, *end;
	char		*buff, *buff_p;
	char *c1, *c2;
	size_t		outlen = 0;
	fr_value_box_t	*vb;

	/*
	 * Nothing to do if input is empty
	 */
	if (!(*in)) {
		return XLAT_ACTION_DONE;
	}

	/*
	 * Concatenate all input
	 */
	if (fr_value_box_list_concat(ctx, *in, in, FR_TYPE_STRING, true) < 0) {
		RPEDEBUG("Failed concatenating input");
		return XLAT_ACTION_FAIL;
	}

	p = (*in)->vb_strvalue;
	end = p + (*in)->vb_length;

	/*
	 * Calculate size of output
	 */
	while (p < end) {
		if (*p == '%') {
			p += 3;
		} else {
			p++;
		}
		outlen++;
	}

	buff = buff_p = talloc_array(NULL, char, outlen + 1);

	/* Reset p to start position */
	p = (*in)->vb_strvalue;

	while (p < end) {
		if (*p != '%') {
			*buff_p++ = *p++;
			continue;
		}
		/* Is a % char */

		/* Don't need \0 check, as it won't be in the hextab */
		if (!(c1 = memchr(hextab, tolower(*++p), 16)) ||
		    !(c2 = memchr(hextab, tolower(*++p), 16))) {
			REMARKER((*in)->vb_strvalue, p - (*in)->vb_strvalue, "Non-hex char in % sequence");
			talloc_free(buff);

			return XLAT_ACTION_FAIL;
		}
		p++;
		*buff_p++ = ((c1 - hextab) << 4) + (c2 - hextab);
	}

	*buff_p = '\0';

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_STRING, NULL, false));
	fr_value_box_bstrsteal(vb, vb, NULL, buff, false);

	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;
}


/** Convert a string to lowercase
 *
 * Example: "%{tolower:Bar}" == "bar"
 *
 * Probably only works for ASCII
 */
static ssize_t tolower_xlat(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			    UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			    UNUSED REQUEST *request, char const *fmt)
{
	char *q;
	char const *p;

	if (outlen <= 1) return 0;

	for (p = fmt, q = *out; *p != '\0'; p++, outlen--) {
		if (outlen <= 1) break;

		*(q++) = tolower((int) *p);
	}

	*q = '\0';

	return strlen(*out);
}

/** Convert a string to uppercase
 *
 * Example: "%{toupper:Foo}" == "FOO"
 *
 * Probably only works for ASCII
 */
static ssize_t toupper_xlat(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			    UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			    UNUSED REQUEST *request, char const *fmt)
{
	char *q;
	char const *p;

	if (outlen <= 1) return 0;

	for (p = fmt, q = *out; *p != '\0'; p++, outlen--) {
		if (outlen <= 1) break;

		*(q++) = toupper((int) *p);
	}

	*q = '\0';

	return strlen(*out);
}

/** Decodes data or &Attr-Name to data
 *
 * This needs to die, and hopefully will die, when xlat functions accept
 * xlat node structures.
 *
 * @param ctx		Talloc ctx for temporary allocations.
 * @param out		fr_value_box_t containing a shallow copy of the attribute,
 *			or the fmt string.
 * @param request	current request.
 * @param fmt		string.
 * @returns
 *	- The length of the data.
 *	- -1 on failure.
 */
static int fr_value_box_from_fmt(TALLOC_CTX *ctx, fr_value_box_t *out, REQUEST *request, char const *fmt)
{
	VALUE_PAIR *vp;

	while (isspace((int) *fmt)) fmt++;

	/*
	 *	Not an attribute reference?  Just use the input format.
	 */
	if (*fmt != '&') {
		memset(out, 0, sizeof(*out));
		out->vb_strvalue = fmt;
		out->datum.length = talloc_array_length(fmt) - 1;
		out->type = FR_TYPE_STRING;
		return 0;
	}

	/*
	 *	If it's an attribute reference, get the underlying
	 *	attribute, and then store the data in network byte
	 *	order.
	 */
	if ((xlat_fmt_get_vp(&vp, request, fmt) < 0) || !vp) return -1;

	fr_value_box_copy(ctx, out, &vp->data);

	return 0;
}

static int fr_value_box_to_bin(TALLOC_CTX *ctx, REQUEST *request, uint8_t **out, size_t *outlen, fr_value_box_t const *in)
{
	fr_value_box_t bin;

	switch (in->type) {
	case FR_TYPE_STRING:
	case FR_TYPE_OCTETS:
		memcpy(out, &in->datum.ptr, sizeof(in));
		*outlen = in->datum.length;
		return 0;

	default:
		if (fr_value_box_cast(ctx, &bin, FR_TYPE_OCTETS, NULL, in) < 0) {
			RPERROR("Failed casting xlat input to 'octets'");
			return -1;
		}
		memcpy(out, &bin.datum.ptr, sizeof(in));
		*outlen = bin.datum.length;
		return 0;
	}
}

#define VALUE_FROM_FMT(_tmp_ctx, _p, _len, _request, _fmt) \
	fr_value_box_t _value; \
	if (!_tmp_ctx) MEM(_tmp_ctx = talloc_new(_request)); \
	if (fr_value_box_from_fmt(_tmp_ctx, &_value, _request, _fmt) < 0) { \
		talloc_free(_tmp_ctx); \
		return -1; \
	} \
	if (fr_value_box_to_bin(_tmp_ctx, _request, &_p, &_len, &_value) < 0) { \
		talloc_free(_tmp_ctx); \
		return -1; \
	}


/** Calculate the MD5 hash of a string or attribute.
 *
 * Example: "%{md5:foo}" == "acbd18db4cc2f85cedef654fccc4a4d8"
 */
static xlat_action_t xlat_md5(TALLOC_CTX *ctx, fr_cursor_t *out,
			      REQUEST *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
			      fr_value_box_t **in)
{
	uint8_t		digest[MD5_DIGEST_LENGTH];
	FR_MD5_CTX	md5_ctx;
	fr_value_box_t	*vb;

	/*
	 * Concatenate all input if there is some
	 */
	if (*in && fr_value_box_list_concat(ctx, *in, in, FR_TYPE_OCTETS, true) < 0) {
		RPEDEBUG("Failed concatenating input");
		return XLAT_ACTION_FAIL;
	}

	fr_md5_init(&md5_ctx);
	if (*in) {
		fr_md5_update(&md5_ctx, (*in)->vb_octets, (*in)->vb_length);
	} else {
		/* MD5 of empty string */
		fr_md5_update(&md5_ctx, NULL, 0);
	}
	fr_md5_final(digest, &md5_ctx);

	MEM(vb = fr_value_box_alloc_null(ctx));
	fr_value_box_memdup(vb, vb, NULL, digest, sizeof(digest), false);

	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

/** Calculate the SHA1 hash of a string or attribute.
 *
 * Example: "%{sha1:foo}" == "0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33"
 */
static ssize_t sha1_xlat(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			 UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			 REQUEST *request, char const *fmt)
{
	uint8_t		digest[20];
	size_t		i, len, inlen;
	uint8_t		*p;
	fr_sha1_ctx 	sha1_ctx;
	TALLOC_CTX	*tmp_ctx = NULL;

	VALUE_FROM_FMT(tmp_ctx, p, inlen, request, fmt);

	fr_sha1_init(&sha1_ctx);
	fr_sha1_update(&sha1_ctx, p, inlen);
	fr_sha1_final(digest, &sha1_ctx);

	/*
	 *      Each digest octet takes two hex digits, plus one for
	 *      the terminating NUL. SHA1 is 160 bits (20 bytes)
	 */
	len = (outlen / 2) - 1;
	if (len > 20) len = 20;

	for (i = 0; i < len; i++) snprintf((*out) + (i * 2), 3, "%02x", digest[i]);

	talloc_free(tmp_ctx);

	return strlen(*out);
}

/** Calculate any digest supported by OpenSSL EVP_MD
 *
 * Example: "%{sha256:foo}" == "0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33"
 */
#ifdef HAVE_OPENSSL_EVP_H
static ssize_t evp_md_xlat(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			   UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			   REQUEST *request, char const *fmt, EVP_MD const *md)
{
	uint8_t		digest[EVP_MAX_MD_SIZE];
	unsigned int	digestlen, i, len;
	size_t		inlen;
	uint8_t		*p;
	EVP_MD_CTX	*md_ctx;
	TALLOC_CTX	*tmp_ctx = NULL;

	VALUE_FROM_FMT(tmp_ctx, p, inlen, request, fmt);

	md_ctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(md_ctx, md, NULL);
	EVP_DigestUpdate(md_ctx, p, inlen);
	EVP_DigestFinal_ex(md_ctx, digest, &digestlen);
	EVP_MD_CTX_destroy(md_ctx);

	/*
	 *      Each digest octet takes two hex digits, plus one for
	 *      the terminating NUL.
	 */
	len = (outlen / 2) - 1;
	if (len > digestlen) len = digestlen;

	for (i = 0; i < len; i++) snprintf((*out) + (i * 2), 3, "%02x", digest[i]);

	talloc_free(tmp_ctx);

	return strlen(*out);
}

#  define EVP_MD_XLAT(_md) \
static ssize_t _md##_xlat(TALLOC_CTX *ctx, char **out, size_t outlen,\
			  void const *mod_inst, void const *xlat_inst,\
			  REQUEST *request, char const *fmt)\
{\
	return evp_md_xlat(ctx, out, outlen, mod_inst, xlat_inst, request, fmt, EVP_##_md());\
}

EVP_MD_XLAT(sha224)
EVP_MD_XLAT(sha256)
EVP_MD_XLAT(sha384)
EVP_MD_XLAT(sha512)

#  ifdef HAVE_EVP_SHA3_512
EVP_MD_XLAT(sha3_224)
EVP_MD_XLAT(sha3_256)
EVP_MD_XLAT(sha3_384)
EVP_MD_XLAT(sha3_512)
#  endif
#endif

/** Generate the HMAC-MD5 of a string or attribute
 *
 * Example: "%{hmacmd5:foo bar}" == "Zm9v"
 */
static ssize_t hmac_md5_xlat(TALLOC_CTX *ctx, char **out, size_t outlen,
			     UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			     REQUEST *request, char const *fmt)
{

	char const	*p, *q;
	uint8_t		digest[MD5_DIGEST_LENGTH];

	char		*data_fmt;

	uint8_t		*data_p, *key_p;
	size_t		data_len, key_len;
	TALLOC_CTX	*tmp_ctx = NULL;

	if (outlen <= (sizeof(digest) * 2)) {
		REDEBUG("Insufficient space to write digest, needed %zu bytes, have %zu bytes",
			(sizeof(digest) * 2) + 1, outlen);
		return -1;
	}

	p = fmt;
	while (isspace(*p)) p++;

	/*
	 *	Find the delimiting char
	 */
	q = strchr(p, ' ');
	if (!q) {
		REDEBUG("HMAC requires exactly two arguments (&data &key)");
		return -1;
	}

	tmp_ctx = talloc_new(ctx);
	data_fmt = talloc_bstrndup(tmp_ctx, p, q - p);
	p = q + 1;

	{
		VALUE_FROM_FMT(tmp_ctx, data_p, data_len, request, data_fmt);
	}
	{
		VALUE_FROM_FMT(tmp_ctx, key_p, key_len, request, p);
	}
	fr_hmac_md5(digest, data_p, data_len, key_p, key_len);
	talloc_free(tmp_ctx);

	return fr_bin2hex(*out, digest, sizeof(digest));
}

/** Generate the HMAC-SHA1 of a string or attribute
 *
 * Example: "%{hmacsha1:foo bar}" == "Zm9v"
 */
static ssize_t hmac_sha1_xlat(TALLOC_CTX *ctx, char **out, size_t outlen,
			      UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			      REQUEST *request, char const *fmt)
{
	char const	*p, *q;
	uint8_t		digest[SHA1_DIGEST_LENGTH];

	char		*data_fmt;

	uint8_t		*data_p, *key_p;
	size_t		data_len, key_len;
	TALLOC_CTX	*tmp_ctx = NULL;

	if (outlen <= (sizeof(digest) * 2)) {
		REDEBUG("Insufficient space to write digest, needed %zu bytes, have %zu bytes",
			(sizeof(digest) * 2) + 1, outlen);
		return -1;
	}

	p = fmt;
	while (isspace(*p)) p++;

	/*
	 *	Find the delimiting char
	 */
	q = strchr(p, ' ');
	if (!q) {
		REDEBUG("HMAC requires exactly two arguments (&data &key)");
		return -1;
	}

	tmp_ctx = talloc_new(ctx);
	data_fmt = talloc_bstrndup(tmp_ctx, p, q - p);
	p = q + 1;

	{
		VALUE_FROM_FMT(tmp_ctx, data_p, data_len, request, data_fmt);
	}
	{
		VALUE_FROM_FMT(tmp_ctx, key_p, key_len, request, p);
	}

	fr_hmac_sha1(digest, data_p, data_len, key_p, key_len);

	talloc_free(tmp_ctx);

	return fr_bin2hex(*out, digest, sizeof(digest));
}

/** Encode attributes as a series of string attribute/value pairs
 *
 * This is intended to serialize one or more attributes as a comma
 * delimited string.
 *
 * Example: "%{pairs:request:}" == "User-Name = 'foo', User-Password = 'bar'"
 */
static ssize_t pairs_xlat(TALLOC_CTX *ctx, char **out, size_t outlen,
			  UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			  REQUEST *request, char const *fmt)
{
	vp_tmpl_t	*vpt = NULL;
	fr_cursor_t	cursor;
	size_t		len, freespace = outlen;
	char		*p = *out;

	VALUE_PAIR *vp;

	if (tmpl_afrom_attr_str(ctx, &vpt, fmt, &(vp_tmpl_rules_t){ .dict_def = request->dict }) <= 0) {
		RPEDEBUG("Invalid input");
		return -1;
	}

	for (vp = tmpl_cursor_init(NULL, &cursor, request, vpt);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
	     	FR_TOKEN op = vp->op;

	     	vp->op = T_OP_EQ;
		len = fr_pair_snprint(p, freespace, vp);
		vp->op = op;

		if (is_truncated(len, freespace)) {
		no_space:
			talloc_free(vpt);
			REDEBUG("Insufficient space to store pair string, needed %zu bytes have %zu bytes",
				(p - *out) + len, outlen);
			return -1;
		}
		p += len;
		freespace -= len;

		if (freespace < 2) {
			len = 2;
			goto no_space;
		}

		*p++ = ',';
		*p++ = ' ';
		freespace -= 2;
	}

	/* Trim the trailing ', ' */
	if (p != *out) p -= 2;
	*p = '\0';
	talloc_free(vpt);

	return (p - *out);
}

/** Encode string or attribute as base64
 *
 * Example: "%{base64:foo}" == "Zm9v"
 */
static xlat_action_t xlat_base64(TALLOC_CTX *ctx, fr_cursor_t *out,
				 REQUEST *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
				 fr_value_box_t **in)
{
	size_t		alen;
	ssize_t		elen;
	char		*buff;
	fr_value_box_t	*vb;
	/*
	 *	If there's no input, there's no output
	 */
	if (!in) return XLAT_ACTION_DONE;

	if (fr_value_box_list_concat(ctx, *in, in, FR_TYPE_OCTETS, true) < 0) {
		RPEDEBUG("Failed concatenating input");
		return XLAT_ACTION_FAIL;
	}

	MEM(vb = fr_value_box_alloc_null(ctx));
	alen = FR_BASE64_ENC_LENGTH((*in)->vb_length);
	MEM(buff = talloc_array(ctx, char, alen + 1));

	elen = fr_base64_encode(buff, alen + 1, (*in)->vb_octets, (*in)->vb_length);
	if (elen < 0) {
		RPEDEBUG("Base64 encoding failed");
		talloc_free(vb);
		return XLAT_ACTION_FAIL;
	}

	rad_assert((size_t)elen <= alen);

	if (fr_value_box_bstrsnteal(vb, vb, NULL, &buff, elen, false) < 0) {
		RPEDEBUG("Failed assigning encoded data buffer to box");
		talloc_free(vb);
		return XLAT_ACTION_FAIL;
	}

	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

/** Convert base64 to hex
 *
 * Example: "%{base64tohex:Zm9v}" == "666f6f"
 */
static ssize_t base64_to_hex_xlat(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
				  UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
				  REQUEST *request, char const *fmt)
{
	uint8_t decbuf[1024];

	ssize_t declen;
	ssize_t len = strlen(fmt);

	declen = fr_base64_decode(decbuf, sizeof(decbuf), fmt, len);
	if (declen < 0) {
		REDEBUG("Base64 string invalid");
		return -1;
	}

	if ((size_t)((declen * 2) + 1) > outlen) {
		REDEBUG("Base64 conversion failed, output buffer exhausted, needed %zd bytes, have %zd bytes",
			(declen * 2) + 1, outlen);
		return -1;
	}

	return fr_bin2hex(*out, decbuf, declen);
}

/** Split an attribute into multiple new attributes based on a delimiter
 *
 * @todo should support multibyte delimiter for string types.
 *
 * Example: "%{explode:&ref <delim>}"
 */
static ssize_t explode_xlat(TALLOC_CTX *ctx, char **out, size_t outlen,
			    UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			    REQUEST *request, char const *fmt)
{
	vp_tmpl_t	*vpt = NULL;
	VALUE_PAIR	*vp;
	fr_cursor_t	cursor, to_merge;
	VALUE_PAIR 	*head = NULL;
	ssize_t		slen;
	int		count = 0;
	char const	*p = fmt;
	char		delim;

	/*
	 *  Trim whitespace
	 */
	while (isspace(*p) && p++);

	slen = tmpl_afrom_attr_substr(ctx, &vpt, p, &(vp_tmpl_rules_t){ .dict_def = request->dict });
	if (slen <= 0) {
		RPEDEBUG("Invalid input");
		return -1;
	}

	p += slen;

	if (*p++ != ' ') {
	arg_error:
		talloc_free(vpt);
		REDEBUG("explode needs exactly two arguments: &ref <delim>");
		return -1;
	}

	if (*p == '\0') goto arg_error;

	delim = *p;

	fr_cursor_init(&to_merge, &head);

	vp = tmpl_cursor_init(NULL, &cursor, request, vpt);
	while (vp) {
	     	VALUE_PAIR *nvp;
	     	char const *end;
		char const *q;

		/*
		 *	This can theoretically operate on lists too
		 *	so we need to check the type of each attribute.
		 */
		switch (vp->vp_type) {
		case FR_TYPE_OCTETS:
		case FR_TYPE_STRING:
			break;

		default:
			goto next;
		}

		p = vp->vp_ptr;
		end = p + vp->vp_length;
		while (p < end) {
			q = memchr(p, delim, end - p);
			if (!q) {
				/* Delimiter not present in attribute */
				if (p == vp->vp_ptr) goto next;
				q = end;
			}

			/* Skip zero length */
			if (q == p) {
				p = q + 1;
				continue;
			}

			nvp = fr_pair_afrom_da(talloc_parent(vp), vp->da);
			if (!nvp) {
				fr_pair_list_free(&head);
				return -1;
			}
			nvp->tag = vp->tag;

			switch (vp->vp_type) {
			case FR_TYPE_OCTETS:
			{
				uint8_t *buff;

				buff = talloc_array(nvp, uint8_t, q - p);
				memcpy(buff, p, q - p);
				fr_pair_value_memsteal(nvp, buff);
			}
				break;

			case FR_TYPE_STRING:
			{
				char *buff;

				buff = talloc_array(nvp, char, (q - p) + 1);
				memcpy(buff, p, q - p);
				buff[q - p] = '\0';
				fr_pair_value_strsteal(nvp, (char *)buff);
			}
				break;

			default:
				rad_assert(0);
			}

			fr_cursor_append(&to_merge, nvp);

			p = q + 1;	/* next */

			count++;
		}

		/*
		 *	Remove the unexploded version
		 */
		vp = fr_cursor_remove(&cursor);
		talloc_free(vp);
		/*
		 *	Remove sets cursor->current to
		 *	the next iter value.
		 */
		vp = fr_cursor_current(&cursor);
		continue;

	next:
	    	vp = fr_cursor_next(&cursor);
	}

	fr_cursor_head(&to_merge);
	fr_cursor_merge(&cursor, &to_merge);
	talloc_free(vpt);

	return snprintf(*out, outlen, "%i", count);
}

/** Calculate number of seconds until the next n hour(s), day(s), week(s), year(s).
 *
 * For example, if it were 16:18 %{nexttime:1h} would expand to 2520.
 *
 * The envisaged usage for this function is to limit sessions so that they don't
 * cross billing periods. The output of the xlat should be combined with %{rand:} to create
 * some jitter, unless the desired effect is every subscriber on the network
 * re-authenticating at the same time.
 */
static ssize_t next_time_xlat(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			      UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			      REQUEST *request, char const *fmt)
{
	long		num;

	char const 	*p;
	char 		*q;
	time_t		now;
	struct tm	*local, local_buff;

	now = time(NULL);
	local = localtime_r(&now, &local_buff);

	p = fmt;

	num = strtoul(p, &q, 10);
	if (!q || *q == '\0') {
		REDEBUG("nexttime: <int> must be followed by period specifier (h|d|w|m|y)");
		return -1;
	}

	if (p == q) {
		num = 1;
	} else {
		p += q - p;
	}

	local->tm_sec = 0;
	local->tm_min = 0;

	switch (*p) {
	case 'h':
		local->tm_hour += num;
		break;

	case 'd':
		local->tm_hour = 0;
		local->tm_mday += num;
		break;

	case 'w':
		local->tm_hour = 0;
		local->tm_mday += (7 - local->tm_wday) + (7 * (num-1));
		break;

	case 'm':
		local->tm_hour = 0;
		local->tm_mday = 1;
		local->tm_mon += num;
		break;

	case 'y':
		local->tm_hour = 0;
		local->tm_mday = 1;
		local->tm_mon = 0;
		local->tm_year += num;
		break;

	default:
		REDEBUG("nexttime: Invalid period specifier '%c', must be h|d|w|m|y", *p);
		return -1;
	}

	return snprintf(*out, outlen, "%" PRIu64, (uint64_t)(mktime(local) - now));
}


/** Parse the 3 arguments to lpad / rpad.
 *
 * Parses a fmt string with the components @verbatim <tmpl> <pad_len> <pad_char>@endverbatim
 *
 * @param[out] vpt_p		Template to retrieve value to pad.
 * @param[out] pad_len_p	Length the string needs to be padded to.
 * @param[out] pad_char_p	Char to use for padding.
 * @param[in] request		The current request.
 * @param[in] fmt		string to parse.
 *
 * @return
 *	- <= 0 the negative offset the parse error ocurred at.
 *	- >0 how many bytes of fmt were parsed.
 */
static ssize_t parse_pad(vp_tmpl_t **vpt_p, size_t *pad_len_p, char *pad_char_p, REQUEST *request, char const *fmt)
{
	ssize_t		slen;
	unsigned long	pad_len;
	char const	*p;
	char		*end;
	vp_tmpl_t	*vpt;

	*pad_char_p = ' ';		/* the default */

	*vpt_p = NULL;

	p = fmt;
	while (isspace((int) *p)) p++;

	if (*p != '&') {
		RDEBUG("First argument must be an attribute reference");
		return 0;
	}

	slen = tmpl_afrom_attr_substr(request, &vpt, p, &(vp_tmpl_rules_t){ .dict_def = request->dict });
	if (slen <= 0) {
		RPEDEBUG("Failed parsing input string");
		return slen;
	}

	p = fmt + slen;

	while (isspace((int) *p)) p++;

	pad_len = strtoul(p, &end, 10);
	if ((pad_len == ULONG_MAX) || (pad_len > 8192)) {
		talloc_free(vpt);
		RDEBUG("Invalid pad_len found at: %s", p);
		return fmt - p;
	}

	p += (end - p);

	/*
	 *	The pad_char_p character is optional.
	 *
	 *	But we must have a space after the previous number,
	 *	and we must have only ONE pad_char_p character.
	 */
	if (*p) {
		if (!isspace(*p)) {
			talloc_free(vpt);
			RDEBUG("Invalid text found at: %s", p);
			return fmt - p;
		}

		while (isspace((int) *p)) p++;

		if (p[1] != '\0') {
			talloc_free(vpt);
			RDEBUG("Invalid text found at: %s", p);
			return fmt - p;
		}

		*pad_char_p = *p++;
	}

	*vpt_p = vpt;
	*pad_len_p = pad_len;

	return p - fmt;
}


/** left pad a string
 *
 *  %{lpad:&Attribute-Name length 'x'}
 */
static ssize_t lpad_xlat(TALLOC_CTX *ctx, char **out, UNUSED size_t outlen,
			 UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			 REQUEST *request, char const *fmt)
{
	char		fill;
	size_t		pad;
	ssize_t		len;
	vp_tmpl_t	*vpt;
	char		*to_pad = NULL;

	if (parse_pad(&vpt, &pad, &fill, request, fmt) <= 0) return 0;

	if (!fr_cond_assert(vpt)) return 0;

	/*
	 *	Print the attribute (left justified).  If it's too
	 *	big, we're done.
	 */
	len = tmpl_aexpand(ctx, &to_pad, request, vpt, NULL, NULL);
	if (len <= 0) return -1;

	/*
	 *	Already big enough, no padding required...
	 */
	if ((size_t) len >= pad) {
		*out = to_pad;
		return pad;
	}

	/*
	 *	Realloc is actually pretty cheap in most cases...
	 */
	MEM(to_pad = talloc_realloc(ctx, to_pad, char, pad + 1));

	/*
	 *	We have to shift the string to the right, and pad with
	 *	"fill" characters.
	 */
	memmove(to_pad + (pad - len), to_pad, len + 1);
	memset(to_pad, fill, pad - len);

	*out = to_pad;

	return pad;
}

/** right pad a string
 *
 *  %{rpad:&Attribute-Name length 'x'}
 */
static ssize_t rpad_xlat(TALLOC_CTX *ctx, char **out, UNUSED size_t outlen,
			 UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			 REQUEST *request, char const *fmt)
{
	char		fill;
	size_t		pad;
	ssize_t		len;
	vp_tmpl_t	*vpt;
	char		*to_pad = NULL;

	rad_assert(!*out);

	if (parse_pad(&vpt, &pad, &fill, request, fmt) <= 0) return 0;

	if (!fr_cond_assert(vpt)) return 0;

	/*
	 *	Print the attribute (left justified).  If it's too
	 *	big, we're done.
	 */
	len = tmpl_aexpand(ctx, &to_pad, request, vpt, NULL, NULL);
	if (len <= 0) return 0;

	if ((size_t) len >= pad) {
		*out = to_pad;
		return pad;
	}

	MEM(to_pad = talloc_realloc(ctx, to_pad, char, pad + 1));

	/*
	 *	We have to pad with "fill" characters.
	 */
	memset(to_pad + len, fill, pad - len);
	to_pad[pad] = '\0';

	*out = to_pad;

	return pad;
}

/*
 *	Compare two xlat_t structs, based ONLY on the module name.
 */
static int xlat_cmp(void const *one, void const *two)
{
	xlat_t const *a = one, *b = two;
	size_t a_len, b_len;
	int ret;

	a_len = strlen(a->name);
	b_len = strlen(b->name);

	ret = (a_len > b_len) - (a_len < b_len);
	if (ret != 0) return ret;

	return memcmp(a->name, b->name, a_len);
}

/*
 *	find the appropriate registered xlat function.
 */
xlat_t *xlat_func_find(char const *name)
{
	xlat_t find;
	xlat_t *found;

	if (!xlat_root) return NULL;

	find.name = name;
	found = rbtree_finddata(xlat_root, &find);

	return found;
}

/** Remove an xlat function from the function tree
 *
 * @param[in] xlat	to free.
 * @return 0
 */
static int _xlat_func_talloc_free(xlat_t *xlat)
{
	if (!xlat_root) return 0;

	rbtree_deletebydata(xlat_root, xlat);
	if (rbtree_num_elements(xlat_root) == 0) TALLOC_FREE(xlat_root);

	return 0;
}

/** Callback for the rbtree to clear out any xlats still registered
 *
 */
static void _xlat_func_tree_free(void *xlat)
{
	talloc_free(xlat);
}

/** Register an xlat function.
 *
 * @param[in] mod_inst		Instance of module that's registering the xlat function.
 * @param[in] name		xlat name.
 * @param[in] func 		xlat function to be called.
 * @param[in] escape		function to sanitize any sub expansions passed to the xlat function.
 * @param[in] instantiate	function to pre-parse any xlat specific data.
 * @param[in] inst_size		sizeof() this xlat's instance data.
 * @param[in] buf_len		Size of the output buffer to allocate when calling the function.
 *				May be 0 if the function allocates its own buffer.
 * @param[in] async_safe	whether or not the function is async-safe.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int xlat_register(void *mod_inst, char const *name,
		  xlat_func_sync_t func, xlat_escape_t escape,
		  xlat_instantiate_t instantiate, size_t inst_size,
		  size_t buf_len, bool async_safe)
{
	xlat_t	*c;
	xlat_t	find;
	bool	new = false;

	if (!xlat_root) xlat_init();

	if (!name || !*name) {
		ERROR("%s: Invalid xlat name", __FUNCTION__);
		return -1;
	}

	/*
	 *	If it already exists, replace the instance.
	 */
	find.name = name;
	c = rbtree_finddata(xlat_root, &find);
	if (c) {
		if (c->internal) {
			ERROR("%s: Cannot re-define internal expansion %s", __FUNCTION__, name);
			return -1;
		}

		if (c->async_safe != async_safe) {
			ERROR("%s: Cannot change async capability of %s", __FUNCTION__, name);
			return -1;
		}

	/*
	 *	Doesn't exist.  Create it.
	 */
	} else {
		c = talloc_zero(xlat_root, xlat_t);
		c->name = talloc_typed_strdup(c, name);
		talloc_set_destructor(c, _xlat_func_talloc_free);
		new = true;
	}

	c->func.sync = func;
	c->type = XLAT_FUNC_SYNC;
	c->buf_len = buf_len;
	c->escape = escape;
	c->mod_inst = mod_inst;
	c->instantiate = instantiate;
	c->inst_size = inst_size;
	c->async_safe = async_safe;

	DEBUG3("%s: %s", __FUNCTION__, c->name);

	if (new && !rbtree_insert(xlat_root, c)) {
		ERROR("Failed inserting xlat registration for %s",
		      c->name);
		talloc_free(c);
		return -1;
	}

	return 0;
}

/** Register an async xlat
 *
 * All functions registered must be async_safe.
 *
 * @param[in] ctx			Used to automate deregistration of the xlat fnction.
 * @param[in] name			of the xlat.
 * @param[in] func			to register.
 * @param[in] instantiate		Instantiation function. Called whenever a xlat is
 *					compiled.
 * @param[in] inst_type			Name of the instance structure.
 * @param[in] inst_size			The size of the instance struct.
 *					Pre-allocated for use by the instantiate function.
 *					If 0, no memory will be allocated.
 * @param[in] detach			Called when an xlat_exp_t is freed.
 * @param[in] thread_instantiate	thread_instantiation_function. Called whenever a
 *					a thread is started to create thread local instance
 *					data.
 * @param[in] thread_inst_type		Name of the thread instance structure.
 * @param[in] thread_inst_size		The size of the thread instance struct.
 *					Pre-allocated for use by the thread instance function.
 *					If 0, no memory will be allocated.
 * @param[in] thread_detach		Called when an xlat_exp_t is freed (if ephemeral),
 *					or when a thread exits.
 * @param[in] uctx			To pass to instantiate callbacks and the xlat function
 *					when it's called.  Usually the module instance that
 *					registered the xlat.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int _xlat_async_register(TALLOC_CTX *ctx,
			 char const *name, xlat_func_async_t func,
			 xlat_instantiate_t instantiate, char const *inst_type, size_t inst_size,
			 xlat_detach_t detach,
			 xlat_thread_instantiate_t thread_instantiate,
			 char const *thread_inst_type, size_t thread_inst_size,
			 xlat_thread_detach_t thread_detach,
			 void *uctx)
{
	xlat_t	*c;
	xlat_t	find;
	bool	new = false;

	if (!xlat_root) xlat_init();

	if (!name || !*name) {
		ERROR("%s: Invalid xlat name", __FUNCTION__);
		return -1;
	}

	/*
	 *	If it already exists, replace the instance.
	 */
	find.name = name;
	c = rbtree_finddata(xlat_root, &find);
	if (c) {
		if (c->internal) {
			ERROR("%s: Cannot re-define internal expansion %s", __FUNCTION__, name);
			return -1;
		}

		if (!c->async_safe) {
			ERROR("%s: Cannot change async capability of %s", __FUNCTION__, name);
			return -1;
		}

	/*
	 *	Doesn't exist.  Create it.
	 */
	} else {
		c = talloc_zero(ctx, xlat_t);
		c->name = talloc_typed_strdup(c, name);
		talloc_set_destructor(c, _xlat_func_talloc_free);
		new = true;
	}

	c->func.async = func;
	c->type = XLAT_FUNC_ASYNC;

	c->instantiate = instantiate;
	c->thread_instantiate = thread_instantiate;

	c->inst_type = inst_type;
	c->inst_size = inst_size;

	c->thread_inst_type = thread_inst_type;
	c->thread_inst_size = thread_inst_size;

	c->detach = detach;
	c->thread_detach = thread_detach;

	c->async_safe = false;	/* async safe in this case means it might yield */
	c->uctx = uctx;

	DEBUG3("%s: %s", __FUNCTION__, c->name);

	if (new && !rbtree_insert(xlat_root, c)) {
		ERROR("%s: Failed inserting xlat registration for %s", __FUNCTION__, c->name);
		talloc_free(c);
		return -1;
	}

	return 0;
}

/** Unregister an xlat function
 *
 * We can only have one function to call per name, so the passing of "func"
 * here is extraneous.
 *
 * @param[in] name xlat to unregister.
 */
void xlat_unregister(char const *name)
{
	xlat_t	*c;
	xlat_t	find = { .name = name };

	if (!name || !xlat_root) return;

	c = rbtree_finddata(xlat_root, &find);
	if (!c) return;

	(void) talloc_get_type_abort(c, xlat_t);

	talloc_free(c);	/* Should also remove from tree */
}

static int _xlat_unregister_callback(void *mod_inst, void *data)
{
	xlat_t *c = (xlat_t *) data;

	if (c->mod_inst != mod_inst) return 0; /* keep walking */

	return 2;		/* delete it */
}

void xlat_unregister_module(void *instance)
{
	if (!xlat_root) return;	/* All xlats have already been freed */

	rbtree_walk(xlat_root, RBTREE_DELETE_ORDER, _xlat_unregister_callback, instance);
}

/*
 *	Internal redundant handler for xlats
 */
typedef enum xlat_redundant_type_t {
	XLAT_INVALID = 0,
	XLAT_REDUNDANT,
	XLAT_LOAD_BALANCE,
	XLAT_REDUNDANT_LOAD_BALANCE,
} xlat_redundant_type_t;

typedef struct xlat_redundant_t {
	xlat_redundant_type_t		type;
	uint32_t			count;
	CONF_SECTION const		*cs;
} xlat_redundant_t;

static ssize_t xlat_redundant(TALLOC_CTX *ctx, char **out, NDEBUG_UNUSED size_t outlen,
			      void const *mod_inst, UNUSED void const *xlat_inst,
			      REQUEST *request, char const *fmt)
{
	xlat_redundant_t const *xr = mod_inst;
	CONF_ITEM *ci;
	char const *name;
	xlat_t *xlat;

	rad_assert((*out == NULL) && (outlen == 0));	/* Caller must not have allocated buf */
	rad_assert(xr->type == XLAT_REDUNDANT);

	/*
	 *	Pick the first xlat which succeeds
	 */
	for (ci = cf_item_next(xr->cs, NULL);
	     ci != NULL;
	     ci = cf_item_next(xr->cs, ci)) {
		ssize_t rcode;

		if (!cf_item_is_pair(ci)) continue;

		name = cf_pair_attr(cf_item_to_pair(ci));
		rad_assert(name != NULL);

		xlat = xlat_func_find(name);
		if (!xlat) continue;

		if (xlat->buf_len > 0) {
			*out = talloc_array(ctx, char, xlat->buf_len);
			**out = '\0';	/* Be sure the string is \0 terminated */
		} else {
			*out = NULL;
		}

		rcode = xlat->func.sync(ctx, out, xlat->buf_len, xlat->mod_inst, NULL, request, fmt);
		if (rcode <= 0) {
			TALLOC_FREE(*out);
			continue;
		}
		return rcode;
	}

	/*
	 *	Everything failed.  Oh well.
	 */
	*out = NULL;
	return 0;
}

static xlat_action_t xlat_concat(TALLOC_CTX *ctx, fr_cursor_t *out,
				 REQUEST *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
				 fr_value_box_t **in)
{
	fr_value_box_t *result;
	char *buff;

	/*
	 *	If there's no input, there's no output
	 */
	if (!in) return XLAT_ACTION_DONE;

	/*
	 *	Otherwise, join the boxes together commas
	 *	FIXME It'd be nice to set a custom delimiter
	 */
	result = fr_value_box_alloc_null(ctx);
	if (!result) {
	error:
		RPEDEBUG("Failed concatenating input");
		return XLAT_ACTION_FAIL;
	}

	buff = fr_value_box_list_asprint(result, *in, ",", '\0');
	if (!buff) goto error;

	fr_value_box_bstrsteal(result, result, NULL, buff, fr_value_box_list_tainted(*in));

	fr_cursor_insert(out, result);

	return XLAT_ACTION_DONE;
}

static xlat_action_t xlat_bin(TALLOC_CTX *ctx, fr_cursor_t *out,
			      REQUEST *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
			      fr_value_box_t **in)
{
	fr_value_box_t	*result;
	char		*buff = NULL, *p, *end;
	uint8_t		*bin;
	size_t		len, outlen;

	/*
	 *	If there's no input, there's no output
	 */
	if (!*in) return XLAT_ACTION_DONE;

	buff = fr_value_box_list_asprint(NULL, *in, NULL, '\0');
	if (!buff) return XLAT_ACTION_FAIL;

	len = talloc_array_length(buff) - 1;
	if ((len > 1) && (len & 0x01)) {
		REDEBUG("Input data length must be >1 and even, got %zu", len);
		talloc_free(buff);
		return XLAT_ACTION_FAIL;
	}

	p = buff;
	end = p + len;

	/*
	 *	Zero length octets string
	 */
	if ((p[0] == '0') && (p[1] == 'x')) p += 2;
	if (p == end) goto finish;

	outlen = len / 2;

	MEM(result = fr_value_box_alloc_null(ctx));
	MEM(bin = talloc_array(result, uint8_t, outlen));

	fr_hex2bin(bin, outlen, p, end - p);
	fr_value_box_memsteal(result, result, NULL, bin, fr_value_box_list_tainted(*in));
	fr_cursor_insert(out, result);

finish:
	talloc_free(buff);
	return XLAT_ACTION_DONE;
}


static ssize_t xlat_load_balance(TALLOC_CTX *ctx, char **out, NDEBUG_UNUSED size_t outlen,
				 void const *mod_inst, UNUSED void const *xlat_inst,
				 REQUEST *request, char const *fmt)
{
	uint32_t count = 0;
	xlat_redundant_t const *xr = mod_inst;
	CONF_ITEM *ci;
	CONF_ITEM *found = NULL;
	char const *name;
	xlat_t *xlat;

	rad_assert((*out == NULL) && (outlen == 0));	/* Caller must not have allocated buf */

	/*
	 *	Choose a child at random.
	 */
	for (ci = cf_item_next(xr->cs, NULL);
	     ci != NULL;
	     ci = cf_item_next(xr->cs, ci)) {
		if (!cf_item_is_pair(ci)) continue;
		count++;

		/*
		 *	Replace the previously found one with a random
		 *	new one.
		 */
		if ((count * (fr_rand() & 0xffff)) < (uint32_t) 0x10000) {
			found = ci;
		}
	}

	/*
	 *	Plain load balancing: do one child, and only one child.
	 */
	if (xr->type == XLAT_LOAD_BALANCE) {
		ssize_t slen;
		name = cf_pair_attr(cf_item_to_pair(found));
		rad_assert(name != NULL);

		xlat = xlat_func_find(name);
		if (!xlat) return -1;

		if (xlat->buf_len > 0) {
			*out = talloc_array(ctx, char, xlat->buf_len);
			**out = '\0';	/* Be sure the string is \0 terminated */
		} else {
			*out = NULL;
		}
		slen = xlat->func.sync(ctx, out, xlat->buf_len, xlat->mod_inst, NULL, request, fmt);
		if (slen <= 0) TALLOC_FREE(*out);

		return slen;
	}

	rad_assert(xr->type == XLAT_REDUNDANT_LOAD_BALANCE);

	/*
	 *	Try the random one we found.  If it fails, keep going
	 *	through the rest of the children.
	 */
	ci = found;
	do {
		name = cf_pair_attr(cf_item_to_pair(ci));
		rad_assert(name != NULL);

		xlat = xlat_func_find(name);
		if (xlat) {
			ssize_t rcode;

			if (xlat->buf_len > 0) {
				*out = talloc_array(ctx, char, xlat->buf_len);
				**out = '\0';	/* Be sure the string is \0 terminated */
			} else {
				*out = NULL;
			}
			rcode = xlat->func.sync(ctx, out, xlat->buf_len, xlat->mod_inst, NULL, request, fmt);
			if (rcode > 0) return rcode;
			TALLOC_FREE(*out);
		}

		/*
		 *	Go to the next one, wrapping around at the end.
		 */
		ci = cf_item_next(xr->cs, ci);
		if (!ci) ci = cf_item_next(xr->cs, NULL);
	} while (ci != found);

	return -1;
}

/** Registers a redundant xlat
 *
 * These xlats wrap the xlat methods of the modules in a redundant section,
 * emulating the behaviour of a redundant section, but over xlats.
 *
 * @todo - make xlat_register() take ASYNC / SYNC / UNKNOWN.  We may
 * need "unknown" here in order to properly handle the children, which
 * we don't know are async-safe or not.  For now, it's best to assume
 * that all xlat's in a redundant block are module calls, and are not async-safe
 *
 * @return
 *	- 0 on success.
 *	- -1 on error.
 *	- 1 if the modules in the section do not have an xlat method.
 */
int xlat_register_redundant(CONF_SECTION *cs)
{
	char const *name1, *name2;
	xlat_redundant_t *xr;

	name1 = cf_section_name1(cs);
	name2 = cf_section_name2(cs);

	if (xlat_func_find(name2)) {
		cf_log_err(cs, "An expansion is already registered for this name");
		return -1;
	}

	MEM(xr = talloc_zero(cs, xlat_redundant_t));

	if (strcmp(name1, "redundant") == 0) {
		xr->type = XLAT_REDUNDANT;
	} else if (strcmp(name1, "redundant-load-balance") == 0) {
		xr->type = XLAT_REDUNDANT_LOAD_BALANCE;
	} else if (strcmp(name1, "load-balance") == 0) {
		xr->type = XLAT_LOAD_BALANCE;
	} else {
		rad_assert(0);
	}

	xr->cs = cs;

	/*
	 *	Get the number of children for load balancing.
	 */
	if (xr->type == XLAT_REDUNDANT) {
		if (xlat_register(xr, name2, xlat_redundant, NULL, NULL, 0, 0, false) < 0) {
			ERROR("Registering xlat for redundant section failed");
			talloc_free(xr);
			return -1;
		}

	} else {
		CONF_ITEM *ci = NULL;

		while ((ci = cf_item_next(cs, ci))) {
			char const *attr;

			if (!cf_item_is_pair(ci)) continue;

			attr = cf_pair_attr(cf_item_to_pair(ci));

			/*
			 *	This is ok, it just means the module
			 *	doesn't have an xlat method.
			 */
			if (!xlat_func_find(attr)) {
				talloc_free(xr);
				return 1;
			}

			xr->count++;
		}

		if (xlat_register(xr, name2, xlat_load_balance, NULL, NULL, 0, 0, false) < 0) {
			ERROR("Registering xlat for load-balance section failed");
			talloc_free(xr);
			return -1;
		}
	}

	return 0;
}

/** Global initialisation for xlat
 *
 * @note Free memory with #xlat_free
 *
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int xlat_init(void)
{
	if (xlat_root) return 0;

	xlat_t	*c;

#ifdef WITH_UNLANG
	int i;
#endif

	/*
	 *	Registers async xlat operations in the `unlang` interpreter.
	 */
	unlang_xlat_init();

	/*
	 *	Create the function tree
	 */
	xlat_root = rbtree_talloc_create(NULL, xlat_cmp, xlat_t, _xlat_func_tree_free, RBTREE_FLAG_REPLACE);
	if (!xlat_root) {
		ERROR("%s: Failed to create tree", __FUNCTION__);
		return -1;
	}

#ifdef WITH_UNLANG
	for (i = 0; xlat_foreach_names[i] != NULL; i++) {
		xlat_register(&xlat_foreach_inst[i], xlat_foreach_names[i], xlat_foreach, NULL, NULL, 0, 0, true);
		c = xlat_func_find(xlat_foreach_names[i]);
		rad_assert(c != NULL);
		c->internal = true;
	}
#endif

#define XLAT_REGISTER(_x) xlat_register(NULL, STRINGIFY(_x), xlat_ ## _x, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true); \
	c = xlat_func_find(STRINGIFY(_x)); \
	rad_assert(c != NULL); \
	c->internal = true

	XLAT_REGISTER(integer);
	XLAT_REGISTER(strlen);
	XLAT_REGISTER(length);
	XLAT_REGISTER(hex);
	XLAT_REGISTER(tag);
	XLAT_REGISTER(string);
	XLAT_REGISTER(xlat);
	XLAT_REGISTER(map);
	XLAT_REGISTER(module);
	XLAT_REGISTER(debug_attr);
#if defined(HAVE_REGEX) && defined(HAVE_REGEX_PCRE)
	XLAT_REGISTER(regex);
#endif

	xlat_register(NULL, "tolower", tolower_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);
	xlat_register(NULL, "toupper", toupper_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);
	xlat_register(NULL, "sha1", sha1_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);
#ifdef HAVE_OPENSSL_EVP_H
	xlat_register(NULL, "sha224", sha224_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);
	xlat_register(NULL, "sha256", sha256_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);
	xlat_register(NULL, "sha384", sha384_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);
	xlat_register(NULL, "sha512", sha512_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);

#  ifdef HAVE_EVP_SHA3_512
	xlat_register(NULL, "sha3_224", sha3_224_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);
	xlat_register(NULL, "sha3_256", sha3_256_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);
	xlat_register(NULL, "sha3_384", sha3_384_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);
	xlat_register(NULL, "sha3_512", sha3_512_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);#  endif
#  endif
#endif
	xlat_register(NULL, "hmacmd5", hmac_md5_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);
	xlat_register(NULL, "hmacsha1", hmac_sha1_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);
	xlat_register(NULL, "pairs", pairs_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);


	xlat_register(NULL, "base64tohex", base64_to_hex_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);

	xlat_register(NULL, "explode", explode_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);

	xlat_register(NULL, "nexttime", next_time_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);
	xlat_register(NULL, "lpad", lpad_xlat, NULL, NULL, 0, 0, true);
	xlat_register(NULL, "rpad", rpad_xlat, NULL, NULL, 0, 0, true);

	xlat_register(&xlat_foreach_inst[0], "debug", xlat_debug, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);
	c = xlat_func_find("debug");
	rad_assert(c != NULL);
	c->internal = true;

	xlat_async_register(NULL, "base64", xlat_base64, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	xlat_async_register(NULL, "concat", xlat_concat, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	xlat_async_register(NULL, "bin", xlat_bin, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	xlat_async_register(NULL, "md5", xlat_md5, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	xlat_async_register(NULL, "rand", xlat_rand, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	xlat_async_register(NULL, "randstr", xlat_randstr, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	xlat_async_register(NULL, "urlquote", xlat_urlquote, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	xlat_async_register(NULL, "urlunquote", xlat_urlunquote, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

	return 0;
}

/** De-register all xlat functions we created
 *
 */
void xlat_free(void)
{
	rbtree_t *xr = xlat_root;		/* Make sure the tree can't be freed multiple times */
	xlat_root = NULL;
	talloc_free(xr);
}


