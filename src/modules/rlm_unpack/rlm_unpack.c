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
 * @file rlm_unpack.c
 * @brief Unpack binary data
 *
 * @copyright 2014 The FreeRADIUS server project
 * @copyright 2014 Alan DeKok (aland@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>

#include <freeradius-devel/util/hex.h>

#include <ctype.h>

static fr_dict_t const *dict_freeradius;

extern fr_dict_autoload_t rlm_unpack_dict[];
fr_dict_autoload_t rlm_unpack_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_cast_base;

extern fr_dict_attr_autoload_t rlm_unpack_dict_attr[];
fr_dict_attr_autoload_t rlm_unpack_dict_attr[] = {
	{ .out = &attr_cast_base, .name = "Cast-Base", .type = FR_TYPE_UINT8, .dict = &dict_freeradius },
	{ NULL }
};

#define GOTO_ERROR do { REDEBUG("Unexpected text at '%s'", p); goto error;} while (0)

/** Unpack data
 *
 * Example:
@verbatim
%{unpack:&Class 0 integer}
@endverbatim
 * Expands Class, treating octet at offset 0 (bytes 0-3) as an "integer".
 *
 * @ingroup xlat_functions
 */
static ssize_t unpack_xlat(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			   UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			   request_t *request, char const *fmt)
{
	char *data_name, *data_size, *data_type;
	char *p;
	size_t len, input_len;
	ssize_t slen;
	int offset;
	fr_type_t type;
	fr_dict_attr_t const *da;
	fr_pair_t *vp, *cast;
	uint8_t const *input;
	char buffer[256];
	uint8_t blob[256];

	/*
	 *	FIXME: copy only the fields here, as we parse them.
	 */
	strlcpy(buffer, fmt, sizeof(buffer));

	p = buffer;
	fr_skip_whitespace(p); /* skip leading spaces */

	data_name = p;

	fr_skip_not_whitespace(p);

	if (!*p) {
	error:
		REDEBUG("Format string should be '<data> <offset> <type>' e.g. '&Class 1 integer'");
	nothing:
		return -1;
	}

	fr_zero_whitespace(p);
	if (!*p) GOTO_ERROR;

	data_size = p;

	fr_skip_not_whitespace(p);
	if (!*p) GOTO_ERROR;

	fr_zero_whitespace(p);
	if (!*p) GOTO_ERROR;

	data_type = p;

	fr_skip_not_whitespace(p);
	if (*p) GOTO_ERROR;	/* anything after the type is an error */

	/*
	 *	Attribute reference
	 */
	if (*data_name == '&') {
		if (xlat_fmt_get_vp(&vp, request, data_name) < 0) goto nothing;

		if ((vp->vp_type != FR_TYPE_OCTETS) &&
		    (vp->vp_type != FR_TYPE_STRING)) {
			REDEBUG("unpack requires the input attribute to be 'string' or 'octets'");
			goto nothing;
		}
		input = vp->vp_octets;
		input_len = vp->vp_length;

	} else if ((data_name[0] == '0') && (data_name[1] == 'x')) {
		/*
		 *	Hex data.
		 */
		len = strlen(data_name + 2);
		if (len > 0) {
			fr_sbuff_parse_error_t err;

			input = blob;
			input_len = fr_hex2bin(&err, &FR_DBUFF_TMP(blob, sizeof(blob)),
					       &FR_SBUFF_IN(data_name + 2, len), true);
			if (err) {
				REDEBUG("Invalid hex string in '%s'", data_name);
				goto nothing;
			}
		} else {
			input = blob;
			input_len = 0;
		}
	} else {
		GOTO_ERROR;
	}

	offset = (int) strtoul(data_size, &p, 10);
	if (*p) {
		REDEBUG("unpack requires a float64 number, not '%s'", data_size);
		goto nothing;
	}

	type = fr_table_value_by_str(fr_value_box_type_table, data_type, FR_TYPE_INVALID);
	if (type == FR_TYPE_INVALID) {
		REDEBUG("Invalid data type '%s'", data_type);
		goto nothing;
	}

	/*
	 *	Output must be a non-zero limited size.
	 */
	if ((dict_attr_sizes[type][0] ==  0) ||
	    (dict_attr_sizes[type][0] != dict_attr_sizes[type][1])) {
		REDEBUG("unpack requires fixed-size output type, not '%s'", data_type);
		goto nothing;
	}

	if (input_len < (offset + dict_attr_sizes[type][0])) {
		REDEBUG("Insufficient data to unpack '%s' from '%s'", data_type, data_name);
		goto nothing;
	}

	da = fr_dict_attr_child_by_num(fr_dict_root(dict_freeradius), attr_cast_base->attr + type);
	if (!da) {
		REDEBUG("Cannot decode type '%s'", data_type);
		goto nothing;
	}

	MEM(cast = fr_pair_afrom_da(request, da));

	memcpy(&(cast->data), input + offset, dict_attr_sizes[type][0]);

	/*
	 *	Hacks
	 */
	switch (type) {
	case FR_TYPE_INT32:
	case FR_TYPE_UINT32:
		cast->vp_uint32 = ntohl(cast->vp_uint32);
		break;

	case FR_TYPE_UINT16:
		cast->vp_uint16 = ((input[offset] << 8) | input[offset + 1]);
		break;

	case FR_TYPE_UINT64:
		cast->vp_uint64 = ntohll(cast->vp_uint64);
		break;

	case FR_TYPE_DATE:
		cast->vp_date = fr_time_from_timeval(&(struct timeval) {.tv_sec = ntohl(cast->vp_uint32)});
		break;

	default:
		break;
	}

	slen = fr_pair_print_value_quoted(&FR_SBUFF_OUT(*out, outlen), cast, T_BARE_WORD);
	talloc_free(cast);
	if (slen < 0) {
		REDEBUG("Insufficient buffer space to unpack data");
		goto nothing;
	}

	return slen;
}

/** Return a substring from a starting character for a given length
 *
 * Example:
@verbatim
%{substring:foobar 2 3}
@endverbatim
 * Returns 3 characters from "foobar" starting at character 2
@verbatim
%{substring:&User-Name -3 2}
@endverbatim
 * Expands User-Name and returns two characters starting three
 * characters from from the end of the expanded string.
@verbatim
%{substring:&DHCP-Client-Hardware-Address 2 -3}
@endverbatim
 * Expands DHCP-Client-Hardware-Address and returns the substring
 * starting at charcter 2, removing the last 3 characters.
 *
 * @param ctx			unused.
 * @param[out] out		Where to write resulting substring.
 * @param[in] outlen		Length of the out buffer.
 * @param mod_inst		unused.
 * @param xlat_inst		unused.
 * @param[in] request		Current request.
 * @param[in] fmt		string to be parsed.
 *
 * @return
 *	- < 0 on error
 *	- >= 0 on success (length of returned substring).
 *
 * @ingroup xlat_functions
 */
static ssize_t substring_xlat(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			      UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			      REQUEST *request, char const *fmt)
{
	ssize_t slen;
	long start, len;
	char const *p = fmt;
	char *end, *buffer;
	fr_sbuff_term_t const 		bareword_terminals =
					FR_SBUFF_TERMS(
						L("\t"),
						L("\n"),
						L(" "),
						L("%"),
						L("&"),
						L(")"),
						L("+"),
						L("-"),
						L("/"),
						L("^"),
						L("|")
					);
	fr_sbuff_parse_rules_t const	p_rules = { .terminals = &bareword_terminals };

	/*
	 *  Trim whitespace
	 */
	while (isspace(*p) && p++);

	/*
	 * Find numeric parameters at the end.
	 * Start with final space in fmt
	 */
	end = strrchr(p, ' ');
	if (!end) {
	arg_error:
		REDEBUG("substring needs exactly three arguments: &ref <start> <len>");
		return -1;
	}
	if (end == fmt) goto arg_error;

	/*
	 * Walk back for previous space
	 */
	end--;
	while ((end >= p) && (*end != ' ') && end--);
	if (*end != ' ') goto arg_error;
	/*
	 * Store the total length of fmt up to the parameters including
	 * leading whitespace - if we're given a plain string we need the
	 * whole thing
	 */
	slen = end - fmt;

	end++;
	start = strtol(end, &end, 10);
	end++;
	len = strtol(end, &end, 10);

	/*
	 * Check for an attribute
	 */
	if (*p == '&') {
		tmpl_t *vpt = NULL;
		slen = tmpl_afrom_attr_substr(request, NULL, &vpt,
					      &FR_SBUFF_IN(p, strlen(p)),
					      &p_rules,
					      &(tmpl_rules_t){ .dict_def = request->dict});
		if (slen <= 0) {
			REDEBUG("%s", fr_strerror());
			return -1;
		}

		slen = tmpl_aexpand(NULL, &buffer, request, vpt, NULL, NULL);
		if (slen < 0) {
			talloc_free(buffer);
			REDEBUG("Unable to expand substring value");
			return -1;
		}

	} else {
		/*
		 * Input is a string, copy it to the workspace
		 */
		buffer = talloc_array(NULL, char, slen + 1);
		strncpy(buffer, fmt, slen);
		buffer[slen] = '\0';
	}
	/*
	 * Negative start counts in from the end of the string,
	 * calculate the actual start position
	 */
	if (start < 0) {
		if ((0 - start) > slen) {
			start = 0;
		} else {
			start = slen + start;
		}
	}

	if (start > slen) {
		*out[0] = '\0';
		talloc_free(buffer);
		WARN("Start position %li is after end of string length of %li", start, slen);
		return 0;
	}

	/*
	 * Negative length drops characters from the end of the string,
	 * calculate the actual length
	 */
	if (len < 0) len = slen - start + len;

	if (len < 0) {
		WARN("String length of %li too short for substring parameters", slen);
		len = 0;
	}

	/*
	 * Reduce length to "out" capacity
	 */
	if (len > (long) outlen) len = outlen;

	if (len > (slen - start)){
		/*
		 * Reduce length to match available string length
		 */
		len = slen - start;
	} else {
		/*
		 * Terminate string to copy
		 */
		buffer[start + len] = '\0';
	}

	strncpy(*out, buffer + start, outlen);
	talloc_free(buffer);
	return len;
}

/*
 *	Register the xlats
 */
static int mod_bootstrap(UNUSED void *instance, CONF_SECTION *conf)
{
	if (cf_section_name2(conf)) return 0;

	xlat_register_legacy(NULL, "unpack", unpack_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN);
	xlat_register_legacy(NULL, "substring", substring_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN);

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
extern module_t rlm_unpack;
module_t rlm_unpack = {
	.magic		= RLM_MODULE_INIT,
	.name		= "unpack",
	.type		= RLM_TYPE_THREAD_SAFE,
	.bootstrap	= mod_bootstrap
};
