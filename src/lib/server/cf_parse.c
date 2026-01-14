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
 * @file cf_parse.c
 * @brief Convert internal format configuration values into native C types.
 *
 * @copyright 2017 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2000,2006 The FreeRADIUS server project
 * @copyright 2000 Miquel van Smoorenburg (miquels@cistron.nl)
 * @copyright 2000 Alan DeKok (aland@freeradius.org)
 */
RCSID("$Id$")

#include <string.h>
#include <sys/errno.h>
#include <sys/fcntl.h>

#include <freeradius-devel/server/cf_file.h>
#include <freeradius-devel/server/cf_parse.h>
#include <freeradius-devel/server/cf_priv.h>
#include <freeradius-devel/server/log.h>
#include <freeradius-devel/server/tmpl.h>
#include <freeradius-devel/server/virtual_servers.h>
#include <freeradius-devel/server/main_config.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/inet.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/perm.h>
#include <freeradius-devel/util/syserror.h>

static conf_parser_t conf_term = CONF_PARSER_TERMINATOR;
static char const parse_spaces[] = "                                                                                                                                                                                                                                              ";

#define PAIR_SPACE(_cs) ((_cs->depth + 1) * 2)
#define SECTION_SPACE(_cs) (_cs->depth * 2)

void cf_pair_debug_log(CONF_SECTION const *cs, CONF_PAIR *cp, conf_parser_t const *rule)
{
	char const	*value;
	char		*tmp = NULL;
	char const	*quote = "";
	bool		secret = (rule && (rule->flags & CONF_FLAG_SECRET));
	fr_type_t	type;

	if (cp->printed) return;

	/*
	 *	tmpls are special, they just need to get printed as string
	 */
	if (!rule || (rule->flags & CONF_FLAG_TMPL)) {
		type = FR_TYPE_STRING;
	} else {
		type = rule->type;
	}

	if (secret && (fr_debug_lvl < L_DBG_LVL_3)) {
		cf_log_debug(cs, "%.*s%s = <<< secret >>>", PAIR_SPACE(cs), parse_spaces, cp->attr);
		return;
	}

	/*
	 *	Print the strings with the correct quotation character and escaping.
	 */
	if (fr_type_is_string(type)) {
		value = tmp = fr_asprint(NULL, cp->value, talloc_array_length(cp->value) - 1, fr_token_quote[cp->rhs_quote]);

	} else {
		value = cf_pair_value(cp);
	}

	if (fr_type_is_quoted(type)) {
		switch (cf_pair_value_quote(cp)) {
		default:
			break;

		case T_DOUBLE_QUOTED_STRING:
			quote = "\"";
			break;

		case T_SINGLE_QUOTED_STRING:
			quote = "'";
			break;

		case T_BACK_QUOTED_STRING:
			quote = "`";
			break;

		case T_SOLIDUS_QUOTED_STRING:
			quote = "/";
			break;
		}
	}

	cf_log_debug(cs, "%.*s%s = %s%s%s", PAIR_SPACE(cs), parse_spaces, cp->attr, quote, value, quote);

	talloc_free(tmp);

	cp->printed = true;
}

/** Parses a #CONF_PAIR into a boxed value
 *
 * @copybrief cf_pair_value
 * @see cf_pair_value
 *
 * @param[in] ctx	to allocate any dynamic buffers in.
 * @param[out] out	Where to write the parsed value.
 * @param[in] cp	to parse.
 * @param[in] rule	to parse to.  May contain flags.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int cf_pair_to_value_box(TALLOC_CTX *ctx, fr_value_box_t *out, CONF_PAIR *cp, conf_parser_t const *rule)
{
	if (fr_value_box_from_str(ctx, out, rule->type, NULL, cp->value, talloc_array_length(cp->value) - 1, NULL) < 0) {
		cf_log_perr(cp, "Invalid value \"%s\" for config item %s",
			    cp->value, cp->attr);

		return -1;
	}

	/*
	 *	Strings can be file paths...
	 */
	if (fr_type_is_string(rule->type)) {
		if (fr_rule_file_socket(rule)) {
			/*
			 *	Attempt to actually connect to the socket.
			 *	There's no real standard behaviour across
			 *	operating systems for this.
			 *
			 *	This also implies fr_rule_file_exists.
			 */
			if (fr_rule_file_readable(rule) || fr_rule_file_writable(rule)) {
				if (cf_file_check_effective(cf_pair_value(cp), cf_file_check_unix_connect, NULL) != 0) {
					cf_log_perr(cp, "File check failed");
					return -1;
				}
			/*
			 *	Otherwise just passively check if the socket
			 *	exists.
			 */
			} else if (fr_rule_file_exists(rule)) {
				if (cf_file_check_effective(cf_pair_value(cp), cf_file_check_unix_perm, NULL) != 0) {
					cf_log_perr(cp, "File check failed");
					return -1;
				}
			/*
			 *	...and if there's no existence requirement
			 *	just check that it's a unix socket.
			 */
			} else {
				switch (cf_file_check_effective(cf_pair_value(cp), cf_file_check_unix_perm, NULL)) {
				default:
					/* ok */
					break;

				case CF_FILE_NO_UNIX_SOCKET:
					cf_log_perr(cp, "File check failed");
					return -1;
				}
			}
		}
		/*
		 *	If there's out AND it's an input file, check
		 *	that we can read it.  This check allows errors
		 *	to be caught as early as possible, during
		 *	server startup.
		 */
		else if (fr_rule_file_readable(rule) && (cf_file_check(cp, true) < 0)) {
		error:
			fr_value_box_clear(out);
			return -1;
		}
		else if (fr_rule_file_exists(rule) && (cf_file_check(cp, false) < 0)) goto error;
	}

	fr_value_box_mark_safe_for(out, FR_VALUE_BOX_SAFE_FOR_ANY);

	return 0;
}

/** Parses a #CONF_PAIR into a C data type
 *
 * @copybrief cf_pair_value
 * @see cf_pair_value
 *
 * @param[in] ctx	to allocate any dynamic buffers in.
 * @param[out] out	Where to write the parsed value.
 * @param[in] base	address of the structure out points into.
 *			May be NULL in the case of manual parsing.
 * @param[in] ci	to parse.
 * @param[in] rule	to parse to.  May contain flags.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int cf_pair_parse_value(TALLOC_CTX *ctx, void *out, UNUSED void *base, CONF_ITEM *ci, conf_parser_t const *rule)
{
	int		ret = 0;
	bool		cant_be_empty, tmpl;

	ssize_t		slen;

	CONF_PAIR	*cp = cf_item_to_pair(ci);

	cant_be_empty = fr_rule_not_empty(rule);
	tmpl = fr_rule_is_tmpl(rule);

	fr_assert(cp);
	fr_assert(!fr_rule_is_attribute(rule) || tmpl);		/* Attribute flag only valid for templates */

	if (fr_rule_required(rule)) cant_be_empty = true;	/* May want to review this in the future... */

	/*
	 *	Everything except templates must have a base type.
	 */
	if (!rule->type && !tmpl) {
		cf_log_err(cp, "Configuration pair \"%s\" must have a data type", cp->attr);
		return -1;
	}

	/*
	 *	Catch crazy errors.
	 */
	if (!cp->value) {
		cf_log_err(cp, "Configuration pair \"%s\" must have a value", cp->attr);
		return -1;
	}

	/*
	 *	Check for zero length strings
	 */
	if ((cp->value[0] == '\0') && cant_be_empty) {
		cf_log_err(cp, "Configuration pair \"%s\" must not be empty (zero length)", cp->attr);
		if (!fr_rule_required(rule)) cf_log_err(cp, "Comment item to silence this message");
	error:
		ret = -1;
		return ret;
	}

	if (tmpl) {
		tmpl_t			*vpt;
		static tmpl_rules_t	rules = {
						.attr = {
							.allow_unknown = true,
							.allow_unresolved = true,
							.allow_foreign = true,
						},
						.literals_safe_for = FR_VALUE_BOX_SAFE_FOR_ANY,
					};
		fr_sbuff_t		sbuff = FR_SBUFF_IN(cp->value, strlen(cp->value));

		rules.attr.list_def = request_attr_request;

		/*
		 *	Bare words are magical sometimes.
		 */
		if (cp->rhs_quote == T_BARE_WORD) {
			/*
			 *	Attributes are parsed as attributes.
			 */
			if (fr_rule_is_attribute(rule)) {
				slen = tmpl_afrom_attr_substr(cp, NULL, &vpt, &sbuff, NULL, &rules);
				if (slen < 0) goto tmpl_error;

				fr_assert(vpt);

				*(tmpl_t **)out = vpt;
				goto finish;
			}

			/*
			 *	@todo - otherwise bare words are NOT parsed as attributes, they're parsed as
			 *	bare words, ala v3.
			 */

		} else if (fr_rule_is_attribute(rule)) {
			cf_log_err(cp, "Unexpected quoted string.  An attribute name is required here.");
			goto error;
		}

		slen = tmpl_afrom_substr(cp, &vpt, &sbuff, cp->rhs_quote,
					 value_parse_rules_unquoted[cp->rhs_quote],
					 &rules);
		if (slen < 0) {
		tmpl_error:
			cf_canonicalize_error(cp, slen, fr_strerror(), cp->value);
			goto error;
		}
		fr_assert(vpt);

		/*
		 *	The caller told us what data type was expected.  If we do have data, then try to cast
		 *	it to the requested type.
		 */
		if ((rule->type != FR_TYPE_VOID) && tmpl_contains_data(vpt)) {
			slen = 0;					// for errors

			if (tmpl_is_data_unresolved(vpt)) {
				tmpl_cast_set(vpt, rule->type);

				if (tmpl_resolve(vpt, NULL) < 0) goto tmpl_error;

			} else if (rule->type != tmpl_value_type(vpt)) {
				fr_assert(tmpl_is_data(vpt));

				if (tmpl_cast_in_place(vpt, rule->type, NULL) < 0) goto tmpl_error;
			}
		}

		*(tmpl_t **)out = vpt;
		goto finish;
	}

	/*
	 *	Parse as a boxed value out of sheer laziness...
	 *
	 *	Then we get all the internal types for free, and only need to add
	 *	one set of printing and parsing functions for new types...
	 */
	{
		fr_value_box_t	vb;

		if (cf_pair_to_value_box(ctx, &vb, cf_item_to_pair(ci), rule) < 0) goto error;

		if (fr_value_box_memcpy_out(out, &vb) < 0) {
			cf_log_perr(cp, "Failed unboxing parsed configuration item value");
			fr_value_box_clear_value(&vb);
			goto error;
		}
	}

finish:

	return ret;
}

/** Allocate a pair using the dflt value and quotation
 *
 * The pair created by this function should fed to #cf_pair_parse for parsing.
 *
 * @param[out] out	Where to write the CONF_PAIR we created with the default value.
 * @param[in] parent	being populated.
 * @param[in] cs	to parent the CONF_PAIR from.
 * @param[in] rule	to use to create the default.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int cf_pair_default(CONF_PAIR **out, void *parent, CONF_SECTION *cs, conf_parser_t const *rule)

{
	int		lineno = 0;
	char const	*expanded;
	CONF_PAIR	*cp;
	char		buffer[8192];
	fr_token_t	dflt_quote = rule->quote;

	fr_assert(rule->dflt || rule->dflt_func);

	if (fr_rule_required(rule)) {
		cf_log_err(cs, "Configuration pair \"%s\" must have a value", rule->name1);
		return -1;
	}

	/*
	 *	If no default quote was set, determine it from the type
	 */
	if (dflt_quote == T_INVALID) {
		if (fr_type_is_quoted(rule->type)) {
			dflt_quote = T_DOUBLE_QUOTED_STRING;
		} else {
			dflt_quote = T_BARE_WORD;
		}
	}

	/*
	 *	Use the dynamic default function if set
	 */
	if (rule->dflt_func) {
		if (rule->dflt_func(out, parent, cs, dflt_quote, rule) < 0) {
			cf_log_perr(cs, "Failed producing default for \"%s\"", rule->name1);
			return -1;
		}

		return 0;
	}

	expanded = cf_expand_variables("<internal>", lineno, cs, buffer, sizeof(buffer), rule->dflt, -1, NULL);
	if (!expanded) {
		cf_log_err(cs, "Failed expanding variable %s", rule->name1);
		return -1;
	}

	cp = cf_pair_alloc(cs, rule->name1, expanded, T_OP_EQ, T_BARE_WORD, dflt_quote);
	if (!cp) return -1;

	/*
	 *	Set the ret to indicate we used a default value
	 */
	*out = cp;

	return 1;
}

static int cf_pair_unescape(CONF_PAIR *cp, conf_parser_t const *rule)
{
	char const *p;
	char *str, *unescaped, *q;

	if (!cp->value) return 0;

	if (cp->rhs_quote != T_DOUBLE_QUOTED_STRING) return 0;

	if (!(rule->flags & CONF_FLAG_TMPL)) {
		if (rule->type != FR_TYPE_STRING) return 0;
	}

	if (strchr(cp->value, '\\') == NULL) return 0;

	str = talloc_strdup(cp, cp->value);
	if (!str) return -1;

	p = cp->value;
	q = str;
	while (*p) {
		unsigned int x;

		if (*p != '\\') {
			*(q++) = *(p++);
			continue;
		}

		p++;
		switch (*p) {
		case 'r':
			*q++ = '\r';
			break;
		case 'n':
			*q++ = '\n';
			break;
		case 't':
			*q++ = '\t';
			break;

		default:
			if (*p >= '0' && *p <= '9' &&
			    sscanf(p, "%3o", &x) == 1) {
				if (!x) {
					cf_log_err(cp, "Cannot have embedded zeros in value for %s", cp->attr);
					return -1;
				}

				*q++ = x;
				p += 2;
			} else {
				*q++ = *p;
			}
			break;
		}
		p++;
	}
	*q = '\0';

	unescaped = talloc_typed_strdup(cp, str); /* no embedded NUL */
	if (!unescaped) return -1;

	talloc_free(str);

	/*
	 *	Replace the old value with the new one.
	 */
	talloc_const_free(cp->value);
	cp->value = unescaped;

	return 0;
}

/** Parses a #CONF_PAIR into a C data type, with a default value.
 *
 * @param[in] ctx	To allocate arrays and values in.
 * @param[out] out	Where to write the result.
 *			Must not be NULL unless rule->runc is provided.
 * @param[in] base	address of the structure out points into.
 *			May be NULL in the case of manual parsing.
 * @param[in] cs	to search for matching #CONF_PAIR in.
 * @param[in] rule	to parse #CONF_PAIR with.
 * @return
 *	- 1 if default value was used, or if there was no CONF_PAIR or dflt.
 *	- 0 on success.
 *	- -1 on error.
 *	- -2 if deprecated.
 */
static int CC_HINT(nonnull(4,5)) cf_pair_parse_internal(TALLOC_CTX *ctx, void *out, void *base,
						        CONF_SECTION *cs, conf_parser_t const *rule)
{
	bool		required, deprecated, was_dflt = false;
	size_t		count = 0;
	CONF_PAIR	*cp = NULL, *dflt_cp = NULL;

#ifndef NDEBUG
	char const	*dflt = rule->dflt;
	fr_token_t	dflt_quote = rule->quote;
#endif
	cf_parse_t	func = rule->func ? rule->func : cf_pair_parse_value;

	fr_assert(!fr_rule_is_tmpl(rule) || !dflt || (dflt_quote != T_INVALID)); /* We ALWAYS need a quoting type for templates */

	/*
	 *	Functions don't necessarily *need* to write
	 *	anywhere, so their data pointer can be NULL.
	 */
	if (!out) {
		if (!rule->func) {
			cf_log_err(cs, "Rule doesn't specify output destination");
			return -1;
		}
	}

	required = fr_rule_required(rule);
	deprecated = fr_rule_deprecated(rule);

	/*
	 *	If the item is multi-valued we allocate an array
	 *	to hold the multiple values.
	 */
	if (fr_rule_multi(rule)) {
		void		**array;
		size_t		i = 0;

		/*
		 *	Easier than re-allocing
		 */
		count = cf_pair_count(cs, rule->name1);

		/*
		 *	Multivalued, but there's no value, create a
		 *	default pair.
		 */
		if (!count) {
			if (deprecated) return 0;

			if (!fr_rule_dflt(rule)) {
				if (required) {
			need_value:
					cf_log_err(cs, "Configuration item \"%s\" must have a value", rule->name1);
					return -1;
				}
				return 1;
			}

			if (cf_pair_default(&dflt_cp, base, cs, rule) < 0) return -1;
			count = cf_pair_count(cs, rule->name1);	/* Dynamic functions can add multiple defaults */
			if (!count) {
				if (fr_rule_not_empty(rule)) {
					cf_log_err(cs, "Configuration item \"%s\" cannot be empty", rule->name1);
					return -1;
				}
				return 0;
			}
		}

		if (deprecated) {
			/*
			 *	Emit the deprecated warning in the
			 *	context of the first pair.
			 */
			cp = cf_pair_find(cs, rule->name1);
			fr_assert(cp);

		deprecated:
			cf_log_err(cp, "Configuration pair \"%s\" is deprecated", cp->attr);
			return -2;
		}

		/*
		 *	No output, so don't bother allocing the array
		 */
		if (!out) {
			array = NULL;

		/*
		 *	Tmpl is outside normal range
		 */
		} else if (fr_rule_is_tmpl(rule)) {
			MEM(array = (void **)talloc_zero_array(ctx, tmpl_t *, count));

		/*
		 *	Allocate an array of values.
		 *
		 *	We don't NULL terminate.  Consumer must use
		 *	talloc_array_length().
		 */
		} else {
			array = fr_type_array_alloc(ctx, rule->type, count);
			if (unlikely(array == NULL)) {
				cf_log_perr(cp, "Failed allocating value array");
				return -1;
			}
		}

		while ((cp = cf_pair_find_next(cs, cp, rule->name1))) {
			int		ret;
			void		*entry;
			TALLOC_CTX	*value_ctx = array;

			/*
			 *	Figure out where to write the output
			 */
			if (!array) {
				entry = NULL;
			} else if ((rule->type == FR_TYPE_VOID) || (rule->flags & CONF_FLAG_TMPL)) {
				entry = &array[i++];
			} else {
				entry = ((uint8_t *) array) + (i++ * fr_value_box_field_sizes[rule->type]);
			}

			if (cf_pair_unescape(cp, rule) < 0) return -1;

			/*
			 *	Switch between custom parsing function
			 *	and the standard value parsing function.
			 */
			cf_pair_debug_log(cs, cp, rule);

			if (cf_pair_is_parsed(cp)) continue;
			ret = func(value_ctx, entry, base, cf_pair_to_item(cp), rule);
			if (ret < 0) {
				talloc_free(array);
				return -1;
			}
			cf_pair_mark_parsed(cp);
		}
		if (array) *(void **)out = array;
	/*
	 *	Single valued config item gets written to
	 *	the data pointer directly.
	 */
	} else {
		CONF_PAIR	*next;
		int		ret;

		cp = cf_pair_find(cs, rule->name1);
		if (!cp) {
			if (deprecated) return 0;

			if (!fr_rule_dflt(rule)) {
				if (required) goto need_value;
				return 1;
			}

			if (cf_pair_default(&dflt_cp, base, cs, rule) < 0) return -1;
			cp = dflt_cp;
			if (!cp) {
				if (fr_rule_not_empty(rule)) {
					cf_log_err(cs, "Configuration item \"%s\" cannot be empty", rule->name1);
					return -1;
				}

				return 0;
			}
			was_dflt = true;
		} else {
			if (cf_pair_unescape(cp, rule) < 0) return -1;
		}

		next = cf_pair_find_next(cs, cp, rule->name1);
		if (next) {
			cf_log_err(cf_pair_to_item(next), "Invalid duplicate configuration item '%s'", rule->name1);
			return -1;
		}
		if (deprecated) goto deprecated;

		cf_pair_debug_log(cs, cp, rule);

		if (cf_pair_is_parsed(cp)) return 0;
		ret = func(ctx, out, base, cf_pair_to_item(cp), rule);
		if (ret < 0) return -1;
		cf_pair_mark_parsed(cp);
	}

	return was_dflt ? 1 : 0;
}

/** Parses a #CONF_PAIR into a C data type, with a default value.
 *
 * Takes fields from a #conf_parser_t struct and uses them to parse the string value
 * of a #CONF_PAIR into a C data type matching the type argument.
 *
 * The format of the types are the same as #fr_value_box_t types.
 *
 * @note The dflt value will only be used if no matching #CONF_PAIR is found. Empty strings will not
 *	 result in the dflt value being used.
 *
 * **fr_type_t to data type mappings**
 * | fr_type_t               | Data type          | Dynamically allocated  |
 * | ----------------------- | ------------------ | ---------------------- |
 * | FR_TYPE_BOOL            | ``bool``           | No                     |
 * | FR_TYPE_UINT32          | ``uint32_t``       | No                     |
 * | FR_TYPE_UINT16          | ``uint16_t``       | No                     |
 * | FR_TYPE_UINT64          | ``uint64_t``       | No                     |
 * | FR_TYPE_INT32           | ``int32_t``        | No                     |
 * | FR_TYPE_STRING          | ``char const *``   | Yes                    |
 * | FR_TYPE_IPV4_ADDR       | ``fr_ipaddr_t``    | No                     |
 * | FR_TYPE_IPV4_PREFIX     | ``fr_ipaddr_t``    | No                     |
 * | FR_TYPE_IPV6_ADDR       | ``fr_ipaddr_t``    | No                     |
 * | FR_TYPE_IPV6_PREFIX     | ``fr_ipaddr_t``    | No                     |
 * | FR_TYPE_COMBO_IP_ADDR   | ``fr_ipaddr_t``    | No                     |
 * | FR_TYPE_COMBO_IP_PREFIX | ``fr_ipaddr_t``    | No                     |
 * | FR_TYPE_TIME_DELTA      | ``fr_time_delta_t``| No                     |
 *
 * @param[in] ctx	To allocate arrays and values in.
 * @param[in] cs	to search for matching #CONF_PAIR in.
 * @param[in] name	of #CONF_PAIR to search for.
 * @param[in] type	Data type to parse #CONF_PAIR value as.
 *			Should be one of the following ``data`` types,
 *			and one or more of the following ``flag`` types or'd together:

 *	- ``data`` #FR_TYPE_BOOL		- @copybrief FR_TYPE_BOOL
 *	- ``data`` #FR_TYPE_UINT32		- @copybrief FR_TYPE_UINT32
 *	- ``data`` #FR_TYPE_UINT16		- @copybrief FR_TYPE_UINT16
 *	- ``data`` #FR_TYPE_UINT64		- @copybrief FR_TYPE_UINT64
 *	- ``data`` #FR_TYPE_INT32		- @copybrief FR_TYPE_INT32
 *	- ``data`` #FR_TYPE_STRING		- @copybrief FR_TYPE_STRING
 *	- ``data`` #FR_TYPE_IPV4_ADDR		- @copybrief FR_TYPE_IPV4_ADDR (IPv4 address with prefix 32).
 *	- ``data`` #FR_TYPE_IPV4_PREFIX		- @copybrief FR_TYPE_IPV4_PREFIX (IPv4 address with variable prefix).
 *	- ``data`` #FR_TYPE_IPV6_ADDR		- @copybrief FR_TYPE_IPV6_ADDR (IPv6 address with prefix 128).
 *	- ``data`` #FR_TYPE_IPV6_PREFIX		- @copybrief FR_TYPE_IPV6_PREFIX (IPv6 address with variable prefix).
 *	- ``data`` #FR_TYPE_COMBO_IP_ADDR 	- @copybrief FR_TYPE_COMBO_IP_ADDR (IPv4/IPv6 address with
 *						  prefix 32/128).
 *	- ``data`` #FR_TYPE_COMBO_IP_PREFIX	- @copybrief FR_TYPE_COMBO_IP_PREFIX (IPv4/IPv6 address with
 *						  variable prefix).
 *	- ``data`` #FR_TYPE_TIME_DELTA		- @copybrief FR_TYPE_TIME_DELTA
 *	- ``flag`` #CONF_FLAG_TMPL		- @copybrief CONF_FLAG_TMPL
 *					  	  Feeds the value into #tmpl_afrom_substr. Value can be
 *					  	  obtained when processing requests, with #tmpl_expand or #tmpl_aexpand.
 *	- ``flag`` #FR_TYPE_DEPRECATED		- @copybrief FR_TYPE_DEPRECATED
 *	- ``flag`` #CONF_FLAG_REQUIRED		- @copybrief CONF_FLAG_REQUIRED
 *	- ``flag`` #CONF_FLAG_ATTRIBUTE		- @copybrief CONF_FLAG_ATTRIBUTE
 *	- ``flag`` #CONF_FLAG_SECRET		- @copybrief CONF_FLAG_SECRET
 *	- ``flag`` #CONF_FLAG_FILE_READABLE	- @copybrief CONF_FLAG_FILE_READABLE
 *	- ``flag`` #CONF_FLAG_FILE_WRITABLE	- @copybrief CONF_FLAG_FILE_WRITABLE
 *	- ``flag`` #CONF_FLAG_NOT_EMPTY		- @copybrief CONF_FLAG_NOT_EMPTY
 *	- ``flag`` #CONF_FLAG_MULTI		- @copybrief CONF_FLAG_MULTI
 *	- ``flag`` #CONF_FLAG_IS_SET		- @copybrief CONF_FLAG_IS_SET
 * @param[out] data		Pointer to a global variable, or pointer to a field in the struct being populated with values.
 * @param[in] dflt		value to use, if no #CONF_PAIR is found.
 * @param[in] dflt_quote	around the dflt value.
 * @return
 *	- 1 if default value was used, or if there was no CONF_PAIR or dflt.
 *	- 0 on success.
 *	- -1 on error.
 *	- -2 if deprecated.
 */
int cf_pair_parse(TALLOC_CTX *ctx, CONF_SECTION *cs, char const *name,
		  unsigned int type, void *data, char const *dflt, fr_token_t dflt_quote)
{
	conf_parser_t rule = {
		.name1 = name,
		.type = type,
		.dflt = dflt,
		.quote = dflt_quote
	};

	return cf_pair_parse_internal(ctx, data, NULL, cs, &rule);
}

/** Pre-allocate a config section structure to allow defaults to be set
 *
 * @param cs		The parent subsection.
 * @param base		pointer or variable.
 * @param rule		that may have defaults in this config section.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int cf_section_parse_init(CONF_SECTION *cs, void *base, conf_parser_t const *rule)
{
	CONF_PAIR *cp;

	/*
	 *	This rule refers to a named subsection
	 */
	if ((rule->flags & CONF_FLAG_SUBSECTION)) {
		char const	*name2 = NULL;
		CONF_SECTION	*subcs;

		/*
		 *	Optional MUST be listed before required ones
		 */
		if ((rule->flags & CONF_FLAG_OPTIONAL) != 0) {
			return 0;
		}

		subcs = cf_section_find(cs, rule->name1, rule->name2);

		/*
		 *	Set the is_set field for the subsection.
		 */
		if (rule->flags & CONF_FLAG_IS_SET) {
			bool *is_set;

			is_set = rule->data ? rule->is_set_ptr : ((uint8_t *)base) + rule->is_set_offset;
			if (is_set) *is_set = (subcs != NULL);
		}

		/*
		 *	It exists, we don't have to do anything else.
		 */
		if (subcs) return 0;

		/*
		 *	If there is no subsection, either complain,
		 *	allow it, or create it with default values.
		 */
		if (rule->flags & CONF_FLAG_REQUIRED) {
		  	cf_log_err(cs, "Missing %s {} subsection", rule->name1);
		  	return -1;
		}

		/*
		 *	It's OK for this to be missing.  Don't
		 *	initialize it.
		 */
		if ((rule->flags & CONF_FLAG_OK_MISSING) != 0) return 0;

		/*
		 *	If there's no subsection in the
		 *	config, BUT the conf_parser_t wants one,
		 *	then create an empty one.  This is so
		 *	that we can track the strings,
		 *	etc. allocated in the subsection.
		 */
		if (DEBUG_ENABLED4) cf_log_debug(cs, "Allocating fake section \"%s\"", rule->name1);

		/*
		 *	If name1 is CF_IDENT_ANY, then don't
		 *	alloc the section as we have no idea
		 *	what it should be called.
		 */
		if (rule->name1 == CF_IDENT_ANY) return 0;

		/*
		 *	Don't specify name2 if it's CF_IDENT_ANY
		 */
		if (rule->name2 != CF_IDENT_ANY) name2 = rule->name2;
		subcs = cf_section_alloc(cs, cs, rule->name1, name2);
		if (!subcs) return -1;

		return 0;
	}

	/*
	 *	This rule refers to another conf_parse_t which is included in-line in
	 *	this section.
	 */
	if ((rule->flags & CONF_FLAG_REF) != 0) {
		conf_parser_t const *rule_p;
		uint8_t *sub_base = base;

		fr_assert(rule->subcs != NULL);

		sub_base += rule->offset;

		for (rule_p = rule->subcs; rule_p->name1; rule_p++) {
			int ret = cf_section_parse_init(cs, sub_base, rule_p);
			if (ret < 0) return ret;
		}
		return 0;
	}

	/*
	 *	Don't re-initialize data which was already parsed.
	 */
	cp = cf_pair_find(cs, rule->name1);
	if (cp && cp->parsed) return 0;

	if ((rule->type != FR_TYPE_STRING) &&
	    (!(rule->flags & CONF_FLAG_FILE_READABLE)) &&
	    (!(rule->flags & CONF_FLAG_FILE_WRITABLE))) {
		return 0;
	}

	if (rule->data) {
		*(char **) rule->data = NULL;
	} else if (base) {
		*(char **) (((char *)base) + rule->offset) = NULL;
	} else {
		return 0;
	}

	return 0;
}

static void cf_section_parse_warn(CONF_SECTION *cs)
{
	cf_item_foreach(&cs->item, ci) {
		/*
		 *	Don't recurse on sections. We can only safely
		 *	check conf pairs at the same level as the
		 *	section that was just parsed.
		 */
		if (ci->type == CONF_ITEM_SECTION) continue;
		if (ci->type == CONF_ITEM_PAIR) {
			CONF_PAIR *cp;

			cp = cf_item_to_pair(ci);
			if (cp->parsed || cp->referenced || (ci->lineno < 0)) continue;

			WARN("%s[%d]: The item '%s' is defined, but is unused by the configuration",
			     ci->filename, ci->lineno,
			     cp->attr);
		}

		/*
		 *	Skip everything else.
		 */
	}
}

/** Parse a subsection
 *
 * @note Turns out using nested structures (instead of pointers) for subsections, was actually
 *	a pretty bad design decision, and will need to be fixed at some future point.
 *	For now we have a horrible hack where only multi-subsections get an array of structures
 *	of the appropriate size.
 *
 * @param[in] ctx	to allocate any additional structures under.
 * @param[out] out	pointer to a struct/pointer to fill with data.
 * @param[in] base	address of the structure out points into.
 *			May be NULL in the case of manual parsing.
 * @param[in] cs	to parse.
 * @param[in] rule	to parse the subcs with.
 * @return
 *	- 0 on success.
 *	- -1 on general error.
 *	- -2 if a deprecated #CONF_ITEM was found.
 */
static int cf_subsection_parse(TALLOC_CTX *ctx, void *out, void *base, CONF_SECTION *cs, conf_parser_t const *rule)
{
	CONF_SECTION		*subcs = NULL;
	int			count = 0, i = 0, ret;

	size_t			subcs_size = rule->subcs_size;
	conf_parser_t const	*rules = rule->subcs;

	uint8_t			**array = NULL;

	fr_assert(rule->flags & CONF_FLAG_SUBSECTION);

	subcs = cf_section_find(cs, rule->name1, rule->name2);
	if (!subcs) return 0;

	/*
	 *	Handle the single subsection case (which is simple)
	 */
	if (!(rule->flags & CONF_FLAG_MULTI)) {
		uint8_t *buff = NULL;

		if (DEBUG_ENABLED4) cf_log_debug(cs, "Evaluating rules for %s section.  Output %p",
						 cf_section_name1(subcs), out);

		/*
		 *	Add any rules, so the func can just call cf_section_parse
		 *	if it wants to continue after doing its stuff.
		 */
		if (cf_section_rules_push(subcs, rules) < 0) return -1;
		if (rule->func) return rule->func(ctx, out, base, cf_section_to_item(subcs), rule);

		/*
		 *	FIXME: We shouldn't allow nested structures like this.
		 *	Each subsection struct should be allocated separately so
		 *	we have a clean talloc hierarchy.
		 */
	 	if (!subcs_size) return cf_section_parse(ctx, out, subcs);

		if (out) {
			MEM(buff = talloc_zero_array(ctx, uint8_t, subcs_size));
			if (rule->subcs_type) talloc_set_name_const(buff, rule->subcs_type);
		}

		ret = cf_section_parse(buff, buff, subcs);
		if (ret < 0) {
			talloc_free(buff);
			return ret;
		}

		if (out) *((uint8_t **)out) = buff;

		return 0;
	}

	fr_assert(subcs_size);

	/*
	 *	Handle the multi subsection case (which is harder)
	 */
	subcs = NULL;
	while ((subcs = cf_section_find_next(cs, subcs, rule->name1, rule->name2))) count++;

	/*
	 *	Allocate an array to hold the subsections
	 */
	if (out) {
		MEM(array = talloc_zero_array(ctx, uint8_t *, count));
		if (rule->subcs_type) talloc_set_name(array, "%s *", rule->subcs_type);
	}
	/*
	 *	Start parsing...
	 *
	 *	Note, we allocate each subsection structure individually
	 *	so that they can be used as talloc contexts and we can
	 *	keep the talloc hierarchy clean.
	 */
	subcs = NULL;
	while ((subcs = cf_section_find_next(cs, subcs, rule->name1, rule->name2))) {
		uint8_t *buff = NULL;

		if (DEBUG_ENABLED4) cf_log_debug(cs, "Evaluating rules for %s[%i] section.  Output %p",
						 cf_section_name1(subcs),
						 i, out);

		if (array) {
			MEM(buff = talloc_zero_array(array, uint8_t, subcs_size));
			if (rule->subcs_type) talloc_set_name_const(buff, rule->subcs_type);
			array[i++] = buff;
		}

		/*
		 *	Add any rules, so the func can just call cf_section_parse
		 *	if it wants to continue after doing its stuff.
		 */
		if (cf_section_rules_push(subcs, rules) < 0) {
			talloc_free(array);
			return -1;
		}
		if (rule->func) {
			ret = rule->func(ctx, buff, base, cf_section_to_item(subcs), rule);
			if (ret < 0) {
				talloc_free(array);
				return ret;
			}
			continue;
		}

		ret = cf_section_parse(buff, buff, subcs);
		if (ret < 0) {
			talloc_free(array);
			return ret;
		}
	}

	if (out) *((uint8_t ***)out) = array;

	return 0;
}

static int cf_section_parse_rule(TALLOC_CTX *ctx, void *base, CONF_SECTION *cs, conf_parser_t const *rule)
{
	int		ret;
	bool		*is_set = NULL;
	void		*data = NULL;

	/*
	 *	Ignore ON_READ parse rules if there's no subsequent
	 *	parse functions.
	 */
	if (!rule->func && rule->on_read) return 0;

	/*
	 *	Pre-allocate the config structure to hold default values
	 */
	if (cf_section_parse_init(cs, base, rule) < 0) return -1;

	if (rule->data) {
		data = rule->data; /* prefer this. */
	} else if (base) {
		data = ((uint8_t *)base) + rule->offset;
	}

	/*
	 *	Handle subsections specially
	 */
	if (rule->flags & CONF_FLAG_SUBSECTION) {
		return cf_subsection_parse(ctx, data, base, cs, rule);
	}

	/*
	 *	Ignore this rule if it's a reference, as the
	 *	rules it points to have been pushed by the
	 *	above function.
	 */
	if ((rule->flags & CONF_FLAG_REF) != 0) {
		conf_parser_t const *rule_p;
		uint8_t *sub_base = base;

		fr_assert(rule->subcs != NULL);

		sub_base += rule->offset;

		for (rule_p = rule->subcs; rule_p->name1; rule_p++) {
			if (rule_p->flags & CONF_FLAG_DEPRECATED) continue;	/* Skip deprecated */

			ret = cf_section_parse_rule(ctx, sub_base, cs, rule_p);
			if (ret < 0) return ret;
		}

		/*
		 *	Ensure we have a proper terminator, type so we catch
		 *	missing terminators reliably
		 */
		fr_cond_assert(rule_p->type == conf_term.type);

		return 0;
	}

	/*
	 *	Else it's a CONF_PAIR
	 */

	/*
	 *	Pair either needs an output destination or
	 *	there needs to be a function associated with
	 *	it.
	 */
	if (!data && !rule->func) {
		cf_log_err(cs, "Rule doesn't specify output destination");
		return -1;
	}

	/*
	 *	Get pointer to where we need to write out
	 *	whether the pointer was set.
	 */
	if (rule->flags & CONF_FLAG_IS_SET) {
		is_set = rule->data ? rule->is_set_ptr : ((uint8_t *)base) + rule->is_set_offset;
	}

	/*
	 *	Parse the pair we found, or a default value.
	 */
	ret = cf_pair_parse_internal(ctx, data, base, cs, rule);
	switch (ret) {
	case 1:		/* Used default (or not present) */
		if (is_set) *is_set = false;
		ret = 0;
		break;

	case 0:		/* OK */
		if (is_set) *is_set = true;
		break;

	case -1:	/* Parse error */
		break;

	case -2:	/* Deprecated CONF ITEM */
		if (((rule + 1)->offset && ((rule + 1)->offset == rule->offset)) ||
		    ((rule + 1)->data && ((rule + 1)->data == rule->data))) {
			cf_log_err(cs, "Replace \"%s\" with \"%s\"", rule->name1,
				   (rule + 1)->name1);
		}
		break;
	}

	return ret;
}

/** Parse a configuration section into user-supplied variables
 *
 * @param[in] ctx		to allocate any strings, or additional structures in.
 *				Usually the same as base, unless base is a nested struct.
 * @param[out] base		pointer to a struct to fill with data.
 * @param[in] cs		to parse.
 * @return
 *	- 0 on success.
 *	- -1 on general error.
 *	- -2 if a deprecated #CONF_ITEM was found.
 */
int cf_section_parse(TALLOC_CTX *ctx, void *base, CONF_SECTION *cs)
{
	CONF_DATA const	*rule_cd = NULL;

	if (!cs->name2) {
		cf_log_debug(cs, "%.*s%s {", SECTION_SPACE(cs), parse_spaces, cs->name1);
	} else {
		cf_log_debug(cs, "%.*s%s %s {", SECTION_SPACE(cs), parse_spaces, cs->name1, cs->name2);
	}

	/*
	 *	Loop over all the child rules of the section
	 */
	while ((rule_cd = cf_data_find_next(cs, rule_cd, conf_parser_t, CF_IDENT_ANY))) {
		int		ret;
		conf_parser_t	*rule;

		rule = cf_data_value(rule_cd);

		ret = cf_section_parse_rule(ctx, base, cs, rule);
		if (ret < 0) return ret;
	}

	cs->base = base;

	/*
	 *	Warn about items in the configuration which weren't
	 *	checked during parsing.
	 */
	if (DEBUG_ENABLED4) cf_section_parse_warn(cs);

	cf_log_debug(cs, "%.*s}", SECTION_SPACE(cs), parse_spaces);

	return 0;
}

/*
 *	Pass2 fixups on tmpl_t
 *
 *	We don't have (or need yet) cf_pair_parse_pass2(), so we just
 *	do it for tmpls.
 */
static int cf_parse_tmpl_pass2(UNUSED CONF_SECTION *cs, tmpl_t **out, CONF_PAIR *cp, fr_type_t type,
			       bool attribute, fr_dict_t const *dict_def)
{
	tmpl_t *vpt = *out;

	fr_assert(vpt);	/* We need something to resolve */

	if (tmpl_resolve(vpt, &(tmpl_res_rules_t){ .dict_def = dict_def, .force_dict_def = (dict_def != NULL)}) < 0) {
		cf_log_perr(cp, "Failed processing configuration item '%s'", cp->attr);
		return -1;
	}

	if (attribute) {
		if (!tmpl_is_attr(vpt)) {
			cf_log_err(cp, "Expected attr got %s",
				   tmpl_type_to_str(vpt->type));
			return -1;
		}
	}

	switch (vpt->type) {
	/*
	 *	All attributes should have been defined by this point.
	 */
	case TMPL_TYPE_ATTR_UNRESOLVED:
		cf_log_err(cp, "Unknown attribute '%s'", tmpl_attr_tail_unresolved(vpt));
		return -1;

	case TMPL_TYPE_DATA_UNRESOLVED:
		/*
		 *	Try to realize the underlying type, if at all possible.
		 */
		if (!attribute && type && (tmpl_cast_in_place(vpt, type, NULL) < 0)) {
			cf_log_perr(cp, "Failed processing configuration item '%s'", cp->attr);
			return -1;
		}
		break;

	case TMPL_TYPE_ATTR:
	case TMPL_TYPE_DATA:
	case TMPL_TYPE_EXEC:
	case TMPL_TYPE_EXEC_UNRESOLVED:
	case TMPL_TYPE_XLAT:
	case TMPL_TYPE_XLAT_UNRESOLVED:
		break;

	case TMPL_TYPE_UNINITIALISED:
	case TMPL_TYPE_REGEX:
	case TMPL_TYPE_REGEX_UNCOMPILED:
	case TMPL_TYPE_REGEX_XLAT:
	case TMPL_TYPE_REGEX_XLAT_UNRESOLVED:
	case TMPL_TYPE_MAX:
		fr_assert(0);
		/* Don't add default */
	}

	return 0;
}

/** Fixup xlat expansions and attributes
 *
 * @param[out] base start of structure to write #tmpl_t s to.
 * @param[in] cs CONF_SECTION to fixup.
 * @return
 *	- 0 on success.
 *	- -1 on failure (parse errors etc...).
 */
int cf_section_parse_pass2(void *base, CONF_SECTION *cs)
{
	CONF_DATA const *rule_cd = NULL;

	while ((rule_cd = cf_data_find_next(cs, rule_cd, conf_parser_t, CF_IDENT_ANY))) {
		bool			attribute, multi, is_tmpl, is_xlat;
		CONF_PAIR		*cp;
		conf_parser_t		*rule = cf_data_value(rule_cd);
		void			*data;
		fr_type_t		type = rule->type;
		conf_parser_flags_t 	flags = rule->flags;
		fr_dict_t const		*dict = NULL;

		is_tmpl = (flags & CONF_FLAG_TMPL);
		is_xlat = (flags & CONF_FLAG_XLAT);
		attribute = (flags & CONF_FLAG_ATTRIBUTE);
		multi = (flags & CONF_FLAG_MULTI);

		/*
		 *	It's a section, recurse!
		 */
		if (flags & CONF_FLAG_SUBSECTION) {
			uint8_t		*subcs_base;
			CONF_SECTION	*subcs = cf_section_find(cs, rule->name1, rule->name2);

			/*
			 *	Select base by whether this is a nested struct,
			 *	or a pointer to another struct.
			 */
			if (!base) {
				subcs_base = NULL;
			} else if (multi) {
				size_t		j, len;
				uint8_t		**array;

				array = *(uint8_t ***)(((uint8_t *)base) + rule->offset);
				len = talloc_array_length(array);

				for (j = 0; j < len; j++) if (cf_section_parse_pass2(array[j], subcs) < 0) return -1;
				continue;
			} else {
				subcs_base = (uint8_t *)base + rule->offset;
			}

			if (cf_section_parse_pass2(subcs_base, subcs) < 0) return -1;

			continue;
		}

		/*
		 *	Find the CONF_PAIR, may still not exist if there was
		 *	no default set for the conf_parser_t.
		 */
		cp = cf_pair_find(cs, rule->name1);
		if (!cp) continue;

		/*
		 *	Figure out which data we need to fix.
		 */
		data = rule->data; /* prefer this. */
		if (!data && base) data = ((char *)base) + rule->offset;
		if (!data) continue;

		/*
		 *	Non-xlat expansions shouldn't have xlat!
		 *
		 *	Except other libraries like libkafka may be the ones
		 *	doing the actual expansion, so we don't _know_
		 *	if the xlatlike value is destined for use in FreeRADIUS
		 *	or not, so we can't definitely determine if this is an
		 *	error.
		 *
		 *	Code left in place to warn other people off re-adding
		 *	this check in future.
		 */
#if 0
		if (!is_xlat && !is_tmpl) {
			/*
			 *	Ignore %{... in shared secrets.
			 *	They're never dynamically expanded.
			 */
			if ((rule->flags & CONF_FLAG_SECRET) != 0) continue;

			if (strstr(cp->value, "%{") != NULL) {
				cf_log_err(cp, "Found dynamic expansion in string which "
					   "will not be dynamically expanded");
				return -1;
			}
			continue;
		}
#endif

		/*
		 *	Search for dictionary data somewhere in the virtual
		 *      server.
		 */
		dict = virtual_server_dict_by_child_ci(cf_section_to_item(cs));

		/*
		 *	Parse (and throw away) the xlat string (for validation).
		 *
		 *	FIXME: All of these should be converted from CONF_FLAG_XLAT
		 *	to CONF_FLAG_TMPL.
		 */
		if (is_xlat) {
			ssize_t		slen;
			xlat_exp_head_t	*xlat;

		redo:
			xlat = NULL;

			/*
			 *	xlat expansions should be parseable.
			 */
			slen = xlat_tokenize(cs, &xlat,
					     &FR_SBUFF_IN(cp->value, talloc_array_length(cp->value) - 1), NULL,
					     &(tmpl_rules_t) {
						     .attr = {
							     .dict_def = dict,
							     .list_def = request_attr_request,
							     .allow_unknown = false,
							     .allow_unresolved = false,
							     .allow_foreign = (dict == NULL)
						     },
					     });
			if (slen < 0) {
				char *spaces, *text;

				fr_canonicalize_error(cs, &spaces, &text, slen, cp->value);

				cf_log_err(cp, "Failed parsing expansion string:");
				cf_log_err(cp, "%s", text);
				cf_log_perr(cp, "%s^", spaces);

				talloc_free(spaces);
				talloc_free(text);
				talloc_free(xlat);
				return -1;
			}

			talloc_free(xlat);

			/*
			 *	If the "multi" flag is set, check all of them.
			 */
			if (multi) {
				cp = cf_pair_find_next(cs, cp, cp->attr);
				if (cp) goto redo;
			}
			continue;

		/*
		 *	Parse the pair into a template
		 */
		} else if (is_tmpl && !multi) {
			if (cf_parse_tmpl_pass2(cs, (tmpl_t **)data, cp, type, attribute, dict) < 0) {
				return -1;
			}

		} else if (is_tmpl) {
			size_t i;
			char const *name = cp->attr;
			tmpl_t **array = *(tmpl_t ***) data;

			for (i = 0; i < talloc_array_length(array); i++, cp = cf_pair_find_next(cs, cp, name)) {
				if (!cp) break;

				if (cf_parse_tmpl_pass2(cs, &array[i], cp, type, attribute, dict) < 0) {
					return -1;
				}
			}
		}
	}

	return 0;
}


/** Add a single rule to a #CONF_SECTION
 *
 * @param[in] cs	to add rules to.
 * @param[in] rule	to add.
 * @param[in] filename	where the rule was pushed.
 * @param[in] lineno	where the rule was pushed.
 * @return
 *	- 0 on success.
 *	- -1 if the rules added conflict.
 */
int _cf_section_rule_push(CONF_SECTION *cs, conf_parser_t const *rule, char const *filename, int lineno)
{
	char const *name1, *name2;

	if (!cs || !rule) return 0;

	name1 = rule->name1 == CF_IDENT_ANY ? "__any__" : rule->name1;
	name2 = rule->name2 == CF_IDENT_ANY ? "__any__" : rule->name2;

	if (DEBUG_ENABLED4) {
		cf_log_debug(cs, "Pushed parse rule to %s section: %s %s",
			     cf_section_name1(cs),
			     name1, rule->flags & CONF_FLAG_SUBSECTION ? "{}": "");
	}

	/*
	 *	Qualifying with name prevents duplicate rules being added
	 *
	 *	Fixme maybe?.. Can't have a section and pair with the same name.
	 */
	if (!_cf_data_add_static(CF_TO_ITEM(cs), rule, "conf_parser_t", name1, filename, lineno)) {
		CONF_DATA const *cd;
		conf_parser_t *old;

		cd = cf_data_find(CF_TO_ITEM(cs), conf_parser_t, name1);
		old = cf_data_value(cd);
		fr_assert(old != NULL);

		/*
		 *	Shut up about duplicates.
		 */
		if (memcmp(rule, old, sizeof(*rule)) == 0) {
			return 0;
		}

		/*
		 *	Remove any ON_READ callbacks, and add the new
		 *	rule in its place.
		 */
		if (old->on_read) {
			CONF_DATA *cd1;

			/*
			 *	Over-write the rule in place.
			 *
			 *	We'd like to call cf_item_remove(), but
			 *	that apparently doesn't work for
			 *	CONF_DATA.  We don't need to
			 *	free/alloc one, so re-using this is
			 *	fine.
			 */
			memcpy(&cd1, &cd, sizeof(cd1));
			cd1->data = rule;
			cd1->item.filename = filename;
			cd1->item.lineno = lineno;
			return 0;
		}

		/*
		 *	If we have a duplicate sub-section, just
		 *	recurse and add the new sub-rules to the
		 *	existing sub-section.
		 */
		if (rule->flags & CONF_FLAG_SUBSECTION) {
			CONF_SECTION *subcs;

			subcs = cf_section_find(cs, name1, name2);
			if (!subcs) {
				cf_log_err(cs, "Failed finding '%s' subsection", name1);
				cf_item_debug(cs);
				return -1;
			}

			/*
			 *	The old rules were delayed until we pushed a matching subsection which is actually used.
			 */
			if ((old->flags & CONF_FLAG_OPTIONAL) != 0) {
				if (cf_section_rules_push(subcs, old->subcs) < 0) return -1;
			}

			return cf_section_rules_push(subcs, rule->subcs);
		}

		cf_log_err(cs, "Data of type %s with name \"%s\" already exists. "
		           "Existing data added %s[%i]", "conf_parser_t",
			   name1, cd->item.filename, cd->item.lineno);

		cf_item_debug(cs);
		return -1;
	}

	return 0;
}

/** Add an array of parse rules to a #CONF_SECTION
 *
 * @param[in] cs	to add rules to.
 * @param[in] rules	to add.  Last element should have NULL name field.
 * @param[in] filename	where the rule was pushed.
 * @param[in] lineno	where the rule was pushed.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int _cf_section_rules_push(CONF_SECTION *cs, conf_parser_t const *rules, char const *filename, int lineno)
{
	conf_parser_t const *rule_p;

	if (!cs || !rules) return 0;

	for (rule_p = rules; rule_p->name1; rule_p++) {
		if (rule_p->flags & CONF_FLAG_DEPRECATED) continue;	/* Skip deprecated */
		if (_cf_section_rule_push(cs, rule_p, filename, lineno) < 0) return -1;
	}

	/*
	 *	Ensure we have a proper terminator, type so we catch
	 *	missing terminators reliably
	 */
	fr_cond_assert(rule_p->type == conf_term.type);

	return 0;
}

/** Generic function for parsing conf pair values as int
 *
 * @note This should be used for enum types as c99 6.4.4.3 states that the enumeration
 * constants are of type int.
 *
 */
int cf_table_parse_int(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent,
		       CONF_ITEM *ci, conf_parser_t const *rule)
{
	int				num;
	cf_table_parse_ctx_t const	*parse_ctx = rule->uctx;

	if (cf_pair_in_table(&num, parse_ctx->table, *parse_ctx->len, cf_item_to_pair(ci)) < 0) return -1;

	*((int *)out) = num;

	return 0;
}

/** Generic function for parsing conf pair values as int32_t (FR_TYPE_INT32)
 *
 */
int cf_table_parse_int32(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent,
			 CONF_ITEM *ci, conf_parser_t const *rule)
{
	int32_t				num;
	cf_table_parse_ctx_t const	*parse_ctx = rule->uctx;

	if (cf_pair_in_table(&num, parse_ctx->table, *parse_ctx->len, cf_item_to_pair(ci)) < 0) return -1;

	*((int32_t *)out) = num;

	return 0;
}

/** Generic function for parsing conf pair values as int32_t (FR_TYPE_UINT32)
 *
 */
int cf_table_parse_uint32(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent,
			  CONF_ITEM *ci, conf_parser_t const *rule)
{
	int32_t				num;
	cf_table_parse_ctx_t const	*parse_ctx = rule->uctx;

	if (cf_pair_in_table(&num, parse_ctx->table, *parse_ctx->len, cf_item_to_pair(ci)) < 0) return -1;
	if (num < 0) {
		cf_log_err(ci, "Resolved value must be a positive integer, got %i", num);
		return -1;
	}
	*((uint32_t *)out) = (uint32_t)num;

	return 0;
}

/** Generic function for resolving UID strings to uid_t values
 *
 * Type should be FR_TYPE_VOID, struct field should be a uid_t.
 */
int cf_parse_uid(TALLOC_CTX *ctx, void *out, UNUSED void *parent,
		 CONF_ITEM *ci, UNUSED conf_parser_t const *rule)
{
	if (fr_perm_uid_from_str(ctx, (uid_t *)out, cf_pair_value(cf_item_to_pair(ci))) < 0) {
		cf_log_perr(ci, "Failed resolving UID");
		return -1;
	}

	return 0;
}

/** Generic function for resolving GID strings to uid_t values
 *
 * Type should be FR_TYPE_VOID, struct field should be a gid_t.
 */
int cf_parse_gid(TALLOC_CTX *ctx, void *out, UNUSED void *parent,
		 CONF_ITEM *ci, UNUSED conf_parser_t const *rule)
{
	if (fr_perm_gid_from_str(ctx, (gid_t *)out, cf_pair_value(cf_item_to_pair(ci))) < 0) {
		cf_log_perr(ci, "Failed resolving GID");
		return -1;
	}

	return 0;
}

/** Generic function for resolving permissions to a mode-t
 *
 * Type should be FR_TYPE_VOID, struct field should be a gid_t.
 */
int cf_parse_permissions(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent,
			 CONF_ITEM *ci, UNUSED conf_parser_t const *rule)
{
	mode_t mode;
	char const *name = cf_pair_value(cf_item_to_pair(ci));

	if (fr_perm_mode_from_str(&mode, name) < 0) {
		cf_log_perr(ci, "Invalid permissions string");
		return -1;
	}

	*(mode_t *) out = mode;

	return 0;
}

/** NULL callback for sections
 *
 *  This callback exists only as a place-holder to ensure that the
 *  nested on_read functions are called.  The conf file routines won't
 *  recurse into every conf_parser_t section to check if there's an
 *  "on_read" callback.  So this place-holder is a signal to do that.
 *
 * @param[in] ctx	to allocate data in.
 * @param[out] out	Unused
 * @param[in] parent	Base structure address.
 * @param[in] ci	#CONF_SECTION containing the current section.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int cf_null_on_read(UNUSED TALLOC_CTX *ctx, UNUSED void *out, UNUSED void *parent,
		    UNUSED CONF_ITEM *ci, UNUSED conf_parser_t const *rule)
{
	return 0;
}
