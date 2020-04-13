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
 * @brief Covert internal format configuration values into native C types.
 *
 * @copyright 2017 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2000,2006 The FreeRADIUS server project
 * @copyright 2000 Miquel van Smoorenburg (miquels@cistron.nl)
 * @copyright 2000 Alan DeKok (aland@freeradius.org)
 */
RCSID("$Id$")

#include <string.h>

#include <freeradius-devel/server/cf_file.h>
#include <freeradius-devel/server/cf_parse.h>
#include <freeradius-devel/server/cf_priv.h>
#include <freeradius-devel/server/log.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/server/tmpl.h>

#include <freeradius-devel/util/inet.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/types.h>

static CONF_PARSER conf_term = CONF_PARSER_TERMINATOR;
static char const parse_spaces[] = "                                                                                                                                                                                                                                              ";

#define PAIR_SPACE(_cs) ((_cs->depth + 1) * 2)
#define SECTION_SPACE(_cs) (_cs->depth * 2)

/** Validation function for ipaddr conf_file types
 *
 */
static inline int CC_HINT(nonnull) fr_item_validate_ipaddr(CONF_SECTION *cs, char const *name,
							   fr_type_t type, char const *value,
							   fr_ipaddr_t *ipaddr)
{
	char ipbuf[128];

	if (strcmp(value, "*") == 0) {
		cf_log_debug(cs, "%.*s%s = *", PAIR_SPACE(cs), parse_spaces, name);
	} else if (strspn(value, ".0123456789abdefABCDEF:%[]/") == strlen(value)) {
		cf_log_debug(cs, "%.*s%s = %s", PAIR_SPACE(cs), parse_spaces, name, value);
	} else {
		cf_log_debug(cs, "%.*s%s = %s IPv%s address [%s]", PAIR_SPACE(cs), parse_spaces, name, value,
			    (ipaddr->af == AF_INET ? "4" : " 6"), fr_inet_ntoh(ipaddr, ipbuf, sizeof(ipbuf)));
	}

	switch (type) {
	case FR_TYPE_IPV4_ADDR:
	case FR_TYPE_IPV6_ADDR:
	case FR_TYPE_COMBO_IP_ADDR:
		switch (ipaddr->af) {
		case AF_INET:
		if (ipaddr->prefix != 32) {
			ERROR("Invalid IPv4 mask length \"/%i\".  Only \"/32\" permitted for non-prefix types",
			      ipaddr->prefix);

			return -1;
		}
			break;

		case AF_INET6:
		if (ipaddr->prefix != 128) {
			ERROR("Invalid IPv6 mask length \"/%i\".  Only \"/128\" permitted for non-prefix types",
			      ipaddr->prefix);

			return -1;
		}
			break;

		default:
			return -1;
		}
		return 0;

	case FR_TYPE_IPV4_PREFIX:
	case FR_TYPE_IPV6_PREFIX:
	case FR_TYPE_COMBO_IP_PREFIX:
		return 0;

	default:
		fr_assert(0);
		return -1;
	}
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
int cf_pair_parse_value(TALLOC_CTX *ctx, void *out, UNUSED void *base, CONF_ITEM *ci, CONF_PARSER const *rule)
{
	int		rcode = 0;
	bool		attribute, required, secret, file_input, cant_be_empty, tmpl, file_exists;

	fr_ipaddr_t	*ipaddr;
	ssize_t		slen;

	int		type = rule->type;
	CONF_PAIR	*cp = cf_item_to_pair(ci);
	CONF_SECTION	*cs = cf_item_to_section(cf_parent(ci));

	attribute = (type & FR_TYPE_ATTRIBUTE);
	required = (type & FR_TYPE_REQUIRED);
	secret = (type & FR_TYPE_SECRET);
	file_input = (type == FR_TYPE_FILE_INPUT);	/* check, not and */
	file_exists = (type == FR_TYPE_FILE_EXISTS);	/* check, not and */
	cant_be_empty = (type & FR_TYPE_NOT_EMPTY);
	tmpl = (type & FR_TYPE_TMPL);

	fr_assert(cp);
	fr_assert(!(type & FR_TYPE_ATTRIBUTE) || tmpl);	 /* Attribute flag only valid for templates */
	fr_assert((type & FR_TYPE_ON_READ) == 0);

	if (required) cant_be_empty = true;		/* May want to review this in the future... */

	type = FR_BASE_TYPE(type);			/* normal types are small */

	/*
	 *	Everything except templates must have a base type.
	 */
	if (!type && !tmpl) {
		cf_log_err(cp, "Configuration pair \"%s\" must have a data type", cf_pair_attr(cp));
		return -1;
	}

	/*
	 *	Catch crazy errors.
	 */
	if (!cp->value) {
		cf_log_err(cp, "Configuration pair \"%s\" must have a value", cf_pair_attr(cp));
		return -1;
	}

	/*
	 *	Check for zero length strings
	 */
	if ((cp->value[0] == '\0') && cant_be_empty) {
		cf_log_err(cp, "Configuration pair \"%s\" must not be empty (zero length)", cf_pair_attr(cp));
		if (!required) cf_log_err(cp, "Comment item to silence this message");
		rcode = -1;

	error:
		return rcode;
	}

	if (tmpl) {
		vp_tmpl_t *vpt;

		if (!cp->printed) cf_log_debug(cs, "%.*s%s = %s", PAIR_SPACE(cs), parse_spaces, cf_pair_attr(cp), cp->value);

		/*
		 *	This is so we produce TMPL_TYPE_ATTR_UNDEFINED template that
		 *	the bootstrap functions can use to create an attribute.
		 *
		 *	For other types of template such as xlats, we don't bother.
		 *	There's no reason bootstrap functions need access to the raw
		 *	xlat strings.
		 */
		if (attribute) {
			slen = tmpl_afrom_attr_str(cp, NULL, &vpt, cp->value,
						   &(vp_tmpl_rules_t){
							.allow_unknown = true,
							.allow_undefined = true
						   });
			if (slen < 0) {
				char *spaces, *text;

				fr_canonicalize_error(ctx, &spaces, &text, slen, cp->value);

				cf_log_err(cp, "Failed parsing attribute reference:");
				cf_log_err(cp, "%s", text);
				cf_log_err(cp, "%s^ %s", spaces, fr_strerror());

				talloc_free(spaces);
				talloc_free(text);
				goto error;
			}
			*(vp_tmpl_t **)out = vpt;
		}
		goto finish;
	}

	switch (type) {
	case FR_TYPE_BOOL:
		/*
		 *	Allow yes/no, true/false, and on/off
		 */
		if ((strcasecmp(cp->value, "yes") == 0) ||
		    (strcasecmp(cp->value, "true") == 0) ||
		    (strcasecmp(cp->value, "on") == 0)) {
			*(bool *)out = true;
		} else if ((strcasecmp(cp->value, "no") == 0) ||
			   (strcasecmp(cp->value, "false") == 0) ||
			   (strcasecmp(cp->value, "off") == 0)) {
			*(bool *)out = false;
		} else {
			cf_log_err(cs, "Invalid value \"%s\" for boolean variable %s",
				   cp->value, cf_pair_attr(cp));
			rcode = -1;
			goto error;
		}
		if (!cp->printed) cf_log_debug(cs, "%.*s%s = %s", PAIR_SPACE(cs), parse_spaces, cf_pair_attr(cp), cp->value);
		break;

	case FR_TYPE_UINT32:
	{
		unsigned long v = strtoul(cp->value, 0, 0);

		/*
		 *	Restrict integer values to 0-INT32_MAX, this means
		 *	it will always be safe to cast them to a signed type
		 *	for comparisons, and imposes the same range limit as
		 *	before we switched to using an unsigned type to
		 *	represent config item integers.
		 */
		if (v > INT32_MAX) {
			cf_log_err(cs, "Invalid value \"%s\" for variable %s, must be between 0-%u", cp->value,
				   cf_pair_attr(cp), INT32_MAX);
			rcode = -1;
			goto error;
		}

		*(uint32_t *)out = v;
		if (!cp->printed) cf_log_debug(cs, "%.*s%s = %u", PAIR_SPACE(cs), parse_spaces, cf_pair_attr(cp), *(uint32_t *)out);
	}
		break;

	case FR_TYPE_UINT8:
	{
		unsigned long v = strtoul(cp->value, 0, 0);

		if (v > UINT8_MAX) {
			cf_log_err(cs, "Invalid value \"%s\" for variable %s, must be between 0-%u", cp->value,
				   cf_pair_attr(cp), UINT8_MAX);
			rcode = -1;
			goto error;
		}
		*(uint8_t *)out = (uint8_t) v;
		if (!cp->printed) cf_log_debug(cs, "%.*s%s = %u", PAIR_SPACE(cs), parse_spaces, cf_pair_attr(cp), *(uint8_t *)out);
	}
		break;

	case FR_TYPE_UINT16:
	{
		unsigned long v = strtoul(cp->value, 0, 0);

		if (v > UINT16_MAX) {
			cf_log_err(cs, "Invalid value \"%s\" for variable %s, must be between 0-%u", cp->value,
				   cf_pair_attr(cp), UINT16_MAX);
			rcode = -1;
			goto error;
		}
		*(uint16_t *)out = (uint16_t) v;
		if (!cp->printed) cf_log_debug(cs, "%.*s%s = %u", PAIR_SPACE(cs), parse_spaces, cf_pair_attr(cp), *(uint16_t *)out);
	}
		break;

	case FR_TYPE_UINT64:
		*(uint64_t *)out = strtoull(cp->value, NULL, 0);
		if (!cp->printed) cf_log_debug(cs, "%.*s%s = %" PRIu64, PAIR_SPACE(cs), parse_spaces, cf_pair_attr(cp), *(uint64_t *)out);
		break;

	case FR_TYPE_SIZE:
	{
		if (fr_size_from_str((size_t *)out, cp->value) < 0) {
			cf_log_perr(cs, "Invalid value \"%s\" for variable %s", cp->value, cf_pair_attr(cp));
			rcode = -1;
			goto error;
		}
		if (!cp->printed) cf_log_debug(cs, "%.*s%s = %zu", PAIR_SPACE(cs), parse_spaces, cf_pair_attr(cp), *(size_t *)out);
		break;
	}

	case FR_TYPE_INT32:
		*(int32_t *)out = strtol(cp->value, NULL, 10);
		if (!cp->printed) cf_log_debug(cs, "%.*s%s = %d", PAIR_SPACE(cs), parse_spaces, cf_pair_attr(cp), *(int32_t *)out);
		break;

	case FR_TYPE_STRING:
	{
		char **str = out;

		/*
		 *	Hide secrets when using "radiusd -X".
		 */
		if (secret && (fr_debug_lvl < L_DBG_LVL_3)) {
			if (!cp->printed) cf_log_debug(cs, "%.*s%s = <<< secret >>>", PAIR_SPACE(cs), parse_spaces, cf_pair_attr(cp));
		} else {
			if (!cp->printed) cf_log_debug(cs, "%.*s%s = \"%pV\"", PAIR_SPACE(cs), parse_spaces, cf_pair_attr(cp),
						       fr_box_strvalue_buffer(cp->value));
		}

		/*
		 *	If there's out AND it's an input file, check
		 *	that we can read it.  This check allows errors
		 *	to be caught as early as possible, during
		 *	server startup.
		 */
		if (file_input && !cf_file_check(cs, cp->value, true)) {
			rcode = -1;
			goto error;
		}

		if (file_exists && !cf_file_check(cs, cp->value, false)) {
			rcode = -1;
			goto error;
		}

		/*
		 *	Free any existing buffers
		 */
		talloc_free(*str);
		*str = talloc_typed_strdup(cs, cp->value);
	}
		break;

	case FR_TYPE_IPV4_ADDR:
	case FR_TYPE_IPV4_PREFIX:
		ipaddr = out;

		if (fr_inet_pton4(ipaddr, cp->value, -1, true, false, true) < 0) {
			cf_log_perr(cp, "Failed parsing config item");
			rcode = -1;
			goto error;
		}
		/* Also prints the IP to the log */
		if (fr_item_validate_ipaddr(cs, cf_pair_attr(cp), type, cp->value, ipaddr) < 0) {
			rcode = -1;
			goto error;
		}
		break;

	case FR_TYPE_IPV6_ADDR:
	case FR_TYPE_IPV6_PREFIX:
		ipaddr = out;

		if (fr_inet_pton6(ipaddr, cp->value, -1, true, false, true) < 0) {
			cf_log_perr(cp, "Failed parsing config item");
			rcode = -1;
			goto error;
		}
		/* Also prints the IP to the log */
		if (fr_item_validate_ipaddr(cs, cf_pair_attr(cp), type, cp->value, ipaddr) < 0) {
			rcode = -1;
			goto error;
		}
		break;

	case FR_TYPE_COMBO_IP_ADDR:
	case FR_TYPE_COMBO_IP_PREFIX:
		ipaddr = out;

		if (fr_inet_pton(ipaddr, cp->value, -1, AF_UNSPEC, true, true) < 0) {
			cf_log_perr(cp, "Failed parsing config item");
			rcode = -1;
			goto error;
		}
		/* Also prints the IP to the log */
		if (fr_item_validate_ipaddr(cs, cf_pair_attr(cp), type, cp->value, ipaddr) < 0) {
			rcode = -1;
			goto error;
		}
		break;

	case FR_TYPE_TIME_DELTA:
	{
		fr_time_delta_t delta;

		if (fr_time_delta_from_str(&delta, cp->value, FR_TIME_RES_SEC) < 0) {
			cf_log_perr(cp, "Failed parsing config item");
			rcode = -1;
			goto error;
		}

		if (!cp->printed) {
			char *p;
			p = fr_value_box_asprint(NULL, fr_box_time_delta(delta), 0);
			cf_log_debug(cs, "%.*s%s = %s", PAIR_SPACE(cs), parse_spaces, cf_pair_attr(cp), p);
			talloc_free(p);
		}

		memcpy(out, &delta, sizeof(delta));
	}
		break;

	case FR_TYPE_FLOAT32:
	{
		float num;

		if (sscanf(cp->value, "%f", &num) != 1) {
			cf_log_err(cp, "Failed parsing floating point number");
			rcode = -1;
			goto error;
		}
		if (!cp->printed) cf_log_debug(cs, "%.*s%s = %f", PAIR_SPACE(cs), parse_spaces, cf_pair_attr(cp),
					       (double) num);
		memcpy(out, &num, sizeof(num));
	}
		break;

	case FR_TYPE_FLOAT64:
	{
		double num;

		if (sscanf(cp->value, "%lf", &num) != 1) {
			cf_log_err(cp, "Failed parsing floating point number");
			rcode = -1;
			goto error;
		}
		if (!cp->printed) cf_log_debug(cs, "%.*s%s = %f", PAIR_SPACE(cs), parse_spaces, cf_pair_attr(cp), num);
		memcpy(out, &num, sizeof(num));
	}
		break;

	default:
		/*
		 *	If we get here, it's a sanity check error.
		 *	It's not an error parsing the configuration
		 *	file.
		 */
		fr_assert(type > FR_TYPE_INVALID);
		fr_assert(type < FR_TYPE_MAX);

		cf_log_err(cp, "type '%s' (%i) is not supported in the configuration files",
			   fr_table_str_by_value(fr_value_box_type_table, type, "?Unknown?"), type);
		rcode = -1;
		goto error;
	}

finish:
	cp->parsed = true;
	cp->printed = true;

	return rcode;
}

/** Allocate a pair using the dflt value and quotation
 *
 * The pair created by this function should fed to #cf_pair_parse for parsing.
 *
 * @param[out] out Where to write the CONF_PAIR we created with the default value.
 * @param[in] cs to parent the CONF_PAIR from.
 * @param[in] name of the CONF_PAIR to create.
 * @param[in] type of conf item being parsed (determines default quoting).
 * @param[in] dflt value to assign the CONF_PAIR.
 * @param[in] dflt_quote surrounding the CONF_PAIR.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int cf_pair_default(CONF_PAIR **out, CONF_SECTION *cs, char const *name,
			   int type, char const *dflt, FR_TOKEN dflt_quote)
{
	int		lineno = 0;
	char const	*expanded;
	CONF_PAIR	*cp;
	char		buffer[8192];

	fr_assert(dflt);

	type = FR_BASE_TYPE(type);

	/*
	 *	Defaults may need their values expanding
	 */
	expanded = cf_expand_variables("<internal>", lineno, cs, buffer, sizeof(buffer), dflt, -1, NULL);
	if (!expanded) {
		cf_log_err(cs, "Failed expanding variable %s", name);
		return -1;
	}

	/*
	 *	If no default quote was set, determine it from the type
	 */
	if (dflt_quote == T_INVALID) {
		switch (type) {
		case FR_TYPE_STRING:
			dflt_quote = T_DOUBLE_QUOTED_STRING;
			break;

		case FR_TYPE_FILE_INPUT:
		case FR_TYPE_FILE_OUTPUT:
			dflt_quote = T_DOUBLE_QUOTED_STRING;
			break;

		default:
			dflt_quote = T_BARE_WORD;
			break;
		}
	}

	cp = cf_pair_alloc(cs, name, expanded, T_OP_EQ, T_BARE_WORD, dflt_quote);
	if (!cp) return -1;

	cp->parsed = true;

	/*
	 *	Set the rcode to indicate we used a default value
	 */
	*out = cp;

	return 1;
}

/** Parses a #CONF_PAIR into a C data type, with a default value.
 *
 * @param[in] ctx	To allocate arrays and values in.
 * @param[out] out	Where to write the result.
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
							CONF_SECTION *cs, CONF_PARSER const *rule)
{
	bool		multi, required, deprecated;
	size_t		count = 0;
	CONF_PAIR	*cp, *dflt_cp = NULL;

	unsigned int	type = rule->type;
	char const	*dflt = rule->dflt;
	FR_TOKEN	dflt_quote = rule->quote;

	fr_assert(!(type & FR_TYPE_TMPL) || !dflt || (dflt_quote != T_INVALID)); /* We ALWAYS need a quoting type for templates */

	multi = (type & FR_TYPE_MULTI);
	required = (type & FR_TYPE_REQUIRED);
	deprecated = (type & FR_TYPE_DEPRECATED);

	/*
	 *	If the item is multi-valued we allocate an array
	 *	to hold the multiple values.
	 */
	if (multi) {
		CONF_PAIR	*first;
		void		**array;
		size_t		i;

		/*
		 *	Don't re-parse things which have already been parsed.
		 */
		first = cf_pair_find(cs, rule->name);
		if (first && first->parsed) return 0;

		/*
		 *	Easier than re-allocing
		 */
		for (cp = first;
		     cp;
		     cp = cf_pair_find_next(cs, cp, rule->name)) count++;

		/*
		 *	Multivalued, but there's no value, create a
		 *	default pair.
		 */
		if (!count) {
			if (deprecated) return 0;
			if (!dflt) {
				if (required) {
			need_value:
					cf_log_err(cs, "Configuration item \"%s\" must have a value", rule->name);
					return -1;
				}
				return 1;
			}

			if (cf_pair_default(&dflt_cp, cs, rule->name, type, dflt, dflt_quote) < 0) return -1;
			cp = dflt_cp;
			count = 1;	/* Need one to hold the default */
		} else {
			cp = first;	/* reset */
		}

		if (deprecated) {
		deprecated:
			cf_log_err(cp, "Configuration pair \"%s\" is deprecated", cf_pair_attr(cp));
			return -2;
		}

		array = NULL;

		/*
		 *	Functions don't necessarily *need* to write
		 *	anywhere, so their data pointer can be NULL.
		 */
		if (!out) {
			if (!rule->func) {
			no_out:
				cf_log_err(cs, "Rule doesn't specify output destination");
				return -1;
			}
		}
		/*
		 *	Tmpl is outside normal range
		 */
		else if (type & FR_TYPE_TMPL) {
			array = (void **)talloc_zero_array(ctx, vp_tmpl_t *, count);
		/*
		 *	Allocate an array of values.
		 *
		 *	We don't NULL terminate.  Consumer must use
		 *	talloc_array_length().
		 */
		} else switch (FR_BASE_TYPE(type)) {
		case FR_TYPE_BOOL:
			array = (void **)talloc_zero_array(ctx, bool, count);
			break;

		case FR_TYPE_UINT32:
			array = (void **)talloc_zero_array(ctx, uint32_t, count);
			break;

		case FR_TYPE_UINT16:
			array = (void **)talloc_zero_array(ctx, uint16_t, count);
			break;

		case FR_TYPE_UINT64:
			array = (void **)talloc_zero_array(ctx, uint64_t, count);
			break;

		case FR_TYPE_INT32:
			array = (void **)talloc_zero_array(ctx, int32_t, count);
			break;

		case FR_TYPE_STRING:
			array = (void **)talloc_zero_array(ctx, char *, count);
			break;

		case FR_TYPE_IPV4_ADDR:
		case FR_TYPE_IPV4_PREFIX:
		case FR_TYPE_IPV6_ADDR:
		case FR_TYPE_IPV6_PREFIX:
		case FR_TYPE_COMBO_IP_ADDR:
		case FR_TYPE_COMBO_IP_PREFIX:
			array = (void **)talloc_zero_array(ctx, fr_ipaddr_t, count);
			break;

		case FR_TYPE_TIME_DELTA:
			array = (void **)talloc_zero_array(ctx, fr_time_delta_t, count);
			break;

		case FR_TYPE_VOID:
			fr_assert(rule->func);
			array = (void **)talloc_zero_array(ctx, void *, count);
			break;

		default:
			cf_log_err(cp, "Unsupported type %i (%i)", type, FR_BASE_TYPE(type));
			fr_assert_fail(NULL);
			return -1;	/* Unsupported type */
		}

		if (!array) return -1;

		for (i = 0; i < count; i++, cp = cf_pair_find_next(cs, cp, rule->name)) {
			int		ret;
			cf_parse_t	func;
			void		*entry;
			TALLOC_CTX	*value_ctx = array ? array : ctx;

			/*
			 *	Figure out where to write the output
			 */
			if (!array) {
				entry = NULL;
			} else if (FR_BASE_TYPE(type) == FR_TYPE_VOID) {
				entry = &array[i];
			} else {
				entry = ((uint8_t *) array) + i * fr_value_box_field_sizes[FR_BASE_TYPE(type)];
			}

			/*
			 *	Switch between custom parsing function
			 *	and the standard value parsing function.
			 */
			if (rule->func) {
				cf_log_debug(cs, "%.*s%s = %s", PAIR_SPACE(cs), parse_spaces,
					     cf_pair_attr(cp), cp->value);
				func = rule->func;
			} else {
				if (!entry) goto no_out;
				func = cf_pair_parse_value;
			}

			ret = func(value_ctx, entry, base, cf_pair_to_item(cp), rule);
			if (ret < 0) {
				talloc_free(array);
				talloc_free(dflt_cp);
				return -1;
			}
			cp->parsed = true;
		}

		if (out) *(void **)out = array;
	/*
	 *	Single valued config item gets written to
	 *	the data pointer directly.
	 */
	} else {
		CONF_PAIR	*next;
		int		ret;
		cf_parse_t	func = cf_pair_parse_value;

		cp = cf_pair_find(cs, rule->name);
		if (!cp) {
			if (deprecated) return 0;
			if (!dflt) {
				if (required) goto need_value;
				return 1;
			}

			if (cf_pair_default(&dflt_cp, cs, rule->name, type, dflt, dflt_quote) < 0) return -1;
			cp = dflt_cp;

		} else if (cp->parsed) {
			/*
			 *	Don't re-parse things which have already been parsed.
			 */
			return 0;
		}

		next = cf_pair_find_next(cs, cp, rule->name);
		if (next) {
			cf_log_err(&(next->item), "Invalid duplicate configuration item '%s'", rule->name);
			return -1;
		}

		if (deprecated) goto deprecated;

		if (rule->func) {
			cf_log_debug(cs, "%.*s%s = %s", PAIR_SPACE(cs), parse_spaces, cf_pair_attr(cp), cp->value);
			cp->printed = true;
			func = rule->func;
		}

		ret = func(ctx, out, base, cf_pair_to_item(cp), rule);
		if (ret < 0) {
			talloc_free(dflt_cp);
			return -1;
		}
		cp->parsed = true;
	}

	/*
	 *	If we created a default cp and succeeded
	 *	in parsing the dflt value, add the new
	 *	cp to the enclosing section.
	 */
	if (dflt_cp) {
		cf_item_add(cs, &(dflt_cp->item));
		return 1;
	}

	return 0;
}

/** Parses a #CONF_PAIR into a C data type, with a default value.
 *
 * Takes fields from a #CONF_PARSER struct and uses them to parse the string value
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
 * | FR_TYPE_TMPL            | ``vp_tmpl_t``      | Yes                    |
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
 *	- ``data`` #FR_TYPE_TMPL 		- @copybrief FR_TYPE_TMPL
 *					  	  Feeds the value into #tmpl_afrom_str. Value can be
 *					  	  obtained when processing requests, with #tmpl_expand or #tmpl_aexpand.
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
 *	- ``flag`` #FR_TYPE_DEPRECATED		- @copybrief FR_TYPE_DEPRECATED
 *	- ``flag`` #FR_TYPE_REQUIRED		- @copybrief FR_TYPE_REQUIRED
 *	- ``flag`` #FR_TYPE_ATTRIBUTE		- @copybrief FR_TYPE_ATTRIBUTE
 *	- ``flag`` #FR_TYPE_SECRET		- @copybrief FR_TYPE_SECRET
 *	- ``flag`` #FR_TYPE_FILE_INPUT		- @copybrief FR_TYPE_FILE_INPUT
 *	- ``flag`` #FR_TYPE_NOT_EMPTY		- @copybrief FR_TYPE_NOT_EMPTY
 *	- ``flag`` #FR_TYPE_MULTI		- @copybrief FR_TYPE_MULTI
 *	- ``flag`` #FR_TYPE_IS_SET		- @copybrief FR_TYPE_IS_SET
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
		  unsigned int type, void *data, char const *dflt, FR_TOKEN dflt_quote)
{
	CONF_PARSER rule = {
		.name = name,
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
static int cf_section_parse_init(CONF_SECTION *cs, void *base, CONF_PARSER const *rule)
{
	CONF_PAIR *cp;

	if ((FR_BASE_TYPE(rule->type) == FR_TYPE_SUBSECTION)) {
		char const	*name2 = NULL;
		CONF_SECTION	*subcs;

		subcs = cf_section_find(cs, rule->name, rule->ident2);

		/*
		 *	Set the is_set field for the subsection.
		 */
		if (rule->type & FR_TYPE_IS_SET) {
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
		if (rule->type & FR_TYPE_REQUIRED) {
		  	cf_log_err(cs, "Missing %s {} subsection", rule->name);
		  	return -1;
		}

		/*
		 *	It's OK for this to be missing.  Don't
		 *	initialize it.
		 */
		if ((rule->type & FR_TYPE_OK_MISSING) != 0) return 0;

		/*
		 *	If there's no subsection in the
		 *	config, BUT the CONF_PARSER wants one,
		 *	then create an empty one.  This is so
		 *	that we can track the strings,
		 *	etc. allocated in the subsection.
		 */
		if (DEBUG_ENABLED4) cf_log_debug(cs, "Allocating fake section \"%s\"", rule->name);

		if (rule->ident2 != CF_IDENT_ANY) name2 = rule->ident2;
		subcs = cf_section_alloc(cs, cs, rule->name, name2);
		if (!subcs) return -1;

		cf_item_add(cs, &(subcs->item));
		return 0;
	}

	/*
	 *	Don't re-initialize data which was already parsed.
	 */
	cp = cf_pair_find(cs, rule->name);
	if (cp && cp->parsed) return 0;

	if ((FR_BASE_TYPE(rule->type) != FR_TYPE_STRING) &&
	    (rule->type != FR_TYPE_FILE_INPUT) &&
	    (rule->type != FR_TYPE_FILE_OUTPUT)) {
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
	CONF_ITEM *ci;

	for (ci = cs->item.child; ci; ci = ci->next) {
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
static int cf_subsection_parse(TALLOC_CTX *ctx, void *out, void *base, CONF_SECTION *cs, CONF_PARSER const *rule)
{
	CONF_SECTION		*subcs = NULL;
	int			count = 0, i = 0, ret;

	fr_type_t		type = rule->type;
	size_t			subcs_size = rule->subcs_size;
	CONF_PARSER const	*rules = rule->subcs;

	uint8_t			**array = NULL;

	fr_assert(type & FR_TYPE_SUBSECTION);

	subcs = cf_section_find(cs, rule->name, rule->ident2);
	if (!subcs) return 0;

	/*
	 *	Handle the single subsection case (which is simple)
	 */
	if (!(type & FR_TYPE_MULTI)) {
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
	while ((subcs = cf_section_find_next(cs, subcs, rule->name, rule->ident2))) count++;

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
	while ((subcs = cf_section_find_next(cs, subcs, rule->name, rule->ident2))) {
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
	int		ret = 0;
	void		*data = NULL;
	CONF_DATA const	*rule_cd = NULL;

	if (!cs->name2) {
		cf_log_debug(cs, "%.*s%s {", SECTION_SPACE(cs), parse_spaces, cs->name1);
	} else {
		cf_log_debug(cs, "%.*s%s %s {", SECTION_SPACE(cs), parse_spaces, cs->name1, cs->name2);
	}

	while ((rule_cd = cf_data_find_next(cs, rule_cd, CONF_PARSER, CF_IDENT_ANY))) {
		CONF_PARSER *rule;
		bool *is_set = NULL;

		rule = cf_data_value(rule_cd);

		/*
		 *	Ignore ON_READ parse rules
		 */
		if ((rule->type & FR_TYPE_ON_READ) != 0) continue;

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
		if (FR_BASE_TYPE(rule->type) == FR_TYPE_SUBSECTION) {
			ret = cf_subsection_parse(ctx, data, base, cs, rule);
			if (ret < 0) goto finish;
			continue;
		} /* else it's a CONF_PAIR */

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
		if (rule->type & FR_TYPE_IS_SET) {
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
			goto finish;

		case -2:	/* Deprecated CONF ITEM */
			if (((rule + 1)->offset && ((rule + 1)->offset == rule->offset)) ||
			    ((rule + 1)->data && ((rule + 1)->data == rule->data))) {
				cf_log_err(cs, "Replace \"%s\" with \"%s\"", rule->name,
					   (rule + 1)->name);
			}
			goto finish;
		}
	}

	cs->base = base;

	/*
	 *	Warn about items in the configuration which weren't
	 *	checked during parsing.
	 */
	if (DEBUG_ENABLED4) cf_section_parse_warn(cs);

	cf_log_debug(cs, "%.*s}", SECTION_SPACE(cs), parse_spaces);

finish:
	return ret;
}

/** Fixup xlat expansions and attributes
 *
 * @param[out] base start of structure to write #vp_tmpl_t s to.
 * @param[in] cs CONF_SECTION to fixup.
 * @return
 *	- 0 on success.
 *	- -1 on failure (parse errors etc...).
 */
int cf_section_parse_pass2(void *base, CONF_SECTION *cs)
{
	CONF_DATA const *rule_cd = NULL;

	while ((rule_cd = cf_data_find_next(cs, rule_cd, CONF_PARSER, CF_IDENT_ANY))) {
		bool		attribute, multi, is_tmpl, is_xlat;
		CONF_PAIR	*cp;
		CONF_PARSER	*rule;
		void		*data;
		int		type;

		rule = cf_data_value(rule_cd);

		type = rule->type;
		is_tmpl = (type & FR_TYPE_TMPL);
		is_xlat = (type & FR_TYPE_XLAT);
		attribute = (type & FR_TYPE_ATTRIBUTE);
		multi = (type & FR_TYPE_MULTI);

		type = FR_BASE_TYPE(type);		/* normal types are small */

		/*
		 *	It's a section, recurse!
		 */
		if (type == FR_TYPE_SUBSECTION) {
			uint8_t		*subcs_base;
			CONF_SECTION	*subcs = cf_section_find(cs, rule->name, rule->ident2);

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
		 *	no default set for the CONF_PARSER.
		 */
		cp = cf_pair_find(cs, rule->name);
		if (!cp) continue;

		/*
		 *	Figure out which data we need to fix.
		 */
		data = rule->data; /* prefer this. */
		if (!data && base) data = ((char *)base) + rule->offset;
		if (!data) continue;

		/*
		 *	Non-xlat expansions shouldn't have xlat!
		 */
		if (!is_xlat && !is_tmpl) {
			/*
			 *	Ignore %{... in shared secrets.
			 *	They're never dynamically expanded.
			 */
			if ((rule->type & FR_TYPE_SECRET) != 0) continue;

			if (strstr(cp->value, "%{") != NULL) {
				cf_log_err(&cp->item, "Found dynamic expansion in string which "
					   "will not be dynamically expanded");
				return -1;
			}
			continue;
		}

		/*
		 *	Parse (and throw away) the xlat string (for validation).
		 *
		 *	FIXME: All of these should be converted from FR_TYPE_XLAT
		 *	to FR_TYPE_TMPL.
		 */
		if (is_xlat) {
			ssize_t		slen;
			xlat_exp_t	*xlat;

		redo:
			xlat = NULL;

			/*
			 *	xlat expansions should be parseable.
			 */
			slen = xlat_tokenize(cs, &xlat, cp->value, talloc_array_length(cp->value) - 1, NULL);
			if (slen < 0) {
				char *spaces, *text;

				fr_canonicalize_error(cs, &spaces, &text, slen, cp->value);

				cf_log_err(cp, "Failed parsing expansion string:");
				cf_log_err(cp, "%s", text);
				cf_log_err(cp, "%s^ %s", spaces, fr_strerror());

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
		} else if (is_tmpl) {
			ssize_t	slen;

			vp_tmpl_t **out = (vp_tmpl_t **)data;
			vp_tmpl_t *vpt;

			slen = tmpl_afrom_str(cs, &vpt, cp->value, talloc_array_length(cp->value) - 1,
					      cf_pair_value_quote(cp),
					      &(vp_tmpl_rules_t){ .allow_unknown = true, .allow_undefined = true },
					      true);
			if (slen < 0) {
				char *spaces, *text;

				fr_canonicalize_error(vpt, &spaces, &text, slen, cp->value);

				cf_log_err(cp, "%s", text);
				cf_log_err(cp, "%s^ %s", spaces, fr_strerror());

				talloc_free(spaces);
				talloc_free(text);
				return -1;
			}

			if (attribute && !tmpl_is_attr(vpt)) {
				cf_log_err(cp, "Expected attr got %s",
					   fr_table_str_by_value(tmpl_type_table, vpt->type, "???"));
				return -1;
			}

			switch (vpt->type) {
			/*
			 *	All attributes should have been defined by this point.
			 */
			case TMPL_TYPE_ATTR_UNDEFINED:
				cf_log_err(cp, "Unknown attribute '%s'", vpt->tmpl_unknown_name);
				talloc_free(vpt);	/* Free last (vpt needed for log) */
				return -1;

			case TMPL_TYPE_UNPARSED:
			case TMPL_TYPE_ATTR:
			case TMPL_TYPE_LIST:
			case TMPL_TYPE_DATA:
			case TMPL_TYPE_EXEC:
			case TMPL_TYPE_XLAT:
			case TMPL_TYPE_XLAT_STRUCT:
				break;

			case TMPL_TYPE_UNKNOWN:
			case TMPL_TYPE_REGEX:
			case TMPL_TYPE_REGEX_STRUCT:
			case TMPL_TYPE_NULL:
				fr_assert(0);
			/* Don't add default */
			}

			/*
			 *	Free the old value if we're overwriting
			 */
			TALLOC_FREE(*out);
			*(vp_tmpl_t **)out = vpt;
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
int _cf_section_rule_push(CONF_SECTION *cs, CONF_PARSER const *rule, char const *filename, int lineno)
{
	if (!cs || !rule) return 0;

	if (DEBUG_ENABLED4) {
		cf_log_debug(cs, "Pushed parse rule to %s section: %s %s",
			     cf_section_name1(cs),
			     rule->name, FR_BASE_TYPE(rule->type) & FR_TYPE_SUBSECTION ? "{}": "");
	}

	/*
	 *	Qualifying with name prevents duplicate rules being added
	 *
	 *	Fixme maybe?.. Can't have a section and pair with the same name.
	 */
	if (!_cf_data_add_static(CF_TO_ITEM(cs), rule, "CONF_PARSER", rule->name, filename, lineno)) {
		CONF_DATA const *cd;
		CONF_PARSER *old;

		cd = cf_data_find(CF_TO_ITEM(cs), CONF_PARSER, rule->name);
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
		if ((old->type & FR_TYPE_ON_READ) != 0) {
			CONF_DATA *cd1;

			/*
			 *	Over-write the rule in place.
			 *
			 *	We'd like to call cf_remove(), but
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
		if (FR_BASE_TYPE(rule->type) == FR_TYPE_SUBSECTION) {
			CONF_SECTION *subcs;

			subcs = cf_section_find(cs, rule->name, rule->ident2);
			if (!subcs) {
				cf_log_err(cs, "Failed finding '%s' subsection", rule->name);
				cf_debug(cs);
				return -1;
			}

			return cf_section_rules_push(subcs, rule->subcs);
		}

		cf_log_err(cs, "Data of type %s with name \"%s\" already exists.  Existing data added %s[%i]", "CONF_PARSER",
			   rule->name, cd->item.filename, cd->item.lineno);

		cf_debug(cs);
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
int _cf_section_rules_push(CONF_SECTION *cs, CONF_PARSER const *rules, char const *filename, int lineno)
{
	CONF_PARSER const *rule_p;

	if (!cs || !rules) return 0;

	for (rule_p = rules; rule_p->name; rule_p++) {
		if (rule_p->type & FR_TYPE_DEPRECATED) continue;	/* Skip deprecated */
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
		       CONF_ITEM *ci, CONF_PARSER const *rule)
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
			 CONF_ITEM *ci, CONF_PARSER const *rule)
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
			  CONF_ITEM *ci, CONF_PARSER const *rule)
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

