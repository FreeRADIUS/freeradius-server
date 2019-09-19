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
 * @file xlat_tokenize.c
 * @brief String expansion ("translation").  Tokenizes xlat expansion strings.
 *
 * @copyright 2000,2006 The FreeRADIUS server project
 * @copyright 2000 Alan DeKok (aland@freeradius.org)
 */

RCSID("$Id$")

#include <freeradius-devel/server/rad_assert.h>
#include <freeradius-devel/server/request.h>
#include <freeradius-devel/server/regex.h>
#include <freeradius-devel/server/xlat_priv.h>

#include <ctype.h>

#undef XLAT_DEBUG
#ifdef DEBUG_XLAT
#  define XLAT_DEBUG DEBUG3
#else
#  define XLAT_DEBUG(...)
#endif

/** Allocate an xlat node
 *
 * @param[in] ctx	to allocate node in.
 * @param[in] type	of the node.
 * @param[in] fmt	original fmt string.
 * @param[in] len	Portion of the fmt string this node represents.
 * @return A new xlat node.
 */
static inline xlat_exp_t *xlat_exp_alloc(TALLOC_CTX *ctx, xlat_type_t type, char const *fmt, size_t len)
{
	xlat_exp_t *node;

	MEM(node = talloc_zero(ctx, xlat_exp_t));
	node->type = type;
	if (fmt) node->fmt = talloc_bstrndup(node, fmt, len);

	return node;
}

/** Try to convert an xlat to a tmpl for efficiency
 *
 * @param ctx to allocate new vp_tmpl_t in.
 * @param node to convert.
 * @return
 *	- NULL if unable to convert (not necessarily error).
 *	- A new #vp_tmpl_t.
 */
vp_tmpl_t *xlat_to_tmpl_attr(TALLOC_CTX *ctx, xlat_exp_t *node)
{
	vp_tmpl_t *vpt;

	if (node->next || (node->type != XLAT_ATTRIBUTE) || !tmpl_is_attr(node->attr)) return NULL;

	/*
	 *   Concat means something completely different as an attribute reference
	 *   Count isn't implemented.
	 */
	if ((node->attr->tmpl_num == NUM_COUNT) || (node->attr->tmpl_num == NUM_ALL)) return NULL;

	vpt = tmpl_alloc(ctx, TMPL_TYPE_ATTR, node->fmt, -1, T_BARE_WORD);
	if (!vpt) return NULL;
	memcpy(&vpt->data, &node->attr->data, sizeof(vpt->data));

	TMPL_VERIFY(vpt);

	return vpt;
}

/** Convert attr tmpl to an xlat for &attr[*]
 *
 * @param ctx to allocate new xlat_expt_t in.
 * @param vpt to convert.
 * @return
 *	- NULL if unable to convert (not necessarily error).
 *	- a new #vp_tmpl_t.
 */
xlat_exp_t *xlat_from_tmpl_attr(TALLOC_CTX *ctx, vp_tmpl_t *vpt)
{
	xlat_exp_t *node;

	if (!tmpl_is_attr(vpt)) return NULL;

	node = xlat_exp_alloc(ctx, XLAT_ATTRIBUTE, vpt->name, vpt->len);
	node->attr = tmpl_alloc(node, TMPL_TYPE_ATTR, node->fmt, talloc_array_length(node->fmt) - 1, T_BARE_WORD);
	memcpy(&node->attr->data, &vpt->data, sizeof(vpt->data));

	return node;
}

static ssize_t xlat_tokenize_expansion(TALLOC_CTX *ctx, xlat_exp_t **head, char const *fmt,
				       vp_tmpl_rules_t const *rules);
static ssize_t xlat_tokenize_literal(TALLOC_CTX *ctx, xlat_exp_t **head, char const *fmt,
				     bool brace, vp_tmpl_rules_t const *rules);

static ssize_t xlat_tokenize_alternation(TALLOC_CTX *ctx, xlat_exp_t **head, char const *fmt,
					 vp_tmpl_rules_t const *rules)
{
	ssize_t		slen;
	char const	*p = fmt;
	xlat_exp_t	*node;

	rad_assert(fmt[0] == '%');
	rad_assert(fmt[1] == '{');
	rad_assert(fmt[2] == '%');
	rad_assert(fmt[3] == '{');

	XLAT_DEBUG("ALTERNATE <-- %s", fmt);

	node = xlat_exp_alloc(ctx, XLAT_ALTERNATE, NULL, 0);
	p += 2;
	slen = xlat_tokenize_expansion(node, &node->child, p, rules);
	if (slen <= 0) {
		talloc_free(node);
		return slen - (p - fmt);
	}
	p += slen;

	if (p[0] != ':') {
		talloc_free(node);
		fr_strerror_printf("Expected ':' after first expansion, got '%pV'",
				   fr_box_strvalue_len(p, 1));
		return -(p - fmt);
	}
	p++;

	if (p[0] != '-') {
		talloc_free(node);
		fr_strerror_printf("Expected '-' after ':'");
		return -(p - fmt);
	}
	p++;

	/*
	 *	Allow the RHS to be empty as a special case.
	 */
	switch (*p) {
	case '}':
		node->alternate = xlat_exp_alloc(node, XLAT_LITERAL, "", 0);
		node->async_safe = node->child->async_safe;
		*head = node;
		return (p + 1) - fmt;

	case '\0':
		fr_strerror_printf("No matching closing brace");
		talloc_free(node);
		return -2;
	}

	/*
	 *	Parse the alternate expansion.
	 */
	slen = xlat_tokenize_literal(node, &node->alternate, p, true, rules);
	if (slen <= 0) {
		talloc_free(node);
		return slen - (p - fmt);
	}

	if (!node->alternate) {
		talloc_free(node);
		fr_strerror_printf("Empty expansion is invalid");
		return -(p - fmt);
	}
	p += slen;

	node->async_safe = (node->child->async_safe && node->alternate->async_safe);
	*head = node;

	return p - fmt;
}

#ifdef HAVE_REGEX
/** Parse an xlat reference
 *
 * Allows access to a subcapture groups
 * @verbatim %{<num>} @endverbatim
 *
 */
static inline ssize_t xlat_tokenize_regex(TALLOC_CTX *ctx, xlat_exp_t **head, char const *fmt)
{
	unsigned long	num;
	char const	*p;
	char		*q;
	xlat_exp_t	*node;

	rad_assert(fmt[0] == '%');
	rad_assert(fmt[1] == '{');

	p = fmt + 2;

	num = strtoul(p, &q, 10);
	if (num > REQUEST_MAX_REGEX) {
		fr_strerror_printf("Invalid regex reference.  Must be in range 0-%u", REQUEST_MAX_REGEX);
		return -(p - fmt);		/* error */
	}

	if (*q != '}') return 0;			/* Not a regex */

	XLAT_DEBUG("REGEX <-- %pV", fr_box_strvalue_len(fmt, (q - p) + 1));

	node = xlat_exp_alloc(ctx, XLAT_REGEX, p, (q - p));	/* fmt is the integer value */
	node->regex_index = num;
	*head = node;

	q++;	/* Skip over '}' */

	return q - fmt;
}
#endif

/** Parse an xlat function and its child arguments
 *
 * Parses a function call string in the format
 * @verbatim %{<func>:<arguments} @endverbatim
 *
 */
static inline ssize_t xlat_tokenize_function(TALLOC_CTX *ctx, xlat_exp_t **head, char const *fmt,
					     vp_tmpl_rules_t const *rules)
{
	ssize_t		slen;
	char const	*p;
	char		*q;
	xlat_exp_t	*node;
	xlat_t		*func;

	rad_assert(fmt[0] == '%');
	rad_assert(fmt[1] == '{');

	p = fmt + 2;

	q = strchr(p, ':');
	if (!q) return 0;

	/*
	 *	Avoid using a temporary buffer to search
	 *	for the function.
	 */
	*q = '\0';
	func = xlat_func_find(p);
	*q = ':';

	if (!func) return 0;

	/*
	 *	Allocate a node to hold the function
	 */
	node = xlat_exp_alloc(ctx, XLAT_FUNC, p, q - p);
	node->xlat = func;

	p = q + 1;
	XLAT_DEBUG("FUNC <-- %s ... %s", node->fmt, p);

	/*
	 *	Now parse the child nodes that form the
	 *	function's arguments.
	 */
	slen = xlat_tokenize_literal(node, &node->child, p, true, rules);
	if (slen < 0) {
		talloc_free(node);
		return slen - (p - fmt);	/* error */
	}
	p += slen;
	if (*(p - 1) != '}') {	/* @fixme: xlat_tokenize_literal should not consume the closing brace */
		fr_strerror_printf("No matching closing brace");
		return -1;						/* error @ second character of format string */
	}

	node->async_safe = (func->async_safe && (!node->child || node->child->async_safe));
	*head = node;

	return p - fmt;
}

/** Parse an attribute ref or a virtual attribute
 *
 */
static inline ssize_t xlat_tokenize_attribute(TALLOC_CTX *ctx, xlat_exp_t **head, char const *fmt,
					      vp_tmpl_rules_t const *rules)
{
	ssize_t			slen;
	char const		*p, *q;
	attr_ref_error_t	err;
	vp_tmpl_t		*vpt = NULL;
	xlat_exp_t		*node;
	xlat_t			*func;

	/*
	 *	We need a local copy as we always allow unknowns.
	 *	This is because not all attribute references
	 *	reference real attributes in the dictionaries,
	 *	and instead are "virtual" attributes like
	 *	Foreach-Variable-N.
	 */
	vp_tmpl_rules_t our_rules;

	rad_assert(fmt[0] == '%');
	rad_assert(fmt[1] == '{');

	if (rules) {
		memcpy(&our_rules, rules, sizeof(our_rules));
	} else {
		memset(&our_rules, 0, sizeof(our_rules));
	}

	p = fmt + 2;

	our_rules.allow_undefined = true;		/* So we can check for virtual attributes later */
  	our_rules.prefix = VP_ATTR_REF_PREFIX_NO;	/* Must be NO to stop %{&User-Name} */
	slen = tmpl_afrom_attr_substr(NULL, &err, &vpt, p, -1, &our_rules);
	if (slen <= 0) {
		/*
		 *	If the parse error occurred before the ':'
		 *	then the error is changed to 'Unknown module',
		 *	as it was more likely to be a bad module name,
		 *	than a request qualifier.
		 */
		if (err == ATTR_REF_ERROR_INVALID_LIST_QUALIFIER) {
			fr_strerror_printf("Unknown expansion function or invalid list qualifier");
		}
		return slen - (p - fmt);		/* error somewhere after second character */
	}
	q = p + slen;

	if (*q != '}') {
		fr_strerror_printf("No matching closing brace");
		return -1;						/* error @ second character of format string */
	}

	q++;	/* Skip over the closing brace */

	/*
	 *	Might be a virtual XLAT attribute, which is identical
	 *	to a normal function but called without an argument
	 *	list.
	 */
	if (tmpl_is_attr_undefined(vpt)) {
		func = xlat_func_find(vpt->tmpl_unknown_name);
		if (func) {
			node = xlat_exp_alloc(ctx, XLAT_VIRTUAL,
					      vpt->tmpl_unknown_name, talloc_array_length(vpt->tmpl_unknown_name) - 1);
			talloc_free(vpt);	/* Free the tmpl, we don't need it */

			XLAT_DEBUG("VIRTUAL <-- %s", node->fmt);
			node->xlat = func;
			node->async_safe = func->async_safe;
			*head = node;

			return q - fmt;
		}
		talloc_free(vpt);

		fr_strerror_printf("Unknown attribute");
		return -2;						/* error @ third character of format string */
	}

	node = xlat_exp_alloc(ctx, XLAT_ATTRIBUTE, vpt->name, vpt->len);
	node->attr = talloc_steal(node, vpt);
	node->async_safe = true; /* attribute expansions are always async-safe */
	*head = node;

	return q - fmt;
}

static ssize_t xlat_tokenize_expansion(TALLOC_CTX *ctx, xlat_exp_t **head,
				       char const *fmt, vp_tmpl_rules_t const *rules)
{
	ssize_t		slen;
	char const	*p = fmt, *q;

	XLAT_DEBUG("EXPANSION <-- %s", fmt);

	rad_assert(fmt[0] == '%');
	rad_assert(fmt[1] == '{');

	/*
	 *	%{%{...}:-bar}
	 */
	if ((fmt[2] == '%') && (fmt[3] == '{')) return xlat_tokenize_alternation(ctx, head, fmt, rules);

	/*
	 *	%{:-bar}
	 */
	if ((fmt[2] == ':') && (fmt[3] == '-')) {
		fr_strerror_printf("First item in alternation cannot be empty");
		return -2;
	}

#ifdef HAVE_REGEX
	/*
	 *	Handle regex's %{<num>} specially.
	 */
	if (isdigit(fmt[2])) {
		slen = xlat_tokenize_regex(ctx, head, fmt);
		if (slen != 0) return slen;	/* If slen == 0 means this wasn't a regex */
	}
#endif /* HAVE_REGEX */

	/*
	 *	%{Attr-Name}
	 *	%{Attr-Name[#]}
	 *	%{Tunnel-Password:1}
	 *	%{Tunnel-Password:1[#]}
	 *	%{request:Attr-Name}
	 *	%{request:Tunnel-Password:1}
	 *	%{request:Tunnel-Password:1[#]}
	 *	%{mod:foo}
	 */

	/*
	 *	This is for efficiency, so we don't search for an xlat,
	 *	when what's being referenced is obviously an attribute.
	 */
	p = fmt;
	for (q = p; *q; q++) {
		if (*q == ':') break;			/* First special token is a ':' i.e. '%{func:' */

		if (isspace((int) *q)) break;		/* First special token is a ' ' - Likely a syntax error */

		if (*q == '[') break;			/* First special token is a '[' i.e. '%{attr[<idx>]}' */

		if (*q == '}') break;			/* First special token is a '}' i.e. '%{<attrref>}' */
	}

	XLAT_DEBUG("EXPANSION HINT TOKEN '%c'", *q);

	/*
	 *	Check for empty expressions %{} %{: %{[
	 */
	if (q == (p + 2)) {
		switch (*q) {
		case '}':
			fr_strerror_printf("Empty expression is invalid");
			return -2;				/* error @ third character of format string */

		case ':':
			fr_strerror_printf("Missing expansion function or list qualifier");
			return -2;

		case '[':
			fr_strerror_printf("Missing attribute name");
			return -2;

		default:
			break;
		}
	}

	/*
	 *      Hint token is a ':' it's either:
	 *	- An xlat function %{<func>:<args}
	 *	- An attribute reference with a list separator %{<list>:<attr>}
	 */
	switch (*q) {
	case ':':
		slen = xlat_tokenize_function(ctx, head, fmt, rules);
		if (slen != 0) return slen;
		/* FALL-THROUGH */

	/*
	 *	Hint token is a:
	 *	- '[' - Which is an attribute index, so it must be an attribute.
	 *      - '}' - The end of the expansion, which means it was a bareword.
	 */
	case '}':
	case '[':
		slen = xlat_tokenize_attribute(ctx, head, fmt, rules);
		if (slen < 0) return slen;
		rad_assert(slen != 0);

		p += slen;
		break;

	/*
	 *	Hint token is a '\0'
	 *
	 *      This means the end of a string not containing any of the other
	 *	tokens was reached.
	 *
	 *	e.g. '%{myfirstxlat'
	 */
	case '\0':
		fr_strerror_printf("No matching closing brace");
		return -1;					/* error @ second character of format string */

	/*
	 *	Hint token was whitespace
	 *
	 *	e.g. '%{my '
	 */
	default:
		/*
		 *	Box is so we get \t \n etc..
		 */
		fr_strerror_printf("Invalid char '%pV' in expression", fr_box_strvalue_len(q, 1));
		return -(q - fmt);
	}

	return (p - fmt);
}


static ssize_t xlat_tokenize_literal(TALLOC_CTX *ctx, xlat_exp_t **head, char const *fmt,
				     bool brace, vp_tmpl_rules_t const *rules)
{
	char const	*p;
	xlat_exp_t	*node;
	char		*start;

	if (!*fmt) return 0;

	XLAT_DEBUG("LITERAL <-- %s", fmt);

	node = talloc_zero(ctx, xlat_exp_t);
	node->fmt = start = talloc_typed_strdup(node, fmt);
	node->len = 0;
	node->type = XLAT_LITERAL;

	p = fmt;

	while (*p) {
		if (*p == '\\') {
			if (!p[1]) {
				talloc_free(node);
				fr_strerror_printf("Invalid escape at end of string");
				return -(p - fmt);
			}

			p += 2;
			node->len += 2;
			continue;
		}

		/*
		 *	Process the expansion.
		 */
		if ((p[0] == '%') && (p[1] == '{')) {
			ssize_t slen;

			XLAT_DEBUG("EXPANSION-2 <-- %s", node->fmt);

			slen = xlat_tokenize_expansion(node, &node->next, p, rules);
			if (slen <= 0) {
				talloc_free(node);
				return slen - (p - fmt);
			}
			p += slen;

			rad_assert(node->next != NULL);

			/*
			 *	Short-circuit the recursive call.
			 *	This saves another function call and
			 *	memory allocation.
			 */
			if (!*p) break;

			/*
			 *	"foo %{User-Name} bar"
			 *	LITERAL		"foo "
			 *	EXPANSION	User-Name
			 *	LITERAL		" bar"
			 */
			slen = xlat_tokenize_literal(node->next, &(node->next->next), p, brace, rules);
			rad_assert(slen != 0);
			if (slen < 0) {
				talloc_free(node);
				return slen - (p - fmt);
			}

			brace = false; /* it was found above, or else the above code errored out */
			p += slen;
			break;	/* stop processing the string */
		}

		/*
		 *	Check for valid single-character expansions.
		 */
		if (p[0] == '%') {
			ssize_t		slen;
			xlat_exp_t	*next;

			if (!p[1] || !strchr("%}cdlmnsetCDGHIMSTYv", p[1])) {
				talloc_free(node);
				fr_strerror_printf("Invalid variable expansion");
				p++;
				return -(p - fmt);
			}

			next = talloc_zero(node, xlat_exp_t);
			next->len = 1;

			switch (p[1]) {
			case '%':
			case '}':
				next->fmt = talloc_bstrndup(next, p + 1, 1);

				XLAT_DEBUG("LITERAL-ESCAPED <-- %s", next->fmt);
				next->type = XLAT_LITERAL;
				break;

			default:
				next->fmt = p + 1;

				XLAT_DEBUG("PERCENT <-- %c", *next->fmt);
				next->type = XLAT_ONE_LETTER;
				break;
			}

			node->next = next;
			p += 2;

			if (!*p) break;

			/*
			 *	And recurse.
			 */
			slen = xlat_tokenize_literal(node->next, &(node->next->next), p, brace, rules);
			rad_assert(slen != 0);
			if (slen < 0) {
				talloc_free(node);
				return slen - (p - fmt);
			}

			brace = false; /* it was found above, or else the above code errored out */
			p += slen;
			break;	/* stop processing the string */
		}

		/*
		 *	If required, eat the brace.
		 */
		if (brace && (*p == '}')) {
			brace = false;
			p++;
			break;
		}

		p++;
		node->len++;
	}

	/*
	 *	We were told to look for a brace, but we ran off of
	 *	the end of the string before we found one.
	 */
	if (brace) {
		fr_strerror_printf("Missing closing brace at end of string");
		return -(p - fmt);
	}

	/*
	 *	Squash zero-width literals
	 */
	if (node->len <= 0) {
		(void) talloc_steal(ctx, node->next);
		*head = node->next;
		talloc_free(node);
		return p - fmt;
	}

	node->async_safe = true; /* literals are always true */
	*head = node;

	/*
	 *	Shrink the buffer to the right size
	 */
	MEM(start = talloc_bstr_realloc(ctx, start, node->len));
	node->fmt = start;

	return p - fmt;
}

static void xlat_tokenize_debug(REQUEST *request, xlat_exp_t const *node)
{
	rad_assert(node != NULL);

	RINDENT();
	while (node) {
		switch (node->type) {
		case XLAT_LITERAL:
			RDEBUG3("literal --> %s", node->fmt);
			break;

		case XLAT_ONE_LETTER:
			RDEBUG3("percent --> %c", node->fmt[0]);
			break;

		case XLAT_ATTRIBUTE:
			rad_assert(node->attr->tmpl_da != NULL);
			RDEBUG3("attribute --> %s", node->attr->tmpl_da->name);
			rad_assert(node->child == NULL);
			if ((node->attr->tmpl_tag != TAG_ANY) || (node->attr->tmpl_num != NUM_ANY)) {
				RDEBUG3("{");

				RINDENT();
				RDEBUG3("ref  %d", node->attr->tmpl_request);
				RDEBUG3("list %d", node->attr->tmpl_list);

				if (node->attr->tmpl_tag != TAG_ANY) {
					RDEBUG3("tag %d", node->attr->tmpl_tag);
				}
				if (node->attr->tmpl_num != NUM_ANY) {
					if (node->attr->tmpl_num == NUM_COUNT) {
						RDEBUG3("[#]");
					} else if (node->attr->tmpl_num == NUM_ALL) {
						RDEBUG3("[*]");
					} else {
						RDEBUG3("[%d]", node->attr->tmpl_num);
					}
				}
				REXDENT();
				RDEBUG3("}");
			}
			break;

		case XLAT_VIRTUAL:
			rad_assert(node->fmt != NULL);
			RDEBUG3("virtual --> %s", node->fmt);
			break;

		case XLAT_FUNC:
			rad_assert(node->xlat != NULL);
			RDEBUG3("xlat --> %s", node->xlat->name);
			if (node->child) {
				RDEBUG3("{");
				xlat_tokenize_debug(request, node->child);
				RDEBUG3("}");
			}
			break;

#ifdef HAVE_REGEX
		case XLAT_REGEX:
			RDEBUG3("regex-var --> %d", node->regex_index);
			break;
#endif

		case XLAT_ALTERNATE:
			DEBUG("XLAT-IF {");
			xlat_tokenize_debug(request, node->child);
			DEBUG("}");
			DEBUG("XLAT-ELSE {");
			xlat_tokenize_debug(request, node->alternate);
			DEBUG("}");
			break;
		}
		node = node->next;
	}
	REXDENT();
}

size_t xlat_snprint(char *out, size_t outlen, xlat_exp_t const *node)
{
	char *p, *end;

	if (!node || (outlen <= 2)) {
		*out = '\0';
		return 0;
	}

	p = out;
	end = out + outlen;

#define CHECK_SPACE(_p, _end) if (_p >= _end) goto oob

	while (node) {
		if (node->type == XLAT_LITERAL) {
			p += strlcpy(p, node->fmt, end - p);
			CHECK_SPACE(p, end);
			goto next;
		}

		if (node->type == XLAT_ONE_LETTER) {
			*(p++) = '%';
			if (p >= end) {
			oob:
				out[outlen - 1] = '\0';
				return outlen + 1;
			}

			*(p++) = node->fmt[0];
			CHECK_SPACE(p, end);
			goto next;
		}

		*(p++) = '%';
		CHECK_SPACE(p, end);
		*(p++) = '{';
		CHECK_SPACE(p, end);

		switch (node->type) {
		case XLAT_ATTRIBUTE:
		{
			size_t need;

			p += tmpl_snprint_attr_str(&need, p, end - p, node->attr);
			if (need > 0) goto oob;
		}
			break;
#ifdef HAVE_REGEX
		case XLAT_REGEX:
			p += snprintf(p, end - p, "%i", node->regex_index);
			CHECK_SPACE(p, end);
			break;
#endif
		case XLAT_VIRTUAL:
			p += strlcpy(p, node->fmt, end - p);
			CHECK_SPACE(p, end);
			break;

		case XLAT_FUNC:
			p += strlcpy(p, node->xlat->name, end - p);
			CHECK_SPACE(p, end);

			*(p++) = ':';
			CHECK_SPACE(p, end);

			if (node->child) {
				p += xlat_snprint(p, end - p, node->child);
				CHECK_SPACE(p, end);
			}
			break;

		case XLAT_ALTERNATE:
			p += xlat_snprint(p, end - p, node->child);
			CHECK_SPACE(p, end);

			*(p++) = ':';
			CHECK_SPACE(p, end);
			*(p++) = '-';
			CHECK_SPACE(p, end);

			p += xlat_snprint(p, end - p, node->alternate);
			CHECK_SPACE(p, end);
			break;

		default:
			if (!fr_cond_assert(0)) break;
		}

		*(p++) = '}';
		CHECK_SPACE(p, end);

	next:
		node = node->next;
	}

	*p = '\0';

	return p - out;
}

/** Tokenize an xlat expansion at runtime
 *
 * This is used for runtime parsing of xlat expansions, such as those we receive from datastores
 * like LDAP or SQL.
 *
 * @param[in] ctx	to allocate dynamic buffers in.
 * @param[out] head	the head of the xlat list / tree structure.
 * @param[in] request	the input request.  Memory will be attached here.
 * @param[in] fmt	the format string to expand.
 * @param[in] rules	controlling how attribute references are parsed.
 * @return
 *	- <= -1 on error.  Return value is negative offset of where parsing
 *	  error occured.
 *	- >= 0 on success.  The number of bytes parsed.
 */
ssize_t xlat_tokenize_ephemeral(TALLOC_CTX *ctx, xlat_exp_t **head, REQUEST *request,
			        char const *fmt, vp_tmpl_rules_t const *rules)
{
	ssize_t		slen;
	char		*tokens;

	*head = NULL;

	/*
	 *	Copy the original format string to a buffer so that
	 *	the later functions can mangle it in-place, which is
	 *	much faster.
	 */
	tokens = talloc_typed_strdup(ctx, fmt);
	if (!tokens) return -1;

	fr_strerror();	/* Clear error buffer */
	slen = xlat_tokenize_literal(request, head, tokens, false, rules);

	/*
	 *	Zero length expansion, return a zero length node.
	 */
	if (slen == 0) {
		MEM(*head = talloc_zero(ctx, xlat_exp_t));
		(*head)->async_safe = true;
	}

	/*
	 *	Output something like:
	 *
	 *	"format string"
	 *	"       ^ error was here"
	 */
	if (slen < 0) {
		talloc_free(tokens);
		return slen;
	}

	if (*head && RDEBUG_ENABLED3) {
		RDEBUG3("%s", fmt);
		RDEBUG3("Parsed xlat tree:");
		xlat_tokenize_debug(request, *head);
	}

	/*
	 *	All of the nodes point to offsets in the "tokens"
	 *	string.  Let's ensure that free'ing head will free
	 *	"tokens", too.
	 */
	(void) talloc_steal(*head, tokens);

	/*
	 *	Create ephemeral instance data for the xlat
	 */
	if (xlat_instantiate_ephemeral(*head) < 0) {
		talloc_free(*head);

		fr_strerror_printf("Failed performing ephemeral instantiation for xlat");
		return -1;
	}

	return slen;
}

/** Tokenize an xlat expansion
 *
 * @param[in] ctx	to allocate dynamic buffers in.
 * @param[out] head	the head of the xlat list / tree structure.
 * @param[in] fmt	the format string to expand.
 * @param[in] rules	controlling how attribute references are parsed.
 * @return
 *	- <0 on error.
 *	- 0 on success.
 */
ssize_t xlat_tokenize(TALLOC_CTX *ctx, xlat_exp_t **head, char *fmt, vp_tmpl_rules_t const *rules)
{
	int ret;

	*head = NULL;

	fr_strerror();	/* Clear error buffer */
	ret = xlat_tokenize_literal(ctx, head, fmt, false, rules);
	if (ret < 0) return ret;

	/*
	 *	Add nodes that need to be bootstrapped to
	 *	the registry.
	 */
	if (xlat_bootstrap(*head) < 0) {
		TALLOC_FREE(*head);
		return -1;
	}

	return ret;
}

