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
 * @copyright 2000,2006  The FreeRADIUS server project
 * @copyright 2000  Alan DeKok <aland@ox.org>
 */

RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/rad_assert.h>

#include <ctype.h>
#include "xlat_priv.h"

#undef XLAT_DEBUG
#ifdef DEBUG_XLAT
#  define XLAT_DEBUG DEBUG3
#else
#  define XLAT_DEBUG(...)
#endif

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

	if (node->next || (node->type != XLAT_ATTRIBUTE) || (node->attr->type != TMPL_TYPE_ATTR)) return NULL;

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

	if (vpt->type != TMPL_TYPE_ATTR) return NULL;

	node = talloc_zero(ctx, xlat_exp_t);
	node->type = XLAT_ATTRIBUTE;
	node->fmt = talloc_bstrndup(node, vpt->name, vpt->len);
	node->attr = tmpl_alloc(node, TMPL_TYPE_ATTR, node->fmt, talloc_array_length(node->fmt) - 1, T_BARE_WORD);
	memcpy(&node->attr->data, &vpt->data, sizeof(vpt->data));

	return node;
}

static ssize_t xlat_tokenize_expansion(TALLOC_CTX *ctx, char *fmt, xlat_exp_t **head,
				       char const **error);
static ssize_t xlat_tokenize_literal(TALLOC_CTX *ctx, char *fmt, xlat_exp_t **head,
				     bool brace, char const **error);

static ssize_t xlat_tokenize_alternation(TALLOC_CTX *ctx, char *fmt, xlat_exp_t **head,
					 char const **error)
{
	ssize_t slen;
	char *p;
	xlat_exp_t *node;

	rad_assert(fmt[0] == '%');
	rad_assert(fmt[1] == '{');
	rad_assert(fmt[2] == '%');
	rad_assert(fmt[3] == '{');

	XLAT_DEBUG("ALTERNATE <-- %s", fmt);

	node = talloc_zero(ctx, xlat_exp_t);
	node->type = XLAT_ALTERNATE;

	p = fmt + 2;
	slen = xlat_tokenize_expansion(node, p, &node->child, error);
	if (slen <= 0) {
		talloc_free(node);
		return slen - (p - fmt);
	}
	p += slen;

	if (p[0] != ':') {
		talloc_free(node);
		*error = "Expected ':' after first expansion";
		return -(p - fmt);
	}
	p++;

	if (p[0] != '-') {
		talloc_free(node);
		*error = "Expected '-' after ':'";
		return -(p - fmt);
	}
	p++;

	/*
	 *	Allow the RHS to be empty as a special case.
	 */
	if (*p == '}') {
		/*
		 *	Hack up an empty string.
		 */
		node->alternate = talloc_zero(node, xlat_exp_t);
		node->alternate->type = XLAT_LITERAL;
		node->alternate->fmt = talloc_typed_strdup(node->alternate, "");
		*(p++) = '\0';

	} else {
		slen = xlat_tokenize_literal(node, p, &node->alternate, true, error);
		if (slen <= 0) {
			talloc_free(node);
			return slen - (p - fmt);
		}

		if (!node->alternate) {
			talloc_free(node);
			*error = "Empty expansion is invalid";
			return -(p - fmt);
		}
		p += slen;
	}

	node->async_safe = (node->child->async_safe && node->alternate->async_safe);

	*head = node;
	return p - fmt;
}

static ssize_t xlat_tokenize_expansion(TALLOC_CTX *ctx, char *fmt, xlat_exp_t **head, char const **error)
{
	ssize_t slen;
	char *p, *q;
	char *start;
	xlat_exp_t *node;
#ifdef HAVE_REGEX
	long num;
#endif

	rad_assert(fmt[0] == '%');
	rad_assert(fmt[1] == '{');

	/*
	 *	%{%{...}:-bar}
	 */
	if ((fmt[2] == '%') && (fmt[3] == '{')) return xlat_tokenize_alternation(ctx, fmt, head, error);

	XLAT_DEBUG("EXPANSION <-- %s", fmt);
	node = talloc_zero(ctx, xlat_exp_t);
	node->fmt = start = talloc_typed_strdup(node, fmt + 2);
	node->len = 0;

#ifdef HAVE_REGEX
	/*
	 *	Handle regex's specially.
	 */
	p = start;
	num = strtol(p, &q, 10);
	if (p != q && (*q == '}')) {
		XLAT_DEBUG("REGEX <-- %s", fmt);
		*q = '\0';

		if ((num > REQUEST_MAX_REGEX) || (num < 0)) {
			talloc_free(node);
			*error = "Invalid regex reference.  Must be in range 0-" STRINGIFY(REQUEST_MAX_REGEX);
			return -2;					/* error */
		}
		node->regex_index = num;

		node->type = XLAT_REGEX;
		*head = node;

		node->len = (q - start);
		MEM(start = talloc_realloc_bstr(start, node->len));
		q++;	/* Skip closing brace */

		return 2 + (q - start);
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
	p = start;
	for (q = p; *q != '\0'; q++) {
		if (*q == ':') break;

		if (isspace((int) *q)) break;

		if (*q == '[') continue;

		if (*q == '}') break;
	}

	/*
	 *	Check for empty expressions %{}
	 */
	if ((*q == '}') && (q == p)) {
		talloc_free(node);
		*error = "Empty expression is invalid";
		return (-(p - start)) - 2;				/* error */
	}

	/*
	 *	Might be a module name reference.
	 *
	 *	If it's not, it's an attribute or parse error.
	 */
	if (*q == ':') {
		*q = '\0';
		node->xlat = xlat_func_find(node->fmt);
		if (node->xlat) {
			/*
			 *	%{mod:foo}
			 */
			node->type = XLAT_FUNC;

			p = q + 1;
			XLAT_DEBUG("MOD <-- %s ... %s", node->fmt, p);

			slen = xlat_tokenize_literal(node, p, &node->child, true, error);
			if (slen < 0) {
				talloc_free(node);
				return (slen - (p - start)) - 2;	/* error */
			}
			p += slen;

			node->async_safe = (node->xlat->async_safe && node->child->async_safe);
			*head = node;
			rad_assert(node->next == NULL);

			node->len = p - start;
			MEM(start = talloc_realloc_bstr(start, node->len));

			return 2 + node->len;
		}
		*q = ':';	/* Avoids a talloc_strdup */
	}

	/*
	 *	The first token ends with:
	 *	- '[' - Which is an attribute index, so it must be an attribute.
	 *      - '}' - The end of the expansion, which means it was a bareword.
	 */
	slen = tmpl_afrom_attr_substr(node, &node->attr, p,
				      &(vp_tmpl_rules_t){ .allow_undefined = true, .allow_unknown = true });
	if (slen <= 0) {
		/*
		 *	If the parse error occurred before the ':'
		 *	then the error is changed to 'Unknown module',
		 *	as it was more likely to be a bad module name,
		 *	than a request qualifier.
		 */
		if ((*q == ':') && ((p + (slen * -1)) < q)) {
			*error = "Unknown module";
		} else {
			*error = fr_strerror();
		}

		talloc_free(node);
		return (slen - (p - start)) - 2;			/* error */
	}

	/*
	 *	Might be a virtual XLAT attribute
	 */
	if (node->attr->type == TMPL_TYPE_ATTR_UNDEFINED) {
		node->xlat = xlat_func_find(node->attr->tmpl_unknown_name);
		if (node->xlat && node->xlat->mod_inst && !node->xlat->internal) {
			talloc_free(node);
			*error = "Missing content in expansion";
			return (-(p - start) - slen) - 2;		/* error */
		}

		if (node->xlat) {
			node->type = XLAT_VIRTUAL;
			node->fmt = node->attr->tmpl_unknown_name;

			XLAT_DEBUG("VIRTUAL <-- %s", node->fmt);
			node->async_safe = node->xlat->async_safe;
			*head = node;
			rad_assert(node->next == NULL);
			q++;

			node->len = (q - start);
			MEM(start = talloc_realloc_bstr(start, node->len));

			return 2 + node->len;
		}

		talloc_free(node);
		*error = "Unknown attribute";
		return (-(p - start)) - 2;				/* error */
	}

	node->type = XLAT_ATTRIBUTE;
	p += slen;

	if (*p != '}') {
		talloc_free(node);
		*error = "No matching closing brace";
		return -1;						/* error @ second character of format string */
	}

	node->len = (p - start);
	node->async_safe = true; /* attribute expansions are always async-safe */
	*head = node;
	rad_assert(node->next == NULL);

	/*
	 *	Shrink the buffer to the right size
	 */
	MEM(start = talloc_realloc_bstr(start, node->len));
	p++;

	return 2 + (p - start);
}


static ssize_t xlat_tokenize_literal(TALLOC_CTX *ctx, char *fmt, xlat_exp_t **head,
				     bool brace, char const **error)
{
	char *p;
	xlat_exp_t *node;
	char *start;

	*error = "";		/* quiet gcc */

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
				*error = "Invalid escape at end of string";
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

			slen = xlat_tokenize_expansion(node, p, &node->next, error);
			if (slen <= 0) {
				talloc_free(node);
				return slen - (p - fmt);
			}
			*p = '\0'; /* end the literal */
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
			slen = xlat_tokenize_literal(node->next, p, &(node->next->next), brace, error);
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
				*error = "Invalid variable expansion";
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
			*p = '\0';
			p += 2;

			if (!*p) break;

			/*
			 *	And recurse.
			 */
			slen = xlat_tokenize_literal(node->next, p, &(node->next->next), brace, error);
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
			*p = '\0';
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
		*error = "Missing closing brace at end of string";
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
	MEM(start = talloc_realloc_bstr(start, node->len));
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

size_t xlat_snprint(char *buffer, size_t bufsize, xlat_exp_t const *node)
{
	size_t len;
	char *p, *end;

	if (!node) {
		*buffer = '\0';
		return 0;
	}

	p = buffer;
	end = buffer + bufsize;

	while (node) {
		switch (node->type) {
		case XLAT_LITERAL:
			strlcpy(p, node->fmt, end - p);
			p += strlen(p);
			break;

		case XLAT_ONE_LETTER:
			p[0] = '%';
			p[1] = node->fmt[0];
			p += 2;
			break;

		case XLAT_ATTRIBUTE:
			*(p++) = '%';
			*(p++) = '{';

			/*
			 *	@todo - just call tmpl_snprint() ??
			 */
			if (node->attr->tmpl_request != REQUEST_CURRENT) {
				strlcpy(p, fr_int2str(request_refs, node->attr->tmpl_request, "??"), end - p);
				p += strlen(p);
				*(p++) = '.';
			}

			if ((node->attr->tmpl_request != REQUEST_CURRENT) ||
			    (node->attr->tmpl_list != PAIR_LIST_REQUEST)) {
				strlcpy(p, fr_int2str(pair_lists, node->attr->tmpl_list, "??"), end - p);
				p += strlen(p);
				*(p++) = ':';
			}

			strlcpy(p, node->attr->tmpl_da->name, end - p);
			p += strlen(p);

			if (TAG_VALID(node->attr->tmpl_tag)) {
				snprintf(p, end - p, ":%d", node->attr->tmpl_tag);
				p += strlen(p);
			}

			if (node->attr->tmpl_num != NUM_ANY) {
				*(p++) = '[';
				switch (node->attr->tmpl_num) {
				case NUM_COUNT:
					*(p++) = '#';
					break;

				case NUM_ALL:
					*(p++) = '*';
					break;

				default:
					snprintf(p, end - p, "%i", node->attr->tmpl_num);
					p += strlen(p);
				}
				*(p++) = ']';
			}
			*(p++) = '}';
			break;
#ifdef HAVE_REGEX
		case XLAT_REGEX:
			snprintf(p, end - p, "%%{%i}", node->regex_index);
			p += strlen(p);
			break;
#endif
		case XLAT_VIRTUAL:
			*(p++) = '%';
			*(p++) = '{';
			strlcpy(p, node->fmt, end - p);
			p += strlen(p);
			*(p++) = '}';
			break;

		case XLAT_FUNC:
			*(p++) = '%';
			*(p++) = '{';
			strlcpy(p, node->xlat->name, end - p);
			p += strlen(p);
			*(p++) = ':';
			rad_assert(node->child != NULL);
			len = xlat_snprint(p, end - p, node->child);
			p += len;
			*(p++) = '}';
			break;

		case XLAT_ALTERNATE:
			*(p++) = '%';
			*(p++) = '{';

			len = xlat_snprint(p, end - p, node->child);
			p += len;

			*(p++) = ':';
			*(p++) = '-';

			len = xlat_snprint(p, end - p, node->alternate);
			p += len;

			*(p++) = '}';
			break;
		}


		if (p == end) break;

		node = node->next;
	}

	*p = '\0';

	return p - buffer;
}

/** Tokenize an xlat expansion at runtime
 *
 * This is used for runtime parsing of xlat expansions, such as those we receive from datastores
 * like LDAP or SQL.
 *
 * @param[in] ctx	to allocate dynamic buffers in.
 * @param[in] request	the input request.  Memory will be attached here.
 * @param[in] fmt	the format string to expand.
 * @param[out] head	the head of the xlat list / tree structure.
 * @return
 *	- <= -1 on error.  Return value is negative offset of where parsing
 *	  error occured.
 *	- >= 0 on success.  The number of bytes parsed.
 */
ssize_t xlat_tokenize_ephemeral(TALLOC_CTX *ctx, REQUEST *request, char const *fmt, xlat_exp_t **head)
{
	ssize_t		slen;
	char		*tokens;
	char const	*error = NULL;

	*head = NULL;

	/*
	 *	Copy the original format string to a buffer so that
	 *	the later functions can mangle it in-place, which is
	 *	much faster.
	 */
	tokens = talloc_typed_strdup(ctx, fmt);
	if (!tokens) return -1;

	slen = xlat_tokenize_literal(request, tokens, head, false, &error);

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
		rad_assert(error != NULL);

		REMARKER(fmt, -slen, error);
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

		REDEBUG("Failed performing ephemeral instantiation for xlat");
		return -1;
	}

	return slen;
}

/** Tokenize an xlat expansion
 *
 * @param[in] ctx	to allocate dynamic buffers in.
 * @param[in] fmt	the format string to expand.
 * @param[out] head	the head of the xlat list / tree structure.
 * @param[out] error	where to write a point to error messages.
 * @return
 *	- <0 on error.
 *	- 0 on success.
 */
ssize_t xlat_tokenize(TALLOC_CTX *ctx, char *fmt, xlat_exp_t **head, char const **error)
{
	int ret;

	ret = xlat_tokenize_literal(ctx, fmt, head, false, error);
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

