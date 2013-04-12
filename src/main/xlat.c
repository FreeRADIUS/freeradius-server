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

/*
 * $Id$
 *
 * @file xlat.c
 * @brief String expansion ("translation"). Implements %Attribute -> value
 *
 * @copyright 2000,2006  The FreeRADIUS server project
 * @copyright 2000  Alan DeKok <aland@ox.org>
 */

RCSID("$Id$")

#include	<freeradius-devel/radiusd.h>
#include	<freeradius-devel/parser.h>
#include	<freeradius-devel/rad_assert.h>
#include	<freeradius-devel/base64.h>

#include	<ctype.h>
#include	<limits.h>

typedef struct xlat_t {
	char			name[MAX_STRING_LEN];	//!< Name of the xlat expansion.
	int			length;			//!< Length of name.
	void			*instance;		//!< Module instance passed to xlat and escape functions.
	RAD_XLAT_FUNC		func;			//!< xlat function.
	RADIUS_ESCAPE_STRING	escape;			//!< Escape function to apply to dynamic input to func.
	int			internal;		//!< If true, cannot be redefined.
} xlat_t;

typedef enum {
	XLAT_LITERAL,		//!< Literal string
	XLAT_PERCENT,		//!< Literal string with %v
	XLAT_MODULE,		//!< xlat module
	XLAT_ATTRIBUTE,		//!< xlat attribute
#ifdef HAVE_REGEX_H
	XLAT_REGEX,		//!< regex reference
#endif
	XLAT_ALTERNATE		//!< xlat conditional syntax :-
} xlat_state_t;

struct xlat_exp {
	const char *fmt;	//!< The format string.
	size_t len;		//!< Length of the format string.

	const DICT_ATTR *da;	//!< the name of the dictionary attribute	
	int num;		//!< attribute number
	int tag;		//!< attribute tag
	pair_lists_t list;	//!< list of which attribute
	request_refs_t ref;	//!< outer / this / ...

	xlat_state_t type;	//!< type of this expansion
	xlat_exp_t *next;	//!< Next in the list.
	
	xlat_exp_t *child;	//!< Nested expansion.
	xlat_exp_t *alternate;	//!< Alternative expansion if this one expanded to a zero length string.		
	
	const xlat_t *xlat;	//!< The xlat expansion to expand format with.
};

typedef struct xlat_out {
	const char *out;	//!< Output data.
	size_t len;		//!< Length of the output string.
} xlat_out_t;

static rbtree_t *xlat_root = NULL;

#ifdef WITH_UNLANG
static const char * const xlat_foreach_names[] = {"Foreach-Variable-0",
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

#if REQUEST_MAX_REGEX > 8
#error Please fix the following line
#endif
static int xlat_inst[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8 };	/* up to 8 for regex */

/** Convert the value on a VALUE_PAIR to string
 *
 */
static int valuepair2str(char * out,int outlen,VALUE_PAIR * pair, int type)
{
	if (pair != NULL) {
		vp_prints_value(out, outlen, pair, -1);
		return strlen(out);
	}

	switch (type) {
	case PW_TYPE_STRING :
		strlcpy(out,"_",outlen);
		break;
	case PW_TYPE_INTEGER64:
	case PW_TYPE_SIGNED:
	case PW_TYPE_INTEGER:
		strlcpy(out,"0",outlen);
		break;
	case PW_TYPE_IPADDR :
		strlcpy(out,"?.?.?.?",outlen);
		break;
	case PW_TYPE_IPV6ADDR :
		strlcpy(out,":?:",outlen);
		break;
	case PW_TYPE_DATE :
		strlcpy(out,"0",outlen);
		break;
	default :
		strlcpy(out,"unknown_type",outlen);
	}
	return strlen(out);
}

/** Print data as integer, not as VALUE.
 *
 */
static size_t xlat_integer(UNUSED void *instance, REQUEST *request,
			   const char *fmt, char *out, size_t outlen)
{
	VALUE_PAIR 	*vp;

	uint64_t 	integer;
	
	while (isspace((int) *fmt)) fmt++;

	if ((radius_get_vp(request, fmt, &vp) < 0) || !vp) {
		*out = '\0';
		return 0;
	}

	switch (vp->da->type)
	{		
		case PW_TYPE_OCTETS:
		case PW_TYPE_STRING:
			if (vp->length > 8) {
				break;
			}

			memcpy(&integer, &(vp->vp_octets), vp->length);
			
			return snprintf(out, outlen, "%llu", ntohll(integer));	
			
		case PW_TYPE_INTEGER64:
			return snprintf(out, outlen, "%llu", vp->vp_integer64);
			
		case PW_TYPE_IPADDR:
		case PW_TYPE_INTEGER:
		case PW_TYPE_SHORT:
		case PW_TYPE_BYTE:
		case PW_TYPE_DATE:
			return snprintf(out, outlen, "%u", vp->vp_integer);
		default:
			break;
	}
	
	*out = '\0';
	return 0;
}

/** Print data as hex, not as VALUE.
 *
 */
static size_t xlat_hex(UNUSED void *instance, REQUEST *request,
		       const char *fmt, char *out, size_t outlen)
{
	size_t i;
	VALUE_PAIR *vp;
	uint8_t	buffer[MAX_STRING_LEN];
	ssize_t	ret;
	size_t	len;

	while (isspace((int) *fmt)) fmt++;

	if ((radius_get_vp(request, fmt, &vp) < 0) || !vp) {
		*out = '\0';
		return 0;
	}
	
	ret = rad_vp2data(vp, buffer, sizeof(buffer));
	len = (size_t) ret;
	
	/*
	 *	Don't truncate the data.
	 */
	if ((ret < 0 ) || (outlen < (len * 2))) {
		*out = 0;
		return 0;
	}

	for (i = 0; i < len; i++) {
		snprintf(out + 2*i, 3, "%02x", buffer[i]);
	}

	return len * 2;
}

/** Print data as base64, not as VALUE
 *
 */
static size_t xlat_base64(UNUSED void *instance, REQUEST *request,
			  const char *fmt, char *out, size_t outlen)
{
	VALUE_PAIR *vp;
	uint8_t buffer[MAX_STRING_LEN];
	ssize_t	ret;
	
	while (isspace((int) *fmt)) fmt++;

	if ((radius_get_vp(request, fmt, &vp) < 0) || !vp) {
		*out = '\0';
		return 0;
	}
	
	ret = rad_vp2data(vp, buffer, sizeof(buffer));
	if (ret < 0) {
		*out = 0;
		return 0;
	}

	return fr_base64_encode(buffer, (size_t) ret, out, outlen);
}

/** Prints the current module processing the request
 *
 */
static size_t xlat_module(UNUSED void *instance, REQUEST *request,
			  UNUSED const char *fmt, char *out, size_t outlen)
{
	strlcpy(out, request->module, outlen);

	return strlen(out);
}

#ifdef WITH_UNLANG
/** Implements the Foreach-Variable-X
 *
 * @see modcall()
 */
static size_t xlat_foreach(void *instance, REQUEST *request,
			   UNUSED const char *fmt, char *out, size_t outlen)
{
	VALUE_PAIR	**pvp;

	/*
	 *	See modcall, "FOREACH" for how this works.
	 */
	pvp = (VALUE_PAIR **) request_data_reference(request, radius_get_vp,
						     *(int*) instance);
	if (!pvp || !*pvp) {
		*out = '\0';
		return 0;
	}

	return valuepair2str(out, outlen, (*pvp), (*pvp)->da->type);
}
#endif

/** Print data as string, if possible.
 *
 * If attribute "Foo" is defined as "octets" it will normally
 * be printed as 0x0a0a0a. The xlat "%{string:Foo}" will instead
 * expand to "\n\n\n"
 */
static size_t xlat_string(UNUSED void *instance, REQUEST *request,
			  const char *fmt, char *out, size_t outlen)
{
	int len;
	VALUE_PAIR *vp;

	while (isspace((int) *fmt)) fmt++;

	if (outlen < 3) {
	nothing:
		*out = '\0';
		return 0;
	}

	if ((radius_get_vp(request, fmt, &vp) < 0) || !vp) goto nothing;

	if (vp->da->type != PW_TYPE_OCTETS) goto nothing;

	len = fr_print_string(vp->vp_strvalue, vp->length, out, outlen);
	out[len] = '\0';

	return len;
}

/** xlat expand string attribute value
 *
 */
static size_t xlat_xlat(UNUSED void *instance, REQUEST *request,
			const char *fmt, char *out, size_t outlen)
{
	VALUE_PAIR *vp;

	while (isspace((int) *fmt)) fmt++;

	if (outlen < 3) {
	nothing:
		*out = '\0';
		return 0;
	}

	if ((radius_get_vp(request, fmt, &vp) < 0) || !vp) goto nothing;

	return radius_xlat(out, outlen, request, vp->vp_strvalue, NULL, NULL);
}

/** Dynamically change the debugging level for the current request
 *
 * Example %{debug:3}
 */
static size_t xlat_debug(UNUSED void *instance, REQUEST *request,
			 const char *fmt, char *out, size_t outlen)
{
	int level = 0;
	
	/*
	 *  Expand to previous (or current) level
	 */
	snprintf(out, outlen, "%d", request->options & RAD_REQUEST_OPTION_DEBUG4);

	/*
	 *  Assume we just want to get the current value and NOT set it to 0
	 */
	if (!*fmt)
		goto done;
		
	level = atoi(fmt);
	if (level == 0) {
		request->options = RAD_REQUEST_OPTION_NONE;
		request->radlog = NULL;
	} else {
		if (level > 4) level = 4;

		request->options = level;
		request->radlog = radlog_request;
	}
	
	done:
	return strlen(out);
}

/*
 *	Compare two xlat_t structs, based ONLY on the module name.
 */
static int xlat_cmp(const void *one, const void *two)
{
	const xlat_t *a = one;
	const xlat_t *b = two;

	if (a->length != b->length) {
		return a->length - b->length;
	}

	return memcmp(a->name, b->name, a->length);
}


/*
 *	find the appropriate registered xlat function.
 */
static xlat_t *xlat_find(const char *name)
{
	xlat_t my_xlat;

	strlcpy(my_xlat.name, name, sizeof(my_xlat.name));
	my_xlat.length = strlen(my_xlat.name);

	return rbtree_finddata(xlat_root, &my_xlat);
}


/** Register an xlat function.
 *
 * @param[in] name xlat name.
 * @param[in] func xlat function to be called.
 * @param[in] escape function to sanitize any sub expansions passed to the xlat function.
 * @param[in] instance of module that's registering the xlat function.
 * @return 0 on success, -1 on failure
 */
int xlat_register(const char *name, RAD_XLAT_FUNC func, RADIUS_ESCAPE_STRING escape, void *instance)
{
	xlat_t	*c;
	xlat_t	my_xlat;

	if (!name || !*name) {
		DEBUG("xlat_register: Invalid xlat name");
		return -1;
	}

	/*
	 *	First time around, build up the tree...
	 *
	 *	FIXME: This code should be hoisted out of this function,
	 *	and into a global "initialization".  But it isn't critical...
	 */
	if (!xlat_root) {
		int i;

		xlat_root = rbtree_create(xlat_cmp, free, 0);
		if (!xlat_root) {
			DEBUG("xlat_register: Failed to create tree.");
			return -1;
		}

#ifdef WITH_UNLANG
		for (i = 0; xlat_foreach_names[i] != NULL; i++) {
			xlat_register(xlat_foreach_names[i],
				      xlat_foreach, NULL, &xlat_inst[i]);
			c = xlat_find(xlat_foreach_names[i]);
			rad_assert(c != NULL);
			c->internal = TRUE;
		}
#endif

#define XLAT_REGISTER(_x) xlat_register(Stringify(_x), xlat_ ## _x, NULL, NULL); \
		c = xlat_find(Stringify(_x)); \
		rad_assert(c != NULL); \
		c->internal = TRUE

		XLAT_REGISTER(integer);
		XLAT_REGISTER(hex);
		XLAT_REGISTER(base64);
		XLAT_REGISTER(string);
		XLAT_REGISTER(xlat);
		XLAT_REGISTER(module);

		xlat_register("debug", xlat_debug, NULL, &xlat_inst[0]);
		c = xlat_find("debug");
		rad_assert(c != NULL);
		c->internal = TRUE;
	}

	/*
	 *	If it already exists, replace the instance.
	 */
	strlcpy(my_xlat.name, name, sizeof(my_xlat.name));
	my_xlat.length = strlen(my_xlat.name);
	c = rbtree_finddata(xlat_root, &my_xlat);
	if (c) {
		if (c->internal) {
			DEBUG("xlat_register: Cannot re-define internal xlat");
			return -1;
		}

		c->func = func;
		c->escape = escape;
		c->instance = instance;
		return 0;
	}

	/*
	 *	Doesn't exist.  Create it.
	 */
	c = rad_malloc(sizeof(*c));
	memset(c, 0, sizeof(*c));

	c->func = func;
	c->escape = escape;
	strlcpy(c->name, name, sizeof(c->name));
	c->length = strlen(c->name);
	c->instance = instance;

	rbtree_insert(xlat_root, c);

	return 0;
}

/** Unregister an xlat function
 *
 * We can only have one function to call per name, so the passing of "func"
 * here is extraneous.
 *
 * @param[in] name xlat to unregister.
 * @param[in] func
 * @param[in] instance
 */
void xlat_unregister(const char *name, UNUSED RAD_XLAT_FUNC func, void *instance)
{
	xlat_t	*c;
	xlat_t		my_xlat;

	if (!name) return;

	strlcpy(my_xlat.name, name, sizeof(my_xlat.name));
	my_xlat.length = strlen(my_xlat.name);

	c = rbtree_finddata(xlat_root, &my_xlat);
	if (!c) return;

	if (c->instance != instance) return;

	rbtree_deletebydata(xlat_root, c);
}

/** De-register all xlat functions, used mainly for debugging.
 *
 */
void xlat_free(void)
{
	rbtree_free(xlat_root);
}

#if 0
#define XLAT_DEBUG(fmt, ...) printf(fmt, ## __VA_ARGS__);printf("\n")
#endif

#ifndef XLAT_DEBUG
#if 0
#define XLAT_DEBUG DEBUG3
#else
#define XLAT_DEBUG(...)
#endif
#endif

static ssize_t xlat_tokenize_expansion(TALLOC_CTX *ctx, char *fmt, xlat_exp_t **head,
				       const char **error);
static ssize_t xlat_tokenize_literal(TALLOC_CTX *ctx, char *fmt, xlat_exp_t **head,
				     int brace, const char **error);
static size_t xlat_process(char **out, REQUEST *request, const xlat_exp_t * const head,
			   RADIUS_ESCAPE_STRING escape, void *escape_ctx);

static ssize_t xlat_tokenize_alternation(TALLOC_CTX *ctx, char *fmt, xlat_exp_t **head,
					 const char **error)
{
	ssize_t slen;
	char *p;
	xlat_exp_t *node;

	rad_assert(fmt[0] == '%');
	rad_assert(fmt[1] == '{');
	rad_assert(fmt[2] == '%');
	rad_assert(fmt[3] == '{');

	XLAT_DEBUG("ALTERNATE: %s", fmt);

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

	slen = xlat_tokenize_literal(node, p,  &node->alternate, TRUE, error);
	if (slen <= 0) {
		talloc_free(node);
		return slen - (p - fmt);
	}
	p += slen;

	*head = node;
	return p - fmt;
}

static ssize_t xlat_tokenize_expansion(TALLOC_CTX *ctx, char *fmt, xlat_exp_t **head,
				       const char **error)
{
	ssize_t slen;
	char *p, *q, *brace;
	const char *attrname;
	xlat_exp_t *node;

	rad_assert(fmt[0] == '%');
	rad_assert(fmt[1] == '{');

	/*
	 *	%{%{...}:-bar}
	 */
	if ((fmt[2] == '%') && (fmt[3] == '{')) {
		return xlat_tokenize_alternation(ctx, fmt, head, error);
	}

	XLAT_DEBUG("EXPANSION: %s", fmt);
	node = talloc_zero(ctx, xlat_exp_t);
	attrname = node->fmt = fmt + 2;
	node->len = 0;

#ifdef HAVE_REGEX_H
	/*
	 *	Handle regex's specially.
	 */
	if (isdigit((int) fmt[2])) {
		if ((fmt[2] == '9') || (fmt[3] != '}')) {
			talloc_free(node);
			*error = "Invalid regex reference";
			return -2;
		}

		XLAT_DEBUG("REGEX: %s", fmt);
		fmt[3] = '\0';
		node->num = fmt[2] - '0'; /* ASCII */

		node->type = XLAT_REGEX;
		*head = node;
		return 4;
	}
#endif /* HAVE_REGEX_H */

	p = strchr(node->fmt, ':');
	if (p) {
		*p = '\0';

		/*
		 *	%{mod: ... }
		 */
		node->xlat = xlat_find(node->fmt);
		if (node->xlat) {
			node->type = XLAT_MODULE;

			XLAT_DEBUG("MOD: %s --> %s", node->fmt, p);
			slen = xlat_tokenize_literal(node, p + 1, &node->child, TRUE, error);
			if (slen <= 0) {
				talloc_free(node);
				return slen - (p - fmt);
			}
			p += slen + 1;

			*head = node;
			rad_assert(node->next == NULL);
			return p - fmt;
		}

		*p = ':';

		brace = strchr(attrname, '}');
		if (!brace) goto no_brace;
		*brace = '\0';

		if (p < brace) {
			XLAT_DEBUG("Looking for list in '%s'", attrname);

			/*
			 *	Not a module.  Has to be an attribute
			 *	reference.
			 *
			 *	As of v3, we've removed %{request: ..>} as
			 *	internally registered xlats.
			 */
			node->ref = radius_request_name(&attrname, REQUEST_CURRENT);
			rad_assert(node->ref != REQUEST_UNKNOWN);
			
			node->list = radius_list_name(&attrname, PAIR_LIST_REQUEST);
			if (node->list == PAIR_LIST_UNKNOWN) {
				talloc_free(node);
				*error = "Unknown module";
				return -2;
			}

			*p = '\0'; /* again */
			p = NULL;  /* and the first stuff is a list, not a tag */

		} else { /* the : is after the brace: the LHS MUST be an attribute */
			XLAT_DEBUG("Is bare attr name %s", attrname);
			p = NULL; /* ignore the ':' */
		}
	} else {
		node->ref = REQUEST_CURRENT;
		node->list = PAIR_LIST_REQUEST;
		brace = strchr(attrname, '}');
		XLAT_DEBUG("is attribute %s", attrname);
	}


	if (!brace) {
	no_brace:
		talloc_free(node);
		*error = "No matching closing brace";
		return -1;	/* second character of format string */
	}
	*brace = '\0';

	XLAT_DEBUG("Looking for attribute name in %s", attrname);

	/*
	 *	Allow for an array reference.
	 */
	q = strchr(attrname, '[');
	if (q) *q = '\0';

	/*
	 *	It's either an attribute name, or a Tunnel-Password:TAG
	 *	with the ':' already set to NULL.
	 */
	node->da = dict_attrbyname(attrname);
	if (!node->da) {
		talloc_free(node);
		*error = "Unknown attribute";
		return -(attrname - fmt);
	}
	
	/*
	 *	Parse the tag.
	 */
	if (p) {
		unsigned long tag;
		char *end;

		if (!node->da->flags.has_tag) {
			talloc_free(node);
			*error = "Attribute cannot have a tag";
			return - (p - fmt);
		}

		tag = strtoul(p + 1, &end, 10);
		p++;
		
		if (tag == ULONG_MAX) {
			talloc_free(node);
			*error = "Invalid tag value";
			return - (p - fmt);
		}

		node->tag = tag;
		p = end;

	} else {
		node->tag = TAG_ANY;
		if (q) {
			*q = '['; /* again */
			p = q;
		} else {
			p = brace;
		}
	}

	/*
	 *	Check for array reference
	 */
	if (*p == '[') {
		unsigned long num;
		char *end;

		p++;
		if (*p== '#') {
			num = 65536;
			p++;

		} else if (*p == '*') {
			num = 65537;
			p++;

		} else if (isdigit((int) *p)) {
			num = strtoul(p, &end, 10);
			if ((num == ULONG_MAX) || (num > 65535)) {
				talloc_free(node);
				*error = "Invalid number";
				return - (p - fmt);
			}
			p = end;
			DEBUG("END %s", p);

		} else {
			talloc_free(node);
			*error = "Invalid array reference";
			return - (p - fmt);
		}

		if (*p != ']') {
			talloc_free(node);
			*error = "Expected ']'";
			return - (p - fmt);
		}
		p++;
	}

	/*
	 *	Anything unexpected (or left over) is a parse error.
	 */
	if (*p) {
		talloc_free(node);
		*error = "Unexpected text";
		return - (p - fmt);
	}

	node->type = XLAT_ATTRIBUTE;
	p++;

	*head = node;
	rad_assert(node->next == NULL);
	return p - fmt;
}


static ssize_t xlat_tokenize_literal(TALLOC_CTX *ctx, char *fmt, xlat_exp_t **head,
				     int brace, const char **error)
{
	char *p, *q;
	xlat_exp_t *node;

	if (!*fmt) return 0;

	XLAT_DEBUG("LITERAL: %s", fmt);

	node = talloc_zero(ctx, xlat_exp_t);
	node->fmt = fmt;
	node->len = 0;
	node->type = XLAT_LITERAL;

	p = fmt;
	q = fmt;

	while (*p) {
		/*
		 *	Convert \n to it's literal representation.
		 */
		if (p[0] == '\\') switch (p[1]) {
			case 't':
				*(q++) = '\t';
				p += 2;
				node->len++;
				continue;

			case 'n':
				*(q++) = '\n';
				p += 2;
				node->len++;
				continue;

			case 'x':
				p += 2;
				if (!p[0] || !p[1]) {
					talloc_free(node);
					*error = "Hex expansion requires two hex digits";
					return -(p - fmt);
				}

				if (!fr_hex2bin(p, (uint8_t *) q, 2)) {
					talloc_free(node);
					*error = "Invalid hex characters";
					return -(p - fmt);
				}

				/*
				 *	Don't let people shoot themselves in the foot.
				 *	\x00 is forbidden.
				 */
				if (!*q) {
					talloc_free(node);
					*error = "Cannot add zero byte to printable string";
					return -(p - fmt);
				}

				p += 2;
				q++;
				node->len++;
				continue;

			default:
				*(q++) = *p;
				p += 2;
				node->len++;
				continue;	
			}

		/*
		 *	Process the expansion.
		 */
		if ((p[0] == '%') && (p[1] == '{')) {
			ssize_t slen;

			XLAT_DEBUG("LITERAL: %s --> %s", node->fmt, p);
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
			if (slen <= 0) {
				talloc_free(node);
				return slen - (p - fmt);
			}

			p += slen;
			break;	/* stop processing the string */
		}

		/*
		 *	Check for valid single-character expansions.
		 */
		if (p[0] == '%') {
			char *c = p;

			while (c) {
				if (!c[1] || !strchr("%dlmtDGHISTY", c[1])) {
					talloc_free(node);
					*error = "Invalid variable expansion";
					c++;
					return - (c - fmt);
				}

				c = strchr(c + 2, '%');
			}

			node->type = XLAT_PERCENT;
		}

		/*
		 *	If required, eat the brace.
		 */
		if (brace && (*p == '}')) {
			*q = '\0';
			p++;
			break;
		}

		*(q++) = *(p++);
		node->len++;
	}

	/*
	 *	Squash zero-width literals
	 */
	if (node->len > 0) {
		*head = node;

	} else {		
		(void) talloc_steal(ctx, node->next);
		*head = node->next;
		talloc_free(node);
	}

	return p - fmt;
}


static const char xlat_tabs[] = "																																																																																																																																";

static void xlat_tokenize_debug(const xlat_exp_t *node, int lvl)
{
	rad_assert(node != NULL);

	if (lvl >= (int) sizeof(xlat_tabs)) lvl = sizeof(xlat_tabs);

	while (node) {
		switch (node->type) {
		case XLAT_LITERAL:
			DEBUG("%.*sliteral: '%s'", lvl, xlat_tabs, node->fmt);
			break;

		case XLAT_PERCENT:
			DEBUG("%.*sliteral (with %%): '%s'", lvl, xlat_tabs, node->fmt);
			break;

		case XLAT_ATTRIBUTE:
			rad_assert(node->da != NULL);
			DEBUG("%.*sattribute: %s", lvl, xlat_tabs, node->da->name);
			rad_assert(node->child == NULL);
			if ((node->tag != 0) || (node->num != 0)) {
				DEBUG("%.*s{", lvl, xlat_tabs);

				DEBUG("%.*sref  %d", lvl + 1, xlat_tabs, node->ref);
				DEBUG("%.*slist %d", lvl + 1, xlat_tabs, node->list);

				if (node->tag) DEBUG("%.*stag %d", lvl + 1, xlat_tabs, node->tag);
				if (node->num) {
					if (node->num == 65536) {
						DEBUG("%.*s[#]", lvl + 1, xlat_tabs);
					} else if (node->num == 65537) {
						DEBUG("%.*s[*]", lvl + 1, xlat_tabs);
					} else {
						DEBUG("%.*s[%d]", lvl + 1, xlat_tabs, node->num);
					}
				}

				DEBUG("%.*s}", lvl, xlat_tabs);
			}
			break;

		case XLAT_MODULE:
			rad_assert(node->xlat != NULL);
			DEBUG("%.*sxlat: %s", lvl, xlat_tabs, node->xlat->name);
			if (node->child) {
				DEBUG("%.*s{", lvl, xlat_tabs);
				xlat_tokenize_debug(node->child, lvl + 1);
				DEBUG("%.*s}", lvl, xlat_tabs);
			}
			break;

#ifdef HAVE_REGEX_H
		case XLAT_REGEX:
			DEBUG("%.*sregex-var: %d", lvl, xlat_tabs, node->num);
			break;
#endif

		case XLAT_ALTERNATE:
			DEBUG("%.*sif {", lvl, xlat_tabs);
			xlat_tokenize_debug(node->child, lvl + 1);
			DEBUG("%.*s}", lvl, xlat_tabs);
			DEBUG("%.*selse {", lvl, xlat_tabs);
			xlat_tokenize_debug(node->alternate, lvl + 1);
			DEBUG("%.*s}", lvl, xlat_tabs);
			break;
		}
		node = node->next;
	}
}

static const char xlat_spaces[] = "                                                                                                                                                                                                                                                                ";


ssize_t xlat_tokenize(TALLOC_CTX *ctx, char *fmt, xlat_exp_t **head,
		      const char **error)
{
	return xlat_tokenize_literal(ctx, fmt, head, FALSE, error);
}


/** Tokenize an xlat expansion
 *
 * @param[in] request the input request.  Memory will be attached here.
 * @param[in] fmt the format string to expand
 * @param[out] head the head of the xlat list / tree structure.
 */
static ssize_t xlat_tokenize_request(REQUEST *request, const char *fmt, xlat_exp_t **head)
{
	ssize_t slen;
	char *tokens;
	const char *error;

	*head = NULL;

	/* 
	 *	Copy the original format string to a buffer so that
	 *	the later functions can mangle it in-place, which is
	 *	much faster.
	 */
	tokens = talloc_strdup(request, fmt);
	if (!tokens) return -1;

	slen = xlat_tokenize_literal(request, tokens, head, FALSE, &error);

	/*
	 *	Output something like:
	 *
	 *	"format string"
	 *	"       ^ error was here"
	 */
	if (slen <= 0) {
		size_t indent = -slen;
		talloc_free(tokens);

		rad_assert(error != NULL);
		if (indent < sizeof(xlat_spaces)) {
			RDEBUGE("%s", fmt);
			RDEBUGE("%.*s^ %s", (int) -slen, xlat_spaces, error);
		}
		return slen;
	}

	if (*head && (debug_flag > 2)) {
		DEBUG("%s", fmt);
		DEBUG("Parsed xlat tree:");
		xlat_tokenize_debug(*head, 0);
	}

	/*
	 *	All of the nodes point to offsets in the "tokens"
	 *	string.  Let's ensure that free'ing head will free
	 *	"tokens", too.
	 */
	(void) talloc_steal(*head, tokens);

	return slen;
}


static char *xlat_getvp(TALLOC_CTX *ctx, REQUEST *request, pair_lists_t list, const DICT_ATTR *da, int8_t tag)
{
	VALUE_PAIR *vp, *vps = NULL;
	RADIUS_PACKET *packet = NULL;
	DICT_VALUE *dv;
	VALUE_PAIR myvp;

	/*
	 *	Arg.  Too much abstraction is annoying.
	 */
	switch (list) {
	default:
		return vp_aprinttype(ctx, da->type);

	case PAIR_LIST_CONTROL:
		vps = request->config_items;
		break;

	case PAIR_LIST_REQUEST:
		packet = request->packet;
		if (packet) vps = packet->vps;
		break;

	case PAIR_LIST_REPLY:
		packet = request->reply;
		if (packet) vps = packet->vps;
		break;

#if WITH_PROXY
	case PAIR_LIST_PROXY_REQUEST:
		packet = request->proxy;
		if (packet) vps = packet->vps;
		break;

	case PAIR_LIST_PROXY_REPLY:
		packet = request->proxy_reply;
		if (packet) vps = packet->vps;
		break;
#endif

#ifdef WITH_COA
	case PAIR_LIST_COA:
	case PAIR_LIST_DM:
		if (request->coa) packet = request->coa->packet;
		if (packet) vps = packet->vps;
		break;

	case PAIR_LIST_COA_REPLY:
	case PAIR_LIST_DM_REPLY:
		if (request->coa) packet = request->coa->reply;
		if (packet) vps = packet->vps;
		break;

#endif
	}

	/*
	 *	Now that we have the list, etc. handled,
	 *	find the VP and print it.
	 */
	if ((da->vendor != 0) || (da->attr < 256) || (list == PAIR_LIST_CONTROL)) {
	print_vp:
		vp = pairfind(vps, da->attr, da->vendor, tag);
		if (!vp) return vp_aprinttype(ctx, da->type);

		return vp_aprint(ctx, vp);
	}

	/*
	 *	Some non-packet expansions
	 */
	switch (da->attr) {
	default:
		break;		/* ignore them */

	case PW_CLIENT_SHORTNAME:
		if (request->client && request->client->shortname) {
			return talloc_strdup(ctx, request->client->shortname);
		}
		return talloc_strdup(ctx, "<UNKNOWN-CLIENT>");

	case PW_REQUEST_PROCESSING_STAGE:
		if (request->component) {
			return talloc_strdup(ctx, request->component);
		}
		return talloc_strdup(ctx, "server_core");

	case PW_VIRTUAL_SERVER:
		if (!request->server) return NULL;
		return talloc_strdup(ctx, request->server);

	case PW_MODULE_RETURN_CODE:
		return talloc_asprintf(ctx, "%d", request->simul_max); /* hack */
	}

	/*
	 *	All of the attributes must now refer to a packet.  If
	 *	there's no packet, we can't print any attribute
	 *	referencing it.
	 */
	if (!packet) return vp_aprinttype(ctx, da->type);

	memset(&myvp, 0, sizeof(myvp));
	myvp.da = da;
	vp = NULL;

	switch (da->attr) {
	default:
		goto print_vp;

	case PW_PACKET_TYPE:
		dv = dict_valbyattr(PW_PACKET_TYPE, 0, packet->code);
		if (dv) return talloc_strdup(ctx, dv->name);
		return talloc_asprintf(ctx, "%d", packet->code);

	case PW_PACKET_AUTHENTICATION_VECTOR:
		myvp.length = sizeof(packet->vector);
		memcpy(&myvp.vp_octets, packet->vector, sizeof(packet->vector));
		vp = &myvp;
		break;

	case PW_CLIENT_IP_ADDRESS:
	case PW_PACKET_SRC_IP_ADDRESS:
		if (packet->src_ipaddr.af == AF_INET) {
			myvp.vp_ipaddr = packet->src_ipaddr.ipaddr.ip4addr.s_addr;
			vp = &myvp;
		}
		break;

	case PW_PACKET_DST_IP_ADDRESS:
		if (packet->dst_ipaddr.af == AF_INET) {
			myvp.vp_ipaddr = packet->dst_ipaddr.ipaddr.ip4addr.s_addr;
			vp = &myvp;
		}
		break;

	case PW_PACKET_SRC_IPV6_ADDRESS:
		if (packet->src_ipaddr.af == AF_INET6) {
			memcpy(&myvp.vp_ipv6addr,
			       &packet->src_ipaddr.ipaddr.ip6addr,
			       sizeof(packet->src_ipaddr.ipaddr.ip6addr));
			vp = &myvp;
		}
		break;

	case PW_PACKET_DST_IPV6_ADDRESS:
		if (packet->dst_ipaddr.af == AF_INET6) {
			memcpy(&myvp.vp_ipv6addr,
			       &packet->dst_ipaddr.ipaddr.ip6addr,
			       sizeof(packet->dst_ipaddr.ipaddr.ip6addr));
			vp = &myvp;
		}
		break;

	case PW_PACKET_SRC_PORT:
		myvp.vp_integer = packet->src_port;
		vp = &myvp;
		break;

	case PW_PACKET_DST_PORT:
		myvp.vp_integer = packet->dst_port;
		vp = &myvp;
		break;
	}

	if (!vp) return vp_aprinttype(ctx, da->type);
	return vp_aprint(ctx, vp);
}

static char *xlat_aprint(TALLOC_CTX *ctx, REQUEST *request, const xlat_exp_t * const node,
			 RADIUS_ESCAPE_STRING escape, void *escape_ctx, int lvl)
{
	size_t rcode;
	char *str, *child;
	REQUEST *ref;

	XLAT_DEBUG("%.*sxlat aprint %d", lvl, xlat_spaces, node->type);

	switch (node->type) {
		/*
		 *	Don't escape this
		 */
	case XLAT_LITERAL:
		return talloc_strdup(ctx, node->fmt);

	case XLAT_PERCENT: {
		const char *p;
		char *q, *nl;
		size_t freespace;
		struct tm *TM, s_TM;
		time_t when;

		str = talloc_array(ctx, char, 256); /* @todo do better allocation */
		p = node->fmt;
		q = str;

		when = request->timestamp;
		if (request->packet) when = request->packet->timestamp.tv_sec;

		while (*p) {
			if (*p != '%') { /* blind copy of non-% characters */
				*(q++) = *(p++);
				continue;
			}

			p++;
			freespace = 256 - (q - str);

			switch (*p) {
			case '%':
				*(q++) = *(p++);
				continue; /* NOT break */

			case 'd': /* request day */
				TM = localtime_r(&when, &s_TM);
				strftime(q, freespace, "%d", TM);
				break;

			case 'l': /* request timestamp */
				snprintf(q, freespace, "%lu",
					 (unsigned long) when);
				break;

			case 'm': /* request month */
				TM = localtime_r(&when, &s_TM);
				strftime(q, freespace, "%m", TM);
				break;

			case 't': /* request timestamp */
				CTIME_R(&when, q, freespace);
				nl = strchr(q, '\n');
				if (nl) *nl = '\0';
				break;

			case 'D': /* request date */
				TM = localtime_r(&when, &s_TM);
				strftime(q, freespace, "%Y%m%d", TM);
				break;

			case 'G': /* request minute */
				TM = localtime_r(&when, &s_TM);
				strftime(q, freespace, "%M", TM);
				break;

			case 'H': /* request hour */
				TM = localtime_r(&when, &s_TM);
				strftime(q, freespace, "%H", TM);
				break;

			case 'I': /* Request ID */
				snprintf(q, freespace, "%i", request->packet->id);
				break;

			case 'S': /* request timestamp in SQL format*/
				TM = localtime_r(&when, &s_TM);
				strftime(q, freespace, "%Y-%m-%d %H:%M:%S", TM);
				break;

			case 'T': /* request timestamp */
				TM = localtime_r(&when, &s_TM);
				strftime(q, freespace, "%Y-%m-%d-%H.%M.%S.000000", TM);
				break;

			case 'Y': /* request year */
				TM = localtime_r(&when, &s_TM);
				strftime(q, freespace, "%Y", TM);
				break;

			default: /* should have been checked at parse time */
				rad_assert(0 == 1);
				if (freespace > 2) {
					q[0] = '%';
					q[1] = *p;
					q[2] = '\0';
				}
				break;
			}

			q += strlen(q);
			p++;
		}
	}
		break;

	case XLAT_ATTRIBUTE:
		ref = request;
		radius_request(&ref, node->ref);

		/*
		 *	Some attributes are virtual <sigh>
		 */
		str = xlat_getvp(ctx, ref, node->list, node->da, node->tag);
		XLAT_DEBUG("expand attr %s --> '%s'", node->da->name, str);
		break;

	case XLAT_MODULE:
		rad_assert(node->child != NULL);

		if (xlat_process(&child, request, node->child, node->xlat->escape, node->xlat->instance) == 0) {
			rad_assert(child == NULL);
			return NULL;
		}

		XLAT_DEBUG("%.*sexpand mod %s --> '%s'", lvl, xlat_spaces, node->fmt, child);

		str = talloc_array(ctx, char, 1024); /* FIXME: have the module call talloc_asprintf */
		rad_assert(node->child != NULL);

		rcode = node->xlat->func(node->xlat->instance, request, child, str, 1024);
		talloc_free(child);
		if (rcode == 0) {
			talloc_free(str);
			return NULL;
		}
		break;

#ifdef HAVE_REGEX_H
	case XLAT_REGEX:
		child = request_data_reference(request, request,
					       REQUEST_DATA_REGEX | node->num);
		if (!child) return NULL;

		str = talloc_strdup(ctx, child);
		break;
#endif

	case XLAT_ALTERNATE:
		rad_assert(node->child != NULL);
		rad_assert(node->alternate != NULL);

		str = xlat_aprint(ctx, request, node->child, node->xlat->escape, node->xlat->instance, lvl);
		if (str) break;

		str = xlat_aprint(ctx, request, node->alternate, node->xlat->escape, node->xlat->instance, lvl);
		break;

	}

	/*
	 *	Escape the non-literals we found above.
	 */
	if (escape) {
		size_t esclen;
		char *escaped;

		escaped = talloc_array(ctx, char, 1024); /* FIXME: do something intelligent */
		esclen = escape(request, escaped, 1024, str, escape_ctx);
		talloc_free(str);
		if (esclen == 0) {
			talloc_free(escaped);
			return NULL;
		}

		str = escaped;
	}

	rad_assert(str != NULL);
	return str;
}


static size_t xlat_process(char **out, REQUEST *request, const xlat_exp_t * const head,
			   RADIUS_ESCAPE_STRING escape, void *escape_ctx)
{
	int i, list;
	size_t total;
	char **array, *answer;
	const xlat_exp_t *node;
	
	*out = NULL;

	/*
	 *	Hack for speed.  If it's one expansion, just allocate
	 *	that and return, instead of allocating an intermediary
	 *	array.
	 */
	if (!head->next) {
		/*
		 *	Pass the MAIN escape function.  Recursive
		 *	calls will call node-specific escape
		 *	functions.
		 */
		answer = xlat_aprint(request, request, head, escape, escape_ctx, 0);
		if (!answer) return 0;
		*out = answer;
		return strlen(answer);
	}

	list = 0;		/* FIXME: calculate this once */
	for (node = head; node != NULL; node = node->next) {
		list++;
	}

	array = talloc_array(request, char *, list);
	if (!array) return -1;

	for (node = head, i = 0; node != NULL; node = node->next, i++) {
		array[i] = xlat_aprint(array, request, node, escape, escape_ctx, 0); /* may be NULL */
	}

	total = 0;
	for (i = 0; i < list; i++) {
		if (array[i]) total += strlen(array[i]); /* FIXME: calculate strlen once */
	}

	if (!total) {
		talloc_free(array);
		return 0;
	}

	answer = talloc_array(request, char, total + 1);

	total = 0;
	for (i = 0; i < list; i++) {
		size_t len;

		if (array[i]) {
			len = strlen(array[i]);
			memcpy(answer + total, array[i], len);
			total += len;
		}
	}
	answer[total] = '\0';
	talloc_free(array);	/* and child entries */

	*out = answer;
	return total;
}


/** Replace %whatever in a string.
 *
 * See 'doc/variables.txt' for more information.
 *
 * @param[out] out Where to write pointer to output buffer.
 * @param[in] outlen Size of out.
 * @param[in] request current request.
 * @param[in] fmt string to expand.
 * @param[in] escape function to escape final value e.g. SQL quoting.
 * @param[in] escape_ctx pointer to pass to escape function.
 * @return length of string written @bug should really have -1 for failure
 */
static ssize_t xlat_expand(char **out, size_t outlen, REQUEST *request, const char *fmt,
			   RADIUS_ESCAPE_STRING escape, void *escape_ctx)
{
	char *buff;
	ssize_t len;
	xlat_exp_t *node;
	
	rad_assert(fmt);
	rad_assert(request);

	/*
	 *	Give better errors than the old code.
	 */
	if (xlat_tokenize_request(request, fmt, &node) <= 0) {
		if (*out) *out[0] = '\0';
		return -1;
	}

	len = xlat_process(&buff, request, node, escape, escape_ctx);
	talloc_free(node);

	if (len <= 0) {
		rad_assert(buff == NULL);
		if (*out) *out[0] = '\0';
		return len;
	}

	/*
	 *	Escape the string, which may double it's size (or more)
	 *
	 *	@todo: For now, we assume that the string can only grow by 50%.
	 */
	if (escape) {
		size_t explen;
		char *exp;

		explen = len + len / 2;

		exp = talloc_array(request, char, explen);
		escape(request, exp, explen, buff, escape_ctx);
		talloc_free(buff);
		buff = exp;
	}

	RDEBUG2("\texpand: '%s' -> '%s'", fmt, buff);

	if (!*out) {
		*out = buff;
	} else {
		strlcpy(*out, buff, outlen);
	}

	return strlen(*out);
}

ssize_t radius_xlat(char *out, size_t outlen, REQUEST *request, const char *fmt, RADIUS_ESCAPE_STRING escape, void *ctx)
{
	return xlat_expand(&out, outlen, request, fmt, escape, ctx);
}
		    
ssize_t radius_axlat(char **out, REQUEST *request, const char *fmt, RADIUS_ESCAPE_STRING escape, void *ctx)
{
	return xlat_expand(out, 0, request, fmt, escape, ctx);
}
