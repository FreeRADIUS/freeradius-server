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
 * @file jpath.c
 * @brief Implements the evaluation and parsing functions for the FreeRADIUS version of jpath.
 *
 * @author Arran Cudbard-Bell
 *
 * @copyright 2015 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2015 Network RADIUS SARL (legal@networkradius.com)
 * @copyright 2015 The FreeRADIUS Server Project
 */
#include <freeradius-devel/util/debug.h>
#include "base.h"

#define	SELECTOR_INDEX_UNSET			INT32_MAX

typedef enum {
	JPATH_OPERAND_LITERAL = 0,		//!< Operand is a literal
	JPATH_OPERAND_JPATH			//!< Operand is a jpath sequence
} jpath_operand_type;

typedef enum {
	JPATH_SELECTOR_INVALID = 0,
	JPATH_SELECTOR_ROOT,			//!< Jump to the root of the document.
	JPATH_SELECTOR_CURRENT,			//!< Continue at the current node in the document.
	JPATH_SELECTOR_WILDCARD,		//!< Wildcard, operate over all array indicies, or fields
	JPATH_SELECTOR_FIELD,			//!< A field, current JSON node must be an object.
	JPATH_SELECTOR_INDEX,			//!< Array index, current JSON node must be an array.
	JPATH_SELECTOR_SLICE,			//!< Array slice, current JSON node must be an array.
	JPATH_SELECTOR_FILTER_EXPRESSION,	//!< Complex filter expression (NYI).
	JPATH_SELECTOR_EXPRESSION,		//!< Expression (NYI).
	JPATH_SELECTOR_RECURSIVE_DESCENT	//!< Descend through the JSON tree, looking for a node which matches
						//!< the next one in the jpath sequence.
} jpath_type_t;

/** Operand in a jpath expression
 *
 */
typedef union {
	char const		*literal;	//!< Operand is a literal (value)
	fr_jpath_node_t		*jpath;		//!< Operand is a jpath expression
} jpath_operand_t;

/** A jpath expression for performing complex comparisons against field values
 *
 */
typedef struct {
	jpath_operand_t		lhs;		//!< LHS value.

	jpath_operand_t		rhs;		//!< RHS value.
} jpath_expr_t;

/** Selects a subset of JSON child nodes
 *
 */
typedef struct jpath_selector jpath_selector_t;
struct jpath_selector {
	union {
		char const	*field;		//!< JSON object name
		int32_t		slice[3];	//!< Array index, or slice, or step

		jpath_expr_t	expr;		//!< Expression
	};
	jpath_type_t		type;		//!< Type of the Jpath node.
	jpath_selector_t	*next;
};

/** Node in a jpath selector sequence
 *
 */
struct fr_jpath_node {
	jpath_selector_t	*selector;	//!< Jpath selector head (there may be multiple).
	fr_jpath_node_t		*next;		//!< Next in the jpath chain.
};

static char const escape_chars[] = "[],*.:\\()?";


/** Escapes special chars
 *
 * Escapes any characters that may have special meaning within a jpath expression
 *
 * @param request Current request (unused may be NULL).
 * @param out Where to write the escaped string.
 * @param outlen Length of the output buffer.
 * @param in data to escape.
 * @param arg uctx data, not used.
 * @return the number of chars written to out.
 */
size_t fr_jpath_escape_func(UNUSED REQUEST *request, char *out, size_t outlen, char const *in, UNUSED void *arg)
{
	char const *p = in;
	char *q = out, *end = out + outlen;

	if (outlen == 0) return 0;

	while (*p && (q < end)) {
		if (memchr(escape_chars, *p, sizeof(escape_chars))) {
			if ((q + 1) >= end) break;
			q[0] = '\\';
			q[1] = *p++;
			q += 2;
			continue;
		}
		*q++ = *p++;
	}
	*q = '\0';

	return q - end;
}

/** Recursive function for jpath_expr_evaluate
 *
 * @param[in,out] ctx to allocate fr_value_box_t in.
 * @param[out] tail Where to write fr_value_box_t (**).
 * @param[in] dst_type FreeRADIUS type to convert to.
 * @param[in] dst_enumv Enumeration values to allow string to integer conversions.
 * @param[in] object current node in the json tree.
 * @param[in] jpath to evaluate.
 * @return
 *	- 1 on match.
 *	- 0 on no match.
 *	- -1 on error.
 */
static int jpath_evaluate(TALLOC_CTX *ctx, fr_value_box_t ***tail,
			  fr_type_t dst_type, fr_dict_attr_t const *dst_enumv,
			  json_object *object, fr_jpath_node_t const *jpath)
{
	fr_value_box_t		*value;
	fr_jpath_node_t const	*node;
	jpath_selector_t const	*selector;
	bool			child_matched = false;
	int			ret = 0;

	/*
	 *	Iterate over the nodes, we only recurse for
	 *	more complex operations.
	 */
	for (node = jpath; node; node = node->next) switch (node->selector->type) {
	case JPATH_SELECTOR_FIELD:
		if (!fr_json_object_is_type(object, json_type_object)) return 0;
		if (!json_object_object_get_ex(object, node->selector->field, &object)) return 0;
		continue;

	case JPATH_SELECTOR_INDEX:
	case JPATH_SELECTOR_SLICE:
	/*
	 *	There may be multiple selectors per node
	 */
	for (selector = node->selector; selector; selector = selector->next) switch (selector->type) {
		case JPATH_SELECTOR_INDEX:
		{
			struct array_list *array_obj;	/* Because array_list is a global... */

			fr_assert(selector->slice[0] != SELECTOR_INDEX_UNSET);

			if (!fr_json_object_is_type(object, json_type_array)) return 0;
			array_obj = json_object_get_array(object);
			if ((selector->slice[0] < 0) ||
			    (selector->slice[0] >= (int32_t)(array_obj->length & INT32_MAX))) continue;

			ret = jpath_evaluate(ctx, tail, dst_type, dst_enumv,
					     array_obj->array[selector->slice[0]], node->next);
			if (ret < 0) return ret;
			if (ret == 1) child_matched = true;
		}
			break;

		case JPATH_SELECTOR_SLICE:
		{
			struct array_list *array_obj;
			int32_t start, end, step, i;

			if (!fr_json_object_is_type(object, json_type_array)) return 0;
			array_obj = json_object_get_array(object);

			/*
			 *	This logic may seem slightly odd, but it perfectly
			 *	emulates python array slicing behaviour AFAICT
			 */
			step = selector->slice[2];
			if (step == SELECTOR_INDEX_UNSET) step = 1;

			start = selector->slice[0];
			if (start == SELECTOR_INDEX_UNSET) start = (step < 0) ?
				(int32_t)((array_obj->length - 1) & INT32_MAX) : 0;
			else if (start < 0) start = array_obj->length + start;

			end = selector->slice[1];
			if (end == SELECTOR_INDEX_UNSET) end = (step < 0) ?
				-1 : (int32_t)((array_obj->length - 1) & INT32_MAX);
			else if (end < 0) end = array_obj->length + end;

			/*
			 *	Descending
			 */
			if (step < 0) for (i = start; (i > end) && (i >= 0); i += step) {
				fr_assert((i >= 0) && (i < (int32_t)(array_obj->length & INT32_MAX)));
				ret = jpath_evaluate(ctx, tail, dst_type, dst_enumv,
						     array_obj->array[i], node->next);
				if (ret < 0) return ret;
				if (ret == 1) child_matched = true;
			/*
			 *	Ascending
			 */
			} else for (i = start; (i < end) && (i < (int32_t)(array_obj->length & INT32_MAX)); i += step) {
				fr_assert((i >= 0) && (i < (int32_t)(array_obj->length & INT32_MAX)));
				ret = jpath_evaluate(ctx, tail, dst_type, dst_enumv,
						     array_obj->array[i], node->next);
				if (ret < 0) return ret;
				if (ret == 1) child_matched = true;
			}
		}
			break;

		default:
			fr_assert(0);
			return -1;
	}
		return child_matched ? 1 : 0;

	/*
	 *	Iterate over fields or array indices
	 */
	case JPATH_SELECTOR_WILDCARD:
	{
		int i;

		if (fr_json_object_is_type(object, json_type_array)) {
			struct array_list *array_obj;

			array_obj = json_object_get_array(object);
			for (i = 0; i < (int32_t)(array_obj->length & INT32_MAX); i++) {
				ret = jpath_evaluate(ctx, tail, dst_type, dst_enumv,
						     array_obj->array[i], node->next);
				if (ret < 0) return ret;
				if (ret == 1) child_matched = true;
			}
			return child_matched ? 1 : 0;
		} else if (fr_json_object_is_type(object, json_type_object)) {
			json_object_object_foreach(object, field_name, field_value) {
#ifndef NDEBUG
				fr_assert(field_name);
#else
				UNUSED_VAR(field_name);
#endif
				ret = jpath_evaluate(ctx, tail, dst_type, dst_enumv,
						     field_value, node->next);
				if (ret < 0) return ret;
				if (ret == 1) child_matched = true;
			}
			return child_matched ? 1 : 0;
		} else return 0;
	}

	/*
	 *  @todo Brute force it more efficiently.
	 */
	case JPATH_SELECTOR_RECURSIVE_DESCENT:
	{
		int i;

		if (fr_json_object_is_type(object, json_type_array)) {
			struct array_list *array_obj;

			/*
			 *	Descend into each element of the array
			 */
			array_obj = json_object_get_array(object);
			for (i = 0; i < (int32_t)(array_obj->length & INT32_MAX); i++) {
				ret = jpath_evaluate(ctx, tail, dst_type, dst_enumv,
						     array_obj->array[i], node);
				if (ret < 0) return ret;
				if (ret == 1) child_matched = true;
			}

			/*
			 *	On the way back up, evaluate the object's fields
			 */
			ret = jpath_evaluate(ctx, tail, dst_type, dst_enumv,
					     object, node->next);
			if (ret < 0) return ret;
			if (ret == 1) child_matched = true;

			return child_matched ? 1 : 0;
		} else if (fr_json_object_is_type(object, json_type_object)) {
			/*
			 *	Descend into each field of the object
			 */
			json_object_object_foreach(object, field_name, field_value) {
#ifndef NDEBUG
				fr_assert(field_name);
#else
				UNUSED_VAR(field_name);
#endif
				ret = jpath_evaluate(ctx, tail, dst_type, dst_enumv,
						     field_value, node);
				if (ret < 0) return ret;
				if (ret == 1) child_matched = true;
			}

			/*
			 *	On the way back up, evaluate the object's fields
			 */
			ret = jpath_evaluate(ctx, tail, dst_type, dst_enumv,
					     object, node->next);
			if (ret < 0) return ret;
			if (ret == 1) child_matched = true;

			return child_matched ? 1 : 0;
		}

		/*
		 *	Descend down to the level of the leaf
		 *
		 *	Parser guarantees that the recursive descent operator
		 *	is never the last in a jpath sequence.
		 */
		return jpath_evaluate(ctx, tail, dst_type, dst_enumv, object, node->next);
	}

	case JPATH_SELECTOR_FILTER_EXPRESSION:
	case JPATH_SELECTOR_EXPRESSION:
	case JPATH_SELECTOR_INVALID:
	case JPATH_SELECTOR_ROOT:
	case JPATH_SELECTOR_CURRENT:
		fr_assert(0);
		return -1;		/* Not yet implemented */
	}

	/*
	 *	We've reached the end of the jpath sequence
	 *	we now attempt conversion of the leaf to
	 *	the specified value.
	 */
	value = fr_value_box_alloc_null(ctx);
	if (fr_json_object_to_value_box(value, value, object, dst_enumv, true) < 0) {
		talloc_free(value);
		return -1;
	}

	if (fr_value_box_cast_in_place(value, value, dst_type, dst_enumv) < 0) {
		talloc_free(value);
		return -1;
	}

	**tail = value;
	*tail = &(**tail)->next;
	return 1;
}

/** Evaluate a parsed jpath expression against a json-c tree
 *
 * Will produce one or more fr_value_box_t structures of the desired type,
 * or error out if the conversion between types fails.
 *
 * @param[in,out] ctx to allocate fr_value_box_t in.
 * @param[out] out Where to write fr_value_box_t.
 * @param[in] dst_type FreeRADIUS type to convert to.
 * @param[in] dst_enumv Enumeration values to allow string to integer conversions.
 * @param[in] root of the json-c tree.
 * @param[in] jpath to evaluate.
 * @return
 *	- 1 on match.
 *	- 0 on no match.
 *	- -1 on error.
 */
int fr_jpath_evaluate_leaf(TALLOC_CTX *ctx, fr_value_box_t **out,
			   fr_type_t dst_type, fr_dict_attr_t const *dst_enumv,
			   json_object *root, fr_jpath_node_t const *jpath)
{
	fr_value_box_t **tail = out;

	*tail = NULL;

	if (!root) return -1;

	switch (jpath->selector->type) {
	case JPATH_SELECTOR_ROOT:
	case JPATH_SELECTOR_CURRENT:
		break;

	default:
		fr_assert(0);
		return -1;
	}

	return jpath_evaluate(ctx, &tail, dst_type, dst_enumv, root, jpath->next);
}

/** Print a node list to a string for debugging
 *
 * Will not be identical to the original parsed string, but should be sufficient
 * for testing purposes.
 *
 * @param ctx to allocate string in.
 * @param head of the node list.
 * @return the string representation of the node list.
 */
char *fr_jpath_asprint(TALLOC_CTX *ctx, fr_jpath_node_t const *head)
{
	fr_jpath_node_t const *node;
	jpath_selector_t *selector;
	char *p;

	p = talloc_zero_array(ctx, char, 1);

	for (node = head; node; node = node->next) switch (node->selector->type) {
	case JPATH_SELECTOR_ROOT:
		p = talloc_strdup_append_buffer(p, "$");
		break;

	case JPATH_SELECTOR_CURRENT:
		p = talloc_strdup_append_buffer(p, "@");
		break;

	case JPATH_SELECTOR_WILDCARD:
		p = talloc_strdup_append_buffer(p, ".*");
		break;

	case JPATH_SELECTOR_FIELD:
	{
		char buffer[257];

		fr_jpath_escape_func(NULL, buffer, sizeof(buffer), node->selector->field, NULL);
		p = talloc_asprintf_append_buffer(p, ".%s", buffer);
	}
		break;

	/*
	 *	Bracketed selectors can contain a mix of types
	 */
	case JPATH_SELECTOR_INDEX:
	case JPATH_SELECTOR_SLICE:
	case JPATH_SELECTOR_FILTER_EXPRESSION:
	case JPATH_SELECTOR_EXPRESSION:
		p = talloc_strdup_append_buffer(p, "[");
		for (selector = node->selector; selector; selector = selector->next) switch (selector->type) {
		case JPATH_SELECTOR_INDEX:
			p = talloc_asprintf_append_buffer(p, "%i%s", selector->slice[0], selector->next ? "," : "");
			break;

		case JPATH_SELECTOR_SLICE:
			if (selector->slice[0] == SELECTOR_INDEX_UNSET) {
				p = talloc_strdup_append_buffer(p, ":");
			} else {
				p = talloc_asprintf_append_buffer(p, "%i:", selector->slice[0]);
			}
			if (selector->slice[1] == SELECTOR_INDEX_UNSET) {
				p = talloc_strdup_append_buffer(p, ":");
			} else if (selector->slice[2] == SELECTOR_INDEX_UNSET) {
				p = talloc_asprintf_append_buffer(p, "%i", selector->slice[1]);
			} else {
				p = talloc_asprintf_append_buffer(p, "%i:", selector->slice[1]);
			}
			if (selector->slice[2] != SELECTOR_INDEX_UNSET) {
				p = talloc_asprintf_append_buffer(p, "%i", selector->slice[2]);
			}
			if (selector->next) p = talloc_strdup_append_buffer(p, ",");
			break;

		default:
			fr_assert(0);	/* Not yet implemented */
			break;
		}
		p = talloc_strdup_append_buffer(p, "]");
		break;

	case JPATH_SELECTOR_RECURSIVE_DESCENT:
		if (node->next) switch (node->next->selector->type) {
		case JPATH_SELECTOR_SLICE:
		case JPATH_SELECTOR_INDEX:
			p = talloc_strdup_append_buffer(p, "..");
			break;

		default:
			p = talloc_strdup_append_buffer(p, ".");
			break;
		}
		break;

	case JPATH_SELECTOR_INVALID:
		fr_assert(0);
		return NULL;
	}

	return p;
}

/** Parse a jpath filter expression, which in our case, is a FreeRADIUS condition
 *
 * @note this requires reworking some of the condition code to accept
 *	callbacks to retrieve virtual attributes, so is not yet implemented.
 */
static ssize_t jpath_filter_expr_parse(UNUSED jpath_selector_t *selector, UNUSED char const *in, UNUSED size_t inlen)
{
	/* selector->type = JPATH_SELECTOR_FILTER_EXPRESSION; */

	fr_strerror_printf("Filter expressions not yet implemented");
	return 0;
}

/** Parse a jpath expression
 *
 * @note this requires reworking some of the condition code to accept
 *	callbacks to retrieve virtual attributes, so is not yet implemented.
 */
static ssize_t jpath_expr_parse(UNUSED jpath_selector_t *selector, UNUSED char const *in, UNUSED size_t inlen)
{
	/* selector->type = JPATH_SELECTOR_EXPRESSION; */

	fr_strerror_printf("Expressions not yet implemented");
	return 0;
}

/** Parse index/slice notation
 *
 * Expects in to point to a buffer containing:
 *
 @verbatim
 	[<int0>:<int1>:<int2>]
 @endverbatim
 *
 * Where each of the integers and its accompanying delimiter is optional.
 *
 * @param selector to populate with index/slice info.
 * @param in input.
 * @param inlen length of in.
 * @return
 *	- > 0 on success.
 *	- <= 0 on error (* -1 to get offset error ocurred at).
 */
static ssize_t jpath_array_parse(jpath_selector_t *selector, char const *in, size_t inlen)
{
	int		idx = 0;
	int32_t		num;
	char const	*p, *end = in + inlen;
	char		*q;
	ssize_t		ret;

	char buffer[33];		/* Max (uin32_t * 3) + 2 + 1 */

	selector->type = JPATH_SELECTOR_INDEX;
	selector->slice[0] = SELECTOR_INDEX_UNSET;
	selector->slice[1] = SELECTOR_INDEX_UNSET;
	selector->slice[2] = SELECTOR_INDEX_UNSET;

	/*
	 *	Scan forward until we find a delimiter or terminator
	 */
	for (p = in; p < end; p++) if ((p[0] == ',') || (p[0] == ']')) break;
	if (p == end) {
		fr_strerror_printf("Missing selector delimiter ',' or terminator ']'");
		return -inlen;
	}

	ret = (p - in);
	if (ret == 0) {
		fr_strerror_printf("Empty selector");
		return 0;
	}

	if (inlen > sizeof(buffer)) {	/* - 1 for ] */
		fr_strerror_printf("Selector too long");
		return -inlen;
	}

	/*
	 *	Have to use an intermediary buffer because strtol
	 *	doesn't accept a terminating address via endptr.
	 */
	memcpy(&buffer, in, p - in);
	buffer[p - in] = '\0';
	p = buffer;

	/*
	 *	Index or start
	 */
	num = (int32_t)strtol(p, &q, 10);
	if (q > p) switch (q[0]) {
	default:
	no_term:
		fr_strerror_printf("Expected num, ':' or ']'");
		return buffer - q;

	case ':':			/* More integers to parse */
		selector->slice[idx] = num;
		break;

	case '\0':			/* Array index */
		selector->slice[idx] = num;
		return ret;
	}
	if (q[0] != ':') goto no_term;
	idx++;
	p = q + 1;

	selector->type = JPATH_SELECTOR_SLICE;

	/*
	 *	End
	 */
	num = (int32_t)strtol(p, &q, 10);
	if (q > p) switch (q[0]) {
	default:
		goto no_term;

	case ':':			/* More integers to parse */
		selector->slice[idx] = num;
		break;

	case '\0':			/* Array End */
		selector->slice[idx] = num;
		return ret;
	}
	if (q[0] != ':') goto no_term;
	idx++;
	p = q + 1;

	/*
	 *	Step
	 */
	num = (int32_t)strtol(p, &q, 10);
	if (q[0] != '\0') {
		fr_strerror_printf("Expected num or ']'");
		return buffer - q;
	}
	if (q > p) {
		if (num == 0) {
			fr_strerror_printf("Step cannot be 0");
			return buffer - p;
		}
		selector->slice[idx] = num;
	}
	return ret;
}

/** Parse a jpath field
 *
 */
static size_t jpath_field_parse(fr_jpath_node_t *node, char const *in, size_t inlen)
{
	char buffer[128];

	char const *p = in, *end = p + inlen;
	char *buff_p = buffer, *buff_end = buff_p + sizeof(buffer);

	/*
	 *	Field name with optional selector
	 */
	while (p < end) {
		int clen;

		if (buff_p == buff_end) {
		name_too_big:
			fr_strerror_printf("Exceeded maximum field name length");
			return in - p;
		}

		clen = fr_utf8_char((uint8_t const *)p, end - p);
		if (clen == 0) {
			fr_strerror_printf("Bad UTF8 char");
			return in - p;
		}

		/*
		 *	Multibyte
		 */
		if (clen > 1) {
			if ((buff_p + clen) >= buff_end) goto name_too_big;
			memcpy(buff_p, p, clen);
			buff_p += clen;
			p += clen;
			continue;
		}

		switch (p[0]) {				/* Normal char */
		default:
			*buff_p++ = *p++;
			continue;

		/*
		 *	Escape sequence
		 */
		case '\\':
			if (++p == end) return p - in;

			if (memchr(escape_chars, p[0], sizeof(escape_chars))) {
				*buff_p++ = *p++;
				continue;
			}
			*buff_p++ = '\\';
			continue;

		/*
		 *	Things that mark the end of a field
		 */
		case '[':
		case ']':	/* Not really, but it's probably not right */
		case '.':
			break;
		}
		break;
	}

	if (buff_p == buffer) {
		fr_strerror_printf("Empty field specifier");
		return 0;
	}
	node->selector->field = talloc_bstrndup(node, buffer, buff_p - buffer);
	node->selector->type = JPATH_SELECTOR_FIELD;

	return p - in;
}

/** parse a jpath selector
 *
 */
static size_t jpath_selector_parse(fr_jpath_node_t *node, char const *in, size_t inlen)
{
	ssize_t slen;
	char const *p = in, *end = p + inlen;

	jpath_selector_t **stail;
	jpath_selector_t *selector;

	stail = &node->selector->next;
	selector = node->selector;

	if (++p == end) {	/* Skip past [ */
	missing_terminator:
		fr_strerror_printf("Missing selector terminator ']'");
		return in - p;
	}

	while (p < end) {
		/*
		 * 	What kind of selector is it?
		 */
		switch (p[0]) {
		case '?':		/* Filter expression */
			slen = jpath_filter_expr_parse(selector, p, end - p);
			break;

		case '(':		/* Expression */
			slen = jpath_expr_parse(selector, p, end - p);
			break;

		default:		/* Index or slice */
			slen = jpath_array_parse(selector, p, end - p);
			break;
		}
		if (slen <= 0) {
			p += -slen;
			return in - p;	/* Error */
		}
		p += slen;
		if (p == end) goto missing_terminator;
		fr_assert(p < end);

		/*
		 *	Things that terminate a selector
		 *
		 *	- ']' a selector terminator.
		 *	- ',' another selector.
		 */
		if (p[0] == ']') break;	/* We're done */
		if (p[0] != ',') {	/* There's more... */
			fr_strerror_printf("Expected selector delimiter ','"
					   "or selector terminator ']'");
			return in - p;	/* Error */
		}
		if (++p == end) goto missing_terminator;

		/*
		 *	Link in an additional selector
		 */
		*stail = selector = talloc_zero(node, jpath_selector_t);
		if (!selector) {
			fr_strerror_printf("Failed allocating selector");
			return in - p;
		}
		stail = &selector->next;
	}
	if (p[0] != ']') goto missing_terminator;

	p++; /* Skip past ] */

	return p - in;
}

/** Parse a jpath string
 *
 * Based on the syntax described here http://goessner.net/articles/JsonPath/
 *
 * Implements parser for everything except unions and expressions
 *
 * @return
 *	- > 0 on success.
 *	- <= 0 on error (* -1 to get offset error ocurred at).
 */
ssize_t fr_jpath_parse(TALLOC_CTX *ctx, fr_jpath_node_t **head, char const *in, size_t inlen)
{
	TALLOC_CTX *tail_ctx = ctx;

	ssize_t slen;
	fr_jpath_node_t *node, **tail = head;

	char const *p = in, *end = p + inlen;

	*head = NULL;

#define NODE_NEW(_node) \
do { \
	tail_ctx = *tail = (_node) = talloc_zero(tail_ctx, fr_jpath_node_t); \
	(_node)->selector = talloc_zero((_node), jpath_selector_t); \
	tail = &(_node)->next; \
} while (0)

	if (inlen < 1) {
	bad_start:
		fr_strerror_printf("Expected root specifier '$', or current node specifier '@'");
		return 0;
	}

	/*
	 *	Start of the jpath expression
	 *
	 *	- '$' JSON root node specifier
	 *	- '@' Current node specifier
	 */
	switch (p[0]) {
	case '$':
		NODE_NEW(node);
		node->selector->type = JPATH_SELECTOR_ROOT;
		p++;
		break;

	case '@':
		NODE_NEW(node);
		node->selector->type = JPATH_SELECTOR_CURRENT;
		p++;
		break;

	default:
		goto bad_start;
	}

	/*
	 *	Valid successions of '$' or '@'
	 *
	 *	- '[' Start of a selector
	 *	- '.' Start of a field specifier
	 */
	while (p < end) {
		NODE_NEW(node);

		switch (p[0]) {
		case '.':
			if (++p == end) {
				fr_strerror_printf("Expected recursive descent '..' "
						   "wildcard '*' or field specifier");
			error:
				TALLOC_FREE(*head);
				return in - p;
			}

			/*
			 *	Valid successions of '.'
			 *
			 *	- '.' recursive descent.
			 *	- '*' wildcard.
			 *	- <name> (fieldname).
			 *
			 *	This should probably be in its own function, but never mind...
			 */
			switch (p[0]) {
			case '.':
				if ((p != end) && (p[1] == '.')) {
					fr_strerror_printf("Recursive descent must not be "
							   "followed by child delimiter '.'");
					p++;
					goto error;
				}
				node->selector->type = JPATH_SELECTOR_RECURSIVE_DESCENT;

				if ((p + 1) == end) {
					fr_strerror_printf("Path may not end in recursive descent");
					goto error;
				}

				/*
				 *	If and only if, the next char is the beginning
				 *	of a selector, advance the pointer.
				 *
				 *	Otherwise we leave it pointing to the second '.'
				 *	allowing .* and .<field>
				 */
				 if (p[1] == '[') p++;
				 continue;

			case '*':
				node->selector->type = JPATH_SELECTOR_WILDCARD;
				p++;
				continue;

			default:
				/*
				 *	Field specifier is the only other valid possibility
				 */
				slen = jpath_field_parse(node, p, (end - p));
				if (slen <= 0) {
					p += -(slen);
					goto error;
				}
				p += slen;
				if (p == end) return p - in;	/* The end of string! */
				fr_assert(p < end);
			}
			break;

		case '[':
			slen = jpath_selector_parse(node, p, (end - p));
			if (slen <= 0) {
				p += -(slen);
				goto error;
			}
			p += slen;
			if (p == end) return p - in;	/* The end of string! */
			fr_assert(p < end);
			break;

		default:
			fr_strerror_printf("Expected field specifier '.' or selector '['");
			goto error;
		}
	}

	return p - in;
}

