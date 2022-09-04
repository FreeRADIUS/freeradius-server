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
 * @file lib/ldap/filter.c
 * @brief Functions to handle basic LDAP filter parsing and filtering
 *
 * @copyright 2022 Network RADIUS SARL (legal@networkradius.com)
 */

#include <freeradius-devel/ldap/base.h>

static fr_table_num_sorted_t const ldap_filter_op_table[] = {
	{ L("<="),	LDAP_FILTER_OP_LE	},
	{ L("="),	LDAP_FILTER_OP_EQ	},
	{ L(">="),	LDAP_FILTER_OP_GE	}
};
static size_t ldap_filter_op_table_len = NUM_ELEMENTS(ldap_filter_op_table);

static bool const 	fr_ldap_attr_allowed_chars[UINT8_MAX + 1] = {
				['-'] = true,
				SBUFF_CHAR_CLASS_ALPHA_NUM
};

#define FILTER_ATTR_MAX_LEN 256
#define FILTER_VALUE_MAX_LEN 256

static fr_slen_t ldap_filter_parse_node(ldap_filter_t *node, fr_sbuff_t *sbuff, int depth,
					filter_attr_check_t attr_check, void *uctx);

/** Parse LDAP filter logic group
 *
 * @param[in,out] node		to populate with parsed filter.
 * @param[in] sbuff		pointing to filter to parse.
 * @param[in] depth		to indent debug output, indicating nesting of groups.
 * @param[in] attr_check	callback to check if required attributes are in the query.
 * @param[in] uctx		passed to attribute check callback.
 * @return
 *  - number of bytes parsed on success
 *  - < 0 on error
 */
static fr_slen_t ldap_filter_parse_logic(ldap_filter_t *node, fr_sbuff_t *sbuff, int depth,
					 filter_attr_check_t attr_check, void *uctx)
{
	ldap_filter_t	*child_node;
	fr_slen_t	ret = 0;
	fr_slen_t	parsed = 0;

	fr_sbuff_switch(sbuff, '\0') {
	case '&':
		node->logic_op = LDAP_FILTER_LOGIC_AND;
		node->orig = talloc_typed_strdup(node, "&");
		break;

	case '|':
		node->logic_op = LDAP_FILTER_LOGIC_OR;
		node->orig = talloc_typed_strdup(node, "|");
		break;

	case '!':
		node->logic_op = LDAP_FILTER_LOGIC_NOT;
		node->orig = talloc_typed_strdup(node, "!");
		break;
	}
	parsed += fr_sbuff_advance(sbuff, 1);

	DEBUG3("%*sCreating LDAP filter group %s", depth, "", node->orig);
	node->filter_type = LDAP_FILTER_GROUP;
	fr_dlist_init(&node->children, ldap_filter_t, entry);
	MEM(child_node = talloc_zero(node, ldap_filter_t));
	fr_dlist_insert_head(&node->children, child_node);

	depth += 2;
	ret = ldap_filter_parse_node(child_node, sbuff, depth, attr_check, uctx);
	if (ret < 0) return ret;
	parsed += ret;

	/*
	 *	Look for sibling nodes to the child just processed
	 */
	while (fr_sbuff_is_char(sbuff, '(')) {
		if (node->logic_op == LDAP_FILTER_LOGIC_NOT) {
			fr_strerror_const("'!' operator can only apply to one filter");
			FR_SBUFF_ERROR_RETURN(sbuff);
		}
		MEM(child_node = talloc_zero(node, ldap_filter_t));
		fr_dlist_insert_tail(&node->children, child_node);
		ret = ldap_filter_parse_node(child_node, sbuff, depth, attr_check, uctx);
		if (ret < 0) return ret;
		parsed += ret;
	}

	return parsed;
}

/** Parse individual LDAP filter
 *
 * @param[in,out] node		to populate with parsed filter.
 * @param[in] sbuff		pointing to filter to parse.
 * @param[in] depth		to indent debug output, indicating nesting of groups.
 * @param[in] attr_check	callback to check if required attributes are in the query.
 * @param[in] uctx		passed to attribute check callback.
 * @return
 *  - number of bytes parsed on success
 *  - < 0 on error
 */
static fr_slen_t ldap_filter_parse_filter(ldap_filter_t *node, fr_sbuff_t *sbuff, int depth,
					  filter_attr_check_t attr_check, void *uctx)
{
	char			attr_buffer[FILTER_ATTR_MAX_LEN], val_buffer[FILTER_VALUE_MAX_LEN];
	fr_sbuff_t		attr_sbuff = FR_SBUFF_IN(attr_buffer, FILTER_ATTR_MAX_LEN);
	fr_sbuff_t		val_sbuff = FR_SBUFF_IN(val_buffer, FILTER_VALUE_MAX_LEN);
	size_t			len;
	ssize_t			slen;
	ldap_filter_op_t	op;
	fr_sbuff_marker_t	marker;

	fr_sbuff_marker(&marker, sbuff);

	/*
	 *	Extract the attribute name, blanking the buffer first.
	 */
	memset(attr_buffer, 0, FILTER_ATTR_MAX_LEN);
	len = fr_sbuff_out_bstrncpy_allowed(&attr_sbuff, sbuff, FILTER_ATTR_MAX_LEN - 1, fr_ldap_attr_allowed_chars);
	if (len == 0) {
		fr_strerror_const("Missing attribute name");
		FR_SBUFF_ERROR_RETURN(sbuff);
	}

	MEM(node->attr = talloc_zero_array(node, char, len+1));
	memcpy(node->attr, attr_buffer, len);

	/*
	 *	Check for the attribute needed for the filter using the
	 *	provided callback.
	 */
	if (attr_check) attr_check(node->attr, uctx);

	/*
	 *	If the attribute name is followed by ':' there is an
	 *	extended match rule.  We only support two of them.
	 */
	if (fr_sbuff_next_if_char(sbuff, ':')) {
		if (fr_sbuff_adv_past_str_literal(sbuff, LDAP_MATCHING_RULE_BIT_AND)) {
			node->op = LDAP_FILTER_OP_BIT_AND;
			goto found_op;
		}
		if (fr_sbuff_adv_past_str_literal(sbuff, LDAP_MATCHING_RULE_BIT_OR)) {
			node->op = LDAP_FILTER_OP_BIT_OR;
			goto found_op;
		}

		fr_strerror_const("Unsupported extended match rule");
		FR_SBUFF_ERROR_RETURN(sbuff);

	found_op:
		if(!(fr_sbuff_next_if_char(sbuff, ':'))) {
			fr_strerror_const("Missing ':' after extended match rule");
			FR_SBUFF_ERROR_RETURN(sbuff);
		}
	}

	fr_sbuff_out_by_longest_prefix(&slen, &op, ldap_filter_op_table, sbuff, 0);

	switch(op) {
	case LDAP_FILTER_OP_EQ:
		if (node->op == LDAP_FILTER_OP_UNSET) node->op = op;
		break;

	case LDAP_FILTER_OP_LE:
	case LDAP_FILTER_OP_GE:
		node->op = op;
		break;

	default:
		fr_strerror_const("Incorrect operator");
		FR_SBUFF_ERROR_RETURN(sbuff);
	}

	if (((node->op == LDAP_FILTER_OP_BIT_AND) || (node->op == LDAP_FILTER_OP_BIT_OR)) &&
	    (op != LDAP_FILTER_OP_EQ)) {
		fr_strerror_const("Extended match rule only valid with '=' operator");
		FR_SBUFF_ERROR_RETURN(sbuff);
	}

	/*
	 *	Capture everything up to the next ')' as the value, blanking the buffer first.
	 */
	memset(val_buffer, 0, FILTER_VALUE_MAX_LEN);
	len = fr_sbuff_out_bstrncpy_until(&val_sbuff, sbuff, FILTER_VALUE_MAX_LEN - 1, &FR_SBUFF_TERM(")"), NULL);

	if (len == 0) {
		fr_strerror_const("Missing filter value");
		FR_SBUFF_ERROR_RETURN(sbuff);
	}

	/*
	 *	An equality test with a value of '*' is a present test
	 */
	if ((len == 1) && (*val_buffer == '*') && (node->op == LDAP_FILTER_OP_EQ)) node->op = LDAP_FILTER_OP_PRESENT;

	/*
	 *	Equality tests with '*' in the value are substring matches
	 */
	fr_sbuff_set_to_start(&val_sbuff);
	if ((node->op == LDAP_FILTER_OP_EQ) && (fr_sbuff_adv_to_chr(&val_sbuff, SIZE_MAX, '*'))) {
		node->op = LDAP_FILTER_OP_SUBSTR;
	}

	MEM(node->value = fr_value_box_alloc_null(node));

	switch (node->op) {
	case LDAP_FILTER_OP_EQ:
	case LDAP_FILTER_OP_PRESENT:
	case LDAP_FILTER_OP_SUBSTR:
		if (fr_value_box_bstrndup(node, node->value, NULL, val_buffer, len, false) < 0) {
			fr_strerror_const("Failed parsing value for filter");
			FR_SBUFF_ERROR_RETURN(sbuff);
		}
		break;

	/*
	 *	Since we don't have the LDAP schema, we make an assumption that <=, >= and
	 *	bitwise operators are going to be used with numeric attributes
	 */
	case LDAP_FILTER_OP_GE:
	case LDAP_FILTER_OP_LE:
	case LDAP_FILTER_OP_BIT_AND:
	case LDAP_FILTER_OP_BIT_OR:
		if (fr_value_box_from_str(node, node->value, FR_TYPE_UINT32, NULL,
					  val_buffer, len, NULL, false) < 0) {
			fr_strerror_const("Failed parsing value for filter");
			FR_SBUFF_ERROR_RETURN(sbuff);
		}
		break;

	/*
	 *	Operator should not be unset at the end of a filter
	 */
	case LDAP_FILTER_OP_UNSET:
		fr_assert(0);
		break;
	}

	/*
	 *	Take a copy of the original filter for debug output
	 */
	MEM(node->orig = talloc_zero_array(node, char, fr_sbuff_diff(sbuff, &marker) + 1));
	memcpy(node->orig, fr_sbuff_current(&marker), fr_sbuff_diff(sbuff, &marker));
	DEBUG3("%*sParsed LDAP filter (%s)", depth, "", node->orig);

	return fr_sbuff_diff(sbuff, &marker);
}

/** Parse individual LDAP filter nodes
 *
 * A node can either be a group of nodes joined with a logical operator
 * or an individual filter.
 *
 * @param[in,out] node		to populate with parsed filter.
 * @param[in] sbuff		pointing to filter to parse.
 * @param[in] depth		to indent debug output, indicating nesting of groups.
 * @param[in] attr_check	callback to check if required attributes are in the query.
 * @param[in] uctx		passed to attribute check callback.
 * @return
 *  - number of bytes parsed on success
 *  - < 0 on error
 */
static fr_slen_t ldap_filter_parse_node(ldap_filter_t *node, fr_sbuff_t *sbuff, int depth,
					filter_attr_check_t attr_check, void *uctx)
{
	fr_sbuff_marker_t	marker;
	fr_slen_t		ret;
	fr_slen_t		parsed = 0;

	static bool const	logical_op_chars[UINT8_MAX +1] = {
					['!'] = true, ['&'] = true, ['|'] = true,
				};

	if (!fr_sbuff_next_if_char(sbuff, '(')) {
		fr_strerror_const("Missing '('");
		FR_SBUFF_ERROR_RETURN(sbuff);
	}

	/*
	 *	Firstly, look for the characters which indicate the start of a group of filters
	 *	to be combined with a logical operator.
	 */
	fr_sbuff_marker(&marker, sbuff);
	if (fr_sbuff_adv_past_allowed(sbuff, 1, logical_op_chars, NULL)) {
		fr_sbuff_set(sbuff, &marker);
		ret = ldap_filter_parse_logic(node, sbuff, depth, attr_check, uctx);
	} else {
		ret = ldap_filter_parse_filter(node, sbuff, depth, attr_check, uctx);
	}

	if (ret < 0) return ret;
	parsed += ret;

	if (!fr_sbuff_next_if_char(sbuff, ')')) {
		fr_strerror_const("Missing ')'");
		FR_SBUFF_ERROR_RETURN(sbuff);
	}
	parsed ++;

	/*
	 *	If we're at the very top level we should be at the end
	 *	of the buffer
	 */
	if ((depth == 0) && (fr_sbuff_extend(sbuff))) {
		fr_strerror_const("Extra characters at the end of LDAP filter");
		FR_SBUFF_ERROR_RETURN(sbuff);
	}

	return parsed;
}

/** Parse an LDAP filter into its component nodes
 *
 * @param[in] ctx		to allocate nodes in.
 * @param[in,out] root		where to allocate the root of the parsed filter.
 * @param[in] filter		to parse.
 * @param[in] attr_check	callback to check if required attributes are in the query.
 * @param[in] uctx		passed to attribute check callback.
 * @return
 *	- number of bytes parsed on success
 *	< 0 on failure
 */
fr_slen_t fr_ldap_filter_parse(TALLOC_CTX *ctx, fr_dlist_head_t **root, fr_sbuff_t *filter,
			       filter_attr_check_t attr_check, void *uctx)
{
	ldap_filter_t	*node;
	fr_slen_t	ret;

	MEM(*root = talloc_zero(ctx, fr_dlist_head_t));
	fr_dlist_init(*root, ldap_filter_t, entry);

	MEM(node = talloc_zero(*root, ldap_filter_t));
	fr_dlist_insert_head(*root, node);

	ret = ldap_filter_parse_node(node, filter, 0, attr_check, uctx);
	if (ret < 0) {
		talloc_free(*root);
		*root = NULL;
		return ret;
	}

	return ret;
}

static bool ldap_filter_node_eval(ldap_filter_t *node, fr_ldap_connection_t *conn, LDAPMessage *msg, int depth);

/** Evaluate a group of LDAP filters
 *
 * Groups have a logical operator of &, | or !
 *
 * @param[in] group	to evaluate.
 * @param[in] conn	LDAP connection the message being filtered was returned on
 * @param[in] msg	to filter
 * @param[in] depth	to indent debug messages, reflecting group nesting
 * @return true or false result of the group evaluation
 */
static bool ldap_filter_group_eval(ldap_filter_t *group, fr_ldap_connection_t *conn, LDAPMessage *msg, int depth)
{
	ldap_filter_t	*node = NULL;
	bool		filter_state = false;

	DEBUG3("%*sEvaluating LDAP filter group %s", depth, "", group->orig);
	depth += 2;
	while ((node = fr_dlist_next(&group->children, node))) {
		switch (node->filter_type) {
		case LDAP_FILTER_GROUP:
			filter_state = ldap_filter_group_eval(node, conn, msg, depth);
			break;
		case LDAP_FILTER_NODE:
			filter_state = ldap_filter_node_eval(node, conn, msg, depth);
			break;
		}

		/*
		 *	Short circuit the group depending on the logical operator
		 *	and the return state of the last node
		 */
		if (((group->logic_op == LDAP_FILTER_LOGIC_OR) && filter_state) ||
		    ((group->logic_op == LDAP_FILTER_LOGIC_AND) && !filter_state)) {
			break;
		}
	}

	filter_state = (group->logic_op == LDAP_FILTER_LOGIC_NOT ? !filter_state : filter_state);

	depth -= 2;
	DEBUG3("%*sLDAP filter group %s results in %s", depth, "", group->orig, (filter_state ? "TRUE" : "FALSE"));
	return filter_state;
}

#define DEBUG_LDAP_ATTR_VAL if (DEBUG_ENABLED3) { \
	fr_value_box_t	value_box; \
	fr_ldap_berval_to_value_str_shallow(&value_box, values[i]); \
	DEBUG3("%*s  Evaluating attribute \"%s\", value \"%pV\"", depth, "", node->attr, &value_box); \
}

/** Evaluate a single LDAP filter node
 *
 * @param[in] node	to evaluate.
 * @param[in] conn	LDAP connection the message being filtered was returned on.
 * @param[in] msg	to filter.
 * @param[in] depth	to indent debug messages, reflecting group nesting.
 * @return true or false result of the node evaluation.
 */
static bool ldap_filter_node_eval(ldap_filter_t *node, fr_ldap_connection_t *conn, LDAPMessage *msg, int depth)
{
	struct berval	**values;
	int		count, i;
	bool		filter_state = false;

	switch (node->filter_type) {
	case LDAP_FILTER_GROUP:
		return ldap_filter_group_eval(node, conn, msg, depth);

	case LDAP_FILTER_NODE:
		DEBUG3("%*sEvaluating LDAP filter (%s)", depth, "", node->orig);
		values = ldap_get_values_len(conn->handle, msg, node->attr);
		count = ldap_count_values_len(values);

		switch (node->op) {
		case LDAP_FILTER_OP_PRESENT:
			filter_state = (count > 0 ? true : false);
			break;

		case LDAP_FILTER_OP_EQ:
			for (i = 0; i < count; i++) {
				DEBUG_LDAP_ATTR_VAL
				if ((node->value->length == values[i]->bv_len) &&
				    (strncasecmp(values[i]->bv_val, node->value->vb_strvalue, values[i]->bv_len) == 0)) {
					filter_state = true;
					break;
				}
			}
			break;

		/*
		 *	LDAP filters only use one wildcard character '*' for zero or more
		 *	character matches.
		 */
		case LDAP_FILTER_OP_SUBSTR:
		{
			char const	*v, *t, *v_end, *t_end;
			bool		skip;

			/*
			 *	Point t_end at the final character of the filter value
			 *	- not the NULL - so we can check for trailing '*'
			 */
			t_end = node->value->vb_strvalue + node->value->length - 1;

			for (i = 0; i < count; i++) {
				DEBUG_LDAP_ATTR_VAL
				t = node->value->vb_strvalue;
				v = values[i]->bv_val;
				v_end = values[i]->bv_val + values[i]->bv_len - 1;
				skip = false;

				/*
				 *	Walk the value (v) and test (t), comparing until
				 *	there is a mis-match or the end of one is reached.
				 */
				while ((v <= v_end) && (t <= t_end)) {
					/*
					 *	If a wildcard is found in the test,
					 *	indicate that we can skip non-matching
					 *	characters in the value
					 */
					if (*t == '*'){
						skip = true;
						t++;
						continue;
					}
					if (skip) {
						while ((tolower(*t) != tolower(*v)) && (v <= v_end)) v++;
					}
					if (tolower(*t) != tolower(*v)) break;
					skip = false;
					t++;
					v++;
				}

				/*
				 *	If we've got to the end of both the test and value,
				 *	or we've used all of the test and the last character is '*'
				 *	then we've matched the pattern.
				 */
				if (((v > v_end) && (t > t_end)) || ((t >= t_end) && (*t_end == '*'))) {
					filter_state = true;
					break;
				}
			}
		}
			break;

		/*
		 *	For >=, <= and bitwise operators, we assume numeric values
		 */
		case LDAP_FILTER_OP_GE:
		case LDAP_FILTER_OP_LE:
		case LDAP_FILTER_OP_BIT_AND:
		case LDAP_FILTER_OP_BIT_OR:
		{
			char		buffer[11];	/* Max uint32_t + 1 */
			uint32_t	value;
			for (i = 0; i < count; i++) {
				DEBUG_LDAP_ATTR_VAL
				/*
				 *	String too long for max uint32
				 */
				if (values[i]->bv_len > 10) continue;

				/*
				 *	bv_val is not NULL terminated - so copy to a
				 *	NULL terminated string before parsing.
				 */
				memcpy(buffer, values[i]->bv_val, values[i]->bv_len);
				buffer[values[i]->bv_len] = '\0';

				value = (uint32_t)strtol(buffer, NULL, 10);
				switch (node->op) {
				case LDAP_FILTER_OP_GE:
					if (value >= node->value->vb_uint32) filter_state = true;
					break;
				case LDAP_FILTER_OP_LE:
					if (value <= node->value->vb_uint32) filter_state = true;
					break;
				case LDAP_FILTER_OP_BIT_AND:
					if (value & node->value->vb_uint32) filter_state = true;
					break;
				case LDAP_FILTER_OP_BIT_OR:
					if (value | node->value->vb_uint32) filter_state = true;
					break;
				default:
					fr_assert(0);
					break;
				}
				if (filter_state) break;
			}
		}
			break;

		default:
			fr_assert(0);
			break;

		}

		ldap_value_free_len(values);
	}

	DEBUG3("%*sLDAP filter returns %s", depth, "", (filter_state ? "TRUE" : "FALSE"));

	return filter_state;
}

/** Evaluate an LDAP filter
 *
 * @param[in] root	of the LDAP filter to evaluate.
 * @param[in] conn	LDAP connection the message being filtered was returned on.
 * @param[in] msg	to filter.
 * @return true or false result of the node evaluation.
 */
bool fr_ldap_filter_eval(fr_dlist_head_t *root, fr_ldap_connection_t *conn, LDAPMessage *msg) {
	return ldap_filter_node_eval(fr_dlist_head(root), conn, msg, 0);
}
