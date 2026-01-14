/*
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** AVP manipulation and search API
 *
 * @file src/lib/util/pair_legacy.c
 *
 * @copyright 2000,2006,2015 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <sys/wait.h>

#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/pair_legacy.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/regex.h>
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/util/sbuff.h>
#include <freeradius-devel/util/value.h>

#include <freeradius-devel/protocol/radius/rfc2865.h>
#include <freeradius-devel/protocol/freeradius/freeradius.internal.h>

static fr_sbuff_term_t const 	bareword_terminals =
				FR_SBUFF_TERMS(
					L("\t"),
					L("\n"),
					L(" "),
					L("!*"),
					L("!="),
					L("!~"),
					L("&&"),		/* Logical operator */
					L(")"),			/* Close condition/sub-condition */
					L("+="),
					L("-="),
					L(":="),
					L("<"),
					L("<="),
					L("=*"),
					L("=="),
					L("=~"),
					L(">"),
					L(">="),
					L("||"),		/* Logical operator */
				);

static fr_table_num_sorted_t const pair_assignment_op_table[] = {
	{ L("+="),	T_OP_ADD_EQ		},
	{ L(":="),	T_OP_SET       		},
	{ L("="),	T_OP_EQ			},
};
static ssize_t pair_assignment_op_table_len = NUM_ELEMENTS(pair_assignment_op_table);

static fr_table_num_sorted_t const pair_comparison_op_table[] = {
	{ L("!*"),	T_OP_CMP_FALSE		},
	{ L("!="),	T_OP_NE			},
	{ L("!~"),	T_OP_REG_NE		},
	{ L("+="),	T_OP_ADD_EQ		},
	{ L(":="),	T_OP_SET		},
	{ L("<"),	T_OP_LT			},
	{ L("<="),	T_OP_LE			},
	{ L("="),	T_OP_EQ			},
	{ L("=*"),	T_OP_CMP_TRUE		},
	{ L("=="),	T_OP_CMP_EQ		},
	{ L("=~"),	T_OP_REG_EQ		},
	{ L(">"),	T_OP_GT			},
	{ L(">="),	T_OP_GE			}
};
static size_t pair_comparison_op_table_len = NUM_ELEMENTS(pair_comparison_op_table);

/*
 *	Stop parsing bare words at whitespace, comma, or end of list.
 *
 *	Note that we don't allow escaping of bare words here, as that screws up parsing of raw attributes with
 *	0x... prefixes.
 */
static fr_sbuff_parse_rules_t const bareword_unquoted = {
	.terminals = &FR_SBUFF_TERMS(
		L(""),
		L("\t"),
		L("\n"),
		L("\r"),
		L(" "),
		L(","),
		L("}")
	)
};


static ssize_t fr_pair_value_from_substr(fr_pair_parse_t const *conf, fr_pair_t *vp, fr_sbuff_t *in)
{
	fr_sbuff_t			our_in = FR_SBUFF(in);
	char				quote;
	ssize_t				slen;
	fr_sbuff_parse_rules_t const	*rules;

	if (fr_sbuff_next_if_char(&our_in, '"')) {
		rules = &value_parse_rules_double_quoted;
		quote = '"';
	parse:
		slen = fr_value_box_from_substr(vp, &vp->data, vp->da->type, vp->da, &our_in, rules);
	} else if (fr_sbuff_next_if_char(&our_in, '\'')) {
		rules = &value_parse_rules_single_quoted;
		quote = '\'';
		goto parse;
	} else if (!fr_sbuff_next_if_char(&our_in, '`')) {
		quote = '\0';
		rules = &bareword_unquoted;
		goto parse;
	/*
	 *	We _sometimes_ support backticks, depending on the
	 *	source of the data.  This should ONLY be used on
	 *	trusted input, like config files.
	 *
	 *	We don't impose arbitrary limits on exec input or
	 *	output, as AGAIN this should only be used on trusted
	 *	input.
	 *
	 *	Only the first line of output from the process is used,
	 *	and no escape sequences in the output are processed.
	 */
	} else {
		fr_sbuff_t		*exec_in;
		size_t			exec_out_buff_len = 0;
		ssize_t			exec_out_len;
		char			*exec_out = NULL;
		FILE			*fp;
		int			ret;

		if (!conf->allow_exec) {
			fr_strerror_const("Backticks are not supported here");
			return 0;
		}

		/*
		 *	Should only be used for trusted resources, so no artificial limits
		 */
		FR_SBUFF_TALLOC_THREAD_LOCAL(&exec_in, 1024, SIZE_MAX);
		(void)fr_sbuff_out_unescape_until(exec_in, &our_in, SIZE_MAX, &FR_SBUFF_TERMS(L("`")), &fr_value_unescape_backtick);
		/*
		 *	Don't exec if we know we're going to fail
		 */
		if (!fr_sbuff_is_char(&our_in, '`')) {
			fr_strerror_const("Unterminated backtick string");
			return 0;
		}

		fp = popen(fr_sbuff_start(exec_in), "r");
		if (!fp) {
			fr_strerror_printf("Cannot execute command `%pV`: %s",
					   fr_box_strvalue_len(fr_sbuff_start(exec_in), fr_sbuff_used(exec_in)),
					   fr_syserror(errno));
			return 0;
		}

		errno = 0; /* If we get EOF immediately, we don't want to emit spurious errors */
		exec_out_len = getline(&exec_out, &exec_out_buff_len, fp);
		if ((exec_out_len < 0) || (exec_out == NULL)) { /* defensive */
			fr_strerror_printf("Cannot read output from command `%pV`: %s",
					   fr_box_strvalue_len(fr_sbuff_start(exec_in), fr_sbuff_used(exec_in)),
					   fr_syserror(errno));
			pclose(fp);
			return 0;
		}

		/*
		 *	Protect against child writing too much data to stdout,
		 *	blocking, and never exiting.
		 *
		 *	This is likely overly cautious for this particular use
		 *	case, but it doesn't hurt.
		 */
		{
			char buffer[128];

			while (fread(buffer, 1, sizeof(buffer), fp) > 0) { /* discard */ }
		}

		errno = 0;	/* ensure we don't have stale errno */
		ret = pclose(fp);
		if (ret < 0) {
			fr_strerror_printf("Error waiting for command `%pV` to finish: %s",
					   fr_box_strvalue_len(fr_sbuff_start(exec_in), fr_sbuff_used(exec_in)),
					   fr_syserror(errno));
		pclose_error:
			free(exec_out);
			return 0;
		} else if (ret != 0) {
			if (WIFEXITED(ret)) {
				fr_strerror_printf("Command `%pV` exited with status %d",
						  fr_box_strvalue_len(fr_sbuff_start(exec_in), fr_sbuff_used(exec_in)),
						  WEXITSTATUS(ret));
			} else if (WIFSIGNALED(ret)) {
				fr_strerror_printf("Command `%pV` terminated by signal %d",
						   fr_box_strvalue_len(fr_sbuff_start(exec_in), fr_sbuff_used(exec_in)),
						   WTERMSIG(ret));
			} else {
				fr_strerror_printf("Command `%pV` terminated abnormally",
						   fr_box_strvalue_len(fr_sbuff_start(exec_in), fr_sbuff_used(exec_in)));
			}
			goto pclose_error;
		}

		/*
		 *	Trim line endings
		 */
		if (exec_out_len > 0 && exec_out[exec_out_len - 1] == '\n') exec_out[--exec_out_len] = '\0';
		if (exec_out_len > 0 && exec_out[exec_out_len - 1] == '\r') exec_out[--exec_out_len] = '\0';

		slen = fr_value_box_from_substr(vp, &vp->data, vp->da->type, vp->da,
						&FR_SBUFF_IN(exec_out, exec_out_len), &value_parse_rules_single_quoted);
		free(exec_out);
		if (unlikely(slen < 0)) {
			return 0; /* slen is parse position in the exec output*/
		}

		quote = '`';
	}

	if (slen < 0) {
		fr_assert(slen >= -((ssize_t) 1 << 20));
		return slen - (quote != 0);
	}

	if (quote && !fr_sbuff_next_if_char(&our_in, quote)) {
		fr_strerror_const("Unterminated string");
		return 0;
	}

	fr_assert(slen <= ((ssize_t) 1 << 20));

	FR_SBUFF_SET_RETURN(in, &our_in);
}

/** Our version of a DA stack.
 *
 *	@todo - add in whether or not we added / created the vp?  maybe an edit list?
 *	and then we can clean up the unknown DAs, simply by talloc freeing the edit list.
 */
typedef struct {
	int depth;
	fr_dict_attr_t const	*da[FR_DICT_MAX_TLV_STACK];	//!< parent for parsing
	fr_pair_t		*vp[FR_DICT_MAX_TLV_STACK];	//!< which VP we have created or found
} legacy_da_stack_t;

/**  Parse a #fr_pair_list_t from a substring
 *
 *	Syntax: ([raw.]|.)<name>[<.name>] op [(cast)] value...
 *
 *	A "raw" prefix creates a raw attribute, which allows us to encode raw data which might be invalid for
 *	the given data type.  Or if a "(cast)" is given, the value is parsed as the specified data type.  Note
 *	that casts can only be to a "leaf" data type, and not to a structural type such as "tlv", "group",
 *	"struct", etc.  The "(cast)" syntax can only be used for "raw" attributes, and not for attributes
 *	which are known.  The "name" can be either a known attribute, or a numerical OID.  Either way, the
 *	final attribute which is created is marked as "raw" or "unknown", and is encoded via the "raw" rules,
 *	and not as the known data type.
 *
 *	If the first name begins with ".", then it is a _relative_ name.  The attribute is created in the
 *	context of the most recently created "structural" data type.
 *
 *	TBD - we have to determine what the heck that means...
 *
 *	The "name" can be one or more names from the input dictionary.  The names must be known, as numerical
 *	OIDs can only be used when the "raw" prefix is used.
 *
 *	If there are multiple names (e.g. "foo.bar.baz"), then only the last name can be a "leaf" data
 *	type.  All of the intermediate names must be "structural" data types.
 *
 *	Depending on the input arguments, the operator can be a comparison operator (==, <=, etc.).  Or, else
 *	it can be an assignment operator (=, +=).  The "=" operator is used to assign, and the "+=" operator
 *	is used to append.  No other assignment operators are permitted.  Note that "+=" cannot be used with
 *	relative names (i.e. where the name begins with ".")
 *
 *	The "value" can either be a "leaf" data type (e.g. number, IP address, etc.) or for "structural" data
 *	types it can be a sub-list.  A sub-list is a set of attribute assignments which are surrounded by
 *	curly brackets "{...}".  When a sub-list is specified, the contents must be either children of the
 *	parent attribute (for "tlv", "struct"), or children referenced by a "group", or internal attributes.
 *
 *	If an intermediate "name" is an ALIAS, then the attributes are created / used as if all intermediate
 *	names were specified.  i.e. ALIAS is a short-cut for names (think "soft link), but it does not change
 *	the hierarchy for normal attributes.
 *
 *
 *	Examples
 *	--------
 *
 *	Name = value
 *		Leaf attributes.
 *		The value MUST be parsed as the leaf data type.
 *
 *	Name = { children }
 *		Structural attributes.
 *		The children MUST be children of the parent.
 *		OR the children can be from the "internal" dictionary.
 *		OR for type 'group', children of the group reference (usually the dictionary root)
 *
 *	raw.Name = 0xabcdef
 *		Raw attributes.
 *		The value MUST be a hex string.
 *
 *	raw.Name = { children }
 *
 * @param[in] root	where we start parsing from
 * @param[in,out] relative where we left off, or where we should continue from
 * @param[in] in	input sbuff
 * @return
 *	- <0 on error
 *	- 0 on no input
 *	- >0 on how many bytes of input we read
 */
fr_slen_t fr_pair_list_afrom_substr(fr_pair_parse_t const *root, fr_pair_parse_t *relative,
				    fr_sbuff_t *in)
{
	int			i, components;
	bool			raw, was_unknown;
	bool			was_relative = false;
	bool			append;
	bool			keep_going;
	fr_type_t		raw_type;
	fr_token_t		op;
	fr_slen_t		slen;
	fr_pair_t		*vp;
	fr_pair_parse_t		my;
	fr_sbuff_marker_t	lhs_m, op_m, rhs_m;
	fr_sbuff_t		our_in = FR_SBUFF(in);
	legacy_da_stack_t      	da_stack = {};

	if (unlikely(!root->ctx)) {
		fr_strerror_const("Missing input context (fr_pair_parse_t)");
		return -1;
	}

	if (unlikely(!root->da)) {
		fr_strerror_const("Missing namespace attribute");
		return -1;
	}

	if (unlikely(!root->list)) {
		fr_strerror_const("Missing list");
		return -1;
	}

	fr_sbuff_adv_past_blank(&our_in, SIZE_MAX, NULL);

	if (fr_sbuff_remaining(&our_in) == 0) return 0;

	/*
	 *	Boot strap the relative references from the root.
	 *
	 *	The comparison operations are only used for internal tests, and should not be used by
	 *	administrators.  So we disallow them, unless the destination list is empty.  This check
	 *	prevents them from being used in administrative policies.
	 */
	if (!relative->da) {
		if (root->allow_compare && !fr_pair_list_empty(root->list)) {
			fr_strerror_const("Attribute comparisons can only be used when the destination list is empty");
			return -1;
		}

		*relative = *root;
	}

#define CLEAN_DA_STACK do { if (was_unknown) {		\
	for (i = 1; i < da_stack.depth; i++) {		\
		fr_dict_attr_unknown_free(&da_stack.da[i]); \
	} } } while (0)


redo:
	raw = false;
	raw_type = FR_TYPE_NULL;
	relative->last_char = 0;
	was_unknown = false;
	vp = NULL;

	fr_sbuff_adv_past_blank(&our_in, SIZE_MAX, NULL);

	/*
	 *	STEP 1: Figure out if we have relative or absolute attributes.
	 *
	 *	Absolute attributes start from the root list / parent.
	 *	Or, when there is no previous relative setting.
	 *
	 *	Relative attributes start from the input list / parent.
	 *
	 *	Once we decide where we start parsing from, all subsequent operations are on the "relative"
	 *	structure.
	 */
	if (!fr_sbuff_next_if_char(&our_in, '.')) {
		*relative = *root;

		append = !was_relative;
		was_relative = false;

		/*
		 *	Be nice to people who expect to use '&' everywhere.
		 */
		(void) fr_sbuff_next_if_char(&our_in, '&');

		/*
		 *	Raw attributes can only be at our root.
		 *
		 *	"raw.foo" means that SOME component of the OID is raw.  But the starting bits might be known.
		 *
		 *	Raw attributes cannot be created in the internal namespace.  But an internal group can
		 *	contain raw protocol attributes.
		 */
		if (fr_sbuff_is_str_literal(&our_in, "raw.")) {
			fr_sbuff_advance(&our_in, 4);
			goto is_raw;
		}

	} else if (relative->da->flags.is_root) {
		fr_strerror_const("The '.Attribute' syntax cannot be used at the root of a dictionary");

	error:
		CLEAN_DA_STACK;
		return fr_sbuff_error(&our_in);

	} else if (relative->da->type == FR_TYPE_GROUP) {
		fr_strerror_printf("The '.Attribute' syntax cannot be used with parent %s of data type 'group'",
				   relative->da->name);
		goto error;

	} else {
		fr_assert(relative->ctx);
		fr_assert(relative->list);

		was_relative = true;
		append = true;
	}

	/*
	 *	If the input root is an unknown attribute, then forbid internal ones, and force everything
	 *	else to be raw, too.
	 */
	if (relative->da->flags.is_unknown) {
	is_raw:
		raw = true;
	}

	/*
	 *	Raw internal attributes don't make sense.  An internal group can contain raw protocol
	 *	attributes, but the group is not raw.
	 */
	if (raw && relative->da->flags.internal) {
		fr_strerror_const("Cannot create internal attributes which are 'raw'");
		goto error;
	}

	/*
	 *	Set the LHS marker to be after any initial '.'
	 */
	fr_sbuff_marker(&lhs_m, &our_in);

	/*
	 *	STEP 2: Find and check the operator.
	 *
	 *	Skip over the attribute name.  We need to get the operator _before_ creating the VPs.
	 */
	components = 0;
	do {
		if (fr_sbuff_adv_past_allowed(&our_in, SIZE_MAX, fr_dict_attr_allowed_chars, NULL) == 0) break;
		components++;
	} while (fr_sbuff_next_if_char(&our_in, '.'));

	/*
	 *	Couldn't find anything.
	 */
	if (!components) goto done;

	fr_sbuff_marker(&op_m, &our_in);
	fr_sbuff_adv_past_blank(&our_in, SIZE_MAX, NULL);

	/*
	 *	Look for the operator.
	 */
	if (relative->allow_compare) {
		fr_sbuff_out_by_longest_prefix(&slen, &op, pair_comparison_op_table, &our_in, T_INVALID);
		if (op == T_INVALID) {
			fr_strerror_const("Expecting operator");
			goto error;
		}

		/*
		 *	People can use this, but it doesn't mean anything.
		 */
		if (op == T_OP_SET) op = T_OP_EQ;

	} else {
		/*
		 *	@todo - handle different operators ala v3?
		 *	What is the difference between ":=" and "="?  Perhaps nothing?
		 */
		fr_sbuff_out_by_longest_prefix(&slen, &op, pair_assignment_op_table, &our_in, T_INVALID);
		if (op == T_INVALID) {
			fr_strerror_const("Expecting operator");
			goto error;
		}

		/*
		 *	+= means "append"
		 *	:= menas "don't append".
		 */
		if (op != T_OP_EQ) {
			if (was_relative) {
				fr_strerror_printf("The '.Attribute' syntax cannot be used along with the '%s' operator",
						   fr_tokens[op]);
				goto error;
			}
		}

		if (op == T_OP_ADD_EQ) {
			append = true;
		}

		if (op == T_OP_SET) {
			append = false;
		}

		op = T_OP_EQ;
	}

	/*
	 *	Check the character after the operator.  This check is only necessary to produce better error
	 *	messages.  i.e. We allow "=", but the user enters "==".
	 */
	{
		uint8_t c = fr_sbuff_char(&our_in, '\0');
		static const bool invalid[UINT8_MAX + 1] = {
			['!'] = true, ['#'] = true, ['$'] = true, ['*'] = true,
			['+'] = true, ['-'] = true, ['/'] = true, ['<'] = true,
			['='] = true, ['>'] = true, ['?'] = true, ['|'] = true,
			['~'] = true,
		};

		if (c && invalid[c]) {
			fr_strerror_printf("Invalid character '%c' after operator '%s'",
					   (char) c, fr_tokens[op]);
			goto error;
		}
	}

	/*
	 *	Skip past whitespace, and set a marker at the RHS value.  We do a quick peek at the value, to
	 *	set the data type of the RHS.  This allows us to parse raw TLVs.
	 */
	fr_sbuff_adv_past_blank(&our_in, SIZE_MAX, NULL);

	/*
	 *	STEP 3: Try to guess the data type for "raw" attributes.
	 *
	 *	If the attribute is raw, and the value of the attribute is 0x..., then we always force the raw
	 *	type to be octets, even if the attribute is named and known.  e.g. raw.Framed-IP-Address =
	 *	0x01.
	 *
	 *	OR if the attribute is entirely unknown (and not a raw version of a known one), then we allow a
	 *	cast which sets the data type.
	 */
	if (raw) {
		if (fr_sbuff_is_str_literal(&our_in, "0x")) {
			raw_type = FR_TYPE_OCTETS;

		} else if (fr_sbuff_next_if_char(&our_in, '(')) {
			fr_sbuff_marker(&rhs_m, &our_in);

			fr_sbuff_out_by_longest_prefix(&slen, &raw_type, fr_type_table, &our_in, FR_TYPE_NULL);

			/*
			 *	The input has to be a real (non-NULL) leaf.  The input shouldn't be cast to a
			 *	TLV.  Instead, the value should just start with '{'.
			 */
			if (!fr_type_is_leaf(raw_type)) {
				fr_sbuff_set(&our_in, &rhs_m);
				fr_strerror_const("Invalid data type in cast");
				goto error;
			}

			if (!fr_sbuff_next_if_char(&our_in, ')')) {
				fr_strerror_const("Missing ')' in cast");
				goto error;
			}

			fr_sbuff_adv_past_blank(&our_in, SIZE_MAX, NULL);

		} else if (fr_sbuff_is_char(&our_in, '{')) {
			/*
			 *	Raw attributes default to data type TLV.
			 */
			raw_type = FR_TYPE_TLV;
			append = false;
		}
	}

	fr_sbuff_marker(&rhs_m, &our_in);

	fr_sbuff_set(&our_in, &lhs_m);

	/*
	 *	That we know the data type, parse each OID component.  We build the DA stack from top to bottom.
	 *
	 *	0 is our relative root.  1..N are the DAs that we find or create.
	 */
	da_stack = (legacy_da_stack_t) {
		.da = {
			[0] = relative->da,
		},
		.depth = 1,
	};

	/*
	 *	STEP 4: Re-parse the attributes, building up the da_stack of #fr_dict_attr_t that we will be
	 *	using as parents.
	 */
	for (i = 1; i <= components; i++, da_stack.depth++) {
		fr_dict_attr_err_t	err;
		fr_dict_attr_t const	*da = NULL;
		fr_dict_attr_t const	*da_unknown = NULL;
		fr_dict_attr_t const	*parent;
		fr_dict_attr_t const	*ref;
		fr_type_t		unknown_type;

		if (da_stack.depth >= FR_DICT_MAX_TLV_STACK) {
			fr_strerror_printf("Attributes are nested too deeply at \"%.*s\"",
					   (int) fr_sbuff_diff(&op_m, &lhs_m), fr_sbuff_current(&lhs_m));
			goto error;
		}

		fr_sbuff_marker(&lhs_m, &our_in);

		/*
		 *	The fr_pair_t parent might be a group, in which case the fr_dict_attr_t parent will be
		 *	different.
		 */
		parent = da_stack.da[da_stack.depth - 1];
		if (parent->type == FR_TYPE_GROUP) {
			parent = fr_dict_attr_ref(parent);
			fr_assert(parent != NULL);
		}

		/*
		 *	Once we parse a completely unknown attribute, all of the rest of them have to be
		 *	unknown, too.  We cannot allow unknown TLVs to contain internal attributes, for
		 *	example.
		 */
		if (was_unknown) {
			goto alloc_unknown;
		}

		/*
		 *	Look up the name (or number).  If it's found, life is easy.  Otherwise, we jump
		 *	through a bunch of hoops to see if we are changing dictionaries, or creating a raw OID
		 *	from a number, etc.
		 */
		slen = fr_dict_oid_component(&err, &da, parent, &our_in, &bareword_terminals);
		if (err != FR_DICT_ATTR_OK) {
			/*
			 *	We were looking in the internal dictionary.  Maybe this attribute is instead
			 *	in the protocol dictionary?
			 */
			if ((i == 1) && (relative->da->dict == relative->internal) && relative->dict) {
				fr_assert(relative->dict != relative->internal);

				/*
				 *	Internal groups can be used to cache protocol data.  Internal
				 *	structural attributes cannot.
				 *
				 *	@todo - this restriction makes sense, but maybe people want to do that
				 *	anyways?
				 */
				if (relative->da->type != FR_TYPE_GROUP) {
					fr_strerror_printf("Internal attribute '%s' of data type '%s' cannot contain protocol attributes",
							   relative->da->name, fr_type_to_str(relative->da->type));
					goto error;
				}

				slen = fr_dict_oid_component(&err, &da, fr_dict_root(relative->dict), &our_in, &bareword_terminals);
				if (err == FR_DICT_ATTR_OK) {
					ref = fr_dict_root(relative->dict);
					goto found;
				}
			}

			/*
			 *	Try to parse the name from the internal namespace first, as this is the most
			 *	likely case.  Plus, if we parse the OIDs second, the errors for unknown
			 *	attributes mention the protocol dictionary, and not the internal one.
			 *
			 *	Raw attributes also cannot be created in the internal dictionary space.
			 */
			if (!raw && relative->internal) {
				/*
				 *	If the current dictionary isn't internal, then look up the attribute
				 *	in the internal dictionary.
				 *
				 *	Buf if the current dictionary is internal, AND the internal type is
				 *	GROUP, AND we we have a protocol dictionary, then allow an internal
				 *	group to contain protocol attributes.
				 */
				if (parent->dict != relative->internal) {
					ref = fr_dict_root(relative->internal);

				} else if ((da_stack.da[da_stack.depth - 1]->type == FR_TYPE_GROUP) && (root->da->dict != root->internal)) {
					ref = fr_dict_root(root->da->dict);

				} else {
					/*
					 *	Otherwise we are already in the internal dictionary, and the
					 *	attribute was not found.  So don't search for it again in the
					 *	internal dictionary.  And because we're in the internal
					 *	dictionary, we don't allow raw attributes.
					 */
					goto notfound;
				}

				slen = fr_dict_oid_component(&err, &da, ref, &our_in, &bareword_terminals);
				if (err == FR_DICT_ATTR_OK) {
					goto found;
				}

				goto notfound;
			}

			/*
			 *	We didn't find anything, that's an error.
			 */
			if (!raw) {
			notfound:
				fr_strerror_printf("Unknown attribute \"%.*s\" for parent \"%s\"",
						   (int) fr_sbuff_diff(&op_m, &our_in), fr_sbuff_current(&our_in),
						   da_stack.da[da_stack.depth - 1]->name);
				goto error;
			}

		alloc_unknown:
			/*
			 *	We looked up raw.FOO, and FOO wasn't found.  See if we can still parse it.
			 */
			if (da_stack.da[da_stack.depth - 1]->type == FR_TYPE_GROUP) {
				fr_strerror_printf("Cannot create 'raw' children in attribute %s of data type 'group'",
						   da_stack.da[da_stack.depth - 1]->name);
				goto error;
			}

			/*
			 *	Unknown attributes must be 'raw.1234'.
			 */
			if (!fr_sbuff_is_digit(&our_in)) {
				goto notfound;
			}

			/*
			 *	Figure out the data type for unknown attributes.  Intermediate attributes are
			 *	structural.  Only the final attribute is forced to "raw_type".
			 */
			if (i < components) {
				if (parent->type == FR_TYPE_VSA) {
					unknown_type = FR_TYPE_VENDOR;
				} else {
					unknown_type = FR_TYPE_TLV;
				}

			} else if (raw_type == FR_TYPE_NULL) {
				unknown_type = FR_TYPE_OCTETS;

			} else if ((raw_type == FR_TYPE_TLV) && (parent->type == FR_TYPE_VSA)) {
				/*
				 *	We had previously parsed a known VSA, but this component is
				 *	perhaps a numerical OID.  Set the data type to VENDOR, so that
				 *	the hierachy is correct.
				 */
				unknown_type = FR_TYPE_VENDOR;

			} else {
				unknown_type = raw_type;
			}

			da_unknown = fr_dict_attr_unknown_afrom_oid(root->ctx, parent, &our_in, unknown_type);
			if (!da_unknown) goto error;

			da = da_unknown;
			was_unknown = true;

			goto next;
		} /* huge block of "we didn't find a known attribute" */

		/*
		 *	We found the component.  It MIGHT be an ALIAS which jumps down a few levels.  Or, it
		 *	might be a group which jumps back to the dictionary root.  Or it may suddenly be an
		 *	internal attribute.
		 *
		 *	For an ALIAS, we need to add intermediate nodes up to the parent.
		 *
		 *	For a GROUP, we need to add nodes up to the ref of the group.
		 *
		 *	For internal attributes, we need to add nodes up to the root of the internal
		 *	dictionary.
		 */
		if (da->parent != parent) {
			int j, diff;
			fr_dict_attr_t const *up;

			ref = parent;

		found:
			fr_assert(fr_dict_attr_common_parent(ref, da, true) == ref);

			diff = da->depth - ref->depth;
			fr_assert(diff >= 1);

			diff--;

			if ((da_stack.depth + diff) >= FR_DICT_MAX_TLV_STACK) {
				fr_strerror_printf("Attributes are nested too deeply at \"%.*s\"",
						   (int) fr_sbuff_diff(&op_m, &lhs_m), fr_sbuff_current(&lhs_m));
				goto error;
			}

			/*
			 *	Go back up the da_stack, setting the parent.
			 */
			up = da;
			for (j = da_stack.depth + diff; j >= da_stack.depth; j--) {
				da_stack.da[j] = up;
				up = up->parent;
			}

			for (j = da_stack.depth; j <= da_stack.depth + diff; j++) {
				fr_assert(da_stack.da[j] != NULL);
			}

			/*
			 *	Record that we've added more attributes to the da_stack.
			 */
			da_stack.depth += diff;
		}

	next:
		/*
		 *	Limit the data types that we can parse.  This check is mainly to get better error
		 *	messages.
		 */
		switch (da->type) {
		case FR_TYPE_GROUP:
			if (raw && (raw_type != FR_TYPE_OCTETS)) {
				fr_strerror_printf("Cannot create 'raw' attributes for data type '%s'", fr_type_to_str(da->type));
				goto error;
			}
			break;

		case FR_TYPE_STRUCTURAL_EXCEPT_GROUP:
		case FR_TYPE_LEAF:
			break;

		default:
			fr_strerror_printf("Invalid data type '%s'", fr_type_to_str(da->type));
			goto error;
		}

		/*
		 *	Everything until the last component must end with a '.', because otherwise there would
		 *	be no next component.
		 */
		if (i < components) {
			if (!fr_sbuff_next_if_char(&our_in, '.')) {
				fr_strerror_printf("Missing '.' at \"%.*s\"",
						   (int) fr_sbuff_diff(&op_m, &lhs_m), fr_sbuff_current(&lhs_m));
				goto error;
			}

			/*
			 *	Leaf attributes cannot appear in the middle of the OID list.
			 */
			if (fr_type_is_leaf(da->type)) {
				if (fr_dict_attr_is_key_field(da)) {
					fr_strerror_printf("Please remove the reference to key field '%s' from the input string",
							   da->name);
				} else {
					fr_strerror_printf("Leaf attribute '%s' cannot have children", da->name);
				}

				goto error;
			}

		} else if (raw && !da->flags.is_unknown) {
			/*
			 *	Only the last component can be raw.  If the attribute we found isn't unknown,
			 *	then create an unknown DA from the known one.
			 *
			 *	We have parsed the full OID tree, *and* found a known attribute.  e.g. raw.Vendor-Specific = ...
			 *
			 *	For some reason, we allow: raw.Vendor-Specific = { ... }
			 *
			 *	But this is what we really want: raw.Vendor-Specific = 0xabcdef
			 */
			if ((raw_type != FR_TYPE_OCTETS) && (raw_type != da->type)) {
				/*
				 *	@todo - because it breaks a lot of the encoders.
				 */
				fr_strerror_printf("Cannot create raw attribute %s which changes data type from %s to %s",
						   da->name, fr_type_to_str(da->type), fr_type_to_str(raw_type));
				fr_sbuff_set(&our_in, &lhs_m);
				goto error;
			}

			da_unknown = fr_dict_attr_unknown_alloc(root->ctx, da, raw_type);
			if (!da_unknown) goto error;

			da = da_unknown;
			was_unknown = true;
		}

		da_stack.da[da_stack.depth] = da;
	}

	/*
	 *	at least [0]=root, [1]=da, [2]=NULL
	 */
	if (da_stack.depth <= 1) {
		fr_strerror_const("Internal sanity check failed on depth 1");
		return fr_sbuff_error(&our_in);
	}

	if (da_stack.depth <= components) {
		fr_strerror_const("Internal sanity check failed on depth 2");
		return fr_sbuff_error(&our_in);
	}

	/*
	 *	STEP 5: Reset the parser to the value, and double-check if it's what we expect.
	 */
	fr_sbuff_set(&our_in, &rhs_m);

	if (fr_type_is_structural(da_stack.da[da_stack.depth - 1]->type)) {
		if (!fr_sbuff_is_char(&our_in, '{')) {
			fr_strerror_printf("Group list for %s MUST start with '{'", da_stack.da[da_stack.depth - 1]->name);
			goto error;
		}

		/*
		 *	The fr_pair_validate() function doesn't support operators for structural attributes,
		 *	so we forbid them here.
		 */
		if (relative->allow_compare && (op != T_OP_EQ) && (op != T_OP_CMP_EQ)) {
			fr_strerror_printf("Structural attribute '%s' must use '=' or '==' for comparisons",
					   da_stack.da[da_stack.depth - 1]->name);
			goto error;
		}

		/*
		 *	If we have "foo = { ... }", then we just create the attribute.
		 */
		if (components == 1) append = (op != T_OP_EQ);
	}

#if 0
	/*
	 *	STEP 5.1: Flatten the hierarchy if necessary.
	 */
	if ((relative->da->flags.allow_flat) && (da_stack.depth > 2)) {
		da_stack.da[1] = da_stack.da[da_stack.depth - 1];

		da_stack.depth = 2;
	}
#endif

	/*
	 *	STEP 6: Use the da_stack to either find or add intermediate #fr_pair_t.
	 */
	my = *relative;
	for (i = 1; i < da_stack.depth; i++) {
		fr_dict_attr_t const *da;

		da = da_stack.da[i];

		/*
		 *	When we have a full path that contains MEMBERs of a STRUCT, we need to check ordering.
		 *	The children MUST be added in order.  If we see a child that is out of order, then
		 *	that means we need to start a new parent STRUCT.
		 */
		if ((da->parent->type == FR_TYPE_STRUCT) && (i > 1)) {
			fr_assert(da_stack.da[i - 1] == da->parent);
			fr_assert(da_stack.vp[i - 1] != NULL);
			fr_assert(my.ctx == da_stack.vp[i - 1]);

			/*
			 *	@todo - cache the last previous child that we added?  Or maybe the DA of the
			 *	last child?
			 */
			for (vp = fr_pair_list_tail(my.list);
			     vp != NULL;
			     vp = fr_pair_list_prev(my.list, vp)) {
				if (!vp->da->flags.internal) break;
			}

			if (vp && (vp->da->attr > da->attr)) {
				fr_pair_t *parent = da_stack.vp[i - 2];

				if (parent) {
					if (fr_pair_append_by_da(parent, &vp, &parent->vp_group, da->parent) < 0) {
						goto error;
					}
				} else {
					if (fr_pair_append_by_da(root->ctx, &vp, root->list, da->parent) < 0) {
						goto error;
					}
				}

				vp->op = T_OP_EQ;
				PAIR_ALLOCED(vp);
				my.ctx = vp;
				my.list = &vp->vp_group;
			}
		}

		/*
		 *	Everything up to the last entry must be structural.
		 *
		 *	The last entry may be structural, or else it might be a leaf.
		 */
		if (fr_type_is_structural(da->type)) {
			if (append) {
				vp = fr_pair_find_last_by_da(my.list, NULL, da);
				if (vp) goto update_relative;
			}

			if (fr_pair_append_by_da(my.ctx, &vp, my.list, da) < 0) {
				goto error;
			}

			vp->op = T_OP_EQ;
			PAIR_ALLOCED(vp);

		update_relative:
			da_stack.vp[i] = vp;

			my.ctx = vp;
			my.da = vp->da;
			my.list = &vp->vp_group;
			continue;
		}

		/*
		 *	We're finally at the leaf attribute, which must be the last attribute.
		 */
		fr_assert(i == (da_stack.depth - 1));

		vp = fr_pair_afrom_da(my.ctx, da);
		if (!vp) goto error;

		PAIR_ALLOCED(vp);
		vp->op = op;
		da_stack.vp[i] = vp;
	}

	/*
	 *	Intermediate nodes always use the operator '='.  The final one uses the assigned operator.
	 */
	fr_assert(vp != NULL);
	fr_assert(vp->op != T_INVALID);

	/*
	 *	STEP 7: Parse the value, recursing if necessary.
	 *
	 *	@todo - do all kinds of cleanups if anything fails.  TBH, this really needs the edit lists,
	 *	and that might be a bit much overhead for this code.
	 */
	if (fr_type_is_structural(vp->da->type)) {
		fr_pair_parse_t child = (fr_pair_parse_t) {
			.allow_compare = root->allow_compare,
			.dict = root->dict,
			.internal = root->internal,
		};

		if (!fr_sbuff_next_if_char(&our_in, '{')) {
			fr_strerror_printf("Child list for %s MUST start with '{'", vp->da->name);
			goto error;
		}

		fr_assert(my.ctx == vp);
		fr_assert(my.da == vp->da);
		fr_assert(my.list == &vp->vp_group);
		my.allow_compare = root->allow_compare;
		my.end_of_list = true;

		while (true) {
			fr_sbuff_adv_past_blank(&our_in, SIZE_MAX, NULL);

			if (fr_sbuff_is_char(&our_in, '}')) {
				break;
			}

			slen = fr_pair_list_afrom_substr(&my, &child, &our_in);
			if (!slen) break;

			if (slen < 0) goto error;
		}

		if (!fr_sbuff_next_if_char(&our_in, '}')) {
			fr_strerror_const("Failed to end list with '}'");
			goto error;
		}

		/*
		 *	This structure was the last thing we parsed.  The next thing starts from here.
		 */
		*relative = my;

	} else {
		slen = fr_pair_value_from_substr(root, vp, &our_in);
		if (slen <= 0) goto error;

		fr_pair_append(my.list, vp);
	}

	PAIR_VERIFY(vp);

	CLEAN_DA_STACK;

	fr_sbuff_adv_past_blank(&our_in, SIZE_MAX, NULL);

	/*
	 *	STEP 8: See if we're done, or if we need to stop parsing this #fr_pair_t.
	 *
	 *	Allow a limited set of characters after a value.
	 *
	 *	It can be "," OR "CRLF" OR ",CRLF".  But not anything else.
	 */
	keep_going = false;
	if (fr_sbuff_next_if_char(&our_in, ',')) {
		fr_sbuff_adv_past_blank(&our_in, SIZE_MAX, NULL);

		keep_going = true;
		relative->last_char = ',';
	}

	/*
	 *	We hit the end of the parent list.  There's no need to update "relative", we just return, and
	 *	let the caller end the list.
	 *
	 *	Note that we allow trailing commas:  Foo = { Bar = Baz, }
	 *
	 *	We don't care about any trailing data.
	 */
	if (relative->end_of_list && fr_sbuff_is_char(&our_in, '}')) {
		relative->last_char = '\0';
		goto done;
	}

	if (relative->allow_crlf) {
		size_t len;

		len = fr_sbuff_adv_past_allowed(&our_in, SIZE_MAX, sbuff_char_line_endings, NULL);
		if (len) {
			keep_going = true;
			if (!relative->last_char) relative->last_char = '\n';
		}
	}

	/*
	 *	This is mainly for the detail file reader.  We allow zeros as end of "attr op value".  But we
	 *	also treat zeros as "don't keep going".
	 */
	if (relative->allow_zeros) {
		while (fr_sbuff_next_if_char(&our_in, '\0')) {
			/* nothing */
		}

		goto done;
	}

	/*
	 *	There's no more input, we're done.  Any next attributes will cause the input to be parsed from
	 *	the root again.
	 */
	(void) fr_sbuff_extend(&our_in);
	if (!fr_sbuff_remaining(&our_in)) goto done;

	/*
	 *	STEP 9: If we need to keep going, then set up the relative references based on what we've
	 *	done, and go back to start over again.
	 *
	 *	The caller is responsible for checking whether or not we have too much data.
	 */
	if (keep_going) {
		/*
		 *	Update the relative list for parsing the next pair.
		 */
		if (fr_type_is_leaf(vp->da->type)) {
			fr_pair_t *parent;

			parent = fr_pair_parent(vp);
			if (!parent) {
				*relative = *root;

			} else {
				relative->ctx = parent;
				relative->da = parent->da;
				relative->list = &parent->vp_group;
			}

		} else {
			relative->ctx = vp;
			relative->da = vp->da;
			relative->list = &vp->vp_group;
		}

		goto redo;
	}

	/*
	 *	STEP 10: Complain if we have unexpected input.
	 *
	 *	We have more input, BUT we didn't have a comma or CRLF to explicitly finish the last pair we
	 *	read.  That's a problem.
	 */
	if (!relative->last_char) {
		size_t remaining;

		remaining = fr_sbuff_remaining(&our_in);

		if (remaining > 20) remaining = 20;

		fr_strerror_printf("Unexpected text '%.*s ...' after value",
				   (int) remaining, fr_sbuff_current(&our_in));
		return fr_sbuff_error(&our_in); /* da_stack has already been cleaned */
	}

done:
	/*
	 *	STEP 11: Finally done.
	 */
	FR_SBUFF_SET_RETURN(in, &our_in);
}

/** Read valuepairs from the fp up to End-Of-File.
 *
 * @param[in] ctx		for talloc
 * @param[in] dict		to resolve attributes in.
 * @param[in,out] out		where the parsed fr_pair_ts will be appended.
 * @param[in] fp		to read valuepairs from.
 * @param[out] pfiledone	true if file parsing complete;
 * @param[in] allow_exec	Whether we allow `backtick` expansions.
 * @return
 *	- 0 on success
 *	- -1 on error
 */
int fr_pair_list_afrom_file(TALLOC_CTX *ctx, fr_dict_t const *dict, fr_pair_list_t *out, FILE *fp, bool *pfiledone, bool allow_exec)
{
	fr_pair_list_t tmp_list;
	fr_pair_parse_t	root, relative;
	bool		found = false;
	char		buf[8192];

	/*
	 *	Read all of the attributes on the current line.
	 *
	 *	If we get nothing but an EOL, it's likely OK.
	 */
	fr_pair_list_init(&tmp_list);

	root = (fr_pair_parse_t) {
		.ctx = ctx,
		.da = fr_dict_root(dict),
		.list = &tmp_list,
		.dict = dict,
		.internal = fr_dict_internal(),
		.allow_crlf = true,
		.allow_compare = true,
		.allow_exec = allow_exec
	};
	relative = (fr_pair_parse_t) { };

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		/*
		 *      If we get a '\n' by itself, we assume that's
		 *      the end of that VP list.
		 */
		if ((buf[0] == '\n') || (buf[0] == '\r')) {
			if (found) {
				*pfiledone = false;
				break;
			}
			continue;
		}

		/*
		 *	Comments get ignored
		 */
		if (buf[0] == '#') continue;

		/*
		 *	Leave "relative" between calls, so that we can do:
		 *
		 *		foo = {}
		 *		.bar = baz
		 *
		 *	and get
		 *
		 *		foo = { bar = baz }
		 */
		if (fr_pair_list_afrom_substr(&root, &relative, &FR_SBUFF_IN_STR(buf)) < 0) {
			*pfiledone = false;
			fr_pair_list_free(&tmp_list);
			return -1;
		}

		found = true;
	}

#ifdef WITH_VERIFY_PTR
	fr_pair_list_verify(__FILE__, __LINE__, ctx, &tmp_list, true);
#endif

	fr_pair_list_append(out, &tmp_list);

	*pfiledone = true;
	return 0;
}


/** Move pairs from source list to destination list respecting operator
 *
 * @note This function does some additional magic that's probably not needed in most places. Consider using
 *	 radius_legacy_map_cmp() and radius_legacy_map_apply() instead.
 *
 * @note fr_pair_list_free should be called on the head of the source list to free
 *	 unmoved attributes (if they're no longer needed).
 *
 * @param[in,out] to destination list.
 * @param[in,out] from source list.
 * @param[in] op operator for list move.
 */
void fr_pair_list_move_op(fr_pair_list_t *to, fr_pair_list_t *from, fr_token_t op)
{
	fr_pair_t *vp, *next, *found;
	fr_pair_list_t head_append, head_prepend;

	if (!to || fr_pair_list_empty(from)) return;

	/*
	 *	We're editing the "to" list while we're adding new
	 *	attributes to it.  We don't want the new attributes to
	 *	be edited, so we create an intermediate list to hold
	 *	them during the editing process.
	 */
	fr_pair_list_init(&head_append);

	/*
	 *	Any attributes that are requested to be prepended
	 *	are added to a temporary list here
	 */
	fr_pair_list_init(&head_prepend);

	/*
	 *	We're looping over the "from" list, moving some
	 *	attributes out, but leaving others in place.
	 */
	for (vp = fr_pair_list_head(from); vp != NULL; vp = next) {
		PAIR_VERIFY(vp);
		next = fr_pair_list_next(from, vp);

		/*
		 *	We never move Fall-Through.
		 */
		if (fr_dict_attr_is_top_level(vp->da) && (vp->da->attr == FR_FALL_THROUGH) &&
		    (fr_dict_by_da(vp->da) == fr_dict_internal())) {
			continue;
		}

		/*
		 *	Unlike previous versions, we treat all other
		 *	attributes as normal.  i.e. there's no special
		 *	treatment for passwords or Hint.
		 */

		switch (vp->op) {
		/*
		 *	Anything else are operators which
		 *	shouldn't occur.  We ignore them, and
		 *	leave them in place.
		 */
		default:
			continue;

		/*
		 *	Add it to the "to" list, but only if
		 *	it doesn't already exist.
		 */
		case T_OP_EQ:
			found = fr_pair_find_by_da(to, NULL, vp->da);
			if (!found) goto do_add;
			continue;

		/*
		 *	Add it to the "to" list, and delete any attribute
		 *	of the same vendor/attr which already exists.
		 */
		case T_OP_SET:
			found = fr_pair_find_by_da(to, NULL, vp->da);
			if (!found) goto do_add;

			/*
			 *	Delete *all* matching attributes.
			 */
			fr_pair_delete_by_da(to, found->da);
			goto do_add;

		/*
		 *	Move it from the old list and add it
		 *	to the new list.
		 */
		case T_OP_ADD_EQ:
	do_add:
			fr_pair_remove(from, vp);
			fr_pair_append(&head_append, vp);
			continue;

		case T_OP_PREPEND:
			fr_pair_remove(from, vp);
			fr_pair_prepend(&head_prepend, vp);
			continue;
		}
	} /* loop over the "from" list. */

	/*
	 *	If the op parameter was prepend, add the "new list
	 *	attributes first as those whose individual operator
	 *	is prepend should be prepended to the resulting list
	 */
	if (op == T_OP_PREPEND) fr_pair_list_prepend(to, &head_append);

	/*
	 *	If there are any items in the prepend list prepend
	 *	it to the "to" list
	 */
	fr_pair_list_prepend(to, &head_prepend);

	/*
	 *	If the op parameter was not prepend, take the "new"
	 *	list, and append it to the "to" list.
	 */
	if (op != T_OP_PREPEND) fr_pair_list_append(to, &head_append);

	fr_pair_list_free(from);
}
