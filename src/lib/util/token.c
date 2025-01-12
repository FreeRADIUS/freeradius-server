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

/** Tokenisation code and constants
 *
 * This is mostly for the attribute filter and user files.
 *
 * @file src/lib/util/token.c
 *
 * @copyright 2001,2006 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/token.h>

#include <ctype.h>

fr_table_num_ordered_t const fr_tokens_table[] = {
	{ L("=~"), 	T_OP_REG_EQ	}, /* order is important! */
	{ L("!~"),	T_OP_REG_NE	},
	{ L("{"),	T_LCBRACE	},
	{ L("}"),	T_RCBRACE	},
	{ L("("),	T_LBRACE	},
	{ L(")"),	T_RBRACE	},
	{ L(","),	T_COMMA		},
	{ L("++"),	T_OP_INCRM	},
	{ L("+="),	T_OP_ADD_EQ	},
	{ L("-="),	T_OP_SUB_EQ	},
	{ L(":="),	T_OP_SET	},
	{ L("=*"), 	T_OP_CMP_TRUE	},
	{ L("!*"), 	T_OP_CMP_FALSE	},
	{ L("=="),	T_OP_CMP_EQ	},
	{ L("==="),	T_OP_CMP_EQ_TYPE },
	{ L("^="),	T_OP_PREPEND	},
	{ L("|="),	T_OP_OR_EQ	},
	{ L("&="),	T_OP_AND_EQ	},
	{ L("="),	T_OP_EQ		},
	{ L("!="),	T_OP_NE		},
	{ L("!=="),	T_OP_CMP_NE_TYPE },
	{ L(">>="),	T_OP_RSHIFT_EQ	},
	{ L(">="),	T_OP_GE		},
	{ L(">"),	T_OP_GT		},
	{ L("<<="),	T_OP_LSHIFT_EQ	},
	{ L("<="),	T_OP_LE		},
	{ L("<"),	T_OP_LT		},
	{ L("#"),	T_HASH		},
	{ L(";"),	T_SEMICOLON	}
};
size_t fr_tokens_table_len = NUM_ELEMENTS(fr_tokens_table);

fr_table_num_sorted_t const fr_token_quotes_table[] = {
	{ L(""),	T_BARE_WORD		},
	{ L("'"),	T_SINGLE_QUOTED_STRING	},
	{ L("/"),	T_SOLIDUS_QUOTED_STRING	},
	{ L("\""),	T_DOUBLE_QUOTED_STRING	},
	{ L("`"),	T_BACK_QUOTED_STRING	}
};
size_t fr_token_quotes_table_len = NUM_ELEMENTS(fr_token_quotes_table);

/*
 *  String versions for all of the tokens.
 */
char const *fr_tokens[T_TOKEN_LAST] = {
	[T_INVALID] = "?",
	[T_EOL] = "EOL",

	[T_LCBRACE] = "{",
	[T_RCBRACE] = "}",
	[T_LBRACE] = "(",
	[T_RBRACE] = ")",
	[T_COMMA] = ",",
	[T_SEMICOLON] = ";",

	[T_ADD]	     = "+",
	[T_SUB]	     = "-",
	[T_MUL]	     = "*",
	[T_DIV]	     = "/",
	[T_AND]	     = "&",
	[T_OR]	     = "|",
	[T_NOT]	     = "!",
	[T_XOR]	     = "^",
	[T_COMPLEMENT]  = "~",
	[T_MOD]  = "%",

	[T_RSHIFT]   = ">>",
	[T_LSHIFT]   = "<<",

	[T_LAND]     = "&&",
	[T_LOR]	     = "||",

	[T_OP_INCRM] = "++",

	[T_OP_ADD_EQ] = "+=",
	[T_OP_SUB_EQ] = "-=",
	[T_OP_SET]    = ":=",
	[T_OP_EQ]     = "=",
	[T_OP_OR_EQ]  = "|=",
	[T_OP_AND_EQ]  = "&=",

	[T_OP_RSHIFT_EQ]   = ">>=",
	[T_OP_LSHIFT_EQ]   = "<<=",

	[T_OP_NE]     = "!=",
	[T_OP_GE]     = ">=",
	[T_OP_GT]     = ">",
	[T_OP_LE]     = "<=",
	[T_OP_LT]     = "<",
	[T_OP_REG_EQ] = "=~",
	[T_OP_REG_NE] = "!~",

	[T_OP_CMP_TRUE] = "=*",
	[T_OP_CMP_FALSE] = "!*",

	[T_OP_CMP_EQ] = "==",

	[T_OP_CMP_EQ_TYPE] = "===",
	[T_OP_CMP_NE_TYPE] = "!==",

	[T_OP_PREPEND] = "^=",

	[T_HASH]                  = "#",
	[T_BARE_WORD]             = "<BARE-WORD>",
	[T_DOUBLE_QUOTED_STRING]  = "<\"STRING\">",
	[T_SINGLE_QUOTED_STRING]  = "<'STRING'>",
	[T_BACK_QUOTED_STRING]    = "<`STRING`>",
	[T_SOLIDUS_QUOTED_STRING] = "</STRING/>",
};


/*
 *	This is fine.  Don't complain.
 */
#ifdef __clang__
#pragma clang diagnostic ignored "-Wgnu-designator"
#endif

/** Convert tokens back to a quoting character
 *
 * Non-string types convert to '?' to screw ups can be identified easily
 */
const char fr_token_quote[T_TOKEN_LAST] = {
	[ 0 ... T_HASH ] = '?',	/* GCC extension for range initialization, also allowed by clang */

	[T_BARE_WORD] = '\0',
	[T_DOUBLE_QUOTED_STRING] = '"',
	[T_SINGLE_QUOTED_STRING] = '\'',
	[T_BACK_QUOTED_STRING] = '`',
	[T_SOLIDUS_QUOTED_STRING] = '/',
};

#define T(_x) [T_OP_ ## _x] = true

const bool fr_assignment_op[T_TOKEN_LAST] = {
	T(INCRM),		/* only used by LDAP :( */

	T(ADD_EQ),
	T(SUB_EQ),
	T(MUL_EQ),
	T(DIV_EQ),
	T(AND_EQ),
	T(OR_EQ),
	T(RSHIFT_EQ),
	T(LSHIFT_EQ),

	T(SET),
	T(EQ),
	T(PREPEND),
};

const bool fr_list_assignment_op[T_TOKEN_LAST] = {
	T(ADD_EQ),		/* append */
	T(SUB_EQ),		/* remove */
	T(AND_EQ),		/* intersection */
	T(OR_EQ),		/* union */
	T(LE),			/* merge RHS */
	T(GE),			/* merge LHS */

	T(SET),
	T(EQ),
	T(PREPEND),		/* prepend */
};

const bool fr_comparison_op[T_TOKEN_LAST] = {
	T(NE),
	T(GE),
	T(GT),
	T(LE),
	T(LT),
	T(REG_EQ),
	T(REG_NE),
	T(CMP_TRUE),
	T(CMP_FALSE),
	T(CMP_EQ),
	T(CMP_EQ_TYPE),
	T(CMP_NE_TYPE),
};

#undef T
#define T(_x) [T_ ## _x] = true

const bool fr_binary_op[T_TOKEN_LAST] = {
	T(ADD),
	T(SUB),
	T(MUL),
	T(DIV),
	T(AND),
	T(OR),
	T(MOD),
	T(RSHIFT),
	T(LSHIFT),
};


#undef T
#define T(_x) [T_## _x] = true
const bool fr_str_tok[T_TOKEN_LAST] = {
	T(BARE_WORD),
	T(DOUBLE_QUOTED_STRING),
	T(SINGLE_QUOTED_STRING),
	T(BACK_QUOTED_STRING),
};

/*
 *	This works only as long as special tokens
 *	are max. 2 characters, but it's fast.
 */
#define TOKEN_MATCH(bptr, tptr) \
	( (tptr)[0] == (bptr)[0] && \
	 ((tptr)[1] == (bptr)[1] || (tptr)[1] == 0))

/*
 *	Read a word from a buffer and advance pointer.
 *	This function knows about escapes and quotes.
 *
 *	At end-of-line, buf[0] is set to '\0'.
 *	Returns 0 or special token value.
 */
static fr_token_t getthing(char const **ptr, char *buf, int buflen, bool tok,
			 fr_table_num_ordered_t const *tokenlist, size_t tokenlist_len, bool unescape)
{
	char			*s;
	char const		*p;
	char			quote;
	bool			triple = false;
	unsigned int		x;
	size_t			i;
	fr_token_t 		token;

	buf[0] = '\0';

	/* Skip whitespace */
	p = *ptr;

	fr_skip_whitespace(p);

	if (!*p) {
		*ptr = p;
		return T_EOL;
	}

	/*
	 *	Might be a 1 or 2 character token.
	 */
	if (tok) {
		for (i = 0; i < tokenlist_len; i++) {
			if (TOKEN_MATCH(p, tokenlist[i].name.str)) {
				strcpy(buf, tokenlist[i].name.str);
				p += tokenlist[i].name.len;

				/*
				 *	Try to shut up Coverity, which claims fr_token_t can be between 0..63, not
				 *	0..48???
				 */
				if ((tokenlist[i].value < 0) || (tokenlist[i].value >= T_TOKEN_LAST)) return T_INVALID;

				token = tokenlist[i].value;
				goto done;
			}
		}
	}

	/* Read word. */
	quote = '\0';
	switch (*p) {
	default:
		token = T_BARE_WORD;
		break;

	case '\'':
		token = T_SINGLE_QUOTED_STRING;
		break;

	case '"':
		token = T_DOUBLE_QUOTED_STRING;
		break;

	case '`':
		token = T_BACK_QUOTED_STRING;
		break;
	}

	if (token != T_BARE_WORD) {
		quote = *p;

		/*
		 *	Triple-quoted strings are copied over verbatim, without escapes.
		 */
		if ((buflen >= 3) && (p[1] == quote) && (p[2] == quote)) {
			p += 3;
			triple = true;
		}

		p++;
	}
	s = buf;

	while (*p && buflen-- > 1) {
		/*
		 *	We're looking for strings.  Stop on spaces, or
		 *	(if given a token list), on a token, or on a
		 *	comma.
		 */
		if (!quote) {
			if (isspace((uint8_t) *p)) break;


			if (tok) {
				for (i = 0; i < tokenlist_len; i++) {
					if (TOKEN_MATCH(p, tokenlist[i].name.str)) {
						*s++ = 0;
						goto done;
					}
				}
			}
			if (*p == ',') break;

			/*
			 *	Copy the character over.
			 */
			*s++ = *p++;
			continue;
		} /* else there was a quotation character */

		/*
		 *	Un-escaped quote character.  We're done.
		 */
		if (*p == quote) {
			if (!triple) {
				p++;
				*s++ = 0;
				goto done;
			}

			if ((buflen >= 3) && (p[1] == quote) && (p[2] == quote)) {
				p += 3;
				*s++ = 0;
				goto done;
			}

			*s++ = *p++;
			continue;
		}

		/*
		 *	Everything but backslash gets copied over.
		 */
		if (*p != '\\') {
			*s++ = *p++;
			continue;
		}

		/*
		 *	There's nothing after the backslash, it's an error.
		 */
		if (!p[1]) {
			fr_strerror_const("Unterminated string");
			return T_INVALID;
		}

		if (unescape) {
			p++;

			switch (*p) {
				case 'r':
					*s++ = '\r';
					break;
				case 'n':
					*s++ = '\n';
					break;
				case 't':
					*s++ = '\t';
					break;

				default:
					if (*p >= '0' && *p <= '9' &&
					    sscanf(p, "%3o", &x) == 1) {
						*s++ = x;
						p += 2;
					} else
						*s++ = *p;
					break;
			}
			p++;

		} else {
			/*
			 *	Convert backslash-quote to quote, but
			 *	leave everything else alone.
			 */
			if (p[1] == quote) { /* convert '\'' --> ' */
				p++;
			} else {
				if (buflen < 2) {
					fr_strerror_const("Truncated input");
					return T_INVALID;
				}

				*(s++) = *(p++);
			}
			*(s++) = *(p++);
		}
	}

	*s++ = 0;

	if (quote) {
		fr_strerror_const("Unterminated string");
		return T_INVALID;
	}

done:
	/* Skip whitespace again. */
	fr_skip_whitespace(p);

	*ptr = p;

	return token;
}

/*
 *	Read a "word" - this means we don't honor
 *	tokens as delimiters.
 */
int getword(char const **ptr, char *buf, int buflen, bool unescape)
{
	return getthing(ptr, buf, buflen, false, fr_tokens_table, fr_tokens_table_len, unescape) == T_EOL ? 0 : 1;
}


/*
 *	Read the next word, use tokens as delimiters.
 */
fr_token_t gettoken(char const **ptr, char *buf, int buflen, bool unescape)
{
	return getthing(ptr, buf, buflen, true, fr_tokens_table, fr_tokens_table_len, unescape);
}

/*
 *	Expect an operator.
 */
fr_token_t getop(char const **ptr)
{
	char op[3];
	fr_token_t token;

	token = getthing(ptr, op, sizeof(op), true, fr_tokens_table, fr_tokens_table_len, false);
	if (!fr_assignment_op[token] && !fr_comparison_op[token]) {
		fr_strerror_const("Expected operator");
		return T_INVALID;
	}
	return token;
}

/*
 *	Expect a string.
 */
fr_token_t getstring(char const **ptr, char *buf, int buflen, bool unescape)
{
	char const *p;

	if (!ptr || !*ptr || !buf) return T_INVALID;

	p = *ptr;

	fr_skip_whitespace(p);

	*ptr = p;

	if ((*p == '"') || (*p == '\'') || (*p == '`')) {
		return gettoken(ptr, buf, buflen, unescape);
	}

	return getthing(ptr, buf, buflen, false, fr_tokens_table, fr_tokens_table_len, unescape);
}

char const *fr_token_name(int token)
{
	return fr_table_str_by_value(fr_tokens_table, token, "<INVALID>");
}


/**  Skip a quoted string.
 *
 *  @param[in] start	start of the string, pointing to the quotation character
 *  @param[in] end	end of the string (or NULL for zero-terminated strings)
 *  @return
 *	>0 length of the string which was parsed
 *	<=0 on error
 */
ssize_t fr_skip_string(char const *start, char const *end)
{
	char const *p = start;
	char quote;

	quote = *(p++);

	while ((end && (p < end)) || *p) {
		/*
		 *	Stop at the quotation character
		 */
		if (*p == quote) {
			p++;
			return p - start;
		}

		/*
		 *	Not an escape character: it's OK.
		 */
		if (*p != '\\') {
			p++;
			continue;
		}

		if (end && ((p + 2) >= end)) {
		fail:
			fr_strerror_const("Unexpected escape at end of string");
			return -(p - start);
		}

		/*
		 *	Escape at EOL is not allowed.
		 */
		if (p[1] < ' ') goto fail;

		/*
		 *	\r or \n, etc.
		 */
		if (!isdigit((uint8_t) p[1])) {
			p += 2;
			continue;
		}

		/*
		 *	Double-quoted strings use \000
		 *	Regexes use \0
		 */
		if (quote == '/') {
			p++;
			continue;
		}

		if (end && ((p + 4) >= end)) goto fail;

		/*
		 *	Allow for \1f in single quoted strings
		 */
		if ((quote == '\'') && isxdigit((uint8_t) p[1]) && isxdigit((uint8_t) p[2])) {
			p += 3;
			continue;
		}

		if (!isdigit((uint8_t) p[2]) || !isdigit((uint8_t) p[3])) {
			fr_strerror_const("Invalid octal escape");
			return -(p - start);
		}

		p += 4;
	}

	/*
	 *	Unexpected end of string.
	 */
	fr_strerror_const("Unexpected end of string");
	return -(p - start);
}

