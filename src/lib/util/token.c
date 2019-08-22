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

#include "token.h"

#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/misc.h>

#include <ctype.h>
#include <stdio.h>
#include <string.h>

fr_table_num_ordered_t const fr_tokens_table[] = {
	{ "=~", T_OP_REG_EQ	}, /* order is important! */
	{ "!~", T_OP_REG_NE	},
	{ "{",	T_LCBRACE	},
	{ "}",	T_RCBRACE	},
	{ "(",	T_LBRACE	},
	{ ")",	T_RBRACE	},
	{ ",",	T_COMMA		},
	{ "++",	T_OP_INCRM	},
	{ "+=",	T_OP_ADD	},
	{ "-=",	T_OP_SUB	},
	{ ":=",	T_OP_SET	},
	{ "=*", T_OP_CMP_TRUE	},
	{ "!*", T_OP_CMP_FALSE	},
	{ "==",	T_OP_CMP_EQ	},
	{ "=",	T_OP_EQ		},
	{ "!=",	T_OP_NE		},
	{ ">=",	T_OP_GE		},
	{ ">",	T_OP_GT		},
	{ "<=",	T_OP_LE		},
	{ "<",	T_OP_LT		},
	{ "#",	T_HASH		},
	{ ";",	T_SEMICOLON	}
};
size_t fr_tokens_table_len = NUM_ELEMENTS(fr_tokens_table);

fr_table_num_sorted_t const fr_token_quotes_table[] = {
	{ "",	T_BARE_WORD		},
	{ "'",	T_SINGLE_QUOTED_STRING	},
	{ "\"", T_DOUBLE_QUOTED_STRING	},
	{ "`",	T_BACK_QUOTED_STRING	}
};
size_t fr_token_quotes_table_len = NUM_ELEMENTS(fr_token_quotes_table);

/*
 *  This is a hack, and has to be kept in sync with tokens.h
 */
char const *fr_tokens[] = {
	"?",			/* T_INVALID */
	"EOL",			/* T_EOL */
	"{",
	"}",
	"(",
	")",
	",",
	";",
	"++",
	"+=",
	"-=",
	":=",
	"=",
	"!=",
	">=",
	">",
	"<=",
	"<",
	"=~",
	"!~",
	"=*",
	"!*",
	"==",
	"#",
	"<BARE-WORD>",
	"<\"STRING\">",
	"<'STRING'>",
	"<`STRING`>"
};


/** Convert tokens back to a quoting character
 *
 * None string types convert to '?' to screw ups can be identified easily
 */
const char fr_token_quote[] = {
	'?',		/* invalid token */
	'?',		/* end of line */
	'?',		/* { */
	'?',		/* } */
	'?',		/* ( */
	'?',		/* ) 		 5 */
	'?',		/* , */
	'?',		/* ; */

	'?',		/* ++ */
	'?',		/* += */
	'?',		/* -=  		10 */
	'?',		/* := */
	'?',		/* = */
	'?',		/* != */
	'?',		/* >= */
	'?',		/* > 		15 */
	'?',		/* <= */
	'?',		/* < */
	'?',		/* =~ */
	'?',		/* !~ */
	'?',		/* =* 		20 */
	'?',		/* !* */
	'?',		/* == */
	'?',				/* # */
	'\0',		/* bare word */
	'"',		/* "foo" 	25 */
	'\'',		/* 'foo' */
	'`',		/* `foo` */
	'?'
};

const bool fr_assignment_op[] = {
	false,		/* invalid token */
	false,		/* end of line */
	false,		/* { */
	false,		/* } */
	false,		/* ( */
	false,		/* ) 		 5 */
	false,		/* , */
	false,		/* ; */

	true,		/* ++ */
	true,		/* += */
	true,		/* -=  		10 */
	true,		/* := */
	true,		/* = */
	false,		/* != */
	false,		/* >= */
	false,		/* > 		15 */
	false,		/* <= */
	false,		/* < */
	false,		/* =~ */
	false,		/* !~ */
	false,		/* =* 		20 */
	false,		/* !* */
	false,		/* == */
	false,				/* # */
	false,		/* bare word */
	false,		/* "foo" 	25 */
	false,		/* 'foo' */
	false,		/* `foo` */
	false
};

const bool fr_equality_op[] = {
	false,		/* invalid token */
	false,		/* end of line */
	false,		/* { */
	false,		/* } */
	false,		/* ( */
	false,		/* ) 		 5 */
	false,		/* , */
	false,		/* ; */

	false,		/* ++ */
	false,		/* += */
	false,		/* -=  		10 */
	false,		/* := */
	false,		/* = */
	true,		/* != */
	true,		/* >= */
	true,		/* > 		15 */
	true,		/* <= */
	true,		/* < */
	true,		/* =~ */
	true,		/* !~ */
	true,		/* =* 		20 */
	true,		/* !* */
	true,		/* == */
	false,				/* # */
	false,		/* bare word */
	false,		/* "foo" 	25 */
	false,		/* 'foo' */
	false,		/* `foo` */
	false
};

const bool fr_str_tok[] = {
	false,		/* invalid token */
	false,		/* end of line */
	false,		/* { */
	false,		/* } */
	false,		/* ( */
	false,		/* ) 		 5 */
	false,		/* , */
	false,		/* ; */

	false,		/* ++ */
	false,		/* += */
	false,		/* -=  		10 */
	false,		/* := */
	false,		/* = */
	false,		/* != */
	false,		/* >= */
	false,		/* > 		15 */
	false,		/* <= */
	false,		/* < */
	false,		/* =~ */
	false,		/* !~ */
	false,		/* =* 		20 */
	false,		/* !* */
	false,		/* == */
	false,				/* # */
	true,		/* bare word */
	true,		/* "foo" 	25 */
	true,		/* 'foo' */
	true,		/* `foo` */
	false
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
static FR_TOKEN getthing(char const **ptr, char *buf, int buflen, bool tok,
			 fr_table_num_ordered_t const *tokenlist, size_t tokenlist_len, bool unescape)
{
	char			*s;
	char const		*p;
	char			quote;
	unsigned int		x;
	size_t			i;
	FR_TOKEN rcode;

	buf[0] = '\0';

	/* Skip whitespace */
	p = *ptr;

	fr_skip_spaces(p);

	if (!*p) {
		*ptr = p;
		return T_EOL;
	}

	/*
	 *	Might be a 1 or 2 character token.
	 */
	if (tok) {
		for (i = 0; i < tokenlist_len; i++) {
			if (TOKEN_MATCH(p, tokenlist[i].name)) {
				strcpy(buf, tokenlist[i].name);
				p += strlen(tokenlist[i].name);

				rcode = tokenlist[i].value;
				goto done;
			}
		}
	}

	/* Read word. */
	quote = '\0';
	switch (*p) {
	default:
		rcode = T_BARE_WORD;
		break;

	case '\'':
		rcode = T_SINGLE_QUOTED_STRING;
		break;

	case '"':
		rcode = T_DOUBLE_QUOTED_STRING;
		break;

	case '`':
		rcode = T_BACK_QUOTED_STRING;
		break;
	}

	if (rcode != T_BARE_WORD) {
		quote = *p;
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
			if (isspace((int) *p)) break;


			if (tok) {
				for (i = 0; i < tokenlist_len; i++) {
					if (TOKEN_MATCH(p, tokenlist[i].name)) {
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
			p++;
			*s++ = 0;
			goto done;
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
			fr_strerror_printf("Unterminated string");
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
					fr_strerror_printf("Truncated input");
					return T_INVALID;
				}

				*(s++) = *(p++);
			}
			*(s++) = *(p++);
		}
	}

	*s++ = 0;

	if (quote) {
		fr_strerror_printf("Unterminated string");
		return T_INVALID;
	}

done:
	/* Skip whitespace again. */
	fr_skip_spaces(p);

	*ptr = p;

	return rcode;
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
FR_TOKEN gettoken(char const **ptr, char *buf, int buflen, bool unescape)
{
	return getthing(ptr, buf, buflen, true, fr_tokens_table, fr_tokens_table_len, unescape);
}

/*
 *	Expect an operator.
 */
FR_TOKEN getop(char const **ptr)
{
	char op[3];
	FR_TOKEN rcode;

	rcode = getthing(ptr, op, sizeof(op), true, fr_tokens_table, fr_tokens_table_len, false);
	if (!fr_assignment_op[rcode] && !fr_equality_op[rcode]) {
		fr_strerror_printf("Expected operator");
		return T_INVALID;
	}
	return rcode;
}

/*
 *	Expect a string.
 */
FR_TOKEN getstring(char const **ptr, char *buf, int buflen, bool unescape)
{
	char const *p;

	if (!ptr || !*ptr || !buf) return T_INVALID;

	p = *ptr;

	fr_skip_spaces(p);

	*ptr = p;

	if ((*p == '"') || (*p == '\'') || (*p == '`')) {
		return gettoken(ptr, buf, buflen, unescape);
	}

	return getthing(ptr, buf, buflen, false, fr_tokens_table, fr_tokens_table_len, unescape);
}

char const *fr_token_name(int token)
{
	return fr_table_str_by_value(fr_tokens_table, token, "???");
}
