/*
 * token.c	Read the next token from a string.
 *		Yes it's pretty primitive but effective.
 *
 * Version:	$Id$
 *
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
 *
 * Copyright 2000,2006  The FreeRADIUS server project
 */

RCSID("$Id$")

#include <freeradius-devel/libradius.h>

#include <ctype.h>

const FR_NAME_NUMBER fr_tokens[] = {
	{ "=~", T_OP_REG_EQ,	}, /* order is important! */
	{ "!~", T_OP_REG_NE,	},
	{ "{",	T_LCBRACE,	},
	{ "}",	T_RCBRACE,	},
	{ "(",	T_LBRACE,	},
	{ ")",	T_RBRACE,	},
	{ ",",	T_COMMA,	},
	{ "++",	T_OP_INCRM,	},
	{ "+=",	T_OP_ADD,	},
	{ "-=",	T_OP_SUB,	},
	{ ":=",	T_OP_SET,	},
	{ "=*", T_OP_CMP_TRUE,  },
	{ "!*", T_OP_CMP_FALSE, },
	{ "==",	T_OP_CMP_EQ,	},
	{ "=",	T_OP_EQ,	},
	{ "!=",	T_OP_NE,	},
	{ ">=",	T_OP_GE,	},
	{ ">",	T_OP_GT,	},
	{ "<=",	T_OP_LE,	},
	{ "<",	T_OP_LT,	},
	{ "#",	T_HASH,		},
	{ ";",	T_SEMICOLON,	},
	{ NULL, 0,		},
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
			 FR_NAME_NUMBER const *tokenlist, bool unescape)
{
	char			*s;
	char const		*p;
	char			quote;
	bool			end = false;
	unsigned int		x;
	FR_NAME_NUMBER const	*t;
	FR_TOKEN rcode;

	buf[0] = '\0';

	/* Skip whitespace */
	p = *ptr;

	while (*p && isspace((int) *p)) p++;

	if (!*p) {
		*ptr = p;
		return T_EOL;
	}

	/*
	 *	Might be a 1 or 2 character token.
	 */
	if (tok) for (t = tokenlist; t->name; t++) {
		if (TOKEN_MATCH(p, t->name)) {
			strcpy(buf, t->name);
			p += strlen(t->name);

			rcode = t->number;
			goto done;
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
		end = false;
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
			if (isspace((int) *p)) {
				break;
			}

			if (tok) {
				for (t = tokenlist; t->name; t++) {
					if (TOKEN_MATCH(p, t->name)) {
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
			end = true;
			p++;
			break;
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

	if (quote && !end) {
		fr_strerror_printf("Unterminated string");
		return T_INVALID;
	}

done:
	/* Skip whitespace again. */
	while (*p && isspace((int) *p)) p++;

	*ptr = p;

	return rcode;
}

/*
 *	Read a "word" - this means we don't honor
 *	tokens as delimiters.
 */
int getword(char const **ptr, char *buf, int buflen, bool unescape)
{
	return getthing(ptr, buf, buflen, false, fr_tokens, unescape) == T_EOL ? 0 : 1;
}


/*
 *	Read the next word, use tokens as delimiters.
 */
FR_TOKEN gettoken(char const **ptr, char *buf, int buflen, bool unescape)
{
	return getthing(ptr, buf, buflen, true, fr_tokens, unescape);
}

/*
 *	Expect an operator.
 */
FR_TOKEN getop(char const **ptr)
{
	char op[3];
	FR_TOKEN rcode;

	rcode = getthing(ptr, op, sizeof(op), true, fr_tokens, false);
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

	while (*p && (isspace((int)*p))) p++;

	*ptr = p;

	if ((*p == '"') || (*p == '\'') || (*p == '`')) {
		return gettoken(ptr, buf, buflen, unescape);
	}

	return getthing(ptr, buf, buflen, false, fr_tokens, unescape);
}

/*
 *	Convert a string to an integer
 */
int fr_str2int(FR_NAME_NUMBER const *table, char const *name, int def)
{
	FR_NAME_NUMBER const *this;

	if (!name) {
		return def;
	}

	for (this = table; this->name != NULL; this++) {
		if (strcasecmp(this->name, name) == 0) {
			return this->number;
		}
	}

	return def;
}

/*
 *	Convert a string matching part of name to an integer.
 */
int fr_substr2int(FR_NAME_NUMBER const *table, char const *name, int def, int len)
{
	FR_NAME_NUMBER const *this;
	size_t max;

	if (!name) {
		return def;
	}

	for (this = table; this->name != NULL; this++) {
		size_t tlen;

		tlen = strlen(this->name);

		/*
		 *	Don't match "request" to user input "req".
		 */
		if ((len > 0) && (len < (int) tlen)) continue;

		/*
		 *	Match up to the length of the table entry if len is < 0.
		 */
		max = (len < 0) ? tlen : (unsigned)len;

		if (strncasecmp(this->name, name, max) == 0) {
			return this->number;
		}
	}

	return def;
}

/*
 *	Convert an integer to a string.
 */
char const *fr_int2str(FR_NAME_NUMBER const *table, int number,
			 char const *def)
{
	FR_NAME_NUMBER const *this;

	for (this = table; this->name != NULL; this++) {
		if (this->number == number) {
			return this->name;
		}
	}

	return def;
}

char const *fr_token_name(int token)
{
	return fr_int2str(fr_tokens, token, "???");
}
