/*
 * token.c	Read the next token from a string.
 *		Yes it's pretty primitive but effective.
 *
 * Version:	$Id$
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "token.h"

static const char rcsid[] = "$Id$";

typedef struct {
	const char *str;
	int token;
} TOKEN;

static const TOKEN tokens[] = {
	{ "=~", T_OP_REG_EQ,	}, /* order is important! */
	{ "!~", T_OP_REG_NE,	},
	{ "{",	T_LCBRACE,	},
	{ "}",	T_RCBRACE,	},
	{ "(",	T_LBRACE,	},
	{ ")",	T_RBRACE,	},
	{ ",",	T_COMMA,	},
	{ "+=",	T_OP_ADD,	},
	{ "-=",	T_OP_SUB,	},
	{ ":=",	T_OP_SET,	},
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
static LRAD_TOKEN getthing(char **ptr, char *buf, int buflen, int tok,
			   const TOKEN *tokenlist)
{
	char	*s, *p;
	int	quote;
	int	escape;
	int	x;
	const TOKEN	*t;

	buf[0] = 0;

	/* Skip whitespace */
	p = *ptr;
	while (*p && isspace(*p))
		p++;

	if (*p == 0) {
		*ptr = p;
		return T_EOL;
	}

	/*
	 *	Might be a 1 or 2 character token.
	 */
	if (tok) for (t = tokenlist; t->str; t++) {
		if (TOKEN_MATCH(p, t->str)) {
			strcpy(buf, t->str);
			p += strlen(t->str);
			while (isspace(*p))
				p++;
			*ptr = p;
			return t->token;
		}
	}

	/* Read word. */
	quote = 0;
	if (*p == '"') {
		quote = 1;
		p++;
	}
	s = buf;
	escape = 0;

	while (*p && buflen-- > 0) {
		if (escape) {
			escape = 0;
			switch(*p) {
				case 'r':
					*s++ = '\r';
					break;
				case 'n':
					*s++ = '\n';
					break;
				case 't':
					*s++ = '\t';
					break;
				case '"':
					*s++ = '"';
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
			continue;
		}
		if (*p == '\\') {
			p++;
			escape = 1;
			continue;
		}
		if (quote && *p == '"') {
			p++;
			break;
		}
		if (!quote) {
			if (isspace(*p))
				break;
			if (tok) {
				for (t = tokenlist; t->str; t++)
					if (TOKEN_MATCH(p, t->str))
						break;
				if (t->str != NULL)
					break;
			}
		}
		*s++ = *p++;
	}
	*s++ = 0;

	/* Skip whitespace again. */
	while (*p && isspace(*p))
		p++;
	*ptr = p;

	/* we got SOME form of output string, even if it is empty */
	return T_INVALID;
}

/*
 *	Read a "word" - this means we don't honor
 *	tokens as delimiters.
 */
LRAD_TOKEN getword(char **ptr, char *buf, int buflen)
{
	return getthing(ptr, buf, buflen, 0, tokens) == T_EOL ? 0 : 1;
}

/*
 *	Read the next word, use tokens as delimiters.
 */
LRAD_TOKEN gettoken(char **ptr, char *buf, int buflen)
{
	return getthing(ptr, buf, buflen, 1, tokens);
}
